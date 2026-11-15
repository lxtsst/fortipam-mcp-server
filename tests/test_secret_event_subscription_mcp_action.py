from dataclasses import asdict
import json

import pytest

from fortipam_mcp.secret_event_subscription_mcp_action import (
    BINDING_CONTRACT, PREFIX, SecretEventSubscriptionMcpAction,
    RECIPIENT_CONTRACT, SecretEventSubscriptionMcpCandidate, _load_binding,
    build_secret_event_subscription_candidate,
)
from test_secret_event_subscription_contract import BINDING
from test_secret_event_subscription_live_workflow import candidate


def test_default_off_and_protected_binding_refuse_broadening(tmp_path):
    assert build_secret_event_subscription_candidate({}) is None
    for environment in ({PREFIX + "EXECUTION_ENABLED": "true"},
                        {PREFIX + "ENABLED": "TRUE"},
                        {PREFIX + "ENABLED": "true", PREFIX + "EXECUTION_ENABLED": "yes"}):
        with pytest.raises(ValueError): build_secret_event_subscription_candidate(environment)
    path = tmp_path / "binding.json"
    path.write_text(json.dumps({"contract": BINDING_CONTRACT, **asdict(BINDING)}))
    path.chmod(0o600)
    assert _load_binding(path) == BINDING
    path.chmod(0o644)
    with pytest.raises(ValueError): _load_binding(path)
    path.chmod(0o600)
    path.write_text(json.dumps({"contract": BINDING_CONTRACT, **asdict(BINDING), "event": "pwd-view"}))
    with pytest.raises(ValueError): _load_binding(path)


def test_authentication_profile_is_exact_and_cannot_substitute_another_actor(tmp_path, monkeypatch):
    import fortipam_mcp.secret_event_subscription_mcp_action as module
    from fortipam_mcp.secret_event_subscription_requester_session import SecretEventSubscriptionRequesterClient
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig

    tmp_path.chmod(0o700)
    key = tmp_path / "key"
    key.write_bytes(b"k" * 32)
    key.chmod(0o600)
    binding = tmp_path / "binding.json"
    binding.write_text(json.dumps({"contract": BINDING_CONTRACT, **asdict(BINDING)}))
    binding.chmod(0o600)
    environment = {PREFIX + "ENABLED": "true", PREFIX + "BINDING_FILE": str(binding),
        PREFIX + "AUTHORIZATION_HMAC_KEY_FILE": str(key), PREFIX + "AUTHORIZATION_DB": str(tmp_path / "db"),
        PREFIX + "SUBSCRIBE_CLAIM_FILE": str(tmp_path / "subscribe.json"),
        PREFIX + "RESTORE_CLAIM_FILE": str(tmp_path / "restore.json"),
        "FORTIPAM_MCP_V4_LOCAL_USER_CREATE_ACTION_BP005_USERNAME": BINDING.owner_name,
        "FORTIPAM_MCP_V4_LOCAL_USER_CREATE_ACTION_BP005_MATERIAL_DIRECTORY": str(tmp_path / "material")}
    monkeypatch.setattr(module, "load_secret_metadata_http_transport_config", lambda e:
        SecretMetadataHttpTransportConfig("https://synthetic.invalid", "synthetic-token", 1, None))
    assert build_secret_event_subscription_candidate({PREFIX + "AUTHENTICATION_PROFILE": "bp005-requester-session"}) is None
    environment[PREFIX + "AUTHENTICATION_PROFILE"] = "bp005-requester-session"
    candidate = build_secret_event_subscription_candidate(environment)
    assert candidate is not None and not candidate.subscribe._execution_enabled
    assert isinstance(candidate.subscribe._workflow._transport._factory, SecretEventSubscriptionRequesterClient)
    assert candidate.subscribe._workflow._transport._factory is candidate.restore._workflow._transport._factory
    for profile in ("cookie", "arbitrary"):
        with pytest.raises(ValueError): build_secret_event_subscription_candidate({**environment, PREFIX + "AUTHENTICATION_PROFILE": profile})
    with pytest.raises(ValueError): build_secret_event_subscription_candidate({**environment,
        "FORTIPAM_MCP_V4_LOCAL_USER_CREATE_ACTION_BP005_USERNAME": "other-private-actor"})

    recipient = tmp_path / "recipient.json"
    record = {"contract": RECIPIENT_CONTRACT, "secret_id": BINDING.secret_id,
              "owner_name": BINDING.owner_name, "recipient": "notification-fixture@example.invalid"}
    recipient.write_text(json.dumps(record))
    recipient.chmod(0o600)
    notification = {**environment, PREFIX + "EMAIL_PROFILE": "bound-lab-recipient",
                    PREFIX + "RECIPIENT_BINDING_FILE": str(recipient)}
    bound = build_secret_event_subscription_candidate(notification)
    assert bound is not None and not bound.subscribe._execution_enabled
    assert bound.subscribe._workflow._transport._expected_email == record["recipient"]
    assert bound.restore._workflow._transport._binding_digest == bound.subscribe._workflow._transport._binding_digest
    assert bound.subscribe._workflow._transport._binding_digest != candidate.subscribe._workflow._transport._binding_digest
    for invalid in ({**notification, PREFIX + "AUTHENTICATION_PROFILE": "bearer"},
                    {**notification, PREFIX + "EMAIL_PROFILE": "unset"},
                    {**notification, PREFIX + "EMAIL_PROFILE": "any-recipient"}):
        with pytest.raises(ValueError): build_secret_event_subscription_candidate(invalid)
    for changes in ({"secret_id": 999}, {"secret_id": True}, {"owner_name": "other-private-actor"},
                    {"recipient": ""}, {"recipient": "one@example.invalid,two@example.invalid"},
                    {"recipient": "one@example.invalid\r\nBCC:two@example.invalid"}, {"extra": "value"}):
        recipient.write_text(json.dumps({**record, **changes}))
        with pytest.raises(ValueError): build_secret_event_subscription_candidate(notification)
    recipient.write_text(json.dumps(record))
    recipient.write_text(recipient.read_text()[:-1] + ', "recipient": "unapproved@example.invalid"}')
    with pytest.raises(ValueError): build_secret_event_subscription_candidate(notification)
    recipient.write_text(json.dumps(record))
    recipient.chmod(0o644)
    with pytest.raises(ValueError): build_secret_event_subscription_candidate(notification)
    recipient.chmod(0o600)
    link = tmp_path / "recipient-link.json"
    link.symlink_to(recipient)
    with pytest.raises(ValueError): build_secret_event_subscription_candidate({**notification,
        PREFIX + "RECIPIENT_BINDING_FILE": str(link)})


@pytest.mark.parametrize("operate,gate", [(False, True), (True, False), (True, True)])
@pytest.mark.parametrize("recipient", ["", "notification-fixture@example.invalid"])
def test_real_http_oauth_requires_operation_scope_and_gate_for_each_direction(tmp_path, operate, gate, recipient):
    from starlette.testclient import TestClient
    from fortipam_mcp.http_server import HttpServerSettings, create_http_app
    from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
    from test_http_server import _v4_environment, _register_public_client, _authorize_and_login, _request_headers

    make, state, portal, _, posts, _ = candidate(tmp_path, expected_email=recipient)
    portal["email"] = recipient
    actions = SecretEventSubscriptionMcpCandidate(
        SecretEventSubscriptionMcpAction(make(), execution_enabled=gate),
        SecretEventSubscriptionMcpAction(make("restore"), execution_enabled=gate))
    environment = _v4_environment(tmp_path / "oauth")
    environment[RUNTIME_PROFILE_ENV] = "v4-controlled"
    settings = HttpServerSettings.from_environment(environment)
    app = create_http_app(settings, v4_secret_event_subscription_candidate=actions)
    scope = "fortipam:read fortipam:plan" + (" fortipam:operate" if operate else "")
    with TestClient(app, base_url="https://mcp.example.com") as client:
        client_id = _register_public_client(client, scope)
        code, verifier = _authorize_and_login(client, client_id, scope)
        token = client.post("/fpamcp/oauth/token", data={
            "grant_type": "authorization_code", "client_id": client_id, "code": code,
            "code_verifier": verifier, "redirect_uri": "https://client.example/callback",
            "resource": "https://mcp.example.com/fpamcp"})
        assert token.status_code == 200
        headers = _request_headers(token.json()["access_token"])
        headers["host"] = "mcp.example.com"

        def rpc(method, params):
            response = client.post("/fpamcp", headers=headers, json={
                "jsonrpc": "2.0", "id": method, "method": method, "params": params})
            assert response.status_code == 200
            return response.json()["result"]

        def call(prefix, operation, arguments):
            return rpc("tools/call", {"name": prefix + "_v4_secret_event_subscription_" + operation + "_700", "arguments": arguments})

        tools = rpc("tools/list", {})["tools"]
        subscription_tools = [t for t in tools if "secret_event_subscription" in t["name"]]
        assert len(subscription_tools) == 6
        for tool in subscription_tools:
            expected = set() if tool["name"].startswith("preview_") else {"preview_ref"} if tool["name"].startswith("confirm_") else {"authorization_ref"}
            assert set(tool["inputSchema"].get("properties", {})) == expected
        for operation in ("subscribe", "restore"):
            preview = call("preview", operation, {})
            assert not preview["isError"]
            confirmation = call("confirm", operation, {"preview_ref": preview["structuredContent"]["preview_ref"]})
            if not operate:
                assert confirmation["isError"] and not posts
                break
            assert not confirmation["isError"]
            arguments = {"authorization_ref": confirmation["structuredContent"]["authorization_ref"]}
            result = call("execute_confirmed", operation, arguments)
            if not gate:
                assert result["isError"] and not posts
                break
            assert not result["isError"] and result["structuredContent"]["outcome"] == "succeeded"
            assert call("execute_confirmed", operation, arguments)["structuredContent"]["idempotent_replay"]
        assert len(posts) == (2 if operate and gate else 0)
        if posts: assert all(r["name"] != BINDING.owner_name for r in state["results"]["subscriber"])


def test_candidate_is_absent_by_default_and_refused_in_read_only_profile(tmp_path):
    from starlette.testclient import TestClient
    from fortipam_mcp.http_server import HttpServerSettings, HttpConfigurationError, create_http_app
    from test_http_server import _v4_environment, _register_public_client, _authorize_and_login, _request_headers
    make, _, _, _, posts, _ = candidate(tmp_path)
    actions = SecretEventSubscriptionMcpCandidate(
        SecretEventSubscriptionMcpAction(make(), execution_enabled=False),
        SecretEventSubscriptionMcpAction(make("restore"), execution_enabled=False))
    environment = _v4_environment(tmp_path / "oauth")
    settings = HttpServerSettings.from_environment(environment)
    with pytest.raises(HttpConfigurationError): create_http_app(settings, v4_secret_event_subscription_candidate=actions)
    app = create_http_app(settings)
    assert not posts
    scope = "fortipam:read fortipam:plan"
    with TestClient(app, base_url="https://mcp.example.com") as client:
        client_id = _register_public_client(client, scope)
        code, verifier = _authorize_and_login(client, client_id, scope)
        token = client.post("/fpamcp/oauth/token", data={
            "grant_type": "authorization_code", "client_id": client_id, "code": code,
            "code_verifier": verifier, "redirect_uri": "https://client.example/callback",
            "resource": "https://mcp.example.com/fpamcp"})
        assert token.status_code == 200
        headers = _request_headers(token.json()["access_token"])
        headers["host"] = "mcp.example.com"
        response = client.post("/fpamcp", headers=headers, json={
            "jsonrpc": "2.0", "id": "default-tools", "method": "tools/list", "params": {}})
        assert response.status_code == 200
        assert not any("secret_event_subscription" in t["name"] for t in response.json()["result"]["tools"])
