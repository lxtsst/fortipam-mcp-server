import asyncio
import json
from types import SimpleNamespace
from dataclasses import replace
import pytest
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from fortipam_mcp.isolated_folder_mcp_action import (
    CONTRACT, PREFIX, IsolatedFolderMcpAction, _private_binding,
    build_isolated_folder_candidate, register_isolated_folder_tools,
)
from fortipam_mcp.isolated_folder_live_workflow import IsolatedFolderLiveWorkflow
from fortipam_mcp.isolated_folder_m4_adapter import IsolatedFolderBinding
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_v4_m3 import _requester
from test_isolated_folder_m4_adapter import Transport


@pytest.mark.parametrize("flag", [None, "false", "true"])
def test_empty_inactive_policy_loader_opt_in_is_internal_and_keeps_default_binding(namespace_startup, monkeypatch, flag):
    from fortipam_mcp import isolated_folder_mcp_action as module
    env, calls = namespace_startup
    env[PREFIX + "OWNERSHIP_EXPECTED_SERIAL"] = "SYNTHETIC_SERIAL"
    if flag is not None: env[PREFIX + "EMPTY_INACTIVE_POLICY_ENABLED"] = flag
    captured = {}
    def workflow(*args, **kwargs):
        captured.update(kwargs)
        return object()
    monkeypatch.setattr(module, "IsolatedFolderLiveWorkflow", workflow)
    action = build_isolated_folder_candidate(env)
    binding = captured["binding"]
    assert binding.empty_inactive_policy is (flag == "true")
    assert action._binding is binding
    assert (binding.parameters_digest != replace(binding, empty_inactive_policy=False).parameters_digest) is (flag == "true")
    assert "empty_inactive_policy" not in calls["transport"]


@pytest.mark.parametrize("suffix,value", [
    ("EMPTY_INACTIVE_POLICY_ENABLED", "TRUE"), ("EMPTY_INACTIVE_POLICY_ENABLED", "1"),
    ("ENABLED", "false"), ("OWNER_READBACK_ENABLED", "false"), ("NAMESPACE_ENABLED", "false"),
    ("OWNERSHIP_EXPECTED_SERIAL", None), ("OWNERSHIP_EXPECTED_SERIAL", ""),
])
def test_empty_inactive_policy_loader_rejects_unbound_prerequisites_before_transport(namespace_startup, suffix, value):
    env, calls = namespace_startup
    env.update({PREFIX + "OWNERSHIP_EXPECTED_SERIAL": "SYNTHETIC_SERIAL",
                PREFIX + "EMPTY_INACTIVE_POLICY_ENABLED": "true"})
    if value is None: env.pop(PREFIX + suffix, None)
    else: env[PREFIX + suffix] = value
    with pytest.raises(ValueError): build_isolated_folder_candidate(env)
    assert not calls


def test_candidate_disabled_default_and_strict_private_binding(tmp_path):
    assert build_isolated_folder_candidate({}) is None
    with pytest.raises(ValueError):
        build_isolated_folder_candidate({PREFIX + "EXECUTION_ENABLED": "true"})
    path = tmp_path / "binding.json"
    value = dict(contract=CONTRACT, name="Collector", parent_folder_id=17,
        owner_name="synthetic-owner", parent_digest="a" * 64, parent_path="Public/Parent")
    path.write_text(json.dumps(value)); path.chmod(0o600)
    binding, parent = _private_binding(path)
    assert binding.owner_name == "synthetic-owner" and parent == "Public/Parent"
    value["extra"] = "not-allowed"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError): _private_binding(path)
    path.write_text(json.dumps({k:v for k,v in value.items() if k != "extra"}))
    path.chmod(0o644)
    with pytest.raises(ValueError): _private_binding(path)


@pytest.mark.parametrize("flag", (None, "true", "false", "TRUE"))
def test_owner_readback_binding_is_explicit_and_uses_private_create_identity(tmp_path, monkeypatch, flag):
    from fortipam_mcp import isolated_folder_mcp_action as module

    binding = IsolatedFolderBinding("Collector", 17, "synthetic-owner", "a" * 64)
    monkeypatch.setattr(module, "_private_binding", lambda path: (binding, "Public/Parent"))
    monkeypatch.setattr(module, "load_secret_metadata_http_transport_config", lambda env: object())
    captured = {}
    provider = lambda: ("synthetic-owner", "synthetic-password")

    def login(env):
        captured["login"] = env
        return provider

    def transport(config, **kwargs):
        captured["transport"] = kwargs
        return object()

    monkeypatch.setattr(module, "owner_login_provider", login)
    monkeypatch.setattr(module, "IsolatedFolderHttpTransport", transport)
    monkeypatch.setattr(module, "IsolatedFolderLiveWorkflow", lambda *args, **kwargs: object())
    env = {PREFIX + "ENABLED": "true"}
    for suffix in ("BINDING_FILE", "AUTHORIZATION_DB", "AUTHORIZATION_HMAC_KEY_FILE"):
        env[PREFIX + suffix] = str(tmp_path / suffix)
    if flag is not None:
        env[PREFIX + "OWNER_READBACK_ENABLED"] = flag
    env.update({PREFIX + "OWNER_LOGIN_ENV_FILE": str(tmp_path / "login.env"),
                PREFIX + "OWNER_USERNAME_VARIABLE": "LAB_USERNAME",
                PREFIX + "OWNER_PASSWORD_VARIABLE": "LAB_PASSWORD"})
    if flag == "TRUE":
        with pytest.raises(ValueError):
            build_isolated_folder_candidate(env)
        assert not captured
        return
    assert build_isolated_folder_candidate(env) is not None
    assert captured["transport"] == {
        "parent_path": "Public/Parent", "child_name": "Collector" if flag == "true" else None,
        "owner_name": "synthetic-owner" if flag == "true" else None,
        "owner_credentials": provider if flag == "true" else None,
    }
    assert ("login" in captured) is (flag == "true")
    if flag == "true":
        assert captured["login"] == {module.OWNER_LOGIN_PREFIX + "SESSION_ENABLED": "true",
            module.OWNER_LOGIN_PREFIX + "LOGIN_ENV_FILE": str(tmp_path / "login.env"),
            module.OWNER_LOGIN_PREFIX + "USERNAME_VARIABLE": "LAB_USERNAME",
            module.OWNER_LOGIN_PREFIX + "PASSWORD_VARIABLE": "LAB_PASSWORD"}
        del env[PREFIX + "OWNER_PASSWORD_VARIABLE"]
        with pytest.raises(ValueError):
            build_isolated_folder_candidate(env)


@pytest.fixture
def namespace_startup(tmp_path, monkeypatch):
    from fortipam_mcp import isolated_folder_mcp_action as module
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    binding = IsolatedFolderBinding("mcp-v4-domain-owner-synthetic", 17, "synthetic-owner", "a" * 64)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("synthetic pinned peer\n"); known_hosts.chmod(0o600)
    monkeypatch.setattr(module, "_private_binding", lambda path: (binding, "Public/Parent"))
    monkeypatch.setattr(module, "load_secret_metadata_http_transport_config", lambda env:
        SecretMetadataHttpTransportConfig("https://fortipam.example.test", "synthetic-token", 5, None))
    calls = {}
    def credentials():
        pytest.fail("startup must never resolve Owner credentials")
    monkeypatch.setattr(module, "owner_login_provider", lambda env: credentials)
    def transport(config, **kwargs):
        calls["transport"] = kwargs
        return object()
    monkeypatch.setattr(module, "IsolatedFolderHttpTransport", transport)
    monkeypatch.setattr(module, "IsolatedFolderLiveWorkflow", lambda *args, **kwargs: object())
    env = {PREFIX + "ENABLED": "true", PREFIX + "OWNER_READBACK_ENABLED": "true",
           PREFIX + "NAMESPACE_ENABLED": "true", PREFIX + "SSH_HOST": "synthetic.invalid",
           PREFIX + "SSH_KNOWN_HOSTS_FILE": str(known_hosts), PREFIX + "NAMESPACE_WITNESS_FOLDER_ID": "18"}
    for suffix in ("BINDING_FILE", "AUTHORIZATION_DB", "AUTHORIZATION_HMAC_KEY_FILE", "OWNER_LOGIN_ENV_FILE"):
        env[PREFIX + suffix] = str(tmp_path / suffix)
    env[PREFIX + "OWNER_USERNAME_VARIABLE"] = "LAB_USERNAME"
    env[PREFIX + "OWNER_PASSWORD_VARIABLE"] = "LAB_PASSWORD"
    return env, calls


def test_namespace_opt_in_is_lazy_preserves_closed_gate_and_adds_no_tools(namespace_startup):
    env, calls = namespace_startup
    action = build_isolated_folder_candidate(env)
    assert action is not None and callable(calls["transport"]["namespace_observer"])
    assert calls["transport"]["child_name"] == "mcp-v4-domain-owner-synthetic"
    env[PREFIX + "NAMESPACE_ENABLED"] = "false"
    assert build_isolated_folder_candidate(env) is not None
    assert "namespace_observer" not in calls["transport"]


def test_creation_ownership_opt_in_requires_pinned_serial_and_lazy_owner_namespace(namespace_startup, monkeypatch):
    from fortipam_mcp import isolated_folder_mcp_action as module
    env, calls = namespace_startup
    captured = {}
    def workflow(*args, **kwargs):
        captured.update(kwargs)
        return object()
    monkeypatch.setattr(module, "IsolatedFolderLiveWorkflow", workflow)
    action = build_isolated_folder_candidate(env)
    assert captured["ownership_expected_serial"] is None
    env[PREFIX + "OWNERSHIP_EXPECTED_SERIAL"] = "SYNTHETIC_SERIAL"
    action = build_isolated_folder_candidate(env)
    assert action is not None and action._workflow is action._action._workflow
    assert captured["ownership_expected_serial"] == "SYNTHETIC_SERIAL"
    assert captured["binding"].owner_name == "synthetic-owner"
    assert callable(calls["transport"]["namespace_observer"])


@pytest.mark.parametrize("suffix,value", (
    ("OWNERSHIP_EXPECTED_SERIAL", ""), ("OWNERSHIP_EXPECTED_SERIAL", "bad serial"),
    ("OWNERSHIP_EXPECTED_SERIAL", "S" * 129), ("OWNER_READBACK_ENABLED", "false"),
    ("NAMESPACE_ENABLED", "false"), ("ENABLED", "false"),
))
def test_creation_ownership_opt_in_refuses_incomplete_source_before_transport(namespace_startup, suffix, value):
    env, calls = namespace_startup
    env[PREFIX + "OWNERSHIP_EXPECTED_SERIAL"] = "SYNTHETIC_SERIAL"
    env[PREFIX + suffix] = value
    with pytest.raises(ValueError): build_isolated_folder_candidate(env)
    assert calls == {}


@pytest.mark.parametrize("suffix,value", (
    ("NAMESPACE_ENABLED", "TRUE"), ("OWNER_READBACK_ENABLED", "false"),
    ("SSH_HOST", "bad host"), ("SSH_PORT", "0"), ("SSH_PORT", "invalid"),
    ("SSH_KNOWN_HOSTS_FILE", "relative"), ("NAMESPACE_WITNESS_FOLDER_ID", "17"),
    ("NAMESPACE_WITNESS_FOLDER_ID", "invalid"),
))
def test_namespace_opt_in_rejects_missing_or_malformed_source_bindings(namespace_startup, suffix, value):
    env, calls = namespace_startup
    env[PREFIX + suffix] = value
    with pytest.raises(ValueError): build_isolated_folder_candidate(env)
    assert calls == {}


def test_namespace_opt_in_rejects_absent_and_unsafe_pinned_hosts(namespace_startup):
    from pathlib import Path
    env, calls = namespace_startup
    path = Path(env[PREFIX + "SSH_KNOWN_HOSTS_FILE"])
    path.chmod(0o644)
    with pytest.raises(ValueError): build_isolated_folder_candidate(env)
    path.chmod(0o600)
    del env[PREFIX + "SSH_HOST"]
    with pytest.raises(ValueError): build_isolated_folder_candidate(env)
    assert calls == {}


@pytest.mark.parametrize("execution_enabled", [False, True])
def test_sdk_candidate_tools_keep_selectors_private_and_enforce_execution_gate(tmp_path, execution_enabled):
    async def scenario():
        key = tmp_path / "key"; key.write_bytes(b"a" * 32); key.chmod(0o600)
        binding = IsolatedFolderBinding("Collector", 17, "synthetic-owner", "a" * 64)
        transport = Transport(None)
        workflow = IsolatedFolderLiveWorkflow(tmp_path / "state.sqlite3", key, transport, binding=binding, clock=lambda:1000)
        principal = V4PlanningPrincipal(_requester(), "b" * 64)
        checks = []
        def operator():
            checks.append("operate")
            return principal
        host = SimpleNamespace(mcp=MCPServer("candidate-test"), _v4_planning_principal=lambda:principal,
            _v4_folder_action_principal=operator)
        register_isolated_folder_tools(host, IsolatedFolderMcpAction(workflow, binding, execution_enabled=execution_enabled))
        listed = await host.mcp.list_tools()
        assert len(listed) == 3
        preview = await host.mcp.call_tool("preview_v4_isolated_folder_create", {})
        assert not preview.is_error
        summary = preview.structured_content
        assert "synthetic-owner" not in json.dumps(summary)
        confirmation = await host.mcp.call_tool("confirm_v4_isolated_folder_create", {"preview_ref": summary["preview_ref"]})
        assert not confirmation.is_error
        arguments = {"authorization_ref": confirmation.structured_content["authorization_ref"]}
        if execution_enabled:
            result = await host.mcp.call_tool("execute_confirmed_v4_isolated_folder", arguments)
            assert not result.is_error and result.structured_content["outcome"] == "succeeded"
        else:
            with pytest.raises(ToolError):
                await host.mcp.call_tool("execute_confirmed_v4_isolated_folder", arguments)
        assert transport.posts == int(execution_enabled)
        assert checks == ["operate", "operate"]
    asyncio.run(scenario())


def test_http_host_rejects_candidate_outside_controlled_oauth_profile(tmp_path):
    from fortipam_mcp.http_server import HttpServerSettings, HttpConfigurationError, create_http_app
    from test_http_server import _v4_environment
    settings = HttpServerSettings.from_environment(_v4_environment(tmp_path))
    with pytest.raises(HttpConfigurationError, match="Isolated Folder candidate requires"):
        create_http_app(settings, v4_isolated_folder_action=object())


def test_actual_oauth_creation_commits_signed_receipt_for_authenticated_creator(tmp_path):
    from starlette.testclient import TestClient
    from fortipam_mcp.http_server import HttpServerSettings, create_http_app
    from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
    from test_http_server import _v4_environment, _register_public_client, _authorize_and_login, _request_headers
    from test_isolated_folder_creation_ownership import SnapshotTransport, SERIAL
    env = _v4_environment(tmp_path / "oauth")
    env[RUNTIME_PROFILE_ENV] = "v4-controlled"
    tmp_path.chmod(0o700)
    key = tmp_path / "candidate-key"; key.write_bytes(b"a" * 32); key.chmod(0o600)
    binding = IsolatedFolderBinding("Collector", 17, "synthetic-owner", "a" * 64)
    transport = SnapshotTransport()
    workflow = IsolatedFolderLiveWorkflow(tmp_path / "candidate.sqlite3", key, transport,
        binding=binding, ownership_expected_serial=SERIAL)
    action = IsolatedFolderMcpAction(workflow, binding, execution_enabled=True)
    app = create_http_app(HttpServerSettings.from_environment(env), v4_isolated_folder_action=action)
    scope = "fortipam:read fortipam:plan fortipam:operate"
    with TestClient(app, base_url="https://mcp.example.com") as client:
        client_id = _register_public_client(client, scope)
        code, verifier = _authorize_and_login(client, client_id, scope)
        token = client.post("/fpamcp/oauth/token", data={"grant_type":"authorization_code",
            "client_id":client_id,"code":code,"code_verifier":verifier,
            "redirect_uri":"https://client.example/callback","resource":"https://mcp.example.com/fpamcp"})
        assert token.status_code == 200
        headers = _request_headers(token.json()["access_token"]); headers["host"] = "mcp.example.com"
        def call(name, arguments):
            result = client.post("/fpamcp", headers=headers,json={"jsonrpc":"2.0","id":name,
                "method":"tools/call","params":{"name":name,"arguments":arguments}}).json()["result"]
            assert not result["isError"]
            return result["structuredContent"]
        preview = call("preview_v4_isolated_folder_create", {})
        confirmed = call("confirm_v4_isolated_folder_create", {"preview_ref":preview["preview_ref"]})
        result = call("execute_confirmed_v4_isolated_folder", {"authorization_ref":confirmed["authorization_ref"]})
        assert result["outcome"] == "succeeded" and transport.posts == transport.snapshot_calls == 1
        creator = workflow._get_by_preview(preview["preview_ref"]).requester_digest
        owned = action._workflow.read_creation_ownership(preview["preview_ref"], creator)
        assert owned.requester_digest == creator and owned.native_folder_id == 23
        assert owned.serial == SERIAL and owned.snapshot.folder == transport.folder
        for private in (SERIAL, "baseline", "user-permission", "native_folder_id"):
            assert private not in json.dumps((preview, confirmed, result))


@pytest.mark.parametrize("operate", [False, True])
def test_real_http_oauth_isolated_candidate_authorizes_one_private_bound_write(tmp_path, operate):
    from starlette.testclient import TestClient
    from fortipam_mcp.http_server import HttpServerSettings, create_http_app
    from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
    from test_http_server import _v4_environment, _register_public_client, _authorize_and_login, _request_headers
    env = _v4_environment(tmp_path / "oauth")
    env[RUNTIME_PROFILE_ENV] = "v4-controlled"
    settings = HttpServerSettings.from_environment(env)
    key = tmp_path / "candidate-key"; key.write_bytes(b"a" * 32); key.chmod(0o600)
    binding = IsolatedFolderBinding("Collector", 17, "synthetic-owner", "a" * 64)
    transport = Transport(None)
    workflow = IsolatedFolderLiveWorkflow(tmp_path / "candidate.sqlite3", key, transport, binding=binding)
    action = IsolatedFolderMcpAction(workflow, binding, execution_enabled=True)
    app = create_http_app(settings, v4_isolated_folder_action=action)
    scope = "fortipam:read fortipam:plan" + (" fortipam:operate" if operate else "")
    with TestClient(app, base_url="https://mcp.example.com") as client:
        client_id = _register_public_client(client, scope)
        code, verifier = _authorize_and_login(client, client_id, scope)
        token = client.post("/fpamcp/oauth/token", data={
            "grant_type":"authorization_code", "client_id":client_id, "code":code,
            "code_verifier":verifier, "redirect_uri":"https://client.example/callback",
            "resource":"https://mcp.example.com/fpamcp"})
        assert token.status_code == 200
        headers = _request_headers(token.json()["access_token"])
        headers["host"] = "mcp.example.com"
        def call(name, arguments):
            response = client.post("/fpamcp", headers=headers, json={"jsonrpc":"2.0", "id":name,
                "method":"tools/call", "params":{"name":name,"arguments":arguments}})
            assert response.status_code == 200
            return response.json()["result"]
        preview = call("preview_v4_isolated_folder_create", {})
        assert not preview["isError"]
        assert "synthetic-owner" not in json.dumps(preview)
        confirmed = call("confirm_v4_isolated_folder_create", {"preview_ref":preview["structuredContent"]["preview_ref"]})
        if not operate:
            assert confirmed["isError"] and transport.posts == 0
            return
        assert not confirmed["isError"]
        arguments = {"authorization_ref":confirmed["structuredContent"]["authorization_ref"]}
        result = call("execute_confirmed_v4_isolated_folder", arguments)
        assert not result["isError"] and result["structuredContent"]["outcome"] == "succeeded"
        replay = call("execute_confirmed_v4_isolated_folder", arguments)
        assert replay["structuredContent"]["idempotent_replay"] is True
        assert transport.posts == 1
