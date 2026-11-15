"""Real local OAuth/MCP composition over synthetic fixed AD native HTTP peers."""

import asyncio
from dataclasses import replace
from urllib.parse import urlsplit

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.ad_discovery_lab_auto_runtime import AdDiscoveryLabAutoPromoter, AdDiscoveryLabAutoRunnerFactory
from fortipam_mcp.ad_discovery_mcp_action import ProtectedAdDiscoveryMcpAction
from fortipam_mcp.ad_discovery_projection_source import ad_discovery_projection_contract
from fortipam_mcp.http_server import HttpConfigurationError, HttpServerSettings, create_http_app
from fortipam_mcp.local_oauth import LocalOAuthProvider
from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
from fortipam_mcp.v4_runtime_host import (
    ad_discovery_v4_plan_host_factory, synthetic_v4_plan_host_factory,
)
from test_ad_discovery_projection_source import _prepared_source
from test_ad_discovery_v4_host import _host_settings
from test_http_server import (
    _v4_bound_environment, _register_public_client, _authorize_and_login, _request_headers,
)
from test_v4_confirmation_http import _csrf, PASSWORD
from test_v4_planning import NOW
from v4_planning import FieldKind
from v4_planning.engine import _object_kind_code
from scripts.v4_linux_onboarding_mcp_oauth_acceptance import (
    _validate_secret_onboarding_preview, _validate_source_backed_status,
    _validate_execution,
)

FEATURE = "FORTIPAM_MCP_V4_AD_DISCOVERY_EXECUTION_TOOLS_ENABLED"
TOOL = "execute_v4_ad_discovery_workflow"
SCOPE = "fortipam:read fortipam:plan fortipam:operate"


def _token(client, client_id, scope):
    code, verifier = _authorize_and_login(client, client_id, scope)
    response = client.post("/fpamcp/oauth/token", data={
        "grant_type": "authorization_code", "client_id": client_id, "code": code,
        "code_verifier": verifier, "redirect_uri": "https://client.example/callback",
        "resource": "https://mcp.example.com/fpamcp",
    })
    assert response.status_code == 200
    return response.json()["access_token"]


def _call(client, token, name, arguments):
    headers = _request_headers(token)
    headers["host"] = "mcp.example.com"
    response = client.post("/fpamcp", headers=headers, json={
        "jsonrpc": "2.0", "id": name, "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })
    assert response.status_code == 200
    return response.json()["result"]


def _grant(components, draft, principal):
    refs = {(draft.environment_ref, "environment"), (draft.scope_ref, "scope"),
            (draft.owner_ref, "owner"), (draft.audience_ref, "audience"),
            *((ref, "evidence") for ref in draft.evidence_refs)}
    for item in draft.desired_objects:
        refs.add((item.object_ref, "object_" + _object_kind_code(item.object_class)))
        contract = ad_discovery_projection_contract(item.object_class)
        refs.add((contract.source_ref, "projection_source"))
        for field, value in item.desired_fields:
            if contract.rules[field].kind is FieldKind.REFERENCE:
                refs.add((value, "field_" + field))
    components.reference_authority.issue_many(tuple(sorted(refs)),
        requester_digest=principal.requester.digest, environment_ref=draft.environment_ref,
        scope_ref=draft.scope_ref, expires_at=NOW + 300, now_epoch=NOW)
    return components.scheme_draft_authority.issue(draft, principal.requester,
        expires_at=NOW + 300, now_epoch=NOW)


@pytest.mark.parametrize("case", ["missing_factory", "disabled_factory", "wrong_profile"])
def test_ad_http_execution_rejects_incomplete_or_disabled_composition(tmp_path, case):
    environment, _ = _v4_bound_environment(tmp_path)
    settings = HttpServerSettings.from_environment(environment)
    if case != "disabled_factory":
        from fortipam_mcp.runtime_profile import RuntimeProfile
        settings = replace(settings, v4_ad_discovery_execution_enabled=True,
                           runtime_profile=RuntimeProfile.V4_CONTROLLED if case != "wrong_profile" else settings.runtime_profile)
    with pytest.raises(HttpConfigurationError):
        create_http_app(settings, v4_ad_discovery_execution_factory=(
            (lambda components: None) if case != "missing_factory" else None))


@pytest.mark.parametrize("value,mode,valid", [
    ("false", "synthetic", True), ("true", "source-backed-ad-discovery", True),
    ("true", "source-backed-secret-onboarding", False), ("1", "source-backed-ad-discovery", False),
])
def test_ad_feature_parser_requires_exact_flag_and_fixed_mode(tmp_path, value, mode, valid):
    environment, _ = _v4_bound_environment(tmp_path)
    environment.update({RUNTIME_PROFILE_ENV: "v4-controlled", FEATURE: value,
                        "FORTIPAM_MCP_V4_PLAN_HOST_MODE": mode})
    if valid:
        settings = HttpServerSettings.from_environment(environment)
        assert settings.v4_ad_discovery_execution_enabled is (value == "true")
    else:
        with pytest.raises(HttpConfigurationError):
            HttpServerSettings.from_environment(environment)


@pytest.mark.parametrize("preparation", ["programmatic", "protected_startup", "offline_bundle"])
def test_real_oauth_mcp_ad_creation_readback_and_no_replay(tmp_path, monkeypatch, preparation):
    protected_startup = preparation != "programmatic"
    environment, bootstrap_host = _v4_bound_environment(tmp_path)
    environment[RUNTIME_PROFILE_ENV] = "v4-controlled"
    base_settings = HttpServerSettings.from_environment(environment)
    provider = LocalOAuthProvider(base_settings.local_oauth)
    with TestClient(create_http_app(base_settings, v4_plan_host_factory=
        synthetic_v4_plan_host_factory(bootstrap_host, clock=lambda: NOW)),
        base_url="https://mcp.example.com") as client:
        client_id = _register_public_client(client, SCOPE)
        token = _token(client, client_id, SCOPE)
        plan_token = _token(client, client_id, "fortipam:read fortipam:plan")
    principal = planning_principal_from_access_token(
        asyncio.run(provider.load_access_token(token)), base_settings.v4_planning_authorization,
    )
    draft, fixture_source, store, writes, state = _prepared_source(tmp_path, monkeypatch)
    binding = replace(fixture_source._binding,
        domain=replace(fixture_source._binding.domain, requester_digest=principal.requester.digest))
    host_settings, _, _ = _host_settings(tmp_path)
    factory = ad_discovery_v4_plan_host_factory(host_settings, binding=binding,
        owner_transport=fixture_source._owner, source_transport=fixture_source._source_transport,
        clock=lambda: NOW + 3)
    def execute_factory(host):
        source = host.ad_discovery_projection_source
        promoter = AdDiscoveryLabAutoPromoter(b"a" * 32, projection_source=source,
            authorized_environment_ref=draft.environment_ref, authorized_scope_ref=draft.scope_ref,
            standing_lab_authorization=True)
        runners = AdDiscoveryLabAutoRunnerFactory(promoter=promoter, execution_store=store,
            source_transport=fixture_source._source_transport, owner_config=fixture_source._owner._config,
            owner_credentials=fixture_source._owner._credentials, clock=lambda: NOW + 3,
            execution_gate_open=True)
        return ProtectedAdDiscoveryMcpAction(host.plan_services,
            host.bind_ad_discovery_action_coordinator(runners),
            authorized_environment_ref=draft.environment_ref, authorized_scope_ref=draft.scope_ref,
            execution_enabled=True)

    if protected_startup:
        from fortipam_mcp import ad_discovery_runtime_host as startup
        prefix = startup.AD_DISCOVERY_RUNTIME_PREFIX
        directory = host_settings.planning_database_path.parent
        inputs = {
            FEATURE: "true", prefix + "BINDING_FILE": str(directory / "private-binding.json"),
            prefix + "EXECUTION_ENABLED": "true", prefix + "STANDING_LAB_AUTHORIZATION": "true",
            prefix + "AUTHORIZED_ENVIRONMENT_REF": draft.environment_ref,
            prefix + "AUTHORIZED_SCOPE_REF": draft.scope_ref,
            prefix + "EXECUTION_STATE_DB": str(directory / "execution.sqlite3"),
        }
        for suffix, marker in (("AUTHORITY_KEY_FILE", b"a"), ("EXECUTION_STATE_HMAC_KEY_FILE", b"e")):
            path = directory / (suffix + ".hmac")
            path.write_bytes(marker * 32)
            path.chmod(0o600)
            inputs[prefix + suffix] = str(path)
        monkeypatch.setattr(startup, "load_ad_discovery_runtime_binding", lambda path: binding)
        monkeypatch.setattr(startup, "load_secret_metadata_http_transport_config",
                            lambda env: fixture_source._source_transport._config)
        monkeypatch.setattr(startup, "owner_login_provider", lambda env: fixture_source._owner._credentials)
        monkeypatch.setattr(startup, "owner_domain_transport", lambda *args, **kwargs: fixture_source._owner)
        factory, execute_factory = startup.build_ad_discovery_runtime_host(
            host_settings, inputs, clock=lambda: NOW + 3,
        )
        assert execute_factory is not None
    components = factory(provider, base_settings.v4_confirmation)
    if preparation == "offline_bundle":
        import json
        from fortipam_mcp import ad_discovery_prepare as prepare
        from fortipam_mcp.reference_grant_bootstrap import (
            ReferenceGrantBootstrapSettings, bootstrap_reference_grants,
        )
        from fortipam_mcp.scheme_draft_bootstrap import (
            SchemeDraftBootstrapSettings, bootstrap_scheme_draft,
        )
        from fortipam_mcp.v4_runtime_host import (
            V4_PERSISTENT_REFERENCE_AUTHORITY_REF, V4_PERSISTENT_SCHEME_DRAFT_AUTHORITY_REF,
        )
        output = tmp_path / "bootstrap-inputs"
        output.mkdir(mode=0o700)
        monkeypatch.setattr(prepare, "load_ad_discovery_runtime_binding", lambda path: binding)
        result = prepare.prepare_ad_discovery_bundle(
            directory / "private-binding.json", output, audience_ref=draft.audience_ref,
            now_epoch=NOW, expires_at=NOW + 300,
        )
        assert result["execution_authorized"] is False
        reference = host_settings.reference_authority
        draft_authority = host_settings.scheme_draft_authority
        bootstrap_reference_grants(ReferenceGrantBootstrapSettings(
            reference.database_path, reference.hmac_key_path, V4_PERSISTENT_REFERENCE_AUTHORITY_REF,
            output / prepare.REFERENCE_INPUT_NAME, output / "grant-refs.json",
        ), now_epoch=NOW)
        bootstrap_scheme_draft(SchemeDraftBootstrapSettings(
            draft_authority.database_path, draft_authority.hmac_key_path,
            V4_PERSISTENT_SCHEME_DRAFT_AUTHORITY_REF,
            output / prepare.DRAFT_INPUT_NAME, output / "draft-ref.json",
        ), now_epoch=NOW)
        draft_ref = json.loads((output / "draft-ref.json").read_text())["scheme_draft_ref"]
    else:
        draft_ref = _grant(components, draft, principal)
    if protected_startup:
        store = execute_factory(components)._coordinator._resolver._factory._store
        assert state["credentials"] == store.claim_count == writes["posts"] == 0

    settings = replace(base_settings, v4_ad_discovery_execution_enabled=True)
    app = create_http_app(settings, v4_plan_host_factory=factory,
                          v4_ad_discovery_execution_factory=execute_factory)
    with TestClient(app, base_url="https://mcp.example.com") as client:
        headers = _request_headers(token)
        headers["host"] = "mcp.example.com"
        response = client.post("/fpamcp", headers=headers, json={"jsonrpc": "2.0", "id": 1,
            "method": "tools/list", "params": {}})
        tool = next(item for item in response.json()["result"]["tools"] if item["name"] == TOOL)
        assert set(tool["inputSchema"]["properties"]) == {"plan_ref", "scheme_draft_ref"}
        status = _call(client, token, "get_v4_plan_status", {})["structuredContent"]
        assert status["runtime_profile"] == "v4-plan-only"
        assert status["ad_discovery_execution_preflight_available"] is True
        _validate_source_backed_status(status, require_secret_create_runtime=False,
                                       require_ad_discovery_runtime=True)
        preview = _call(client, token, "preview_v4_administrative_intent",
                        {"scheme_draft_ref": draft_ref})["structuredContent"]
        _validate_secret_onboarding_preview(preview, "FPA-BP-014", require_ad_discovery_source=True)
        path = urlsplit(preview["confirmation_url"]).path
        initial = client.get(path)
        review = client.post(path, data={"csrf_token": _csrf(initial.text), "username": "operator",
            "password": PASSWORD, "action": "review"}, headers={"origin": "https://mcp.example.com"})
        assert review.status_code == 200 and "periodic_scanning_disabled" in review.text
        response = client.post(path, data={"csrf_token": _csrf(review.text), "action": "affirm"},
                               headers={"origin": "https://mcp.example.com"})
        assert response.status_code == 200
        confirmation = _call(client, token, "confirm_v4_administrative_intent", {
            "summary_ref": preview["summary_ref"], "summary_revision": preview["revision"],
        })["structuredContent"]
        plan = _call(client, token, "prepare_v4_non_executable_plan", {
            "summary_ref": preview["summary_ref"], "confirmation_ref": confirmation["confirmation_ref"],
        })["structuredContent"]
        args = {"plan_ref": plan["plan_ref"], "scheme_draft_ref": draft_ref}
        assert _call(client, plan_token, TOOL, args)["isError"] is True
        assert store.claim_count == writes["posts"] == 0
        result = _call(client, token, TOOL, args)
        assert result["isError"] is False
        payload = result["structuredContent"]
        assert payload["outcome"] == "succeeded" and payload["post_write_status"] == "expected_state_matches"
        assert payload["authorization_scope"] == "source_bound_ad_discovery"
        _validate_execution(payload, authorization_scope="source_bound_ad_discovery")
        assert len(payload["completed_line_refs"]) == 1
        assert store.claim_count == writes["posts"] == 1 and writes["reads_after_post"] >= 3
        replay = _call(client, token, TOOL, args)
        assert replay.get("isError") is True or replay["structuredContent"]["outcome"] != "succeeded"
        assert store.claim_count == writes["posts"] == 1
        assert "private_binding_digest" not in str(result) and binding.source.request.source_name not in str(result)
