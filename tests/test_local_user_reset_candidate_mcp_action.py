"""Synthetic OAuth/MCP acceptance of the fixed, private-bound reset candidate."""

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs

import httpx
import pytest

from fortipam_mcp.local_user_reset_api_actor import LocalUserResetApiActor
from fortipam_mcp.local_user_reset_candidate_mcp_action import (
    CONTRACT, PREFIX, LocalUserResetCandidateMcpAction, LocalUserResetCandidateMcpError,
    build_local_user_reset_candidate,
)
import fortipam_mcp.local_user_reset_candidate_mcp_action as action_module
from fortipam_mcp.local_user_reset_http_transport import LocalUserResetBinding, _POLICY_PATH
from fortipam_mcp.local_user_reset_fixture_preflight import _ACTOR
from fortipam_mcp.local_user_reset_metadata_reader import _device_identity_digest
from fortipam_mcp.local_user_reset_policy_reader import FortiPamLocalUserResetPolicyReader
from fortipam_mcp.local_user_reset_provenance_inspector import FortiPamLocalUserResetProvenanceInspector
from fortipam_mcp.local_user_reset_ssh_candidate import FortiPamLocalUserResetSshCandidate
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig, SYSTEM_STATUS_PATH
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
import fortipam_mcp.local_user_reset_ssh_transport as ssh_module

from test_local_user_reset_api_actor import _Connection
from test_local_user_reset_execution import _policy
from test_local_user_reset_material_source import _automatic_current_source
from test_local_user_reset_metadata_reader import _monitor
from test_local_user_reset_ssh_transport import _FakeSshSession, _config
from test_m4_execution_store import _claim
from test_v4_m3 import _requester


@pytest.fixture
def harness(tmp_path, monkeypatch):
    source = _automatic_current_source(tmp_path)
    source._reset = source._reset.rename(tmp_path / "reset-next")
    binding = LocalUserResetBinding(replace(source._binding.expected, status="enable"))
    config = SecretMetadataHttpTransportConfig("https://pam.example.test", "synthetic-token", 5, None)
    identity = _device_identity_digest(b"SYNTHETIC01")
    inspector = object.__new__(FortiPamLocalUserResetProvenanceInspector)
    inspector._config, inspector._principal = config, "synthetic-api-principal"
    inspector._metadata = SimpleNamespace(read_device_identity_digest=lambda: identity)
    state = SimpleNamespace(writer="super_admin", now=1000, baseline=binding.expected, writes=0,
                            calls=[], sessions=[], policy=_policy())
    monkeypatch.setattr(FortiPamLocalUserResetProvenanceInspector, "read_nonmaterial_baseline",
                        lambda self: state.baseline)
    monkeypatch.setattr(FortiPamLocalUserResetPolicyReader, "read_policy_snapshot", lambda self: state.policy)
    policy_reader = FortiPamLocalUserResetPolicyReader(config)
    source._binding, source._inspector = binding, inspector
    actor = LocalUserResetApiActor(config, binding=binding, inspector=inspector, enabled=True,
        connection_factory=lambda *args, **kwargs: _Connection(state.calls), clock=lambda: 100.0)

    class Session(_FakeSshSession):
        def dispatch(self, data):
            command = data.decode().strip()
            if command == "get system status":
                self.commands.append(command)
                self._emit(b"Serial-Number: SYNTHETIC01\r\nfpa #")
            else:
                if command.startswith("set password "):
                    state.writes += 1
                super().dispatch(data)

    def connect(*args, **kwargs):
        session = Session(compact=b"", full_outputs=[], writer_profile=state.writer)
        state.sessions.append(session)
        return session

    monkeypatch.setattr(ssh_module.asyncssh, "connect", connect)
    candidate = FortiPamLocalUserResetSshCandidate(config, ssh_config=_config(tmp_path), binding=binding,
        inspector=inspector, owner_session=actor, material_lease_provider=source,
        device_identity_digest=identity, enabled=True)
    key = source._reset / "execution.key"
    key.write_bytes(b"synthetic-m4-key-" + b"a" * 32)
    key.chmod(0o600)
    store = PersistentM4ExecutionStateStore(source._reset / "execution.sqlite3", key)
    action = LocalUserResetCandidateMcpAction(candidate, store, policy_reader,
        execution_enabled=True, clock=lambda: state.now)
    state.action, state.source, state.store = action, source, store
    state.principal = V4PlanningPrincipal(_requester(), "b" * 64)
    return state


def test_builder_is_default_off_and_does_not_accept_partial_activation():
    assert build_local_user_reset_candidate({}) is None
    for env in ({PREFIX + "EXECUTION_ENABLED": "true"}, {PREFIX + "ENABLED": "True"},
                {PREFIX + "ENABLED": "true"}, {PREFIX + "LOGIN_ACCEPTANCE_ENABLED": "true"},
                {PREFIX + "LOGIN_ACCEPTANCE_ENABLED": "yes"}):
        with pytest.raises(LocalUserResetCandidateMcpError):
            build_local_user_reset_candidate(env)


def test_unqualified_writer_returns_preview_gap_before_material_or_claim(harness):
    h = harness
    h.writer = "custom"
    preview = h.action.preview(h.principal)
    assert preview["state"] == "not_ready" and preview["gaps"] == ["writer_role_unqualified"]
    assert not preview["can_confirm"] and "preview_ref" not in preview
    assert not h.source._consumed and h.store.claim_count == 0 and h.writes == 0


@pytest.mark.parametrize("gate", [False, True])
@pytest.mark.parametrize("login", [False, True])
def test_builder_reuses_prepared_material_and_existing_store(harness, monkeypatch, gate, login):
    h = harness
    candidate = h.action._candidate
    monkeypatch.setattr(action_module, "load_secret_metadata_http_transport_config", lambda env: candidate._owner._config)
    monkeypatch.setattr(action_module, "load_local_user_create_ssh_transport_config", lambda env: candidate._ssh_config)
    monkeypatch.setattr(action_module, "FortiPamLocalUserResetProvenanceInspector", lambda *args, **kwargs: candidate._inspector)
    action = build_local_user_reset_candidate({PREFIX + "ENABLED": "true",
        PREFIX + "EXECUTION_ENABLED": str(gate).lower(),
        PREFIX + "LOGIN_ACCEPTANCE_ENABLED": str(login).lower(),
        PREFIX + "FIXTURE_DIRECTORY": str(h.source._fixture),
        PREFIX + "RESET_DIRECTORY": str(h.source._reset), PREFIX + "API_PRINCIPAL": "synthetic-api-principal"})
    assert action._execution_enabled is gate
    assert action._login_acceptance_enabled is login
    assert action._candidate._enabled is gate
    assert action._candidate._owner._enabled is gate
    assert action._candidate._material_provider._enabled is gate
    assert action._candidate._material_provider._binding_digest == h.source._binding_digest
    assert action._store._path == h.store._path and action._store.claim_count == 0
    assert not h.sessions and not h.calls and h.writes == 0


@pytest.mark.parametrize("login_enabled", [False, True])
def test_failure_after_reservation_is_not_retried(harness, monkeypatch, login_enabled):
    h = harness
    login = _integrated_login(h, monkeypatch) if login_enabled else None
    preview = h.action.preview(h.principal)
    authorized = h.action.confirm(preview["preview_ref"], h.principal)

    def unavailable(self):
        raise RuntimeError("synthetic-private-failure-detail")

    monkeypatch.setattr(action_module.FortiPamLocalUserResetExecution, "execute", unavailable)
    result = h.action.execute(authorized["authorization_ref"], h.principal)
    assert result["outcome"] == "reconciliation_required" and not result["password_change_confirmed"]
    assert not result["password_write_acknowledged"] and not result["login_verified"]
    assert result["current_login_reconciliation_required"]
    assert "synthetic-private-failure-detail" not in json.dumps(result)
    assert h.action.execute(authorized["authorization_ref"], h.principal)["idempotent_replay"]
    assert (h.source._reset / "dispatch-invocation").is_file()
    assert not h.action.preview(h.principal)["can_confirm"]
    assert h.writes == 0 and not h.source._consumed
    assert (h.source._fixture / "current-login-transition.json").is_file()
    if login is not None:
        assert result["login_acceptance_reason"] == "reset_unverified"
        assert not login.calls and not (h.source._reset / "result.json").exists()


def test_repeated_preview_preserves_confirmation_and_expired_result_cache(harness):
    h = harness
    preview = h.action.preview(h.principal)
    authorized = h.action.confirm(preview["preview_ref"], h.principal)
    h.now += 1
    repeated = h.action.preview(h.principal)
    assert repeated["preview_ref"] == preview["preview_ref"]
    assert repeated["summary_digest"] == preview["summary_digest"]
    assert repeated["expires_at"] == preview["expires_at"]
    assert repeated["confirmation"] == "recorded" and not repeated["can_confirm"]
    result = h.action.execute(authorized["authorization_ref"], h.principal)
    assert result["outcome"] == "succeeded" and h.writes == 1
    h.now = preview["expires_at"] + 1
    assert not h.action.preview(h.principal)["can_confirm"]
    assert h.action.execute(authorized["authorization_ref"], h.principal)["idempotent_replay"]
    assert h.writes == 1 and h.store.claim_count == 1


def test_capacity_preserves_live_records_and_reclaims_expired_authority(harness):
    h = harness
    principals = [V4PlanningPrincipal(h.principal.requester, f"{index:064x}") for index in range(33)]
    previews = [h.action.preview(principal) for principal in principals[:32]]
    authorized = h.action.confirm(previews[0]["preview_ref"], principals[0])
    sessions = len(h.sessions)
    full = h.action.preview(principals[32])
    assert full["gaps"] == ["preview_capacity_exhausted"] and "preview_ref" not in full
    assert len(h.action._records) == 32 and len(h.sessions) == sessions
    assert h.action.preview(principals[0])["preview_ref"] == previews[0]["preview_ref"]
    h.now = previews[0]["expires_at"]
    fresh = h.action.preview(principals[32])
    assert fresh["can_confirm"] and len(h.action._records) == 1
    with pytest.raises(LocalUserResetCandidateMcpError):
        h.action.execute(authorized["authorization_ref"], principals[0])
    with pytest.raises(LocalUserResetCandidateMcpError):
        h.action.confirm(previews[1]["preview_ref"], principals[1])
    assert h.writes == 0 and h.store.claim_count == 0 and not h.source._consumed


def test_preview_reports_drift_without_replacing_confirmation(harness):
    h = harness
    preview = h.action.preview(h.principal)
    authorized = h.action.confirm(preview["preview_ref"], h.principal)
    original_policy = h.policy
    h.policy = replace(h.policy, minimum_length=h.policy.minimum_length + 1)
    changed = h.action.preview(h.principal)
    assert changed["gaps"] == ["confirmed_preview_changed"] and not changed["can_confirm"]
    with pytest.raises(LocalUserResetCandidateMcpError):
        h.action.execute(authorized["authorization_ref"], h.principal)
    assert h.writes == 0 and h.store.claim_count == 0
    h.policy = original_policy
    assert h.action.execute(authorized["authorization_ref"], h.principal)["outcome"] == "succeeded"
    assert h.writes == 1


@pytest.mark.parametrize("failure", ["namespace", "expired", "metadata", "material", "writer", "gate"])
def test_changed_or_unauthorized_request_cannot_dispatch(harness, failure):
    h = harness
    preview = h.action.preview(h.principal)
    authorized = h.action.confirm(preview["preview_ref"], h.principal)
    principal = h.principal
    if failure == "namespace":
        principal = V4PlanningPrincipal(h.principal.requester, "c" * 64)
        with pytest.raises(LocalUserResetCandidateMcpError):
            h.action.confirm(preview["preview_ref"], principal)
    elif failure == "expired":
        h.now = preview["expires_at"]
    elif failure == "metadata":
        h.baseline = replace(h.baseline, nonmaterial_state_digest="c" * 64)
    elif failure == "material":
        (h.source._fixture / "current-login-binding.json").unlink()
    elif failure == "writer":
        h.writer = "custom"
    else:
        h.action._execution_enabled = False
    with pytest.raises(LocalUserResetCandidateMcpError):
        h.action.execute(authorized["authorization_ref"], principal)
    assert h.writes == 0 and h.store.claim_count == 0 and not h.source._consumed
    assert not (h.source._reset / "dispatch-invocation").exists()


@pytest.mark.parametrize("reserved_by", ["claim", "marker"])
def test_restart_retains_unfinished_reservation(harness, reserved_by):
    h = harness
    if reserved_by == "claim":
        _claim(h.store)
        assert h.store.audit_events == () and h.store.claim_count == 1
    else:
        marker = h.source._reset / "dispatch-invocation"
        marker.write_bytes(b"reserved")
        marker.chmod(0o600)
    restarted_store = PersistentM4ExecutionStateStore(h.store._path, h.store._key_path)
    restarted = LocalUserResetCandidateMcpAction(h.action._candidate, restarted_store,
        h.action._policy_reader, clock=lambda: h.now)
    preview = restarted.preview(h.principal)
    assert preview["gaps"] == ["execution_reserved_or_consumed"]
    assert not preview["can_confirm"] and "preview_ref" not in preview
    assert not h.sessions and not h.source._consumed and h.writes == 0


def test_http_host_rejects_candidate_outside_controlled_oauth_profile(tmp_path):
    from fortipam_mcp.http_server import HttpServerSettings, HttpConfigurationError, create_http_app
    from test_http_server import _v4_environment
    settings = HttpServerSettings.from_environment(_v4_environment(tmp_path))
    with pytest.raises(HttpConfigurationError, match="Local User reset candidate requires"):
        create_http_app(settings, v4_local_user_reset_candidate_action=object())


def _integrated_login(h, monkeypatch, *, reject=False):
    observed = SimpleNamespace(calls=[], active=False)

    def respond(request):
        path = request.url.path
        observed.calls.append((request.method, path))
        assert "authorization" not in request.headers
        if path == "/remote/login":
            return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH" method="post">')
        if path == "/XX/YY/ZZ/AUTH":
            values = parse_qs(request.content.decode())
            assert values["username"] == [h.source._binding.expected.username]
            assert values["password"] == [(h.source._reset / "next-password").read_text()]
            observed.active = not reject
            return httpx.Response(200 if reject else 303, headers={"location": "/"})
        if path == "/":
            return httpx.Response(200)
        if path == SYSTEM_STATUS_PATH:
            return httpx.Response(200 if observed.active else 401, json={"version": "v7.0.0", "build": 29})
        if path == _ACTOR:
            name = h.source._binding.expected.username
            return httpx.Response(200, content=bytes(_monitor("web-ui/state", {"admin": {
                "name": name, "login_name": name, "sponsored_group_name": "", "guest_admin": False}})),
                headers={"content-type": "application/json"})
        if path == "/logout":
            observed.active = False
            return httpx.Response(200)
        raise AssertionError("Unexpected login route")

    original = action_module.finalize_verified_reset_login

    def finalize(*args, **kwargs):
        return original(*args, **kwargs,
            client_factory=lambda **settings: httpx.Client(**settings, transport=httpx.MockTransport(respond)))

    monkeypatch.setattr(action_module, "finalize_verified_reset_login", finalize)
    h.action = LocalUserResetCandidateMcpAction(h.action._candidate, h.store, h.action._policy_reader,
        execution_enabled=True, login_acceptance_enabled=True, clock=lambda: h.now)
    return observed


@pytest.mark.parametrize("failure_file", ["result.json", "login-finalization.json"])
def test_integrated_acceptance_persistence_failure_keeps_execution_nonreplayable(
    harness, monkeypatch, failure_file,
):
    h = harness
    login = _integrated_login(h, monkeypatch)
    preview = h.action.preview(h.principal)
    assert preview["login_acceptance_mode"] == "one_private_attempt"
    confirmed = h.action.confirm(preview["preview_ref"], h.principal)
    original = action_module._write_once

    def write(directory, identity, name, content):
        if name == failure_file:
            raise OSError("synthetic-private-disk-failure")
        return original(directory, identity, name, content)

    monkeypatch.setattr(action_module, "_write_once", write)
    result = h.action.execute(confirmed["authorization_ref"], h.principal)
    assert result["outcome"] == "reconciliation_required"
    assert result["write_outcome"] == "succeeded" and result["password_write_acknowledged"]
    assert result["login_acceptance_reason"] == "persistence_failed"
    assert "synthetic-private" not in json.dumps(result)
    expected_login_count = int(failure_file == "login-finalization.json")
    assert login.calls.count(("POST", "/XX/YY/ZZ/AUTH")) == expected_login_count
    assert result["current_binding_updated"] is bool(expected_login_count)
    calls = list(login.calls)
    replay = h.action.execute(confirmed["authorization_ref"], h.principal)
    assert replay == {**result, "idempotent_replay": True}
    assert login.calls == calls and h.writes == 1 and h.store.claim_count == 1


def test_integrated_acceptance_mode_drift_rejects_before_reset(harness, monkeypatch):
    h = harness
    login = _integrated_login(h, monkeypatch)
    preview = h.action.preview(h.principal)
    confirmed = h.action.confirm(preview["preview_ref"], h.principal)
    h.action._login_acceptance_enabled = False
    with pytest.raises(LocalUserResetCandidateMcpError):
        h.action.execute(confirmed["authorization_ref"], h.principal)
    assert not login.calls and h.writes == 0 and h.store.claim_count == 0


def test_integrated_acceptance_refuses_preexisting_result_before_reset(harness, monkeypatch):
    h = harness
    login = _integrated_login(h, monkeypatch)
    path = h.source._reset / "result.json"
    path.write_text("preserved-synthetic-result")
    path.chmod(0o600)
    result = h.action.preview(h.principal)
    assert result["gaps"] == ["execution_reserved_or_consumed"]
    assert path.read_text() == "preserved-synthetic-result"
    assert not login.calls and not h.sessions and h.store.claim_count == 0


@pytest.mark.parametrize("operate", [False, True])
@pytest.mark.parametrize("login_mode", ["separate", "verified", "rejected"])
def test_http_oauth_mcp_keeps_selectors_private_and_dispatches_only_once(
    tmp_path: Path, harness, monkeypatch, operate, login_mode,
):
    from starlette.testclient import TestClient
    from fortipam_mcp.http_server import HttpServerSettings, create_http_app
    from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
    from test_http_server import _v4_environment, _register_public_client, _authorize_and_login, _request_headers
    h = harness
    login = None if login_mode == "separate" else _integrated_login(h, monkeypatch,
        reject=login_mode == "rejected")
    env = _v4_environment(tmp_path / "oauth")
    env[RUNTIME_PROFILE_ENV] = "v4-controlled"
    app = create_http_app(HttpServerSettings.from_environment(env), v4_local_user_reset_candidate_action=h.action)
    scope = "fortipam:read fortipam:plan" + (" fortipam:operate" if operate else "")
    with TestClient(app, base_url="https://mcp.example.com") as client:
        client_id = _register_public_client(client, scope)
        code, verifier = _authorize_and_login(client, client_id, scope)
        token = client.post("/fpamcp/oauth/token", data={"grant_type": "authorization_code",
            "client_id": client_id, "code": code, "code_verifier": verifier,
            "redirect_uri": "https://client.example/callback", "resource": "https://mcp.example.com/fpamcp"})
        assert token.status_code == 200
        headers = _request_headers(token.json()["access_token"])
        headers["host"] = "mcp.example.com"

        def request(method, params, request_headers=None):
            response = client.post("/fpamcp", headers=request_headers or headers,
                json={"jsonrpc": "2.0", "id": "request", "method": method, "params": params})
            assert response.status_code == 200
            return response.json()["result"]

        def call(name, arguments, request_headers=None):
            return request("tools/call", {"name": name, "arguments": arguments}, request_headers)

        schemas = {t["name"]: t["inputSchema"] for t in request("tools/list", {})["tools"]}
        assert schemas["preview_v4_bound_local_user_reset"]["properties"] == {}
        assert set(schemas["confirm_v4_bound_local_user_reset"]["properties"]) == {"preview_ref"}
        assert set(schemas["execute_confirmed_v4_bound_local_user_reset"]["properties"]) == {"authorization_ref"}
        assert all(schemas[name]["additionalProperties"] is False for name in (
            "preview_v4_bound_local_user_reset", "confirm_v4_bound_local_user_reset",
            "execute_confirmed_v4_bound_local_user_reset"))
        invalid = call("preview_v4_bound_local_user_reset", {"username": "synthetic-caller-target"})
        assert invalid["isError"] and not h.sessions
        preview = call("preview_v4_bound_local_user_reset", {})
        assert not preview["isError"]
        summary = preview["structuredContent"]
        assert summary["contract"] == CONTRACT and summary["can_confirm"]
        assert summary["Current State"]["status"] == "enable"
        assert summary["Current State"]["access_profile"] == "Guest"
        assert h.source._binding.expected.username not in json.dumps(preview)
        assert "synthetic-token" not in json.dumps(preview)
        confirmed = call("confirm_v4_bound_local_user_reset", {"preview_ref": summary["preview_ref"]})
        if not operate:
            assert confirmed["isError"] and h.writes == 0 and h.store.claim_count == 0
            assert call("execute_confirmed_v4_bound_local_user_reset", {"authorization_ref": "invalid"})["isError"]
            return
        assert not confirmed["isError"]
        arguments = {"authorization_ref": confirmed["structuredContent"]["authorization_ref"]}
        planning_scope = "fortipam:read fortipam:plan"
        planning_client = _register_public_client(client, planning_scope)
        planning_code, planning_verifier = _authorize_and_login(client, planning_client, planning_scope)
        planning_token = client.post("/fpamcp/oauth/token", data={"grant_type": "authorization_code",
            "client_id": planning_client, "code": planning_code, "code_verifier": planning_verifier,
            "redirect_uri": "https://client.example/callback", "resource": "https://mcp.example.com/fpamcp"})
        assert planning_token.status_code == 200
        planning_headers = _request_headers(planning_token.json()["access_token"])
        planning_headers["host"] = "mcp.example.com"
        other_preview = call("preview_v4_bound_local_user_reset", {}, planning_headers)
        assert not other_preview["isError"]
        other_ref = other_preview["structuredContent"]["preview_ref"]
        assert other_ref != summary["preview_ref"]
        assert call("confirm_v4_bound_local_user_reset", {"preview_ref": other_ref}, planning_headers)["isError"]
        assert call("execute_confirmed_v4_bound_local_user_reset", arguments, planning_headers)["isError"]
        result = call("execute_confirmed_v4_bound_local_user_reset", arguments)
        assert not result["isError"]
        outcome = result["structuredContent"]
        assert outcome["outcome"] == ("reconciliation_required" if login_mode == "rejected" else "succeeded")
        assert outcome["password_write_acknowledged"] and not outcome["credential_values_returned"]
        assert outcome["password_change_confirmed"] is (login_mode == "verified")
        assert outcome["login_verified"] is (login_mode == "verified")
        if login is not None:
            assert outcome["write_outcome"] == "succeeded"
            assert outcome["login_acceptance_reason"] == ("verified" if login_mode == "verified" else "login_failed")
            assert outcome["current_binding_updated"] is (login_mode == "verified")
            assert login.calls.count(("POST", "/XX/YY/ZZ/AUTH")) == 1
            stored = json.loads((h.source._reset / "result.json").read_bytes())
            assert stored["outcome"] == "succeeded" and not stored["login_verified"]
            completion = json.loads((h.source._reset / "login-finalization.json").read_bytes())
            assert completion["login_verified"] is (login_mode == "verified")
        replay = call("execute_confirmed_v4_bound_local_user_reset", arguments)
        assert replay["structuredContent"] == {**outcome, "idempotent_replay": True}
        if login is not None:
            assert login.calls.count(("POST", "/XX/YY/ZZ/AUTH")) == 1
        assert h.writes == 1 and h.calls == [_POLICY_PATH]
        assert h.store.claim_count == 1 and len(h.store.audit_events) == 1
        assert (h.source._reset / "dispatch-invocation").is_file()
        assert (h.source._fixture / "current-login-transition.json").is_file() is (login_mode != "verified")
        assert outcome["current_login_reconciliation_required"] is (login_mode != "verified")
        assert not call("preview_v4_bound_local_user_reset", {})["structuredContent"]["can_confirm"]
        restarted = LocalUserResetCandidateMcpAction(h.action._candidate,
            PersistentM4ExecutionStateStore(h.store._path, h.store._key_path), h.action._policy_reader)
        assert restarted.preview(h.principal)["gaps"] == ["execution_reserved_or_consumed"]
        with pytest.raises(LocalUserResetCandidateMcpError):
            restarted.execute(arguments["authorization_ref"], h.principal)
        assert h.writes == 1
