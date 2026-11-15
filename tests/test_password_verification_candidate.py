"""Behavior coverage for the bounded build-29 verification candidate."""

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
import sqlite3
from types import SimpleNamespace

import pytest

import fortipam_mcp.password_verification_http_transport as transport_module
from fortipam_mcp.password_verification_http_transport import (
    FortiPamPasswordVerificationHttpTransport,
    PasswordVerificationBinding,
    PasswordVerificationHttpTransportError,
    PasswordVerificationReadback,
    PasswordVerificationState,
)
from fortipam_mcp.password_verification_live_workflow import (
    PasswordVerificationLiveWorkflow,
    PasswordVerificationLiveWorkflowError,
)
from fortipam_mcp.password_verification_mcp_action import (
    BINDING_CONTRACT, PREFIX, PasswordVerificationMcpAction,
    _load_binding, build_password_verification_candidate,
)
from test_secret_session_controls_http_transport import _Connection, _Response, _config


BINDING = PasswordVerificationBinding(
    "Public/test", "unix-verification-fixture", "test-target", "192.0.2.10", "test-user",
)
CURRENT = PasswordVerificationState(23, 17, False, True, 60, False, True, True, True, True)
REQUESTER = "b" * 64


class WorkflowTransport(FortiPamPasswordVerificationHttpTransport):
    def __init__(self, failure=None):
        self.state = CURRENT
        self.failure = failure
        self.writes = 0

    def inspect(self):
        return self.state

    def enable_and_readback(self, expected):
        assert expected == CURRENT
        self.writes += 1
        if self.failure == "ambiguous":
            raise TimeoutError("synthetic protected response")
        self.state = replace(CURRENT, enabled=True, start_time_present=True)
        return PasswordVerificationReadback(True, self.failure != "readback", 1000)


def workflow_factory(tmp_path, transport):
    tmp_path.chmod(0o700)
    key = tmp_path / "key"
    key.write_bytes(b"a" * 32)
    key.chmod(0o600)
    return lambda: PasswordVerificationLiveWorkflow(
        tmp_path / "state.sqlite3", key, transport, BINDING, clock=lambda: 1000,
    )


@pytest.mark.parametrize("failure", [None, "ambiguous", "readback"])
def test_workflow_preserves_one_dispatch_across_restart_and_multiple_previews(tmp_path, failure):
    transport = WorkflowTransport(failure)
    factory = workflow_factory(tmp_path, transport)
    previews = [factory().preview(requester_digest=REQUESTER) for _ in range(2)]
    assert BINDING.secret_name not in json.dumps(previews)
    refs = [factory().confirm(p["preview_ref"], requester_digest=REQUESTER)["authorization_ref"]
            for p in previews]
    result = factory().execute(refs[0], requester_digest=REQUESTER)
    assert result["outcome"] == ("succeeded" if failure is None else "reconciliation_required")
    assert factory().execute(refs[0], requester_digest=REQUESTER)["idempotent_replay"]
    with pytest.raises(PasswordVerificationLiveWorkflowError):
        factory().execute(refs[1], requester_digest=REQUESTER)
    transport.state = CURRENT
    with pytest.raises(PasswordVerificationLiveWorkflowError):
        factory().preview(requester_digest=REQUESTER)
    assert transport.writes == 1


def test_drift_and_requester_mismatch_prevent_a_write(tmp_path):
    transport = WorkflowTransport()
    factory = workflow_factory(tmp_path, transport)
    preview = factory().preview(requester_digest=REQUESTER)
    with pytest.raises(PasswordVerificationLiveWorkflowError):
        factory().confirm(preview["preview_ref"], requester_digest="c" * 64)
    confirmed = factory().confirm(preview["preview_ref"], requester_digest=REQUESTER)
    transport.state = replace(CURRENT, secret_id=24)
    result = factory().execute(confirmed["authorization_ref"], requester_digest=REQUESTER)
    assert result["outcome"] == "not_executed"
    assert not result["device_write_may_have_occurred"]
    assert transport.writes == 0


@pytest.mark.parametrize("path", ["preview", "dispatch"])
def test_tampering_with_terminal_state_cannot_reopen_a_consumed_binding(tmp_path, path):
    transport = WorkflowTransport()
    factory = workflow_factory(tmp_path, transport)
    preview = factory().preview(requester_digest=REQUESTER)
    confirmed = factory().confirm(preview["preview_ref"], requester_digest=REQUESTER)
    another = factory().preview(requester_digest=REQUESTER)
    pending = factory().confirm(another["preview_ref"], requester_digest=REQUESTER)
    factory().execute(confirmed["authorization_ref"], requester_digest=REQUESTER)
    with sqlite3.connect(tmp_path / "state.sqlite3") as connection:
        connection.execute(
            "UPDATE password_verification_workflow SET state='previewed' WHERE preview_ref=?",
            (preview["preview_ref"],),
        )
    transport.state = CURRENT
    with pytest.raises(PasswordVerificationLiveWorkflowError):
        if path == "preview":
            factory().preview(requester_digest=REQUESTER)
        else:
            factory().execute(pending["authorization_ref"], requester_digest=REQUESTER)
    assert transport.writes == 1


def raw_detail():
    return {
        "id": 23, "name": BINDING.secret_name, "folder": 17,
        "template": "Unix Account (SSH Password)", "target": BINDING.target_name,
        "password-heartbeat": "disable", "heartbeat-use-policy-default": "enable",
        "heartbeat-interval": 60, "heartbeat-start-time": "",
        "inherit-permission": "enable", "ssh-service-status": "up",
        "sftp-service-status": "up", "recording": "enable",
        "field": [
            {"id": 1, "name": "Host", "value": BINDING.target_address},
            {"id": 2, "name": "Username", "value": BINDING.account_name, "keyinfo": ""},
            {"id": 3, "name": "Password", "value": "synthetic-password", "keyinfo": ""},
        ],
    }


@pytest.mark.parametrize("changed", [None, "target", "recording", "normalized_time"])
def test_transport_reuses_protected_fields_once_and_checks_normalized_readback(monkeypatch, caplog, changed):
    calls = []
    raw = raw_detail()
    if changed in {"target", "recording"}:
        raw[changed] = "changed"
    moment = datetime(2026, 9, 29, 10, 0, tzinfo=timezone.utc)
    epoch = int((moment + timedelta(minutes=5)).timestamp())
    responses = iter([_Response(200, {"results": [raw]}), _Response(200, {"status": "success"})])
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamPasswordVerificationHttpTransport(
        _config(), BINDING, connection_factory=lambda *_a, **_k: _Connection(next(responses), calls),
        clock=lambda: moment,
    )
    monkeypatch.setattr(transport, "inspect", lambda: (
        replace(CURRENT, enabled=True, start_time_present=True)
        if any(c["method"] == "PUT" for c in calls) else CURRENT
    ))
    transport._metadata = SimpleNamespace(
        resolve_existing_secret_id=lambda *_: 23, resolve_folder_id=lambda *_: 17,
        _request_projection_detail=lambda *_: (
            200, {"results": [{"heartbeat-start-time": epoch + int(changed == "normalized_time")}]}, True,
        ),
    )
    if changed in {"target", "recording"}:
        with pytest.raises(PasswordVerificationHttpTransportError):
            transport.enable_and_readback(CURRENT)
        assert [c["method"] for c in calls] == ["GET"]
        return
    result = transport.enable_and_readback(CURRENT)
    assert result.accepted and result.verified == (changed is None)
    assert [c["method"] for c in calls] == ["GET", "PUT"]
    body = json.loads(calls[-1]["body"])
    assert body["field"] == raw["field"][1:]
    assert body["heartbeat-start-time"] == "2026-09-29 18:05:00"
    assert "synthetic-password" not in repr(result) + caplog.text


def test_private_binding_and_default_off_gate(tmp_path):
    assert build_password_verification_candidate({}) is None
    with pytest.raises(ValueError):
        build_password_verification_candidate({PREFIX + "EXECUTION_ENABLED": "true"})
    path = tmp_path / "binding.json"
    data = {"contract": BINDING_CONTRACT, **asdict(BINDING)}
    path.write_text(json.dumps(data)); path.chmod(0o600)
    assert _load_binding(path) == BINDING
    path.chmod(0o644)
    with pytest.raises(ValueError):
        _load_binding(path)


@pytest.mark.parametrize("operate,gate", [(False, True), (True, False), (True, True)])
def test_http_oauth_authorizes_one_private_bound_mcp_write(tmp_path, operate, gate):
    from starlette.testclient import TestClient
    from fortipam_mcp.http_server import HttpServerSettings, create_http_app
    from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
    from test_http_server import _v4_environment, _register_public_client, _authorize_and_login, _request_headers

    environment = _v4_environment(tmp_path / "oauth")
    environment[RUNTIME_PROFILE_ENV] = "v4-controlled"
    transport = WorkflowTransport()
    action = PasswordVerificationMcpAction(workflow_factory(tmp_path, transport)(), execution_enabled=gate)
    app = create_http_app(HttpServerSettings.from_environment(environment),
                          v4_password_verification_candidate_action=action)
    scope = "fortipam:read fortipam:plan" + (" fortipam:operate" if operate else "")
    with TestClient(app, base_url="https://mcp.example.com") as client:
        client_id = _register_public_client(client, scope)
        code, verifier = _authorize_and_login(client, client_id, scope)
        token = client.post("/fpamcp/oauth/token", data={
            "grant_type": "authorization_code", "client_id": client_id, "code": code,
            "code_verifier": verifier, "redirect_uri": "https://client.example/callback",
            "resource": "https://mcp.example.com/fpamcp",
        })
        assert token.status_code == 200
        headers = _request_headers(token.json()["access_token"])
        headers["host"] = "mcp.example.com"

        def call(name, arguments):
            response = client.post("/fpamcp", headers=headers, json={
                "jsonrpc": "2.0", "id": name, "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            })
            assert response.status_code == 200
            return response.json()["result"]

        preview = call("preview_v4_password_verification_700", {})
        assert not preview["isError"]
        assert BINDING.secret_name not in json.dumps(preview)
        confirmation = call("confirm_v4_password_verification_700", {
            "preview_ref": preview["structuredContent"]["preview_ref"],
        })
        if not operate:
            assert confirmation["isError"] and transport.writes == 0
            return
        assert not confirmation["isError"]
        args = {"authorization_ref": confirmation["structuredContent"]["authorization_ref"]}
        result = call("execute_confirmed_v4_password_verification_700", args)
        if not gate:
            assert result["isError"] and transport.writes == 0
            return
        assert not result["isError"] and result["structuredContent"]["outcome"] == "succeeded"
        assert call("execute_confirmed_v4_password_verification_700", args)["structuredContent"]["idempotent_replay"]
        assert transport.writes == 1
