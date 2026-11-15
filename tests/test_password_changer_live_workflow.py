from __future__ import annotations

from pathlib import Path
import json
import os
import stat

import pytest

from fortipam_mcp.password_changer_http_transport import (
    FortiPamUnixPasswordChangerHttpTransport,
    PasswordChangerInspection,
    PasswordChangerReadback,
)
from fortipam_mcp.password_changer_live_workflow import (
    PasswordChangerCreateLiveWorkflow,
    PasswordChangerLiveWorkflowError,
)
from fortipam_mcp.password_changer_mcp_action import (
    BINDING_CONTRACT, PREFIX, PasswordChangerMcpAction, _load_binding,
    build_password_changer_candidate,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig


REQUESTER = "a" * 64


def _workflow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[
    PasswordChangerCreateLiveWorkflow, list[PasswordChangerInspection], list[PasswordChangerInspection],
]:
    transport = FortiPamUnixPasswordChangerHttpTransport(
        SecretMetadataHttpTransportConfig("https://fpa.example.test", "synthetic", 10, None),
        "mcp-v4-bp013-unix-changer-test01",
    )
    current = [PasswordChangerInspection("b" * 64, False)]
    writes: list[PasswordChangerInspection] = []
    monkeypatch.setattr(transport, "inspect", lambda: current[0])

    def write(expected: PasswordChangerInspection) -> PasswordChangerReadback:
        writes.append(expected)
        return PasswordChangerReadback(True, True, True, False)

    monkeypatch.setattr(transport, "create_and_readback", write)
    return PasswordChangerCreateLiveWorkflow(transport, tmp_path / "claim"), current, writes


def test_one_shot_preview_confirm_execute_and_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow, _, writes = _workflow(tmp_path, monkeypatch)
    preview = workflow.preview(requester_digest=REQUESTER)
    assert preview["Proposed Changes"]["template_or_secret_association"] is False
    authorization = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    first = workflow.execute(authorization["authorization_ref"], requester_digest=REQUESTER)
    replay = workflow.execute(authorization["authorization_ref"], requester_digest=REQUESTER)

    assert first["outcome"] == "succeeded"
    assert first["independent_ui_reference_check_required"] is True
    assert replay["idempotent_replay"] is True
    assert len(writes) == 1
    assert (tmp_path / "claim").is_file()
    with pytest.raises(PasswordChangerLiveWorkflowError):
        workflow.preview(requester_digest=REQUESTER)


def test_source_drift_prevents_claim_and_post(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow, current, writes = _workflow(tmp_path, monkeypatch)
    preview = workflow.preview(requester_digest=REQUESTER)
    authorization = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    current[0] = PasswordChangerInspection("c" * 64, False)
    with pytest.raises(PasswordChangerLiveWorkflowError):
        workflow.execute(authorization["authorization_ref"], requester_digest=REQUESTER)
    assert writes == []
    assert not (tmp_path / "claim").exists()


def test_ambiguous_post_consumes_claim_across_workflow_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow, _, writes = _workflow(tmp_path, monkeypatch)
    preview = workflow.preview(requester_digest=REQUESTER)
    authorization = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)

    def ambiguous(_: PasswordChangerInspection) -> PasswordChangerReadback:
        writes.append(PasswordChangerInspection("b" * 64, False))
        raise TimeoutError("synthetic ambiguous POST")

    monkeypatch.setattr(workflow._transport, "create_and_readback", ambiguous)
    result = workflow.execute(authorization["authorization_ref"], requester_digest=REQUESTER)
    assert result["outcome"] == "reconciliation_required"
    restarted = PasswordChangerCreateLiveWorkflow(workflow._transport, tmp_path / "claim")
    with pytest.raises(PasswordChangerLiveWorkflowError):
        restarted.preview(requester_digest=REQUESTER)
    assert len(writes) == 1


def test_directory_sync_failure_retains_claim_and_prevents_post(tmp_path, monkeypatch):
    workflow, _, writes = _workflow(tmp_path, monkeypatch)
    preview = workflow.preview(requester_digest=REQUESTER)
    auth = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    synced = []
    original = os.fsync

    def sync(fd):
        directory = stat.S_ISDIR(os.fstat(fd).st_mode)
        synced.append(directory)
        if directory:
            raise OSError("synthetic directory sync failure")
        original(fd)

    monkeypatch.setattr(os, "fsync", sync)
    with pytest.raises(PasswordChangerLiveWorkflowError):
        workflow.execute(auth["authorization_ref"], requester_digest=REQUESTER)
    assert synced == [False, True] and writes == []
    claim = tmp_path / "claim"
    assert claim.exists() and stat.S_IMODE(claim.stat().st_mode) == 0o600
    restarted = PasswordChangerCreateLiveWorkflow(workflow._transport, claim)
    monkeypatch.setattr(workflow._transport, "inspect", lambda: pytest.fail("consumed claim must precede reads"))
    with pytest.raises(PasswordChangerLiveWorkflowError):
        restarted.preview(requester_digest=REQUESTER)


def test_dangling_claim_symlink_refuses_before_source_read(tmp_path, monkeypatch):
    workflow, _, writes = _workflow(tmp_path, monkeypatch)
    (tmp_path / "claim").symlink_to(tmp_path / "absent")
    monkeypatch.setattr(workflow._transport, "inspect", lambda: pytest.fail("claim symlink must precede reads"))
    with pytest.raises(PasswordChangerLiveWorkflowError):
        workflow.preview(requester_digest=REQUESTER)
    assert writes == []


def test_candidate_defaults_off_and_execute_gate_stays_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert build_password_changer_candidate({}) is None
    with pytest.raises(ValueError):
        build_password_changer_candidate({PREFIX + "EXECUTION_ENABLED": "true"})
    workflow, _, writes = _workflow(tmp_path, monkeypatch)
    action = PasswordChangerMcpAction(workflow, execution_enabled=False)
    with pytest.raises(RuntimeError):
        action.execute("password-changer-authorized-synthetic", object())
    assert writes == []


def test_binding_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "binding.json"
    path.write_text(json.dumps({
        "contract": BINDING_CONTRACT,
        "target_name": "mcp-v4-bp013-unix-changer-test01",
    }))
    path.chmod(0o600)
    assert _load_binding(path) == "mcp-v4-bp013-unix-changer-test01"
    path.chmod(0o644)
    with pytest.raises(ValueError):
        _load_binding(path)


@pytest.mark.parametrize("operate,gate", [(False, True), (True, False), (True, True)])
def test_oauth_mcp_candidate_requires_operation_scope_and_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operate: bool, gate: bool,
) -> None:
    from starlette.testclient import TestClient
    from fortipam_mcp.http_server import HttpServerSettings, create_http_app
    from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
    from test_http_server import (
        _v4_environment, _register_public_client, _authorize_and_login, _request_headers,
    )

    environment = _v4_environment(tmp_path / "oauth")
    environment[RUNTIME_PROFILE_ENV] = "v4-controlled"
    workflow, _, writes = _workflow(tmp_path, monkeypatch)
    action = PasswordChangerMcpAction(workflow, execution_enabled=gate)
    app = create_http_app(
        HttpServerSettings.from_environment(environment),
        v4_password_changer_candidate_action=action,
    )
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

        def call(name: str, arguments: dict[str, object]) -> dict[str, object]:
            response = client.post("/fpamcp", headers=headers, json={
                "jsonrpc": "2.0", "id": name, "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            })
            assert response.status_code == 200
            return response.json()["result"]

        preview = call("preview_v4_password_changer_create_700", {})
        assert not preview["isError"]
        assert "synthetic step" not in json.dumps(preview)
        confirmation = call("confirm_v4_password_changer_create_700", {
            "preview_ref": preview["structuredContent"]["preview_ref"],
        })
        if not operate:
            assert confirmation["isError"] and not writes
            return
        assert not confirmation["isError"]
        args = {"authorization_ref": confirmation["structuredContent"]["authorization_ref"]}
        result = call("execute_confirmed_v4_password_changer_create_700", args)
        if not gate:
            assert result["isError"] and not writes
            return
        assert result["structuredContent"]["outcome"] == "succeeded"
        replay = call("execute_confirmed_v4_password_changer_create_700", args)
        assert replay["structuredContent"]["idempotent_replay"]
        assert len(writes) == 1
