"""Durable one-dispatch recovery workflow behavior."""

from __future__ import annotations

from pathlib import Path
import json

import pytest

from fortipam_mcp.password_changer_delete_http_transport import (
    FortiPamUnixPasswordChangerDeleteHttpTransport,
    PasswordChangerDeleteInspection,
    PasswordChangerDeleteReadback,
)
from fortipam_mcp.password_changer_delete_live_workflow import (
    PasswordChangerDeleteLiveWorkflow,
    PasswordChangerDeleteLiveWorkflowError,
)
from fortipam_mcp.password_changer_delete_mcp_action import (
    PREFIX, PasswordChangerDeleteMcpAction, build_password_changer_delete_candidate,
)
from fortipam_mcp.password_changer_mcp_action import BINDING_CONTRACT


REQUESTER = "a" * 64


def _workflow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    state = {"digest": "b" * 64, "calls": 0, "references_zero": True}
    transport = object.__new__(FortiPamUnixPasswordChangerDeleteHttpTransport)

    def inspect() -> PasswordChangerDeleteInspection:
        return PasswordChangerDeleteInspection(
            True, True, state["references_zero"], state["digest"], "c" * 64,
        )

    def delete(_expected: PasswordChangerDeleteInspection) -> PasswordChangerDeleteReadback:
        state["calls"] += 1
        return PasswordChangerDeleteReadback(True, True, True, True, True)

    monkeypatch.setattr(transport, "inspect", inspect)
    monkeypatch.setattr(transport, "delete_and_readback", delete)
    parent = tmp_path / "state"
    parent.mkdir(mode=0o700)
    return PasswordChangerDeleteLiveWorkflow(transport, parent / "claim.json"), state


def test_confirmed_recovery_consumes_once_and_replay_is_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow, state = _workflow(tmp_path, monkeypatch)
    preview = workflow.preview(requester_digest=REQUESTER)
    assert preview["Current State"]["template_secret_target_references_known_zero"] is True
    authorization = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    result = workflow.execute(authorization["authorization_ref"], requester_digest=REQUESTER)
    assert result["outcome"] == "succeeded"
    assert result["raw_api_or_cli_returned"] is False
    assert state["calls"] == 1
    assert workflow.execute(authorization["authorization_ref"], requester_digest=REQUESTER)["idempotent_replay"] is True
    assert state["calls"] == 1
    assert (tmp_path / "state/claim.json").stat().st_mode & 0o777 == 0o600


def test_reference_or_digest_drift_blocks_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow, state = _workflow(tmp_path, monkeypatch)
    preview = workflow.preview(requester_digest=REQUESTER)
    authorization = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    state["references_zero"] = False
    with pytest.raises(PasswordChangerDeleteLiveWorkflowError):
        workflow.execute(authorization["authorization_ref"], requester_digest=REQUESTER)
    assert state["calls"] == 0
    assert not (tmp_path / "state/claim.json").exists()


def test_candidate_defaults_off_and_final_gate_stays_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert build_password_changer_delete_candidate({}) is None
    with pytest.raises(ValueError):
        build_password_changer_delete_candidate({PREFIX + "EXECUTION_ENABLED": "true"})
    workflow, state = _workflow(tmp_path, monkeypatch)
    action = PasswordChangerDeleteMcpAction(workflow, execution_enabled=False)
    with pytest.raises(RuntimeError):
        action.execute("password-changer-delete-authorized-synthetic", object())
    assert state["calls"] == 0


def test_candidate_loads_existing_bound_api_and_template_ssh_settings(
    tmp_path: Path,
) -> None:
    binding = tmp_path / "binding.json"
    binding.write_text(json.dumps({
        "contract": BINDING_CONTRACT,
        "target_name": "mcp-v4-bp013-unix-changer-test-delete",
    }))
    binding.chmod(0o600)
    password_file = tmp_path / "ssh-password"
    password_file.write_text("synthetic-password")
    password_file.chmod(0o600)
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("synthetic-host-key")
    known_hosts.chmod(0o600)
    environment = {
        PREFIX + "ENABLED": "true",
        PREFIX + "EXECUTION_ENABLED": "false",
        PREFIX + "BINDING_FILE": str(binding),
        PREFIX + "CLAIM_FILE": str(tmp_path / "claim.json"),
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_BASE_URL": "https://fpa.example.test",
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_API_TOKEN": "synthetic-token",
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_SSH_HOST": "fpa.example.test",
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_SSH_USERNAME": "synthetic-user",
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_SSH_PASSWORD_FILE": str(password_file),
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }
    action = build_password_changer_delete_candidate(environment)
    assert isinstance(action, PasswordChangerDeleteMcpAction)
    assert action._execution_enabled is False


@pytest.mark.parametrize("operate,gate", [(False, True), (True, False), (True, True)])
def test_oauth_mcp_recovery_requires_operation_scope_and_gate(
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
    workflow, state = _workflow(tmp_path, monkeypatch)
    action = PasswordChangerDeleteMcpAction(workflow, execution_enabled=gate)
    app = create_http_app(
        HttpServerSettings.from_environment(environment),
        v4_password_changer_delete_candidate_action=action,
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

        preview = call("preview_v4_password_changer_delete_700", {})
        assert not preview["isError"]
        assert "synthetic step" not in json.dumps(preview)
        confirmation = call("confirm_v4_password_changer_delete_700", {
            "preview_ref": preview["structuredContent"]["preview_ref"],
        })
        if not operate:
            assert confirmation["isError"] and state["calls"] == 0
            return
        assert not confirmation["isError"]
        args = {"authorization_ref": confirmation["structuredContent"]["authorization_ref"]}
        result = call("execute_confirmed_v4_password_changer_delete_700", args)
        if not gate:
            assert result["isError"] and state["calls"] == 0
            return
        assert result["structuredContent"]["outcome"] == "succeeded"
        replay = call("execute_confirmed_v4_password_changer_delete_700", args)
        assert replay["structuredContent"]["idempotent_replay"]
        assert state["calls"] == 1
