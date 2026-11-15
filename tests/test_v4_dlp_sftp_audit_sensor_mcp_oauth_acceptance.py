"""Canonical OAuth client over the real fixed workflows and synthetic transports."""
from __future__ import annotations

import asyncio
from pathlib import Path
import json
import stat
from types import SimpleNamespace
from typing import Any, Callable

import pytest

from scripts import v4_dlp_sftp_audit_sensor_mcp_oauth_acceptance as acceptance
from fortipam_mcp.dlp_sftp_audit_sensor_live_workflow import DlpSftpAuditSensorLiveWorkflow
from fortipam_mcp.dlp_sftp_audit_sensor_delete_live_workflow import DlpSftpAuditSensorDeleteLiveWorkflow
from fortipam_mcp.dlp_sftp_audit_sensor_http_transport import (
    DlpSftpAuditSensorInspection, DlpSftpAuditSensorReadback,
    DlpSftpAuditSensorDeleteInspection, DlpSftpAuditSensorDeleteReadback,
)

NAME = "mcp-v4-dlp-sftp-audit-test"
REQUESTER = "a" * 64


class Transport:
    """Finite in-memory create/recovery lifetime, without HTTP or credentials."""
    def __init__(self) -> None:
        self.exists = False
        self.posts = self.deletes = 0

    def inspect_sftp_sensor(self, sensor_name: str) -> DlpSftpAuditSensorInspection:
        assert sensor_name == NAME
        return DlpSftpAuditSensorInspection(self.exists, "b" * 64)

    def create_sftp_and_readback(
        self, sensor_name: str, *, expires_at: int, clock: Callable[[], int],
    ) -> DlpSftpAuditSensorReadback:
        assert sensor_name == NAME and expires_at > clock()
        self.posts += 1
        self.exists = True
        return DlpSftpAuditSensorReadback(*([True] * 9))

    def inspect_owned_sftp_delete_target(self) -> DlpSftpAuditSensorDeleteInspection:
        assert self.exists
        return DlpSftpAuditSensorDeleteInspection(True, True, 0, 0, "c" * 64,
                                                 "d" * 64, 64, 5, "e" * 64)

    def delete_owned_sftp_and_readback(
        self, *, expected_target_digest: str, expected_state_digest: str,
        expires_at: int, clock: Callable[[], int],
    ) -> DlpSftpAuditSensorDeleteReadback:
        assert expected_target_digest == "c" * 64 and len(expected_state_digest) == 64
        assert expires_at > clock()
        self.deletes += 1
        self.exists = False
        return DlpSftpAuditSensorDeleteReadback(True, True)


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> SimpleNamespace:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    transport = Transport()
    workflows = {"create": DlpSftpAuditSensorLiveWorkflow(transport, clock=lambda: 100),
                 "delete": DlpSftpAuditSensorDeleteLiveWorkflow(transport, clock=lambda: 100)}
    calls: list[tuple[str, dict[str, object]]] = []
    h = SimpleNamespace(transport=transport, workflows=workflows, calls=calls,
        state=state, transform=None, common_transform=None, omitted_tool=None)

    class Session:
        async def list_tools(self) -> SimpleNamespace:
            tools = acceptance._tools("create") | acceptance._tools("delete")
            return SimpleNamespace(tools=[SimpleNamespace(name=name) for name in tools if name != h.omitted_tool])

        async def call_tool(self, name: str, arguments: dict[str, object]) -> SimpleNamespace:
            calls.append((name, arguments))
            operation = "delete" if name.endswith("delete") else "create"
            workflow = workflows[operation]
            if name.startswith("preview"):
                assert arguments["configuration_profile"] == "web_sftp_regexp_log_only"
                if operation == "create":
                    assert set(arguments) == {"configuration_profile", "sensor_name"}
                    result = workflow.preview(sensor_name=arguments["sensor_name"], requester_digest=REQUESTER)
                else:
                    assert set(arguments) == {"configuration_profile"}
                    result = workflow.preview(requester_digest=REQUESTER)
            elif name.startswith("confirm"):
                assert set(arguments) == {"preview_ref"}
                result = workflow.confirm(arguments["preview_ref"], requester_digest=REQUESTER)
            else:
                assert set(arguments) == {"authorization_ref"}
                result = workflow.execute(arguments["authorization_ref"], requester_digest=REQUESTER)
            if h.transform is not None:
                h.transform(name, result)
            return SimpleNamespace(is_error=False, structured_content=result)

    async def common(*args: Any, **kwargs: Any) -> dict[str, object]:
        assert kwargs["ca_file"] == tmp_path / "ca.pem"
        assert kwargs["lab_connect_host"] == "127.0.0.1" and kwargs["lab_connect_port"] == 28443
        assert kwargs["allow_loopback_tunnel"] is True
        assert kwargs["required_tools"] in (acceptance._tools("create"), acceptance._tools("delete"))
        await kwargs["tool_session_callback"](Session())
        result: dict[str, object] = {"oauth_metadata_verified": True, "mcp_initialized": True,
                  "token_revoked": True, "credential_values_returned": False}
        if h.common_transform:
            h.common_transform(result)
        return result

    monkeypatch.setattr(acceptance.oauth, "run_address_mcp_oauth_surface_acceptance", common)
    return h


def _run(h: SimpleNamespace, tmp_path: Path, operation: str, *, execute: bool = False,
         discover: bool = False) -> dict[str, object]:
    kwargs: dict[str, Any] = {"ca_file": tmp_path / "ca.pem", "lab_connect_host": "127.0.0.1",
                             "lab_connect_port": 28443, "allow_loopback_tunnel": True}
    path = h.state / f"{operation}.json"
    if not discover:
        kwargs["execute_preview_state_file" if execute else "preview_state_file"] = path
        if operation == "create" and not execute:
            kwargs["preview_sensor_name"] = NAME
    run = (acceptance.run_dlp_sftp_audit_sensor_mcp_oauth_acceptance if operation == "create"
           else acceptance.run_dlp_sftp_audit_sensor_delete_mcp_oauth_acceptance)
    return asyncio.run(run("https://fpamcp.example.test/fpamcp-v4", tmp_path / "login.env",
                          tmp_path / "client.json", **kwargs))


def test_canonical_create_then_same_creator_owned_recovery(harness: SimpleNamespace, tmp_path: Path) -> None:
    for operation in ("create", "delete"):
        preview = _run(harness, tmp_path, operation)
        path = harness.state / f"{operation}.json"
        stored = json.loads(path.read_text())
        assert set(stored) == {"contract", "operation", "preview_ref"}
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert preview["device_write_executed"] is False
        result = _run(harness, tmp_path, operation, execute=True)
        assert result["execution_verified"] is result["token_revoked"] is True
        assert not path.exists()
        claim = path.with_name(path.name + ".dispatch.json")
        assert stat.S_IMODE(claim.stat().st_mode) == 0o600
        assert json.loads(claim.read_text())["retry_allowed"] is False
        public = json.dumps(result) + claim.read_text()
        assert NAME not in public and "authorized-" not in public and "preview-" not in public
    assert harness.transport.posts == harness.transport.deletes == 1
    assert not harness.transport.exists
    assert [name for name, _ in harness.calls] == [
        "preview_v4_dlp_sensor_create", "confirm_v4_dlp_sensor_create", "execute_confirmed_v4_dlp_sensor_create",
        "preview_v4_dlp_sensor_delete", "confirm_v4_dlp_sensor_delete", "execute_confirmed_v4_dlp_sensor_delete"]


@pytest.mark.parametrize("operation", ["create", "delete"])
def test_discovery_never_invokes_device_tools(harness: SimpleNamespace, tmp_path: Path, operation: str) -> None:
    result = _run(harness, tmp_path, operation, discover=True)
    assert not harness.calls and not list(harness.state.iterdir())
    assert result["device_tool_invoked"] is result["device_write_executed"] is False


@pytest.mark.parametrize("operation", ["create", "delete"])
def test_missing_tool_fails_before_preview(harness: SimpleNamespace, tmp_path: Path, operation: str) -> None:
    harness.omitted_tool = f"execute_confirmed_v4_dlp_sensor_{operation}"
    with pytest.raises(acceptance.DlpSftpAuditSensorMcpOAuthAcceptanceError, match="surface"):
        _run(harness, tmp_path, operation)
    assert not harness.calls


@pytest.mark.parametrize(("operation", "section", "field", "value"), [
    ("create", "Proposed Changes", "action", "block"),
    ("create", "Proposed Changes", "full_archive_protocols", ["http-get"]),
    ("create", "Proposed Changes", "filter_archive", "enable"),
    ("create", "Proposed Changes", "remaining_native_fields", "unknown"),
    ("create", "Proposed Changes", "filter_count", True),
    ("create", "Proposed Changes", "configuration_profile", "single_http_get_file_regexp_block_v1"),
    ("create", "Expected State", "native_defaults_match", False),
    ("create", "Expected State", "filter_count_matches", 1),
    ("create", "Current State", "sensor_name_exists", True),
    ("delete", "Current State", "verified_creation_ownership", False),
    ("delete", "Current State", "secret_reference_count", 1),
    ("delete", "Current State", "policy_reference_count", False),
    ("delete", "Current State", "dependency_source", "unqualified"),
    ("delete", "Expected State", "readback_transports", ["rest_api"]),
    ("delete", "Expected State", "owned_audit_sensor_absent", False),
    ("delete", "Current State", "private_native_id", 123),
])
def test_exact_cpe_rejects_unsafe_or_widened_profiles(
    harness: SimpleNamespace, tmp_path: Path, operation: str, section: str, field: str, value: object,
) -> None:
    harness.transport.exists = operation == "delete"
    harness.transform = lambda name, result: result[section].update({field: value})
    with pytest.raises(acceptance.DlpSftpAuditSensorMcpOAuthAcceptanceError, match="projection"):
        _run(harness, tmp_path, operation)
    assert not list(harness.state.iterdir())
    assert harness.transport.posts == harness.transport.deletes == 0


@pytest.mark.parametrize(("operation", "phase", "field", "value"), [
    ("create", "confirm", "authorization_ref", "dlp-regexp-sensor-authorized-other"),
    ("create", "confirm", "preview_ref", "dlp-sftp-audit-sensor-preview-other"),
    ("delete", "confirm", "authorization_ref", "dlp-sensor-delete-authorized-other"),
    ("create", "execute", "raw_api_returned", True),
    ("create", "execute", "idempotent_replay", True),
    ("create", "execute", "verification", "unknown"),
    ("delete", "execute", "raw_api_or_cli_response_returned", True),
    ("delete", "execute", "compensation", "separate_dlp_sensor_create_action_required"),
    ("delete", "execute", "private_native_id", 123),
])
def test_confirmation_and_readback_fail_closed_without_replay(
    harness: SimpleNamespace, tmp_path: Path, operation: str, phase: str, field: str, value: object,
) -> None:
    harness.transport.exists = operation == "delete"
    _run(harness, tmp_path, operation)
    def transform(name: str, result: dict[str, Any]) -> None:
        if name.startswith(phase):
            result[field] = value
    harness.transform = transform
    with pytest.raises(acceptance.DlpSftpAuditSensorMcpOAuthAcceptanceError):
        _run(harness, tmp_path, operation, execute=True)
    attempts = len(harness.calls)
    with pytest.raises(acceptance.DlpSftpAuditSensorMcpOAuthAcceptanceError):
        _run(harness, tmp_path, operation, execute=True)
    assert len(harness.calls) == attempts
    if phase == "confirm":
        assert harness.transport.posts == harness.transport.deletes == 0


@pytest.mark.parametrize("field", ["oauth_metadata_verified", "mcp_initialized", "token_revoked"])
def test_transport_requires_independent_acceptance_flags(
    harness: SimpleNamespace, tmp_path: Path, field: str,
) -> None:
    harness.common_transform = lambda result: result.update({field: False})
    with pytest.raises(acceptance.DlpSftpAuditSensorMcpOAuthAcceptanceError, match="transport acceptance"):
        _run(harness, tmp_path, "create", discover=True)


@pytest.mark.parametrize("defect", ["world_readable", "symlink", "widened", "other_operation", "other_profile"])
def test_proof_state_rejects_permissions_selectors_and_foreign_refs(
    harness: SimpleNamespace, tmp_path: Path, defect: str,
) -> None:
    _run(harness, tmp_path, "create")
    path = harness.state / "create.json"
    if defect == "world_readable":
        path.chmod(0o644)
    elif defect == "symlink":
        target = path.with_name("real.json")
        path.rename(target)
        path.symlink_to(target)
    else:
        stored = json.loads(path.read_text())
        if defect == "widened":
            stored["native_id"] = 123
        elif defect == "other_operation":
            stored["operation"] = "delete"
        else:
            stored["preview_ref"] = "dlp-regexp-sensor-preview-other"
        path.write_text(json.dumps(stored))
    with pytest.raises(acceptance.DlpSftpAuditSensorMcpOAuthAcceptanceError, match="state"):
        _run(harness, tmp_path, "create", execute=True)
    assert len(harness.calls) == 1 and harness.transport.posts == 0


@pytest.mark.parametrize("defect", ["incomplete", "combined", "wrong_name"])
def test_create_inputs_reject_expansion_before_oauth(tmp_path: Path, defect: str) -> None:
    kwargs: dict[str, Any] = {"preview_sensor_name": NAME}
    if defect == "combined":
        kwargs.update(preview_state_file=tmp_path / "preview.json", execute_preview_state_file=tmp_path / "execute.json")
    elif defect == "wrong_name":
        kwargs.update(preview_sensor_name="arbitrary-target", preview_state_file=tmp_path / "preview.json")
    with pytest.raises(acceptance.DlpSftpAuditSensorMcpOAuthAcceptanceError, match="inputs"):
        asyncio.run(acceptance.run_dlp_sftp_audit_sensor_mcp_oauth_acceptance(
            "https://fpamcp.example.test/fpamcp-v4", tmp_path / "login.env", tmp_path / "client.json", **kwargs))


def test_cli_recovery_has_no_target_selector(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import sys
    monkeypatch.setattr(sys, "argv", ["acceptance", "--url", "https://fpamcp.example.test/fpamcp-v4",
        "--login-file", str(tmp_path / "login.env"), "--client-state-file", str(tmp_path / "client.json"),
        "--operation", "delete", "--preview-sensor-name", NAME])
    with pytest.raises(SystemExit) as error:
        acceptance.main()
    assert error.value.code == 2


def test_cli_can_run_from_outside_repository(tmp_path: Path) -> None:
    import os
    import subprocess
    import sys
    result = subprocess.run([sys.executable, str(Path(acceptance.__file__).resolve()), "--help"],
        cwd=tmp_path, env={"PATH": os.environ["PATH"], "PYTHONNOUSERSITE": "1"},
        capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert "--operation" in result.stdout and "--execute-preview-state-file" in result.stdout
