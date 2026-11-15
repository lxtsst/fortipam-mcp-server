from __future__ import annotations

import pytest

from fortipam_mcp.launcher_live_workflow import (
    LauncherCreateLiveWorkflow,
    LauncherLiveWorkflowError,
)
from fortipam_mcp.launcher_ssh_transport import LauncherInspection, LauncherReadback


REQUESTER = "a" * 64
LAUNCHER_NAME = "mcp-v4-launcher-01"


class FakeLauncherTransport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[str] = []
        self.readback = LauncherReadback(True, True, True, True, True, True, True)

    def inspect(self, launcher_name: str) -> LauncherInspection:
        return LauncherInspection(self.exists)

    def create_and_readback(self, launcher_name: str) -> LauncherReadback:
        self.create_calls.append(launcher_name)
        self.exists = True
        return self.readback


def _preview(workflow: LauncherCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(launcher_name=LAUNCHER_NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_excludes_association_changes() -> None:
    workflow = LauncherCreateLiveWorkflow(FakeLauncherTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_launcher_name": LAUNCHER_NAME,
        "launcher_name_exists": False,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_native_rdp_launcher_via_cli_fallback",
        "launcher_name": LAUNCHER_NAME,
        "configuration_profile": "windows-rdp-mstsc-cmdkey-timeout-15-v2",
        "launcher_type": "rdp",
        "client_executable": "mstsc.exe",
        "rdp_parameter_template": "/V:$HOST:$PORT /noConsentPrompt",
        "initial_command": "cmdkey_setup",
        "cleanup_command": "cmdkey_delete",
        "launch_timeout_seconds": 15,
        "secret_or_template_association_changes": False,
        "session_or_target_changes": False,
        "rest_write_attempted": False,
    }
    assert preview["Expected State"]["launcher_name_matches"] is True
    assert preview["Expected State"]["cmdkey_clean_command_present"] is True
    assert preview["Expected State"]["launch_timeout_seconds"] == 15
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeLauncherTransport()
    workflow = LauncherCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(LauncherLiveWorkflowError):
        workflow.execute("launcher-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.create_calls == [LAUNCHER_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["secret_or_template_association_changes"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_launcher_appears_after_preview() -> None:
    transport = FakeLauncherTransport()
    workflow = LauncherCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(LauncherLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_readback_failure_requires_reconciliation() -> None:
    transport = FakeLauncherTransport()
    transport.readback = LauncherReadback(True, True, True, True, True, True, False)
    workflow = LauncherCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(LauncherLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_or_out_of_scope_inputs() -> None:
    transport = FakeLauncherTransport()
    workflow = LauncherCreateLiveWorkflow(transport)

    with pytest.raises(LauncherLiveWorkflowError):
        workflow.preview(launcher_name="Example Windows RDP", requester_digest=REQUESTER)
    transport.exists = True
    with pytest.raises(LauncherLiveWorkflowError):
        _preview(workflow)
