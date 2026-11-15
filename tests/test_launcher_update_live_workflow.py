from __future__ import annotations

import pytest

from fortipam_mcp.launcher_ssh_transport import (
    LAUNCHER_DEFAULT_TIMEOUT_SECONDS,
    LAUNCHER_UPDATED_TIMEOUT_SECONDS,
    LauncherUpdateBaselineReadback,
    LauncherUpdateReadback,
)
from fortipam_mcp.launcher_update_live_workflow import (
    LauncherTimeoutUpdateLiveWorkflow,
    LauncherUpdateLiveWorkflowError,
)


REQUESTER = "a" * 64
LAUNCHER_NAME = "mcp-v4-launcher-01"


class FakeLauncherUpdateTransport:
    def __init__(self) -> None:
        self.baseline = LauncherUpdateBaselineReadback(
            True,
            True,
            True,
            True,
            True,
            True,
            True,
        )
        self.updated = LauncherUpdateReadback(
            True,
            True,
            True,
            True,
            True,
            True,
            True,
        )
        self.update_calls: list[str] = []

    def update_baseline_readback(
        self,
        launcher_name: str,
    ) -> LauncherUpdateBaselineReadback:
        assert launcher_name == LAUNCHER_NAME
        return self.baseline

    def update_timeout_and_readback(self, launcher_name: str) -> LauncherUpdateReadback:
        assert launcher_name == LAUNCHER_NAME
        self.update_calls.append(launcher_name)
        return self.updated


def _preview(workflow: LauncherTimeoutUpdateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(launcher_name=LAUNCHER_NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_limits_the_change_to_timeout() -> None:
    workflow = LauncherTimeoutUpdateLiveWorkflow(
        FakeLauncherUpdateTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_launcher_name": LAUNCHER_NAME,
        "launcher_name_exists": True,
        "known_native_rdp_create_baseline_verified": True,
        "launch_timeout_seconds": LAUNCHER_DEFAULT_TIMEOUT_SECONDS,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"]["launcher_name"] == LAUNCHER_NAME
    assert preview["Proposed Changes"]["launch_timeout_seconds"] == {
        "from": LAUNCHER_DEFAULT_TIMEOUT_SECONDS,
        "to": LAUNCHER_UPDATED_TIMEOUT_SECONDS,
    }
    assert preview["Proposed Changes"]["launcher_type_or_command_changes"] is False
    assert preview["Expected State"]["launcher_name_matches"] is True
    assert preview["Expected State"]["launch_timeout_seconds"] == (
        LAUNCHER_UPDATED_TIMEOUT_SECONDS
    )
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_update() -> None:
    transport = FakeLauncherUpdateTransport()
    workflow = LauncherTimeoutUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(LauncherUpdateLiveWorkflowError):
        workflow.execute("launcher-update-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.update_calls == [LAUNCHER_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["launcher_type_or_command_changes"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.update_calls) == 1


def test_confirm_invalidates_when_known_baseline_drifts() -> None:
    transport = FakeLauncherUpdateTransport()
    workflow = LauncherTimeoutUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.baseline = LauncherUpdateBaselineReadback(
        True,
        True,
        True,
        True,
        True,
        True,
        False,
    )

    with pytest.raises(LauncherUpdateLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.update_calls == []


def test_invalid_post_write_readback_requires_reconciliation() -> None:
    transport = FakeLauncherUpdateTransport()
    transport.updated = LauncherUpdateReadback(
        True,
        True,
        True,
        True,
        True,
        True,
        False,
    )
    workflow = LauncherTimeoutUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(LauncherUpdateLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_out_of_scope_input_and_non_string_requester() -> None:
    workflow = LauncherTimeoutUpdateLiveWorkflow(FakeLauncherUpdateTransport())

    with pytest.raises(LauncherUpdateLiveWorkflowError):
        workflow.preview(launcher_name="Example Windows RDP", requester_digest=REQUESTER)
    with pytest.raises(LauncherUpdateLiveWorkflowError):
        workflow.preview(launcher_name=LAUNCHER_NAME, requester_digest=object())  # type: ignore[arg-type]
