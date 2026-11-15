from __future__ import annotations

import pytest

from fortipam_mcp.launcher_matcher_live_workflow import (
    LauncherMatcherLiveWorkflow,
    LauncherMatcherLiveWorkflowError,
)
from fortipam_mcp.launcher_ssh_transport import (
    LAUNCHER_DEFAULT_TIMEOUT_SECONDS,
    LauncherMatcherBaselineReadback,
    LauncherMatcherReadback,
)


REQUESTER = "a" * 64
LAUNCHER_NAME = "mcp-v4-launcher-01"


class FakeLauncherMatcherTransport:
    def __init__(self) -> None:
        self.baseline = LauncherMatcherBaselineReadback(
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
        )
        self.configured = LauncherMatcherReadback(
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
        )
        self.configure_calls: list[str] = []

    def matcher_baseline_readback(
        self,
        launcher_name: str,
    ) -> LauncherMatcherBaselineReadback:
        assert launcher_name == LAUNCHER_NAME
        return self.baseline

    def configure_command_line_matcher_and_readback(
        self,
        launcher_name: str,
    ) -> LauncherMatcherReadback:
        assert launcher_name == LAUNCHER_NAME
        self.configure_calls.append(launcher_name)
        return self.configured


def _preview(workflow: LauncherMatcherLiveWorkflow) -> dict[str, object]:
    return workflow.preview(launcher_name=LAUNCHER_NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_limits_the_change_to_the_fixed_matcher() -> None:
    workflow = LauncherMatcherLiveWorkflow(
        FakeLauncherMatcherTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_launcher_name": LAUNCHER_NAME,
        "launcher_name_exists": True,
        "known_native_rdp_create_baseline_verified": True,
        "launch_timeout_seconds": LAUNCHER_DEFAULT_TIMEOUT_SECONDS,
        "custom_process_matcher_configured": False,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"]["launcher_name"] == LAUNCHER_NAME
    assert preview["Proposed Changes"]["process_matcher"] == "fixed_native_rdp_command_line"
    assert preview["Proposed Changes"]["multiprocess_mode"] == "enable"
    assert preview["Expected State"]["launcher_name_matches"] is True
    assert preview["Expected State"]["fullscreen_recording"] == "enabled"
    assert preview["Expected State"]["launch_timeout_seconds"] == LAUNCHER_DEFAULT_TIMEOUT_SECONDS
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_matcher_update() -> None:
    transport = FakeLauncherMatcherTransport()
    workflow = LauncherMatcherLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(LauncherMatcherLiveWorkflowError):
        workflow.execute("launcher-matcher-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.configure_calls == [LAUNCHER_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["launcher_type_or_command_changes"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.configure_calls) == 1


def test_confirm_invalidates_when_known_baseline_drifts() -> None:
    transport = FakeLauncherMatcherTransport()
    workflow = LauncherMatcherLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.baseline = LauncherMatcherBaselineReadback(
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        False,
        True,
    )

    with pytest.raises(LauncherMatcherLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.configure_calls == []


def test_invalid_post_write_readback_requires_reconciliation() -> None:
    transport = FakeLauncherMatcherTransport()
    transport.configured = LauncherMatcherReadback(
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        False,
    )
    workflow = LauncherMatcherLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(LauncherMatcherLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_out_of_scope_input_and_non_string_requester() -> None:
    workflow = LauncherMatcherLiveWorkflow(FakeLauncherMatcherTransport())

    with pytest.raises(LauncherMatcherLiveWorkflowError):
        workflow.preview(launcher_name="Example Windows RDP", requester_digest=REQUESTER)
    with pytest.raises(LauncherMatcherLiveWorkflowError):
        workflow.preview(launcher_name=LAUNCHER_NAME, requester_digest=object())  # type: ignore[arg-type]
