from __future__ import annotations

import pytest

from fortipam_mcp.ztna_wad_debug_live_workflow import (
    ZtnaWadDebugLiveWorkflow,
    ZtnaWadDebugLiveWorkflowError,
)
from fortipam_mcp.ztna_wad_debug_ssh_transport import (
    ZtnaWadDebugInspection,
    ZtnaWadDebugReadback,
)


REQUESTER = "a" * 64


def test_one_confirmed_wad_debug_capture_is_cleaned_up_and_idempotent() -> None:
    transport = _Transport()
    workflow = ZtnaWadDebugLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    assert preview["Current State"] == {
        "global_debug_state": "disabled",
        "raw_cli_returned": False,
        "identity_tag_target_secret_or_session_data_returned": False,
        "persistent_configuration_changed": False,
    }
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert result["outcome"] == "succeeded"
    assert result["global_debug_cleanup_confirmed"] is True
    assert result["device_context_state"] == "available"
    assert result["raw_cli_returned"] is False
    assert transport.capture_count == 1
    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert replay["idempotent_replay"] is True
    assert transport.capture_count == 1


def test_confirmation_and_execution_fail_closed_if_global_debug_changes() -> None:
    transport = _Transport()
    workflow = ZtnaWadDebugLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    transport.disabled = False
    with pytest.raises(ZtnaWadDebugLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)


def test_cleanup_unknown_requires_reconciliation_without_raw_output() -> None:
    transport = _Transport(cleanup_confirmed=False)
    workflow = ZtnaWadDebugLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert result["outcome"] == "reconciliation_required"
    assert result["global_debug_cleanup_confirmed"] is False
    assert result["device_context_state"] == "inconclusive"
    assert result["raw_cli_returned"] is False


class _Transport:
    def __init__(self, *, cleanup_confirmed: bool = True) -> None:
        self.disabled = True
        self.cleanup_confirmed = cleanup_confirmed
        self.capture_count = 0

    def inspect(self) -> ZtnaWadDebugInspection:
        return ZtnaWadDebugInspection(debug_is_disabled=self.disabled)

    def capture_and_cleanup(self) -> ZtnaWadDebugReadback:
        self.capture_count += 1
        return ZtnaWadDebugReadback(
            capture_collected=True,
            cleanup_confirmed=self.cleanup_confirmed,
            device_context_state="available" if self.cleanup_confirmed else "inconclusive",
            device_tag_match_state="matched" if self.cleanup_confirmed else "unknown",
            launch_authorization_state="allowed" if self.cleanup_confirmed else "unknown",
        )
