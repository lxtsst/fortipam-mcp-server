from __future__ import annotations

import pytest

from fortipam_mcp.approval_profile_update_live_workflow import (
    ApprovalProfileUpdateLiveWorkflow,
    ApprovalProfileUpdateLiveWorkflowError,
)
from fortipam_mcp.approval_profile_ssh_transport import (
    ApprovalProfileReadback,
    ApprovalProfileUpdateReadback,
)


REQUESTER = "a" * 64
PROFILE_NAME = "mcp-v4-approval-profile-01"


class FakeApprovalProfileUpdateTransport:
    def __init__(self) -> None:
        self.current = ApprovalProfileReadback(
            True, True, True, True, True, True, True, True, True
        )
        self.update_calls: list[str] = []
        self.updated = ApprovalProfileUpdateReadback(
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

    def readback(self, profile_name: str) -> ApprovalProfileReadback:
        return self.current

    def update_description_and_readback(
        self,
        profile_name: str,
    ) -> ApprovalProfileUpdateReadback:
        self.update_calls.append(profile_name)
        return self.updated


def _preview(workflow: ApprovalProfileUpdateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(profile_name=PROFILE_NAME, requester_digest=REQUESTER)


def test_preview_requires_known_create_baseline_and_shows_only_description_change() -> None:
    workflow = ApprovalProfileUpdateLiveWorkflow(
        FakeApprovalProfileUpdateTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"]["requested_profile_name"] == PROFILE_NAME
    assert preview["Current State"]["known_create_baseline_verified"] is True
    assert preview["Proposed Changes"]["profile_name"] == PROFILE_NAME
    assert preview["Proposed Changes"]["description_value_returned"] is False
    assert preview["Proposed Changes"]["approval_type_or_tier_changes"] is False
    assert preview["Expected State"]["profile_name_matches"] is True
    assert preview["Expected State"]["updated_description_present"] is True
    assert preview["Expected State"]["secret_association_changes"] is False
    assert preview["device_write_executed"] is False


def test_execute_requires_confirmation_and_preserves_single_dispatch() -> None:
    transport = FakeApprovalProfileUpdateTransport()
    workflow = ApprovalProfileUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(ApprovalProfileUpdateLiveWorkflowError):
        workflow.execute("approval-profile-update-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.update_calls == [PROFILE_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["approval_type_or_tier_changes"] is False
    assert result["secret_association_changes"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.update_calls) == 1


def test_confirm_rejects_drift_or_nonbaseline_current_state() -> None:
    transport = FakeApprovalProfileUpdateTransport()
    workflow = ApprovalProfileUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.current = ApprovalProfileReadback(
        True, True, True, True, False, True, True, True, True
    )

    with pytest.raises(ApprovalProfileUpdateLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.update_calls == []


def test_execute_rechecks_current_state_and_reconciles_bad_readback() -> None:
    transport = FakeApprovalProfileUpdateTransport()
    workflow = ApprovalProfileUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.updated = ApprovalProfileUpdateReadback(
        True,
        True,
        True,
        True,
        False,
        True,
        True,
        True,
        True,
    )

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    assert transport.update_calls == [PROFILE_NAME]


def test_preview_rejects_out_of_scope_or_nonbaseline_profile() -> None:
    transport = FakeApprovalProfileUpdateTransport()
    workflow = ApprovalProfileUpdateLiveWorkflow(transport)

    with pytest.raises(ApprovalProfileUpdateLiveWorkflowError):
        workflow.preview(profile_name="default", requester_digest=REQUESTER)
    transport.current = ApprovalProfileReadback(
        True, True, True, True, False, True, True, True, True
    )
    with pytest.raises(ApprovalProfileUpdateLiveWorkflowError):
        _preview(workflow)
