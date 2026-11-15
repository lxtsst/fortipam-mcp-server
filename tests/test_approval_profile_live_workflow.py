from __future__ import annotations

import pytest

from fortipam_mcp.approval_profile_live_workflow import (
    ApprovalProfileCreateLiveWorkflow,
    ApprovalProfileLiveWorkflowError,
)
from fortipam_mcp.approval_profile_ssh_transport import (
    ApprovalProfileInspection,
    ApprovalProfileReadback,
)


REQUESTER = "a" * 64
PROFILE_NAME = "mcp-v4-approval-profile-01"


class FakeApprovalProfileTransport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[str] = []
        self.readback = ApprovalProfileReadback(
            True, True, True, True, True, True, True, True, True
        )

    def inspect(self, profile_name: str) -> ApprovalProfileInspection:
        return ApprovalProfileInspection(self.exists)

    def create_and_readback(self, profile_name: str) -> ApprovalProfileReadback:
        self.create_calls.append(profile_name)
        self.exists = True
        return self.readback


def _preview(workflow: ApprovalProfileCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(profile_name=PROFILE_NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_excludes_secret_or_approval_execution() -> None:
    workflow = ApprovalProfileCreateLiveWorkflow(
        FakeApprovalProfileTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_profile_name": PROFILE_NAME,
        "profile_name_exists": False,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_approval_profile_via_cli_fallback",
        "profile_name": PROFILE_NAME,
        "configuration_profile": "single-tier-admin-unbound-v1",
        "approval_type": "single",
        "approval_tier_count": 1,
        "approver_identity_returned": False,
        "secret_association_changes": False,
        "approval_request_or_email_execution": False,
        "rest_write_attempted": False,
    }
    assert preview["Expected State"]["profile_name_matches"] is True
    assert preview["Expected State"]["fixed_approver_present"] is True
    assert preview["Expected State"]["secret_association_changes"] is False
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeApprovalProfileTransport()
    workflow = ApprovalProfileCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(ApprovalProfileLiveWorkflowError):
        workflow.execute("approval-profile-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.create_calls == [PROFILE_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["secret_association_changes"] is False
    assert result["approval_request_or_email_execution"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_profile_appears_after_preview() -> None:
    transport = FakeApprovalProfileTransport()
    workflow = ApprovalProfileCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(ApprovalProfileLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_execute_rechecks_absence_and_rejects_prewrite_drift() -> None:
    transport = FakeApprovalProfileTransport()
    workflow = ApprovalProfileCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.exists = True

    with pytest.raises(ApprovalProfileLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )

    assert transport.create_calls == []


def test_readback_failure_requires_reconciliation() -> None:
    transport = FakeApprovalProfileTransport()
    transport.readback = ApprovalProfileReadback(
        True, True, True, False, True, True, True, True, True
    )
    workflow = ApprovalProfileCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(ApprovalProfileLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_or_out_of_scope_inputs() -> None:
    transport = FakeApprovalProfileTransport()
    workflow = ApprovalProfileCreateLiveWorkflow(transport)

    with pytest.raises(ApprovalProfileLiveWorkflowError):
        workflow.preview(profile_name="default", requester_digest=REQUESTER)
    transport.exists = True
    with pytest.raises(ApprovalProfileLiveWorkflowError):
        _preview(workflow)
