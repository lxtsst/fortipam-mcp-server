from __future__ import annotations

import pytest

from fortipam_mcp.approval_profile_delete_http_transport import (
    ApprovalProfileDeleteInspection,
    ApprovalProfileDeleteReadback,
)
from fortipam_mcp.approval_profile_delete_live_workflow import (
    ApprovalProfileDeleteLiveWorkflow,
    ApprovalProfileDeleteLiveWorkflowError,
)


REQUESTER = "a" * 64
TARGET_DIGEST = "b" * 64


class _Transport:
    def __init__(self) -> None:
        self.exists = True
        self.eligible = True
        self.references = 0
        self.target_digest = TARGET_DIGEST
        self.delete_calls: list[str] = []
        self.readback = ApprovalProfileDeleteReadback(True, True)

    def inspect_delete_target(self) -> ApprovalProfileDeleteInspection:
        return ApprovalProfileDeleteInspection(
            self.exists,
            self.eligible,
            self.references,
            self.target_digest,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> ApprovalProfileDeleteReadback:
        self.delete_calls.append(expected_target_digest)
        self.exists = False
        return self.readback


def test_preview_is_fixed_destructive_cpe_without_selector_or_values() -> None:
    preview = ApprovalProfileDeleteLiveWorkflow(
        _Transport(),
        clock=lambda: 100,
    ).preview(requester_digest=REQUESTER)

    assert preview["Current State"] == {
        "accepted_approval_profile_exists": True,
        "exact_b38_updated_projection_observed": True,
        "complete_api_record_digest_matches": True,
        "profile_reference_count": 0,
        "read_transports": ["rest_api", "ssh_cli"],
    }
    assert preview["Proposed Changes"] == {
        "operation": "delete_exact_unreferenced_approval_profile_via_api",
        "profile_count_affected": 1,
        "irreversible_after_execution": True,
        "secret_or_approval_execution_changes": False,
    }
    assert preview["Expected State"] == {
        "accepted_approval_profile_absent": True,
        "secret_or_approval_execution_changes": False,
        "readback_transports": ["rest_api", "ssh_cli"],
    }
    assert "mcp-v4-approval-profile" not in repr(preview)


def test_execute_requires_confirmation_and_never_redispatches_success() -> None:
    transport = _Transport()
    workflow = ApprovalProfileDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmed = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmed["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    replay = workflow.execute(
        str(confirmed["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "succeeded"
    assert result["profile_fields_returned"] is False
    assert transport.delete_calls == [TARGET_DIGEST]
    assert replay["idempotent_replay"] is True


def test_drift_reference_absence_expiry_and_requester_fail_closed() -> None:
    transport = _Transport()
    now = 100
    workflow = ApprovalProfileDeleteLiveWorkflow(transport, clock=lambda: now)
    preview = workflow.preview(requester_digest=REQUESTER)
    transport.references = 1
    transport.eligible = False
    with pytest.raises(ApprovalProfileDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.delete_calls == []

    transport = _Transport()
    transport.exists = False
    with pytest.raises(ApprovalProfileDeleteLiveWorkflowError):
        ApprovalProfileDeleteLiveWorkflow(transport).preview(
            requester_digest=REQUESTER
        )
    with pytest.raises(ApprovalProfileDeleteLiveWorkflowError):
        ApprovalProfileDeleteLiveWorkflow(_Transport()).preview(
            requester_digest="invalid"
        )

    workflow = ApprovalProfileDeleteLiveWorkflow(_Transport(), clock=lambda: now)
    preview = workflow.preview(requester_digest=REQUESTER)
    now = 701
    with pytest.raises(ApprovalProfileDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)


def test_unverified_readback_is_reconciliation_required_and_nonretry() -> None:
    transport = _Transport()
    transport.readback = ApprovalProfileDeleteReadback(True, False)
    workflow = ApprovalProfileDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmed = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmed["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    with pytest.raises(ApprovalProfileDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmed["authorization_ref"]),
            requester_digest=REQUESTER,
        )
