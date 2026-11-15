from __future__ import annotations

import pytest

from fortipam_mcp.approval_email_template_update_live_workflow import (
    ApprovalEmailTemplateUpdateLiveWorkflow,
    ApprovalEmailTemplateUpdateLiveWorkflowError,
)
from fortipam_mcp.approval_email_template_ssh_transport import (
    ApprovalEmailTemplateReadback,
    ApprovalEmailTemplateUpdateReadback,
)


REQUESTER = "a" * 64
TEMPLATE_NAME = "mcp-v4-approval-email-template-01"


class FakeApprovalEmailTemplateUpdateTransport:
    def __init__(self) -> None:
        self.current = ApprovalEmailTemplateReadback(True, True, True)
        self.update_calls: list[str] = []
        self.updated = ApprovalEmailTemplateUpdateReadback(True, True, True)

    def readback(self, template_name: str) -> ApprovalEmailTemplateReadback:
        return self.current

    def update_and_readback(
        self,
        template_name: str,
    ) -> ApprovalEmailTemplateUpdateReadback:
        self.update_calls.append(template_name)
        return self.updated


def _preview(workflow: ApprovalEmailTemplateUpdateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(template_name=TEMPLATE_NAME, requester_digest=REQUESTER)


def test_preview_requires_known_baseline_and_excludes_delivery() -> None:
    workflow = ApprovalEmailTemplateUpdateLiveWorkflow(
        FakeApprovalEmailTemplateUpdateTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"]["requested_template_name"] == TEMPLATE_NAME
    assert preview["Current State"]["known_create_baseline_verified"] is True
    assert preview["Proposed Changes"]["template_name"] == TEMPLATE_NAME
    assert preview["Proposed Changes"]["subject_or_content_value_returned"] is False
    assert preview["Proposed Changes"]["email_server_changes"] is False
    assert preview["Expected State"]["template_name_matches"] is True
    assert preview["Expected State"]["updated_subject_present"] is True
    assert preview["Expected State"]["email_delivery_or_approval_execution"] is False
    assert preview["device_write_executed"] is False


def test_execute_requires_confirmation_and_performs_one_update() -> None:
    transport = FakeApprovalEmailTemplateUpdateTransport()
    workflow = ApprovalEmailTemplateUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(ApprovalEmailTemplateUpdateLiveWorkflowError):
        workflow.execute(
            "approval-email-template-update-authorized-missing",
            requester_digest=REQUESTER,
        )

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.update_calls == [TEMPLATE_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["email_server_changes"] is False
    assert result["email_delivery_or_approval_execution"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.update_calls) == 1


def test_confirm_rejects_baseline_drift_and_execute_reconciles_bad_readback() -> None:
    transport = FakeApprovalEmailTemplateUpdateTransport()
    workflow = ApprovalEmailTemplateUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.current = ApprovalEmailTemplateReadback(True, True, False)

    with pytest.raises(ApprovalEmailTemplateUpdateLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    transport = FakeApprovalEmailTemplateUpdateTransport()
    workflow = ApprovalEmailTemplateUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.updated = ApprovalEmailTemplateUpdateReadback(True, False, True)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert result["outcome"] == "reconciliation_required"
    assert transport.update_calls == [TEMPLATE_NAME]


def test_preview_rejects_out_of_scope_or_nonbaseline_template() -> None:
    transport = FakeApprovalEmailTemplateUpdateTransport()
    workflow = ApprovalEmailTemplateUpdateLiveWorkflow(transport)

    with pytest.raises(ApprovalEmailTemplateUpdateLiveWorkflowError):
        workflow.preview(template_name="default", requester_digest=REQUESTER)
    transport.current = ApprovalEmailTemplateReadback(True, False, True)
    with pytest.raises(ApprovalEmailTemplateUpdateLiveWorkflowError):
        _preview(workflow)
