from __future__ import annotations

import pytest

from fortipam_mcp.approval_email_template_live_workflow import (
    ApprovalEmailTemplateCreateLiveWorkflow,
    ApprovalEmailTemplateLiveWorkflowError,
)
from fortipam_mcp.approval_email_template_ssh_transport import (
    ApprovalEmailTemplateInspection,
    ApprovalEmailTemplateReadback,
)


REQUESTER = "a" * 64
TEMPLATE_NAME = "mcp-v4-approval-email-template-01"


class FakeApprovalEmailTemplateTransport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[str] = []
        self.readback = ApprovalEmailTemplateReadback(True, True, True)

    def inspect(self, template_name: str) -> ApprovalEmailTemplateInspection:
        return ApprovalEmailTemplateInspection(self.exists)

    def create_and_readback(self, template_name: str) -> ApprovalEmailTemplateReadback:
        self.create_calls.append(template_name)
        self.exists = True
        return self.readback


def _preview(workflow: ApprovalEmailTemplateCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(template_name=TEMPLATE_NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_excludes_email_or_approval_execution() -> None:
    workflow = ApprovalEmailTemplateCreateLiveWorkflow(
        FakeApprovalEmailTemplateTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_template_name": TEMPLATE_NAME,
        "template_name_exists": False,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"]["template_name"] == TEMPLATE_NAME
    assert preview["Proposed Changes"]["fixed_subject_and_content"] is True
    assert preview["Proposed Changes"]["email_server_changes"] is False
    assert preview["Expected State"]["template_name_matches"] is True
    assert preview["Expected State"]["approval_profile_or_secret_association_changes"] is False
    assert preview["Expected State"]["email_delivery_or_approval_execution"] is False
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeApprovalEmailTemplateTransport()
    workflow = ApprovalEmailTemplateCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(ApprovalEmailTemplateLiveWorkflowError):
        workflow.execute(
            "approval-email-template-authorized-missing",
            requester_digest=REQUESTER,
        )

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.create_calls == [TEMPLATE_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["email_server_changes"] is False
    assert result["email_delivery_or_approval_execution"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_template_appears_after_preview() -> None:
    transport = FakeApprovalEmailTemplateTransport()
    workflow = ApprovalEmailTemplateCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(ApprovalEmailTemplateLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_execute_rechecks_absence_and_rejects_prewrite_drift() -> None:
    transport = FakeApprovalEmailTemplateTransport()
    workflow = ApprovalEmailTemplateCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.exists = True

    with pytest.raises(ApprovalEmailTemplateLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )

    assert transport.create_calls == []


def test_readback_failure_requires_reconciliation() -> None:
    transport = FakeApprovalEmailTemplateTransport()
    transport.readback = ApprovalEmailTemplateReadback(True, True, False)
    workflow = ApprovalEmailTemplateCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(ApprovalEmailTemplateLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)
