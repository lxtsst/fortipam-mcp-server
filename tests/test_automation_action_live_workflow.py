from __future__ import annotations

import pytest

from fortipam_mcp.automation_action_live_workflow import (
    AutomationActionCreateLiveWorkflow,
    AutomationActionLiveWorkflowError,
)
from fortipam_mcp.automation_action_ssh_transport import (
    AutomationActionInspection,
    AutomationActionReadback,
)


REQUESTER = "a" * 64
ACTION_NAME = "mcp-v4-automation-action-01"


class FakeAutomationActionTransport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[str] = []
        self.readback = AutomationActionReadback(True, True, True, True, True, True)

    def inspect(self, action_name: str) -> AutomationActionInspection:
        return AutomationActionInspection(self.exists)

    def create_and_readback(self, action_name: str) -> AutomationActionReadback:
        self.create_calls.append(action_name)
        self.exists = True
        return self.readback


def _preview(workflow: AutomationActionCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(action_name=ACTION_NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_excludes_stitch_or_email_execution() -> None:
    workflow = AutomationActionCreateLiveWorkflow(
        FakeAutomationActionTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_action_name": ACTION_NAME,
        "action_name_exists": False,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_automation_action_via_cli_fallback",
        "action_name": ACTION_NAME,
        "configuration_profile": "email-fixed-recipient-no-stitch-v1",
        "action_type": "email",
        "recipient_returned": False,
        "automation_action_or_stitch_association_changes": False,
        "direct_email_execution": False,
        "rest_write_attempted": False,
    }
    assert preview["Expected State"]["action_name_matches"] is True
    assert preview["Expected State"]["fixed_recipient_present"] is True
    assert preview["Expected State"]["direct_email_execution"] is False
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeAutomationActionTransport()
    workflow = AutomationActionCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(AutomationActionLiveWorkflowError):
        workflow.execute("automation-action-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.create_calls == [ACTION_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["automation_action_or_stitch_association_changes"] is False
    assert result["direct_email_execution"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_action_appears_after_preview() -> None:
    transport = FakeAutomationActionTransport()
    workflow = AutomationActionCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(AutomationActionLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_execute_rechecks_absence_and_rejects_prewrite_drift() -> None:
    transport = FakeAutomationActionTransport()
    workflow = AutomationActionCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.exists = True

    with pytest.raises(AutomationActionLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )

    assert transport.create_calls == []


def test_readback_failure_requires_reconciliation() -> None:
    transport = FakeAutomationActionTransport()
    transport.readback = AutomationActionReadback(True, True, False, True, True, True)
    workflow = AutomationActionCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(AutomationActionLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_or_out_of_scope_inputs() -> None:
    transport = FakeAutomationActionTransport()
    workflow = AutomationActionCreateLiveWorkflow(transport)

    with pytest.raises(AutomationActionLiveWorkflowError):
        workflow.preview(action_name="default", requester_digest=REQUESTER)
    transport.exists = True
    with pytest.raises(AutomationActionLiveWorkflowError):
        _preview(workflow)
