from __future__ import annotations

import pytest

from fortipam_mcp.automation_trigger_live_workflow import (
    AutomationTriggerCreateLiveWorkflow,
    AutomationTriggerLiveWorkflowError,
)
from fortipam_mcp.automation_trigger_ssh_transport import (
    AutomationTriggerInspection,
    AutomationTriggerReadback,
)


REQUESTER = "a" * 64
TRIGGER_NAME = "mcp-v4-automation-trigger-01"


class FakeAutomationTriggerTransport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[str] = []
        self.readback = AutomationTriggerReadback(True, True, True, True, True, True)

    def inspect(self, trigger_name: str) -> AutomationTriggerInspection:
        return AutomationTriggerInspection(self.exists)

    def create_and_readback(self, trigger_name: str) -> AutomationTriggerReadback:
        self.create_calls.append(trigger_name)
        self.exists = True
        return self.readback


def _preview(workflow: AutomationTriggerCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(trigger_name=TRIGGER_NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_excludes_action_or_stitch_changes() -> None:
    workflow = AutomationTriggerCreateLiveWorkflow(
        FakeAutomationTriggerTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_trigger_name": TRIGGER_NAME,
        "trigger_name_exists": False,
        "write_transport": "ssh_cli",
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_automation_trigger_via_cli",
        "trigger_name": TRIGGER_NAME,
        "configuration_profile": "event-log-44547-msg-regex-no-action-v1",
        "event_type": "event-log",
        "automation_action_or_stitch_changes": False,
        "direct_automation_execution": False,
        "rest_write_attempted": False,
    }
    assert preview["Expected State"]["trigger_name_matches"] is True
    assert preview["Expected State"]["msg_regex_field_present"] is True
    assert preview["Expected State"]["automation_action_or_stitch_changes"] is False
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeAutomationTriggerTransport()
    workflow = AutomationTriggerCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(AutomationTriggerLiveWorkflowError):
        workflow.execute("automation-trigger-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.create_calls == [TRIGGER_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["automation_action_or_stitch_changes"] is False
    assert result["direct_automation_execution"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_trigger_appears_after_preview() -> None:
    transport = FakeAutomationTriggerTransport()
    workflow = AutomationTriggerCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(AutomationTriggerLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_execute_rechecks_absence_and_rejects_prewrite_drift() -> None:
    transport = FakeAutomationTriggerTransport()
    workflow = AutomationTriggerCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.exists = True

    with pytest.raises(AutomationTriggerLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )

    assert transport.create_calls == []


def test_readback_failure_requires_reconciliation() -> None:
    transport = FakeAutomationTriggerTransport()
    transport.readback = AutomationTriggerReadback(True, False, True, True, True, True)
    workflow = AutomationTriggerCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(AutomationTriggerLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_or_out_of_scope_inputs() -> None:
    transport = FakeAutomationTriggerTransport()
    workflow = AutomationTriggerCreateLiveWorkflow(transport)

    with pytest.raises(AutomationTriggerLiveWorkflowError):
        workflow.preview(trigger_name="default", requester_digest=REQUESTER)
    transport.exists = True
    with pytest.raises(AutomationTriggerLiveWorkflowError):
        _preview(workflow)
