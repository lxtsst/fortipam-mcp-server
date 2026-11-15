from __future__ import annotations

import pytest

from fortipam_mcp.automation_stitch_live_workflow import (
    AutomationStitchCreateLiveWorkflow,
    AutomationStitchLiveWorkflowError,
)
from fortipam_mcp.automation_stitch_ssh_transport import (
    AutomationStitchInspection,
    AutomationStitchReadback,
)


REQUESTER = "a" * 64
STITCH_NAME = "mcp-v4-automation-stitch-01"
TRIGGER_NAME = "mcp-v4-automation-trigger-01"
ACTION_NAME = "mcp-v4-automation-action-01"


class FakeAutomationStitchTransport:
    def __init__(self) -> None:
        self.stitch_exists = False
        self.trigger_exists = True
        self.action_exists = True
        self.create_calls: list[tuple[str, str, str]] = []
        self.readback = AutomationStitchReadback(
            True,
            True,
            True,
            True,
            True,
            True,
            True,
        )
        self.fail_create = False

    def inspect(
        self,
        stitch_name: str,
        trigger_name: str,
        action_name: str,
    ) -> AutomationStitchInspection:
        assert stitch_name == STITCH_NAME
        assert trigger_name == TRIGGER_NAME
        assert action_name == ACTION_NAME
        return AutomationStitchInspection(
            self.stitch_exists,
            self.trigger_exists,
            self.action_exists,
        )

    def create_and_readback(
        self,
        stitch_name: str,
        trigger_name: str,
        action_name: str,
    ) -> AutomationStitchReadback:
        self.create_calls.append((stitch_name, trigger_name, action_name))
        self.stitch_exists = True
        if self.fail_create:
            raise RuntimeError("transport failure")
        return self.readback


def _preview(workflow: AutomationStitchCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(
        stitch_name=STITCH_NAME,
        trigger_name=TRIGGER_NAME,
        action_name=ACTION_NAME,
        requester_digest=REQUESTER,
    )


def test_preview_is_live_cpe_and_excludes_automation_execution() -> None:
    workflow = AutomationStitchCreateLiveWorkflow(
        FakeAutomationStitchTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_stitch_name": STITCH_NAME,
        "requested_trigger_name": TRIGGER_NAME,
        "requested_action_name": ACTION_NAME,
        "stitch_name_exists": False,
        "approved_trigger_exists": True,
        "approved_action_exists": True,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"]["stitch_name"] == STITCH_NAME
    assert preview["Proposed Changes"]["trigger_name"] == TRIGGER_NAME
    assert preview["Proposed Changes"]["action_name"] == ACTION_NAME
    assert preview["Proposed Changes"]["stitch_status"] == "disable"
    assert preview["Proposed Changes"]["trigger_or_action_object_modified"] is False
    assert preview["Proposed Changes"]["automation_test_or_execution"] is False
    assert preview["Expected State"]["stitch_name_matches"] is True
    assert preview["Expected State"]["status_disabled"] is True
    assert preview["Expected State"]["email_or_external_side_effect"] is False
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_disabled_create() -> None:
    transport = FakeAutomationStitchTransport()
    workflow = AutomationStitchCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(AutomationStitchLiveWorkflowError):
        workflow.execute("automation-stitch-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.create_calls == [(STITCH_NAME, TRIGGER_NAME, ACTION_NAME)]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["stitch_status"] == "disable"
    assert result["automation_test_or_execution"] is False
    assert result["email_or_external_side_effect"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_prerequisite_or_stitch_state_drifts() -> None:
    transport = FakeAutomationStitchTransport()
    workflow = AutomationStitchCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.action_exists = False

    with pytest.raises(AutomationStitchLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_execute_rechecks_absence_and_prerequisites_before_write() -> None:
    transport = FakeAutomationStitchTransport()
    workflow = AutomationStitchCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.stitch_exists = True

    with pytest.raises(AutomationStitchLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )

    assert transport.create_calls == []


def test_readback_failure_or_transport_error_requires_reconciliation() -> None:
    transport = FakeAutomationStitchTransport()
    transport.readback = AutomationStitchReadback(
        True,
        False,
        True,
        True,
        True,
        True,
        True,
    )
    workflow = AutomationStitchCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(AutomationStitchLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)

    failing_transport = FakeAutomationStitchTransport()
    failing_transport.fail_create = True
    failing_workflow = AutomationStitchCreateLiveWorkflow(
        failing_transport,
        clock=lambda: 100,
    )
    failing_preview = _preview(failing_workflow)
    failing_confirmation = failing_workflow.confirm(
        str(failing_preview["preview_ref"]),
        requester_digest=REQUESTER,
    )
    failing_result = failing_workflow.execute(
        str(failing_confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert failing_result["outcome"] == "reconciliation_required"


def test_preview_rejects_existing_missing_prerequisite_or_out_of_scope_inputs() -> None:
    transport = FakeAutomationStitchTransport()
    workflow = AutomationStitchCreateLiveWorkflow(transport)

    with pytest.raises(AutomationStitchLiveWorkflowError):
        workflow.preview(
            stitch_name="default",
            trigger_name=TRIGGER_NAME,
            action_name=ACTION_NAME,
            requester_digest=REQUESTER,
        )
    transport.trigger_exists = False
    with pytest.raises(AutomationStitchLiveWorkflowError):
        _preview(workflow)
    transport.trigger_exists = True
    transport.stitch_exists = True
    with pytest.raises(AutomationStitchLiveWorkflowError):
        _preview(workflow)
