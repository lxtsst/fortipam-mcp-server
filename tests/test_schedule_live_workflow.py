from __future__ import annotations

import pytest

from fortipam_mcp.schedule_live_workflow import (
    ScheduleCreateLiveWorkflow,
    ScheduleLiveWorkflowError,
)
from fortipam_mcp.schedule_ssh_transport import (
    ScheduleInspection,
    ScheduleReadback,
)


REQUESTER = "a" * 64
SCHEDULE_NAME = "mcp-v4-schedule-01"


class FakeScheduleTransport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[str] = []
        self.readback = ScheduleReadback(True, True, True, True, True)

    def inspect(self, schedule_name: str) -> ScheduleInspection:
        assert schedule_name == SCHEDULE_NAME
        return ScheduleInspection(self.exists)

    def create_and_readback(self, schedule_name: str) -> ScheduleReadback:
        self.create_calls.append(schedule_name)
        self.exists = True
        return self.readback


def _preview(workflow: ScheduleCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(schedule_name=SCHEDULE_NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_excludes_assignments_or_session_changes() -> None:
    workflow = ScheduleCreateLiveWorkflow(FakeScheduleTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_schedule_name": SCHEDULE_NAME,
        "schedule_name_exists": False,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_recurring_schedule_via_cli_fallback",
        "schedule_name": SCHEDULE_NAME,
        "configuration_profile": "recurring-monday-0100-0130-unattached-v1",
        "user_or_role_assignment": False,
        "folder_or_secret_acl_change": False,
        "policy_or_session_change": False,
        "rest_write_attempted": False,
    }
    assert preview["Expected State"]["schedule_name_matches"] is True
    assert preview["Expected State"]["recurring_window_matches"] is True
    assert preview["Expected State"]["user_or_role_assignment"] is False
    assert SCHEDULE_NAME in str(preview)
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeScheduleTransport()
    workflow = ScheduleCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(ScheduleLiveWorkflowError):
        workflow.execute("schedule-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.create_calls == [SCHEDULE_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["user_or_role_assignment"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_schedule_appears_after_preview() -> None:
    transport = FakeScheduleTransport()
    workflow = ScheduleCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(ScheduleLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_execute_rechecks_absence_and_rejects_prewrite_drift() -> None:
    transport = FakeScheduleTransport()
    workflow = ScheduleCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )
    transport.exists = True

    with pytest.raises(ScheduleLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )

    assert transport.create_calls == []


def test_readback_failure_requires_reconciliation() -> None:
    transport = FakeScheduleTransport()
    transport.readback = ScheduleReadback(True, True, False, True, True)
    workflow = ScheduleCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(ScheduleLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )


def test_preview_rejects_existing_or_out_of_scope_inputs() -> None:
    transport = FakeScheduleTransport()
    workflow = ScheduleCreateLiveWorkflow(transport)

    with pytest.raises(ScheduleLiveWorkflowError):
        workflow.preview(schedule_name="always", requester_digest=REQUESTER)
    transport.exists = True
    with pytest.raises(ScheduleLiveWorkflowError):
        _preview(workflow)
