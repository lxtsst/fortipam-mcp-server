from __future__ import annotations

import pytest

from fortipam_mcp.schedule_assign_contract import (
    ScheduleDetachInspection,
    ScheduleDetachReadback,
)
from fortipam_mcp.schedule_assign_detach_live_workflow import (
    EXECUTION_CONTRACT,
    ScheduleAssignDetachLiveWorkflow,
    ScheduleAssignDetachLiveWorkflowError,
    WORKFLOW_CONTRACT,
)


REQUESTER = "a" * 64


class _Transport:
    def __init__(self) -> None:
        self.state = "1" * 64
        self.reference_count = 1
        self.write_calls = 0
        self.readback: ScheduleDetachReadback | Exception = ScheduleDetachReadback(
            True, True, True, True, True, True, True, True, True, True, 0
        )

    def inspect_fixed_detach(self) -> ScheduleDetachInspection:
        return ScheduleDetachInspection(
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            self.reference_count,
            self.reference_count == 1,
            self.state,
            "2" * 64,
            "3" * 64,
        )

    def detach_fixed_and_readback(
        self,
        *,
        expected_user_record_digest: str,
        expected_user_non_schedule_state_digest: str,
        expected_schedule_state_digest: str,
    ) -> ScheduleDetachReadback:
        assert expected_user_record_digest == "1" * 64
        assert expected_user_non_schedule_state_digest == "2" * 64
        assert expected_schedule_state_digest == "3" * 64
        self.write_calls += 1
        if isinstance(self.readback, Exception):
            raise self.readback
        return self.readback


def test_workflow_renders_fixed_cpe_and_executes_once() -> None:
    transport = _Transport()
    workflow = ScheduleAssignDetachLiveWorkflow(transport, clock=lambda: 100)

    preview = workflow.preview(requester_digest=REQUESTER)
    assert preview["contract"] == WORKFLOW_CONTRACT
    assert preview["Current State"]["schedule_reference_count"] == 1
    assert preview["Proposed Changes"]["password_mfa_trust_or_role_change"] is False
    assert preview["Expected State"]["schedule_reference_count"] == 0
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["contract"] == EXECUTION_CONTRACT
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["idempotent_replay"] is False
    assert transport.write_calls == 1
    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert replay["idempotent_replay"] is True
    assert transport.write_calls == 1


def test_workflow_rejects_reference_or_digest_drift() -> None:
    transport = _Transport()
    workflow = ScheduleAssignDetachLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    transport.reference_count = 2

    with pytest.raises(ScheduleAssignDetachLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.write_calls == 0

    transport.reference_count = 1
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    transport.state = "4" * 64
    with pytest.raises(ScheduleAssignDetachLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )
    assert transport.write_calls == 0


def test_workflow_marks_ambiguous_write_nonretry() -> None:
    transport = _Transport()
    transport.readback = RuntimeError("ambiguous")
    workflow = ScheduleAssignDetachLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    authorization = str(confirmation["authorization_ref"])

    result = workflow.execute(authorization, requester_digest=REQUESTER)
    assert result["outcome"] == "reconciliation_required"
    assert transport.write_calls == 1
    with pytest.raises(ScheduleAssignDetachLiveWorkflowError):
        workflow.execute(authorization, requester_digest=REQUESTER)
    assert transport.write_calls == 1


def test_workflow_is_requester_bound() -> None:
    workflow = ScheduleAssignDetachLiveWorkflow(_Transport(), clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    with pytest.raises(ScheduleAssignDetachLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest="b" * 64)
