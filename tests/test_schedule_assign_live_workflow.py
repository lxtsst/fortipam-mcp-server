from __future__ import annotations

import pytest

from fortipam_mcp.schedule_assign_contract import (
    ScheduleAssignInspection,
    ScheduleAssignReadback,
)
from fortipam_mcp.schedule_assign_live_workflow import (
    EXECUTION_CONTRACT,
    ScheduleAssignLiveWorkflow,
    ScheduleAssignLiveWorkflowError,
    WORKFLOW_CONTRACT,
)


REQUESTER = "a" * 64
USER = "mcp-v4-user-b57"
SCHEDULE = "mcp-v4-schedule-b66"


class _Transport:
    def __init__(self) -> None:
        self.user_exists = True
        self.schedule_exists = True
        self.user_disabled = True
        self.user_local = True
        self.schedule_unassigned = True
        self.state = "1" * 64
        self.write_calls = 0
        self.readback: ScheduleAssignReadback | Exception = ScheduleAssignReadback(
            True, True, True, True, True, True, True
        )

    def inspect_assignment(
        self,
        username: str,
        schedule_name: str,
    ) -> ScheduleAssignInspection:
        assert (username, schedule_name) == (USER, SCHEDULE)
        return ScheduleAssignInspection(
            self.user_exists,
            self.schedule_exists,
            self.user_disabled,
            self.user_local,
            self.schedule_unassigned,
            "2" * 64,
            "3" * 64,
            self.state,
        )

    def assign_and_readback(
        self,
        username: str,
        schedule_name: str,
        *,
        user_non_schedule_state_digest: str,
        schedule_state_digest: str,
    ) -> ScheduleAssignReadback:
        assert (username, schedule_name) == (USER, SCHEDULE)
        assert user_non_schedule_state_digest == "2" * 64
        assert schedule_state_digest == "3" * 64
        self.write_calls += 1
        if isinstance(self.readback, Exception):
            raise self.readback
        return self.readback


def _preview(workflow: ScheduleAssignLiveWorkflow) -> dict[str, object]:
    return workflow.preview(
        username=USER,
        schedule_name=SCHEDULE,
        requester_digest=REQUESTER,
    )


@pytest.mark.parametrize("phase", ["confirm", "execute"])
def test_expiry_during_current_state_read_refuses_authorization_and_write(
    phase: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [100]
    transport = _Transport()
    workflow = ScheduleAssignLiveWorkflow(transport, clock=lambda: now[0])
    preview = _preview(workflow)
    reference = str(preview["preview_ref"])
    if phase == "execute":
        confirmation = workflow.confirm(reference, requester_digest=REQUESTER)
        reference = str(confirmation["authorization_ref"])
    expires_at = int(str(preview["expires_at"]))
    now[0] = expires_at - 1
    inspect = transport.inspect_assignment

    def expire_during_query(username: str, schedule_name: str) -> ScheduleAssignInspection:
        result = inspect(username, schedule_name)
        now[0] = expires_at
        return result

    monkeypatch.setattr(transport, "inspect_assignment", expire_during_query)
    with pytest.raises(ScheduleAssignLiveWorkflowError):
        if phase == "confirm":
            workflow.confirm(reference, requester_digest=REQUESTER)
        else:
            workflow.execute(reference, requester_digest=REQUESTER)

    assert now[0] == expires_at
    assert transport.write_calls == 0


def test_workflow_renders_exact_cpe_and_executes_once() -> None:
    transport = _Transport()
    workflow = ScheduleAssignLiveWorkflow(transport, clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["contract"] == WORKFLOW_CONTRACT
    assert preview["Current State"] == {
        "requested_username": USER,
        "user_exists": True,
        "user_status": "disabled",
        "user_type": "local",
        "current_schedule_unassigned": True,
        "requested_schedule_name": SCHEDULE,
        "schedule_exists": True,
        "write_transport": "rest_api",
    }
    assert preview["Proposed Changes"] == {
        "operation": "assign_existing_login_schedule_to_disabled_local_user_via_api",
        "username": USER,
        "schedule_name": SCHEDULE,
        "request_body": "product_ui_existing_user_projection_schedule_only_change",
    }
    assert preview["Expected State"] == {
        "user_exists": True,
        "schedule_exists": True,
        "user_remains_disabled": True,
        "user_remains_local": True,
        "schedule_matches": True,
        "user_non_schedule_state_preserved": True,
        "schedule_state_preserved": True,
        "readback_transport": "rest_api",
    }
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


@pytest.mark.parametrize(
    "attribute",
    [
        "user_exists",
        "schedule_exists",
        "user_disabled",
        "user_local",
        "schedule_unassigned",
    ],
)
def test_workflow_requires_exact_eligible_baseline(attribute: str) -> None:
    transport = _Transport()
    setattr(transport, attribute, False)
    workflow = ScheduleAssignLiveWorkflow(transport)

    with pytest.raises(ScheduleAssignLiveWorkflowError):
        _preview(workflow)


def test_workflow_rejects_drift_before_confirmation_and_execution() -> None:
    transport = _Transport()
    workflow = ScheduleAssignLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.state = "4" * 64

    with pytest.raises(ScheduleAssignLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.write_calls == 0

    transport.state = "1" * 64
    preview = _preview(workflow)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    transport.schedule_unassigned = False
    with pytest.raises(ScheduleAssignLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )
    assert transport.write_calls == 0


def test_workflow_marks_uncertain_write_nonretry() -> None:
    transport = _Transport()
    transport.readback = RuntimeError("uncertain")
    workflow = ScheduleAssignLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    authorization_ref = str(confirmation["authorization_ref"])

    result = workflow.execute(authorization_ref, requester_digest=REQUESTER)

    assert result["outcome"] == "reconciliation_required"
    assert transport.write_calls == 1
    with pytest.raises(ScheduleAssignLiveWorkflowError):
        workflow.execute(authorization_ref, requester_digest=REQUESTER)
    assert transport.write_calls == 1


def test_workflow_rejects_nonlaboratory_names() -> None:
    workflow = ScheduleAssignLiveWorkflow(_Transport())

    with pytest.raises(ScheduleAssignLiveWorkflowError):
        workflow.preview(
            username="admin",
            schedule_name=SCHEDULE,
            requester_digest=REQUESTER,
        )
    with pytest.raises(ScheduleAssignLiveWorkflowError):
        workflow.preview(
            username=USER,
            schedule_name="always",
            requester_digest=REQUESTER,
        )
