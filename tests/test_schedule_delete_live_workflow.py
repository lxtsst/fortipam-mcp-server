from __future__ import annotations

import pytest

from fortipam_mcp.schedule_delete_http_transport import (
    ScheduleDeleteInspection,
    ScheduleDeleteReadback,
)
from fortipam_mcp.schedule_delete_live_workflow import (
    ScheduleDeleteLiveWorkflow,
    ScheduleDeleteLiveWorkflowError,
)


REQUESTER = "a" * 64
TARGET_DIGEST = "b" * 64


class _Transport:
    def __init__(self) -> None:
        self.exists = True
        self.eligible = True
        self.user_references = 0
        self.cmdb_references = 0
        self.user_unassigned = True
        self.target_digest = TARGET_DIGEST
        self.delete_calls: list[str] = []
        self.readback = ScheduleDeleteReadback(True, True, True)

    def inspect_delete_target(self) -> ScheduleDeleteInspection:
        return ScheduleDeleteInspection(
            self.exists,
            self.eligible,
            self.user_references,
            self.cmdb_references,
            self.target_digest,
            self.user_unassigned,
        )

    def delete_and_readback(self, expected_target_digest: str) -> ScheduleDeleteReadback:
        self.delete_calls.append(expected_target_digest)
        self.exists = False
        return self.readback


def test_preview_is_fixed_no_selector_destructive_cpe() -> None:
    preview = ScheduleDeleteLiveWorkflow(_Transport(), clock=lambda: 100).preview(
        requester_digest=REQUESTER
    )
    assert preview["Current State"] == {
        "accepted_recurring_schedule_exists": True,
        "exact_fixed_rest_and_ssh_projection_observed": True,
        "complete_api_record_digest_matches": True,
        "fixed_user_unassigned": True,
        "user_reference_count": 0,
        "cmdb_reference_count": 0,
        "read_transports": ["rest_api", "ssh_cli"],
    }
    assert preview["Proposed Changes"]["schedule_count_affected"] == 1
    assert preview["Expected State"]["accepted_recurring_schedule_absent"] is True
    assert "mcp-v4-schedule" not in repr(preview)


def test_execute_requires_confirmation_and_success_replay_never_redispatches() -> None:
    transport = _Transport()
    workflow = ScheduleDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmed = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(str(confirmed["authorization_ref"]), requester_digest=REQUESTER)
    replay = workflow.execute(str(confirmed["authorization_ref"]), requester_digest=REQUESTER)
    assert result["outcome"] == "succeeded"
    assert result["schedule_fields_returned"] is False
    assert result["fixed_user_unassigned"] is True
    assert transport.delete_calls == [TARGET_DIGEST]
    assert replay["idempotent_replay"] is True


def test_drift_references_user_expiry_and_requester_fail_closed() -> None:
    transport = _Transport()
    now = 100
    workflow = ScheduleDeleteLiveWorkflow(transport, clock=lambda: now)
    preview = workflow.preview(requester_digest=REQUESTER)
    transport.user_unassigned = False
    with pytest.raises(ScheduleDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.delete_calls == []

    for field in ("user_references", "cmdb_references"):
        transport = _Transport()
        setattr(transport, field, 1)
        with pytest.raises(ScheduleDeleteLiveWorkflowError):
            ScheduleDeleteLiveWorkflow(transport).preview(requester_digest=REQUESTER)
    with pytest.raises(ScheduleDeleteLiveWorkflowError):
        ScheduleDeleteLiveWorkflow(_Transport()).preview(requester_digest="bad")

    workflow = ScheduleDeleteLiveWorkflow(_Transport(), clock=lambda: now)
    preview = workflow.preview(requester_digest=REQUESTER)
    now = 701
    with pytest.raises(ScheduleDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)


def test_unverified_readback_is_reconciliation_required_and_nonretry() -> None:
    transport = _Transport()
    transport.readback = ScheduleDeleteReadback(True, False, True)
    workflow = ScheduleDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmed = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(str(confirmed["authorization_ref"]), requester_digest=REQUESTER)
    assert result["outcome"] == "reconciliation_required"
    with pytest.raises(ScheduleDeleteLiveWorkflowError):
        workflow.execute(str(confirmed["authorization_ref"]), requester_digest=REQUESTER)
