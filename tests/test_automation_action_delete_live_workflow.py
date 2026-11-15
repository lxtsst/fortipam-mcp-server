from __future__ import annotations

import pytest

from fortipam_mcp.automation_action_delete_http_transport import (
    AutomationActionDeleteInspection,
    AutomationActionDeleteReadback,
)
from fortipam_mcp.automation_action_delete_live_workflow import (
    AutomationActionDeleteLiveWorkflow,
    AutomationActionDeleteLiveWorkflowError,
)


REQUESTER = "a" * 64
TARGET_DIGEST = "b" * 64


class _Transport:
    def __init__(self) -> None:
        self.exists = True
        self.eligible = True
        self.references = 0
        self.trigger_absent = True
        self.stitch_absent = True
        self.target_digest = TARGET_DIGEST
        self.delete_calls: list[str] = []
        self.readback = AutomationActionDeleteReadback(True, True)

    def inspect_delete_target(self) -> AutomationActionDeleteInspection:
        return AutomationActionDeleteInspection(
            self.exists,
            self.eligible,
            self.references,
            self.target_digest,
            self.trigger_absent,
            self.stitch_absent,
        )

    def delete_and_readback(self, expected_target_digest: str) -> AutomationActionDeleteReadback:
        self.delete_calls.append(expected_target_digest)
        self.exists = False
        return self.readback


def test_preview_is_fixed_no_selector_destructive_cpe() -> None:
    preview = AutomationActionDeleteLiveWorkflow(_Transport(), clock=lambda: 100).preview(
        requester_digest=REQUESTER
    )
    assert preview["Current State"] == {
        "accepted_unbound_automation_action_exists": True,
        "exact_fixed_projection_observed": True,
        "complete_api_record_digest_matches": True,
        "accepted_trigger_absent": True,
        "accepted_stitch_absent": True,
        "action_reference_count": 0,
        "read_transports": ["rest_api", "ssh_cli"],
    }
    assert preview["Proposed Changes"]["action_count_affected"] == 1
    assert preview["Expected State"]["accepted_automation_action_absent"] is True
    assert "mcp-v4-automation" not in repr(preview)


def test_execute_requires_confirmation_and_success_replay_never_redispatches() -> None:
    transport = _Transport()
    workflow = AutomationActionDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmed = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(str(confirmed["authorization_ref"]), requester_digest=REQUESTER)
    replay = workflow.execute(str(confirmed["authorization_ref"]), requester_digest=REQUESTER)
    assert result["outcome"] == "succeeded"
    assert result["action_fields_returned"] is False
    assert transport.delete_calls == [TARGET_DIGEST]
    assert replay["idempotent_replay"] is True


def test_drift_reference_dependency_expiry_and_requester_fail_closed() -> None:
    transport = _Transport()
    now = 100
    workflow = AutomationActionDeleteLiveWorkflow(transport, clock=lambda: now)
    preview = workflow.preview(requester_digest=REQUESTER)
    transport.stitch_absent = False
    with pytest.raises(AutomationActionDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.delete_calls == []

    transport = _Transport()
    transport.references = 1
    with pytest.raises(AutomationActionDeleteLiveWorkflowError):
        AutomationActionDeleteLiveWorkflow(transport).preview(requester_digest=REQUESTER)
    with pytest.raises(AutomationActionDeleteLiveWorkflowError):
        AutomationActionDeleteLiveWorkflow(_Transport()).preview(requester_digest="bad")

    workflow = AutomationActionDeleteLiveWorkflow(_Transport(), clock=lambda: now)
    preview = workflow.preview(requester_digest=REQUESTER)
    now = 701
    with pytest.raises(AutomationActionDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)


def test_unverified_readback_is_reconciliation_required_and_nonretry() -> None:
    transport = _Transport()
    transport.readback = AutomationActionDeleteReadback(True, False)
    workflow = AutomationActionDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmed = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(str(confirmed["authorization_ref"]), requester_digest=REQUESTER)
    assert result["outcome"] == "reconciliation_required"
    with pytest.raises(AutomationActionDeleteLiveWorkflowError):
        workflow.execute(str(confirmed["authorization_ref"]), requester_digest=REQUESTER)
