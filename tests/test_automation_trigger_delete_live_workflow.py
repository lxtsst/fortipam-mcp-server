from __future__ import annotations

import pytest

from fortipam_mcp.automation_trigger_delete_http_transport import (
    AutomationTriggerDeleteInspection,
    AutomationTriggerDeleteReadback,
)
from fortipam_mcp.automation_trigger_delete_live_workflow import (
    AutomationTriggerDeleteLiveWorkflow,
    AutomationTriggerDeleteLiveWorkflowError,
)


REQUESTER = "a" * 64
TARGET_DIGEST = "b" * 64
ACTION_DIGEST = "c" * 64


class _Transport:
    def __init__(self) -> None:
        self.exists = True
        self.eligible = True
        self.references = 0
        self.target_digest = TARGET_DIGEST
        self.action_digest = ACTION_DIGEST
        self.delete_calls: list[str] = []
        self.readback = AutomationTriggerDeleteReadback(True, True, True, True)

    def inspect_delete_target(self) -> AutomationTriggerDeleteInspection:
        return AutomationTriggerDeleteInspection(
            self.exists,
            self.eligible,
            self.references,
            self.target_digest,
            self.action_digest,
        )

    def delete_and_readback(self, expected_target_digest: str) -> AutomationTriggerDeleteReadback:
        self.delete_calls.append(expected_target_digest)
        self.exists = False
        return self.readback


def test_preview_is_fixed_no_selector_destructive_cpe() -> None:
    preview = AutomationTriggerDeleteLiveWorkflow(_Transport(), clock=lambda: 100).preview(
        requester_digest=REQUESTER
    )
    assert preview["Current State"] == {
        "accepted_unbound_automation_trigger_exists": True,
        "exact_fixed_projection_observed": True,
        "complete_api_record_digest_matches": True,
        "fixed_action_dependency_matches": True,
        "trigger_reference_count": 0,
        "read_transports": ["rest_api", "ssh_cli"],
    }
    assert preview["Proposed Changes"]["trigger_count_affected"] == 1
    assert preview["Expected State"]["fixed_action_dependency_preserved"] is True
    assert "mcp-v4-automation" not in repr(preview)


def test_execute_requires_confirmation_and_success_replay_never_redispatches() -> None:
    transport = _Transport()
    workflow = AutomationTriggerDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmed = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(str(confirmed["authorization_ref"]), requester_digest=REQUESTER)
    replay = workflow.execute(str(confirmed["authorization_ref"]), requester_digest=REQUESTER)
    assert result["outcome"] == "succeeded"
    assert result["trigger_or_action_fields_returned"] is False
    assert transport.delete_calls == [TARGET_DIGEST]
    assert replay["idempotent_replay"] is True


def test_drift_reference_absence_expiry_and_requester_fail_closed() -> None:
    transport = _Transport()
    now = 100
    workflow = AutomationTriggerDeleteLiveWorkflow(transport, clock=lambda: now)
    preview = workflow.preview(requester_digest=REQUESTER)
    transport.action_digest = "d" * 64
    with pytest.raises(AutomationTriggerDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.delete_calls == []

    transport = _Transport()
    transport.references = 1
    with pytest.raises(AutomationTriggerDeleteLiveWorkflowError):
        AutomationTriggerDeleteLiveWorkflow(transport).preview(requester_digest=REQUESTER)
    with pytest.raises(AutomationTriggerDeleteLiveWorkflowError):
        AutomationTriggerDeleteLiveWorkflow(_Transport()).preview(requester_digest="bad")

    workflow = AutomationTriggerDeleteLiveWorkflow(_Transport(), clock=lambda: now)
    preview = workflow.preview(requester_digest=REQUESTER)
    now = 701
    with pytest.raises(AutomationTriggerDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)


def test_unverified_readback_is_reconciliation_required_and_nonretry() -> None:
    transport = _Transport()
    transport.readback = AutomationTriggerDeleteReadback(True, True, False, True)
    workflow = AutomationTriggerDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmed = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(str(confirmed["authorization_ref"]), requester_digest=REQUESTER)
    assert result["outcome"] == "reconciliation_required"
    with pytest.raises(AutomationTriggerDeleteLiveWorkflowError):
        workflow.execute(str(confirmed["authorization_ref"]), requester_digest=REQUESTER)
