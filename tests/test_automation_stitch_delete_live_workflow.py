from __future__ import annotations

import pytest

from fortipam_mcp.automation_stitch_delete_http_transport import (
    AutomationStitchDeleteInspection,
    AutomationStitchDeleteReadback,
)
from fortipam_mcp.automation_stitch_delete_live_workflow import (
    AutomationStitchDeleteLiveWorkflow,
    AutomationStitchDeleteLiveWorkflowError,
)


REQUESTER = "a" * 64
TARGET_DIGEST = "b" * 64
TRIGGER_DIGEST = "c" * 64
ACTION_DIGEST = "d" * 64


class _Transport:
    def __init__(self) -> None:
        self.exists = True
        self.eligible = True
        self.references = 0
        self.target_digest = TARGET_DIGEST
        self.trigger_digest = TRIGGER_DIGEST
        self.action_digest = ACTION_DIGEST
        self.delete_calls: list[str] = []
        self.readback = AutomationStitchDeleteReadback(
            True, True, True, True, True, True
        )

    def inspect_delete_target(self) -> AutomationStitchDeleteInspection:
        return AutomationStitchDeleteInspection(
            self.exists,
            self.eligible,
            self.references,
            self.target_digest,
            self.trigger_digest,
            self.action_digest,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> AutomationStitchDeleteReadback:
        self.delete_calls.append(expected_target_digest)
        self.exists = False
        return self.readback


def test_preview_is_fixed_destructive_cpe_without_selector_or_values() -> None:
    preview = AutomationStitchDeleteLiveWorkflow(
        _Transport(),
        clock=lambda: 100,
    ).preview(requester_digest=REQUESTER)

    assert preview["Current State"] == {
        "accepted_disabled_automation_stitch_exists": True,
        "exact_fixed_projection_observed": True,
        "complete_api_record_digest_matches": True,
        "fixed_trigger_and_action_dependencies_match": True,
        "stitch_reference_count": 0,
        "read_transports": ["rest_api", "ssh_cli"],
    }
    assert preview["Proposed Changes"] == {
        "operation": "delete_exact_unreferenced_automation_stitch_via_api",
        "stitch_count_affected": 1,
        "irreversible_after_execution": True,
        "trigger_or_action_object_changes": False,
        "automation_test_or_execution": False,
        "email_or_external_side_effect": False,
    }
    assert preview["Expected State"] == {
        "accepted_automation_stitch_absent": True,
        "fixed_trigger_and_action_dependencies_preserved": True,
        "automation_test_or_execution": False,
        "email_or_external_side_effect": False,
        "readback_transports": ["rest_api", "ssh_cli"],
    }
    assert "mcp-v4-automation" not in repr(preview)


def test_execute_requires_confirmation_and_never_redispatches_success() -> None:
    transport = _Transport()
    workflow = AutomationStitchDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmed = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmed["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    replay = workflow.execute(
        str(confirmed["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "succeeded"
    assert result["stitch_or_dependency_fields_returned"] is False
    assert transport.delete_calls == [TARGET_DIGEST]
    assert replay["idempotent_replay"] is True


def test_drift_reference_absence_expiry_and_requester_fail_closed() -> None:
    transport = _Transport()
    now = 100
    workflow = AutomationStitchDeleteLiveWorkflow(transport, clock=lambda: now)
    preview = workflow.preview(requester_digest=REQUESTER)
    transport.trigger_digest = "e" * 64
    with pytest.raises(AutomationStitchDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.delete_calls == []

    transport = _Transport()
    transport.exists = False
    with pytest.raises(AutomationStitchDeleteLiveWorkflowError):
        AutomationStitchDeleteLiveWorkflow(transport).preview(
            requester_digest=REQUESTER
        )
    with pytest.raises(AutomationStitchDeleteLiveWorkflowError):
        AutomationStitchDeleteLiveWorkflow(_Transport()).preview(
            requester_digest="invalid"
        )

    workflow = AutomationStitchDeleteLiveWorkflow(_Transport(), clock=lambda: now)
    preview = workflow.preview(requester_digest=REQUESTER)
    now = 701
    with pytest.raises(AutomationStitchDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)


def test_unverified_dependency_readback_is_reconciliation_required_and_nonretry() -> None:
    transport = _Transport()
    transport.readback = AutomationStitchDeleteReadback(
        True, True, True, False, True, True
    )
    workflow = AutomationStitchDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmed = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmed["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    with pytest.raises(AutomationStitchDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmed["authorization_ref"]),
            requester_digest=REQUESTER,
        )
