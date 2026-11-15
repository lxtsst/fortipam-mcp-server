from __future__ import annotations

import pytest

from fortipam_mcp.rdp_event_filter_delete_http_transport import (
    RdpEventFilterDeleteInspection,
    RdpEventFilterDeleteReadback,
)
from fortipam_mcp.rdp_event_filter_delete_live_workflow import (
    RdpEventFilterDeleteLiveWorkflow,
    RdpEventFilterDeleteLiveWorkflowError,
)


REQUESTER = "a" * 64
TARGET_DIGEST = "b" * 64


class _Transport:
    def __init__(self) -> None:
        self.exists = True
        self.eligible = True
        self.secret_references = 0
        self.policy_references = 0
        self.target_digest = TARGET_DIGEST
        self.delete_calls: list[str] = []
        self.readback = RdpEventFilterDeleteReadback(True, True)

    def inspect_delete_target(self) -> RdpEventFilterDeleteInspection:
        return RdpEventFilterDeleteInspection(
            self.exists,
            self.eligible,
            self.secret_references,
            self.policy_references,
            self.target_digest,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> RdpEventFilterDeleteReadback:
        self.delete_calls.append(expected_target_digest)
        self.exists = False
        return self.readback


def _preview(workflow: RdpEventFilterDeleteLiveWorkflow) -> dict[str, object]:
    return workflow.preview(requester_digest=REQUESTER)


def test_preview_is_fixed_destructive_cpe_without_name_or_content() -> None:
    preview = _preview(RdpEventFilterDeleteLiveWorkflow(_Transport(), clock=lambda: 100))

    assert preview["Current State"] == {
        "accepted_rdp_event_filter_exists": True,
        "exact_fixed_three_event_profile_observed": True,
        "complete_api_record_digest_matches": True,
        "secret_reference_count": 0,
        "policy_reference_count": 0,
        "read_transports": ["rest_api", "ssh_cli"],
    }
    assert preview["Proposed Changes"] == {
        "operation": "delete_exact_unreferenced_rdp_event_filter_via_api",
        "rdp_event_filter_count_affected": 1,
        "irreversible_after_execution": True,
        "secret_or_policy_association_changes": False,
        "target_winrm_or_audit_policy_changes": False,
        "monitoring_or_session_changes": False,
    }
    assert preview["Expected State"] == {
        "accepted_rdp_event_filter_absent": True,
        "secret_or_policy_association_changes": False,
        "target_winrm_or_audit_policy_changes": False,
        "monitoring_or_session_changes": False,
        "readback_transports": ["rest_api", "ssh_cli"],
    }
    assert preview["device_write_executed"] is False
    assert "mcp-v4-rdp-event-filter" not in repr(preview)


def test_execute_requires_confirmation_and_is_idempotent_only_after_success() -> None:
    transport = _Transport()
    workflow = RdpEventFilterDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "succeeded"
    assert result["rdp_event_filter_name_returned"] is False
    assert result["profile_content_returned"] is False
    assert transport.delete_calls == [TARGET_DIGEST]
    assert replay["idempotent_replay"] is True


def test_target_drift_or_new_dependency_is_rejected_before_delete() -> None:
    transport = _Transport()
    workflow = RdpEventFilterDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.target_digest = "c" * 64
    with pytest.raises(RdpEventFilterDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.delete_calls == []

    transport = _Transport()
    workflow = RdpEventFilterDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )
    transport.policy_references = 1
    transport.eligible = False
    with pytest.raises(RdpEventFilterDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )
    assert transport.delete_calls == []


def test_unverified_absence_requires_reconciliation_without_replay() -> None:
    transport = _Transport()
    transport.readback = RdpEventFilterDeleteReadback(True, False)
    workflow = RdpEventFilterDeleteLiveWorkflow(transport, clock=lambda: 100)
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
    with pytest.raises(RdpEventFilterDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )


def test_absent_referenced_expired_and_wrong_requester_fail_closed() -> None:
    transport = _Transport()
    now = 100
    workflow = RdpEventFilterDeleteLiveWorkflow(transport, clock=lambda: now)
    transport.exists = False
    with pytest.raises(RdpEventFilterDeleteLiveWorkflowError):
        _preview(workflow)
    transport.exists = True
    transport.secret_references = 1
    transport.eligible = False
    with pytest.raises(RdpEventFilterDeleteLiveWorkflowError):
        _preview(workflow)
    transport.secret_references = 0
    transport.eligible = True
    with pytest.raises(RdpEventFilterDeleteLiveWorkflowError):
        workflow.preview(requester_digest="invalid")

    preview = _preview(workflow)
    now = 701
    with pytest.raises(RdpEventFilterDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
