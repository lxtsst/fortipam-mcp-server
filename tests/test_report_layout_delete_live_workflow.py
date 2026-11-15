from __future__ import annotations

import pytest

from fortipam_mcp.report_layout_delete_live_workflow import (
    ReportLayoutDeleteLiveWorkflow,
    ReportLayoutDeleteLiveWorkflowError,
)
from fortipam_mcp.report_layout_http_transport import (
    ReportLayoutDeleteInspection,
    ReportLayoutDeleteReadback,
)


REQUESTER = "a" * 64
TARGET_DIGEST = "b" * 64


class _Transport:
    def __init__(self) -> None:
        self.exists = True
        self.eligible = True
        self.target_digest = TARGET_DIGEST
        self.delete_calls: list[str] = []
        self.readback = ReportLayoutDeleteReadback(True)

    def inspect_delete_target(self) -> ReportLayoutDeleteInspection:
        return ReportLayoutDeleteInspection(
            self.exists,
            self.eligible,
            self.target_digest,
        )

    def delete_and_readback(
        self, expected_target_digest: str
    ) -> ReportLayoutDeleteReadback:
        self.delete_calls.append(expected_target_digest)
        self.exists = False
        return self.readback


def _preview(workflow: ReportLayoutDeleteLiveWorkflow) -> dict[str, object]:
    return workflow.preview(requester_digest=REQUESTER)


def test_preview_is_fixed_destructive_cpe_without_name_or_content() -> None:
    preview = _preview(ReportLayoutDeleteLiveWorkflow(_Transport(), clock=lambda: 100))

    assert preview["Current State"] == {
        "accepted_report_layout_exists": True,
        "exact_default_clone_observed": True,
        "read_transport": "rest_api",
    }
    assert preview["Proposed Changes"] == {
        "operation": "delete_exact_accepted_report_layout_via_api",
        "report_layout_count_affected": 1,
        "irreversible_after_execution": True,
        "report_generation_requested": False,
        "report_content_accessed": False,
    }
    assert preview["Expected State"]["accepted_report_layout_absent"] is True
    assert preview["device_write_executed"] is False
    assert "MCPV4Report" not in repr(preview)


def test_execute_requires_confirmation_and_is_idempotent_after_success() -> None:
    transport = _Transport()
    workflow = ReportLayoutDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "succeeded"
    assert result["report_content_returned"] is False
    assert transport.delete_calls == [TARGET_DIGEST]
    assert replay["idempotent_replay"] is True


def test_target_drift_or_ineligible_clone_is_rejected_before_delete() -> None:
    transport = _Transport()
    workflow = ReportLayoutDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.target_digest = "c" * 64
    with pytest.raises(ReportLayoutDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.delete_calls == []

    transport = _Transport()
    workflow = ReportLayoutDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.eligible = False
    with pytest.raises(ReportLayoutDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )
    assert transport.delete_calls == []


def test_unverified_absence_requires_reconciliation_without_replay() -> None:
    transport = _Transport()
    transport.readback = ReportLayoutDeleteReadback(False)
    workflow = ReportLayoutDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    with pytest.raises(ReportLayoutDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )


def test_absent_target_and_wrong_requester_fail_closed() -> None:
    transport = _Transport()
    workflow = ReportLayoutDeleteLiveWorkflow(transport)
    transport.exists = False
    with pytest.raises(ReportLayoutDeleteLiveWorkflowError):
        _preview(workflow)
    transport.exists = True
    with pytest.raises(ReportLayoutDeleteLiveWorkflowError):
        workflow.preview(requester_digest="invalid")
