from __future__ import annotations

import pytest

from fortipam_mcp.report_layout_http_transport import (
    ReportLayoutInspection,
    ReportLayoutReadback,
)
from fortipam_mcp.report_layout_live_workflow import (
    ReportLayoutCreateLiveWorkflow,
    ReportLayoutLiveWorkflowError,
)


REQUESTER = "a" * 64
NAME = "MCPV4ReportB163Test"
DEFAULT_DIGEST = "b" * 64


class _Transport:
    def __init__(self) -> None:
        self.exists = False
        self.default_digest = DEFAULT_DIGEST
        self.create_calls: list[tuple[str, str]] = []
        self.readback = ReportLayoutReadback(True, True, True, True, True, True, True)

    def inspect(self, name: str) -> ReportLayoutInspection:
        assert name == NAME
        return ReportLayoutInspection(self.exists, True, self.default_digest)

    def create_and_readback(
        self, name: str, expected_default_digest: str
    ) -> ReportLayoutReadback:
        self.create_calls.append((name, expected_default_digest))
        self.exists = True
        return self.readback


def _preview(workflow: ReportLayoutCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(name=NAME, requester_digest=REQUESTER)


def test_preview_is_bounded_cpe_and_does_not_generate_or_return_report() -> None:
    preview = _preview(ReportLayoutCreateLiveWorkflow(_Transport(), clock=lambda: 100))

    assert preview["Current State"] == {
        "requested_report_layout_name": NAME,
        "report_layout_exists": False,
        "eligible_default_layout_observed": True,
        "write_transport": "rest_api",
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_bounded_default_report_layout_clone_via_api",
        "report_layout_name": NAME,
        "schedule": "daily_at_00_00",
        "format": "pdf",
        "email_delivery": "disabled",
        "report_filters": "none",
        "report_generation_requested": False,
    }
    assert preview["Expected State"]["report_content_returned"] is False
    assert preview["device_write_executed"] is False


def test_execute_requires_confirmation_and_is_idempotent_after_success() -> None:
    transport = _Transport()
    workflow = ReportLayoutCreateLiveWorkflow(transport, clock=lambda: 100)
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
    assert transport.create_calls == [(NAME, DEFAULT_DIGEST)]
    assert replay["idempotent_replay"] is True


def test_target_or_default_drift_is_rejected_before_write() -> None:
    transport = _Transport()
    workflow = ReportLayoutCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.default_digest = "c" * 64
    with pytest.raises(ReportLayoutLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    transport = _Transport()
    workflow = ReportLayoutCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.exists = True
    with pytest.raises(ReportLayoutLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )
    assert transport.create_calls == []


def test_unverified_readback_requires_reconciliation_without_replay() -> None:
    transport = _Transport()
    transport.readback = ReportLayoutReadback(True, True, False, True, True, True, True)
    workflow = ReportLayoutCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    with pytest.raises(ReportLayoutLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )


def test_invalid_name_requester_and_existing_target_fail_closed() -> None:
    transport = _Transport()
    workflow = ReportLayoutCreateLiveWorkflow(transport)
    with pytest.raises(ReportLayoutLiveWorkflowError):
        workflow.preview(name="MCP-V4-Report", requester_digest=REQUESTER)
    with pytest.raises(ReportLayoutLiveWorkflowError):
        workflow.preview(name=NAME, requester_digest="invalid")
    transport.exists = True
    with pytest.raises(ReportLayoutLiveWorkflowError):
        _preview(workflow)
