from __future__ import annotations

import hashlib

import pytest

from fortipam_mcp.fortianalyzer_live_workflow import (
    FortiAnalyzerLiveWorkflow,
    FortiAnalyzerLiveWorkflowError,
)
from fortipam_mcp.fortianalyzer_ssh_transport import (
    FortiAnalyzerInspection,
    FortiAnalyzerReadback,
)


REQUESTER = "a" * 64
BINDING = hashlib.sha256(b'"faz.private.example"').hexdigest()
OTHER_BINDING = hashlib.sha256(b'"faz-other.private.example"').hexdigest()


class FakeFortiAnalyzerTransport:
    def __init__(self) -> None:
        self.current = FortiAnalyzerInspection("disable", BINDING)
        self.enable_calls = 0
        self.readback = FortiAnalyzerReadback("enable", BINDING)

    def inspect(self) -> FortiAnalyzerInspection:
        return self.current

    def enable_and_readback(
        self,
        *,
        expected_server_binding_digest: str,
    ) -> FortiAnalyzerReadback:
        assert expected_server_binding_digest == BINDING
        self.enable_calls += 1
        self.current = FortiAnalyzerInspection("enable", BINDING)
        return self.readback


def _preview(workflow: FortiAnalyzerLiveWorkflow) -> dict[str, object]:
    return workflow.preview(requester_digest=REQUESTER)


def test_preview_is_cpe_and_hides_configured_server_identity() -> None:
    workflow = FortiAnalyzerLiveWorkflow(FakeFortiAnalyzerTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"]["fortianalyzer_delivery_status"] == "disable"
    assert preview["Current State"]["configured_server_present"] is True
    proposed = preview["Proposed Changes"]
    assert proposed["fortianalyzer_delivery_status"] == "enable"
    assert proposed["server_configuration_changed"] is False
    assert proposed["upload_schedule_changed"] is False
    assert proposed["certificate_or_authorization_changed"] is False
    assert proposed["connectivity_test_executed"] is False
    assert proposed["rest_write_attempted"] is False
    assert "faz.private.example" not in str(preview)
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_preserves_server_binding() -> None:
    transport = FakeFortiAnalyzerTransport()
    workflow = FortiAnalyzerLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(FortiAnalyzerLiveWorkflowError):
        workflow.execute("fortianalyzer-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.enable_calls == 1
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["server_configuration_changed"] is False
    assert result["end_to_end_delivery_verified"] is False
    assert result["raw_cli_returned"] is False
    assert workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )["idempotent_replay"] is True


def test_prewrite_drift_of_status_or_server_binding_rejects_execution() -> None:
    transport = FakeFortiAnalyzerTransport()
    workflow = FortiAnalyzerLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.current = FortiAnalyzerInspection("disable", OTHER_BINDING)

    with pytest.raises(FortiAnalyzerLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )

    assert transport.enable_calls == 0


def test_failed_readback_requires_reconciliation() -> None:
    transport = FakeFortiAnalyzerTransport()
    transport.readback = FortiAnalyzerReadback("enable", OTHER_BINDING)
    workflow = FortiAnalyzerLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(FortiAnalyzerLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )
