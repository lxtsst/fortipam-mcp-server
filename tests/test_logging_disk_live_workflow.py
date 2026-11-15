from __future__ import annotations

import pytest

from fortipam_mcp.logging_disk_live_workflow import (
    LoggingDiskLiveWorkflow,
    LoggingDiskLiveWorkflowError,
)
from fortipam_mcp.logging_disk_ssh_transport import (
    LoggingDiskInspection,
    LoggingDiskReadback,
)


REQUESTER = "a" * 64


class FakeLoggingDiskTransport:
    def __init__(self) -> None:
        self.current = LoggingDiskInspection("enable", "enable")
        self.disable_calls = 0
        self.readback = LoggingDiskReadback("enable", "disable")

    def inspect(self) -> LoggingDiskInspection:
        return self.current

    def disable_and_readback(self) -> LoggingDiskReadback:
        self.disable_calls += 1
        self.current = LoggingDiskInspection("enable", "disable")
        return self.readback


def _preview(workflow: LoggingDiskLiveWorkflow) -> dict[str, object]:
    return workflow.preview(requester_digest=REQUESTER)


def test_preview_is_cpe_and_excludes_unrelated_logging_controls() -> None:
    workflow = LoggingDiskLiveWorkflow(FakeLoggingDiskTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    current = preview["Current State"]
    assert current["memory_log_status"] == "enable"
    assert current["disk_log_status"] == "enable"
    proposed = preview["Proposed Changes"]
    assert proposed["memory_log_status"] == "enable"
    assert proposed["disk_log_status"] == "disable"
    assert proposed["remote_syslog_configuration_changed"] is False
    assert proposed["event_logging_configuration_changed"] is False
    assert proposed["disk_encryption_changed"] is False
    assert proposed["rest_write_attempted"] is False
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_has_one_fixed_transition() -> None:
    transport = FakeLoggingDiskTransport()
    workflow = LoggingDiskLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(LoggingDiskLiveWorkflowError):
        workflow.execute("logging-disk-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.disable_calls == 1
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["memory_log_status"] == "enable"
    assert result["disk_log_status"] == "disable"
    assert result["raw_cli_returned"] is False
    assert workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )["idempotent_replay"] is True


def test_prewrite_drift_or_prerequisite_gap_rejects_execution() -> None:
    transport = FakeLoggingDiskTransport()
    workflow = LoggingDiskLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.current = LoggingDiskInspection("disable", "enable")

    with pytest.raises(LoggingDiskLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )

    assert transport.disable_calls == 0


def test_failed_readback_requires_reconciliation() -> None:
    transport = FakeLoggingDiskTransport()
    transport.readback = LoggingDiskReadback("enable", "enable")
    workflow = LoggingDiskLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(LoggingDiskLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )
