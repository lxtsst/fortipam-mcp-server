from __future__ import annotations

import pytest

from fortipam_mcp.maintenance_mode_live_workflow import (
    MaintenanceModeLiveWorkflow,
    MaintenanceModeLiveWorkflowError,
    MaintenanceModeRollbackLiveWorkflow,
)
from fortipam_mcp.maintenance_mode_ssh_transport import (
    MaintenanceModeInspection,
    MaintenanceModeReadback,
)


REQUESTER = "a" * 64


class FakeMaintenanceModeTransport:
    def __init__(self) -> None:
        self.current = MaintenanceModeInspection("disable")
        self.enable_calls = 0
        self.disable_calls = 0
        self.readback = MaintenanceModeReadback("enable")
        self.rollback_readback = MaintenanceModeReadback("disable")

    def inspect(self) -> MaintenanceModeInspection:
        return self.current

    def enable_and_readback(self) -> MaintenanceModeReadback:
        self.enable_calls += 1
        self.current = MaintenanceModeInspection("enable")
        return self.readback

    def disable_and_readback(self) -> MaintenanceModeReadback:
        self.disable_calls += 1
        self.current = MaintenanceModeInspection("disable")
        return self.rollback_readback


def _preview(workflow: MaintenanceModeLiveWorkflow) -> dict[str, object]:
    return workflow.preview(requester_digest=REQUESTER)


def test_preview_is_cpe_and_excludes_disruptive_operations() -> None:
    workflow = MaintenanceModeLiveWorkflow(FakeMaintenanceModeTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"]["maintenance_mode_status"] == "disable"
    proposed = preview["Proposed Changes"]
    assert proposed["maintenance_mode_status"] == "enable"
    assert proposed["reboot_requested"] is False
    assert proposed["firmware_or_license_upload_requested"] is False
    assert proposed["configuration_restore_requested"] is False
    assert proposed["tpm_or_disk_encryption_changed"] is False
    assert proposed["rest_write_attempted"] is False
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_has_one_fixed_transition() -> None:
    transport = FakeMaintenanceModeTransport()
    workflow = MaintenanceModeLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(MaintenanceModeLiveWorkflowError):
        workflow.execute("maintenance-mode-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.enable_calls == 1
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["reboot_requested"] is False
    assert result["raw_cli_returned"] is False
    assert workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )["idempotent_replay"] is True


def test_prewrite_drift_or_prerequisite_gap_rejects_execution() -> None:
    transport = FakeMaintenanceModeTransport()
    workflow = MaintenanceModeLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.current = MaintenanceModeInspection("enable")

    with pytest.raises(MaintenanceModeLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )

    assert transport.enable_calls == 0


def test_failed_readback_requires_reconciliation() -> None:
    transport = FakeMaintenanceModeTransport()
    transport.readback = MaintenanceModeReadback("disable")
    workflow = MaintenanceModeLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(MaintenanceModeLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )


def test_rollback_requires_enabled_state_and_restores_ordinary_disabled_mode() -> None:
    transport = FakeMaintenanceModeTransport()
    transport.current = MaintenanceModeInspection("enable")
    workflow = MaintenanceModeRollbackLiveWorkflow(transport, clock=lambda: 100)

    preview = workflow.preview(requester_digest=REQUESTER)
    assert preview["Current State"]["maintenance_mode_status"] == "enable"
    assert preview["Proposed Changes"]["maintenance_mode_status"] == "disable"
    assert preview["Expected State"]["pre_action_state_restored"] is True
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.disable_calls == 1
    assert result["outcome"] == "succeeded"
    assert result["pre_action_state_restored"] is True
    assert result["raw_cli_returned"] is False


def test_rollback_rejects_drift_and_ambiguous_readback() -> None:
    transport = FakeMaintenanceModeTransport()
    transport.current = MaintenanceModeInspection("enable")
    workflow = MaintenanceModeRollbackLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    transport.current = MaintenanceModeInspection("disable")
    with pytest.raises(MaintenanceModeLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )
    assert transport.disable_calls == 0

    transport = FakeMaintenanceModeTransport()
    transport.current = MaintenanceModeInspection("enable")
    transport.rollback_readback = MaintenanceModeReadback("enable")
    workflow = MaintenanceModeRollbackLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]), requester_digest=REQUESTER
    )
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert result["outcome"] == "reconciliation_required"
