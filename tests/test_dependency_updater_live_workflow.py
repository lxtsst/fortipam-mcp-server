from __future__ import annotations

import pytest

from fortipam_mcp.dependency_updater_live_workflow import (
    DependencyUpdaterCreateLiveWorkflow,
    DependencyUpdaterLiveWorkflowError,
)
from fortipam_mcp.dependency_updater_ssh_transport import (
    DependencyUpdaterInspection,
    DependencyUpdaterReadback,
)


REQUESTER = "a" * 64
UPDATER_NAME = "mcp-v4-dependency-updater-01"
SERVICE_NAME = "McpV4LabService"


class FakeDependencyUpdaterTransport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[tuple[str, str]] = []
        self.readback = DependencyUpdaterReadback(True, True, True, True)

    def inspect(self, updater_name: str) -> DependencyUpdaterInspection:
        return DependencyUpdaterInspection(self.exists)

    def create_and_readback(
        self,
        updater_name: str,
        service_name: str,
    ) -> DependencyUpdaterReadback:
        self.create_calls.append((updater_name, service_name))
        self.exists = True
        return self.readback


def _preview(workflow: DependencyUpdaterCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(
        updater_name=UPDATER_NAME,
        service_name=SERVICE_NAME,
        requester_digest=REQUESTER,
    )


def test_preview_is_live_cpe_and_excludes_association_or_service_effects() -> None:
    workflow = DependencyUpdaterCreateLiveWorkflow(
        FakeDependencyUpdaterTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_updater_name": UPDATER_NAME,
        "requested_service_name": SERVICE_NAME,
        "updater_name_exists": False,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_dependency_updater_via_cli_fallback",
        "updater_name": UPDATER_NAME,
        "service_name": SERVICE_NAME,
        "configuration_profile": "win-service-restart-disabled-v1",
        "updater_type": "win-service",
        "restart_after_updates": "disable",
        "secret_or_target_association_changes": False,
        "service_operation_executed": False,
        "rest_write_attempted": False,
    }
    assert preview["Expected State"]["updater_name_matches"] is True
    assert preview["Expected State"]["service_name_matches"] is True
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeDependencyUpdaterTransport()
    workflow = DependencyUpdaterCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(DependencyUpdaterLiveWorkflowError):
        workflow.execute(
            "dependency-updater-authorized-missing",
            requester_digest=REQUESTER,
        )

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.create_calls == [(UPDATER_NAME, SERVICE_NAME)]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["service_operation_executed"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_updater_appears_after_preview() -> None:
    transport = FakeDependencyUpdaterTransport()
    workflow = DependencyUpdaterCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(DependencyUpdaterLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_execute_rechecks_absence_and_rejects_prewrite_drift() -> None:
    transport = FakeDependencyUpdaterTransport()
    workflow = DependencyUpdaterCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.exists = True

    with pytest.raises(DependencyUpdaterLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )

    assert transport.create_calls == []


def test_readback_failure_requires_reconciliation() -> None:
    transport = FakeDependencyUpdaterTransport()
    transport.readback = DependencyUpdaterReadback(True, False, True, True)
    workflow = DependencyUpdaterCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(DependencyUpdaterLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_or_out_of_scope_inputs() -> None:
    transport = FakeDependencyUpdaterTransport()
    workflow = DependencyUpdaterCreateLiveWorkflow(transport)

    with pytest.raises(DependencyUpdaterLiveWorkflowError):
        workflow.preview(
            updater_name="default",
            service_name=SERVICE_NAME,
            requester_digest=REQUESTER,
        )
    with pytest.raises(DependencyUpdaterLiveWorkflowError):
        workflow.preview(
            updater_name=UPDATER_NAME,
            service_name="invalid service name",
            requester_digest=REQUESTER,
        )
    transport.exists = True
    with pytest.raises(DependencyUpdaterLiveWorkflowError):
        _preview(workflow)
