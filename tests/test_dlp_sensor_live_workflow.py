from __future__ import annotations

import pytest

from fortipam_mcp.dlp_sensor_live_workflow import (
    DlpSensorLiveWorkflow,
    DlpSensorLiveWorkflowError,
)
from fortipam_mcp.dlp_sensor_ssh_transport import DlpSensorInspection, DlpSensorReadback


REQUESTER = "a" * 64
SENSOR_NAME = "mcp-v4-dlp-sensor-01"
PATTERN_ID = 1001
PATTERN_NAME = "mcp-v4-dlp-pattern-01"


class FakeDlpSensorTransport:
    def __init__(self) -> None:
        self.sensor_exists = False
        self.pattern_id_exists = True
        self.pattern_name_exists = True
        self.binding_matches = True
        self.create_calls: list[tuple[str, int]] = []
        self.readback = DlpSensorReadback(True, True, True, True, True, True, True)

    def inspect(
        self,
        sensor_name: str,
        file_pattern_id: int,
        file_pattern_name: str,
    ) -> DlpSensorInspection:
        return DlpSensorInspection(
            self.sensor_exists,
            self.pattern_id_exists,
            self.pattern_name_exists,
            self.binding_matches,
        )

    def create_and_readback(
        self,
        sensor_name: str,
        file_pattern_id: int,
    ) -> DlpSensorReadback:
        self.create_calls.append((sensor_name, file_pattern_id))
        self.sensor_exists = True
        return self.readback


def _preview(workflow: DlpSensorLiveWorkflow) -> dict[str, object]:
    return workflow.preview(
        sensor_name=SENSOR_NAME,
        file_pattern_id=PATTERN_ID,
        file_pattern_name=PATTERN_NAME,
        requester_digest=REQUESTER,
    )


def test_preview_is_live_cpe_and_excludes_secret_association_and_credentials() -> None:
    workflow = DlpSensorLiveWorkflow(FakeDlpSensorTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_sensor_name": SENSOR_NAME,
        "requested_file_pattern_id": PATTERN_ID,
        "requested_file_pattern_name": PATTERN_NAME,
        "sensor_name_exists": False,
        "file_pattern_id_exists": True,
        "file_pattern_name_exists": True,
        "file_pattern_binding_matches": True,
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_single_http_get_pdf_block_dlp_sensor",
        "sensor_name": SENSOR_NAME,
        "file_pattern_id": PATTERN_ID,
        "file_pattern_name": PATTERN_NAME,
        "configuration_profile": "single_http_get_pdf_block_v1",
        "protocol": "http-get",
        "filter_by": "file-type",
        "action": "block",
        "dlp_secret_association_changes": False,
    }
    assert preview["Expected State"]["sensor_name_matches"] is True
    assert preview["Expected State"]["action_matches"] is True
    assert preview["device_write_executed"] is False
    assert "password" not in repr(preview).lower()


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeDlpSensorTransport()
    workflow = DlpSensorLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(DlpSensorLiveWorkflowError):
        workflow.execute("dlp-sensor-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.create_calls == [(SENSOR_NAME, PATTERN_ID)]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["dlp_secret_association_changes"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_sensor_or_file_pattern_changes_after_preview() -> None:
    transport = FakeDlpSensorTransport()
    workflow = DlpSensorLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.binding_matches = False

    with pytest.raises(DlpSensorLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_execute_rechecks_prewrite_state_and_rejects_drift() -> None:
    transport = FakeDlpSensorTransport()
    workflow = DlpSensorLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.sensor_exists = True

    with pytest.raises(DlpSensorLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )

    assert transport.create_calls == []


def test_readback_failure_requires_reconciliation() -> None:
    transport = FakeDlpSensorTransport()
    transport.readback = DlpSensorReadback(True, True, True, True, True, True, False)
    workflow = DlpSensorLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(DlpSensorLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_missing_or_out_of_scope_inputs() -> None:
    transport = FakeDlpSensorTransport()
    workflow = DlpSensorLiveWorkflow(transport)

    with pytest.raises(DlpSensorLiveWorkflowError):
        workflow.preview(
            sensor_name="dlp-sensor",
            file_pattern_id=PATTERN_ID,
            file_pattern_name=PATTERN_NAME,
            requester_digest=REQUESTER,
        )
    with pytest.raises(DlpSensorLiveWorkflowError):
        workflow.preview(
            sensor_name=SENSOR_NAME,
            file_pattern_id=999,
            file_pattern_name=PATTERN_NAME,
            requester_digest=REQUESTER,
        )
    transport.pattern_id_exists = False
    with pytest.raises(DlpSensorLiveWorkflowError):
        _preview(workflow)
