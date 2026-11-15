from __future__ import annotations

import pytest

from fortipam_mcp.dlp_regexp_sensor_live_workflow import (
    DlpRegexpSensorLiveWorkflow,
    DlpRegexpSensorLiveWorkflowError,
)
from fortipam_mcp.dlp_sensor_ssh_transport import (
    DlpRegexpSensorInspection,
    DlpRegexpSensorReadback,
)


REQUESTER = "a" * 64
SENSOR_NAME = "mcp-v4-dlp-regexp-sensor-01"


class FakeDlpRegexpSensorTransport:
    def __init__(self) -> None:
        self.sensor_exists = False
        self.create_calls: list[str] = []
        self.readback = DlpRegexpSensorReadback(
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
        )

    def inspect_regexp_sensor(self, sensor_name: str) -> DlpRegexpSensorInspection:
        assert sensor_name == SENSOR_NAME
        return DlpRegexpSensorInspection(self.sensor_exists)

    def create_regexp_and_readback(self, sensor_name: str) -> DlpRegexpSensorReadback:
        assert sensor_name == SENSOR_NAME
        self.create_calls.append(sensor_name)
        self.sensor_exists = True
        return self.readback


def _preview(workflow: DlpRegexpSensorLiveWorkflow) -> dict[str, object]:
    return workflow.preview(sensor_name=SENSOR_NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_never_returns_the_regexp_value() -> None:
    workflow = DlpRegexpSensorLiveWorkflow(
        FakeDlpRegexpSensorTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_sensor_name": SENSOR_NAME,
        "sensor_name_exists": False,
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_single_http_get_file_regexp_block_dlp_sensor",
        "sensor_name": SENSOR_NAME,
        "configuration_profile": "single_http_get_file_regexp_block_v1",
        "protocol": "http-get",
        "filter_type": "file",
        "filter_by": "regexp",
        "regexp_pattern_class": "fixed_lab_sentinel",
        "regexp_value_returned": False,
        "action": "block",
        "dlp_secret_association_changes": False,
    }
    assert preview["Expected State"]["sensor_name_matches"] is True
    assert preview["Expected State"]["regexp_matches"] is True
    assert preview["device_write_executed"] is False
    assert "MCP_V4_DLP_REGEX_SENTINEL" not in repr(preview)
    assert "password" not in repr(preview).lower()


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeDlpRegexpSensorTransport()
    workflow = DlpRegexpSensorLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(DlpRegexpSensorLiveWorkflowError):
        workflow.execute(
            "dlp-regexp-sensor-authorized-missing",
            requester_digest=REQUESTER,
        )

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.create_calls == [SENSOR_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["regexp_value_returned"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_sensor_changes_after_preview() -> None:
    transport = FakeDlpRegexpSensorTransport()
    workflow = DlpRegexpSensorLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.sensor_exists = True

    with pytest.raises(DlpRegexpSensorLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_execute_rechecks_prewrite_state_and_rejects_drift() -> None:
    transport = FakeDlpRegexpSensorTransport()
    workflow = DlpRegexpSensorLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.sensor_exists = True

    with pytest.raises(DlpRegexpSensorLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )

    assert transport.create_calls == []


def test_readback_failure_requires_reconciliation() -> None:
    transport = FakeDlpRegexpSensorTransport()
    transport.readback = DlpRegexpSensorReadback(
        True,
        True,
        True,
        True,
        True,
        True,
        False,
        True,
    )
    workflow = DlpRegexpSensorLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(DlpRegexpSensorLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_or_out_of_scope_sensor_name() -> None:
    transport = FakeDlpRegexpSensorTransport()
    workflow = DlpRegexpSensorLiveWorkflow(transport)

    with pytest.raises(DlpRegexpSensorLiveWorkflowError):
        workflow.preview(sensor_name="dlp-sensor", requester_digest=REQUESTER)
    transport.sensor_exists = True
    with pytest.raises(DlpRegexpSensorLiveWorkflowError):
        _preview(workflow)
