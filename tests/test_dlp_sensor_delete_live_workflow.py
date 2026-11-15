from __future__ import annotations

import pytest

from fortipam_mcp.dlp_sensor_delete_http_transport import (
    DlpSensorDeleteInspection,
    DlpSensorDeleteReadback,
)
from fortipam_mcp.dlp_sensor_delete_live_workflow import (
    DlpSensorDeleteLiveWorkflow,
    DlpSensorDeleteLiveWorkflowError,
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
        self.readback = DlpSensorDeleteReadback(True, True, True)

    def inspect_delete_target(self) -> DlpSensorDeleteInspection:
        return DlpSensorDeleteInspection(
            self.exists,
            self.eligible,
            self.secret_references,
            self.policy_references,
            self.target_digest,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> DlpSensorDeleteReadback:
        self.delete_calls.append(expected_target_digest)
        self.exists = False
        return self.readback


def _preview(workflow: DlpSensorDeleteLiveWorkflow) -> dict[str, object]:
    return workflow.preview(requester_digest=REQUESTER)


def test_preview_is_fixed_destructive_cpe_without_name_or_content() -> None:
    preview = _preview(DlpSensorDeleteLiveWorkflow(_Transport(), clock=lambda: 100))

    assert preview["Current State"] == {
        "accepted_dlp_sensor_exists": True,
        "exact_fixed_http_get_pdf_block_sensor_observed": True,
        "complete_api_record_digest_matches": True,
        "secret_reference_count": 0,
        "policy_reference_count": 0,
        "file_pattern_binding_present": True,
        "read_transports": ["rest_api", "ssh_cli"],
    }
    assert preview["Proposed Changes"] == {
        "operation": "delete_exact_unreferenced_dlp_sensor_via_api",
        "dlp_sensor_count_affected": 1,
        "irreversible_after_execution": True,
        "file_pattern_changes": False,
        "regexp_sensor_changes": False,
        "secret_or_policy_association_changes": False,
        "license_or_session_changes": False,
    }
    assert preview["Expected State"]["file_pattern_preserved"] is True  # type: ignore[index]
    assert preview["device_write_executed"] is False
    assert "mcp-v4-dlp" not in repr(preview)


def test_execute_requires_confirmation_and_replays_only_verified_result() -> None:
    transport = _Transport()
    workflow = DlpSensorDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "succeeded"
    assert result["dlp_sensor_name_returned"] is False
    assert result["file_pattern_changes"] is False
    assert transport.delete_calls == [TARGET_DIGEST]
    assert replay["idempotent_replay"] is True


def test_drift_or_new_dependency_rejects_before_delete() -> None:
    transport = _Transport()
    workflow = DlpSensorDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.target_digest = "c" * 64
    with pytest.raises(DlpSensorDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.delete_calls == []

    transport = _Transport()
    workflow = DlpSensorDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.secret_references = 1
    transport.eligible = False
    with pytest.raises(DlpSensorDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )
    assert transport.delete_calls == []


def test_unverified_readback_requires_reconciliation_without_replay() -> None:
    transport = _Transport()
    transport.readback = DlpSensorDeleteReadback(True, True, False)
    workflow = DlpSensorDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    with pytest.raises(DlpSensorDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )


def test_absent_referenced_expired_and_wrong_requester_fail_closed() -> None:
    transport = _Transport()
    now = 100
    workflow = DlpSensorDeleteLiveWorkflow(transport, clock=lambda: now)
    transport.exists = False
    with pytest.raises(DlpSensorDeleteLiveWorkflowError):
        _preview(workflow)
    transport.exists = True
    transport.policy_references = 1
    transport.eligible = False
    with pytest.raises(DlpSensorDeleteLiveWorkflowError):
        _preview(workflow)
    transport.policy_references = 0
    transport.eligible = True
    with pytest.raises(DlpSensorDeleteLiveWorkflowError):
        workflow.preview(requester_digest="invalid")

    preview = _preview(workflow)
    now = 701
    with pytest.raises(DlpSensorDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
