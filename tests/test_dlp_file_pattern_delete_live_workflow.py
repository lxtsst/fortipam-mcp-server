from __future__ import annotations

import pytest

from fortipam_mcp.dlp_file_pattern_delete_http_transport import (
    DlpFilePatternDeleteInspection,
    DlpFilePatternDeleteReadback,
)
from fortipam_mcp.dlp_file_pattern_delete_live_workflow import (
    DlpFilePatternDeleteLiveWorkflow,
    DlpFilePatternDeleteLiveWorkflowError,
)


REQUESTER = "a" * 64
TARGET_DIGEST = "b" * 64
REGEXP_DIGEST = "c" * 64


class _Transport:
    def __init__(self) -> None:
        self.exists = True
        self.eligible = True
        self.rest_references = 0
        self.ssh_references = 0
        self.target_digest = TARGET_DIGEST
        self.regexp_digest = REGEXP_DIGEST
        self.delete_calls: list[tuple[str, str]] = []
        self.readback = DlpFilePatternDeleteReadback(True, True, True, True)

    def inspect_delete_target(self) -> DlpFilePatternDeleteInspection:
        return DlpFilePatternDeleteInspection(
            self.exists,
            self.eligible,
            self.rest_references,
            self.ssh_references,
            self.target_digest,
            self.regexp_digest,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
        expected_regexp_sensor_digest: str,
    ) -> DlpFilePatternDeleteReadback:
        self.delete_calls.append(
            (expected_target_digest, expected_regexp_sensor_digest)
        )
        self.exists = False
        return self.readback


def _preview(workflow: DlpFilePatternDeleteLiveWorkflow) -> dict[str, object]:
    return workflow.preview(requester_digest=REQUESTER)


def test_preview_is_fixed_destructive_cpe_without_id_name_or_content() -> None:
    preview = _preview(DlpFilePatternDeleteLiveWorkflow(_Transport(), clock=lambda: 100))

    assert preview["Current State"] == {
        "accepted_dlp_file_pattern_exists": True,
        "exact_fixed_single_pdf_pattern_observed": True,
        "complete_api_record_digest_matches": True,
        "sensor_reference_count_rest": 0,
        "sensor_reference_count_ssh": 0,
        "fixed_regexp_sensor_present": True,
        "read_transports": ["rest_api", "ssh_cli"],
    }
    assert preview["Proposed Changes"] == {
        "operation": "delete_exact_unreferenced_dlp_file_pattern_via_api",
        "dlp_file_pattern_count_affected": 1,
        "irreversible_after_execution": True,
        "dlp_sensor_changes": False,
        "secret_or_policy_association_changes": False,
        "license_or_session_changes": False,
    }
    assert preview["Expected State"]["fixed_regexp_sensor_preserved"] is True  # type: ignore[index]
    assert preview["device_write_executed"] is False
    assert "1000" not in repr(preview)
    assert "mcp-v4-dlp" not in repr(preview)


def test_execute_requires_confirmation_and_replays_only_verified_result() -> None:
    transport = _Transport()
    workflow = DlpFilePatternDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "succeeded"
    assert result["dlp_file_pattern_id_or_name_returned"] is False
    assert result["dlp_sensor_changes"] is False
    assert transport.delete_calls == [(TARGET_DIGEST, REGEXP_DIGEST)]
    assert replay["idempotent_replay"] is True


def test_drift_or_new_dependency_rejects_before_delete() -> None:
    transport = _Transport()
    workflow = DlpFilePatternDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.regexp_digest = "d" * 64
    with pytest.raises(DlpFilePatternDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.delete_calls == []

    transport = _Transport()
    workflow = DlpFilePatternDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.rest_references = 1
    transport.eligible = False
    with pytest.raises(DlpFilePatternDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )
    assert transport.delete_calls == []


def test_unverified_readback_requires_reconciliation_without_replay() -> None:
    transport = _Transport()
    transport.readback = DlpFilePatternDeleteReadback(True, True, True, False)
    workflow = DlpFilePatternDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    with pytest.raises(DlpFilePatternDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )


def test_absent_referenced_expired_and_wrong_requester_fail_closed() -> None:
    transport = _Transport()
    now = 100
    workflow = DlpFilePatternDeleteLiveWorkflow(transport, clock=lambda: now)
    transport.exists = False
    with pytest.raises(DlpFilePatternDeleteLiveWorkflowError):
        _preview(workflow)
    transport.exists = True
    transport.ssh_references = 1
    transport.eligible = False
    with pytest.raises(DlpFilePatternDeleteLiveWorkflowError):
        _preview(workflow)
    transport.ssh_references = 0
    transport.eligible = True
    with pytest.raises(DlpFilePatternDeleteLiveWorkflowError):
        workflow.preview(requester_digest="invalid")

    preview = _preview(workflow)
    now = 701
    with pytest.raises(DlpFilePatternDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
