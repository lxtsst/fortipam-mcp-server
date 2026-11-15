from __future__ import annotations

import pytest

from fortipam_mcp.dlp_file_pattern_live_workflow import (
    DlpFilePatternLiveWorkflow,
    DlpFilePatternLiveWorkflowError,
)
from fortipam_mcp.dlp_file_pattern_ssh_transport import (
    DlpFilePatternInspection,
    DlpFilePatternReadback,
)


REQUESTER = "a" * 64
PATTERN_ID = 1001
PATTERN_NAME = "mcp-v4-dlp-pattern-01"


class FakeDlpFilePatternTransport:
    def __init__(self) -> None:
        self.id_exists = False
        self.name_exists = False
        self.create_calls: list[tuple[int, str]] = []
        self.readback = DlpFilePatternReadback(True, True, True)

    def inspect(
        self,
        pattern_id: int,
        pattern_name: str,
    ) -> DlpFilePatternInspection:
        return DlpFilePatternInspection(self.id_exists, self.name_exists)

    def create_and_readback(
        self,
        pattern_id: int,
        pattern_name: str,
    ) -> DlpFilePatternReadback:
        self.create_calls.append((pattern_id, pattern_name))
        self.id_exists = True
        self.name_exists = True
        return self.readback


def _preview(workflow: DlpFilePatternLiveWorkflow) -> dict[str, object]:
    return workflow.preview(
        pattern_id=PATTERN_ID,
        pattern_name=PATTERN_NAME,
        requester_digest=REQUESTER,
    )


def test_preview_is_live_cpe_and_excludes_sensor_secret_and_credentials() -> None:
    workflow = DlpFilePatternLiveWorkflow(
        FakeDlpFilePatternTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_pattern_id": PATTERN_ID,
        "requested_pattern_name": PATTERN_NAME,
        "pattern_id_exists": False,
        "pattern_name_exists": False,
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_single_pdf_dlp_file_pattern",
        "pattern_id": PATTERN_ID,
        "pattern_name": PATTERN_NAME,
        "configuration_profile": "single_pdf_file_type_v1",
        "dlp_sensor_or_secret_changes": False,
    }
    assert preview["Expected State"] == {
        "pattern_id_matches": True,
        "pattern_id_exists": True,
        "pattern_name_matches": True,
        "pdf_file_type_entry_matches": True,
        "dlp_sensor_or_secret_changes": False,
    }
    assert preview["device_write_executed"] is False
    assert "password" not in repr(preview).lower()


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeDlpFilePatternTransport()
    workflow = DlpFilePatternLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(DlpFilePatternLiveWorkflowError):
        workflow.execute(
            "dlp-file-pattern-authorized-missing",
            requester_digest=REQUESTER,
        )

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.create_calls == [(PATTERN_ID, PATTERN_NAME)]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["dlp_sensor_or_secret_changes"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_id_or_name_appears_after_preview() -> None:
    transport = FakeDlpFilePatternTransport()
    workflow = DlpFilePatternLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.name_exists = True

    with pytest.raises(DlpFilePatternLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_execute_rechecks_absence_and_rejects_prewrite_drift() -> None:
    transport = FakeDlpFilePatternTransport()
    workflow = DlpFilePatternLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.id_exists = True

    with pytest.raises(DlpFilePatternLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )

    assert transport.create_calls == []


def test_readback_failure_requires_reconciliation() -> None:
    transport = FakeDlpFilePatternTransport()
    transport.readback = DlpFilePatternReadback(True, True, False)
    workflow = DlpFilePatternLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(DlpFilePatternLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_out_of_range_or_unprefixed_inputs() -> None:
    transport = FakeDlpFilePatternTransport()
    workflow = DlpFilePatternLiveWorkflow(transport)

    with pytest.raises(DlpFilePatternLiveWorkflowError):
        workflow.preview(
            pattern_id=999,
            pattern_name=PATTERN_NAME,
            requester_digest=REQUESTER,
        )
    with pytest.raises(DlpFilePatternLiveWorkflowError):
        workflow.preview(
            pattern_id=PATTERN_ID,
            pattern_name="pdf-pattern",
            requester_digest=REQUESTER,
        )
    transport.id_exists = True
    with pytest.raises(DlpFilePatternLiveWorkflowError):
        _preview(workflow)
