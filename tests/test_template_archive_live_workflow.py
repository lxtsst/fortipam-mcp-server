from __future__ import annotations

import pytest

from fortipam_mcp.template_archive_http_transport import TemplateArchiveDeleteReadback
from fortipam_mcp.template_archive_live_workflow import (
    TemplateArchiveLiveWorkflow,
    TemplateArchiveLiveWorkflowError,
)
from fortipam_mcp.template_ssh_transport import (
    TemplateArchiveAbsenceReadback,
    TemplateArchivePreflightReadback,
)


REQUESTER = "a" * 64
NAME = "mcp-v4-template-archive-01"


def _preflight(*, target_references_absent: bool = True) -> TemplateArchivePreflightReadback:
    return TemplateArchivePreflightReadback(
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        target_references_absent,
    )


class _InspectionTransport:
    def __init__(self) -> None:
        self.preflight = _preflight()
        self.absence = TemplateArchiveAbsenceReadback(True, True, True)
        self.preflight_calls: list[str] = []
        self.absence_calls: list[str] = []

    def archive_preflight_readback(self, template_name: str) -> TemplateArchivePreflightReadback:
        self.preflight_calls.append(template_name)
        return self.preflight

    def archive_absence_readback(self, template_name: str) -> TemplateArchiveAbsenceReadback:
        self.absence_calls.append(template_name)
        return self.absence


class _DeleteTransport:
    def __init__(self) -> None:
        self.result = TemplateArchiveDeleteReadback(True)
        self.calls: list[str] = []

    def delete_template(self, template_name: str) -> TemplateArchiveDeleteReadback:
        self.calls.append(template_name)
        return self.result


def _preview(workflow: TemplateArchiveLiveWorkflow) -> dict[str, object]:
    return workflow.preview(template_name=NAME, requester_digest=REQUESTER)


def test_preview_requires_exact_unreferenced_baseline_and_discloses_irreversibility() -> None:
    inspection = _InspectionTransport()
    workflow = TemplateArchiveLiveWorkflow(
        inspection,
        _DeleteTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_template_name": NAME,
        "template_exists": True,
        "known_web_vnc_create_baseline_verified": True,
        "secret_reference_absent": True,
        "target_reference_absent": True,
        "write_transport": "rest_api",
    }
    assert preview["Proposed Changes"]["template_name"] == NAME
    assert preview["Proposed Changes"]["irreversible_after_execution"] is True
    assert preview["Expected State"]["template_name_absent"] is True
    assert preview["Expected State"]["template_exists"] is False
    assert preview["device_write_executed"] is False

    inspection.preflight = _preflight(target_references_absent=False)
    with pytest.raises(TemplateArchiveLiveWorkflowError):
        _preview(workflow)


def test_execute_requires_one_confirmation_and_performs_one_rest_delete() -> None:
    inspection = _InspectionTransport()
    deletion = _DeleteTransport()
    workflow = TemplateArchiveLiveWorkflow(inspection, deletion, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(TemplateArchiveLiveWorkflowError):
        workflow.execute("template-archive-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert deletion.calls == [NAME]
    assert inspection.absence_calls == [NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["template_name_returned"] is False
    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert deletion.calls == [NAME]


def test_confirm_and_execution_reject_prewrite_reference_drift() -> None:
    inspection = _InspectionTransport()
    workflow = TemplateArchiveLiveWorkflow(inspection, _DeleteTransport(), clock=lambda: 100)
    preview = _preview(workflow)
    inspection.preflight = _preflight(target_references_absent=False)

    with pytest.raises(TemplateArchiveLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert workflow._records[str(preview["preview_ref"])].state == "invalidated"


def test_unverified_delete_or_absence_requires_reconciliation() -> None:
    inspection = _InspectionTransport()
    deletion = _DeleteTransport()
    workflow = TemplateArchiveLiveWorkflow(inspection, deletion, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    deletion.result = TemplateArchiveDeleteReadback(False)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(TemplateArchiveLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_non_archive_name_or_nonrequester() -> None:
    workflow = TemplateArchiveLiveWorkflow(_InspectionTransport(), _DeleteTransport())

    with pytest.raises(TemplateArchiveLiveWorkflowError):
        workflow.preview(template_name="mcp-v4-template-01", requester_digest=REQUESTER)
    with pytest.raises(TemplateArchiveLiveWorkflowError):
        workflow.preview(template_name=NAME, requester_digest=object())  # type: ignore[arg-type]
