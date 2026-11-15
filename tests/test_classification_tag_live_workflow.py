from __future__ import annotations

import pytest

from fortipam_mcp.classification_tag_http_transport import (
    ClassificationTagInspection,
    ClassificationTagReadback,
)
from fortipam_mcp.classification_tag_live_workflow import (
    ClassificationTagCreateLiveWorkflow,
    ClassificationTagLiveWorkflowError,
)


REQUESTER = "a" * 64


class _Transport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[tuple[str, str]] = []
        self.readback = ClassificationTagReadback(True, True, True)

    def inspect(self, name: str) -> ClassificationTagInspection:
        return ClassificationTagInspection(self.exists)

    def create_and_readback(self, name: str, description: str) -> ClassificationTagReadback:
        self.create_calls.append((name, description))
        self.exists = True
        return self.readback


def _preview(workflow: ClassificationTagCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(
        name="mcp-classification-tag-01",
        description="Lab ownership marker",
        requester_digest=REQUESTER,
    )


def test_preview_is_live_cpe_and_shows_requested_non_secret_tag_values() -> None:
    workflow = ClassificationTagCreateLiveWorkflow(_Transport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_classification_tag_name": "mcp-classification-tag-01",
        "requested_classification_tag_description": "Lab ownership marker",
        "classification_tag_exists": False,
        "write_transport": "rest_api",
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_classification_tag_via_api",
        "classification_tag_name": "mcp-classification-tag-01",
        "classification_tag_description": "Lab ownership marker",
        "request_body": "fixed_name_and_description_only",
    }
    assert preview["Expected State"] == {
        "classification_tag_exists": True,
        "classification_tag_name_matches": True,
        "description_matches": True,
        "readback_transport": "rest_api",
    }
    assert "mcp-classification-tag-01" in str(preview)
    assert "Lab ownership marker" in str(preview)
    assert preview["device_write_executed"] is False


def test_execute_requires_confirmation_and_is_idempotent_after_success() -> None:
    transport = _Transport()
    workflow = ClassificationTagCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(ClassificationTagLiveWorkflowError):
        workflow.execute("classification-tag-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.create_calls == [
        ("mcp-classification-tag-01", "Lab ownership marker")
    ]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["classification_tag_name_returned"] is False
    assert result["description_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirmation_rejects_current_state_drift() -> None:
    transport = _Transport()
    workflow = ClassificationTagCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(ClassificationTagLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_unverifiable_readback_requires_reconciliation_without_replay() -> None:
    transport = _Transport()
    transport.readback = ClassificationTagReadback(True, True, False)
    workflow = ClassificationTagCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(ClassificationTagLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)
