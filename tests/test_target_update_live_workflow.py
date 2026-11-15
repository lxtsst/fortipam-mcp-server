from __future__ import annotations

import pytest

from fortipam_mcp.target_contract import TargetUpdateInspection, TargetUpdateReadback
from fortipam_mcp.target_update_live_workflow import (
    TargetDescriptionUpdateLiveWorkflow,
    TargetDescriptionUpdateLiveWorkflowError,
)


REQUESTER = "a" * 64


class FakeTargetDescriptionTransport:
    def __init__(self) -> None:
        self.exists = True
        self.description = "old description"
        self.update_calls: list[tuple[str, str]] = []
        self.readback = TargetUpdateReadback(True, True)

    def inspect_description_update(
        self,
        target_name: str,
        description: str,
    ) -> TargetUpdateInspection:
        return TargetUpdateInspection(
            exists=self.exists,
            description_matches=self.description == description,
            state_digest=f"state:{self.exists}:{self.description}",
        )

    def update_description_and_readback(
        self,
        target_name: str,
        description: str,
    ) -> TargetUpdateReadback:
        self.update_calls.append((target_name, description))
        self.description = description
        return self.readback


def _preview(workflow: TargetDescriptionUpdateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(
        target_name="mcp-target-01",
        description="new description",
        requester_digest=REQUESTER,
    )


def test_preview_is_live_cpe_and_shows_requested_non_secret_update() -> None:
    workflow = TargetDescriptionUpdateLiveWorkflow(
        FakeTargetDescriptionTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_target_name": "mcp-target-01",
        "target_exists": True,
        "requested_description_already_matches": False,
        "write_transport": "rest_api",
    }
    assert preview["Proposed Changes"] == {
        "operation": "update_target_description_via_api",
        "target_name": "mcp-target-01",
        "requested_description": "new description",
    }
    assert preview["Expected State"] == {
        "target_exists": True,
        "target_name_matches": True,
        "description_matches_requested_value": True,
    }
    assert "mcp-target-01" in str(preview)
    assert "new description" in str(preview)
    assert preview["device_write_executed"] is False


def test_execute_requires_confirmation_and_performs_one_api_update() -> None:
    transport = FakeTargetDescriptionTransport()
    workflow = TargetDescriptionUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(TargetDescriptionUpdateLiveWorkflowError):
        workflow.execute("target-update-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.update_calls == [("mcp-target-01", "new description")]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["target_name_returned"] is False
    assert result["description_returned"] is False
    assert result["raw_api_response_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.update_calls) == 1


def test_confirm_invalidates_when_description_changes() -> None:
    transport = FakeTargetDescriptionTransport()
    workflow = TargetDescriptionUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.description = "changed elsewhere"

    with pytest.raises(TargetDescriptionUpdateLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.update_calls == []


@pytest.mark.parametrize("phase", ["confirm", "execute"])
def test_expiry_during_current_state_read_refuses_authorization_and_write(
    phase: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [100]
    transport = FakeTargetDescriptionTransport()
    workflow = TargetDescriptionUpdateLiveWorkflow(transport, clock=lambda: now[0])
    preview = _preview(workflow)
    reference = str(preview["preview_ref"])
    if phase == "execute":
        confirmation = workflow.confirm(reference, requester_digest=REQUESTER)
        reference = str(confirmation["authorization_ref"])
    expires_at = int(str(preview["expires_at"]))
    now[0] = expires_at - 1
    inspect = transport.inspect_description_update

    def expire_during_query(
        target_name: str, description: str,
    ) -> TargetUpdateInspection:
        current = inspect(target_name, description)
        now[0] = expires_at
        return current

    monkeypatch.setattr(transport, "inspect_description_update", expire_during_query)
    with pytest.raises(TargetDescriptionUpdateLiveWorkflowError):
        if phase == "confirm":
            workflow.confirm(reference, requester_digest=REQUESTER)
        else:
            workflow.execute(reference, requester_digest=REQUESTER)

    assert now[0] == expires_at
    assert transport.update_calls == []


def test_failed_readback_requires_reconciliation_without_replay() -> None:
    transport = FakeTargetDescriptionTransport()
    transport.readback = TargetUpdateReadback(True, False)
    workflow = TargetDescriptionUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(TargetDescriptionUpdateLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_missing_target_noop_or_unsafe_description() -> None:
    transport = FakeTargetDescriptionTransport()
    workflow = TargetDescriptionUpdateLiveWorkflow(transport)

    transport.exists = False
    with pytest.raises(TargetDescriptionUpdateLiveWorkflowError):
        _preview(workflow)
    transport.exists = True
    transport.description = "new description"
    with pytest.raises(TargetDescriptionUpdateLiveWorkflowError):
        _preview(workflow)
    with pytest.raises(TargetDescriptionUpdateLiveWorkflowError):
        workflow.preview(
            target_name="unsafe name",
            description="new description",
            requester_digest=REQUESTER,
        )
    with pytest.raises(TargetDescriptionUpdateLiveWorkflowError):
        workflow.preview(
            target_name="mcp-target-01",
            description="unsafe\nvalue",
            requester_digest=REQUESTER,
        )
