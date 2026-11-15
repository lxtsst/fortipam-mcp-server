from __future__ import annotations

import pytest

from fortipam_mcp.character_set_http_transport import (
    CHARACTER_SET_VALUE,
    CharacterSetInspection,
    CharacterSetReadback,
)
from fortipam_mcp.character_set_live_workflow import (
    CharacterSetCreateLiveWorkflow,
    CharacterSetLiveWorkflowError,
)


REQUESTER = "a" * 64
NAME = "mcp-v4-char-set-01"


class _Transport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[str] = []
        self.readback = CharacterSetReadback(True, True, True)

    def inspect(self, name: str) -> CharacterSetInspection:
        assert name == NAME
        return CharacterSetInspection(self.exists)

    def create_and_readback(self, name: str) -> CharacterSetReadback:
        assert name == NAME
        self.create_calls.append(name)
        self.exists = True
        return self.readback


def _preview(workflow: CharacterSetCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(name=NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_includes_non_secret_declared_inputs() -> None:
    workflow = CharacterSetCreateLiveWorkflow(_Transport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_character_set_name": NAME,
        "character_set_exists": False,
        "write_transport": "rest_api",
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_documented_symbol_character_set_via_api",
        "character_set_name": NAME,
        "character_set_value": CHARACTER_SET_VALUE,
        "configuration_profile": "documented-symbol-set-v1",
        "password_policy_or_template_association_changes": False,
    }
    assert preview["Expected State"] == {
        "character_set_exists": True,
        "character_set_name_matches": True,
        "character_set_value_matches": True,
        "password_policy_or_template_association_changes": False,
        "readback_transport": "rest_api",
    }
    assert NAME in str(preview)
    assert CHARACTER_SET_VALUE in str(preview)
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_is_idempotent_after_success() -> None:
    transport = _Transport()
    workflow = CharacterSetCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(CharacterSetLiveWorkflowError):
        workflow.execute("character-set-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.create_calls == [NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["character_set_name_returned"] is False
    assert result["character_set_value_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirmation_and_execution_reject_current_state_drift() -> None:
    transport = _Transport()
    workflow = CharacterSetCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(CharacterSetLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    transport = _Transport()
    workflow = CharacterSetCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.exists = True
    with pytest.raises(CharacterSetLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )
    assert transport.create_calls == []


def test_unverifiable_readback_requires_reconciliation_without_replay() -> None:
    transport = _Transport()
    transport.readback = CharacterSetReadback(True, True, False)
    workflow = CharacterSetCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(CharacterSetLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_out_of_scope_or_invalid_requester() -> None:
    transport = _Transport()
    workflow = CharacterSetCreateLiveWorkflow(transport)

    with pytest.raises(CharacterSetLiveWorkflowError):
        workflow.preview(name="global-character-set", requester_digest=REQUESTER)
    with pytest.raises(CharacterSetLiveWorkflowError):
        workflow.preview(name=NAME, requester_digest=object())  # type: ignore[arg-type]
    transport.exists = True
    with pytest.raises(CharacterSetLiveWorkflowError):
        _preview(workflow)
