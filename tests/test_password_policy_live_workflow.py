from __future__ import annotations

import pytest

from fortipam_mcp.password_policy_http_transport import (
    MAXIMUM_LENGTH,
    MINIMUM_LENGTH,
    PASSWORD_REQUIREMENTS,
    PasswordPolicyInspection,
    PasswordPolicyReadback,
)
from fortipam_mcp.password_policy_live_workflow import (
    PasswordPolicyCreateLiveWorkflow,
    PasswordPolicyLiveWorkflowError,
)


REQUESTER = "a" * 64
NAME = "mcp-v4-password-policy-01"


class _Transport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[str] = []
        self.readback = PasswordPolicyReadback(True, True, True, True)

    def inspect(self, name: str) -> PasswordPolicyInspection:
        assert name == NAME
        return PasswordPolicyInspection(self.exists)

    def create_and_readback(self, name: str) -> PasswordPolicyReadback:
        assert name == NAME
        self.create_calls.append(name)
        self.exists = True
        return self.readback


def _preview(workflow: PasswordPolicyCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(name=NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_includes_non_secret_declared_inputs() -> None:
    workflow = PasswordPolicyCreateLiveWorkflow(_Transport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_password_policy_name": NAME,
        "password_policy_exists": False,
        "write_transport": "rest_api",
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_four_default_set_password_policy_via_api",
        "password_policy_name": NAME,
        "configuration_profile": "four-default-sets-length-12-to-16-v1",
        "minimum_length": MINIMUM_LENGTH,
        "maximum_length": MAXIMUM_LENGTH,
        "password_requirements": [
            {
                "id": item_id,
                "character_set": char_set,
                "minimum_num": minimum_num,
            }
            for item_id, char_set, minimum_num in PASSWORD_REQUIREMENTS
        ],
        "password_values_generated_or_handled": False,
        "template_or_secret_association_changes": False,
    }
    assert preview["Expected State"] == {
        "password_policy_exists": True,
        "password_policy_name_matches": True,
        "minimum_length_matches": True,
        "maximum_length_matches": True,
        "four_default_set_requirements_match": True,
        "password_values_generated_or_handled": False,
        "template_or_secret_association_changes": False,
        "readback_transport": "rest_api",
    }
    assert NAME in str(preview)
    assert "lower" in str(preview)
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_is_idempotent_after_success() -> None:
    transport = _Transport()
    workflow = PasswordPolicyCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(PasswordPolicyLiveWorkflowError):
        workflow.execute("password-policy-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.create_calls == [NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["password_policy_name_returned"] is False
    assert result["password_requirement_values_returned"] is False
    assert result["password_values_generated_or_handled"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirmation_and_execution_reject_current_state_drift() -> None:
    transport = _Transport()
    workflow = PasswordPolicyCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(PasswordPolicyLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    transport = _Transport()
    workflow = PasswordPolicyCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.exists = True
    with pytest.raises(PasswordPolicyLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]), requester_digest=REQUESTER
        )
    assert transport.create_calls == []


def test_unverifiable_readback_requires_reconciliation_without_replay() -> None:
    transport = _Transport()
    transport.readback = PasswordPolicyReadback(True, True, True, False)
    workflow = PasswordPolicyCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(PasswordPolicyLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_out_of_scope_or_invalid_requester() -> None:
    transport = _Transport()
    workflow = PasswordPolicyCreateLiveWorkflow(transport)

    with pytest.raises(PasswordPolicyLiveWorkflowError):
        workflow.preview(name="global-password-policy", requester_digest=REQUESTER)
    with pytest.raises(PasswordPolicyLiveWorkflowError):
        workflow.preview(name=NAME, requester_digest=object())  # type: ignore[arg-type]
    transport.exists = True
    with pytest.raises(PasswordPolicyLiveWorkflowError):
        _preview(workflow)
