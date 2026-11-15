from __future__ import annotations

import pytest

from fortipam_mcp.password_policy_delete_live_workflow import (
    PasswordPolicyDeleteLiveWorkflow,
    PasswordPolicyDeleteLiveWorkflowError,
)
from fortipam_mcp.password_policy_http_transport import (
    PasswordPolicyDeleteInspection,
    PasswordPolicyDeleteReadback,
)


REQUESTER = "a" * 64
TARGET_DIGEST = "b" * 64


class _Transport:
    def __init__(self) -> None:
        self.exists = True
        self.eligible = True
        self.target_digest = TARGET_DIGEST
        self.delete_calls: list[str] = []
        self.readback = PasswordPolicyDeleteReadback(True)

    def inspect_delete_target(self) -> PasswordPolicyDeleteInspection:
        return PasswordPolicyDeleteInspection(
            self.exists,
            self.eligible,
            self.target_digest,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> PasswordPolicyDeleteReadback:
        self.delete_calls.append(expected_target_digest)
        self.exists = False
        return self.readback


def _preview(workflow: PasswordPolicyDeleteLiveWorkflow) -> dict[str, object]:
    return workflow.preview(requester_digest=REQUESTER)


def test_preview_is_fixed_destructive_cpe_without_name_or_policy_body() -> None:
    preview = _preview(PasswordPolicyDeleteLiveWorkflow(_Transport(), clock=lambda: 100))

    assert preview["Current State"] == {
        "accepted_password_policy_exists": True,
        "exact_fixed_policy_observed": True,
        "known_association_changes_since_create": False,
        "read_transport": "rest_api",
    }
    assert preview["Proposed Changes"] == {
        "operation": "delete_exact_accepted_password_policy_via_api",
        "password_policy_count_affected": 1,
        "irreversible_after_execution": True,
        "password_values_generated_or_handled": False,
        "template_or_secret_association_changes": False,
    }
    assert preview["Expected State"]["accepted_password_policy_absent"] is True
    assert preview["device_write_executed"] is False
    assert "mcp-v4-password-policy" not in repr(preview)


def test_execute_requires_confirmation_and_is_idempotent_after_success() -> None:
    transport = _Transport()
    workflow = PasswordPolicyDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "succeeded"
    assert result["password_policy_name_returned"] is False
    assert transport.delete_calls == [TARGET_DIGEST]
    assert replay["idempotent_replay"] is True


def test_target_drift_or_ineligible_policy_is_rejected_before_delete() -> None:
    transport = _Transport()
    workflow = PasswordPolicyDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.target_digest = "c" * 64
    with pytest.raises(PasswordPolicyDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.delete_calls == []

    transport = _Transport()
    workflow = PasswordPolicyDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )
    transport.eligible = False
    with pytest.raises(PasswordPolicyDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )
    assert transport.delete_calls == []


def test_unverified_absence_requires_reconciliation_without_replay() -> None:
    transport = _Transport()
    transport.readback = PasswordPolicyDeleteReadback(False)
    workflow = PasswordPolicyDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    with pytest.raises(PasswordPolicyDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )


def test_absent_target_and_wrong_requester_fail_closed() -> None:
    transport = _Transport()
    workflow = PasswordPolicyDeleteLiveWorkflow(transport)
    transport.exists = False
    with pytest.raises(PasswordPolicyDeleteLiveWorkflowError):
        _preview(workflow)
    transport.exists = True
    with pytest.raises(PasswordPolicyDeleteLiveWorkflowError):
        workflow.preview(requester_digest="invalid")
