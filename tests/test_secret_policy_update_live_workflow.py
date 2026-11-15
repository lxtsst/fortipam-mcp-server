from __future__ import annotations

from typing import cast

import pytest

from fortipam_mcp.secret_policy_ssh_transport import (
    SecretPolicyUpdateBaseline,
    SecretPolicyUpdateReadback,
)
from fortipam_mcp.secret_policy_update_live_workflow import (
    SecretPolicyUpdateLiveWorkflow,
    SecretPolicyUpdateLiveWorkflowError,
)


REQUESTER = "a" * 64
POLICY_NAME = "mcp-v4-secret-policy-01"


class _FakeTransport:
    def __init__(self) -> None:
        self.baseline = SecretPolicyUpdateBaseline(True, True, True)
        self.update_readback = SecretPolicyUpdateReadback(True, True, True)
        self.update_calls: list[str] = []

    def read_update_baseline(self, policy_name: str) -> SecretPolicyUpdateBaseline:
        assert policy_name == POLICY_NAME
        return self.baseline

    def update_clipboard_and_readback(
        self,
        policy_name: str,
    ) -> SecretPolicyUpdateReadback:
        self.update_calls.append(policy_name)
        return self.update_readback


def _preview(workflow: SecretPolicyUpdateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(policy_name=POLICY_NAME, requester_digest=REQUESTER)


def test_preview_is_baseline_bound_and_excludes_policy_association() -> None:
    workflow = SecretPolicyUpdateLiveWorkflow(_FakeTransport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_policy_name": POLICY_NAME,
        "policy_name_exists": True,
        "known_create_baseline_verified": True,
        "ssh_filter_disabled": True,
        "rdp_clipboard_block_enabled": True,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"] == {
        "operation": "update_secret_policy_rdp_clipboard_via_cli_fallback",
        "policy_name": POLICY_NAME,
        "configuration_profile": "clipboard-block-disable-on-create-baseline-v1",
        "rdp_clipboard_block": "disable",
        "ssh_filter_changes": False,
        "folder_or_secret_association_changes": False,
        "rest_write_attempted": False,
    }
    expected_state = cast(dict[str, object], preview["Expected State"])
    assert expected_state["policy_name_matches"] is True
    assert expected_state["rdp_clipboard_block_disabled"] is True
    assert preview["device_write_executed"] is False


def test_execute_requires_confirmation_and_updates_exactly_once() -> None:
    transport = _FakeTransport()
    workflow = SecretPolicyUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(SecretPolicyUpdateLiveWorkflowError):
        workflow.execute("secret-policy-update-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.update_calls == [POLICY_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["folder_or_secret_association_changes"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert transport.update_calls == [POLICY_NAME]


def test_confirm_and_execute_reject_baseline_drift() -> None:
    transport = _FakeTransport()
    workflow = SecretPolicyUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.baseline = SecretPolicyUpdateBaseline(True, True, False)

    with pytest.raises(SecretPolicyUpdateLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.update_calls == []

    transport = _FakeTransport()
    workflow = SecretPolicyUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.baseline = SecretPolicyUpdateBaseline(True, False, True)
    with pytest.raises(SecretPolicyUpdateLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )
    assert transport.update_calls == []


def test_failed_categorical_readback_requires_reconciliation() -> None:
    transport = _FakeTransport()
    transport.update_readback = SecretPolicyUpdateReadback(True, True, False)
    workflow = SecretPolicyUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(SecretPolicyUpdateLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )


def test_preview_rejects_nonbaseline_or_out_of_scope_policy() -> None:
    transport = _FakeTransport()
    workflow = SecretPolicyUpdateLiveWorkflow(transport)

    with pytest.raises(SecretPolicyUpdateLiveWorkflowError):
        workflow.preview(policy_name="default", requester_digest=REQUESTER)
    transport.baseline = SecretPolicyUpdateBaseline(True, False, True)
    with pytest.raises(SecretPolicyUpdateLiveWorkflowError):
        _preview(workflow)
