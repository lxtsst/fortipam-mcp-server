from __future__ import annotations

import pytest

from fortipam_mcp.secret_policy_live_workflow import (
    SecretPolicyCreateLiveWorkflow,
    SecretPolicyLiveWorkflowError,
)
from fortipam_mcp.secret_policy_ssh_transport import (
    SecretPolicyInspection,
    SecretPolicyReadback,
)


REQUESTER = "a" * 64
POLICY_NAME = "mcp-v4-secret-policy-01"


class FakeSecretPolicyTransport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[str] = []
        self.readback = SecretPolicyReadback(True, True, True)

    def inspect(self, policy_name: str) -> SecretPolicyInspection:
        return SecretPolicyInspection(self.exists)

    def create_and_readback(self, policy_name: str) -> SecretPolicyReadback:
        self.create_calls.append(policy_name)
        self.exists = True
        return self.readback


def _preview(workflow: SecretPolicyCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(policy_name=POLICY_NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_excludes_association_changes() -> None:
    workflow = SecretPolicyCreateLiveWorkflow(
        FakeSecretPolicyTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_policy_name": POLICY_NAME,
        "policy_name_exists": False,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_unattached_secret_policy_via_cli_fallback",
        "policy_name": POLICY_NAME,
        "configuration_profile": "clipboard-block-and-ssh-filter-disabled-v1",
        "ssh_filter": "disable",
        "rdp_clipboard_block": "enable",
        "folder_or_secret_association_changes": False,
        "rest_write_attempted": False,
    }
    assert preview["Expected State"]["policy_name_matches"] is True
    assert preview["Expected State"]["rdp_clipboard_block_enabled"] is True
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeSecretPolicyTransport()
    workflow = SecretPolicyCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(SecretPolicyLiveWorkflowError):
        workflow.execute("secret-policy-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.create_calls == [POLICY_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["folder_or_secret_association_changes"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_policy_appears_after_preview() -> None:
    transport = FakeSecretPolicyTransport()
    workflow = SecretPolicyCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(SecretPolicyLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_execute_rechecks_absence_and_rejects_prewrite_drift() -> None:
    transport = FakeSecretPolicyTransport()
    workflow = SecretPolicyCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.exists = True

    with pytest.raises(SecretPolicyLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )

    assert transport.create_calls == []


def test_readback_failure_requires_reconciliation() -> None:
    transport = FakeSecretPolicyTransport()
    transport.readback = SecretPolicyReadback(True, False, True)
    workflow = SecretPolicyCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(SecretPolicyLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_preview_rejects_existing_or_out_of_scope_inputs() -> None:
    transport = FakeSecretPolicyTransport()
    workflow = SecretPolicyCreateLiveWorkflow(transport)

    with pytest.raises(SecretPolicyLiveWorkflowError):
        workflow.preview(policy_name="default", requester_digest=REQUESTER)
    transport.exists = True
    with pytest.raises(SecretPolicyLiveWorkflowError):
        _preview(workflow)
