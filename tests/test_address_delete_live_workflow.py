from __future__ import annotations

import pytest

from fortipam_mcp.address_delete_http_transport import (
    AddressDeleteInspection,
    AddressDeleteReadback,
)
from fortipam_mcp.address_delete_live_workflow import (
    AddressDeleteLiveWorkflow,
    AddressDeleteLiveWorkflowError,
)


REQUESTER = "a" * 64
TARGET_DIGEST = "b" * 64


class _Transport:
    def __init__(self) -> None:
        self.exists = True
        self.eligible = True
        self.references = 0
        self.target_digest = TARGET_DIGEST
        self.delete_calls: list[str] = []
        self.readback = AddressDeleteReadback(True, True)

    def inspect_delete_target(self) -> AddressDeleteInspection:
        return AddressDeleteInspection(
            self.exists,
            self.eligible,
            self.references,
            self.target_digest,
        )

    def delete_and_readback(self, expected_target_digest: str) -> AddressDeleteReadback:
        self.delete_calls.append(expected_target_digest)
        self.exists = False
        return self.readback


def test_preview_is_fixed_destructive_cpe_without_selector_or_values() -> None:
    preview = AddressDeleteLiveWorkflow(_Transport(), clock=lambda: 100).preview(
        requester_digest=REQUESTER
    )

    assert preview["Current State"] == {
        "accepted_address_exists": True,
        "exact_ipv4_ipmask_observed": True,
        "complete_api_record_digest_matches": True,
        "address_reference_count": 0,
        "read_transports": ["rest_api", "ssh_cli"],
    }
    assert preview["Proposed Changes"] == {
        "operation": "delete_exact_unreferenced_ipv4_address_via_api",
        "address_count_affected": 1,
        "irreversible_after_execution": True,
        "group_policy_or_interface_changes": False,
    }
    assert preview["Expected State"] == {
        "accepted_address_absent": True,
        "group_policy_or_interface_changes": False,
        "readback_transports": ["rest_api", "ssh_cli"],
    }
    assert "mcp-v4-address" not in repr(preview)


def test_execute_requires_confirmation_and_never_redispatches_success() -> None:
    transport = _Transport()
    workflow = AddressDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmed = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmed["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    replay = workflow.execute(
        str(confirmed["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "succeeded"
    assert result["address_name_or_subnet_returned"] is False
    assert transport.delete_calls == [TARGET_DIGEST]
    assert replay["idempotent_replay"] is True


def test_drift_reference_absence_expiry_and_requester_fail_closed() -> None:
    transport = _Transport()
    now = 100
    workflow = AddressDeleteLiveWorkflow(transport, clock=lambda: now)
    preview = workflow.preview(requester_digest=REQUESTER)
    transport.references = 1
    transport.eligible = False
    with pytest.raises(AddressDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.delete_calls == []

    transport = _Transport()
    transport.exists = False
    with pytest.raises(AddressDeleteLiveWorkflowError):
        AddressDeleteLiveWorkflow(transport).preview(requester_digest=REQUESTER)
    with pytest.raises(AddressDeleteLiveWorkflowError):
        AddressDeleteLiveWorkflow(_Transport()).preview(requester_digest="invalid")

    workflow = AddressDeleteLiveWorkflow(_Transport(), clock=lambda: now)
    preview = workflow.preview(requester_digest=REQUESTER)
    now = 701
    with pytest.raises(AddressDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)


def test_unverified_readback_is_reconciliation_required_and_nonretry() -> None:
    transport = _Transport()
    transport.readback = AddressDeleteReadback(True, False)
    workflow = AddressDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmed = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmed["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    with pytest.raises(AddressDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmed["authorization_ref"]),
            requester_digest=REQUESTER,
        )
