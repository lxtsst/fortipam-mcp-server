from __future__ import annotations

import pytest

from fortipam_mcp.address_group_delete_http_transport import (
    AddressGroupDeleteInspection,
    AddressGroupDeleteReadback,
)
from fortipam_mcp.address_group_delete_live_workflow import (
    AddressGroupDeleteLiveWorkflow,
    AddressGroupDeleteLiveWorkflowError,
)


REQUESTER = "a" * 64
TARGET_DIGEST = "b" * 64


class _Transport:
    def __init__(self) -> None:
        self.exists = True
        self.eligible = True
        self.group_references = 0
        self.calibration_references = 1
        self.target_digest = TARGET_DIGEST
        self.delete_calls: list[str] = []
        self.readback = AddressGroupDeleteReadback(True, True, True)

    def inspect_delete_target(self) -> AddressGroupDeleteInspection:
        return AddressGroupDeleteInspection(
            self.exists,
            self.eligible,
            self.group_references,
            self.calibration_references,
            self.target_digest,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> AddressGroupDeleteReadback:
        self.delete_calls.append(expected_target_digest)
        self.exists = False
        return self.readback


def _preview(workflow: AddressGroupDeleteLiveWorkflow) -> dict[str, object]:
    return workflow.preview(requester_digest=REQUESTER)


def test_preview_is_fixed_destructive_cpe_without_selector_or_names() -> None:
    preview = _preview(AddressGroupDeleteLiveWorkflow(_Transport(), clock=lambda: 100))

    assert preview["Current State"] == {
        "accepted_address_group_exists": True,
        "exact_fixed_single_member_group_observed": True,
        "complete_api_record_digest_matches": True,
        "group_reference_count": 0,
        "calibration_address_reference_count": 1,
        "member_address_present": True,
        "read_transports": ["rest_api", "ssh_cli"],
    }
    assert preview["Proposed Changes"] == {
        "operation": "delete_exact_unreferenced_address_group_via_api",
        "address_group_count_affected": 1,
        "irreversible_after_execution": True,
        "member_address_changes": False,
        "policy_or_interface_changes": False,
    }
    assert preview["Expected State"] == {
        "accepted_address_group_absent": True,
        "member_address_preserved": True,
        "policy_or_interface_changes": False,
        "readback_transports": ["rest_api", "ssh_cli"],
    }
    assert preview["device_write_executed"] is False
    assert "mcp-v4-address" not in repr(preview)


def test_execute_requires_confirmation_and_replays_only_verified_result() -> None:
    transport = _Transport()
    workflow = AddressGroupDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "succeeded"
    assert result["address_group_or_member_name_returned"] is False
    assert result["member_address_changes"] is False
    assert transport.delete_calls == [TARGET_DIGEST]
    assert replay["idempotent_replay"] is True


def test_drift_or_reference_change_rejects_before_delete() -> None:
    transport = _Transport()
    workflow = AddressGroupDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.target_digest = "c" * 64
    with pytest.raises(AddressGroupDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert transport.delete_calls == []

    transport = _Transport()
    workflow = AddressGroupDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.group_references = 1
    transport.eligible = False
    with pytest.raises(AddressGroupDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )
    assert transport.delete_calls == []


def test_bad_calibration_absence_expiry_and_requester_fail_closed() -> None:
    transport = _Transport()
    now = 100
    workflow = AddressGroupDeleteLiveWorkflow(transport, clock=lambda: now)
    transport.calibration_references = 0
    transport.eligible = False
    with pytest.raises(AddressGroupDeleteLiveWorkflowError):
        _preview(workflow)
    transport.calibration_references = 1
    transport.eligible = True
    transport.exists = False
    with pytest.raises(AddressGroupDeleteLiveWorkflowError):
        _preview(workflow)
    transport.exists = True
    with pytest.raises(AddressGroupDeleteLiveWorkflowError):
        workflow.preview(requester_digest="invalid")

    preview = _preview(workflow)
    now = 701
    with pytest.raises(AddressGroupDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)


def test_unverified_readback_is_reconciliation_required_and_nonretry() -> None:
    transport = _Transport()
    transport.readback = AddressGroupDeleteReadback(True, False, True)
    workflow = AddressGroupDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    with pytest.raises(AddressGroupDeleteLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )
