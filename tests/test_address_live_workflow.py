from __future__ import annotations

import pytest

from fortipam_mcp.address_http_transport import AddressInspection, AddressReadback
from fortipam_mcp.address_live_workflow import (
    AddressCreateLiveWorkflow,
    AddressLiveWorkflowError,
)


REQUESTER = "a" * 64
NAME = "mcp-address-01"
CIDR = "198.51.100.10/32"


class _Transport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[tuple[str, str]] = []
        self.readback = AddressReadback(True, True, True, True)

    def inspect(self, name: str) -> AddressInspection:
        return AddressInspection(self.exists)

    def create_and_readback(self, name: str, cidr: str) -> AddressReadback:
        self.create_calls.append((name, cidr))
        self.exists = True
        return self.readback


def _preview(workflow: AddressCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(name=NAME, cidr=CIDR, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_shows_requested_non_secret_address_values() -> None:
    workflow = AddressCreateLiveWorkflow(_Transport(), clock=lambda: 100)

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_address_name": NAME,
        "requested_ipv4_cidr": CIDR,
        "address_exists": False,
        "write_transport": "rest_api",
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_ipv4_ipmask_address_via_api",
        "address_name": NAME,
        "ipv4_cidr": CIDR,
        "address_type": "ipmask",
        "request_body": "fixed_name_type_ipmask_subnet_only",
    }
    assert preview["Expected State"] == {
        "address_exists": True,
        "address_name_matches": True,
        "address_type_matches": True,
        "ipv4_cidr_matches": True,
        "readback_transport": "rest_api",
    }
    assert NAME in str(preview)
    assert CIDR in str(preview)
    assert preview["device_write_executed"] is False


def test_execute_requires_confirmation_and_is_idempotent_after_success() -> None:
    transport = _Transport()
    workflow = AddressCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(AddressLiveWorkflowError):
        workflow.execute("address-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert transport.create_calls == [(NAME, CIDR)]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["address_name_returned"] is False
    assert result["cidr_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirmation_rejects_current_state_drift_and_invalid_input() -> None:
    transport = _Transport()
    workflow = AddressCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(AddressLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    with pytest.raises(AddressLiveWorkflowError):
        workflow.preview(
            name=NAME,
            cidr="198.51.100.10/24",
            requester_digest=REQUESTER,
        )
    assert transport.create_calls == []


def test_unverifiable_readback_requires_reconciliation_without_replay() -> None:
    transport = _Transport()
    transport.readback = AddressReadback(True, True, True, False)
    workflow = AddressCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]), requester_digest=REQUESTER
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(AddressLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)
