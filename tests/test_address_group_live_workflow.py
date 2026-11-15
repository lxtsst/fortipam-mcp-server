from __future__ import annotations

import pytest

from fortipam_mcp.address_group_live_workflow import (
    AddressGroupCreateLiveWorkflow,
    AddressGroupLiveWorkflowError,
)
from fortipam_mcp.address_group_ssh_transport import (
    AddressGroupInspection,
    AddressGroupReadback,
)
from fortipam_mcp.address_http_transport import AddressInspection


REQUESTER = "a" * 64
GROUP = "mcp-address-group-01"
MEMBER = "mcp-address-01"


class _GroupTransport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[tuple[str, str]] = []
        self.readback = AddressGroupReadback(True, True)

    def inspect(self, group_name: str) -> AddressGroupInspection:
        return AddressGroupInspection(self.exists)

    def create_and_readback(
        self,
        group_name: str,
        member_name: str,
    ) -> AddressGroupReadback:
        self.create_calls.append((group_name, member_name))
        self.exists = True
        return self.readback


class _MemberTransport:
    def __init__(self) -> None:
        self.inspection = AddressInspection(True, True)

    def inspect(self, name: str) -> AddressInspection:
        return self.inspection


def _workflow() -> tuple[AddressGroupCreateLiveWorkflow, _GroupTransport, _MemberTransport]:
    group_transport = _GroupTransport()
    member_transport = _MemberTransport()
    return (
        AddressGroupCreateLiveWorkflow(
            group_transport,
            member_transport,
            clock=lambda: 100,
        ),
        group_transport,
        member_transport,
    )


def test_preview_is_cpe_and_shows_only_caller_supplied_group_and_member_identifiers() -> None:
    workflow, _, _ = _workflow()

    preview = workflow.preview(
        group_name=GROUP,
        member_name=MEMBER,
        requester_digest=REQUESTER,
    )

    assert preview["Current State"] == {
        "requested_address_group_name": GROUP,
        "requested_member_address_name": MEMBER,
        "address_group_exists": False,
        "member_address_exists": True,
        "member_address_type": "ipv4_ipmask",
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_single_member_address_group_via_cli_fallback",
        "address_group_name": GROUP,
        "member_address_name": MEMBER,
        "member_count": 1,
        "rest_write_attempted": False,
        "compiled_cli_sequence": "firewall_addrgrp_edit_set_member",
    }
    assert preview["Expected State"] == {
        "address_group_name_matches": True,
        "member_address_name_matches": True,
        "address_group_exists": True,
        "exactly_one_member_matches": True,
        "readback_transport": "ssh_cli",
    }
    assert GROUP in str(preview)
    assert MEMBER in str(preview)
    assert preview["device_write_executed"] is False


def test_execute_requires_confirmation_and_is_idempotent_after_success() -> None:
    workflow, group_transport, _ = _workflow()
    preview = workflow.preview(
        group_name=GROUP,
        member_name=MEMBER,
        requester_digest=REQUESTER,
    )

    with pytest.raises(AddressGroupLiveWorkflowError):
        workflow.execute("address-group-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert group_transport.create_calls == [(GROUP, MEMBER)]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["address_group_name_returned"] is False
    assert result["member_address_name_returned"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(group_transport.create_calls) == 1


def test_rejects_non_ipmask_member_or_prewrite_state_drift() -> None:
    workflow, group_transport, member_transport = _workflow()
    member_transport.inspection = AddressInspection(True, False)

    with pytest.raises(AddressGroupLiveWorkflowError):
        workflow.preview(
            group_name=GROUP,
            member_name=MEMBER,
            requester_digest=REQUESTER,
        )

    member_transport.inspection = AddressInspection(True, True)
    preview = workflow.preview(
        group_name=GROUP,
        member_name=MEMBER,
        requester_digest=REQUESTER,
    )
    member_transport.inspection = AddressInspection(False, False)
    with pytest.raises(AddressGroupLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert group_transport.create_calls == []


def test_unverifiable_readback_requires_reconciliation() -> None:
    workflow, group_transport, _ = _workflow()
    group_transport.readback = AddressGroupReadback(True, False)
    preview = workflow.preview(
        group_name=GROUP,
        member_name=MEMBER,
        requester_digest=REQUESTER,
    )
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(AddressGroupLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)
