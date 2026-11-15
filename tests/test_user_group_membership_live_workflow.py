from __future__ import annotations

import pytest

from fortipam_mcp.user_group_membership_live_workflow import (
    UserGroupMembershipChangeLiveWorkflow,
    UserGroupMembershipLiveWorkflowError,
)
from fortipam_mcp.user_group_ssh_transport import (
    UserGroupMembershipInspection,
    UserGroupMembershipReadback,
)


REQUESTER = "a" * 64
USER_GROUP = "mcp-v4-user-group-01"
LDAP_SERVER = "lab-ldap"
PRIMARY_DN = "cn=PAM_Primary,cn=users,dc=fortipam,dc=ca"
ADDITIONAL_DN = "cn=PAM_Secondary,cn=users,dc=fortipam,dc=ca"


class FakeUserGroupMembershipTransport:
    def __init__(self) -> None:
        self.current = UserGroupMembershipInspection(True, True, True, True, False)
        self.change_calls: list[tuple[str, str, str, str]] = []
        self.readback = UserGroupMembershipReadback(
            True,
            True,
            True,
            True,
            True,
            True,
        )

    def inspect_membership(
        self,
        user_group_name: str,
        ldap_server_name: str,
        primary_ldap_group_dn: str,
        additional_ldap_group_dn: str,
    ) -> UserGroupMembershipInspection:
        assert user_group_name == USER_GROUP
        assert ldap_server_name == LDAP_SERVER
        assert primary_ldap_group_dn == PRIMARY_DN
        assert additional_ldap_group_dn == ADDITIONAL_DN
        return self.current

    def add_remote_ldap_match_and_readback(
        self,
        user_group_name: str,
        ldap_server_name: str,
        primary_ldap_group_dn: str,
        additional_ldap_group_dn: str,
    ) -> UserGroupMembershipReadback:
        self.change_calls.append(
            (
                user_group_name,
                ldap_server_name,
                primary_ldap_group_dn,
                additional_ldap_group_dn,
            )
        )
        return self.readback


def _preview(
    workflow: UserGroupMembershipChangeLiveWorkflow,
) -> dict[str, object]:
    return workflow.preview(
        user_group_name=USER_GROUP,
        ldap_server_name=LDAP_SERVER,
        primary_ldap_group_dn=PRIMARY_DN,
        additional_ldap_group_dn=ADDITIONAL_DN,
        requester_digest=REQUESTER,
    )


def test_preview_requires_exact_single_match_baseline_and_shows_requested_identifiers() -> None:
    workflow = UserGroupMembershipChangeLiveWorkflow(
        FakeUserGroupMembershipTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_user_group_name": USER_GROUP,
        "requested_ldap_server_name": LDAP_SERVER,
        "requested_primary_ldap_group_dn": PRIMARY_DN,
        "requested_additional_ldap_group_dn": ADDITIONAL_DN,
        "user_group_exists": True,
        "known_single_match_baseline_verified": True,
        "additional_remote_group_match_present": False,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"]["user_group_name"] == USER_GROUP
    assert preview["Proposed Changes"]["ldap_server_name"] == LDAP_SERVER
    assert preview["Proposed Changes"]["primary_ldap_group_dn"] == PRIMARY_DN
    assert preview["Proposed Changes"]["additional_ldap_group_dn"] == ADDITIONAL_DN
    assert preview["Proposed Changes"]["existing_remote_group_match_preserved"] is True
    assert preview["Expected State"]["user_group_name_matches"] is True
    assert preview["Expected State"]["additional_remote_group_match_present"] is True
    assert preview["device_write_executed"] is False


def test_execute_requires_confirmation_and_performs_one_match_change() -> None:
    transport = FakeUserGroupMembershipTransport()
    workflow = UserGroupMembershipChangeLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(UserGroupMembershipLiveWorkflowError):
        workflow.execute(
            "user-group-membership-authorized-missing",
            requester_digest=REQUESTER,
        )

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.change_calls == [(USER_GROUP, LDAP_SERVER, PRIMARY_DN, ADDITIONAL_DN)]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["existing_remote_group_match_preserved"] is True
    assert result["role_assignment"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.change_calls) == 1


def test_confirm_and_execute_reject_any_second_match_or_baseline_drift() -> None:
    transport = FakeUserGroupMembershipTransport()
    workflow = UserGroupMembershipChangeLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.current = UserGroupMembershipInspection(True, True, True, True, True)

    with pytest.raises(UserGroupMembershipLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.change_calls == []


def test_bad_readback_requires_reconciliation() -> None:
    transport = FakeUserGroupMembershipTransport()
    transport.readback = UserGroupMembershipReadback(
        True,
        True,
        True,
        True,
        True,
        False,
    )
    workflow = UserGroupMembershipChangeLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"


def test_preview_rejects_nonbaseline_group_or_duplicate_group_match() -> None:
    transport = FakeUserGroupMembershipTransport()
    workflow = UserGroupMembershipChangeLiveWorkflow(transport)

    with pytest.raises(UserGroupMembershipLiveWorkflowError):
        workflow.preview(
            user_group_name="everyone",
            ldap_server_name=LDAP_SERVER,
            primary_ldap_group_dn=PRIMARY_DN,
            additional_ldap_group_dn=ADDITIONAL_DN,
            requester_digest=REQUESTER,
        )
    with pytest.raises(UserGroupMembershipLiveWorkflowError):
        workflow.preview(
            user_group_name=USER_GROUP,
            ldap_server_name=LDAP_SERVER,
            primary_ldap_group_dn=PRIMARY_DN,
            additional_ldap_group_dn=PRIMARY_DN,
            requester_digest=REQUESTER,
        )
    transport.current = UserGroupMembershipInspection(True, True, False, True, False)
    with pytest.raises(UserGroupMembershipLiveWorkflowError):
        _preview(workflow)
