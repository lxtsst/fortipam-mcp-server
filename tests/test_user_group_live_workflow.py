from __future__ import annotations

import pytest

from fortipam_mcp.user_group_live_workflow import (
    UserGroupCreateLiveWorkflow,
    UserGroupLiveWorkflowError,
)
from fortipam_mcp.user_group_ssh_transport import (
    UserGroupInspection,
    UserGroupReadback,
)


REQUESTER = "a" * 64
USER_GROUP = "mcp-v4-user-group-01"
LDAP_SERVER = "lab-ldap"
LDAP_GROUP_DN = "cn=PAM_Group,cn=users,dc=fortipam,dc=ca"


class FakeUserGroupTransport:
    def __init__(self) -> None:
        self.exists = False
        self.create_calls: list[tuple[str, str, str]] = []
        self.readback = UserGroupReadback(True, True, True, True)

    def inspect(self, user_group_name: str) -> UserGroupInspection:
        assert user_group_name == USER_GROUP
        return UserGroupInspection(self.exists)

    def create_and_readback(
        self,
        user_group_name: str,
        ldap_server_name: str,
        ldap_group_dn: str,
    ) -> UserGroupReadback:
        self.create_calls.append((user_group_name, ldap_server_name, ldap_group_dn))
        self.exists = True
        return self.readback


def _preview(workflow: UserGroupCreateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(
        user_group_name=USER_GROUP,
        ldap_server_name=LDAP_SERVER,
        ldap_group_dn=LDAP_GROUP_DN,
        requester_digest=REQUESTER,
    )


def test_preview_is_live_cpe_and_excludes_access_or_provisioning_changes() -> None:
    workflow = UserGroupCreateLiveWorkflow(
        FakeUserGroupTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_user_group_name": USER_GROUP,
        "requested_ldap_server_name": LDAP_SERVER,
        "requested_ldap_group_dn": LDAP_GROUP_DN,
        "user_group_name_exists": False,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"] == {
        "operation": "create_remote_ldap_user_group_via_cli_fallback",
        "user_group_name": USER_GROUP,
        "ldap_server_name": LDAP_SERVER,
        "ldap_group_dn": LDAP_GROUP_DN,
        "configuration_profile": "remote-ldap-single-match-unbound-v1",
        "one_ldap_server_member_created": True,
        "one_remote_group_match_created": True,
        "role_assignment": False,
        "auto_provision_rule_created": False,
        "folder_or_secret_acl_change": False,
        "user_import_or_session_change": False,
        "rest_write_attempted": False,
    }
    assert preview["Expected State"]["user_group_name_matches"] is True
    assert preview["Expected State"]["remote_group_match_matches"] is True
    assert preview["device_write_executed"] is False


def test_execute_requires_one_confirmation_and_performs_one_create() -> None:
    transport = FakeUserGroupTransport()
    workflow = UserGroupCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)

    with pytest.raises(UserGroupLiveWorkflowError):
        workflow.execute("user-group-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.create_calls == [(USER_GROUP, LDAP_SERVER, LDAP_GROUP_DN)]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["role_assignment"] is False
    assert result["auto_provision_rule_created"] is False
    assert result["raw_cli_returned"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.create_calls) == 1


def test_confirm_invalidates_when_user_group_appears_after_preview() -> None:
    transport = FakeUserGroupTransport()
    workflow = UserGroupCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.exists = True

    with pytest.raises(UserGroupLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.create_calls == []


def test_execute_rechecks_absence_and_rejects_prewrite_drift() -> None:
    transport = FakeUserGroupTransport()
    workflow = UserGroupCreateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )
    transport.exists = True

    with pytest.raises(UserGroupLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )

    assert transport.create_calls == []


def test_readback_failure_requires_reconciliation() -> None:
    transport = FakeUserGroupTransport()
    transport.readback = UserGroupReadback(True, True, False, True)
    workflow = UserGroupCreateLiveWorkflow(transport, clock=lambda: 100)
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
    assert result["verification"] == "unknown"
    with pytest.raises(UserGroupLiveWorkflowError):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )


def test_preview_rejects_existing_or_out_of_scope_inputs() -> None:
    transport = FakeUserGroupTransport()
    workflow = UserGroupCreateLiveWorkflow(transport)

    with pytest.raises(UserGroupLiveWorkflowError):
        workflow.preview(
            user_group_name="everyone",
            ldap_server_name=LDAP_SERVER,
            ldap_group_dn=LDAP_GROUP_DN,
            requester_digest=REQUESTER,
        )
    with pytest.raises(UserGroupLiveWorkflowError):
        workflow.preview(
            user_group_name=USER_GROUP,
            ldap_server_name=LDAP_SERVER,
            ldap_group_dn='cn=unsafe"\nset x y',
            requester_digest=REQUESTER,
        )
    transport.exists = True
    with pytest.raises(UserGroupLiveWorkflowError):
        _preview(workflow)
