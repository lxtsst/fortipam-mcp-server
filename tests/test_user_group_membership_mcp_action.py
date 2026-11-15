from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.user_group_membership_mcp_action import (
    ProtectedUserGroupMembershipMcpAction,
    V4_USER_GROUP_MEMBERSHIP_ACTION_FEATURE_ENV,
    V4_USER_GROUP_MEMBERSHIP_ACTION_UNAVAILABLE,
    V4_USER_GROUP_MEMBERSHIP_EXECUTION_ENV,
    V4UserGroupMembershipActionConfigurationError,
    V4UserGroupMembershipActionRuntimeError,
    build_v4_user_group_membership_action,
    load_v4_user_group_membership_action_feature,
    load_v4_user_group_membership_execution_feature,
    user_group_membership_action_principal_from_access_token,
)
from fortipam_mcp.v4_plan_runtime import (
    V4PlanningAuthorizationSettings,
    V4PlanningPrincipal,
)
from test_v4_m3 import _requester


USER_GROUP = "mcp-v4-user-group-01"
LDAP_SERVER = "lab-ldap"
PRIMARY_DN = "cn=PAM_Primary,cn=users,dc=fortipam,dc=ca"
ADDITIONAL_DN = "cn=PAM_Secondary,cn=users,dc=fortipam,dc=ca"


def test_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_user_group_membership_action_feature({}) is False
    assert (
        load_v4_user_group_membership_action_feature(
            {V4_USER_GROUP_MEMBERSHIP_ACTION_FEATURE_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_user_group_membership_action_feature(
            {V4_USER_GROUP_MEMBERSHIP_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4UserGroupMembershipActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_user_group_membership_action_feature(
            {V4_USER_GROUP_MEMBERSHIP_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_final_dispatch_gate_defaults_false_and_is_exact() -> None:
    assert load_v4_user_group_membership_execution_feature({}) is False
    assert (
        load_v4_user_group_membership_execution_feature(
            {V4_USER_GROUP_MEMBERSHIP_EXECUTION_ENV: "true"}
        )
        is True
    )
    with pytest.raises(V4UserGroupMembershipActionConfigurationError):
        load_v4_user_group_membership_execution_feature(
            {V4_USER_GROUP_MEMBERSHIP_EXECUTION_ENV: "yes"}
        )


def test_final_dispatch_gate_denies_after_confirmation() -> None:
    workflow = _Workflow()
    action = ProtectedUserGroupMembershipMcpAction(
        workflow,
        execution_enabled=False,
    )
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    preview = action.preview(
        USER_GROUP,
        LDAP_SERVER,
        PRIMARY_DN,
        ADDITIONAL_DN,
        principal,
    )
    confirmation = action.confirm(str(preview["preview_ref"]), principal)

    with pytest.raises(V4UserGroupMembershipActionRuntimeError):
        action.execute(str(confirmation["authorization_ref"]), principal)
    assert workflow.calls == ["preview", "confirm"]


def test_builder_never_falls_back_to_generic_credentials() -> None:
    with pytest.raises(
        V4UserGroupMembershipActionConfigurationError,
        match=V4_USER_GROUP_MEMBERSHIP_ACTION_UNAVAILABLE,
    ):
        build_v4_user_group_membership_action(
            {V4_USER_GROUP_MEMBERSHIP_ACTION_FEATURE_ENV: "true"}
        )


def test_membership_action_requires_non_default_operation_scope() -> None:
    resource = "https://mcp.example.test/fpamcp-v4"
    settings = V4PlanningAuthorizationSettings(resource, b"p" * 32)

    def token(scopes: list[str]) -> AccessToken:
        return AccessToken(
            token="opaque-sdk-validated-access-token",
            client_id="client-0001",
            scopes=scopes,
            expires_at=2_000_000_000,
            resource=resource,
            subject="operator-0001",
            claims={"iss": "https://mcp.example.test/oauth"},
        )

    with pytest.raises(
        V4UserGroupMembershipActionRuntimeError,
        match=V4_USER_GROUP_MEMBERSHIP_ACTION_UNAVAILABLE,
    ):
        user_group_membership_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]),
            settings,
        )

    assert isinstance(
        user_group_membership_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_action_binds_requester_and_hides_workflow_failures() -> None:
    workflow = _Workflow()
    action = ProtectedUserGroupMembershipMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(USER_GROUP, LDAP_SERVER, PRIMARY_DN, ADDITIONAL_DN, principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4UserGroupMembershipActionRuntimeError,
        match=V4_USER_GROUP_MEMBERSHIP_ACTION_UNAVAILABLE,
    ):
        action.preview(USER_GROUP, LDAP_SERVER, PRIMARY_DN, ADDITIONAL_DN, object())


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["user_group_name"] == USER_GROUP
        assert kwargs["ldap_server_name"] == LDAP_SERVER
        assert kwargs["primary_ldap_group_dn"] == PRIMARY_DN
        assert kwargs["additional_ldap_group_dn"] == ADDITIONAL_DN
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "user-group-membership-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "user-group-membership-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "user-group-membership-authorized-00000001"}

    def execute(
        self,
        authorization_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "user-group-membership-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
