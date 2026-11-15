from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.role_update_mcp_action import (
    ProtectedRoleUpdateMcpAction,
    V4_ROLE_UPDATE_ACTION_FEATURE_ENV,
    V4_ROLE_UPDATE_ACTION_UNAVAILABLE,
    V4_ROLE_UPDATE_EXECUTION_ENV,
    V4RoleUpdateActionConfigurationError,
    V4RoleUpdateActionRuntimeError,
    build_v4_role_update_action,
    load_v4_role_update_action_feature,
    load_v4_role_update_execution_feature,
    role_update_action_principal_from_access_token,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_role_update_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_role_update_action_feature({}) is False
    assert (
        load_v4_role_update_action_feature(
            {V4_ROLE_UPDATE_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4RoleUpdateActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_role_update_action_feature(
            {V4_ROLE_UPDATE_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_role_update_execution_gate_is_disabled_by_default_and_exact() -> None:
    assert load_v4_role_update_execution_feature({}) is False
    assert (
        load_v4_role_update_execution_feature(
            {V4_ROLE_UPDATE_EXECUTION_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4RoleUpdateActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_role_update_execution_feature(
            {V4_ROLE_UPDATE_EXECUTION_ENV: "TRUE"}
        )


def test_role_update_builder_never_falls_back_to_generic_credentials() -> None:
    with pytest.raises(
        V4RoleUpdateActionConfigurationError,
        match=V4_ROLE_UPDATE_ACTION_UNAVAILABLE,
    ):
        build_v4_role_update_action({V4_ROLE_UPDATE_ACTION_FEATURE_ENV: "true"})


def test_role_update_requires_non_default_operation_scope() -> None:
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
        V4RoleUpdateActionRuntimeError,
        match=V4_ROLE_UPDATE_ACTION_UNAVAILABLE,
    ):
        role_update_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]), settings
        )

    assert isinstance(
        role_update_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_role_update_action_binds_requester_and_hides_transport_failures() -> None:
    workflow = _Workflow()
    action = ProtectedRoleUpdateMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("mcp-v4-role-01", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4RoleUpdateActionRuntimeError,
        match=V4_ROLE_UPDATE_ACTION_UNAVAILABLE,
    ):
        action.preview("mcp-v4-role-02", object())


def test_role_update_keeps_tools_callable_but_denies_final_dispatch() -> None:
    workflow = _Workflow()
    action = ProtectedRoleUpdateMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("mcp-v4-role-01", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    with pytest.raises(
        V4RoleUpdateActionRuntimeError,
        match=V4_ROLE_UPDATE_ACTION_UNAVAILABLE,
    ):
        action.execute(str(confirmation["authorization_ref"]), principal)

    assert workflow.calls == ["preview", "confirm"]


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["role_name"] == "mcp-v4-role-01"
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "role-update-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "role-update-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "role-update-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "role-update-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
