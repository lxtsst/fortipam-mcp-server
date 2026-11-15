from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.apl_disable_mcp_action import (
    ProtectedAplDisableMcpAction,
    V4_APL_DISABLE_ACTION_FEATURE_ENV,
    V4_APL_DISABLE_ACTION_UNAVAILABLE,
    V4_APL_DISABLE_EXECUTION_ENV,
    V4AplDisableActionConfigurationError,
    V4AplDisableActionRuntimeError,
    apl_disable_action_principal_from_access_token,
    build_v4_apl_disable_action,
    load_v4_apl_disable_action_feature,
    load_v4_apl_disable_execution_feature,
)
from fortipam_mcp.v4_plan_runtime import (
    V4PlanningAuthorizationSettings,
    V4PlanningPrincipal,
)
from test_v4_m3 import _requester


RULE = "mcp-v4-apl-01"
USER_GROUP = "mcp-v4-user-group-01"
ROLE = "mcp-v4-role-01"


def test_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_apl_disable_action_feature({}) is False
    assert (
        load_v4_apl_disable_action_feature(
            {V4_APL_DISABLE_ACTION_FEATURE_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_apl_disable_action_feature(
            {V4_APL_DISABLE_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4AplDisableActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_apl_disable_action_feature(
            {V4_APL_DISABLE_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_final_dispatch_gate_defaults_false_and_is_exact() -> None:
    assert load_v4_apl_disable_execution_feature({}) is False
    assert (
        load_v4_apl_disable_execution_feature(
            {V4_APL_DISABLE_EXECUTION_ENV: "true"}
        )
        is True
    )
    with pytest.raises(V4AplDisableActionConfigurationError):
        load_v4_apl_disable_execution_feature(
            {V4_APL_DISABLE_EXECUTION_ENV: "yes"}
        )


def test_final_dispatch_gate_denies_after_confirmation() -> None:
    workflow = _Workflow()
    action = ProtectedAplDisableMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    preview = action.preview(RULE, USER_GROUP, ROLE, principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)

    with pytest.raises(V4AplDisableActionRuntimeError):
        action.execute(str(confirmation["authorization_ref"]), principal)
    assert workflow.calls == ["preview", "confirm"]


def test_builder_never_falls_back_to_generic_credentials() -> None:
    with pytest.raises(
        V4AplDisableActionConfigurationError,
        match=V4_APL_DISABLE_ACTION_UNAVAILABLE,
    ):
        build_v4_apl_disable_action({V4_APL_DISABLE_ACTION_FEATURE_ENV: "true"})


def test_apl_disable_action_requires_non_default_operation_scope() -> None:
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
        V4AplDisableActionRuntimeError,
        match=V4_APL_DISABLE_ACTION_UNAVAILABLE,
    ):
        apl_disable_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]),
            settings,
        )
    assert isinstance(
        apl_disable_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_action_binds_requester_and_hides_workflow_failures() -> None:
    workflow = _Workflow()
    action = ProtectedAplDisableMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(RULE, USER_GROUP, ROLE, principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4AplDisableActionRuntimeError,
        match=V4_APL_DISABLE_ACTION_UNAVAILABLE,
    ):
        action.preview(RULE, USER_GROUP, ROLE, object())


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["auto_provision_rule_name"] == RULE
        assert kwargs["remote_user_group_name"] == USER_GROUP
        assert kwargs["role_name"] == ROLE
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "apl-disable-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "apl-disable-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "apl-disable-authorized-00000001"}

    def execute(
        self,
        authorization_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "apl-disable-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
