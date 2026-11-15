from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.ztna_user_control_mcp_action import (
    ProtectedZtnaUserControlMcpAction,
    V4_ZTNA_USER_CONTROL_ACTION_FEATURE_ENV,
    V4_ZTNA_USER_CONTROL_ACTION_UNAVAILABLE,
    V4_ZTNA_USER_CONTROL_EXECUTION_ENV,
    V4_ZTNA_USER_CONTROL_ROLLBACK_EXECUTION_ENV,
    V4ZtnaUserControlActionConfigurationError,
    V4ZtnaUserControlActionRuntimeError,
    build_v4_ztna_user_control_action,
    load_v4_ztna_user_control_action_feature,
    load_v4_ztna_user_control_execution_feature,
    load_v4_ztna_user_control_rollback_execution_feature,
    ztna_user_control_action_principal_from_access_token,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_ztna_user_control_action_feature({}) is False
    assert load_v4_ztna_user_control_action_feature(
        {V4_ZTNA_USER_CONTROL_ACTION_FEATURE_ENV: "true"}
    ) is True
    with pytest.raises(V4ZtnaUserControlActionConfigurationError):
        load_v4_ztna_user_control_action_feature(
            {V4_ZTNA_USER_CONTROL_ACTION_FEATURE_ENV: "yes"}
        )


def test_forward_and_rollback_dispatch_gates_are_independent_default_denied() -> None:
    assert load_v4_ztna_user_control_execution_feature({}) is False
    assert load_v4_ztna_user_control_rollback_execution_feature({}) is False
    assert load_v4_ztna_user_control_execution_feature(
        {V4_ZTNA_USER_CONTROL_EXECUTION_ENV: "true"}
    ) is True
    assert load_v4_ztna_user_control_rollback_execution_feature(
        {V4_ZTNA_USER_CONTROL_ROLLBACK_EXECUTION_ENV: "true"}
    ) is True
    with pytest.raises(V4ZtnaUserControlActionConfigurationError):
        load_v4_ztna_user_control_execution_feature(
            {V4_ZTNA_USER_CONTROL_EXECUTION_ENV: "yes"}
        )
    with pytest.raises(V4ZtnaUserControlActionConfigurationError):
        load_v4_ztna_user_control_rollback_execution_feature(
            {V4_ZTNA_USER_CONTROL_ROLLBACK_EXECUTION_ENV: "yes"}
        )


def test_builder_never_falls_back_to_generic_credentials() -> None:
    with pytest.raises(
        V4ZtnaUserControlActionConfigurationError,
        match=V4_ZTNA_USER_CONTROL_ACTION_UNAVAILABLE,
    ):
        build_v4_ztna_user_control_action(
            {V4_ZTNA_USER_CONTROL_ACTION_FEATURE_ENV: "true"}
        )


def test_action_requires_the_nondefault_operation_scope() -> None:
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

    with pytest.raises(V4ZtnaUserControlActionRuntimeError):
        ztna_user_control_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]), settings
        )
    assert isinstance(
        ztna_user_control_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_action_binds_requester_and_hides_workflow_failures() -> None:
    workflow = _Workflow()
    rollback = _RollbackWorkflow()
    action = ProtectedZtnaUserControlMcpAction(
        workflow,
        rollback_workflow=rollback,
        execution_enabled=True,
        rollback_execution_enabled=True,
    )
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    rollback_preview = action.preview_rollback(principal)
    rollback_confirmation = action.confirm_rollback(
        str(rollback_preview["preview_ref"]), principal
    )
    rollback_result = action.execute_rollback(
        str(rollback_confirmation["authorization_ref"]), principal
    )
    assert rollback_result["outcome"] == "succeeded"
    assert rollback.calls == ["preview", "confirm", "execute"]
    with pytest.raises(V4ZtnaUserControlActionRuntimeError):
        action.preview(object())


def test_forward_and_rollback_execution_require_their_own_dispatch_gate() -> None:
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    denied = ProtectedZtnaUserControlMcpAction(
        _Workflow(),
        rollback_workflow=_RollbackWorkflow(),
        execution_enabled=False,
        rollback_execution_enabled=False,
    )
    preview = denied.preview(principal)
    confirmation = denied.confirm(str(preview["preview_ref"]), principal)
    with pytest.raises(V4ZtnaUserControlActionRuntimeError):
        denied.execute(str(confirmation["authorization_ref"]), principal)
    rollback_preview = denied.preview_rollback(principal)
    rollback_confirmation = denied.confirm_rollback(
        str(rollback_preview["preview_ref"]), principal
    )
    with pytest.raises(V4ZtnaUserControlActionRuntimeError):
        denied.execute_rollback(
            str(rollback_confirmation["authorization_ref"]), principal
        )


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("preview")
        assert requester_digest == _requester().digest
        return {"preview_ref": "ztna-user-control-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "ztna-user-control-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "ztna-user-control-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "ztna-user-control-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}


class _RollbackWorkflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("preview")
        assert requester_digest == _requester().digest
        return {"preview_ref": "ztna-user-control-rollback-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "ztna-user-control-rollback-preview-00000001"
        assert requester_digest == _requester().digest
        return {
            "authorization_ref": "ztna-user-control-rollback-authorized-00000001"
        }

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "ztna-user-control-rollback-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
