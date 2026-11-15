from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.secret_policy_mcp_action import (
    ProtectedSecretPolicyMcpAction,
    V4_SECRET_POLICY_ACTION_FEATURE_ENV,
    V4_SECRET_POLICY_ACTION_UNAVAILABLE,
    V4SecretPolicyActionConfigurationError,
    V4SecretPolicyActionRuntimeError,
    build_v4_secret_policy_action,
    load_v4_secret_policy_action_feature,
    secret_policy_action_principal_from_access_token,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_secret_policy_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_secret_policy_action_feature({}) is False
    assert (
        load_v4_secret_policy_action_feature(
            {V4_SECRET_POLICY_ACTION_FEATURE_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_secret_policy_action_feature(
            {V4_SECRET_POLICY_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4SecretPolicyActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_secret_policy_action_feature(
            {V4_SECRET_POLICY_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_secret_policy_builder_never_falls_back_to_generic_credentials() -> None:
    with pytest.raises(
        V4SecretPolicyActionConfigurationError,
        match=V4_SECRET_POLICY_ACTION_UNAVAILABLE,
    ):
        build_v4_secret_policy_action(
            {V4_SECRET_POLICY_ACTION_FEATURE_ENV: "true"}
        )


def test_secret_policy_requires_the_non_default_operation_scope() -> None:
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
        V4SecretPolicyActionRuntimeError,
        match=V4_SECRET_POLICY_ACTION_UNAVAILABLE,
    ):
        secret_policy_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]),
            settings,
        )

    assert isinstance(
        secret_policy_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_secret_policy_action_binds_requester_and_hides_transport_failures() -> None:
    workflow = _Workflow()
    update_workflow = _UpdateWorkflow()
    action = ProtectedSecretPolicyMcpAction(workflow, update_workflow=update_workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("mcp-v4-secret-policy-01", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    update_preview = action.preview_update("mcp-v4-secret-policy-01", principal)
    update_confirmation = action.confirm_update(
        str(update_preview["preview_ref"]),
        principal,
    )
    update_result = action.execute_update(
        str(update_confirmation["authorization_ref"]),
        principal,
    )
    assert update_result["outcome"] == "succeeded"
    assert update_workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4SecretPolicyActionRuntimeError,
        match=V4_SECRET_POLICY_ACTION_UNAVAILABLE,
    ):
        action.preview("mcp-v4-secret-policy-02", object())


def test_secret_policy_update_is_unavailable_without_its_bound_workflow() -> None:
    action = ProtectedSecretPolicyMcpAction(_Workflow())
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    with pytest.raises(
        V4SecretPolicyActionRuntimeError,
        match=V4_SECRET_POLICY_ACTION_UNAVAILABLE,
    ):
        action.preview_update("mcp-v4-secret-policy-01", principal)


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["policy_name"] == "mcp-v4-secret-policy-01"
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "secret-policy-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "secret-policy-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "secret-policy-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "secret-policy-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}


class _UpdateWorkflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["policy_name"] == "mcp-v4-secret-policy-01"
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "secret-policy-update-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "secret-policy-update-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "secret-policy-update-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "secret-policy-update-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
