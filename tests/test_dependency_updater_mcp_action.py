from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.dependency_updater_mcp_action import (
    ProtectedDependencyUpdaterMcpAction,
    V4_DEPENDENCY_UPDATER_ACTION_FEATURE_ENV,
    V4_DEPENDENCY_UPDATER_ACTION_UNAVAILABLE,
    V4_DEPENDENCY_UPDATER_EXECUTION_ENV,
    V4DependencyUpdaterActionConfigurationError,
    V4DependencyUpdaterActionRuntimeError,
    build_v4_dependency_updater_action,
    dependency_updater_action_principal_from_access_token,
    load_v4_dependency_updater_action_feature,
    load_v4_dependency_updater_execution_feature,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_dependency_updater_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_dependency_updater_action_feature({}) is False
    assert (
        load_v4_dependency_updater_action_feature(
            {V4_DEPENDENCY_UPDATER_ACTION_FEATURE_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_dependency_updater_action_feature(
            {V4_DEPENDENCY_UPDATER_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4DependencyUpdaterActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_dependency_updater_action_feature(
            {V4_DEPENDENCY_UPDATER_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_dependency_updater_execution_gate_is_disabled_by_default_and_exact() -> None:
    assert load_v4_dependency_updater_execution_feature({}) is False
    assert load_v4_dependency_updater_execution_feature({V4_DEPENDENCY_UPDATER_EXECUTION_ENV: "false"}) is False
    assert load_v4_dependency_updater_execution_feature({V4_DEPENDENCY_UPDATER_EXECUTION_ENV: "true"}) is True
    with pytest.raises(V4DependencyUpdaterActionConfigurationError, match="exactly true or false"):
        load_v4_dependency_updater_execution_feature({V4_DEPENDENCY_UPDATER_EXECUTION_ENV: "TRUE"})


def test_dependency_updater_builder_never_falls_back_to_generic_credentials() -> None:
    with pytest.raises(
        V4DependencyUpdaterActionConfigurationError,
        match=V4_DEPENDENCY_UPDATER_ACTION_UNAVAILABLE,
    ):
        build_v4_dependency_updater_action(
            {V4_DEPENDENCY_UPDATER_ACTION_FEATURE_ENV: "true"}
        )


def test_dependency_updater_requires_the_non_default_operation_scope() -> None:
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
        V4DependencyUpdaterActionRuntimeError,
        match=V4_DEPENDENCY_UPDATER_ACTION_UNAVAILABLE,
    ):
        dependency_updater_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]),
            settings,
        )

    assert isinstance(
        dependency_updater_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_dependency_updater_action_binds_requester_and_hides_transport_failures() -> None:
    workflow = _Workflow()
    action = ProtectedDependencyUpdaterMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(
        "mcp-v4-dependency-updater-01",
        "McpV4LabService",
        principal,
    )
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4DependencyUpdaterActionRuntimeError,
        match=V4_DEPENDENCY_UPDATER_ACTION_UNAVAILABLE,
    ):
        action.preview("mcp-v4-dependency-updater-02", "McpV4LabService", object())


def test_dependency_updater_execution_gate_denies_after_confirmation() -> None:
    workflow = _Workflow()
    action = ProtectedDependencyUpdaterMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    preview = action.preview("mcp-v4-dependency-updater-01", "McpV4LabService", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    with pytest.raises(V4DependencyUpdaterActionRuntimeError, match=V4_DEPENDENCY_UPDATER_ACTION_UNAVAILABLE):
        action.execute(str(confirmation["authorization_ref"]), principal)
    assert workflow.calls == ["preview", "confirm"]


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["updater_name"] == "mcp-v4-dependency-updater-01"
        assert kwargs["service_name"] == "McpV4LabService"
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "dependency-updater-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "dependency-updater-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "dependency-updater-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "dependency-updater-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
