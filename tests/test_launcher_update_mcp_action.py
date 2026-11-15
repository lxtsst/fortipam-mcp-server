from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.launcher_update_mcp_action import (
    ProtectedLauncherUpdateMcpAction,
    V4_LAUNCHER_UPDATE_ACTION_FEATURE_ENV,
    V4_LAUNCHER_UPDATE_ACTION_UNAVAILABLE,
    V4_LAUNCHER_UPDATE_EXECUTION_ENV,
    V4LauncherUpdateActionConfigurationError,
    V4LauncherUpdateActionRuntimeError,
    build_v4_launcher_update_action,
    launcher_update_action_principal_from_access_token,
    load_v4_launcher_update_action_feature,
    load_v4_launcher_update_execution_feature,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_launcher_update_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_launcher_update_action_feature({}) is False
    assert (
        load_v4_launcher_update_action_feature(
            {V4_LAUNCHER_UPDATE_ACTION_FEATURE_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_launcher_update_action_feature(
            {V4_LAUNCHER_UPDATE_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(V4LauncherUpdateActionConfigurationError, match="exactly true or false"):
        load_v4_launcher_update_action_feature(
            {V4_LAUNCHER_UPDATE_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_launcher_update_execution_gate_is_disabled_by_default_and_exact() -> None:
    assert load_v4_launcher_update_execution_feature({}) is False
    assert (
        load_v4_launcher_update_execution_feature(
            {V4_LAUNCHER_UPDATE_EXECUTION_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_launcher_update_execution_feature(
            {V4_LAUNCHER_UPDATE_EXECUTION_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4LauncherUpdateActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_launcher_update_execution_feature(
            {V4_LAUNCHER_UPDATE_EXECUTION_ENV: "TRUE"}
        )


def test_launcher_update_builder_never_falls_back_to_generic_credentials() -> None:
    with pytest.raises(
        V4LauncherUpdateActionConfigurationError,
        match=V4_LAUNCHER_UPDATE_ACTION_UNAVAILABLE,
    ):
        build_v4_launcher_update_action({V4_LAUNCHER_UPDATE_ACTION_FEATURE_ENV: "true"})


def test_launcher_update_requires_the_non_default_operation_scope() -> None:
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

    with pytest.raises(V4LauncherUpdateActionRuntimeError, match=V4_LAUNCHER_UPDATE_ACTION_UNAVAILABLE):
        launcher_update_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]),
            settings,
        )

    assert isinstance(
        launcher_update_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_launcher_update_action_binds_requester_and_hides_transport_failures() -> None:
    workflow = _Workflow()
    action = ProtectedLauncherUpdateMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("mcp-v4-launcher-01", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(V4LauncherUpdateActionRuntimeError, match=V4_LAUNCHER_UPDATE_ACTION_UNAVAILABLE):
        action.preview("mcp-v4-launcher-02", object())


def test_launcher_update_execution_gate_denies_after_confirmation_without_dispatch() -> None:
    workflow = _Workflow()
    action = ProtectedLauncherUpdateMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("mcp-v4-launcher-01", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    with pytest.raises(
        V4LauncherUpdateActionRuntimeError,
        match=V4_LAUNCHER_UPDATE_ACTION_UNAVAILABLE,
    ):
        action.execute(str(confirmation["authorization_ref"]), principal)

    assert workflow.calls == ["preview", "confirm"]


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["launcher_name"] == "mcp-v4-launcher-01"
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "launcher-update-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "launcher-update-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "launcher-update-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "launcher-update-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
