from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.target_update_mcp_action import (
    ProtectedTargetUpdateMcpAction,
    TARGET_UPDATE_PROFILE_WEB_PROXY_ENABLE,
    V4_TARGET_UPDATE_ACTION_FEATURE_ENV,
    V4_TARGET_UPDATE_ACTION_UNAVAILABLE,
    V4_TARGET_UPDATE_DESCRIPTION_EXECUTION_ENV,
    V4_TARGET_WEB_PROXY_EXECUTION_ENV,
    V4TargetUpdateActionConfigurationError,
    V4TargetUpdateActionRuntimeError,
    load_v4_target_update_action_feature,
    load_v4_target_update_description_execution_feature,
    load_v4_target_web_proxy_execution_feature,
    target_update_action_principal_from_access_token,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_target_update_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_target_update_action_feature({}) is False
    assert (
        load_v4_target_update_action_feature(
            {V4_TARGET_UPDATE_ACTION_FEATURE_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_target_update_action_feature(
            {V4_TARGET_UPDATE_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4TargetUpdateActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_target_update_action_feature(
            {V4_TARGET_UPDATE_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_target_update_final_dispatch_gates_default_false_and_are_exact() -> None:
    assert load_v4_target_update_description_execution_feature({}) is False
    assert load_v4_target_web_proxy_execution_feature({}) is False
    assert load_v4_target_update_description_execution_feature(
        {V4_TARGET_UPDATE_DESCRIPTION_EXECUTION_ENV: "true"}
    ) is True
    assert load_v4_target_web_proxy_execution_feature(
        {V4_TARGET_WEB_PROXY_EXECUTION_ENV: "true"}
    ) is True
    with pytest.raises(V4TargetUpdateActionConfigurationError):
        load_v4_target_update_description_execution_feature(
            {V4_TARGET_UPDATE_DESCRIPTION_EXECUTION_ENV: "yes"}
        )
    with pytest.raises(V4TargetUpdateActionConfigurationError):
        load_v4_target_web_proxy_execution_feature(
            {V4_TARGET_WEB_PROXY_EXECUTION_ENV: "yes"}
        )


def test_target_update_final_dispatch_gates_are_profile_specific() -> None:
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    description_workflow = _Workflow()
    action = ProtectedTargetUpdateMcpAction(
        description_workflow,
        description_execution_enabled=False,
        web_proxy_execution_enabled=True,
    )
    preview = action.preview("mcp-target-01", "new description", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    with pytest.raises(V4TargetUpdateActionRuntimeError):
        action.execute(str(confirmation["authorization_ref"]), principal)
    assert description_workflow.calls == ["preview", "confirm"]

    web_proxy_workflow = _WebProxyWorkflow()
    action = ProtectedTargetUpdateMcpAction(
        _Workflow(),
        web_proxy_workflow=web_proxy_workflow,
        description_execution_enabled=True,
        web_proxy_execution_enabled=False,
    )
    preview = action.preview(
        "mcp-target-web-01",
        None,
        principal,
        TARGET_UPDATE_PROFILE_WEB_PROXY_ENABLE,
    )
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    with pytest.raises(V4TargetUpdateActionRuntimeError):
        action.execute(str(confirmation["authorization_ref"]), principal)
    assert web_proxy_workflow.calls == ["preview", "confirm"]


def test_target_update_action_requires_the_non_default_operation_scope() -> None:
    resource = "https://mcp.example.test/fpamcp-v4"
    settings = V4PlanningAuthorizationSettings(resource, b"p" * 32)
    token = AccessToken(
        token="opaque-sdk-validated-access-token",
        client_id="client-0001",
        scopes=["fortipam:read", "fortipam:plan"],
        expires_at=2_000_000_000,
        resource=resource,
        subject="operator-0001",
        claims={"iss": "https://mcp.example.test/oauth"},
    )

    with pytest.raises(
        V4TargetUpdateActionRuntimeError,
        match=V4_TARGET_UPDATE_ACTION_UNAVAILABLE,
    ):
        target_update_action_principal_from_access_token(token, settings)


def test_target_update_action_binds_requester_and_hides_transport_failures() -> None:
    workflow = _Workflow()
    action = ProtectedTargetUpdateMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("mcp-target-01", "new description", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4TargetUpdateActionRuntimeError,
        match=V4_TARGET_UPDATE_ACTION_UNAVAILABLE,
    ):
        action.preview("mcp-target-02", "new description", object())


def test_target_update_action_routes_fixed_web_proxy_profile() -> None:
    description_workflow = _Workflow()
    web_proxy_workflow = _WebProxyWorkflow()
    action = ProtectedTargetUpdateMcpAction(
        description_workflow,
        web_proxy_workflow=web_proxy_workflow,
    )
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(
        "mcp-target-web-01",
        None,
        principal,
        TARGET_UPDATE_PROFILE_WEB_PROXY_ENABLE,
    )
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert description_workflow.calls == []
    assert web_proxy_workflow.calls == ["preview", "confirm", "execute"]


def test_target_update_action_rejects_unbound_or_nonfixed_web_proxy_profile() -> None:
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    action = ProtectedTargetUpdateMcpAction(_Workflow())

    with pytest.raises(
        V4TargetUpdateActionRuntimeError,
        match=V4_TARGET_UPDATE_ACTION_UNAVAILABLE,
    ):
        action.preview(
            "mcp-target-web-01",
            None,
            principal,
            TARGET_UPDATE_PROFILE_WEB_PROXY_ENABLE,
        )
    with pytest.raises(
        V4TargetUpdateActionRuntimeError,
        match=V4_TARGET_UPDATE_ACTION_UNAVAILABLE,
    ):
        action.preview(
            "mcp-target-web-01",
            "unexpected description",
            principal,
            TARGET_UPDATE_PROFILE_WEB_PROXY_ENABLE,
        )


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["requester_digest"] == _requester().digest
        assert kwargs["description"] == "new description"
        return {"preview_ref": "target-update-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "target-update-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "target-update-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "target-update-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}


class _WebProxyWorkflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["target_name"] == "mcp-target-web-01"
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "target-web-proxy-enable-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "target-web-proxy-enable-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "target-web-proxy-enable-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "target-web-proxy-enable-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
