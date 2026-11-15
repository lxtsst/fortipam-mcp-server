from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.folder_policy_detach_mcp_action import (
    ProtectedFolderPolicyDetachMcpAction,
    V4_FOLDER_POLICY_DETACH_ACTION_FEATURE_ENV,
    V4_FOLDER_POLICY_DETACH_ACTION_UNAVAILABLE,
    V4_FOLDER_POLICY_DETACH_EXECUTION_ENV,
    V4FolderPolicyDetachActionConfigurationError,
    V4FolderPolicyDetachActionRuntimeError,
    folder_policy_detach_action_principal_from_access_token,
    load_v4_folder_policy_detach_action_feature,
    load_v4_folder_policy_detach_execution_feature,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_folder_policy_detach_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_folder_policy_detach_action_feature({}) is False
    assert (
        load_v4_folder_policy_detach_action_feature(
            {V4_FOLDER_POLICY_DETACH_ACTION_FEATURE_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_folder_policy_detach_action_feature(
            {V4_FOLDER_POLICY_DETACH_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4FolderPolicyDetachActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_folder_policy_detach_action_feature(
            {V4_FOLDER_POLICY_DETACH_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_folder_policy_detach_execution_gate_is_disabled_by_default_and_exact() -> None:
    assert load_v4_folder_policy_detach_execution_feature({}) is False
    assert (
        load_v4_folder_policy_detach_execution_feature(
            {V4_FOLDER_POLICY_DETACH_EXECUTION_ENV: "true"}
        )
        is True
    )
    with pytest.raises(V4FolderPolicyDetachActionConfigurationError):
        load_v4_folder_policy_detach_execution_feature(
            {V4_FOLDER_POLICY_DETACH_EXECUTION_ENV: "TRUE"}
        )


def test_folder_policy_detach_action_requires_the_non_default_operation_scope() -> None:
    resource = "https://mcp.example.test/fpamcp-v4"
    settings = V4PlanningAuthorizationSettings(resource, b"p" * 32)
    token = AccessToken(
        token="test-token",
        client_id="test-client",
        scopes=["fortipam:read", "fortipam:plan"],
        resource=resource,
    )

    with pytest.raises(
        V4FolderPolicyDetachActionRuntimeError,
        match=V4_FOLDER_POLICY_DETACH_ACTION_UNAVAILABLE,
    ):
        folder_policy_detach_action_principal_from_access_token(token, settings)


def test_folder_policy_detach_action_binds_requester_and_hides_workflow_failures() -> None:
    workflow = _Workflow()
    action = ProtectedFolderPolicyDetachMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(42, principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4FolderPolicyDetachActionRuntimeError,
        match=V4_FOLDER_POLICY_DETACH_ACTION_UNAVAILABLE,
    ):
        action.preview(42, object())


def test_folder_policy_detach_denies_final_dispatch_when_policy_is_off() -> None:
    workflow = _Workflow()
    action = ProtectedFolderPolicyDetachMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(42, principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    with pytest.raises(
        V4FolderPolicyDetachActionRuntimeError,
        match=V4_FOLDER_POLICY_DETACH_ACTION_UNAVAILABLE,
    ):
        action.execute(str(confirmation["authorization_ref"]), principal)

    assert workflow.calls == ["preview", "confirm"]


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["requester_digest"] == _requester().digest
        assert kwargs["folder_id"] == 42
        return {"preview_ref": "folder-policy-detach-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "folder-policy-detach-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "folder-policy-detach-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "folder-policy-detach-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
