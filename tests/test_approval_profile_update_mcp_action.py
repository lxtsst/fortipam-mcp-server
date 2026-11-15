from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.approval_profile_update_mcp_action import (
    ProtectedApprovalProfileUpdateMcpAction,
    V4_APPROVAL_PROFILE_DELETE_EXECUTION_ENV,
    V4_APPROVAL_PROFILE_UPDATE_ACTION_FEATURE_ENV,
    V4_APPROVAL_PROFILE_UPDATE_ACTION_UNAVAILABLE,
    V4_APPROVAL_PROFILE_UPDATE_EXECUTION_ENV,
    V4ApprovalProfileUpdateActionConfigurationError,
    V4ApprovalProfileUpdateActionRuntimeError,
    approval_profile_update_action_principal_from_access_token,
    build_v4_approval_profile_update_action,
    load_v4_approval_profile_update_action_feature,
    load_v4_approval_profile_delete_execution_feature,
    load_v4_approval_profile_update_execution_feature,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_approval_profile_update_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_approval_profile_update_action_feature({}) is False
    assert (
        load_v4_approval_profile_update_action_feature(
            {V4_APPROVAL_PROFILE_UPDATE_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4ApprovalProfileUpdateActionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_approval_profile_update_action_feature(
            {V4_APPROVAL_PROFILE_UPDATE_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_approval_profile_update_final_dispatch_gate_defaults_false_and_is_exact() -> None:
    assert load_v4_approval_profile_update_execution_feature({}) is False
    assert (
        load_v4_approval_profile_update_execution_feature(
            {V4_APPROVAL_PROFILE_UPDATE_EXECUTION_ENV: "true"}
        )
        is True
    )
    with pytest.raises(V4ApprovalProfileUpdateActionConfigurationError):
        load_v4_approval_profile_update_execution_feature(
            {V4_APPROVAL_PROFILE_UPDATE_EXECUTION_ENV: "yes"}
        )
    assert load_v4_approval_profile_delete_execution_feature({}) is False
    assert (
        load_v4_approval_profile_delete_execution_feature(
            {V4_APPROVAL_PROFILE_DELETE_EXECUTION_ENV: "true"}
        )
        is True
    )
    with pytest.raises(V4ApprovalProfileUpdateActionConfigurationError):
        load_v4_approval_profile_delete_execution_feature(
            {V4_APPROVAL_PROFILE_DELETE_EXECUTION_ENV: "TRUE"}
        )


def test_approval_profile_update_final_dispatch_gate_denies_after_confirmation() -> None:
    workflow = _Workflow()
    action = ProtectedApprovalProfileUpdateMcpAction(
        workflow,
        execution_enabled=False,
    )
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    preview = action.preview("mcp-v4-approval-profile-01", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)

    with pytest.raises(V4ApprovalProfileUpdateActionRuntimeError):
        action.execute(str(confirmation["authorization_ref"]), principal)
    assert workflow.calls == ["preview", "confirm"]


def test_approval_profile_update_builder_never_falls_back_to_generic_credentials() -> None:
    with pytest.raises(
        V4ApprovalProfileUpdateActionConfigurationError,
        match=V4_APPROVAL_PROFILE_UPDATE_ACTION_UNAVAILABLE,
    ):
        build_v4_approval_profile_update_action(
            {V4_APPROVAL_PROFILE_UPDATE_ACTION_FEATURE_ENV: "true"}
        )


def test_approval_profile_update_requires_the_non_default_operation_scope() -> None:
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
        V4ApprovalProfileUpdateActionRuntimeError,
        match=V4_APPROVAL_PROFILE_UPDATE_ACTION_UNAVAILABLE,
    ):
        approval_profile_update_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]),
            settings,
        )

    assert isinstance(
        approval_profile_update_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan", "fortipam:operate"]),
            settings,
        ),
        V4PlanningPrincipal,
    )


def test_approval_profile_update_binds_requester_and_hides_transport_failures() -> None:
    workflow = _Workflow()
    action = ProtectedApprovalProfileUpdateMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("mcp-v4-approval-profile-01", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4ApprovalProfileUpdateActionRuntimeError,
        match=V4_APPROVAL_PROFILE_UPDATE_ACTION_UNAVAILABLE,
    ):
        action.preview("mcp-v4-approval-profile-02", object())


def test_delete_action_is_no_input_and_independently_dispatch_gated() -> None:
    workflow = _DeleteWorkflow()
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    denied = ProtectedApprovalProfileUpdateMcpAction(
        _Workflow(),
        delete_workflow=workflow,
        delete_execution_enabled=False,
    )
    preview = denied.preview_delete(principal)
    confirmation = denied.confirm_delete(str(preview["preview_ref"]), principal)
    with pytest.raises(V4ApprovalProfileUpdateActionRuntimeError):
        denied.execute_delete(str(confirmation["authorization_ref"]), principal)
    assert workflow.calls == ["preview", "confirm"]

    workflow = _DeleteWorkflow()
    enabled = ProtectedApprovalProfileUpdateMcpAction(
        _Workflow(),
        execution_enabled=False,
        delete_workflow=workflow,
        delete_execution_enabled=True,
    )
    preview = enabled.preview_delete(principal)
    confirmation = enabled.confirm_delete(str(preview["preview_ref"]), principal)
    result = enabled.execute_delete(str(confirmation["authorization_ref"]), principal)
    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["profile_name"] == "mcp-v4-approval-profile-01"
        assert kwargs["requester_digest"] == _requester().digest
        return {"preview_ref": "approval-profile-update-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "approval-profile-update-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "approval-profile-update-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "approval-profile-update-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}


class _DeleteWorkflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("preview")
        assert requester_digest == _requester().digest
        return {"preview_ref": "approval-profile-delete-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "approval-profile-delete-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "approval-profile-delete-authorized-00000001"}

    def execute(
        self,
        authorization_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "approval-profile-delete-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
