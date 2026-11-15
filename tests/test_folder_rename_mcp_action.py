from __future__ import annotations

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.folder_rename_mcp_action import (
    ProtectedFolderRenameMcpAction,
    V4_FOLDER_RENAME_ACTION_FEATURE_ENV,
    V4_FOLDER_RENAME_ACTION_UNAVAILABLE,
    V4_FOLDER_RENAME_EXECUTION_ENV,
    V4FolderRenameActionConfigurationError,
    V4FolderRenameActionRuntimeError,
    folder_rename_action_principal_from_access_token,
    load_v4_folder_rename_action_feature,
    load_v4_folder_rename_execution_feature,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_v4_m3 import _requester


def test_folder_rename_feature_flag_is_disabled_by_default_and_exact() -> None:
    assert load_v4_folder_rename_action_feature({}) is False
    assert (
        load_v4_folder_rename_action_feature(
            {V4_FOLDER_RENAME_ACTION_FEATURE_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_folder_rename_action_feature(
            {V4_FOLDER_RENAME_ACTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(V4FolderRenameActionConfigurationError, match="exactly true or false"):
        load_v4_folder_rename_action_feature(
            {V4_FOLDER_RENAME_ACTION_FEATURE_ENV: "TRUE"}
        )


def test_folder_rename_final_dispatch_gate_defaults_false_and_is_exact() -> None:
    assert load_v4_folder_rename_execution_feature({}) is False
    assert (
        load_v4_folder_rename_execution_feature(
            {V4_FOLDER_RENAME_EXECUTION_ENV: "true"}
        )
        is True
    )
    with pytest.raises(V4FolderRenameActionConfigurationError):
        load_v4_folder_rename_execution_feature(
            {V4_FOLDER_RENAME_EXECUTION_ENV: "yes"}
        )


def test_folder_rename_final_dispatch_gate_denies_after_confirmation() -> None:
    workflow = _Workflow()
    action = ProtectedFolderRenameMcpAction(workflow, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    preview = action.preview(42, "Requested-Folder-Name", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)

    with pytest.raises(V4FolderRenameActionRuntimeError):
        action.execute(str(confirmation["authorization_ref"]), principal)
    assert workflow.calls == ["preview", "confirm"]


def test_folder_rename_action_requires_the_non_default_operation_scope() -> None:
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
        V4FolderRenameActionRuntimeError,
        match=V4_FOLDER_RENAME_ACTION_UNAVAILABLE,
    ):
        folder_rename_action_principal_from_access_token(token, settings)


def test_folder_rename_action_binds_requester_and_hides_transport_failures() -> None:
    workflow = _Workflow()
    action = ProtectedFolderRenameMcpAction(workflow)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview(42, "Requested-Folder-Name", principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result["outcome"] == "succeeded"
    assert workflow.calls == ["preview", "confirm", "execute"]
    with pytest.raises(
        V4FolderRenameActionRuntimeError,
        match=V4_FOLDER_RENAME_ACTION_UNAVAILABLE,
    ):
        action.preview(42, "Requested-Folder-Name", object())


class _Workflow:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preview(self, **kwargs: object) -> dict[str, object]:
        self.calls.append("preview")
        assert kwargs["requester_digest"] == _requester().digest
        assert kwargs["folder_id"] == 42
        assert kwargs["new_name"] == "Requested-Folder-Name"
        return {"preview_ref": "folder-rename-preview-00000001"}

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("confirm")
        assert preview_ref == "folder-rename-preview-00000001"
        assert requester_digest == _requester().digest
        return {"authorization_ref": "folder-rename-authorized-00000001"}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        self.calls.append("execute")
        assert authorization_ref == "folder-rename-authorized-00000001"
        assert requester_digest == _requester().digest
        return {"outcome": "succeeded"}
