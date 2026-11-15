"""MCP boundary for one controlled FortiPAM Public Folder user-ACL grant."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_FOLDER_ACL_ACTION_PREFIX = "FORTIPAM_MCP_V4_FOLDER_ACL_ACTION_"
V4_FOLDER_ACL_ACTION_FEATURE_ENV = f"{V4_FOLDER_ACL_ACTION_PREFIX}ENABLED"
V4_FOLDER_ACL_EXECUTION_ENV = "FORTIPAM_MCP_V4_FOLDER_ACL_EXECUTION_ENABLED"
V4_FOLDER_ACL_PREVIEW_TOOL = "preview_v4_folder_user_acl_grant"
V4_FOLDER_ACL_CONFIRM_TOOL = "confirm_v4_folder_user_acl_grant"
V4_FOLDER_ACL_ACTION_TOOL = "execute_confirmed_v4_folder_user_acl_grant"
V4_FOLDER_ACL_ACTION_UNAVAILABLE = "FortiPAM V4 Folder ACL grant action is unavailable."


class V4FolderAclActionConfigurationError(ValueError):
    """Raised when the Folder ACL action host is incomplete or unsafe."""


class V4FolderAclActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Folder ACL action failure."""


def load_v4_folder_acl_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Folder ACL opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_FOLDER_ACL_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4FolderAclActionConfigurationError(
        f"{V4_FOLDER_ACL_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_folder_acl_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_FOLDER_ACL_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4FolderAclActionConfigurationError(
        f"{V4_FOLDER_ACL_EXECUTION_ENV} must be exactly true or false."
    )


def folder_acl_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as Folder create."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4FolderAclActionRuntimeError(V4_FOLDER_ACL_ACTION_UNAVAILABLE) from exc


class ProtectedFolderAclMcpAction:
    """Expose C/P/E confirmation and execution for one Public Folder user grant."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(
        self,
        folder_id: int,
        username: str,
        folder_permission: str,
        secret_permission: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    folder_id=folder_id,
                    username=username,
                    folder_permission=folder_permission,
                    secret_permission=secret_permission,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4FolderAclActionRuntimeError(
                V4_FOLDER_ACL_ACTION_UNAVAILABLE
            ) from exc

    def preview_group(
        self,
        folder_id: int,
        group_name: str,
        folder_permission: str,
        secret_permission: str,
        principal: Any,
    ) -> dict[str, object]:
        """Bind an internal group grant without registering another MCP Tool."""

        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview_group(
                    folder_id=folder_id,
                    group_name=group_name,
                    folder_permission=folder_permission,
                    secret_permission=secret_permission,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4FolderAclActionRuntimeError(
                V4_FOLDER_ACL_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4FolderAclActionRuntimeError(
                V4_FOLDER_ACL_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4FolderAclActionRuntimeError(V4_FOLDER_ACL_ACTION_UNAVAILABLE)
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.execute(
                    authorization_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4FolderAclActionRuntimeError(
                V4_FOLDER_ACL_ACTION_UNAVAILABLE
            ) from exc


def build_v4_folder_acl_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedFolderAclMcpAction:
    """Construct the API-first Folder ACL action with a dedicated identity."""

    env = os.environ if environment is None else environment
    try:
        from .folder_acl_live_workflow import FolderAclGrantLiveWorkflow
        from .folder_http_transport import (
            FortiPamFolderHttpTransport,
            load_folder_acl_transport_config,
        )

        workflow = FolderAclGrantLiveWorkflow(
            FortiPamFolderHttpTransport(load_folder_acl_transport_config(env))
        )
    except Exception as exc:
        raise V4FolderAclActionConfigurationError(
            V4_FOLDER_ACL_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedFolderAclMcpAction(
        workflow,
        execution_enabled=load_v4_folder_acl_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4FolderAclActionRuntimeError(V4_FOLDER_ACL_ACTION_UNAVAILABLE) from exc


__all__ = [
    "ProtectedFolderAclMcpAction",
    "V4_FOLDER_ACL_ACTION_FEATURE_ENV",
    "V4_FOLDER_ACL_ACTION_PREFIX",
    "V4_FOLDER_ACL_ACTION_TOOL",
    "V4_FOLDER_ACL_ACTION_UNAVAILABLE",
    "V4_FOLDER_ACL_CONFIRM_TOOL",
    "V4_FOLDER_ACL_EXECUTION_ENV",
    "V4_FOLDER_ACL_PREVIEW_TOOL",
    "V4FolderAclActionConfigurationError",
    "V4FolderAclActionRuntimeError",
    "build_v4_folder_acl_action",
    "folder_acl_action_principal_from_access_token",
    "load_v4_folder_acl_action_feature",
    "load_v4_folder_acl_execution_feature",
]
