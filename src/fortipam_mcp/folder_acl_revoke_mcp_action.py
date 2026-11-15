"""MCP boundary for one controlled FortiPAM Public Folder user-ACL revoke."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_acl_mcp_action import folder_acl_action_principal_from_access_token


V4_FOLDER_ACL_REVOKE_ACTION_PREFIX = "FORTIPAM_MCP_V4_FOLDER_ACL_REVOKE_ACTION_"
V4_FOLDER_ACL_REVOKE_ACTION_FEATURE_ENV = (
    f"{V4_FOLDER_ACL_REVOKE_ACTION_PREFIX}ENABLED"
)
V4_FOLDER_ACL_REVOKE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_FOLDER_ACL_REVOKE_EXECUTION_ENABLED"
)
V4_FOLDER_ACL_REVOKE_PREVIEW_TOOL = "preview_v4_folder_user_acl_revoke"
V4_FOLDER_ACL_REVOKE_CONFIRM_TOOL = "confirm_v4_folder_user_acl_revoke"
V4_FOLDER_ACL_REVOKE_ACTION_TOOL = "execute_confirmed_v4_folder_user_acl_revoke"
V4_FOLDER_ACL_REVOKE_ACTION_UNAVAILABLE = (
    "FortiPAM V4 Folder ACL revoke action is unavailable."
)


class V4FolderAclRevokeActionConfigurationError(ValueError):
    """Raised when the Folder ACL revoke action host is incomplete or unsafe."""


class V4FolderAclRevokeActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Folder ACL revoke action failure."""


def load_v4_folder_acl_revoke_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Folder ACL revoke opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_FOLDER_ACL_REVOKE_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4FolderAclRevokeActionConfigurationError(
        f"{V4_FOLDER_ACL_REVOKE_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_folder_acl_revoke_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_FOLDER_ACL_REVOKE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4FolderAclRevokeActionConfigurationError(
        f"{V4_FOLDER_ACL_REVOKE_EXECUTION_ENV} must be exactly true or false."
    )


def folder_acl_revoke_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as ACL grant."""

    try:
        return folder_acl_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4FolderAclRevokeActionRuntimeError(
            V4_FOLDER_ACL_REVOKE_ACTION_UNAVAILABLE
        ) from exc


class ProtectedFolderAclRevokeMcpAction:
    """Expose C/P/E confirmation and execution for one direct user-ACL revoke."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(
        self,
        folder_id: int,
        username: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    folder_id=folder_id,
                    username=username,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4FolderAclRevokeActionRuntimeError(
                V4_FOLDER_ACL_REVOKE_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4FolderAclRevokeActionRuntimeError(
                V4_FOLDER_ACL_REVOKE_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4FolderAclRevokeActionRuntimeError(
                V4_FOLDER_ACL_REVOKE_ACTION_UNAVAILABLE
            )
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
            raise V4FolderAclRevokeActionRuntimeError(
                V4_FOLDER_ACL_REVOKE_ACTION_UNAVAILABLE
            ) from exc


def build_v4_folder_acl_revoke_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedFolderAclRevokeMcpAction:
    """Construct the API-first revoke action using the accepted Folder transport."""

    env = os.environ if environment is None else environment
    try:
        from .folder_acl_revoke_live_workflow import FolderAclRevokeLiveWorkflow
        from .folder_http_transport import (
            FortiPamFolderHttpTransport,
            load_folder_acl_transport_config,
        )

        workflow = FolderAclRevokeLiveWorkflow(
            FortiPamFolderHttpTransport(load_folder_acl_transport_config(env))
        )
    except Exception as exc:
        raise V4FolderAclRevokeActionConfigurationError(
            V4_FOLDER_ACL_REVOKE_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedFolderAclRevokeMcpAction(
        workflow,
        execution_enabled=load_v4_folder_acl_revoke_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4FolderAclRevokeActionRuntimeError(
            V4_FOLDER_ACL_REVOKE_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedFolderAclRevokeMcpAction",
    "V4_FOLDER_ACL_REVOKE_ACTION_FEATURE_ENV",
    "V4_FOLDER_ACL_REVOKE_ACTION_PREFIX",
    "V4_FOLDER_ACL_REVOKE_ACTION_TOOL",
    "V4_FOLDER_ACL_REVOKE_ACTION_UNAVAILABLE",
    "V4_FOLDER_ACL_REVOKE_CONFIRM_TOOL",
    "V4_FOLDER_ACL_REVOKE_EXECUTION_ENV",
    "V4_FOLDER_ACL_REVOKE_PREVIEW_TOOL",
    "V4FolderAclRevokeActionConfigurationError",
    "V4FolderAclRevokeActionRuntimeError",
    "build_v4_folder_acl_revoke_action",
    "folder_acl_revoke_action_principal_from_access_token",
    "load_v4_folder_acl_revoke_action_feature",
    "load_v4_folder_acl_revoke_execution_feature",
]
