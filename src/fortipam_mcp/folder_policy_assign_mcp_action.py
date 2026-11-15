"""MCP boundary for one controlled API-first Public child-Folder policy assignment."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_acl_mcp_action import folder_acl_action_principal_from_access_token


V4_FOLDER_POLICY_ASSIGN_ACTION_PREFIX = "FORTIPAM_MCP_V4_FOLDER_POLICY_ASSIGN_ACTION_"
V4_FOLDER_POLICY_ASSIGN_ACTION_FEATURE_ENV = (
    f"{V4_FOLDER_POLICY_ASSIGN_ACTION_PREFIX}ENABLED"
)
V4_FOLDER_POLICY_ASSIGN_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_FOLDER_POLICY_ASSIGN_EXECUTION_ENABLED"
)
V4_FOLDER_POLICY_ASSIGN_PREVIEW_TOOL = "preview_v4_public_child_folder_policy_assign"
V4_FOLDER_POLICY_ASSIGN_CONFIRM_TOOL = "confirm_v4_public_child_folder_policy_assign"
V4_FOLDER_POLICY_ASSIGN_ACTION_TOOL = (
    "execute_confirmed_v4_public_child_folder_policy_assign"
)
V4_FOLDER_POLICY_ASSIGN_ACTION_UNAVAILABLE = (
    "FortiPAM V4 Public child Folder policy assignment is unavailable."
)


class V4FolderPolicyAssignActionConfigurationError(ValueError):
    """Raised when the Folder policy-assignment host is incomplete or unsafe."""


class V4FolderPolicyAssignActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Folder policy-assignment action failure."""


def load_v4_folder_policy_assign_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Folder policy-assignment opt-in, defaulting off."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_FOLDER_POLICY_ASSIGN_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4FolderPolicyAssignActionConfigurationError(
        f"{V4_FOLDER_POLICY_ASSIGN_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_folder_policy_assign_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_FOLDER_POLICY_ASSIGN_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4FolderPolicyAssignActionConfigurationError(
        f"{V4_FOLDER_POLICY_ASSIGN_EXECUTION_ENV} must be exactly true or false."
    )


def folder_policy_assign_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the explicit planning and operation scope used by Folder writes."""

    try:
        return folder_acl_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4FolderPolicyAssignActionRuntimeError(
            V4_FOLDER_POLICY_ASSIGN_ACTION_UNAVAILABLE
        ) from exc


class ProtectedFolderPolicyAssignMcpAction:
    """Expose C/P/E confirmation and execution for one explicit Folder policy."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(
        self,
        folder_id: int,
        policy_name: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    folder_id=folder_id,
                    policy_name=policy_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4FolderPolicyAssignActionRuntimeError(
                V4_FOLDER_POLICY_ASSIGN_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4FolderPolicyAssignActionRuntimeError(
                V4_FOLDER_POLICY_ASSIGN_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4FolderPolicyAssignActionRuntimeError(
                V4_FOLDER_POLICY_ASSIGN_ACTION_UNAVAILABLE
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
            raise V4FolderPolicyAssignActionRuntimeError(
                V4_FOLDER_POLICY_ASSIGN_ACTION_UNAVAILABLE
            ) from exc


def build_v4_folder_policy_assign_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedFolderPolicyAssignMcpAction:
    """Construct the policy action using the accepted Folder update transport."""

    env = os.environ if environment is None else environment
    try:
        from .folder_http_transport import (
            FortiPamFolderHttpTransport,
            load_folder_acl_transport_config,
        )
        from .folder_policy_assign_live_workflow import FolderPolicyAssignLiveWorkflow

        workflow = FolderPolicyAssignLiveWorkflow(
            FortiPamFolderHttpTransport(load_folder_acl_transport_config(env))
        )
    except Exception as exc:
        raise V4FolderPolicyAssignActionConfigurationError(
            V4_FOLDER_POLICY_ASSIGN_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedFolderPolicyAssignMcpAction(
        workflow,
        execution_enabled=load_v4_folder_policy_assign_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4FolderPolicyAssignActionRuntimeError(
            V4_FOLDER_POLICY_ASSIGN_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedFolderPolicyAssignMcpAction",
    "V4_FOLDER_POLICY_ASSIGN_ACTION_FEATURE_ENV",
    "V4_FOLDER_POLICY_ASSIGN_ACTION_PREFIX",
    "V4_FOLDER_POLICY_ASSIGN_ACTION_TOOL",
    "V4_FOLDER_POLICY_ASSIGN_ACTION_UNAVAILABLE",
    "V4_FOLDER_POLICY_ASSIGN_CONFIRM_TOOL",
    "V4_FOLDER_POLICY_ASSIGN_EXECUTION_ENV",
    "V4_FOLDER_POLICY_ASSIGN_PREVIEW_TOOL",
    "V4FolderPolicyAssignActionConfigurationError",
    "V4FolderPolicyAssignActionRuntimeError",
    "build_v4_folder_policy_assign_action",
    "folder_policy_assign_action_principal_from_access_token",
    "load_v4_folder_policy_assign_action_feature",
    "load_v4_folder_policy_assign_execution_feature",
]
