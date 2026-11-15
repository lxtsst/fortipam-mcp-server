"""MCP boundary for one controlled FortiPAM laboratory Role assignment."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_ROLE_ASSIGN_ACTION_PREFIX = "FORTIPAM_MCP_V4_ROLE_ASSIGN_ACTION_"
V4_ROLE_ASSIGN_ACTION_FEATURE_ENV = f"{V4_ROLE_ASSIGN_ACTION_PREFIX}ENABLED"
V4_ROLE_ASSIGN_EXECUTION_ENV = "FORTIPAM_MCP_V4_ROLE_ASSIGN_EXECUTION_ENABLED"
V4_ROLE_ASSIGN_PREVIEW_TOOL = "preview_v4_role_assign"
V4_ROLE_ASSIGN_CONFIRM_TOOL = "confirm_v4_role_assign"
V4_ROLE_ASSIGN_ACTION_TOOL = "execute_confirmed_v4_role_assign"
V4_ROLE_ASSIGN_ACTION_UNAVAILABLE = "FortiPAM V4 Role assignment action is unavailable."


class V4RoleAssignActionConfigurationError(ValueError):
    """Raised when the Role-assignment action host is incomplete or unsafe."""


class V4RoleAssignActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Role-assignment action failure."""


def load_v4_role_assign_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Role-assignment opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ROLE_ASSIGN_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4RoleAssignActionConfigurationError(
        f"{V4_ROLE_ASSIGN_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_role_assign_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ROLE_ASSIGN_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4RoleAssignActionConfigurationError(
        f"{V4_ROLE_ASSIGN_EXECUTION_ENV} must be exactly true or false."
    )


def role_assign_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scopes as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4RoleAssignActionRuntimeError(
            V4_ROLE_ASSIGN_ACTION_UNAVAILABLE
        ) from exc


class ProtectedRoleAssignMcpAction:
    """Expose only C/P/E, confirmation, and one exact REST assignment."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(
        self,
        username: str,
        role_name: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    username=username,
                    role_name=role_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4RoleAssignActionRuntimeError(
                V4_ROLE_ASSIGN_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4RoleAssignActionRuntimeError(
                V4_ROLE_ASSIGN_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4RoleAssignActionRuntimeError(
                V4_ROLE_ASSIGN_ACTION_UNAVAILABLE
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
            raise V4RoleAssignActionRuntimeError(
                V4_ROLE_ASSIGN_ACTION_UNAVAILABLE
            ) from exc


def build_v4_role_assign_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedRoleAssignMcpAction:
    """Construct the Role-assignment action from its dedicated API settings."""

    env = os.environ if environment is None else environment
    try:
        from .role_assign_http_transport import (
            FortiPamRoleAssignHttpTransport,
            load_role_assign_http_transport_config,
        )
        from .role_assign_live_workflow import RoleAssignLiveWorkflow

        workflow = RoleAssignLiveWorkflow(
            FortiPamRoleAssignHttpTransport(
                load_role_assign_http_transport_config(env)
            )
        )
    except Exception as exc:
        raise V4RoleAssignActionConfigurationError(
            V4_ROLE_ASSIGN_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedRoleAssignMcpAction(
        workflow,
        execution_enabled=load_v4_role_assign_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4RoleAssignActionRuntimeError(
            V4_ROLE_ASSIGN_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedRoleAssignMcpAction",
    "V4_ROLE_ASSIGN_ACTION_FEATURE_ENV",
    "V4_ROLE_ASSIGN_ACTION_PREFIX",
    "V4_ROLE_ASSIGN_ACTION_TOOL",
    "V4_ROLE_ASSIGN_ACTION_UNAVAILABLE",
    "V4_ROLE_ASSIGN_CONFIRM_TOOL",
    "V4_ROLE_ASSIGN_EXECUTION_ENV",
    "V4_ROLE_ASSIGN_PREVIEW_TOOL",
    "V4RoleAssignActionConfigurationError",
    "V4RoleAssignActionRuntimeError",
    "build_v4_role_assign_action",
    "load_v4_role_assign_action_feature",
    "load_v4_role_assign_execution_feature",
    "role_assign_action_principal_from_access_token",
]
