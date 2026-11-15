"""MCP boundary for one controlled FortiPAM Role diagnostics-permission update."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_ROLE_UPDATE_ACTION_PREFIX = "FORTIPAM_MCP_V4_ROLE_UPDATE_ACTION_"
V4_ROLE_UPDATE_ACTION_FEATURE_ENV = f"{V4_ROLE_UPDATE_ACTION_PREFIX}ENABLED"
V4_ROLE_UPDATE_EXECUTION_ENV = "FORTIPAM_MCP_V4_ROLE_UPDATE_EXECUTION_ENABLED"
V4_ROLE_UPDATE_PREVIEW_TOOL = "preview_v4_role_diagnostics_enable"
V4_ROLE_UPDATE_CONFIRM_TOOL = "confirm_v4_role_diagnostics_enable"
V4_ROLE_UPDATE_ACTION_TOOL = "execute_confirmed_v4_role_diagnostics_enable"
V4_ROLE_UPDATE_ACTION_UNAVAILABLE = "FortiPAM V4 Role update action is unavailable."


class V4RoleUpdateActionConfigurationError(ValueError):
    """Raised when the Role update action host is incomplete or unsafe."""


class V4RoleUpdateActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Role update action failure."""


def load_v4_role_update_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Role update opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ROLE_UPDATE_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4RoleUpdateActionConfigurationError(
        f"{V4_ROLE_UPDATE_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_role_update_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ROLE_UPDATE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4RoleUpdateActionConfigurationError(
        f"{V4_ROLE_UPDATE_EXECUTION_ENV} must be exactly true or false."
    )


def role_update_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4RoleUpdateActionRuntimeError(
            V4_ROLE_UPDATE_ACTION_UNAVAILABLE
        ) from exc


class ProtectedRoleUpdateMcpAction:
    """Expose only C/P/E, confirmation, and one fixed Role update."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(self, role_name: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    role_name=role_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4RoleUpdateActionRuntimeError(
                V4_ROLE_UPDATE_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4RoleUpdateActionRuntimeError(
                V4_ROLE_UPDATE_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4RoleUpdateActionRuntimeError(V4_ROLE_UPDATE_ACTION_UNAVAILABLE)
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
            raise V4RoleUpdateActionRuntimeError(
                V4_ROLE_UPDATE_ACTION_UNAVAILABLE
            ) from exc


def build_v4_role_update_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedRoleUpdateMcpAction:
    """Use explicit build-29 REST state or the separately configured SSH fallback."""

    env = os.environ if environment is None else environment
    try:
        from .role_create_ssh_transport import (
            FortiPamRoleCreateSshTransport,
            load_role_update_ssh_transport_config,
        )
        from .role_update_http_transport import (
            FortiPamRoleUpdateHttpTransport,
            load_role_update_http_transport_config,
        )
        from .role_update_live_workflow import RoleUpdateLiveWorkflow

        if env.get("FPA_HOME_LAB_FPA1_V4_ROLE_UPDATE_API_ENABLED") == "true":
            workflow = RoleUpdateLiveWorkflow(
                FortiPamRoleUpdateHttpTransport(
                    load_role_update_http_transport_config(env)
                ),
                write_transport="rest_api",
            )
        else:
            ssh_transport = FortiPamRoleCreateSshTransport(
                load_role_update_ssh_transport_config(env)
            )
            workflow = RoleUpdateLiveWorkflow(ssh_transport)
    except Exception as exc:
        raise V4RoleUpdateActionConfigurationError(
            V4_ROLE_UPDATE_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedRoleUpdateMcpAction(
        workflow,
        execution_enabled=load_v4_role_update_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4RoleUpdateActionRuntimeError(
            V4_ROLE_UPDATE_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedRoleUpdateMcpAction",
    "V4_ROLE_UPDATE_ACTION_FEATURE_ENV",
    "V4_ROLE_UPDATE_ACTION_PREFIX",
    "V4_ROLE_UPDATE_ACTION_TOOL",
    "V4_ROLE_UPDATE_ACTION_UNAVAILABLE",
    "V4_ROLE_UPDATE_CONFIRM_TOOL",
    "V4_ROLE_UPDATE_EXECUTION_ENV",
    "V4_ROLE_UPDATE_PREVIEW_TOOL",
    "V4RoleUpdateActionConfigurationError",
    "V4RoleUpdateActionRuntimeError",
    "build_v4_role_update_action",
    "load_v4_role_update_action_feature",
    "load_v4_role_update_execution_feature",
    "role_update_action_principal_from_access_token",
]
