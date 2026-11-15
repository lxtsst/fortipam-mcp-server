"""MCP boundary for one controlled FortiPAM native RDP Launcher create."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_LAUNCHER_ACTION_PREFIX = "FORTIPAM_MCP_V4_LAUNCHER_ACTION_"
V4_LAUNCHER_ACTION_FEATURE_ENV = f"{V4_LAUNCHER_ACTION_PREFIX}ENABLED"
V4_LAUNCHER_EXECUTION_ENV = "FORTIPAM_MCP_V4_LAUNCHER_EXECUTION_ENABLED"
V4_LAUNCHER_PREVIEW_TOOL = "preview_v4_launcher_create"
V4_LAUNCHER_CONFIRM_TOOL = "confirm_v4_launcher_create"
V4_LAUNCHER_ACTION_TOOL = "execute_confirmed_v4_launcher_create"
V4_LAUNCHER_ACTION_UNAVAILABLE = "FortiPAM V4 Launcher create action is unavailable."


class V4LauncherActionConfigurationError(ValueError):
    """Raised when the Launcher action host is incomplete or unsafe."""


class V4LauncherActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Launcher action failure."""


def load_v4_launcher_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Launcher opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_LAUNCHER_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4LauncherActionConfigurationError(
        f"{V4_LAUNCHER_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_launcher_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_LAUNCHER_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4LauncherActionConfigurationError(
        f"{V4_LAUNCHER_EXECUTION_ENV} must be exactly true or false."
    )


def launcher_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4LauncherActionRuntimeError(V4_LAUNCHER_ACTION_UNAVAILABLE) from exc


class ProtectedLauncherMcpAction:
    """Expose only C/P/E, confirmation, and execution for one Launcher."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(self, launcher_name: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    launcher_name=launcher_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4LauncherActionRuntimeError(V4_LAUNCHER_ACTION_UNAVAILABLE) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4LauncherActionRuntimeError(V4_LAUNCHER_ACTION_UNAVAILABLE) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4LauncherActionRuntimeError(V4_LAUNCHER_ACTION_UNAVAILABLE)
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
            raise V4LauncherActionRuntimeError(V4_LAUNCHER_ACTION_UNAVAILABLE) from exc


def build_v4_launcher_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedLauncherMcpAction:
    """Construct the action from dedicated pinned SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .launcher_live_workflow import LauncherCreateLiveWorkflow
        from .launcher_ssh_transport import (
            FortiPamLauncherSshTransport,
            load_launcher_ssh_transport_config,
        )

        workflow = LauncherCreateLiveWorkflow(
            FortiPamLauncherSshTransport(load_launcher_ssh_transport_config(env))
        )
    except Exception as exc:
        raise V4LauncherActionConfigurationError(
            V4_LAUNCHER_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedLauncherMcpAction(
        workflow,
        execution_enabled=load_v4_launcher_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4LauncherActionRuntimeError(V4_LAUNCHER_ACTION_UNAVAILABLE) from exc


__all__ = [
    "ProtectedLauncherMcpAction",
    "V4_LAUNCHER_ACTION_FEATURE_ENV",
    "V4_LAUNCHER_ACTION_PREFIX",
    "V4_LAUNCHER_ACTION_TOOL",
    "V4_LAUNCHER_ACTION_UNAVAILABLE",
    "V4_LAUNCHER_CONFIRM_TOOL",
    "V4_LAUNCHER_EXECUTION_ENV",
    "V4_LAUNCHER_PREVIEW_TOOL",
    "V4LauncherActionConfigurationError",
    "V4LauncherActionRuntimeError",
    "build_v4_launcher_action",
    "launcher_action_principal_from_access_token",
    "load_v4_launcher_action_feature",
    "load_v4_launcher_execution_feature",
]
