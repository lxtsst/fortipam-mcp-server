"""MCP boundary for one controlled FortiPAM native RDP Launcher matcher action."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_LAUNCHER_MATCHER_ACTION_PREFIX = "FORTIPAM_MCP_V4_LAUNCHER_MATCHER_ACTION_"
V4_LAUNCHER_MATCHER_ACTION_FEATURE_ENV = (
    f"{V4_LAUNCHER_MATCHER_ACTION_PREFIX}ENABLED"
)
V4_LAUNCHER_MATCHER_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_LAUNCHER_MATCHER_EXECUTION_ENABLED"
)
V4_LAUNCHER_MATCHER_PREVIEW_TOOL = "preview_v4_launcher_command_line_matcher_configure"
V4_LAUNCHER_MATCHER_CONFIRM_TOOL = "confirm_v4_launcher_command_line_matcher_configure"
V4_LAUNCHER_MATCHER_ACTION_TOOL = (
    "execute_confirmed_v4_launcher_command_line_matcher_configure"
)
V4_LAUNCHER_MATCHER_ACTION_UNAVAILABLE = (
    "FortiPAM V4 Launcher matcher action is unavailable."
)


class V4LauncherMatcherActionConfigurationError(ValueError):
    """Raised when the Launcher-matcher action host is incomplete or unsafe."""


class V4LauncherMatcherActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Launcher-matcher action failure."""


def load_v4_launcher_matcher_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Launcher-matcher opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_LAUNCHER_MATCHER_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4LauncherMatcherActionConfigurationError(
        f"{V4_LAUNCHER_MATCHER_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_launcher_matcher_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_LAUNCHER_MATCHER_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4LauncherMatcherActionConfigurationError(
        f"{V4_LAUNCHER_MATCHER_EXECUTION_ENV} must be exactly true or false."
    )


def launcher_matcher_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4LauncherMatcherActionRuntimeError(
            V4_LAUNCHER_MATCHER_ACTION_UNAVAILABLE
        ) from exc


class ProtectedLauncherMatcherMcpAction:
    """Expose only C/P/E, confirmation, and one fixed Launcher matcher action."""

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
            raise V4LauncherMatcherActionRuntimeError(
                V4_LAUNCHER_MATCHER_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4LauncherMatcherActionRuntimeError(
                V4_LAUNCHER_MATCHER_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4LauncherMatcherActionRuntimeError(
                V4_LAUNCHER_MATCHER_ACTION_UNAVAILABLE
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
            raise V4LauncherMatcherActionRuntimeError(
                V4_LAUNCHER_MATCHER_ACTION_UNAVAILABLE
            ) from exc


def build_v4_launcher_matcher_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedLauncherMatcherMcpAction:
    """Construct the matcher action from dedicated pinned SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .launcher_matcher_live_workflow import LauncherMatcherLiveWorkflow
        from .launcher_ssh_transport import (
            FortiPamLauncherSshTransport,
            load_launcher_matcher_ssh_transport_config,
        )

        workflow = LauncherMatcherLiveWorkflow(
            FortiPamLauncherSshTransport(
                load_launcher_matcher_ssh_transport_config(env)
            )
        )
    except Exception as exc:
        raise V4LauncherMatcherActionConfigurationError(
            V4_LAUNCHER_MATCHER_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedLauncherMatcherMcpAction(
        workflow,
        execution_enabled=load_v4_launcher_matcher_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4LauncherMatcherActionRuntimeError(
            V4_LAUNCHER_MATCHER_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedLauncherMatcherMcpAction",
    "V4_LAUNCHER_MATCHER_ACTION_FEATURE_ENV",
    "V4_LAUNCHER_MATCHER_ACTION_PREFIX",
    "V4_LAUNCHER_MATCHER_ACTION_TOOL",
    "V4_LAUNCHER_MATCHER_ACTION_UNAVAILABLE",
    "V4_LAUNCHER_MATCHER_CONFIRM_TOOL",
    "V4_LAUNCHER_MATCHER_EXECUTION_ENV",
    "V4_LAUNCHER_MATCHER_PREVIEW_TOOL",
    "V4LauncherMatcherActionConfigurationError",
    "V4LauncherMatcherActionRuntimeError",
    "build_v4_launcher_matcher_action",
    "launcher_matcher_action_principal_from_access_token",
    "load_v4_launcher_matcher_action_feature",
    "load_v4_launcher_matcher_execution_feature",
]
