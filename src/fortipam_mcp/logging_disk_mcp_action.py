"""MCP boundary for one controlled FortiPAM disk-logging disable transition."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_LOGGING_DISK_ACTION_PREFIX = "FORTIPAM_MCP_V4_LOGGING_DISK_ACTION_"
V4_LOGGING_DISK_ACTION_FEATURE_ENV = f"{V4_LOGGING_DISK_ACTION_PREFIX}ENABLED"
V4_LOGGING_DISK_EXECUTION_ENV = "FORTIPAM_MCP_V4_LOGGING_DISK_EXECUTION_ENABLED"
V4_LOGGING_DISK_PREVIEW_TOOL = "preview_v4_logging_disk_disable"
V4_LOGGING_DISK_CONFIRM_TOOL = "confirm_v4_logging_disk_disable"
V4_LOGGING_DISK_ACTION_TOOL = "execute_confirmed_v4_logging_disk_disable"
V4_LOGGING_DISK_ACTION_UNAVAILABLE = "FortiPAM V4 logging-disk action is unavailable."


class V4LoggingDiskActionConfigurationError(ValueError):
    """Raised when the fixed logging-disk action host is unsafe."""


class V4LoggingDiskActionRuntimeError(RuntimeError):
    """Stable non-disclosing logging-disk action failure."""


def load_v4_logging_disk_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent logging-disk opt-in, defaulting disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_LOGGING_DISK_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4LoggingDiskActionConfigurationError(
        f"{V4_LOGGING_DISK_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_logging_disk_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_LOGGING_DISK_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4LoggingDiskActionConfigurationError(
        f"{V4_LOGGING_DISK_EXECUTION_ENV} must be exactly true or false."
    )


def logging_disk_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the established HTTP OAuth planning and operation scope."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4LoggingDiskActionRuntimeError(V4_LOGGING_DISK_ACTION_UNAVAILABLE) from exc


class ProtectedLoggingDiskMcpAction:
    """Expose only C/P/E for one fixed disk-logging disable transition."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(dict[str, object], self._workflow.preview(requester_digest=requester_digest))
        except Exception as exc:
            raise V4LoggingDiskActionRuntimeError(V4_LOGGING_DISK_ACTION_UNAVAILABLE) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4LoggingDiskActionRuntimeError(V4_LOGGING_DISK_ACTION_UNAVAILABLE) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4LoggingDiskActionRuntimeError(V4_LOGGING_DISK_ACTION_UNAVAILABLE)
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.execute(authorization_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4LoggingDiskActionRuntimeError(V4_LOGGING_DISK_ACTION_UNAVAILABLE) from exc


def build_v4_logging_disk_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedLoggingDiskMcpAction:
    """Construct the action from the current shared Profile SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .logging_disk_live_workflow import LoggingDiskLiveWorkflow
        from .antivirus_profile_ssh_transport import (
            load_antivirus_profile_ssh_transport_config,
        )
        from .logging_disk_ssh_transport import (
            FortiPamLoggingDiskSshTransport,
            LoggingDiskSshTransportConfig,
        )

        current_profile = load_antivirus_profile_ssh_transport_config(env)

        workflow = LoggingDiskLiveWorkflow(
            FortiPamLoggingDiskSshTransport(
                LoggingDiskSshTransportConfig(
                    host=current_profile.host,
                    port=current_profile.port,
                    username=current_profile.username,
                    password=current_profile.password,
                    known_hosts_file=current_profile.known_hosts_file,
                    timeout_seconds=current_profile.timeout_seconds,
                )
            )
        )
    except Exception as exc:
        raise V4LoggingDiskActionConfigurationError(
            V4_LOGGING_DISK_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedLoggingDiskMcpAction(
        workflow,
        execution_enabled=load_v4_logging_disk_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4LoggingDiskActionRuntimeError(V4_LOGGING_DISK_ACTION_UNAVAILABLE) from exc


__all__ = [
    "ProtectedLoggingDiskMcpAction",
    "V4_LOGGING_DISK_ACTION_FEATURE_ENV",
    "V4_LOGGING_DISK_ACTION_PREFIX",
    "V4_LOGGING_DISK_ACTION_TOOL",
    "V4_LOGGING_DISK_ACTION_UNAVAILABLE",
    "V4_LOGGING_DISK_CONFIRM_TOOL",
    "V4_LOGGING_DISK_EXECUTION_ENV",
    "V4_LOGGING_DISK_PREVIEW_TOOL",
    "V4LoggingDiskActionConfigurationError",
    "V4LoggingDiskActionRuntimeError",
    "build_v4_logging_disk_action",
    "load_v4_logging_disk_action_feature",
    "load_v4_logging_disk_execution_feature",
    "logging_disk_action_principal_from_access_token",
]
