"""MCP boundary for a one-confirmation self-cleaning ZTNA WAD diagnostic."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_ZTNA_WAD_DEBUG_ACTION_PREFIX = "FORTIPAM_MCP_V4_ZTNA_WAD_DEBUG_ACTION_"
V4_ZTNA_WAD_DEBUG_ACTION_FEATURE_ENV = f"{V4_ZTNA_WAD_DEBUG_ACTION_PREFIX}ENABLED"
V4_ZTNA_WAD_DEBUG_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_ZTNA_WAD_DEBUG_EXECUTION_ENABLED"
)
V4_ZTNA_WAD_DEBUG_CAPTURE_WINDOW_ENV = (
    "FPA_HOME_LAB_FPA1_V4_ZTNA_WAD_DEBUG_CAPTURE_WINDOW_SECONDS"
)
V4_ZTNA_WAD_DEBUG_PREVIEW_TOOL = "preview_v4_ztna_wad_debug_diagnostic"
V4_ZTNA_WAD_DEBUG_CONFIRM_TOOL = "confirm_v4_ztna_wad_debug_diagnostic"
V4_ZTNA_WAD_DEBUG_ACTION_TOOL = "execute_confirmed_v4_ztna_wad_debug_diagnostic"
V4_ZTNA_WAD_DEBUG_ACTION_UNAVAILABLE = (
    "FortiPAM V4 ZTNA WAD debug diagnostic is unavailable."
)


class V4ZtnaWadDebugActionConfigurationError(ValueError):
    """Raised when the fixed WAD diagnostic action host is unsafe."""


class V4ZtnaWadDebugActionRuntimeError(RuntimeError):
    """Stable non-disclosing WAD diagnostic action failure."""


def load_v4_ztna_wad_debug_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent WAD diagnostic opt-in, defaulting disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ZTNA_WAD_DEBUG_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ZtnaWadDebugActionConfigurationError(
        f"{V4_ZTNA_WAD_DEBUG_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_ztna_wad_debug_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ZTNA_WAD_DEBUG_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ZtnaWadDebugActionConfigurationError(
        f"{V4_ZTNA_WAD_DEBUG_EXECUTION_ENV} must be exactly true or false."
    )


def ztna_wad_debug_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the established HTTP OAuth planning and operation scope."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4ZtnaWadDebugActionRuntimeError(
            V4_ZTNA_WAD_DEBUG_ACTION_UNAVAILABLE
        ) from exc


class ProtectedZtnaWadDebugMcpAction:
    """Expose only C/P/E for the fixed time-boxed WAD debug sequence."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(dict[str, object], self._workflow.preview(requester_digest=requester_digest))
        except Exception as exc:
            raise V4ZtnaWadDebugActionRuntimeError(
                V4_ZTNA_WAD_DEBUG_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4ZtnaWadDebugActionRuntimeError(
                V4_ZTNA_WAD_DEBUG_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4ZtnaWadDebugActionRuntimeError(
                V4_ZTNA_WAD_DEBUG_ACTION_UNAVAILABLE
            )
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.execute(authorization_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4ZtnaWadDebugActionRuntimeError(
                V4_ZTNA_WAD_DEBUG_ACTION_UNAVAILABLE
            ) from exc


def build_v4_ztna_wad_debug_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedZtnaWadDebugMcpAction:
    """Construct the WAD diagnostic from current Profile SSH and fixed timing."""

    env = os.environ if environment is None else environment
    try:
        from .ztna_wad_debug_live_workflow import ZtnaWadDebugLiveWorkflow
        from .ztna_wad_debug_ssh_transport import (
            FortiPamZtnaWadDebugSshTransport,
            ZtnaWadDebugSshTransportConfig,
        )
        from .antivirus_profile_ssh_transport import (
            load_antivirus_profile_ssh_transport_config,
        )

        current_profile = load_antivirus_profile_ssh_transport_config(env)
        capture_window = float(
            env.get(V4_ZTNA_WAD_DEBUG_CAPTURE_WINDOW_ENV, "10").strip()
        )
        workflow = ZtnaWadDebugLiveWorkflow(
            FortiPamZtnaWadDebugSshTransport(
                ZtnaWadDebugSshTransportConfig(
                    host=current_profile.host,
                    port=current_profile.port,
                    username=current_profile.username,
                    password=current_profile.password,
                    known_hosts_file=current_profile.known_hosts_file,
                    timeout_seconds=max(current_profile.timeout_seconds, 20.0),
                    capture_window_seconds=capture_window,
                )
            )
        )
    except Exception as exc:
        raise V4ZtnaWadDebugActionConfigurationError(
            V4_ZTNA_WAD_DEBUG_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedZtnaWadDebugMcpAction(
        workflow,
        execution_enabled=load_v4_ztna_wad_debug_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4ZtnaWadDebugActionRuntimeError(
            V4_ZTNA_WAD_DEBUG_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedZtnaWadDebugMcpAction",
    "V4_ZTNA_WAD_DEBUG_ACTION_FEATURE_ENV",
    "V4_ZTNA_WAD_DEBUG_ACTION_PREFIX",
    "V4_ZTNA_WAD_DEBUG_ACTION_TOOL",
    "V4_ZTNA_WAD_DEBUG_ACTION_UNAVAILABLE",
    "V4_ZTNA_WAD_DEBUG_CAPTURE_WINDOW_ENV",
    "V4_ZTNA_WAD_DEBUG_CONFIRM_TOOL",
    "V4_ZTNA_WAD_DEBUG_EXECUTION_ENV",
    "V4_ZTNA_WAD_DEBUG_PREVIEW_TOOL",
    "V4ZtnaWadDebugActionConfigurationError",
    "V4ZtnaWadDebugActionRuntimeError",
    "build_v4_ztna_wad_debug_action",
    "load_v4_ztna_wad_debug_action_feature",
    "load_v4_ztna_wad_debug_execution_feature",
    "ztna_wad_debug_action_principal_from_access_token",
]
