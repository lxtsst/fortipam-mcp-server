"""MCP boundary for one controlled FortiAnalyzer delivery enable transition."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_FORTIANALYZER_ACTION_PREFIX = "FORTIPAM_MCP_V4_FORTIANALYZER_ACTION_"
V4_FORTIANALYZER_ACTION_FEATURE_ENV = f"{V4_FORTIANALYZER_ACTION_PREFIX}ENABLED"
V4_FORTIANALYZER_EXECUTION_ENV = "FORTIPAM_MCP_V4_FORTIANALYZER_EXECUTION_ENABLED"
V4_FORTIANALYZER_PREVIEW_TOOL = "preview_v4_fortianalyzer_enable"
V4_FORTIANALYZER_CONFIRM_TOOL = "confirm_v4_fortianalyzer_enable"
V4_FORTIANALYZER_ACTION_TOOL = "execute_confirmed_v4_fortianalyzer_enable"
V4_FORTIANALYZER_ACTION_UNAVAILABLE = "FortiPAM V4 FortiAnalyzer action is unavailable."


class V4FortiAnalyzerActionConfigurationError(ValueError):
    """Raised when the fixed FortiAnalyzer action host is unsafe."""


class V4FortiAnalyzerActionRuntimeError(RuntimeError):
    """Stable non-disclosing FortiAnalyzer action failure."""


def load_v4_fortianalyzer_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent FortiAnalyzer opt-in, defaulting disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_FORTIANALYZER_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4FortiAnalyzerActionConfigurationError(
        f"{V4_FORTIANALYZER_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_fortianalyzer_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_FORTIANALYZER_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4FortiAnalyzerActionConfigurationError(
        f"{V4_FORTIANALYZER_EXECUTION_ENV} must be exactly true or false."
    )


def fortianalyzer_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the established HTTP OAuth planning and operation scope."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4FortiAnalyzerActionRuntimeError(
            V4_FORTIANALYZER_ACTION_UNAVAILABLE
        ) from exc


class ProtectedFortiAnalyzerMcpAction:
    """Expose only C/P/E for one fixed FortiAnalyzer enable transition."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(dict[str, object], self._workflow.preview(requester_digest=requester_digest))
        except Exception as exc:
            raise V4FortiAnalyzerActionRuntimeError(
                V4_FORTIANALYZER_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4FortiAnalyzerActionRuntimeError(
                V4_FORTIANALYZER_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4FortiAnalyzerActionRuntimeError(
                V4_FORTIANALYZER_ACTION_UNAVAILABLE
            )
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.execute(authorization_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4FortiAnalyzerActionRuntimeError(
                V4_FORTIANALYZER_ACTION_UNAVAILABLE
            ) from exc


def build_v4_fortianalyzer_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedFortiAnalyzerMcpAction:
    """Construct the action from the current shared Profile SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .fortianalyzer_live_workflow import FortiAnalyzerLiveWorkflow
        from .antivirus_profile_ssh_transport import (
            load_antivirus_profile_ssh_transport_config,
        )
        from .fortianalyzer_ssh_transport import (
            FortiAnalyzerSshTransportConfig,
            FortiPamFortiAnalyzerSshTransport,
        )

        current_profile = load_antivirus_profile_ssh_transport_config(env)

        workflow = FortiAnalyzerLiveWorkflow(
            FortiPamFortiAnalyzerSshTransport(
                FortiAnalyzerSshTransportConfig(
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
        raise V4FortiAnalyzerActionConfigurationError(
            V4_FORTIANALYZER_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedFortiAnalyzerMcpAction(
        workflow,
        execution_enabled=load_v4_fortianalyzer_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4FortiAnalyzerActionRuntimeError(
            V4_FORTIANALYZER_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedFortiAnalyzerMcpAction",
    "V4_FORTIANALYZER_ACTION_FEATURE_ENV",
    "V4_FORTIANALYZER_ACTION_PREFIX",
    "V4_FORTIANALYZER_ACTION_TOOL",
    "V4_FORTIANALYZER_ACTION_UNAVAILABLE",
    "V4_FORTIANALYZER_CONFIRM_TOOL",
    "V4_FORTIANALYZER_EXECUTION_ENV",
    "V4_FORTIANALYZER_PREVIEW_TOOL",
    "V4FortiAnalyzerActionConfigurationError",
    "V4FortiAnalyzerActionRuntimeError",
    "build_v4_fortianalyzer_action",
    "fortianalyzer_action_principal_from_access_token",
    "load_v4_fortianalyzer_action_feature",
    "load_v4_fortianalyzer_execution_feature",
]
