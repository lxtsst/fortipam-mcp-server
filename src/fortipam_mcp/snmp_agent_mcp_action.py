"""MCP boundary for one controlled FortiPAM SNMP Agent enable transition."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_SNMP_AGENT_ACTION_PREFIX = "FORTIPAM_MCP_V4_SNMP_AGENT_ACTION_"
V4_SNMP_AGENT_ACTION_FEATURE_ENV = f"{V4_SNMP_AGENT_ACTION_PREFIX}ENABLED"
V4_SNMP_AGENT_EXECUTION_ENV = "FORTIPAM_MCP_V4_SNMP_AGENT_EXECUTION_ENABLED"
V4_SNMP_AGENT_ROLLBACK_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_SNMP_AGENT_ROLLBACK_EXECUTION_ENABLED"
)
V4_SNMP_AGENT_PREVIEW_TOOL = "preview_v4_snmp_agent_enable"
V4_SNMP_AGENT_CONFIRM_TOOL = "confirm_v4_snmp_agent_enable"
V4_SNMP_AGENT_ACTION_TOOL = "execute_confirmed_v4_snmp_agent_enable"
V4_SNMP_AGENT_ROLLBACK_PREVIEW_TOOL = "preview_v4_snmp_agent_rollback"
V4_SNMP_AGENT_ROLLBACK_CONFIRM_TOOL = "confirm_v4_snmp_agent_rollback"
V4_SNMP_AGENT_ROLLBACK_ACTION_TOOL = "execute_confirmed_v4_snmp_agent_rollback"
V4_SNMP_AGENT_ACTION_UNAVAILABLE = "FortiPAM V4 SNMP agent action is unavailable."


class V4SnmpAgentActionConfigurationError(ValueError):
    """Raised when the fixed SNMP agent action host is unsafe."""


class V4SnmpAgentActionRuntimeError(RuntimeError):
    """Stable non-disclosing SNMP agent action failure."""


def load_v4_snmp_agent_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent SNMP agent opt-in, defaulting disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_SNMP_AGENT_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4SnmpAgentActionConfigurationError(
        f"{V4_SNMP_AGENT_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_snmp_agent_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent forward-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_SNMP_AGENT_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4SnmpAgentActionConfigurationError(
        f"{V4_SNMP_AGENT_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_snmp_agent_rollback_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent rollback-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_SNMP_AGENT_ROLLBACK_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4SnmpAgentActionConfigurationError(
        f"{V4_SNMP_AGENT_ROLLBACK_EXECUTION_ENV} must be exactly true or false."
    )


def snmp_agent_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the established HTTP OAuth planning and operation scope."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4SnmpAgentActionRuntimeError(V4_SNMP_AGENT_ACTION_UNAVAILABLE) from exc


class ProtectedSnmpAgentMcpAction:
    """Expose only C/P/E for one fixed preconfigured SNMP Agent transition."""

    def __init__(
        self,
        workflow: Any,
        *,
        rollback_workflow: Any | None = None,
        execution_enabled: bool = True,
        rollback_execution_enabled: bool = True,
    ) -> None:
        self._workflow = workflow
        self._rollback_workflow = rollback_workflow
        self._execution_enabled = execution_enabled
        self._rollback_execution_enabled = rollback_execution_enabled

    def preview(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(dict[str, object], self._workflow.preview(requester_digest=requester_digest))
        except Exception as exc:
            raise V4SnmpAgentActionRuntimeError(V4_SNMP_AGENT_ACTION_UNAVAILABLE) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4SnmpAgentActionRuntimeError(V4_SNMP_AGENT_ACTION_UNAVAILABLE) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4SnmpAgentActionRuntimeError(V4_SNMP_AGENT_ACTION_UNAVAILABLE)
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.execute(authorization_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4SnmpAgentActionRuntimeError(V4_SNMP_AGENT_ACTION_UNAVAILABLE) from exc

    def preview_rollback(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            if self._rollback_workflow is None:
                raise RuntimeError("rollback workflow unavailable")
            return cast(
                dict[str, object],
                self._rollback_workflow.preview(requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4SnmpAgentActionRuntimeError(V4_SNMP_AGENT_ACTION_UNAVAILABLE) from exc

    def confirm_rollback(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            if self._rollback_workflow is None:
                raise RuntimeError("rollback workflow unavailable")
            return cast(
                dict[str, object],
                self._rollback_workflow.confirm(
                    preview_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4SnmpAgentActionRuntimeError(V4_SNMP_AGENT_ACTION_UNAVAILABLE) from exc

    def execute_rollback(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._rollback_execution_enabled:
            raise V4SnmpAgentActionRuntimeError(V4_SNMP_AGENT_ACTION_UNAVAILABLE)
        requester_digest = _requester_digest(principal)
        try:
            if self._rollback_workflow is None:
                raise RuntimeError("rollback workflow unavailable")
            return cast(
                dict[str, object],
                self._rollback_workflow.execute(
                    authorization_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4SnmpAgentActionRuntimeError(V4_SNMP_AGENT_ACTION_UNAVAILABLE) from exc


def build_v4_snmp_agent_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedSnmpAgentMcpAction:
    """Construct the successor from exact API status and pinned SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .snmp_agent_live_workflow import (
            SnmpAgentLiveWorkflow,
            SnmpAgentRollbackLiveWorkflow,
        )
        from .snmp_agent_status_http_transport import (
            FortiPamSnmpAgentStatusHttpTransport,
            FortiPamSnmpAgentSuccessorTransport,
            load_snmp_agent_status_http_transport_config,
        )
        from .snmp_agent_ssh_transport import (
            FortiPamSnmpAgentSshTransport,
            load_snmp_agent_ssh_transport_config,
        )

        transport = FortiPamSnmpAgentSuccessorTransport(
            FortiPamSnmpAgentStatusHttpTransport(
                load_snmp_agent_status_http_transport_config(env)
            ),
            FortiPamSnmpAgentSshTransport(
                load_snmp_agent_ssh_transport_config(env)
            ),
        )
        workflow = SnmpAgentLiveWorkflow(transport)
        rollback_workflow = SnmpAgentRollbackLiveWorkflow(transport)
    except Exception as exc:
        raise V4SnmpAgentActionConfigurationError(
            V4_SNMP_AGENT_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedSnmpAgentMcpAction(
        workflow,
        rollback_workflow=rollback_workflow,
        execution_enabled=load_v4_snmp_agent_execution_feature(env),
        rollback_execution_enabled=load_v4_snmp_agent_rollback_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4SnmpAgentActionRuntimeError(V4_SNMP_AGENT_ACTION_UNAVAILABLE) from exc


__all__ = [
    "ProtectedSnmpAgentMcpAction",
    "V4_SNMP_AGENT_ACTION_FEATURE_ENV",
    "V4_SNMP_AGENT_ACTION_PREFIX",
    "V4_SNMP_AGENT_ACTION_TOOL",
    "V4_SNMP_AGENT_ACTION_UNAVAILABLE",
    "V4_SNMP_AGENT_CONFIRM_TOOL",
    "V4_SNMP_AGENT_EXECUTION_ENV",
    "V4_SNMP_AGENT_PREVIEW_TOOL",
    "V4_SNMP_AGENT_ROLLBACK_ACTION_TOOL",
    "V4_SNMP_AGENT_ROLLBACK_CONFIRM_TOOL",
    "V4_SNMP_AGENT_ROLLBACK_EXECUTION_ENV",
    "V4_SNMP_AGENT_ROLLBACK_PREVIEW_TOOL",
    "V4SnmpAgentActionConfigurationError",
    "V4SnmpAgentActionRuntimeError",
    "build_v4_snmp_agent_action",
    "load_v4_snmp_agent_action_feature",
    "load_v4_snmp_agent_execution_feature",
    "load_v4_snmp_agent_rollback_execution_feature",
    "snmp_agent_action_principal_from_access_token",
]
