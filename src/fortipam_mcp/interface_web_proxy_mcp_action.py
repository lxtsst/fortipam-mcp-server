"""MCP boundary for one controlled FortiPAM Explicit Web Proxy transition."""

from __future__ import annotations

from collections.abc import Mapping
import os
from pathlib import Path
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_INTERFACE_WEB_PROXY_ACTION_PREFIX = "FORTIPAM_MCP_V4_INTERFACE_WEB_PROXY_ACTION_"
V4_INTERFACE_WEB_PROXY_ACTION_FEATURE_ENV = f"{V4_INTERFACE_WEB_PROXY_ACTION_PREFIX}ENABLED"
V4_INTERFACE_WEB_PROXY_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_INTERFACE_WEB_PROXY_EXECUTION_ENABLED"
)
V4_INTERFACE_WEB_PROXY_ROLLBACK_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_INTERFACE_WEB_PROXY_ROLLBACK_EXECUTION_ENABLED"
)
V4_INTERFACE_WEB_PROXY_SELECTOR_ENV = (
    "FPA_HOME_LAB_FPA1_V4_INTERFACE_WEB_PROXY_INTERFACE_NAME"
)
V4_INTERFACE_WEB_PROXY_PREVIEW_TOOL = "preview_v4_interface_explicit_web_proxy_enable"
V4_INTERFACE_WEB_PROXY_CONFIRM_TOOL = "confirm_v4_interface_explicit_web_proxy_enable"
V4_INTERFACE_WEB_PROXY_ACTION_TOOL = "execute_confirmed_v4_interface_explicit_web_proxy_enable"
V4_INTERFACE_WEB_PROXY_ROLLBACK_PREVIEW_TOOL = (
    "preview_v4_interface_explicit_web_proxy_rollback"
)
V4_INTERFACE_WEB_PROXY_ROLLBACK_CONFIRM_TOOL = (
    "confirm_v4_interface_explicit_web_proxy_rollback"
)
V4_INTERFACE_WEB_PROXY_ROLLBACK_ACTION_TOOL = (
    "execute_confirmed_v4_interface_explicit_web_proxy_rollback"
)
V4_INTERFACE_WEB_PROXY_ACTION_UNAVAILABLE = (
    "FortiPAM V4 interface Explicit Web Proxy action is unavailable."
)


class V4InterfaceWebProxyActionConfigurationError(ValueError):
    """Raised when the fixed interface action host is unsafe."""


class V4InterfaceWebProxyActionRuntimeError(RuntimeError):
    """Stable non-disclosing interface action failure."""


def load_v4_interface_web_proxy_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent interface Web Proxy opt-in, defaulting disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_INTERFACE_WEB_PROXY_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4InterfaceWebProxyActionConfigurationError(
        f"{V4_INTERFACE_WEB_PROXY_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_interface_web_proxy_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_INTERFACE_WEB_PROXY_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4InterfaceWebProxyActionConfigurationError(
        f"{V4_INTERFACE_WEB_PROXY_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_interface_web_proxy_rollback_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent rollback-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_INTERFACE_WEB_PROXY_ROLLBACK_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4InterfaceWebProxyActionConfigurationError(
        f"{V4_INTERFACE_WEB_PROXY_ROLLBACK_EXECUTION_ENV} must be exactly true or false."
    )


def interface_web_proxy_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the established HTTP OAuth planning and operation scope."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4InterfaceWebProxyActionRuntimeError(
            V4_INTERFACE_WEB_PROXY_ACTION_UNAVAILABLE
        ) from exc


class ProtectedInterfaceWebProxyMcpAction:
    """Expose only C/P/E for one fixed existing-interface transition."""

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
            return cast(
                dict[str, object],
                self._workflow.preview(requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4InterfaceWebProxyActionRuntimeError(
                V4_INTERFACE_WEB_PROXY_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4InterfaceWebProxyActionRuntimeError(
                V4_INTERFACE_WEB_PROXY_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4InterfaceWebProxyActionRuntimeError(
                V4_INTERFACE_WEB_PROXY_ACTION_UNAVAILABLE
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
            raise V4InterfaceWebProxyActionRuntimeError(
                V4_INTERFACE_WEB_PROXY_ACTION_UNAVAILABLE
            ) from exc

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
            raise V4InterfaceWebProxyActionRuntimeError(
                V4_INTERFACE_WEB_PROXY_ACTION_UNAVAILABLE
            ) from exc

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
            raise V4InterfaceWebProxyActionRuntimeError(
                V4_INTERFACE_WEB_PROXY_ACTION_UNAVAILABLE
            ) from exc

    def execute_rollback(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._rollback_execution_enabled:
            raise V4InterfaceWebProxyActionRuntimeError(
                V4_INTERFACE_WEB_PROXY_ACTION_UNAVAILABLE
            )
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
            raise V4InterfaceWebProxyActionRuntimeError(
                V4_INTERFACE_WEB_PROXY_ACTION_UNAVAILABLE
            ) from exc


def build_v4_interface_web_proxy_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedInterfaceWebProxyMcpAction:
    """Construct the action from current Profile SSH and one fixed selector."""

    env = os.environ if environment is None else environment
    try:
        from .interface_web_proxy_live_workflow import (
            InterfaceWebProxyLiveWorkflow,
            InterfaceWebProxyRollbackLiveWorkflow,
        )
        from .antivirus_profile_ssh_transport import (
            load_antivirus_profile_ssh_transport_config,
        )
        from .interface_web_proxy_ssh_transport import (
            FortiPamInterfaceWebProxySshTransport,
            InterfaceWebProxySshTransportConfig,
        )

        current_profile = load_antivirus_profile_ssh_transport_config(env)
        interface_name = env.get(V4_INTERFACE_WEB_PROXY_SELECTOR_ENV, "").strip()

        transport = FortiPamInterfaceWebProxySshTransport(
            InterfaceWebProxySshTransportConfig(
                host=current_profile.host,
                port=current_profile.port,
                username=current_profile.username,
                password=current_profile.password,
                known_hosts_file=current_profile.known_hosts_file,
                interface_name=interface_name,
                timeout_seconds=current_profile.timeout_seconds,
                claim_directory=(Path(directory) if (directory := env.get(
                    "FPA_HOME_LAB_FPA1_V4_INTERFACE_WEB_PROXY_CLAIM_DIRECTORY"
                )) else None),
            )
        )
        workflow = InterfaceWebProxyLiveWorkflow(transport)
        rollback_workflow = InterfaceWebProxyRollbackLiveWorkflow(transport)
    except Exception as exc:
        raise V4InterfaceWebProxyActionConfigurationError(
            V4_INTERFACE_WEB_PROXY_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedInterfaceWebProxyMcpAction(
        workflow,
        rollback_workflow=rollback_workflow,
        execution_enabled=load_v4_interface_web_proxy_execution_feature(env),
        rollback_execution_enabled=(
            load_v4_interface_web_proxy_rollback_execution_feature(env)
        ),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4InterfaceWebProxyActionRuntimeError(
            V4_INTERFACE_WEB_PROXY_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedInterfaceWebProxyMcpAction",
    "V4_INTERFACE_WEB_PROXY_ACTION_FEATURE_ENV",
    "V4_INTERFACE_WEB_PROXY_ACTION_PREFIX",
    "V4_INTERFACE_WEB_PROXY_ACTION_TOOL",
    "V4_INTERFACE_WEB_PROXY_ACTION_UNAVAILABLE",
    "V4_INTERFACE_WEB_PROXY_CONFIRM_TOOL",
    "V4_INTERFACE_WEB_PROXY_EXECUTION_ENV",
    "V4_INTERFACE_WEB_PROXY_PREVIEW_TOOL",
    "V4_INTERFACE_WEB_PROXY_ROLLBACK_ACTION_TOOL",
    "V4_INTERFACE_WEB_PROXY_ROLLBACK_CONFIRM_TOOL",
    "V4_INTERFACE_WEB_PROXY_ROLLBACK_EXECUTION_ENV",
    "V4_INTERFACE_WEB_PROXY_ROLLBACK_PREVIEW_TOOL",
    "V4_INTERFACE_WEB_PROXY_SELECTOR_ENV",
    "V4InterfaceWebProxyActionConfigurationError",
    "V4InterfaceWebProxyActionRuntimeError",
    "build_v4_interface_web_proxy_action",
    "interface_web_proxy_action_principal_from_access_token",
    "load_v4_interface_web_proxy_action_feature",
    "load_v4_interface_web_proxy_execution_feature",
    "load_v4_interface_web_proxy_rollback_execution_feature",
]
