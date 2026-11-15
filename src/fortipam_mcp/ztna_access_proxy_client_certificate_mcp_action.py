"""MCP boundary for one controlled FortiPAM ZTNA Access Proxy prerequisite."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_ZTNA_ACCESS_PROXY_ACTION_PREFIX = "FORTIPAM_MCP_V4_ZTNA_ACCESS_PROXY_ACTION_"
V4_ZTNA_ACCESS_PROXY_ACTION_FEATURE_ENV = f"{V4_ZTNA_ACCESS_PROXY_ACTION_PREFIX}ENABLED"
V4_ZTNA_ACCESS_PROXY_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_ZTNA_ACCESS_PROXY_EXECUTION_ENABLED"
)
V4_ZTNA_ACCESS_PROXY_ROLLBACK_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_ZTNA_ACCESS_PROXY_ROLLBACK_EXECUTION_ENABLED"
)
V4_ZTNA_ACCESS_PROXY_SELECTOR_ENV = (
    "FPA_HOME_LAB_FPA1_V4_ZTNA_ACCESS_PROXY_ACCESS_PROXY_NAME"
)
V4_ZTNA_ACCESS_PROXY_PREVIEW_TOOL = "preview_v4_ztna_access_proxy_client_certificate"
V4_ZTNA_ACCESS_PROXY_CONFIRM_TOOL = "confirm_v4_ztna_access_proxy_client_certificate"
V4_ZTNA_ACCESS_PROXY_ACTION_TOOL = "execute_confirmed_v4_ztna_access_proxy_client_certificate"
V4_ZTNA_ACCESS_PROXY_ROLLBACK_PREVIEW_TOOL = (
    "preview_v4_ztna_access_proxy_client_certificate_rollback"
)
V4_ZTNA_ACCESS_PROXY_ROLLBACK_CONFIRM_TOOL = (
    "confirm_v4_ztna_access_proxy_client_certificate_rollback"
)
V4_ZTNA_ACCESS_PROXY_ROLLBACK_ACTION_TOOL = (
    "execute_confirmed_v4_ztna_access_proxy_client_certificate_rollback"
)
V4_ZTNA_ACCESS_PROXY_ACTION_UNAVAILABLE = "FortiPAM V4 ZTNA Access Proxy action is unavailable."


class V4ZtnaAccessProxyActionConfigurationError(ValueError):
    """Raised when the protected ZTNA Access Proxy action host is unsafe."""


class V4ZtnaAccessProxyActionRuntimeError(RuntimeError):
    """Stable non-disclosing ZTNA Access Proxy action failure."""


def load_v4_ztna_access_proxy_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent ZTNA Access Proxy opt-in, defaulting disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ZTNA_ACCESS_PROXY_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ZtnaAccessProxyActionConfigurationError(
        f"{V4_ZTNA_ACCESS_PROXY_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_ztna_access_proxy_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ZTNA_ACCESS_PROXY_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ZtnaAccessProxyActionConfigurationError(
        f"{V4_ZTNA_ACCESS_PROXY_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_ztna_access_proxy_rollback_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent rollback-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ZTNA_ACCESS_PROXY_ROLLBACK_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ZtnaAccessProxyActionConfigurationError(
        f"{V4_ZTNA_ACCESS_PROXY_ROLLBACK_EXECUTION_ENV} must be exactly true or false."
    )


def ztna_access_proxy_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the established HTTP OAuth planning and operation scope."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4ZtnaAccessProxyActionRuntimeError(
            V4_ZTNA_ACCESS_PROXY_ACTION_UNAVAILABLE
        ) from exc


class ProtectedZtnaAccessProxyMcpAction:
    """Expose only C/P/E for one fixed client-certificate prerequisite."""

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

    def preview(
        self,
        endpoint_access_mode: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    endpoint_access_mode=endpoint_access_mode,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ZtnaAccessProxyActionRuntimeError(
                V4_ZTNA_ACCESS_PROXY_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4ZtnaAccessProxyActionRuntimeError(
                V4_ZTNA_ACCESS_PROXY_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4ZtnaAccessProxyActionRuntimeError(
                V4_ZTNA_ACCESS_PROXY_ACTION_UNAVAILABLE
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
            raise V4ZtnaAccessProxyActionRuntimeError(
                V4_ZTNA_ACCESS_PROXY_ACTION_UNAVAILABLE
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
            raise V4ZtnaAccessProxyActionRuntimeError(
                V4_ZTNA_ACCESS_PROXY_ACTION_UNAVAILABLE
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
            raise V4ZtnaAccessProxyActionRuntimeError(
                V4_ZTNA_ACCESS_PROXY_ACTION_UNAVAILABLE
            ) from exc

    def execute_rollback(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._rollback_execution_enabled:
            raise V4ZtnaAccessProxyActionRuntimeError(
                V4_ZTNA_ACCESS_PROXY_ACTION_UNAVAILABLE
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
            raise V4ZtnaAccessProxyActionRuntimeError(
                V4_ZTNA_ACCESS_PROXY_ACTION_UNAVAILABLE
            ) from exc


def build_v4_ztna_access_proxy_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedZtnaAccessProxyMcpAction:
    """Construct the action from current Profile SSH and one fixed selector."""

    env = os.environ if environment is None else environment
    try:
        from .ztna_access_proxy_client_certificate_live_workflow import (
            ZtnaAccessProxyClientCertificateLiveWorkflow,
            ZtnaAccessProxyClientCertificateRollbackLiveWorkflow,
        )
        from .ztna_access_proxy_client_certificate_ssh_transport import (
            FortiPamZtnaAccessProxySshTransport,
            ZtnaAccessProxySshTransportConfig,
        )
        from .antivirus_profile_ssh_transport import (
            load_antivirus_profile_ssh_transport_config,
        )

        current_profile = load_antivirus_profile_ssh_transport_config(env)
        access_proxy_name = env.get(V4_ZTNA_ACCESS_PROXY_SELECTOR_ENV, "").strip()
        transport = FortiPamZtnaAccessProxySshTransport(
            ZtnaAccessProxySshTransportConfig(
                host=current_profile.host,
                port=current_profile.port,
                username=current_profile.username,
                password=current_profile.password,
                known_hosts_file=current_profile.known_hosts_file,
                access_proxy_name=access_proxy_name,
                timeout_seconds=current_profile.timeout_seconds,
            )
        )
        workflow = ZtnaAccessProxyClientCertificateLiveWorkflow(transport)
        rollback_workflow = ZtnaAccessProxyClientCertificateRollbackLiveWorkflow(
            transport
        )
    except Exception as exc:
        raise V4ZtnaAccessProxyActionConfigurationError(
            V4_ZTNA_ACCESS_PROXY_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedZtnaAccessProxyMcpAction(
        workflow,
        rollback_workflow=rollback_workflow,
        execution_enabled=load_v4_ztna_access_proxy_execution_feature(env),
        rollback_execution_enabled=(
            load_v4_ztna_access_proxy_rollback_execution_feature(env)
        ),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4ZtnaAccessProxyActionRuntimeError(
            V4_ZTNA_ACCESS_PROXY_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedZtnaAccessProxyMcpAction",
    "V4_ZTNA_ACCESS_PROXY_ACTION_FEATURE_ENV",
    "V4_ZTNA_ACCESS_PROXY_ACTION_PREFIX",
    "V4_ZTNA_ACCESS_PROXY_ACTION_TOOL",
    "V4_ZTNA_ACCESS_PROXY_ACTION_UNAVAILABLE",
    "V4_ZTNA_ACCESS_PROXY_CONFIRM_TOOL",
    "V4_ZTNA_ACCESS_PROXY_EXECUTION_ENV",
    "V4_ZTNA_ACCESS_PROXY_PREVIEW_TOOL",
    "V4_ZTNA_ACCESS_PROXY_ROLLBACK_ACTION_TOOL",
    "V4_ZTNA_ACCESS_PROXY_ROLLBACK_CONFIRM_TOOL",
    "V4_ZTNA_ACCESS_PROXY_ROLLBACK_EXECUTION_ENV",
    "V4_ZTNA_ACCESS_PROXY_ROLLBACK_PREVIEW_TOOL",
    "V4_ZTNA_ACCESS_PROXY_SELECTOR_ENV",
    "V4ZtnaAccessProxyActionConfigurationError",
    "V4ZtnaAccessProxyActionRuntimeError",
    "build_v4_ztna_access_proxy_action",
    "load_v4_ztna_access_proxy_action_feature",
    "load_v4_ztna_access_proxy_execution_feature",
    "load_v4_ztna_access_proxy_rollback_execution_feature",
    "ztna_access_proxy_action_principal_from_access_token",
]
