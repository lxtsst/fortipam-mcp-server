"""MCP boundary for one controlled disabled FortiPAM Auto-Provision Rule."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_APL_ACTION_PREFIX = "FORTIPAM_MCP_V4_APL_"
V4_APL_ACTION_FEATURE_ENV = f"{V4_APL_ACTION_PREFIX}ENABLED"
V4_APL_EXECUTION_ENV = "FORTIPAM_MCP_V4_APL_EXECUTION_ENABLED"
V4_APL_PREVIEW_TOOL = "preview_v4_auto_provision_rule_create"
V4_APL_CONFIRM_TOOL = "confirm_v4_auto_provision_rule_create"
V4_APL_ACTION_TOOL = "execute_confirmed_v4_auto_provision_rule_create"
V4_APL_ACTION_UNAVAILABLE = "FortiPAM V4 Auto-Provision Rule create action is unavailable."


class V4AplActionConfigurationError(ValueError):
    """Raised when the Auto-Provision Rule action host is incomplete or unsafe."""


class V4AplActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Auto-Provision Rule action failure."""


def load_v4_apl_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent APL opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_APL_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4AplActionConfigurationError(
        f"{V4_APL_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_apl_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_APL_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4AplActionConfigurationError(
        f"{V4_APL_EXECUTION_ENV} must be exactly true or false."
    )


def apl_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4AplActionRuntimeError(V4_APL_ACTION_UNAVAILABLE) from exc


class ProtectedAplMcpAction:
    """Expose C/P/E, confirmation, and one disabled APL create."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(
        self,
        auto_provision_rule_name: str,
        remote_user_group_name: str,
        role_name: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    auto_provision_rule_name=auto_provision_rule_name,
                    remote_user_group_name=remote_user_group_name,
                    role_name=role_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4AplActionRuntimeError(V4_APL_ACTION_UNAVAILABLE) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4AplActionRuntimeError(V4_APL_ACTION_UNAVAILABLE) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4AplActionRuntimeError(V4_APL_ACTION_UNAVAILABLE)
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
            raise V4AplActionRuntimeError(V4_APL_ACTION_UNAVAILABLE) from exc


def build_v4_apl_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedAplMcpAction:
    """Construct the action from its explicitly selected dedicated transport."""

    env = os.environ if environment is None else environment
    try:
        from .apl_live_workflow import AplCreateLiveWorkflow
        from .apl_ssh_transport import (
            FortiPamAplSshTransport,
            load_apl_ssh_transport_config,
        )

        transport_kind = env.get(V4_APL_ACTION_PREFIX + "TRANSPORT", "ssh_cli_fallback")
        if transport_kind == "rest_700":
            from .apl_create_http_transport import load_apl_create_http_transport

            workflow = AplCreateLiveWorkflow(
                load_apl_create_http_transport(env), write_transport="rest_700"
            )
        elif transport_kind == "ssh_cli_fallback":
            workflow = AplCreateLiveWorkflow(
                FortiPamAplSshTransport(load_apl_ssh_transport_config(env))
            )
        else:
            raise ValueError("unsupported APL create transport")
    except Exception as exc:
        raise V4AplActionConfigurationError(V4_APL_ACTION_UNAVAILABLE) from exc
    return ProtectedAplMcpAction(
        workflow,
        execution_enabled=load_v4_apl_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4AplActionRuntimeError(V4_APL_ACTION_UNAVAILABLE) from exc


__all__ = [
    "ProtectedAplMcpAction",
    "V4_APL_ACTION_FEATURE_ENV",
    "V4_APL_ACTION_PREFIX",
    "V4_APL_ACTION_TOOL",
    "V4_APL_ACTION_UNAVAILABLE",
    "V4_APL_CONFIRM_TOOL",
    "V4_APL_EXECUTION_ENV",
    "V4_APL_PREVIEW_TOOL",
    "V4AplActionConfigurationError",
    "V4AplActionRuntimeError",
    "apl_action_principal_from_access_token",
    "build_v4_apl_action",
    "load_v4_apl_action_feature",
    "load_v4_apl_execution_feature",
]
