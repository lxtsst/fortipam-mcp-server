"""MCP boundary for one controlled FortiPAM Local User disable workflow."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_LOCAL_USER_DISABLE_ACTION_PREFIX = "FORTIPAM_MCP_V4_LOCAL_USER_DISABLE_ACTION_"
V4_LOCAL_USER_DISABLE_ACTION_FEATURE_ENV = (
    f"{V4_LOCAL_USER_DISABLE_ACTION_PREFIX}ENABLED"
)
V4_LOCAL_USER_DISABLE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_LOCAL_USER_DISABLE_EXECUTION_ENABLED"
)
V4_LOCAL_USER_DISABLE_PREVIEW_TOOL = "preview_v4_local_user_disable"
V4_LOCAL_USER_DISABLE_CONFIRM_TOOL = "confirm_v4_local_user_disable"
V4_LOCAL_USER_DISABLE_ACTION_TOOL = "execute_confirmed_v4_local_user_disable"
V4_LOCAL_USER_DISABLE_ACTION_UNAVAILABLE = (
    "FortiPAM V4 Local User disable action is unavailable."
)


class V4LocalUserDisableActionConfigurationError(ValueError):
    """Raised when the Local User action host is incomplete or unsafe."""


class V4LocalUserDisableActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Local User action failure."""


def load_v4_local_user_disable_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Local User disable opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_LOCAL_USER_DISABLE_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4LocalUserDisableActionConfigurationError(
        f"{V4_LOCAL_USER_DISABLE_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_local_user_disable_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_LOCAL_USER_DISABLE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4LocalUserDisableActionConfigurationError(
        f"{V4_LOCAL_USER_DISABLE_EXECUTION_ENV} must be exactly true or false."
    )


def local_user_disable_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4LocalUserDisableActionRuntimeError(
            V4_LOCAL_USER_DISABLE_ACTION_UNAVAILABLE
        ) from exc


class ProtectedLocalUserDisableMcpAction:
    """Expose only C/P/E, confirmation, and execution for one Local User disable."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(self, username: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    username=username,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4LocalUserDisableActionRuntimeError(
                V4_LOCAL_USER_DISABLE_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4LocalUserDisableActionRuntimeError(
                V4_LOCAL_USER_DISABLE_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4LocalUserDisableActionRuntimeError(
                V4_LOCAL_USER_DISABLE_ACTION_UNAVAILABLE
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
            raise V4LocalUserDisableActionRuntimeError(
                V4_LOCAL_USER_DISABLE_ACTION_UNAVAILABLE
            ) from exc


def build_v4_local_user_disable_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedLocalUserDisableMcpAction:
    """Construct the Local User action with the approved V4 API identity."""

    env = os.environ if environment is None else environment
    try:
        from .local_user_http_transport import (
            FortiPamLocalUserHttpTransport,
            load_local_user_http_transport_config,
        )
        from .local_user_live_workflow import LocalUserDisableLiveWorkflow

        workflow = LocalUserDisableLiveWorkflow(
            FortiPamLocalUserHttpTransport(
                load_local_user_http_transport_config(env)
            )
        )
    except Exception as exc:
        raise V4LocalUserDisableActionConfigurationError(
            V4_LOCAL_USER_DISABLE_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedLocalUserDisableMcpAction(
        workflow,
        execution_enabled=load_v4_local_user_disable_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4LocalUserDisableActionRuntimeError(
            V4_LOCAL_USER_DISABLE_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedLocalUserDisableMcpAction",
    "V4_LOCAL_USER_DISABLE_ACTION_FEATURE_ENV",
    "V4_LOCAL_USER_DISABLE_ACTION_PREFIX",
    "V4_LOCAL_USER_DISABLE_ACTION_TOOL",
    "V4_LOCAL_USER_DISABLE_ACTION_UNAVAILABLE",
    "V4_LOCAL_USER_DISABLE_CONFIRM_TOOL",
    "V4_LOCAL_USER_DISABLE_EXECUTION_ENV",
    "V4_LOCAL_USER_DISABLE_PREVIEW_TOOL",
    "V4LocalUserDisableActionConfigurationError",
    "V4LocalUserDisableActionRuntimeError",
    "build_v4_local_user_disable_action",
    "load_v4_local_user_disable_action_feature",
    "load_v4_local_user_disable_execution_feature",
    "local_user_disable_action_principal_from_access_token",
]
