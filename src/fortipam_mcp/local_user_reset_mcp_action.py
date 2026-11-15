"""MCP boundary for one controlled FortiPAM Local User password reset."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_LOCAL_USER_RESET_ACTION_PREFIX = "FORTIPAM_MCP_V4_LOCAL_USER_RESET_ACTION_"
V4_LOCAL_USER_RESET_ACTION_FEATURE_ENV = (
    f"{V4_LOCAL_USER_RESET_ACTION_PREFIX}ENABLED"
)
V4_LOCAL_USER_RESET_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_LOCAL_USER_RESET_EXECUTION_ENABLED"
)
V4_LOCAL_USER_RESET_PREVIEW_TOOL = "preview_v4_local_user_reset"
V4_LOCAL_USER_RESET_CONFIRM_TOOL = "confirm_v4_local_user_reset"
V4_LOCAL_USER_RESET_ACTION_TOOL = "execute_confirmed_v4_local_user_reset"
V4_LOCAL_USER_RESET_ACTION_UNAVAILABLE = (
    "FortiPAM V4 Local User reset action is unavailable."
)


class V4LocalUserResetActionConfigurationError(ValueError):
    """Raised when the reset action host is incomplete or unsafe."""


class V4LocalUserResetActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Local User reset action failure."""


def load_v4_local_user_reset_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent reset opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_LOCAL_USER_RESET_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4LocalUserResetActionConfigurationError(
        f"{V4_LOCAL_USER_RESET_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_local_user_reset_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_LOCAL_USER_RESET_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4LocalUserResetActionConfigurationError(
        f"{V4_LOCAL_USER_RESET_EXECUTION_ENV} must be exactly true or false."
    )


def local_user_reset_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4LocalUserResetActionRuntimeError(
            V4_LOCAL_USER_RESET_ACTION_UNAVAILABLE
        ) from exc


class ProtectedLocalUserResetMcpAction:
    """Expose only C/P/E, confirmation, and one password-reset operation."""

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
            raise V4LocalUserResetActionRuntimeError(
                V4_LOCAL_USER_RESET_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4LocalUserResetActionRuntimeError(
                V4_LOCAL_USER_RESET_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4LocalUserResetActionRuntimeError(
                V4_LOCAL_USER_RESET_ACTION_UNAVAILABLE
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
            raise V4LocalUserResetActionRuntimeError(
                V4_LOCAL_USER_RESET_ACTION_UNAVAILABLE
            ) from exc


def build_v4_local_user_reset_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedLocalUserResetMcpAction:
    """Construct the action using the existing pinned Local User CLI identity.

    The reset feature is independent, while its SSH connector deliberately
    reuses the owner-only V4 Local User create transport settings.  This avoids
    a second unmanaged copy of the same laboratory writer credential.
    """

    env = os.environ if environment is None else environment
    try:
        from .local_user_create_ssh_transport import (
            load_local_user_create_ssh_transport_config,
        )
        from .local_user_reset_live_workflow import LocalUserResetLiveWorkflow
        from .local_user_reset_ssh_transport import FortiPamLocalUserResetSshTransport

        workflow = LocalUserResetLiveWorkflow(
            FortiPamLocalUserResetSshTransport(
                load_local_user_create_ssh_transport_config(env)
            )
        )
    except Exception as exc:
        raise V4LocalUserResetActionConfigurationError(
            V4_LOCAL_USER_RESET_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedLocalUserResetMcpAction(
        workflow,
        execution_enabled=load_v4_local_user_reset_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4LocalUserResetActionRuntimeError(
            V4_LOCAL_USER_RESET_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedLocalUserResetMcpAction",
    "V4_LOCAL_USER_RESET_ACTION_FEATURE_ENV",
    "V4_LOCAL_USER_RESET_ACTION_PREFIX",
    "V4_LOCAL_USER_RESET_ACTION_TOOL",
    "V4_LOCAL_USER_RESET_ACTION_UNAVAILABLE",
    "V4_LOCAL_USER_RESET_CONFIRM_TOOL",
    "V4_LOCAL_USER_RESET_EXECUTION_ENV",
    "V4_LOCAL_USER_RESET_PREVIEW_TOOL",
    "V4LocalUserResetActionConfigurationError",
    "V4LocalUserResetActionRuntimeError",
    "build_v4_local_user_reset_action",
    "load_v4_local_user_reset_action_feature",
    "load_v4_local_user_reset_execution_feature",
    "local_user_reset_action_principal_from_access_token",
]
