"""MCP boundary for one controlled FortiPAM Access-level ZTNA transition."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_ZTNA_USER_CONTROL_ACTION_PREFIX = "FORTIPAM_MCP_V4_ZTNA_USER_CONTROL_ACTION_"
V4_ZTNA_USER_CONTROL_ACTION_FEATURE_ENV = (
    f"{V4_ZTNA_USER_CONTROL_ACTION_PREFIX}ENABLED"
)
V4_ZTNA_USER_CONTROL_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_ZTNA_USER_CONTROL_EXECUTION_ENABLED"
)
V4_ZTNA_USER_CONTROL_ROLLBACK_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_ZTNA_USER_CONTROL_ROLLBACK_EXECUTION_ENABLED"
)
V4_ZTNA_USER_CONTROL_PREVIEW_TOOL = "preview_v4_ztna_user_control_configure"
V4_ZTNA_USER_CONTROL_CONFIRM_TOOL = "confirm_v4_ztna_user_control_configure"
V4_ZTNA_USER_CONTROL_ACTION_TOOL = "execute_confirmed_v4_ztna_user_control_configure"
V4_ZTNA_USER_CONTROL_ROLLBACK_PREVIEW_TOOL = (
    "preview_v4_ztna_user_control_rollback"
)
V4_ZTNA_USER_CONTROL_ROLLBACK_CONFIRM_TOOL = (
    "confirm_v4_ztna_user_control_rollback"
)
V4_ZTNA_USER_CONTROL_ROLLBACK_ACTION_TOOL = (
    "execute_confirmed_v4_ztna_user_control_rollback"
)
V4_ZTNA_USER_CONTROL_ACTION_UNAVAILABLE = (
    "FortiPAM V4 ZTNA user-control action is unavailable."
)


class V4ZtnaUserControlActionConfigurationError(ValueError):
    """Raised when the fixed ZTNA user-control action host is unsafe."""


class V4ZtnaUserControlActionRuntimeError(RuntimeError):
    """Stable non-disclosing ZTNA user-control action failure."""


def load_v4_ztna_user_control_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Access-level ZTNA opt-in, defaulting disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ZTNA_USER_CONTROL_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ZtnaUserControlActionConfigurationError(
        f"{V4_ZTNA_USER_CONTROL_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_ztna_user_control_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent forward-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ZTNA_USER_CONTROL_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ZtnaUserControlActionConfigurationError(
        f"{V4_ZTNA_USER_CONTROL_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_ztna_user_control_rollback_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent rollback-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_ZTNA_USER_CONTROL_ROLLBACK_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ZtnaUserControlActionConfigurationError(
        f"{V4_ZTNA_USER_CONTROL_ROLLBACK_EXECUTION_ENV} must be exactly true or false."
    )


def ztna_user_control_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the established HTTP OAuth planning and operation scope."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4ZtnaUserControlActionRuntimeError(
            V4_ZTNA_USER_CONTROL_ACTION_UNAVAILABLE
        ) from exc


class ProtectedZtnaUserControlMcpAction:
    """Expose only C/P/E for one fixed Access-level policy transition."""

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
            raise V4ZtnaUserControlActionRuntimeError(
                V4_ZTNA_USER_CONTROL_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4ZtnaUserControlActionRuntimeError(
                V4_ZTNA_USER_CONTROL_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4ZtnaUserControlActionRuntimeError(
                V4_ZTNA_USER_CONTROL_ACTION_UNAVAILABLE
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
            raise V4ZtnaUserControlActionRuntimeError(
                V4_ZTNA_USER_CONTROL_ACTION_UNAVAILABLE
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
            raise V4ZtnaUserControlActionRuntimeError(
                V4_ZTNA_USER_CONTROL_ACTION_UNAVAILABLE
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
            raise V4ZtnaUserControlActionRuntimeError(
                V4_ZTNA_USER_CONTROL_ACTION_UNAVAILABLE
            ) from exc

    def execute_rollback(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._rollback_execution_enabled:
            raise V4ZtnaUserControlActionRuntimeError(
                V4_ZTNA_USER_CONTROL_ACTION_UNAVAILABLE
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
            raise V4ZtnaUserControlActionRuntimeError(
                V4_ZTNA_USER_CONTROL_ACTION_UNAVAILABLE
            ) from exc


def build_v4_ztna_user_control_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedZtnaUserControlMcpAction:
    """Construct the action only from dedicated pinned SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .ztna_user_control_live_workflow import (
            ZtnaUserControlLiveWorkflow,
            ZtnaUserControlRollbackLiveWorkflow,
        )
        from .ztna_user_control_ssh_transport import (
            FortiPamZtnaUserControlSshTransport,
            load_ztna_user_control_ssh_transport_config,
        )

        transport = FortiPamZtnaUserControlSshTransport(
            load_ztna_user_control_ssh_transport_config(env)
        )
        workflow = ZtnaUserControlLiveWorkflow(transport)
        rollback_workflow = ZtnaUserControlRollbackLiveWorkflow(transport)
    except Exception as exc:
        raise V4ZtnaUserControlActionConfigurationError(
            V4_ZTNA_USER_CONTROL_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedZtnaUserControlMcpAction(
        workflow,
        rollback_workflow=rollback_workflow,
        execution_enabled=load_v4_ztna_user_control_execution_feature(env),
        rollback_execution_enabled=(
            load_v4_ztna_user_control_rollback_execution_feature(env)
        ),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4ZtnaUserControlActionRuntimeError(
            V4_ZTNA_USER_CONTROL_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedZtnaUserControlMcpAction",
    "V4_ZTNA_USER_CONTROL_ACTION_FEATURE_ENV",
    "V4_ZTNA_USER_CONTROL_ACTION_PREFIX",
    "V4_ZTNA_USER_CONTROL_ACTION_TOOL",
    "V4_ZTNA_USER_CONTROL_ACTION_UNAVAILABLE",
    "V4_ZTNA_USER_CONTROL_CONFIRM_TOOL",
    "V4_ZTNA_USER_CONTROL_EXECUTION_ENV",
    "V4_ZTNA_USER_CONTROL_PREVIEW_TOOL",
    "V4_ZTNA_USER_CONTROL_ROLLBACK_ACTION_TOOL",
    "V4_ZTNA_USER_CONTROL_ROLLBACK_CONFIRM_TOOL",
    "V4_ZTNA_USER_CONTROL_ROLLBACK_EXECUTION_ENV",
    "V4_ZTNA_USER_CONTROL_ROLLBACK_PREVIEW_TOOL",
    "V4ZtnaUserControlActionConfigurationError",
    "V4ZtnaUserControlActionRuntimeError",
    "build_v4_ztna_user_control_action",
    "load_v4_ztna_user_control_action_feature",
    "load_v4_ztna_user_control_execution_feature",
    "load_v4_ztna_user_control_rollback_execution_feature",
    "ztna_user_control_action_principal_from_access_token",
]
