"""MCP boundary for one controlled FortiPAM maintenance-mode enable transition."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_MAINTENANCE_MODE_ACTION_PREFIX = "FORTIPAM_MCP_V4_MAINTENANCE_MODE_ACTION_"
V4_MAINTENANCE_MODE_ACTION_FEATURE_ENV = f"{V4_MAINTENANCE_MODE_ACTION_PREFIX}ENABLED"
V4_MAINTENANCE_MODE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_MAINTENANCE_MODE_EXECUTION_ENABLED"
)
V4_MAINTENANCE_MODE_ROLLBACK_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_MAINTENANCE_MODE_ROLLBACK_EXECUTION_ENABLED"
)
V4_MAINTENANCE_MODE_PREVIEW_TOOL = "preview_v4_maintenance_mode_enable"
V4_MAINTENANCE_MODE_CONFIRM_TOOL = "confirm_v4_maintenance_mode_enable"
V4_MAINTENANCE_MODE_ACTION_TOOL = "execute_confirmed_v4_maintenance_mode_enable"
V4_MAINTENANCE_MODE_ROLLBACK_PREVIEW_TOOL = "preview_v4_maintenance_mode_rollback"
V4_MAINTENANCE_MODE_ROLLBACK_CONFIRM_TOOL = "confirm_v4_maintenance_mode_rollback"
V4_MAINTENANCE_MODE_ROLLBACK_ACTION_TOOL = (
    "execute_confirmed_v4_maintenance_mode_rollback"
)
V4_MAINTENANCE_MODE_ACTION_UNAVAILABLE = "FortiPAM V4 maintenance mode action is unavailable."


class V4MaintenanceModeActionConfigurationError(ValueError):
    """Raised when the fixed maintenance-mode action host is unsafe."""


class V4MaintenanceModeActionRuntimeError(RuntimeError):
    """Stable non-disclosing maintenance-mode action failure."""


def load_v4_maintenance_mode_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent maintenance-mode opt-in, defaulting disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_MAINTENANCE_MODE_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4MaintenanceModeActionConfigurationError(
        f"{V4_MAINTENANCE_MODE_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_maintenance_mode_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent forward-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_MAINTENANCE_MODE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4MaintenanceModeActionConfigurationError(
        f"{V4_MAINTENANCE_MODE_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_maintenance_mode_rollback_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent rollback-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_MAINTENANCE_MODE_ROLLBACK_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4MaintenanceModeActionConfigurationError(
        f"{V4_MAINTENANCE_MODE_ROLLBACK_EXECUTION_ENV} must be exactly true or false."
    )


def maintenance_mode_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the established HTTP OAuth planning and operation scope."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4MaintenanceModeActionRuntimeError(
            V4_MAINTENANCE_MODE_ACTION_UNAVAILABLE
        ) from exc


class ProtectedMaintenanceModeMcpAction:
    """Expose only C/P/E for one fixed maintenance-mode enable transition."""

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
            raise V4MaintenanceModeActionRuntimeError(
                V4_MAINTENANCE_MODE_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4MaintenanceModeActionRuntimeError(
                V4_MAINTENANCE_MODE_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4MaintenanceModeActionRuntimeError(
                V4_MAINTENANCE_MODE_ACTION_UNAVAILABLE
            )
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.execute(authorization_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4MaintenanceModeActionRuntimeError(
                V4_MAINTENANCE_MODE_ACTION_UNAVAILABLE
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
            raise V4MaintenanceModeActionRuntimeError(
                V4_MAINTENANCE_MODE_ACTION_UNAVAILABLE
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
            raise V4MaintenanceModeActionRuntimeError(
                V4_MAINTENANCE_MODE_ACTION_UNAVAILABLE
            ) from exc

    def execute_rollback(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._rollback_execution_enabled:
            raise V4MaintenanceModeActionRuntimeError(
                V4_MAINTENANCE_MODE_ACTION_UNAVAILABLE
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
            raise V4MaintenanceModeActionRuntimeError(
                V4_MAINTENANCE_MODE_ACTION_UNAVAILABLE
            ) from exc


def build_v4_maintenance_mode_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedMaintenanceModeMcpAction:
    """Construct the successor from exact API status and pinned SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .maintenance_mode_live_workflow import (
            MaintenanceModeLiveWorkflow,
            MaintenanceModeRollbackLiveWorkflow,
        )
        from .maintenance_mode_status_http_transport import (
            FortiPamMaintenanceModeStatusHttpTransport,
            FortiPamMaintenanceModeSuccessorTransport,
            load_maintenance_mode_status_http_transport_config,
        )
        from .maintenance_mode_ssh_transport import (
            FortiPamMaintenanceModeSshTransport,
            load_maintenance_mode_ssh_transport_config,
        )

        transport = FortiPamMaintenanceModeSuccessorTransport(
            FortiPamMaintenanceModeStatusHttpTransport(
                load_maintenance_mode_status_http_transport_config(env)
            ),
            FortiPamMaintenanceModeSshTransport(
                load_maintenance_mode_ssh_transport_config(env)
            ),
        )
        workflow = MaintenanceModeLiveWorkflow(transport)
        rollback_workflow = MaintenanceModeRollbackLiveWorkflow(transport)
    except Exception as exc:
        raise V4MaintenanceModeActionConfigurationError(
            V4_MAINTENANCE_MODE_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedMaintenanceModeMcpAction(
        workflow,
        rollback_workflow=rollback_workflow,
        execution_enabled=load_v4_maintenance_mode_execution_feature(env),
        rollback_execution_enabled=(
            load_v4_maintenance_mode_rollback_execution_feature(env)
        ),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4MaintenanceModeActionRuntimeError(
            V4_MAINTENANCE_MODE_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedMaintenanceModeMcpAction",
    "V4_MAINTENANCE_MODE_ACTION_FEATURE_ENV",
    "V4_MAINTENANCE_MODE_ACTION_PREFIX",
    "V4_MAINTENANCE_MODE_ACTION_TOOL",
    "V4_MAINTENANCE_MODE_ACTION_UNAVAILABLE",
    "V4_MAINTENANCE_MODE_CONFIRM_TOOL",
    "V4_MAINTENANCE_MODE_EXECUTION_ENV",
    "V4_MAINTENANCE_MODE_PREVIEW_TOOL",
    "V4_MAINTENANCE_MODE_ROLLBACK_ACTION_TOOL",
    "V4_MAINTENANCE_MODE_ROLLBACK_CONFIRM_TOOL",
    "V4_MAINTENANCE_MODE_ROLLBACK_EXECUTION_ENV",
    "V4_MAINTENANCE_MODE_ROLLBACK_PREVIEW_TOOL",
    "V4MaintenanceModeActionConfigurationError",
    "V4MaintenanceModeActionRuntimeError",
    "build_v4_maintenance_mode_action",
    "load_v4_maintenance_mode_action_feature",
    "load_v4_maintenance_mode_execution_feature",
    "load_v4_maintenance_mode_rollback_execution_feature",
    "maintenance_mode_action_principal_from_access_token",
]
