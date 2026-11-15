"""MCP boundary for one controlled FortiPAM recurring Schedule create."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_SCHEDULE_ACTION_PREFIX = "FORTIPAM_MCP_V4_SCHEDULE_"
V4_SCHEDULE_ACTION_FEATURE_ENV = f"{V4_SCHEDULE_ACTION_PREFIX}ENABLED"
V4_SCHEDULE_EXECUTION_ENV = "FORTIPAM_MCP_V4_SCHEDULE_EXECUTION_ENABLED"
V4_SCHEDULE_PREVIEW_TOOL = "preview_v4_schedule_create"
V4_SCHEDULE_CONFIRM_TOOL = "confirm_v4_schedule_create"
V4_SCHEDULE_ACTION_TOOL = "execute_confirmed_v4_schedule_create"
V4_SCHEDULE_DELETE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_SCHEDULE_DELETE_EXECUTION_ENABLED"
)
V4_SCHEDULE_DELETE_PREVIEW_TOOL = "preview_v4_schedule_delete"
V4_SCHEDULE_DELETE_CONFIRM_TOOL = "confirm_v4_schedule_delete"
V4_SCHEDULE_DELETE_ACTION_TOOL = "execute_confirmed_v4_schedule_delete"
V4_SCHEDULE_ACTION_UNAVAILABLE = "FortiPAM V4 Schedule create action is unavailable."


class V4ScheduleActionConfigurationError(ValueError):
    """Raised when the Schedule action host is incomplete or unsafe."""


class V4ScheduleActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Schedule action failure."""


def load_v4_schedule_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Schedule opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_SCHEDULE_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ScheduleActionConfigurationError(
        f"{V4_SCHEDULE_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_schedule_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_SCHEDULE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ScheduleActionConfigurationError(
        f"{V4_SCHEDULE_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_schedule_delete_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent fixed Schedule recovery dispatch gate."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_SCHEDULE_DELETE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ScheduleActionConfigurationError(
        f"{V4_SCHEDULE_DELETE_EXECUTION_ENV} must be exactly true or false."
    )


def schedule_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4ScheduleActionRuntimeError(V4_SCHEDULE_ACTION_UNAVAILABLE) from exc


class ProtectedScheduleMcpAction:
    """Expose controlled create and fixed recovery for one Schedule."""

    def __init__(
        self,
        workflow: Any,
        *,
        execution_enabled: bool = True,
        delete_workflow: Any | None = None,
        delete_execution_enabled: bool = False,
    ) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled
        self._delete_workflow = delete_workflow
        self._delete_execution_enabled = delete_execution_enabled

    def preview(
        self,
        schedule_name: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    schedule_name=schedule_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ScheduleActionRuntimeError(V4_SCHEDULE_ACTION_UNAVAILABLE) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4ScheduleActionRuntimeError(V4_SCHEDULE_ACTION_UNAVAILABLE) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4ScheduleActionRuntimeError(V4_SCHEDULE_ACTION_UNAVAILABLE)
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
            raise V4ScheduleActionRuntimeError(V4_SCHEDULE_ACTION_UNAVAILABLE) from exc

    def preview_delete(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._delete_workflow is None:
            raise V4ScheduleActionRuntimeError(V4_SCHEDULE_ACTION_UNAVAILABLE)
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.preview(requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4ScheduleActionRuntimeError(V4_SCHEDULE_ACTION_UNAVAILABLE) from exc

    def confirm_delete(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._delete_workflow is None:
            raise V4ScheduleActionRuntimeError(V4_SCHEDULE_ACTION_UNAVAILABLE)
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.confirm(
                    preview_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ScheduleActionRuntimeError(V4_SCHEDULE_ACTION_UNAVAILABLE) from exc

    def execute_delete(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._delete_execution_enabled or self._delete_workflow is None:
            raise V4ScheduleActionRuntimeError(V4_SCHEDULE_ACTION_UNAVAILABLE)
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.execute(
                    authorization_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ScheduleActionRuntimeError(V4_SCHEDULE_ACTION_UNAVAILABLE) from exc


def build_v4_schedule_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedScheduleMcpAction:
    """Construct the action from dedicated pinned SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .schedule_assign_http_transport import (
            load_schedule_assign_http_transport_config,
        )
        from .schedule_delete_http_transport import FortiPamScheduleDeleteHttpTransport
        from .schedule_delete_live_workflow import ScheduleDeleteLiveWorkflow
        from .schedule_live_workflow import ScheduleCreateLiveWorkflow
        from .schedule_ssh_transport import (
            FortiPamScheduleSshTransport,
            load_schedule_ssh_transport_config,
        )

        schedule_ssh_transport = FortiPamScheduleSshTransport(
            load_schedule_ssh_transport_config(env)
        )
        workflow = ScheduleCreateLiveWorkflow(schedule_ssh_transport)
        delete_workflow = ScheduleDeleteLiveWorkflow(
            FortiPamScheduleDeleteHttpTransport(
                load_schedule_assign_http_transport_config(env),
                schedule_ssh_transport,
            )
        )
    except Exception as exc:
        raise V4ScheduleActionConfigurationError(
            V4_SCHEDULE_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedScheduleMcpAction(
        workflow,
        execution_enabled=load_v4_schedule_execution_feature(env),
        delete_workflow=delete_workflow,
        delete_execution_enabled=load_v4_schedule_delete_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4ScheduleActionRuntimeError(V4_SCHEDULE_ACTION_UNAVAILABLE) from exc


__all__ = [
    "ProtectedScheduleMcpAction",
    "V4_SCHEDULE_ACTION_FEATURE_ENV",
    "V4_SCHEDULE_ACTION_PREFIX",
    "V4_SCHEDULE_ACTION_TOOL",
    "V4_SCHEDULE_ACTION_UNAVAILABLE",
    "V4_SCHEDULE_CONFIRM_TOOL",
    "V4_SCHEDULE_DELETE_ACTION_TOOL",
    "V4_SCHEDULE_DELETE_CONFIRM_TOOL",
    "V4_SCHEDULE_DELETE_EXECUTION_ENV",
    "V4_SCHEDULE_DELETE_PREVIEW_TOOL",
    "V4_SCHEDULE_EXECUTION_ENV",
    "V4_SCHEDULE_PREVIEW_TOOL",
    "V4ScheduleActionConfigurationError",
    "V4ScheduleActionRuntimeError",
    "build_v4_schedule_action",
    "load_v4_schedule_action_feature",
    "load_v4_schedule_delete_execution_feature",
    "load_v4_schedule_execution_feature",
    "schedule_action_principal_from_access_token",
]
