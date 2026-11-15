"""Feature-gated MCP boundary for one Local User login-Schedule assignment."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_SCHEDULE_ASSIGN_ACTION_FEATURE_ENV = (
    "FORTIPAM_MCP_V4_SCHEDULE_ASSIGN_ACTION_ENABLED"
)
V4_SCHEDULE_ASSIGN_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_SCHEDULE_ASSIGN_EXECUTION_ENABLED"
)
V4_SCHEDULE_ASSIGN_PREVIEW_TOOL = "preview_v4_schedule_assign"
V4_SCHEDULE_ASSIGN_CONFIRM_TOOL = "confirm_v4_schedule_assign"
V4_SCHEDULE_ASSIGN_ACTION_TOOL = "execute_confirmed_v4_schedule_assign"
V4_SCHEDULE_ASSIGN_DETACH_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_SCHEDULE_ASSIGN_DETACH_EXECUTION_ENABLED"
)
V4_SCHEDULE_ASSIGN_DETACH_PREVIEW_TOOL = "preview_v4_schedule_assignment_detach"
V4_SCHEDULE_ASSIGN_DETACH_CONFIRM_TOOL = "confirm_v4_schedule_assignment_detach"
V4_SCHEDULE_ASSIGN_DETACH_ACTION_TOOL = (
    "execute_confirmed_v4_schedule_assignment_detach"
)
V4_SCHEDULE_ASSIGN_ACTION_UNAVAILABLE = (
    "FortiPAM V4 Schedule assignment is unavailable."
)


class V4ScheduleAssignActionConfigurationError(ValueError):
    """Raised when the assignment action host is incomplete or unsafe."""


class V4ScheduleAssignActionRuntimeError(RuntimeError):
    """Stable non-disclosing assignment action failure."""


def load_v4_schedule_assign_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent assignment opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_SCHEDULE_ASSIGN_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ScheduleAssignActionConfigurationError(
        f"{V4_SCHEDULE_ASSIGN_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_schedule_assign_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_SCHEDULE_ASSIGN_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ScheduleAssignActionConfigurationError(
        f"{V4_SCHEDULE_ASSIGN_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_schedule_assign_detach_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent fixed detach dispatch gate."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_SCHEDULE_ASSIGN_DETACH_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ScheduleAssignActionConfigurationError(
        f"{V4_SCHEDULE_ASSIGN_DETACH_EXECUTION_ENV} must be exactly true or false."
    )


def schedule_assign_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require explicit planning and operation scopes for assignment."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4ScheduleAssignActionRuntimeError(
            V4_SCHEDULE_ASSIGN_ACTION_UNAVAILABLE
        ) from exc


class ProtectedScheduleAssignMcpAction:
    """Bind an authenticated requester to the exact assignment workflow."""

    def __init__(
        self,
        workflow: Any,
        *,
        execution_enabled: bool = True,
        detach_workflow: Any | None = None,
        detach_execution_enabled: bool = False,
    ) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled
        self._detach_workflow = detach_workflow
        self._detach_execution_enabled = detach_execution_enabled

    def preview(
        self,
        username: str,
        schedule_name: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    username=username,
                    schedule_name=schedule_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ScheduleAssignActionRuntimeError(
                V4_SCHEDULE_ASSIGN_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(
                    preview_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ScheduleAssignActionRuntimeError(
                V4_SCHEDULE_ASSIGN_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4ScheduleAssignActionRuntimeError(
                V4_SCHEDULE_ASSIGN_ACTION_UNAVAILABLE
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
            raise V4ScheduleAssignActionRuntimeError(
                V4_SCHEDULE_ASSIGN_ACTION_UNAVAILABLE
            ) from exc

    def preview_detach(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._detach_workflow is None:
            raise V4ScheduleAssignActionRuntimeError(
                V4_SCHEDULE_ASSIGN_ACTION_UNAVAILABLE
            )
        try:
            return cast(
                dict[str, object],
                self._detach_workflow.preview(requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4ScheduleAssignActionRuntimeError(
                V4_SCHEDULE_ASSIGN_ACTION_UNAVAILABLE
            ) from exc

    def confirm_detach(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._detach_workflow is None:
            raise V4ScheduleAssignActionRuntimeError(
                V4_SCHEDULE_ASSIGN_ACTION_UNAVAILABLE
            )
        try:
            return cast(
                dict[str, object],
                self._detach_workflow.confirm(
                    preview_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ScheduleAssignActionRuntimeError(
                V4_SCHEDULE_ASSIGN_ACTION_UNAVAILABLE
            ) from exc

    def execute_detach(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._detach_execution_enabled or self._detach_workflow is None:
            raise V4ScheduleAssignActionRuntimeError(
                V4_SCHEDULE_ASSIGN_ACTION_UNAVAILABLE
            )
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._detach_workflow.execute(
                    authorization_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ScheduleAssignActionRuntimeError(
                V4_SCHEDULE_ASSIGN_ACTION_UNAVAILABLE
            ) from exc


def build_v4_schedule_assign_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedScheduleAssignMcpAction:
    """Build the action from its dedicated fixed User/Schedule API adapter."""

    env = os.environ if environment is None else environment
    try:
        from .schedule_assign_http_transport import (
            FortiPamScheduleAssignHttpTransport,
            load_schedule_assign_http_transport_config,
        )
        from .schedule_assign_detach_live_workflow import (
            ScheduleAssignDetachLiveWorkflow,
        )
        from .schedule_assign_live_workflow import ScheduleAssignLiveWorkflow
        from .schedule_ssh_transport import (
            FortiPamScheduleSshTransport,
            load_schedule_ssh_transport_config,
        )

        transport = FortiPamScheduleAssignHttpTransport(
            load_schedule_assign_http_transport_config(env),
            schedule_ssh_transport=FortiPamScheduleSshTransport(
                load_schedule_ssh_transport_config(env)
            ),
        )
        workflow = ScheduleAssignLiveWorkflow(transport)
        detach_workflow = ScheduleAssignDetachLiveWorkflow(transport)
    except Exception as exc:
        raise V4ScheduleAssignActionConfigurationError(
            V4_SCHEDULE_ASSIGN_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedScheduleAssignMcpAction(
        workflow,
        execution_enabled=load_v4_schedule_assign_execution_feature(env),
        detach_workflow=detach_workflow,
        detach_execution_enabled=(
            load_v4_schedule_assign_detach_execution_feature(env)
        ),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4ScheduleAssignActionRuntimeError(
            V4_SCHEDULE_ASSIGN_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedScheduleAssignMcpAction",
    "V4_SCHEDULE_ASSIGN_ACTION_FEATURE_ENV",
    "V4_SCHEDULE_ASSIGN_ACTION_TOOL",
    "V4_SCHEDULE_ASSIGN_ACTION_UNAVAILABLE",
    "V4_SCHEDULE_ASSIGN_CONFIRM_TOOL",
    "V4_SCHEDULE_ASSIGN_DETACH_ACTION_TOOL",
    "V4_SCHEDULE_ASSIGN_DETACH_CONFIRM_TOOL",
    "V4_SCHEDULE_ASSIGN_DETACH_EXECUTION_ENV",
    "V4_SCHEDULE_ASSIGN_DETACH_PREVIEW_TOOL",
    "V4_SCHEDULE_ASSIGN_EXECUTION_ENV",
    "V4_SCHEDULE_ASSIGN_PREVIEW_TOOL",
    "V4ScheduleAssignActionConfigurationError",
    "V4ScheduleAssignActionRuntimeError",
    "build_v4_schedule_assign_action",
    "load_v4_schedule_assign_action_feature",
    "load_v4_schedule_assign_detach_execution_feature",
    "load_v4_schedule_assign_execution_feature",
    "schedule_assign_action_principal_from_access_token",
]
