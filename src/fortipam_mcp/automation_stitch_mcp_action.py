"""MCP boundary for one controlled FortiPAM Automation Stitch create."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_AUTOMATION_STITCH_ACTION_PREFIX = "FORTIPAM_MCP_V4_AUTOMATION_STITCH_"
V4_AUTOMATION_STITCH_ACTION_FEATURE_ENV = (
    f"{V4_AUTOMATION_STITCH_ACTION_PREFIX}ENABLED"
)
V4_AUTOMATION_STITCH_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_AUTOMATION_STITCH_EXECUTION_ENABLED"
)
V4_AUTOMATION_STITCH_PREVIEW_TOOL = "preview_v4_automation_stitch_create"
V4_AUTOMATION_STITCH_CONFIRM_TOOL = "confirm_v4_automation_stitch_create"
V4_AUTOMATION_STITCH_ACTION_TOOL = "execute_confirmed_v4_automation_stitch_create"
V4_AUTOMATION_STITCH_DELETE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_AUTOMATION_STITCH_DELETE_EXECUTION_ENABLED"
)
V4_AUTOMATION_STITCH_DELETE_PREVIEW_TOOL = "preview_v4_automation_stitch_delete"
V4_AUTOMATION_STITCH_DELETE_CONFIRM_TOOL = "confirm_v4_automation_stitch_delete"
V4_AUTOMATION_STITCH_DELETE_ACTION_TOOL = (
    "execute_confirmed_v4_automation_stitch_delete"
)
V4_AUTOMATION_STITCH_ACTION_UNAVAILABLE = (
    "FortiPAM V4 Automation Stitch create action is unavailable."
)


class V4AutomationStitchActionConfigurationError(ValueError):
    """Raised when the Automation Stitch action host is incomplete or unsafe."""


class V4AutomationStitchActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Automation Stitch action failure."""


def load_v4_automation_stitch_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Automation Stitch opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_AUTOMATION_STITCH_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4AutomationStitchActionConfigurationError(
        f"{V4_AUTOMATION_STITCH_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_automation_stitch_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_AUTOMATION_STITCH_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4AutomationStitchActionConfigurationError(
        f"{V4_AUTOMATION_STITCH_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_automation_stitch_delete_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent fixed Stitch recovery dispatch gate."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_AUTOMATION_STITCH_DELETE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4AutomationStitchActionConfigurationError(
        f"{V4_AUTOMATION_STITCH_DELETE_EXECUTION_ENV} must be exactly true or false."
    )


def automation_stitch_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4AutomationStitchActionRuntimeError(
            V4_AUTOMATION_STITCH_ACTION_UNAVAILABLE
        ) from exc


class ProtectedAutomationStitchMcpAction:
    """Expose only C/P/E, confirmation, and execution for one disabled Stitch."""

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
        stitch_name: str,
        trigger_name: str,
        action_name: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    stitch_name=stitch_name,
                    trigger_name=trigger_name,
                    action_name=action_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4AutomationStitchActionRuntimeError(
                V4_AUTOMATION_STITCH_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4AutomationStitchActionRuntimeError(
                V4_AUTOMATION_STITCH_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4AutomationStitchActionRuntimeError(
                V4_AUTOMATION_STITCH_ACTION_UNAVAILABLE
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
            raise V4AutomationStitchActionRuntimeError(
                V4_AUTOMATION_STITCH_ACTION_UNAVAILABLE
            ) from exc

    def preview_delete(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._delete_workflow is None:
            raise V4AutomationStitchActionRuntimeError(
                V4_AUTOMATION_STITCH_ACTION_UNAVAILABLE
            )
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.preview(requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4AutomationStitchActionRuntimeError(
                V4_AUTOMATION_STITCH_ACTION_UNAVAILABLE
            ) from exc

    def confirm_delete(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._delete_workflow is None:
            raise V4AutomationStitchActionRuntimeError(
                V4_AUTOMATION_STITCH_ACTION_UNAVAILABLE
            )
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.confirm(
                    preview_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4AutomationStitchActionRuntimeError(
                V4_AUTOMATION_STITCH_ACTION_UNAVAILABLE
            ) from exc

    def execute_delete(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._delete_execution_enabled or self._delete_workflow is None:
            raise V4AutomationStitchActionRuntimeError(
                V4_AUTOMATION_STITCH_ACTION_UNAVAILABLE
            )
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
            raise V4AutomationStitchActionRuntimeError(
                V4_AUTOMATION_STITCH_ACTION_UNAVAILABLE
            ) from exc


def build_v4_automation_stitch_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedAutomationStitchMcpAction:
    """Construct the action from dedicated pinned SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .address_http_transport import load_address_http_transport_config
        from .automation_stitch_delete_http_transport import (
            FortiPamAutomationStitchDeleteHttpTransport,
        )
        from .automation_stitch_delete_live_workflow import (
            AutomationStitchDeleteLiveWorkflow,
        )
        from .automation_stitch_live_workflow import AutomationStitchCreateLiveWorkflow
        from .automation_stitch_ssh_transport import (
            FortiPamAutomationStitchSshTransport,
            load_automation_stitch_ssh_transport_config,
        )

        ssh_transport = FortiPamAutomationStitchSshTransport(
            load_automation_stitch_ssh_transport_config(env)
        )
        workflow = AutomationStitchCreateLiveWorkflow(ssh_transport)
        delete_workflow = AutomationStitchDeleteLiveWorkflow(
            FortiPamAutomationStitchDeleteHttpTransport(
                load_address_http_transport_config(env),
                ssh_transport,
            )
        )
    except Exception as exc:
        raise V4AutomationStitchActionConfigurationError(
            V4_AUTOMATION_STITCH_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedAutomationStitchMcpAction(
        workflow,
        execution_enabled=load_v4_automation_stitch_execution_feature(env),
        delete_workflow=delete_workflow,
        delete_execution_enabled=(
            load_v4_automation_stitch_delete_execution_feature(env)
        ),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4AutomationStitchActionRuntimeError(
            V4_AUTOMATION_STITCH_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedAutomationStitchMcpAction",
    "V4_AUTOMATION_STITCH_ACTION_FEATURE_ENV",
    "V4_AUTOMATION_STITCH_ACTION_PREFIX",
    "V4_AUTOMATION_STITCH_ACTION_TOOL",
    "V4_AUTOMATION_STITCH_ACTION_UNAVAILABLE",
    "V4_AUTOMATION_STITCH_DELETE_ACTION_TOOL",
    "V4_AUTOMATION_STITCH_DELETE_CONFIRM_TOOL",
    "V4_AUTOMATION_STITCH_DELETE_EXECUTION_ENV",
    "V4_AUTOMATION_STITCH_DELETE_PREVIEW_TOOL",
    "V4_AUTOMATION_STITCH_CONFIRM_TOOL",
    "V4_AUTOMATION_STITCH_EXECUTION_ENV",
    "V4_AUTOMATION_STITCH_PREVIEW_TOOL",
    "V4AutomationStitchActionConfigurationError",
    "V4AutomationStitchActionRuntimeError",
    "automation_stitch_action_principal_from_access_token",
    "build_v4_automation_stitch_action",
    "load_v4_automation_stitch_action_feature",
    "load_v4_automation_stitch_delete_execution_feature",
    "load_v4_automation_stitch_execution_feature",
]
