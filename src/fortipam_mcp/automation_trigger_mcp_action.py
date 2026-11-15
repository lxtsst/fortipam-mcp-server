"""MCP boundary for one controlled FortiPAM Automation Trigger create."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_AUTOMATION_TRIGGER_ACTION_PREFIX = "FORTIPAM_MCP_V4_AUTOMATION_TRIGGER_ACTION_"
V4_AUTOMATION_TRIGGER_ACTION_FEATURE_ENV = (
    f"{V4_AUTOMATION_TRIGGER_ACTION_PREFIX}ENABLED"
)
V4_AUTOMATION_TRIGGER_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_AUTOMATION_TRIGGER_EXECUTION_ENABLED"
)
V4_AUTOMATION_TRIGGER_PREVIEW_TOOL = "preview_v4_automation_trigger_create"
V4_AUTOMATION_TRIGGER_CONFIRM_TOOL = "confirm_v4_automation_trigger_create"
V4_AUTOMATION_TRIGGER_ACTION_TOOL = "execute_confirmed_v4_automation_trigger_create"
V4_AUTOMATION_TRIGGER_DELETE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_AUTOMATION_TRIGGER_DELETE_EXECUTION_ENABLED"
)
V4_AUTOMATION_TRIGGER_DELETE_PREVIEW_TOOL = "preview_v4_automation_trigger_delete"
V4_AUTOMATION_TRIGGER_DELETE_CONFIRM_TOOL = "confirm_v4_automation_trigger_delete"
V4_AUTOMATION_TRIGGER_DELETE_ACTION_TOOL = (
    "execute_confirmed_v4_automation_trigger_delete"
)
V4_AUTOMATION_TRIGGER_ACTION_UNAVAILABLE = (
    "FortiPAM V4 Automation Trigger create action is unavailable."
)


class V4AutomationTriggerActionConfigurationError(ValueError):
    """Raised when the Automation Trigger action host is incomplete or unsafe."""


class V4AutomationTriggerActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Automation Trigger action failure."""


def load_v4_automation_trigger_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Automation Trigger opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_AUTOMATION_TRIGGER_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4AutomationTriggerActionConfigurationError(
        f"{V4_AUTOMATION_TRIGGER_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_automation_trigger_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_AUTOMATION_TRIGGER_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4AutomationTriggerActionConfigurationError(
        f"{V4_AUTOMATION_TRIGGER_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_automation_trigger_delete_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent fixed Trigger recovery dispatch gate."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_AUTOMATION_TRIGGER_DELETE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4AutomationTriggerActionConfigurationError(
        f"{V4_AUTOMATION_TRIGGER_DELETE_EXECUTION_ENV} must be exactly true or false."
    )


def automation_trigger_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4AutomationTriggerActionRuntimeError(
            V4_AUTOMATION_TRIGGER_ACTION_UNAVAILABLE
        ) from exc


class ProtectedAutomationTriggerMcpAction:
    """Expose only C/P/E, confirmation, and execution for one trigger."""

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

    def preview(self, trigger_name: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    trigger_name=trigger_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4AutomationTriggerActionRuntimeError(
                V4_AUTOMATION_TRIGGER_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4AutomationTriggerActionRuntimeError(
                V4_AUTOMATION_TRIGGER_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4AutomationTriggerActionRuntimeError(
                V4_AUTOMATION_TRIGGER_ACTION_UNAVAILABLE
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
            raise V4AutomationTriggerActionRuntimeError(
                V4_AUTOMATION_TRIGGER_ACTION_UNAVAILABLE
            ) from exc

    def preview_delete(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._delete_workflow is None:
            raise V4AutomationTriggerActionRuntimeError(
                V4_AUTOMATION_TRIGGER_ACTION_UNAVAILABLE
            )
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.preview(requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4AutomationTriggerActionRuntimeError(
                V4_AUTOMATION_TRIGGER_ACTION_UNAVAILABLE
            ) from exc

    def confirm_delete(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._delete_workflow is None:
            raise V4AutomationTriggerActionRuntimeError(
                V4_AUTOMATION_TRIGGER_ACTION_UNAVAILABLE
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
            raise V4AutomationTriggerActionRuntimeError(
                V4_AUTOMATION_TRIGGER_ACTION_UNAVAILABLE
            ) from exc

    def execute_delete(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._delete_execution_enabled or self._delete_workflow is None:
            raise V4AutomationTriggerActionRuntimeError(
                V4_AUTOMATION_TRIGGER_ACTION_UNAVAILABLE
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
            raise V4AutomationTriggerActionRuntimeError(
                V4_AUTOMATION_TRIGGER_ACTION_UNAVAILABLE
            ) from exc


def build_v4_automation_trigger_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedAutomationTriggerMcpAction:
    """Construct the action from dedicated pinned SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .address_http_transport import load_address_http_transport_config
        from .automation_action_ssh_transport import (
            FortiPamAutomationActionSshTransport,
            load_automation_action_ssh_transport_config,
        )
        from .automation_trigger_delete_http_transport import (
            FortiPamAutomationTriggerDeleteHttpTransport,
        )
        from .automation_trigger_delete_live_workflow import (
            AutomationTriggerDeleteLiveWorkflow,
        )
        from .automation_trigger_live_workflow import (
            AutomationTriggerCreateLiveWorkflow,
        )
        from .automation_trigger_ssh_transport import (
            FortiPamAutomationTriggerSshTransport,
            load_automation_trigger_ssh_transport_config,
        )

        trigger_ssh_transport = FortiPamAutomationTriggerSshTransport(
            load_automation_trigger_ssh_transport_config(env)
        )
        workflow = AutomationTriggerCreateLiveWorkflow(trigger_ssh_transport)
        delete_workflow = AutomationTriggerDeleteLiveWorkflow(
            FortiPamAutomationTriggerDeleteHttpTransport(
                load_address_http_transport_config(env),
                trigger_ssh_transport,
                FortiPamAutomationActionSshTransport(
                    load_automation_action_ssh_transport_config(env)
                ),
            )
        )
    except Exception as exc:
        raise V4AutomationTriggerActionConfigurationError(
            V4_AUTOMATION_TRIGGER_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedAutomationTriggerMcpAction(
        workflow,
        execution_enabled=load_v4_automation_trigger_execution_feature(env),
        delete_workflow=delete_workflow,
        delete_execution_enabled=(
            load_v4_automation_trigger_delete_execution_feature(env)
        ),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4AutomationTriggerActionRuntimeError(
            V4_AUTOMATION_TRIGGER_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedAutomationTriggerMcpAction",
    "V4_AUTOMATION_TRIGGER_ACTION_FEATURE_ENV",
    "V4_AUTOMATION_TRIGGER_ACTION_PREFIX",
    "V4_AUTOMATION_TRIGGER_ACTION_TOOL",
    "V4_AUTOMATION_TRIGGER_ACTION_UNAVAILABLE",
    "V4_AUTOMATION_TRIGGER_CONFIRM_TOOL",
    "V4_AUTOMATION_TRIGGER_DELETE_ACTION_TOOL",
    "V4_AUTOMATION_TRIGGER_DELETE_CONFIRM_TOOL",
    "V4_AUTOMATION_TRIGGER_DELETE_EXECUTION_ENV",
    "V4_AUTOMATION_TRIGGER_DELETE_PREVIEW_TOOL",
    "V4_AUTOMATION_TRIGGER_EXECUTION_ENV",
    "V4_AUTOMATION_TRIGGER_PREVIEW_TOOL",
    "V4AutomationTriggerActionConfigurationError",
    "V4AutomationTriggerActionRuntimeError",
    "automation_trigger_action_principal_from_access_token",
    "build_v4_automation_trigger_action",
    "load_v4_automation_trigger_action_feature",
    "load_v4_automation_trigger_delete_execution_feature",
    "load_v4_automation_trigger_execution_feature",
]
