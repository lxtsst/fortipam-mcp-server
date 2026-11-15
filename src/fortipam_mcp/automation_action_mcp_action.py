"""MCP boundary for one controlled FortiPAM Automation Action create."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_AUTOMATION_ACTION_ACTION_PREFIX = "FORTIPAM_MCP_V4_AUTOMATION_ACTION_"
V4_AUTOMATION_ACTION_ACTION_FEATURE_ENV = (
    f"{V4_AUTOMATION_ACTION_ACTION_PREFIX}ENABLED"
)
V4_AUTOMATION_ACTION_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_AUTOMATION_ACTION_EXECUTION_ENABLED"
)
V4_AUTOMATION_ACTION_PREVIEW_TOOL = "preview_v4_automation_action_create"
V4_AUTOMATION_ACTION_CONFIRM_TOOL = "confirm_v4_automation_action_create"
V4_AUTOMATION_ACTION_ACTION_TOOL = "execute_confirmed_v4_automation_action_create"
V4_AUTOMATION_ACTION_DELETE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_AUTOMATION_ACTION_DELETE_EXECUTION_ENABLED"
)
V4_AUTOMATION_ACTION_DELETE_PREVIEW_TOOL = "preview_v4_automation_action_delete"
V4_AUTOMATION_ACTION_DELETE_CONFIRM_TOOL = "confirm_v4_automation_action_delete"
V4_AUTOMATION_ACTION_DELETE_ACTION_TOOL = (
    "execute_confirmed_v4_automation_action_delete"
)
V4_AUTOMATION_ACTION_ACTION_UNAVAILABLE = (
    "FortiPAM V4 Automation Action create action is unavailable."
)


class V4AutomationActionActionConfigurationError(ValueError):
    """Raised when the Automation Action action host is incomplete or unsafe."""


class V4AutomationActionActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Automation Action action failure."""


def load_v4_automation_action_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Automation Action opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_AUTOMATION_ACTION_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4AutomationActionActionConfigurationError(
        f"{V4_AUTOMATION_ACTION_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_automation_action_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_AUTOMATION_ACTION_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4AutomationActionActionConfigurationError(
        f"{V4_AUTOMATION_ACTION_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_automation_action_delete_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent fixed Action recovery dispatch gate."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_AUTOMATION_ACTION_DELETE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4AutomationActionActionConfigurationError(
        f"{V4_AUTOMATION_ACTION_DELETE_EXECUTION_ENV} must be exactly true or false."
    )


def automation_action_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4AutomationActionActionRuntimeError(
            V4_AUTOMATION_ACTION_ACTION_UNAVAILABLE
        ) from exc


class ProtectedAutomationActionMcpAction:
    """Expose only C/P/E, confirmation, and execution for one Action."""

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

    def preview(self, action_name: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    action_name=action_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4AutomationActionActionRuntimeError(
                V4_AUTOMATION_ACTION_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4AutomationActionActionRuntimeError(
                V4_AUTOMATION_ACTION_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4AutomationActionActionRuntimeError(
                V4_AUTOMATION_ACTION_ACTION_UNAVAILABLE
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
            raise V4AutomationActionActionRuntimeError(
                V4_AUTOMATION_ACTION_ACTION_UNAVAILABLE
            ) from exc

    def preview_delete(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._delete_workflow is None:
            raise V4AutomationActionActionRuntimeError(
                V4_AUTOMATION_ACTION_ACTION_UNAVAILABLE
            )
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.preview(requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4AutomationActionActionRuntimeError(
                V4_AUTOMATION_ACTION_ACTION_UNAVAILABLE
            ) from exc

    def confirm_delete(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._delete_workflow is None:
            raise V4AutomationActionActionRuntimeError(
                V4_AUTOMATION_ACTION_ACTION_UNAVAILABLE
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
            raise V4AutomationActionActionRuntimeError(
                V4_AUTOMATION_ACTION_ACTION_UNAVAILABLE
            ) from exc

    def execute_delete(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._delete_execution_enabled or self._delete_workflow is None:
            raise V4AutomationActionActionRuntimeError(
                V4_AUTOMATION_ACTION_ACTION_UNAVAILABLE
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
            raise V4AutomationActionActionRuntimeError(
                V4_AUTOMATION_ACTION_ACTION_UNAVAILABLE
            ) from exc


def build_v4_automation_action_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedAutomationActionMcpAction:
    """Construct the action from dedicated pinned SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .address_http_transport import load_address_http_transport_config
        from .automation_action_delete_http_transport import (
            FortiPamAutomationActionDeleteHttpTransport,
        )
        from .automation_action_delete_live_workflow import (
            AutomationActionDeleteLiveWorkflow,
        )
        from .automation_action_live_workflow import AutomationActionCreateLiveWorkflow
        from .automation_action_ssh_transport import (
            FortiPamAutomationActionSshTransport,
            load_automation_action_ssh_transport_config,
        )

        action_ssh_transport = FortiPamAutomationActionSshTransport(
            load_automation_action_ssh_transport_config(env)
        )
        workflow = AutomationActionCreateLiveWorkflow(action_ssh_transport)
        delete_workflow = AutomationActionDeleteLiveWorkflow(
            FortiPamAutomationActionDeleteHttpTransport(
                load_address_http_transport_config(env),
                action_ssh_transport,
            )
        )
    except Exception as exc:
        raise V4AutomationActionActionConfigurationError(
            V4_AUTOMATION_ACTION_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedAutomationActionMcpAction(
        workflow,
        execution_enabled=load_v4_automation_action_execution_feature(env),
        delete_workflow=delete_workflow,
        delete_execution_enabled=(
            load_v4_automation_action_delete_execution_feature(env)
        ),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4AutomationActionActionRuntimeError(
            V4_AUTOMATION_ACTION_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedAutomationActionMcpAction",
    "V4_AUTOMATION_ACTION_ACTION_FEATURE_ENV",
    "V4_AUTOMATION_ACTION_ACTION_PREFIX",
    "V4_AUTOMATION_ACTION_ACTION_TOOL",
    "V4_AUTOMATION_ACTION_ACTION_UNAVAILABLE",
    "V4_AUTOMATION_ACTION_CONFIRM_TOOL",
    "V4_AUTOMATION_ACTION_DELETE_ACTION_TOOL",
    "V4_AUTOMATION_ACTION_DELETE_CONFIRM_TOOL",
    "V4_AUTOMATION_ACTION_DELETE_EXECUTION_ENV",
    "V4_AUTOMATION_ACTION_DELETE_PREVIEW_TOOL",
    "V4_AUTOMATION_ACTION_EXECUTION_ENV",
    "V4_AUTOMATION_ACTION_PREVIEW_TOOL",
    "V4AutomationActionActionConfigurationError",
    "V4AutomationActionActionRuntimeError",
    "automation_action_action_principal_from_access_token",
    "build_v4_automation_action_action",
    "load_v4_automation_action_action_feature",
    "load_v4_automation_action_delete_execution_feature",
    "load_v4_automation_action_execution_feature",
]
