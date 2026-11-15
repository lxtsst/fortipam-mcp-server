"""MCP boundary for one controlled FortiPAM Report Layout create action."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_acl_mcp_action import folder_acl_action_principal_from_access_token


V4_REPORT_LAYOUT_ACTION_PREFIX = "FORTIPAM_MCP_V4_REPORT_LAYOUT_ACTION_"
V4_REPORT_LAYOUT_ACTION_FEATURE_ENV = f"{V4_REPORT_LAYOUT_ACTION_PREFIX}ENABLED"
V4_REPORT_LAYOUT_EXECUTION_ENV = "FORTIPAM_MCP_V4_REPORT_LAYOUT_EXECUTION_ENABLED"
V4_REPORT_LAYOUT_DELETE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_REPORT_LAYOUT_DELETE_EXECUTION_ENABLED"
)
V4_REPORT_LAYOUT_PREVIEW_TOOL = "preview_v4_report_layout_create"
V4_REPORT_LAYOUT_CONFIRM_TOOL = "confirm_v4_report_layout_create"
V4_REPORT_LAYOUT_ACTION_TOOL = "execute_confirmed_v4_report_layout_create"
V4_REPORT_LAYOUT_DELETE_PREVIEW_TOOL = "preview_v4_report_layout_delete"
V4_REPORT_LAYOUT_DELETE_CONFIRM_TOOL = "confirm_v4_report_layout_delete"
V4_REPORT_LAYOUT_DELETE_ACTION_TOOL = "execute_confirmed_v4_report_layout_delete"
V4_REPORT_LAYOUT_ACTION_UNAVAILABLE = "FortiPAM V4 Report Layout action is unavailable."


class V4ReportLayoutActionConfigurationError(ValueError):
    """Raised when the Report Layout action host is incomplete or unsafe."""


class V4ReportLayoutActionRuntimeError(RuntimeError):
    """Stable non-disclosing Report Layout action failure."""


def load_v4_report_layout_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    env = os.environ if environment is None else environment
    raw = env.get(V4_REPORT_LAYOUT_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ReportLayoutActionConfigurationError(
        f"{V4_REPORT_LAYOUT_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_report_layout_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    env = os.environ if environment is None else environment
    raw = env.get(V4_REPORT_LAYOUT_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ReportLayoutActionConfigurationError(
        f"{V4_REPORT_LAYOUT_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_report_layout_delete_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    env = os.environ if environment is None else environment
    raw = env.get(V4_REPORT_LAYOUT_DELETE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ReportLayoutActionConfigurationError(
        f"{V4_REPORT_LAYOUT_DELETE_EXECUTION_ENV} must be exactly true or false."
    )


def report_layout_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    try:
        return folder_acl_action_principal_from_access_token(
            access_token,
            planning_settings,
        )
    except Exception as exc:
        raise V4ReportLayoutActionRuntimeError(
            V4_REPORT_LAYOUT_ACTION_UNAVAILABLE
        ) from exc


class ProtectedReportLayoutMcpAction:
    """Expose only C/P/E, confirmation, and execution for one layout clone."""

    def __init__(
        self,
        workflow: Any,
        *,
        delete_workflow: Any | None = None,
        execution_enabled: bool = True,
        delete_execution_enabled: bool = False,
    ) -> None:
        self._workflow = workflow
        self._delete_workflow = delete_workflow
        self._execution_enabled = execution_enabled
        self._delete_execution_enabled = delete_execution_enabled

    def preview(self, name: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(name=name, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4ReportLayoutActionRuntimeError(
                V4_REPORT_LAYOUT_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4ReportLayoutActionRuntimeError(
                V4_REPORT_LAYOUT_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4ReportLayoutActionRuntimeError(V4_REPORT_LAYOUT_ACTION_UNAVAILABLE)
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
            raise V4ReportLayoutActionRuntimeError(
                V4_REPORT_LAYOUT_ACTION_UNAVAILABLE
            ) from exc

    def preview_delete(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._delete_workflow is None:
            raise V4ReportLayoutActionRuntimeError(V4_REPORT_LAYOUT_ACTION_UNAVAILABLE)
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.preview(requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4ReportLayoutActionRuntimeError(
                V4_REPORT_LAYOUT_ACTION_UNAVAILABLE
            ) from exc

    def confirm_delete(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._delete_workflow is None:
            raise V4ReportLayoutActionRuntimeError(V4_REPORT_LAYOUT_ACTION_UNAVAILABLE)
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.confirm(
                    preview_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ReportLayoutActionRuntimeError(
                V4_REPORT_LAYOUT_ACTION_UNAVAILABLE
            ) from exc

    def execute_delete(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._delete_execution_enabled or self._delete_workflow is None:
            raise V4ReportLayoutActionRuntimeError(V4_REPORT_LAYOUT_ACTION_UNAVAILABLE)
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
            raise V4ReportLayoutActionRuntimeError(
                V4_REPORT_LAYOUT_ACTION_UNAVAILABLE
            ) from exc


def build_v4_report_layout_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedReportLayoutMcpAction:
    """Construct the Report Layout action with the existing central identity."""

    env = os.environ if environment is None else environment
    try:
        from .report_layout_http_transport import (
            FortiPamReportLayoutHttpTransport,
            load_report_layout_http_transport_config,
        )
        from .report_layout_live_workflow import ReportLayoutCreateLiveWorkflow
        from .report_layout_delete_live_workflow import ReportLayoutDeleteLiveWorkflow

        transport = FortiPamReportLayoutHttpTransport(
            load_report_layout_http_transport_config(env)
        )
        workflow = ReportLayoutCreateLiveWorkflow(transport)
        delete_workflow = ReportLayoutDeleteLiveWorkflow(transport)
    except Exception as exc:
        raise V4ReportLayoutActionConfigurationError(
            V4_REPORT_LAYOUT_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedReportLayoutMcpAction(
        workflow,
        delete_workflow=delete_workflow,
        execution_enabled=load_v4_report_layout_execution_feature(env),
        delete_execution_enabled=load_v4_report_layout_delete_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4ReportLayoutActionRuntimeError(
            V4_REPORT_LAYOUT_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedReportLayoutMcpAction",
    "V4_REPORT_LAYOUT_ACTION_FEATURE_ENV",
    "V4_REPORT_LAYOUT_ACTION_PREFIX",
    "V4_REPORT_LAYOUT_ACTION_TOOL",
    "V4_REPORT_LAYOUT_ACTION_UNAVAILABLE",
    "V4_REPORT_LAYOUT_CONFIRM_TOOL",
    "V4_REPORT_LAYOUT_DELETE_ACTION_TOOL",
    "V4_REPORT_LAYOUT_DELETE_CONFIRM_TOOL",
    "V4_REPORT_LAYOUT_DELETE_EXECUTION_ENV",
    "V4_REPORT_LAYOUT_DELETE_PREVIEW_TOOL",
    "V4_REPORT_LAYOUT_EXECUTION_ENV",
    "V4_REPORT_LAYOUT_PREVIEW_TOOL",
    "V4ReportLayoutActionConfigurationError",
    "V4ReportLayoutActionRuntimeError",
    "build_v4_report_layout_action",
    "load_v4_report_layout_action_feature",
    "load_v4_report_layout_delete_execution_feature",
    "load_v4_report_layout_execution_feature",
    "report_layout_action_principal_from_access_token",
]
