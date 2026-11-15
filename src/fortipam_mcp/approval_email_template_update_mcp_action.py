"""MCP boundary for one controlled FortiPAM Approval Email Template update."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_PREFIX = (
    "FORTIPAM_MCP_V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_"
)
V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_FEATURE_ENV = (
    f"{V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_PREFIX}ENABLED"
)
V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_EXECUTION_ENABLED"
)
V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_PREVIEW_TOOL = (
    "preview_v4_approval_email_template_content_update"
)
V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_CONFIRM_TOOL = (
    "confirm_v4_approval_email_template_content_update"
)
V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_TOOL = (
    "execute_confirmed_v4_approval_email_template_content_update"
)
V4_APPROVAL_EMAIL_TEMPLATE_DELETE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_APPROVAL_EMAIL_TEMPLATE_DELETE_EXECUTION_ENABLED"
)
V4_APPROVAL_EMAIL_TEMPLATE_DELETE_PREVIEW_TOOL = (
    "preview_v4_approval_email_template_delete"
)
V4_APPROVAL_EMAIL_TEMPLATE_DELETE_CONFIRM_TOOL = (
    "confirm_v4_approval_email_template_delete"
)
V4_APPROVAL_EMAIL_TEMPLATE_DELETE_ACTION_TOOL = (
    "execute_confirmed_v4_approval_email_template_delete"
)
V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_UNAVAILABLE = (
    "FortiPAM V4 Approval Email Template update action is unavailable."
)


class V4ApprovalEmailTemplateUpdateActionConfigurationError(ValueError):
    """Raised when the template update host is incomplete or unsafe."""


class V4ApprovalEmailTemplateUpdateActionRuntimeError(RuntimeError):
    """Stable, non-disclosing template update failure."""


def load_v4_approval_email_template_update_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent template update opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ApprovalEmailTemplateUpdateActionConfigurationError(
        f"{V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_approval_email_template_update_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ApprovalEmailTemplateUpdateActionConfigurationError(
        f"{V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_approval_email_template_delete_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Template recovery dispatch gate."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_APPROVAL_EMAIL_TEMPLATE_DELETE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ApprovalEmailTemplateUpdateActionConfigurationError(
        f"{V4_APPROVAL_EMAIL_TEMPLATE_DELETE_EXECUTION_ENV} must be exactly true or false."
    )


def approval_email_template_update_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4ApprovalEmailTemplateUpdateActionRuntimeError(
            V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_UNAVAILABLE
        ) from exc


class ProtectedApprovalEmailTemplateUpdateMcpAction:
    """Expose only C/P/E, confirmation, and one fixed template update."""

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

    def preview(self, template_name: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    template_name=template_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ApprovalEmailTemplateUpdateActionRuntimeError(
                V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4ApprovalEmailTemplateUpdateActionRuntimeError(
                V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4ApprovalEmailTemplateUpdateActionRuntimeError(
                V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_UNAVAILABLE
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
            raise V4ApprovalEmailTemplateUpdateActionRuntimeError(
                V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_UNAVAILABLE
            ) from exc

    def preview_delete(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._delete_workflow is None:
            raise V4ApprovalEmailTemplateUpdateActionRuntimeError(
                V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_UNAVAILABLE
            )
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.preview(requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4ApprovalEmailTemplateUpdateActionRuntimeError(
                V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_UNAVAILABLE
            ) from exc

    def confirm_delete(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._delete_workflow is None:
            raise V4ApprovalEmailTemplateUpdateActionRuntimeError(
                V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_UNAVAILABLE
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
            raise V4ApprovalEmailTemplateUpdateActionRuntimeError(
                V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_UNAVAILABLE
            ) from exc

    def execute_delete(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._delete_execution_enabled or self._delete_workflow is None:
            raise V4ApprovalEmailTemplateUpdateActionRuntimeError(
                V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_UNAVAILABLE
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
            raise V4ApprovalEmailTemplateUpdateActionRuntimeError(
                V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_UNAVAILABLE
            ) from exc


def build_v4_approval_email_template_update_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedApprovalEmailTemplateUpdateMcpAction:
    """Construct the update action from dedicated pinned SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .address_http_transport import load_address_http_transport_config
        from .approval_email_template_delete_http_transport import (
            FortiPamApprovalEmailTemplateDeleteHttpTransport,
        )
        from .approval_email_template_delete_live_workflow import (
            ApprovalEmailTemplateDeleteLiveWorkflow,
        )
        from .approval_email_template_ssh_transport import (
            FortiPamApprovalEmailTemplateSshTransport,
            load_approval_email_template_update_ssh_transport_config,
        )
        from .approval_email_template_update_live_workflow import (
            ApprovalEmailTemplateUpdateLiveWorkflow,
        )

        ssh_transport = FortiPamApprovalEmailTemplateSshTransport(
            load_approval_email_template_update_ssh_transport_config(env)
        )
        workflow = ApprovalEmailTemplateUpdateLiveWorkflow(ssh_transport)
        delete_workflow = ApprovalEmailTemplateDeleteLiveWorkflow(
            FortiPamApprovalEmailTemplateDeleteHttpTransport(
                load_address_http_transport_config(env),
                ssh_transport,
            )
        )
    except Exception as exc:
        raise V4ApprovalEmailTemplateUpdateActionConfigurationError(
            V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedApprovalEmailTemplateUpdateMcpAction(
        workflow,
        execution_enabled=load_v4_approval_email_template_update_execution_feature(env),
        delete_workflow=delete_workflow,
        delete_execution_enabled=(
            load_v4_approval_email_template_delete_execution_feature(env)
        ),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4ApprovalEmailTemplateUpdateActionRuntimeError(
            V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedApprovalEmailTemplateUpdateMcpAction",
    "V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_FEATURE_ENV",
    "V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_PREFIX",
    "V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_TOOL",
    "V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_UNAVAILABLE",
    "V4_APPROVAL_EMAIL_TEMPLATE_DELETE_ACTION_TOOL",
    "V4_APPROVAL_EMAIL_TEMPLATE_DELETE_CONFIRM_TOOL",
    "V4_APPROVAL_EMAIL_TEMPLATE_DELETE_EXECUTION_ENV",
    "V4_APPROVAL_EMAIL_TEMPLATE_DELETE_PREVIEW_TOOL",
    "V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_CONFIRM_TOOL",
    "V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_EXECUTION_ENV",
    "V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_PREVIEW_TOOL",
    "V4ApprovalEmailTemplateUpdateActionConfigurationError",
    "V4ApprovalEmailTemplateUpdateActionRuntimeError",
    "approval_email_template_update_action_principal_from_access_token",
    "build_v4_approval_email_template_update_action",
    "load_v4_approval_email_template_update_action_feature",
    "load_v4_approval_email_template_delete_execution_feature",
    "load_v4_approval_email_template_update_execution_feature",
]
