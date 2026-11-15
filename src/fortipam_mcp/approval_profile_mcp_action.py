"""MCP boundary for one controlled FortiPAM Approval Profile create."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_APPROVAL_PROFILE_ACTION_PREFIX = "FORTIPAM_MCP_V4_APPROVAL_PROFILE_ACTION_"
V4_APPROVAL_PROFILE_ACTION_FEATURE_ENV = (
    f"{V4_APPROVAL_PROFILE_ACTION_PREFIX}ENABLED"
)
V4_APPROVAL_PROFILE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_APPROVAL_PROFILE_EXECUTION_ENABLED"
)
V4_APPROVAL_PROFILE_PREVIEW_TOOL = "preview_v4_approval_profile_create"
V4_APPROVAL_PROFILE_CONFIRM_TOOL = "confirm_v4_approval_profile_create"
V4_APPROVAL_PROFILE_ACTION_TOOL = "execute_confirmed_v4_approval_profile_create"
V4_APPROVAL_PROFILE_ACTION_UNAVAILABLE = (
    "FortiPAM V4 Approval Profile create action is unavailable."
)


class V4ApprovalProfileActionConfigurationError(ValueError):
    """Raised when the Approval Profile action host is incomplete or unsafe."""


class V4ApprovalProfileActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Approval Profile action failure."""


def load_v4_approval_profile_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Approval Profile opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_APPROVAL_PROFILE_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ApprovalProfileActionConfigurationError(
        f"{V4_APPROVAL_PROFILE_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_approval_profile_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_APPROVAL_PROFILE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ApprovalProfileActionConfigurationError(
        f"{V4_APPROVAL_PROFILE_EXECUTION_ENV} must be exactly true or false."
    )


def approval_profile_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4ApprovalProfileActionRuntimeError(
            V4_APPROVAL_PROFILE_ACTION_UNAVAILABLE
        ) from exc


class ProtectedApprovalProfileMcpAction:
    """Expose only C/P/E, confirmation, and execution for one Profile."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(self, profile_name: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    profile_name=profile_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ApprovalProfileActionRuntimeError(
                V4_APPROVAL_PROFILE_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4ApprovalProfileActionRuntimeError(
                V4_APPROVAL_PROFILE_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4ApprovalProfileActionRuntimeError(
                V4_APPROVAL_PROFILE_ACTION_UNAVAILABLE
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
            raise V4ApprovalProfileActionRuntimeError(
                V4_APPROVAL_PROFILE_ACTION_UNAVAILABLE
            ) from exc


def build_v4_approval_profile_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedApprovalProfileMcpAction:
    """Construct the action from dedicated pinned SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .approval_profile_live_workflow import ApprovalProfileCreateLiveWorkflow
        from .approval_profile_ssh_transport import (
            FortiPamApprovalProfileSshTransport,
            load_approval_profile_ssh_transport_config,
        )

        workflow = ApprovalProfileCreateLiveWorkflow(
            FortiPamApprovalProfileSshTransport(
                load_approval_profile_ssh_transport_config(env)
            )
        )
    except Exception as exc:
        raise V4ApprovalProfileActionConfigurationError(
            V4_APPROVAL_PROFILE_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedApprovalProfileMcpAction(
        workflow,
        execution_enabled=load_v4_approval_profile_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4ApprovalProfileActionRuntimeError(
            V4_APPROVAL_PROFILE_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedApprovalProfileMcpAction",
    "V4_APPROVAL_PROFILE_ACTION_FEATURE_ENV",
    "V4_APPROVAL_PROFILE_ACTION_PREFIX",
    "V4_APPROVAL_PROFILE_ACTION_TOOL",
    "V4_APPROVAL_PROFILE_ACTION_UNAVAILABLE",
    "V4_APPROVAL_PROFILE_CONFIRM_TOOL",
    "V4_APPROVAL_PROFILE_EXECUTION_ENV",
    "V4_APPROVAL_PROFILE_PREVIEW_TOOL",
    "V4ApprovalProfileActionConfigurationError",
    "V4ApprovalProfileActionRuntimeError",
    "approval_profile_action_principal_from_access_token",
    "build_v4_approval_profile_action",
    "load_v4_approval_profile_action_feature",
    "load_v4_approval_profile_execution_feature",
]
