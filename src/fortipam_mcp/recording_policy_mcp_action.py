"""MCP boundary for one controlled FortiPAM recording-policy enable action."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_acl_mcp_action import folder_acl_action_principal_from_access_token


V4_RECORDING_POLICY_ACTION_PREFIX = "FORTIPAM_MCP_V4_RECORDING_POLICY_ACTION_"
V4_RECORDING_POLICY_ACTION_FEATURE_ENV = f"{V4_RECORDING_POLICY_ACTION_PREFIX}ENABLED"
V4_RECORDING_POLICY_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_RECORDING_POLICY_EXECUTION_ENABLED"
)
V4_RECORDING_POLICY_PREVIEW_TOOL = "preview_v4_recording_policy_enable"
V4_RECORDING_POLICY_CONFIRM_TOOL = "confirm_v4_recording_policy_enable"
V4_RECORDING_POLICY_ACTION_TOOL = "execute_confirmed_v4_recording_policy_enable"
V4_RECORDING_POLICY_ACTION_UNAVAILABLE = "FortiPAM V4 Recording Policy action is unavailable."


class V4RecordingPolicyActionConfigurationError(ValueError):
    """Raised when the Recording Policy action host is incomplete or unsafe."""


class V4RecordingPolicyActionRuntimeError(RuntimeError):
    """Stable non-disclosing Recording Policy action failure."""


def load_v4_recording_policy_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent recording-policy opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_RECORDING_POLICY_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4RecordingPolicyActionConfigurationError(
        f"{V4_RECORDING_POLICY_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_recording_policy_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_RECORDING_POLICY_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4RecordingPolicyActionConfigurationError(
        f"{V4_RECORDING_POLICY_EXECUTION_ENV} must be exactly true or false."
    )


def recording_policy_action_principal_from_access_token(
    access_token: Any, planning_settings: Any
) -> Any:
    """Require the same explicit planning/operation scope as other writes."""

    try:
        return folder_acl_action_principal_from_access_token(
            access_token, planning_settings
        )
    except Exception as exc:
        raise V4RecordingPolicyActionRuntimeError(
            V4_RECORDING_POLICY_ACTION_UNAVAILABLE
        ) from exc


class ProtectedRecordingPolicyMcpAction:
    """Expose only C/P/E, confirmation, and recording enable execution."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(self, policy_name: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    policy_name=policy_name, requester_digest=requester_digest
                ),
            )
        except Exception as exc:
            raise V4RecordingPolicyActionRuntimeError(
                V4_RECORDING_POLICY_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4RecordingPolicyActionRuntimeError(
                V4_RECORDING_POLICY_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4RecordingPolicyActionRuntimeError(
                V4_RECORDING_POLICY_ACTION_UNAVAILABLE
            )
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.execute(
                    authorization_ref, requester_digest=requester_digest
                ),
            )
        except Exception as exc:
            raise V4RecordingPolicyActionRuntimeError(
                V4_RECORDING_POLICY_ACTION_UNAVAILABLE
            ) from exc


def build_v4_recording_policy_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedRecordingPolicyMcpAction:
    """Construct the dedicated Recording Policy API action host."""

    env = os.environ if environment is None else environment
    try:
        from .recording_policy_http_transport import (
            FortiPamRecordingPolicyHttpTransport,
            load_recording_policy_http_transport_config,
        )
        from .recording_policy_live_workflow import RecordingPolicyEnableLiveWorkflow

        workflow = RecordingPolicyEnableLiveWorkflow(
            FortiPamRecordingPolicyHttpTransport(
                load_recording_policy_http_transport_config(env)
            )
        )
    except Exception as exc:
        raise V4RecordingPolicyActionConfigurationError(
            V4_RECORDING_POLICY_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedRecordingPolicyMcpAction(
        workflow,
        execution_enabled=load_v4_recording_policy_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4RecordingPolicyActionRuntimeError(
            V4_RECORDING_POLICY_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedRecordingPolicyMcpAction",
    "V4_RECORDING_POLICY_ACTION_FEATURE_ENV",
    "V4_RECORDING_POLICY_ACTION_PREFIX",
    "V4_RECORDING_POLICY_ACTION_TOOL",
    "V4_RECORDING_POLICY_ACTION_UNAVAILABLE",
    "V4_RECORDING_POLICY_CONFIRM_TOOL",
    "V4_RECORDING_POLICY_EXECUTION_ENV",
    "V4_RECORDING_POLICY_PREVIEW_TOOL",
    "V4RecordingPolicyActionConfigurationError",
    "V4RecordingPolicyActionRuntimeError",
    "build_v4_recording_policy_action",
    "load_v4_recording_policy_action_feature",
    "load_v4_recording_policy_execution_feature",
    "recording_policy_action_principal_from_access_token",
]
