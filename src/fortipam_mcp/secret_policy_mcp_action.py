"""MCP boundary for one controlled FortiPAM Secret Policy create workflow."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_SECRET_POLICY_ACTION_PREFIX = "FORTIPAM_MCP_V4_SECRET_POLICY_ACTION_"
V4_SECRET_POLICY_ACTION_FEATURE_ENV = f"{V4_SECRET_POLICY_ACTION_PREFIX}ENABLED"
V4_SECRET_POLICY_EXECUTION_ENV = "FORTIPAM_MCP_V4_SECRET_POLICY_EXECUTION_ENABLED"
V4_SECRET_POLICY_UPDATE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_SECRET_POLICY_UPDATE_EXECUTION_ENABLED"
)
V4_SECRET_POLICY_PREVIEW_TOOL = "preview_v4_secret_policy_create"
V4_SECRET_POLICY_CONFIRM_TOOL = "confirm_v4_secret_policy_create"
V4_SECRET_POLICY_ACTION_TOOL = "execute_confirmed_v4_secret_policy_create"
V4_SECRET_POLICY_UPDATE_PREVIEW_TOOL = "preview_v4_secret_policy_update"
V4_SECRET_POLICY_UPDATE_CONFIRM_TOOL = "confirm_v4_secret_policy_update"
V4_SECRET_POLICY_UPDATE_ACTION_TOOL = "execute_confirmed_v4_secret_policy_update"
V4_SECRET_POLICY_ACTION_UNAVAILABLE = (
    "FortiPAM V4 Secret Policy create action is unavailable."
)


class V4SecretPolicyActionConfigurationError(ValueError):
    """Raised when the Secret Policy action host is incomplete or unsafe."""


class V4SecretPolicyActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Secret Policy action failure."""


def load_v4_secret_policy_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Secret Policy opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_SECRET_POLICY_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4SecretPolicyActionConfigurationError(
        f"{V4_SECRET_POLICY_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def _load_exact_execution_feature(
    environment: Mapping[str, str] | None,
    variable: str,
) -> bool:
    env = os.environ if environment is None else environment
    raw = env.get(variable)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4SecretPolicyActionConfigurationError(
        f"{variable} must be exactly true or false."
    )


def load_v4_secret_policy_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent create final-dispatch gate."""

    return _load_exact_execution_feature(environment, V4_SECRET_POLICY_EXECUTION_ENV)


def load_v4_secret_policy_update_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent update final-dispatch gate."""

    return _load_exact_execution_feature(
        environment,
        V4_SECRET_POLICY_UPDATE_EXECUTION_ENV,
    )


def secret_policy_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4SecretPolicyActionRuntimeError(
            V4_SECRET_POLICY_ACTION_UNAVAILABLE
        ) from exc


class ProtectedSecretPolicyMcpAction:
    """Expose only C/P/E, confirmation, and execution for one Secret Policy."""

    def __init__(
        self,
        workflow: Any,
        *,
        update_workflow: Any | None = None,
        execution_enabled: bool = True,
        update_execution_enabled: bool = True,
    ) -> None:
        self._workflow = workflow
        self._update_workflow = update_workflow
        self._execution_enabled = execution_enabled
        self._update_execution_enabled = update_execution_enabled

    def preview(self, policy_name: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    policy_name=policy_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4SecretPolicyActionRuntimeError(
                V4_SECRET_POLICY_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4SecretPolicyActionRuntimeError(
                V4_SECRET_POLICY_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4SecretPolicyActionRuntimeError(V4_SECRET_POLICY_ACTION_UNAVAILABLE)
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
            raise V4SecretPolicyActionRuntimeError(
                V4_SECRET_POLICY_ACTION_UNAVAILABLE
            ) from exc

    def preview_update(self, policy_name: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._require_update_workflow().preview(
                    policy_name=policy_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4SecretPolicyActionRuntimeError(
                V4_SECRET_POLICY_ACTION_UNAVAILABLE
            ) from exc

    def confirm_update(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._require_update_workflow().confirm(
                    preview_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4SecretPolicyActionRuntimeError(
                V4_SECRET_POLICY_ACTION_UNAVAILABLE
            ) from exc

    def execute_update(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._update_execution_enabled:
            raise V4SecretPolicyActionRuntimeError(V4_SECRET_POLICY_ACTION_UNAVAILABLE)
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._require_update_workflow().execute(
                    authorization_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4SecretPolicyActionRuntimeError(
                V4_SECRET_POLICY_ACTION_UNAVAILABLE
            ) from exc

    def _require_update_workflow(self) -> Any:
        if self._update_workflow is None:
            raise V4SecretPolicyActionRuntimeError(V4_SECRET_POLICY_ACTION_UNAVAILABLE)
        return self._update_workflow


def build_v4_secret_policy_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedSecretPolicyMcpAction:
    """Construct the action from dedicated pinned SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .secret_policy_live_workflow import SecretPolicyCreateLiveWorkflow
        from .secret_policy_update_live_workflow import SecretPolicyUpdateLiveWorkflow
        from .secret_policy_ssh_transport import (
            FortiPamSecretPolicySshTransport,
            load_secret_policy_ssh_transport_config,
        )

        transport = FortiPamSecretPolicySshTransport(
            load_secret_policy_ssh_transport_config(env)
        )
        workflow = SecretPolicyCreateLiveWorkflow(transport)
        update_workflow = SecretPolicyUpdateLiveWorkflow(transport)
    except Exception as exc:
        raise V4SecretPolicyActionConfigurationError(
            V4_SECRET_POLICY_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedSecretPolicyMcpAction(
        workflow,
        update_workflow=update_workflow,
        execution_enabled=load_v4_secret_policy_execution_feature(env),
        update_execution_enabled=load_v4_secret_policy_update_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4SecretPolicyActionRuntimeError(
            V4_SECRET_POLICY_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedSecretPolicyMcpAction",
    "V4_SECRET_POLICY_ACTION_FEATURE_ENV",
    "V4_SECRET_POLICY_ACTION_PREFIX",
    "V4_SECRET_POLICY_ACTION_TOOL",
    "V4_SECRET_POLICY_ACTION_UNAVAILABLE",
    "V4_SECRET_POLICY_CONFIRM_TOOL",
    "V4_SECRET_POLICY_EXECUTION_ENV",
    "V4_SECRET_POLICY_PREVIEW_TOOL",
    "V4_SECRET_POLICY_UPDATE_ACTION_TOOL",
    "V4_SECRET_POLICY_UPDATE_CONFIRM_TOOL",
    "V4_SECRET_POLICY_UPDATE_EXECUTION_ENV",
    "V4_SECRET_POLICY_UPDATE_PREVIEW_TOOL",
    "V4SecretPolicyActionConfigurationError",
    "V4SecretPolicyActionRuntimeError",
    "build_v4_secret_policy_action",
    "load_v4_secret_policy_action_feature",
    "load_v4_secret_policy_execution_feature",
    "load_v4_secret_policy_update_execution_feature",
    "secret_policy_action_principal_from_access_token",
]
