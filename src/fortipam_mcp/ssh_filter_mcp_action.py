"""MCP boundary for controlled SSH Filter create and fixed recovery."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_SSH_FILTER_ACTION_PREFIX = "FORTIPAM_MCP_V4_SSH_FILTER_ACTION_"
V4_SSH_FILTER_ACTION_FEATURE_ENV = f"{V4_SSH_FILTER_ACTION_PREFIX}ENABLED"
V4_SSH_FILTER_EXECUTION_ENV = "FORTIPAM_MCP_V4_SSH_FILTER_EXECUTION_ENABLED"
V4_SSH_FILTER_DELETE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_SSH_FILTER_DELETE_EXECUTION_ENABLED"
)
V4_SSH_FILTER_PREVIEW_TOOL = "preview_v4_ssh_filter_create"
V4_SSH_FILTER_CONFIRM_TOOL = "confirm_v4_ssh_filter_create"
V4_SSH_FILTER_ACTION_TOOL = "execute_confirmed_v4_ssh_filter_create"
V4_SSH_FILTER_DELETE_PREVIEW_TOOL = "preview_v4_ssh_filter_delete"
V4_SSH_FILTER_DELETE_CONFIRM_TOOL = "confirm_v4_ssh_filter_delete"
V4_SSH_FILTER_DELETE_ACTION_TOOL = "execute_confirmed_v4_ssh_filter_delete"
V4_SSH_FILTER_ACTION_UNAVAILABLE = (
    "FortiPAM V4 SSH Filter Profile create action is unavailable."
)


class V4SshFilterActionConfigurationError(ValueError):
    """Raised when the SSH Filter action host is incomplete or unsafe."""


class V4SshFilterActionRuntimeError(RuntimeError):
    """Stable, non-disclosing SSH Filter action failure."""


def load_v4_ssh_filter_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent SSH Filter opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_SSH_FILTER_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4SshFilterActionConfigurationError(
        f"{V4_SSH_FILTER_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_ssh_filter_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_SSH_FILTER_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4SshFilterActionConfigurationError(
        f"{V4_SSH_FILTER_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_ssh_filter_delete_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent destructive final-dispatch gate."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_SSH_FILTER_DELETE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4SshFilterActionConfigurationError(
        f"{V4_SSH_FILTER_DELETE_EXECUTION_ENV} must be exactly true or false."
    )


def ssh_filter_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4SshFilterActionRuntimeError(V4_SSH_FILTER_ACTION_UNAVAILABLE) from exc


class ProtectedSshFilterMcpAction:
    """Expose separately gated create and fixed recovery C/P/E flows."""

    def __init__(
        self,
        workflow: Any,
        *,
        execution_enabled: bool = True,
        delete_workflow: Any = None,
        delete_execution_enabled: bool = False,
    ) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled
        self._delete_workflow = delete_workflow
        self._delete_execution_enabled = delete_execution_enabled

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
            raise V4SshFilterActionRuntimeError(
                V4_SSH_FILTER_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4SshFilterActionRuntimeError(
                V4_SSH_FILTER_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4SshFilterActionRuntimeError(V4_SSH_FILTER_ACTION_UNAVAILABLE)
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
            raise V4SshFilterActionRuntimeError(
                V4_SSH_FILTER_ACTION_UNAVAILABLE
            ) from exc

    def preview_delete(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.preview(requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4SshFilterActionRuntimeError(
                V4_SSH_FILTER_ACTION_UNAVAILABLE
            ) from exc

    def confirm_delete(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.confirm(
                    preview_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4SshFilterActionRuntimeError(
                V4_SSH_FILTER_ACTION_UNAVAILABLE
            ) from exc

    def execute_delete(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._delete_execution_enabled:
            raise V4SshFilterActionRuntimeError(V4_SSH_FILTER_ACTION_UNAVAILABLE)
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
            raise V4SshFilterActionRuntimeError(
                V4_SSH_FILTER_ACTION_UNAVAILABLE
            ) from exc


def build_v4_ssh_filter_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedSshFilterMcpAction:
    """Construct the action from dedicated pinned SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .ssh_filter_live_workflow import SshFilterCreateLiveWorkflow
        from .ssh_filter_ssh_transport import (
            FortiPamSshFilterSshTransport,
            load_ssh_filter_ssh_transport_config,
        )
        from .ssh_filter_delete_http_transport import (
            FortiPamSshFilterDeleteHttpTransport,
            load_ssh_filter_delete_http_transport_config,
        )
        from .ssh_filter_delete_live_workflow import SshFilterDeleteLiveWorkflow

        ssh_transport = FortiPamSshFilterSshTransport(
            load_ssh_filter_ssh_transport_config(env)
        )
        workflow = SshFilterCreateLiveWorkflow(ssh_transport)
        delete_workflow = SshFilterDeleteLiveWorkflow(
            FortiPamSshFilterDeleteHttpTransport(
                load_ssh_filter_delete_http_transport_config(env),
                ssh_transport,
            )
        )
    except Exception as exc:
        raise V4SshFilterActionConfigurationError(
            V4_SSH_FILTER_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedSshFilterMcpAction(
        workflow,
        execution_enabled=load_v4_ssh_filter_execution_feature(env),
        delete_workflow=delete_workflow,
        delete_execution_enabled=load_v4_ssh_filter_delete_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4SshFilterActionRuntimeError(V4_SSH_FILTER_ACTION_UNAVAILABLE) from exc


__all__ = [
    "ProtectedSshFilterMcpAction",
    "V4_SSH_FILTER_ACTION_FEATURE_ENV",
    "V4_SSH_FILTER_ACTION_PREFIX",
    "V4_SSH_FILTER_ACTION_TOOL",
    "V4_SSH_FILTER_ACTION_UNAVAILABLE",
    "V4_SSH_FILTER_CONFIRM_TOOL",
    "V4_SSH_FILTER_DELETE_ACTION_TOOL",
    "V4_SSH_FILTER_DELETE_CONFIRM_TOOL",
    "V4_SSH_FILTER_DELETE_EXECUTION_ENV",
    "V4_SSH_FILTER_DELETE_PREVIEW_TOOL",
    "V4_SSH_FILTER_EXECUTION_ENV",
    "V4_SSH_FILTER_PREVIEW_TOOL",
    "V4SshFilterActionConfigurationError",
    "V4SshFilterActionRuntimeError",
    "build_v4_ssh_filter_action",
    "load_v4_ssh_filter_action_feature",
    "load_v4_ssh_filter_delete_execution_feature",
    "load_v4_ssh_filter_execution_feature",
    "ssh_filter_action_principal_from_access_token",
]
