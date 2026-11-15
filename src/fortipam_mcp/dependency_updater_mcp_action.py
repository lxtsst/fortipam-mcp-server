"""MCP boundary for one controlled FortiPAM Dependency Updater create."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_DEPENDENCY_UPDATER_ACTION_PREFIX = "FORTIPAM_MCP_V4_DEPENDENCY_UPDATER_ACTION_"
V4_DEPENDENCY_UPDATER_ACTION_FEATURE_ENV = (
    f"{V4_DEPENDENCY_UPDATER_ACTION_PREFIX}ENABLED"
)
V4_DEPENDENCY_UPDATER_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_DEPENDENCY_UPDATER_EXECUTION_ENABLED"
)
V4_DEPENDENCY_UPDATER_PREVIEW_TOOL = "preview_v4_dependency_updater_create"
V4_DEPENDENCY_UPDATER_CONFIRM_TOOL = "confirm_v4_dependency_updater_create"
V4_DEPENDENCY_UPDATER_ACTION_TOOL = "execute_confirmed_v4_dependency_updater_create"
V4_DEPENDENCY_UPDATER_ACTION_UNAVAILABLE = (
    "FortiPAM V4 Dependency Updater create action is unavailable."
)


class V4DependencyUpdaterActionConfigurationError(ValueError):
    """Raised when the Dependency Updater action host is incomplete or unsafe."""


class V4DependencyUpdaterActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Dependency Updater action failure."""


def load_v4_dependency_updater_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Dependency Updater opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_DEPENDENCY_UPDATER_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4DependencyUpdaterActionConfigurationError(
        f"{V4_DEPENDENCY_UPDATER_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_dependency_updater_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_DEPENDENCY_UPDATER_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4DependencyUpdaterActionConfigurationError(
        f"{V4_DEPENDENCY_UPDATER_EXECUTION_ENV} must be exactly true or false."
    )


def dependency_updater_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4DependencyUpdaterActionRuntimeError(
            V4_DEPENDENCY_UPDATER_ACTION_UNAVAILABLE
        ) from exc


class ProtectedDependencyUpdaterMcpAction:
    """Expose only C/P/E, confirmation, and execution for one updater."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(
        self,
        updater_name: str,
        service_name: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    updater_name=updater_name,
                    service_name=service_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4DependencyUpdaterActionRuntimeError(
                V4_DEPENDENCY_UPDATER_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4DependencyUpdaterActionRuntimeError(
                V4_DEPENDENCY_UPDATER_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4DependencyUpdaterActionRuntimeError(
                V4_DEPENDENCY_UPDATER_ACTION_UNAVAILABLE
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
            raise V4DependencyUpdaterActionRuntimeError(
                V4_DEPENDENCY_UPDATER_ACTION_UNAVAILABLE
            ) from exc


def build_v4_dependency_updater_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedDependencyUpdaterMcpAction:
    """Construct the action from dedicated pinned SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .dependency_updater_live_workflow import (
            DependencyUpdaterCreateLiveWorkflow,
        )
        from .dependency_updater_ssh_transport import (
            FortiPamDependencyUpdaterSshTransport,
            load_dependency_updater_ssh_transport_config,
        )

        workflow = DependencyUpdaterCreateLiveWorkflow(
            FortiPamDependencyUpdaterSshTransport(
                load_dependency_updater_ssh_transport_config(env)
            )
        )
    except Exception as exc:
        raise V4DependencyUpdaterActionConfigurationError(
            V4_DEPENDENCY_UPDATER_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedDependencyUpdaterMcpAction(
        workflow,
        execution_enabled=load_v4_dependency_updater_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4DependencyUpdaterActionRuntimeError(
            V4_DEPENDENCY_UPDATER_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedDependencyUpdaterMcpAction",
    "V4_DEPENDENCY_UPDATER_ACTION_FEATURE_ENV",
    "V4_DEPENDENCY_UPDATER_ACTION_PREFIX",
    "V4_DEPENDENCY_UPDATER_ACTION_TOOL",
    "V4_DEPENDENCY_UPDATER_ACTION_UNAVAILABLE",
    "V4_DEPENDENCY_UPDATER_CONFIRM_TOOL",
    "V4_DEPENDENCY_UPDATER_EXECUTION_ENV",
    "V4_DEPENDENCY_UPDATER_PREVIEW_TOOL",
    "V4DependencyUpdaterActionConfigurationError",
    "V4DependencyUpdaterActionRuntimeError",
    "build_v4_dependency_updater_action",
    "dependency_updater_action_principal_from_access_token",
    "load_v4_dependency_updater_action_feature",
    "load_v4_dependency_updater_execution_feature",
]
