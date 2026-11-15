"""MCP boundary for one controlled FortiPAM remote LDAP User Group create."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_USER_GROUP_ACTION_PREFIX = "FORTIPAM_MCP_V4_USER_GROUP_"
V4_USER_GROUP_ACTION_FEATURE_ENV = f"{V4_USER_GROUP_ACTION_PREFIX}ENABLED"
V4_USER_GROUP_EXECUTION_ENV = "FORTIPAM_MCP_V4_USER_GROUP_EXECUTION_ENABLED"
V4_USER_GROUP_PREVIEW_TOOL = "preview_v4_user_group_create"
V4_USER_GROUP_CONFIRM_TOOL = "confirm_v4_user_group_create"
V4_USER_GROUP_ACTION_TOOL = "execute_confirmed_v4_user_group_create"
V4_USER_GROUP_ACTION_UNAVAILABLE = "FortiPAM V4 User Group create action is unavailable."


class V4UserGroupActionConfigurationError(ValueError):
    """Raised when the User Group action host is incomplete or unsafe."""


class V4UserGroupActionRuntimeError(RuntimeError):
    """Stable, non-disclosing User Group action failure."""


def load_v4_user_group_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent User Group opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_USER_GROUP_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4UserGroupActionConfigurationError(
        f"{V4_USER_GROUP_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_user_group_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_USER_GROUP_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4UserGroupActionConfigurationError(
        f"{V4_USER_GROUP_EXECUTION_ENV} must be exactly true or false."
    )


def user_group_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4UserGroupActionRuntimeError(
            V4_USER_GROUP_ACTION_UNAVAILABLE
        ) from exc


class ProtectedUserGroupMcpAction:
    """Expose C/P/E, confirmation, and one remote LDAP User Group create."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(
        self,
        user_group_name: str,
        ldap_server_name: str,
        ldap_group_dn: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    user_group_name=user_group_name,
                    ldap_server_name=ldap_server_name,
                    ldap_group_dn=ldap_group_dn,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4UserGroupActionRuntimeError(
                V4_USER_GROUP_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4UserGroupActionRuntimeError(
                V4_USER_GROUP_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4UserGroupActionRuntimeError(
                V4_USER_GROUP_ACTION_UNAVAILABLE
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
            raise V4UserGroupActionRuntimeError(
                V4_USER_GROUP_ACTION_UNAVAILABLE
            ) from exc


def build_v4_user_group_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedUserGroupMcpAction:
    """Construct the action from dedicated pinned SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .user_group_live_workflow import UserGroupCreateLiveWorkflow
        from .user_group_ssh_transport import (
            FortiPamUserGroupSshTransport,
            load_user_group_ssh_transport_config,
        )

        workflow = UserGroupCreateLiveWorkflow(
            FortiPamUserGroupSshTransport(
                load_user_group_ssh_transport_config(env)
            )
        )
    except Exception as exc:
        raise V4UserGroupActionConfigurationError(
            V4_USER_GROUP_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedUserGroupMcpAction(
        workflow,
        execution_enabled=load_v4_user_group_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4UserGroupActionRuntimeError(
            V4_USER_GROUP_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedUserGroupMcpAction",
    "V4_USER_GROUP_ACTION_FEATURE_ENV",
    "V4_USER_GROUP_ACTION_PREFIX",
    "V4_USER_GROUP_ACTION_TOOL",
    "V4_USER_GROUP_ACTION_UNAVAILABLE",
    "V4_USER_GROUP_CONFIRM_TOOL",
    "V4_USER_GROUP_EXECUTION_ENV",
    "V4_USER_GROUP_PREVIEW_TOOL",
    "V4UserGroupActionConfigurationError",
    "V4UserGroupActionRuntimeError",
    "build_v4_user_group_action",
    "load_v4_user_group_action_feature",
    "load_v4_user_group_execution_feature",
    "user_group_action_principal_from_access_token",
]
