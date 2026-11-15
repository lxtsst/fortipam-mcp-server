"""MCP boundary for controlled FortiPAM Character Set create and recovery."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_acl_mcp_action import folder_acl_action_principal_from_access_token


V4_CHARACTER_SET_ACTION_PREFIX = "FORTIPAM_MCP_V4_CHARACTER_SET_ACTION_"
V4_CHARACTER_SET_ACTION_FEATURE_ENV = f"{V4_CHARACTER_SET_ACTION_PREFIX}ENABLED"
V4_CHARACTER_SET_EXECUTION_ENV = "FORTIPAM_MCP_V4_CHARACTER_SET_EXECUTION_ENABLED"
V4_CHARACTER_SET_DELETE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_CHARACTER_SET_DELETE_EXECUTION_ENABLED"
)
V4_CHARACTER_SET_PREVIEW_TOOL = "preview_v4_character_set_create"
V4_CHARACTER_SET_CONFIRM_TOOL = "confirm_v4_character_set_create"
V4_CHARACTER_SET_ACTION_TOOL = "execute_confirmed_v4_character_set_create"
V4_CHARACTER_SET_DELETE_PREVIEW_TOOL = "preview_v4_character_set_delete"
V4_CHARACTER_SET_DELETE_CONFIRM_TOOL = "confirm_v4_character_set_delete"
V4_CHARACTER_SET_DELETE_ACTION_TOOL = "execute_confirmed_v4_character_set_delete"
V4_CHARACTER_SET_ACTION_UNAVAILABLE = "FortiPAM V4 Character Set action is unavailable."


class V4CharacterSetActionConfigurationError(ValueError):
    """Raised when the Character Set action host is incomplete or unsafe."""


class V4CharacterSetActionRuntimeError(RuntimeError):
    """Stable non-disclosing Character Set action failure."""


def load_v4_character_set_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Character Set opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_CHARACTER_SET_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4CharacterSetActionConfigurationError(
        f"{V4_CHARACTER_SET_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_character_set_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_CHARACTER_SET_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4CharacterSetActionConfigurationError(
        f"{V4_CHARACTER_SET_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_character_set_delete_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent destructive final-dispatch gate."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_CHARACTER_SET_DELETE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4CharacterSetActionConfigurationError(
        f"{V4_CHARACTER_SET_DELETE_EXECUTION_ENV} must be exactly true or false."
    )


def character_set_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning/operation scope as other writes."""

    try:
        return folder_acl_action_principal_from_access_token(
            access_token,
            planning_settings,
        )
    except Exception as exc:
        raise V4CharacterSetActionRuntimeError(
            V4_CHARACTER_SET_ACTION_UNAVAILABLE
        ) from exc


class ProtectedCharacterSetMcpAction:
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
        self._delete_workflow = delete_workflow
        self._execution_enabled = execution_enabled
        self._delete_execution_enabled = delete_execution_enabled

    def preview(self, name: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    name=name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4CharacterSetActionRuntimeError(
                V4_CHARACTER_SET_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4CharacterSetActionRuntimeError(
                V4_CHARACTER_SET_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4CharacterSetActionRuntimeError(V4_CHARACTER_SET_ACTION_UNAVAILABLE)
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
            raise V4CharacterSetActionRuntimeError(
                V4_CHARACTER_SET_ACTION_UNAVAILABLE
            ) from exc

    def preview_delete(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.preview(requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4CharacterSetActionRuntimeError(
                V4_CHARACTER_SET_ACTION_UNAVAILABLE
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
            raise V4CharacterSetActionRuntimeError(
                V4_CHARACTER_SET_ACTION_UNAVAILABLE
            ) from exc

    def execute_delete(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._delete_execution_enabled:
            raise V4CharacterSetActionRuntimeError(
                V4_CHARACTER_SET_ACTION_UNAVAILABLE
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
            raise V4CharacterSetActionRuntimeError(
                V4_CHARACTER_SET_ACTION_UNAVAILABLE
            ) from exc


def build_v4_character_set_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedCharacterSetMcpAction:
    """Construct the dedicated Character Set API action host."""

    env = os.environ if environment is None else environment
    try:
        from .character_set_http_transport import (
            FortiPamCharacterSetHttpTransport,
            load_character_set_http_transport_config,
        )
        from .character_set_live_workflow import CharacterSetCreateLiveWorkflow
        from .character_set_delete_live_workflow import CharacterSetDeleteLiveWorkflow

        transport = FortiPamCharacterSetHttpTransport(
            load_character_set_http_transport_config(env)
        )
        workflow = CharacterSetCreateLiveWorkflow(transport)
        delete_workflow = CharacterSetDeleteLiveWorkflow(transport)
    except Exception as exc:
        raise V4CharacterSetActionConfigurationError(
            V4_CHARACTER_SET_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedCharacterSetMcpAction(
        workflow,
        execution_enabled=load_v4_character_set_execution_feature(env),
        delete_workflow=delete_workflow,
        delete_execution_enabled=load_v4_character_set_delete_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4CharacterSetActionRuntimeError(
            V4_CHARACTER_SET_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedCharacterSetMcpAction",
    "V4_CHARACTER_SET_ACTION_FEATURE_ENV",
    "V4_CHARACTER_SET_ACTION_PREFIX",
    "V4_CHARACTER_SET_ACTION_TOOL",
    "V4_CHARACTER_SET_ACTION_UNAVAILABLE",
    "V4_CHARACTER_SET_CONFIRM_TOOL",
    "V4_CHARACTER_SET_DELETE_ACTION_TOOL",
    "V4_CHARACTER_SET_DELETE_CONFIRM_TOOL",
    "V4_CHARACTER_SET_DELETE_EXECUTION_ENV",
    "V4_CHARACTER_SET_DELETE_PREVIEW_TOOL",
    "V4_CHARACTER_SET_EXECUTION_ENV",
    "V4_CHARACTER_SET_PREVIEW_TOOL",
    "V4CharacterSetActionConfigurationError",
    "V4CharacterSetActionRuntimeError",
    "build_v4_character_set_action",
    "character_set_action_principal_from_access_token",
    "load_v4_character_set_action_feature",
    "load_v4_character_set_delete_execution_feature",
    "load_v4_character_set_execution_feature",
]
