"""HTTP-OAuth host boundary for the usable V4 child Folder workflow.

Beta 7 exposes only three bounded operations: live preview, one explicit
confirmation, and one authorized create with fixed readback.  No generic
Folder CRUD or arbitrary FortiPAM request is accepted.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
import os
import re
from typing import Any, cast

V4_FOLDER_ACTION_FEATURE_ENV = "FORTIPAM_MCP_V4_FOLDER_ACTION_ENABLED"
V4_FOLDER_EXECUTION_ENV = "FORTIPAM_MCP_V4_FOLDER_EXECUTION_ENABLED"
V4_FOLDER_ACTION_PREFIX = "FORTIPAM_MCP_V4_FOLDER_ACTION_"
V4_FOLDER_PREVIEW_TOOL = "preview_v4_child_folder_create"
V4_FOLDER_CONFIRM_TOOL = "confirm_v4_child_folder_create"
V4_FOLDER_ACTION_TOOL = "execute_confirmed_v4_child_folder"
V4_FOLDER_ACTION_SCOPE = "fortipam:operate"
V4_FOLDER_ACTION_UNAVAILABLE = "FortiPAM V4 child Folder action is unavailable."
_OPAQUE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")


class V4FolderActionConfigurationError(ValueError):
    """Raised when the opt-in child Folder action host is incomplete."""


class V4FolderActionRuntimeError(RuntimeError):
    """Stable, non-disclosing controlled-action failure."""


def folder_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require both planning and non-default operation authority."""

    try:
        from mcp.server.auth.provider import AccessToken

        from .v4_plan_runtime import planning_principal_from_access_token

        if not isinstance(access_token, AccessToken):
            raise TypeError("validated access token required")
        principal = planning_principal_from_access_token(
            access_token,
            planning_settings,
        )
        scopes = access_token.scopes
        if (
            isinstance(scopes, (str, bytes, bytearray))
            or not isinstance(scopes, (list, tuple))
            or V4_FOLDER_ACTION_SCOPE not in scopes
        ):
            raise PermissionError("operation scope required")
        return principal
    except Exception as exc:
        raise V4FolderActionRuntimeError(V4_FOLDER_ACTION_UNAVAILABLE) from exc


def load_v4_folder_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the exact opt-in feature value, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_FOLDER_ACTION_FEATURE_ENV)
    if raw is None:
        return False
    if raw == "true":
        return True
    if raw == "false":
        return False
    raise V4FolderActionConfigurationError(
        f"{V4_FOLDER_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_folder_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_FOLDER_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4FolderActionConfigurationError(
        f"{V4_FOLDER_EXECUTION_ENV} must be exactly true or false."
    )


class ProtectedChildFolderMcpAction:
    """Expose one actual C/P/E-confirmed child Folder create workflow."""

    def __init__(
        self,
        workflow: Any,
        *,
        execution_enabled: bool = True,
    ) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(
        self,
        folder_name: str,
        parent_folder_id: int,
        principal: Any,
    ) -> dict[str, object]:
        """Return actual Current/Proposed/Expected state without a write."""

        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise V4FolderActionRuntimeError(V4_FOLDER_ACTION_UNAVAILABLE)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    folder_name=folder_name,
                    parent_folder_id=parent_folder_id,
                    requester_digest=principal.requester.digest,
                ),
            )
        except Exception as exc:
            raise V4FolderActionRuntimeError(V4_FOLDER_ACTION_UNAVAILABLE) from exc

    def confirm(
        self,
        preview_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        """Record one explicit human-confirmed preview for execution."""

        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise V4FolderActionRuntimeError(V4_FOLDER_ACTION_UNAVAILABLE)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(
                    preview_ref,
                    requester_digest=principal.requester.digest,
                ),
            )
        except Exception as exc:
            raise V4FolderActionRuntimeError(V4_FOLDER_ACTION_UNAVAILABLE) from exc

    def execute(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        """Execute one exact authorization and return only categorical evidence."""

        if not self._execution_enabled:
            raise V4FolderActionRuntimeError(V4_FOLDER_ACTION_UNAVAILABLE)

        from .v4_plan_runtime import V4PlanningPrincipal

        if (
            not isinstance(principal, V4PlanningPrincipal)
            or _OPAQUE_REF.fullmatch(authorization_ref) is None
        ):
            raise V4FolderActionRuntimeError(V4_FOLDER_ACTION_UNAVAILABLE)
        try:
            result = self._workflow.execute(
                authorization_ref,
                requester_digest=principal.requester.digest,
            )
        except Exception as exc:
            raise V4FolderActionRuntimeError(V4_FOLDER_ACTION_UNAVAILABLE) from exc
        return cast(dict[str, object], result)


def build_v4_folder_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedChildFolderMcpAction:
    """Assemble the controlled action from owner-protected host state."""

    env = os.environ if environment is None else environment
    try:
        from .folder_http_transport import (
            FortiPamFolderHttpTransport,
            load_folder_transport_config,
        )
        from .folder_live_workflow import ChildFolderLiveWorkflow

        authorization_db = _absolute_path(env, "AUTHORIZATION_DB")
        authorization_key = _absolute_path(env, "AUTHORIZATION_HMAC_KEY_FILE")
        transport = FortiPamFolderHttpTransport(load_folder_transport_config(env))
        workflow = ChildFolderLiveWorkflow(
            authorization_db,
            authorization_key,
            transport,
        )
    except Exception as exc:
        raise V4FolderActionConfigurationError(
            V4_FOLDER_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedChildFolderMcpAction(
        workflow,
        execution_enabled=load_v4_folder_execution_feature(env),
    )


def _absolute_path(environment: Mapping[str, str], suffix: str) -> Path:
    raw: Any = environment.get(f"{V4_FOLDER_ACTION_PREFIX}{suffix}")
    if type(raw) is not str or not raw.strip():
        raise V4FolderActionConfigurationError(V4_FOLDER_ACTION_UNAVAILABLE)
    path = Path(raw.strip()).expanduser()
    if not path.is_absolute():
        raise V4FolderActionConfigurationError(V4_FOLDER_ACTION_UNAVAILABLE)
    return path


__all__ = [
    "ProtectedChildFolderMcpAction",
    "V4_FOLDER_ACTION_FEATURE_ENV",
    "V4_FOLDER_ACTION_PREFIX",
    "V4_FOLDER_ACTION_SCOPE",
    "V4_FOLDER_ACTION_TOOL",
    "V4_FOLDER_CONFIRM_TOOL",
    "V4_FOLDER_EXECUTION_ENV",
    "V4_FOLDER_PREVIEW_TOOL",
    "V4_FOLDER_ACTION_UNAVAILABLE",
    "V4FolderActionConfigurationError",
    "V4FolderActionRuntimeError",
    "build_v4_folder_action",
    "folder_action_principal_from_access_token",
    "load_v4_folder_action_feature",
    "load_v4_folder_execution_feature",
]
