"""MCP boundary for one controlled FortiPAM Local User create workflow."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_LOCAL_USER_CREATE_ACTION_PREFIX = "FORTIPAM_MCP_V4_LOCAL_USER_CREATE_ACTION_"
V4_LOCAL_USER_CREATE_ACTION_FEATURE_ENV = (
    f"{V4_LOCAL_USER_CREATE_ACTION_PREFIX}ENABLED"
)
V4_LOCAL_USER_CREATE_CONTRACT_ENV = (
    f"{V4_LOCAL_USER_CREATE_ACTION_PREFIX}CONTRACT"
)
V4_LOCAL_USER_CREATE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_LOCAL_USER_CREATE_EXECUTION_ENABLED"
)
V4_LOCAL_USER_CREATE_PREVIEW_TOOL = "preview_v4_local_user_create"
V4_LOCAL_USER_CREATE_CONFIRM_TOOL = "confirm_v4_local_user_create"
V4_LOCAL_USER_CREATE_ACTION_TOOL = "execute_confirmed_v4_local_user_create"
V4_LOCAL_USER_CREATE_ACTION_UNAVAILABLE = (
    "FortiPAM V4 Local User create action is unavailable."
)


class V4LocalUserCreateActionConfigurationError(ValueError):
    """Raised when the Local User create action host is incomplete or unsafe."""


class V4LocalUserCreateActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Local User create action failure."""


def load_v4_local_user_create_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Local User create opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_LOCAL_USER_CREATE_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4LocalUserCreateActionConfigurationError(
        f"{V4_LOCAL_USER_CREATE_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_local_user_create_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_LOCAL_USER_CREATE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4LocalUserCreateActionConfigurationError(
        f"{V4_LOCAL_USER_CREATE_EXECUTION_ENV} must be exactly true or false."
    )


def local_user_create_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4LocalUserCreateActionRuntimeError(
            V4_LOCAL_USER_CREATE_ACTION_UNAVAILABLE
        ) from exc


class ProtectedLocalUserCreateMcpAction:
    """Expose only C/P/E, confirmation, and execution for one Local User create."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(self, username: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    username=username,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4LocalUserCreateActionRuntimeError(
                V4_LOCAL_USER_CREATE_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4LocalUserCreateActionRuntimeError(
                V4_LOCAL_USER_CREATE_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4LocalUserCreateActionRuntimeError(
                V4_LOCAL_USER_CREATE_ACTION_UNAVAILABLE
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
            raise V4LocalUserCreateActionRuntimeError(
                V4_LOCAL_USER_CREATE_ACTION_UNAVAILABLE
            ) from exc


def build_v4_local_user_create_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedLocalUserCreateMcpAction:
    """Construct one explicit fixed Local User creation profile."""

    env = os.environ if environment is None else environment
    try:
        from .local_user_create_live_workflow import (
            BP002_ENABLED_GUEST_WORKFLOW_CONTRACT,
            BP005_STANDARD_USER_WORKFLOW_CONTRACT,
            LocalUserCreateLiveWorkflow,
        )
        contract = env.get(V4_LOCAL_USER_CREATE_CONTRACT_ENV)
        if contract in {"bp005-standard-enabled-v1", "bp002-guest-enabled-v1"}:
            from pathlib import Path

            from .bp005_standard_user_transport import FortiPamBp005StandardUserTransport
            from .local_user_reset_fixture_transport import FortiPamLocalUserResetFixtureTransport
            from .m4_execution_store import PersistentM4ExecutionStateStore
            from .secret_metadata_http_transport import load_secret_metadata_http_transport_config

            standard_user = contract == "bp005-standard-enabled-v1"
            profile = "BP005" if standard_user else "BP002"
            values = {
                key: env.get(f"{V4_LOCAL_USER_CREATE_ACTION_PREFIX}{profile}_{key}")
                for key in (
                    "USERNAME", "API_PRINCIPAL", "MATERIAL_DIRECTORY",
                    "EXECUTION_DATABASE", "EXECUTION_KEY_FILE",
                )
            }
            if any(value is None or not value for value in values.values()):
                raise ValueError
            paths = [Path(cast(str, values[key])) for key in (
                "MATERIAL_DIRECTORY", "EXECUTION_DATABASE", "EXECUTION_KEY_FILE",
            )]
            if any(not path.is_absolute() for path in paths):
                raise ValueError
            if standard_user and (
                paths[1] == paths[2]
                or any(paths[0] == path or paths[0] in path.parents for path in paths[1:])
            ):
                raise ValueError
            if not standard_user and (
                paths[1] != paths[0] / "execution.sqlite3"
                or paths[2] != paths[0] / "execution.key"
            ):
                raise ValueError
            execution_store = PersistentM4ExecutionStateStore(paths[1], paths[2])
            enabled = load_v4_local_user_create_execution_feature(env)
            transport_class = (
                FortiPamBp005StandardUserTransport
                if standard_user else FortiPamLocalUserResetFixtureTransport
            )
            transport = transport_class(
                load_secret_metadata_http_transport_config(env),
                username=cast(str, values["USERNAME"]),
                api_principal=cast(str, values["API_PRINCIPAL"]),
                material_directory=paths[0],
                enabled=enabled,
            )
            workflow = LocalUserCreateLiveWorkflow(
                transport,
                execution_store=execution_store,
                workflow_contract=(
                    BP005_STANDARD_USER_WORKFLOW_CONTRACT
                    if standard_user else BP002_ENABLED_GUEST_WORKFLOW_CONTRACT
                ),
            )
        elif contract is None:
            workflow = LocalUserCreateLiveWorkflow(
                _legacy_local_user_create_ssh_transport(env)
            )
        else:
            raise ValueError
    except Exception as exc:
        raise V4LocalUserCreateActionConfigurationError(
            V4_LOCAL_USER_CREATE_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedLocalUserCreateMcpAction(
        workflow,
        execution_enabled=load_v4_local_user_create_execution_feature(env),
    )


def _legacy_local_user_create_ssh_transport(environment: Mapping[str, str]) -> Any:
    from .local_user_create_ssh_transport import (
        FortiPamLocalUserCreateSshTransport,
        load_local_user_create_ssh_transport_config,
    )

    return FortiPamLocalUserCreateSshTransport(
        load_local_user_create_ssh_transport_config(environment)
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4LocalUserCreateActionRuntimeError(
            V4_LOCAL_USER_CREATE_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedLocalUserCreateMcpAction",
    "V4_LOCAL_USER_CREATE_ACTION_FEATURE_ENV",
    "V4_LOCAL_USER_CREATE_ACTION_PREFIX",
    "V4_LOCAL_USER_CREATE_CONTRACT_ENV",
    "V4_LOCAL_USER_CREATE_ACTION_TOOL",
    "V4_LOCAL_USER_CREATE_ACTION_UNAVAILABLE",
    "V4_LOCAL_USER_CREATE_CONFIRM_TOOL",
    "V4_LOCAL_USER_CREATE_EXECUTION_ENV",
    "V4_LOCAL_USER_CREATE_PREVIEW_TOOL",
    "V4LocalUserCreateActionConfigurationError",
    "V4LocalUserCreateActionRuntimeError",
    "build_v4_local_user_create_action",
    "load_v4_local_user_create_action_feature",
    "load_v4_local_user_create_execution_feature",
    "local_user_create_action_principal_from_access_token",
]
