"""MCP boundary for the bounded V4 empty Public Folder archive action."""

from __future__ import annotations

from collections.abc import Mapping
import os
from pathlib import Path
from typing import Any, cast

from .folder_rename_mcp_action import folder_rename_action_principal_from_access_token


V4_FOLDER_ARCHIVE_ACTION_FEATURE_ENV = "FORTIPAM_MCP_V4_FOLDER_ARCHIVE_ACTION_ENABLED"
V4_FOLDER_ARCHIVE_EXECUTION_ENV = "FORTIPAM_MCP_V4_FOLDER_ARCHIVE_EXECUTION_ENABLED"
V4_FOLDER_ARCHIVE_CLAIM_PATH_ENV = "FORTIPAM_MCP_V4_FOLDER_ARCHIVE_CLAIM_PATH"
V4_FOLDER_ARCHIVE_PREVIEW_TOOL = "preview_v4_empty_public_child_folder_archive"
V4_FOLDER_ARCHIVE_CONFIRM_TOOL = "confirm_v4_empty_public_child_folder_archive"
V4_FOLDER_ARCHIVE_ACTION_TOOL = "execute_confirmed_v4_empty_public_child_folder_archive"
V4_FOLDER_ARCHIVE_ACTION_UNAVAILABLE = (
    "FortiPAM V4 empty Public Folder archive action is unavailable."
)


class V4FolderArchiveActionConfigurationError(ValueError):
    """Raised when the destructive Folder action host is incomplete or unsafe."""


class V4FolderArchiveActionRuntimeError(RuntimeError):
    """Stable, non-disclosing empty-Folder archive failure."""


def load_v4_folder_archive_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent empty-Folder archive opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_FOLDER_ARCHIVE_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4FolderArchiveActionConfigurationError(
        f"{V4_FOLDER_ARCHIVE_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_folder_archive_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent destructive dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_FOLDER_ARCHIVE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4FolderArchiveActionConfigurationError(
        f"{V4_FOLDER_ARCHIVE_EXECUTION_ENV} must be exactly true or false."
    )


def folder_archive_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the V4 operation scope used by other Folder mutations."""

    try:
        return folder_rename_action_principal_from_access_token(
            access_token,
            planning_settings,
        )
    except Exception as exc:
        raise V4FolderArchiveActionRuntimeError(
            V4_FOLDER_ARCHIVE_ACTION_UNAVAILABLE
        ) from exc


class ProtectedFolderArchiveMcpAction:
    """Expose C/P/E, one confirmation, and one irreversible empty-Folder delete."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(self, folder_id: int, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    folder_id=folder_id,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4FolderArchiveActionRuntimeError(
                V4_FOLDER_ARCHIVE_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4FolderArchiveActionRuntimeError(
                V4_FOLDER_ARCHIVE_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4FolderArchiveActionRuntimeError(
                V4_FOLDER_ARCHIVE_ACTION_UNAVAILABLE
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
            raise V4FolderArchiveActionRuntimeError(
                V4_FOLDER_ARCHIVE_ACTION_UNAVAILABLE
            ) from exc


def build_v4_folder_archive_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedFolderArchiveMcpAction:
    """Construct the exact archive action from the current fixed Folder API."""

    env = os.environ if environment is None else environment
    try:
        from .folder_archive_live_workflow import (
            FolderArchiveLiveWorkflow, FolderArchiveTransport, FolderArchiveActorReader, FolderArchiveReferenceReader,
        )
        from .folder_archive_owner_session import (
            PREFIX as OWNER_PREFIX, build_folder_archive_owner_session,
        )
        from .folder_archive_reference_ssh_transport import (
            ENV_PREFIX as REFERENCE_ENV_PREFIX,
            FortiPamFolderArchiveReferenceSshTransport,
            OwnerFolderArchiveReferenceSshTransport,
            load_folder_archive_reference_config,
        )
        from .folder_http_transport import (
            FortiPamFolderHttpTransport,
            load_folder_acl_transport_config,
        )
        from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig
        from .secret_request_actor_http_transport import FortiPamSecretRequestActorHttpTransport

        execution_enabled = load_v4_folder_archive_execution_feature(env)
        claim_path = env.get(V4_FOLDER_ARCHIVE_CLAIM_PATH_ENV)
        if execution_enabled and (not isinstance(claim_path, str) or not claim_path.strip()):
            raise ValueError("A durable archive claim binding is required.")
        api_config = load_folder_acl_transport_config(env)
        reference_reader: FolderArchiveReferenceReader | None = None
        owner_reference = env.get(REFERENCE_ENV_PREFIX + "OWNER_LOGIN_ENABLED", "false")
        if owner_reference not in {"true", "false"}:
            raise ValueError("The Owner reference binding flag is invalid.")
        if owner_reference == "true" and (
            env.get(OWNER_PREFIX + "ENABLED") != "true"
            or env.get(REFERENCE_ENV_PREFIX + "ENABLED") != "true"
        ):
            raise ValueError("The explicit Owner and reference bindings are required.")
        if env.get(REFERENCE_ENV_PREFIX + "ENABLED") == "true" and owner_reference == "false":
            reference_config = load_folder_archive_reference_config(env)
            reference_reader = FortiPamFolderArchiveReferenceSshTransport(reference_config)
        elif env.get(REFERENCE_ENV_PREFIX + "ENABLED") not in (None, "false", "true"):
            raise ValueError("The reference binding flag must be exactly true or false.")
        if execution_enabled and reference_reader is None and owner_reference == "false":
            raise ValueError("Calibrated archive reference evidence is required.")
        transport: FolderArchiveTransport = FortiPamFolderHttpTransport(api_config)
        actor_reader: FolderArchiveActorReader = FortiPamSecretRequestActorHttpTransport(
                SecretMetadataHttpTransportConfig(
                    api_config.base_url, api_config.bearer_token,
                    api_config.timeout_seconds, api_config.ca_file,
                )
            )
        bound_folder_name = None
        owner_enabled = env.get(OWNER_PREFIX + "ENABLED", "false")
        if owner_enabled not in {"true", "false"}:
            raise ValueError("The Owner binding flag must be exactly true or false.")
        if owner_enabled == "true":
            owner_transport = build_folder_archive_owner_session(api_config, env)
            transport = owner_transport
            actor_reader = owner_transport
            bound_folder_name = owner_transport.folder_name
            if owner_reference == "true":
                from .owner_collector_runtime import PREFIX as LOGIN_PREFIX, owner_login_provider
                login = {LOGIN_PREFIX + "SESSION_ENABLED": "true"}
                for suffix in ("LOGIN_ENV_FILE", "USERNAME_VARIABLE", "PASSWORD_VARIABLE"):
                    login[LOGIN_PREFIX + suffix] = env[OWNER_PREFIX + suffix]
                credentials = owner_login_provider(login)
                if credentials is None:
                    raise ValueError("The fixed Owner provider is required.")
                reference_reader = OwnerFolderArchiveReferenceSshTransport(
                    env, owner_name=env[OWNER_PREFIX + "USERNAME"], credentials=credentials)
        if execution_enabled and reference_reader is None:
            raise ValueError("Calibrated archive reference evidence is required.")
        workflow = FolderArchiveLiveWorkflow(
            transport,
            claim_path=Path(claim_path).expanduser() if claim_path else None,
            reference_reader=reference_reader,
            actor_reader=actor_reader,
            bound_folder_name=bound_folder_name,
            delete_authentication="owner_session" if owner_enabled == "true" else "api_bearer",
        )
    except Exception as exc:
        raise V4FolderArchiveActionConfigurationError(
            V4_FOLDER_ARCHIVE_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedFolderArchiveMcpAction(
        workflow,
        execution_enabled=execution_enabled,
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4FolderArchiveActionRuntimeError(
            V4_FOLDER_ARCHIVE_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedFolderArchiveMcpAction",
    "V4_FOLDER_ARCHIVE_ACTION_FEATURE_ENV",
    "V4_FOLDER_ARCHIVE_ACTION_TOOL",
    "V4_FOLDER_ARCHIVE_ACTION_UNAVAILABLE",
    "V4_FOLDER_ARCHIVE_CLAIM_PATH_ENV",
    "V4_FOLDER_ARCHIVE_CONFIRM_TOOL",
    "V4_FOLDER_ARCHIVE_EXECUTION_ENV",
    "V4_FOLDER_ARCHIVE_PREVIEW_TOOL",
    "V4FolderArchiveActionConfigurationError",
    "V4FolderArchiveActionRuntimeError",
    "build_v4_folder_archive_action",
    "folder_archive_action_principal_from_access_token",
    "load_v4_folder_archive_action_feature",
    "load_v4_folder_archive_execution_feature",
]
