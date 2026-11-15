"""MCP boundary for one controlled metadata-only FortiPAM Secret create."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_SECRET_METADATA_ACTION_FEATURE_ENV = "FORTIPAM_MCP_V4_SECRET_METADATA_ACTION_ENABLED"
V4_SECRET_METADATA_EXECUTION_ENV = "FORTIPAM_MCP_V4_SECRET_METADATA_EXECUTION_ENABLED"
V4_SECRET_METADATA_PREVIEW_TOOL = "preview_v4_secret_metadata_create"
V4_SECRET_METADATA_CONFIRM_TOOL = "confirm_v4_secret_metadata_create"
V4_SECRET_METADATA_ACTION_TOOL = "execute_confirmed_v4_secret_metadata_create"
V4_SECRET_METADATA_ACTION_UNAVAILABLE = (
    "FortiPAM V4 Secret metadata action is unavailable."
)


class V4SecretMetadataActionConfigurationError(ValueError):
    """Raised when the metadata-only Secret action host is incomplete or unsafe."""


class V4SecretMetadataActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Secret metadata action failure."""


def load_v4_secret_metadata_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Secret metadata action opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_SECRET_METADATA_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4SecretMetadataActionConfigurationError(
        f"{V4_SECRET_METADATA_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_secret_metadata_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_SECRET_METADATA_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4SecretMetadataActionConfigurationError(
        f"{V4_SECRET_METADATA_EXECUTION_ENV} must be exactly true or false."
    )


def secret_metadata_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4SecretMetadataActionRuntimeError(
            V4_SECRET_METADATA_ACTION_UNAVAILABLE
        ) from exc


class ProtectedSecretMetadataMcpAction:
    """Expose only C/P/E, confirmation, and no-credential material creation."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(
        self,
        folder_path: str,
        secret_name: str,
        template: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    folder_path=folder_path,
                    secret_name=secret_name,
                    template=template,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4SecretMetadataActionRuntimeError(
                V4_SECRET_METADATA_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4SecretMetadataActionRuntimeError(
                V4_SECRET_METADATA_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4SecretMetadataActionRuntimeError(
                V4_SECRET_METADATA_ACTION_UNAVAILABLE
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
            raise V4SecretMetadataActionRuntimeError(
                V4_SECRET_METADATA_ACTION_UNAVAILABLE
            ) from exc


def build_v4_secret_metadata_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedSecretMetadataMcpAction:
    """Construct the independent metadata-only REST action host."""

    env = os.environ if environment is None else environment
    try:
        from .secret_metadata_http_transport import (
            FortiPamSecretMetadataHttpTransport,
            load_secret_metadata_http_transport_config,
        )
        from .secret_metadata_live_workflow import SecretMetadataLiveWorkflow

        workflow = SecretMetadataLiveWorkflow(
            FortiPamSecretMetadataHttpTransport(
                load_secret_metadata_http_transport_config(env)
            )
        )
    except Exception as exc:
        raise V4SecretMetadataActionConfigurationError(
            V4_SECRET_METADATA_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedSecretMetadataMcpAction(
        workflow,
        execution_enabled=load_v4_secret_metadata_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4SecretMetadataActionRuntimeError(
            V4_SECRET_METADATA_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedSecretMetadataMcpAction",
    "V4_SECRET_METADATA_ACTION_FEATURE_ENV",
    "V4_SECRET_METADATA_ACTION_TOOL",
    "V4_SECRET_METADATA_ACTION_UNAVAILABLE",
    "V4_SECRET_METADATA_CONFIRM_TOOL",
    "V4_SECRET_METADATA_EXECUTION_ENV",
    "V4_SECRET_METADATA_PREVIEW_TOOL",
    "V4SecretMetadataActionConfigurationError",
    "V4SecretMetadataActionRuntimeError",
    "build_v4_secret_metadata_action",
    "load_v4_secret_metadata_action_feature",
    "load_v4_secret_metadata_execution_feature",
    "secret_metadata_action_principal_from_access_token",
]
