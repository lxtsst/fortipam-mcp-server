"""MCP boundary for one controlled FortiPAM client-integrity precondition."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_CLIENT_INTEGRITY_ACTION_PREFIX = "FORTIPAM_MCP_V4_CLIENT_INTEGRITY_ACTION_"
V4_CLIENT_INTEGRITY_ACTION_FEATURE_ENV = f"{V4_CLIENT_INTEGRITY_ACTION_PREFIX}ENABLED"
V4_CLIENT_INTEGRITY_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_CLIENT_INTEGRITY_EXECUTION_ENABLED"
)
V4_CLIENT_INTEGRITY_PREVIEW_TOOL = "preview_v4_client_integrity_configure"
V4_CLIENT_INTEGRITY_CONFIRM_TOOL = "confirm_v4_client_integrity_configure"
V4_CLIENT_INTEGRITY_ACTION_TOOL = "execute_confirmed_v4_client_integrity_configure"
V4_CLIENT_INTEGRITY_ACTION_UNAVAILABLE = (
    "FortiPAM V4 client-integrity action is unavailable."
)


class V4ClientIntegrityActionConfigurationError(ValueError):
    """Raised when the client-integrity action host is incomplete or unsafe."""


class V4ClientIntegrityActionRuntimeError(RuntimeError):
    """Stable, non-disclosing client-integrity action failure."""


def load_v4_client_integrity_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent client-integrity opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_CLIENT_INTEGRITY_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ClientIntegrityActionConfigurationError(
        f"{V4_CLIENT_INTEGRITY_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_client_integrity_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_CLIENT_INTEGRITY_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ClientIntegrityActionConfigurationError(
        f"{V4_CLIENT_INTEGRITY_EXECUTION_ENV} must be exactly true or false."
    )


def client_integrity_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4ClientIntegrityActionRuntimeError(
            V4_CLIENT_INTEGRITY_ACTION_UNAVAILABLE
        ) from exc


class ProtectedClientIntegrityMcpAction:
    """Expose only C/P/E, confirmation, and execution for one precondition."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(
        self,
        client_software_name: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    client_software_name=client_software_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ClientIntegrityActionRuntimeError(
                V4_CLIENT_INTEGRITY_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4ClientIntegrityActionRuntimeError(
                V4_CLIENT_INTEGRITY_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4ClientIntegrityActionRuntimeError(
                V4_CLIENT_INTEGRITY_ACTION_UNAVAILABLE
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
            raise V4ClientIntegrityActionRuntimeError(
                V4_CLIENT_INTEGRITY_ACTION_UNAVAILABLE
            ) from exc


def build_v4_client_integrity_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedClientIntegrityMcpAction:
    """Construct the action from the current shared Profile SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .client_integrity_live_workflow import (
            ClientIntegrityConfigureLiveWorkflow,
        )
        from .antivirus_profile_ssh_transport import (
            load_antivirus_profile_ssh_transport_config,
        )
        from .client_integrity_ssh_transport import (
            ClientIntegritySshTransportConfig,
            FortiPamClientIntegritySshTransport,
        )

        current_profile = load_antivirus_profile_ssh_transport_config(env)

        workflow = ClientIntegrityConfigureLiveWorkflow(
            FortiPamClientIntegritySshTransport(
                ClientIntegritySshTransportConfig(
                    host=current_profile.host,
                    port=current_profile.port,
                    username=current_profile.username,
                    password=current_profile.password,
                    known_hosts_file=current_profile.known_hosts_file,
                    timeout_seconds=current_profile.timeout_seconds,
                )
            )
        )
    except Exception as exc:
        raise V4ClientIntegrityActionConfigurationError(
            V4_CLIENT_INTEGRITY_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedClientIntegrityMcpAction(
        workflow,
        execution_enabled=load_v4_client_integrity_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4ClientIntegrityActionRuntimeError(
            V4_CLIENT_INTEGRITY_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedClientIntegrityMcpAction",
    "V4_CLIENT_INTEGRITY_ACTION_FEATURE_ENV",
    "V4_CLIENT_INTEGRITY_ACTION_PREFIX",
    "V4_CLIENT_INTEGRITY_ACTION_TOOL",
    "V4_CLIENT_INTEGRITY_ACTION_UNAVAILABLE",
    "V4_CLIENT_INTEGRITY_CONFIRM_TOOL",
    "V4_CLIENT_INTEGRITY_EXECUTION_ENV",
    "V4_CLIENT_INTEGRITY_PREVIEW_TOOL",
    "V4ClientIntegrityActionConfigurationError",
    "V4ClientIntegrityActionRuntimeError",
    "build_v4_client_integrity_action",
    "client_integrity_action_principal_from_access_token",
    "load_v4_client_integrity_action_feature",
    "load_v4_client_integrity_execution_feature",
]
