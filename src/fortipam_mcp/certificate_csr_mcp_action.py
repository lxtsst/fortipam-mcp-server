"""MCP boundary for one controlled FortiPAM CSR generation workflow."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_CERTIFICATE_CSR_ACTION_FEATURE_ENV = (
    "FORTIPAM_MCP_V4_CERTIFICATE_CSR_ACTION_ENABLED"
)
V4_CERTIFICATE_CSR_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_CERTIFICATE_CSR_EXECUTION_ENABLED"
)
V4_CERTIFICATE_CSR_PREVIEW_TOOL = "preview_v4_certificate_csr_generate"
V4_CERTIFICATE_CSR_CONFIRM_TOOL = "confirm_v4_certificate_csr_generate"
V4_CERTIFICATE_CSR_ACTION_TOOL = "execute_confirmed_v4_certificate_csr_generate"
V4_CERTIFICATE_CSR_ACTION_UNAVAILABLE = (
    "FortiPAM V4 certificate CSR action is unavailable."
)


class V4CertificateCsrActionConfigurationError(ValueError):
    """Raised when the CSR action host is incomplete or unsafe."""


class V4CertificateCsrActionRuntimeError(RuntimeError):
    """Stable, non-disclosing CSR action failure."""


def load_v4_certificate_csr_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent CSR action opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_CERTIFICATE_CSR_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4CertificateCsrActionConfigurationError(
        f"{V4_CERTIFICATE_CSR_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_certificate_csr_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_CERTIFICATE_CSR_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4CertificateCsrActionConfigurationError(
        f"{V4_CERTIFICATE_CSR_EXECUTION_ENV} must be exactly true or false."
    )


def certificate_csr_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require explicit read, plan, and operate scopes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4CertificateCsrActionRuntimeError(
            V4_CERTIFICATE_CSR_ACTION_UNAVAILABLE
        ) from exc


class ProtectedCertificateCsrMcpAction:
    """Expose only C/P/E, confirmation, and one fixed CSR execution."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(
        self,
        certificate_name: str,
        subject_ipv4: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    certificate_name=certificate_name,
                    subject_ipv4=subject_ipv4,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4CertificateCsrActionRuntimeError(
                V4_CERTIFICATE_CSR_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(
                    preview_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4CertificateCsrActionRuntimeError(
                V4_CERTIFICATE_CSR_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4CertificateCsrActionRuntimeError(
                V4_CERTIFICATE_CSR_ACTION_UNAVAILABLE
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
            raise V4CertificateCsrActionRuntimeError(
                V4_CERTIFICATE_CSR_ACTION_UNAVAILABLE
            ) from exc


def build_v4_certificate_csr_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedCertificateCsrMcpAction:
    """Construct the fixed CSR action from the current central API settings."""

    env = os.environ if environment is None else environment
    try:
        from .certificate_csr_http_transport import (
            CertificateCsrHttpTransportConfig,
            FortiPamCertificateCsrHttpTransport,
        )
        from .certificate_csr_live_workflow import CertificateCsrLiveWorkflow
        from .target_http_transport import load_target_http_transport_config

        central = load_target_http_transport_config(env)

        workflow = CertificateCsrLiveWorkflow(
            FortiPamCertificateCsrHttpTransport(
                CertificateCsrHttpTransportConfig(
                    base_url=central.base_url,
                    bearer_token=central.bearer_token,
                    timeout_seconds=central.timeout_seconds,
                    ca_file=central.ca_file,
                )
            )
        )
    except Exception as exc:
        raise V4CertificateCsrActionConfigurationError(
            V4_CERTIFICATE_CSR_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedCertificateCsrMcpAction(
        workflow,
        execution_enabled=load_v4_certificate_csr_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4CertificateCsrActionRuntimeError(
            V4_CERTIFICATE_CSR_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedCertificateCsrMcpAction",
    "V4_CERTIFICATE_CSR_ACTION_FEATURE_ENV",
    "V4_CERTIFICATE_CSR_ACTION_TOOL",
    "V4_CERTIFICATE_CSR_ACTION_UNAVAILABLE",
    "V4_CERTIFICATE_CSR_CONFIRM_TOOL",
    "V4_CERTIFICATE_CSR_EXECUTION_ENV",
    "V4_CERTIFICATE_CSR_PREVIEW_TOOL",
    "V4CertificateCsrActionConfigurationError",
    "V4CertificateCsrActionRuntimeError",
    "build_v4_certificate_csr_action",
    "certificate_csr_action_principal_from_access_token",
    "load_v4_certificate_csr_action_feature",
    "load_v4_certificate_csr_execution_feature",
]
