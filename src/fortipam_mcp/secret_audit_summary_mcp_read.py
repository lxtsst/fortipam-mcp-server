"""Independent read-only MCP boundary for Secret Audit aggregate counts."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any

from .folder_mcp_action import folder_action_principal_from_access_token
from .secret_audit_summary_http_transport import (
    FortiPamSecretAuditSummaryHttpTransport,
)
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config
from .v4_plan_runtime import V4PlanningPrincipal


V4_SECRET_AUDIT_SUMMARY_FEATURE_ENV = "FORTIPAM_MCP_V4_SECRET_AUDIT_SUMMARY_ENABLED"
V4_SECRET_AUDIT_SUMMARY_TOOL = "summarize_v4_secret_access_audit"
V4_SECRET_AUDIT_SUMMARY_UNAVAILABLE = "FortiPAM Secret Access Audit summary is unavailable."


class V4SecretAuditSummaryError(RuntimeError):
    """Stable failure without report content or private identity values."""


def load_v4_secret_audit_summary_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    env = os.environ if environment is None else environment
    raw = env.get(V4_SECRET_AUDIT_SUMMARY_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4SecretAuditSummaryError(V4_SECRET_AUDIT_SUMMARY_UNAVAILABLE)


def secret_audit_summary_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> V4PlanningPrincipal:
    """Require explicit V4 operation scope for sensitive aggregate access."""

    try:
        principal = folder_action_principal_from_access_token(
            access_token, planning_settings
        )
        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("V4 principal required")
        return principal
    except Exception as exc:
        raise V4SecretAuditSummaryError(V4_SECRET_AUDIT_SUMMARY_UNAVAILABLE) from exc


class ProtectedSecretAuditSummaryMcpRead:
    """Expose only the latest existing report's fixed aggregate projection."""

    def __init__(self, transport: FortiPamSecretAuditSummaryHttpTransport) -> None:
        self._transport = transport

    def summarize(self, principal: V4PlanningPrincipal) -> dict[str, object]:
        if not isinstance(principal, V4PlanningPrincipal):
            raise V4SecretAuditSummaryError(V4_SECRET_AUDIT_SUMMARY_UNAVAILABLE)
        try:
            return self._transport.summarize_latest()
        except Exception as exc:
            raise V4SecretAuditSummaryError(V4_SECRET_AUDIT_SUMMARY_UNAVAILABLE) from exc


def build_v4_secret_audit_summary_read(
    environment: Mapping[str, str] | None = None,
) -> ProtectedSecretAuditSummaryMcpRead:
    env = os.environ if environment is None else environment
    try:
        config = load_secret_metadata_http_transport_config(env)
        return ProtectedSecretAuditSummaryMcpRead(
            FortiPamSecretAuditSummaryHttpTransport(config)
        )
    except Exception as exc:
        raise V4SecretAuditSummaryError(V4_SECRET_AUDIT_SUMMARY_UNAVAILABLE) from exc


__all__ = [
    "ProtectedSecretAuditSummaryMcpRead",
    "V4_SECRET_AUDIT_SUMMARY_FEATURE_ENV",
    "V4_SECRET_AUDIT_SUMMARY_TOOL",
    "V4_SECRET_AUDIT_SUMMARY_UNAVAILABLE",
    "V4SecretAuditSummaryError",
    "build_v4_secret_audit_summary_read",
    "load_v4_secret_audit_summary_feature",
    "secret_audit_summary_principal_from_access_token",
]
