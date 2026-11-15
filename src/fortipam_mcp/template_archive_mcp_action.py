"""MCP boundary for one controlled FortiPAM disposable Template archive."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token
from .template_ssh_transport import TemplateArchivePreflightReadback


V4_TEMPLATE_ARCHIVE_ACTION_PREFIX = "FORTIPAM_MCP_V4_TEMPLATE_ARCHIVE_ACTION_"
V4_TEMPLATE_ARCHIVE_ACTION_FEATURE_ENV = f"{V4_TEMPLATE_ARCHIVE_ACTION_PREFIX}ENABLED"
V4_TEMPLATE_ARCHIVE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_TEMPLATE_ARCHIVE_EXECUTION_ENABLED"
)
V4_TEMPLATE_ARCHIVE_PREVIEW_TOOL = "preview_v4_disposable_template_archive"
V4_TEMPLATE_ARCHIVE_CONFIRM_TOOL = "confirm_v4_disposable_template_archive"
V4_TEMPLATE_ARCHIVE_ACTION_TOOL = "execute_confirmed_v4_disposable_template_archive"
V4_TEMPLATE_ARCHIVE_ACTION_UNAVAILABLE = (
    "FortiPAM V4 Template archive action is unavailable."
)


class V4TemplateArchiveActionConfigurationError(ValueError):
    """Raised when the isolated Template archive action host is unsafe."""


class V4TemplateArchiveActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Template archive action failure."""


def load_v4_template_archive_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Template archive feature, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_TEMPLATE_ARCHIVE_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4TemplateArchiveActionConfigurationError(
        f"{V4_TEMPLATE_ARCHIVE_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_template_archive_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_TEMPLATE_ARCHIVE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4TemplateArchiveActionConfigurationError(
        f"{V4_TEMPLATE_ARCHIVE_EXECUTION_ENV} must be exactly true or false."
    )


def template_archive_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the explicit V4 operation scope used by other mutations."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4TemplateArchiveActionRuntimeError(
            V4_TEMPLATE_ARCHIVE_ACTION_UNAVAILABLE
        ) from exc


class ProtectedTemplateArchiveMcpAction:
    """Expose only C/P/E, one confirmation, and one fixed REST delete."""

    def __init__(self, workflow: Any, *, execution_enabled: bool = True) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled

    def preview(self, template_name: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    template_name=template_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4TemplateArchiveActionRuntimeError(
                V4_TEMPLATE_ARCHIVE_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4TemplateArchiveActionRuntimeError(
                V4_TEMPLATE_ARCHIVE_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4TemplateArchiveActionRuntimeError(
                V4_TEMPLATE_ARCHIVE_ACTION_UNAVAILABLE
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
            raise V4TemplateArchiveActionRuntimeError(
                V4_TEMPLATE_ARCHIVE_ACTION_UNAVAILABLE
            ) from exc


class _TemplateArchiveApiSshInspectionTransport:
    """Use API detail for Template shape and SSH only for direct references."""

    def __init__(self, api_transport: Any, ssh_transport: Any) -> None:
        self._api_transport = api_transport
        self._ssh_transport = ssh_transport

    def archive_preflight_readback(
        self,
        template_name: str,
    ) -> TemplateArchivePreflightReadback:
        baseline = self._api_transport.read_default_web_vnc_baseline(template_name)
        references = self._ssh_transport.archive_preflight_readback(template_name)
        return TemplateArchivePreflightReadback(
            template_name_exists=baseline.template_name_exists,
            access_everyone=baseline.access_everyone,
            username_field_present=baseline.username_field_present,
            username_field_mandatory=baseline.username_field_mandatory,
            password_field_present=baseline.password_field_present,
            password_field_mandatory=baseline.password_field_mandatory,
            web_vnc_launcher_present=baseline.web_vnc_launcher_present,
            web_vnc_port_is_default=baseline.web_vnc_port_is_default,
            secret_references_absent=references.secret_references_absent,
            target_references_absent=references.target_references_absent,
        )

    def archive_absence_readback(self, template_name: str) -> Any:
        return self._ssh_transport.archive_absence_readback(template_name)


def build_v4_template_archive_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedTemplateArchiveMcpAction:
    """Build archive workflow from current Template REST and SSH configurations."""

    env = os.environ if environment is None else environment
    try:
        from .template_archive_http_transport import (
            FortiPamTemplateArchiveHttpTransport,
            TemplateArchiveHttpTransportConfig,
        )
        from .template_archive_live_workflow import TemplateArchiveLiveWorkflow
        from .template_reconciliation_http_transport import (
            FortiPamTemplateReconciliationHttpTransport,
            TemplateReconciliationHttpTransportConfig,
            load_template_reconciliation_http_transport_config,
        )
        from .template_ssh_transport import (
            FortiPamTemplateSshTransport,
            load_template_ssh_transport_config,
        )

        current_api = load_template_reconciliation_http_transport_config(env)
        api_config = TemplateArchiveHttpTransportConfig(
            base_url=current_api.base_url,
            bearer_token=current_api.bearer_token,
            timeout_seconds=current_api.timeout_seconds,
            ca_file=current_api.ca_file,
        )
        ssh_transport = FortiPamTemplateSshTransport(
            load_template_ssh_transport_config(env)
        )
        workflow = TemplateArchiveLiveWorkflow(
            _TemplateArchiveApiSshInspectionTransport(
                FortiPamTemplateReconciliationHttpTransport(
                    TemplateReconciliationHttpTransportConfig(
                        base_url=api_config.base_url,
                        bearer_token=api_config.bearer_token,
                        timeout_seconds=api_config.timeout_seconds,
                        ca_file=api_config.ca_file,
                    )
                ),
                ssh_transport,
            ),
            FortiPamTemplateArchiveHttpTransport(api_config),
        )
    except Exception as exc:
        raise V4TemplateArchiveActionConfigurationError(
            V4_TEMPLATE_ARCHIVE_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedTemplateArchiveMcpAction(
        workflow,
        execution_enabled=load_v4_template_archive_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4TemplateArchiveActionRuntimeError(
            V4_TEMPLATE_ARCHIVE_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedTemplateArchiveMcpAction",
    "V4_TEMPLATE_ARCHIVE_ACTION_FEATURE_ENV",
    "V4_TEMPLATE_ARCHIVE_ACTION_PREFIX",
    "V4_TEMPLATE_ARCHIVE_ACTION_TOOL",
    "V4_TEMPLATE_ARCHIVE_ACTION_UNAVAILABLE",
    "V4_TEMPLATE_ARCHIVE_CONFIRM_TOOL",
    "V4_TEMPLATE_ARCHIVE_EXECUTION_ENV",
    "V4_TEMPLATE_ARCHIVE_PREVIEW_TOOL",
    "V4TemplateArchiveActionConfigurationError",
    "V4TemplateArchiveActionRuntimeError",
    "build_v4_template_archive_action",
    "load_v4_template_archive_action_feature",
    "load_v4_template_archive_execution_feature",
    "template_archive_action_principal_from_access_token",
]
