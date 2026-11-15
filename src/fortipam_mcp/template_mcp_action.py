"""MCP boundary for one controlled FortiPAM Web VNC Template create."""

from __future__ import annotations

from collections.abc import Mapping
import os
from pathlib import Path
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_TEMPLATE_ACTION_PREFIX = "FORTIPAM_MCP_V4_TEMPLATE_ACTION_"
V4_TEMPLATE_ACTION_FEATURE_ENV = f"{V4_TEMPLATE_ACTION_PREFIX}ENABLED"
V4_TEMPLATE_EXECUTION_ENV = "FORTIPAM_MCP_V4_TEMPLATE_EXECUTION_ENABLED"
V4_TEMPLATE_UPDATE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_TEMPLATE_UPDATE_EXECUTION_ENABLED"
)
V4_TEMPLATE_UPDATE_CLAIM_ENV = "FORTIPAM_MCP_V4_TEMPLATE_UPDATE_CLAIM_FILE"
V4_TEMPLATE_PREVIEW_TOOL = "preview_v4_template_create"
V4_TEMPLATE_CONFIRM_TOOL = "confirm_v4_template_create"
V4_TEMPLATE_ACTION_TOOL = "execute_confirmed_v4_template_create"
V4_TEMPLATE_UPDATE_PREVIEW_TOOL = "preview_v4_template_web_vnc_port_update"
V4_TEMPLATE_UPDATE_CONFIRM_TOOL = "confirm_v4_template_web_vnc_port_update"
V4_TEMPLATE_UPDATE_ACTION_TOOL = "execute_confirmed_v4_template_web_vnc_port_update"
V4_TEMPLATE_ACTION_UNAVAILABLE = "FortiPAM V4 Template create action is unavailable."


class V4TemplateActionConfigurationError(ValueError):
    """Raised when the Template action host is incomplete or unsafe."""


class V4TemplateActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Template action failure."""


def load_v4_template_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Template opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_TEMPLATE_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4TemplateActionConfigurationError(
        f"{V4_TEMPLATE_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def _load_exact_execution_feature(
    environment: Mapping[str, str] | None,
    variable: str,
) -> bool:
    env = os.environ if environment is None else environment
    raw = env.get(variable)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4TemplateActionConfigurationError(
        f"{variable} must be exactly true or false."
    )


def load_v4_template_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent create final-dispatch gate."""

    return _load_exact_execution_feature(environment, V4_TEMPLATE_EXECUTION_ENV)


def load_v4_template_update_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent update final-dispatch gate."""

    return _load_exact_execution_feature(
        environment,
        V4_TEMPLATE_UPDATE_EXECUTION_ENV,
    )


def template_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4TemplateActionRuntimeError(V4_TEMPLATE_ACTION_UNAVAILABLE) from exc


class ProtectedTemplateMcpAction:
    """Expose bounded create and baseline-bound update C/P/E workflows."""

    def __init__(
        self,
        workflow: Any,
        *,
        update_workflow: Any | None = None,
        execution_enabled: bool = True,
        update_execution_enabled: bool = True,
    ) -> None:
        self._workflow = workflow
        self._update_workflow = update_workflow
        self._execution_enabled = execution_enabled
        self._update_execution_enabled = update_execution_enabled

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
            raise V4TemplateActionRuntimeError(V4_TEMPLATE_ACTION_UNAVAILABLE) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4TemplateActionRuntimeError(V4_TEMPLATE_ACTION_UNAVAILABLE) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4TemplateActionRuntimeError(V4_TEMPLATE_ACTION_UNAVAILABLE)
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
            raise V4TemplateActionRuntimeError(V4_TEMPLATE_ACTION_UNAVAILABLE) from exc

    def preview_update(self, template_name: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._require_update_workflow().preview(
                    template_name=template_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4TemplateActionRuntimeError(V4_TEMPLATE_ACTION_UNAVAILABLE) from exc

    def confirm_update(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._require_update_workflow().confirm(
                    preview_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4TemplateActionRuntimeError(V4_TEMPLATE_ACTION_UNAVAILABLE) from exc

    def execute_update(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._update_execution_enabled:
            raise V4TemplateActionRuntimeError(V4_TEMPLATE_ACTION_UNAVAILABLE)
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._require_update_workflow().execute(
                    authorization_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4TemplateActionRuntimeError(V4_TEMPLATE_ACTION_UNAVAILABLE) from exc

    def _require_update_workflow(self) -> Any:
        if self._update_workflow is None:
            raise V4TemplateActionRuntimeError(V4_TEMPLATE_ACTION_UNAVAILABLE)
        return self._update_workflow


def build_v4_template_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedTemplateMcpAction:
    """Construct the action from dedicated pinned SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .template_live_workflow import TemplateCreateLiveWorkflow
        from .template_ssh_transport import (
            FortiPamTemplateSshTransport,
            load_template_ssh_transport_config,
        )
        from .template_update_live_workflow import TemplateWebVncPortUpdateLiveWorkflow

        update_gate = load_v4_template_update_execution_feature(env)
        claim_file = env.get(V4_TEMPLATE_UPDATE_CLAIM_ENV)
        if update_gate and not claim_file:
            raise ValueError
        direction = env.get("FORTIPAM_MCP_V4_TEMPLATE_UPDATE_DIRECTION", "update_port")
        rest_prefix = "FPA_HOME_LAB_FPA1_V4_TEMPLATE_UPDATE_API_"
        if (direction not in {"update_port", "restore_default_port"}
                or (direction == "restore_default_port" and env.get(rest_prefix + "ENABLED") != "true")):
            raise ValueError
        transport = FortiPamTemplateSshTransport(load_template_ssh_transport_config(env))
        workflow = TemplateCreateLiveWorkflow(transport)
        update_transport: Any = transport
        write_transport = "ssh_cli_fallback"
        rest_prefix = "FPA_HOME_LAB_FPA1_V4_TEMPLATE_UPDATE_API_"
        rest_enabled = env.get(f"{rest_prefix}ENABLED")
        if rest_enabled not in {None, "false", "true"}:
            raise ValueError
        if rest_enabled == "true":
            from .template_reconciliation_http_transport import (
                ENV_PREFIX as reconcile_prefix,
                load_template_reconciliation_http_transport_config,
            )
            from .template_update_http_transport import (
                FortiPamTemplateUpdateHttpTransport, load_template_update_http_binding,
            )

            binding_file = env.get(f"{rest_prefix}BINDING_FILE")
            transport_claim = env.get(f"{rest_prefix}CLAIM_FILE")
            if not binding_file or not transport_claim:
                raise ValueError
            api_env = {
                f"{reconcile_prefix}{key}": env[f"{rest_prefix}{key}"]
                for key in ("ENABLED", "BASE_URL", "HOST", "API_TOKEN_FILE", "TIMEOUT_SECONDS", "CA_FILE")
                if f"{rest_prefix}{key}" in env
            }
            update_transport = FortiPamTemplateUpdateHttpTransport(
                load_template_reconciliation_http_transport_config(api_env),
                load_template_update_http_binding(Path(binding_file)), transport, Path(transport_claim),
                restore_default_port=direction == "restore_default_port",
            )
            write_transport = "rest_api"
        update_workflow = TemplateWebVncPortUpdateLiveWorkflow(
            update_transport, claim_path=Path(claim_file) if claim_file else None,
            write_transport=write_transport,
            restore_default_port=direction == "restore_default_port",
        )
    except Exception as exc:
        raise V4TemplateActionConfigurationError(
            V4_TEMPLATE_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedTemplateMcpAction(
        workflow,
        update_workflow=update_workflow,
        execution_enabled=load_v4_template_execution_feature(env),
        update_execution_enabled=update_gate,
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4TemplateActionRuntimeError(V4_TEMPLATE_ACTION_UNAVAILABLE) from exc


__all__ = [
    "ProtectedTemplateMcpAction",
    "V4_TEMPLATE_ACTION_FEATURE_ENV",
    "V4_TEMPLATE_ACTION_PREFIX",
    "V4_TEMPLATE_ACTION_TOOL",
    "V4_TEMPLATE_ACTION_UNAVAILABLE",
    "V4_TEMPLATE_CONFIRM_TOOL",
    "V4_TEMPLATE_EXECUTION_ENV",
    "V4_TEMPLATE_PREVIEW_TOOL",
    "V4_TEMPLATE_UPDATE_ACTION_TOOL",
    "V4_TEMPLATE_UPDATE_CONFIRM_TOOL",
    "V4_TEMPLATE_UPDATE_EXECUTION_ENV",
    "V4_TEMPLATE_UPDATE_CLAIM_ENV",
    "V4_TEMPLATE_UPDATE_PREVIEW_TOOL",
    "V4TemplateActionConfigurationError",
    "V4TemplateActionRuntimeError",
    "build_v4_template_action",
    "load_v4_template_action_feature",
    "load_v4_template_execution_feature",
    "load_v4_template_update_execution_feature",
    "template_action_principal_from_access_token",
]
