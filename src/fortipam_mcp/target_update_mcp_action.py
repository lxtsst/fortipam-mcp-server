"""MCP boundary for two fixed API-first FortiPAM Target update profiles."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_TARGET_UPDATE_ACTION_FEATURE_ENV = "FORTIPAM_MCP_V4_TARGET_UPDATE_ACTION_ENABLED"
V4_TARGET_UPDATE_DESCRIPTION_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_TARGET_UPDATE_DESCRIPTION_EXECUTION_ENABLED"
)
V4_TARGET_WEB_PROXY_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_TARGET_WEB_PROXY_EXECUTION_ENABLED"
)
V4_TARGET_UPDATE_PREVIEW_TOOL = "preview_v4_target_update_description"
V4_TARGET_UPDATE_CONFIRM_TOOL = "confirm_v4_target_update_description"
V4_TARGET_UPDATE_ACTION_TOOL = "execute_confirmed_v4_target_update_description"
V4_TARGET_UPDATE_ACTION_UNAVAILABLE = "FortiPAM V4 Target update action is unavailable."
TARGET_UPDATE_PROFILE_DESCRIPTION = "description"
TARGET_UPDATE_PROFILE_WEB_PROXY_ENABLE = "web_proxy_enable"
_DESCRIPTION_PREVIEW_REF_PREFIX = "target-update-preview-"
_DESCRIPTION_AUTHORIZATION_REF_PREFIX = "target-update-authorized-"
_WEB_PROXY_PREVIEW_REF_PREFIX = "target-web-proxy-enable-preview-"
_WEB_PROXY_AUTHORIZATION_REF_PREFIX = "target-web-proxy-enable-authorized-"


class V4TargetUpdateActionConfigurationError(ValueError):
    """Raised when the Target update action host is incomplete or unsafe."""


class V4TargetUpdateActionRuntimeError(RuntimeError):
    """Stable, non-disclosing Target update action failure."""


def load_v4_target_update_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Target update action opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_TARGET_UPDATE_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4TargetUpdateActionConfigurationError(
        f"{V4_TARGET_UPDATE_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_target_update_description_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the Target description final-dispatch gate, defaulting denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_TARGET_UPDATE_DESCRIPTION_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4TargetUpdateActionConfigurationError(
        f"{V4_TARGET_UPDATE_DESCRIPTION_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_target_web_proxy_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the Target Web Proxy final-dispatch gate, defaulting denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_TARGET_WEB_PROXY_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4TargetUpdateActionConfigurationError(
        f"{V4_TARGET_WEB_PROXY_EXECUTION_ENV} must be exactly true or false."
    )


def target_update_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as Target create."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4TargetUpdateActionRuntimeError(
            V4_TARGET_UPDATE_ACTION_UNAVAILABLE
        ) from exc


class ProtectedTargetUpdateMcpAction:
    """Expose two fixed Target update profiles through one existing tool set."""

    def __init__(
        self,
        workflow: Any,
        *,
        web_proxy_workflow: Any | None = None,
        description_execution_enabled: bool = True,
        web_proxy_execution_enabled: bool = True,
    ) -> None:
        self._workflow = workflow
        self._web_proxy_workflow = web_proxy_workflow
        self._description_execution_enabled = description_execution_enabled
        self._web_proxy_execution_enabled = web_proxy_execution_enabled

    def preview(
        self,
        target_name: str,
        description: str | None,
        principal: Any,
        configuration_profile: str = TARGET_UPDATE_PROFILE_DESCRIPTION,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            if configuration_profile == TARGET_UPDATE_PROFILE_DESCRIPTION:
                if not isinstance(description, str):
                    raise TypeError("description profile requires a description")
                return cast(
                    dict[str, object],
                    self._workflow.preview(
                        target_name=target_name,
                        description=description,
                        requester_digest=requester_digest,
                    ),
                )
            if configuration_profile == TARGET_UPDATE_PROFILE_WEB_PROXY_ENABLE:
                if description is not None:
                    raise TypeError("Web Proxy profile accepts no description")
                return cast(
                    dict[str, object],
                    self._require_web_proxy_workflow().preview(
                        target_name=target_name,
                        requester_digest=requester_digest,
                    ),
                )
            raise TypeError("unsupported Target update profile")
        except Exception as exc:
            raise V4TargetUpdateActionRuntimeError(
                V4_TARGET_UPDATE_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow_for_preview(preview_ref).confirm(
                    preview_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4TargetUpdateActionRuntimeError(
                V4_TARGET_UPDATE_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        workflow = self._workflow_for_authorization(authorization_ref)
        if not self._execution_enabled_for_authorization(authorization_ref):
            raise V4TargetUpdateActionRuntimeError(
                V4_TARGET_UPDATE_ACTION_UNAVAILABLE
            )
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                workflow.execute(
                    authorization_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4TargetUpdateActionRuntimeError(
                V4_TARGET_UPDATE_ACTION_UNAVAILABLE
            ) from exc

    def _require_web_proxy_workflow(self) -> Any:
        if self._web_proxy_workflow is None:
            raise V4TargetUpdateActionRuntimeError(
                V4_TARGET_UPDATE_ACTION_UNAVAILABLE
            )
        return self._web_proxy_workflow

    def _workflow_for_preview(self, preview_ref: str) -> Any:
        if isinstance(preview_ref, str) and preview_ref.startswith(
            _DESCRIPTION_PREVIEW_REF_PREFIX
        ):
            return self._workflow
        if isinstance(preview_ref, str) and preview_ref.startswith(_WEB_PROXY_PREVIEW_REF_PREFIX):
            return self._require_web_proxy_workflow()
        raise V4TargetUpdateActionRuntimeError(V4_TARGET_UPDATE_ACTION_UNAVAILABLE)

    def _workflow_for_authorization(self, authorization_ref: str) -> Any:
        if isinstance(authorization_ref, str) and authorization_ref.startswith(
            _DESCRIPTION_AUTHORIZATION_REF_PREFIX
        ):
            return self._workflow
        if isinstance(authorization_ref, str) and authorization_ref.startswith(
            _WEB_PROXY_AUTHORIZATION_REF_PREFIX
        ):
            return self._require_web_proxy_workflow()
        raise V4TargetUpdateActionRuntimeError(V4_TARGET_UPDATE_ACTION_UNAVAILABLE)

    def _execution_enabled_for_authorization(self, authorization_ref: str) -> bool:
        if isinstance(authorization_ref, str) and authorization_ref.startswith(
            _DESCRIPTION_AUTHORIZATION_REF_PREFIX
        ):
            return self._description_execution_enabled
        if isinstance(authorization_ref, str) and authorization_ref.startswith(
            _WEB_PROXY_AUTHORIZATION_REF_PREFIX
        ):
            return self._web_proxy_execution_enabled
        raise V4TargetUpdateActionRuntimeError(V4_TARGET_UPDATE_ACTION_UNAVAILABLE)


def build_v4_target_update_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedTargetUpdateMcpAction:
    """Construct the independent Target update host from API settings."""

    env = os.environ if environment is None else environment
    try:
        from .target_http_transport import (
            FortiPamTargetHttpTransport,
            load_target_http_transport_config,
        )
        from .target_update_live_workflow import TargetDescriptionUpdateLiveWorkflow
        from .target_web_proxy_enable_live_workflow import TargetWebProxyEnableLiveWorkflow

        transport = FortiPamTargetHttpTransport(load_target_http_transport_config(env))
        workflow = TargetDescriptionUpdateLiveWorkflow(transport)
        web_proxy_workflow = TargetWebProxyEnableLiveWorkflow(transport)
    except Exception as exc:
        raise V4TargetUpdateActionConfigurationError(
            V4_TARGET_UPDATE_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedTargetUpdateMcpAction(
        workflow,
        web_proxy_workflow=web_proxy_workflow,
        description_execution_enabled=(
            load_v4_target_update_description_execution_feature(env)
        ),
        web_proxy_execution_enabled=load_v4_target_web_proxy_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4TargetUpdateActionRuntimeError(
            V4_TARGET_UPDATE_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedTargetUpdateMcpAction",
    "TARGET_UPDATE_PROFILE_DESCRIPTION",
    "TARGET_UPDATE_PROFILE_WEB_PROXY_ENABLE",
    "V4_TARGET_UPDATE_ACTION_FEATURE_ENV",
    "V4_TARGET_UPDATE_ACTION_TOOL",
    "V4_TARGET_UPDATE_ACTION_UNAVAILABLE",
    "V4_TARGET_UPDATE_CONFIRM_TOOL",
    "V4_TARGET_UPDATE_DESCRIPTION_EXECUTION_ENV",
    "V4_TARGET_UPDATE_PREVIEW_TOOL",
    "V4_TARGET_WEB_PROXY_EXECUTION_ENV",
    "V4TargetUpdateActionConfigurationError",
    "V4TargetUpdateActionRuntimeError",
    "build_v4_target_update_action",
    "load_v4_target_update_action_feature",
    "load_v4_target_update_description_execution_feature",
    "load_v4_target_web_proxy_execution_feature",
    "target_update_action_principal_from_access_token",
]
