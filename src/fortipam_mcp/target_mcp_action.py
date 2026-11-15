"""MCP boundary for one controlled API-first FortiPAM Target creation workflow."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import os
import hashlib
from pathlib import Path
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token
from .target_namespace_ssh_reader import TargetNamespaceObservation


V4_TARGET_ACTION_FEATURE_ENV = "FORTIPAM_MCP_V4_TARGET_ACTION_ENABLED"
V4_TARGET_EXECUTION_ENV = "FORTIPAM_MCP_V4_TARGET_EXECUTION_ENABLED"
V4_TARGET_DELETE_ACTION_FEATURE_ENV = (
    "FORTIPAM_MCP_V4_TARGET_DELETE_ACTION_ENABLED"
)
V4_TARGET_DELETE_EXECUTION_ENV = "FORTIPAM_MCP_V4_TARGET_DELETE_EXECUTION_ENABLED"
V4_TARGET_DELETE_SELECTOR_PREFIX = "FPA_HOME_LAB_FPA1_V4_TARGET_DELETE_"
V4_TARGET_DELETE_TARGET_ENV = f"{V4_TARGET_DELETE_SELECTOR_PREFIX}TARGET_NAME"
V4_TARGET_DELETE_TAG_ENV = (
    f"{V4_TARGET_DELETE_SELECTOR_PREFIX}CLASSIFICATION_TAG_NAME"
)
V4_TARGET_DELETE_ACCEPTED_DIGEST_ENV = (
    f"{V4_TARGET_DELETE_SELECTOR_PREFIX}ACCEPTED_DIGEST"
)
V4_TARGET_DELETE_CLAIM_FILE_ENV = f"{V4_TARGET_DELETE_SELECTOR_PREFIX}CLAIM_FILE"
V4_TARGET_PREVIEW_TOOL = "preview_v4_ssh_target_create"
V4_WEB_TARGET_PREVIEW_TOOL = "preview_v4_bound_web_target_create"
V4_WEB_TARGET_CONFIRM_TOOL = "confirm_v4_bound_web_target_create"
V4_WEB_TARGET_ACTION_TOOL = "execute_confirmed_v4_bound_web_target_create"
V4_TARGET_CONFIRM_TOOL = "confirm_v4_ssh_target_create"
V4_TARGET_ACTION_TOOL = "execute_confirmed_v4_ssh_target"
V4_TARGET_DELETE_PREVIEW_TOOL = "preview_v4_ssh_target_delete"
V4_TARGET_DELETE_CONFIRM_TOOL = "confirm_v4_ssh_target_delete"
V4_TARGET_DELETE_ACTION_TOOL = "execute_confirmed_v4_ssh_target_delete"
V4_TARGET_ACTION_UNAVAILABLE = "FortiPAM V4 Target action is unavailable."


class V4TargetActionConfigurationError(ValueError):
    """Raised when the target-action host is incomplete or unsafe."""


class V4TargetActionRuntimeError(RuntimeError):
    """Stable, non-disclosing target-action failure."""


def load_v4_target_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Target action opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_TARGET_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4TargetActionConfigurationError(
        f"{V4_TARGET_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_target_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_TARGET_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4TargetActionConfigurationError(
        f"{V4_TARGET_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_target_delete_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent fixed-delete host opt-in, defaulting disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_TARGET_DELETE_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4TargetActionConfigurationError(
        f"{V4_TARGET_DELETE_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_target_delete_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent destructive Target dispatch gate."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_TARGET_DELETE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4TargetActionConfigurationError(
        f"{V4_TARGET_DELETE_EXECUTION_ENV} must be exactly true or false."
    )


def target_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as Folder writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4TargetActionRuntimeError(V4_TARGET_ACTION_UNAVAILABLE) from exc


class ProtectedTargetMcpAction:
    """Expose bounded create plus fixed accepted-Target recovery C/P/E."""

    def __init__(
        self,
        workflow: Any,
        *,
        execution_enabled: bool = True,
        delete_workflow: Any | None = None,
        delete_execution_enabled: bool = False,
        web_workflow: Any | None = None,
    ) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled
        self._delete_workflow = delete_workflow
        self._delete_execution_enabled = delete_execution_enabled
        self._web_workflow = web_workflow

    @property
    def web_create_enabled(self) -> bool:
        return self._web_workflow is not None

    def _web_requester(self, principal: Any) -> str:
        from .v4_plan_runtime import V4PlanningPrincipal

        if type(principal) is not V4PlanningPrincipal or self._web_workflow is None:
            raise V4TargetActionRuntimeError(V4_TARGET_ACTION_UNAVAILABLE)
        principal.__post_init__()
        return hashlib.sha256(("bp007-web-target-requester/v1\0" + principal.requester.digest
                               + "\0" + principal.transport_namespace_digest).encode()).hexdigest()

    def preview_web(self, principal: Any) -> dict[str, object]:
        try:
            requester = self._web_requester(principal)
            assert self._web_workflow is not None
            return cast(dict[str, object], self._web_workflow.preview(requester_digest=requester))
        except Exception:
            raise V4TargetActionRuntimeError(V4_TARGET_ACTION_UNAVAILABLE) from None

    def confirm_web(self, preview_ref: str, principal: Any) -> dict[str, object]:
        try:
            requester = self._web_requester(principal)
            assert self._web_workflow is not None
            return cast(dict[str, object], self._web_workflow.confirm(preview_ref, requester_digest=requester))
        except Exception:
            raise V4TargetActionRuntimeError(V4_TARGET_ACTION_UNAVAILABLE) from None

    def execute_web(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        try:
            requester = self._web_requester(principal)
            assert self._web_workflow is not None
            return cast(dict[str, object], self._web_workflow.execute(authorization_ref, requester_digest=requester))
        except Exception:
            raise V4TargetActionRuntimeError(V4_TARGET_ACTION_UNAVAILABLE) from None

    def preview(
        self,
        target_name: str,
        address: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    target_name=target_name,
                    address=address,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4TargetActionRuntimeError(V4_TARGET_ACTION_UNAVAILABLE) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4TargetActionRuntimeError(V4_TARGET_ACTION_UNAVAILABLE) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4TargetActionRuntimeError(V4_TARGET_ACTION_UNAVAILABLE)
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
            raise V4TargetActionRuntimeError(V4_TARGET_ACTION_UNAVAILABLE) from exc

    def preview_delete(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._delete_workflow is None:
            raise V4TargetActionRuntimeError(V4_TARGET_ACTION_UNAVAILABLE)
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.preview(requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4TargetActionRuntimeError(V4_TARGET_ACTION_UNAVAILABLE) from exc

    def confirm_delete(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._delete_workflow is None:
            raise V4TargetActionRuntimeError(V4_TARGET_ACTION_UNAVAILABLE)
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.confirm(
                    preview_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4TargetActionRuntimeError(V4_TARGET_ACTION_UNAVAILABLE) from exc

    def execute_delete(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._delete_execution_enabled or self._delete_workflow is None:
            raise V4TargetActionRuntimeError(V4_TARGET_ACTION_UNAVAILABLE)
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.execute(
                    authorization_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4TargetActionRuntimeError(V4_TARGET_ACTION_UNAVAILABLE) from exc


# Compatibility alias for the pre-API-first Beta ToolPack class name.  The
# current builder uses the REST transport above, not this legacy SSH label.
ProtectedSshTargetMcpAction = ProtectedTargetMcpAction


def build_v4_target_action(
    environment: Mapping[str, str] | None = None,
    *, web_target_namespace_observer: Callable[[str], TargetNamespaceObservation] | None = None,
) -> ProtectedTargetMcpAction:
    """Construct the independent Target action host from dedicated API settings."""

    env = os.environ if environment is None else environment
    try:
        from .target_delete_http_transport import FortiPamTargetDeleteHttpTransport
        from .target_delete_live_workflow import TargetDeleteLiveWorkflow
        from .target_live_workflow import TargetLiveWorkflow
        from .target_http_transport import (
            FortiPamTargetHttpTransport,
            load_target_http_transport_config,
        )
        from .target_reference_ssh_transport import FortiPamTargetReferenceSshTransport
        from .target_ssh_transport import (
            FortiPamTargetSshTransport,
            load_target_ssh_transport_config,
        )

        config = load_target_http_transport_config(env)
        target_transport = FortiPamTargetHttpTransport(
            config, web_target_namespace_observer=web_target_namespace_observer,
        )
        workflow = TargetLiveWorkflow(target_transport)
        from .web_target_live_workflow import build_web_target_workflow
        web_workflow = build_web_target_workflow(env, target_transport)
        delete_workflow = None
        if load_v4_target_delete_action_feature(env):
            ssh_config = load_target_ssh_transport_config(env)
            target_name = env.get(V4_TARGET_DELETE_TARGET_ENV, "").strip()
            accepted_digest = env.get(V4_TARGET_DELETE_ACCEPTED_DIGEST_ENV, "").strip()
            auth_mode = env.get(V4_TARGET_DELETE_SELECTOR_PREFIX + "AUTH_MODE", "api-bearer")
            session_dispatcher = None
            if auth_mode == "owner-session":
                from .target_delete_owner_session import build_target_delete_owner_session
                session_dispatcher = build_target_delete_owner_session(
                    config, env, target_name=target_name, accepted_digest=accepted_digest,
                )
            elif auth_mode != "api-bearer":
                raise ValueError
            delete_workflow = TargetDeleteLiveWorkflow(
                FortiPamTargetDeleteHttpTransport(
                    config,
                    target_transport,
                    FortiPamTargetSshTransport(ssh_config),
                    FortiPamTargetReferenceSshTransport(ssh_config),
                    target_name=target_name,
                    classification_tag_name=env.get(
                        V4_TARGET_DELETE_TAG_ENV,
                        "",
                    ).strip(),
                    accepted_digest=accepted_digest,
                    claim_path=Path(env.get(V4_TARGET_DELETE_CLAIM_FILE_ENV, "")),
                    session_dispatcher=session_dispatcher,
                )
            )
    except Exception as exc:
        raise V4TargetActionConfigurationError(V4_TARGET_ACTION_UNAVAILABLE) from exc
    return ProtectedTargetMcpAction(
        workflow,
        execution_enabled=load_v4_target_execution_feature(env),
        delete_workflow=delete_workflow,
        delete_execution_enabled=load_v4_target_delete_execution_feature(env),
        web_workflow=web_workflow,
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4TargetActionRuntimeError(V4_TARGET_ACTION_UNAVAILABLE) from exc


__all__ = [
    "ProtectedTargetMcpAction",
    "ProtectedSshTargetMcpAction",
    "V4_TARGET_ACTION_FEATURE_ENV",
    "V4_TARGET_ACTION_TOOL",
    "V4_TARGET_ACTION_UNAVAILABLE",
    "V4_TARGET_CONFIRM_TOOL",
    "V4_TARGET_DELETE_ACCEPTED_DIGEST_ENV",
    "V4_TARGET_DELETE_CLAIM_FILE_ENV",
    "V4_TARGET_DELETE_ACTION_FEATURE_ENV",
    "V4_TARGET_DELETE_ACTION_TOOL",
    "V4_TARGET_DELETE_CONFIRM_TOOL",
    "V4_TARGET_DELETE_EXECUTION_ENV",
    "V4_TARGET_DELETE_PREVIEW_TOOL",
    "V4_TARGET_DELETE_SELECTOR_PREFIX",
    "V4_TARGET_DELETE_TAG_ENV",
    "V4_TARGET_DELETE_TARGET_ENV",
    "V4_TARGET_EXECUTION_ENV",
    "V4_TARGET_PREVIEW_TOOL",
    "V4TargetActionConfigurationError",
    "V4TargetActionRuntimeError",
    "build_v4_target_action",
    "load_v4_target_action_feature",
    "load_v4_target_delete_action_feature",
    "load_v4_target_delete_execution_feature",
    "load_v4_target_execution_feature",
    "target_action_principal_from_access_token",
]
