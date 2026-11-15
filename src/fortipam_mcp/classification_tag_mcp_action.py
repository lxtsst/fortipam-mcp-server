"""MCP boundary for one controlled API-first Classification Tag create action."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_acl_mcp_action import folder_acl_action_principal_from_access_token


V4_CLASSIFICATION_TAG_ACTION_FEATURE_ENV = (
    "FORTIPAM_MCP_V4_CLASSIFICATION_TAG_ACTION_ENABLED"
)
V4_CLASSIFICATION_TAG_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_CLASSIFICATION_TAG_EXECUTION_ENABLED"
)
V4_CLASSIFICATION_TAG_DELETE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_CLASSIFICATION_TAG_DELETE_EXECUTION_ENABLED"
)
V4_CLASSIFICATION_TAG_DELETE_ACTION_FEATURE_ENV = (
    "FORTIPAM_MCP_V4_CLASSIFICATION_TAG_DELETE_ACTION_ENABLED"
)
V4_CLASSIFICATION_TAG_DELETE_SELECTOR_PREFIX = (
    "FPA_HOME_LAB_FPA1_V4_CLASSIFICATION_TAG_DELETE_"
)
V4_CLASSIFICATION_TAG_DELETE_TAG_ENV = (
    f"{V4_CLASSIFICATION_TAG_DELETE_SELECTOR_PREFIX}TAG_NAME"
)
V4_CLASSIFICATION_TAG_DELETE_TARGET_ENV = (
    f"{V4_CLASSIFICATION_TAG_DELETE_SELECTOR_PREFIX}TARGET_NAME"
)
V4_CLASSIFICATION_TAG_DELETE_ACCEPTED_DIGEST_ENV = (
    f"{V4_CLASSIFICATION_TAG_DELETE_SELECTOR_PREFIX}ACCEPTED_DIGEST"
)
V4_CLASSIFICATION_TAG_PREVIEW_TOOL = "preview_v4_classification_tag_create"
V4_CLASSIFICATION_TAG_CONFIRM_TOOL = "confirm_v4_classification_tag_create"
V4_CLASSIFICATION_TAG_ACTION_TOOL = "execute_confirmed_v4_classification_tag_create"
V4_CLASSIFICATION_TAG_DELETE_PREVIEW_TOOL = "preview_v4_classification_tag_delete"
V4_CLASSIFICATION_TAG_DELETE_CONFIRM_TOOL = "confirm_v4_classification_tag_delete"
V4_CLASSIFICATION_TAG_DELETE_ACTION_TOOL = (
    "execute_confirmed_v4_classification_tag_delete"
)
V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE = (
    "FortiPAM V4 Classification Tag action is unavailable."
)


class V4ClassificationTagActionConfigurationError(ValueError):
    """Raised when the Classification Tag action host is incomplete or unsafe."""


class V4ClassificationTagActionRuntimeError(RuntimeError):
    """Stable non-disclosing Classification Tag action failure."""


def load_v4_classification_tag_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Classification Tag opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_CLASSIFICATION_TAG_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ClassificationTagActionConfigurationError(
        f"{V4_CLASSIFICATION_TAG_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_classification_tag_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_CLASSIFICATION_TAG_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ClassificationTagActionConfigurationError(
        f"{V4_CLASSIFICATION_TAG_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_classification_tag_delete_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent destructive recovery dispatch gate."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_CLASSIFICATION_TAG_DELETE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ClassificationTagActionConfigurationError(
        f"{V4_CLASSIFICATION_TAG_DELETE_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_classification_tag_delete_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent fixed-delete host opt-in, defaulting disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_CLASSIFICATION_TAG_DELETE_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ClassificationTagActionConfigurationError(
        f"{V4_CLASSIFICATION_TAG_DELETE_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def classification_tag_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning/operation scope as Folder ACL actions."""

    try:
        return folder_acl_action_principal_from_access_token(
            access_token,
            planning_settings,
        )
    except Exception as exc:
        raise V4ClassificationTagActionRuntimeError(
            V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE
        ) from exc


class ProtectedClassificationTagMcpAction:
    """Expose bounded create plus fixed accepted-Tag recovery C/P/E."""

    def __init__(
        self,
        workflow: Any,
        *,
        execution_enabled: bool = True,
        delete_workflow: Any | None = None,
        delete_execution_enabled: bool = False,
    ) -> None:
        self._workflow = workflow
        self._execution_enabled = execution_enabled
        self._delete_workflow = delete_workflow
        self._delete_execution_enabled = delete_execution_enabled

    def preview(
        self,
        name: str,
        description: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    name=name,
                    description=description,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ClassificationTagActionRuntimeError(
                V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4ClassificationTagActionRuntimeError(
                V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4ClassificationTagActionRuntimeError(
                V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE
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
            raise V4ClassificationTagActionRuntimeError(
                V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE
            ) from exc

    def preview_delete(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._delete_workflow is None:
            raise V4ClassificationTagActionRuntimeError(
                V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE
            )
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.preview(requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4ClassificationTagActionRuntimeError(
                V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE
            ) from exc

    def confirm_delete(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        if self._delete_workflow is None:
            raise V4ClassificationTagActionRuntimeError(
                V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE
            )
        try:
            return cast(
                dict[str, object],
                self._delete_workflow.confirm(
                    preview_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ClassificationTagActionRuntimeError(
                V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE
            ) from exc

    def execute_delete(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._delete_execution_enabled or self._delete_workflow is None:
            raise V4ClassificationTagActionRuntimeError(
                V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE
            )
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
            raise V4ClassificationTagActionRuntimeError(
                V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE
            ) from exc


def build_v4_classification_tag_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedClassificationTagMcpAction:
    """Construct the Tag host from the existing dedicated lab Folder ACL transport."""

    env = os.environ if environment is None else environment
    try:
        from .classification_tag_delete_http_transport import (
            FortiPamClassificationTagDeleteHttpTransport,
        )
        from .classification_tag_delete_live_workflow import (
            ClassificationTagDeleteLiveWorkflow,
        )
        from .classification_tag_http_transport import (
            FortiPamClassificationTagHttpTransport,
        )
        from .classification_tag_live_workflow import (
            ClassificationTagCreateLiveWorkflow,
        )
        from .classification_tag_reference_ssh_transport import (
            FortiPamClassificationTagReferenceSshTransport,
        )
        from .folder_http_transport import load_folder_acl_transport_config
        from .target_http_transport import (
            FortiPamTargetHttpTransport,
            load_target_http_transport_config,
        )
        from .target_ssh_transport import load_target_ssh_transport_config

        tag_config = load_folder_acl_transport_config(env)
        workflow = ClassificationTagCreateLiveWorkflow(
            FortiPamClassificationTagHttpTransport(
                tag_config
            )
        )
        delete_workflow = None
        if load_v4_classification_tag_delete_action_feature(env):
            delete_workflow = ClassificationTagDeleteLiveWorkflow(
                FortiPamClassificationTagDeleteHttpTransport(
                    tag_config,
                    FortiPamTargetHttpTransport(
                        load_target_http_transport_config(env)
                    ),
                    FortiPamClassificationTagReferenceSshTransport(
                        load_target_ssh_transport_config(env)
                    ),
                    tag_name=env.get(
                        V4_CLASSIFICATION_TAG_DELETE_TAG_ENV,
                        "",
                    ).strip(),
                    target_name=env.get(
                        V4_CLASSIFICATION_TAG_DELETE_TARGET_ENV,
                        "",
                    ).strip(),
                    accepted_digest=env.get(
                        V4_CLASSIFICATION_TAG_DELETE_ACCEPTED_DIGEST_ENV,
                        "",
                    ).strip(),
                )
            )
    except Exception as exc:
        raise V4ClassificationTagActionConfigurationError(
            V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedClassificationTagMcpAction(
        workflow,
        execution_enabled=load_v4_classification_tag_execution_feature(env),
        delete_workflow=delete_workflow,
        delete_execution_enabled=(
            load_v4_classification_tag_delete_execution_feature(env)
        ),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4ClassificationTagActionRuntimeError(
            V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedClassificationTagMcpAction",
    "V4_CLASSIFICATION_TAG_ACTION_FEATURE_ENV",
    "V4_CLASSIFICATION_TAG_ACTION_TOOL",
    "V4_CLASSIFICATION_TAG_ACTION_UNAVAILABLE",
    "V4_CLASSIFICATION_TAG_CONFIRM_TOOL",
    "V4_CLASSIFICATION_TAG_DELETE_ACCEPTED_DIGEST_ENV",
    "V4_CLASSIFICATION_TAG_DELETE_ACTION_FEATURE_ENV",
    "V4_CLASSIFICATION_TAG_DELETE_ACTION_TOOL",
    "V4_CLASSIFICATION_TAG_DELETE_CONFIRM_TOOL",
    "V4_CLASSIFICATION_TAG_DELETE_EXECUTION_ENV",
    "V4_CLASSIFICATION_TAG_DELETE_PREVIEW_TOOL",
    "V4_CLASSIFICATION_TAG_DELETE_SELECTOR_PREFIX",
    "V4_CLASSIFICATION_TAG_DELETE_TAG_ENV",
    "V4_CLASSIFICATION_TAG_DELETE_TARGET_ENV",
    "V4_CLASSIFICATION_TAG_EXECUTION_ENV",
    "V4_CLASSIFICATION_TAG_PREVIEW_TOOL",
    "V4ClassificationTagActionConfigurationError",
    "V4ClassificationTagActionRuntimeError",
    "build_v4_classification_tag_action",
    "classification_tag_action_principal_from_access_token",
    "load_v4_classification_tag_action_feature",
    "load_v4_classification_tag_delete_action_feature",
    "load_v4_classification_tag_delete_execution_feature",
    "load_v4_classification_tag_execution_feature",
]
