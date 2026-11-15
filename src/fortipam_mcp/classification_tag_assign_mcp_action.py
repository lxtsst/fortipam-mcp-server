"""Feature-gated MCP boundary for one Target Classification Tag assignment."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_CLASSIFICATION_TAG_ASSIGN_ACTION_FEATURE_ENV = (
    "FORTIPAM_MCP_V4_CLASSIFICATION_TAG_ASSIGN_ACTION_ENABLED"
)
V4_CLASSIFICATION_TAG_ASSIGN_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_CLASSIFICATION_TAG_ASSIGN_EXECUTION_ENABLED"
)
V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_EXECUTION_ENABLED"
)
V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_SELECTOR_PREFIX = (
    "FPA_HOME_LAB_FPA1_V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_"
)
V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_TARGET_ENV = (
    f"{V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_SELECTOR_PREFIX}TARGET_NAME"
)
V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_TAG_ENV = (
    f"{V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_SELECTOR_PREFIX}TAG_NAME"
)
V4_CLASSIFICATION_TAG_ASSIGN_PREVIEW_TOOL = (
    "preview_v4_classification_tag_assign"
)
V4_CLASSIFICATION_TAG_ASSIGN_CONFIRM_TOOL = (
    "confirm_v4_classification_tag_assign"
)
V4_CLASSIFICATION_TAG_ASSIGN_ACTION_TOOL = (
    "execute_confirmed_v4_classification_tag_assign"
)
V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_PREVIEW_TOOL = (
    "preview_v4_classification_tag_assign_rollback"
)
V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_CONFIRM_TOOL = (
    "confirm_v4_classification_tag_assign_rollback"
)
V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_ACTION_TOOL = (
    "execute_confirmed_v4_classification_tag_assign_rollback"
)
V4_CLASSIFICATION_TAG_ASSIGN_ACTION_UNAVAILABLE = (
    "FortiPAM V4 Classification Tag assignment is unavailable."
)


class V4ClassificationTagAssignActionConfigurationError(ValueError):
    """Raised when the assignment action host is incomplete or unsafe."""


class V4ClassificationTagAssignActionRuntimeError(RuntimeError):
    """Stable non-disclosing assignment action failure."""


def load_v4_classification_tag_assign_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent assignment opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_CLASSIFICATION_TAG_ASSIGN_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ClassificationTagAssignActionConfigurationError(
        f"{V4_CLASSIFICATION_TAG_ASSIGN_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_classification_tag_assign_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_CLASSIFICATION_TAG_ASSIGN_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ClassificationTagAssignActionConfigurationError(
        f"{V4_CLASSIFICATION_TAG_ASSIGN_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_classification_tag_assign_rollback_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent rollback final-dispatch gate, defaulting denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ClassificationTagAssignActionConfigurationError(
        f"{V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_EXECUTION_ENV} must be exactly true or false."
    )


def classification_tag_assign_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require explicit planning and operation scopes for assignment."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4ClassificationTagAssignActionRuntimeError(
            V4_CLASSIFICATION_TAG_ASSIGN_ACTION_UNAVAILABLE
        ) from exc


class ProtectedClassificationTagAssignMcpAction:
    """Bind an authenticated requester to the exact assignment workflow."""

    def __init__(
        self,
        workflow: Any,
        *,
        rollback_workflow: Any | None = None,
        execution_enabled: bool = True,
        rollback_execution_enabled: bool = True,
    ) -> None:
        self._workflow = workflow
        self._rollback_workflow = rollback_workflow
        self._execution_enabled = execution_enabled
        self._rollback_execution_enabled = rollback_execution_enabled

    def preview(
        self,
        target_name: str,
        classification_tag_name: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    target_name=target_name,
                    classification_tag_name=classification_tag_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ClassificationTagAssignActionRuntimeError(
                V4_CLASSIFICATION_TAG_ASSIGN_ACTION_UNAVAILABLE
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
            raise V4ClassificationTagAssignActionRuntimeError(
                V4_CLASSIFICATION_TAG_ASSIGN_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4ClassificationTagAssignActionRuntimeError(
                V4_CLASSIFICATION_TAG_ASSIGN_ACTION_UNAVAILABLE
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
            raise V4ClassificationTagAssignActionRuntimeError(
                V4_CLASSIFICATION_TAG_ASSIGN_ACTION_UNAVAILABLE
            ) from exc

    def preview_rollback(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            if self._rollback_workflow is None:
                raise RuntimeError("rollback workflow unavailable")
            return cast(
                dict[str, object],
                self._rollback_workflow.preview(requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4ClassificationTagAssignActionRuntimeError(
                V4_CLASSIFICATION_TAG_ASSIGN_ACTION_UNAVAILABLE
            ) from exc

    def confirm_rollback(
        self,
        preview_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            if self._rollback_workflow is None:
                raise RuntimeError("rollback workflow unavailable")
            return cast(
                dict[str, object],
                self._rollback_workflow.confirm(
                    preview_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ClassificationTagAssignActionRuntimeError(
                V4_CLASSIFICATION_TAG_ASSIGN_ACTION_UNAVAILABLE
            ) from exc

    def execute_rollback(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._rollback_execution_enabled:
            raise V4ClassificationTagAssignActionRuntimeError(
                V4_CLASSIFICATION_TAG_ASSIGN_ACTION_UNAVAILABLE
            )
        requester_digest = _requester_digest(principal)
        try:
            if self._rollback_workflow is None:
                raise RuntimeError("rollback workflow unavailable")
            return cast(
                dict[str, object],
                self._rollback_workflow.execute(
                    authorization_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4ClassificationTagAssignActionRuntimeError(
                V4_CLASSIFICATION_TAG_ASSIGN_ACTION_UNAVAILABLE
            ) from exc


def build_v4_classification_tag_assign_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedClassificationTagAssignMcpAction:
    """Build the assignment host from the existing Target API route."""

    env = os.environ if environment is None else environment
    try:
        from .classification_tag_assign_live_workflow import (
            ClassificationTagAssignLiveWorkflow,
            ClassificationTagAssignRollbackLiveWorkflow,
        )
        from .target_http_transport import (
            FortiPamTargetHttpTransport,
            load_target_http_transport_config,
        )

        transport = FortiPamTargetHttpTransport(load_target_http_transport_config(env))
        workflow = ClassificationTagAssignLiveWorkflow(transport)
        rollback_workflow = ClassificationTagAssignRollbackLiveWorkflow(
            transport,
            target_name=env.get(
                V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_TARGET_ENV,
                "",
            ).strip(),
            classification_tag_name=env.get(
                V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_TAG_ENV,
                "",
            ).strip(),
        )
    except Exception as exc:
        raise V4ClassificationTagAssignActionConfigurationError(
            V4_CLASSIFICATION_TAG_ASSIGN_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedClassificationTagAssignMcpAction(
        workflow,
        rollback_workflow=rollback_workflow,
        execution_enabled=load_v4_classification_tag_assign_execution_feature(env),
        rollback_execution_enabled=(
            load_v4_classification_tag_assign_rollback_execution_feature(env)
        ),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4ClassificationTagAssignActionRuntimeError(
            V4_CLASSIFICATION_TAG_ASSIGN_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedClassificationTagAssignMcpAction",
    "V4_CLASSIFICATION_TAG_ASSIGN_ACTION_FEATURE_ENV",
    "V4_CLASSIFICATION_TAG_ASSIGN_ACTION_TOOL",
    "V4_CLASSIFICATION_TAG_ASSIGN_ACTION_UNAVAILABLE",
    "V4_CLASSIFICATION_TAG_ASSIGN_CONFIRM_TOOL",
    "V4_CLASSIFICATION_TAG_ASSIGN_EXECUTION_ENV",
    "V4_CLASSIFICATION_TAG_ASSIGN_PREVIEW_TOOL",
    "V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_ACTION_TOOL",
    "V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_CONFIRM_TOOL",
    "V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_EXECUTION_ENV",
    "V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_PREVIEW_TOOL",
    "V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_SELECTOR_PREFIX",
    "V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_TAG_ENV",
    "V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_TARGET_ENV",
    "V4ClassificationTagAssignActionConfigurationError",
    "V4ClassificationTagAssignActionRuntimeError",
    "build_v4_classification_tag_assign_action",
    "classification_tag_assign_action_principal_from_access_token",
    "load_v4_classification_tag_assign_action_feature",
    "load_v4_classification_tag_assign_execution_feature",
    "load_v4_classification_tag_assign_rollback_execution_feature",
]
