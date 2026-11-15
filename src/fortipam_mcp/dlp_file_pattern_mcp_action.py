"""MCP boundary for one controlled FortiPAM DLP file-pattern create workflow."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_DLP_FILE_PATTERN_ACTION_PREFIX = "FORTIPAM_MCP_V4_DLP_FILE_PATTERN_ACTION_"
V4_DLP_FILE_PATTERN_ACTION_FEATURE_ENV = f"{V4_DLP_FILE_PATTERN_ACTION_PREFIX}ENABLED"
V4_DLP_FILE_PATTERN_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_DLP_FILE_PATTERN_EXECUTION_ENABLED"
)
V4_DLP_FILE_PATTERN_DELETE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_DLP_FILE_PATTERN_DELETE_EXECUTION_ENABLED"
)
V4_DLP_FILE_PATTERN_PREVIEW_TOOL = "preview_v4_dlp_file_pattern_create"
V4_DLP_FILE_PATTERN_CONFIRM_TOOL = "confirm_v4_dlp_file_pattern_create"
V4_DLP_FILE_PATTERN_ACTION_TOOL = "execute_confirmed_v4_dlp_file_pattern_create"
V4_DLP_FILE_PATTERN_DELETE_PREVIEW_TOOL = "preview_v4_dlp_file_pattern_delete"
V4_DLP_FILE_PATTERN_DELETE_CONFIRM_TOOL = "confirm_v4_dlp_file_pattern_delete"
V4_DLP_FILE_PATTERN_DELETE_ACTION_TOOL = (
    "execute_confirmed_v4_dlp_file_pattern_delete"
)
V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE = (
    "FortiPAM V4 DLP file-pattern create action is unavailable."
)


class V4DlpFilePatternActionConfigurationError(ValueError):
    """Raised when the DLP file-pattern action host is incomplete or unsafe."""


class V4DlpFilePatternActionRuntimeError(RuntimeError):
    """Stable, non-disclosing DLP file-pattern action failure."""


def load_v4_dlp_file_pattern_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent DLP file-pattern opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_DLP_FILE_PATTERN_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4DlpFilePatternActionConfigurationError(
        f"{V4_DLP_FILE_PATTERN_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_dlp_file_pattern_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_DLP_FILE_PATTERN_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4DlpFilePatternActionConfigurationError(
        f"{V4_DLP_FILE_PATTERN_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_dlp_file_pattern_delete_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent destructive final-dispatch gate, default denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_DLP_FILE_PATTERN_DELETE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4DlpFilePatternActionConfigurationError(
        f"{V4_DLP_FILE_PATTERN_DELETE_EXECUTION_ENV} must be exactly true or false."
    )


def dlp_file_pattern_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4DlpFilePatternActionRuntimeError(
            V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE
        ) from exc


class ProtectedDlpFilePatternMcpAction:
    """Expose only C/P/E, confirmation, and execution for one DLP file pattern."""

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
        pattern_id: int,
        pattern_name: str,
        principal: Any,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.preview(
                    pattern_id=pattern_id,
                    pattern_name=pattern_name,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4DlpFilePatternActionRuntimeError(
                V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE
            ) from exc

    def confirm(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow.confirm(preview_ref, requester_digest=requester_digest),
            )
        except Exception as exc:
            raise V4DlpFilePatternActionRuntimeError(
                V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4DlpFilePatternActionRuntimeError(
                V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE
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
            raise V4DlpFilePatternActionRuntimeError(
                V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE
            ) from exc

    def preview_delete(self, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._require_delete_workflow().preview(
                    requester_digest=requester_digest
                ),
            )
        except Exception as exc:
            raise V4DlpFilePatternActionRuntimeError(
                V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE
            ) from exc

    def confirm_delete(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._require_delete_workflow().confirm(
                    preview_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4DlpFilePatternActionRuntimeError(
                V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE
            ) from exc

    def execute_delete(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._delete_execution_enabled:
            raise V4DlpFilePatternActionRuntimeError(
                V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE
            )
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._require_delete_workflow().execute(
                    authorization_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4DlpFilePatternActionRuntimeError(
                V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE
            ) from exc

    def _require_delete_workflow(self) -> Any:
        if self._delete_workflow is None:
            raise V4DlpFilePatternActionRuntimeError(
                V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE
            )
        return self._delete_workflow


def build_v4_dlp_file_pattern_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedDlpFilePatternMcpAction:
    """Construct the DLP file-pattern action from dedicated SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .dlp_file_pattern_delete_http_transport import (
            FortiPamDlpFilePatternDeleteHttpTransport,
            load_dlp_file_pattern_delete_http_transport_config,
        )
        from .dlp_file_pattern_delete_live_workflow import (
            DlpFilePatternDeleteLiveWorkflow,
        )
        from .dlp_file_pattern_live_workflow import DlpFilePatternLiveWorkflow
        from .dlp_file_pattern_ssh_transport import (
            FortiPamDlpFilePatternSshTransport,
            load_dlp_file_pattern_ssh_transport_config,
        )
        from .dlp_sensor_ssh_transport import (
            FortiPamDlpSensorSshTransport,
            load_dlp_sensor_ssh_transport_config,
        )

        pattern_transport = FortiPamDlpFilePatternSshTransport(
            load_dlp_file_pattern_ssh_transport_config(env)
        )
        sensor_transport = FortiPamDlpSensorSshTransport(
            load_dlp_sensor_ssh_transport_config(env)
        )
        workflow = DlpFilePatternLiveWorkflow(pattern_transport)
        delete_workflow = DlpFilePatternDeleteLiveWorkflow(
            FortiPamDlpFilePatternDeleteHttpTransport(
                load_dlp_file_pattern_delete_http_transport_config(env),
                pattern_transport,
                sensor_transport,
            )
        )
    except Exception as exc:
        raise V4DlpFilePatternActionConfigurationError(
            V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedDlpFilePatternMcpAction(
        workflow,
        execution_enabled=load_v4_dlp_file_pattern_execution_feature(env),
        delete_workflow=delete_workflow,
        delete_execution_enabled=(
            load_v4_dlp_file_pattern_delete_execution_feature(env)
        ),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4DlpFilePatternActionRuntimeError(
            V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE
        ) from exc


__all__ = [
    "ProtectedDlpFilePatternMcpAction",
    "V4_DLP_FILE_PATTERN_ACTION_FEATURE_ENV",
    "V4_DLP_FILE_PATTERN_ACTION_PREFIX",
    "V4_DLP_FILE_PATTERN_ACTION_TOOL",
    "V4_DLP_FILE_PATTERN_ACTION_UNAVAILABLE",
    "V4_DLP_FILE_PATTERN_CONFIRM_TOOL",
    "V4_DLP_FILE_PATTERN_DELETE_ACTION_TOOL",
    "V4_DLP_FILE_PATTERN_DELETE_CONFIRM_TOOL",
    "V4_DLP_FILE_PATTERN_DELETE_EXECUTION_ENV",
    "V4_DLP_FILE_PATTERN_DELETE_PREVIEW_TOOL",
    "V4_DLP_FILE_PATTERN_EXECUTION_ENV",
    "V4_DLP_FILE_PATTERN_PREVIEW_TOOL",
    "V4DlpFilePatternActionConfigurationError",
    "V4DlpFilePatternActionRuntimeError",
    "build_v4_dlp_file_pattern_action",
    "dlp_file_pattern_action_principal_from_access_token",
    "load_v4_dlp_file_pattern_action_feature",
    "load_v4_dlp_file_pattern_delete_execution_feature",
    "load_v4_dlp_file_pattern_execution_feature",
]
