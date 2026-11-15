"""MCP boundary for one controlled FortiPAM DLP Sensor create workflow."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, cast

from .folder_mcp_action import folder_action_principal_from_access_token


V4_DLP_SENSOR_ACTION_PREFIX = "FORTIPAM_MCP_V4_DLP_SENSOR_ACTION_"
V4_DLP_SENSOR_ACTION_FEATURE_ENV = f"{V4_DLP_SENSOR_ACTION_PREFIX}ENABLED"
V4_DLP_SENSOR_EXECUTION_ENV = "FORTIPAM_MCP_V4_DLP_SENSOR_EXECUTION_ENABLED"
V4_DLP_SENSOR_DELETE_EXECUTION_ENV = (
    "FORTIPAM_MCP_V4_DLP_SENSOR_DELETE_EXECUTION_ENABLED"
)
V4_DLP_SENSOR_PREVIEW_TOOL = "preview_v4_dlp_sensor_create"
V4_DLP_SENSOR_CONFIRM_TOOL = "confirm_v4_dlp_sensor_create"
V4_DLP_SENSOR_ACTION_TOOL = "execute_confirmed_v4_dlp_sensor_create"
V4_DLP_SENSOR_DELETE_PREVIEW_TOOL = "preview_v4_dlp_sensor_delete"
V4_DLP_SENSOR_DELETE_CONFIRM_TOOL = "confirm_v4_dlp_sensor_delete"
V4_DLP_SENSOR_DELETE_ACTION_TOOL = "execute_confirmed_v4_dlp_sensor_delete"
V4_DLP_SENSOR_ACTION_UNAVAILABLE = "FortiPAM V4 DLP Sensor create action is unavailable."
DLP_PROFILE_FILE_TYPE_PDF = "file_type_pdf"
DLP_PROFILE_REGEXP_SENTINEL = "regexp_sentinel"
DLP_PROFILE_SFTP_AUDIT = "web_sftp_regexp_log_only"
_PDF_PREVIEW_REF_PREFIX = "dlp-sensor-preview-"
_PDF_AUTHORIZATION_REF_PREFIX = "dlp-sensor-authorized-"
_REGEXP_PREVIEW_REF_PREFIX = "dlp-regexp-sensor-preview-"
_REGEXP_AUTHORIZATION_REF_PREFIX = "dlp-regexp-sensor-authorized-"
_SFTP_PREVIEW_REF_PREFIX = "dlp-sftp-audit-sensor-preview-"
_SFTP_AUTHORIZATION_REF_PREFIX = "dlp-sftp-audit-sensor-authorized-"
_SFTP_DELETE_PREVIEW_REF_PREFIX = "dlp-sftp-audit-sensor-delete-preview-"
_SFTP_DELETE_AUTHORIZATION_REF_PREFIX = "dlp-sftp-audit-sensor-delete-authorized-"


class V4DlpSensorActionConfigurationError(ValueError):
    """Raised when the DLP Sensor action host is incomplete or unsafe."""


class V4DlpSensorActionRuntimeError(RuntimeError):
    """Stable, non-disclosing DLP Sensor action failure."""


def load_v4_dlp_sensor_action_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent DLP Sensor opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_DLP_SENSOR_ACTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4DlpSensorActionConfigurationError(
        f"{V4_DLP_SENSOR_ACTION_FEATURE_ENV} must be exactly true or false."
    )


def load_v4_dlp_sensor_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent final-dispatch gate, defaulting to denied."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_DLP_SENSOR_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4DlpSensorActionConfigurationError(
        f"{V4_DLP_SENSOR_EXECUTION_ENV} must be exactly true or false."
    )


def load_v4_dlp_sensor_delete_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent destructive final-dispatch gate."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_DLP_SENSOR_DELETE_EXECUTION_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4DlpSensorActionConfigurationError(
        f"{V4_DLP_SENSOR_DELETE_EXECUTION_ENV} must be exactly true or false."
    )


def dlp_sensor_action_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> Any:
    """Require the same explicit planning and operation scope as other writes."""

    try:
        return folder_action_principal_from_access_token(access_token, planning_settings)
    except Exception as exc:
        raise V4DlpSensorActionRuntimeError(V4_DLP_SENSOR_ACTION_UNAVAILABLE) from exc


class ProtectedDlpSensorMcpAction:
    """Expose fixed DLP Sensor profiles through one bounded action family."""

    def __init__(
        self,
        workflow: Any,
        *,
        regexp_workflow: Any | None = None,
        sftp_workflow: Any | None = None,
        execution_enabled: bool = True,
        delete_workflow: Any | None = None,
        sftp_delete_workflow: Any | None = None,
        delete_execution_enabled: bool = False,
    ) -> None:
        self._workflow = workflow
        self._regexp_workflow = regexp_workflow
        self._sftp_workflow = sftp_workflow
        self._execution_enabled = execution_enabled
        self._delete_workflow = delete_workflow
        self._sftp_delete_workflow = sftp_delete_workflow
        self._delete_execution_enabled = delete_execution_enabled

    def preview(
        self,
        sensor_name: str,
        file_pattern_id: int | None,
        file_pattern_name: str | None,
        principal: Any,
        configuration_profile: str = DLP_PROFILE_FILE_TYPE_PDF,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            if configuration_profile == DLP_PROFILE_FILE_TYPE_PDF:
                if type(file_pattern_id) is not int or not isinstance(
                    file_pattern_name, str
                ):
                    raise TypeError("PDF file pattern binding required")
                return cast(
                    dict[str, object],
                    self._workflow.preview(
                        sensor_name=sensor_name,
                        file_pattern_id=file_pattern_id,
                        file_pattern_name=file_pattern_name,
                        requester_digest=requester_digest,
                    ),
                )
            if configuration_profile == DLP_PROFILE_REGEXP_SENTINEL:
                if file_pattern_id is not None or file_pattern_name is not None:
                    raise TypeError("Regexp profile accepts no file pattern binding")
                return cast(
                    dict[str, object],
                    self._require_regexp_workflow().preview(
                        sensor_name=sensor_name,
                        requester_digest=requester_digest,
                    ),
                )
            if configuration_profile == DLP_PROFILE_SFTP_AUDIT:
                if file_pattern_id is not None or file_pattern_name is not None:
                    raise TypeError("SFTP audit profile accepts no file pattern binding")
                return cast(
                    dict[str, object],
                    self._require_sftp_workflow().preview(
                        sensor_name=sensor_name,
                        requester_digest=requester_digest,
                    ),
                )
            raise TypeError("unsupported DLP profile")
        except Exception as exc:
            raise V4DlpSensorActionRuntimeError(
                V4_DLP_SENSOR_ACTION_UNAVAILABLE
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
            raise V4DlpSensorActionRuntimeError(
                V4_DLP_SENSOR_ACTION_UNAVAILABLE
            ) from exc

    def execute(self, authorization_ref: str, principal: Any) -> dict[str, object]:
        if not self._execution_enabled:
            raise V4DlpSensorActionRuntimeError(V4_DLP_SENSOR_ACTION_UNAVAILABLE)
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._workflow_for_authorization(authorization_ref).execute(
                    authorization_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4DlpSensorActionRuntimeError(
                V4_DLP_SENSOR_ACTION_UNAVAILABLE
            ) from exc

    def preview_delete(
        self, principal: Any, configuration_profile: str = DLP_PROFILE_FILE_TYPE_PDF,
    ) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._delete_workflow_for_profile(configuration_profile).preview(
                    requester_digest=requester_digest
                ),
            )
        except Exception as exc:
            raise V4DlpSensorActionRuntimeError(
                V4_DLP_SENSOR_ACTION_UNAVAILABLE
            ) from exc

    def confirm_delete(self, preview_ref: str, principal: Any) -> dict[str, object]:
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._delete_workflow_for_preview(preview_ref).confirm(
                    preview_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4DlpSensorActionRuntimeError(
                V4_DLP_SENSOR_ACTION_UNAVAILABLE
            ) from exc

    def execute_delete(
        self,
        authorization_ref: str,
        principal: Any,
    ) -> dict[str, object]:
        if not self._delete_execution_enabled:
            raise V4DlpSensorActionRuntimeError(V4_DLP_SENSOR_ACTION_UNAVAILABLE)
        requester_digest = _requester_digest(principal)
        try:
            return cast(
                dict[str, object],
                self._delete_workflow_for_authorization(authorization_ref).execute(
                    authorization_ref,
                    requester_digest=requester_digest,
                ),
            )
        except Exception as exc:
            raise V4DlpSensorActionRuntimeError(
                V4_DLP_SENSOR_ACTION_UNAVAILABLE
            ) from exc

    def _require_regexp_workflow(self) -> Any:
        if self._regexp_workflow is None:
            raise V4DlpSensorActionRuntimeError(V4_DLP_SENSOR_ACTION_UNAVAILABLE)
        return self._regexp_workflow

    def _require_delete_workflow(self) -> Any:
        if self._delete_workflow is None:
            raise V4DlpSensorActionRuntimeError(V4_DLP_SENSOR_ACTION_UNAVAILABLE)
        return self._delete_workflow

    def _require_sftp_workflow(self) -> Any:
        if self._sftp_workflow is None:
            raise V4DlpSensorActionRuntimeError(V4_DLP_SENSOR_ACTION_UNAVAILABLE)
        return self._sftp_workflow

    def _delete_workflow_for_profile(self, configuration_profile: str) -> Any:
        if configuration_profile == DLP_PROFILE_FILE_TYPE_PDF:
            return self._require_delete_workflow()
        if configuration_profile == DLP_PROFILE_SFTP_AUDIT and self._sftp_delete_workflow is not None:
            return self._sftp_delete_workflow
        raise V4DlpSensorActionRuntimeError(V4_DLP_SENSOR_ACTION_UNAVAILABLE)

    def _delete_workflow_for_preview(self, preview_ref: str) -> Any:
        if isinstance(preview_ref, str) and preview_ref.startswith(_SFTP_DELETE_PREVIEW_REF_PREFIX):
            return self._delete_workflow_for_profile(DLP_PROFILE_SFTP_AUDIT)
        return self._require_delete_workflow()

    def _delete_workflow_for_authorization(self, authorization_ref: str) -> Any:
        if isinstance(authorization_ref, str) and authorization_ref.startswith(
            _SFTP_DELETE_AUTHORIZATION_REF_PREFIX
        ):
            return self._delete_workflow_for_profile(DLP_PROFILE_SFTP_AUDIT)
        return self._require_delete_workflow()

    def _workflow_for_preview(self, preview_ref: str) -> Any:
        if isinstance(preview_ref, str) and preview_ref.startswith(_PDF_PREVIEW_REF_PREFIX):
            return self._workflow
        if isinstance(preview_ref, str) and preview_ref.startswith(_REGEXP_PREVIEW_REF_PREFIX):
            return self._require_regexp_workflow()
        if isinstance(preview_ref, str) and preview_ref.startswith(_SFTP_PREVIEW_REF_PREFIX):
            return self._require_sftp_workflow()
        raise V4DlpSensorActionRuntimeError(V4_DLP_SENSOR_ACTION_UNAVAILABLE)

    def _workflow_for_authorization(self, authorization_ref: str) -> Any:
        if isinstance(authorization_ref, str) and authorization_ref.startswith(
            _PDF_AUTHORIZATION_REF_PREFIX
        ):
            return self._workflow
        if isinstance(authorization_ref, str) and authorization_ref.startswith(
            _REGEXP_AUTHORIZATION_REF_PREFIX
        ):
            return self._require_regexp_workflow()
        if isinstance(authorization_ref, str) and authorization_ref.startswith(
            _SFTP_AUTHORIZATION_REF_PREFIX
        ):
            return self._require_sftp_workflow()
        raise V4DlpSensorActionRuntimeError(V4_DLP_SENSOR_ACTION_UNAVAILABLE)


def build_v4_dlp_sensor_action(
    environment: Mapping[str, str] | None = None,
) -> ProtectedDlpSensorMcpAction:
    """Construct the DLP Sensor action from dedicated SSH settings."""

    env = os.environ if environment is None else environment
    try:
        from .dlp_sensor_delete_http_transport import (
            FortiPamDlpSensorDeleteHttpTransport,
            load_dlp_sensor_delete_http_transport_config,
        )
        from .dlp_sensor_delete_live_workflow import DlpSensorDeleteLiveWorkflow
        from .dlp_regexp_sensor_live_workflow import DlpRegexpSensorLiveWorkflow
        from .dlp_sensor_live_workflow import DlpSensorLiveWorkflow
        from .dlp_sensor_ssh_transport import (
            FortiPamDlpSensorSshTransport,
            load_dlp_sensor_ssh_transport_config,
        )

        transport = FortiPamDlpSensorSshTransport(
            load_dlp_sensor_ssh_transport_config(env)
        )
        workflow = DlpSensorLiveWorkflow(transport)
        regexp_workflow = DlpRegexpSensorLiveWorkflow(transport)
        delete_workflow = DlpSensorDeleteLiveWorkflow(
            FortiPamDlpSensorDeleteHttpTransport(
                load_dlp_sensor_delete_http_transport_config(env),
                transport,
            )
        )
    except Exception as exc:
        raise V4DlpSensorActionConfigurationError(
            V4_DLP_SENSOR_ACTION_UNAVAILABLE
        ) from exc
    return ProtectedDlpSensorMcpAction(
        workflow,
        regexp_workflow=regexp_workflow,
        execution_enabled=load_v4_dlp_sensor_execution_feature(env),
        delete_workflow=delete_workflow,
        delete_execution_enabled=load_v4_dlp_sensor_delete_execution_feature(env),
    )


def _requester_digest(principal: Any) -> str:
    try:
        from .v4_plan_runtime import V4PlanningPrincipal

        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("planning principal required")
        return principal.requester.digest
    except Exception as exc:
        raise V4DlpSensorActionRuntimeError(V4_DLP_SENSOR_ACTION_UNAVAILABLE) from exc


__all__ = [
    "DLP_PROFILE_FILE_TYPE_PDF",
    "DLP_PROFILE_REGEXP_SENTINEL",
    "DLP_PROFILE_SFTP_AUDIT",
    "ProtectedDlpSensorMcpAction",
    "V4_DLP_SENSOR_ACTION_FEATURE_ENV",
    "V4_DLP_SENSOR_ACTION_PREFIX",
    "V4_DLP_SENSOR_ACTION_TOOL",
    "V4_DLP_SENSOR_ACTION_UNAVAILABLE",
    "V4_DLP_SENSOR_CONFIRM_TOOL",
    "V4_DLP_SENSOR_DELETE_ACTION_TOOL",
    "V4_DLP_SENSOR_DELETE_CONFIRM_TOOL",
    "V4_DLP_SENSOR_DELETE_EXECUTION_ENV",
    "V4_DLP_SENSOR_DELETE_PREVIEW_TOOL",
    "V4_DLP_SENSOR_EXECUTION_ENV",
    "V4_DLP_SENSOR_PREVIEW_TOOL",
    "V4DlpSensorActionConfigurationError",
    "V4DlpSensorActionRuntimeError",
    "build_v4_dlp_sensor_action",
    "dlp_sensor_action_principal_from_access_token",
    "load_v4_dlp_sensor_action_feature",
    "load_v4_dlp_sensor_delete_execution_feature",
    "load_v4_dlp_sensor_execution_feature",
]
