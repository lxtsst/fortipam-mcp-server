"""Fixed Web SFTP log-only profile using the existing Regexp state machine."""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import json
from typing import Protocol

from .dlp_regexp_sensor_live_workflow import (
    DlpRegexpSensorLiveWorkflow, DlpRegexpSensorLiveWorkflowError,
    _DlpRegexpSensorRecord,
)
from .dlp_sensor_ssh_transport import (
    DLP_SFTP_AUDIT_SENSOR_PROFILE, DlpRegexpSensorInspection, DlpRegexpSensorReadback,
    _SFTP_AUDIT_SENSOR_NAME,
)
from .dlp_sftp_audit_sensor_http_transport import (
    DlpSftpAuditSensorInspection, DlpSftpAuditSensorReadback,
)

WORKFLOW_CONTRACT = "fortipam_v4_dlp_sftp_audit_sensor_create_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Web SFTP audit Sensor workflow is unavailable."
DlpSftpAuditSensorLiveWorkflowError = DlpRegexpSensorLiveWorkflowError


class DlpSftpAuditSensorLiveWorkflowTransport(Protocol):
    """Only pinned fixed-profile inspection, one POST, and complete readback."""

    def inspect_sftp_sensor(self, sensor_name: str) -> DlpSftpAuditSensorInspection: ...

    def create_sftp_and_readback(
        self, sensor_name: str, *, expires_at: int, clock: Callable[[], int],
    ) -> DlpSftpAuditSensorReadback: ...


class _FixedProfileAdapter:
    """Adapt the fixed transport to the established Regexp workflow protocol."""

    def __init__(self, transport: DlpSftpAuditSensorLiveWorkflowTransport) -> None:
        self._transport = transport

    def inspect_regexp_sensor(self, sensor_name: str) -> DlpSftpAuditSensorInspection:
        result = self._transport.inspect_sftp_sensor(sensor_name)
        if (not isinstance(result, DlpSftpAuditSensorInspection)
                or type(result.sensor_name_exists) is not bool
                or not isinstance(result.source_digest, str)
                or len(result.source_digest) != 64
                or any(character not in "0123456789abcdef" for character in result.source_digest)):
            raise DlpSftpAuditSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def create_regexp_and_readback(self, sensor_name: str) -> DlpRegexpSensorReadback:
        raise DlpSftpAuditSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)


class DlpSftpAuditSensorLiveWorkflow(DlpRegexpSensorLiveWorkflow):
    """An explicitly injected fixed profile; never built by the default host."""

    _name_pattern = _SFTP_AUDIT_SENSOR_NAME
    _preview_ref_prefix = "dlp-sftp-audit-sensor-preview-"
    _authorization_ref_prefix = "dlp-sftp-audit-sensor-authorized-"
    _workflow_contract = WORKFLOW_CONTRACT
    _execution_contract = "fortipam_v4_dlp_sftp_audit_sensor_create_execution_v1"

    def __init__(
        self, transport: DlpSftpAuditSensorLiveWorkflowTransport,
        *, clock: Callable[[], int] | None = None,
    ) -> None:
        self._sftp_transport = transport
        super().__init__(_FixedProfileAdapter(transport), clock=clock)

    def _create_confirmed_and_readback(
        self, record: _DlpRegexpSensorRecord,
    ) -> DlpRegexpSensorReadback:
        result = self._sftp_transport.create_sftp_and_readback(
            record.sensor_name, expires_at=record.expires_at, clock=self._clock,
        )
        if not isinstance(result, DlpSftpAuditSensorReadback):
            raise DlpSftpAuditSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    @staticmethod
    def _current_digest(current: DlpRegexpSensorInspection) -> str:
        if not isinstance(current, DlpSftpAuditSensorInspection):
            raise DlpSftpAuditSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return hashlib.sha256(json.dumps(
            {"sensor_name_exists": current.sensor_name_exists,
             "source_digest": current.source_digest},
            sort_keys=True, separators=(",", ":"),
        ).encode("ascii")).hexdigest()

    @classmethod
    def _preview_projection(
        cls, record: _DlpRegexpSensorRecord, current: DlpRegexpSensorInspection,
    ) -> dict[str, object]:
        preview = super()._preview_projection(record, current)
        preview["Proposed Changes"] = {
            "operation": "create_single_web_sftp_file_regexp_log_only_dlp_sensor",
            "sensor_name": record.sensor_name,
            "configuration_profile": DLP_SFTP_AUDIT_SENSOR_PROFILE,
            "protocols": ["http-get", "http-post"], "filter_type": "file",
            "filter_by": "regexp", "regexp_pattern_class": "fixed_lab_sentinel",
            "regexp_value_returned": False, "action": "log-only", "filter_count": 1,
            "dlp_log": "enable", "summary_protocols": [], "full_archive_protocols": [],
            "filter_archive": "disable", "remaining_native_fields": "qualified_defaults",
            "dlp_secret_association_changes": False,
        }
        expected = preview["Expected State"]
        assert isinstance(expected, dict)
        expected["native_defaults_match"] = True
        expected["filter_count_matches"] = True
        return preview

    def _result(
        self, record: _DlpRegexpSensorRecord, *, idempotent_replay: bool,
    ) -> dict[str, object]:
        result = super()._result(record, idempotent_replay=idempotent_replay)
        result["raw_api_returned"] = False
        return result
