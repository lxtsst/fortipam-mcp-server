"""Explicitly injected recovery of the same creator's verified audit Sensor."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from .dlp_sensor_delete_http_transport import DlpSensorDeleteInspection, DlpSensorDeleteReadback
from .dlp_sensor_delete_live_workflow import (
    DlpSensorDeleteLiveWorkflow, DlpSensorDeleteLiveWorkflowError, _Record,
)
from .dlp_sftp_audit_sensor_http_transport import (
    DlpSftpAuditSensorDeleteInspection, DlpSftpAuditSensorDeleteReadback,
    _recovery_inspection_digest,
)

WORKFLOW_CONTRACT = "fortipam_v4_dlp_sftp_audit_sensor_delete_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 owned Web SFTP audit Sensor recovery is unavailable."
DlpSftpAuditSensorDeleteLiveWorkflowError = DlpSensorDeleteLiveWorkflowError


class DlpSftpAuditSensorDeleteLiveWorkflowTransport(Protocol):
    """The same private creator, without imported ownership attestations."""

    def inspect_owned_sftp_delete_target(self) -> DlpSftpAuditSensorDeleteInspection: ...

    def delete_owned_sftp_and_readback(
        self, *, expected_target_digest: str, expected_state_digest: str,
        expires_at: int, clock: Callable[[], int],
    ) -> DlpSftpAuditSensorDeleteReadback: ...


class _OwnedRecoveryAdapter:
    def __init__(self, transport: DlpSftpAuditSensorDeleteLiveWorkflowTransport) -> None:
        self._transport = transport

    def inspect_delete_target(self) -> DlpSftpAuditSensorDeleteInspection:
        result = self._transport.inspect_owned_sftp_delete_target()
        if not isinstance(result, DlpSftpAuditSensorDeleteInspection):
            raise DlpSftpAuditSensorDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def delete_and_readback(self, expected_target_digest: str) -> DlpSensorDeleteReadback:
        raise DlpSftpAuditSensorDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)


class DlpSftpAuditSensorDeleteLiveWorkflow(DlpSensorDeleteLiveWorkflow):
    """One fixed recovery with independent refs and dispatch-time expiry checks."""

    _preview_ref_prefix = "dlp-sftp-audit-sensor-delete-preview-"
    _authorization_ref_prefix = "dlp-sftp-audit-sensor-delete-authorized-"
    _workflow_contract = WORKFLOW_CONTRACT
    _execution_contract = "fortipam_v4_dlp_sftp_audit_sensor_delete_execution_v1"

    def __init__(
        self, transport: DlpSftpAuditSensorDeleteLiveWorkflowTransport,
        *, clock: Callable[[], int] | None = None,
    ) -> None:
        self._owned_transport = transport
        super().__init__(_OwnedRecoveryAdapter(transport), clock=clock)

    @staticmethod
    def _current_digest(current: DlpSensorDeleteInspection) -> str:
        if not isinstance(current, DlpSftpAuditSensorDeleteInspection):
            raise DlpSftpAuditSensorDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return _recovery_inspection_digest(current)

    def _delete_confirmed_and_readback(self, record: _Record) -> object:
        return self._owned_transport.delete_owned_sftp_and_readback(
            expected_target_digest=record.target_digest,
            expected_state_digest=record.current_digest,
            expires_at=record.expires_at, clock=self._clock,
        )

    @staticmethod
    def _readback_verified(readback: object) -> bool:
        return isinstance(readback, DlpSftpAuditSensorDeleteReadback) and readback.verified

    @classmethod
    def _preview_projection(cls, record: _Record) -> dict[str, object]:
        return {
            "contract": cls._workflow_contract, "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "verified_creation_ownership": True, "fixed_log_only_sensor_exists": True,
                "complete_native_profile_digest_matches": True,
                "secret_reference_count": 0, "policy_reference_count": 0,
                "dependency_source": "qualified_native_global_columns",
                "read_transports": ["rest_api", "ssh_cli"],
            },
            "Proposed Changes": {
                "operation": "delete_exact_owned_unreferenced_web_sftp_audit_sensor",
                "dlp_sensor_count_affected": 1, "irreversible_after_execution": True,
                "secret_or_policy_association_changes": False,
            },
            "Expected State": {
                "owned_audit_sensor_absent": True,
                "readback_transports": ["rest_api", "ssh_cli"],
                "secret_or_policy_association_changes": False,
            },
            "device_write_executed": False,
        }

    def _result(self, record: _Record, *, idempotent_replay: bool) -> dict[str, object]:
        result = super()._result(record, idempotent_replay=idempotent_replay)
        result.pop("regexp_sensor_changes")
        result["compensation"] = "fresh_separate_owned_sensor_create_required"
        return result
