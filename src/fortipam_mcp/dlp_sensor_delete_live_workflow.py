"""One confirmation-gated recovery for the accepted b34 PDF DLP Sensor."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Protocol

from .dlp_sensor_delete_http_transport import (
    DlpSensorDeleteInspection,
    DlpSensorDeleteReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_dlp_sensor_delete_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 DLP Sensor recovery is unavailable."
_TTL_SECONDS = 600


class DlpSensorDeleteLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing fixed recovery failure."""


class DlpSensorDeleteLiveWorkflowTransport(Protocol):
    """Exact accepted-target preflight and DELETE/readback contract."""

    def inspect_delete_target(self) -> DlpSensorDeleteInspection: ...

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> DlpSensorDeleteReadback: ...


@dataclass(frozen=True, slots=True)
class _Record:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    current_digest: str
    target_digest: str
    state: str
    expires_at: int


class DlpSensorDeleteLiveWorkflow:
    """Volatile one-confirmation flow for the exact unreferenced b34 target."""

    _preview_ref_prefix = "dlp-sensor-delete-preview-"
    _authorization_ref_prefix = "dlp-sensor-delete-authorized-"
    _workflow_contract = WORKFLOW_CONTRACT
    _execution_contract = "fortipam_v4_dlp_sensor_delete_api_execution_v1"

    def __init__(
        self,
        transport: DlpSensorDeleteLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _Record] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        _require_requester(requester_digest)
        current = self._inspect()
        if (
            not current.exists
            or not current.eligible_fixed_sensor
            or current.secret_reference_count != 0
            or current.policy_reference_count != 0
        ):
            raise DlpSensorDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _Record(
            preview_ref=self._preview_ref_prefix + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            current_digest=self._current_digest(current),
            target_digest=current.target_digest,
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect()
            self._validate_record(record, requester_digest, "previewed")
            if not hmac.compare_digest(
                self._current_digest(current),
                record.current_digest,
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise DlpSensorDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = (
                self._authorization_ref_prefix + secrets.token_urlsafe(24)
            )
            updated = replace(
                record,
                authorization_ref=authorization_ref,
                state="authorized",
            )
            self._records[record.preview_ref] = updated
            self._authorization_index[authorization_ref] = record.preview_ref
        return {
            "contract": self._workflow_contract,
            "preview_ref": updated.preview_ref,
            "authorization_ref": authorization_ref,
            "confirmation": "recorded",
            "execution": "authorized_once",
            "expires_at": updated.expires_at,
            "device_write_executed": False,
        }

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect()
            self._validate_record(record, requester_digest, "authorized")
            if not hmac.compare_digest(
                self._current_digest(current),
                record.current_digest,
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise DlpSensorDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._delete_confirmed_and_readback(record)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed"
                if self._readback_verified(readback)
                else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _delete_confirmed_and_readback(self, record: _Record) -> object:
        return self._transport.delete_and_readback(record.target_digest)

    @staticmethod
    def _readback_verified(readback: object) -> bool:
        return isinstance(readback, DlpSensorDeleteReadback) and readback.verified

    @staticmethod
    def _current_digest(current: DlpSensorDeleteInspection) -> str:
        return _inspection_digest(current)

    def _inspect(self) -> DlpSensorDeleteInspection:
        try:
            result = self._transport.inspect_delete_target()
        except Exception as exc:
            raise DlpSensorDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, DlpSensorDeleteInspection):
            raise DlpSensorDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _Record:
        if not _valid_ref(preview_ref, self._preview_ref_prefix):
            raise DlpSensorDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise DlpSensorDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _Record:
        if not _valid_ref(authorization_ref, self._authorization_ref_prefix):
            raise DlpSensorDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise DlpSensorDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _Record,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise DlpSensorDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _Record, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise DlpSensorDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise DlpSensorDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._records[preview_ref] = replace(record, state=state)

    def _purge_expired_locked(self) -> None:
        now_epoch = self._clock()
        expired = [
            ref
            for ref, record in self._records.items()
            if record.expires_at <= now_epoch and record.state != "completed"
        ]
        for preview_ref in expired:
            record = self._records.pop(preview_ref)
            if record.authorization_ref is not None:
                self._authorization_index.pop(record.authorization_ref, None)

    @classmethod
    def _preview_projection(cls, record: _Record) -> dict[str, object]:
        return {
            "contract": cls._workflow_contract,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "accepted_dlp_sensor_exists": True,
                "exact_fixed_http_get_pdf_block_sensor_observed": True,
                "complete_api_record_digest_matches": True,
                "secret_reference_count": 0,
                "policy_reference_count": 0,
                "file_pattern_binding_present": True,
                "read_transports": ["rest_api", "ssh_cli"],
            },
            "Proposed Changes": {
                "operation": "delete_exact_unreferenced_dlp_sensor_via_api",
                "dlp_sensor_count_affected": 1,
                "irreversible_after_execution": True,
                "file_pattern_changes": False,
                "regexp_sensor_changes": False,
                "secret_or_policy_association_changes": False,
                "license_or_session_changes": False,
            },
            "Expected State": {
                "accepted_dlp_sensor_absent": True,
                "file_pattern_preserved": True,
                "regexp_sensor_changes": False,
                "secret_or_policy_association_changes": False,
                "license_or_session_changes": False,
                "readback_transports": ["rest_api", "ssh_cli"],
            },
            "device_write_executed": False,
        }

    def _result(self, record: _Record, *, idempotent_replay: bool) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": self._execution_contract,
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_dlp_sensor_create_action_required",
            "irreversible_after_execution": True,
            "dlp_sensor_name_returned": False,
            "profile_content_returned": False,
            "file_pattern_changes": False,
            "regexp_sensor_changes": False,
            "secret_or_policy_association_changes": False,
            "license_or_session_changes": False,
            "raw_api_or_cli_response_returned": False,
        }


def _inspection_digest(inspection: DlpSensorDeleteInspection) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "exists": inspection.exists,
                "eligible_fixed_sensor": inspection.eligible_fixed_sensor,
                "secret_reference_count": inspection.secret_reference_count,
                "policy_reference_count": inspection.policy_reference_count,
                "target_digest": inspection.target_digest,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _require_requester(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DlpSensorDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "DlpSensorDeleteLiveWorkflow",
    "DlpSensorDeleteLiveWorkflowError",
    "DlpSensorDeleteLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
