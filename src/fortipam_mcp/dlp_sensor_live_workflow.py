"""One live, confirmation-gated FortiPAM DLP Sensor create workflow."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from typing import Protocol

from .dlp_sensor_ssh_transport import (
    DLP_SENSOR_PROFILE,
    DlpSensorInspection,
    DlpSensorReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_dlp_sensor_create_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 DLP Sensor create workflow is unavailable."
_TTL_SECONDS = 600
_MIN_PATTERN_ID = 1000
_MAX_PATTERN_ID = 9999
_SENSOR_NAME = re.compile(r"mcp-v4-dlp-sensor-[A-Za-z0-9][A-Za-z0-9._-]{0,39}\Z")
_PATTERN_NAME = re.compile(r"mcp-v4-dlp-pattern-[A-Za-z0-9][A-Za-z0-9._-]{0,39}\Z")


class DlpSensorLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded DLP Sensor flow."""


class DlpSensorLiveWorkflowTransport(Protocol):
    """Exact DLP Sensor preflight and create/readback contract."""

    def inspect(
        self,
        sensor_name: str,
        file_pattern_id: int,
        file_pattern_name: str,
    ) -> DlpSensorInspection: ...

    def create_and_readback(
        self,
        sensor_name: str,
        file_pattern_id: int,
    ) -> DlpSensorReadback: ...


@dataclass(frozen=True, slots=True)
class _DlpSensorRequest:
    sensor_name: str
    file_pattern_id: int
    file_pattern_name: str

    @classmethod
    def create(
        cls,
        *,
        sensor_name: str,
        file_pattern_id: int,
        file_pattern_name: str,
    ) -> "_DlpSensorRequest":
        if not isinstance(sensor_name, str) or _SENSOR_NAME.fullmatch(sensor_name) is None:
            raise DlpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if (
            type(file_pattern_id) is not int
            or not _MIN_PATTERN_ID <= file_pattern_id <= _MAX_PATTERN_ID
        ):
            raise DlpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        if (
            not isinstance(file_pattern_name, str)
            or _PATTERN_NAME.fullmatch(file_pattern_name) is None
        ):
            raise DlpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(
            sensor_name=sensor_name,
            file_pattern_id=file_pattern_id,
            file_pattern_name=file_pattern_name,
        )


@dataclass(frozen=True, slots=True)
class _DlpSensorRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    sensor_name: str
    file_pattern_id: int
    file_pattern_name: str
    current_digest: str
    state: str
    expires_at: int


class DlpSensorLiveWorkflow:
    """Volatile one-confirmation workflow for one HTTP-GET PDF-block Sensor."""

    def __init__(
        self,
        transport: DlpSensorLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _DlpSensorRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        sensor_name: str,
        file_pattern_id: int,
        file_pattern_name: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read current state and render C/P/E without a device write."""

        request = _DlpSensorRequest.create(
            sensor_name=sensor_name,
            file_pattern_id=file_pattern_id,
            file_pattern_name=file_pattern_name,
        )
        _require_requester(requester_digest)
        current = self._inspect(request)
        if (
            current.sensor_name_exists
            or not current.file_pattern_id_exists
            or not current.file_pattern_name_exists
            or not current.file_pattern_binding_matches
        ):
            raise DlpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _DlpSensorRecord(
            preview_ref="dlp-sensor-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            sensor_name=request.sensor_name,
            file_pattern_id=request.file_pattern_id,
            file_pattern_name=request.file_pattern_name,
            current_digest=_inspection_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record, current)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm unchanged preflight state and issue one execution reference."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect(_request_from_record(record))
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise DlpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "dlp-sensor-authorized-" + secrets.token_urlsafe(24)
            updated = replace(
                record,
                authorization_ref=authorization_ref,
                state="authorized",
            )
            self._records[record.preview_ref] = updated
            self._authorization_index[authorization_ref] = record.preview_ref
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": updated.preview_ref,
            "authorization_ref": authorization_ref,
            "confirmation": "recorded",
            "execution": "authorized_once",
            "expires_at": updated.expires_at,
            "device_write_executed": False,
        }

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Create exactly the confirmed Sensor and return categorical readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(_request_from_record(record))
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise DlpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.create_and_readback(
                record.sensor_name,
                record.file_pattern_id,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, DlpSensorReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, request: _DlpSensorRequest) -> DlpSensorInspection:
        try:
            result = self._transport.inspect(
                request.sensor_name,
                request.file_pattern_id,
                request.file_pattern_name,
            )
        except Exception as exc:
            raise DlpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, DlpSensorInspection):
            raise DlpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _DlpSensorRecord:
        if not _valid_ref(preview_ref, "dlp-sensor-preview-"):
            raise DlpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise DlpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _DlpSensorRecord:
        if not _valid_ref(authorization_ref, "dlp-sensor-authorized-"):
            raise DlpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise DlpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _DlpSensorRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise DlpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _DlpSensorRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise DlpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise DlpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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

    @staticmethod
    def _preview_projection(
        record: _DlpSensorRecord,
        current: DlpSensorInspection,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_sensor_name": record.sensor_name,
                "requested_file_pattern_id": record.file_pattern_id,
                "requested_file_pattern_name": record.file_pattern_name,
                "sensor_name_exists": current.sensor_name_exists,
                "file_pattern_id_exists": current.file_pattern_id_exists,
                "file_pattern_name_exists": current.file_pattern_name_exists,
                "file_pattern_binding_matches": current.file_pattern_binding_matches,
            },
            "Proposed Changes": {
                "operation": "create_single_http_get_pdf_block_dlp_sensor",
                "sensor_name": record.sensor_name,
                "file_pattern_id": record.file_pattern_id,
                "file_pattern_name": record.file_pattern_name,
                "configuration_profile": DLP_SENSOR_PROFILE,
                "protocol": "http-get",
                "filter_by": "file-type",
                "action": "block",
                "dlp_secret_association_changes": False,
            },
            "Expected State": {
                "sensor_name_matches": True,
                "sensor_name_exists": True,
                "filter_id_exists": True,
                "filter_name_matches": True,
                "protocol_matches": True,
                "filter_by_matches": True,
                "file_pattern_id_matches": True,
                "action_matches": True,
                "dlp_secret_association_changes": False,
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _DlpSensorRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_dlp_sensor_create_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "not_requested",
            "dlp_secret_association_changes": False,
            "raw_cli_returned": False,
        }


def _request_from_record(record: _DlpSensorRecord) -> _DlpSensorRequest:
    return _DlpSensorRequest(
        sensor_name=record.sensor_name,
        file_pattern_id=record.file_pattern_id,
        file_pattern_name=record.file_pattern_name,
    )


def _inspection_digest(inspection: DlpSensorInspection) -> str:
    payload = json.dumps(
        {
            "sensor_name_exists": inspection.sensor_name_exists,
            "file_pattern_id_exists": inspection.file_pattern_id_exists,
            "file_pattern_name_exists": inspection.file_pattern_name_exists,
            "file_pattern_binding_matches": inspection.file_pattern_binding_matches,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise DlpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "DlpSensorLiveWorkflow",
    "DlpSensorLiveWorkflowError",
    "DlpSensorLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
