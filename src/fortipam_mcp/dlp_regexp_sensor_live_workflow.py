"""One live, confirmation-gated FortiPAM fixed-Regexp Sensor workflow."""

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
    DLP_REGEXP_SENSOR_PROFILE,
    DlpRegexpSensorInspection,
    DlpRegexpSensorReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_dlp_regexp_sensor_create_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 DLP Regexp Sensor create workflow is unavailable."
_TTL_SECONDS = 600
_SENSOR_NAME = re.compile(
    r"mcp-v4-dlp-regexp-sensor-[A-Za-z0-9][A-Za-z0-9._-]{0,32}\Z"
)


class DlpRegexpSensorLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the fixed Regexp Sensor flow."""


class DlpRegexpSensorLiveWorkflowTransport(Protocol):
    """Exact fixed-Regexp Sensor preflight and create/readback contract."""

    def inspect_regexp_sensor(self, sensor_name: str) -> DlpRegexpSensorInspection: ...

    def create_regexp_and_readback(self, sensor_name: str) -> DlpRegexpSensorReadback: ...


@dataclass(frozen=True, slots=True)
class _DlpRegexpSensorRequest:
    sensor_name: str

    @classmethod
    def create(
        cls, *, sensor_name: str, name_pattern: re.Pattern[str] = _SENSOR_NAME,
    ) -> "_DlpRegexpSensorRequest":
        if not isinstance(sensor_name, str) or name_pattern.fullmatch(sensor_name) is None:
            raise DlpRegexpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(sensor_name=sensor_name)


@dataclass(frozen=True, slots=True)
class _DlpRegexpSensorRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    sensor_name: str
    current_digest: str
    state: str
    expires_at: int


class DlpRegexpSensorLiveWorkflow:
    """Volatile one-confirmation flow for one fixed laboratory Regexp Sensor."""

    _name_pattern = _SENSOR_NAME
    _preview_ref_prefix = "dlp-regexp-sensor-preview-"
    _authorization_ref_prefix = "dlp-regexp-sensor-authorized-"
    _workflow_contract = WORKFLOW_CONTRACT
    _execution_contract = "fortipam_v4_dlp_regexp_sensor_create_execution_v1"

    def __init__(
        self,
        transport: DlpRegexpSensorLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _DlpRegexpSensorRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        sensor_name: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read current state and render C/P/E without a device write."""

        request = _DlpRegexpSensorRequest.create(
            sensor_name=sensor_name, name_pattern=self._name_pattern,
        )
        _require_requester(requester_digest)
        current = self._inspect(request)
        if current.sensor_name_exists:
            raise DlpRegexpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _DlpRegexpSensorRecord(
            preview_ref=self._preview_ref_prefix + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            sensor_name=request.sensor_name,
            current_digest=self._current_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record, current)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm unchanged state and issue one execution reference."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect(_request_from_record(record))
            self._validate_record(record, requester_digest, "previewed")
            if self._current_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise DlpRegexpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = self._authorization_ref_prefix + secrets.token_urlsafe(24)
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
        """Create exactly the confirmed Sensor and return categorical readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(_request_from_record(record))
            self._validate_record(record, requester_digest, "authorized")
            if self._current_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise DlpRegexpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._create_confirmed_and_readback(record)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, DlpRegexpSensorReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _create_and_readback(self, sensor_name: str) -> DlpRegexpSensorReadback:
        return self._transport.create_regexp_and_readback(sensor_name)

    def _create_confirmed_and_readback(
        self, record: _DlpRegexpSensorRecord,
    ) -> DlpRegexpSensorReadback:
        return self._create_and_readback(record.sensor_name)

    @staticmethod
    def _current_digest(current: DlpRegexpSensorInspection) -> str:
        return _inspection_digest(current)

    def _inspect(
        self,
        request: _DlpRegexpSensorRequest,
    ) -> DlpRegexpSensorInspection:
        try:
            result = self._transport.inspect_regexp_sensor(request.sensor_name)
        except Exception as exc:
            raise DlpRegexpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, DlpRegexpSensorInspection):
            raise DlpRegexpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _DlpRegexpSensorRecord:
        if not _valid_ref(preview_ref, self._preview_ref_prefix):
            raise DlpRegexpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise DlpRegexpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _DlpRegexpSensorRecord:
        if not _valid_ref(authorization_ref, self._authorization_ref_prefix):
            raise DlpRegexpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise DlpRegexpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _DlpRegexpSensorRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise DlpRegexpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _DlpRegexpSensorRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise DlpRegexpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise DlpRegexpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(
        cls,
        record: _DlpRegexpSensorRecord,
        current: DlpRegexpSensorInspection,
    ) -> dict[str, object]:
        return {
            "contract": cls._workflow_contract,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_sensor_name": record.sensor_name,
                "sensor_name_exists": current.sensor_name_exists,
            },
            "Proposed Changes": {
                "operation": "create_single_http_get_file_regexp_block_dlp_sensor",
                "sensor_name": record.sensor_name,
                "configuration_profile": DLP_REGEXP_SENSOR_PROFILE,
                "protocol": "http-get",
                "filter_type": "file",
                "filter_by": "regexp",
                "regexp_pattern_class": "fixed_lab_sentinel",
                "regexp_value_returned": False,
                "action": "block",
                "dlp_secret_association_changes": False,
            },
            "Expected State": {
                "sensor_name_matches": True,
                "sensor_name_exists": True,
                "filter_id_exists": True,
                "filter_name_matches": True,
                "filter_type_matches": True,
                "protocol_matches": True,
                "filter_by_matches": True,
                "regexp_matches": True,
                "action_matches": True,
                "dlp_secret_association_changes": False,
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _DlpRegexpSensorRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": self._execution_contract,
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "not_requested",
            "dlp_secret_association_changes": False,
            "regexp_value_returned": False,
            "raw_cli_returned": False,
        }


def _request_from_record(record: _DlpRegexpSensorRecord) -> _DlpRegexpSensorRequest:
    return _DlpRegexpSensorRequest(sensor_name=record.sensor_name)


def _inspection_digest(inspection: DlpRegexpSensorInspection) -> str:
    payload = json.dumps(
        {"sensor_name_exists": inspection.sensor_name_exists},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _require_requester(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DlpRegexpSensorLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return isinstance(value, str) and value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "DlpRegexpSensorLiveWorkflow",
    "DlpRegexpSensorLiveWorkflowError",
    "DlpRegexpSensorLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
