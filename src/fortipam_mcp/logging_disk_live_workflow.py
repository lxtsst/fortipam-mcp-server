"""One confirmation-gated FortiPAM disk-logging disable workflow."""

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

from .logging_disk_ssh_transport import (
    LOGGING_DISK_CONFIGURATION,
    LoggingDiskInspection,
    LoggingDiskReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_logging_disk_disable_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 logging-disk action is unavailable."
_TTL_SECONDS = 600


class LoggingDiskLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded logging-disk workflow."""


class LoggingDiskLiveWorkflowTransport(Protocol):
    """Fixed logging-disk inspection and disable/readback contract."""

    def inspect(self) -> LoggingDiskInspection: ...

    def disable_and_readback(self) -> LoggingDiskReadback: ...


@dataclass(frozen=True, slots=True)
class _LoggingDiskRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    current_digest: str
    state: str
    expires_at: int


class LoggingDiskLiveWorkflow:
    """Volatile C/P/E flow for one documented disk-logging disable transition."""

    def __init__(
        self,
        transport: LoggingDiskLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _LoggingDiskRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        """Read the exact enabled-memory/enabled-disk baseline without a write."""

        _require_requester(requester_digest)
        current = self._inspect()
        if not current.exact_disable_baseline:
            raise LoggingDiskLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _LoggingDiskRecord(
            preview_ref="logging-disk-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            current_digest=_inspection_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record, current)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm unchanged baseline and issue one execution reference."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect()
            if (
                not current.exact_disable_baseline
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise LoggingDiskLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "logging-disk-authorized-" + secrets.token_urlsafe(24)
            updated = replace(record, authorization_ref=authorization_ref, state="authorized")
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
        """Disable only confirmed disk logging and categorize fixed readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect()
            if (
                not current.exact_disable_baseline
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise LoggingDiskLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.disable_and_readback()
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, LoggingDiskReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self) -> LoggingDiskInspection:
        try:
            current = self._transport.inspect()
        except Exception as exc:
            raise LoggingDiskLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(current, LoggingDiskInspection):
            raise LoggingDiskLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return current

    def _record_for_preview_locked(self, preview_ref: str) -> _LoggingDiskRecord:
        if not _valid_ref(preview_ref, "logging-disk-preview-"):
            raise LoggingDiskLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise LoggingDiskLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _LoggingDiskRecord:
        if not _valid_ref(authorization_ref, "logging-disk-authorized-"):
            raise LoggingDiskLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise LoggingDiskLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _LoggingDiskRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise LoggingDiskLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _LoggingDiskRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise LoggingDiskLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise LoggingDiskLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._records[preview_ref] = replace(record, state=state)

    def _purge_expired_locked(self) -> None:
        now_epoch = self._clock()
        expired = [
            preview_ref
            for preview_ref, record in self._records.items()
            if record.expires_at <= now_epoch and record.state != "completed"
        ]
        for preview_ref in expired:
            record = self._records.pop(preview_ref)
            if record.authorization_ref is not None:
                self._authorization_index.pop(record.authorization_ref, None)

    @staticmethod
    def _preview_projection(
        record: _LoggingDiskRecord,
        current: LoggingDiskInspection,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "memory_log_status": current.memory_status,
                "disk_log_status": current.disk_status,
                "remote_syslog_configuration_changed": False,
                "event_logging_configuration_changed": False,
                "disk_encryption_changed": False,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "disable_disk_logging_via_cli_fallback",
                "configuration_profile": LOGGING_DISK_CONFIGURATION,
                "memory_log_status": "enable",
                "disk_log_status": "disable",
                "remote_syslog_configuration_changed": False,
                "event_logging_configuration_changed": False,
                "disk_encryption_changed": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "memory_log_status": "enable",
                "disk_log_status": "disable",
                "remote_syslog_configuration_changed": False,
                "event_logging_configuration_changed": False,
                "disk_encryption_changed": False,
                "logging_effect_verified": False,
                "readback_transport": "ssh_cli",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _LoggingDiskRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_logging_disk_disable_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_logging_disk_enable_action_required",
            "memory_log_status": "enable" if succeeded else "unknown",
            "disk_log_status": "disable" if succeeded else "unknown",
            "remote_syslog_configuration_changed": False,
            "event_logging_configuration_changed": False,
            "disk_encryption_changed": False,
            "logging_effect_verified": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: LoggingDiskInspection) -> str:
    payload = json.dumps(
        {
            "memory_status": inspection.memory_status,
            "disk_status": inspection.disk_status,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise LoggingDiskLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "LoggingDiskLiveWorkflow",
    "LoggingDiskLiveWorkflowError",
    "LoggingDiskLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
