"""One confirmation-gated recovery for the accepted b32 DLP File Pattern."""

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

from .dlp_file_pattern_delete_http_transport import (
    DlpFilePatternDeleteInspection,
    DlpFilePatternDeleteReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_dlp_file_pattern_delete_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 DLP File Pattern recovery is unavailable."
_TTL_SECONDS = 600


class DlpFilePatternDeleteLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing fixed recovery failure."""


class DlpFilePatternDeleteLiveWorkflowTransport(Protocol):
    """Exact accepted-target preflight and DELETE/readback contract."""

    def inspect_delete_target(self) -> DlpFilePatternDeleteInspection: ...

    def delete_and_readback(
        self,
        expected_target_digest: str,
        expected_regexp_sensor_digest: str,
    ) -> DlpFilePatternDeleteReadback: ...


@dataclass(frozen=True, slots=True)
class _Record:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    current_digest: str
    target_digest: str
    regexp_sensor_digest: str
    state: str
    expires_at: int


class DlpFilePatternDeleteLiveWorkflow:
    """Volatile one-confirmation flow for the exact unreferenced b32 target."""

    def __init__(
        self,
        transport: DlpFilePatternDeleteLiveWorkflowTransport,
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
            or not current.eligible_fixed_pattern
            or current.sensor_reference_count_rest != 0
            or current.sensor_reference_count_ssh != 0
        ):
            raise DlpFilePatternDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _Record(
            preview_ref="dlp-file-pattern-delete-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            current_digest=_inspection_digest(current),
            target_digest=current.target_digest,
            regexp_sensor_digest=current.regexp_sensor_digest,
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
            if not hmac.compare_digest(
                _inspection_digest(current),
                record.current_digest,
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise DlpFilePatternDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = (
                "dlp-file-pattern-delete-authorized-" + secrets.token_urlsafe(24)
            )
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
        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect()
            if not hmac.compare_digest(
                _inspection_digest(current),
                record.current_digest,
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise DlpFilePatternDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.delete_and_readback(
                record.target_digest,
                record.regexp_sensor_digest,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed"
                if isinstance(readback, DlpFilePatternDeleteReadback)
                and readback.verified
                else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self) -> DlpFilePatternDeleteInspection:
        try:
            result = self._transport.inspect_delete_target()
        except Exception as exc:
            raise DlpFilePatternDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, DlpFilePatternDeleteInspection):
            raise DlpFilePatternDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _Record:
        if not _valid_ref(preview_ref, "dlp-file-pattern-delete-preview-"):
            raise DlpFilePatternDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise DlpFilePatternDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _Record:
        if not _valid_ref(
            authorization_ref,
            "dlp-file-pattern-delete-authorized-",
        ):
            raise DlpFilePatternDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise DlpFilePatternDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _Record,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise DlpFilePatternDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _Record, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise DlpFilePatternDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise DlpFilePatternDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(record: _Record) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "accepted_dlp_file_pattern_exists": True,
                "exact_fixed_single_pdf_pattern_observed": True,
                "complete_api_record_digest_matches": True,
                "sensor_reference_count_rest": 0,
                "sensor_reference_count_ssh": 0,
                "fixed_regexp_sensor_present": True,
                "read_transports": ["rest_api", "ssh_cli"],
            },
            "Proposed Changes": {
                "operation": "delete_exact_unreferenced_dlp_file_pattern_via_api",
                "dlp_file_pattern_count_affected": 1,
                "irreversible_after_execution": True,
                "dlp_sensor_changes": False,
                "secret_or_policy_association_changes": False,
                "license_or_session_changes": False,
            },
            "Expected State": {
                "accepted_dlp_file_pattern_absent": True,
                "fixed_regexp_sensor_preserved": True,
                "dlp_sensor_changes": False,
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
            "contract": "fortipam_v4_dlp_file_pattern_delete_api_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_dlp_file_pattern_create_action_required",
            "irreversible_after_execution": True,
            "dlp_file_pattern_id_or_name_returned": False,
            "profile_content_returned": False,
            "dlp_sensor_changes": False,
            "secret_or_policy_association_changes": False,
            "license_or_session_changes": False,
            "raw_api_or_cli_response_returned": False,
        }


def _inspection_digest(inspection: DlpFilePatternDeleteInspection) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "exists": inspection.exists,
                "eligible_fixed_pattern": inspection.eligible_fixed_pattern,
                "sensor_reference_count_rest": inspection.sensor_reference_count_rest,
                "sensor_reference_count_ssh": inspection.sensor_reference_count_ssh,
                "target_digest": inspection.target_digest,
                "regexp_sensor_digest": inspection.regexp_sensor_digest,
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
        raise DlpFilePatternDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "DlpFilePatternDeleteLiveWorkflow",
    "DlpFilePatternDeleteLiveWorkflowError",
    "DlpFilePatternDeleteLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
