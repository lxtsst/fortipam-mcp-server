"""One confirmation-gated FortiPAM FortiAnalyzer delivery enable workflow."""

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

from .fortianalyzer_ssh_transport import (
    FORTIANALYZER_CONFIGURATION,
    FortiAnalyzerInspection,
    FortiAnalyzerReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_fortianalyzer_enable_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 FortiAnalyzer action is unavailable."
_TTL_SECONDS = 600


class FortiAnalyzerLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded FortiAnalyzer workflow."""


class FortiAnalyzerLiveWorkflowTransport(Protocol):
    """Fixed FortiAnalyzer inspection and enable/readback contract."""

    def inspect(self) -> FortiAnalyzerInspection: ...

    def enable_and_readback(
        self,
        *,
        expected_server_binding_digest: str,
    ) -> FortiAnalyzerReadback: ...


@dataclass(frozen=True, slots=True)
class _FortiAnalyzerRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    current_digest: str
    server_binding_digest: str
    state: str
    expires_at: int


class FortiAnalyzerLiveWorkflow:
    """Volatile C/P/E flow for one preconfigured FortiAnalyzer enable transition."""

    def __init__(
        self,
        transport: FortiAnalyzerLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _FortiAnalyzerRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        """Read an unchanged preconfigured disabled baseline without a write."""

        _require_requester(requester_digest)
        current = self._inspect()
        if not current.exact_disabled_baseline or current.server_binding_digest is None:
            raise FortiAnalyzerLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _FortiAnalyzerRecord(
            preview_ref="fortianalyzer-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            current_digest=_inspection_digest(current),
            server_binding_digest=current.server_binding_digest,
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
                not current.exact_disabled_baseline
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise FortiAnalyzerLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "fortianalyzer-authorized-" + secrets.token_urlsafe(24)
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
        """Enable only the confirmed FortiAnalyzer delivery status."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect()
            if (
                not current.exact_disabled_baseline
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise FortiAnalyzerLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.enable_and_readback(
                expected_server_binding_digest=record.server_binding_digest
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if (
            not isinstance(readback, FortiAnalyzerReadback)
            or readback.server_binding_digest is None
            or not hmac.compare_digest(
                readback.server_binding_digest,
                record.server_binding_digest,
            )
        ):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self) -> FortiAnalyzerInspection:
        try:
            current = self._transport.inspect()
        except Exception as exc:
            raise FortiAnalyzerLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(current, FortiAnalyzerInspection):
            raise FortiAnalyzerLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return current

    def _record_for_preview_locked(self, preview_ref: str) -> _FortiAnalyzerRecord:
        if not _valid_ref(preview_ref, "fortianalyzer-preview-"):
            raise FortiAnalyzerLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise FortiAnalyzerLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _FortiAnalyzerRecord:
        if not _valid_ref(authorization_ref, "fortianalyzer-authorized-"):
            raise FortiAnalyzerLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise FortiAnalyzerLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _FortiAnalyzerRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise FortiAnalyzerLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _FortiAnalyzerRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise FortiAnalyzerLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise FortiAnalyzerLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
        record: _FortiAnalyzerRecord,
        current: FortiAnalyzerInspection,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "fortianalyzer_delivery_status": current.status,
                "configured_server_present": current.server_configured,
                "server_configuration_changed": False,
                "upload_schedule_changed": False,
                "certificate_or_authorization_changed": False,
                "connectivity_test_executed": False,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "enable_existing_fortianalyzer_delivery_via_cli_fallback",
                "configuration_profile": FORTIANALYZER_CONFIGURATION,
                "fortianalyzer_delivery_status": "enable",
                "configured_server_present": True,
                "server_configuration_changed": False,
                "upload_schedule_changed": False,
                "certificate_or_authorization_changed": False,
                "connectivity_test_executed": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "fortianalyzer_delivery_status": "enable",
                "configured_server_present": True,
                "server_configuration_changed": False,
                "upload_schedule_changed": False,
                "certificate_or_authorization_changed": False,
                "end_to_end_delivery_verified": False,
                "readback_transport": "ssh_cli",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _FortiAnalyzerRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_fortianalyzer_enable_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_fortianalyzer_disable_action_required",
            "fortianalyzer_delivery_status": "enable" if succeeded else "unknown",
            "configured_server_present": True if succeeded else "unknown",
            "server_configuration_changed": False,
            "upload_schedule_changed": False,
            "certificate_or_authorization_changed": False,
            "end_to_end_delivery_verified": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: FortiAnalyzerInspection) -> str:
    payload = json.dumps(
        {
            "status": inspection.status,
            "server_binding_digest": inspection.server_binding_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise FortiAnalyzerLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "FortiAnalyzerLiveWorkflow",
    "FortiAnalyzerLiveWorkflowError",
    "FortiAnalyzerLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
