"""One confirmation-gated FortiPAM Secret Audit report-generation workflow."""

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

from .secret_audit_ssh_transport import (
    SECRET_AUDIT_CONFIGURATION,
    SecretAuditInspection,
    SecretAuditReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_secret_audit_generate_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Secret Audit action is unavailable."
_TTL_SECONDS = 600


class SecretAuditLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded report workflow."""


class SecretAuditLiveWorkflowTransport(Protocol):
    """Fixed Secret Audit preflight and generated-report readback contract."""

    def inspect(self) -> SecretAuditInspection: ...

    def generate_and_readback(self) -> SecretAuditReadback: ...


@dataclass(frozen=True, slots=True)
class _SecretAuditRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    current_digest: str
    state: str
    expires_at: int


class SecretAuditGenerateLiveWorkflow:
    """Volatile C/P/E flow for one redacted Secret Audit report generation."""

    def __init__(
        self,
        transport: SecretAuditLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _SecretAuditRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        """Validate a live fixed CLI session and render C/P/E without generation."""

        _require_requester(requester_digest)
        current = self._inspect()
        if not current.exact_current_state:
            raise SecretAuditLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _SecretAuditRecord(
            preview_ref="secret-audit-preview-" + secrets.token_urlsafe(24),
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
        """Confirm one unchanged live CLI preflight and issue one execution reference."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect()
            if (
                not current.exact_current_state
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise SecretAuditLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "secret-audit-authorized-" + secrets.token_urlsafe(24)
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
        """Generate only the confirmed report and return categorical readback evidence."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect()
            if (
                not current.exact_current_state
                or _inspection_digest(current) != record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise SecretAuditLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.generate_and_readback()
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, SecretAuditReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self) -> SecretAuditInspection:
        try:
            current = self._transport.inspect()
        except Exception as exc:
            raise SecretAuditLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(current, SecretAuditInspection):
            raise SecretAuditLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return current

    def _record_for_preview_locked(self, preview_ref: str) -> _SecretAuditRecord:
        if not _valid_ref(preview_ref, "secret-audit-preview-"):
            raise SecretAuditLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise SecretAuditLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _SecretAuditRecord:
        if not _valid_ref(authorization_ref, "secret-audit-authorized-"):
            raise SecretAuditLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise SecretAuditLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _SecretAuditRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise SecretAuditLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _SecretAuditRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise SecretAuditLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise SecretAuditLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
        record: _SecretAuditRecord,
        current: SecretAuditInspection,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "fixed_cli_preflight_reachable": current.cli_reachable,
                "report_inventory_read": current.report_inventory_read,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "generate_secret_access_audit_report_via_cli_fallback",
                "configuration_profile": SECRET_AUDIT_CONFIGURATION,
                "caller_controlled_report_scope": False,
                "report_content_returned": False,
                "report_name_returned": False,
                "identity_target_folder_secret_data_returned": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "report_generation_command_completed": True,
                "generated_report_name_observed_internally": True,
                "report_content_returned": False,
                "report_name_returned": False,
                "identity_target_folder_secret_data_returned": False,
                "readback_transport": (
                    "rest_inventory_delta"
                    if current.report_inventory_read
                    else "ssh_cli"
                ),
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _SecretAuditRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_secret_audit_generate_cli_fallback_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "report-retention-management-is-a-separate-action",
            "report_generation_command_completed": succeeded,
            "report_content_returned": False,
            "report_name_returned": False,
            "identity_target_folder_secret_data_returned": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: SecretAuditInspection) -> str:
    payload = json.dumps(
        {
            "cli_reachable": inspection.cli_reachable,
            "report_inventory_read": inspection.report_inventory_read,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise SecretAuditLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "SecretAuditGenerateLiveWorkflow",
    "SecretAuditLiveWorkflowError",
    "SecretAuditLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
