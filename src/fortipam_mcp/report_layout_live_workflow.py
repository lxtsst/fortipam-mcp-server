"""One confirmation-gated FortiPAM Report Layout create workflow."""

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

from .report_layout_http_transport import (
    REPORT_LAYOUT_NAME_PREFIX,
    ReportLayoutInspection,
    ReportLayoutReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_report_layout_create_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Report Layout action is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"MCPV4Report[A-Za-z0-9]{1,36}\Z")


class ReportLayoutLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded workflow."""


class ReportLayoutLiveWorkflowTransport(Protocol):
    """Exact Report Layout preflight and create/readback contract."""

    def inspect(self, name: str) -> ReportLayoutInspection: ...

    def create_and_readback(
        self, name: str, expected_default_digest: str
    ) -> ReportLayoutReadback: ...


@dataclass(frozen=True, slots=True)
class _ReportLayoutRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    name: str
    current_digest: str
    default_digest: str
    state: str
    expires_at: int


class ReportLayoutCreateLiveWorkflow:
    """Volatile one-confirmation flow for one bounded default-layout clone."""

    def __init__(
        self,
        transport: ReportLayoutLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _ReportLayoutRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, name: str, requester_digest: str) -> dict[str, object]:
        safe_name = _name(name)
        _require_requester(requester_digest)
        current = self._inspect(safe_name)
        if current.exists or not current.default_eligible:
            raise ReportLayoutLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _ReportLayoutRecord(
            preview_ref="report-layout-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            name=safe_name,
            current_digest=_inspection_digest(safe_name, current),
            default_digest=current.default_digest,
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
            current = self._inspect(record.name)
            if not hmac.compare_digest(
                _inspection_digest(record.name, current), record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ReportLayoutLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "report-layout-authorized-" + secrets.token_urlsafe(24)
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
            current = self._inspect(record.name)
            if not hmac.compare_digest(
                _inspection_digest(record.name, current), record.current_digest
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ReportLayoutLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.create_and_readback(
                record.name,
                record.default_digest,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed"
                if isinstance(readback, ReportLayoutReadback) and readback.verified
                else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, name: str) -> ReportLayoutInspection:
        try:
            result = self._transport.inspect(name)
        except Exception as exc:
            raise ReportLayoutLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, ReportLayoutInspection):
            raise ReportLayoutLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _ReportLayoutRecord:
        if not _valid_ref(preview_ref, "report-layout-preview-"):
            raise ReportLayoutLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise ReportLayoutLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _ReportLayoutRecord:
        if not _valid_ref(authorization_ref, "report-layout-authorized-"):
            raise ReportLayoutLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise ReportLayoutLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _ReportLayoutRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise ReportLayoutLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _ReportLayoutRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise ReportLayoutLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise ReportLayoutLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(record: _ReportLayoutRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_report_layout_name": record.name,
                "report_layout_exists": False,
                "eligible_default_layout_observed": True,
                "write_transport": "rest_api",
            },
            "Proposed Changes": {
                "operation": "create_bounded_default_report_layout_clone_via_api",
                "report_layout_name": record.name,
                "schedule": "daily_at_00_00",
                "format": "pdf",
                "email_delivery": "disabled",
                "report_filters": "none",
                "report_generation_requested": False,
            },
            "Expected State": {
                "report_layout_exists": True,
                "default_clone_matches": True,
                "daily_schedule_matches": True,
                "email_delivery_disabled": True,
                "report_filters_absent": True,
                "report_content_returned": False,
                "readback_transport": "rest_api",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _ReportLayoutRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_report_layout_create_api_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_report_layout_delete_action_required",
            "report_layout_name_returned": False,
            "report_content_returned": False,
            "email_delivery_enabled": False,
            "report_generation_requested": False,
            "raw_api_response_returned": False,
        }


def _inspection_digest(name: str, inspection: ReportLayoutInspection) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "name": name,
                "exists": inspection.exists,
                "default_eligible": inspection.default_eligible,
                "default_digest": inspection.default_digest,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise ReportLayoutLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ReportLayoutLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "REPORT_LAYOUT_NAME_PREFIX",
    "ReportLayoutCreateLiveWorkflow",
    "ReportLayoutLiveWorkflowError",
    "ReportLayoutLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
