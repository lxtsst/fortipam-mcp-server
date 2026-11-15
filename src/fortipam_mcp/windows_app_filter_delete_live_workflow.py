"""One confirmation-gated recovery for an accepted Windows App Filter Profile."""

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

from .windows_app_filter_http_transport import (
    WindowsAppFilterDeleteInspection,
    WindowsAppFilterDeleteReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_windows_app_filter_delete_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Windows App Filter recovery is unavailable."
_TTL_SECONDS = 600


class WindowsAppFilterDeleteLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the fixed recovery workflow."""


class WindowsAppFilterDeleteLiveWorkflowTransport(Protocol):
    """Exact accepted-target preflight and DELETE/absence contract."""

    def inspect_delete_target(self) -> WindowsAppFilterDeleteInspection: ...

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> WindowsAppFilterDeleteReadback: ...


@dataclass(frozen=True, slots=True)
class _Record:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    current_digest: str
    target_digest: str
    state: str
    expires_at: int


class WindowsAppFilterDeleteLiveWorkflow:
    """Volatile one-confirmation flow for the exact unreferenced b27 target."""

    def __init__(
        self,
        transport: WindowsAppFilterDeleteLiveWorkflowTransport,
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
            or not current.eligible_fixed_profile
            or current.secret_reference_count != 0
        ):
            raise WindowsAppFilterDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _Record(
            preview_ref=(
                "windows-app-filter-delete-preview-" + secrets.token_urlsafe(24)
            ),
            authorization_ref=None,
            requester_digest=requester_digest,
            current_digest=_inspection_digest(current),
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
            if not hmac.compare_digest(
                _inspection_digest(current),
                record.current_digest,
            ):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise WindowsAppFilterDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = (
                "windows-app-filter-delete-authorized-" + secrets.token_urlsafe(24)
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
                raise WindowsAppFilterDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.delete_and_readback(record.target_digest)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed"
                if isinstance(readback, WindowsAppFilterDeleteReadback)
                and readback.verified
                else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self) -> WindowsAppFilterDeleteInspection:
        try:
            result = self._transport.inspect_delete_target()
        except Exception as exc:
            raise WindowsAppFilterDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, WindowsAppFilterDeleteInspection):
            raise WindowsAppFilterDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _Record:
        if not _valid_ref(preview_ref, "windows-app-filter-delete-preview-"):
            raise WindowsAppFilterDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise WindowsAppFilterDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _Record:
        if not _valid_ref(
            authorization_ref,
            "windows-app-filter-delete-authorized-",
        ):
            raise WindowsAppFilterDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise WindowsAppFilterDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _Record,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise WindowsAppFilterDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _Record, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise WindowsAppFilterDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise WindowsAppFilterDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
                "accepted_windows_app_filter_profile_exists": True,
                "exact_fixed_empty_profile_observed": True,
                "secret_reference_count": 0,
                "read_transport": "rest_api",
            },
            "Proposed Changes": {
                "operation": "delete_exact_unreferenced_windows_app_filter_profile_via_api",
                "windows_app_filter_profile_count_affected": 1,
                "irreversible_after_execution": True,
                "filter_or_exception_changes": False,
                "secret_target_or_policy_association_changes": False,
            },
            "Expected State": {
                "accepted_windows_app_filter_profile_absent": True,
                "filter_or_exception_changes": False,
                "secret_target_or_policy_association_changes": False,
                "readback_transport": "rest_api",
            },
            "device_write_executed": False,
        }

    def _result(self, record: _Record, *, idempotent_replay: bool) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_windows_app_filter_delete_api_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_windows_app_filter_create_action_required",
            "irreversible_after_execution": True,
            "windows_app_filter_profile_name_returned": False,
            "filter_or_exception_content_returned": False,
            "secret_target_or_policy_association_changes": False,
            "raw_api_response_returned": False,
        }


def _inspection_digest(inspection: WindowsAppFilterDeleteInspection) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "exists": inspection.exists,
                "eligible_fixed_profile": inspection.eligible_fixed_profile,
                "secret_reference_count": inspection.secret_reference_count,
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
        raise WindowsAppFilterDeleteLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "WindowsAppFilterDeleteLiveWorkflow",
    "WindowsAppFilterDeleteLiveWorkflowError",
    "WindowsAppFilterDeleteLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
