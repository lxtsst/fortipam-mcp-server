"""One confirmation-gated recovery for the accepted b57/b66 assignment."""

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

from .schedule_assign_contract import (
    ScheduleDetachInspection,
    ScheduleDetachReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_schedule_assign_detach_api_workflow_v1"
EXECUTION_CONTRACT = "fortipam_v4_schedule_assign_detach_api_execution_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Schedule assignment recovery is unavailable."
_TTL_SECONDS = 600


class ScheduleAssignDetachLiveWorkflowError(RuntimeError):
    """Stable non-disclosing fixed recovery failure."""


class ScheduleAssignDetachTransport(Protocol):
    def inspect_fixed_detach(self) -> ScheduleDetachInspection: ...

    def detach_fixed_and_readback(
        self,
        *,
        expected_user_record_digest: str,
        expected_user_non_schedule_state_digest: str,
        expected_schedule_state_digest: str,
    ) -> ScheduleDetachReadback: ...


@dataclass(frozen=True, slots=True)
class _Record:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    current_digest: str
    user_record_digest: str
    user_non_schedule_state_digest: str
    schedule_state_digest: str
    state: str
    expires_at: int


class ScheduleAssignDetachLiveWorkflow:
    """Volatile one-confirmation flow for only the accepted assignment."""

    def __init__(
        self,
        transport: ScheduleAssignDetachTransport,
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
        if not current.eligible:
            raise ScheduleAssignDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _Record(
            preview_ref="schedule-assign-detach-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            current_digest=_inspection_digest(current),
            user_record_digest=current.user_record_digest,
            user_non_schedule_state_digest=(
                current.user_non_schedule_state_digest
            ),
            schedule_state_digest=current.schedule_state_digest,
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
                _inspection_digest(current), record.current_digest
            ):
                self._records[record.preview_ref] = replace(
                    record, state="invalidated"
                )
                raise ScheduleAssignDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = (
                "schedule-assign-detach-authorized-" + secrets.token_urlsafe(24)
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
                _inspection_digest(current), record.current_digest
            ):
                self._records[record.preview_ref] = replace(
                    record, state="invalidated"
                )
                raise ScheduleAssignDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.detach_fixed_and_readback(
                expected_user_record_digest=record.user_record_digest,
                expected_user_non_schedule_state_digest=(
                    record.user_non_schedule_state_digest
                ),
                expected_schedule_state_digest=record.schedule_state_digest,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed"
                if isinstance(readback, ScheduleDetachReadback) and readback.verified
                else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self) -> ScheduleDetachInspection:
        try:
            result = self._transport.inspect_fixed_detach()
        except Exception as exc:
            raise ScheduleAssignDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, ScheduleDetachInspection):
            raise ScheduleAssignDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _Record:
        if not _valid_ref(preview_ref, "schedule-assign-detach-preview-"):
            raise ScheduleAssignDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise ScheduleAssignDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _Record:
        if not _valid_ref(
            authorization_ref, "schedule-assign-detach-authorized-"
        ):
            raise ScheduleAssignDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise ScheduleAssignDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _Record,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise ScheduleAssignDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _Record, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise ScheduleAssignDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise ScheduleAssignDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
                "fixed_schedule_assignment_exists": True,
                "user_disabled": True,
                "user_local": True,
                "fixed_role_preserved": True,
                "complete_user_record_digest_matches": True,
                "complete_schedule_record_digest_matches": True,
                "schedule_rest_and_ssh_projection_matches": True,
                "schedule_reference_count": 1,
                "only_fixed_user_references_schedule": True,
                "read_transports": ["rest_api", "ssh_cli"],
            },
            "Proposed Changes": {
                "operation": "detach_fixed_login_schedule_via_api",
                "user_count_affected": 1,
                "request_body": "product_ui_existing_user_projection_schedule_only_clear",
                "password_mfa_trust_or_role_change": False,
                "effective_login_or_session_effect": False,
            },
            "Expected State": {
                "fixed_user_schedule_unassigned": True,
                "all_non_schedule_user_state_preserved": True,
                "fixed_role_preserved": True,
                "complete_schedule_preserved": True,
                "schedule_reference_count": 0,
                "readback_transports": ["rest_api", "ssh_cli"],
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _Record,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": EXECUTION_CONTRACT,
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_schedule_assignment_action_required",
            "user_or_schedule_identifier_returned": False,
            "non_schedule_user_state_preserved": succeeded,
            "schedule_preserved": succeeded,
            "schedule_reference_count": 0 if succeeded else -1,
            "password_mfa_trust_or_role_change": False,
            "effective_login_or_session_effect": False,
            "raw_api_or_cli_response_returned": False,
        }


def _inspection_digest(inspection: ScheduleDetachInspection) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "eligible": inspection.eligible,
                "schedule_reference_count": inspection.schedule_reference_count,
                "only_fixed_user_references_schedule": (
                    inspection.only_fixed_user_references_schedule
                ),
                "user_record_digest": inspection.user_record_digest,
                "user_non_schedule_state_digest": (
                    inspection.user_non_schedule_state_digest
                ),
                "schedule_state_digest": inspection.schedule_state_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()


def _require_requester(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ScheduleAssignDetachLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and value.isascii()
        and len(value) <= 128
    )


def _now() -> int:
    return int(time.time())


__all__ = [
    "EXECUTION_CONTRACT",
    "ScheduleAssignDetachLiveWorkflow",
    "ScheduleAssignDetachLiveWorkflowError",
    "ScheduleAssignDetachTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
