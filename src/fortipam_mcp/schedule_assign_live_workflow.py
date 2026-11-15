"""One confirmation-gated Local User login-Schedule assignment workflow."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hmac
import re
import secrets
import threading
import time
from typing import Protocol

from .schedule_assign_contract import ScheduleAssignInspection, ScheduleAssignReadback


WORKFLOW_CONTRACT = "fortipam_v4_schedule_assign_api_workflow_v1"
EXECUTION_CONTRACT = "fortipam_v4_schedule_assign_api_execution_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Schedule assignment is unavailable."
_TTL_SECONDS = 600
_USER_NAME = re.compile(r"mcp-v4-user-[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")
_SCHEDULE_NAME = re.compile(r"mcp-v4-schedule-[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")


class ScheduleAssignLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded assignment workflow."""


class ScheduleAssignTransport(Protocol):
    """The exact User/Schedule preflight, write, and readback contract."""

    def inspect_assignment(
        self,
        username: str,
        schedule_name: str,
    ) -> ScheduleAssignInspection: ...

    def assign_and_readback(
        self,
        username: str,
        schedule_name: str,
        *,
        user_non_schedule_state_digest: str,
        schedule_state_digest: str,
    ) -> ScheduleAssignReadback: ...


@dataclass(frozen=True, slots=True)
class _ScheduleAssignRequest:
    username: str
    schedule_name: str

    @classmethod
    def create(cls, username: str, schedule_name: str) -> "_ScheduleAssignRequest":
        if (
            not isinstance(username, str)
            or _USER_NAME.fullmatch(username) is None
            or not isinstance(schedule_name, str)
            or _SCHEDULE_NAME.fullmatch(schedule_name) is None
        ):
            raise ScheduleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(username, schedule_name)


@dataclass(frozen=True, slots=True)
class _ScheduleAssignRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    request: _ScheduleAssignRequest
    current_digest: str
    user_non_schedule_state_digest: str
    schedule_state_digest: str
    state: str
    expires_at: int


class ScheduleAssignLiveWorkflow:
    """Volatile one-confirmation workflow for one disabled laboratory User."""

    def __init__(
        self,
        transport: ScheduleAssignTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _ScheduleAssignRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        username: str,
        schedule_name: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read live state and render the exact Current/Proposed/Expected plan."""

        request = _ScheduleAssignRequest.create(username, schedule_name)
        _require_requester(requester_digest)
        current = self._inspect(request)
        if not _eligible(current):
            raise ScheduleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _ScheduleAssignRecord(
            preview_ref="schedule-assign-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            request=request,
            current_digest=current.state_digest,
            user_non_schedule_state_digest=current.user_non_schedule_state_digest,
            schedule_state_digest=current.schedule_state_digest,
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Re-read one exact preview and authorize one execution."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            if not self._state_is_unchanged(record):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ScheduleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._validate_record(record, requester_digest, "previewed")
            authorization_ref = "schedule-assign-authorized-" + secrets.token_urlsafe(24)
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

    def execute(
        self,
        authorization_ref: str,
        *,
        requester_digest: str,
    ) -> dict[str, object]:
        """Execute once; uncertain results become non-retry reconciliation state."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            if not self._state_is_unchanged(record):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise ScheduleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._validate_record(record, requester_digest, "authorized")
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.assign_and_readback(
                record.request.username,
                record.request.schedule_name,
                user_non_schedule_state_digest=record.user_non_schedule_state_digest,
                schedule_state_digest=record.schedule_state_digest,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                (
                    "completed"
                    if isinstance(readback, ScheduleAssignReadback) and readback.verified
                    else "reconciliation_required"
                ),
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, request: _ScheduleAssignRequest) -> ScheduleAssignInspection:
        try:
            result = self._transport.inspect_assignment(
                request.username,
                request.schedule_name,
            )
        except Exception as exc:
            raise ScheduleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, ScheduleAssignInspection):
            raise ScheduleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _state_is_unchanged(self, record: _ScheduleAssignRecord) -> bool:
        current = self._inspect(record.request)
        return _eligible(current) and hmac.compare_digest(
            current.state_digest,
            record.current_digest,
        )

    def _record_for_preview_locked(self, preview_ref: str) -> _ScheduleAssignRecord:
        if not _valid_ref(preview_ref, "schedule-assign-preview-"):
            raise ScheduleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise ScheduleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _ScheduleAssignRecord:
        if not _valid_ref(authorization_ref, "schedule-assign-authorized-"):
            raise ScheduleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise ScheduleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _ScheduleAssignRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise ScheduleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _ScheduleAssignRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise ScheduleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise ScheduleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._records[preview_ref] = replace(record, state=state)

    def _purge_expired_locked(self) -> None:
        expired = [
            preview_ref
            for preview_ref, record in self._records.items()
            if record.expires_at <= self._clock() and record.state != "completed"
        ]
        for preview_ref in expired:
            record = self._records.pop(preview_ref)
            if record.authorization_ref is not None:
                self._authorization_index.pop(record.authorization_ref, None)

    @staticmethod
    def _preview_projection(record: _ScheduleAssignRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_username": record.request.username,
                "user_exists": True,
                "user_status": "disabled",
                "user_type": "local",
                "current_schedule_unassigned": True,
                "requested_schedule_name": record.request.schedule_name,
                "schedule_exists": True,
                "write_transport": "rest_api",
            },
            "Proposed Changes": {
                "operation": "assign_existing_login_schedule_to_disabled_local_user_via_api",
                "username": record.request.username,
                "schedule_name": record.request.schedule_name,
                "request_body": "product_ui_existing_user_projection_schedule_only_change",
            },
            "Expected State": {
                "user_exists": True,
                "schedule_exists": True,
                "user_remains_disabled": True,
                "user_remains_local": True,
                "schedule_matches": True,
                "user_non_schedule_state_preserved": True,
                "schedule_state_preserved": True,
                "readback_transport": "rest_api",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _ScheduleAssignRecord,
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
            "compensation": "separate_confirmed_login_schedule_change_required",
            "username_returned": False,
            "schedule_name_returned": False,
            "user_payload_returned": False,
            "schedule_payload_returned": False,
            "credential_material_returned": False,
            "raw_api_response_returned": False,
        }


def _eligible(inspection: ScheduleAssignInspection) -> bool:
    return (
        inspection.user_exists
        and inspection.schedule_exists
        and inspection.user_disabled
        and inspection.user_local
        and inspection.schedule_unassigned
    )


def _require_requester(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ScheduleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and value.isascii()
        and len(value) <= 160
    )


def _now() -> int:
    return int(time.time())


__all__ = [
    "EXECUTION_CONTRACT",
    "ScheduleAssignLiveWorkflow",
    "ScheduleAssignLiveWorkflowError",
    "ScheduleAssignTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
