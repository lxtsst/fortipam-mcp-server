"""One live, confirmation-gated FortiPAM laboratory Role-assignment workflow."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hmac
import re
import secrets
import threading
import time
from typing import Protocol

from .role_assign_http_transport import RoleAssignInspection, RoleAssignReadback


WORKFLOW_CONTRACT = "fortipam_v4_role_assign_api_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Role assignment workflow is unavailable."
_TTL_SECONDS = 600
_USER_NAME = re.compile(r"mcp-v4-user-[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")
_ROLE_NAME = re.compile(r"mcp-v4-role-[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")


class RoleAssignLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded Role-assignment flow."""


class RoleAssignLiveWorkflowTransport(Protocol):
    """The exact user/Role preflight and assignment/readback contract."""

    def inspect_assignment(self, username: str, role_name: str) -> RoleAssignInspection: ...

    def assign_and_readback(self, username: str, role_name: str) -> RoleAssignReadback: ...


@dataclass(frozen=True, slots=True)
class _RoleAssignRequest:
    username: str
    role_name: str

    @classmethod
    def create(cls, username: str, role_name: str) -> "_RoleAssignRequest":
        if (
            not isinstance(username, str)
            or _USER_NAME.fullmatch(username) is None
            or not isinstance(role_name, str)
            or _ROLE_NAME.fullmatch(role_name) is None
        ):
            raise RoleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(username=username, role_name=role_name)


@dataclass(frozen=True, slots=True)
class _RoleAssignRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    username: str
    role_name: str
    current_digest: str
    state: str
    expires_at: int


class RoleAssignLiveWorkflow:
    """Volatile one-confirmation workflow for one disabled laboratory user."""

    def __init__(
        self,
        transport: RoleAssignLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _RoleAssignRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        username: str,
        role_name: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read live state and return the exact Current/Proposed/Expected plan."""

        request = _RoleAssignRequest.create(username, role_name)
        _require_requester(requester_digest)
        current = self._inspect(request)
        if (
            not current.user_exists
            or not current.role_exists
            or not current.user_disabled
            or current.assignment_matches
        ):
            raise RoleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _RoleAssignRecord(
            preview_ref="role-assign-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            username=request.username,
            role_name=request.role_name,
            current_digest=current.state_digest,
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm a still-current user/Role assignment preview once."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            if not self._state_is_unchanged(record):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise RoleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._validate_record(record, requester_digest, "previewed")
            authorization_ref = "role-assign-authorized-" + secrets.token_urlsafe(24)
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
        """Perform one confirmed minimal REST assignment and fixed readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            if not self._state_is_unchanged(record):
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise RoleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._validate_record(record, requester_digest, "authorized")
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.assign_and_readback(
                record.username,
                record.role_name,
            )
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, RoleAssignReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, request: _RoleAssignRequest) -> RoleAssignInspection:
        try:
            result = self._transport.inspect_assignment(
                request.username,
                request.role_name,
            )
        except Exception as exc:
            raise RoleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, RoleAssignInspection):
            raise RoleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _state_is_unchanged(self, record: _RoleAssignRecord) -> bool:
        current = self._inspect(_RoleAssignRequest(record.username, record.role_name))
        return (
            current.user_exists
            and current.role_exists
            and current.user_disabled
            and not current.assignment_matches
            and hmac.compare_digest(current.state_digest, record.current_digest)
        )

    def _record_for_preview_locked(self, preview_ref: str) -> _RoleAssignRecord:
        if not _valid_ref(preview_ref, "role-assign-preview-"):
            raise RoleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise RoleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _RoleAssignRecord:
        if not _valid_ref(authorization_ref, "role-assign-authorized-"):
            raise RoleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise RoleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _RoleAssignRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise RoleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _RoleAssignRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise RoleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise RoleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(record: _RoleAssignRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_username": record.username,
                "requested_role_name": record.role_name,
                "laboratory_user_exists": True,
                "laboratory_user_status": "disable",
                "requested_laboratory_role_exists": True,
                "requested_role_already_assigned": False,
                "write_transport": "rest_api",
            },
            "Proposed Changes": {
                "operation": "assign_existing_laboratory_role_to_disabled_laboratory_local_user_via_api",
                "username": record.username,
                "role_name": record.role_name,
                "user_status_change": False,
                "folder_target_or_secret_changes": False,
            },
            "Expected State": {
                "username_matches": True,
                "role_name_matches": True,
                "laboratory_user_exists": True,
                "laboratory_user_status": "disable",
                "requested_laboratory_role_exists": True,
                "requested_role_assigned": True,
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _RoleAssignRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_role_assign_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "not_requested",
            "user_status_changed": False,
            "raw_api_response_returned": False,
        }


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise RoleAssignLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "RoleAssignLiveWorkflow",
    "RoleAssignLiveWorkflowError",
    "RoleAssignLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
