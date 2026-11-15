"""One live, confirmation-gated FortiPAM Local User disable workflow."""

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

from .local_user_ssh_transport import LocalUserInspection, LocalUserReadback


WORKFLOW_CONTRACT = "fortipam_v4_local_user_disable_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Local User disable workflow is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class LocalUserLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded Local User workflow."""


class LocalUserLiveWorkflowTransport(Protocol):
    """The exact Local User preflight and disable/readback contract."""

    def inspect(self, username: str) -> LocalUserInspection: ...

    def disable_and_readback(self, username: str) -> LocalUserReadback: ...


@dataclass(frozen=True, slots=True)
class _LocalUserRequest:
    username: str

    @classmethod
    def create(cls, username: str) -> "_LocalUserRequest":
        if not isinstance(username, str) or _NAME.fullmatch(username) is None:
            raise LocalUserLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(username=username)


@dataclass(frozen=True, slots=True)
class _LocalUserRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    username: str
    current_digest: str
    state: str
    expires_at: int


class LocalUserDisableLiveWorkflow:
    """Volatile one-confirmation live workflow for one Local User disable."""

    def __init__(
        self,
        transport: LocalUserLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _LocalUserRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(
        self,
        *,
        username: str,
        requester_digest: str,
    ) -> dict[str, object]:
        """Read live Local User state and return Current/Proposed/Expected only."""

        request = _LocalUserRequest.create(username)
        _require_requester(requester_digest)
        current = self._inspect(request)
        if not current.enabled:
            raise LocalUserLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _LocalUserRecord(
            preview_ref="local-user-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            username=request.username,
            current_digest=_inspection_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm a still-unchanged preview and issue one execution reference."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect(_LocalUserRequest(record.username))
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise LocalUserLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "local-user-authorized-" + secrets.token_urlsafe(24)
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
        """Perform one confirmed disable and return categorical readback evidence."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(_LocalUserRequest(record.username))
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise LocalUserLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.disable_and_readback(record.username)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, LocalUserReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, request: _LocalUserRequest) -> LocalUserInspection:
        try:
            result = self._transport.inspect(request.username)
        except Exception as exc:
            raise LocalUserLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, LocalUserInspection):
            raise LocalUserLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _LocalUserRecord:
        if not _valid_ref(preview_ref, "local-user-preview-"):
            raise LocalUserLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise LocalUserLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _LocalUserRecord:
        if not _valid_ref(authorization_ref, "local-user-authorized-"):
            raise LocalUserLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise LocalUserLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _LocalUserRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise LocalUserLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _LocalUserRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise LocalUserLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise LocalUserLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(record: _LocalUserRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_username": record.username,
                "user_exists": True,
                "status": "enable",
            },
            "Proposed Changes": {
                "operation": "disable_local_user",
                "username": record.username,
            },
            "Expected State": {
                "username_matches": True,
                "user_exists": True,
                "status": "disable",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _LocalUserRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_local_user_disable_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "not_requested",
            "credentials_returned": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: LocalUserInspection) -> str:
    payload = json.dumps(
        {"exists": inspection.exists, "status": inspection.status},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise LocalUserLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "LocalUserDisableLiveWorkflow",
    "LocalUserLiveWorkflowError",
    "LocalUserLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
