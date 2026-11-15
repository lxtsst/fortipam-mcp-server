"""One live, confirmation-gated FortiPAM custom Role create workflow."""

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

from .role_create_ssh_transport import (
    ROLE_CONFIGURATION_PROFILE,
    RoleCreateInspection,
    RoleCreateReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_role_create_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Role create workflow is unavailable."
_TTL_SECONDS = 600
_ROLE_NAME = re.compile(r"mcp-v4-role-[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")


class RoleCreateLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded Role create flow."""


class RoleCreateLiveWorkflowTransport(Protocol):
    """The exact Role preflight and create/readback contract."""

    def inspect(self, role_name: str) -> RoleCreateInspection: ...

    def create_and_readback(self, role_name: str) -> RoleCreateReadback: ...


@dataclass(frozen=True, slots=True)
class _RoleCreateRequest:
    role_name: str

    @classmethod
    def create(cls, role_name: str) -> "_RoleCreateRequest":
        if not isinstance(role_name, str) or _ROLE_NAME.fullmatch(role_name) is None:
            raise RoleCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return cls(role_name=role_name)


@dataclass(frozen=True, slots=True)
class _RoleCreateRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    role_name: str
    current_digest: str
    state: str
    expires_at: int


class RoleCreateLiveWorkflow:
    """Volatile one-confirmation workflow for one unassigned custom Role."""

    def __init__(
        self,
        transport: RoleCreateLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _RoleCreateRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, role_name: str, requester_digest: str) -> dict[str, object]:
        """Read live state and prepare Current/Proposed/Expected without a write."""

        request = _RoleCreateRequest.create(role_name)
        _require_requester(requester_digest)
        current = self._inspect(request)
        if current.exists:
            raise RoleCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _RoleCreateRecord(
            preview_ref="role-create-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            role_name=request.role_name,
            current_digest=_inspection_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm unchanged absence and issue one execution reference."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect(_RoleCreateRequest(record.role_name))
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise RoleCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "role-create-authorized-" + secrets.token_urlsafe(24)
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
        """Create exactly the confirmed Role and report categorical readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(_RoleCreateRequest(record.role_name))
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise RoleCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.create_and_readback(record.role_name)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, RoleCreateReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, request: _RoleCreateRequest) -> RoleCreateInspection:
        try:
            result = self._transport.inspect(request.role_name)
        except Exception as exc:
            raise RoleCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, RoleCreateInspection):
            raise RoleCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _RoleCreateRecord:
        if not _valid_ref(preview_ref, "role-create-preview-"):
            raise RoleCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise RoleCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _RoleCreateRecord:
        if not _valid_ref(authorization_ref, "role-create-authorized-"):
            raise RoleCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise RoleCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _RoleCreateRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise RoleCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _RoleCreateRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise RoleCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise RoleCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
    def _preview_projection(record: _RoleCreateRecord) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_role_name": record.role_name,
                "role_exists": False,
            },
            "Proposed Changes": {
                "operation": "create_unassigned_guide_example_role",
                "role_name": record.role_name,
                "configuration_profile": ROLE_CONFIGURATION_PROFILE,
                "user_or_group_assignment_changes": False,
                "folder_target_or_secret_changes": False,
            },
            "Expected State": {
                "role_name_matches": True,
                "role_exists": True,
                "core_access_matches": True,
                "secret_permissions_match": True,
                "system_diagnostics_disabled": True,
                "user_or_group_assignment_changes": False,
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _RoleCreateRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_role_create_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "not_requested",
            "role_assignments_changed": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: RoleCreateInspection) -> str:
    payload = json.dumps(
        {"exists": inspection.exists}, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise RoleCreateLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "RoleCreateLiveWorkflow",
    "RoleCreateLiveWorkflowError",
    "RoleCreateLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
