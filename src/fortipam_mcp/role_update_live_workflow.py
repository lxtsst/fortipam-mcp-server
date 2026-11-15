"""One confirmation-gated FortiPAM Role diagnostics-permission update."""

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
    ROLE_UPDATE_CONFIGURATION_PROFILE,
    RoleUpdateInspection,
    RoleUpdateReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_role_diagnostics_enable_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Role update action is unavailable."
_TTL_SECONDS = 600
_ROLE_NAME = re.compile(r"mcp-v4-role-[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")


class RoleUpdateLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded Role update."""


class RoleUpdateLiveWorkflowTransport(Protocol):
    """Exact preflight and diagnostics-enable/readback contract."""

    def inspect_update(self, role_name: str) -> RoleUpdateInspection: ...

    def enable_diagnostics_and_readback(self, role_name: str) -> RoleUpdateReadback: ...


@dataclass(frozen=True, slots=True)
class _RoleUpdateRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    role_name: str
    current_digest: str
    state: str
    expires_at: int


class RoleUpdateLiveWorkflow:
    """Enable only system diagnostics on the exact unassigned guide baseline."""

    def __init__(
        self,
        transport: RoleUpdateLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
        write_transport: str = "ssh_cli_fallback",
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        if write_transport not in {"ssh_cli_fallback", "rest_api"}:
            raise ValueError("Role update write transport is invalid.")
        self._write_transport = write_transport
        self._records: dict[str, _RoleUpdateRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, role_name: str, requester_digest: str) -> dict[str, object]:
        """Read the exact eligible baseline and render C/P/E without a write."""

        safe_name = _role_name(role_name)
        _require_requester(requester_digest)
        current = self._inspect(safe_name)
        if not current.verified:
            raise RoleUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _RoleUpdateRecord(
            preview_ref="role-update-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            role_name=safe_name,
            current_digest=_inspection_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record, current)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Require the verified unassigned baseline to be unchanged."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect(record.role_name)
            if not current.verified or _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise RoleUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "role-update-authorized-" + secrets.token_urlsafe(24)
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
        """Perform the one confirmed CLI fallback and return categorical proof."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(record.role_name)
            if not current.verified or _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise RoleUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.enable_diagnostics_and_readback(record.role_name)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, RoleUpdateReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, role_name: str) -> RoleUpdateInspection:
        try:
            result = self._transport.inspect_update(role_name)
        except Exception as exc:
            raise RoleUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, RoleUpdateInspection):
            raise RoleUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _RoleUpdateRecord:
        if not _valid_ref(preview_ref, "role-update-preview-"):
            raise RoleUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise RoleUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(self, authorization_ref: str) -> _RoleUpdateRecord:
        if not _valid_ref(authorization_ref, "role-update-authorized-"):
            raise RoleUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise RoleUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _RoleUpdateRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise RoleUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _RoleUpdateRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise RoleUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise RoleUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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

    def _preview_projection(
        self,
        record: _RoleUpdateRecord,
        current: RoleUpdateInspection,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_role_name": record.role_name,
                "role_exists": current.role_exists,
                "guide_example_permissions_match": (
                    current.core_access_matches and current.secret_permissions_match
                ),
                "system_diagnostics_disabled": current.system_diagnostics_disabled,
                "role_assigned_to_any_local_user": current.role_assigned,
                "write_transport": self._write_transport,
            },
            "Proposed Changes": {
                "operation": "enable_role_system_diagnostics_via_"
                + ("cli_fallback" if self._write_transport == "ssh_cli_fallback" else "rest_api"),
                "role_name": record.role_name,
                "configuration_profile": ROLE_UPDATE_CONFIGURATION_PROFILE,
                "system_diagnostics": "enable",
                "role_assignment_changes": False,
                "folder_target_secret_or_credential_changes": False,
                "rest_write_attempted": self._write_transport == "rest_api",
            },
            "Expected State": {
                "role_name_matches": True,
                "role_exists": True,
                "guide_example_permissions_preserved": True,
                "system_diagnostics_enabled": True,
                "role_assigned_to_any_local_user": False,
                "role_assignment_changes": False,
                "folder_target_secret_or_credential_changes": False,
                "readback_transport": self._write_transport,
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _RoleUpdateRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_role_diagnostics_enable_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_role_diagnostics_disable_action_required",
            "role_assignment_changes": False,
            "folder_target_secret_or_credential_changes": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: RoleUpdateInspection) -> str:
    payload = json.dumps(
        {
            "role_exists": inspection.role_exists,
            "core_access_matches": inspection.core_access_matches,
            "secret_permissions_match": inspection.secret_permissions_match,
            "system_diagnostics_disabled": inspection.system_diagnostics_disabled,
            "role_assigned": inspection.role_assigned,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _role_name(value: str) -> str:
    if not isinstance(value, str) or _ROLE_NAME.fullmatch(value) is None:
        raise RoleUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise RoleUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "RoleUpdateLiveWorkflow",
    "RoleUpdateLiveWorkflowError",
    "RoleUpdateLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
