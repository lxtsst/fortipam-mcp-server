"""One live, confirmation-gated FortiPAM SSH Filter Profile create workflow."""

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

from .ssh_filter_ssh_transport import (
    SSH_FILTER_CONFIGURATION,
    SshFilterInspection,
    SshFilterReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_ssh_filter_create_cli_fallback_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 SSH Filter Profile create action is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"mcp-v4-ssh-filter-[A-Za-z0-9][A-Za-z0-9._-]{0,45}\Z")


class SshFilterLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded SSH Filter workflow."""


class SshFilterLiveWorkflowTransport(Protocol):
    """Exact SSH Filter preflight and create/readback contract."""

    def inspect(self, profile_name: str) -> SshFilterInspection: ...

    def create_and_readback(self, profile_name: str) -> SshFilterReadback: ...


@dataclass(frozen=True, slots=True)
class _SshFilterRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    profile_name: str
    current_digest: str
    state: str
    expires_at: int


class SshFilterCreateLiveWorkflow:
    """Volatile one-confirmation flow for one unattached SSH Filter Profile."""

    def __init__(
        self,
        transport: SshFilterLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _SshFilterRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, profile_name: str, requester_digest: str) -> dict[str, object]:
        """Read current state and render C/P/E without a device write."""

        safe_name = _profile_name(profile_name)
        _require_requester(requester_digest)
        current = self._inspect(safe_name)
        if current.profile_name_exists:
            raise SshFilterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _SshFilterRecord(
            preview_ref="ssh-filter-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            profile_name=safe_name,
            current_digest=_inspection_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record, current)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm unchanged absence and issue one execution reference."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._inspect(record.profile_name)
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise SshFilterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "ssh-filter-authorized-" + secrets.token_urlsafe(24)
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
        """Create exactly the confirmed Profile and return categorical readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._inspect(record.profile_name)
            if _inspection_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise SshFilterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.create_and_readback(record.profile_name)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, SshFilterReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _inspect(self, profile_name: str) -> SshFilterInspection:
        try:
            result = self._transport.inspect(profile_name)
        except Exception as exc:
            raise SshFilterLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, SshFilterInspection):
            raise SshFilterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _SshFilterRecord:
        if not _valid_ref(preview_ref, "ssh-filter-preview-"):
            raise SshFilterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise SshFilterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _SshFilterRecord:
        if not _valid_ref(authorization_ref, "ssh-filter-authorized-"):
            raise SshFilterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise SshFilterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _SshFilterRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise SshFilterLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(record: _SshFilterRecord, requester_digest: str) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise SshFilterLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise SshFilterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
        record: _SshFilterRecord,
        current: SshFilterInspection,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_profile_name": record.profile_name,
                "profile_name_exists": current.profile_name_exists,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "create_ssh_filter_profile_via_cli_fallback",
                "profile_name": record.profile_name,
                "configuration_profile": SSH_FILTER_CONFIGURATION,
                "mode": "deny",
                "shell_pattern": "rm",
                "pattern_log": "enable",
                "pattern_alert": "enable",
                "secret_or_policy_association_changes": False,
                "target_or_session_changes": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "profile_name_matches": True,
                "profile_name_exists": True,
                "deny_mode_enabled": True,
                "rm_pattern_present": True,
                "pattern_log_enabled": True,
                "pattern_alert_enabled": True,
                "secret_or_policy_association_changes": False,
                "readback_transport": "ssh_cli",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _SshFilterRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_ssh_filter_create_cli_fallback_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_ssh_filter_profile_delete_action_required",
            "profile_name_returned": False,
            "secret_or_policy_association_changes": False,
            "raw_cli_returned": False,
        }


def _inspection_digest(inspection: SshFilterInspection) -> str:
    payload = json.dumps(
        {"profile_name_exists": inspection.profile_name_exists},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _profile_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise SshFilterLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise SshFilterLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "SshFilterCreateLiveWorkflow",
    "SshFilterLiveWorkflowError",
    "SshFilterLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
