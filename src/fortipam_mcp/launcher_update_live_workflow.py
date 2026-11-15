"""One confirmation-gated FortiPAM native RDP Launcher timeout update."""

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

from .launcher_ssh_transport import (
    LAUNCHER_DEFAULT_TIMEOUT_SECONDS,
    LAUNCHER_UPDATED_TIMEOUT_SECONDS,
    LAUNCHER_UPDATE_CONFIGURATION,
    LauncherUpdateBaselineReadback,
    LauncherUpdateReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_launcher_timeout_update_cli_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Launcher timeout update action is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"mcp-v4-launcher-[A-Za-z0-9][A-Za-z0-9._-]{0,46}\Z")


class LauncherUpdateLiveWorkflowError(RuntimeError):
    """Stable non-disclosing failure for the bounded Launcher update."""


class LauncherUpdateLiveWorkflowTransport(Protocol):
    """Exact baseline inspection and fixed timeout-update/readback contract."""

    def update_baseline_readback(
        self,
        launcher_name: str,
    ) -> LauncherUpdateBaselineReadback: ...

    def update_timeout_and_readback(
        self,
        launcher_name: str,
    ) -> LauncherUpdateReadback: ...


@dataclass(frozen=True, slots=True)
class _LauncherUpdateRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    launcher_name: str
    current_digest: str
    state: str
    expires_at: int


class LauncherTimeoutUpdateLiveWorkflow:
    """One-confirmation 15-to-30 second update of one known Launcher baseline."""

    def __init__(
        self,
        transport: LauncherUpdateLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or _now
        self._records: dict[str, _LauncherUpdateRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, launcher_name: str, requester_digest: str) -> dict[str, object]:
        """Read the exact create baseline and render C/P/E without a device write."""

        safe_name = _launcher_name(launcher_name)
        _require_requester(requester_digest)
        current = self._baseline_readback(safe_name)
        if not current.verified:
            raise LauncherUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _LauncherUpdateRecord(
            preview_ref="launcher-update-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            launcher_name=safe_name,
            current_digest=_readback_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record, current)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm the exact baseline remains unchanged and issue one execution ref."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            current = self._baseline_readback(record.launcher_name)
            if not current.verified or _readback_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise LauncherUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "launcher-update-authorized-" + secrets.token_urlsafe(24)
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
        """Change only the confirmed timeout and return categorical readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            current = self._baseline_readback(record.launcher_name)
            if not current.verified or _readback_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise LauncherUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.update_timeout_and_readback(record.launcher_name)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        if not isinstance(readback, LauncherUpdateReadback):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _baseline_readback(self, launcher_name: str) -> LauncherUpdateBaselineReadback:
        try:
            result = self._transport.update_baseline_readback(launcher_name)
        except Exception as exc:
            raise LauncherUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        if not isinstance(result, LauncherUpdateBaselineReadback):
            raise LauncherUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _LauncherUpdateRecord:
        if not _valid_ref(preview_ref, "launcher-update-preview-"):
            raise LauncherUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise LauncherUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _LauncherUpdateRecord:
        if not _valid_ref(authorization_ref, "launcher-update-authorized-"):
            raise LauncherUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise LauncherUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _LauncherUpdateRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise LauncherUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _LauncherUpdateRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise LauncherUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise LauncherUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
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
        record: _LauncherUpdateRecord,
        current: LauncherUpdateBaselineReadback,
    ) -> dict[str, object]:
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_launcher_name": record.launcher_name,
                "launcher_name_exists": current.launcher_name_exists,
                "known_native_rdp_create_baseline_verified": current.verified,
                "launch_timeout_seconds": LAUNCHER_DEFAULT_TIMEOUT_SECONDS,
                "write_transport": "ssh_cli_fallback",
            },
            "Proposed Changes": {
                "operation": "update_native_rdp_launcher_timeout_via_cli_fallback",
                "launcher_name": record.launcher_name,
                "configuration_profile": LAUNCHER_UPDATE_CONFIGURATION,
                "launch_timeout_seconds": {
                    "from": LAUNCHER_DEFAULT_TIMEOUT_SECONDS,
                    "to": LAUNCHER_UPDATED_TIMEOUT_SECONDS,
                },
                "launcher_type_or_command_changes": False,
                "secret_or_template_association_changes": False,
                "session_or_target_changes": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "launcher_name_matches": True,
                "launcher_name_exists": True,
                "native_rdp_create_baseline_preserved": True,
                "launch_timeout_seconds": LAUNCHER_UPDATED_TIMEOUT_SECONDS,
                "launcher_type_or_command_changes": False,
                "secret_or_template_association_changes": False,
                "session_or_target_changes": False,
                "readback_transport": "ssh_cli_fallback",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _LauncherUpdateRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_launcher_timeout_update_cli_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": "separate_launcher_timeout_restore_action_required",
            "launcher_name_returned": False,
            "launcher_type_or_command_changes": False,
            "secret_or_template_association_changes": False,
            "raw_cli_returned": False,
        }


def _readback_digest(readback: LauncherUpdateBaselineReadback) -> str:
    payload = json.dumps(
        {
            "launcher_name_exists": readback.launcher_name_exists,
            "type_is_rdp": readback.type_is_rdp,
            "mstsc_executable_present": readback.mstsc_executable_present,
            "native_rdp_parameter_present": readback.native_rdp_parameter_present,
            "cmdkey_initial_command_present": readback.cmdkey_initial_command_present,
            "cmdkey_clean_command_present": readback.cmdkey_clean_command_present,
            "launch_timeout_is_default": readback.launch_timeout_is_default,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _launcher_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise LauncherUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise LauncherUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return isinstance(value, str) and value.startswith(prefix) and value.isascii() and len(value) <= 128


def _now() -> int:
    return int(time.time())


__all__ = [
    "LauncherTimeoutUpdateLiveWorkflow",
    "LauncherUpdateLiveWorkflowError",
    "LauncherUpdateLiveWorkflowTransport",
    "WORKFLOW_CONTRACT",
    "WORKFLOW_UNAVAILABLE",
]
