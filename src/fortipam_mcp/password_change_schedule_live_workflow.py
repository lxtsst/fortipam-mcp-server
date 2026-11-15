"""Persistent one-dispatch workflow for a privately bound Unix Secret."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time
from typing import Callable, Literal

from .password_change_schedule_http_transport import (
    FortiPamPasswordChangeScheduleHttpTransport,
    PasswordChangeScheduleBinding,
    PasswordChangeScheduleReadback,
    PasswordChangeScheduleState,
)


CONTRACT = "fortipam_v4_password_change_schedule_unix_700_candidate_v1"
_UNAVAILABLE = "FortiPAM V4 password change schedule workflow is unavailable."
_TTL_SECONDS = 600
_DIGEST_CHARS = frozenset("0123456789abcdef")


class PasswordChangeScheduleLiveWorkflowError(RuntimeError):
    """Stable non-disclosing candidate workflow failure."""


@dataclass(frozen=True, slots=True)
class _Record:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    binding_digest: str
    current_digest: str
    state: str
    expires_at: int


class PasswordChangeScheduleLiveWorkflow:
    """Bind one fixed C/P/E to one durable, non-retry device dispatch."""

    def __init__(
        self,
        database: Path,
        hmac_key_file: Path,
        transport: FortiPamPasswordChangeScheduleHttpTransport,
        binding: PasswordChangeScheduleBinding,
        *,
        operation: Literal["enable", "disable"],
        clock: Callable[[], int] | None = None,
    ) -> None:
        if not isinstance(transport, FortiPamPasswordChangeScheduleHttpTransport):
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE)
        if not isinstance(binding, PasswordChangeScheduleBinding):
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE)
        if operation not in {"enable", "disable"}:
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE)
        self._operation = operation
        self._database = Path(database)
        self._key = _private_key(Path(hmac_key_file))
        self._transport = transport
        self._binding_digest = hmac.new(
            self._key,
            json.dumps({"operation": operation, "binding": asdict(binding)}, sort_keys=True, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).hexdigest()
        self._clock = clock or (lambda: int(time.time()))
        self._prepare_database()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        _requester(requester_digest)
        if self._has_consumed_dispatch():
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE)
        current = self._transport.inspect()
        if not _eligible(current, self._operation):
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE)
        record = _Record(
            preview_ref=f"password-change-schedule-{self._operation}-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            binding_digest=self._binding_digest,
            current_digest=_state_digest(current),
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        self._insert(record)
        return {
            "contract": CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "exact_private_secret_matched": True,
                "automatic_change_enabled": current.enabled,
                "custom_daily_interval_one": not current.uses_policy_default and current.frequency == "day" and current.interval == 1,
            },
            "Proposed Changes": {
                "operation": self._operation + "_automatic_password_change",
                "frequency": "day" if self._operation == "enable" else None,
                "interval": 1 if self._operation == "enable" else None,
                "start_delay_minutes": 5 if self._operation == "enable" else None,
                "existing_protected_fields_reused_in_device_update": True,
                "credential_values_returned": False,
            },
            "Expected State": {
                "automatic_change_enabled": self._operation == "enable",
                "ssh_sftp_recording_preserved": True,
                "disabled_schedule_fields_may_normalize": self._operation == "disable",
                "actual_job_not_proven_by_configuration": True,
                "credential_values_returned": False,
            },
            "device_write_executed": False,
        }

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        record = self._select("preview_ref", preview_ref)
        self._require(record, requester_digest, "previewed")
        if _state_digest(self._transport.inspect()) != record.current_digest:
            self._transition(record, replace(record, state="invalidated"))
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE)
        authorized = replace(
            record,
            authorization_ref=f"password-change-schedule-{self._operation}-authorized-"
            + secrets.token_urlsafe(24),
            state="authorized",
        )
        if not self._transition(record, authorized):
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE)
        return {
            "contract": CONTRACT,
            "preview_ref": record.preview_ref,
            "authorization_ref": authorized.authorization_ref,
            "confirmation": "recorded",
            "execution": "authorized_once",
            "expires_at": record.expires_at,
            "device_write_executed": False,
        }

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        record = self._select("authorization_ref", authorization_ref)
        self._require_requester(record, requester_digest)
        if record.state in {"completed", "executing", "reconciliation_required", "invalidated"}:
            return self._result(record, idempotent_replay=True)
        self._require(record, requester_digest, "authorized")
        reserved = replace(record, state="executing")
        if not self._reserve(record, reserved):
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE)
        try:
            current = self._transport.inspect()
            if not _eligible(current, self._operation) or _state_digest(current) != record.current_digest:
                self._transition(reserved, replace(reserved, state="invalidated"))
                return self._result(record, idempotent_replay=False)
        except Exception:
            self._transition(reserved, replace(reserved, state="invalidated"))
            return self._result(record, idempotent_replay=False)
        # Once the protected read or PUT starts, any failure is ambiguous.
        try:
            readback = (self._transport.enable_and_readback(current) if self._operation == "enable"
                        else self._transport.disable_and_readback(current))
            terminal = "completed" if (
                isinstance(readback, PasswordChangeScheduleReadback)
                and readback.accepted and readback.verified and readback.logout_verified
                and readback.enabled == (self._operation == "enable")
            ) else "reconciliation_required"
        except Exception:
            terminal = "reconciliation_required"
        self._transition(reserved, replace(reserved, state=terminal))
        return self._result(record, idempotent_replay=False)

    def _result(self, record: _Record, *, idempotent_replay: bool) -> dict[str, object]:
        latest = self._select("preview_ref", record.preview_ref)
        outcome = {
            "completed": "succeeded",
            "invalidated": "not_executed",
            "executing": "reconciliation_required",
            "reconciliation_required": "reconciliation_required",
        }.get(latest.state, "unavailable")
        return {
            "contract": CONTRACT,
            "operation": self._operation,
            "outcome": outcome,
            "verification": "verified" if outcome == "succeeded" else "unknown",
            "idempotent_replay": idempotent_replay,
            "device_write_may_have_occurred": latest.state in {
                "completed", "executing", "reconciliation_required"
            },
            "credential_values_returned": False,
            "raw_api_response_returned": False,
        }

    def _require(self, record: _Record, requester_digest: str, state: str) -> None:
        self._require_requester(record, requester_digest)
        if record.state != state or self._clock() >= record.expires_at:
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE)

    def _require_requester(self, record: _Record, requester_digest: str) -> None:
        _requester(requester_digest)
        if (
            not hmac.compare_digest(record.requester_digest, requester_digest)
            or not hmac.compare_digest(record.binding_digest, self._binding_digest)
        ):
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE)

    def _prepare_database(self) -> None:
        parent = self._database.parent
        if not parent.is_absolute():
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE)
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        _private_directory(parent)
        try:
            descriptor = os.open(
                self._database, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                0o600,
            )
        except FileExistsError:
            pass
        except OSError:
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE) from None
        else:
            os.close(descriptor)
        _private_file(self._database)
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS password_change_schedule_workflow "
                "(preview_ref TEXT PRIMARY KEY, authorization_ref TEXT UNIQUE, "
                "requester_digest TEXT NOT NULL, binding_digest TEXT NOT NULL, "
                "current_digest TEXT NOT NULL, state TEXT NOT NULL, "
                "expires_at INTEGER NOT NULL, record_mac TEXT NOT NULL)"
            )
            connection.commit()

    def _connect(self) -> sqlite3.Connection:
        _private_file(self._database)
        connection = sqlite3.connect(self._database, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _insert(self, record: _Record) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO password_change_schedule_workflow VALUES (?,?,?,?,?,?,?,?)",
                    (*_values(record), self._mac(record)),
                )
                connection.commit()
        except sqlite3.Error:
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE) from None

    def _select(self, field: str, value: str) -> _Record:
        prefix = (
            f"password-change-schedule-{self._operation}-preview-" if field == "preview_ref"
            else f"password-change-schedule-{self._operation}-authorized-" if field == "authorization_ref"
            else None
        )
        if prefix is None or not isinstance(value, str) or not value.startswith(prefix):
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE)
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM password_change_schedule_workflow WHERE " + field + "=?",
                    (value,),
                ).fetchone()
        except sqlite3.Error:
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE) from None
        if row is None:
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE)
        return self._verified_record(row)

    def _verified_record(self, row: sqlite3.Row) -> _Record:
        record = _Record(
            row["preview_ref"], row["authorization_ref"], row["requester_digest"],
            row["binding_digest"], row["current_digest"], row["state"], row["expires_at"],
        )
        if not hmac.compare_digest(row["record_mac"], self._mac(record)):
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE)
        return record

    def _transition(self, before: _Record, after: _Record) -> bool:
        try:
            with self._connect() as connection:
                result = connection.execute(
                    "UPDATE password_change_schedule_workflow SET authorization_ref=?, "
                    "state=?, record_mac=? WHERE preview_ref=? AND state=? AND record_mac=?",
                    (after.authorization_ref, after.state, self._mac(after),
                     before.preview_ref, before.state, self._mac(before)),
                )
                connection.commit()
                return result.rowcount == 1
        except sqlite3.Error:
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE) from None

    def _has_consumed_dispatch(self) -> bool:
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT * FROM password_change_schedule_workflow",
                ).fetchall()
        except sqlite3.Error:
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE) from None
        records = [self._verified_record(row) for row in rows]
        return any(
            record.binding_digest == self._binding_digest
            and record.state in {"executing", "completed", "reconciliation_required"}
            for record in records
        )

    def _reserve(self, before: _Record, after: _Record) -> bool:
        """Atomically allow only one dispatch for this bound Secret."""

        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                records = [self._verified_record(row) for row in connection.execute(
                    "SELECT * FROM password_change_schedule_workflow"
                ).fetchall()]
                other = any(
                    record.binding_digest == self._binding_digest
                    and record.state in {"executing", "completed", "reconciliation_required"}
                    for record in records
                )
                if other:
                    connection.rollback()
                    return False
                result = connection.execute(
                    "UPDATE password_change_schedule_workflow SET state=?, record_mac=? "
                    "WHERE preview_ref=? AND state=? AND record_mac=?",
                    (after.state, self._mac(after), before.preview_ref,
                     before.state, self._mac(before)),
                )
                connection.commit()
                return result.rowcount == 1
        except sqlite3.Error:
            raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE) from None

    def _mac(self, record: _Record) -> str:
        payload = json.dumps(_values(record), separators=(",", ":"), ensure_ascii=True)
        return hmac.new(self._key, payload.encode("ascii"), hashlib.sha256).hexdigest()


def _values(record: _Record) -> tuple[object, ...]:
    return (
        record.preview_ref, record.authorization_ref, record.requester_digest,
        record.binding_digest, record.current_digest, record.state, record.expires_at,
    )


def _eligible(state: PasswordChangeScheduleState, operation: str) -> bool:
    return isinstance(state, PasswordChangeScheduleState) and (
        type(state.secret_id) is int and state.secret_id > 0
        and type(state.folder_id) is int and state.folder_id > 0
        and (not state.enabled if operation == "enable" else
             state.enabled and not state.uses_policy_default and state.frequency == "day"
             and state.interval == 1 and state.start_epoch > 0)
    )


def _state_digest(state: PasswordChangeScheduleState) -> str:
    return hashlib.sha256(
        json.dumps(asdict(state), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _requester(value: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in _DIGEST_CHARS for character in value
    ):
        raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE)


def _private_directory(path: Path) -> None:
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE)


def _private_file(path: Path) -> None:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE)


def _private_key(path: Path) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 32 <= info.st_size <= 4096
            ):
                raise ValueError
            value = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
        if not 32 <= len(value) <= 4096:
            raise ValueError
        return value
    except Exception:
        raise PasswordChangeScheduleLiveWorkflowError(_UNAVAILABLE) from None


__all__ = ["PasswordChangeScheduleLiveWorkflow", "PasswordChangeScheduleLiveWorkflowError"]
