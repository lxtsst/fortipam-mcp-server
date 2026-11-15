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
from typing import Callable

from .secret_checkout_association_http_transport import (
    SecretCheckoutAssociationHttpTransport,
    SecretCheckoutBinding,
    SecretCheckoutReadback,
    SecretCheckoutInspection,
)


CONTRACT = "fortipam_v4_secret_checkout_association_unix_700_candidate_v5"
_UNAVAILABLE = "FortiPAM V4 Secret checkout association workflow is unavailable."
_TTL_SECONDS = 600
_DIGEST_CHARS = frozenset("0123456789abcdef")


class SecretCheckoutAssociationLiveWorkflowError(RuntimeError):
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


class SecretCheckoutAssociationLiveWorkflow:
    """Bind one fixed C/P/E to one durable, non-retry device dispatch."""

    def __init__(
        self,
        database: Path,
        hmac_key_file: Path,
        transport: SecretCheckoutAssociationHttpTransport,
        binding: SecretCheckoutBinding,
        *,
        restore: bool = False,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if not isinstance(transport, SecretCheckoutAssociationHttpTransport):
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE)
        if not isinstance(binding, SecretCheckoutBinding):
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE)
        if (type(restore) is not bool or transport._checkout_binding != binding
                or transport._restore != restore or transport._private._retained_account is None):
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE)
        self._script_free = binding.checkout_script == binding.checkin_script == ""
        self._operation = ("restore_checkout_baseline" if restore else
                           "configure_basic_checkout" if self._script_free else "associate_checkout_scripts")
        self._database = Path(database)
        self._key = _private_key(Path(hmac_key_file))
        self._transport = transport
        self._binding_digest = hmac.new(
            self._key,
            json.dumps({"contract": CONTRACT, "operation": self._operation, "binding": asdict(binding)}, sort_keys=True, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).hexdigest()
        self._clock = clock or (lambda: int(time.time()))
        self._prepare_database()

    def preview(self, *, requester_digest: str) -> dict[str, object]:
        _requester(requester_digest)
        if self._has_consumed_dispatch():
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE)
        current = self._transport.inspect()
        if not _eligible(current):
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE)
        record = _Record(
            preview_ref=f"secret-checkout-association-{self._operation}-preview-" + secrets.token_urlsafe(24),
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
                "exact_checkout_baseline_or_associated_state_matched": True,
                "both_fixed_harmless_scripts_matched": not self._script_free,
                "script_free_checkout_profile": self._script_free,
                "proxy_and_recording_enabled": True,
                "exact_associated_ssh_execution_account_matched": True,
                "target_wide_privilege_role_unassigned": True,
                "credential_values_returned": False,
            },
            "Proposed Changes": {
                "operation": self._operation,
                "fixed_seven_control_delta": True,
                "original_force_checkout_idle_time_preserved": True,
                "proxy_and_recording_remain_enabled": True,
                "associated_execution_account_and_privilege_flags_preserved": True,
                "checkout_duration_minutes": "original_baseline" if self._operation == "restore_checkout_baseline" else 5,
                "renewal_and_password_change_remain_disabled": True,
                "existing_opaque_fields_retained_at_private_dispatch": True,
                "credential_values_returned": False,
            },
            "Expected State": {
                "checkout_controls_match_private_proposal": True,
                "other_redacted_metadata_preserved": True,
                "retained_field_values_match": True,
                "stored_password_and_launcher_not_proven": True,
                "checkout_effects_require_independent_readback": True,
                "execution_account_login_and_script_effects_unproven": True,
                "credential_values_returned": False,
            },
            "device_write_executed": False,
        }

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        record = self._select("preview_ref", preview_ref)
        self._require(record, requester_digest, "previewed")
        if _state_digest(self._transport.inspect()) != record.current_digest:
            self._transition(record, replace(record, state="invalidated"))
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE)
        authorized = replace(
            record,
            authorization_ref=f"secret-checkout-association-{self._operation}-authorized-"
            + secrets.token_urlsafe(24),
            state="authorized",
        )
        if not self._transition(record, authorized):
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE)
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
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE)
        try:
            current = self._transport.inspect()
            if not _eligible(current) or _state_digest(current) != record.current_digest:
                self._transition(reserved, replace(reserved, state="invalidated"))
                return self._result(record, idempotent_replay=False)
        except Exception:
            self._transition(reserved, replace(reserved, state="invalidated"))
            return self._result(record, idempotent_replay=False)
        # Once the protected read or PUT starts, any failure is ambiguous.
        try:
            readback = self._transport.associate_and_readback(current)
            terminal = "completed" if (
                isinstance(readback, SecretCheckoutReadback)
                and readback.verified
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
            "stored_password_and_launcher_not_proven": True,
            "checkout_effects_require_independent_readback": True,
        }

    def _require(self, record: _Record, requester_digest: str, state: str) -> None:
        self._require_requester(record, requester_digest)
        if record.state != state or self._clock() >= record.expires_at:
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE)

    def _require_requester(self, record: _Record, requester_digest: str) -> None:
        _requester(requester_digest)
        if (
            not hmac.compare_digest(record.requester_digest, requester_digest)
            or not hmac.compare_digest(record.binding_digest, self._binding_digest)
        ):
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE)

    def _prepare_database(self) -> None:
        parent = self._database.parent
        if not parent.is_absolute():
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE)
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
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE) from None
        else:
            os.close(descriptor)
        _private_file(self._database)
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS secret_checkout_association_workflow "
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
                    "INSERT INTO secret_checkout_association_workflow VALUES (?,?,?,?,?,?,?,?)",
                    (*_values(record), self._mac(record)),
                )
                connection.commit()
        except sqlite3.Error:
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE) from None

    def _select(self, field: str, value: str) -> _Record:
        prefix = (
            f"secret-checkout-association-{self._operation}-preview-" if field == "preview_ref"
            else f"secret-checkout-association-{self._operation}-authorized-" if field == "authorization_ref"
            else None
        )
        if prefix is None or not isinstance(value, str) or not value.startswith(prefix):
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE)
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM secret_checkout_association_workflow WHERE " + field + "=?",
                    (value,),
                ).fetchone()
        except sqlite3.Error:
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE) from None
        if row is None:
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE)
        return self._verified_record(row)

    def _verified_record(self, row: sqlite3.Row) -> _Record:
        record = _Record(
            row["preview_ref"], row["authorization_ref"], row["requester_digest"],
            row["binding_digest"], row["current_digest"], row["state"], row["expires_at"],
        )
        if not hmac.compare_digest(row["record_mac"], self._mac(record)):
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE)
        return record

    def _transition(self, before: _Record, after: _Record) -> bool:
        try:
            with self._connect() as connection:
                result = connection.execute(
                    "UPDATE secret_checkout_association_workflow SET authorization_ref=?, "
                    "state=?, record_mac=? WHERE preview_ref=? AND state=? AND record_mac=?",
                    (after.authorization_ref, after.state, self._mac(after),
                     before.preview_ref, before.state, self._mac(before)),
                )
                connection.commit()
                return result.rowcount == 1
        except sqlite3.Error:
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE) from None

    def _has_consumed_dispatch(self) -> bool:
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT * FROM secret_checkout_association_workflow",
                ).fetchall()
        except sqlite3.Error:
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE) from None
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
                    "SELECT * FROM secret_checkout_association_workflow"
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
                    "UPDATE secret_checkout_association_workflow SET state=?, record_mac=? "
                    "WHERE preview_ref=? AND state=? AND record_mac=?",
                    (after.state, self._mac(after), before.preview_ref,
                     before.state, self._mac(before)),
                )
                connection.commit()
                return result.rowcount == 1
        except sqlite3.Error:
            raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE) from None

    def _mac(self, record: _Record) -> str:
        payload = json.dumps(_values(record), separators=(",", ":"), ensure_ascii=True)
        return hmac.new(self._key, payload.encode("ascii"), hashlib.sha256).hexdigest()


def _values(record: _Record) -> tuple[object, ...]:
    return (
        record.preview_ref, record.authorization_ref, record.requester_digest,
        record.binding_digest, record.current_digest, record.state, record.expires_at,
    )


def _eligible(state: SecretCheckoutInspection) -> bool:
    return isinstance(state, SecretCheckoutInspection) and all(
        isinstance(value, str) and len(value) == 64
        and all(character in _DIGEST_CHARS for character in value)
        for value in (state.body_digest, state.unchanged_metadata_digest,
                      state.script_definition_digest, state.execution_account_digest)
    )


def _state_digest(state: SecretCheckoutInspection) -> str:
    return hashlib.sha256(
        json.dumps(asdict(state), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _requester(value: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in _DIGEST_CHARS for character in value
    ):
        raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE)


def _private_directory(path: Path) -> None:
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE)


def _private_file(path: Path) -> None:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE)


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
        raise SecretCheckoutAssociationLiveWorkflowError(_UNAVAILABLE) from None


__all__ = ["SecretCheckoutAssociationLiveWorkflow", "SecretCheckoutAssociationLiveWorkflowError"]
