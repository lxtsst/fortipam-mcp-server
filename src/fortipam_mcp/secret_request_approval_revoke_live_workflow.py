"""Persistent one-dispatch workflow for a privately bound original reviewer grant."""

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

from .secret_request_approval_revoke_http_transport import (
    FortiPamSecretRequestApprovalRevokeHttpTransport,
    SecretRequestApprovalRevokeReadback,
    SecretRequestApprovalRevokeInspection,
)

from .secret_request_approval_revoke_resolver import OwnerOnlySecretRequestApprovalRevokeResolver

CONTRACT = "fortipam_v4_secret_request_approval_revoke_700_candidate_v1"
_UNAVAILABLE = "FortiPAM V4 Secret Request approval withdrawal workflow is unavailable."
_TTL_SECONDS = 120
_DIGEST_CHARS = frozenset("0123456789abcdef")


class SecretRequestApprovalRevokeLiveWorkflowError(RuntimeError):
    """Stable non-disclosing candidate workflow failure."""


@dataclass(frozen=True, slots=True)
class _Record:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    binding_digest: str
    current_digest: str
    creation_digest: str
    state: str
    expires_at: int


class SecretRequestApprovalRevokeLiveWorkflow:
    """Private standing-lab candidate for an original reviewer withdrawing a grant.

    Authorization is a technical intent record, never an independent approval
    receipt or M4 authorization. This does not replace BP008 configuration's
    execution kernel or independent approval contract. Both execution gates
    default closed; trusted owner-only startup composition must verify that the
    supplied OAuth actor maps to the original product reviewer and pin its
    transport namespace. Digest grammar alone is not that identity evidence.
    """

    def __init__(
        self,
        database: Path,
        hmac_key_file: Path,
        transport: FortiPamSecretRequestApprovalRevokeHttpTransport,
        resolver: OwnerOnlySecretRequestApprovalRevokeResolver,
        *,
        allowed_requester_digest: str,
        allowed_transport_digest: str,
        execution_enabled: bool = False,
        clock: Callable[[], int] | None = None,
    ) -> None:
        try:
            if (type(transport) is not FortiPamSecretRequestApprovalRevokeHttpTransport
                    or type(resolver) is not OwnerOnlySecretRequestApprovalRevokeResolver
                    or type(execution_enabled) is not bool):
                raise ValueError
            _requester(allowed_requester_digest)
            _requester(allowed_transport_digest)
            resolved = resolver.resolve()
            if transport._binding != resolved.binding:
                raise ValueError
            self._operation = "withdraw_secret_request_approval"
            self._database = Path(database)
            self._key = _private_key(Path(hmac_key_file))
            if any(hmac.compare_digest(self._key, key) for key in
                   (transport._key, resolver._key, resolver._store._key)):
                raise ValueError
            protected_paths = (transport._claim, resolver._claim_path,
                               resolver._continuity_path, resolver._store._path, Path(hmac_key_file))
            if self._database.resolve() in {path.resolve() for path in protected_paths}:
                raise ValueError
            self._transport, self._resolver = transport, resolver
            self._allowed_requester = allowed_requester_digest
            self._allowed_transport = allowed_transport_digest
            self._enabled = execution_enabled
            self._binding = resolved.binding
            # Stable across new previews and changed provenance for the same object.
            self._binding_digest = hmac.new(self._key, json.dumps(
                {"operation": self._operation, "binding": asdict(self._binding)},
                sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
        except Exception:
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE) from None
        self._clock = clock or (lambda: int(time.time()))
        self._prepare_database()

    def preview(self, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        self._actor(requester_digest, transport_digest)
        creation_digest = self._creation()
        if self._has_consumed_dispatch():
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)
        current = self._inspect()
        if not _eligible(current):
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)
        record = _Record(
            preview_ref=f"secret-request-approval-revoke-{self._operation}-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            binding_digest=self._binding_digest,
            current_digest=self._state_digest(current),
            creation_digest=creation_digest,
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        self._insert(record)
        return {
            "contract": CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "exact_active_original_grant_verified": True,
                "original_reviewer_verified": True,
                "credential_values_returned": False,
            },
            "Proposed Changes": {
                "operation": self._operation,
                "own_grant_withdrawal_only": True,
                "request_and_parent_metadata_preserved": True,
            },
            "Expected State": {
                "request_pending": True,
                "request_and_parent_metadata_preserved": True,
                "backend_launch_denial_requires_independent_evidence": True,
            },
            "device_write_executed": False,
        }

    def authorize(self, preview_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        self._actor(requester_digest, transport_digest)
        record = self._select("preview_ref", preview_ref)
        self._require(record, requester_digest, "previewed")
        if (self._creation() != record.creation_digest
                or self._state_digest(self._inspect()) != record.current_digest
                or self._clock() >= record.expires_at):
            self._transition(record, replace(record, state="invalidated"))
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)
        authorized = replace(
            record,
            authorization_ref=f"secret-request-approval-revoke-{self._operation}-authorized-"
            + secrets.token_urlsafe(24),
            state="authorized",
        )
        if not self._transition(record, authorized):
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)
        return {
            "contract": CONTRACT,
            "preview_ref": record.preview_ref,
            "authorization_ref": authorized.authorization_ref,
            "confirmation": "recorded",
            "execution": "authorized_once",
            "expires_at": record.expires_at,
            "device_write_executed": False,
        }

    def execute(self, authorization_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        self._actor(requester_digest, transport_digest)
        record = self._select("authorization_ref", authorization_ref)
        self._require_requester(record, requester_digest)
        if record.state in {"completed", "executing", "reconciliation_required", "invalidated"}:
            return self._result(record, idempotent_replay=True)
        self._require(record, requester_digest, "authorized")
        if not self._enabled:
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)
        reserved = replace(record, state="executing")
        if not self._reserve(record, reserved):
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)
        try:
            creation_digest = self._creation()
            current = self._inspect()
            if (creation_digest != record.creation_digest or not _eligible(current) or self._state_digest(current) != record.current_digest
                    or self._clock() >= record.expires_at):
                self._transition(reserved, replace(reserved, state="invalidated"))
                return self._result(record, idempotent_replay=False)
        except Exception:
            self._transition(reserved, replace(reserved, state="invalidated"))
            return self._result(record, idempotent_replay=False)
        # Once the review dispatch path starts, retain an ambiguous failure as non-retry.
        try:
            readback = self._transport.withdraw_and_readback(
                current, authorization_expires_at=record.expires_at,
            )
            terminal = "completed" if (
                isinstance(readback, SecretRequestApprovalRevokeReadback)
                and readback.dispatch_consumed and readback.http_accepted
                and readback.pending_and_metadata_preserved and readback.reviewer_logout_verified and not readback.reconciliation_required
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
            "backend_launch_denial_requires_independent_evidence": True,
        }

    def _inspect(self) -> SecretRequestApprovalRevokeInspection:
        try:
            current = self._transport.inspect()
            if not _eligible(current):
                raise ValueError
            return current
        except Exception:
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE) from None

    def _actor(self, requester: str, transport: str) -> None:
        _requester(requester)
        _requester(transport)
        if (not hmac.compare_digest(requester, self._allowed_requester)
                or not hmac.compare_digest(transport, self._allowed_transport)):
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)

    def _creation(self) -> str:
        try:
            resolved = self._resolver.resolve()
            if resolved.binding != self._binding or self._transport._binding != self._binding:
                raise ValueError
            _requester(resolved.private_creation_digest)
            return resolved.private_creation_digest
        except Exception:
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE) from None

    def _require(self, record: _Record, requester_digest: str, state: str) -> None:
        self._require_requester(record, requester_digest)
        if record.state != state or self._clock() >= record.expires_at:
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)

    def _require_requester(self, record: _Record, requester_digest: str) -> None:
        _requester(requester_digest)
        if (
            not hmac.compare_digest(record.requester_digest, requester_digest)
            or not hmac.compare_digest(record.binding_digest, self._binding_digest)
        ):
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)

    def _prepare_database(self) -> None:
        parent = self._database.parent
        if not parent.is_absolute():
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)
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
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE) from None
        else:
            os.close(descriptor)
        _private_file(self._database)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("CREATE TABLE IF NOT EXISTS withdrawal_namespace "
                               "(id INTEGER PRIMARY KEY CHECK (id=1), binding TEXT NOT NULL)")
            namespace = hmac.new(self._key, json.dumps(
                [CONTRACT, self._allowed_requester, self._allowed_transport, self._binding_digest],
                separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
            row = connection.execute("SELECT binding FROM withdrawal_namespace WHERE id=1").fetchone()
            if row is None:
                connection.execute("INSERT INTO withdrawal_namespace VALUES (1, ?)", (namespace,))
            elif not hmac.compare_digest(row["binding"], namespace):
                raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)
            connection.execute(
                "CREATE TABLE IF NOT EXISTS secret_request_approval_revoke_workflow "
                "(preview_ref TEXT PRIMARY KEY, authorization_ref TEXT UNIQUE, "
                "requester_digest TEXT NOT NULL, binding_digest TEXT NOT NULL, "
                "current_digest TEXT NOT NULL, creation_digest TEXT NOT NULL, state TEXT NOT NULL, "
                "expires_at INTEGER NOT NULL, record_mac TEXT NOT NULL)"
            )
            connection.commit()

    def _connect(self) -> sqlite3.Connection:
        _private_directory(self._database.parent)
        _private_file(self._database)
        connection = sqlite3.connect(self._database, timeout=10)
        connection.execute("PRAGMA synchronous=FULL")
        connection.row_factory = sqlite3.Row
        return connection

    def _insert(self, record: _Record) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO secret_request_approval_revoke_workflow VALUES (?,?,?,?,?,?,?,?,?)",
                    (*_values(record), self._mac(record)),
                )
                connection.commit()
        except sqlite3.Error:
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE) from None

    def _select(self, field: str, value: str) -> _Record:
        prefix = (
            f"secret-request-approval-revoke-{self._operation}-preview-" if field == "preview_ref"
            else f"secret-request-approval-revoke-{self._operation}-authorized-" if field == "authorization_ref"
            else None
        )
        if prefix is None or not isinstance(value, str) or not value.startswith(prefix):
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM secret_request_approval_revoke_workflow WHERE " + field + "=?",
                    (value,),
                ).fetchone()
        except sqlite3.Error:
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE) from None
        if row is None:
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)
        return self._verified_record(row)

    def _verified_record(self, row: sqlite3.Row) -> _Record:
        record = _Record(
            row["preview_ref"], row["authorization_ref"], row["requester_digest"],
            row["binding_digest"], row["current_digest"], row["creation_digest"], row["state"], row["expires_at"],
        )
        if not hmac.compare_digest(row["record_mac"], self._mac(record)):
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)
        return record

    def _transition(self, before: _Record, after: _Record) -> bool:
        try:
            with self._connect() as connection:
                result = connection.execute(
                    "UPDATE secret_request_approval_revoke_workflow SET authorization_ref=?, "
                    "state=?, record_mac=? WHERE preview_ref=? AND state=? AND record_mac=?",
                    (after.authorization_ref, after.state, self._mac(after),
                     before.preview_ref, before.state, self._mac(before)),
                )
                connection.commit()
                return result.rowcount == 1
        except sqlite3.Error:
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE) from None

    def _has_consumed_dispatch(self) -> bool:
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT * FROM secret_request_approval_revoke_workflow",
                ).fetchall()
        except sqlite3.Error:
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE) from None
        records = [self._verified_record(row) for row in rows]
        return any(
            record.binding_digest == self._binding_digest
            and record.state in {"executing", "completed", "reconciliation_required"}
            for record in records
        )

    def _reserve(self, before: _Record, after: _Record) -> bool:
        """Atomically allow only one dispatch for this bound Secret Request."""

        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                records = [self._verified_record(row) for row in connection.execute(
                    "SELECT * FROM secret_request_approval_revoke_workflow"
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
                    "UPDATE secret_request_approval_revoke_workflow SET state=?, record_mac=? "
                    "WHERE preview_ref=? AND state=? AND record_mac=?",
                    (after.state, self._mac(after), before.preview_ref,
                     before.state, self._mac(before)),
                )
                connection.commit()
                return result.rowcount == 1
        except sqlite3.Error:
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE) from None

    def _state_digest(self, state: SecretRequestApprovalRevokeInspection) -> str:
        if not _eligible(state):
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)
        return hmac.new(self._key, json.dumps(asdict(state), sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()

    def _mac(self, record: _Record) -> str:
        payload = json.dumps(_values(record), separators=(",", ":"), ensure_ascii=True)
        return hmac.new(self._key, payload.encode("ascii"), hashlib.sha256).hexdigest()


def _values(record: _Record) -> tuple[object, ...]:
    return (
        record.preview_ref, record.authorization_ref, record.requester_digest,
        record.binding_digest, record.current_digest, record.creation_digest, record.state, record.expires_at,
    )


def _eligible(state: SecretRequestApprovalRevokeInspection) -> bool:
    try:
        if type(state) is not SecretRequestApprovalRevokeInspection:
            return False
        for witness in (state.detail, state.relation):
            for value in asdict(witness).values():
                _requester(value)
        return state.detail.private_binding_digest == state.relation.private_binding_digest
    except Exception:
        return False


def _requester(value: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in _DIGEST_CHARS for character in value
    ):
        raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)


def _private_directory(path: Path) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)


def _private_file(path: Path) -> None:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
    ):
        raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE)


def _private_key(path: Path) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
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
        raise SecretRequestApprovalRevokeLiveWorkflowError(_UNAVAILABLE) from None


__all__ = ["SecretRequestApprovalRevokeLiveWorkflow", "SecretRequestApprovalRevokeLiveWorkflowError"]
