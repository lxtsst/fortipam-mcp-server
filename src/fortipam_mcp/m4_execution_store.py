"""Owner-only persistent state for the V4 M4 execution kernel.

The store is intentionally independent of MCP, product transports, and
credentials.  It persists an append-only SQLite ledger protected by a
domain-separated HMAC chain and a keyed tail anchor.  Plan, requester,
idempotency, context, and execution-authorization inputs are stored only as
HMAC-derived keys.

An unfinished claim remains unfinished across process restarts.  A matching
retry therefore returns ``IN_PROGRESS`` and must never redispatch a product
mutation.  Only the execution kernel's closed public result and audit fields
can be reconstructed from the database.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from contextlib import closing
from dataclasses import dataclass, replace
from pathlib import Path
import re
import sqlite3
import stat
from typing import ClassVar, Final, Protocol

from v4_planning.execution_kernel import (
    M4AuditEvent,
    M4AuthorizationReplay,
    M4Claim,
    M4ClaimState,
    M4Compensation,
    M4ExecutionError,
    M4ExecutionResult,
    M4Outcome,
    M4Verification,
)


_SCHEMA_VERSION: Final = 1
_CHAIN_ROOT: Final = "m4-execution-state-chain-root-v1"
_EVENT_TYPES: Final = frozenset({"claim", "finalize", "audit"})
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_AUDIT_AUTHORIZATION = re.compile(r"^[a-z][a-z0-9_]{1,63}$")


class PersistentM4ExecutionStoreError(M4ExecutionError):
    """Raised when persistent M4 execution state cannot be trusted."""


class M4MonotonicCheckpointError(RuntimeError):
    """Raised when the external M4 execution checkpoint cannot be trusted."""


@dataclass(frozen=True, slots=True)
class M4ExecutionStoreTail:
    """Value-free execution-ledger position bound to one opaque store ref."""

    store_ref: str
    sequence: int
    chain_hmac: str

    @classmethod
    def empty(cls, store_ref: str) -> M4ExecutionStoreTail:
        """Construct the only valid initial position for one execution store."""

        return cls(store_ref, 0, _CHAIN_ROOT)

    def __post_init__(self) -> None:
        _require_ref(self.store_ref, "execution checkpoint store_ref")
        if type(self.sequence) is not int or self.sequence < 0:
            raise PersistentM4ExecutionStoreError(
                "M4 execution checkpoint sequence is invalid."
            )
        if self.sequence == 0:
            if self.chain_hmac != _CHAIN_ROOT:
                raise PersistentM4ExecutionStoreError(
                    "Empty M4 execution checkpoint tail is invalid."
                )
            return
        _require_digest(self.chain_hmac, "execution checkpoint chain_hmac")


class MonotonicM4ExecutionCheckpoint(Protocol):
    """Compare-and-swap authority owned outside the execution SQLite store."""

    authority_ref: str

    def verify(self, tail: M4ExecutionStoreTail) -> None: ...

    def advance(
        self,
        previous: M4ExecutionStoreTail,
        current: M4ExecutionStoreTail,
    ) -> None: ...


class PersistentM4ExecutionStateStore:
    """SQLite/HMAC implementation of ``M4ExecutionStateStore``.

    The append-only ledger is the authoritative state.  There is no mutable
    claim cache whose loss could accidentally make an interrupted mutation
    dispatchable again.  Every read and write verifies the complete chain and
    its keyed tail anchor in one SQLite snapshot.
    """

    def __init__(
        self,
        database_path: Path,
        hmac_key_path: Path,
        *,
        monotonic_checkpoint: MonotonicM4ExecutionCheckpoint | None = None,
        checkpoint_store_ref: str | None = None,
        read_only: bool = False,
    ) -> None:
        if type(read_only) is not bool:
            raise PersistentM4ExecutionStoreError("M4 execution read mode is invalid.")
        self._read_only = read_only
        self._path = Path(database_path)
        self._key_path = Path(hmac_key_path)
        if (monotonic_checkpoint is None) is not (checkpoint_store_ref is None):
            raise PersistentM4ExecutionStoreError(
                "M4 execution checkpoint binding is incomplete."
            )
        self._monotonic_checkpoint = monotonic_checkpoint
        self._checkpoint_store_ref = checkpoint_store_ref
        if monotonic_checkpoint is not None and checkpoint_store_ref is not None:
            try:
                _require_ref(
                    monotonic_checkpoint.authority_ref,
                    "execution checkpoint authority_ref",
                )
                _require_ref(
                    checkpoint_store_ref,
                    "execution checkpoint store_ref",
                )
            except (AttributeError, PersistentM4ExecutionStoreError) as exc:
                raise PersistentM4ExecutionStoreError(
                    "M4 execution checkpoint binding is invalid."
                ) from exc
        if self._path == self._key_path:
            raise PersistentM4ExecutionStoreError(
                "M4 execution database and HMAC key paths must be independent."
            )
        created = self._prepare_database_path()
        self._key = self._load_key()
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN" if read_only else "BEGIN IMMEDIATE")
                if read_only:
                    if int(connection.execute("PRAGMA user_version").fetchone()[0]) != _SCHEMA_VERSION:
                        raise PersistentM4ExecutionStoreError("M4 execution state schema is unsupported.")
                else:
                    self._initialize_schema(connection, allow_create=created)
                self._read_state(connection)
                connection.commit()
        except PersistentM4ExecutionStoreError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise PersistentM4ExecutionStoreError(
                "M4 execution state integrity validation failed."
            ) from exc

    @property
    def monotonic_checkpoint_protocol_bound(self) -> bool:
        """Report whether rollback protection is bound outside this store."""

        return self._monotonic_checkpoint is not None

    def verify_ready(self) -> None:
        """Revalidate owner-only state and the exact external checkpoint tail."""

        try:
            with self._connect() as connection:
                connection.execute("BEGIN")
                self._read_state(connection)
                connection.commit()
        except PersistentM4ExecutionStoreError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise PersistentM4ExecutionStoreError(
                "M4 execution state readiness validation failed."
            ) from exc

    @property
    def claim_count(self) -> int:
        """Count verified reservations, including unfinished claims after restart."""
        try:
            with self._connect() as connection:
                connection.execute("BEGIN")
                state = self._read_state(connection)
                connection.commit()
                return len(state.claims)
        except PersistentM4ExecutionStoreError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise PersistentM4ExecutionStoreError(
                "M4 execution reservation state could not be read safely."
            ) from exc

    @property
    def audit_events(self) -> tuple[M4AuditEvent, ...]:
        """Return deterministic, value-free public audit events."""

        try:
            with self._connect() as connection:
                connection.execute("BEGIN")
                state = self._read_state(connection)
                connection.commit()
                return state.audit
        except PersistentM4ExecutionStoreError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise PersistentM4ExecutionStoreError(
                "M4 execution audit state could not be read safely."
            ) from exc

    def inspect_claim(
        self, *, plan_ref: str, requester_digest: str, idempotency_digest: str,
        context_digest: str, authorization_digest: str,
    ) -> M4Claim:
        """Read one exact verified reservation without creating or consuming it."""
        _require_ref(plan_ref, "plan_ref")
        for field, value in (("requester_digest", requester_digest),
                             ("idempotency_digest", idempotency_digest),
                             ("context_digest", context_digest),
                             ("authorization_digest", authorization_digest)):
            _require_digest(value, field)
        namespace = self._namespace(plan_ref, requester_digest, idempotency_digest)
        context_key = self._digest_key("context", context_digest)
        authorization_key = self._digest_key("execution-authorization", authorization_digest)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN")
                state = self._read_state(connection)
                existing = state.claims.get(namespace)
                original = connection.execute(
                    "SELECT authorization_key FROM execution_ledger WHERE event_type = 'claim' "
                    "AND plan_key = ? AND requester_key = ? AND idempotency_key = ?",
                    (namespace.plan_key, namespace.requester_key, namespace.idempotency_key),
                ).fetchone()
                if (existing is None or not hmac.compare_digest(existing.context_key, context_key)
                        or original is None
                        or not hmac.compare_digest(original["authorization_key"], authorization_key)):
                    raise M4ExecutionError("execution reservation is unavailable.")
                connection.commit()
                return M4Claim(M4ClaimState.IN_PROGRESS if existing.result is None
                               else M4ClaimState.REPLAY, existing.result)
        except M4ExecutionError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError):
            raise PersistentM4ExecutionStoreError("M4 execution reservation cannot be inspected safely.") from None

    def _inspect_original_claims(
        self, *, plan_ref: str, requester_digest: str, idempotency_digests: tuple[str, ...],
    ) -> tuple[M4Claim, ...]:
        """One private, checkpoint-verified parent snapshot; never reserves a line.

        Original tuple status is sufficient to stop forward work. A verified
        result alone grants no dependency ownership or new dispatch authority;
        callers still join exact authorization/ACK/material evidence separately.
        """
        _require_ref(plan_ref, 'plan_ref')
        _require_digest(requester_digest, 'requester_digest')
        if (not self.monotonic_checkpoint_protocol_bound or type(idempotency_digests) is not tuple
                or not 1 <= len(idempotency_digests) <= 512):
            raise PersistentM4ExecutionStoreError('Original parent claims are unavailable.')
        for value in idempotency_digests:
            _require_digest(value, 'original idempotency')
        if len(set(idempotency_digests)) != len(idempotency_digests):
            raise PersistentM4ExecutionStoreError('Original parent claims are unavailable.')
        try:
            with self._connect() as connection:
                connection.execute('BEGIN')
                state = self._read_state(connection)
                result = []
                for value in idempotency_digests:
                    existing = state.claims.get(self._namespace(plan_ref, requester_digest, value))
                    result.append(M4Claim(M4ClaimState.NEW) if existing is None else
                        M4Claim(M4ClaimState.IN_PROGRESS) if existing.result is None else
                        M4Claim(M4ClaimState.REPLAY, existing.result))
                connection.commit()
                return tuple(result)
        except M4ExecutionError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError):
            raise PersistentM4ExecutionStoreError('Original parent claims cannot be inspected safely.') from None

    def claim(
        self,
        *,
        plan_ref: str,
        requester_digest: str,
        idempotency_digest: str,
        context_digest: str,
        authorization_digest: str,
    ) -> M4Claim:
        """Atomically reserve one context and consume one authorization."""

        self._require_writable()
        _require_ref(plan_ref, "plan_ref")
        for field, value in (
            ("requester_digest", requester_digest),
            ("idempotency_digest", idempotency_digest),
            ("context_digest", context_digest),
            ("authorization_digest", authorization_digest),
        ):
            _require_digest(value, field)
        namespace = self._namespace(plan_ref, requester_digest, idempotency_digest)
        context_key = self._digest_key("context", context_digest)
        authorization_key = self._digest_key(
            "execution-authorization", authorization_digest
        )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._read_state(connection)
                existing = state.claims.get(namespace)
                if existing is not None:
                    if not hmac.compare_digest(existing.context_key, context_key):
                        connection.rollback()
                        raise M4ExecutionError("idempotency context conflict.")
                    connection.commit()
                    if existing.result is None:
                        return M4Claim(M4ClaimState.IN_PROGRESS)
                    return M4Claim(M4ClaimState.REPLAY, existing.result)
                if authorization_key in state.authorizations:
                    connection.rollback()
                    raise M4AuthorizationReplay(
                        "execution authorization was already consumed."
                    )
                previous_tail = self._checkpoint_tail(state)
                current_tail = self._append_record(
                    connection,
                    state,
                    _Record.claim(namespace, context_key, authorization_key),
                )
                connection.commit()
                self._advance_monotonic_checkpoint(previous_tail, current_tail)
                return M4Claim(M4ClaimState.NEW)
        except (M4ExecutionError, M4AuthorizationReplay):
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise PersistentM4ExecutionStoreError(
                "M4 execution state could not be claimed safely."
            ) from exc

    def finalize(
        self,
        *,
        plan_ref: str,
        requester_digest: str,
        idempotency_digest: str,
        context_digest: str,
        result: M4ExecutionResult,
        event: M4AuditEvent,
    ) -> None:
        """Atomically persist one terminal result and its public audit event."""

        self._require_writable()
        _require_ref(plan_ref, "plan_ref")
        for field, value in (
            ("requester_digest", requester_digest),
            ("idempotency_digest", idempotency_digest),
            ("context_digest", context_digest),
        ):
            _require_digest(value, field)
        _validate_result(result)
        _validate_audit(event)
        if (
            event.outcome is not result.outcome
            or event.verification is not result.verification
            or event.compensation is not result.compensation
        ):
            raise PersistentM4ExecutionStoreError(
                "M4 execution result and audit event are inconsistent."
            )
        namespace = self._namespace(plan_ref, requester_digest, idempotency_digest)
        context_key = self._digest_key("context", context_digest)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._read_state(connection)
                existing = state.claims.get(namespace)
                if (
                    existing is None
                    or not hmac.compare_digest(existing.context_key, context_key)
                    or existing.result is not None
                ):
                    connection.rollback()
                    raise M4ExecutionError("execution claim cannot be finalized.")
                previous_tail = self._checkpoint_tail(state)
                current_tail = self._append_record(
                    connection,
                    state,
                    _Record.finalize(
                        namespace,
                        context_key,
                        result,
                        _renumber(event, len(state.audit) + 1),
                    ),
                )
                connection.commit()
                self._advance_monotonic_checkpoint(previous_tail, current_tail)
        except M4ExecutionError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise PersistentM4ExecutionStoreError(
                "M4 execution final state could not be persisted safely."
            ) from exc

    def append_audit(self, event: M4AuditEvent) -> None:
        """Append one closed public audit event under the same HMAC chain."""

        self._require_writable()
        _validate_audit(event)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._read_state(connection)
                previous_tail = self._checkpoint_tail(state)
                current_tail = self._append_record(
                    connection,
                    state,
                    _Record.audit_only(_renumber(event, len(state.audit) + 1)),
                )
                connection.commit()
                self._advance_monotonic_checkpoint(previous_tail, current_tail)
        except PersistentM4ExecutionStoreError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise PersistentM4ExecutionStoreError(
                "M4 execution audit event could not be persisted safely."
            ) from exc

    def _read_state(self, connection: sqlite3.Connection) -> _State:
        anchor = connection.execute(
            "SELECT last_sequence, last_hmac, anchor_hmac "
            "FROM execution_integrity_anchor WHERE singleton = 1"
        ).fetchone()
        if anchor is None:
            raise PersistentM4ExecutionStoreError(
                "M4 execution integrity anchor is unavailable."
            )
        anchor_sequence = int(anchor["last_sequence"])
        anchor_hmac = str(anchor["last_hmac"])
        if not hmac.compare_digest(
            str(anchor["anchor_hmac"]),
            self._anchor_hmac(anchor_sequence, anchor_hmac),
        ):
            raise PersistentM4ExecutionStoreError(
                "M4 execution integrity anchor is invalid."
            )

        claims: dict[_Namespace, _ClaimState] = {}
        authorizations: set[str] = set()
        audit: list[M4AuditEvent] = []
        previous_hmac = _CHAIN_ROOT
        expected_sequence = 1
        rows = connection.execute(
            "SELECT * FROM execution_ledger ORDER BY sequence"
        ).fetchall()
        for row in rows:
            record = _Record.from_row(row)
            if (
                record.sequence != expected_sequence
                or record.previous_hmac != previous_hmac
                or not hmac.compare_digest(
                    record.chain_hmac,
                    self._record_hmac(record.without_chain()),
                )
            ):
                raise PersistentM4ExecutionStoreError(
                    "M4 execution audit chain is invalid."
                )
            if record.event_type == "claim":
                self._apply_claim(record, claims, authorizations)
            elif record.event_type == "finalize":
                self._apply_finalize(record, claims, audit)
            elif record.event_type == "audit":
                self._apply_audit(record, audit)
            else:
                raise PersistentM4ExecutionStoreError(
                    "M4 execution audit chain is invalid."
                )
            previous_hmac = record.chain_hmac
            expected_sequence += 1
        if anchor_sequence != len(rows) or not hmac.compare_digest(
            anchor_hmac, previous_hmac
        ):
            raise PersistentM4ExecutionStoreError(
                "M4 execution integrity anchor does not match the audit chain."
            )
        state = _State(
            claims,
            authorizations,
            tuple(audit),
            len(rows),
            previous_hmac,
        )
        self._verify_monotonic_checkpoint(self._checkpoint_tail(state))
        return state

    @staticmethod
    def _apply_claim(
        record: _Record,
        claims: dict[_Namespace, _ClaimState],
        authorizations: set[str],
    ) -> None:
        if not record.is_valid_claim():
            raise PersistentM4ExecutionStoreError(
                "M4 execution claim record is invalid."
            )
        namespace = record.namespace()
        assert record.context_key is not None
        assert record.authorization_key is not None
        if namespace in claims or record.authorization_key in authorizations:
            raise PersistentM4ExecutionStoreError(
                "M4 execution claim ledger is inconsistent."
            )
        claims[namespace] = _ClaimState(record.context_key, None)
        authorizations.add(record.authorization_key)

    @staticmethod
    def _apply_finalize(
        record: _Record,
        claims: dict[_Namespace, _ClaimState],
        audit: list[M4AuditEvent],
    ) -> None:
        if not record.is_valid_finalize():
            raise PersistentM4ExecutionStoreError(
                "M4 execution final record is invalid."
            )
        namespace = record.namespace()
        prior = claims.get(namespace)
        result = record.result()
        event = record.audit_event()
        assert record.context_key is not None
        if (
            prior is None
            or prior.result is not None
            or not hmac.compare_digest(prior.context_key, record.context_key)
            or event.ordinal != len(audit) + 1
            or event.outcome is not result.outcome
            or event.verification is not result.verification
            or event.compensation is not result.compensation
        ):
            raise PersistentM4ExecutionStoreError(
                "M4 execution final ledger is inconsistent."
            )
        claims[namespace] = _ClaimState(prior.context_key, result)
        audit.append(event)

    @staticmethod
    def _apply_audit(record: _Record, audit: list[M4AuditEvent]) -> None:
        if not record.is_valid_audit():
            raise PersistentM4ExecutionStoreError(
                "M4 execution audit record is invalid."
            )
        event = record.audit_event()
        if event.ordinal != len(audit) + 1:
            raise PersistentM4ExecutionStoreError(
                "M4 execution audit ordinal is invalid."
            )
        audit.append(event)

    def _append_record(
        self,
        connection: sqlite3.Connection,
        state: _State,
        record: _Record,
    ) -> M4ExecutionStoreTail | None:
        sequence = state.last_sequence + 1
        unsigned = record.numbered(sequence, state.last_hmac)
        chain_hmac = self._record_hmac(unsigned)
        values = unsigned.with_chain(chain_hmac)
        connection.execute(
            """
            INSERT INTO execution_ledger(
                sequence, event_type, plan_key, requester_key, idempotency_key,
                context_key, authorization_key, result_outcome,
                result_verification, result_compensation, result_replay,
                public_ordinal, audit_authorization, audit_outcome,
                audit_verification, audit_compensation, audit_digest_reference,
                previous_hmac, chain_hmac
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values.as_sql_tuple(),
        )
        connection.execute(
            """
            UPDATE execution_integrity_anchor
            SET last_sequence = ?, last_hmac = ?, anchor_hmac = ?
            WHERE singleton = 1
            """,
            (sequence, chain_hmac, self._anchor_hmac(sequence, chain_hmac)),
        )
        return self._checkpoint_tail_values(sequence, chain_hmac)

    def _checkpoint_tail(
        self,
        state: _State,
    ) -> M4ExecutionStoreTail | None:
        return self._checkpoint_tail_values(state.last_sequence, state.last_hmac)

    def _checkpoint_tail_values(
        self,
        sequence: int,
        chain_hmac: str,
    ) -> M4ExecutionStoreTail | None:
        if self._monotonic_checkpoint is None:
            return None
        if self._checkpoint_store_ref is None:
            raise PersistentM4ExecutionStoreError(
                "M4 execution checkpoint store binding is unavailable."
            )
        return M4ExecutionStoreTail(
            self._checkpoint_store_ref,
            sequence,
            chain_hmac,
        )

    def _verify_monotonic_checkpoint(
        self,
        tail: M4ExecutionStoreTail | None,
    ) -> None:
        checkpoint = self._monotonic_checkpoint
        if checkpoint is None:
            return
        if tail is None:
            raise PersistentM4ExecutionStoreError(
                "M4 execution checkpoint state is unavailable."
            )
        try:
            checkpoint.verify(tail)
        except M4MonotonicCheckpointError as exc:
            raise PersistentM4ExecutionStoreError(
                "M4 execution checkpoint verification failed."
            ) from exc

    def _advance_monotonic_checkpoint(
        self,
        previous: M4ExecutionStoreTail | None,
        current: M4ExecutionStoreTail | None,
    ) -> None:
        checkpoint = self._monotonic_checkpoint
        if checkpoint is None:
            return
        if previous is None or current is None:
            raise PersistentM4ExecutionStoreError(
                "M4 execution checkpoint state is unavailable."
            )
        try:
            checkpoint.advance(previous, current)
        except M4MonotonicCheckpointError as exc:
            raise PersistentM4ExecutionStoreError(
                "M4 execution checkpoint advance failed."
            ) from exc

    def _namespace(
        self, plan_ref: str, requester_digest: str, idempotency_digest: str
    ) -> _Namespace:
        return _Namespace(
            self._reference_key("plan", plan_ref),
            self._digest_key("requester", requester_digest),
            self._digest_key("idempotency", idempotency_digest),
        )

    def _reference_key(self, domain: str, value: str) -> str:
        return _hmac_hex(
            self._key,
            domain.encode("ascii") + b"\x00" + value.encode("utf-8"),
        )

    def _digest_key(self, domain: str, value: str) -> str:
        return _hmac_hex(
            self._key,
            domain.encode("ascii") + b"\x00" + value.encode("ascii"),
        )

    def _record_hmac(self, record: _Record) -> str:
        return _hmac_hex(self._key, _canonical_bytes(record.hmac_fields()))

    def _anchor_hmac(self, sequence: int, chain_hmac: str) -> str:
        return _hmac_hex(
            self._key,
            _canonical_bytes(
                {
                    "domain": "m4-execution-tail-anchor-v1",
                    "last_hmac": chain_hmac,
                    "last_sequence": sequence,
                }
            ),
        )

    def _prepare_database_path(self) -> bool:
        if not self._path.is_absolute() or not self._key_path.is_absolute():
            raise PersistentM4ExecutionStoreError(
                "M4 execution state paths must be absolute and owner-only."
            )
        try:
            _assert_no_symlink_components(self._path.parent)
            if self._read_only:
                _assert_owner_only(self._path.parent, directory=True)
                _assert_owner_only(self._path, directory=False)
                return False
            existed = self._path.parent.exists()
            self._path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            if not existed:
                os.chmod(self._path.parent, 0o700)
            _assert_owner_only(self._path.parent, directory=True)
            if self._path.exists() or self._path.is_symlink():
                _assert_owner_only(self._path, directory=False)
                return False
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self._path, flags, 0o600)
            os.close(descriptor)
            os.chmod(self._path, 0o600)
            _assert_owner_only(self._path, directory=False)
            return True
        except PersistentM4ExecutionStoreError:
            raise
        except OSError as exc:
            raise PersistentM4ExecutionStoreError(
                "M4 execution database path is unsafe."
            ) from exc

    def _load_key(self) -> bytes:
        try:
            _assert_no_symlink_components(self._key_path.parent)
            _assert_owner_only(self._key_path.parent, directory=True)
            _assert_owner_only(self._key_path, directory=False)
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self._key_path, flags)
            try:
                value = os.read(descriptor, 129)
            finally:
                os.close(descriptor)
            if not 32 <= len(value) <= 128:
                raise PersistentM4ExecutionStoreError(
                    "M4 execution HMAC key is invalid."
                )
            return value
        except PersistentM4ExecutionStoreError:
            raise
        except OSError as exc:
            raise PersistentM4ExecutionStoreError(
                "M4 execution HMAC key is invalid."
            ) from exc

    def _connect(self) -> sqlite3.Connection:
        _assert_owner_only(self._path.parent, directory=True)
        _assert_owner_only(self._path, directory=False)
        connection = sqlite3.connect(self._path.as_uri() + "?mode=ro", uri=True,
                                    timeout=5.0, isolation_level=None) if self._read_only else (
            sqlite3.connect(self._path, timeout=5.0, isolation_level=None))
        connection.row_factory = sqlite3.Row
        if self._read_only:
            connection.execute("PRAGMA query_only=ON")
        else:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA temp_store=MEMORY")
        return connection

    def _require_writable(self) -> None:
        if self._read_only:
            raise PersistentM4ExecutionStoreError("The read-only M4 execution store cannot mutate.")

    def _initialize_schema(
        self, connection: sqlite3.Connection, *, allow_create: bool
    ) -> None:
        current = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if current == 0 and not allow_create:
            raise PersistentM4ExecutionStoreError(
                "Existing M4 execution database has no trusted schema."
            )
        if current not in {0, _SCHEMA_VERSION}:
            raise PersistentM4ExecutionStoreError(
                "M4 execution state schema is unsupported."
            )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS execution_ledger(
                sequence INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL CHECK(event_type IN ('claim','finalize','audit')),
                plan_key TEXT,
                requester_key TEXT,
                idempotency_key TEXT,
                context_key TEXT,
                authorization_key TEXT,
                result_outcome TEXT,
                result_verification TEXT,
                result_compensation TEXT,
                result_replay INTEGER CHECK(result_replay IN (0,1)),
                public_ordinal INTEGER,
                audit_authorization TEXT,
                audit_outcome TEXT,
                audit_verification TEXT,
                audit_compensation TEXT,
                audit_digest_reference TEXT,
                previous_hmac TEXT NOT NULL,
                chain_hmac TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS execution_integrity_anchor(
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                last_sequence INTEGER NOT NULL,
                last_hmac TEXT NOT NULL,
                anchor_hmac TEXT NOT NULL
            ) WITHOUT ROWID
            """
        )
        anchor = connection.execute(
            "SELECT singleton FROM execution_integrity_anchor WHERE singleton = 1"
        ).fetchone()
        if anchor is None:
            if current != 0 or not allow_create:
                raise PersistentM4ExecutionStoreError(
                    "M4 execution integrity anchor is missing."
                )
            connection.execute(
                """
                INSERT INTO execution_integrity_anchor(
                    singleton, last_sequence, last_hmac, anchor_hmac
                ) VALUES (1, 0, ?, ?)
                """,
                (_CHAIN_ROOT, self._anchor_hmac(0, _CHAIN_ROOT)),
            )
        connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")


class _Namespace(tuple[str, str, str]):
    __slots__ = ()

    def __new__(cls, plan: str, requester: str, idempotency: str) -> _Namespace:
        return tuple.__new__(cls, (plan, requester, idempotency))

    @property
    def plan_key(self) -> str:
        return self[0]

    @property
    def requester_key(self) -> str:
        return self[1]

    @property
    def idempotency_key(self) -> str:
        return self[2]


class _ClaimState:
    __slots__ = ("context_key", "result")

    def __init__(self, context_key: str, result: M4ExecutionResult | None) -> None:
        self.context_key = context_key
        self.result = result


class _State:
    __slots__ = ("claims", "authorizations", "audit", "last_sequence", "last_hmac")

    def __init__(
        self,
        claims: dict[_Namespace, _ClaimState],
        authorizations: set[str],
        audit: tuple[M4AuditEvent, ...],
        last_sequence: int,
        last_hmac: str,
    ) -> None:
        self.claims = claims
        self.authorizations = authorizations
        self.audit = audit
        self.last_sequence = last_sequence
        self.last_hmac = last_hmac


@dataclass(frozen=True, slots=True)
class _Record:
    """Closed ledger row with helpers for strict shape validation."""

    sequence: int
    event_type: str
    plan_key: str | None = None
    requester_key: str | None = None
    idempotency_key: str | None = None
    context_key: str | None = None
    authorization_key: str | None = None
    result_outcome: str | None = None
    result_verification: str | None = None
    result_compensation: str | None = None
    result_replay: int | None = None
    public_ordinal: int | None = None
    audit_authorization: str | None = None
    audit_outcome: str | None = None
    audit_verification: str | None = None
    audit_compensation: str | None = None
    audit_digest_reference: str | None = None
    previous_hmac: str = ""
    chain_hmac: str = ""

    _FIELDS: ClassVar[tuple[str, ...]] = (
        "sequence",
        "event_type",
        "plan_key",
        "requester_key",
        "idempotency_key",
        "context_key",
        "authorization_key",
        "result_outcome",
        "result_verification",
        "result_compensation",
        "result_replay",
        "public_ordinal",
        "audit_authorization",
        "audit_outcome",
        "audit_verification",
        "audit_compensation",
        "audit_digest_reference",
        "previous_hmac",
        "chain_hmac",
    )

    @classmethod
    def claim(
        cls,
        namespace: _Namespace,
        context_key: str,
        authorization_key: str,
    ) -> _Record:
        return cls(
            sequence=0,
            event_type="claim",
            plan_key=namespace.plan_key,
            requester_key=namespace.requester_key,
            idempotency_key=namespace.idempotency_key,
            context_key=context_key,
            authorization_key=authorization_key,
            previous_hmac="",
            chain_hmac="",
        )

    @classmethod
    def finalize(
        cls,
        namespace: _Namespace,
        context_key: str,
        result: M4ExecutionResult,
        event: M4AuditEvent,
    ) -> _Record:
        return cls(
            sequence=0,
            event_type="finalize",
            plan_key=namespace.plan_key,
            requester_key=namespace.requester_key,
            idempotency_key=namespace.idempotency_key,
            context_key=context_key,
            result_outcome=result.outcome.value,
            result_verification=result.verification.value,
            result_compensation=result.compensation.value,
            result_replay=int(result.idempotent_replay),
            public_ordinal=event.ordinal,
            audit_authorization=event.authorization,
            audit_outcome=event.outcome.value,
            audit_verification=event.verification.value,
            audit_compensation=event.compensation.value,
            audit_digest_reference=event.digest_reference,
            previous_hmac="",
            chain_hmac="",
        )

    @classmethod
    def audit_only(cls, event: M4AuditEvent) -> _Record:
        return cls(
            sequence=0,
            event_type="audit",
            public_ordinal=event.ordinal,
            audit_authorization=event.authorization,
            audit_outcome=event.outcome.value,
            audit_verification=event.verification.value,
            audit_compensation=event.compensation.value,
            audit_digest_reference=event.digest_reference,
            previous_hmac="",
            chain_hmac="",
        )

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> _Record:
        return cls(
            sequence=int(row["sequence"]),
            event_type=str(row["event_type"]),
            plan_key=_optional_str(row["plan_key"]),
            requester_key=_optional_str(row["requester_key"]),
            idempotency_key=_optional_str(row["idempotency_key"]),
            context_key=_optional_str(row["context_key"]),
            authorization_key=_optional_str(row["authorization_key"]),
            result_outcome=_optional_str(row["result_outcome"]),
            result_verification=_optional_str(row["result_verification"]),
            result_compensation=_optional_str(row["result_compensation"]),
            result_replay=_optional_int(row["result_replay"]),
            public_ordinal=_optional_int(row["public_ordinal"]),
            audit_authorization=_optional_str(row["audit_authorization"]),
            audit_outcome=_optional_str(row["audit_outcome"]),
            audit_verification=_optional_str(row["audit_verification"]),
            audit_compensation=_optional_str(row["audit_compensation"]),
            audit_digest_reference=_optional_str(row["audit_digest_reference"]),
            previous_hmac=str(row["previous_hmac"]),
            chain_hmac=str(row["chain_hmac"]),
        )

    def numbered(self, sequence: int, previous_hmac: str) -> _Record:
        return replace(
            self,
            sequence=sequence,
            previous_hmac=previous_hmac,
            chain_hmac="",
        )

    def with_chain(self, chain_hmac: str) -> _Record:
        return replace(self, chain_hmac=chain_hmac)

    def without_chain(self) -> _Record:
        return replace(self, chain_hmac="")

    def as_dict(self) -> dict[str, object]:
        return {field: getattr(self, field) for field in self._FIELDS}

    def as_sql_tuple(self) -> tuple[object, ...]:
        return tuple(getattr(self, field) for field in self._FIELDS)

    def hmac_fields(self) -> dict[str, object]:
        return {
            field: getattr(self, field)
            for field in self._FIELDS
            if field != "chain_hmac"
        }

    def namespace(self) -> _Namespace:
        if not all(
            _is_digest(value)
            for value in (self.plan_key, self.requester_key, self.idempotency_key)
        ):
            raise PersistentM4ExecutionStoreError(
                "M4 execution namespace record is invalid."
            )
        return _Namespace(
            str(self.plan_key), str(self.requester_key), str(self.idempotency_key)
        )

    def result(self) -> M4ExecutionResult:
        try:
            return M4ExecutionResult(
                M4Outcome(str(self.result_outcome)),
                M4Verification(str(self.result_verification)),
                M4Compensation(str(self.result_compensation)),
                bool(_strict_bit(self.result_replay)),
            )
        except (TypeError, ValueError) as exc:
            raise PersistentM4ExecutionStoreError(
                "M4 execution result record is invalid."
            ) from exc

    def audit_event(self) -> M4AuditEvent:
        try:
            event = M4AuditEvent(
                _required_int(self.public_ordinal),
                str(self.audit_authorization),
                M4Outcome(str(self.audit_outcome)),
                M4Verification(str(self.audit_verification)),
                M4Compensation(str(self.audit_compensation)),
                str(self.audit_digest_reference),
            )
            _validate_audit(event)
            return event
        except (TypeError, ValueError) as exc:
            raise PersistentM4ExecutionStoreError(
                "M4 execution audit record is invalid."
            ) from exc

    def is_valid_claim(self) -> bool:
        return (
            self.event_type == "claim"
            and all(
                _is_digest(value)
                for value in (
                    self.plan_key,
                    self.requester_key,
                    self.idempotency_key,
                    self.context_key,
                    self.authorization_key,
                )
            )
            and all(
                getattr(self, field) is None
                for field in (
                    "result_outcome",
                    "result_verification",
                    "result_compensation",
                    "result_replay",
                    "public_ordinal",
                    "audit_authorization",
                    "audit_outcome",
                    "audit_verification",
                    "audit_compensation",
                    "audit_digest_reference",
                )
            )
        )

    def is_valid_finalize(self) -> bool:
        try:
            result = self.result()
            event = self.audit_event()
        except PersistentM4ExecutionStoreError:
            return False
        return (
            self.event_type == "finalize"
            and all(
                _is_digest(value)
                for value in (
                    self.plan_key,
                    self.requester_key,
                    self.idempotency_key,
                    self.context_key,
                )
            )
            and self.authorization_key is None
            and event.outcome is result.outcome
            and event.verification is result.verification
            and event.compensation is result.compensation
        )

    def is_valid_audit(self) -> bool:
        try:
            self.audit_event()
        except PersistentM4ExecutionStoreError:
            return False
        return self.event_type == "audit" and all(
            getattr(self, field) is None
            for field in (
                "plan_key",
                "requester_key",
                "idempotency_key",
                "context_key",
                "authorization_key",
                "result_outcome",
                "result_verification",
                "result_compensation",
                "result_replay",
            )
        )


def _validate_result(result: object) -> None:
    if (
        not isinstance(result, M4ExecutionResult)
        or not isinstance(result.outcome, M4Outcome)
        or not isinstance(result.verification, M4Verification)
        or not isinstance(result.compensation, M4Compensation)
        or type(result.idempotent_replay) is not bool
    ):
        raise PersistentM4ExecutionStoreError(
            "M4 execution result is invalid."
        )


def _validate_audit(event: object) -> None:
    if (
        not isinstance(event, M4AuditEvent)
        or type(event.ordinal) is not int
        or event.ordinal < 0
        or not isinstance(event.authorization, str)
        or _AUDIT_AUTHORIZATION.fullmatch(event.authorization) is None
        or not isinstance(event.outcome, M4Outcome)
        or not isinstance(event.verification, M4Verification)
        or not isinstance(event.compensation, M4Compensation)
        or not _is_digest(event.digest_reference)
    ):
        raise PersistentM4ExecutionStoreError(
            "M4 execution audit event is invalid."
        )


def _renumber(event: M4AuditEvent, ordinal: int) -> M4AuditEvent:
    return M4AuditEvent(
        ordinal,
        event.authorization,
        event.outcome,
        event.verification,
        event.compensation,
        event.digest_reference,
    )


def _require_ref(value: object, field: str) -> None:
    if not isinstance(value, str) or _REF.fullmatch(value) is None:
        raise PersistentM4ExecutionStoreError(f"{field} is invalid.")


def _require_digest(value: object, field: str) -> None:
    if not _is_digest(value):
        raise PersistentM4ExecutionStoreError(f"{field} is invalid.")


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _strict_bit(value: object) -> int:
    if type(value) is not int or value not in {0, 1}:
        raise ValueError("not a strict SQLite bit")
    return value


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    if type(value) is not str:
        raise PersistentM4ExecutionStoreError(
            "M4 execution ledger text field is invalid."
        )
    return value


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int:
        raise PersistentM4ExecutionStoreError(
            "M4 execution ledger integer field is invalid."
        )
    return value


def _required_int(value: object) -> int:
    if type(value) is not int:
        raise PersistentM4ExecutionStoreError(
            "M4 execution ledger integer field is invalid."
        )
    return value


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _hmac_hex(key: bytes, value: bytes) -> str:
    return hmac.new(key, value, hashlib.sha256).hexdigest()


def _assert_no_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if current.exists() or current.is_symlink():
            if stat.S_ISLNK(os.lstat(current).st_mode):
                raise PersistentM4ExecutionStoreError(
                    "M4 execution state path is unsafe."
                )


def _assert_owner_only(path: Path, *, directory: bool) -> None:
    details = os.lstat(path)
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    required_mode = 0o700 if directory else 0o600
    if (
        stat.S_ISLNK(details.st_mode)
        or details.st_uid != os.getuid()
        or not expected_type(details.st_mode)
        or stat.S_IMODE(details.st_mode) != required_mode
    ):
        raise PersistentM4ExecutionStoreError(
            "M4 execution state path must be owner-only."
        )


__all__ = [
    "M4ExecutionStoreTail",
    "M4MonotonicCheckpointError",
    "MonotonicM4ExecutionCheckpoint",
    "PersistentM4ExecutionStateStore",
    "PersistentM4ExecutionStoreError",
]
