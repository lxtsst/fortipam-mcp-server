"""Owner-only persistent state for V3 controlled operations.

The store is deliberately transport and product independent.  It persists only
closed approval bindings, operation outcomes, and HMAC-derived references.  Raw
approval, nonce, principal, target, and idempotency values are never stored.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import time
from typing import Callable, Final

from .controlled_operations import (
    ApprovalBinding,
    ApprovalRejected,
    AuditEvent,
    AuthenticatedPrincipal,
    ClaimState as EngineClaimState,
    ControlledOperationResult,
    IdempotencyConflict,
    OperationClaim,
    PublicOutcome,
    RollbackState,
    VerificationState,
    VerifiedApprovalClaims,
)


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ACTION = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_PURPOSES: Final = frozenset({"forward", "rollback"})
_APPROVAL_STATES: Final = frozenset({"issued", "approved", "denied"})
_IDEMPOTENCY_STATES: Final = frozenset({"claimed", "finalized"})
_AUDIT_EVENTS: Final = frozenset(
    {
        "approval_issued",
        "approval_approved",
        "approval_denied",
        "approval_verified",
        "operation_claimed",
        "operation_finalized",
        "operation_denied",
        "idempotent_replay",
        "idempotent_in_progress",
        "store_verified",
    }
)
_AUTHORIZATION: Final = frozenset(
    {
        "pending",
        "approved",
        "denied",
        "consumed",
        "idempotent_replay",
        "idempotent_in_progress",
    }
)
_MAX_APPROVAL_LIFETIME: Final = 900
_SCHEMA_VERSION: Final = 1


class ControlledOperationStoreError(ValueError):
    """Raised when persistent controlled-operation state cannot be trusted."""


class ClaimState(StrEnum):
    NEW = "new"
    REPLAY = "replay"
    IN_PROGRESS = "in_progress"
    MISSING = "missing"


@dataclass(frozen=True, slots=True)
class IssuedApproval:
    """Ephemeral references returned once to the trusted approval transport."""

    approval_reference: str
    approval_nonce: str
    expires_at: int


@dataclass(frozen=True, slots=True)
class StateClaim:
    state: ClaimState
    result: ControlledOperationResult | None = None


@dataclass(frozen=True, slots=True)
class PersistentAuditEvent:
    """Closed audit input; all reference digests are HMAC-hidden at rest."""

    event_type: str
    principal_digest: str
    principal_class: str
    action_id: str
    action_version: str
    target_class: str
    purpose: str
    authorization: str
    outcome: str
    verification: str
    rollback: str
    digest_reference: str
    occurred_at: int

    def __post_init__(self) -> None:
        if not _valid_audit_event(self):
            raise ControlledOperationStoreError(
                "The controlled operation audit event is invalid."
            )


class ControlledOperationStateStore:
    """SQLite approval verifier and persistent engine state boundary.

    ``claim`` atomically consumes a verified receipt and reserves one
    principal-scoped idempotency key.  A matching unfinished reservation is
    reported as ``in_progress`` after restart or concurrency, so an engine must
    not execute the adapter again.
    """

    def __init__(
        self,
        database_path: Path,
        hmac_key_path: Path,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._path = Path(database_path)
        self._key_path = Path(hmac_key_path)
        self._clock = clock or (lambda: int(time.time()))
        if not callable(self._clock):
            raise ControlledOperationStoreError(
                "The controlled operation store clock is invalid."
            )
        self._prepare_database_path()
        self._key = self._load_key()
        try:
            with self._connect() as connection:
                self._initialize_schema(connection)
                self._verify_audit_chain(connection)
        except ControlledOperationStoreError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise ControlledOperationStoreError(
                "The controlled operation store integrity check failed."
            ) from exc

    def issue_approval(
        self,
        binding: ApprovalBinding,
        *,
        lifetime_seconds: int = 300,
        now_epoch: int | None = None,
    ) -> IssuedApproval:
        """Issue one opaque approval reference and single-use decision nonce."""

        _validate_binding(binding)
        now = self._now(now_epoch)
        if (
            type(lifetime_seconds) is not int
            or lifetime_seconds < 30
            or lifetime_seconds > _MAX_APPROVAL_LIFETIME
        ):
            raise ControlledOperationStoreError(
                "The controlled operation approval lifetime is invalid."
            )
        approval_reference = "approval-" + secrets.token_urlsafe(32)
        nonce = "nonce-" + secrets.token_urlsafe(32)
        approval_key = self._reference_key("approval", approval_reference)
        nonce_key = self._reference_key("nonce", nonce)
        receipt_id, nonce_digest, receipt_key = self._receipt_material(approval_key, nonce_key)
        expires_at = now + lifetime_seconds
        principal_key = self._digest_key("principal", binding.principal_digest)
        target_key = self._digest_key("target", binding.target_digest)
        event = self._approval_audit(
            "approval_issued", binding, "pending", now, approval_key
        )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._verify_audit_chain(connection)
                connection.execute(
                    """
                    INSERT INTO approvals(
                        approval_key, nonce_key, receipt_key, state, purpose,
                        principal_key, action_id, action_version, target_key,
                        parameters_digest, expected_current_digest, issued_at,
                        expires_at, decided_at, approver_key, receipt_consumed
                    ) VALUES (?, ?, ?, 'issued', ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, 0)
                    """,
                    (
                        approval_key,
                        nonce_key,
                        receipt_key,
                        binding.purpose,
                        principal_key,
                        binding.action_id,
                        binding.action_version,
                        target_key,
                        binding.parameters_digest,
                        binding.expected_current_digest,
                        now,
                        expires_at,
                    ),
                )
                self._append_audit(connection, event)
                connection.commit()
        except (ControlledOperationStoreError, sqlite3.IntegrityError):
            raise ControlledOperationStoreError(
                "The controlled operation approval could not be issued."
            )
        except (OSError, sqlite3.Error) as exc:
            raise ControlledOperationStoreError(
                "The controlled operation approval could not be issued."
            ) from exc
        # receipt_id and nonce_digest are intentionally derived, never persisted raw.
        assert receipt_id and nonce_digest
        return IssuedApproval(approval_reference, nonce, expires_at)

    def approve(
        self,
        approval_reference: str,
        approval_nonce: str,
        approver_principal_ref: str,
        *,
        now_epoch: int | None = None,
    ) -> None:
        self._decide(
            approval_reference,
            approval_nonce,
            approver_principal_ref,
            approved=True,
            now_epoch=now_epoch,
        )

    def deny(
        self,
        approval_reference: str,
        approval_nonce: str,
        approver_principal_ref: str,
        *,
        now_epoch: int | None = None,
    ) -> None:
        self._decide(
            approval_reference,
            approval_nonce,
            approver_principal_ref,
            approved=False,
            now_epoch=now_epoch,
        )

    def verify(
        self,
        approval_reference: str,
        principal: AuthenticatedPrincipal,
        binding: ApprovalBinding,
        *,
        now_epoch: int,
    ) -> VerifiedApprovalClaims:
        """Implement the controlled-operation ``ApprovalVerifier`` protocol."""

        _validate_binding(binding)
        if not isinstance(principal, AuthenticatedPrincipal):
            raise ApprovalRejected("The controlled operation approval was rejected.")
        authenticated_principal_digest = hashlib.sha256(
            principal.subject_ref.encode("utf-8")
        ).hexdigest()
        if not hmac.compare_digest(
            authenticated_principal_digest, binding.principal_digest
        ):
            raise ApprovalRejected("The controlled operation approval was rejected.")
        now = self._now(now_epoch)
        approval_key = self._reference_key_or_reject("approval", approval_reference)
        expected_principal = self._digest_key("principal", binding.principal_digest)
        expected_target = self._digest_key("target", binding.target_digest)
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM approvals WHERE approval_key = ?", (approval_key,)
                ).fetchone()
                self._verify_audit_chain(connection)
            if (
                row is None
                or row["state"] != "approved"
                or int(row["expires_at"]) <= now
                or row["purpose"] != binding.purpose
                or row["principal_key"] != expected_principal
                or row["action_id"] != binding.action_id
                or row["action_version"] != binding.action_version
                or row["target_key"] != expected_target
                or row["parameters_digest"] != binding.parameters_digest
                or row["expected_current_digest"] != binding.expected_current_digest
            ):
                raise ApprovalRejected(
                    "The controlled operation approval was rejected."
                )
            receipt_id, nonce_digest, receipt_key = self._receipt_material(
                approval_key, str(row["nonce_key"])
            )
            if not hmac.compare_digest(receipt_key, str(row["receipt_key"])):
                raise ApprovalRejected(
                    "The controlled operation approval was rejected."
                )
            return VerifiedApprovalClaims(
                receipt_id=receipt_id,
                binding=binding,
                nonce_digest=nonce_digest,
                expires_at=int(row["expires_at"]),
            )
        except ApprovalRejected:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise ApprovalRejected(
                "The controlled operation approval was rejected."
            ) from exc

    def claim(
        self,
        purpose: str,
        principal_digest: str,
        idempotency_digest: str,
        context_digest: str,
        receipt_digest: str,
        *,
        now_epoch: int | None = None,
    ) -> StateClaim:
        """Atomically reserve idempotency state and consume one approval receipt."""

        _validate_state_request(
            purpose, principal_digest, idempotency_digest, context_digest
        )
        _require_digest(receipt_digest)
        now = self._now(now_epoch)
        principal_key = self._digest_key("principal", principal_digest)
        idempotency_key = self._digest_key("idempotency", idempotency_digest)
        receipt_key = self._digest_key("receipt-consume", receipt_digest)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._verify_audit_chain(connection)
                prior = connection.execute(
                    """
                    SELECT * FROM idempotency
                    WHERE purpose = ? AND principal_key = ? AND idempotency_key = ?
                    """,
                    (purpose, principal_key, idempotency_key),
                ).fetchone()
                if prior is not None:
                    if not hmac.compare_digest(str(prior["context_digest"]), context_digest):
                        connection.rollback()
                        raise IdempotencyConflict(
                            "The controlled operation idempotency context conflicts."
                        )
                    if prior["state"] == "finalized":
                        result = _result_from_row(prior, replay=True)
                        connection.commit()
                        return StateClaim(ClaimState.REPLAY, result)
                    connection.commit()
                    return StateClaim(
                        ClaimState.IN_PROGRESS, _unknown_replay(purpose)
                    )
                approval = connection.execute(
                    "SELECT * FROM approvals WHERE receipt_key = ?", (receipt_key,)
                ).fetchone()
                if (
                    approval is None
                    or approval["state"] != "approved"
                    or int(approval["expires_at"]) <= now
                    or int(approval["receipt_consumed"]) != 0
                    or approval["purpose"] != purpose
                    or approval["principal_key"] != principal_key
                ):
                    connection.rollback()
                    raise ApprovalRejected(
                        "The controlled operation approval was rejected."
                    )
                updated = connection.execute(
                    """
                    UPDATE approvals SET receipt_consumed = 1
                    WHERE approval_key = ? AND receipt_consumed = 0
                    """,
                    (approval["approval_key"],),
                ).rowcount
                if updated != 1:
                    connection.rollback()
                    raise ApprovalRejected(
                        "The controlled operation approval was rejected."
                    )
                connection.execute(
                    """
                    INSERT INTO idempotency(
                        purpose, principal_key, idempotency_key, context_digest,
                        state, outcome, verification, rollback, claimed_at, finalized_at
                    ) VALUES (?, ?, ?, ?, 'claimed', NULL, NULL, NULL, ?, NULL)
                    """,
                    (purpose, principal_key, idempotency_key, context_digest, now),
                )
                event = self._row_audit(
                    "operation_claimed", approval, "consumed", now, idempotency_key
                )
                self._append_audit(connection, event)
                connection.commit()
                return StateClaim(ClaimState.NEW)
        except (ApprovalRejected, IdempotencyConflict):
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise ControlledOperationStoreError(
                "The controlled operation state could not be claimed."
            ) from exc

    def get_idempotency(
        self,
        purpose: str,
        principal_digest: str,
        idempotency_digest: str,
        context_digest: str,
    ) -> StateClaim:
        """Read a principal-scoped idempotency result without reserving it."""

        _validate_state_request(
            purpose, principal_digest, idempotency_digest, context_digest
        )
        principal_key = self._digest_key("principal", principal_digest)
        idempotency_key = self._digest_key("idempotency", idempotency_digest)
        try:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT * FROM idempotency
                    WHERE purpose = ? AND principal_key = ? AND idempotency_key = ?
                    """,
                    (purpose, principal_key, idempotency_key),
                ).fetchone()
                self._verify_audit_chain(connection)
            if row is None:
                return StateClaim(ClaimState.MISSING)
            if not hmac.compare_digest(str(row["context_digest"]), context_digest):
                raise IdempotencyConflict(
                    "The controlled operation idempotency context conflicts."
                )
            if row["state"] == "claimed":
                return StateClaim(ClaimState.IN_PROGRESS, _unknown_replay(purpose))
            return StateClaim(ClaimState.REPLAY, _result_from_row(row, replay=True))
        except IdempotencyConflict:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise ControlledOperationStoreError(
                "The controlled operation state could not be read."
            ) from exc

    def finalize(
        self,
        purpose: str,
        principal_digest: str,
        idempotency_digest: str,
        context_digest: str,
        result: ControlledOperationResult,
        event: PersistentAuditEvent,
        *,
        now_epoch: int | None = None,
    ) -> None:
        """Atomically persist a terminal result and its audit event."""

        _validate_state_request(
            purpose, principal_digest, idempotency_digest, context_digest
        )
        if not isinstance(result, ControlledOperationResult) or not isinstance(
            event, PersistentAuditEvent
        ):
            raise ControlledOperationStoreError(
                "The controlled operation final state is invalid."
            )
        now = self._now(now_epoch)
        principal_key = self._digest_key("principal", principal_digest)
        idempotency_key = self._digest_key("idempotency", idempotency_digest)
        if (
            event.event_type != "operation_finalized"
            or event.purpose != purpose
            or self._digest_key("principal", event.principal_digest) != principal_key
            or event.outcome != result.outcome.value
            or event.verification != result.verification.value
            or event.rollback != result.rollback.value
        ):
            raise ControlledOperationStoreError(
                "The controlled operation final state is invalid."
            )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._verify_audit_chain(connection)
                row = connection.execute(
                    """
                    SELECT * FROM idempotency
                    WHERE purpose = ? AND principal_key = ? AND idempotency_key = ?
                    """,
                    (purpose, principal_key, idempotency_key),
                ).fetchone()
                if row is None or not hmac.compare_digest(
                    str(row["context_digest"]), context_digest
                ):
                    connection.rollback()
                    raise IdempotencyConflict(
                        "The controlled operation idempotency context conflicts."
                    )
                if row["state"] == "finalized":
                    prior = _result_from_row(row, replay=False)
                    if prior != result:
                        connection.rollback()
                        raise IdempotencyConflict(
                            "The controlled operation idempotency context conflicts."
                        )
                    connection.commit()
                    return
                connection.execute(
                    """
                    UPDATE idempotency
                    SET state = 'finalized', outcome = ?, verification = ?,
                        rollback = ?, finalized_at = ?
                    WHERE purpose = ? AND principal_key = ? AND idempotency_key = ?
                    """,
                    (
                        result.outcome.value,
                        result.verification.value,
                        result.rollback.value,
                        now,
                        purpose,
                        principal_key,
                        idempotency_key,
                    ),
                )
                self._append_audit(connection, event)
                connection.commit()
        except IdempotencyConflict:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise ControlledOperationStoreError(
                "The controlled operation final state could not be persisted."
            ) from exc

    def put_idempotency(
        self,
        purpose: str,
        principal_digest: str,
        idempotency_digest: str,
        context_digest: str,
        result: ControlledOperationResult,
        event: PersistentAuditEvent,
        *,
        now_epoch: int | None = None,
    ) -> None:
        """Protocol-friendly alias for ``finalize``."""

        self.finalize(
            purpose,
            principal_digest,
            idempotency_digest,
            context_digest,
            result,
            event,
            now_epoch=now_epoch,
        )

    def append_audit(self, event: PersistentAuditEvent) -> None:
        if not isinstance(event, PersistentAuditEvent):
            raise ControlledOperationStoreError(
                "The controlled operation audit event is invalid."
            )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._verify_audit_chain(connection)
                self._append_audit(connection, event)
                connection.commit()
        except ControlledOperationStoreError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise ControlledOperationStoreError(
                "The controlled operation audit event could not be appended."
            ) from exc

    def audit_events(self) -> tuple[PersistentAuditEvent, ...]:
        """Return only closed fields and already-HMAC-hidden references."""

        try:
            with self._connect() as connection:
                self._verify_audit_chain(connection)
                rows = connection.execute(
                    "SELECT * FROM audit_events ORDER BY sequence"
                ).fetchall()
            return tuple(
                PersistentAuditEvent(
                    event_type=str(row["event_type"]),
                    principal_digest=str(row["principal_key"]),
                    principal_class=str(row["principal_class"]),
                    action_id=str(row["action_id"]),
                    action_version=str(row["action_version"]),
                    target_class=str(row["target_class"]),
                    purpose=str(row["purpose"]),
                    authorization=str(row["authorization"]),
                    outcome=str(row["outcome"]),
                    verification=str(row["verification"]),
                    rollback=str(row["rollback"]),
                    digest_reference=str(row["digest_reference"]),
                    occurred_at=int(row["occurred_at"]),
                )
                for row in rows
            )
        except ControlledOperationStoreError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise ControlledOperationStoreError(
                "The controlled operation audit chain is invalid."
            ) from exc

    def _decide(
        self,
        approval_reference: str,
        approval_nonce: str,
        approver_principal_ref: str,
        *,
        approved: bool,
        now_epoch: int | None,
    ) -> None:
        now = self._now(now_epoch)
        approval_key = self._reference_key_or_reject("approval", approval_reference)
        nonce_key = self._reference_key_or_reject("nonce", approval_nonce)
        if type(approver_principal_ref) is not str or not 8 <= len(approver_principal_ref) <= 256:
            raise ApprovalRejected("The controlled operation approval was rejected.")
        approver_key = self._reference_key("approver", approver_principal_ref)
        state = "approved" if approved else "denied"
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._verify_audit_chain(connection)
                row = connection.execute(
                    "SELECT * FROM approvals WHERE approval_key = ?", (approval_key,)
                ).fetchone()
                if (
                    row is None
                    or row["state"] != "issued"
                    or int(row["expires_at"]) <= now
                    or not hmac.compare_digest(str(row["nonce_key"]), nonce_key)
                ):
                    connection.rollback()
                    raise ApprovalRejected(
                        "The controlled operation approval was rejected."
                    )
                updated = connection.execute(
                    """
                    UPDATE approvals
                    SET state = ?, decided_at = ?, approver_key = ?
                    WHERE approval_key = ? AND state = 'issued'
                    """,
                    (state, now, approver_key, approval_key),
                ).rowcount
                if updated != 1:
                    connection.rollback()
                    raise ApprovalRejected(
                        "The controlled operation approval was rejected."
                    )
                event = self._row_audit(
                    "approval_approved" if approved else "approval_denied",
                    row,
                    state,
                    now,
                    approval_key,
                )
                self._append_audit(connection, event)
                connection.commit()
        except ApprovalRejected:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise ApprovalRejected(
                "The controlled operation approval was rejected."
            ) from exc

    def _approval_audit(
        self,
        event_type: str,
        binding: ApprovalBinding,
        authorization: str,
        occurred_at: int,
        reference: str,
    ) -> PersistentAuditEvent:
        return PersistentAuditEvent(
            event_type,
            binding.principal_digest,
            "operator",
            binding.action_id,
            binding.action_version,
            "approved-target",
            binding.purpose,
            authorization,
            "not_started",
            "not_started",
            "not_requested",
            reference,
            occurred_at,
        )

    def _row_audit(
        self,
        event_type: str,
        row: sqlite3.Row,
        authorization: str,
        occurred_at: int,
        reference: str,
    ) -> PersistentAuditEvent:
        # Row keys are already HMAC-derived or closed contract fields.
        return PersistentAuditEvent(
            event_type=event_type,
            principal_digest=str(row["principal_key"]),
            principal_class="operator",
            action_id=str(row["action_id"]),
            action_version=str(row["action_version"]),
            target_class="approved-target",
            purpose=str(row["purpose"]),
            authorization=authorization,
            outcome="not_started",
            verification="not_started",
            rollback="not_requested",
            digest_reference=reference,
            occurred_at=occurred_at,
        )

    def _append_audit(
        self, connection: sqlite3.Connection, event: PersistentAuditEvent
    ) -> None:
        prior = connection.execute(
            "SELECT sequence, chain_hmac FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if prior is None else int(prior["sequence"]) + 1
        previous_hmac = "" if prior is None else str(prior["chain_hmac"])
        principal_key = self._digest_key("audit-principal", event.principal_digest)
        digest_reference = self._digest_key("audit-reference", event.digest_reference)
        fields = {
            "sequence": sequence,
            "occurred_at": event.occurred_at,
            "event_type": event.event_type,
            "principal_key": principal_key,
            "principal_class": event.principal_class,
            "action_id": event.action_id,
            "action_version": event.action_version,
            "target_class": event.target_class,
            "purpose": event.purpose,
            "authorization": event.authorization,
            "outcome": event.outcome,
            "verification": event.verification,
            "rollback": event.rollback,
            "digest_reference": digest_reference,
            "previous_hmac": previous_hmac,
        }
        chain_hmac = _hmac_hex(self._key, _canonical_bytes(fields))
        connection.execute(
            """
            INSERT INTO audit_events(
                sequence, occurred_at, event_type, principal_key, principal_class,
                action_id, action_version, target_class, purpose, authorization,
                outcome, verification, rollback, digest_reference, previous_hmac,
                chain_hmac
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (*fields.values(), chain_hmac),
        )

    def _verify_audit_chain(self, connection: sqlite3.Connection) -> None:
        expected_sequence = 1
        previous_hmac = ""
        for row in connection.execute("SELECT * FROM audit_events ORDER BY sequence"):
            fields = {
                "sequence": int(row["sequence"]),
                "occurred_at": int(row["occurred_at"]),
                "event_type": str(row["event_type"]),
                "principal_key": str(row["principal_key"]),
                "principal_class": str(row["principal_class"]),
                "action_id": str(row["action_id"]),
                "action_version": str(row["action_version"]),
                "target_class": str(row["target_class"]),
                "purpose": str(row["purpose"]),
                "authorization": str(row["authorization"]),
                "outcome": str(row["outcome"]),
                "verification": str(row["verification"]),
                "rollback": str(row["rollback"]),
                "digest_reference": str(row["digest_reference"]),
                "previous_hmac": str(row["previous_hmac"]),
            }
            if (
                fields["sequence"] != expected_sequence
                or fields["previous_hmac"] != previous_hmac
                or fields["event_type"] not in _AUDIT_EVENTS
            ):
                raise ControlledOperationStoreError(
                    "The controlled operation audit chain is invalid."
                )
            expected = _hmac_hex(self._key, _canonical_bytes(fields))
            actual = row["chain_hmac"]
            if type(actual) is not str or not hmac.compare_digest(expected, actual):
                raise ControlledOperationStoreError(
                    "The controlled operation audit chain is invalid."
                )
            previous_hmac = actual
            expected_sequence += 1

    def _reference_key(self, domain: str, value: str) -> str:
        return _hmac_hex(self._key, domain.encode("ascii") + b"\x00" + value.encode("utf-8"))

    def _reference_key_or_reject(self, domain: str, value: object) -> str:
        if type(value) is not str or not 16 <= len(value) <= 256:
            raise ApprovalRejected("The controlled operation approval was rejected.")
        return self._reference_key(domain, value)

    def _digest_key(self, domain: str, digest: str) -> str:
        _require_digest(digest)
        return _hmac_hex(self._key, domain.encode("ascii") + b"\x00" + digest.encode("ascii"))

    def _receipt_material(self, approval_key: str, nonce_key: str) -> tuple[str, str, str]:
        receipt_id = "receipt-" + _hmac_hex(
            self._key, b"receipt-id\x00" + approval_key.encode("ascii")
        )
        nonce_digest = _hmac_hex(
            self._key, b"receipt-nonce\x00" + nonce_key.encode("ascii")
        )
        engine_digest = hashlib.sha256((receipt_id + nonce_digest).encode()).hexdigest()
        return receipt_id, nonce_digest, self._digest_key("receipt-consume", engine_digest)

    def _now(self, supplied: int | None) -> int:
        try:
            value = self._clock() if supplied is None else supplied
        except Exception as exc:
            raise ControlledOperationStoreError(
                "The controlled operation store clock is invalid."
            ) from exc
        if type(value) is not int or not 0 <= value <= 4_102_444_800:
            raise ControlledOperationStoreError(
                "The controlled operation store clock is invalid."
            )
        return value

    def _prepare_database_path(self) -> None:
        if not self._path.is_absolute() or not self._key_path.is_absolute():
            raise ControlledOperationStoreError(
                "The controlled operation store path is unsafe."
            )
        parent = self._path.parent
        try:
            _assert_no_symlink_components(parent)
            existed = parent.exists()
            parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            if not existed:
                os.chmod(parent, 0o700)
            _assert_owner_only(parent, directory=True)
            if self._path.exists() or self._path.is_symlink():
                _assert_owner_only(self._path, directory=False)
                return
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self._path, flags, 0o600)
            os.close(descriptor)
            os.chmod(self._path, 0o600)
            _assert_owner_only(self._path, directory=False)
        except ControlledOperationStoreError:
            raise
        except OSError as exc:
            raise ControlledOperationStoreError(
                "The controlled operation store path is unsafe."
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
                raise ControlledOperationStoreError(
                    "The controlled operation store key is invalid."
                )
            return value
        except ControlledOperationStoreError:
            raise
        except OSError as exc:
            raise ControlledOperationStoreError(
                "The controlled operation store key is invalid."
            ) from exc

    def _connect(self) -> sqlite3.Connection:
        _assert_owner_only(self._path.parent, directory=True)
        _assert_owner_only(self._path, directory=False)
        connection = sqlite3.connect(self._path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        return connection

    @staticmethod
    def _initialize_schema(connection: sqlite3.Connection) -> None:
        current = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if current not in {0, _SCHEMA_VERSION}:
            raise ControlledOperationStoreError(
                "The controlled operation store schema is unsupported."
            )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS approvals(
                approval_key TEXT PRIMARY KEY,
                nonce_key TEXT NOT NULL UNIQUE,
                receipt_key TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL CHECK(state IN ('issued','approved','denied')),
                purpose TEXT NOT NULL CHECK(purpose IN ('forward','rollback')),
                principal_key TEXT NOT NULL,
                action_id TEXT NOT NULL,
                action_version TEXT NOT NULL,
                target_key TEXT NOT NULL,
                parameters_digest TEXT NOT NULL,
                expected_current_digest TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                decided_at INTEGER,
                approver_key TEXT,
                receipt_consumed INTEGER NOT NULL CHECK(receipt_consumed IN (0,1))
            ) WITHOUT ROWID
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS idempotency(
                purpose TEXT NOT NULL CHECK(purpose IN ('forward','rollback')),
                principal_key TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                context_digest TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('claimed','finalized')),
                outcome TEXT,
                verification TEXT,
                rollback TEXT,
                claimed_at INTEGER NOT NULL,
                finalized_at INTEGER,
                PRIMARY KEY(purpose, principal_key, idempotency_key)
            ) WITHOUT ROWID
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events(
                sequence INTEGER PRIMARY KEY,
                occurred_at INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                principal_key TEXT NOT NULL,
                principal_class TEXT NOT NULL,
                action_id TEXT NOT NULL,
                action_version TEXT NOT NULL,
                target_class TEXT NOT NULL,
                purpose TEXT NOT NULL,
                authorization TEXT NOT NULL,
                outcome TEXT NOT NULL,
                verification TEXT NOT NULL,
                rollback TEXT NOT NULL,
                digest_reference TEXT NOT NULL,
                previous_hmac TEXT NOT NULL,
                chain_hmac TEXT NOT NULL
            )
            """
        )
        connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")


class PersistentControlledOperationEngineStore:
    """Adapt the SQLite store to the controlled-operation engine protocol."""

    def __init__(self, store: ControlledOperationStateStore) -> None:
        if not isinstance(store, ControlledOperationStateStore):
            raise ControlledOperationStoreError(
                "The controlled operation engine store is invalid."
            )
        self._store = store

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]:
        return tuple(
            AuditEvent(
                ordinal,
                event.principal_class,
                event.action_id,
                event.action_version,
                event.target_class,
                event.purpose,
                event.authorization,
                event.outcome,
                event.verification,
                event.rollback,
                event.digest_reference,
            )
            for ordinal, event in enumerate(self._store.audit_events(), start=1)
        )

    def claim(
        self,
        purpose: str,
        principal_digest: str,
        idempotency_digest: str,
        context_digest: str,
        receipt_digest: str,
    ) -> OperationClaim:
        state = self._store.claim(
            purpose,
            principal_digest,
            idempotency_digest,
            context_digest,
            receipt_digest,
        )
        if state.state is ClaimState.NEW:
            return OperationClaim(EngineClaimState.NEW)
        if state.state is ClaimState.IN_PROGRESS:
            return OperationClaim(EngineClaimState.IN_PROGRESS)
        if state.state is ClaimState.REPLAY and state.result is not None:
            return OperationClaim(EngineClaimState.REPLAY, state.result)
        raise ControlledOperationStoreError(
            "The controlled operation claim state is invalid."
        )

    def finalize(
        self,
        purpose: str,
        principal_digest: str,
        idempotency_digest: str,
        context_digest: str,
        result: ControlledOperationResult,
        event: AuditEvent,
    ) -> None:
        self._store.finalize(
            purpose,
            principal_digest,
            idempotency_digest,
            context_digest,
            result,
            self._persistent_event(
                principal_digest,
                event,
                event_type="operation_finalized",
            ),
        )

    def append_audit(self, principal_digest: str, event: AuditEvent) -> None:
        event_type = {
            "denied": "operation_denied",
            "idempotent_replay": "idempotent_replay",
            "idempotent_in_progress": "idempotent_in_progress",
        }.get(event.authorization, "operation_finalized")
        self._store.append_audit(
            self._persistent_event(
                principal_digest,
                event,
                event_type=event_type,
            )
        )

    def _persistent_event(
        self,
        principal_digest: str,
        event: AuditEvent,
        *,
        event_type: str,
    ) -> PersistentAuditEvent:
        if not isinstance(event, AuditEvent):
            raise ControlledOperationStoreError(
                "The controlled operation engine audit event is invalid."
            )
        return PersistentAuditEvent(
            event_type=event_type,
            principal_digest=principal_digest,
            principal_class=event.principal_class,
            action_id=event.action_id,
            action_version=event.action_version,
            target_class=event.target_class,
            purpose=event.purpose,
            authorization=event.authorization,
            outcome=event.outcome,
            verification=event.verification,
            rollback=event.rollback,
            digest_reference=event.digest_reference,
            occurred_at=self._store._now(None),
        )


def _assert_owner_only(path: Path, *, directory: bool) -> None:
    info = os.lstat(path)
    required_type = stat.S_ISDIR if directory else stat.S_ISREG
    required_mode = 0o700 if directory else 0o600
    if (
        stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or not required_type(info.st_mode)
        or stat.S_IMODE(info.st_mode) != required_mode
    ):
        raise ControlledOperationStoreError(
            "The controlled operation store path is unsafe."
        )


def _assert_no_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if not current.exists():
            return
        if stat.S_ISLNK(os.lstat(current).st_mode):
            raise ControlledOperationStoreError(
                "The controlled operation store path is unsafe."
            )


def _validate_binding(binding: ApprovalBinding) -> None:
    if (
        not isinstance(binding, ApprovalBinding)
        or binding.purpose not in _PURPOSES
        or _ACTION.fullmatch(binding.action_id) is None
        or _VERSION.fullmatch(binding.action_version) is None
    ):
        raise ControlledOperationStoreError(
            "The controlled operation approval binding is invalid."
        )
    for value in (
        binding.principal_digest,
        binding.target_digest,
        binding.parameters_digest,
        binding.expected_current_digest,
    ):
        _require_digest(value)


def _validate_state_request(
    purpose: str,
    principal_digest: str,
    idempotency_digest: str,
    context_digest: str,
) -> None:
    if purpose not in _PURPOSES:
        raise ControlledOperationStoreError(
            "The controlled operation state request is invalid."
        )
    for value in (principal_digest, idempotency_digest, context_digest):
        _require_digest(value)


def _require_digest(value: object) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ControlledOperationStoreError(
            "The controlled operation digest is invalid."
        )


def _valid_audit_event(event: PersistentAuditEvent) -> bool:
    return bool(
        event.event_type in _AUDIT_EVENTS
        and _DIGEST.fullmatch(event.principal_digest)
        and event.principal_class in {"operator", "automation"}
        and _ACTION.fullmatch(event.action_id)
        and _VERSION.fullmatch(event.action_version)
        and _ACTION.fullmatch(event.target_class)
        and event.purpose in _PURPOSES
        and event.authorization in _AUTHORIZATION
        and event.outcome
        in {"not_started", *(item.value for item in PublicOutcome)}
        and event.verification
        in {"not_started", *(item.value for item in VerificationState)}
        and event.rollback in {item.value for item in RollbackState}
        and _DIGEST.fullmatch(event.digest_reference)
        and type(event.occurred_at) is int
        and 0 <= event.occurred_at <= 4_102_444_800
    )


def _result_from_row(row: sqlite3.Row, *, replay: bool) -> ControlledOperationResult:
    if row["state"] not in _IDEMPOTENCY_STATES or row["state"] != "finalized":
        raise ControlledOperationStoreError(
            "The controlled operation stored result is invalid."
        )
    try:
        return ControlledOperationResult(
            PublicOutcome(str(row["outcome"])),
            VerificationState(str(row["verification"])),
            RollbackState(str(row["rollback"])),
            replay,
        )
    except ValueError as exc:
        raise ControlledOperationStoreError(
            "The controlled operation stored result is invalid."
        ) from exc


def _unknown_replay(purpose: str) -> ControlledOperationResult:
    return ControlledOperationResult(
        PublicOutcome.VERIFICATION_UNKNOWN,
        VerificationState.UNKNOWN,
        RollbackState.UNKNOWN if purpose == "rollback" else RollbackState.NOT_REQUESTED,
        True,
    )


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _hmac_hex(key: bytes, value: bytes) -> str:
    return hmac.new(key, value, hashlib.sha256).hexdigest()
