"""Owner-only SQLite/HMAC state for V4 human-intent confirmation.

The store contains no browser transport, product adapter, C3 material, approval
decision, or execution transition.  A dedicated receipt key authenticates
affirm/deny receipts independently from the append-only store chain key.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
from collections.abc import Callable, Mapping
from typing import NoReturn, cast

from .canonical import CanonicalValue, canonical_digest, canonical_json
from .confirmation import (
    ConfirmationReceiptAuthenticator,
    IntentConfirmationChallenge,
    IntentConfirmationClaim,
    IntentConfirmationError,
    IntentConfirmationReceipt,
    IntentReauthenticationRecord,
    SummaryInvalidationRecord,
    build_claim,
    build_receipt,
)
from .models import require_digest


_SCHEMA_VERSION = 1
_CHAIN_ROOT = "confirmation-chain-root"
_RECORD_TYPES = frozenset(
    {
        "challenge",
        "reauthentication",
        "receipt",
        "summary_invalidation",
        "receipt_claim",
    }
)


class PersistentIntentConfirmationError(IntentConfirmationError):
    """Fail-closed error for confirmation persistence or state transitions."""


@dataclass(slots=True)
class _State:
    challenges: dict[str, IntentConfirmationChallenge]
    reauthentications: dict[str, IntentReauthenticationRecord]
    receipts: dict[str, IntentConfirmationReceipt]
    invalidations: dict[tuple[str, int], SummaryInvalidationRecord]
    claims: dict[str, IntentConfirmationClaim]


class PersistentIntentConfirmationStore:
    """Tamper-evident, restart-safe confirmation state with one-time claims."""

    def __init__(
        self,
        database_path: Path,
        store_hmac_key_path: Path,
        receipt_hmac_key_path: Path,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._path = Path(database_path)
        self._store_key_path = Path(store_hmac_key_path)
        self._receipt_key_path = Path(receipt_hmac_key_path)
        self._clock = clock or (lambda: int(time.time()))
        self._prepare_database_path()
        self._store_key = self._load_key(self._store_key_path, "store")
        receipt_key = self._load_key(self._receipt_key_path, "receipt")
        if hmac.compare_digest(self._store_key, receipt_key):
            raise PersistentIntentConfirmationError(
                "Confirmation store and receipt HMAC keys must be independent."
            )
        self._receipt_authenticator = ConfirmationReceiptAuthenticator(receipt_key)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN")
                self._initialize_schema(connection)
                self._verify_integrity(connection)
                connection.commit()
        except PersistentIntentConfirmationError:
            raise
        except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
            raise PersistentIntentConfirmationError(
                "Confirmation store integrity validation failed."
            ) from exc

    def create_receipt(self, **values: object) -> IntentConfirmationReceipt:
        """Build a receipt under the private receipt key without persisting it."""

        return build_receipt(self._receipt_authenticator, **values)

    def put_challenge(self, challenge: IntentConfirmationChallenge) -> None:
        self._require_record_active_at_write(
            challenge.issued_at,
            challenge.expires_at,
            "Confirmation challenge",
        )
        self._write_one(
            record_type="challenge",
            record_ref=challenge.challenge_ref,
            payload={**challenge.canonical_content(), "record_digest": challenge.record_digest},
            object_digest=challenge.record_digest,
            issued_at=challenge.issued_at,
            expires_at=challenge.expires_at,
            validate=lambda state: self._validate_new_challenge(state, challenge),
            parent=(
                "external_summary",
                challenge.summary_ref,
                challenge.summary_revision,
                challenge.summary_digest,
            ),
        )

    def put_reauthentication(self, record: IntentReauthenticationRecord) -> None:
        self._require_record_active_at_write(
            record.authenticated_at,
            record.expires_at,
            "Reauthentication record",
        )
        def parent(state: _State) -> tuple[str, str, int, str]:
            challenge = self._validate_new_reauthentication(state, record)
            return ("challenge", challenge.challenge_ref, 1, challenge.record_digest)

        self._write_one(
            record_type="reauthentication",
            record_ref=record.reauthentication_ref,
            payload={**record.canonical_content(), "record_digest": record.record_digest},
            object_digest=record.record_digest,
            issued_at=record.authenticated_at,
            expires_at=record.expires_at,
            validate=lambda state: parent(state),
            parent=parent,
        )

    def put_receipt(
        self,
        receipt: IntentConfirmationReceipt,
        *,
        invalidation: SummaryInvalidationRecord | None = None,
    ) -> None:
        """Persist one decision and its mandatory denial marker atomically."""

        self._require_record_active_at_write(
            receipt.issued_at,
            receipt.expires_at,
            "Confirmation receipt",
        )

        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._verify_integrity(connection)
                existing = state.receipts.get(receipt.receipt_ref)
                if existing is not None:
                    if existing == receipt:
                        connection.rollback()
                        return
                    raise PersistentIntentConfirmationError(
                        "Confirmation receipt is immutable."
                    )
                reauthentication = self._validate_new_receipt(state, receipt)
                if receipt.decision == "deny":
                    if invalidation is None:
                        raise PersistentIntentConfirmationError(
                            "Denied confirmation requires summary invalidation."
                        )
                    self._validate_invalidation(state, receipt, invalidation)
                elif invalidation is not None:
                    raise PersistentIntentConfirmationError(
                        "Affirmed confirmation cannot invalidate the Summary."
                    )
                self._append_record(
                    connection,
                    record_type="receipt",
                    record_ref=receipt.receipt_ref,
                    parent=(
                        "reauthentication",
                        reauthentication.reauthentication_ref,
                        1,
                        reauthentication.record_digest,
                    ),
                    payload={
                        **receipt.canonical_content(),
                        "receipt_digest": receipt.receipt_digest,
                        "receipt_mac": receipt.receipt_mac,
                    },
                    object_digest=receipt.receipt_digest,
                    issued_at=receipt.issued_at,
                    expires_at=receipt.expires_at,
                )
                if invalidation is not None:
                    self._append_record(
                        connection,
                        record_type="summary_invalidation",
                        record_ref=invalidation.invalidation_ref,
                        parent=("receipt", receipt.receipt_ref, 1, receipt.receipt_digest),
                        payload={
                            **invalidation.canonical_content(),
                            "record_digest": invalidation.record_digest,
                        },
                        object_digest=invalidation.record_digest,
                        issued_at=invalidation.invalidated_at,
                        expires_at=receipt.expires_at,
                    )
                connection.commit()
        except PersistentIntentConfirmationError:
            raise
        except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
            raise PersistentIntentConfirmationError(
                "Confirmation receipt could not be persisted."
            ) from exc

    def claim_receipt(
        self,
        receipt_ref: str,
        *,
        claim_ref: str,
        now_epoch: int,
        requester_digest: str,
        principal_namespace_digest: str,
        summary_ref: str,
        summary_revision: int,
        summary_digest: str,
    ) -> IntentConfirmationClaim:
        """Atomically consume one exact active receipt without execution authority."""

        if type(now_epoch) is not int:
            raise PersistentIntentConfirmationError("Trusted confirmation clock is invalid.")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._verify_integrity(connection)
                receipt = state.receipts.get(receipt_ref)
                if receipt is None:
                    raise PersistentIntentConfirmationError(
                        "Confirmation receipt is unavailable."
                    )
                if not self._receipt_authenticator.verify(receipt):
                    raise PersistentIntentConfirmationError(
                        "Confirmation receipt authenticity is invalid."
                    )
                if now_epoch < receipt.issued_at or now_epoch >= receipt.expires_at:
                    raise PersistentIntentConfirmationError(
                        "Confirmation receipt is outside its active lifetime."
                    )
                if (
                    receipt.requester_digest != requester_digest
                    or receipt.principal_namespace_digest != principal_namespace_digest
                    or receipt.summary_ref != summary_ref
                    or receipt.summary_revision != summary_revision
                    or receipt.summary_digest != summary_digest
                ):
                    raise PersistentIntentConfirmationError(
                        "Confirmation receipt is not bound to the exact requester and Summary."
                    )
                existing_claim = state.claims.get(receipt_ref)
                if existing_claim is not None:
                    if (
                        existing_claim.receipt_digest != receipt.receipt_digest
                        or existing_claim.requester_digest != requester_digest
                        or existing_claim.principal_namespace_digest
                        != principal_namespace_digest
                        or existing_claim.summary_ref != summary_ref
                        or existing_claim.summary_revision != summary_revision
                        or existing_claim.summary_digest != summary_digest
                        or existing_claim.decision != receipt.decision
                    ):
                        raise PersistentIntentConfirmationError(
                            "Confirmation receipt was replayed with different bindings."
                        )
                    connection.rollback()
                    return existing_claim
                if receipt.decision == "deny" and (
                    summary_ref,
                    summary_revision,
                ) not in state.invalidations:
                    raise PersistentIntentConfirmationError(
                        "Denied confirmation lacks persistent Summary invalidation."
                    )
                claim = build_claim(
                    claim_ref=claim_ref,
                    receipt_ref=receipt.receipt_ref,
                    receipt_digest=receipt.receipt_digest,
                    requester_digest=requester_digest,
                    principal_namespace_digest=principal_namespace_digest,
                    summary_ref=summary_ref,
                    summary_revision=summary_revision,
                    summary_digest=summary_digest,
                    decision=receipt.decision,
                    claimed_at=now_epoch,
                    execution_authorized=False,
                )
                self._append_record(
                    connection,
                    record_type="receipt_claim",
                    record_ref=claim.claim_ref,
                    parent=("receipt", receipt.receipt_ref, 1, receipt.receipt_digest),
                    payload={**claim.canonical_content(), "record_digest": claim.record_digest},
                    object_digest=claim.record_digest,
                    issued_at=claim.claimed_at,
                    expires_at=receipt.expires_at,
                )
                connection.commit()
                return claim
        except PersistentIntentConfirmationError:
            raise
        except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
            raise PersistentIntentConfirmationError(
                "Confirmation receipt claim could not be persisted."
            ) from exc

    def get_challenge(self, challenge_ref: str) -> IntentConfirmationChallenge:
        value = self._read_state().challenges.get(challenge_ref)
        if value is None:
            self._missing("Confirmation challenge")
        return value

    def get_challenge_by_token_digest(
        self,
        challenge_token_digest: str,
    ) -> IntentConfirmationChallenge:
        """Resolve one challenge by a server-generated raw-token digest only."""

        require_digest(challenge_token_digest, "challenge_token_digest")
        matches = [
            value
            for value in self._read_state().challenges.values()
            if hmac.compare_digest(
                value.challenge_token_digest,
                challenge_token_digest,
            )
        ]
        if len(matches) != 1:
            self._missing("Confirmation challenge")
        return matches[0]

    def get_challenge_for_summary(
        self,
        *,
        summary_ref: str,
        summary_revision: int,
        requester_digest: str,
        principal_namespace_digest: str,
    ) -> IntentConfirmationChallenge:
        matches = [
            value
            for value in self._read_state().challenges.values()
            if value.summary_ref == summary_ref
            and value.summary_revision == summary_revision
            and value.requester_digest == requester_digest
            and value.principal_namespace_digest == principal_namespace_digest
        ]
        if len(matches) != 1:
            self._missing("Confirmation challenge")
        return matches[0]

    def get_reauthentication(
        self,
        reauthentication_ref: str,
    ) -> IntentReauthenticationRecord:
        value = self._read_state().reauthentications.get(reauthentication_ref)
        if value is None:
            self._missing("Reauthentication record")
        return value

    def get_reauthentication_for_challenge(
        self,
        challenge_ref: str,
    ) -> IntentReauthenticationRecord:
        matches = [
            value
            for value in self._read_state().reauthentications.values()
            if value.challenge_ref == challenge_ref
        ]
        if len(matches) != 1:
            self._missing("Reauthentication record")
        return matches[0]

    def get_receipt(self, receipt_ref: str) -> IntentConfirmationReceipt:
        value = self._read_state().receipts.get(receipt_ref)
        if value is None:
            self._missing("Confirmation receipt")
        return value

    def get_receipt_for_challenge(
        self,
        challenge_ref: str,
    ) -> IntentConfirmationReceipt:
        matches = [
            value
            for value in self._read_state().receipts.values()
            if value.challenge_ref == challenge_ref
        ]
        if len(matches) != 1:
            self._missing("Confirmation receipt")
        return matches[0]

    def get_claim(self, receipt_ref: str) -> IntentConfirmationClaim:
        value = self._read_state().claims.get(receipt_ref)
        if value is None:
            self._missing("Confirmation receipt claim")
        return value

    def get_summary_invalidation(
        self,
        summary_ref: str,
        summary_revision: int,
    ) -> SummaryInvalidationRecord:
        value = self._read_state().invalidations.get((summary_ref, summary_revision))
        if value is None:
            self._missing("Summary invalidation")
        return value

    def summary_is_invalidated(self, summary_ref: str, summary_revision: int) -> bool:
        return (summary_ref, summary_revision) in self._read_state().invalidations

    def _write_one(
        self,
        *,
        record_type: str,
        record_ref: str,
        payload: Mapping[str, object],
        object_digest: str,
        issued_at: int,
        expires_at: int,
        validate: Callable[[_State], object],
        parent: tuple[str, str, int, str]
        | Callable[[_State], tuple[str, str, int, str]],
    ) -> None:
        encoded = canonical_json(payload)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = self._verify_integrity(connection)
                existing = connection.execute(
                    "SELECT payload_json, object_digest FROM confirmation_records "
                    "WHERE record_type = ? AND record_ref = ?",
                    (record_type, record_ref),
                ).fetchone()
                if existing is not None:
                    if (
                        str(existing["payload_json"]) == encoded
                        and str(existing["object_digest"]) == object_digest
                    ):
                        connection.rollback()
                        return
                    raise PersistentIntentConfirmationError(
                        "Confirmation record is immutable."
                    )
                validate(state)
                selected_parent = parent(state) if callable(parent) else parent
                self._append_record(
                    connection,
                    record_type=record_type,
                    record_ref=record_ref,
                    parent=selected_parent,
                    payload=payload,
                    object_digest=object_digest,
                    issued_at=issued_at,
                    expires_at=expires_at,
                )
                connection.commit()
        except PersistentIntentConfirmationError:
            raise
        except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
            raise PersistentIntentConfirmationError(
                "Confirmation record could not be persisted."
            ) from exc

    def _validate_new_challenge(
        self,
        state: _State,
        challenge: IntentConfirmationChallenge,
    ) -> None:
        if any(
            item.challenge_token_digest == challenge.challenge_token_digest
            for item in state.challenges.values()
        ):
            raise PersistentIntentConfirmationError(
                "Confirmation challenge token was replayed."
            )
        if any(
            item.summary_ref == challenge.summary_ref
            and item.summary_revision == challenge.summary_revision
            and item.requester_digest == challenge.requester_digest
            and item.principal_namespace_digest == challenge.principal_namespace_digest
            for item in state.challenges.values()
        ):
            raise PersistentIntentConfirmationError(
                "Summary revision already has a confirmation challenge."
            )

    def _validate_new_reauthentication(
        self,
        state: _State,
        record: IntentReauthenticationRecord,
    ) -> IntentConfirmationChallenge:
        challenge = state.challenges.get(record.challenge_ref)
        if challenge is None:
            raise PersistentIntentConfirmationError(
                "Reauthentication requires its exact challenge."
            )
        if any(
            item.challenge_ref == record.challenge_ref
            for item in state.reauthentications.values()
        ):
            raise PersistentIntentConfirmationError(
                "Challenge already produced a reauthentication record."
            )
        if (
            record.challenge_digest != challenge.record_digest
            or record.principal_namespace_digest
            != challenge.principal_namespace_digest
            or record.required_scope != challenge.required_scope
            or record.authenticated_at < challenge.issued_at
            or record.expires_at > challenge.expires_at
        ):
            raise PersistentIntentConfirmationError(
                "Reauthentication is not bound to the exact challenge."
            )
        return challenge

    def _validate_new_receipt(
        self,
        state: _State,
        receipt: IntentConfirmationReceipt,
    ) -> IntentReauthenticationRecord:
        challenge = state.challenges.get(receipt.challenge_ref)
        reauthentication = state.reauthentications.get(receipt.reauthentication_ref)
        if challenge is None or reauthentication is None:
            raise PersistentIntentConfirmationError(
                "Confirmation receipt requires challenge and reauthentication records."
            )
        if any(
            item.challenge_ref == receipt.challenge_ref for item in state.receipts.values()
        ):
            raise PersistentIntentConfirmationError(
                "Challenge already produced a confirmation receipt."
            )
        if any(item.nonce_digest == receipt.nonce_digest for item in state.receipts.values()):
            raise PersistentIntentConfirmationError(
                "Confirmation receipt nonce was replayed."
            )
        if not self._receipt_authenticator.verify(receipt):
            raise PersistentIntentConfirmationError(
                "Confirmation receipt authenticity is invalid."
            )
        if (
            receipt.challenge_digest != challenge.record_digest
            or receipt.reauthentication_digest != reauthentication.record_digest
            or reauthentication.challenge_ref != challenge.challenge_ref
            or receipt.requester_digest != challenge.requester_digest
            or receipt.principal_namespace_digest
            != challenge.principal_namespace_digest
            or receipt.principal_namespace_digest
            != reauthentication.principal_namespace_digest
            or receipt.audience_ref != challenge.audience_ref
            or receipt.summary_ref != challenge.summary_ref
            or receipt.summary_revision != challenge.summary_revision
            or receipt.summary_digest != challenge.summary_digest
            or receipt.required_scope != challenge.required_scope
            or receipt.required_scope != reauthentication.required_scope
            or receipt.issued_at < reauthentication.authenticated_at
            or receipt.expires_at > reauthentication.expires_at
            or receipt.expires_at > challenge.expires_at
        ):
            raise PersistentIntentConfirmationError(
                "Confirmation receipt is not bound to the exact interaction."
            )
        return reauthentication

    @staticmethod
    def _validate_invalidation(
        state: _State,
        receipt: IntentConfirmationReceipt,
        invalidation: SummaryInvalidationRecord,
    ) -> None:
        key = (receipt.summary_ref, receipt.summary_revision)
        if key in state.invalidations:
            raise PersistentIntentConfirmationError(
                "Summary revision is already invalidated."
            )
        if (
            invalidation.receipt_ref != receipt.receipt_ref
            or invalidation.receipt_digest != receipt.receipt_digest
            or invalidation.summary_ref != receipt.summary_ref
            or invalidation.summary_revision != receipt.summary_revision
            or invalidation.summary_digest != receipt.summary_digest
            or invalidation.requester_digest != receipt.requester_digest
            or invalidation.invalidated_at != receipt.issued_at
        ):
            raise PersistentIntentConfirmationError(
                "Summary invalidation is not bound to the denied receipt."
            )

    def _read_state(self) -> _State:
        try:
            with self._connect() as connection:
                connection.execute("BEGIN")
                state = self._verify_integrity(connection)
                connection.commit()
                return state
        except PersistentIntentConfirmationError:
            raise
        except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
            raise PersistentIntentConfirmationError(
                "Confirmation store could not be read."
            ) from exc

    def _require_record_active_at_write(
        self,
        issued_at: int,
        expires_at: int,
        label: str,
    ) -> None:
        now_epoch = self._clock()
        if (
            type(now_epoch) is not int
            or issued_at > now_epoch
            or now_epoch >= expires_at
        ):
            raise PersistentIntentConfirmationError(
                f"{label} is outside its active lifetime."
            )

    def _verify_integrity(self, connection: sqlite3.Connection) -> _State:
        anchor = connection.execute(
            "SELECT last_sequence, last_hmac, anchor_hmac "
            "FROM confirmation_integrity_anchor WHERE singleton = 1"
        ).fetchone()
        if anchor is None:
            raise PersistentIntentConfirmationError(
                "Confirmation integrity anchor is unavailable."
            )
        expected_anchor = self._anchor_hmac(
            int(anchor["last_sequence"]),
            str(anchor["last_hmac"]),
        )
        if not hmac.compare_digest(expected_anchor, str(anchor["anchor_hmac"])):
            raise PersistentIntentConfirmationError(
                "Confirmation integrity anchor is invalid."
            )
        state = _State({}, {}, {}, {}, {})
        previous_hmac = _CHAIN_ROOT
        sequence = 0
        rows = connection.execute(
            "SELECT * FROM confirmation_records ORDER BY sequence"
        ).fetchall()
        for row in rows:
            sequence += 1
            if int(row["sequence"]) != sequence:
                raise PersistentIntentConfirmationError(
                    "Confirmation record sequence is invalid."
                )
            if str(row["previous_hmac"]) != previous_hmac:
                raise PersistentIntentConfirmationError(
                    "Confirmation record chain is invalid."
                )
            expected = self._store_hmac("record", self._row_hmac_fields(row))
            if not hmac.compare_digest(expected, str(row["chain_hmac"])):
                raise PersistentIntentConfirmationError(
                    "Confirmation record authenticity is invalid."
                )
            self._apply_row(state, row)
            previous_hmac = str(row["chain_hmac"])
        if (
            int(anchor["last_sequence"]) != sequence
            or str(anchor["last_hmac"]) != previous_hmac
        ):
            raise PersistentIntentConfirmationError(
                "Confirmation integrity anchor does not match the record chain."
            )
        return state

    def _apply_row(self, state: _State, row: sqlite3.Row) -> None:
        record_type = str(row["record_type"])
        if record_type not in _RECORD_TYPES:
            raise PersistentIntentConfirmationError(
                "Confirmation record type is invalid."
            )
        payload = _payload(str(row["payload_json"]))
        if record_type == "challenge":
            challenge_record = _challenge_from_payload(payload)
            self._validate_row(
                row,
                challenge_record.challenge_ref,
                challenge_record.record_digest,
                challenge_record.issued_at,
                challenge_record.expires_at,
                (
                    "external_summary",
                    challenge_record.summary_ref,
                    challenge_record.summary_revision,
                    challenge_record.summary_digest,
                ),
            )
            self._validate_new_challenge(state, challenge_record)
            state.challenges[challenge_record.challenge_ref] = challenge_record
            return
        if record_type == "reauthentication":
            reauthentication_record = _reauthentication_from_payload(payload)
            challenge = self._validate_new_reauthentication(
                state,
                reauthentication_record,
            )
            self._validate_row(
                row,
                reauthentication_record.reauthentication_ref,
                reauthentication_record.record_digest,
                reauthentication_record.authenticated_at,
                reauthentication_record.expires_at,
                ("challenge", challenge.challenge_ref, 1, challenge.record_digest),
            )
            state.reauthentications[
                reauthentication_record.reauthentication_ref
            ] = reauthentication_record
            return
        if record_type == "receipt":
            receipt_record = _receipt_from_payload(payload)
            reauthentication = self._validate_new_receipt(state, receipt_record)
            self._validate_row(
                row,
                receipt_record.receipt_ref,
                receipt_record.receipt_digest,
                receipt_record.issued_at,
                receipt_record.expires_at,
                (
                    "reauthentication",
                    reauthentication.reauthentication_ref,
                    1,
                    reauthentication.record_digest,
                ),
            )
            state.receipts[receipt_record.receipt_ref] = receipt_record
            return
        if record_type == "summary_invalidation":
            invalidation = _invalidation_from_payload(payload)
            invalidation_receipt = state.receipts.get(invalidation.receipt_ref)
            if invalidation_receipt is None or invalidation_receipt.decision != "deny":
                raise PersistentIntentConfirmationError(
                    "Persisted Summary invalidation lacks a denied receipt."
                )
            self._validate_invalidation(state, invalidation_receipt, invalidation)
            self._validate_row(
                row,
                invalidation.invalidation_ref,
                invalidation.record_digest,
                invalidation.invalidated_at,
                invalidation_receipt.expires_at,
                (
                    "receipt",
                    invalidation_receipt.receipt_ref,
                    1,
                    invalidation_receipt.receipt_digest,
                ),
            )
            state.invalidations[(invalidation.summary_ref, invalidation.summary_revision)] = invalidation
            return
        claim = _claim_from_payload(payload)
        claimed_receipt = state.receipts.get(claim.receipt_ref)
        if claimed_receipt is None:
            raise PersistentIntentConfirmationError(
                "Persisted receipt claim lacks its receipt."
            )
        if claimed_receipt.receipt_ref in state.claims:
            raise PersistentIntentConfirmationError(
                "Confirmation receipt replay was persisted."
            )
        if (
            claim.receipt_digest != claimed_receipt.receipt_digest
            or claim.requester_digest != claimed_receipt.requester_digest
            or claim.principal_namespace_digest
            != claimed_receipt.principal_namespace_digest
            or claim.summary_ref != claimed_receipt.summary_ref
            or claim.summary_revision != claimed_receipt.summary_revision
            or claim.summary_digest != claimed_receipt.summary_digest
            or claim.decision != claimed_receipt.decision
            or claim.claimed_at < claimed_receipt.issued_at
            or claim.claimed_at >= claimed_receipt.expires_at
        ):
            raise PersistentIntentConfirmationError(
                "Persisted receipt claim binding is invalid."
            )
        if claimed_receipt.decision == "deny" and (
            claimed_receipt.summary_ref,
            claimed_receipt.summary_revision,
        ) not in state.invalidations:
            raise PersistentIntentConfirmationError(
                "Denied receipt claim lacks Summary invalidation."
            )
        self._validate_row(
            row,
            claim.claim_ref,
            claim.record_digest,
            claim.claimed_at,
            claimed_receipt.expires_at,
            (
                "receipt",
                claimed_receipt.receipt_ref,
                1,
                claimed_receipt.receipt_digest,
            ),
        )
        state.claims[claimed_receipt.receipt_ref] = claim

    @staticmethod
    def _validate_row(
        row: sqlite3.Row,
        record_ref: str,
        object_digest: str,
        issued_at: int,
        expires_at: int,
        parent: tuple[str, str, int, str],
    ) -> None:
        actual_parent = (
            str(row["parent_type"]),
            str(row["parent_ref"]),
            int(row["parent_revision"]),
            str(row["parent_digest"]),
        )
        if (
            str(row["record_ref"]) != record_ref
            or int(row["revision"]) != 1
            or str(row["object_digest"]) != object_digest
            or int(row["issued_at"]) != issued_at
            or int(row["expires_at"]) != expires_at
            or actual_parent != parent
        ):
            raise PersistentIntentConfirmationError(
                "Confirmation record envelope is invalid."
            )

    def _append_record(
        self,
        connection: sqlite3.Connection,
        *,
        record_type: str,
        record_ref: str,
        parent: tuple[str, str, int, str],
        payload: Mapping[str, object],
        object_digest: str,
        issued_at: int,
        expires_at: int,
    ) -> None:
        if record_type not in _RECORD_TYPES or expires_at <= issued_at:
            raise PersistentIntentConfirmationError(
                "Confirmation record envelope is invalid."
            )
        anchor = connection.execute(
            "SELECT last_sequence, last_hmac FROM confirmation_integrity_anchor "
            "WHERE singleton = 1"
        ).fetchone()
        if anchor is None:
            raise PersistentIntentConfirmationError(
                "Confirmation integrity anchor is unavailable."
            )
        sequence = int(anchor["last_sequence"]) + 1
        previous_hmac = str(anchor["last_hmac"])
        parent_type, parent_ref, parent_revision, parent_digest = parent
        payload_json = canonical_json(payload)
        fields: dict[str, CanonicalValue] = {
            "expires_at": expires_at,
            "issued_at": issued_at,
            "object_digest": object_digest,
            "parent_digest": parent_digest,
            "parent_ref": parent_ref,
            "parent_revision": parent_revision,
            "parent_type": parent_type,
            "payload_json": payload_json,
            "previous_hmac": previous_hmac,
            "record_ref": record_ref,
            "record_type": record_type,
            "revision": 1,
            "sequence": sequence,
        }
        chain_hmac = self._store_hmac("record", fields)
        connection.execute(
            """
            INSERT INTO confirmation_records(
                sequence, record_type, record_ref, revision, parent_type,
                parent_ref, parent_revision, parent_digest, payload_json,
                object_digest, issued_at, expires_at, previous_hmac, chain_hmac
            ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sequence,
                record_type,
                record_ref,
                parent_type,
                parent_ref,
                parent_revision,
                parent_digest,
                payload_json,
                object_digest,
                issued_at,
                expires_at,
                previous_hmac,
                chain_hmac,
            ),
        )
        connection.execute(
            "UPDATE confirmation_integrity_anchor SET last_sequence = ?, "
            "last_hmac = ?, anchor_hmac = ? WHERE singleton = 1",
            (sequence, chain_hmac, self._anchor_hmac(sequence, chain_hmac)),
        )

    def _row_hmac_fields(self, row: sqlite3.Row) -> dict[str, CanonicalValue]:
        return {
            "expires_at": int(row["expires_at"]),
            "issued_at": int(row["issued_at"]),
            "object_digest": str(row["object_digest"]),
            "parent_digest": str(row["parent_digest"]),
            "parent_ref": str(row["parent_ref"]),
            "parent_revision": int(row["parent_revision"]),
            "parent_type": str(row["parent_type"]),
            "payload_json": str(row["payload_json"]),
            "previous_hmac": str(row["previous_hmac"]),
            "record_ref": str(row["record_ref"]),
            "record_type": str(row["record_type"]),
            "revision": int(row["revision"]),
            "sequence": int(row["sequence"]),
        }

    def _store_hmac(self, domain: str, value: object) -> str:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        payload = domain.encode("ascii") + b"\x00" + encoded
        return hmac.new(self._store_key, payload, hashlib.sha256).hexdigest()

    def _anchor_hmac(self, sequence: int, chain_hmac: str) -> str:
        return self._store_hmac(
            "anchor",
            {
                "last_hmac": chain_hmac,
                "last_sequence": sequence,
                "schema_version": _SCHEMA_VERSION,
            },
        )

    def _prepare_database_path(self) -> None:
        if (
            not self._path.is_absolute()
            or not self._store_key_path.is_absolute()
            or not self._receipt_key_path.is_absolute()
        ):
            raise PersistentIntentConfirmationError(
                "Confirmation state paths must be absolute."
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
        except PersistentIntentConfirmationError:
            raise
        except OSError as exc:
            raise PersistentIntentConfirmationError(
                "Confirmation database path is unsafe."
            ) from exc

    @staticmethod
    def _load_key(path: Path, purpose: str) -> bytes:
        try:
            _assert_no_symlink_components(path.parent)
            _assert_owner_only(path.parent, directory=True)
            _assert_owner_only(path, directory=False)
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
            try:
                key = os.read(descriptor, 129)
            finally:
                os.close(descriptor)
        except (OSError, PersistentIntentConfirmationError) as exc:
            raise PersistentIntentConfirmationError(
                f"Confirmation {purpose} HMAC key is invalid."
            ) from exc
        if not 32 <= len(key) <= 128:
            raise PersistentIntentConfirmationError(
                f"Confirmation {purpose} HMAC key is invalid."
            )
        return key

    def _connect(self) -> sqlite3.Connection:
        _assert_owner_only(self._path.parent, directory=True)
        _assert_owner_only(self._path, directory=False)
        connection = sqlite3.connect(self._path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        return connection

    def _initialize_schema(self, connection: sqlite3.Connection) -> None:
        current = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if current not in {0, _SCHEMA_VERSION}:
            raise PersistentIntentConfirmationError(
                "Confirmation store schema is unsupported."
            )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS confirmation_records(
                sequence INTEGER PRIMARY KEY,
                record_type TEXT NOT NULL,
                record_ref TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision = 1),
                parent_type TEXT NOT NULL,
                parent_ref TEXT NOT NULL,
                parent_revision INTEGER NOT NULL CHECK(parent_revision >= 0),
                parent_digest TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                object_digest TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                previous_hmac TEXT NOT NULL,
                chain_hmac TEXT NOT NULL,
                UNIQUE(record_type, record_ref)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS confirmation_integrity_anchor(
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                last_sequence INTEGER NOT NULL,
                last_hmac TEXT NOT NULL,
                anchor_hmac TEXT NOT NULL
            )
            """
        )
        anchor = connection.execute(
            "SELECT singleton FROM confirmation_integrity_anchor WHERE singleton = 1"
        ).fetchone()
        if anchor is None:
            if connection.execute("SELECT COUNT(*) FROM confirmation_records").fetchone()[0]:
                raise PersistentIntentConfirmationError(
                    "Confirmation integrity anchor is missing."
                )
            connection.execute(
                "INSERT INTO confirmation_integrity_anchor("
                "singleton, last_sequence, last_hmac, anchor_hmac) VALUES(1, 0, ?, ?)",
                (_CHAIN_ROOT, self._anchor_hmac(0, _CHAIN_ROOT)),
            )
        connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")

    @staticmethod
    def _missing(label: str) -> NoReturn:
        raise PersistentIntentConfirmationError(f"{label} is unavailable.")


def _payload(value: str) -> dict[str, object]:
    parsed = json.loads(value)
    if type(parsed) is not dict:
        raise PersistentIntentConfirmationError(
            "Confirmation record payload is invalid."
        )
    return cast(dict[str, object], parsed)


def _challenge_from_payload(value: Mapping[str, object]) -> IntentConfirmationChallenge:
    return IntentConfirmationChallenge(
        challenge_ref=_string(value, "challenge_ref"),
        challenge_token_digest=_string(value, "challenge_token_digest"),
        requester_digest=_string(value, "requester_digest"),
        principal_namespace_digest=_string(value, "principal_namespace_digest"),
        audience_ref=_string(value, "audience_ref"),
        summary_ref=_string(value, "summary_ref"),
        summary_revision=_integer(value, "summary_revision"),
        summary_digest=_string(value, "summary_digest"),
        required_scope=_string(value, "required_scope"),
        issued_at=_integer(value, "issued_at"),
        expires_at=_integer(value, "expires_at"),
        record_digest=_string(value, "record_digest"),
    )


def _reauthentication_from_payload(
    value: Mapping[str, object],
) -> IntentReauthenticationRecord:
    return IntentReauthenticationRecord(
        reauthentication_ref=_string(value, "reauthentication_ref"),
        reauthentication_session_digest=_string(
            value,
            "reauthentication_session_digest",
        ),
        challenge_ref=_string(value, "challenge_ref"),
        challenge_digest=_string(value, "challenge_digest"),
        principal_namespace_digest=_string(value, "principal_namespace_digest"),
        required_scope=_string(value, "required_scope"),
        authenticated_at=_integer(value, "authenticated_at"),
        expires_at=_integer(value, "expires_at"),
        record_digest=_string(value, "record_digest"),
    )


def _receipt_from_payload(value: Mapping[str, object]) -> IntentConfirmationReceipt:
    return IntentConfirmationReceipt(
        receipt_ref=_string(value, "receipt_ref"),
        challenge_ref=_string(value, "challenge_ref"),
        challenge_digest=_string(value, "challenge_digest"),
        reauthentication_ref=_string(value, "reauthentication_ref"),
        reauthentication_digest=_string(value, "reauthentication_digest"),
        requester_digest=_string(value, "requester_digest"),
        principal_namespace_digest=_string(value, "principal_namespace_digest"),
        audience_ref=_string(value, "audience_ref"),
        summary_ref=_string(value, "summary_ref"),
        summary_revision=_integer(value, "summary_revision"),
        summary_digest=_string(value, "summary_digest"),
        decision=_string(value, "decision"),
        interaction_ref=_string(value, "interaction_ref"),
        nonce_digest=_string(value, "nonce_digest"),
        required_scope=_string(value, "required_scope"),
        issued_at=_integer(value, "issued_at"),
        expires_at=_integer(value, "expires_at"),
        one_time=_boolean(value, "one_time"),
        execution_authorized=_boolean(value, "execution_authorized"),
        receipt_digest=_string(value, "receipt_digest"),
        receipt_mac=_string(value, "receipt_mac"),
    )


def _invalidation_from_payload(value: Mapping[str, object]) -> SummaryInvalidationRecord:
    return SummaryInvalidationRecord(
        invalidation_ref=_string(value, "invalidation_ref"),
        receipt_ref=_string(value, "receipt_ref"),
        receipt_digest=_string(value, "receipt_digest"),
        summary_ref=_string(value, "summary_ref"),
        summary_revision=_integer(value, "summary_revision"),
        summary_digest=_string(value, "summary_digest"),
        requester_digest=_string(value, "requester_digest"),
        reason_code=_string(value, "reason_code"),
        invalidated_at=_integer(value, "invalidated_at"),
        record_digest=_string(value, "record_digest"),
    )


def _claim_from_payload(value: Mapping[str, object]) -> IntentConfirmationClaim:
    return IntentConfirmationClaim(
        claim_ref=_string(value, "claim_ref"),
        receipt_ref=_string(value, "receipt_ref"),
        receipt_digest=_string(value, "receipt_digest"),
        requester_digest=_string(value, "requester_digest"),
        principal_namespace_digest=_string(value, "principal_namespace_digest"),
        summary_ref=_string(value, "summary_ref"),
        summary_revision=_integer(value, "summary_revision"),
        summary_digest=_string(value, "summary_digest"),
        decision=_string(value, "decision"),
        claimed_at=_integer(value, "claimed_at"),
        execution_authorized=_boolean(value, "execution_authorized"),
        record_digest=_string(value, "record_digest"),
    )


def _string(value: Mapping[str, object], field: str) -> str:
    result = value.get(field)
    if type(result) is not str:
        raise PersistentIntentConfirmationError(
            "Confirmation record payload is invalid."
        )
    return result


def _integer(value: Mapping[str, object], field: str) -> int:
    result = value.get(field)
    if type(result) is not int:
        raise PersistentIntentConfirmationError(
            "Confirmation record payload is invalid."
        )
    return result


def _boolean(value: Mapping[str, object], field: str) -> bool:
    result = value.get(field)
    if type(result) is not bool:
        raise PersistentIntentConfirmationError(
            "Confirmation record payload is invalid."
        )
    return result


def _assert_owner_only(path: Path, *, directory: bool) -> None:
    if path.is_symlink() or not path.exists():
        raise PersistentIntentConfirmationError(
            "Confirmation state path is unsafe."
        )
    if directory and not path.is_dir():
        raise PersistentIntentConfirmationError(
            "Confirmation state directory is unsafe."
        )
    if not directory and not path.is_file():
        raise PersistentIntentConfirmationError(
            "Confirmation state file is unsafe."
        )
    path_stat = path.stat()
    mode = stat.S_IMODE(path_stat.st_mode)
    expected = 0o700 if directory else 0o600
    if mode != expected or path_stat.st_uid != os.getuid():
        raise PersistentIntentConfirmationError(
            "Confirmation state paths must be owner-only."
        )


def _assert_no_symlink_components(path: Path) -> None:
    current = path
    while current != current.parent:
        if current.is_symlink():
            raise PersistentIntentConfirmationError(
                "Confirmation state path contains a symbolic link."
            )
        current = current.parent


__all__ = [
    "PersistentIntentConfirmationError",
    "PersistentIntentConfirmationStore",
]
