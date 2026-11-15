from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import os
from pathlib import Path
import sqlite3
import stat

import pytest

from v4_planning.confirmation import (
    PLAN_CONFIRMATION_SCOPE,
    IntentConfirmationChallenge,
    IntentConfirmationReceipt,
    IntentReauthenticationRecord,
    build_challenge,
    build_invalidation,
    build_reauthentication,
)
from v4_planning.confirmation_persistence import (
    PersistentIntentConfirmationError,
    PersistentIntentConfirmationStore,
)


NOW = 1_900_000_000
STORE_KEY = b"confirmation-store-key-0000000000000000000000001"
RECEIPT_KEY = b"confirmation-receipt-key-00000000000000000000001"


def _store(
    root: Path,
    *,
    now_epoch: int = NOW + 40,
    store_key: bytes = STORE_KEY,
    receipt_key: bytes = RECEIPT_KEY,
) -> tuple[PersistentIntentConfirmationStore, Path, Path, Path]:
    state = root / "confirmation-state"
    state.mkdir(parents=True, mode=0o700)
    os.chmod(state, 0o700)
    store_key_path = state / "store.hmac"
    receipt_key_path = state / "receipt.hmac"
    store_key_path.write_bytes(store_key)
    receipt_key_path.write_bytes(receipt_key)
    os.chmod(store_key_path, 0o600)
    os.chmod(receipt_key_path, 0o600)
    database = state / "confirmation.sqlite3"
    return (
        PersistentIntentConfirmationStore(
            database,
            store_key_path,
            receipt_key_path,
            clock=lambda: now_epoch,
        ),
        database,
        store_key_path,
        receipt_key_path,
    )


def _challenge(
    *,
    challenge_ref: str = "intent-challenge-ref0001",
    summary_ref: str = "summary-record-ref0001",
    summary_revision: int = 1,
    token_digest: str = "1" * 64,
) -> IntentConfirmationChallenge:
    return build_challenge(
        challenge_ref=challenge_ref,
        challenge_token_digest=token_digest,
        requester_digest="2" * 64,
        principal_namespace_digest="3" * 64,
        audience_ref="audience-record-ref01",
        summary_ref=summary_ref,
        summary_revision=summary_revision,
        summary_digest="4" * 64,
        required_scope=PLAN_CONFIRMATION_SCOPE,
        issued_at=NOW,
        expires_at=NOW + 180,
    )


def _reauthentication(
    challenge: IntentConfirmationChallenge,
    *,
    reference: str = "reauthentication-ref0001",
) -> IntentReauthenticationRecord:
    return build_reauthentication(
        reauthentication_ref=reference,
        reauthentication_session_digest="5" * 64,
        challenge_ref=challenge.challenge_ref,
        challenge_digest=challenge.record_digest,
        principal_namespace_digest=challenge.principal_namespace_digest,
        required_scope=PLAN_CONFIRMATION_SCOPE,
        authenticated_at=NOW + 10,
        expires_at=NOW + 130,
    )


def _receipt(
    store: PersistentIntentConfirmationStore,
    challenge: IntentConfirmationChallenge,
    reauthentication: IntentReauthenticationRecord,
    *,
    decision: str = "affirm",
    receipt_ref: str = "intent-receipt-ref0001",
    nonce_digest: str = "6" * 64,
) -> IntentConfirmationReceipt:
    return store.create_receipt(
        receipt_ref=receipt_ref,
        challenge_ref=challenge.challenge_ref,
        challenge_digest=challenge.record_digest,
        reauthentication_ref=reauthentication.reauthentication_ref,
        reauthentication_digest=reauthentication.record_digest,
        requester_digest=challenge.requester_digest,
        principal_namespace_digest=challenge.principal_namespace_digest,
        audience_ref=challenge.audience_ref,
        summary_ref=challenge.summary_ref,
        summary_revision=challenge.summary_revision,
        summary_digest=challenge.summary_digest,
        decision=decision,
        interaction_ref="human-interaction-ref01",
        nonce_digest=nonce_digest,
        required_scope=PLAN_CONFIRMATION_SCOPE,
        issued_at=NOW + 20,
        expires_at=NOW + 120,
        one_time=True,
        execution_authorized=False,
    )


def _persist_affirmed(
    store: PersistentIntentConfirmationStore,
) -> tuple[
    IntentConfirmationChallenge,
    IntentReauthenticationRecord,
    IntentConfirmationReceipt,
]:
    challenge = _challenge()
    reauthentication = _reauthentication(challenge)
    receipt = _receipt(store, challenge, reauthentication)
    store.put_challenge(challenge)
    store.put_reauthentication(reauthentication)
    store.put_receipt(receipt)
    return challenge, reauthentication, receipt


def test_affirmed_receipt_survives_restart_and_claim_is_non_executing(
    tmp_path: Path,
) -> None:
    store, database, store_key, receipt_key = _store(tmp_path)
    challenge, reauthentication, receipt = _persist_affirmed(store)

    assert stat.S_IMODE(database.stat().st_mode) == 0o600
    assert stat.S_IMODE(database.parent.stat().st_mode) == 0o700
    restarted = PersistentIntentConfirmationStore(
        database,
        store_key,
        receipt_key,
        clock=lambda: NOW + 40,
    )
    assert restarted.get_challenge(challenge.challenge_ref) == challenge
    assert restarted.get_reauthentication(reauthentication.reauthentication_ref) == reauthentication
    assert restarted.get_receipt(receipt.receipt_ref) == receipt

    claim = restarted.claim_receipt(
        receipt.receipt_ref,
        claim_ref="intent-claim-ref000001",
        now_epoch=NOW + 40,
        requester_digest=challenge.requester_digest,
        principal_namespace_digest=challenge.principal_namespace_digest,
        summary_ref=challenge.summary_ref,
        summary_revision=challenge.summary_revision,
        summary_digest=challenge.summary_digest,
    )
    assert claim.decision == "affirm"
    assert claim.execution_authorized is False

    final = PersistentIntentConfirmationStore(
        database,
        store_key,
        receipt_key,
        clock=lambda: NOW + 50,
    )
    assert final.get_claim(receipt.receipt_ref) == claim
    retried = final.claim_receipt(
        receipt.receipt_ref,
        claim_ref="intent-claim-ref000002",
        now_epoch=NOW + 50,
        requester_digest=challenge.requester_digest,
        principal_namespace_digest=challenge.principal_namespace_digest,
        summary_ref=challenge.summary_ref,
        summary_revision=challenge.summary_revision,
        summary_digest=challenge.summary_digest,
    )
    assert retried == claim


def test_receipt_rejects_wrong_namespace_summary_expiry_and_mac(tmp_path: Path) -> None:
    store, _database, _store_key, _receipt_key = _store(tmp_path / "active")
    challenge, reauthentication, receipt = _persist_affirmed(store)

    with pytest.raises(PersistentIntentConfirmationError, match="exact requester"):
        store.claim_receipt(
            receipt.receipt_ref,
            claim_ref="intent-claim-wrong-ref1",
            now_epoch=NOW + 40,
            requester_digest=challenge.requester_digest,
            principal_namespace_digest="a" * 64,
            summary_ref=challenge.summary_ref,
            summary_revision=challenge.summary_revision,
            summary_digest=challenge.summary_digest,
        )

    forged_store, _db2, _key2, _receipt2 = _store(tmp_path / "forged")
    forged_store.put_challenge(challenge)
    forged_store.put_reauthentication(reauthentication)
    forged = replace(receipt, receipt_mac="0" * 64)
    with pytest.raises(PersistentIntentConfirmationError, match="authenticity"):
        forged_store.put_receipt(forged)

    expiring_store, expired_database, expired_store_key, expired_receipt_key = _store(
        tmp_path / "expired",
        now_epoch=NOW + 119,
    )
    _challenge_value, _reauth_value, expired_receipt = _persist_affirmed(expiring_store)
    expired_store = PersistentIntentConfirmationStore(
        expired_database,
        expired_store_key,
        expired_receipt_key,
        clock=lambda: NOW + 120,
    )
    with pytest.raises(PersistentIntentConfirmationError, match="active lifetime"):
        expired_store.claim_receipt(
            expired_receipt.receipt_ref,
            claim_ref="intent-claim-expired01",
            now_epoch=NOW + 120,
            requester_digest=challenge.requester_digest,
            principal_namespace_digest=challenge.principal_namespace_digest,
            summary_ref=challenge.summary_ref,
            summary_revision=challenge.summary_revision,
            summary_digest=challenge.summary_digest,
        )


def test_denial_requires_atomic_invalidation_and_survives_restart(tmp_path: Path) -> None:
    store, database, store_key, receipt_key = _store(tmp_path)
    challenge = _challenge()
    reauthentication = _reauthentication(challenge)
    receipt = _receipt(store, challenge, reauthentication, decision="deny")
    store.put_challenge(challenge)
    store.put_reauthentication(reauthentication)

    with pytest.raises(PersistentIntentConfirmationError, match="requires summary invalidation"):
        store.put_receipt(receipt)
    invalidation = build_invalidation(
        invalidation_ref="summary-invalidation-ref1",
        receipt_ref=receipt.receipt_ref,
        receipt_digest=receipt.receipt_digest,
        summary_ref=receipt.summary_ref,
        summary_revision=receipt.summary_revision,
        summary_digest=receipt.summary_digest,
        requester_digest=receipt.requester_digest,
        reason_code="requester_denied",
        invalidated_at=receipt.issued_at,
    )
    store.put_receipt(receipt, invalidation=invalidation)
    assert store.summary_is_invalidated(challenge.summary_ref, challenge.summary_revision)

    restarted = PersistentIntentConfirmationStore(
        database,
        store_key,
        receipt_key,
        clock=lambda: NOW + 40,
    )
    assert restarted.get_summary_invalidation(
        challenge.summary_ref,
        challenge.summary_revision,
    ) == invalidation
    claim = restarted.claim_receipt(
        receipt.receipt_ref,
        claim_ref="denial-claim-reference01",
        now_epoch=NOW + 40,
        requester_digest=challenge.requester_digest,
        principal_namespace_digest=challenge.principal_namespace_digest,
        summary_ref=challenge.summary_ref,
        summary_revision=challenge.summary_revision,
        summary_digest=challenge.summary_digest,
    )
    assert claim.decision == "deny"
    assert claim.execution_authorized is False


def test_store_tamper_and_non_independent_keys_fail_closed(tmp_path: Path) -> None:
    store, database, store_key, receipt_key = _store(tmp_path / "tamper")
    _persist_affirmed(store)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE confirmation_records SET payload_json = ? WHERE sequence = 1",
            ('{"tampered":true}',),
        )
    with pytest.raises(PersistentIntentConfirmationError, match="authenticity"):
        PersistentIntentConfirmationStore(database, store_key, receipt_key)

    with pytest.raises(PersistentIntentConfirmationError, match="must be independent"):
        _store(
            tmp_path / "same-key",
            store_key=STORE_KEY,
            receipt_key=STORE_KEY,
        )


@pytest.mark.parametrize("unsafe_target", ("directory", "database", "store_key", "receipt_key"))
def test_group_readable_confirmation_state_fails_closed(
    tmp_path: Path,
    unsafe_target: str,
) -> None:
    store, database, store_key, receipt_key = _store(tmp_path)
    del store
    selected = {
        "directory": database.parent,
        "database": database,
        "store_key": store_key,
        "receipt_key": receipt_key,
    }[unsafe_target]
    os.chmod(selected, 0o750 if selected.is_dir() else 0o640)

    with pytest.raises(
        PersistentIntentConfirmationError,
        match="owner-only|HMAC key is invalid",
    ):
        PersistentIntentConfirmationStore(database, store_key, receipt_key)


def test_concurrent_competing_decisions_allow_exactly_one_receipt(tmp_path: Path) -> None:
    store, database, store_key, receipt_key = _store(tmp_path)
    challenge = _challenge()
    reauthentication = _reauthentication(challenge)
    store.put_challenge(challenge)
    store.put_reauthentication(reauthentication)
    receipts = {
        decision: _receipt(
            store,
            challenge,
            reauthentication,
            decision=decision,
            receipt_ref=f"competing-{decision}-receipt-ref",
            nonce_digest=("a" if decision == "affirm" else "b") * 64,
        )
        for decision in ("affirm", "deny")
    }

    def decide(decision: str) -> str:
        receipt = receipts[decision]
        invalidation = None
        if decision == "deny":
            invalidation = build_invalidation(
                invalidation_ref="competing-denial-invalidation-ref",
                receipt_ref=receipt.receipt_ref,
                receipt_digest=receipt.receipt_digest,
                summary_ref=receipt.summary_ref,
                summary_revision=receipt.summary_revision,
                summary_digest=receipt.summary_digest,
                requester_digest=receipt.requester_digest,
                reason_code="requester_denied",
                invalidated_at=receipt.issued_at,
            )
        try:
            store.put_receipt(receipt, invalidation=invalidation)
        except PersistentIntentConfirmationError:
            return "rejected"
        return decision

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(decide, ("affirm", "deny")))
    assert outcomes.count("rejected") == 1
    winner = next(value for value in outcomes if value != "rejected")

    restarted = PersistentIntentConfirmationStore(
        database,
        store_key,
        receipt_key,
        clock=lambda: NOW + 50,
    )
    persisted = restarted.get_receipt_for_challenge(challenge.challenge_ref)
    assert persisted.decision == winner
    assert restarted.summary_is_invalidated(
        challenge.summary_ref,
        challenge.summary_revision,
    ) is (winner == "deny")


def test_concurrent_claim_persists_exactly_one_idempotent_consumer(tmp_path: Path) -> None:
    store, database, store_key, receipt_key = _store(tmp_path)
    challenge, _reauthentication_value, receipt = _persist_affirmed(store)

    def claim(index: int) -> str:
        return store.claim_receipt(
            receipt.receipt_ref,
            claim_ref=f"concurrent-claim-ref{index:04d}",
            now_epoch=NOW + 40,
            requester_digest=challenge.requester_digest,
            principal_namespace_digest=challenge.principal_namespace_digest,
            summary_ref=challenge.summary_ref,
            summary_revision=challenge.summary_revision,
            summary_digest=challenge.summary_digest,
        ).claim_ref

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(claim, (1, 2)))
    assert len(set(outcomes)) == 1

    restarted = PersistentIntentConfirmationStore(
        database,
        store_key,
        receipt_key,
        clock=lambda: NOW + 50,
    )
    assert restarted.get_claim(receipt.receipt_ref).execution_authorized is False


def test_challenge_reauthentication_and_nonce_replay_are_rejected(tmp_path: Path) -> None:
    store, _database, _store_key, _receipt_key = _store(tmp_path)
    challenge, reauthentication, receipt = _persist_affirmed(store)

    duplicate_challenge = _challenge(
        challenge_ref="intent-challenge-ref0002",
        token_digest="7" * 64,
    )
    with pytest.raises(PersistentIntentConfirmationError, match="already has"):
        store.put_challenge(duplicate_challenge)
    with pytest.raises(PersistentIntentConfirmationError, match="already produced"):
        store.put_reauthentication(
            _reauthentication(challenge, reference="reauthentication-ref0002")
        )

    next_challenge = _challenge(
        challenge_ref="intent-challenge-ref0003",
        summary_ref="summary-record-ref0002",
        token_digest="8" * 64,
    )
    next_reauthentication = _reauthentication(
        next_challenge,
        reference="reauthentication-ref0003",
    )
    next_receipt = _receipt(
        store,
        next_challenge,
        next_reauthentication,
        receipt_ref="intent-receipt-ref0003",
        nonce_digest=receipt.nonce_digest,
    )
    store.put_challenge(next_challenge)
    store.put_reauthentication(next_reauthentication)
    with pytest.raises(PersistentIntentConfirmationError, match="nonce was replayed"):
        store.put_receipt(next_receipt)
