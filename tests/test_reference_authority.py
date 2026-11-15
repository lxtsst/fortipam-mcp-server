from __future__ import annotations

import os
from pathlib import Path
import sqlite3

import pytest

from v4_planning import (
    PersistentReferenceAuthority,
    ReferenceAuthorityCheckpointError,
    ReferenceAuthorityError,
    ReferenceAuthorityStoreTail,
    VerifiedReferenceDecision,
    canonical_digest,
)


NOW = 1_900_000_000
REFERENCE = "folder-object-ref0001"
REFERENCE_KIND = "object_public_folder"
REQUESTER_DIGEST = "a" * 64
ENVIRONMENT_REF = "laboratory-environment-ref01"
SCOPE_REF = "laboratory-scope-ref0001"
AUTHORITY_REF = "protected-reference-authority-ref01"
CHECKPOINT_AUTHORITY_REF = "protected-reference-checkpoint-ref01"
CHECKPOINT_STORE_REF = "protected-reference-store-ref0001"


class ExternalReferenceCheckpoint:
    authority_ref = CHECKPOINT_AUTHORITY_REF

    def __init__(self, store_ref: str = CHECKPOINT_STORE_REF) -> None:
        self.tail = ReferenceAuthorityStoreTail.empty(store_ref)

    def verify(self, tail: ReferenceAuthorityStoreTail) -> None:
        if tail != self.tail:
            raise ReferenceAuthorityCheckpointError("checkpoint mismatch")

    def advance(
        self,
        previous: ReferenceAuthorityStoreTail,
        current: ReferenceAuthorityStoreTail,
    ) -> None:
        if (
            previous != self.tail
            or current.store_ref != previous.store_ref
            or current.sequence < previous.sequence
            or current.last_seen_at < previous.last_seen_at
            or current == previous
        ):
            raise ReferenceAuthorityCheckpointError("checkpoint conflict")
        self.tail = current

    def uses_key_material(self, candidate: bytes) -> bool:
        del candidate
        return False


def _write_key(path: Path, value: bytes = b"r" * 32) -> None:
    path.write_bytes(value)
    os.chmod(path, 0o600)


def _new_authority(
    root: Path,
    *,
    key_value: bytes = b"r" * 32,
) -> tuple[PersistentReferenceAuthority, Path, Path]:
    os.chmod(root, 0o700)
    key = root / "reference-authority.hmac"
    database = root / "reference-authority.sqlite3"
    if not key.exists():
        _write_key(key, key_value)
    return (
        PersistentReferenceAuthority(
            database,
            key,
            authority_ref=AUTHORITY_REF,
            clock=lambda: NOW,
        ),
        database,
        key,
    )


def _issue(authority: PersistentReferenceAuthority) -> str:
    return authority.issue(
        REFERENCE,
        reference_kind=REFERENCE_KIND,
        requester_digest=REQUESTER_DIGEST,
        environment_ref=ENVIRONMENT_REF,
        scope_ref=SCOPE_REF,
        expires_at=NOW + 120,
        now_epoch=NOW,
    )


def _authorize(
    authority: PersistentReferenceAuthority,
    *,
    reference: str = REFERENCE,
    reference_kind: str = REFERENCE_KIND,
    requester_digest: str = REQUESTER_DIGEST,
    environment_ref: str = ENVIRONMENT_REF,
    scope_ref: str = SCOPE_REF,
    now_epoch: int = NOW + 1,
) -> VerifiedReferenceDecision:
    return authority.authorize(
        reference,
        reference_kind=reference_kind,
        requester_digest=requester_digest,
        environment_ref=environment_ref,
        scope_ref=scope_ref,
        now_epoch=now_epoch,
    )


def test_exact_grant_returns_only_value_free_decision_and_stores_digests(
    tmp_path: Path,
) -> None:
    authority, database, _key = _new_authority(tmp_path)
    grant_ref = _issue(authority)

    decision = _authorize(authority)

    assert decision.authorized is True
    assert decision.reference_digest == canonical_digest(REFERENCE)
    assert decision.reference_kind == REFERENCE_KIND
    assert decision.authority_ref == AUTHORITY_REF
    assert decision.requester_digest == REQUESTER_DIGEST
    assert decision.environment_digest == canonical_digest(ENVIRONMENT_REF)
    assert decision.scope_digest == canonical_digest(SCOPE_REF)
    assert decision.checked_at == NOW + 1
    assert decision.expires_at == NOW + 61
    stored = database.read_bytes()
    for private_value in (
        REFERENCE,
        ENVIRONMENT_REF,
        SCOPE_REF,
        grant_ref,
    ):
        assert private_value.encode("utf-8") not in stored


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("reference", "different-object-ref0001"),
        ("reference_kind", "object_access_grant"),
        ("requester_digest", "b" * 64),
        ("environment_ref", "different-environment-ref01"),
        ("scope_ref", "different-scope-ref000001"),
    ),
)
def test_authorization_requires_the_exact_reference_context(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    authority, _database, _key = _new_authority(tmp_path)
    _issue(authority)
    kwargs = {field: value}

    decision = _authorize(authority, **kwargs)  # type: ignore[arg-type]

    assert decision.authorized is False
    assert decision.expires_at == NOW + 61


def test_revocation_and_restart_remain_fail_closed(tmp_path: Path) -> None:
    authority, database, key = _new_authority(tmp_path)
    grant_ref = _issue(authority)
    authority.revoke(grant_ref, now_epoch=NOW + 2)

    restarted = PersistentReferenceAuthority(
        database,
        key,
        authority_ref=AUTHORITY_REF,
        clock=lambda: NOW + 3,
    )

    assert _authorize(restarted, now_epoch=NOW + 3).authorized is False
    with pytest.raises(ReferenceAuthorityError, match="unavailable"):
        restarted.revoke(grant_ref, now_epoch=NOW + 4)


def test_expiry_duplicate_and_clock_rollback_are_rejected(tmp_path: Path) -> None:
    authority, _database, _key = _new_authority(tmp_path)
    _issue(authority)

    with pytest.raises(ReferenceAuthorityError, match="already exists"):
        _issue(authority)
    assert _authorize(authority, now_epoch=NOW + 120).authorized is False
    with pytest.raises(ReferenceAuthorityError, match="moved backwards"):
        _authorize(authority, now_epoch=NOW + 119)


def test_bounded_batch_issue_is_atomic(tmp_path: Path) -> None:
    authority, _database, _key = _new_authority(tmp_path)
    second_reference = "folder-object-ref0002"
    grant_refs = authority.issue_many(
        (
            (REFERENCE, REFERENCE_KIND),
            (second_reference, REFERENCE_KIND),
        ),
        requester_digest=REQUESTER_DIGEST,
        environment_ref=ENVIRONMENT_REF,
        scope_ref=SCOPE_REF,
        expires_at=NOW + 120,
        now_epoch=NOW,
    )

    assert len(grant_refs) == 2
    assert _authorize(authority, now_epoch=NOW + 1).authorized is True
    assert (
        _authorize(
            authority,
            reference=second_reference,
            now_epoch=NOW + 1,
        ).authorized
        is True
    )
    third_reference = "folder-object-ref0003"
    with pytest.raises(ReferenceAuthorityError, match="already exists"):
        authority.issue_many(
            (
                (REFERENCE, REFERENCE_KIND),
                (third_reference, REFERENCE_KIND),
            ),
            requester_digest=REQUESTER_DIGEST,
            environment_ref=ENVIRONMENT_REF,
            scope_ref=SCOPE_REF,
            expires_at=NOW + 120,
            now_epoch=NOW + 1,
        )
    assert (
        _authorize(
            authority,
            reference=third_reference,
            now_epoch=NOW + 2,
        ).authorized
        is False
    )


def test_bounded_batch_revocation_is_atomic(tmp_path: Path) -> None:
    authority, _database, _key = _new_authority(tmp_path)
    second_reference = "folder-object-ref0002"
    grant_refs = authority.issue_many(
        (
            (REFERENCE, REFERENCE_KIND),
            (second_reference, REFERENCE_KIND),
        ),
        requester_digest=REQUESTER_DIGEST,
        environment_ref=ENVIRONMENT_REF,
        scope_ref=SCOPE_REF,
        expires_at=NOW + 120,
        now_epoch=NOW,
    )

    with pytest.raises(ReferenceAuthorityError, match="unavailable"):
        authority.revoke_many(
            (grant_refs[0], "unknown-reference-grant"),
            now_epoch=NOW + 1,
        )
    assert _authorize(authority, now_epoch=NOW + 2).authorized is True
    assert (
        _authorize(authority, reference=second_reference, now_epoch=NOW + 2).authorized
        is True
    )

    authority.revoke_many(grant_refs, now_epoch=NOW + 3)

    assert _authorize(authority, now_epoch=NOW + 4).authorized is False
    assert (
        _authorize(authority, reference=second_reference, now_epoch=NOW + 4).authorized
        is False
    )


def test_database_tampering_and_wrong_key_fail_integrity(tmp_path: Path) -> None:
    authority, database, key = _new_authority(tmp_path)
    _issue(authority)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE reference_events SET expires_at = expires_at + 1 WHERE sequence = 1"
        )

    with pytest.raises(ReferenceAuthorityError, match="integrity"):
        _authorize(authority)

    _write_key(key, b"w" * 32)
    with pytest.raises(ReferenceAuthorityError, match="integrity"):
        PersistentReferenceAuthority(
            database,
            key,
            authority_ref=AUTHORITY_REF,
        )


def test_owner_only_state_and_key_are_required(tmp_path: Path) -> None:
    key = tmp_path / "reference-authority.hmac"
    _write_key(key)
    os.chmod(tmp_path, 0o750)

    with pytest.raises(ReferenceAuthorityError, match="owner-only"):
        PersistentReferenceAuthority(
            tmp_path / "reference-authority.sqlite3",
            key,
            authority_ref=AUTHORITY_REF,
        )

    os.chmod(tmp_path, 0o700)
    os.chmod(key, 0o644)

    with pytest.raises(ReferenceAuthorityError, match="owner-only"):
        PersistentReferenceAuthority(
            tmp_path / "reference-authority.sqlite3",
            key,
            authority_ref=AUTHORITY_REF,
        )


def test_external_checkpoint_rejects_event_and_time_watermark_rollback(
    tmp_path: Path,
) -> None:
    os.chmod(tmp_path, 0o700)
    key = tmp_path / "reference-authority.hmac"
    database = tmp_path / "reference-authority.sqlite3"
    _write_key(key)
    checkpoint = ExternalReferenceCheckpoint()
    authority = PersistentReferenceAuthority(
        database,
        key,
        authority_ref=AUTHORITY_REF,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
        clock=lambda: NOW,
    )
    empty_database = database.read_bytes()
    _issue(authority)
    issued_database = database.read_bytes()
    assert checkpoint.tail.sequence == 1
    assert checkpoint.tail.last_seen_at == NOW

    _authorize(authority, now_epoch=NOW + 1)
    current_database = database.read_bytes()
    assert checkpoint.tail.sequence == 1
    assert checkpoint.tail.last_seen_at == NOW + 1
    assert authority.monotonic_checkpoint_protocol_bound is True

    database.write_bytes(issued_database)
    with pytest.raises(ReferenceAuthorityError, match="checkpoint verification"):
        authority.verify_ready()
    database.write_bytes(empty_database)
    with pytest.raises(ReferenceAuthorityError, match="checkpoint verification"):
        PersistentReferenceAuthority(
            database,
            key,
            authority_ref=AUTHORITY_REF,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )
    database.write_bytes(current_database)
    authority.verify_ready()


def test_checkpoint_binding_and_key_domains_must_be_complete_and_distinct(
    tmp_path: Path,
) -> None:
    os.chmod(tmp_path, 0o700)
    key = tmp_path / "reference-authority.hmac"
    _write_key(key)
    checkpoint = ExternalReferenceCheckpoint()

    with pytest.raises(ReferenceAuthorityError, match="binding is incomplete"):
        PersistentReferenceAuthority(
            tmp_path / "incomplete.sqlite3",
            key,
            authority_ref=AUTHORITY_REF,
            monotonic_checkpoint=checkpoint,
        )

    checkpoint.authority_ref = AUTHORITY_REF
    with pytest.raises(ReferenceAuthorityError, match="binding is invalid"):
        PersistentReferenceAuthority(
            tmp_path / "same-authority.sqlite3",
            key,
            authority_ref=AUTHORITY_REF,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )

    checkpoint.authority_ref = CHECKPOINT_AUTHORITY_REF
    checkpoint.uses_key_material = lambda candidate: candidate == b"r" * 32  # type: ignore[method-assign]
    with pytest.raises(ReferenceAuthorityError, match="keys must be independent"):
        PersistentReferenceAuthority(
            tmp_path / "reused-key.sqlite3",
            key,
            authority_ref=AUTHORITY_REF,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )
