from __future__ import annotations

import os
from pathlib import Path
import sqlite3

import pytest

from v4_planning import (
    PersistentReferenceAuthority,
    PersistentReferenceCheckpointAuthority,
    ReferenceAuthorityCheckpointError,
    ReferenceAuthorityError,
    ReferenceAuthorityStoreTail,
)


AUTHORITY_REF = "v4-reference-checkpoint-test"
STORE_REF = "v4-reference-store-test"


def _owner_file(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    os.chmod(path, 0o600)
    return path


def _authority(
    tmp_path: Path,
    *,
    key: bytes = b"k" * 32,
) -> tuple[PersistentReferenceCheckpointAuthority, Path, Path]:
    state = tmp_path / "checkpoint-state"
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(state, 0o700)
    key_path = state / "checkpoint.hmac"
    if not key_path.exists():
        _owner_file(key_path, key)
    database = state / "checkpoint.sqlite3"
    return (
        PersistentReferenceCheckpointAuthority(
            database,
            key_path,
            authority_ref=AUTHORITY_REF,
        ),
        database,
        key_path,
    )


def _tail(sequence: int, chain_mac: str, last_seen_at: int) -> ReferenceAuthorityStoreTail:
    return ReferenceAuthorityStoreTail(
        STORE_REF,
        sequence,
        chain_mac,
        last_seen_at,
    )


def test_reference_checkpoint_persists_event_and_time_advances(
    tmp_path: Path,
) -> None:
    authority, database, key_path = _authority(tmp_path)
    empty = ReferenceAuthorityStoreTail.empty(STORE_REF)
    observed = _tail(0, empty.chain_mac, 10)
    issued = _tail(2, "a" * 64, 10)
    authorized = _tail(2, "a" * 64, 11)

    authority.verify(empty)
    authority.advance(empty, observed)
    authority.advance(observed, issued)
    authority.advance(issued, authorized)
    authority.verify(authorized)
    PersistentReferenceCheckpointAuthority(
        database,
        key_path,
        authority_ref=AUTHORITY_REF,
    ).verify(authorized)


def test_reference_checkpoint_isolates_stores_and_rejects_stale_or_regression(
    tmp_path: Path,
) -> None:
    authority, _database, _key_path = _authority(tmp_path)
    empty = ReferenceAuthorityStoreTail.empty(STORE_REF)
    first = _tail(1, "a" * 64, 10)
    other_empty = ReferenceAuthorityStoreTail.empty("v4-other-reference-store")
    other_first = ReferenceAuthorityStoreTail(
        other_empty.store_ref,
        1,
        "b" * 64,
        5,
    )
    authority.advance(empty, first)
    authority.advance(other_empty, other_first)
    authority.verify(other_first)

    with pytest.raises(ReferenceAuthorityCheckpointError, match="failed"):
        authority.advance(empty, first)
    batch = _tail(3, "c" * 64, 11)
    authority.advance(first, batch)
    authority.verify(batch)
    with pytest.raises(ReferenceAuthorityCheckpointError, match="invalid"):
        authority.advance(batch, _tail(2, "d" * 64, 12))
    with pytest.raises(ReferenceAuthorityCheckpointError, match="invalid"):
        authority.advance(
            first,
            ReferenceAuthorityStoreTail(
                other_empty.store_ref,
                2,
                "c" * 64,
                11,
            ),
        )


def test_reference_checkpoint_rejects_invalid_transition_shapes(
    tmp_path: Path,
) -> None:
    authority, _database, _key_path = _authority(tmp_path)
    empty = ReferenceAuthorityStoreTail.empty(STORE_REF)
    with pytest.raises(ReferenceAuthorityCheckpointError, match="invalid"):
        authority.advance(empty, _tail(0, empty.chain_mac, 0))
    with pytest.raises(ReferenceAuthorityCheckpointError, match="invalid"):
        authority.advance(_tail(1, "a" * 64, 1), _tail(2, "a" * 64, 2))
    with pytest.raises(ReferenceAuthorityCheckpointError, match="invalid"):
        authority.advance(_tail(0, empty.chain_mac, 10), _tail(1, "a" * 64, 9))


def test_reference_checkpoint_rejects_wrong_key_tamper_and_unsafe_paths(
    tmp_path: Path,
) -> None:
    authority, database, key_path = _authority(tmp_path)
    authority.advance(
        ReferenceAuthorityStoreTail.empty(STORE_REF),
        _tail(1, "a" * 64, 10),
    )
    original_key = key_path.read_bytes()
    key_path.write_bytes(b"w" * 32)
    with pytest.raises(ReferenceAuthorityCheckpointError, match="integrity failed"):
        PersistentReferenceCheckpointAuthority(
            database,
            key_path,
            authority_ref=AUTHORITY_REF,
        )
    key_path.write_bytes(original_key)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE reference_checkpoint_events SET current_last_seen_at = 11 "
            "WHERE event_sequence = 1"
        )
    with pytest.raises(ReferenceAuthorityCheckpointError, match="integrity failed"):
        PersistentReferenceCheckpointAuthority(
            database,
            key_path,
            authority_ref=AUTHORITY_REF,
        )

    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    os.chmod(unsafe, 0o755)
    unsafe_key = _owner_file(unsafe / "checkpoint.hmac", b"u" * 32)
    with pytest.raises(ReferenceAuthorityCheckpointError, match="owner-only"):
        PersistentReferenceCheckpointAuthority(
            unsafe / "checkpoint.sqlite3",
            unsafe_key,
            authority_ref=AUTHORITY_REF,
        )


def test_reference_authority_rejects_checkpoint_key_reuse(tmp_path: Path) -> None:
    checkpoint, _database, _key_path = _authority(tmp_path, key=b"k" * 32)
    state = tmp_path / "reference-state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    reference_key = _owner_file(state / "reference.hmac", b"k" * 32)
    with pytest.raises(ReferenceAuthorityError, match="must be independent"):
        PersistentReferenceAuthority(
            state / "reference.sqlite3",
            reference_key,
            authority_ref="v4-reference-authority-test",
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=STORE_REF,
        )
