from __future__ import annotations

import os
from pathlib import Path
import sqlite3

import pytest

from v4_planning import (
    ApproverAuthorityCheckpointError,
    ApproverAuthorityStoreTail,
    ApproverAuthorityError,
    PersistentApproverAuthorizationAuthority,
    PersistentApproverCheckpointAuthority,
)


AUTHORITY_REF = "v4-approver-checkpoint-test"
STORE_REF = "v4-approver-store-test"


def _owner_file(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    os.chmod(path, 0o600)
    return path


def _authority(
    tmp_path: Path,
    *,
    key: bytes = b"k" * 32,
) -> tuple[PersistentApproverCheckpointAuthority, Path, Path]:
    state = tmp_path / "checkpoint-state"
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(state, 0o700)
    key_path = state / "checkpoint.hmac"
    if not key_path.exists():
        _owner_file(key_path, key)
    database = state / "checkpoint.sqlite3"
    return (
        PersistentApproverCheckpointAuthority(
            database,
            key_path,
            authority_ref=AUTHORITY_REF,
        ),
        database,
        key_path,
    )


def _tail(sequence: int, chain_mac: str, last_seen_at: int) -> ApproverAuthorityStoreTail:
    return ApproverAuthorityStoreTail(
        STORE_REF,
        sequence,
        chain_mac,
        last_seen_at,
    )


def test_approver_checkpoint_persists_event_and_time_advances(
    tmp_path: Path,
) -> None:
    authority, database, key_path = _authority(tmp_path)
    empty = ApproverAuthorityStoreTail.empty(STORE_REF)
    observed = _tail(0, empty.chain_mac, 10)
    issued = _tail(1, "a" * 64, 10)
    authorized = _tail(1, "a" * 64, 11)

    authority.verify(empty)
    authority.advance(empty, observed)
    authority.advance(observed, issued)
    authority.advance(issued, authorized)
    authority.verify(authorized)
    restarted = PersistentApproverCheckpointAuthority(
        database,
        key_path,
        authority_ref=AUTHORITY_REF,
    )
    restarted.verify(authorized)


def test_approver_checkpoint_isolates_stores_and_rejects_stale_or_skip(
    tmp_path: Path,
) -> None:
    authority, _database, _key_path = _authority(tmp_path)
    empty = ApproverAuthorityStoreTail.empty(STORE_REF)
    first = _tail(1, "a" * 64, 10)
    other_empty = ApproverAuthorityStoreTail.empty("v4-other-approver-store")
    other_first = ApproverAuthorityStoreTail(
        other_empty.store_ref,
        1,
        "b" * 64,
        5,
    )
    authority.advance(empty, first)
    authority.advance(other_empty, other_first)
    authority.verify(other_first)

    with pytest.raises(ApproverAuthorityCheckpointError, match="failed"):
        authority.advance(empty, first)
    with pytest.raises(ApproverAuthorityCheckpointError, match="invalid"):
        authority.advance(first, _tail(3, "c" * 64, 11))
    with pytest.raises(ApproverAuthorityCheckpointError, match="invalid"):
        authority.advance(
            first,
            ApproverAuthorityStoreTail(
                other_empty.store_ref,
                2,
                "c" * 64,
                11,
            ),
        )


def test_approver_checkpoint_rejects_invalid_transition_shapes(
    tmp_path: Path,
) -> None:
    authority, _database, _key_path = _authority(tmp_path)
    empty = ApproverAuthorityStoreTail.empty(STORE_REF)

    with pytest.raises(ApproverAuthorityCheckpointError, match="invalid"):
        authority.advance(empty, _tail(0, empty.chain_mac, 0))
    with pytest.raises(ApproverAuthorityCheckpointError, match="invalid"):
        authority.advance(_tail(1, "a" * 64, 1), _tail(2, "a" * 64, 2))
    with pytest.raises(ApproverAuthorityCheckpointError, match="invalid"):
        authority.advance(_tail(0, empty.chain_mac, 10), _tail(1, "a" * 64, 9))


def test_approver_checkpoint_rejects_wrong_key_and_tamper(tmp_path: Path) -> None:
    authority, database, key_path = _authority(tmp_path)
    authority.advance(
        ApproverAuthorityStoreTail.empty(STORE_REF),
        _tail(1, "a" * 64, 10),
    )
    original_key = key_path.read_bytes()
    key_path.write_bytes(b"w" * 32)
    with pytest.raises(ApproverAuthorityCheckpointError, match="integrity failed"):
        PersistentApproverCheckpointAuthority(
            database,
            key_path,
            authority_ref=AUTHORITY_REF,
        )
    key_path.write_bytes(original_key)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE approver_checkpoint_events SET current_last_seen_at = 11 "
            "WHERE event_sequence = 1"
        )
    with pytest.raises(ApproverAuthorityCheckpointError, match="integrity failed"):
        PersistentApproverCheckpointAuthority(
            database,
            key_path,
            authority_ref=AUTHORITY_REF,
        )


def test_approver_checkpoint_requires_owner_only_distinct_paths(
    tmp_path: Path,
) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    os.chmod(unsafe, 0o755)
    key_path = _owner_file(unsafe / "checkpoint.hmac", b"k" * 32)
    with pytest.raises(ApproverAuthorityCheckpointError, match="owner-only"):
        PersistentApproverCheckpointAuthority(
            unsafe / "checkpoint.sqlite3",
            key_path,
            authority_ref=AUTHORITY_REF,
        )

    safe = tmp_path / "safe"
    safe.mkdir(mode=0o700)
    os.chmod(safe, 0o700)
    reused = _owner_file(safe / "reused", b"k" * 32)
    with pytest.raises(ApproverAuthorityCheckpointError, match="paths are invalid"):
        PersistentApproverCheckpointAuthority(
            reused,
            reused,
            authority_ref=AUTHORITY_REF,
        )


def test_approver_checkpoint_reports_key_reuse_without_exposing_key(
    tmp_path: Path,
) -> None:
    authority, _database, _key_path = _authority(tmp_path)
    other, _other_database, _other_key_path = _authority(
        tmp_path / "other",
        key=b"k" * 32,
    )
    distinct, _distinct_database, _distinct_key_path = _authority(
        tmp_path / "distinct",
        key=b"d" * 32,
    )
    assert authority.shares_key_material_with(other)
    assert not authority.shares_key_material_with(distinct)


def test_approver_authority_rejects_checkpoint_key_reuse(tmp_path: Path) -> None:
    checkpoint, _database, _key_path = _authority(tmp_path, key=b"k" * 32)
    approver_state = tmp_path / "approver-state"
    approver_state.mkdir(mode=0o700)
    os.chmod(approver_state, 0o700)
    approver_key = _owner_file(approver_state / "approver.hmac", b"k" * 32)

    with pytest.raises(ApproverAuthorityError, match="must be independent"):
        PersistentApproverAuthorizationAuthority(
            approver_state / "approver.sqlite3",
            approver_key,
            authority_ref="v4-approver-authority-test",
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=STORE_REF,
        )
