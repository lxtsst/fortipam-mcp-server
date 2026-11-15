from __future__ import annotations

import os
from pathlib import Path
import sqlite3

import pytest

from v4_planning import (
    MaterialUseMonotonicCheckpointError,
    MaterialUseStoreTail,
    PersistentMaterialUseCheckpointAuthority,
    PersistentMaterialUseStateStore,
    PersistentMaterialUseStateStoreError,
)


AUTHORITY_REF = "v4-material-checkpoint-test"
STORE_REF = "v4-material-store-test"


def _owner_file(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    os.chmod(path, 0o600)
    return path


def _authority(
    tmp_path: Path,
    *,
    key: bytes = b"k" * 32,
) -> tuple[PersistentMaterialUseCheckpointAuthority, Path, Path]:
    state = tmp_path / "checkpoint-state"
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(state, 0o700)
    key_path = state / "checkpoint.hmac"
    if not key_path.exists():
        _owner_file(key_path, key)
    database = state / "checkpoint.sqlite3"
    return (
        PersistentMaterialUseCheckpointAuthority(
            database,
            key_path,
            authority_ref=AUTHORITY_REF,
        ),
        database,
        key_path,
    )


def _tail(sequence: int, chain_hmac: str) -> MaterialUseStoreTail:
    return MaterialUseStoreTail(STORE_REF, sequence, chain_hmac)


def test_material_checkpoint_compare_and_swap_survives_restart(
    tmp_path: Path,
) -> None:
    authority, database, key_path = _authority(tmp_path)
    empty = MaterialUseStoreTail.empty(STORE_REF)
    first = _tail(1, "a" * 64)
    second = _tail(2, "b" * 64)

    authority.verify(empty)
    authority.advance(empty, first)
    authority.verify(first)
    restarted = PersistentMaterialUseCheckpointAuthority(
        database,
        key_path,
        authority_ref=AUTHORITY_REF,
    )
    restarted.advance(first, second)
    restarted.verify(second)

    with pytest.raises(MaterialUseMonotonicCheckpointError, match="does not match"):
        restarted.verify(first)
    with pytest.raises(MaterialUseMonotonicCheckpointError, match="failed"):
        restarted.advance(first, second)


def test_material_checkpoint_rejects_invalid_transition_and_isolates_stores(
    tmp_path: Path,
) -> None:
    authority, _database, _key_path = _authority(tmp_path)
    empty = MaterialUseStoreTail.empty(STORE_REF)
    first = _tail(1, "a" * 64)
    other_empty = MaterialUseStoreTail.empty("v4-other-material-store")
    other_first = MaterialUseStoreTail(
        other_empty.store_ref,
        1,
        "c" * 64,
    )

    with pytest.raises(MaterialUseMonotonicCheckpointError, match="invalid"):
        authority.advance(empty, _tail(2, "b" * 64))
    with pytest.raises(MaterialUseMonotonicCheckpointError, match="invalid"):
        authority.advance(empty, other_first)
    authority.advance(empty, first)
    authority.verify(other_empty)
    authority.advance(other_empty, other_first)
    authority.verify(first)
    authority.verify(other_first)


def test_material_checkpoint_rejects_wrong_key_tamper_and_unsafe_paths(
    tmp_path: Path,
) -> None:
    authority, database, key_path = _authority(tmp_path)
    authority.advance(MaterialUseStoreTail.empty(STORE_REF), _tail(1, "a" * 64))
    original_key = key_path.read_bytes()
    key_path.write_bytes(b"w" * 32)
    with pytest.raises(MaterialUseMonotonicCheckpointError, match="integrity failed"):
        PersistentMaterialUseCheckpointAuthority(
            database,
            key_path,
            authority_ref=AUTHORITY_REF,
        )

    key_path.write_bytes(original_key)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE material_checkpoint_events SET current_chain_hmac = ? "
            "WHERE sequence = 1",
            ("d" * 64,),
        )
    with pytest.raises(MaterialUseMonotonicCheckpointError, match="integrity failed"):
        PersistentMaterialUseCheckpointAuthority(
            database,
            key_path,
            authority_ref=AUTHORITY_REF,
        )

    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    os.chmod(unsafe, 0o755)
    unsafe_key = _owner_file(unsafe / "checkpoint.hmac", b"u" * 32)
    with pytest.raises(MaterialUseMonotonicCheckpointError, match="owner-only"):
        PersistentMaterialUseCheckpointAuthority(
            unsafe / "checkpoint.sqlite3",
            unsafe_key,
            authority_ref=AUTHORITY_REF,
        )


def test_material_store_rejects_key_reuse_and_valid_older_database_restore(
    tmp_path: Path,
) -> None:
    checkpoint, _checkpoint_database, _checkpoint_key = _authority(
        tmp_path,
        key=b"k" * 32,
    )
    state = tmp_path / "material-state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    reused_key = _owner_file(state / "reused.hmac", b"k" * 32)
    with pytest.raises(PersistentMaterialUseStateStoreError, match="independent"):
        PersistentMaterialUseStateStore(
            state / "reused.sqlite3",
            reused_key,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=STORE_REF,
        )

    store_key = _owner_file(state / "material.hmac", b"m" * 32)
    database = state / "material.sqlite3"
    store = PersistentMaterialUseStateStore(
        database,
        store_key,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=STORE_REF,
    )
    empty_database = database.read_bytes()
    store.claim(request_digest="1" * 64, authorization_digest="2" * 64)
    checkpoint.verify(_tail(1, _material_tail(database)))

    database.write_bytes(empty_database)
    with pytest.raises(
        PersistentMaterialUseStateStoreError,
        match="checkpoint verification failed",
    ):
        PersistentMaterialUseStateStore(
            database,
            store_key,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=STORE_REF,
        )


def _material_tail(database: Path) -> str:
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT last_hmac FROM material_use_integrity_anchor WHERE singleton = 1"
        ).fetchone()
    assert row is not None
    return str(row[0])
