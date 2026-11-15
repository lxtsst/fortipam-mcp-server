from __future__ import annotations

import os
from pathlib import Path
import sqlite3

import pytest

from v4_planning import (
    MonotonicCheckpointError,
    PersistentPlanningCheckpointAuthority,
    PlanningStoreTail,
)


STORE_REF = "v4-planning-store-test"


def _authority(
    root: Path,
    *,
    key: bytes = b"planning-checkpoint-authority-test-key-00000000001",
) -> tuple[PersistentPlanningCheckpointAuthority, Path, Path]:
    state = root / "checkpoint-state"
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(state, 0o700)
    key_path = state / "checkpoint.hmac"
    if not key_path.exists():
        key_path.write_bytes(key)
        os.chmod(key_path, 0o600)
    database = state / "checkpoint.sqlite3"
    return (
        PersistentPlanningCheckpointAuthority(
            database,
            key_path,
            authority_ref="v4-planning-checkpoint-authority-test",
        ),
        database,
        key_path,
    )


def _tail(sequence: int, value: str) -> PlanningStoreTail:
    return PlanningStoreTail(STORE_REF, sequence, value)


def test_checkpoint_authority_compare_and_swap_survives_restart(
    tmp_path: Path,
) -> None:
    authority, database, key_path = _authority(tmp_path)
    empty = _tail(0, "chain-root")
    first = _tail(1, "a" * 64)
    second = _tail(2, "b" * 64)

    authority.verify(empty)
    authority.advance(empty, first)
    authority.verify(first)
    restarted = PersistentPlanningCheckpointAuthority(
        database,
        key_path,
        authority_ref="v4-planning-checkpoint-authority-test",
    )
    restarted.advance(first, second)
    restarted.verify(second)

    with pytest.raises(MonotonicCheckpointError, match="does not match"):
        restarted.verify(first)
    with pytest.raises(MonotonicCheckpointError, match="compare-and-swap failed"):
        restarted.advance(first, second)


@pytest.mark.parametrize("populated", [False, True])
def test_checkpoint_restart_and_verify_preserve_existing_file_bytes(
    tmp_path: Path, populated: bool,
) -> None:
    authority, database, key_path = _authority(tmp_path)
    tail = _tail(0, "chain-root")
    if populated:
        current = _tail(1, "a" * 64)
        authority.advance(tail, current)
        tail = current
    before = database.read_bytes()

    restarted = PersistentPlanningCheckpointAuthority(
        database, key_path, authority_ref="v4-planning-checkpoint-authority-test",
    )
    restarted.verify(tail)
    restarted.verify_ready()
    assert database.read_bytes() == before


def test_checkpoint_authority_rejects_invalid_transition_and_isolates_stores(
    tmp_path: Path,
) -> None:
    authority, _database, _key_path = _authority(tmp_path)
    empty = _tail(0, "chain-root")
    first = _tail(1, "a" * 64)
    other_empty = PlanningStoreTail("v4-other-planning-store", 0, "chain-root")
    other_first = PlanningStoreTail("v4-other-planning-store", 1, "c" * 64)

    with pytest.raises(MonotonicCheckpointError, match="invalid"):
        authority.advance(empty, _tail(2, "b" * 64))
    with pytest.raises(MonotonicCheckpointError, match="invalid"):
        authority.advance(empty, other_first)
    authority.advance(empty, first)
    authority.verify(other_empty)
    authority.advance(other_empty, other_first)
    authority.verify(first)
    authority.verify(other_first)


def test_checkpoint_authority_rejects_wrong_key_and_tamper(tmp_path: Path) -> None:
    authority, database, key_path = _authority(tmp_path)
    authority.advance(_tail(0, "chain-root"), _tail(1, "a" * 64))
    original_key = key_path.read_bytes()
    key_path.write_bytes(b"different-checkpoint-authority-key-000000000000001")
    with pytest.raises(MonotonicCheckpointError, match="integrity failed"):
        PersistentPlanningCheckpointAuthority(
            database,
            key_path,
            authority_ref="v4-planning-checkpoint-authority-test",
        )

    key_path.write_bytes(original_key)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE planning_checkpoint_events SET current_chain_hmac = ? "
            "WHERE sequence = 1",
            ("d" * 64,),
        )
    with pytest.raises(MonotonicCheckpointError, match="integrity failed"):
        PersistentPlanningCheckpointAuthority(
            database,
            key_path,
            authority_ref="v4-planning-checkpoint-authority-test",
        )


def test_checkpoint_authority_requires_owner_only_paths(tmp_path: Path) -> None:
    state = tmp_path / "unsafe-checkpoint-state"
    state.mkdir(mode=0o755)
    os.chmod(state, 0o755)
    key_path = state / "checkpoint.hmac"
    key_path.write_bytes(b"planning-checkpoint-authority-test-key-00000000001")
    os.chmod(key_path, 0o600)

    with pytest.raises(MonotonicCheckpointError, match="owner-only"):
        PersistentPlanningCheckpointAuthority(
            state / "checkpoint.sqlite3",
            key_path,
            authority_ref="v4-planning-checkpoint-authority-test",
        )
