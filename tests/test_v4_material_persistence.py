from __future__ import annotations

import os
from pathlib import Path
import sqlite3
from typing import cast

import pytest

from v4_planning.material_persistence import (
    MaterialUseMonotonicCheckpointError,
    MaterialUseStoreTail,
    MonotonicMaterialUseCheckpoint,
    PersistentMaterialUseStateStore,
    PersistentMaterialUseStateStoreError,
)
from v4_planning.material_provider import (
    C3MaterialBinding,
    MaterialBindingStatus,
    MaterialLease,
    MaterialLeaseCompletion,
    MaterialLeaseRequest,
    MaterialProvider,
    MaterialProviderClass,
    MaterialPurpose,
    MaterialRevocationReason,
)
from v4_planning.material_runtime import (
    MaterialLeaseCoordinator,
    MaterialRuntimeOutcome,
    MaterialUseClaimState,
    MaterialUseOutcome,
    material_lease_request_digest,
)


CHECKPOINT_STORE_REF = "material-use-state-test"


class _ExternalMaterialCheckpoint:
    authority_ref = "material-use-monotonic-checkpoint-test"

    def __init__(self, store_ref: str = CHECKPOINT_STORE_REF) -> None:
        self.tail = MaterialUseStoreTail.empty(store_ref)
        self.fail_next_advance = False
        self.advance_then_fail = False

    def verify(self, tail: MaterialUseStoreTail) -> None:
        if tail != self.tail:
            raise MaterialUseMonotonicCheckpointError("checkpoint mismatch")

    def advance(
        self,
        previous: MaterialUseStoreTail,
        current: MaterialUseStoreTail,
    ) -> None:
        if self.fail_next_advance:
            self.fail_next_advance = False
            raise MaterialUseMonotonicCheckpointError("checkpoint unavailable")
        if (
            previous != self.tail
            or current.store_ref != previous.store_ref
            or current.sequence != previous.sequence + 1
        ):
            raise MaterialUseMonotonicCheckpointError(
                "checkpoint compare-and-swap failed"
            )
        self.tail = current
        if self.advance_then_fail:
            self.advance_then_fail = False
            raise MaterialUseMonotonicCheckpointError(
                "checkpoint completion is ambiguous"
            )


def _request(*, plan_digest: str = "1" * 64) -> MaterialLeaseRequest:
    return MaterialLeaseRequest(
        action_id="secret-create-from-reference",
        action_version="1.0.0",
        plan_digest=plan_digest,
        policy_decision_digest="2" * 64,
        authorization_digest="3" * 64,
        scope_digest="4" * 64,
        audience_digest="5" * 64,
        provider_class=MaterialProviderClass.EXTERNAL_VAULT_LEASE,
        purpose=MaterialPurpose.INITIAL_ONBOARDING,
        requested_at=1_000,
        expires_at=1_120,
    )
def _paths(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "material-state"
    root.mkdir(mode=0o700, parents=True)
    os.chmod(root, 0o700)
    key = root / "material.key"
    key.write_bytes(b"m" * 32)
    os.chmod(key, 0o600)
    return root / "material.db", key


def _store(
    tmp_path: Path,
    *,
    monotonic_checkpoint: MonotonicMaterialUseCheckpoint | None = None,
    checkpoint_store_ref: str | None = None,
) -> PersistentMaterialUseStateStore:
    database = tmp_path / "material-state" / "material.db"
    key = tmp_path / "material-state" / "material.key"
    if not key.exists():
        database, key = _paths(tmp_path)
    return PersistentMaterialUseStateStore(
        database,
        key,
        monotonic_checkpoint=monotonic_checkpoint,
        checkpoint_store_ref=checkpoint_store_ref,
    )


class _Provider:
    def __init__(self) -> None:
        self.events: list[object] = []
        self.lease = MaterialLease()

    def validate_binding(
        self,
        binding: C3MaterialBinding,
        request: MaterialLeaseRequest,
    ) -> MaterialBindingStatus:
        del binding, request
        self.events.append("validate")
        return MaterialBindingStatus.AVAILABLE

    def acquire_lease(
        self,
        binding: C3MaterialBinding,
        request: MaterialLeaseRequest,
    ) -> MaterialLease:
        del binding, request
        self.events.append("acquire")
        return self.lease

    def release_lease(self, lease: MaterialLease) -> MaterialLeaseCompletion:
        assert lease is self.lease
        self.events.append("release")
        return MaterialLeaseCompletion.RELEASED

    def revoke_lease(
        self,
        lease: MaterialLease,
        *,
        reason: MaterialRevocationReason,
    ) -> MaterialLeaseCompletion:
        assert lease is self.lease
        self.events.extend(("revoke", reason))
        return MaterialLeaseCompletion.REVOKED


def test_claim_and_terminal_outcome_survive_restart(tmp_path: Path) -> None:
    database, key = _paths(tmp_path)
    request = _request()
    digest = material_lease_request_digest(request)
    store = PersistentMaterialUseStateStore(database, key)
    assert store.claim_count == 0

    first = store.claim(
        request_digest=digest,
        authorization_digest=request.authorization_digest,
    )
    assert first.state is MaterialUseClaimState.NEW
    assert store.claim_count == PersistentMaterialUseStateStore(database, key).claim_count == 1
    assert PersistentMaterialUseStateStore(database, key).claim(
        request_digest=digest,
        authorization_digest=request.authorization_digest,
    ).state is MaterialUseClaimState.IN_PROGRESS

    store.finalize(
        request_digest=digest,
        authorization_digest=request.authorization_digest,
        outcome=MaterialRuntimeOutcome.VERIFIED_AND_RELEASED,
    )
    replay = PersistentMaterialUseStateStore(database, key).claim(
        request_digest=digest,
        authorization_digest=request.authorization_digest,
    )
    assert replay.state is MaterialUseClaimState.REPLAY
    assert replay.outcome is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
    assert store.claim_count == PersistentMaterialUseStateStore(database, key).claim_count == 1


def test_external_checkpoint_rejects_database_rollback_and_advance_loss(
    tmp_path: Path,
) -> None:
    rollback_root = tmp_path / "rollback"
    checkpoint = _ExternalMaterialCheckpoint()
    store = _store(
        rollback_root,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
    )
    database = rollback_root / "material-state" / "material.db"
    key = rollback_root / "material-state" / "material.key"
    empty_database = database.read_bytes()
    request = _request()
    request_digest = material_lease_request_digest(request)
    assert store.claim(
        request_digest=request_digest,
        authorization_digest=request.authorization_digest,
    ).state is MaterialUseClaimState.NEW
    store.finalize(
        request_digest=request_digest,
        authorization_digest=request.authorization_digest,
        outcome=MaterialRuntimeOutcome.VERIFIED_AND_RELEASED,
    )
    assert checkpoint.tail.sequence == 2

    database.write_bytes(empty_database)
    with pytest.raises(
        PersistentMaterialUseStateStoreError,
        match="checkpoint verification failed",
    ):
        PersistentMaterialUseStateStore(
            database,
            key,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )

    ambiguous_root = tmp_path / "ambiguous"
    ambiguous_checkpoint = _ExternalMaterialCheckpoint()
    ambiguous_store = _store(
        ambiguous_root,
        monotonic_checkpoint=ambiguous_checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
    )
    ambiguous_checkpoint.advance_then_fail = True
    with pytest.raises(
        PersistentMaterialUseStateStoreError,
        match="checkpoint advance failed",
    ):
        ambiguous_store.claim(
            request_digest=request_digest,
            authorization_digest=request.authorization_digest,
        )
    assert ambiguous_checkpoint.tail.sequence == 1
    recovered = _store(
        ambiguous_root,
        monotonic_checkpoint=ambiguous_checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
    ).claim(
        request_digest=request_digest,
        authorization_digest=request.authorization_digest,
    )
    assert recovered.state is MaterialUseClaimState.IN_PROGRESS

    advance_root = tmp_path / "advance"
    advance_checkpoint = _ExternalMaterialCheckpoint()
    advance_store = _store(
        advance_root,
        monotonic_checkpoint=advance_checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
    )
    advance_checkpoint.fail_next_advance = True
    with pytest.raises(
        PersistentMaterialUseStateStoreError,
        match="checkpoint advance failed",
    ):
        advance_store.claim(
            request_digest=request_digest,
            authorization_digest=request.authorization_digest,
        )
    assert advance_checkpoint.tail.sequence == 0
    with pytest.raises(
        PersistentMaterialUseStateStoreError,
        match="checkpoint verification failed",
    ):
        _store(
            advance_root,
            monotonic_checkpoint=advance_checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )


def test_external_checkpoint_requires_complete_valid_binding(
    tmp_path: Path,
) -> None:
    database, key = _paths(tmp_path)
    checkpoint = _ExternalMaterialCheckpoint()

    with pytest.raises(PersistentMaterialUseStateStoreError, match="incomplete"):
        PersistentMaterialUseStateStore(
            database,
            key,
            monotonic_checkpoint=checkpoint,
        )
    with pytest.raises(PersistentMaterialUseStateStoreError, match="incomplete"):
        PersistentMaterialUseStateStore(
            database,
            key,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )
    with pytest.raises(PersistentMaterialUseStateStoreError, match="invalid"):
        PersistentMaterialUseStateStore(
            database,
            key,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref="short",
        )


def test_coordinator_restart_replay_never_reacquires_or_reconsumes(
    tmp_path: Path,
) -> None:
    database, key = _paths(tmp_path)
    provider = _Provider()
    request = _request()
    calls = 0

    def consume(lease: MaterialLease) -> MaterialUseOutcome:
        nonlocal calls
        assert lease is provider.lease
        calls += 1
        return MaterialUseOutcome.VERIFIED

    first = MaterialLeaseCoordinator(
        cast(MaterialProvider, provider),
        PersistentMaterialUseStateStore(database, key),
    ).execute_once(C3MaterialBinding(), request, consume, now_epoch=1_001)
    second = MaterialLeaseCoordinator(
        cast(MaterialProvider, provider),
        PersistentMaterialUseStateStore(database, key),
    ).execute_once(C3MaterialBinding(), request, consume, now_epoch=1_002)

    assert first is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
    assert second is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
    assert calls == 1
    assert provider.events == [
        "validate",
        "acquire",
        "release",
        "validate",
    ]


def test_unfinished_claim_recovers_as_reconciliation_without_provider_acquire(
    tmp_path: Path,
) -> None:
    database, key = _paths(tmp_path)
    request = _request()
    store = PersistentMaterialUseStateStore(database, key)
    store.claim(
        request_digest=material_lease_request_digest(request),
        authorization_digest=request.authorization_digest,
    )
    provider = _Provider()

    result = MaterialLeaseCoordinator(
        cast(MaterialProvider, provider),
        PersistentMaterialUseStateStore(database, key),
    ).execute_once(
        C3MaterialBinding(),
        request,
        lambda lease: MaterialUseOutcome.VERIFIED,
        now_epoch=1_001,
    )

    assert result is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
    assert provider.events == ["validate"]


def test_authorization_cannot_be_reused_for_a_different_request(
    tmp_path: Path,
) -> None:
    database, key = _paths(tmp_path)
    first = _request()
    second = _request(plan_digest="6" * 64)
    store = PersistentMaterialUseStateStore(database, key)
    store.claim(
        request_digest=material_lease_request_digest(first),
        authorization_digest=first.authorization_digest,
    )

    with pytest.raises(PersistentMaterialUseStateStoreError, match="unavailable"):
        store.claim(
            request_digest=material_lease_request_digest(second),
            authorization_digest=second.authorization_digest,
        )


def test_tamper_wrong_key_and_unsafe_permissions_fail_closed(
    tmp_path: Path,
) -> None:
    database, key = _paths(tmp_path / "tamper")
    request = _request()
    store = PersistentMaterialUseStateStore(database, key)
    store.claim(
        request_digest=material_lease_request_digest(request),
        authorization_digest=request.authorization_digest,
    )
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE material_use_ledger SET outcome = ? WHERE sequence = 1",
            (MaterialRuntimeOutcome.VERIFIED_AND_RELEASED.value,),
        )
    with pytest.raises(PersistentMaterialUseStateStoreError, match="invalid"):
        PersistentMaterialUseStateStore(database, key)
    with pytest.raises(PersistentMaterialUseStateStoreError, match="invalid"):
        _ = store.claim_count

    wrong_root = tmp_path / "wrong"
    wrong_database, wrong_key = _paths(wrong_root)
    PersistentMaterialUseStateStore(wrong_database, wrong_key)
    other_key = wrong_key.with_name("other.key")
    other_key.write_bytes(b"x" * 32)
    os.chmod(other_key, 0o600)
    with pytest.raises(PersistentMaterialUseStateStoreError):
        PersistentMaterialUseStateStore(wrong_database, other_key)

    unsafe_root = tmp_path / "unsafe"
    unsafe_database, unsafe_key = _paths(unsafe_root)
    os.chmod(unsafe_key, 0o644)
    with pytest.raises(PersistentMaterialUseStateStoreError, match="unsafe"):
        PersistentMaterialUseStateStore(unsafe_database, unsafe_key)


def test_store_retains_only_keyed_digests_and_closed_outcomes(
    tmp_path: Path,
) -> None:
    database, key = _paths(tmp_path)
    request = _request()
    request_digest = material_lease_request_digest(request)
    store = PersistentMaterialUseStateStore(database, key)
    store.claim(
        request_digest=request_digest,
        authorization_digest=request.authorization_digest,
    )
    store.finalize(
        request_digest=request_digest,
        authorization_digest=request.authorization_digest,
        outcome=MaterialRuntimeOutcome.RECONCILIATION_REQUIRED,
    )

    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT request_key, authorization_key, outcome "
            "FROM material_use_ledger ORDER BY sequence"
        ).fetchall()
    assert len(rows) == 2
    assert all(row[0] != request_digest for row in rows)
    assert all(row[1] != request.authorization_digest for row in rows)
    assert rows[-1][2] == MaterialRuntimeOutcome.RECONCILIATION_REQUIRED.value
