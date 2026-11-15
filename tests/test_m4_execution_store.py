from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import sqlite3
import stat

import pytest

import fortipam_mcp.m4_execution_store as store_module
from fortipam_mcp.m4_execution_store import (
    M4ExecutionStoreTail,
    M4MonotonicCheckpointError,
    MonotonicM4ExecutionCheckpoint,
    PersistentM4ExecutionStateStore,
    PersistentM4ExecutionStoreError,
)
from v4_planning import (
    M4AuditEvent,
    M4AuthorizationReplay,
    M4Claim,
    M4ClaimState,
    M4Compensation,
    M4ExecutionAuthorization,
    M4ExecutionError,
    M4ExecutionKernel,
    M4ExecutionPlan,
    M4ExecutionResult,
    M4Outcome,
    M4Verification,
    canonical_digest,
)


KEY = b"persistent-m4-execution-store-key-0001"
PLAN_REF = "m4-plan-persistent-reference-01"
REQUESTER = "1" * 64
IDEMPOTENCY = "2" * 64
CONTEXT = "3" * 64
AUTHORIZATION = "4" * 64
AUDIT_REFERENCE = "5" * 64
NOW = 1_000
CHECKPOINT_STORE_REF = "m4-execution-store-test"


class _ExternalM4Checkpoint:
    authority_ref = "m4-external-monotonic-checkpoint-test"

    def __init__(self, store_ref: str = CHECKPOINT_STORE_REF) -> None:
        self.tail = M4ExecutionStoreTail.empty(store_ref)
        self.fail_next_advance = False

    def verify(self, tail: M4ExecutionStoreTail) -> None:
        if tail != self.tail:
            raise M4MonotonicCheckpointError("checkpoint mismatch")

    def advance(
        self,
        previous: M4ExecutionStoreTail,
        current: M4ExecutionStoreTail,
    ) -> None:
        if self.fail_next_advance:
            self.fail_next_advance = False
            raise M4MonotonicCheckpointError("checkpoint unavailable")
        if (
            previous != self.tail
            or current.store_ref != previous.store_ref
            or current.sequence != previous.sequence + 1
        ):
            raise M4MonotonicCheckpointError("checkpoint compare-and-swap failed")
        self.tail = current


def _paths(tmp_path: Path) -> tuple[Path, Path]:
    state = tmp_path / "state"
    state.mkdir(mode=0o700, parents=True)
    os.chmod(state, 0o700)
    key = state / "execution.key"
    key.write_bytes(KEY)
    os.chmod(key, 0o600)
    return state / "execution.sqlite3", key


def _store(
    tmp_path: Path,
    *,
    monotonic_checkpoint: MonotonicM4ExecutionCheckpoint | None = None,
    checkpoint_store_ref: str | None = None,
) -> PersistentM4ExecutionStateStore:
    database = tmp_path / "state" / "execution.sqlite3"
    key = tmp_path / "state" / "execution.key"
    if not key.exists():
        database, key = _paths(tmp_path)
    return PersistentM4ExecutionStateStore(
        database,
        key,
        monotonic_checkpoint=monotonic_checkpoint,
        checkpoint_store_ref=checkpoint_store_ref,
    )


def _claim(
    store: PersistentM4ExecutionStateStore,
    *,
    plan_ref: str = PLAN_REF,
    requester: str = REQUESTER,
    idempotency: str = IDEMPOTENCY,
    context: str = CONTEXT,
    authorization: str = AUTHORIZATION,
) -> M4Claim:
    return store.claim(
        plan_ref=plan_ref,
        requester_digest=requester,
        idempotency_digest=idempotency,
        context_digest=context,
        authorization_digest=authorization,
    )


def test_inspect_claim_is_readonly_and_matches_exact_original_authorization(tmp_path: Path) -> None:
    store = _store(tmp_path)
    values = {"plan_ref":PLAN_REF,"requester_digest":REQUESTER,"idempotency_digest":IDEMPOTENCY,
              "context_digest":CONTEXT,"authorization_digest":AUTHORIZATION}
    with pytest.raises(M4ExecutionError):
        store.inspect_claim(**values)
    assert store.claim_count==0 and not store.audit_events
    _claim(store)
    assert store.inspect_claim(**values).state is M4ClaimState.IN_PROGRESS
    assert store.claim_count==1 and not store.audit_events
    _claim(store,plan_ref="m4-plan-other-reference",authorization="9"*64)
    for key,value in (("context_digest","8"*64),("authorization_digest","9"*64),
                      ("plan_ref","m4-plan-missing-reference")):
        with pytest.raises(M4ExecutionError):
            store.inspect_claim(**{**values,key:value})
    _finalize(store)
    before = store.audit_events
    inspected = store.inspect_claim(**values)
    assert inspected.state is M4ClaimState.REPLAY and inspected.result==_result()
    assert store.claim_count==2 and store.audit_events==before


def test_readonly_reopen_preserves_unknown_bytes_and_denies_every_write(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _claim(store)
    result = M4ExecutionResult(M4Outcome.RECONCILIATION_REQUIRED, M4Verification.UNKNOWN,
                              M4Compensation.NOT_REQUESTED, False)
    event = _event(authorization="dispatch_unknown", outcome=result.outcome, verification=result.verification)
    store.finalize(plan_ref=PLAN_REF, requester_digest=REQUESTER, idempotency_digest=IDEMPOTENCY,
                   context_digest=CONTEXT, result=result, event=event)
    before = store._path.read_bytes()
    readonly = PersistentM4ExecutionStateStore(store._path, store._key_path, read_only=True)
    readonly.verify_ready()
    assert readonly.claim_count == 1 and readonly.audit_events == store.audit_events
    assert readonly.inspect_claim(plan_ref=PLAN_REF, requester_digest=REQUESTER,
        idempotency_digest=IDEMPOTENCY, context_digest=CONTEXT, authorization_digest=AUTHORIZATION).result == result
    for write in (lambda: _claim(readonly), lambda: _finalize(readonly), lambda: readonly.append_audit(event)):
        with pytest.raises(PersistentM4ExecutionStoreError, match="read-only"):
            write()
    with closing(readonly._connect()) as connection:
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("DELETE FROM execution_ledger")
    assert readonly._path.read_bytes() == before


@pytest.mark.parametrize("missing", ["database", "directory"])
def test_readonly_reopen_never_creates_missing_runtime(tmp_path: Path, missing: str) -> None:
    database, key = _paths(tmp_path)
    if missing == "directory":
        database = database.parent / "missing" / database.name
    with pytest.raises(PersistentM4ExecutionStoreError):
        PersistentM4ExecutionStateStore(database, key, read_only=True)
    assert not database.exists()
    if missing == "directory":
        assert not database.parent.exists()


@pytest.mark.parametrize("damage", ["schema", "version", "hmac"])
def test_readonly_reopen_rejects_untrusted_state_without_repair(tmp_path: Path, damage: str) -> None:
    store = _store(tmp_path)
    with closing(sqlite3.connect(store._path)) as connection:
        connection.execute({"schema": "DROP TABLE execution_ledger", "version": "PRAGMA user_version=2",
                            "hmac": "UPDATE execution_integrity_anchor SET anchor_hmac='invalid'"}[damage])
        connection.commit()
    before = store._path.read_bytes()
    with pytest.raises(PersistentM4ExecutionStoreError):
        PersistentM4ExecutionStateStore(store._path, store._key_path, read_only=True)
    assert store._path.read_bytes() == before


def _result() -> M4ExecutionResult:
    return M4ExecutionResult(
        M4Outcome.SUCCEEDED,
        M4Verification.VERIFIED,
        M4Compensation.NOT_REQUESTED,
        False,
    )


def _event(
    *,
    authorization: str = "verified",
    outcome: M4Outcome = M4Outcome.SUCCEEDED,
    verification: M4Verification = M4Verification.VERIFIED,
    compensation: M4Compensation = M4Compensation.NOT_REQUESTED,
    digest_reference: str = AUDIT_REFERENCE,
) -> M4AuditEvent:
    return M4AuditEvent(
        0,
        authorization,
        outcome,
        verification,
        compensation,
        digest_reference,
    )


def _finalize(store: PersistentM4ExecutionStateStore) -> None:
    store.finalize(
        plan_ref=PLAN_REF,
        requester_digest=REQUESTER,
        idempotency_digest=IDEMPOTENCY,
        context_digest=CONTEXT,
        result=_result(),
        event=_event(),
    )


def test_owner_only_paths_and_safe_sqlite_settings_are_required(tmp_path: Path) -> None:
    store = _store(tmp_path)
    database = tmp_path / "state" / "execution.sqlite3"
    key = tmp_path / "state" / "execution.key"
    assert stat.S_IMODE(database.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(database.stat().st_mode) == 0o600
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    with store._connect() as connection:  # noqa: SLF001 - hardening assertion.
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2

    os.chmod(database, 0o640)
    with pytest.raises(PersistentM4ExecutionStoreError, match="owner-only"):
        PersistentM4ExecutionStateStore(database, key)
    os.chmod(database, 0o600)
    os.chmod(key, 0o640)
    with pytest.raises(PersistentM4ExecutionStoreError, match="owner-only"):
        PersistentM4ExecutionStateStore(database, key)


def test_new_finalize_and_idempotent_replay_survive_restart(tmp_path: Path) -> None:
    store = _store(tmp_path)
    assert _claim(store).state is M4ClaimState.NEW
    _finalize(store)

    restarted = _store(tmp_path)
    replay = _claim(restarted)
    assert replay.state is M4ClaimState.REPLAY
    assert replay.result == _result()
    assert restarted.audit_events == (
        M4AuditEvent(
            1,
            "verified",
            M4Outcome.SUCCEEDED,
            M4Verification.VERIFIED,
            M4Compensation.NOT_REQUESTED,
            AUDIT_REFERENCE,
        ),
    )


def test_external_checkpoint_rejects_database_rollback_and_advance_loss(
    tmp_path: Path,
) -> None:
    rollback_root = tmp_path / "rollback"
    checkpoint = _ExternalM4Checkpoint()
    store = _store(
        rollback_root,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
    )
    database = rollback_root / "state" / "execution.sqlite3"
    key = rollback_root / "state" / "execution.key"
    empty_database = database.read_bytes()
    assert _claim(store).state is M4ClaimState.NEW
    _finalize(store)
    assert checkpoint.tail.sequence == 2

    database.write_bytes(empty_database)
    with pytest.raises(PersistentM4ExecutionStoreError, match="verification failed"):
        PersistentM4ExecutionStateStore(
            database,
            key,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )

    advance_root = tmp_path / "advance"
    advance_checkpoint = _ExternalM4Checkpoint()
    advance_store = _store(
        advance_root,
        monotonic_checkpoint=advance_checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
    )
    advance_checkpoint.fail_next_advance = True
    with pytest.raises(PersistentM4ExecutionStoreError, match="advance failed"):
        _claim(advance_store)
    assert advance_checkpoint.tail.sequence == 0
    with pytest.raises(PersistentM4ExecutionStoreError, match="verification failed"):
        _store(
            advance_root,
            monotonic_checkpoint=advance_checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )


def test_external_checkpoint_requires_complete_valid_binding(tmp_path: Path) -> None:
    database, key = _paths(tmp_path)
    checkpoint = _ExternalM4Checkpoint()

    with pytest.raises(PersistentM4ExecutionStoreError, match="incomplete"):
        PersistentM4ExecutionStateStore(
            database,
            key,
            monotonic_checkpoint=checkpoint,
        )
    with pytest.raises(PersistentM4ExecutionStoreError, match="incomplete"):
        PersistentM4ExecutionStateStore(
            database,
            key,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )
    with pytest.raises(PersistentM4ExecutionStoreError, match="invalid"):
        PersistentM4ExecutionStateStore(
            database,
            key,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref="short",
        )


def test_unfinished_claim_is_in_progress_after_restart_and_kernel_never_dispatches(
    tmp_path: Path,
) -> None:
    plan = _plan()
    authorization = _authorization(plan)
    context = canonical_digest(
        {
            "authorization_digest": authorization.authorization_digest,
            "plan_digest": plan.plan_digest,
            "revision": plan.revision,
        }
    )
    store = _store(tmp_path)
    assert store.claim(
        plan_ref=plan.plan_ref,
        requester_digest=plan.requester_digest,
        idempotency_digest=plan.idempotency_digest,
        context_digest=context,
        authorization_digest=authorization.authorization_digest,
    ).state is M4ClaimState.NEW

    adapter = _Adapter()
    result = M4ExecutionKernel(
        adapter,
        _Verifier(),
        _store(tmp_path),
    ).execute(plan, authorization, now_epoch=NOW)
    assert result == M4ExecutionResult(
        M4Outcome.RECONCILIATION_REQUIRED,
        M4Verification.UNKNOWN,
        M4Compensation.NOT_REQUESTED,
        True,
    )
    assert adapter.calls == []
    assert _store(tmp_path).audit_events[-1].authorization == "in_progress"


def test_context_conflict_fails_without_changing_original_claim(tmp_path: Path) -> None:
    store = _store(tmp_path)
    assert _claim(store).state is M4ClaimState.NEW
    with pytest.raises(M4ExecutionError, match="idempotency context conflict"):
        _claim(store, context="6" * 64)
    assert _claim(_store(tmp_path)).state is M4ClaimState.IN_PROGRESS


def test_execution_authorization_is_consumed_once_across_namespaces(tmp_path: Path) -> None:
    store = _store(tmp_path)
    assert _claim(store).state is M4ClaimState.NEW
    with pytest.raises(M4AuthorizationReplay, match="already consumed"):
        _claim(
            store,
            plan_ref="m4-plan-persistent-reference-02",
            idempotency="7" * 64,
            context="8" * 64,
        )
    assert _claim(_store(tmp_path)).state is M4ClaimState.IN_PROGRESS


def test_concurrent_claim_has_exactly_one_new_reservation(tmp_path: Path) -> None:
    _store(tmp_path)

    def claim() -> M4ClaimState:
        return _claim(_store(tmp_path)).state

    with ThreadPoolExecutor(max_workers=2) as executor:
        states = list(executor.map(lambda _: claim(), range(2)))
    assert sorted(states) == [M4ClaimState.IN_PROGRESS, M4ClaimState.NEW]


def test_raw_execution_identifiers_are_not_persisted(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _claim(store)
    _finalize(store)
    raw = (tmp_path / "state" / "execution.sqlite3").read_bytes()
    for value in (PLAN_REF, REQUESTER, IDEMPOTENCY, CONTEXT, AUTHORIZATION):
        assert value.encode("ascii") not in raw


def test_content_tail_anchor_and_wrong_key_tamper_fail_closed(tmp_path: Path) -> None:
    content = tmp_path / "content"
    store = _store(content)
    _claim(store)
    database = content / "state" / "execution.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE execution_ledger SET context_key = ? WHERE sequence = 1",
            ("9" * 64,),
        )
    with pytest.raises(PersistentM4ExecutionStoreError, match="audit chain"):
        _store(content)

    tail = tmp_path / "tail"
    store = _store(tail)
    _claim(store)
    _finalize(store)
    tail_database = tail / "state" / "execution.sqlite3"
    with sqlite3.connect(tail_database) as connection:
        connection.execute("DELETE FROM execution_ledger WHERE sequence = 2")
    with pytest.raises(PersistentM4ExecutionStoreError, match="anchor"):
        _store(tail)

    wrong_key = tmp_path / "wrong-key"
    _store(wrong_key)
    key = wrong_key / "state" / "execution.key"
    key.write_bytes(b"different-persistent-m4-key-material")
    os.chmod(key, 0o600)
    with pytest.raises(PersistentM4ExecutionStoreError, match="anchor"):
        _store(wrong_key)


def test_audit_reconstruction_is_deterministic_and_tamper_blocks_reads(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    first = _event(
        authorization="in_progress",
        outcome=M4Outcome.RECONCILIATION_REQUIRED,
        verification=M4Verification.UNKNOWN,
    )
    second = _event(
        authorization="adapter_denied",
        outcome=M4Outcome.DENIED,
        verification=M4Verification.NOT_STARTED,
        digest_reference="a" * 64,
    )
    store.append_audit(first)
    store.append_audit(second)
    expected = (
        replace(first, ordinal=1),
        replace(second, ordinal=2),
    )
    assert store.audit_events == expected
    assert _store(tmp_path).audit_events == expected

    database = tmp_path / "state" / "execution.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE execution_ledger SET audit_authorization = 'verified' "
            "WHERE sequence = 1"
        )
    with pytest.raises(PersistentM4ExecutionStoreError, match="audit chain"):
        _ = store.audit_events


def test_failed_transaction_rolls_back_and_restart_recovers_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    assert _claim(store).state is M4ClaimState.NEW
    original = store._append_record  # noqa: SLF001 - transactional fault injection.

    def fail_after_insert(
        connection: sqlite3.Connection,
        state: object,
        record: object,
    ) -> None:
        original(connection, state, record)  # type: ignore[arg-type]
        raise sqlite3.OperationalError("simulated durable-write failure")

    monkeypatch.setattr(store, "_append_record", fail_after_insert)
    with pytest.raises(PersistentM4ExecutionStoreError, match="persisted safely"):
        _finalize(store)
    monkeypatch.setattr(store, "_append_record", original)

    restarted = _store(tmp_path)
    assert _claim(restarted).state is M4ClaimState.IN_PROGRESS
    assert restarted.audit_events == ()


def test_finalize_requires_exact_open_claim_context_and_consistent_audit(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    with pytest.raises(M4ExecutionError, match="cannot be finalized"):
        _finalize(store)
    assert _claim(store).state is M4ClaimState.NEW
    with pytest.raises(M4ExecutionError, match="cannot be finalized"):
        store.finalize(
            plan_ref=PLAN_REF,
            requester_digest=REQUESTER,
            idempotency_digest=IDEMPOTENCY,
            context_digest="b" * 64,
            result=_result(),
            event=_event(),
        )
    with pytest.raises(PersistentM4ExecutionStoreError, match="inconsistent"):
        store.finalize(
            plan_ref=PLAN_REF,
            requester_digest=REQUESTER,
            idempotency_digest=IDEMPOTENCY,
            context_digest=CONTEXT,
            result=_result(),
            event=_event(outcome=M4Outcome.DENIED),
        )
    _finalize(store)
    with pytest.raises(M4ExecutionError, match="cannot be finalized"):
        _finalize(store)


class _Verifier:
    def verify(
        self,
        plan: M4ExecutionPlan,
        authorization: M4ExecutionAuthorization,
        *,
        now_epoch: int,
    ) -> None:
        del plan, authorization, now_epoch


class _Adapter:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def read_current(self, plan: M4ExecutionPlan) -> str:
        del plan
        self.calls.append("read_current")
        return "c" * 64

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        del plan
        self.calls.append("dispatch")

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        del plan
        self.calls.append("read_postcondition")
        return "d" * 64


def _plan() -> M4ExecutionPlan:
    values = {
        "action_id": "folder-create",
        "action_version": "3.2.0",
        "adapter_ref": "folder-adapter-reference-01",
        "approval_digest": "e" * 64,
        "compensation_ref": None,
        "confirmation_digest": "f" * 64,
        "expected_current_digest": "c" * 64,
        "expected_state_digest": "d" * 64,
        "expires_at": NOW + 300,
        "idempotency_digest": "6" * 64,
        "parameters_digest": "7" * 64,
        "plan_ref": "m4-kernel-persistent-plan-01",
        "requester_digest": "8" * 64,
        "revision": 1,
        "summary_digest": "9" * 64,
        "target_ref": "public-folder-target-reference-01",
    }
    return M4ExecutionPlan(
        plan_ref=str(values["plan_ref"]),
        revision=1,
        action_id="folder-create",
        action_version="3.2.0",
        adapter_ref="folder-adapter-reference-01",
        target_ref="public-folder-target-reference-01",
        requester_digest="8" * 64,
        summary_digest="9" * 64,
        confirmation_digest="f" * 64,
        approval_digest="e" * 64,
        parameters_digest="7" * 64,
        expected_current_digest="c" * 64,
        expected_state_digest="d" * 64,
        idempotency_digest="6" * 64,
        expires_at=NOW + 300,
        compensation_ref=None,
        plan_digest=canonical_digest(values),
    )


def _authorization(plan: M4ExecutionPlan) -> M4ExecutionAuthorization:
    values = {
        "approval_digest": plan.approval_digest,
        "approval_ref": "approval-persistent-reference-01",
        "approver_digest": "a" * 64,
        "authorization_ref": "authorization-persistent-ref-01",
        "confirmation_digest": plan.confirmation_digest,
        "confirmation_ref": "confirmation-persistent-ref-01",
        "execution_authorized": True,
        "expires_at": NOW + 120,
        "issued_at": NOW - 1,
        "one_time": True,
        "plan_digest": plan.plan_digest,
        "plan_ref": plan.plan_ref,
        "requester_digest": plan.requester_digest,
    }
    return M4ExecutionAuthorization(
        authorization_ref="authorization-persistent-ref-01",
        plan_ref=plan.plan_ref,
        plan_digest=plan.plan_digest,
        requester_digest=plan.requester_digest,
        confirmation_ref="confirmation-persistent-ref-01",
        confirmation_digest=plan.confirmation_digest,
        approval_ref="approval-persistent-reference-01",
        approval_digest=plan.approval_digest,
        approver_digest="a" * 64,
        issued_at=NOW - 1,
        expires_at=NOW + 120,
        one_time=True,
        execution_authorized=True,
        authorization_digest=canonical_digest(values),
    )
