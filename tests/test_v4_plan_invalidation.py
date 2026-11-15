"""Append-only invalidation preserves the chain and refuses plan resurrection."""

import json
import sqlite3

import pytest

from test_v4_persistence import _new_store, _persist_complete_chain, _ExternalCheckpoint, CHECKPOINT_STORE_REF
from test_v4_m3 import NOW
from v4_planning.persistence import PersistentPlanningStoreError, PersistentProtectedPlanningStore
from v4_planning.store import InMemoryProtectedPlanningStore, PlanInvalidationRecord, ProtectedStoreError
from v4_planning import canonical_digest


def _store(tmp_path, kind):
    if kind == "memory":
        return InMemoryProtectedPlanningStore(clock=lambda: NOW + 50), None, None
    return _new_store(tmp_path)


@pytest.mark.parametrize("kind", ["memory", "persistent"])
def test_invalidated_parent_refuses_plan_policy_receipt_claim_and_repreparation(tmp_path, kind):
    store, database, key = _store(tmp_path, kind)
    requester, summary, confirmation, plan, decision, receipt = _persist_complete_chain(store)
    assert store.get_plan(plan.plan_ref) == plan  # Existing chains remain readable.
    store.invalidate_plan(plan.plan_ref, evaluated_at=NOW + 50, reason_codes=("current_state_drift",))
    store.invalidate_plan(plan.plan_ref, evaluated_at=NOW + 50, reason_codes=("current_state_drift",))
    assert store.get_summary(summary.summary_ref, summary.revision) == summary
    assert store.get_confirmation(confirmation.confirmation_ref) == confirmation
    for operation in (
        lambda: store.get_plan(plan.plan_ref),
        lambda: store.find_plan_for_confirmation(confirmation.confirmation_ref),
        lambda: store.put_plan(plan),
        lambda: store.get_policy_decision(decision.decision_ref),
        lambda: store.put_policy_decision(decision),
        lambda: store.get_approval_receipt(receipt.receipt_ref),
        lambda: store.put_approval_receipt(receipt),
        lambda: store.claim_approval(receipt.receipt_ref, plan.plan_ref, requester.digest),
    ):
        with pytest.raises(ProtectedStoreError, match="invalidated"):
            operation()
    with pytest.raises(ProtectedStoreError):
        store.invalidate_plan(plan.plan_ref, evaluated_at=NOW + 51, reason_codes=("current_state_drift",))
    if database is not None:
        with sqlite3.connect(database) as connection:
            assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
            assert connection.execute("SELECT count(*) FROM planning_records WHERE record_type='plan_invalidation'").fetchone()[0] == 1
            row = connection.execute("SELECT parent_ref,parent_digest,parent_revision,payload_json FROM planning_records WHERE record_type='plan_invalidation'").fetchone()
            assert row[:3] == (plan.plan_ref, plan.plan_digest, plan.revision)
            assert json.loads(row[3]) == PlanInvalidationRecord(plan.plan_ref, plan.plan_digest,
                NOW + 50, ("current_state_drift",)).as_dict()
        restarted = PersistentProtectedPlanningStore(database, key, clock=lambda: NOW + 50)
        with pytest.raises(ProtectedStoreError, match="invalidated"):
            restarted.get_plan(plan.plan_ref)
        with pytest.raises(ProtectedStoreError, match="invalidated"):
            restarted.find_plan_for_confirmation(confirmation.confirmation_ref)
        assert restarted.get_summary(summary.summary_ref, summary.revision) == summary


@pytest.mark.parametrize("kind", ["memory", "persistent"])
@pytest.mark.parametrize("field,value", [
    ("evaluated_at", True), ("evaluated_at", -1), ("evaluated_at", NOW - 1),
    ("reason_codes", ["current_state_drift"]), ("reason_codes", ()),
    ("reason_codes", ("other_reason",)),
    ("reason_codes", ("current_state_drift", "current_state_unavailable_or_unsafe")),
    ("plan_ref", "missing-plan-ref01"), ("plan_ref", ["wrong-type"]),
])
def test_invalidation_rejects_noncanonical_inputs_without_appending(tmp_path, kind, field, value):
    store, database, _ = _store(tmp_path, kind)
    _, _, _, plan, _, _ = _persist_complete_chain(store)
    arguments = {"plan_ref": plan.plan_ref, "evaluated_at": NOW + 50, "reason_codes": ("current_state_drift",)}
    arguments[field] = value
    with pytest.raises(ProtectedStoreError):
        store.invalidate_plan(**arguments)
    assert store.get_plan(plan.plan_ref) == plan
    if database:
        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT count(*) FROM planning_records WHERE record_type='plan_invalidation'").fetchone()[0] == 0


def test_claim_record_remains_preserved_but_unavailable_after_invalidation(tmp_path):
    store, database, key = _new_store(tmp_path)
    requester, _, _, plan, _, receipt = _persist_complete_chain(store)
    store.claim_approval(receipt.receipt_ref, plan.plan_ref, requester.digest)
    store.invalidate_plan(plan.plan_ref, evaluated_at=NOW + 50,
        reason_codes=("current_state_unavailable_or_unsafe",))
    restarted = PersistentProtectedPlanningStore(database, key, clock=lambda: NOW + 50)
    with pytest.raises(ProtectedStoreError, match="invalidated"):
        restarted.get_approval_claim(receipt.receipt_ref)
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT count(*) FROM planning_records WHERE record_type='approval_claim'").fetchone()[0] == 1


@pytest.mark.parametrize("mutation", ["parent_digest", "payload_digest", "reason", "timestamp", "delete"])
def test_tampered_invalidation_chain_fails_closed_across_restart(tmp_path, mutation):
    store, database, key = _new_store(tmp_path)
    _, _, _, plan, _, _ = _persist_complete_chain(store)
    store.invalidate_plan(plan.plan_ref, evaluated_at=NOW + 50, reason_codes=("current_state_drift",))
    with sqlite3.connect(database) as connection:
        if mutation == "parent_digest":
            connection.execute("UPDATE planning_records SET parent_digest=? WHERE record_type='plan_invalidation'", ("a" * 64,))
        elif mutation == "delete":
            connection.execute("DELETE FROM planning_records WHERE record_type='plan_invalidation'")
        else:
            payload = json.loads(connection.execute("SELECT payload_json FROM planning_records WHERE record_type='plan_invalidation'").fetchone()[0])
            changes = {"payload_digest": {"plan_digest": "a" * 64}, "reason": {"reason_codes": ["other_reason"]},
                       "timestamp": {"evaluated_at": True}}[mutation]
            payload.update(changes)
            connection.execute("UPDATE planning_records SET payload_json=? WHERE record_type='plan_invalidation'",
                (json.dumps(payload, sort_keys=True, separators=(",", ":")),))
    with pytest.raises(PersistentPlanningStoreError):
        PersistentProtectedPlanningStore(database, key, clock=lambda: NOW + 50).get_plan(plan.plan_ref)


def test_invalidation_uses_existing_checkpoint_and_exact_record_retry(tmp_path):
    checkpoint = _ExternalCheckpoint()
    store, database, key = _new_store(tmp_path, monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF)
    _, _, _, plan, _, _ = _persist_complete_chain(store)
    before = checkpoint.tail
    store.invalidate_plan(plan.plan_ref, evaluated_at=NOW + 50, reason_codes=("current_state_drift",))
    assert checkpoint.tail.sequence == before.sequence + 1
    after = checkpoint.tail
    store.invalidate_plan(plan.plan_ref, evaluated_at=NOW + 50, reason_codes=("current_state_drift",))
    assert checkpoint.tail == after
    with pytest.raises(ProtectedStoreError):
        PersistentProtectedPlanningStore(database, key, clock=lambda: NOW + 50,
            monotonic_checkpoint=checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF).get_plan(plan.plan_ref)


def test_legacy_schema_v1_chain_without_invalidation_reopens_unchanged(tmp_path):
    store, database, key = _new_store(tmp_path)
    _, summary, confirmation, plan, decision, receipt = _persist_complete_chain(store)
    restarted = PersistentProtectedPlanningStore(database, key, clock=lambda: NOW + 50)
    assert restarted.get_summary(summary.summary_ref, summary.revision) == summary
    assert restarted.get_confirmation(confirmation.confirmation_ref) == confirmation
    assert restarted.get_plan(plan.plan_ref) == plan
    assert restarted.get_policy_decision(decision.decision_ref) == decision
    assert restarted.get_approval_receipt(receipt.receipt_ref) == receipt
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM planning_records WHERE record_type='plan_invalidation'").fetchone()[0] == 0


def test_invalidation_checkpoint_failure_never_returns_success(tmp_path):
    checkpoint = _ExternalCheckpoint()
    store, database, _ = _new_store(tmp_path, monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF)
    _, _, _, plan, _, _ = _persist_complete_chain(store)
    before = checkpoint.tail
    checkpoint.fail_next_advance = True
    with pytest.raises(PersistentPlanningStoreError):
        store.invalidate_plan(plan.plan_ref, evaluated_at=NOW + 50, reason_codes=("current_state_drift",))
    assert checkpoint.tail == before
    with pytest.raises(PersistentPlanningStoreError):
        store.get_plan(plan.plan_ref)
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT count(*) FROM planning_records WHERE record_type='plan_invalidation'").fetchone()[0] == 1
