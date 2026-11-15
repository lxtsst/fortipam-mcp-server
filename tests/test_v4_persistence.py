from __future__ import annotations

import copy
from dataclasses import replace
import os
from pathlib import Path
import sqlite3
import stat
import threading
from typing import cast

import pytest

from test_v4_m3 import (
    ExactApproverAuthority,
    Issuer,
    NOW,
    StaticPlanningEngine,
    _confirmation,
    _interaction,
    _plan,
    _requester,
    _summary,
)
from v4_planning import (
    AuthenticatedRequester,
    M2PlanningEngine,
    M3PlanOnlyWorkflowService,
    PlanningContractError,
    SchemeDraft,
    SummaryState,
    canonical_digest,
)
from v4_planning.approval import (
    ApprovalReceiptAuthenticator,
    AuthenticatedApprover,
    M3ApprovalGate,
)
from v4_planning.persistence import (
    MonotonicCheckpointError,
    MonotonicPlanningCheckpoint,
    PersistentPlanningStoreError,
    PersistentProtectedPlanningStore,
    PlanningStoreTail,
)
from v4_planning.policy import M3PlanPolicy


CHECKPOINT_STORE_REF = "v4-planning-store-test"


class _ExternalCheckpoint:
    authority_ref = "v4-external-monotonic-checkpoint-test"

    def __init__(self, store_ref: str = CHECKPOINT_STORE_REF) -> None:
        self.tail = PlanningStoreTail(store_ref, 0, "chain-root")
        self.fail_next_advance = False

    def verify(self, tail: PlanningStoreTail) -> None:
        if tail != self.tail:
            raise MonotonicCheckpointError("checkpoint mismatch")

    def advance(
        self,
        previous: PlanningStoreTail,
        current: PlanningStoreTail,
    ) -> None:
        if self.fail_next_advance:
            self.fail_next_advance = False
            raise MonotonicCheckpointError("checkpoint unavailable")
        if (
            previous != self.tail
            or current.store_ref != previous.store_ref
            or current.sequence != previous.sequence + 1
        ):
            raise MonotonicCheckpointError("checkpoint compare-and-swap failed")
        self.tail = current


def _new_store(
    root: Path,
    *,
    key: bytes = b"v4-m32-persistence-test-key-00000000000000000001",
    now_epoch: int = NOW + 50,
    monotonic_checkpoint: MonotonicPlanningCheckpoint | None = None,
    checkpoint_store_ref: str | None = None,
    approval_receipt_authenticator: ApprovalReceiptAuthenticator | None = None,
) -> tuple[PersistentProtectedPlanningStore, Path, Path]:
    state = root / "planning-state"
    state.mkdir(mode=0o700, parents=True)
    os.chmod(state, 0o700)
    key_path = state / "planning.hmac"
    key_path.write_bytes(key)
    os.chmod(key_path, 0o600)
    database = state / "planning.sqlite3"
    return (
        PersistentProtectedPlanningStore(
            database,
            key_path,
            clock=lambda: now_epoch,
            monotonic_checkpoint=monotonic_checkpoint,
            checkpoint_store_ref=checkpoint_store_ref,
            approval_receipt_authenticator=approval_receipt_authenticator,
        ),
        database,
        key_path,
    )


def _persist_complete_chain(
    store: PersistentProtectedPlanningStore,
    *,
    receipt_authenticator: ApprovalReceiptAuthenticator | None = None,
):
    requester = _requester()
    summary = _summary(requester)
    confirmation = _confirmation(summary)
    plan = _plan(requester, summary, confirmation)
    issuer = Issuer()
    decision = M3PlanPolicy(issuer).evaluate(
        plan,
        requester,
        now_epoch=NOW + 30,
    )
    receipt = M3ApprovalGate(
        issuer,
        receipt_authenticator=receipt_authenticator,
    ).approve(
        decision,
        AuthenticatedApprover("approver-subject-0001"),
        now_epoch=NOW + 40,
    )
    store.put_summary(summary)
    store.put_confirmation(confirmation)
    store.put_plan(plan)
    store.put_policy_decision(decision)
    store.put_approval_receipt(receipt)
    return requester, summary, confirmation, plan, decision, receipt


def test_authenticated_approval_receipt_requires_verifier_across_restart(
    tmp_path: Path,
) -> None:
    authenticator = ApprovalReceiptAuthenticator(b"a" * 32)
    store, database, key = _new_store(
        tmp_path,
        approval_receipt_authenticator=authenticator,
    )
    requester, _summary_value, _confirmation_value, plan, _decision, receipt = (
        _persist_complete_chain(
            store,
            receipt_authenticator=authenticator,
        )
    )
    assert receipt.receipt_mac is not None

    restarted = PersistentProtectedPlanningStore(
        database,
        key,
        clock=lambda: NOW + 50,
        approval_receipt_authenticator=authenticator,
    )
    assert restarted.get_approval_receipt(receipt.receipt_ref) == receipt
    claim = restarted.claim_approval(
        receipt.receipt_ref,
        plan.plan_ref,
        requester.digest,
    )
    assert claim.execution_authorized is False

    with pytest.raises(PersistentPlanningStoreError, match="unavailable"):
        PersistentProtectedPlanningStore(database, key)
    with pytest.raises(PersistentPlanningStoreError, match="authenticity"):
        PersistentProtectedPlanningStore(
            database,
            key,
            approval_receipt_authenticator=ApprovalReceiptAuthenticator(b"b" * 32),
        )

    with pytest.raises(PersistentPlanningStoreError, match="must be independent"):
        _new_store(
            tmp_path / "shared-key",
            key=b"a" * 32,
            approval_receipt_authenticator=authenticator,
        )


def test_authorized_approver_binding_survives_protected_store_restart(
    tmp_path: Path,
) -> None:
    authenticator = ApprovalReceiptAuthenticator(b"z" * 32)
    store, database, key = _new_store(
        tmp_path,
        approval_receipt_authenticator=authenticator,
    )
    requester = AuthenticatedRequester(
        "operator-subject-0001",
        "operator",
        identity_authority_ref="identity-authority-ref01",
        subject_namespace="workforce-namespace-v1",
    )
    approver = AuthenticatedApprover(
        "approver-subject-0001",
        identity_authority_ref="identity-authority-ref01",
        subject_namespace="workforce-namespace-v1",
    )
    summary = _summary(requester)
    confirmation = _confirmation(summary)
    plan = _plan(requester, summary, confirmation)
    issuer = Issuer()
    decision = M3PlanPolicy(issuer).evaluate(
        plan,
        requester,
        now_epoch=NOW + 30,
    )
    store.put_summary(summary)
    store.put_confirmation(confirmation)
    store.put_plan(plan)
    store.put_policy_decision(decision)
    service = M3PlanOnlyWorkflowService(
        cast(M2PlanningEngine, StaticPlanningEngine(summary, confirmation, plan)),
        store,
        M3PlanPolicy(issuer),
        M3ApprovalGate(
            issuer,
            receipt_authenticator=authenticator,
            approver_authorizer=ExactApproverAuthority(),
        ),
    )

    receipt = service.approve(
        decision.decision_ref,
        approver,
        requester=requester,
        now_epoch=NOW + 40,
    )

    restarted = PersistentProtectedPlanningStore(
        database,
        key,
        clock=lambda: NOW + 50,
        approval_receipt_authenticator=authenticator,
    )
    assert restarted.get_approval_receipt(receipt.receipt_ref) == receipt
    assert receipt.approver_authorization_digest is not None
    assert receipt.approval_nonce_digest is not None
    assert receipt.policy_version == decision.policy_version
    claim = restarted.claim_approval(
        receipt.receipt_ref,
        plan.plan_ref,
        requester.digest,
    )
    assert claim.execution_authorized is False


def test_owner_only_store_survives_restart_with_exact_record_chain(
    tmp_path: Path,
) -> None:
    store, database, key = _new_store(tmp_path)
    requester, summary, confirmation, plan, decision, receipt = (
        _persist_complete_chain(store)
    )

    assert stat.S_IMODE(database.stat().st_mode) == 0o600
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert stat.S_IMODE(database.parent.stat().st_mode) == 0o700

    restarted = PersistentProtectedPlanningStore(
        database,
        key,
        clock=lambda: NOW + 50,
    )
    assert restarted.get_summary(summary.summary_ref, summary.revision) == summary
    assert restarted.get_confirmation(confirmation.confirmation_ref) == confirmation
    assert restarted.get_plan(plan.plan_ref) == plan
    assert restarted.get_policy_decision(decision.decision_ref) == decision
    assert restarted.get_approval_receipt(receipt.receipt_ref) == receipt
    assert requester.digest == plan.requester_digest


def test_store_round_trips_positive_integer_object_fields(tmp_path: Path) -> None:
    store, database, key = _new_store(tmp_path)
    summary = _summary(_requester())
    change = replace(
        summary.object_changes[0],
        current_fields=(("maximum_members", 1),),
        proposed_fields=(("maximum_members", 2),),
        expected_fields=(("maximum_members", 2),),
    )
    candidate = copy.copy(summary)
    object.__setattr__(candidate, "object_changes", (change,))
    integer_summary = replace(
        summary,
        object_changes=(change,),
        summary_digest=canonical_digest(candidate.canonical_content()),
    )
    store.put_summary(integer_summary)

    restarted = PersistentProtectedPlanningStore(database, key, clock=lambda: NOW + 50)
    restored = restarted.get_summary(
        integer_summary.summary_ref, integer_summary.revision
    )
    assert dict(restored.object_changes[0].current_fields)["maximum_members"] == 1
    assert dict(restored.object_changes[0].expected_fields)["maximum_members"] == 2


def test_chain_order_immutability_and_policy_replay_fail_closed(tmp_path: Path) -> None:
    store, _database, _key = _new_store(tmp_path)
    requester = _requester()
    summary = _summary(requester)
    confirmation = _confirmation(summary)
    plan = _plan(requester, summary, confirmation)

    with pytest.raises(PersistentPlanningStoreError, match="summary and confirmation"):
        store.put_plan(plan)
    store.put_summary(summary)
    with pytest.raises(PersistentPlanningStoreError, match="immutable"):
        store.put_summary(replace(summary, state=SummaryState.INVALIDATED))
    store.put_confirmation(confirmation)
    store.put_plan(plan)

    issuer = Issuer()
    first = M3PlanPolicy(issuer).evaluate(plan, requester, now_epoch=NOW + 30)
    second = M3PlanPolicy(issuer).evaluate(plan, requester, now_epoch=NOW + 31)
    store.put_policy_decision(first)
    with pytest.raises(PersistentPlanningStoreError, match="already produced"):
        store.put_policy_decision(second)


def test_workflow_persists_decision_receipt_and_claim_across_restarts(
    tmp_path: Path,
) -> None:
    authenticator = ApprovalReceiptAuthenticator(b"c" * 32)
    store, database, key = _new_store(
        tmp_path,
        now_epoch=NOW + 50,
        approval_receipt_authenticator=authenticator,
    )
    requester = _requester()
    summary = _summary(requester)
    confirmation = _confirmation(summary)
    plan = _plan(requester, summary, confirmation)
    issuer = Issuer()
    service = M3PlanOnlyWorkflowService(
        cast(M2PlanningEngine, StaticPlanningEngine(summary, confirmation, plan)),
        store,
        M3PlanPolicy(issuer),
        M3ApprovalGate(issuer, receipt_authenticator=authenticator),
    )
    service.compile_summary(cast(SchemeDraft, object()), requester, (), now_epoch=NOW)
    service.confirm_intent(
        summary.summary_ref,
        requester,
        _interaction(summary, requester),
        now_epoch=NOW + 10,
    )
    service.prepare_plan(
        summary.summary_ref,
        confirmation.confirmation_ref,
        requester,
        now_epoch=NOW + 20,
    )
    decision = service.request_approval(
        plan.plan_ref,
        requester,
        now_epoch=NOW + 30,
    )

    restarted_store = PersistentProtectedPlanningStore(
        database,
        key,
        clock=lambda: NOW + 50,
        approval_receipt_authenticator=authenticator,
    )
    restarted = M3PlanOnlyWorkflowService(
        cast(M2PlanningEngine, StaticPlanningEngine(summary, confirmation, plan)),
        restarted_store,
        M3PlanPolicy(Issuer()),
        M3ApprovalGate(Issuer(), receipt_authenticator=authenticator),
    )
    receipt = restarted.approve(
        decision.decision_ref,
        AuthenticatedApprover("approver-subject-0001"),
        now_epoch=NOW + 40,
    )
    assert receipt.receipt_mac is not None

    final_store = PersistentProtectedPlanningStore(
        database,
        key,
        clock=lambda: NOW + 50,
        approval_receipt_authenticator=authenticator,
    )
    final = M3PlanOnlyWorkflowService(
        cast(M2PlanningEngine, StaticPlanningEngine(summary, confirmation, plan)),
        final_store,
        M3PlanPolicy(Issuer()),
        M3ApprovalGate(Issuer(), receipt_authenticator=authenticator),
    )
    result = final.claim_approval(receipt.receipt_ref, plan.plan_ref, requester)
    assert result.approval_validated is True
    assert result.ready_for_dispatch is False
    assert result.execution_authorized is False


def test_receipt_claim_replay_and_expiry_fail_closed_after_restart(
    tmp_path: Path,
) -> None:
    store, database, key = _new_store(tmp_path / "active")
    requester, _summary_value, _confirmation_value, plan, _decision, receipt = (
        _persist_complete_chain(store)
    )
    with pytest.raises(PersistentPlanningStoreError, match="exact prepared plan"):
        store.claim_approval(
            receipt.receipt_ref,
            plan.plan_ref,
            "0" * 64,
        )
    claim = store.claim_approval(
        receipt.receipt_ref,
        plan.plan_ref,
        requester.digest,
    )
    assert claim.execution_authorized is False
    assert claim.plan_digest == plan.plan_digest

    restarted = PersistentProtectedPlanningStore(
        database,
        key,
        clock=lambda: NOW + 60,
    )
    assert restarted.get_approval_claim(receipt.receipt_ref) == claim
    with pytest.raises(PersistentPlanningStoreError, match="replayed"):
        restarted.claim_approval(
            receipt.receipt_ref,
            plan.plan_ref,
            requester.digest,
        )

    expired, _expired_database, _expired_key = _new_store(
        tmp_path / "expired",
        now_epoch=NOW + 200,
    )
    requester, _summary_value, _confirmation_value, plan, _decision, receipt = (
        _persist_complete_chain(expired)
    )
    with pytest.raises(PersistentPlanningStoreError, match="active lifetime"):
        expired.claim_approval(
            receipt.receipt_ref,
            plan.plan_ref,
            requester.digest,
        )


def test_hmac_chain_anchor_detects_content_and_tail_tampering(tmp_path: Path) -> None:
    content_store, content_database, content_key = _new_store(tmp_path / "content")
    _persist_complete_chain(content_store)
    with sqlite3.connect(content_database) as connection:
        connection.execute(
            "UPDATE planning_records SET payload_json = '{}' WHERE sequence = 1"
        )
    with pytest.raises(PersistentPlanningStoreError, match="HMAC chain"):
        PersistentProtectedPlanningStore(content_database, content_key)

    tail_store, tail_database, tail_key = _new_store(tmp_path / "tail")
    _persist_complete_chain(tail_store)
    with sqlite3.connect(tail_database) as connection:
        connection.execute(
            "DELETE FROM planning_records WHERE record_type = 'approval_receipt'"
        )
    with pytest.raises(PersistentPlanningStoreError, match="tail"):
        PersistentProtectedPlanningStore(tail_database, tail_key)


def test_external_monotonic_checkpoint_detects_whole_database_rollback(
    tmp_path: Path,
) -> None:
    checkpoint = _ExternalCheckpoint()
    store, database, key = _new_store(
        tmp_path,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
    )
    requester = _requester()
    summary = _summary(requester)
    confirmation = _confirmation(summary)

    store.put_summary(summary)
    rolled_back_database = database.read_bytes()
    store.put_confirmation(confirmation)
    assert checkpoint.tail.sequence == 2

    database.write_bytes(rolled_back_database)
    with pytest.raises(
        PersistentPlanningStoreError,
        match="monotonic checkpoint verification",
    ):
        PersistentProtectedPlanningStore(
            database,
            key,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )


def test_external_checkpoint_advances_complete_chain_and_survives_restart(
    tmp_path: Path,
) -> None:
    checkpoint = _ExternalCheckpoint()
    store, database, key = _new_store(
        tmp_path,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
    )
    requester, _summary_value, _confirmation_value, plan, _decision, receipt = (
        _persist_complete_chain(store)
    )
    assert checkpoint.tail.sequence == 5

    restarted = PersistentProtectedPlanningStore(
        database,
        key,
        clock=lambda: NOW + 50,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
    )
    claim = restarted.claim_approval(
        receipt.receipt_ref,
        plan.plan_ref,
        requester.digest,
    )

    assert claim.execution_authorized is False
    assert checkpoint.tail.sequence == 6


def test_external_checkpoint_advance_failure_leaves_store_fail_closed(
    tmp_path: Path,
) -> None:
    checkpoint = _ExternalCheckpoint()
    store, database, key = _new_store(
        tmp_path,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
    )
    checkpoint.fail_next_advance = True

    with pytest.raises(
        PersistentPlanningStoreError,
        match="monotonic checkpoint advance",
    ):
        store.put_summary(_summary(_requester()))
    with pytest.raises(
        PersistentPlanningStoreError,
        match="monotonic checkpoint verification",
    ):
        PersistentProtectedPlanningStore(
            database,
            key,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )


def test_external_checkpoint_requires_complete_exact_binding(tmp_path: Path) -> None:
    _store, database, key = _new_store(tmp_path)
    checkpoint = _ExternalCheckpoint()

    with pytest.raises(PersistentPlanningStoreError, match="binding is incomplete"):
        PersistentProtectedPlanningStore(
            database,
            key,
            monotonic_checkpoint=checkpoint,
        )
    with pytest.raises(PersistentPlanningStoreError, match="binding is incomplete"):
        PersistentProtectedPlanningStore(
            database,
            key,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )


def test_store_rejects_non_owner_only_key_and_database(tmp_path: Path) -> None:
    store, database, key = _new_store(tmp_path)
    del store
    os.chmod(key, 0o644)
    with pytest.raises(PersistentPlanningStoreError, match="unsafe"):
        PersistentProtectedPlanningStore(database, key)


def test_object_change_rejects_noncanonical_or_duplicate_field_tuples() -> None:
    change = _summary(_requester()).object_changes[0]
    with pytest.raises(PlanningContractError, match="canonically ordered"):
        replace(
            change,
            current_fields=(("z_field", True), ("a_field", False)),
        )
    with pytest.raises(PlanningContractError, match="canonically ordered"):
        replace(
            change,
            expected_fields=(("same_field", True), ("same_field", False)),
        )


def test_read_integrity_verification_uses_one_sqlite_snapshot(tmp_path: Path) -> None:
    reader, database, key = _new_store(tmp_path)
    writer = PersistentProtectedPlanningStore(
        database,
        key,
        clock=lambda: NOW + 50,
    )
    summary = _summary(_requester())
    appended = threading.Event()
    write_finished = threading.Event()
    original_append = writer._append_record

    def append_with_signal(*args: object, **kwargs: object) -> None:
        original_append(*args, **kwargs)  # type: ignore[arg-type]
        appended.set()

    writer._append_record = append_with_signal  # type: ignore[method-assign]

    def write_summary() -> None:
        writer.put_summary(summary)
        write_finished.set()

    original_anchor_hmac = reader._anchor_hmac
    started = False
    thread: threading.Thread | None = None

    def anchor_hmac_with_concurrent_writer(sequence: int, chain_hmac: str) -> str:
        nonlocal started, thread
        if not started:
            started = True
            thread = threading.Thread(target=write_summary, daemon=True)
            thread.start()
            assert appended.wait(timeout=2)
            assert not write_finished.is_set()
        return original_anchor_hmac(sequence, chain_hmac)

    reader._anchor_hmac = anchor_hmac_with_concurrent_writer  # type: ignore[method-assign]
    with pytest.raises(PersistentPlanningStoreError, match="unavailable"):
        reader.get_summary(summary.summary_ref, summary.revision)
    assert thread is not None
    thread.join(timeout=2)
    assert write_finished.is_set()
    assert reader.get_summary(summary.summary_ref, summary.revision) == summary

    os.chmod(key, 0o600)
    os.chmod(database, 0o644)
    with pytest.raises(PersistentPlanningStoreError, match="unsafe"):
        PersistentProtectedPlanningStore(database, key)
