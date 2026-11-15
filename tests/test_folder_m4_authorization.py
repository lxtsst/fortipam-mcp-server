from __future__ import annotations

from dataclasses import fields, replace
import os
from pathlib import Path
import sqlite3

import pytest

from fortipam_mcp.folder_create_contract import FolderCreateRequest
from fortipam_mcp.folder_m4_adapter import (
    ACTION_ID,
    ACTION_VERSION,
    ADAPTER_REF,
    PreparedChildFolderCreate,
)
from fortipam_mcp.folder_m4_authorization import (
    FolderM4AuthorizationCheckpointError,
    FolderM4AuthorizationError,
    FolderM4AuthorizationStoreTail,
    MonotonicFolderM4AuthorizationCheckpoint,
    PersistentFolderM4AuthorizationStore,
    PersistentFolderM4PromotionAuthority,
    ProtectedFolderM4AuthorizationVerifier,
    ProtectedPreparedFolderActionResolver,
)
from test_v4_m3 import (
    Issuer,
    NOW,
    _confirmation,
    _plan,
    _requester,
    _summary,
)
from v4_planning import (
    FinalIntentSummary,
    M4AuthorizationReplay,
    M4ExecutionPlan,
    PreparedPlan,
    canonical_digest,
)
from v4_planning.approval import AuthenticatedApprover, M3ApprovalGate
from v4_planning.persistence import PersistentProtectedPlanningStore
from v4_planning.policy import M3PlanPolicy


ACTIVE = NOW + 50
IDEMPOTENCY = "9" * 64
CHECKPOINT_STORE_REF = "folder-m4-authorization-store-test"


class _ExternalAuthorizationCheckpoint:
    authority_ref = "folder-m4-monotonic-checkpoint-test"

    def __init__(self, store_ref: str = CHECKPOINT_STORE_REF) -> None:
        self.tail = FolderM4AuthorizationStoreTail.empty(store_ref)
        self.fail_next_advance = False
        self.advance_then_fail = False

    def verify(self, tail: FolderM4AuthorizationStoreTail) -> None:
        if tail != self.tail:
            raise FolderM4AuthorizationCheckpointError("checkpoint mismatch")

    def advance(
        self,
        previous: FolderM4AuthorizationStoreTail,
        current: FolderM4AuthorizationStoreTail,
    ) -> None:
        if self.fail_next_advance:
            self.fail_next_advance = False
            raise FolderM4AuthorizationCheckpointError("checkpoint unavailable")
        if (
            previous != self.tail
            or current.store_ref != previous.store_ref
            or current.sequence != previous.sequence + 1
        ):
            raise FolderM4AuthorizationCheckpointError(
                "checkpoint compare-and-swap failed"
            )
        self.tail = current
        if self.advance_then_fail:
            self.advance_then_fail = False
            raise FolderM4AuthorizationCheckpointError(
                "checkpoint completion is ambiguous"
            )


def _write_key(path: Path, value: bytes) -> None:
    path.write_bytes(value)
    os.chmod(path, 0o600)


def _new_authorization_store(
    root: Path,
    *,
    now_epoch: int = ACTIVE,
    monotonic_checkpoint: (
        MonotonicFolderM4AuthorizationCheckpoint | None
    ) = None,
    checkpoint_store_ref: str | None = None,
) -> tuple[PersistentFolderM4AuthorizationStore, Path, Path, Path]:
    state = root / "folder-m4"
    state.mkdir(parents=True, mode=0o700)
    os.chmod(state, 0o700)
    store_key = state / "store.hmac"
    promotion_key = state / "promotion.hmac"
    _write_key(store_key, b"folder-m4-store-key-000000000000000001")
    _write_key(promotion_key, b"folder-m4-promotion-key-0000000000001")
    database = state / "authorization.sqlite3"
    return (
        PersistentFolderM4AuthorizationStore(
            database,
            store_key,
            promotion_key,
            monotonic_checkpoint=monotonic_checkpoint,
            checkpoint_store_ref=checkpoint_store_ref,
            clock=lambda: now_epoch,
        ),
        database,
        store_key,
        promotion_key,
    )


def _prepared() -> PreparedChildFolderCreate:
    return PreparedChildFolderCreate.build(
        plan_ref="prepared-plan-ref0001",
        target_ref="folder-object-ref0001",
        request=FolderCreateRequest.child("V4-Demo", 17),
    )


def _folder_summary(prepared: PreparedChildFolderCreate) -> FinalIntentSummary:
    requester = _requester()
    base = _summary(requester)
    change = replace(
        base.object_changes[0],
        proposed_fields=(("request_parameters_digest", prepared.parameters_digest),),
        current_projection_digest=prepared.expected_current_digest,
        expected_projection_digest=prepared.expected_state_digest,
    )
    values = {
        item.name: getattr(base, item.name)
        for item in fields(base)
        if item.name != "summary_digest"
    }
    values.update(
        {
            "action_family_ref": ACTION_ID,
            "action_family_version": ACTION_VERSION,
            "object_changes": (change,),
            "current_state_digest": prepared.expected_current_digest,
            "proposed_changes_digest": prepared.parameters_digest,
            "expected_state_digest": prepared.expected_state_digest,
        }
    )
    content = dict(base.canonical_content())
    content.update(
        {
            "action_family_ref": ACTION_ID,
            "action_family_version": ACTION_VERSION,
            "object_changes": [change.as_dict()],
            "current_state_digest": prepared.expected_current_digest,
            "proposed_changes_digest": prepared.parameters_digest,
            "expected_state_digest": prepared.expected_state_digest,
        }
    )
    return FinalIntentSummary(
        **values,
        summary_digest=canonical_digest(content),
    )


def _folder_plan(
    prepared: PreparedChildFolderCreate,
    summary: FinalIntentSummary,
) -> PreparedPlan:
    requester = _requester()
    confirmation = _confirmation(summary)
    base = _plan(requester, summary, confirmation, plan_ref=prepared.plan_ref)
    line = replace(
        base.lines[0],
        action_family_ref=ACTION_ID,
        action_family_version=ACTION_VERSION,
        target_ref=prepared.target_ref,
        expected_current_digest=prepared.expected_current_digest,
        expected_state_digest=prepared.expected_state_digest,
    )
    values = {
        item.name: getattr(base, item.name)
        for item in fields(base)
        if item.name != "plan_digest"
    }
    values["lines"] = (line,)
    content = dict(base.canonical_content())
    content["lines"] = [line.as_dict()]
    return PreparedPlan(**values, plan_digest=canonical_digest(content))


def _planning_chain(root: Path):
    prepared = _prepared()
    requester = _requester()
    summary = _folder_summary(prepared)
    confirmation = _confirmation(summary)
    plan = _folder_plan(prepared, summary)
    state = root / "planning"
    state.mkdir(parents=True, mode=0o700)
    os.chmod(state, 0o700)
    key = state / "planning.hmac"
    _write_key(key, b"planning-key-folder-m4-00000000000000001")
    planning = PersistentProtectedPlanningStore(
        state / "planning.sqlite3",
        key,
        clock=lambda: ACTIVE,
    )
    issuer = Issuer()
    decision = M3PlanPolicy(issuer).evaluate(plan, requester, now_epoch=NOW + 30)
    receipt = M3ApprovalGate(issuer).approve(
        decision,
        AuthenticatedApprover("approver-subject-0001"),
        now_epoch=NOW + 40,
    )
    planning.put_summary(summary)
    planning.put_confirmation(confirmation)
    planning.put_plan(plan)
    planning.put_policy_decision(decision)
    planning.put_approval_receipt(receipt)
    claim = planning.claim_approval(receipt.receipt_ref, plan.plan_ref, requester.digest)
    return planning, prepared, summary, confirmation, plan, decision, receipt, claim


def _promotion(authority: PersistentFolderM4PromotionAuthority, chain: tuple[object, ...]):
    _planning, prepared, summary, confirmation, plan, decision, receipt, claim = chain
    assert isinstance(prepared, PreparedChildFolderCreate)
    return authority.issue(
        promotion_ref="folder-m4-promotion-ref0001",
        issuer_ref="trusted-m4-promotion-authority-ref01",
        policy_version="1.0.0",
        source_plan_ref=plan.plan_ref,
        source_plan_revision=plan.revision,
        source_plan_digest=plan.plan_digest,
        summary_ref=summary.summary_ref,
        summary_revision=summary.revision,
        summary_digest=summary.summary_digest,
        confirmation_ref=confirmation.confirmation_ref,
        confirmation_digest=confirmation.record_digest,
        source_decision_ref=decision.decision_ref,
        source_decision_digest=decision.decision_digest,
        approval_ref=receipt.receipt_ref,
        approval_digest=receipt.receipt_digest,
        source_claim_digest=canonical_digest(claim.as_dict()),
        requester_digest=plan.requester_digest,
        approver_digest=receipt.approver_digest,
        action_id=ACTION_ID,
        action_version=ACTION_VERSION,
        adapter_ref=ADAPTER_REF,
        target_ref=prepared.target_ref,
        parameters_digest=prepared.parameters_digest,
        expected_current_digest=prepared.expected_current_digest,
        expected_state_digest=prepared.expected_state_digest,
        idempotency_digest=IDEMPOTENCY,
        issued_at=ACTIVE,
        expires_at=ACTIVE + 30,
        one_time=True,
        execution_authorized=True,
    )


def _issue(
    root: Path,
    *,
    monotonic_checkpoint: (
        MonotonicFolderM4AuthorizationCheckpoint | None
    ) = None,
    checkpoint_store_ref: str | None = None,
):
    chain = _planning_chain(root)
    planning, prepared, _summary_value, _confirmation_value, _plan_value, _decision, receipt, _claim = chain
    store, database, store_key, promotion_key = _new_authorization_store(
        root,
        monotonic_checkpoint=monotonic_checkpoint,
        checkpoint_store_ref=checkpoint_store_ref,
    )
    authority = PersistentFolderM4PromotionAuthority(promotion_key)
    binding = store.issue(
        planning,
        prepared,
        approval_receipt_ref=receipt.receipt_ref,
        idempotency_digest=IDEMPOTENCY,
        promotion=_promotion(authority, chain),
        now_epoch=ACTIVE,
    )
    return store, binding, database, store_key, promotion_key


def test_external_checkpoint_rejects_issue_and_consumption_rollback(
    tmp_path: Path,
) -> None:
    checkpoint = _ExternalAuthorizationCheckpoint()
    chain = _planning_chain(tmp_path)
    planning, prepared, _summary_value, _confirmation_value, _plan_value, _decision, receipt, _claim = chain
    store, database, store_key, promotion_key = _new_authorization_store(
        tmp_path,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
    )
    empty_database = database.read_bytes()
    binding = store.issue(
        planning,
        prepared,
        approval_receipt_ref=receipt.receipt_ref,
        idempotency_digest=IDEMPOTENCY,
        promotion=_promotion(PersistentFolderM4PromotionAuthority(promotion_key), chain),
        now_epoch=ACTIVE,
    )
    issued_database = database.read_bytes()
    assert checkpoint.tail.sequence == 1
    store.consume(
        binding.plan,
        binding.authorization,
        authenticated_requester_digest=binding.plan.requester_digest,
        now_epoch=ACTIVE + 1,
    )
    assert checkpoint.tail.sequence == 2

    database.write_bytes(issued_database)
    with pytest.raises(FolderM4AuthorizationError, match="verification failed"):
        PersistentFolderM4AuthorizationStore(
            database,
            store_key,
            promotion_key,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )
    database.write_bytes(empty_database)
    with pytest.raises(FolderM4AuthorizationError, match="verification failed"):
        PersistentFolderM4AuthorizationStore(
            database,
            store_key,
            promotion_key,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )


def test_external_checkpoint_advance_loss_and_ambiguity_fail_closed(
    tmp_path: Path,
) -> None:
    lost_root = tmp_path / "lost"
    lost_checkpoint = _ExternalAuthorizationCheckpoint()
    chain = _planning_chain(lost_root)
    planning, prepared, _summary_value, _confirmation_value, _plan_value, _decision, receipt, _claim = chain
    store, database, store_key, promotion_key = _new_authorization_store(
        lost_root,
        monotonic_checkpoint=lost_checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
    )
    lost_checkpoint.fail_next_advance = True
    with pytest.raises(FolderM4AuthorizationError, match="checkpoint advance failed"):
        store.issue(
            planning,
            prepared,
            approval_receipt_ref=receipt.receipt_ref,
            idempotency_digest=IDEMPOTENCY,
            promotion=_promotion(
                PersistentFolderM4PromotionAuthority(promotion_key),
                chain,
            ),
            now_epoch=ACTIVE,
        )
    assert lost_checkpoint.tail.sequence == 0
    with pytest.raises(FolderM4AuthorizationError, match="verification failed"):
        PersistentFolderM4AuthorizationStore(
            database,
            store_key,
            promotion_key,
            monotonic_checkpoint=lost_checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )

    ambiguous_root = tmp_path / "ambiguous"
    ambiguous_checkpoint = _ExternalAuthorizationCheckpoint()
    chain = _planning_chain(ambiguous_root)
    planning, prepared, _summary_value, _confirmation_value, _plan_value, _decision, receipt, _claim = chain
    store, database, store_key, promotion_key = _new_authorization_store(
        ambiguous_root,
        monotonic_checkpoint=ambiguous_checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
    )
    promotion_authority = PersistentFolderM4PromotionAuthority(promotion_key)
    ambiguous_checkpoint.advance_then_fail = True
    with pytest.raises(FolderM4AuthorizationError, match="checkpoint advance failed"):
        store.issue(
            planning,
            prepared,
            approval_receipt_ref=receipt.receipt_ref,
            idempotency_digest=IDEMPOTENCY,
            promotion=_promotion(promotion_authority, chain),
            now_epoch=ACTIVE,
        )
    assert ambiguous_checkpoint.tail.sequence == 1
    restarted = PersistentFolderM4AuthorizationStore(
        database,
        store_key,
        promotion_key,
        monotonic_checkpoint=ambiguous_checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
    )
    assert restarted.monotonic_checkpoint_protocol_bound is True
    assert restarted.resolve_execution_binding(
        "folder-m4-promotion-ref0001"
    ).plan.plan_ref == prepared.plan_ref
    with pytest.raises(FolderM4AuthorizationError, match="already"):
        restarted.issue(
            planning,
            prepared,
            approval_receipt_ref=receipt.receipt_ref,
            idempotency_digest=IDEMPOTENCY,
            promotion=_promotion(promotion_authority, chain),
            now_epoch=ACTIVE,
        )


def test_authorization_store_requires_three_independent_state_paths(
    tmp_path: Path,
) -> None:
    state = tmp_path / "independent-paths"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    shared = state / "shared-state"
    promotion_key = state / "promotion.hmac"
    _write_key(shared, b"folder-m4-store-key-000000000000000001")
    _write_key(promotion_key, b"folder-m4-promotion-key-0000000000001")

    with pytest.raises(FolderM4AuthorizationError, match="paths must be independent"):
        PersistentFolderM4AuthorizationStore(shared, shared, promotion_key)


def test_external_checkpoint_requires_complete_valid_binding(
    tmp_path: Path,
) -> None:
    state = tmp_path / "checkpoint-binding"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    database = state / "authorization.sqlite3"
    store_key = state / "store.hmac"
    promotion_key = state / "promotion.hmac"
    _write_key(store_key, b"folder-m4-store-key-000000000000000001")
    _write_key(promotion_key, b"folder-m4-promotion-key-0000000000001")
    checkpoint = _ExternalAuthorizationCheckpoint()

    with pytest.raises(FolderM4AuthorizationError, match="incomplete"):
        PersistentFolderM4AuthorizationStore(
            database,
            store_key,
            promotion_key,
            monotonic_checkpoint=checkpoint,
        )
    with pytest.raises(FolderM4AuthorizationError, match="incomplete"):
        PersistentFolderM4AuthorizationStore(
            database,
            store_key,
            promotion_key,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )
    with pytest.raises(FolderM4AuthorizationError, match="invalid"):
        PersistentFolderM4AuthorizationStore(
            database,
            store_key,
            promotion_key,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref="short",
        )
    checkpoint.authority_ref = "short"
    with pytest.raises(FolderM4AuthorizationError, match="invalid"):
        PersistentFolderM4AuthorizationStore(
            database,
            store_key,
            promotion_key,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )


def test_m3_chain_alone_cannot_promote_or_bind(tmp_path: Path) -> None:
    chain = _planning_chain(tmp_path)
    planning, prepared, _summary_value, _confirmation_value, _plan_value, _decision, receipt, _claim = chain
    store, _database, _store_key, _promotion_key = _new_authorization_store(tmp_path)

    with pytest.raises(FolderM4AuthorizationError, match="separate authenticated"):
        store.issue(
            planning,
            prepared,
            approval_receipt_ref=receipt.receipt_ref,
            idempotency_digest=IDEMPOTENCY,
            now_epoch=ACTIVE,
        )


def test_restart_resolve_and_one_time_authorization_are_fail_closed(tmp_path: Path) -> None:
    store, binding, database, store_key, promotion_key = _issue(tmp_path)
    restarted = PersistentFolderM4AuthorizationStore(
        database,
        store_key,
        promotion_key,
        clock=lambda: ACTIVE + 1,
    )
    assert ProtectedPreparedFolderActionResolver(restarted).resolve(binding.plan) == binding.prepared_action()
    verifier = ProtectedFolderM4AuthorizationVerifier(
        restarted,
        binding.plan.requester_digest,
    )
    verifier.verify(binding.plan, binding.authorization, now_epoch=ACTIVE + 1)

    second_restart = PersistentFolderM4AuthorizationStore(
        database,
        store_key,
        promotion_key,
        clock=lambda: ACTIVE + 2,
    )
    with pytest.raises(M4AuthorizationReplay):
        ProtectedFolderM4AuthorizationVerifier(
            second_restart,
            binding.plan.requester_digest,
        ).verify(binding.plan, binding.authorization, now_epoch=ACTIVE + 2)
    assert store.resolve(binding.plan) == binding.prepared_action()


def test_identity_expiry_plan_drift_and_promotion_tamper_are_denied(tmp_path: Path) -> None:
    store, binding, _database, _store_key, _promotion_key = _issue(tmp_path / "identity")
    with pytest.raises(FolderM4AuthorizationError, match="identity"):
        ProtectedFolderM4AuthorizationVerifier(store, "f" * 64).verify(
            binding.plan,
            binding.authorization,
            now_epoch=ACTIVE + 1,
        )
    changed_content = dict(binding.plan.canonical_content())
    changed_content["expected_current_digest"] = "e" * 64
    changed = replace(
        binding.plan,
        expected_current_digest="e" * 64,
        plan_digest=canonical_digest(changed_content),
    )
    with pytest.raises(FolderM4AuthorizationError, match="exact active"):
        ProtectedFolderM4AuthorizationVerifier(
            store,
            binding.plan.requester_digest,
        ).verify(changed, binding.authorization, now_epoch=ACTIVE + 1)
    with pytest.raises(FolderM4AuthorizationError, match="active"):
        ProtectedFolderM4AuthorizationVerifier(
            store,
            binding.plan.requester_digest,
        ).verify(binding.plan, binding.authorization, now_epoch=ACTIVE + 31)

    chain = _planning_chain(tmp_path / "promotion")
    planning, prepared, _summary_value, _confirmation_value, _plan_value, _decision, receipt, _claim = chain
    promotion_store, _db, _sk, promotion_key = _new_authorization_store(tmp_path / "promotion")
    tampered = replace(
        _promotion(PersistentFolderM4PromotionAuthority(promotion_key), chain),
        decision_mac="0" * 64,
    )
    with pytest.raises(FolderM4AuthorizationError, match="authenticity"):
        promotion_store.issue(
            planning,
            prepared,
            approval_receipt_ref=receipt.receipt_ref,
            idempotency_digest=IDEMPOTENCY,
            promotion=tampered,
            now_epoch=ACTIVE,
        )


def test_database_tamper_is_detected_on_restart(tmp_path: Path) -> None:
    _store, _binding, database, store_key, promotion_key = _issue(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE folder_m4_events SET payload_json = ? WHERE ordinal = 1",
            ('{"tampered":true}',),
        )
    with pytest.raises(FolderM4AuthorizationError, match="payload|digest|HMAC"):
        PersistentFolderM4AuthorizationStore(database, store_key, promotion_key)
