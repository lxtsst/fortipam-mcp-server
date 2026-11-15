"""Restart and idempotency coverage for the V4 plan-only record chain."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

from test_v4_planning import (
    Authorizer,
    Issuer,
    NOW,
    _access_draft,
    _absent_projections,
    _interaction,
    _promoted_registry,
    _requester,
)
from v4_planning import M2PlanningEngine, M3PlanOnlyWorkflowService, canonical_digest
from v4_planning.approval import M3ApprovalGate
from v4_planning.persistence import PersistentProtectedPlanningStore
from v4_planning.policy import M3PlanPolicy
from v4_planning.store import InMemoryProtectedPlanningStore, ProtectedStoreError
from v4_planning.workflow_service import WorkflowRecordUnavailable


def _persistent_store(root: Path) -> PersistentProtectedPlanningStore:
    state = root / "state"
    state.mkdir(mode=0o700, parents=True)
    os.chmod(state, 0o700)
    key = state / "planning.hmac"
    key.write_bytes(b"v4-planning-recovery-test-key-00000000000000000001")
    os.chmod(key, 0o600)
    return PersistentProtectedPlanningStore(
        state / "planning.sqlite3",
        key,
        clock=lambda: NOW + 10,
    )


def _service(
    store: InMemoryProtectedPlanningStore | PersistentProtectedPlanningStore,
) -> M3PlanOnlyWorkflowService:
    draft = _access_draft()
    issuer = Issuer()
    return M3PlanOnlyWorkflowService(
        M2PlanningEngine(_promoted_registry(), issuer, Authorizer((draft,))),
        store,
        M3PlanPolicy(issuer),
        M3ApprovalGate(issuer),
    )


def test_hmac_verified_summary_survives_restart_then_confirms_and_prepares(
    tmp_path: Path,
) -> None:
    draft = _access_draft()
    requester = _requester()
    store = _persistent_store(tmp_path)
    first = _service(store)
    projections = _absent_projections(first._planning_engine, draft)  # noqa: SLF001
    summary = first.compile_summary(draft, requester, projections, now_epoch=NOW)

    restarted_before_confirmation = _service(
        PersistentProtectedPlanningStore(
            store._path,  # noqa: SLF001 - exact restart path is the test subject
            store._key_path,  # noqa: SLF001
            clock=lambda: NOW + 10,
        )
    )
    interaction = _interaction(summary, requester)
    confirmation = restarted_before_confirmation.confirm_intent(
        summary.summary_ref,
        requester,
        interaction,
        now_epoch=NOW + 1,
    )

    restarted_before_plan = _service(
        PersistentProtectedPlanningStore(
            store._path,  # noqa: SLF001
            store._key_path,  # noqa: SLF001
            clock=lambda: NOW + 10,
        )
    )
    plan = restarted_before_plan.prepare_plan(
        summary.summary_ref,
        confirmation.confirmation_ref,
        requester,
        now_epoch=NOW + 2,
    )

    assert plan.confirmation_ref == confirmation.confirmation_ref
    assert plan.dispatchable is False
    assert plan.executor_runtime_packaged is False
    # A second process restart reads the exact persisted plan rather than
    # issuing another one, while also restoring the engine's record chain.
    restarted_after_plan = _service(
        PersistentProtectedPlanningStore(
            store._path,  # noqa: SLF001
            store._key_path,  # noqa: SLF001
            clock=lambda: NOW + 10,
        )
    )
    assert (
        restarted_after_plan.prepare_plan(
            summary.summary_ref,
            confirmation.confirmation_ref,
            requester,
            now_epoch=NOW + 2,
        )
        == plan
    )


def test_same_bound_confirmation_and_plan_retry_return_exact_records() -> None:
    draft = _access_draft()
    requester = _requester()
    service = _service(InMemoryProtectedPlanningStore(clock=lambda: NOW + 10))
    projections = _absent_projections(service._planning_engine, draft)  # noqa: SLF001
    summary = service.compile_summary(draft, requester, projections, now_epoch=NOW)
    interaction = _interaction(summary, requester)
    confirmation = service.confirm_intent(
        summary.summary_ref,
        requester,
        interaction,
        now_epoch=NOW + 1,
    )
    assert (
        service.confirm_intent(
            summary.summary_ref,
            requester,
            interaction,
            now_epoch=NOW + 1,
        )
        == confirmation
    )

    plan = service.prepare_plan(
        summary.summary_ref,
        confirmation.confirmation_ref,
        requester,
        now_epoch=NOW + 2,
    )
    assert (
        service.prepare_plan(
            summary.summary_ref,
            confirmation.confirmation_ref,
            requester,
            now_epoch=NOW + 2,
        )
        == plan
    )
    assert plan.dispatchable is False


def test_confirmation_retry_rejects_any_interaction_binding_mismatch_or_expiry() -> None:
    draft = _access_draft()
    requester = _requester()
    service = _service(InMemoryProtectedPlanningStore(clock=lambda: NOW + 10))
    projections = _absent_projections(service._planning_engine, draft)  # noqa: SLF001
    summary = service.compile_summary(draft, requester, projections, now_epoch=NOW)
    interaction = _interaction(summary, requester)
    service.confirm_intent(
        summary.summary_ref,
        requester,
        interaction,
        now_epoch=NOW + 1,
    )

    for tampered in (
        replace(interaction, nonce_digest=canonical_digest("other-nonce")),
        replace(interaction, interaction_ref="other-interaction-ref01"),
        replace(interaction, confirmed_at=NOW + 2),
        replace(interaction, expires_at=NOW + 199),
    ):
        with pytest.raises(WorkflowRecordUnavailable, match="not bound"):
            service.confirm_intent(
                summary.summary_ref,
                requester,
                tampered,
                now_epoch=NOW + 2,
            )

    tampered_type = _interaction(summary, requester)
    object.__setattr__(tampered_type, "interaction_type", "tampered_interaction_type")
    with pytest.raises(WorkflowRecordUnavailable, match="not bound"):
        service.confirm_intent(
            summary.summary_ref,
            requester,
            tampered_type,
            now_epoch=NOW + 2,
        )
    with pytest.raises(WorkflowRecordUnavailable, match="not bound"):
        service.confirm_intent(
            summary.summary_ref,
            requester,
            interaction,
            now_epoch=summary.expires_at,
        )
    with pytest.raises(WorkflowRecordUnavailable, match="not bound"):
        service.confirm_intent(
            summary.summary_ref,
            requester,
            interaction,
            now_epoch=summary.created_at - 1,
        )


def test_plan_retry_rejects_expired_or_time_reversed_record_chain() -> None:
    draft = _access_draft()
    requester = _requester()
    service = _service(InMemoryProtectedPlanningStore(clock=lambda: NOW + 10))
    projections = _absent_projections(service._planning_engine, draft)  # noqa: SLF001
    summary = service.compile_summary(draft, requester, projections, now_epoch=NOW)
    confirmation = service.confirm_intent(
        summary.summary_ref,
        requester,
        _interaction(summary, requester),
        now_epoch=NOW + 1,
    )
    plan = service.prepare_plan(
        summary.summary_ref,
        confirmation.confirmation_ref,
        requester,
        now_epoch=NOW + 2,
    )

    with pytest.raises(WorkflowRecordUnavailable, match="not bound"):
        service.prepare_plan(
            summary.summary_ref,
            confirmation.confirmation_ref,
            requester,
            now_epoch=plan.expires_at,
        )
    with pytest.raises(WorkflowRecordUnavailable, match="not bound"):
        service.prepare_plan(
            summary.summary_ref,
            confirmation.confirmation_ref,
            requester,
            now_epoch=summary.created_at - 1,
        )


class _FailOnceStore(InMemoryProtectedPlanningStore):
    def __init__(self) -> None:
        super().__init__(clock=lambda: NOW + 10)
        self.fail_confirmation = True
        self.fail_plan = True

    def put_confirmation(self, record):  # type: ignore[no-untyped-def]
        if self.fail_confirmation:
            self.fail_confirmation = False
            raise ProtectedStoreError("injected confirmation persistence failure")
        super().put_confirmation(record)

    def put_plan(self, plan):  # type: ignore[no-untyped-def]
        if self.fail_plan:
            self.fail_plan = False
            raise ProtectedStoreError("injected plan persistence failure")
        super().put_plan(plan)


def test_persistence_failure_does_not_strand_engine_in_consumed_transient_state() -> None:
    draft = _access_draft()
    requester = _requester()
    store = _FailOnceStore()
    service = _service(store)
    projections = _absent_projections(service._planning_engine, draft)  # noqa: SLF001
    summary = service.compile_summary(draft, requester, projections, now_epoch=NOW)
    interaction = _interaction(summary, requester)

    with pytest.raises(ProtectedStoreError, match="injected confirmation"):
        service.confirm_intent(
            summary.summary_ref,
            requester,
            interaction,
            now_epoch=NOW + 1,
        )
    confirmation = service.confirm_intent(
        summary.summary_ref,
        requester,
        interaction,
        now_epoch=NOW + 1,
    )

    with pytest.raises(ProtectedStoreError, match="injected plan"):
        service.prepare_plan(
            summary.summary_ref,
            confirmation.confirmation_ref,
            requester,
            now_epoch=NOW + 2,
        )
    plan = service.prepare_plan(
        summary.summary_ref,
        confirmation.confirmation_ref,
        requester,
        now_epoch=NOW + 2,
    )
    assert plan.dispatchable is False
