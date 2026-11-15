"""Closed orchestration boundary for the repository-only V4 M3 workflow."""

from __future__ import annotations

from collections.abc import Sequence

from .approval import (
    ApprovalReceipt,
    AuthenticatedApprover,
    M3ApprovalGate,
    PlanGateResult,
)
from .canonical import canonical_digest
from .engine import M2PlanningEngine
from .models import (
    AuthenticatedRequester,
    AuthoritativeProjection,
    ConfirmationRecord,
    FinalIntentSummary,
    PlanningContractError,
    PostWriteEvaluation,
    PreWriteEvaluation,
    PreWriteStatus,
    PreparedPlan,
    SchemeDraft,
    VerifiedConfirmationInteraction,
)
from .policy import M3PlanPolicy, PlanPolicyDecision
from .store import ProtectedPlanningStore, ProtectedStoreError


class WorkflowRecordUnavailable(PlanningContractError):
    """Raised when a caller references a record outside the active workflow."""


class M3PlanOnlyWorkflowService:
    """Bind planning, human confirmation, and approval without dispatch.

    Trusted transports must construct the authenticated requester, verified
    confirmation interaction, and authenticated approver. This service does
    not authenticate users, parse natural language, load C3 material, contact
    FortiPAM, expose MCP, or register a product adapter.
    """

    def __init__(
        self,
        planning_engine: M2PlanningEngine,
        store: ProtectedPlanningStore,
        policy: M3PlanPolicy,
        approval_gate: M3ApprovalGate,
    ) -> None:
        self._planning_engine = planning_engine
        self._store = store
        self._policy = policy
        self._approval_gate = approval_gate

    def compile_summary(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
        projections: Sequence[AuthoritativeProjection],
        *,
        now_epoch: int,
        prior_summary_ref: str | None = None,
    ) -> FinalIntentSummary:
        summary = self._planning_engine.compile_summary(
            draft,
            requester,
            projections,
            now_epoch=now_epoch,
            prior_summary_ref=prior_summary_ref,
        )
        self._store.put_summary(summary)
        return summary

    def confirm_intent(
        self,
        summary_ref: str,
        requester: AuthenticatedRequester,
        interaction: VerifiedConfirmationInteraction,
        *,
        now_epoch: int,
    ) -> ConfirmationRecord:
        summary = self._require_summary(summary_ref, interaction.summary_revision)
        existing = self._find_confirmation_for_summary(summary)
        if existing is not None:
            self._validate_confirmation_retry(summary, existing, requester, interaction, now_epoch)
            return existing
        self._recover_awaiting_summary(summary)
        try:
            record = self._planning_engine.confirm_intent(
                summary_ref,
                requester,
                interaction,
                now_epoch=now_epoch,
            )
            self._store.put_confirmation(record)
        except Exception:
            # The durable store remains authoritative.  A failed append must
            # not strand this process in a consumed-summary transient state.
            self._recover_awaiting_summary(summary)
            raise
        return record

    def prepare_plan(
        self,
        summary_ref: str,
        confirmation_ref: str,
        requester: AuthenticatedRequester,
        *,
        now_epoch: int,
    ) -> PreparedPlan:
        confirmation = self._require_confirmation(confirmation_ref)
        summary = self._require_summary(summary_ref, confirmation.summary_revision)
        self._validate_confirmation_chain(summary, confirmation, requester)
        existing = self._find_plan_for_confirmation(confirmation)
        if existing is not None:
            self._validate_plan_retry(
                summary,
                confirmation,
                existing,
                requester,
                now_epoch,
            )
            self._recover_prepared_chain(summary, confirmation, existing)
            return existing
        self._recover_confirmed_chain(summary, confirmation)
        try:
            plan = self._planning_engine.prepare_plan(
                summary_ref,
                confirmation_ref,
                requester,
                now_epoch=now_epoch,
            )
            self._store.put_plan(plan)
        except Exception:
            # See confirm_intent: recover exactly the durable chain before
            # surfacing an append or planner failure to the caller.
            self._recover_confirmed_chain(summary, confirmation)
            raise
        return plan

    def request_approval(
        self,
        plan_ref: str,
        requester: AuthenticatedRequester,
        *,
        now_epoch: int,
    ) -> PlanPolicyDecision:
        plan = self._require_plan(plan_ref)
        decision = self._policy.evaluate(plan, requester, now_epoch=now_epoch)
        self._store.put_policy_decision(decision)
        return decision

    def approve(
        self,
        decision_ref: str,
        approver: AuthenticatedApprover,
        *,
        requester: AuthenticatedRequester | None = None,
        now_epoch: int,
    ) -> ApprovalReceipt:
        try:
            decision = self._store.get_policy_decision(decision_ref)
        except ProtectedStoreError as exc:
            raise WorkflowRecordUnavailable("Policy decision is unavailable.") from exc
        plan = self._require_plan(decision.plan_ref)
        receipt = self._approval_gate.approve(
            decision,
            approver,
            now_epoch=now_epoch,
            plan=plan,
            requester=requester,
        )
        self._store.put_approval_receipt(receipt)
        return receipt

    def claim_approval(
        self,
        receipt_ref: str,
        plan_ref: str,
        requester: AuthenticatedRequester,
    ) -> PlanGateResult:
        try:
            claim = self._store.claim_approval(
                receipt_ref,
                plan_ref,
                requester.digest,
            )
        except ProtectedStoreError as exc:
            raise WorkflowRecordUnavailable(
                "Approval receipt claim is unavailable."
            ) from exc
        return PlanGateResult(
            plan_ref=claim.plan_ref,
            plan_digest=claim.plan_digest,
            approval_validated=True,
            ready_for_dispatch=False,
            execution_authorized=False,
            blocker_codes=("adapter_registry_unbound", "plan_non_dispatchable"),
        )

    def evaluate_pre_write(
        self,
        plan_ref: str,
        projections: Sequence[AuthoritativeProjection],
        *,
        now_epoch: int,
    ) -> PreWriteEvaluation:
        """Compare one trusted reread without dispatching a product action."""

        self._require_plan(plan_ref)
        result = self._planning_engine.evaluate_pre_write(
            plan_ref,
            projections,
            now_epoch=now_epoch,
        )
        if result.status is not PreWriteStatus.MATCH:
            self._store.invalidate_plan(
                plan_ref,
                evaluated_at=result.evaluated_at,
                reason_codes=result.reason_codes,
            )
        return result

    def evaluate_post_write(
        self,
        plan_ref: str,
        projections: Sequence[AuthoritativeProjection],
        *,
        now_epoch: int,
    ) -> PostWriteEvaluation:
        """Compare one trusted readback without asserting that a write occurred."""

        self._require_plan(plan_ref)
        return self._planning_engine.evaluate_post_write(
            plan_ref,
            projections,
            now_epoch=now_epoch,
        )

    def resolve_prepared_plan(
        self,
        plan_ref: str,
        requester: AuthenticatedRequester,
        *,
        now_epoch: int,
    ) -> PreparedPlan:
        """Resolve one active protected plan for an internal action binder."""

        plan = self._require_plan(plan_ref)
        summary = self._require_summary(plan.summary_ref, plan.summary_revision)
        confirmation = self._require_confirmation(plan.confirmation_ref)
        self._validate_plan_retry(summary, confirmation, plan, requester, now_epoch)
        self._recover_prepared_chain(summary, confirmation, plan)
        return plan

    def _require_summary(self, summary_ref: str, revision: int) -> FinalIntentSummary:
        try:
            return self._store.get_summary(summary_ref, revision)
        except ProtectedStoreError as exc:
            raise WorkflowRecordUnavailable("Final Intent Summary is unavailable.") from exc

    def _require_confirmation(self, confirmation_ref: str) -> ConfirmationRecord:
        try:
            return self._store.get_confirmation(confirmation_ref)
        except ProtectedStoreError as exc:
            raise WorkflowRecordUnavailable("Confirmation record is unavailable.") from exc

    def _find_confirmation_for_summary(
        self,
        summary: FinalIntentSummary,
    ) -> ConfirmationRecord | None:
        try:
            return self._store.find_confirmation_for_summary(
                summary.summary_ref,
                summary.revision,
            )
        except ProtectedStoreError as exc:
            raise WorkflowRecordUnavailable("Confirmation record is unavailable.") from exc

    def _find_plan_for_confirmation(
        self,
        confirmation: ConfirmationRecord,
    ) -> PreparedPlan | None:
        try:
            return self._store.find_plan_for_confirmation(confirmation.confirmation_ref)
        except ProtectedStoreError as exc:
            raise WorkflowRecordUnavailable("Prepared plan is unavailable.") from exc

    @staticmethod
    def _validate_confirmation_chain(
        summary: FinalIntentSummary,
        confirmation: ConfirmationRecord,
        requester: AuthenticatedRequester,
    ) -> None:
        if (
            confirmation.requester_digest != requester.digest
            or requester.digest != summary.requester_digest
            or confirmation.audience_ref != summary.audience_ref
            or confirmation.summary_ref != summary.summary_ref
            or confirmation.summary_revision != summary.revision
            or confirmation.summary_digest != summary.summary_digest
        ):
            raise WorkflowRecordUnavailable("Confirmation record is not bound to the summary.")

    def _validate_confirmation_retry(
        self,
        summary: FinalIntentSummary,
        confirmation: ConfirmationRecord,
        requester: AuthenticatedRequester,
        interaction: VerifiedConfirmationInteraction,
        now_epoch: int,
    ) -> None:
        self._validate_confirmation_chain(summary, confirmation, requester)
        if (
            now_epoch < summary.created_at
            or now_epoch >= summary.expires_at
            or now_epoch < confirmation.confirmed_at
            or now_epoch >= confirmation.expires_at
            or interaction.decision != "affirm"
            or interaction.requester_digest != requester.digest
            or interaction.audience_ref != summary.audience_ref
            or interaction.summary_ref != summary.summary_ref
            or interaction.summary_revision != summary.revision
            or interaction.summary_digest != summary.summary_digest
            or interaction.interaction_type != confirmation.interaction_type
            or interaction.nonce_digest != confirmation.nonce_digest
            or canonical_digest(interaction.interaction_ref)
            != confirmation.interaction_ref_digest
            or interaction.confirmed_at != confirmation.confirmed_at
            or interaction.expires_at != confirmation.expires_at
            or interaction.confirmed_at < summary.created_at
            or interaction.confirmed_at > now_epoch
            or interaction.expires_at <= now_epoch
        ):
            raise WorkflowRecordUnavailable("Confirmation retry is not bound to the summary.")

    @staticmethod
    def _validate_plan_retry(
        summary: FinalIntentSummary,
        confirmation: ConfirmationRecord,
        plan: PreparedPlan,
        requester: AuthenticatedRequester,
        now_epoch: int,
    ) -> None:
        if (
            now_epoch < summary.created_at
            or now_epoch >= summary.expires_at
            or now_epoch < confirmation.confirmed_at
            or now_epoch >= confirmation.expires_at
            or now_epoch < plan.created_at
            or now_epoch >= plan.expires_at
            or plan.requester_digest != requester.digest
            or plan.summary_ref != summary.summary_ref
            or plan.summary_revision != summary.revision
            or plan.summary_digest != summary.summary_digest
            or plan.confirmation_ref != confirmation.confirmation_ref
            or plan.confirmation_digest != confirmation.record_digest
            or plan.dispatchable
        ):
            raise WorkflowRecordUnavailable("Prepared plan is not bound to the confirmation.")

    def _recover_awaiting_summary(self, summary: FinalIntentSummary) -> None:
        self._planning_engine.recover_awaiting_summary(summary)

    def _recover_confirmed_chain(
        self,
        summary: FinalIntentSummary,
        confirmation: ConfirmationRecord,
    ) -> None:
        self._planning_engine.recover_confirmed_chain(summary, confirmation)

    def _recover_prepared_chain(
        self,
        summary: FinalIntentSummary,
        confirmation: ConfirmationRecord,
        plan: PreparedPlan,
    ) -> None:
        self._planning_engine.recover_prepared_chain(summary, confirmation, plan)

    def _require_plan(self, plan_ref: str) -> PreparedPlan:
        try:
            return self._store.get_plan(plan_ref)
        except ProtectedStoreError as exc:
            raise WorkflowRecordUnavailable("Prepared plan is unavailable.") from exc


__all__ = ["M3PlanOnlyWorkflowService", "WorkflowRecordUnavailable"]
