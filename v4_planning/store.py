"""Protected-store protocol and in-memory V4 plan-only reference store.

The implementation is deliberately in-memory and process-local.  It exposes no
serialization, filesystem, network, MCP, or product adapter surface.  A future
persistent implementation must preserve the same exact binding checks.
"""

from __future__ import annotations

from dataclasses import dataclass
import time
from collections.abc import Callable
from typing import Protocol

from .approval import ApprovalReceipt, ApprovalReceiptAuthenticationAuthority
from .canonical import CanonicalValue
from .models import ConfirmationRecord, FinalIntentSummary, PreparedPlan, require_digest, require_ref
from .policy import PlanPolicyDecision


class ProtectedStoreError(ValueError):
    """Raised when an immutable planning record cannot be stored safely."""


@dataclass(frozen=True, slots=True, repr=False)
class OriginalImportBindingRecord:
    """Private C2 parent commitments, never material or execution authority."""

    plan_ref: str
    plan_digest: str
    requester_digest: str
    parent_idempotency_digest: str
    input_commitment: str
    source_commitment: str
    dependency_commitment: str
    namespace_key_digest: str
    row_count: int

    def __post_init__(self) -> None:
        try:
            require_ref(self.plan_ref, "Original import parent")
            for name in ("plan_digest", "requester_digest", "parent_idempotency_digest",
                         "input_commitment", "source_commitment", "dependency_commitment",
                         "namespace_key_digest"):
                require_digest(getattr(self, name), name)
            if type(self.row_count) is not int or not 1 <= self.row_count <= 256:
                raise ValueError
        except Exception:
            raise ProtectedStoreError("Original import binding is invalid.") from None

    def as_dict(self) -> dict[str, CanonicalValue]:
        return {"plan_ref": self.plan_ref, "plan_digest": self.plan_digest,
                "requester_digest": self.requester_digest,
                "parent_idempotency_digest": self.parent_idempotency_digest,
                "input_commitment": self.input_commitment,
                "source_commitment": self.source_commitment,
                "dependency_commitment": self.dependency_commitment,
                "namespace_key_digest": self.namespace_key_digest,
                "row_count": self.row_count}


@dataclass(frozen=True, slots=True, repr=False)
class OriginalImportRowAckRecord:
    """Private original-response evidence, never ownership or dispatch authority."""

    plan_ref: str
    parent_binding_digest: str
    requester_digest: str
    row_index: int
    idempotency_digest: str
    parameters_digest: str
    child_plan_digest: str
    child_revision: int
    authorization_digest: str
    context_digest: str
    serial_digest: str
    defaults_digest: str
    ack_source_digest: str
    acknowledgement_digest: str
    native_secret_id: int

    def __post_init__(self) -> None:
        try:
            require_ref(self.plan_ref, "Original import parent")
            for name in ("parent_binding_digest", "requester_digest", "idempotency_digest",
                         "parameters_digest", "child_plan_digest", "authorization_digest",
                         "context_digest", "serial_digest", "defaults_digest",
                         "ack_source_digest", "acknowledgement_digest"):
                require_digest(getattr(self, name), name)
            if (type(self.row_index) is not int or not 0 <= self.row_index < 256
                    or type(self.child_revision) is not int or not 1 <= self.child_revision < 2**31
                    or type(self.native_secret_id) is not int or not 1 <= self.native_secret_id < 2**31):
                raise ValueError
        except Exception:
            raise ProtectedStoreError("Original import ACK evidence is invalid.") from None

    def as_dict(self) -> dict[str, CanonicalValue]:
        return {"plan_ref": self.plan_ref, "parent_binding_digest": self.parent_binding_digest,
                "requester_digest": self.requester_digest, "row_index": self.row_index,
                "idempotency_digest": self.idempotency_digest, "parameters_digest": self.parameters_digest,
                "child_plan_digest": self.child_plan_digest, "child_revision": self.child_revision,
                "authorization_digest": self.authorization_digest, "context_digest": self.context_digest,
                "serial_digest": self.serial_digest, "defaults_digest": self.defaults_digest,
                "ack_source_digest": self.ack_source_digest,
                "acknowledgement_digest": self.acknowledgement_digest,
                "native_secret_id": self.native_secret_id}


@dataclass(frozen=True, slots=True)
class PlanInvalidationRecord:
    """Append-only refusal bound to one immutable prepared parent plan."""

    plan_ref: str
    plan_digest: str
    evaluated_at: int
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        try:
            require_ref(self.plan_ref, "Invalidated plan reference")
            require_digest(self.plan_digest, "Invalidated plan digest")
            if (type(self.evaluated_at) is not int or not 0 <= self.evaluated_at < 2**31 - 1
                or type(self.reason_codes) is not tuple
                or any(type(code) is not str for code in self.reason_codes)
                or self.reason_codes not in {
                    ("current_state_drift",), ("current_state_unavailable_or_unsafe",),
                }):
                raise ValueError
        except Exception:
            raise ProtectedStoreError("Plan invalidation record is invalid.") from None

    def as_dict(self) -> dict[str, CanonicalValue]:
        return {"plan_ref": self.plan_ref, "plan_digest": self.plan_digest,
                "evaluated_at": self.evaluated_at, "reason_codes": list(self.reason_codes)}


@dataclass(frozen=True, slots=True)
class ApprovalClaimRecord:
    """Non-dispatching evidence that one approval receipt was consumed."""

    receipt_ref: str
    receipt_digest: str
    plan_ref: str
    plan_digest: str
    requester_digest: str
    claimed_at: int
    execution_authorized: bool = False

    def as_dict(self) -> dict[str, CanonicalValue]:
        return {
            "claimed_at": self.claimed_at,
            "execution_authorized": self.execution_authorized,
            "plan_digest": self.plan_digest,
            "plan_ref": self.plan_ref,
            "receipt_digest": self.receipt_digest,
            "receipt_ref": self.receipt_ref,
            "requester_digest": self.requester_digest,
        }

    def __post_init__(self) -> None:
        if self.execution_authorized is not False or type(self.claimed_at) is not int:
            raise ProtectedStoreError("Approval claim widened execution authority.")


class ProtectedPlanningStore(Protocol):
    """Exact append-only record-chain boundary required by the workflow service."""

    def put_summary(self, summary: FinalIntentSummary) -> None: ...
    def put_confirmation(self, record: ConfirmationRecord) -> None: ...
    def put_plan(self, plan: PreparedPlan) -> None: ...
    def invalidate_plan(self, plan_ref: str, *, evaluated_at: int,
                        reason_codes: tuple[str, ...]) -> None: ...
    def put_policy_decision(self, decision: PlanPolicyDecision) -> None: ...
    def put_approval_receipt(self, receipt: ApprovalReceipt) -> None: ...
    def get_summary(self, summary_ref: str, revision: int) -> FinalIntentSummary: ...
    def get_confirmation(self, confirmation_ref: str) -> ConfirmationRecord: ...
    def find_confirmation_for_summary(
        self,
        summary_ref: str,
        revision: int,
    ) -> ConfirmationRecord | None: ...
    def get_plan(self, plan_ref: str) -> PreparedPlan: ...
    def find_plan_for_confirmation(self, confirmation_ref: str) -> PreparedPlan | None: ...
    def get_policy_decision(self, decision_ref: str) -> PlanPolicyDecision: ...
    def get_approval_receipt(self, receipt_ref: str) -> ApprovalReceipt: ...
    def claim_approval(
        self,
        receipt_ref: str,
        plan_ref: str,
        requester_digest: str,
    ) -> ApprovalClaimRecord: ...


class InMemoryProtectedPlanningStore:
    """Append-only M3 record store with exact digest and revision bindings."""

    def __init__(
        self,
        *,
        clock: Callable[[], int] | None = None,
        approval_receipt_authenticator: (
            ApprovalReceiptAuthenticationAuthority | None
        ) = None,
    ) -> None:
        self._summaries: dict[tuple[str, int], FinalIntentSummary] = {}
        self._confirmations: dict[str, ConfirmationRecord] = {}
        self._plans: dict[str, PreparedPlan] = {}
        self._invalidations: dict[str, PlanInvalidationRecord] = {}
        self._decisions: dict[str, PlanPolicyDecision] = {}
        self._receipts: dict[str, ApprovalReceipt] = {}
        self._claims: dict[str, ApprovalClaimRecord] = {}
        self._clock = clock or (lambda: int(time.time()))
        self._approval_receipt_authenticator = approval_receipt_authenticator

    def put_summary(self, summary: FinalIntentSummary) -> None:
        key = (summary.summary_ref, summary.revision)
        existing = self._summaries.get(key)
        if existing is not None:
            if existing != summary:
                raise ProtectedStoreError("Summary revision is immutable.")
            return
        if summary.revision > 1 and (summary.summary_ref, summary.revision - 1) not in self._summaries:
            raise ProtectedStoreError("Summary revision history is incomplete.")
        if any(
            ref == summary.summary_ref and revision > summary.revision
            for ref, revision in self._summaries
        ):
            raise ProtectedStoreError("Summary revision cannot move backwards.")
        self._summaries[key] = summary

    def put_confirmation(self, record: ConfirmationRecord) -> None:
        summary = self._summaries.get((record.summary_ref, record.summary_revision))
        if summary is None:
            raise ProtectedStoreError("Confirmation requires the exact stored summary revision.")
        if (
            record.summary_digest != summary.summary_digest
            or record.requester_digest != summary.requester_digest
            or record.audience_ref != summary.audience_ref
            or record.confirmed_at < summary.created_at
            or record.expires_at > summary.expires_at
        ):
            raise ProtectedStoreError("Confirmation is not bound to the stored summary.")
        existing = self._confirmations.get(record.confirmation_ref)
        if existing is not None and existing != record:
            raise ProtectedStoreError("Confirmation record is immutable.")
        prior = self.find_confirmation_for_summary(
            record.summary_ref,
            record.summary_revision,
        )
        if prior is not None and prior != record:
            raise ProtectedStoreError("Summary revision already produced a confirmation.")
        self._confirmations[record.confirmation_ref] = record

    def put_plan(self, plan: PreparedPlan) -> None:
        summary = self._summaries.get((plan.summary_ref, plan.summary_revision))
        confirmation = self._confirmations.get(plan.confirmation_ref)
        if summary is None or confirmation is None:
            raise ProtectedStoreError("Plan requires its exact summary and confirmation records.")
        if (
            plan.summary_digest != summary.summary_digest
            or plan.confirmation_digest != confirmation.record_digest
            or plan.requester_digest != summary.requester_digest
            or plan.requester_digest != confirmation.requester_digest
            or plan.created_at < confirmation.confirmed_at
            or plan.expires_at > confirmation.expires_at
            or plan.environment_ref != summary.environment_ref
            or plan.scope_ref != summary.scope_ref
        ):
            raise ProtectedStoreError("Plan is not bound to the stored record chain.")
        existing = self._plans.get(plan.plan_ref)
        if existing is not None and existing != plan:
            raise ProtectedStoreError("Prepared plan is immutable.")
        prior = self.find_plan_for_confirmation(plan.confirmation_ref)
        if prior is not None and prior != plan:
            raise ProtectedStoreError("Confirmation already produced a prepared plan.")
        self._plans[plan.plan_ref] = plan

    def get_summary(self, summary_ref: str, revision: int) -> FinalIntentSummary:
        try:
            return self._summaries[(summary_ref, revision)]
        except KeyError as exc:
            raise ProtectedStoreError("Summary revision is unavailable.") from exc

    def get_confirmation(self, confirmation_ref: str) -> ConfirmationRecord:
        try:
            return self._confirmations[confirmation_ref]
        except KeyError as exc:
            raise ProtectedStoreError("Confirmation record is unavailable.") from exc

    def find_confirmation_for_summary(
        self,
        summary_ref: str,
        revision: int,
    ) -> ConfirmationRecord | None:
        records = [
            record
            for record in self._confirmations.values()
            if record.summary_ref == summary_ref and record.summary_revision == revision
        ]
        if len(records) > 1:
            raise ProtectedStoreError("Summary revision has multiple confirmations.")
        return records[0] if records else None

    def get_plan(self, plan_ref: str) -> PreparedPlan:
        if plan_ref in self._invalidations:
            raise ProtectedStoreError("Prepared plan was invalidated.")
        try:
            return self._plans[plan_ref]
        except KeyError as exc:
            raise ProtectedStoreError("Prepared plan is unavailable.") from exc

    def find_plan_for_confirmation(self, confirmation_ref: str) -> PreparedPlan | None:
        records = [
            plan
            for plan in self._plans.values()
            if plan.confirmation_ref == confirmation_ref
        ]
        if len(records) > 1:
            raise ProtectedStoreError("Confirmation has multiple prepared plans.")
        return self.get_plan(records[0].plan_ref) if records else None

    def invalidate_plan(self, plan_ref: str, *, evaluated_at: int,
                        reason_codes: tuple[str, ...]) -> None:
        try:
            require_ref(plan_ref, "Invalidated plan reference")
        except Exception:
            raise ProtectedStoreError("Plan invalidation reference is invalid.") from None
        plan = self._plans.get(plan_ref)
        if plan is None:
            raise ProtectedStoreError("Prepared plan is unavailable.")
        record = PlanInvalidationRecord(plan_ref, plan.plan_digest, evaluated_at, reason_codes)
        if evaluated_at < plan.created_at:
            raise ProtectedStoreError("Plan invalidation predates its parent plan.")
        prior = self._invalidations.get(plan_ref)
        if prior is not None and prior != record:
            raise ProtectedStoreError("Plan invalidation record is immutable.")
        self._invalidations[plan_ref] = record

    def put_policy_decision(self, decision: PlanPolicyDecision) -> None:
        plan = self.get_plan(decision.plan_ref)
        if plan is None or (
            decision.plan_digest != plan.plan_digest
            or decision.requester_digest != plan.requester_digest
            or decision.issued_at < plan.created_at
            or decision.expires_at > plan.expires_at
        ):
            raise ProtectedStoreError(
                "Policy decision is not bound to the stored prepared plan."
            )
        if any(item.plan_ref == decision.plan_ref for item in self._decisions.values()):
            existing = self._decisions.get(decision.decision_ref)
            if existing == decision:
                return
            raise ProtectedStoreError("Prepared plan already produced a policy decision.")
        self._decisions[decision.decision_ref] = decision

    def get_policy_decision(self, decision_ref: str) -> PlanPolicyDecision:
        try:
            decision = self._decisions[decision_ref]
        except KeyError as exc:
            raise ProtectedStoreError("Policy decision is unavailable.") from exc
        self.get_plan(decision.plan_ref)
        return decision

    def put_approval_receipt(self, receipt: ApprovalReceipt) -> None:
        self.get_plan(receipt.plan_ref)
        self._verify_approval_receipt_authenticity(receipt)
        decision = self._decisions.get(receipt.decision_ref)
        if decision is None or (
            receipt.decision_digest != decision.decision_digest
            or receipt.plan_ref != decision.plan_ref
            or receipt.plan_digest != decision.plan_digest
            or receipt.requester_digest != decision.requester_digest
            or (
                receipt.policy_version is not None
                and receipt.policy_version != decision.policy_version
            )
            or receipt.issued_at < decision.issued_at
            or receipt.expires_at > decision.expires_at
        ):
            raise ProtectedStoreError(
                "Approval receipt is not bound to the stored policy decision."
            )
        if any(
            item.decision_ref == receipt.decision_ref for item in self._receipts.values()
        ):
            existing = self._receipts.get(receipt.receipt_ref)
            if existing == receipt:
                return
            raise ProtectedStoreError(
                "Policy decision already produced an approval receipt."
            )
        self._receipts[receipt.receipt_ref] = receipt

    def get_approval_receipt(self, receipt_ref: str) -> ApprovalReceipt:
        try:
            receipt = self._receipts[receipt_ref]
        except KeyError as exc:
            raise ProtectedStoreError("Approval receipt is unavailable.") from exc
        self.get_plan(receipt.plan_ref)
        return receipt

    def claim_approval(
        self,
        receipt_ref: str,
        plan_ref: str,
        requester_digest: str,
    ) -> ApprovalClaimRecord:
        now_epoch = self._clock()
        if type(now_epoch) is not int:
            raise ProtectedStoreError("Trusted approval-claim clock is invalid.")
        receipt = self._receipts.get(receipt_ref)
        plan = self.get_plan(plan_ref)
        if receipt is None or plan is None:
            raise ProtectedStoreError(
                "Approval receipt or prepared plan is unavailable."
            )
        self._verify_approval_receipt_authenticity(receipt)
        if receipt_ref in self._claims:
            raise ProtectedStoreError("Approval receipt was replayed.")
        if (
            now_epoch < receipt.issued_at
            or now_epoch >= receipt.expires_at
            or now_epoch < plan.created_at
            or now_epoch >= plan.expires_at
        ):
            raise ProtectedStoreError(
                "Approval receipt or prepared plan is outside its active lifetime."
            )
        if (
            receipt.plan_ref != plan.plan_ref
            or receipt.plan_digest != plan.plan_digest
            or receipt.requester_digest != requester_digest
            or plan.requester_digest != requester_digest
        ):
            raise ProtectedStoreError(
                "Approval receipt is not bound to the exact prepared plan."
            )
        claim = ApprovalClaimRecord(
            receipt_ref=receipt.receipt_ref,
            receipt_digest=receipt.receipt_digest,
            plan_ref=plan.plan_ref,
            plan_digest=plan.plan_digest,
            requester_digest=requester_digest,
            claimed_at=now_epoch,
        )
        self._claims[receipt_ref] = claim
        return claim

    def _verify_approval_receipt_authenticity(
        self,
        receipt: ApprovalReceipt,
    ) -> None:
        authenticator = self._approval_receipt_authenticator
        if authenticator is None:
            if receipt.authenticator_ref is not None:
                raise ProtectedStoreError(
                    "Approval receipt authenticator is unavailable."
                )
            return
        if not authenticator.verify(receipt):
            raise ProtectedStoreError("Approval receipt authenticity is invalid.")


__all__ = [
    "ApprovalClaimRecord",
    "InMemoryProtectedPlanningStore",
    "ProtectedPlanningStore",
    "ProtectedStoreError",
]
