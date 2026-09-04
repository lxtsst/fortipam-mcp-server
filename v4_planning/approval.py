"""Requester/approver separation and one-time receipt for V4 M3."""

from __future__ import annotations

from dataclasses import dataclass

from .canonical import CanonicalValue, canonical_digest
from .engine import ReferenceIssuer
from .models import (
    AuthenticatedRequester,
    PreparedPlan,
    PlanningContractError,
    require_digest,
    require_ref,
)
from .policy import PlanPolicyDecision


class ApprovalDenied(PlanningContractError):
    """Raised when the M3 approval gate fails closed."""


@dataclass(frozen=True, slots=True)
class AuthenticatedApprover:
    subject_ref: str
    principal_class: str = "approver"

    def __post_init__(self) -> None:
        require_ref(self.subject_ref, "approver subject_ref")
        if self.principal_class != "approver":
            raise PlanningContractError("M3 approval requires an authenticated approver.")

    @property
    def digest(self) -> str:
        return canonical_digest(
            {"principal_class": self.principal_class, "subject_ref": self.subject_ref}
        )


@dataclass(frozen=True, slots=True)
class ApprovalReceipt:
    receipt_ref: str
    decision_ref: str
    decision_digest: str
    plan_ref: str
    plan_digest: str
    requester_digest: str
    approver_digest: str
    issued_at: int
    expires_at: int
    one_time: bool
    execution_authorized: bool
    receipt_digest: str

    def canonical_content(self) -> dict[str, CanonicalValue]:
        return {
            "approver_digest": self.approver_digest,
            "decision_digest": self.decision_digest,
            "decision_ref": self.decision_ref,
            "execution_authorized": self.execution_authorized,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "one_time": self.one_time,
            "plan_digest": self.plan_digest,
            "plan_ref": self.plan_ref,
            "receipt_ref": self.receipt_ref,
            "requester_digest": self.requester_digest,
        }

    def __post_init__(self) -> None:
        for field, value in (
            ("receipt_ref", self.receipt_ref),
            ("decision_ref", self.decision_ref),
            ("plan_ref", self.plan_ref),
        ):
            require_ref(value, field)
        for field, value in (
            ("decision_digest", self.decision_digest),
            ("plan_digest", self.plan_digest),
            ("requester_digest", self.requester_digest),
            ("approver_digest", self.approver_digest),
            ("receipt_digest", self.receipt_digest),
        ):
            require_digest(value, field)
        if (
            self.requester_digest == self.approver_digest
            or self.one_time is not True
            or self.execution_authorized is not False
            or self.expires_at <= self.issued_at
        ):
            raise PlanningContractError("M3 approval receipt widened authority or separation.")
        if self.receipt_digest != canonical_digest(self.canonical_content()):
            raise PlanningContractError("M3 approval receipt digest is invalid.")


@dataclass(frozen=True, slots=True)
class PlanGateResult:
    plan_ref: str
    plan_digest: str
    approval_validated: bool
    ready_for_dispatch: bool
    execution_authorized: bool
    blocker_codes: tuple[str, ...]


class M3ApprovalGate:
    """Issue and consume approval evidence while keeping dispatch denied."""

    def __init__(self, issuer: ReferenceIssuer) -> None:
        self._issuer = issuer
        self._approved_decisions: set[str] = set()
        self._consumed_receipts: set[str] = set()

    def approve(
        self,
        decision: PlanPolicyDecision,
        approver: AuthenticatedApprover,
        *,
        now_epoch: int,
    ) -> ApprovalReceipt:
        if now_epoch < decision.issued_at or now_epoch >= decision.expires_at:
            raise ApprovalDenied("Policy decision is outside its active lifetime.")
        if decision.execution_authorized or decision.outcome != "requires_independent_approval":
            raise ApprovalDenied("Policy decision cannot enter the approval gate.")
        if (
            approver.digest == decision.requester_digest
            or canonical_digest(approver.subject_ref)
            == decision.requester_subject_digest
        ):
            raise ApprovalDenied("Requester and approver separation is required.")
        if decision.decision_ref in self._approved_decisions:
            raise ApprovalDenied("Policy decision already produced an approval receipt.")
        receipt_ref = self._issuer.issue("approval-receipt")
        expires_at = min(decision.expires_at, now_epoch + 180)
        content: dict[str, CanonicalValue] = {
            "approver_digest": approver.digest,
            "decision_digest": decision.decision_digest,
            "decision_ref": decision.decision_ref,
            "execution_authorized": False,
            "expires_at": expires_at,
            "issued_at": now_epoch,
            "one_time": True,
            "plan_digest": decision.plan_digest,
            "plan_ref": decision.plan_ref,
            "receipt_ref": receipt_ref,
            "requester_digest": decision.requester_digest,
        }
        receipt = ApprovalReceipt(
            receipt_ref=receipt_ref,
            decision_ref=decision.decision_ref,
            decision_digest=decision.decision_digest,
            plan_ref=decision.plan_ref,
            plan_digest=decision.plan_digest,
            requester_digest=decision.requester_digest,
            approver_digest=approver.digest,
            issued_at=now_epoch,
            expires_at=expires_at,
            one_time=True,
            execution_authorized=False,
            receipt_digest=canonical_digest(content),
        )
        self._approved_decisions.add(decision.decision_ref)
        return receipt

    def claim_for_plan(
        self,
        receipt: ApprovalReceipt,
        plan: PreparedPlan,
        requester: AuthenticatedRequester,
        *,
        now_epoch: int,
    ) -> PlanGateResult:
        if now_epoch < receipt.issued_at or now_epoch >= receipt.expires_at:
            raise ApprovalDenied("Approval receipt is outside its active lifetime.")
        if receipt.receipt_ref in self._consumed_receipts:
            raise ApprovalDenied("Approval receipt was replayed.")
        if (
            receipt.plan_ref != plan.plan_ref
            or receipt.plan_digest != plan.plan_digest
            or receipt.requester_digest != requester.digest
            or requester.digest != plan.requester_digest
            or now_epoch >= plan.expires_at
        ):
            raise ApprovalDenied("Approval receipt is not bound to the exact active plan.")
        self._consumed_receipts.add(receipt.receipt_ref)
        return PlanGateResult(
            plan_ref=plan.plan_ref,
            plan_digest=plan.plan_digest,
            approval_validated=True,
            ready_for_dispatch=False,
            execution_authorized=False,
            blocker_codes=("adapter_registry_unbound", "plan_non_dispatchable"),
        )


__all__ = [
    "ApprovalDenied",
    "ApprovalReceipt",
    "AuthenticatedApprover",
    "M3ApprovalGate",
    "PlanGateResult",
]
