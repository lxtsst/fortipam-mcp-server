"""Exact plan-digest policy decision for the V4 M3 plan-only candidate."""

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
    require_version,
)


class PlanPolicyDenied(PlanningContractError):
    """Raised when a prepared plan cannot enter the M3 approval gate."""


@dataclass(frozen=True, slots=True)
class PlanPolicyDecision:
    decision_ref: str
    plan_ref: str
    plan_digest: str
    requester_digest: str
    requester_subject_digest: str
    outcome: str
    approval_class: str
    separation_required: bool
    execution_authorized: bool
    policy_version: str
    issued_at: int
    expires_at: int
    decision_digest: str

    def canonical_content(self) -> dict[str, CanonicalValue]:
        return {
            "approval_class": self.approval_class,
            "decision_ref": self.decision_ref,
            "execution_authorized": self.execution_authorized,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "outcome": self.outcome,
            "plan_digest": self.plan_digest,
            "plan_ref": self.plan_ref,
            "policy_version": self.policy_version,
            "requester_digest": self.requester_digest,
            "requester_subject_digest": self.requester_subject_digest,
            "separation_required": self.separation_required,
        }

    def __post_init__(self) -> None:
        require_ref(self.decision_ref, "decision_ref")
        require_ref(self.plan_ref, "plan_ref")
        require_digest(self.plan_digest, "plan_digest")
        require_digest(self.requester_digest, "requester_digest")
        require_digest(self.requester_subject_digest, "requester_subject_digest")
        require_version(self.policy_version, "policy_version")
        require_digest(self.decision_digest, "decision_digest")
        if (
            self.outcome != "requires_independent_approval"
            or self.approval_class != "independent_approval"
            or self.separation_required is not True
            or self.execution_authorized is not False
        ):
            raise PlanningContractError("M3 policy decision widened execution authority.")
        if self.expires_at <= self.issued_at:
            raise PlanningContractError("M3 policy decision lifetime is invalid.")
        if self.decision_digest != canonical_digest(self.canonical_content()):
            raise PlanningContractError("M3 policy decision digest is invalid.")


class M3PlanPolicy:
    """Authorize only entry into independent approval, never product execution."""

    def __init__(self, issuer: ReferenceIssuer, *, policy_version: str = "1.0.0") -> None:
        require_version(policy_version, "policy_version")
        self._issuer = issuer
        self._policy_version = policy_version

    def evaluate(
        self,
        plan: PreparedPlan,
        requester: AuthenticatedRequester,
        *,
        now_epoch: int,
    ) -> PlanPolicyDecision:
        if now_epoch < plan.created_at or now_epoch >= plan.expires_at:
            raise PlanPolicyDenied("Prepared plan is outside its active lifetime.")
        if requester.digest != plan.requester_digest:
            raise PlanPolicyDenied("Requester is not bound to the prepared plan.")
        if (
            plan.dispatchable
            or plan.adapter_registry_bound
            or plan.runtime_packaged
            or plan.mcp_exposed
            or any(line.dispatchable or line.adapter != "none" for line in plan.lines)
        ):
            raise PlanPolicyDenied("Prepared plan exceeds the M3 plan-only boundary.")
        decision_ref = self._issuer.issue("policy-decision")
        expires_at = min(plan.expires_at, now_epoch + 300)
        content: dict[str, CanonicalValue] = {
            "approval_class": "independent_approval",
            "decision_ref": decision_ref,
            "execution_authorized": False,
            "expires_at": expires_at,
            "issued_at": now_epoch,
            "outcome": "requires_independent_approval",
            "plan_digest": plan.plan_digest,
            "plan_ref": plan.plan_ref,
            "policy_version": self._policy_version,
            "requester_digest": requester.digest,
            "requester_subject_digest": canonical_digest(requester.subject_ref),
            "separation_required": True,
        }
        return PlanPolicyDecision(
            decision_ref=decision_ref,
            plan_ref=plan.plan_ref,
            plan_digest=plan.plan_digest,
            requester_digest=requester.digest,
            requester_subject_digest=canonical_digest(requester.subject_ref),
            outcome="requires_independent_approval",
            approval_class="independent_approval",
            separation_required=True,
            execution_authorized=False,
            policy_version=self._policy_version,
            issued_at=now_epoch,
            expires_at=expires_at,
            decision_digest=canonical_digest(content),
        )


__all__ = ["M3PlanPolicy", "PlanPolicyDecision", "PlanPolicyDenied"]
