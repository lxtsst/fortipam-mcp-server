"""Promote one signed BP008 approval chain to an exact M4 authorization.

The promotion is deterministic and action-specific.  It adds no second human
confirmation: one independently authorized, authenticated, and already-claimed
M3 approval receipt may produce only the fixed interactive-approval update.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from v4_planning import (
    ApprovalReceiptAuthenticationAuthority,
    ChangeKind,
    M4AuthorizationDenied,
    M4ExecutionAuthorization,
    M4ExecutionPlan,
    ObjectClass,
    SchemeId,
    canonical_digest,
)
from v4_planning.approval import ApprovalReceipt
from v4_planning.canonical import CanonicalValue
from v4_planning.models import ConfirmationRecord, FinalIntentSummary, PreparedPlan
from v4_planning.policy import PlanPolicyDecision
from v4_planning.store import ApprovalClaimRecord

from .approval_and_observe_projection_source import (
    ApprovalAndObserveBinding,
    SOURCE_REF,
)
from .secret_approval_m4_runtime import (
    SECRET_APPROVAL_ACTION_ID,
    SECRET_APPROVAL_ACTION_VERSION,
    SECRET_APPROVAL_ADAPTER_REF,
    SecretApprovalM4ExecutionBinding,
    secret_approval_parameters_digest,
)


_UNAVAILABLE = "Trusted Secret approval authorization is unavailable."
_PROJECTION_CONTRACT = "approval-and-observe-state-v1"
_PROJECTION_VERSION = "1.0.0"
_ACTION_FAMILY = "approval-checkout-jit-and-jobs-plan"
_ACTION_FAMILY_VERSION = "1.0.0"


class SecretApprovalM4AuthorizationError(M4AuthorizationDenied):
    """Stable denial for an incomplete or mismatched BP008 approval chain."""


class SecretApprovalPlanningChainReader(Protocol):
    """Read the existing protected M3 chain without adding a new ledger."""

    def get_summary(self, summary_ref: str, revision: int) -> FinalIntentSummary: ...

    def get_confirmation(self, confirmation_ref: str) -> ConfirmationRecord: ...

    def get_plan(self, plan_ref: str) -> PreparedPlan: ...

    def get_policy_decision(self, decision_ref: str) -> PlanPolicyDecision: ...

    def get_approval_receipt(self, receipt_ref: str) -> ApprovalReceipt: ...

    def get_approval_claim(self, receipt_ref: str) -> ApprovalClaimRecord: ...


@dataclass(frozen=True, slots=True)
class _PlanningChain:
    summary: FinalIntentSummary
    confirmation: ConfirmationRecord
    plan: PreparedPlan
    decision: PlanPolicyDecision
    receipt: ApprovalReceipt
    claim: ApprovalClaimRecord


def promote_secret_approval_m4_binding(
    planning: SecretApprovalPlanningChainReader,
    receipt_authenticator: ApprovalReceiptAuthenticationAuthority,
    approval_binding: ApprovalAndObserveBinding,
    *,
    source_plan_ref: str,
    approval_receipt_ref: str,
    approver_authority_ref: str,
    authorization_ref: str,
    now_epoch: int,
) -> SecretApprovalM4ExecutionBinding:
    """Derive one fixed M4 binding from a signed, claimed BP008 receipt."""

    chain = _validated_chain(
        planning,
        receipt_authenticator,
        approval_binding,
        source_plan_ref=source_plan_ref,
        approval_receipt_ref=approval_receipt_ref,
        approver_authority_ref=approver_authority_ref,
        now_epoch=now_epoch,
    )
    source_plan = chain.plan
    line = source_plan.lines[0]
    receipt = chain.receipt
    claim = chain.claim
    expires_at = min(
        source_plan.expires_at,
        chain.summary.expires_at,
        chain.confirmation.expires_at,
        chain.decision.expires_at,
        receipt.expires_at,
        *(change.fresh_until for change in chain.summary.object_changes),
    )
    parameters_digest = secret_approval_parameters_digest(approval_binding)
    idempotency_digest = canonical_digest(
        {
            "action_id": SECRET_APPROVAL_ACTION_ID,
            "action_version": SECRET_APPROVAL_ACTION_VERSION,
            "approval_digest": receipt.receipt_digest,
            "parameters_digest": parameters_digest,
            "source_plan_digest": source_plan.plan_digest,
            "target_ref": line.target_ref,
        }
    )
    plan_values: dict[str, CanonicalValue] = {
        "action_id": SECRET_APPROVAL_ACTION_ID,
        "action_version": SECRET_APPROVAL_ACTION_VERSION,
        "adapter_ref": SECRET_APPROVAL_ADAPTER_REF,
        "approval_digest": receipt.receipt_digest,
        "compensation_ref": None,
        "confirmation_digest": source_plan.confirmation_digest,
        "expected_current_digest": line.expected_current_digest,
        "expected_state_digest": line.expected_state_digest,
        "expires_at": expires_at,
        "idempotency_digest": idempotency_digest,
        "parameters_digest": parameters_digest,
        "plan_ref": source_plan.plan_ref,
        "requester_digest": source_plan.requester_digest,
        "revision": source_plan.revision,
        "summary_digest": source_plan.summary_digest,
        "target_ref": line.target_ref,
    }
    m4_plan = M4ExecutionPlan(
        plan_ref=source_plan.plan_ref,
        revision=source_plan.revision,
        action_id=SECRET_APPROVAL_ACTION_ID,
        action_version=SECRET_APPROVAL_ACTION_VERSION,
        adapter_ref=SECRET_APPROVAL_ADAPTER_REF,
        target_ref=line.target_ref,
        requester_digest=source_plan.requester_digest,
        summary_digest=source_plan.summary_digest,
        confirmation_digest=source_plan.confirmation_digest,
        approval_digest=receipt.receipt_digest,
        parameters_digest=parameters_digest,
        expected_current_digest=line.expected_current_digest,
        expected_state_digest=line.expected_state_digest,
        idempotency_digest=idempotency_digest,
        expires_at=expires_at,
        compensation_ref=None,
        plan_digest=canonical_digest(plan_values),
    )
    authorization_values: dict[str, CanonicalValue] = {
        "approval_digest": receipt.receipt_digest,
        "approval_ref": receipt.receipt_ref,
        "approver_digest": receipt.approver_digest,
        "authorization_ref": authorization_ref,
        "confirmation_digest": source_plan.confirmation_digest,
        "confirmation_ref": source_plan.confirmation_ref,
        "execution_authorized": True,
        "expires_at": expires_at,
        "issued_at": claim.claimed_at,
        "one_time": True,
        "plan_digest": m4_plan.plan_digest,
        "plan_ref": m4_plan.plan_ref,
        "requester_digest": m4_plan.requester_digest,
    }
    try:
        authorization = M4ExecutionAuthorization(
            authorization_ref=authorization_ref,
            plan_ref=m4_plan.plan_ref,
            plan_digest=m4_plan.plan_digest,
            requester_digest=m4_plan.requester_digest,
            confirmation_ref=source_plan.confirmation_ref,
            confirmation_digest=source_plan.confirmation_digest,
            approval_ref=receipt.receipt_ref,
            approval_digest=receipt.receipt_digest,
            approver_digest=receipt.approver_digest,
            issued_at=claim.claimed_at,
            expires_at=expires_at,
            one_time=True,
            execution_authorized=True,
            authorization_digest=canonical_digest(authorization_values),
        )
    except (TypeError, ValueError) as exc:
        raise SecretApprovalM4AuthorizationError(_UNAVAILABLE) from exc
    return SecretApprovalM4ExecutionBinding(m4_plan, authorization, approval_binding)


class PlanningChainSecretApprovalM4AuthorizationVerifier:
    """Rebuild and compare the exact signed BP008 promotion at execution."""

    def __init__(
        self,
        planning: SecretApprovalPlanningChainReader,
        receipt_authenticator: ApprovalReceiptAuthenticationAuthority,
        approval_binding: ApprovalAndObserveBinding,
        *,
        source_plan_ref: str,
        approval_receipt_ref: str,
        approver_authority_ref: str,
        authorization_ref: str,
    ) -> None:
        self._planning = planning
        self._receipt_authenticator = receipt_authenticator
        self._approval_binding = approval_binding
        self._source_plan_ref = source_plan_ref
        self._approval_receipt_ref = approval_receipt_ref
        self._approver_authority_ref = approver_authority_ref
        self._authorization_ref = authorization_ref

    def verify(
        self,
        plan: M4ExecutionPlan,
        authorization: M4ExecutionAuthorization,
        *,
        now_epoch: int,
    ) -> None:
        try:
            expected = promote_secret_approval_m4_binding(
                self._planning,
                self._receipt_authenticator,
                self._approval_binding,
                source_plan_ref=self._source_plan_ref,
                approval_receipt_ref=self._approval_receipt_ref,
                approver_authority_ref=self._approver_authority_ref,
                authorization_ref=self._authorization_ref,
                now_epoch=now_epoch,
            )
            if expected.plan != plan or expected.authorization != authorization:
                raise SecretApprovalM4AuthorizationError(_UNAVAILABLE)
        except SecretApprovalM4AuthorizationError:
            raise
        except Exception as exc:
            raise SecretApprovalM4AuthorizationError(_UNAVAILABLE) from exc


def _validated_chain(
    planning: SecretApprovalPlanningChainReader,
    receipt_authenticator: ApprovalReceiptAuthenticationAuthority,
    approval_binding: ApprovalAndObserveBinding,
    *,
    source_plan_ref: str,
    approval_receipt_ref: str,
    approver_authority_ref: str,
    now_epoch: int,
) -> _PlanningChain:
    try:
        plan = planning.get_plan(source_plan_ref)
        summary = planning.get_summary(plan.summary_ref, plan.summary_revision)
        confirmation = planning.get_confirmation(plan.confirmation_ref)
        receipt = planning.get_approval_receipt(approval_receipt_ref)
        decision = planning.get_policy_decision(receipt.decision_ref)
        claim = planning.get_approval_claim(receipt.receipt_ref)
    except Exception as exc:
        raise SecretApprovalM4AuthorizationError(_UNAVAILABLE) from exc
    chain = _PlanningChain(summary, confirmation, plan, decision, receipt, claim)
    _validate_action_chain(chain, approval_binding, now_epoch=now_epoch)
    _validate_approval_chain(
        chain,
        receipt_authenticator,
        approver_authority_ref=approver_authority_ref,
        now_epoch=now_epoch,
    )
    return chain


def _validate_action_chain(
    chain: _PlanningChain,
    binding: ApprovalAndObserveBinding,
    *,
    now_epoch: int,
) -> None:
    summary = chain.summary
    plan = chain.plan
    if len(plan.lines) != 1 or len(summary.object_changes) != 2:
        raise SecretApprovalM4AuthorizationError(_UNAVAILABLE)
    line = plan.lines[0]
    changes = {item.object_class: item for item in summary.object_changes}
    profile = changes.get(ObjectClass.APPROVAL_PROFILE_BINDING)
    secret = changes.get(ObjectClass.SECRET_APPROVAL_BINDING)
    expected_profile = {
        "exists": True,
        "profile_mode": "single_tier",
        "profile_ref": binding.approval_profile_ref,
    }
    expected_current = {
        "approval_profile_attached": False,
        "exists": True,
        "interactive_approval_required": False,
        "job_approval_required": False,
        "owner_bypass_allowed": False,
    }
    expected_secret = {
        "approval_profile_attached": True,
        "exists": True,
        "interactive_approval_required": True,
        "job_approval_required": False,
        "owner_bypass_allowed": False,
    }
    if (
        summary.scheme_id is not SchemeId.APPROVAL_AND_OBSERVE
        or summary.blueprint_ref != "FPA-BP-008"
        or summary.outcome_code != "require_interactive_approval"
        or summary.action_family_ref != _ACTION_FAMILY
        or summary.action_family_version != _ACTION_FAMILY_VERSION
        or summary.approval_class != "independent_approval"
        or summary.separation_required is not True
        or summary.material_reference_metadata is not None
        or any(
            now_epoch < item.observed_at or now_epoch >= item.fresh_until
            for item in summary.object_changes
        )
        or profile is None
        or secret is None
        or profile.object_ref != binding.approval_profile_object_ref
        or profile.change_kind is not ChangeKind.NO_OP
        or dict(profile.current_fields) != expected_profile
        or dict(profile.expected_fields) != expected_profile
        or profile.proposed_fields
        or secret.object_ref != binding.secret_approval_object_ref
        or secret.change_kind is not ChangeKind.UPDATE
        or dict(secret.current_fields) != expected_current
        or dict(secret.expected_fields) != expected_secret
        or dict(secret.proposed_fields)
        != {
            "approval_profile_attached": True,
            "interactive_approval_required": True,
        }
        or any(
            item.projection_contract_ref != _PROJECTION_CONTRACT
            or item.projection_contract_version != _PROJECTION_VERSION
            or item.projection_source_ref != SOURCE_REF
            for item in (profile, secret)
        )
        or plan.scheme_id is not SchemeId.APPROVAL_AND_OBSERVE
        or plan.scheme_version != "1.0.0"
        or plan.registry_schema_version != summary.registry_schema_version
        or plan.summary_ref != summary.summary_ref
        or plan.summary_revision != summary.revision
        or plan.confirmation_ref != chain.confirmation.confirmation_ref
        or plan.environment_ref != summary.environment_ref
        or plan.scope_ref != summary.scope_ref
        or line.action_family_ref != _ACTION_FAMILY
        or line.action_family_version != _ACTION_FAMILY_VERSION
        or line.target_ref != binding.secret_approval_object_ref
        or line.target_class is not ObjectClass.SECRET_APPROVAL_BINDING
        or line.change_kind is not ChangeKind.UPDATE
        or line.depends_on
        or line.expected_current_digest != secret.current_projection_digest
        or line.expected_state_digest != secret.expected_projection_digest
        or line.projection_contract_ref != _PROJECTION_CONTRACT
    ):
        raise SecretApprovalM4AuthorizationError(_UNAVAILABLE)


def _validate_approval_chain(
    chain: _PlanningChain,
    authenticator: ApprovalReceiptAuthenticationAuthority,
    *,
    approver_authority_ref: str,
    now_epoch: int,
) -> None:
    summary = chain.summary
    confirmation = chain.confirmation
    plan = chain.plan
    decision = chain.decision
    receipt = chain.receipt
    claim = chain.claim
    if (
        type(now_epoch) is not int
        or receipt.authenticator_ref != authenticator.authority_ref
        or receipt.receipt_mac is None
        or receipt.approver_authority_ref != approver_authority_ref
        or receipt.approver_authorization_digest is None
        or receipt.policy_version != decision.policy_version
        or receipt.approval_nonce_digest is None
        or not authenticator.verify(receipt)
        or confirmation.summary_ref != summary.summary_ref
        or confirmation.summary_revision != summary.revision
        or confirmation.summary_digest != summary.summary_digest
        or confirmation.requester_digest != summary.requester_digest
        or confirmation.record_digest != plan.confirmation_digest
        or confirmation.interaction_type != "authenticated_human_confirmation"
        or plan.summary_digest != summary.summary_digest
        or plan.requester_digest != summary.requester_digest
        or decision.plan_ref != plan.plan_ref
        or decision.plan_digest != plan.plan_digest
        or decision.requester_digest != plan.requester_digest
        or decision.outcome != "requires_independent_approval"
        or decision.approval_class != "independent_approval"
        or decision.separation_required is not True
        or decision.execution_authorized is not False
        or receipt.decision_ref != decision.decision_ref
        or receipt.decision_digest != decision.decision_digest
        or receipt.plan_ref != plan.plan_ref
        or receipt.plan_digest != plan.plan_digest
        or receipt.requester_digest != plan.requester_digest
        or receipt.approver_digest == plan.requester_digest
        or receipt.one_time is not True
        or receipt.execution_authorized is not False
        or claim.receipt_ref != receipt.receipt_ref
        or claim.receipt_digest != receipt.receipt_digest
        or claim.plan_ref != plan.plan_ref
        or claim.plan_digest != plan.plan_digest
        or claim.requester_digest != plan.requester_digest
        or claim.execution_authorized is not False
        or claim.claimed_at < receipt.issued_at
        or claim.claimed_at > now_epoch
        or any(
            now_epoch < issued_at or now_epoch >= expires_at
            for issued_at, expires_at in (
                (summary.created_at, summary.expires_at),
                (confirmation.confirmed_at, confirmation.expires_at),
                (plan.created_at, plan.expires_at),
                (decision.issued_at, decision.expires_at),
                (receipt.issued_at, receipt.expires_at),
            )
        )
    ):
        raise SecretApprovalM4AuthorizationError(_UNAVAILABLE)


__all__ = [
    "PlanningChainSecretApprovalM4AuthorizationVerifier",
    "SecretApprovalM4AuthorizationError",
    "SecretApprovalPlanningChainReader",
    "promote_secret_approval_m4_binding",
]
