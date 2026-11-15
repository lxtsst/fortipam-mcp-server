"""Default-closed BP008 owned-original restoration through a new M3 chain.

The public profile contains categories and one non-resolving evidence reference.
Full original/applied states and forward execution pins remain in this private
source instance. No key, approval protocol, Tool, or product transport is added.
"""

from __future__ import annotations

from dataclasses import replace

from v4_planning import (
    ApprovalReceiptAuthenticationAuthority, AuthenticatedRequester,
    AuthoritativeProjection, ChangeKind, DesiredObject, FieldKind, FieldRule,
    M4AuthorizationDenied, M4ExecutionAuthorization, M4ExecutionPlan,
    ObjectClass, ProjectionContract, SchemeDraft, SchemeId, canonical_digest,
)
from v4_planning.approval import ApprovalReceipt
from v4_planning.canonical import CanonicalValue
from v4_planning.models import ConfirmationRecord, FinalIntentSummary, PreparedPlan, require_ref
from v4_planning.policy import PlanPolicyDecision
from v4_planning.store import ApprovalClaimRecord

from .secret_approval_build29_m4_authorization import _validate_private_transition
from .secret_approval_build29_m4_composition import _validate_draft_summary
from .secret_approval_build29_m4_runtime import (
    ACTION_ID, ACTION_VERSION, ADAPTER_REF, RESTORE_ACTION_ID,
    SecretApprovalBuild29M4ExecutionBinding, secret_approval_build29_binding_digest,
    secret_approval_build29_parameters_digest, secret_approval_build29_restore_parameters_digest,
)
from .secret_approval_build29_projection_source import FortiPamSecretApprovalBuild29ProjectionSource
from .secret_approval_m4_authorization import (
    SecretApprovalPlanningChainReader, _PlanningChain, _validate_approval_chain,
)


RESTORE_OUTCOME = "restore_owned_original_approval"
RESTORE_SOURCE_REF = "fortipam-700-build29-approval-owned-restore-projection"
RESTORE_PROJECTION_CONTRACT = "approval-owned-restore-build29-state-v1"
RESTORE_PROFILE_VERSION = "1.0.0"
_UNAVAILABLE = "Protected build-29 owned approval restoration is unavailable."


class SecretApprovalBuild29RestoreError(M4AuthorizationDenied):
    """Stable denial without selectors, state digests, or underlying responses."""


def secret_approval_build29_restore_projection_contract(object_class: ObjectClass) -> ProjectionContract:
    rules: tuple[FieldRule, ...]
    if object_class is ObjectClass.APPROVAL_PROFILE_BINDING:
        rules = (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule("profile_mode", FieldKind.ENUM, ("single_tier",)),
            FieldRule("profile_ref", FieldKind.REFERENCE),
        )
    elif object_class is ObjectClass.SECRET_APPROVAL_BINDING:
        rules = tuple(FieldRule(name, FieldKind.BOOLEAN) for name in (
            "exists", "approval_profile_attached", "interactive_approval_required",
            "job_approval_required", "owner_bypass_allowed", "owned_original_baseline_verified",
        )) + (FieldRule("ownership_evidence_ref", FieldKind.REFERENCE),)
    else:
        raise SecretApprovalBuild29RestoreError(_UNAVAILABLE)
    return ProjectionContract(
        contract_id=RESTORE_PROJECTION_CONTRACT, version=RESTORE_PROFILE_VERSION,
        source_ref=RESTORE_SOURCE_REF, object_class=object_class,
        field_rules=rules, max_age_seconds=300,
    )


class SecretApprovalBuild29OwnedRestoreSource:
    """One same-process applied transition, never imported restoration ownership.

    Construct only from the actual successful enable runtime's binding and its
    original categorical source. The evidence reference is independently
    authorized by the existing reference authority; it is not a state hash or
    locator. Full-state reread is deliberately deferred until the signed claim.
    """

    def __init__(
        self, source: FortiPamSecretApprovalBuild29ProjectionSource,
        enable_draft: SchemeDraft, requester: AuthenticatedRequester,
        enable_binding: SecretApprovalBuild29M4ExecutionBinding,
        *, ownership_evidence_ref: str,
    ) -> None:
        try:
            require_ref(ownership_evidence_ref, "ownership evidence")
            if (type(source) is not FortiPamSecretApprovalBuild29ProjectionSource
                    or source.contract_registered is not True
                    or type(enable_binding) is not SecretApprovalBuild29M4ExecutionBinding):
                raise ValueError
            self._source, self._enable_draft, self._requester = source, enable_draft, requester
            self._forward = enable_binding
            self._approval_binding = source.resolve_private_binding(enable_draft, requester)
            self._evidence_ref = ownership_evidence_ref
            self._binding_digest = secret_approval_build29_binding_digest(enable_binding)
            self._original = enable_binding.baseline
            ownership = enable_binding.transport._ownership
            if ownership is None:
                raise ValueError
            self._applied = ownership[1]
            self._check_owned()
            binding = self._approval_binding
            desired = tuple(
                DesiredObject(item.object_ref, item.object_class, True, tuple(sorted(
                    (name, value) for name, value in self._fields(item.object_class, restored=True).items()
                    if name != "exists"
                ))) for item in enable_draft.desired_objects
            )
            self._draft = replace(
                enable_draft, outcome_code=RESTORE_OUTCOME, desired_objects=desired,
                external_effects=("restore_owned_approval_baseline",),
                verification_codes=("owned_original_approval_readback",),
                reversibility_class="manual_reconciliation_only",
                evidence_refs=tuple(dict.fromkeys((*enable_draft.evidence_refs, ownership_evidence_ref))),
            )
            if {item.object_ref for item in desired} != {
                binding.approval_profile_object_ref, binding.secret_approval_object_ref,
            }:
                raise ValueError
        except Exception:
            raise SecretApprovalBuild29RestoreError(_UNAVAILABLE) from None

    def __repr__(self) -> str:
        return "<SecretApprovalBuild29OwnedRestoreSource protected>"

    @property
    def draft(self) -> SchemeDraft:
        """Expose only the immutable categorical restoration intent."""
        return self._draft

    def _fields(self, object_class: ObjectClass, *, restored: bool) -> dict[str, bool | str]:
        if object_class is ObjectClass.APPROVAL_PROFILE_BINDING:
            return {"exists": True, "profile_mode": "single_tier",
                    "profile_ref": self._approval_binding.approval_profile_ref}
        if object_class is not ObjectClass.SECRET_APPROVAL_BINDING:
            raise ValueError
        return {
            "exists": True, "approval_profile_attached": not restored,
            "interactive_approval_required": not restored, "job_approval_required": False,
            "owner_bypass_allowed": False, "owned_original_baseline_verified": True,
            "ownership_evidence_ref": self._evidence_ref,
        }

    def _check_owned(self) -> None:
        forward, binding = self._forward, self._approval_binding
        plan, auth = forward.plan, forward.authorization
        transport = forward.transport
        if (forward.operation != "enable" or transport._ownership != (self._original, self._applied)
                or plan.action_id != ACTION_ID or plan.action_version != ACTION_VERSION
                or plan.adapter_ref != ADAPTER_REF or forward.target_ref != binding.secret_approval_object_ref
                or plan.target_ref != forward.target_ref or plan.requester_digest != self._requester.digest
                or plan.expected_current_digest != self._original.state_digest
                or plan.expected_state_digest != self._applied.state_digest
                or auth.plan_ref != plan.plan_ref or auth.plan_digest != plan.plan_digest
                or auth.requester_digest != plan.requester_digest
                or auth.approval_digest != plan.approval_digest
                or auth.confirmation_digest != plan.confirmation_digest
                or plan.parameters_digest != secret_approval_build29_parameters_digest(self._binding_digest)):
            raise ValueError
        _validate_private_transition(
            binding, transport, self._original, self._applied, self._binding_digest,
        )

    def project(
        self, draft: SchemeDraft, requester: AuthenticatedRequester, *, now_epoch: int,
    ) -> tuple[AuthoritativeProjection, ...]:
        """Use only the existing safe categorical getters before M3 approval."""
        try:
            if draft != self.draft or requester != self._requester:
                raise ValueError
            self._check_owned()
            current = self._source.project(self._enable_draft, requester, now_epoch=now_epoch)
            by_class = {item.contract.object_class: item for item in current}
            if len(current) != 2 or set(by_class) != {
                ObjectClass.APPROVAL_PROFILE_BINDING, ObjectClass.SECRET_APPROVAL_BINDING,
            }:
                raise ValueError
            projected: list[AuthoritativeProjection] = []
            for item in draft.desired_objects:
                original = by_class[item.object_class]
                fields = self._fields(item.object_class, restored=False)
                categorical = {key: value for key, value in fields.items()
                               if key not in {"ownership_evidence_ref", "owned_original_baseline_verified"}}
                if original.object_ref != item.object_ref or dict(original.fields) != categorical:
                    raise ValueError
                projected.append(AuthoritativeProjection.from_mapping(
                    contract=secret_approval_build29_restore_projection_contract(item.object_class),
                    object_ref=item.object_ref, observed_at=original.observed_at,
                    fresh_until=original.fresh_until, fields=fields,
                ))
            return tuple(projected)
        except Exception:
            raise SecretApprovalBuild29RestoreError(_UNAVAILABLE) from None


def validate_secret_approval_build29_restore_chain(
    planning: SecretApprovalPlanningChainReader,
    receipt_authenticator: ApprovalReceiptAuthenticationAuthority,
    source: SecretApprovalBuild29OwnedRestoreSource,
    *, source_plan_ref: str, approval_receipt_ref: str, approver_authority_ref: str,
    now_epoch: int,
) -> _PlanningChain:
    """Material-free predicate; no full-state/private source getter is invoked."""
    try:
        if type(source) is not SecretApprovalBuild29OwnedRestoreSource or type(now_epoch) is not int:
            raise ValueError
        for ref in (source_plan_ref, approval_receipt_ref, approver_authority_ref):
            require_ref(ref, "protected reference")
        plan = planning.get_plan(source_plan_ref)
        summary = planning.get_summary(plan.summary_ref, plan.summary_revision)
        confirmation = planning.get_confirmation(plan.confirmation_ref)
        receipt = planning.get_approval_receipt(approval_receipt_ref)
        decision = planning.get_policy_decision(receipt.decision_ref)
        claim = planning.get_approval_claim(receipt.receipt_ref)
        if tuple(type(value) for value in (plan, summary, confirmation, receipt, decision, claim)) != (
            PreparedPlan, FinalIntentSummary, ConfirmationRecord, ApprovalReceipt, PlanPolicyDecision, ApprovalClaimRecord,
        ):
            raise ValueError
        for record, digest in ((plan, plan.plan_digest), (summary, summary.summary_digest),
                               (confirmation, confirmation.record_digest), (receipt, receipt.receipt_digest),
                               (decision, decision.decision_digest)):
            if digest != canonical_digest(record.canonical_content()):
                raise ValueError
        chain = _PlanningChain(summary, confirmation, plan, decision, receipt, claim)
        _validate_approval_chain(chain, receipt_authenticator,
                                 approver_authority_ref=approver_authority_ref, now_epoch=now_epoch)
        draft, forward = source.draft, source._forward
        _validate_draft_summary(draft, summary)
        if (plan.plan_ref != source_plan_ref or receipt.receipt_ref != approval_receipt_ref
                or plan.plan_ref == forward.plan.plan_ref
                or receipt.receipt_ref == forward.authorization.approval_ref
                or confirmation.confirmation_ref == forward.authorization.confirmation_ref
                or summary.summary_digest == forward.plan.summary_digest
                or plan.requester_digest != source._requester.digest
                or summary.requester_digest != source._requester.digest
                or (plan.environment_ref, plan.scope_ref) != (draft.environment_ref, draft.scope_ref)
                or (summary.environment_ref, summary.scope_ref) != (draft.environment_ref, draft.scope_ref)
                or plan.scheme_id is not SchemeId.APPROVAL_AND_OBSERVE
                or plan.scheme_version != draft.scheme_version or plan.registry_schema_version != draft.registry_schema_version
                or plan.summary_ref != summary.summary_ref or plan.summary_revision != summary.revision
                or plan.confirmation_ref != confirmation.confirmation_ref
                or summary.scheme_id is not draft.scheme_id or summary.scheme_version != draft.scheme_version
                or summary.registry_schema_version != draft.registry_schema_version
                or summary.blueprint_ref != "FPA-BP-008" or summary.outcome_code != RESTORE_OUTCOME
                or summary.action_family_ref != "approval-checkout-jit-and-jobs-plan"
                or summary.action_family_version != "1.0.0"
                or summary.external_effects != draft.external_effects
                or summary.verification_codes != draft.verification_codes
                or summary.reversibility_class != draft.reversibility_class
                or summary.material_reference_metadata is not None
                or summary.approval_class != "independent_approval" or summary.separation_required is not True
                or plan.dispatchable or plan.adapter_registry_bound or plan.executor_runtime_packaged or plan.executor_mcp_exposed
                or len(plan.lines) != 1 or len(summary.object_changes) != 2):
            raise ValueError
        changes = {change.object_class: change for change in summary.object_changes}
        for item in draft.desired_objects:
            change = changes[item.object_class]
            contract = secret_approval_build29_restore_projection_contract(item.object_class)
            current, expected = source._fields(item.object_class, restored=False), source._fields(item.object_class, restored=True)
            proposed = {name: value for name, value in expected.items() if current[name] != value}
            if (change.object_ref != item.object_ref or dict(change.current_fields) != current
                    or dict(change.expected_fields) != expected or dict(change.proposed_fields) != proposed
                    or change.change_kind is not (ChangeKind.UPDATE if proposed else ChangeKind.NO_OP)
                    or (change.projection_contract_ref, change.projection_contract_version, change.projection_source_ref)
                    != (contract.contract_id, contract.version, contract.source_ref)
                    or not change.observed_at <= now_epoch < change.fresh_until
                    or change.fresh_until - change.observed_at > contract.max_age_seconds):
                raise ValueError
            for fields, digest in ((current, change.current_projection_digest), (expected, change.expected_projection_digest)):
                if digest != canonical_digest({"contract": contract.as_dict(), "fields": fields, "object_ref": item.object_ref}):
                    raise ValueError
        secret = changes[ObjectClass.SECRET_APPROVAL_BINDING]
        line = plan.lines[0]
        if (line.target_ref != source._approval_binding.secret_approval_object_ref
                or line.target_class is not ObjectClass.SECRET_APPROVAL_BINDING
                or line.action_family_ref != summary.action_family_ref or line.action_family_version != summary.action_family_version
                or line.change_kind is not ChangeKind.UPDATE or line.depends_on or line.dispatchable or line.adapter != "none"
                or line.expected_current_digest != secret.current_projection_digest
                or line.expected_state_digest != secret.expected_projection_digest
                or line.projection_contract_ref != RESTORE_PROJECTION_CONTRACT
                or summary.current_state_digest != canonical_digest([c.current_projection_digest for c in summary.object_changes])
                or summary.expected_state_digest != canonical_digest([c.expected_projection_digest for c in summary.object_changes])
                or summary.proposed_changes_digest != canonical_digest([c.as_dict() for c in summary.object_changes])):
            raise ValueError
        return chain
    except Exception:
        raise SecretApprovalBuild29RestoreError(_UNAVAILABLE) from None


def promote_secret_approval_build29_restore_binding(
    planning: SecretApprovalPlanningChainReader,
    receipt_authenticator: ApprovalReceiptAuthenticationAuthority,
    source: SecretApprovalBuild29OwnedRestoreSource,
    *, source_plan_ref: str, approval_receipt_ref: str, approver_authority_ref: str,
    authorization_ref: str, now_epoch: int,
) -> SecretApprovalBuild29M4ExecutionBinding:
    """Validate signed restore claim before reading the full owned current state."""
    try:
        chain = validate_secret_approval_build29_restore_chain(
            planning, receipt_authenticator, source, source_plan_ref=source_plan_ref,
            approval_receipt_ref=approval_receipt_ref, approver_authority_ref=approver_authority_ref,
            now_epoch=now_epoch,
        )
        require_ref(authorization_ref, "restore authorization")
        if authorization_ref == source._forward.authorization.authorization_ref:
            raise ValueError
        source._check_owned()
        if source._forward.transport.inspect_transition() != source._applied:
            raise ValueError
        source._check_owned()
        parameters = secret_approval_build29_restore_parameters_digest(source._binding_digest, source._original.state_digest)
        expires = min(chain.plan.expires_at, chain.summary.expires_at, chain.confirmation.expires_at,
                      chain.decision.expires_at, chain.receipt.expires_at,
                      *(change.fresh_until for change in chain.summary.object_changes))
        idempotency = canonical_digest({
            "action_id": RESTORE_ACTION_ID, "action_version": ACTION_VERSION,
            "source_plan_digest": chain.plan.plan_digest, "approval_digest": chain.receipt.receipt_digest,
            "forward_plan_digest": source._forward.plan.plan_digest,
            "parameters_digest": parameters, "target_ref": source._approval_binding.secret_approval_object_ref,
        })
        values: dict[str, CanonicalValue] = {
            "action_id": RESTORE_ACTION_ID, "action_version": ACTION_VERSION, "adapter_ref": ADAPTER_REF,
            "approval_digest": chain.receipt.receipt_digest, "compensation_ref": None,
            "confirmation_digest": chain.plan.confirmation_digest,
            "expected_current_digest": source._applied.state_digest, "expected_state_digest": source._original.state_digest,
            "expires_at": expires,
            "idempotency_digest": idempotency,
            "parameters_digest": parameters, "plan_ref": chain.plan.plan_ref,
            "requester_digest": chain.plan.requester_digest, "revision": chain.plan.revision,
            "summary_digest": chain.summary.summary_digest, "target_ref": source._approval_binding.secret_approval_object_ref,
        }
        plan = M4ExecutionPlan(
            plan_ref=chain.plan.plan_ref, revision=chain.plan.revision,
            action_id=RESTORE_ACTION_ID, action_version=ACTION_VERSION, adapter_ref=ADAPTER_REF,
            target_ref=source._approval_binding.secret_approval_object_ref,
            requester_digest=chain.plan.requester_digest, summary_digest=chain.summary.summary_digest,
            confirmation_digest=chain.plan.confirmation_digest, approval_digest=chain.receipt.receipt_digest,
            parameters_digest=parameters, expected_current_digest=source._applied.state_digest,
            expected_state_digest=source._original.state_digest, idempotency_digest=idempotency,
            expires_at=expires, compensation_ref=None, plan_digest=canonical_digest(values),
        )
        auth_values: dict[str, CanonicalValue] = {
            "approval_digest": chain.receipt.receipt_digest, "approval_ref": chain.receipt.receipt_ref,
            "approver_digest": chain.receipt.approver_digest, "authorization_ref": authorization_ref,
            "confirmation_digest": chain.plan.confirmation_digest, "confirmation_ref": chain.plan.confirmation_ref,
            "execution_authorized": True, "expires_at": expires, "issued_at": chain.claim.claimed_at,
            "one_time": True, "plan_digest": plan.plan_digest, "plan_ref": plan.plan_ref,
            "requester_digest": plan.requester_digest,
        }
        authorization = M4ExecutionAuthorization(
            authorization_ref=authorization_ref, plan_ref=plan.plan_ref, plan_digest=plan.plan_digest,
            requester_digest=plan.requester_digest, confirmation_ref=chain.plan.confirmation_ref,
            confirmation_digest=chain.plan.confirmation_digest, approval_ref=chain.receipt.receipt_ref,
            approval_digest=chain.receipt.receipt_digest, approver_digest=chain.receipt.approver_digest,
            issued_at=chain.claim.claimed_at, expires_at=expires, one_time=True,
            execution_authorized=True, authorization_digest=canonical_digest(auth_values),
        )
        return SecretApprovalBuild29M4ExecutionBinding(
            plan, authorization, source._approval_binding.secret_approval_object_ref,
            source._original, source._forward.transport, "restore",
        )
    except Exception:
        raise SecretApprovalBuild29RestoreError(_UNAVAILABLE) from None


class PlanningChainSecretApprovalBuild29RestoreAuthorizationVerifier:
    """Rebuild only this independent restore authorization before an M4 claim."""

    def __init__(
        self, planning: SecretApprovalPlanningChainReader,
        receipt_authenticator: ApprovalReceiptAuthenticationAuthority,
        source: SecretApprovalBuild29OwnedRestoreSource,
        *, source_plan_ref: str, approval_receipt_ref: str,
        approver_authority_ref: str, authorization_ref: str,
    ) -> None:
        self._planning, self._authenticator, self._source = planning, receipt_authenticator, source
        self._plan_ref, self._receipt_ref = source_plan_ref, approval_receipt_ref
        self._authority_ref, self._authorization_ref = approver_authority_ref, authorization_ref

    def verify(
        self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int,
    ) -> None:
        expected = promote_secret_approval_build29_restore_binding(
            self._planning, self._authenticator, self._source,
            source_plan_ref=self._plan_ref, approval_receipt_ref=self._receipt_ref,
            approver_authority_ref=self._authority_ref, authorization_ref=self._authorization_ref,
            now_epoch=now_epoch,
        )
        if type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization:
            raise SecretApprovalBuild29RestoreError(_UNAVAILABLE)
        if plan != expected.plan or authorization != expected.authorization:
            raise SecretApprovalBuild29RestoreError(_UNAVAILABLE)
