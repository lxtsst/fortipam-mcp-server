"""Fixed build-29 BP008 promotion after an authenticated planning-chain claim.

The first predicate is material-free. Private transition states are supplied
only by the protected provider after that predicate; neither promotion nor
verification reads account material or establishes product qualification.
Restore requires its own independent protected M4 authorization path.
"""

from __future__ import annotations

from v4_planning import (
    ApprovalReceiptAuthenticationAuthority, ChangeKind, M4AuthorizationDenied,
    M4ExecutionAuthorization, M4ExecutionPlan, ObjectClass, SchemeId,
    canonical_digest,
)
from v4_planning.approval import ApprovalReceipt
from v4_planning.models import (
    ConfirmationRecord, FinalIntentSummary, PreparedPlan, require_digest, require_ref,
)
from v4_planning.policy import PlanPolicyDecision
from v4_planning.store import ApprovalClaimRecord

from .approval_and_observe_projection_source import ApprovalAndObserveBinding
from .secret_approval_build29_contract import compile_secret_approval_build29_enable_body
from .secret_approval_build29_http_transport import (
    FortiPamSecretApprovalBuild29HttpTransport, SecretApprovalBuild29PrivateState,
    SecretApprovalBuild29WebFieldsBinding, SecretApprovalBuild29LinuxFieldsBinding,
)
from .secret_approval_build29_m4_runtime import (
    ACTION_ID, ACTION_VERSION, ADAPTER_REF, SecretApprovalBuild29M4ExecutionBinding,
    secret_approval_build29_binding_digest, secret_approval_build29_parameters_digest,
    secret_approval_build29_transport_binding_digest,
)
from .secret_approval_build29_projection_source import secret_approval_build29_projection_contract
from .secret_approval_m4_authorization import (
    SecretApprovalPlanningChainReader, _PlanningChain, _validate_approval_chain,
)


SOURCE_REF = "fortipam-700-build29-approval-observe-projection"
PROJECTION_CONTRACT = "approval-and-observe-build29-state-v1"
PROJECTION_VERSION = "1.0.0"
_UNAVAILABLE = "Protected build-29 Secret approval authorization is unavailable."


class SecretApprovalBuild29M4AuthorizationError(M4AuthorizationDenied):
    """A stable failure with no private selectors, states or underlying cause."""


def validate_build29_planning_chain(
    planning: SecretApprovalPlanningChainReader,
    receipt_authenticator: ApprovalReceiptAuthenticationAuthority,
    approval_binding: ApprovalAndObserveBinding,
    *,
    source_plan_ref: str,
    approval_receipt_ref: str,
    approver_authority_ref: str,
    authenticated_requester_digest: str,
    authorized_environment_ref: str,
    authorized_scope_ref: str,
    now_epoch: int,
) -> _PlanningChain:
    """Validate the entire claimed enable chain before any material production.

    Reading protected planning records and authenticating the existing receipt
    confers no device, restore or source-qualification authority by itself.
    """
    try:
        for ref in (source_plan_ref, approval_receipt_ref, approver_authority_ref,
                    authorized_environment_ref, authorized_scope_ref):
            require_ref(ref, "protected reference")
        require_digest(authenticated_requester_digest, "authenticated_requester_digest")
        if type(now_epoch) is not int or now_epoch < 0 or type(approval_binding) is not ApprovalAndObserveBinding:
            raise ValueError
        plan = planning.get_plan(source_plan_ref)
        summary = planning.get_summary(plan.summary_ref, plan.summary_revision)
        confirmation = planning.get_confirmation(plan.confirmation_ref)
        receipt = planning.get_approval_receipt(approval_receipt_ref)
        decision = planning.get_policy_decision(receipt.decision_ref)
        claim = planning.get_approval_claim(receipt.receipt_ref)
        if (type(plan) is not PreparedPlan or type(summary) is not FinalIntentSummary
                or type(confirmation) is not ConfirmationRecord or type(receipt) is not ApprovalReceipt
                or type(decision) is not PlanPolicyDecision or type(claim) is not ApprovalClaimRecord
                or plan.plan_ref != source_plan_ref or receipt.receipt_ref != approval_receipt_ref
                or plan.requester_digest != authenticated_requester_digest
                or plan.environment_ref != authorized_environment_ref
                or plan.scope_ref != authorized_scope_ref
                or summary.environment_ref != authorized_environment_ref
                or summary.scope_ref != authorized_scope_ref):
            raise ValueError
        chain = _PlanningChain(summary, confirmation, plan, decision, receipt, claim)
        if (summary.summary_digest != canonical_digest(summary.canonical_content())
                or plan.plan_digest != canonical_digest(plan.canonical_content())
                or confirmation.record_digest != canonical_digest(confirmation.canonical_content())
                or decision.decision_digest != canonical_digest(decision.canonical_content())
                or receipt.receipt_digest != canonical_digest(receipt.canonical_content())):
            raise ValueError
        _validate_build29_action_chain(chain, approval_binding, now_epoch=now_epoch)
        _validate_approval_chain(chain, receipt_authenticator,
                                 approver_authority_ref=approver_authority_ref, now_epoch=now_epoch)
        return chain
    except Exception:
        raise SecretApprovalBuild29M4AuthorizationError(_UNAVAILABLE) from None


def _validate_build29_action_chain(
    chain: _PlanningChain, binding: ApprovalAndObserveBinding, *, now_epoch: int,
) -> None:
    summary, plan = chain.summary, chain.plan
    if len(plan.lines) != 1 or len(summary.object_changes) != 2:
        raise ValueError
    line = plan.lines[0]
    changes = {change.object_class: change for change in summary.object_changes}
    profile = changes.get(ObjectClass.APPROVAL_PROFILE_BINDING)
    secret = changes.get(ObjectClass.SECRET_APPROVAL_BINDING)
    profile_fields = {"exists": True, "profile_mode": "single_tier", "profile_ref": binding.approval_profile_ref}
    current_fields = {"exists": True, "approval_profile_attached": False,
                      "interactive_approval_required": False, "job_approval_required": False,
                      "owner_bypass_allowed": False}
    expected_fields = {**current_fields, "approval_profile_attached": True, "interactive_approval_required": True}
    if (summary.scheme_id is not SchemeId.APPROVAL_AND_OBSERVE
            or summary.scheme_version != "1.0.0" or summary.blueprint_ref != "FPA-BP-008"
            or summary.outcome_code != "require_interactive_approval"
            or summary.action_family_ref != "approval-checkout-jit-and-jobs-plan"
            or summary.action_family_version != "1.0.0"
            or summary.approval_class != "independent_approval" or summary.separation_required is not True
            or summary.material_reference_metadata is not None
            or profile is None or secret is None
            or profile.object_ref != binding.approval_profile_object_ref
            or profile.change_kind is not ChangeKind.NO_OP
            or dict(profile.current_fields) != profile_fields
            or dict(profile.expected_fields) != profile_fields or profile.proposed_fields
            or secret.object_ref != binding.secret_approval_object_ref
            or secret.change_kind is not ChangeKind.UPDATE
            or dict(secret.current_fields) != current_fields
            or dict(secret.expected_fields) != expected_fields
            or dict(secret.proposed_fields) != {"approval_profile_attached": True, "interactive_approval_required": True}
            or plan.scheme_id is not SchemeId.APPROVAL_AND_OBSERVE or plan.scheme_version != "1.0.0"
            or plan.registry_schema_version != summary.registry_schema_version
            or plan.summary_ref != summary.summary_ref or plan.summary_revision != summary.revision
            or plan.confirmation_ref != chain.confirmation.confirmation_ref
            or plan.dispatchable or plan.adapter_registry_bound or plan.executor_runtime_packaged or plan.executor_mcp_exposed
            or line.dispatchable or line.adapter != "none"
            or line.action_family_ref != summary.action_family_ref
            or line.action_family_version != summary.action_family_version
            or line.target_ref != binding.secret_approval_object_ref
            or line.target_class is not ObjectClass.SECRET_APPROVAL_BINDING
            or line.change_kind is not ChangeKind.UPDATE or line.depends_on
            or line.expected_current_digest != secret.current_projection_digest
            or line.expected_state_digest != secret.expected_projection_digest
            or line.projection_contract_ref != PROJECTION_CONTRACT):
        raise ValueError
    for change in (profile, secret):
        contract = secret_approval_build29_projection_contract(change.object_class)
        if (contract.contract_id != PROJECTION_CONTRACT or contract.version != PROJECTION_VERSION
                or contract.source_ref != SOURCE_REF
                or change.projection_contract_ref != PROJECTION_CONTRACT
                or change.projection_contract_version != PROJECTION_VERSION
                or change.projection_source_ref != SOURCE_REF
                or not change.observed_at <= now_epoch < change.fresh_until
                or change.fresh_until - change.observed_at > contract.max_age_seconds):
            raise ValueError
        for fields, digest in ((change.current_fields, change.current_projection_digest),
                               (change.expected_fields, change.expected_projection_digest)):
            validated = contract.validate_fields(dict(fields), complete=True)
            if fields != validated or digest != canonical_digest({
                "contract": contract.as_dict(), "fields": dict(validated), "object_ref": change.object_ref,
            }):
                raise ValueError
    if (summary.current_state_digest != canonical_digest([c.current_projection_digest for c in summary.object_changes])
            or summary.expected_state_digest != canonical_digest([c.expected_projection_digest for c in summary.object_changes])
            or summary.proposed_changes_digest != canonical_digest([c.as_dict() for c in summary.object_changes])):
        raise ValueError


def _validate_private_transition(
    binding: ApprovalAndObserveBinding, transport: FortiPamSecretApprovalBuild29HttpTransport,
    baseline: SecretApprovalBuild29PrivateState, expected: SecretApprovalBuild29PrivateState,
    expected_binding_digest: str,
) -> None:
    require_digest(expected_binding_digest, "expected_binding_digest")
    if (type(transport) is not FortiPamSecretApprovalBuild29HttpTransport
            or type(baseline) is not SecretApprovalBuild29PrivateState
            or type(expected) is not SecretApprovalBuild29PrivateState):
        raise ValueError
    mutation = transport._mutation
    if (transport._closed or mutation is None
            or not (
                transport._linux_target_name is None
                and type(mutation.web_fields) is SecretApprovalBuild29WebFieldsBinding
                and mutation.linux_fields is None and mutation.expected_folder_acl_digest is None
                or transport._linux_target_name is not None
                and mutation.web_fields is None
                and type(mutation.linux_fields) is SecretApprovalBuild29LinuxFieldsBinding
                and mutation.linux_fields.target_name == transport._linux_target_name
                and type(mutation.expected_folder_acl_digest) is str
            )
            or transport._identity["id"] != binding.secret_id
            or transport._identity["name"] != binding.secret_name
            or transport._folder_path != binding.folder_path
            or mutation.approval_profile_name != binding.approval_profile_name
            or secret_approval_build29_transport_binding_digest(transport, binding.secret_approval_object_ref)
            != expected_binding_digest
            or baseline.approval_values != ("disable", "disable", "disable", "")
            or expected.approval_values != ("enable", "disable", "disable", binding.approval_profile_name)
            or (baseline.metadata_digest, baseline.profile_digest, baseline.native_digest)
            != (expected.metadata_digest, expected.profile_digest, expected.native_digest)):
        raise ValueError
    proposed = compile_secret_approval_build29_enable_body(
        transport._projection(baseline.approval_values), schema=transport._schema,
        identity=transport._identity, approval_profile_name=binding.approval_profile_name,
    )
    if proposed != dict(zip(("need-approval", "need-approval-job", "bypass-approval", "approval-profile"), expected.approval_values)):
        raise ValueError
    for state in (baseline, expected):
        for digest in (state.metadata_digest, state.profile_digest, state.native_digest, state.state_digest):
            require_digest(digest, "private state digest")
        if transport._transition_state(state.approval_values, state.metadata_digest,
                                       state.profile_digest, state.native_digest) != state:
            raise ValueError
    if baseline.state_digest == expected.state_digest:
        raise ValueError


def promote_secret_approval_build29_m4_binding(
    planning: SecretApprovalPlanningChainReader,
    receipt_authenticator: ApprovalReceiptAuthenticationAuthority,
    approval_binding: ApprovalAndObserveBinding,
    *,
    source_plan_ref: str, approval_receipt_ref: str, approver_authority_ref: str,
    authorization_ref: str, authenticated_requester_digest: str,
    authorized_environment_ref: str, authorized_scope_ref: str, now_epoch: int,
    transport: FortiPamSecretApprovalBuild29HttpTransport,
    baseline: SecretApprovalBuild29PrivateState,
    expected_private_state: SecretApprovalBuild29PrivateState,
    expected_binding_digest: str,
) -> SecretApprovalBuild29M4ExecutionBinding:
    """Bind signed categorical C/P/E to one preserved private enable transition.

    The protected provider owns the provenance of the full states. Exact sealed
    association and canonical state reconstruction do not replace its separate
    native/material/source qualification or grant restore ownership.
    """
    try:
        chain = validate_build29_planning_chain(
            planning, receipt_authenticator, approval_binding,
            source_plan_ref=source_plan_ref, approval_receipt_ref=approval_receipt_ref,
            approver_authority_ref=approver_authority_ref,
            authenticated_requester_digest=authenticated_requester_digest,
            authorized_environment_ref=authorized_environment_ref, authorized_scope_ref=authorized_scope_ref,
            now_epoch=now_epoch,
        )
        require_ref(authorization_ref, "authorization_ref")
        _validate_private_transition(approval_binding, transport, baseline, expected_private_state, expected_binding_digest)
        source, receipt = chain.plan, chain.receipt
        expires_at = min(source.expires_at, chain.summary.expires_at, chain.confirmation.expires_at,
                         chain.decision.expires_at, receipt.expires_at,
                         *(change.fresh_until for change in chain.summary.object_changes))
        parameters = secret_approval_build29_parameters_digest(expected_binding_digest)
        idempotency = canonical_digest({
            "action_id": ACTION_ID, "action_version": ACTION_VERSION,
            "approval_digest": receipt.receipt_digest, "parameters_digest": parameters,
            "source_plan_digest": source.plan_digest, "target_ref": approval_binding.secret_approval_object_ref,
        })
        values = {
            "action_id": ACTION_ID, "action_version": ACTION_VERSION, "adapter_ref": ADAPTER_REF,
            "approval_digest": receipt.receipt_digest, "compensation_ref": None,
            "confirmation_digest": source.confirmation_digest,
            "expected_current_digest": baseline.state_digest,
            "expected_state_digest": expected_private_state.state_digest, "expires_at": expires_at,
            "idempotency_digest": idempotency,
            "parameters_digest": parameters, "plan_ref": source.plan_ref,
            "requester_digest": source.requester_digest, "revision": source.revision,
            "summary_digest": source.summary_digest, "target_ref": approval_binding.secret_approval_object_ref,
        }
        plan = M4ExecutionPlan(
            plan_ref=source.plan_ref, revision=source.revision, action_id=ACTION_ID,
            action_version=ACTION_VERSION, adapter_ref=ADAPTER_REF,
            target_ref=approval_binding.secret_approval_object_ref,
            requester_digest=source.requester_digest, summary_digest=source.summary_digest,
            confirmation_digest=source.confirmation_digest, approval_digest=receipt.receipt_digest,
            parameters_digest=parameters, expected_current_digest=baseline.state_digest,
            expected_state_digest=expected_private_state.state_digest,
            idempotency_digest=idempotency, expires_at=expires_at,
            compensation_ref=None, plan_digest=canonical_digest(values),
        )
        auth_values = {
            "approval_digest": receipt.receipt_digest, "approval_ref": receipt.receipt_ref,
            "approver_digest": receipt.approver_digest, "authorization_ref": authorization_ref,
            "confirmation_digest": source.confirmation_digest, "confirmation_ref": source.confirmation_ref,
            "execution_authorized": True, "expires_at": expires_at, "issued_at": chain.claim.claimed_at,
            "one_time": True, "plan_digest": plan.plan_digest, "plan_ref": plan.plan_ref,
            "requester_digest": plan.requester_digest,
        }
        authorization = M4ExecutionAuthorization(
            authorization_ref=authorization_ref, plan_ref=plan.plan_ref, plan_digest=plan.plan_digest,
            requester_digest=plan.requester_digest, confirmation_ref=source.confirmation_ref,
            confirmation_digest=source.confirmation_digest, approval_ref=receipt.receipt_ref,
            approval_digest=receipt.receipt_digest, approver_digest=receipt.approver_digest,
            issued_at=chain.claim.claimed_at, expires_at=expires_at, one_time=True,
            execution_authorized=True, authorization_digest=canonical_digest(auth_values),
        )
        result = SecretApprovalBuild29M4ExecutionBinding(
            plan, authorization, approval_binding.secret_approval_object_ref, baseline, transport,
        )
        if secret_approval_build29_binding_digest(result) != expected_binding_digest:
            raise ValueError
        return result
    except Exception:
        raise SecretApprovalBuild29M4AuthorizationError(_UNAVAILABLE) from None


class PlanningChainSecretApprovalBuild29M4AuthorizationVerifier:
    """Revalidate the same independent receipt and exact private state pairing."""

    def __init__(
        self, planning: SecretApprovalPlanningChainReader,
        receipt_authenticator: ApprovalReceiptAuthenticationAuthority,
        approval_binding: ApprovalAndObserveBinding,
        *, source_plan_ref: str, approval_receipt_ref: str, approver_authority_ref: str,
        authorization_ref: str, authenticated_requester_digest: str,
        authorized_environment_ref: str, authorized_scope_ref: str,
        transport: FortiPamSecretApprovalBuild29HttpTransport,
        baseline: SecretApprovalBuild29PrivateState, expected_private_state: SecretApprovalBuild29PrivateState,
        expected_binding_digest: str,
    ) -> None:
        self._planning = planning
        self._authenticator = receipt_authenticator
        self._binding = approval_binding
        self._source_plan_ref = source_plan_ref
        self._receipt_ref = approval_receipt_ref
        self._authority_ref = approver_authority_ref
        self._authorization_ref = authorization_ref
        self._requester = authenticated_requester_digest
        self._environment = authorized_environment_ref
        self._scope = authorized_scope_ref
        self._transport = transport
        self._baseline = baseline
        self._expected = expected_private_state
        self._binding_digest = expected_binding_digest

    def verify(
        self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int,
    ) -> None:
        try:
            expected = promote_secret_approval_build29_m4_binding(
                self._planning, self._authenticator, self._binding,
                source_plan_ref=self._source_plan_ref, approval_receipt_ref=self._receipt_ref,
                approver_authority_ref=self._authority_ref, authorization_ref=self._authorization_ref,
                authenticated_requester_digest=self._requester, authorized_environment_ref=self._environment,
                authorized_scope_ref=self._scope, now_epoch=now_epoch, transport=self._transport,
                baseline=self._baseline, expected_private_state=self._expected,
                expected_binding_digest=self._binding_digest,
            )
            if type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization:
                raise ValueError
            if plan != expected.plan or authorization != expected.authorization:
                raise ValueError
        except Exception:
            raise SecretApprovalBuild29M4AuthorizationError(_UNAVAILABLE) from None
