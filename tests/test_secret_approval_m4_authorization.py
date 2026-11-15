from __future__ import annotations

import pytest

from fortipam_mcp.approval_and_observe_projection_source import (
    ApprovalAndObserveBinding,
    SOURCE_REF,
    approval_and_observe_projection_contract,
)
from fortipam_mcp.secret_approval_m4_authorization import (
    PlanningChainSecretApprovalM4AuthorizationVerifier,
    SecretApprovalM4AuthorizationError,
    promote_secret_approval_m4_binding,
)
from fortipam_mcp.secret_approval_m4_runtime import (
    SECRET_APPROVAL_ACTION_ID,
    secret_approval_parameters_digest,
)
from fortipam_mcp.secret_metadata_http_transport import (
    SecretApprovalProjectionInspection,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from fortipam_mcp.v4_runtime_host import V4PlanHostComponents
from test_v4_m3 import ExactApproverAuthority
from test_v4_planning import (
    NOW,
    Authorizer,
    Issuer,
    _approval_and_observe_draft,
    _interaction,
    _projection,
    _promoted_registry,
)
from v4_planning import (
    AuthenticatedRequester,
    InMemoryM4ExecutionStateStore,
    M2PlanningEngine,
    M4Outcome,
    ObjectClass,
)
from v4_planning.approval import (
    ApprovalReceiptAuthenticator,
    AuthenticatedApprover,
    M3ApprovalGate,
)
from v4_planning.policy import M3PlanPolicy
from v4_planning.store import (
    ApprovalClaimRecord,
    InMemoryProtectedPlanningStore,
)


class _ClaimedPlanningReader:
    def __init__(
        self,
        store: InMemoryProtectedPlanningStore,
        claim: ApprovalClaimRecord,
    ) -> None:
        self._store = store
        self._claim = claim

    def get_summary(self, summary_ref: str, revision: int):
        return self._store.get_summary(summary_ref, revision)

    def get_confirmation(self, confirmation_ref: str):
        return self._store.get_confirmation(confirmation_ref)

    def get_plan(self, plan_ref: str):
        return self._store.get_plan(plan_ref)

    def get_policy_decision(self, decision_ref: str):
        return self._store.get_policy_decision(decision_ref)

    def get_approval_receipt(self, receipt_ref: str):
        return self._store.get_approval_receipt(receipt_ref)

    def get_approval_claim(self, receipt_ref: str) -> ApprovalClaimRecord:
        assert receipt_ref == self._claim.receipt_ref
        return self._claim


def _binding() -> ApprovalAndObserveBinding:
    return ApprovalAndObserveBinding(
        approval_profile_object_ref="approval-profile-object-ref01",
        approval_profile_ref="approval-profile-ref0001",
        approval_profile_name="mcp-v4-approval-profile-01",
        secret_approval_object_ref="secret-approval-object-ref01",
        folder_path="Public/folder",
        secret_name="mcp-v4-secret-metadata-01",
        secret_id=42,
    )


def _source_contract(scheme_id, object_class):
    assert scheme_id.value == "ApprovalAndObserveScheme"
    return approval_and_observe_projection_contract(object_class)


def _claimed_chain(
    *,
    independent_authority: bool = True,
    projection_fresh_until: int = NOW + 100,
):
    draft = _approval_and_observe_draft()
    issuer = Issuer()
    engine = M2PlanningEngine(
        _promoted_registry(),
        issuer,
        Authorizer((draft,), projection_source_ref=SOURCE_REF),
        projection_contract_resolver=_source_contract,
    )
    requester = AuthenticatedRequester(
        "operator-subject-0001",
        "operator",
        identity_authority_ref="identity-authority-ref01",
        subject_namespace="workforce-namespace-v1",
    )
    desired = {item.object_class: item for item in draft.desired_objects}
    current = (
        _projection(
            engine,
            draft.scheme_id,
            desired[ObjectClass.APPROVAL_PROFILE_BINDING],
            {
                "exists": True,
                "profile_mode": "single_tier",
                "profile_ref": "approval-profile-ref0001",
            },
            fresh_until=projection_fresh_until,
        ),
        _projection(
            engine,
            draft.scheme_id,
            desired[ObjectClass.SECRET_APPROVAL_BINDING],
            {
                "exists": True,
                "approval_profile_attached": False,
                "interactive_approval_required": False,
                "job_approval_required": False,
                "owner_bypass_allowed": False,
            },
            fresh_until=projection_fresh_until,
        ),
    )
    summary = engine.compile_summary(draft, requester, current, now_epoch=NOW)
    confirmation = engine.confirm_intent(
        summary.summary_ref,
        requester,
        _interaction(summary, requester),
        now_epoch=NOW + 1,
    )
    plan = engine.prepare_plan(
        summary.summary_ref,
        confirmation.confirmation_ref,
        requester,
        now_epoch=NOW + 2,
    )
    decision = M3PlanPolicy(issuer).evaluate(plan, requester, now_epoch=NOW + 3)
    authenticator = ApprovalReceiptAuthenticator(b"a" * 32)
    gate = M3ApprovalGate(
        issuer,
        receipt_authenticator=authenticator,
        approver_authorizer=(
            ExactApproverAuthority() if independent_authority else None
        ),
    )
    receipt = gate.approve(
        decision,
        AuthenticatedApprover(
            "approver-subject-0001",
            identity_authority_ref="identity-authority-ref01",
            subject_namespace="workforce-namespace-v1",
        ),
        now_epoch=NOW + 4,
        plan=plan if independent_authority else None,
        requester=requester if independent_authority else None,
    )
    store = InMemoryProtectedPlanningStore(
        clock=lambda: NOW + 5,
        approval_receipt_authenticator=authenticator,
    )
    store.put_summary(summary)
    store.put_confirmation(confirmation)
    store.put_plan(plan)
    store.put_policy_decision(decision)
    store.put_approval_receipt(receipt)
    claim = store.claim_approval(receipt.receipt_ref, plan.plan_ref, requester.digest)
    return (
        _ClaimedPlanningReader(store, claim),
        authenticator,
        requester,
        draft,
        plan,
        receipt,
    )


class _State:
    def __init__(self) -> None:
        self.enabled = False
        self.writes = 0

    def enable_interactive_approval(
        self,
        secret_id: int,
        approval_profile_name: str,
    ) -> None:
        assert (secret_id, approval_profile_name) == (
            42,
            "mcp-v4-approval-profile-01",
        )
        self.writes += 1
        self.enabled = True

    def inspect_approval_projection(
        self,
        folder_path: str,
        secret_name: str,
        approval_profile_name: str,
        *,
        expected_secret_id: int,
    ) -> SecretApprovalProjectionInspection:
        assert (
            folder_path,
            secret_name,
            approval_profile_name,
            expected_secret_id,
        ) == (
            "Public/folder",
            "mcp-v4-secret-metadata-01",
            "mcp-v4-approval-profile-01",
            42,
        )
        return SecretApprovalProjectionInspection(
            True,
            self.enabled,
            False,
            False,
            self.enabled,
            not self.enabled,
            True,
        )


class _HostPlanServices:
    def __init__(self, plan, draft, state: _State) -> None:
        self._plan = plan
        self._draft = draft
        self._state = state

    def resolve_execution_context(
        self,
        plan_ref: str,
        scheme_draft_ref: str,
        principal: V4PlanningPrincipal,
    ):
        assert plan_ref == self._plan.plan_ref
        assert scheme_draft_ref == "approval-scheme-draft-ref01"
        assert principal.requester.digest == self._plan.requester_digest
        return self._plan, self._draft

    def evaluate_pre_write(self, *_args, **_kwargs):
        return {"status": "match"}

    def evaluate_post_write(self, *_args, **_kwargs):
        assert self._state.enabled is True
        return {"status": "expected_state_matches"}


class _HostProjectionSource:
    def resolve_private_binding(self, *_args, **_kwargs) -> ApprovalAndObserveBinding:
        return _binding()


def test_signed_independent_bp008_receipt_promotes_without_second_confirmation() -> None:
    planning, authenticator, _requester, _draft, plan, receipt = _claimed_chain()
    binding = _binding()

    promoted = promote_secret_approval_m4_binding(
        planning,
        authenticator,
        binding,
        source_plan_ref=plan.plan_ref,
        approval_receipt_ref=receipt.receipt_ref,
        approver_authority_ref=ExactApproverAuthority.authority_ref,
        authorization_ref="secret-approval-authorization-ref01",
        now_epoch=NOW + 5,
    )

    assert promoted.plan.action_id == SECRET_APPROVAL_ACTION_ID
    assert promoted.plan.plan_ref == plan.plan_ref
    assert promoted.plan.approval_digest == receipt.receipt_digest
    assert promoted.plan.parameters_digest == secret_approval_parameters_digest(binding)
    assert promoted.authorization.one_time is True
    assert promoted.authorization.execution_authorized is True
    assert promoted.authorization.issued_at == NOW + 5
    assert binding.approval_profile_name not in str(promoted.plan.canonical_content())
    assert binding.secret_name not in str(promoted.authorization.canonical_content())

    verifier = PlanningChainSecretApprovalM4AuthorizationVerifier(
        planning,
        authenticator,
        binding,
        source_plan_ref=plan.plan_ref,
        approval_receipt_ref=receipt.receipt_ref,
        approver_authority_ref=ExactApproverAuthority.authority_ref,
        authorization_ref="secret-approval-authorization-ref01",
    )
    verifier.verify(promoted.plan, promoted.authorization, now_epoch=NOW + 5)


def test_promotion_rejects_signed_receipt_without_independent_authority() -> None:
    planning, authenticator, _requester, _draft, plan, receipt = _claimed_chain(
        independent_authority=False
    )

    with pytest.raises(SecretApprovalM4AuthorizationError):
        promote_secret_approval_m4_binding(
            planning,
            authenticator,
            _binding(),
            source_plan_ref=plan.plan_ref,
            approval_receipt_ref=receipt.receipt_ref,
            approver_authority_ref=ExactApproverAuthority.authority_ref,
            authorization_ref="secret-approval-authorization-ref01",
            now_epoch=NOW + 5,
        )


def test_promotion_rejects_untrusted_independent_authority() -> None:
    planning, authenticator, _requester, _draft, plan, receipt = _claimed_chain()

    with pytest.raises(SecretApprovalM4AuthorizationError):
        promote_secret_approval_m4_binding(
            planning,
            authenticator,
            _binding(),
            source_plan_ref=plan.plan_ref,
            approval_receipt_ref=receipt.receipt_ref,
            approver_authority_ref="different-approver-authority-ref01",
            authorization_ref="secret-approval-authorization-ref01",
            now_epoch=NOW + 5,
        )


def test_promotion_rejects_expired_confirmed_projection() -> None:
    planning, authenticator, _requester, _draft, plan, receipt = _claimed_chain(
        projection_fresh_until=NOW + 8
    )

    with pytest.raises(SecretApprovalM4AuthorizationError):
        promote_secret_approval_m4_binding(
            planning,
            authenticator,
            _binding(),
            source_plan_ref=plan.plan_ref,
            approval_receipt_ref=receipt.receipt_ref,
            approver_authority_ref=ExactApproverAuthority.authority_ref,
            authorization_ref="secret-approval-authorization-ref01",
            now_epoch=NOW + 9,
        )


def test_host_composition_executes_the_promoted_binding_without_a_second_confirm() -> None:
    planning, authenticator, requester, draft, plan, receipt = _claimed_chain()
    state = _State()
    services = _HostPlanServices(plan, draft, state)
    components = V4PlanHostComponents(
        plan_services=services,  # type: ignore[arg-type]
        confirmation_service=object(),  # type: ignore[arg-type]
        approval_and_observe_projection_source=(
            _HostProjectionSource()  # type: ignore[arg-type]
        ),
        _secret_approval_planning_reader=planning,
        _secret_approval_receipt_authenticator=authenticator,
        _secret_approval_approver_authority_ref=(
            ExactApproverAuthority.authority_ref
        ),
        _clock=lambda: NOW + 5,
    )
    action = components.bind_trusted_approval_and_observe_execution_mcp_action(
        source_plan_ref=plan.plan_ref,
        scheme_draft_ref="approval-scheme-draft-ref01",
        approval_receipt_ref=receipt.receipt_ref,
        authorization_ref="secret-approval-authorization-ref01",
        principal=V4PlanningPrincipal(requester, "a" * 64),
        read_transport=state,
        write_transport=state,
        execution_store=InMemoryM4ExecutionStateStore(),
        authorized_environment_ref=draft.environment_ref,
        authorized_scope_ref=draft.scope_ref,
        execution_enabled=True,
    )

    result = action.execute(
        plan.plan_ref,
        "approval-scheme-draft-ref01",
        V4PlanningPrincipal(requester, "a" * 64),
    )

    assert result["outcome"] == M4Outcome.SUCCEEDED.value
    assert result["post_write_status"] == "expected_state_matches"
    assert result["policy_mode"] == "independent_approval"
    assert state.writes == 1
