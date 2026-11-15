from dataclasses import replace

import pytest

from fortipam_mcp.secret_onboarding_projection_source import (
    SOURCE_REF,
    WebSecretOnboardingBinding,
    secret_onboarding_projection_contract,
)
from fortipam_mcp.web_secret_service_m4_adapter import (
    ACTION_ID,
    WebSecretServiceBinding,
    parameters_digest,
)
from fortipam_mcp.web_secret_service_m4_authorization import (
    PlanningChainWebSecretServiceM4AuthorizationVerifier,
    WebSecretServiceM4AuthorizationError,
    promote_web_secret_service_m4_binding,
)
from test_secret_approval_m4_authorization import _ClaimedPlanningReader
from test_v4_m3 import ExactApproverAuthority
from test_v4_planning import (
    NOW,
    Authorizer,
    Issuer,
    _existing_web_service_draft,
    _existing_web_service_projections,
    _interaction,
    _promoted_registry,
)
from v4_planning import AuthenticatedRequester, M2PlanningEngine, canonical_digest
from v4_planning.approval import (
    ApprovalReceiptAuthenticator,
    AuthenticatedApprover,
    M3ApprovalGate,
)
from v4_planning.policy import M3PlanPolicy
from v4_planning.store import InMemoryProtectedPlanningStore


def _service_binding() -> WebSecretServiceBinding:
    return WebSecretServiceBinding(
        "web-secret-service-object-ref01", "Public/folder", "mcp-v4-web-secret", 24
    )


def _onboarding_binding() -> WebSecretOnboardingBinding:
    return WebSecretOnboardingBinding(
        folder_object_ref="folder-binding-ref01", folder_path="Public/folder",
        folder_ref="approved-folder-ref01", template_object_ref="template-binding-ref1",
        template_name="Web Account", template_ref="template-approved-ref1",
        secret_object_ref="web-secret-metadata-ref01", secret_name="mcp-v4-web-secret",
        web_url="https://web.example.test", session_recording=True,
        service_object_ref="web-secret-service-object-ref01", existing_secret_id=24,
    )


def _contract(scheme_id, object_class):
    assert scheme_id.value == "SecretOnboardingScheme"
    return secret_onboarding_projection_contract(object_class)


def _claimed_chain():
    draft = _existing_web_service_draft()
    issuer = Issuer()
    authorizer = Authorizer((draft,), projection_source_ref=SOURCE_REF)
    authorizer._grants.add((SOURCE_REF, "projection_source"))
    engine = M2PlanningEngine(
        _promoted_registry(), issuer, authorizer,
        projection_contract_resolver=_contract,
    )
    requester = AuthenticatedRequester(
        "operator-subject-0001", "operator",
        identity_authority_ref="identity-authority-ref01",
        subject_namespace="workforce-namespace-v1",
    )
    summary = engine.compile_summary(
        draft, requester, _existing_web_service_projections(engine, draft), now_epoch=NOW
    )
    confirmation = engine.confirm_intent(
        summary.summary_ref, requester, _interaction(summary, requester), now_epoch=NOW + 1
    )
    plan = engine.prepare_plan(
        summary.summary_ref, confirmation.confirmation_ref, requester, now_epoch=NOW + 2
    )
    decision = M3PlanPolicy(issuer).evaluate(plan, requester, now_epoch=NOW + 3)
    authenticator = ApprovalReceiptAuthenticator(b"a" * 32)
    receipt = M3ApprovalGate(
        issuer, receipt_authenticator=authenticator,
        approver_authorizer=ExactApproverAuthority(),
    ).approve(
        decision, AuthenticatedApprover(
            "approver-subject-0001", identity_authority_ref="identity-authority-ref01",
            subject_namespace="workforce-namespace-v1",
        ), now_epoch=NOW + 4, plan=plan, requester=requester,
    )
    store = InMemoryProtectedPlanningStore(
        clock=lambda: NOW + 5, approval_receipt_authenticator=authenticator
    )
    store.put_summary(summary); store.put_confirmation(confirmation); store.put_plan(plan)
    store.put_policy_decision(decision); store.put_approval_receipt(receipt)
    claim = store.claim_approval(receipt.receipt_ref, plan.plan_ref, requester.digest)
    return _ClaimedPlanningReader(store, claim), authenticator, plan, receipt


def _promote(*, now_epoch: int = NOW + 5, service=None, onboarding=None):
    planning, authenticator, plan, receipt = _claimed_chain()
    return promote_web_secret_service_m4_binding(
        planning, authenticator, service or _service_binding(),
        onboarding_binding=onboarding or _onboarding_binding(),
        source_plan_ref=plan.plan_ref, approval_receipt_ref=receipt.receipt_ref,
        approver_authority_ref=ExactApproverAuthority.authority_ref,
        authorization_ref="web-service-authorization-ref01", now_epoch=now_epoch,
    )


def test_signed_bp007_receipt_promotes_only_fixed_web_service_enable() -> None:
    promoted = _promote()

    assert promoted.plan.action_id == ACTION_ID
    assert promoted.plan.parameters_digest == parameters_digest(_service_binding())
    assert promoted.authorization.one_time is True
    assert promoted.authorization.execution_authorized is True

    planning, authenticator, plan, receipt = _claimed_chain()
    PlanningChainWebSecretServiceM4AuthorizationVerifier(
        planning, authenticator, _service_binding(), onboarding_binding=_onboarding_binding(),
        source_plan_ref=plan.plan_ref, approval_receipt_ref=receipt.receipt_ref,
        approver_authority_ref=ExactApproverAuthority.authority_ref,
        authorization_ref="web-service-authorization-ref01",
    ).verify(promoted.plan, promoted.authorization, now_epoch=NOW + 5)


@pytest.mark.parametrize("kind", ["service_id", "onboarding_relation", "expired"])
def test_web_service_promotion_rejects_mismatched_or_expired_chain(kind: str) -> None:
    kwargs = {}
    if kind == "service_id":
        kwargs["service"] = replace(_service_binding(), secret_id=25)
    elif kind == "onboarding_relation":
        kwargs["onboarding"] = replace(_onboarding_binding(), service_object_ref="other-service-ref01")
    elif kind == "expired":
        kwargs["now_epoch"] = NOW + 301
    with pytest.raises(WebSecretServiceM4AuthorizationError):
        _promote(**kwargs)


def test_verifier_rejects_tampered_promoted_m4_records() -> None:
    promoted = _promote()
    planning, authenticator, plan, receipt = _claimed_chain()
    verifier = PlanningChainWebSecretServiceM4AuthorizationVerifier(
        planning, authenticator, _service_binding(), onboarding_binding=_onboarding_binding(),
        source_plan_ref=plan.plan_ref, approval_receipt_ref=receipt.receipt_ref,
        approver_authority_ref=ExactApproverAuthority.authority_ref,
        authorization_ref="web-service-authorization-ref01",
    )
    content = dict(promoted.plan.canonical_content())
    content["parameters_digest"] = "0" * 64
    tampered_plan = replace(
        promoted.plan, parameters_digest="0" * 64,
        plan_digest=canonical_digest(content),
    )
    with pytest.raises(WebSecretServiceM4AuthorizationError):
        verifier.verify(
            tampered_plan,
            promoted.authorization,
            now_epoch=NOW + 5,
        )
