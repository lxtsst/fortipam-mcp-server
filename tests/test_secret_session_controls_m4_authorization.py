from __future__ import annotations

from dataclasses import replace

import pytest

from fortipam_mcp.secret_onboarding_projection_source import (
    SECRET_SESSION_CONTROLS_SOURCE_CONTRACT,
    SECRET_SESSION_CONTROLS_SOURCE_REF,
    SECRET_SESSION_CONTROLS_SOURCE_VERSION,
    SOURCE_REF,
    SecretOnboardingBinding,
    secret_onboarding_projection_contract,
)
from fortipam_mcp.secret_session_controls_m4_authorization import (
    PlanningChainSecretSessionControlsM4AuthorizationVerifier,
    SecretSessionControlsM4AuthorizationError,
    promote_secret_session_controls_m4_binding,
)
from fortipam_mcp.secret_session_controls_m4_runtime import (
    SECRET_SESSION_CONTROLS_ACTION_ID,
    SecretSessionControlsBinding,
    secret_session_controls_parameters_digest,
)
from fortipam_mcp.secret_metadata_http_transport import (
    secret_session_controls_event_filter_profile_digest,
)
from test_secret_approval_m4_authorization import _ClaimedPlanningReader
from test_v4_m3 import ExactApproverAuthority
from test_v4_planning import (
    NOW,
    Authorizer,
    Issuer,
    _existing_controls_projections,
    _existing_secret_controls_draft,
    _interaction,
    _promoted_registry,
)
from v4_planning import (
    AuthenticatedRequester,
    FieldKind,
    FieldRule,
    M2PlanningEngine,
    ObjectClass,
    ProjectionContract,
)
from v4_planning.approval import (
    ApprovalReceiptAuthenticator,
    AuthenticatedApprover,
    M3ApprovalGate,
)
from v4_planning.policy import M3PlanPolicy
from v4_planning.store import InMemoryProtectedPlanningStore


PROFILE = "mcp-v4-rdp-event-filter-existing01"
OLD_PROFILE = "mcp-v4-rdp-event-filter-existing00"


def _binding() -> SecretSessionControlsBinding:
    return SecretSessionControlsBinding(
        secret_session_controls_object_ref="secret-controls-object-ref01",
        folder_ref="approved-folder-ref01", folder_path="Public/folder",
        secret_name="mcp-v4-secret-metadata-01",
        template_ref="template-approved-ref1", template_name="Windows Local Account",
        target_ref="target-relation-ref01", target_name="MCP Windows Target",
        secret_id=42, rdp_event_filter_profile_ref="event-filter-profile-ref01",
        rdp_event_filter_profile_name=PROFILE,
        prewrite_recording_enabled=True,
        prewrite_clipboard_blocking_enabled=False,
        prewrite_rdp_event_filter_enabled=False,
        prewrite_rdp_event_filter_profile_matches=False,
        prewrite_rdp_event_filter_profile_digest=(
            secret_session_controls_event_filter_profile_digest(OLD_PROFILE)
        ),
        preserved_identity_relations_digest="1" * 64,
    )


def _onboarding_binding() -> SecretOnboardingBinding:
    return SecretOnboardingBinding(
        folder_object_ref="folder-binding-ref01", folder_path="Public/folder",
        folder_ref="approved-folder-ref01", target_object_ref="target-relation-ref01",
        target_name="MCP Windows Target", target_protocol="rdp",
        connectivity_profile_ref="connectivity-profile01", target_ipv4_address="192.0.2.42",
        template_object_ref="template-binding-ref1", template_name="Windows Local Account",
        template_ref="template-approved-ref1", secret_object_ref="secret-metadata-ref01",
        secret_name="mcp-v4-secret-metadata-01",
        rdp_event_filter_object_ref="event-filter-object-ref01",
        rdp_event_filter_profile_name=PROFILE,
        rdp_event_filter_profile_ref="event-filter-profile-ref01",
        secret_session_controls_object_ref="secret-controls-object-ref01",
        existing_secret_id=42,
        session_controls_identity_digest="1" * 64,
    )


def _contract(scheme_id, object_class):
    assert scheme_id.value == "SecretOnboardingScheme"
    if object_class is not ObjectClass.SECRET_SESSION_CONTROLS_BINDING:
        return secret_onboarding_projection_contract(object_class)
    return ProjectionContract(
        SECRET_SESSION_CONTROLS_SOURCE_CONTRACT,
        SECRET_SESSION_CONTROLS_SOURCE_VERSION,
        SECRET_SESSION_CONTROLS_SOURCE_REF,
        object_class,
        (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule("recording_enabled", FieldKind.BOOLEAN),
            FieldRule("clipboard_blocking_enabled", FieldKind.BOOLEAN),
            FieldRule("rdp_event_filter_enabled", FieldKind.BOOLEAN),
            FieldRule("rdp_event_filter_profile_matches", FieldKind.BOOLEAN),
            FieldRule("preserved_identity_digest", FieldKind.DIGEST),
            FieldRule("event_filter_profile_digest", FieldKind.DIGEST),
            FieldRule("profile_ref", FieldKind.REFERENCE),
        ),
        300,
    )


def _claimed_chain(*, include_engine: bool = False):
    draft = _existing_secret_controls_draft()
    issuer = Issuer()
    authorizer = Authorizer(
        (draft,), projection_source_ref=SECRET_SESSION_CONTROLS_SOURCE_REF
    )
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
        draft, requester, _existing_controls_projections(engine, draft), now_epoch=NOW
    )
    confirmation = engine.confirm_intent(
        summary.summary_ref, requester, _interaction(summary, requester), now_epoch=NOW + 1
    )
    plan = engine.prepare_plan(summary.summary_ref, confirmation.confirmation_ref, requester, now_epoch=NOW + 2)
    decision = M3PlanPolicy(issuer).evaluate(plan, requester, now_epoch=NOW + 3)
    authenticator = ApprovalReceiptAuthenticator(b"a" * 32)
    receipt = M3ApprovalGate(
        issuer, receipt_authenticator=authenticator,
        approver_authorizer=ExactApproverAuthority(),
    ).approve(
        decision, AuthenticatedApprover(
            "approver-subject-0001", identity_authority_ref="identity-authority-ref01",
            subject_namespace="workforce-namespace-v1",
        ), now_epoch=NOW + 4,
        plan=plan, requester=requester,
    )
    store = InMemoryProtectedPlanningStore(clock=lambda: NOW + 5, approval_receipt_authenticator=authenticator)
    store.put_summary(summary); store.put_confirmation(confirmation); store.put_plan(plan)
    store.put_policy_decision(decision); store.put_approval_receipt(receipt)
    claim = store.claim_approval(receipt.receipt_ref, plan.plan_ref, requester.digest)
    result = (_ClaimedPlanningReader(store, claim), authenticator, plan, receipt)
    if include_engine:
        return (*result, engine, draft)
    return result


def test_signed_bp006_receipt_promotes_only_fixed_existing_secret_controls() -> None:
    planning, authenticator, plan, receipt = _claimed_chain()
    binding, onboarding = _binding(), _onboarding_binding()

    promoted = promote_secret_session_controls_m4_binding(
        planning, authenticator, binding, onboarding_binding=onboarding,
        source_plan_ref=plan.plan_ref, approval_receipt_ref=receipt.receipt_ref,
        approver_authority_ref=ExactApproverAuthority.authority_ref,
        authorization_ref="session-controls-authorization-ref01", now_epoch=NOW + 5,
    )

    assert promoted.plan.action_id == SECRET_SESSION_CONTROLS_ACTION_ID
    assert promoted.plan.parameters_digest == secret_session_controls_parameters_digest(binding)
    assert promoted.plan.expected_current_digest != plan.lines[0].expected_current_digest
    assert binding.secret_name not in str(promoted.plan.canonical_content())
    PlanningChainSecretSessionControlsM4AuthorizationVerifier(
        planning, authenticator, binding, onboarding_binding=onboarding,
        source_plan_ref=plan.plan_ref, approval_receipt_ref=receipt.receipt_ref,
        approver_authority_ref=ExactApproverAuthority.authority_ref,
        authorization_ref="session-controls-authorization-ref01",
    ).verify(promoted.plan, promoted.authorization, now_epoch=NOW + 5)


def test_promotion_rejects_onboarding_binding_cross_reference_drift() -> None:
    planning, authenticator, plan, receipt = _claimed_chain()

    with pytest.raises(SecretSessionControlsM4AuthorizationError):
        promote_secret_session_controls_m4_binding(
            planning, authenticator, _binding(),
            onboarding_binding=replace(_onboarding_binding(), target_object_ref="target-other-ref0001"),
            source_plan_ref=plan.plan_ref, approval_receipt_ref=receipt.receipt_ref,
            approver_authority_ref=ExactApproverAuthority.authority_ref,
            authorization_ref="session-controls-authorization-ref01", now_epoch=NOW + 5,
        )


@pytest.mark.parametrize(
    ("binding_change", "onboarding_change"),
    (
        (
            {"preserved_identity_relations_digest": "2" * 64},
            {"session_controls_identity_digest": "2" * 64},
        ),
        (
            {"prewrite_rdp_event_filter_profile_digest": "2" * 64},
            {},
        ),
    ),
)
def test_promotion_rejects_receipt_bound_baseline_digest_drift(
    binding_change: dict[str, str],
    onboarding_change: dict[str, str],
) -> None:
    planning, authenticator, plan, receipt = _claimed_chain()

    with pytest.raises(SecretSessionControlsM4AuthorizationError):
        promote_secret_session_controls_m4_binding(
            planning, authenticator, replace(_binding(), **binding_change),
            onboarding_binding=replace(_onboarding_binding(), **onboarding_change),
            source_plan_ref=plan.plan_ref, approval_receipt_ref=receipt.receipt_ref,
            approver_authority_ref=ExactApproverAuthority.authority_ref,
            authorization_ref="session-controls-authorization-ref01", now_epoch=NOW + 5,
        )
