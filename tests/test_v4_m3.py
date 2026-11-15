from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sqlite3
from types import SimpleNamespace
from typing import cast

import pytest

from v4_planning import (
    AuthenticatedRequester,
    ChangeKind,
    ConfirmationRecord,
    FinalIntentSummary,
    ObjectChange,
    ObjectClass,
    PlanLine,
    PlanState,
    PlanningContractError,
    PreparedPlan,
    PreWriteEvaluation,
    PreWriteStatus,
    PostWriteStatus,
    PlanningDenied,
    SchemeId,
    SummaryState,
    VerifiedConfirmationInteraction,
    M2PlanningEngine,
    M3PlanOnlyWorkflowService,
    SchemeDraft,
    canonical_digest,
)
from v4_planning.approval import (
    ApprovalDenied,
    ApprovalReceiptAuthenticator,
    ApproverAuthorizationDecision,
    AuthenticatedApprover,
    M3ApprovalGate,
    approval_action_set_digest,
    approval_delegation_digest,
)
from v4_planning.material_provider import DenyAllMaterialProvider
from v4_planning.policy import M3PlanPolicy, PlanPolicyDecision, PlanPolicyDenied
from v4_planning.product_adapter import DenyAllProductAdapter, ProductDispatchDenied
from v4_planning.store import InMemoryProtectedPlanningStore, ProtectedStoreError
from v4_planning.workflow_service import WorkflowRecordUnavailable
from v4_planning.persistence import PersistentProtectedPlanningStore
from test_v4_planning import (
    _access_draft, _absent_projections, _expected_projections,
    _interaction as _engine_interaction,
)
from test_v4_planning_recovery import _persistent_store, _service as _recovery_service


NOW = 1_800_000_000


class Issuer:
    def __init__(self) -> None:
        self._counter = 0

    def issue(self, purpose: str) -> str:
        self._counter += 1
        return f"{purpose}-ref-{self._counter:08d}"


class ExactApproverAuthority:
    authority_ref = "approver-authority-ref01"

    def __init__(self, *, tamper_field: str | None = None) -> None:
        self.tamper_field = tamper_field
        self.calls = 0

    def authorize(
        self,
        plan: PreparedPlan,
        decision: PlanPolicyDecision,
        requester: AuthenticatedRequester,
        approver: AuthenticatedApprover,
        *,
        now_epoch: int,
    ) -> ApproverAuthorizationDecision:
        self.calls += 1
        assert requester.identity_digest is not None
        assert approver.identity_digest is not None
        assert approver.identity_authority_ref is not None
        assert approver.subject_namespace is not None
        values = {
            "action_set_digest": approval_action_set_digest(plan),
            "approval_class": decision.approval_class,
            "approver_digest": approver.digest,
            "approver_identity_digest": approver.identity_digest,
            "authority_ref": self.authority_ref,
            "authorization_ref": "approver-authorization-ref01",
            "authorized": True,
            "checked_at": now_epoch,
            "delegated_role": "independent_approver",
            "delegation_digest": approval_delegation_digest(
                plan,
                decision,
                approver,
            ),
            "environment_digest": canonical_digest(plan.environment_ref),
            "execution_authorized": False,
            "executor_separation_required": True,
            "expires_at": min(decision.expires_at, now_epoch + 90),
            "identity_authority_ref": approver.identity_authority_ref,
            "plan_digest": plan.plan_digest,
            "plan_ref": plan.plan_ref,
            "policy_decision_digest": decision.decision_digest,
            "policy_decision_ref": decision.decision_ref,
            "policy_version": decision.policy_version,
            "requester_digest": requester.digest,
            "requester_identity_digest": requester.identity_digest,
            "scope_digest": canonical_digest(plan.scope_ref),
            "separation_required": True,
            "subject_namespace": approver.subject_namespace,
        }
        if self.tamper_field == "scope":
            values["scope_digest"] = "0" * 64
        elif self.tamper_field == "policy":
            values["policy_version"] = "9.9.9"
        elif self.tamper_field == "action":
            values["action_set_digest"] = "0" * 64
        elif self.tamper_field == "expiry":
            values["expires_at"] = decision.expires_at + 1
        return ApproverAuthorizationDecision(
            **values,  # type: ignore[arg-type]
            authorization_digest=canonical_digest(values),  # type: ignore[arg-type]
        )


class StaticPlanningEngine:
    """Return one exact record chain without adding product authority."""

    def __init__(
        self,
        summary: FinalIntentSummary,
        confirmation: ConfirmationRecord,
        plan: PreparedPlan,
    ) -> None:
        self.summary = summary
        self.confirmation = confirmation
        self.plan = plan

    def compile_summary(self, *args: object, **kwargs: object) -> FinalIntentSummary:
        del args, kwargs
        return self.summary

    def confirm_intent(self, *args: object, **kwargs: object) -> ConfirmationRecord:
        del args, kwargs
        return self.confirmation

    def prepare_plan(self, *args: object, **kwargs: object) -> PreparedPlan:
        del args, kwargs
        return self.plan

    def recover_awaiting_summary(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

    def recover_confirmed_chain(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

    def recover_prepared_chain(self, *args: object, **kwargs: object) -> None:
        del args, kwargs


def _requester() -> AuthenticatedRequester:
    return AuthenticatedRequester("operator-subject-0001", "operator")


def _summary(requester: AuthenticatedRequester) -> FinalIntentSummary:
    change = ObjectChange(
        object_ref="folder-object-ref0001",
        object_class=ObjectClass.PUBLIC_FOLDER,
        change_kind=ChangeKind.CREATE,
        current_fields=(("exists", False),),
        proposed_fields=(("enabled", True), ("owner_ref", "owner-object-ref0001")),
        expected_fields=(
            ("enabled", True),
            ("exists", True),
            ("owner_ref", "owner-object-ref0001"),
        ),
        current_projection_digest="a" * 64,
        expected_projection_digest="b" * 64,
        projection_contract_ref="projection-contract-ref1",
        projection_contract_version="1.0.0",
        projection_source_ref="projection-source-ref01",
        observed_at=NOW,
        fresh_until=NOW + 300,
    )
    values = {
        "summary_ref": "summary-record-ref0001",
        "revision": 1,
        "state": SummaryState.CONFIRMED,
        "requester_digest": requester.digest,
        "requester_class": "operator",
        "audience_ref": "audience-record-ref01",
        "scheme_id": SchemeId.ACCESS_DOMAIN,
        "scheme_version": "1.0.0",
        "registry_schema_version": "1.1.0",
        "blueprint_ref": "FPA-BP-004",
        "action_family_ref": "administrative-action-family",
        "action_family_version": "1.0.0",
        "environment_ref": "environment-record-ref01",
        "scope_ref": "scope-record-ref000001",
        "owner_ref": "owner-object-ref0001",
        "outcome_code": "establish_access_domain",
        "object_changes": (change,),
        "unchanged_boundary": ("c3_material_excluded",),
        "facts": ("evidence-record-ref001",),
        "assumptions": ("owner_relationship_prevalidated",),
        "excluded_scope": ("credential_material",),
        "verification_codes": ("acl_relation_readback",),
        "stop_codes": ("current_state_drift",),
        "evidence_policy": "redacted_contract_evidence",
        "maintenance_class": "none",
        "reversibility_class": "compensating_action_required",
        "unresolved_gaps": (),
        "risk_class": "high",
        "external_effects": ("access_scope_change",),
        "approval_class": "independent_approval",
        "separation_required": True,
        "reconciliation_strategy": "reconcile_or_manual",
        "material_reference_metadata": None,
        "reference_authority_ref": "reference-authority-ref01",
        "reference_authorization_digest": "c" * 64,
        "reference_authorization_expires_at": NOW + 300,
        "created_at": NOW,
        "expires_at": NOW + 240,
        "current_state_digest": "d" * 64,
        "proposed_changes_digest": "e" * 64,
        "expected_state_digest": "f" * 64,
    }
    content = {
        "action_family_ref": values["action_family_ref"],
        "action_family_version": values["action_family_version"],
        "approval_class": values["approval_class"],
        "assumptions": list(values["assumptions"]),
        "audience_ref": values["audience_ref"],
        "blueprint_ref": values["blueprint_ref"],
        "created_at": values["created_at"],
        "current_state_digest": values["current_state_digest"],
        "environment_ref": values["environment_ref"],
        "expected_state_digest": values["expected_state_digest"],
        "expires_at": values["expires_at"],
        "excluded_scope": list(values["excluded_scope"]),
        "external_effects": list(values["external_effects"]),
        "facts": list(values["facts"]),
        "evidence_policy": values["evidence_policy"],
        "material_reference_metadata": None,
        "object_changes": [change.as_dict()],
        "outcome_code": values["outcome_code"],
        "owner_ref": values["owner_ref"],
        "proposed_changes_digest": values["proposed_changes_digest"],
        "reconciliation_strategy": values["reconciliation_strategy"],
        "reference_authority_ref": values["reference_authority_ref"],
        "reference_authorization_digest": values["reference_authorization_digest"],
        "reference_authorization_expires_at": values[
            "reference_authorization_expires_at"
        ],
        "registry_schema_version": values["registry_schema_version"],
        "requester_class": values["requester_class"],
        "requester_digest": values["requester_digest"],
        "revision": values["revision"],
        "reversibility_class": values["reversibility_class"],
        "risk_class": values["risk_class"],
        "scheme_id": SchemeId.ACCESS_DOMAIN.value,
        "scheme_version": values["scheme_version"],
        "scope_ref": values["scope_ref"],
        "separation_required": values["separation_required"],
        "summary_ref": values["summary_ref"],
        "stop_codes": list(values["stop_codes"]),
        "unchanged_boundary": list(values["unchanged_boundary"]),
        "unresolved_gaps": list(values["unresolved_gaps"]),
        "verification_codes": list(values["verification_codes"]),
        "maintenance_class": values["maintenance_class"],
    }
    return FinalIntentSummary(**values, summary_digest=canonical_digest(content))  # type: ignore[arg-type]


def _confirmation(summary: FinalIntentSummary) -> ConfirmationRecord:
    values = {
        "confirmation_ref": "confirmation-record-ref1",
        "requester_digest": summary.requester_digest,
        "audience_ref": summary.audience_ref,
        "summary_ref": summary.summary_ref,
        "summary_revision": summary.revision,
        "summary_digest": summary.summary_digest,
        "interaction_ref_digest": "1" * 64,
        "interaction_type": "authenticated_human_confirmation",
        "nonce_digest": "2" * 64,
        "confirmed_at": NOW + 10,
        "expires_at": NOW + 220,
        "state": "confirmed",
    }
    return ConfirmationRecord(
        **values,
        record_digest=canonical_digest(values),  # type: ignore[arg-type]
    )


def _interaction(
    summary: FinalIntentSummary,
    requester: AuthenticatedRequester,
) -> VerifiedConfirmationInteraction:
    return VerifiedConfirmationInteraction(
        interaction_ref="human-interaction-ref01",
        interaction_type="authenticated_human_confirmation",
        nonce_digest="3" * 64,
        requester_digest=requester.digest,
        audience_ref=summary.audience_ref,
        summary_ref=summary.summary_ref,
        summary_revision=summary.revision,
        summary_digest=summary.summary_digest,
        decision="affirm",
        confirmed_at=NOW + 10,
        expires_at=NOW + 220,
    )


def _plan(
    requester: AuthenticatedRequester,
    summary: FinalIntentSummary | None = None,
    confirmation: ConfirmationRecord | None = None,
    *,
    plan_ref: str = "prepared-plan-ref0001",
) -> PreparedPlan:
    summary = summary or _summary(requester)
    confirmation = confirmation or _confirmation(summary)
    line = PlanLine(
        line_ref="prepared-line-ref0001",
        action_family_ref=summary.action_family_ref,
        action_family_version=summary.action_family_version,
        target_ref="folder-object-ref0001",
        target_class=ObjectClass.PUBLIC_FOLDER,
        change_kind=ChangeKind.CREATE,
        expected_current_digest="a" * 64,
        expected_state_digest="b" * 64,
        projection_contract_ref="projection-contract-ref1",
        depends_on=(),
    )
    values = {
        "plan_ref": plan_ref,
        "revision": 1,
        "state": PlanState.PREPARED_NON_EXECUTABLE,
        "summary_ref": summary.summary_ref,
        "summary_revision": summary.revision,
        "summary_digest": summary.summary_digest,
        "confirmation_ref": confirmation.confirmation_ref,
        "confirmation_digest": confirmation.record_digest,
        "requester_digest": requester.digest,
        "environment_ref": summary.environment_ref,
        "scope_ref": summary.scope_ref,
        "scheme_id": summary.scheme_id,
        "scheme_version": summary.scheme_version,
        "registry_schema_version": summary.registry_schema_version,
        "created_at": NOW + 20,
        "expires_at": NOW + 200,
        "lines": (line,),
        "dispatchable": False,
        "adapter_registry_bound": False,
        "planner_runtime_packaged": True,
        "planner_mcp_exposed": False,
        "executor_runtime_packaged": False,
        "executor_mcp_exposed": False,
    }
    content = {
        "adapter_registry_bound": False,
        "confirmation_digest": confirmation.record_digest,
        "confirmation_ref": confirmation.confirmation_ref,
        "created_at": NOW + 20,
        "dispatchable": False,
        "environment_ref": summary.environment_ref,
        "expires_at": NOW + 200,
        "lines": [line.as_dict()],
        "executor_mcp_exposed": False,
        "executor_runtime_packaged": False,
        "plan_ref": plan_ref,
        "planner_mcp_exposed": False,
        "planner_runtime_packaged": True,
        "registry_schema_version": summary.registry_schema_version,
        "requester_digest": requester.digest,
        "revision": 1,
        "scheme_id": summary.scheme_id.value,
        "scheme_version": summary.scheme_version,
        "scope_ref": summary.scope_ref,
        "summary_digest": summary.summary_digest,
        "summary_ref": summary.summary_ref,
        "summary_revision": summary.revision,
    }
    return PreparedPlan(**values, plan_digest=canonical_digest(content))


def test_protected_store_requires_exact_record_chain() -> None:
    requester = _requester()
    summary = _summary(requester)
    confirmation = _confirmation(summary)
    plan = _plan(requester, summary, confirmation)
    store = InMemoryProtectedPlanningStore()

    with pytest.raises(ProtectedStoreError, match="summary and confirmation"):
        store.put_plan(plan)
    store.put_summary(summary)
    store.put_confirmation(confirmation)
    store.put_plan(plan)

    assert store.get_summary(summary.summary_ref, 1) == summary
    assert store.get_confirmation(confirmation.confirmation_ref) == confirmation
    assert store.get_plan(plan.plan_ref) == plan


def test_policy_approval_and_claim_remain_plan_only() -> None:
    requester = _requester()
    plan = _plan(requester)
    issuer = Issuer()
    decision = M3PlanPolicy(issuer).evaluate(plan, requester, now_epoch=NOW + 30)
    gate = M3ApprovalGate(issuer)
    receipt = gate.approve(
        decision,
        AuthenticatedApprover("approver-subject-0001"),
        now_epoch=NOW + 40,
    )
    result = gate.claim_for_plan(receipt, plan, requester, now_epoch=NOW + 50)

    assert decision.execution_authorized is False
    assert receipt.execution_authorized is False
    assert result.approval_validated is True
    assert result.ready_for_dispatch is False
    assert result.execution_authorized is False
    assert result.blocker_codes == ("adapter_registry_unbound", "plan_non_dispatchable")
    with pytest.raises(ApprovalDenied, match="replayed"):
        gate.claim_for_plan(receipt, plan, requester, now_epoch=NOW + 60)


def test_independently_authenticated_approval_receipt_rejects_forgery() -> None:
    requester = _requester()
    plan = _plan(requester)
    issuer = Issuer()
    decision = M3PlanPolicy(issuer).evaluate(plan, requester, now_epoch=NOW + 30)
    authenticator = ApprovalReceiptAuthenticator(b"a" * 32)
    gate = M3ApprovalGate(issuer, receipt_authenticator=authenticator)
    receipt = gate.approve(
        decision,
        AuthenticatedApprover("approver-subject-0001"),
        now_epoch=NOW + 40,
    )

    assert receipt.authenticator_ref == authenticator.authority_ref
    assert receipt.receipt_mac == authenticator.mac(receipt.receipt_digest)
    with pytest.raises(PlanningContractError, match="authentication binding"):
        replace(receipt, receipt_mac=None)
    forged = replace(receipt, receipt_mac="0" * 64)
    with pytest.raises(ApprovalDenied, match="authenticity"):
        M3ApprovalGate(
            Issuer(),
            receipt_authenticator=authenticator,
        ).claim_for_plan(forged, plan, requester, now_epoch=NOW + 50)
    with pytest.raises(ApprovalDenied, match="unavailable"):
        M3ApprovalGate(Issuer()).claim_for_plan(
            receipt,
            plan,
            requester,
            now_epoch=NOW + 50,
        )

    result = gate.claim_for_plan(receipt, plan, requester, now_epoch=NOW + 50)
    assert result.approval_validated is True
    assert result.execution_authorized is False


def test_approver_authority_binds_exact_identity_delegation_and_receipt() -> None:
    requester = AuthenticatedRequester(
        "operator-subject-0001",
        "operator",
        identity_authority_ref="identity-authority-ref01",
        subject_namespace="workforce-namespace-v1",
    )
    approver = AuthenticatedApprover(
        "approver-subject-0001",
        identity_authority_ref="identity-authority-ref01",
        subject_namespace="workforce-namespace-v1",
    )
    plan = _plan(requester)
    issuer = Issuer()
    decision = M3PlanPolicy(issuer).evaluate(plan, requester, now_epoch=NOW + 30)
    authority = ExactApproverAuthority()
    authenticator = ApprovalReceiptAuthenticator(b"a" * 32)
    gate = M3ApprovalGate(
        issuer,
        receipt_authenticator=authenticator,
        approver_authorizer=authority,
    )

    receipt = gate.approve(
        decision,
        approver,
        now_epoch=NOW + 40,
        plan=plan,
        requester=requester,
    )

    assert authority.calls == 1
    assert receipt.approver_authority_ref == authority.authority_ref
    assert receipt.approver_authorization_digest is not None
    assert receipt.approval_nonce_digest is not None
    assert receipt.policy_version == decision.policy_version
    assert receipt.authenticator_ref == authenticator.authority_ref
    assert authenticator.verify(receipt) is True
    assert receipt.execution_authorized is False
    with pytest.raises(PlanningContractError, match="binding is incomplete"):
        replace(receipt, approval_nonce_digest=None)


def test_approver_authority_requires_signed_receipt_and_exact_context() -> None:
    requester = AuthenticatedRequester(
        "operator-subject-0001",
        "operator",
        identity_authority_ref="identity-authority-ref01",
        subject_namespace="workforce-namespace-v1",
    )
    approver = AuthenticatedApprover(
        "approver-subject-0001",
        identity_authority_ref="identity-authority-ref01",
        subject_namespace="workforce-namespace-v1",
    )
    plan = _plan(requester)
    issuer = Issuer()
    decision = M3PlanPolicy(issuer).evaluate(plan, requester, now_epoch=NOW + 30)
    authority = ExactApproverAuthority()

    with pytest.raises(PlanningContractError, match="receipt authenticator"):
        M3ApprovalGate(issuer, approver_authorizer=authority)
    gate = M3ApprovalGate(
        issuer,
        receipt_authenticator=ApprovalReceiptAuthenticator(b"b" * 32),
        approver_authorizer=authority,
    )
    with pytest.raises(ApprovalDenied, match="context is unavailable"):
        gate.approve(decision, approver, now_epoch=NOW + 40)


@pytest.mark.parametrize(
    "tamper_field",
    ["scope", "policy", "action", "expiry"],
)
def test_approver_authority_rejects_widened_or_stale_delegation(
    tamper_field: str,
) -> None:
    requester = AuthenticatedRequester(
        "operator-subject-0001",
        "operator",
        identity_authority_ref="identity-authority-ref01",
        subject_namespace="workforce-namespace-v1",
    )
    approver = AuthenticatedApprover(
        "approver-subject-0001",
        identity_authority_ref="identity-authority-ref01",
        subject_namespace="workforce-namespace-v1",
    )
    plan = _plan(requester)
    issuer = Issuer()
    decision = M3PlanPolicy(issuer).evaluate(plan, requester, now_epoch=NOW + 30)
    gate = M3ApprovalGate(
        issuer,
        receipt_authenticator=ApprovalReceiptAuthenticator(b"c" * 32),
        approver_authorizer=ExactApproverAuthority(tamper_field=tamper_field),
    )

    with pytest.raises(ApprovalDenied, match="decision is not exact"):
        gate.approve(
            decision,
            approver,
            now_epoch=NOW + 40,
            plan=plan,
            requester=requester,
        )


def test_approver_authority_requires_comparable_identity_namespace() -> None:
    requester = AuthenticatedRequester(
        "operator-subject-0001",
        "operator",
        identity_authority_ref="identity-authority-ref01",
        subject_namespace="workforce-namespace-v1",
    )
    approver = AuthenticatedApprover(
        "approver-subject-0001",
        identity_authority_ref="other-identity-authority",
        subject_namespace="workforce-namespace-v1",
    )
    plan = _plan(requester)
    issuer = Issuer()
    decision = M3PlanPolicy(issuer).evaluate(plan, requester, now_epoch=NOW + 30)
    gate = M3ApprovalGate(
        issuer,
        receipt_authenticator=ApprovalReceiptAuthenticator(b"d" * 32),
        approver_authorizer=ExactApproverAuthority(),
    )

    with pytest.raises(ApprovalDenied, match="Comparable"):
        gate.approve(
            decision,
            approver,
            now_epoch=NOW + 40,
            plan=plan,
            requester=requester,
        )


def test_approval_rejects_same_human_even_with_approver_role() -> None:
    requester = _requester()
    issuer = Issuer()
    plan = _plan(requester)
    decision = M3PlanPolicy(issuer).evaluate(plan, requester, now_epoch=NOW + 30)

    with pytest.raises(ApprovalDenied, match="separation"):
        M3ApprovalGate(issuer).approve(
            decision,
            AuthenticatedApprover(requester.subject_ref),
            now_epoch=NOW + 40,
        )


def test_policy_and_receipt_are_bound_to_exact_plan_digest() -> None:
    requester = _requester()
    issuer = Issuer()
    plan = _plan(requester)
    other_plan = _plan(requester, plan_ref="prepared-plan-ref0002")
    decision = M3PlanPolicy(issuer).evaluate(plan, requester, now_epoch=NOW + 30)
    gate = M3ApprovalGate(issuer)
    receipt = gate.approve(
        decision,
        AuthenticatedApprover("approver-subject-0001"),
        now_epoch=NOW + 40,
    )

    with pytest.raises(ApprovalDenied, match="exact active plan"):
        gate.claim_for_plan(receipt, other_plan, requester, now_epoch=NOW + 50)
    with pytest.raises(PlanPolicyDenied, match="Requester"):
        M3PlanPolicy(issuer).evaluate(
            plan,
            AuthenticatedRequester("operator-subject-0002", "operator"),
            now_epoch=NOW + 30,
        )


def test_m3_material_and_product_adapters_deny_all() -> None:
    assert not hasattr(DenyAllMaterialProvider(), "acquire")
    with pytest.raises(ProductDispatchDenied):
        DenyAllProductAdapter().dispatch(_plan(_requester()))


def test_plan_only_workflow_service_enforces_the_complete_record_chain() -> None:
    requester = _requester()
    summary = _summary(requester)
    confirmation = _confirmation(summary)
    plan = _plan(requester, summary, confirmation)
    issuer = Issuer()
    authenticator = ApprovalReceiptAuthenticator(b"b" * 32)
    service = M3PlanOnlyWorkflowService(
        cast(
            M2PlanningEngine,
            StaticPlanningEngine(summary, confirmation, plan),
        ),
        InMemoryProtectedPlanningStore(
            clock=lambda: NOW + 50,
            approval_receipt_authenticator=authenticator,
        ),
        M3PlanPolicy(issuer),
        M3ApprovalGate(issuer, receipt_authenticator=authenticator),
    )

    stored_summary = service.compile_summary(
        cast(SchemeDraft, object()),
        requester,
        (),
        now_epoch=NOW,
    )
    stored_confirmation = service.confirm_intent(
        summary.summary_ref,
        requester,
        _interaction(summary, requester),
        now_epoch=NOW + 10,
    )
    stored_plan = service.prepare_plan(
        summary.summary_ref,
        confirmation.confirmation_ref,
        requester,
        now_epoch=NOW + 20,
    )
    resolved_plan = service.resolve_prepared_plan(
        plan.plan_ref,
        requester,
        now_epoch=NOW + 25,
    )
    decision = service.request_approval(
        plan.plan_ref,
        requester,
        now_epoch=NOW + 30,
    )
    receipt = service.approve(
        decision.decision_ref,
        AuthenticatedApprover("approver-subject-0001"),
        now_epoch=NOW + 40,
    )
    result = service.claim_approval(
        receipt.receipt_ref,
        plan.plan_ref,
        requester,
    )

    assert stored_summary == summary
    assert stored_confirmation == confirmation
    assert stored_plan == plan
    assert resolved_plan == plan
    assert receipt.receipt_mac is not None
    assert result.approval_validated is True
    assert result.ready_for_dispatch is False
    assert result.execution_authorized is False
    assert result.blocker_codes == ("adapter_registry_unbound", "plan_non_dispatchable")


def _cold_comparison_service(tmp_path: Path) -> tuple[
    M3PlanOnlyWorkflowService, M3PlanOnlyWorkflowService, SchemeDraft, PreparedPlan,
]:
    store = _persistent_store(tmp_path)
    first = _recovery_service(store)
    draft, requester = _access_draft(), _requester()
    projections = _absent_projections(first._planning_engine, draft)
    summary = first.compile_summary(draft, requester, projections, now_epoch=NOW)
    confirmation = first.confirm_intent(summary.summary_ref, requester,
                                       _engine_interaction(summary, requester), now_epoch=NOW + 1)
    plan = first.prepare_plan(summary.summary_ref, confirmation.confirmation_ref,
                              requester, now_epoch=NOW + 2)
    cold = _recovery_service(PersistentProtectedPlanningStore(
        store._path, store._key_path, clock=lambda: NOW + 10,
    ))
    return first, cold, draft, plan


def test_resolve_persisted_plan_recovers_cold_engine_for_timed_pre_and_post_comparison(tmp_path: Path) -> None:
    first, cold, draft, plan = _cold_comparison_service(tmp_path)
    current = _absent_projections(cold._planning_engine, draft)
    assert first.evaluate_pre_write(plan.plan_ref, current, now_epoch=NOW + 3).status is PreWriteStatus.MATCH
    assert cold._planning_engine._plans == {}
    assert cold.resolve_prepared_plan(plan.plan_ref, _requester(), now_epoch=NOW + 3) == plan
    # Recovery does not carry a previous process's pre-write match or confer
    # dispatch authority. A fresh match in this engine remains mandatory.
    expected = _expected_projections(cold._planning_engine, draft, observed_at=NOW + 4)
    unknown = cold.evaluate_post_write(plan.plan_ref, expected, now_epoch=NOW + 4)
    assert unknown.status is PostWriteStatus.COMPARISON_UNKNOWN
    assert unknown.reason_codes == ("prewrite_match_not_established",)
    with pytest.raises(PlanningDenied, match="time cannot move backwards"):
        cold.evaluate_pre_write(plan.plan_ref, current, now_epoch=NOW + 1)
    assert cold.evaluate_pre_write(plan.plan_ref, current, now_epoch=NOW + 5).status is PreWriteStatus.MATCH
    # The action resolver is used again for post-write; re-resolution must not
    # erase comparison timestamps or allow a backwards comparison.
    assert cold.resolve_prepared_plan(plan.plan_ref, _requester(), now_epoch=NOW + 5) == plan
    with pytest.raises(PlanningDenied, match="time cannot move backwards"):
        cold.evaluate_pre_write(plan.plan_ref, current, now_epoch=NOW + 4)
    with pytest.raises(PlanningDenied, match="cannot precede"):
        cold.evaluate_post_write(plan.plan_ref, expected, now_epoch=NOW + 4)
    post = cold.evaluate_post_write(plan.plan_ref, expected, now_epoch=NOW + 6)
    assert post.status is PostWriteStatus.EXPECTED_STATE_MATCHES
    assert post.mutation_observed is False and post.operational_success is False
    assert plan.dispatchable is plan.adapter_registry_bound is plan.executor_runtime_packaged is False


@pytest.mark.parametrize("rejection", ["actor", "expiry", "backwards", "summary", "confirmation", "plan"])
def test_cold_resolve_rejects_actor_expiry_time_reversal_and_tampering_before_recovery(tmp_path: Path, rejection: str) -> None:
    _first, cold, _draft, plan = _cold_comparison_service(tmp_path)
    requester, now = _requester(), NOW + 3
    if rejection == "actor":
        requester = replace(requester, subject_ref="foreign-operator-subject01")
    elif rejection == "expiry":
        now = plan.expires_at
    elif rejection == "backwards":
        now = plan.created_at - 1
    else:
        # Corrupt each persisted record without changing its protected HMAC.
        sequence = {"summary": 1, "confirmation": 2, "plan": 3}[rejection]
        with sqlite3.connect(cold._store._path) as database:
            database.execute("UPDATE planning_records SET payload_json = '{}' WHERE sequence = ?", (sequence,))
    with pytest.raises(WorkflowRecordUnavailable):
        cold.resolve_prepared_plan(plan.plan_ref, requester, now_epoch=now)
    assert cold._planning_engine._summaries == {}
    assert cold._planning_engine._confirmations == {}
    assert cold._planning_engine._plans == {}


def test_prewrite_invalidation_append_failure_is_not_returned_as_success() -> None:
    requester = _requester()
    summary = _summary(requester)
    confirmation = _confirmation(summary)
    plan = _plan(requester, summary, confirmation)

    class FailingInvalidationStore(InMemoryProtectedPlanningStore):
        def invalidate_plan(self, plan_ref, *, evaluated_at, reason_codes):
            raise ProtectedStoreError("injected invalidation append failure")

    store = FailingInvalidationStore()
    store.put_summary(summary)
    store.put_confirmation(confirmation)
    store.put_plan(plan)
    evaluation = PreWriteEvaluation(plan_ref=plan.plan_ref, status=PreWriteStatus.INVALIDATED,
        reason_codes=("current_state_drift",), evaluated_at=NOW + 30,
        observed_state_digest="a" * 64)
    engine = cast(M2PlanningEngine, SimpleNamespace(evaluate_pre_write=lambda *args, **kwargs: evaluation))
    service = M3PlanOnlyWorkflowService(engine, store, M3PlanPolicy(Issuer()), M3ApprovalGate(Issuer()))
    with pytest.raises(ProtectedStoreError, match="injected invalidation append failure"):
        service.evaluate_pre_write(plan.plan_ref, (), now_epoch=NOW + 30)


def test_plan_only_workflow_service_rejects_unissued_transition_references() -> None:
    requester = _requester()
    summary = _summary(requester)
    confirmation = _confirmation(summary)
    plan = _plan(requester, summary, confirmation)
    issuer = Issuer()
    service = M3PlanOnlyWorkflowService(
        cast(
            M2PlanningEngine,
            StaticPlanningEngine(summary, confirmation, plan),
        ),
        InMemoryProtectedPlanningStore(clock=lambda: NOW + 50),
        M3PlanPolicy(issuer),
        M3ApprovalGate(issuer),
    )

    with pytest.raises(WorkflowRecordUnavailable, match="Summary"):
        service.confirm_intent(
            summary.summary_ref,
            requester,
            _interaction(summary, requester),
            now_epoch=NOW + 10,
        )
    with pytest.raises(WorkflowRecordUnavailable, match="Prepared plan"):
        service.request_approval(
            plan.plan_ref,
            requester,
            now_epoch=NOW + 30,
        )
    with pytest.raises(WorkflowRecordUnavailable, match="decision"):
        service.approve(
            "unissued-policy-decision-ref1",
            AuthenticatedApprover("approver-subject-0001"),
            now_epoch=NOW + 40,
        )
    with pytest.raises(WorkflowRecordUnavailable, match="receipt"):
        service.claim_approval(
            "unissued-approval-receipt-ref1",
            plan.plan_ref,
            requester,
        )
