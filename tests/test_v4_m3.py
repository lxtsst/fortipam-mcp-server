from __future__ import annotations

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
    PreparedPlan,
    SchemeId,
    SummaryState,
    canonical_digest,
)
from v4_planning.approval import (
    ApprovalDenied,
    AuthenticatedApprover,
    M3ApprovalGate,
)
from v4_planning.material_provider import DenyAllMaterialProvider, MaterialAccessDenied
from v4_planning.policy import M3PlanPolicy, PlanPolicyDenied
from v4_planning.product_adapter import DenyAllProductAdapter, ProductDispatchDenied
from v4_planning.store import InMemoryProtectedPlanningStore, ProtectedStoreError


NOW = 1_800_000_000


class Issuer:
    def __init__(self) -> None:
        self._counter = 0

    def issue(self, purpose: str) -> str:
        self._counter += 1
        return f"{purpose}-ref-{self._counter:08d}"


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
        "runtime_packaged": False,
        "mcp_exposed": False,
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
        "mcp_exposed": False,
        "plan_ref": plan_ref,
        "registry_schema_version": summary.registry_schema_version,
        "requester_digest": requester.digest,
        "revision": 1,
        "runtime_packaged": False,
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
    with pytest.raises(MaterialAccessDenied):
        DenyAllMaterialProvider().acquire("material-record-ref01", purpose="onboarding")
    with pytest.raises(ProductDispatchDenied):
        DenyAllProductAdapter().dispatch(_plan(_requester()))
