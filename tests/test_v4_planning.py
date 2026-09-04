from __future__ import annotations

import copy
from dataclasses import asdict, replace
import json
from pathlib import Path
from typing import cast

import pytest

import v4_planning
from scripts.v4_registry import load_registry, validate_registry
from v4_planning import (
    AuthenticatedRequester,
    AuthoritativeProjection,
    ChangeKind,
    DesiredObject,
    M2PlanningEngine,
    MaterialReferenceMetadata,
    ObjectClass,
    PlanningContractError,
    PlanningDenied,
    PostWriteStatus,
    PreWriteStatus,
    SchemeDraft,
    SchemeId,
    VerifiedConfirmationInteraction,
    VerifiedReferenceDecision,
    canonical_digest,
    canonical_json,
)


NOW = 1_800_000_000
PROJECT_ROOT = Path(__file__).resolve().parents[1]


class Issuer:
    def __init__(self) -> None:
        self._counter = 0

    def issue(self, purpose: str) -> str:
        self._counter += 1
        return f"{purpose}-ref-{self._counter:08d}"


class DuplicateIssuer:
    def issue(self, purpose: str) -> str:
        del purpose
        return "duplicate-issued-ref01"


def _promoted_registry() -> dict[str, object]:
    registry = copy.deepcopy(load_registry())
    for scheme in registry["schemes"]:  # type: ignore[index]
        if scheme["id"] in {"AccessDomainScheme", "SecretOnboardingScheme"}:
            scheme["status"] = "planned"
            scheme["maturity"] = "contract_tested"
            scheme["lifecycle"] = "contract_tested"
            scheme["implementation_evidence"]["evidence_status"] = "contract_tested"
    validate_registry(registry)
    return registry


def _requester(suffix: str = "alpha") -> AuthenticatedRequester:
    return AuthenticatedRequester(f"operator-subject-{suffix}", "operator")


def _desired(
    object_ref: str,
    object_class: ObjectClass,
    values: dict[str, bool | str],
    *,
    exists: bool = True,
) -> DesiredObject:
    return DesiredObject(
        object_ref=object_ref,
        object_class=object_class,
        desired_exists=exists,
        desired_fields=tuple(sorted(values.items())),
    )


def _access_draft(*, gaps: tuple[str, ...] = ()) -> SchemeDraft:
    return SchemeDraft(
        scheme_id=SchemeId.ACCESS_DOMAIN,
        scheme_version="1.0.0",
        registry_schema_version="1.1.0",
        blueprint_ref="FPA-BP-004",
        environment_ref="environment-ref-lab01",
        scope_ref="scope-ref-access01",
        owner_ref="owner-ref-team0001",
        audience_ref="audience-ref-admin01",
        outcome_code="establish_access_domain",
        desired_objects=(
            _desired(
                "folder-relation-ref01",
                ObjectClass.PUBLIC_FOLDER,
                {"enabled": True, "owner_ref": "owner-ref-team0001"},
            ),
            _desired(
                "grant-relation-ref001",
                ObjectClass.ACCESS_GRANT,
                {
                    "permission": "use",
                    "subject_class": "group",
                    "subject_ref": "group-relation-ref01",
                },
            ),
        ),
        approval_class="independent_approval",
        separation_required=True,
        risk_class="high",
        external_effects=("access_scope_change",),
        assumption_codes=("owner_relationship_prevalidated",),
        excluded_scope_codes=("credential_material", "runtime_execution"),
        verification_codes=("acl_relation_readback", "negative_access_check"),
        stop_codes=("current_state_drift", "projection_unavailable"),
        evidence_policy="redacted_contract_evidence",
        maintenance_class="none",
        reversibility_class="compensating_action_required",
        evidence_refs=("evidence-ref-access01",),
        unresolved_gap_codes=gaps,
        reconciliation_strategy="reconcile_or_manual",
        summary_ttl_seconds=300,
    )


def _secret_draft() -> SchemeDraft:
    return SchemeDraft(
        scheme_id=SchemeId.SECRET_ONBOARDING,
        scheme_version="1.0.0",
        registry_schema_version="1.1.0",
        blueprint_ref="FPA-BP-005",
        environment_ref="environment-ref-lab01",
        scope_ref="scope-ref-secret01",
        owner_ref="owner-ref-team0001",
        audience_ref="audience-ref-admin01",
        outcome_code="onboard_privileged_resource",
        desired_objects=(
            _desired(
                "folder-binding-ref01",
                ObjectClass.FOLDER_BINDING,
                {"folder_ref": "approved-folder-ref01"},
            ),
            _desired(
                "target-relation-ref01",
                ObjectClass.TARGET,
                {
                    "connectivity_profile_ref": "connectivity-profile01",
                    "protocol": "ssh",
                },
            ),
            _desired(
                "template-binding-ref1",
                ObjectClass.TEMPLATE_BINDING,
                {"compatibility": "compatible", "template_ref": "template-approved-ref1"},
            ),
            _desired(
                "secret-metadata-ref01",
                ObjectClass.SECRET_METADATA,
                {
                    "account_type": "local",
                    "enabled": True,
                    "lifecycle_class": "managed",
                },
            ),
            _desired(
                "launcher-binding-ref1",
                ObjectClass.LAUNCHER_BINDING,
                {"launcher_profile_ref": "launcher-profile-ref1"},
            ),
        ),
        approval_class="independent_approval",
        separation_required=True,
        risk_class="high",
        external_effects=("privileged_access_metadata_change",),
        assumption_codes=("folder_relationship_prevalidated",),
        excluded_scope_codes=("credential_material", "session_launch"),
        verification_codes=("association_readback", "launch_readiness_metadata"),
        stop_codes=("current_state_drift", "material_unavailable"),
        evidence_policy="redacted_contract_evidence",
        maintenance_class="maintenance_window_required",
        reversibility_class="manual_reconciliation_only",
        evidence_refs=("evidence-ref-secret01",),
        unresolved_gap_codes=(),
        reconciliation_strategy="reconcile_or_manual",
        summary_ttl_seconds=300,
        material_reference_metadata=MaterialReferenceMetadata(
            provider_class="external_vault_lease",
            purpose="initial_onboarding",
            lifecycle="available",
        ),
    )


_OBJECT_KIND = {
    ObjectClass.PUBLIC_FOLDER: "public_folder",
    ObjectClass.ACCESS_GRANT: "access_grant",
    ObjectClass.CLASSIFICATION_BINDING: "classification_binding",
    ObjectClass.FOLDER_POLICY_BINDING: "folder_policy_binding",
    ObjectClass.FOLDER_BINDING: "folder_binding",
    ObjectClass.TARGET: "target",
    ObjectClass.TEMPLATE_BINDING: "template_binding",
    ObjectClass.SECRET_METADATA: "secret_metadata",
    ObjectClass.LAUNCHER_BINDING: "launcher_binding",
    ObjectClass.POLICY_BINDING: "policy_binding",
}


class Authorizer:
    authority_ref = "m2-fake-reference-authority"

    def __init__(self, drafts: tuple[SchemeDraft, ...]) -> None:
        self._grants: set[tuple[str, str]] = {
            ("m2-fake-projection-source", "projection_source")
        }
        for draft in drafts:
            self._grants.update(
                {
                    (draft.environment_ref, "environment"),
                    (draft.scope_ref, "scope"),
                    (draft.owner_ref, "owner"),
                    (draft.audience_ref, "audience"),
                    *((reference, "evidence") for reference in draft.evidence_refs),
                }
            )
            for desired in draft.desired_objects:
                self._grants.add(
                    (desired.object_ref, f"object_{_OBJECT_KIND[desired.object_class]}")
                )
                self._grants.update(
                    (value, f"field_{field}")
                    for field, value in desired.desired_fields
                    if field.endswith("_ref") and type(value) is str
                )

    def authorize(
        self,
        reference: str,
        *,
        reference_kind: str,
        requester_digest: str,
        environment_ref: str,
        scope_ref: str,
        now_epoch: int,
    ) -> VerifiedReferenceDecision:
        return VerifiedReferenceDecision(
            reference_digest=canonical_digest(reference),
            reference_kind=reference_kind,
            authority_ref=self.authority_ref,
            requester_digest=requester_digest,
            environment_digest=canonical_digest(environment_ref),
            scope_digest=canonical_digest(scope_ref),
            authorized=(reference, reference_kind) in self._grants,
            checked_at=now_epoch,
            expires_at=now_epoch + 300,
        )


class TamperedAuthorizer(Authorizer):
    def __init__(self, drafts: tuple[SchemeDraft, ...], mode: str) -> None:
        super().__init__(drafts)
        self.mode = mode

    def authorize(self, reference: str, **kwargs: object) -> VerifiedReferenceDecision:
        decision = super().authorize(reference, **kwargs)  # type: ignore[arg-type]
        if self.mode == "reference_kind":
            return replace(decision, reference_kind="wrong_kind")
        if self.mode == "authority_ref":
            return replace(decision, authority_ref="untrusted-reference-authority")
        if self.mode == "requester_digest":
            return replace(decision, requester_digest="0" * 64)
        if self.mode == "environment_digest":
            return replace(decision, environment_digest="0" * 64)
        if self.mode == "scope_digest":
            return replace(decision, scope_digest="0" * 64)
        if self.mode == "reference_digest":
            return replace(decision, reference_digest="0" * 64)
        if self.mode == "expired":
            now_epoch = cast(int, kwargs["now_epoch"])
            return replace(
                decision,
                checked_at=now_epoch - 2,
                expires_at=now_epoch - 1,
            )
        raise AssertionError(f"Unsupported tamper mode: {self.mode}")


class StatefulAuthorizer(Authorizer):
    def __init__(self, drafts: tuple[SchemeDraft, ...], ttl_seconds: int = 300) -> None:
        super().__init__(drafts)
        self.ttl_seconds = ttl_seconds
        self.revoked = False

    def authorize(self, reference: str, **kwargs: object) -> VerifiedReferenceDecision:
        decision = super().authorize(reference, **kwargs)  # type: ignore[arg-type]
        now_epoch = cast(int, kwargs["now_epoch"])
        return replace(
            decision,
            authorized=decision.authorized and not self.revoked,
            expires_at=now_epoch + self.ttl_seconds,
        )


def _engine(
    *drafts: SchemeDraft,
    issuer: Issuer | DuplicateIssuer | None = None,
) -> M2PlanningEngine:
    profiles = drafts or (_access_draft(), _secret_draft())
    return M2PlanningEngine(
        _promoted_registry(),
        issuer or Issuer(),
        Authorizer(profiles),
    )


def _projection(
    engine: M2PlanningEngine,
    scheme_id: SchemeId,
    desired: DesiredObject,
    values: dict[str, bool | str],
    *,
    observed_at: int = NOW - 10,
    fresh_until: int = NOW + 100,
    **flags: bool,
) -> AuthoritativeProjection:
    return AuthoritativeProjection.from_mapping(
        contract=engine.projection_contract(scheme_id, desired.object_class),
        object_ref=desired.object_ref,
        observed_at=observed_at,
        fresh_until=fresh_until,
        fields=values,
        **flags,
    )


def _absent_projections(engine: M2PlanningEngine, draft: SchemeDraft) -> list[AuthoritativeProjection]:
    return [
        _projection(engine, draft.scheme_id, desired, {"exists": False})
        for desired in draft.desired_objects
    ]


def _expected_projections(
    engine: M2PlanningEngine,
    draft: SchemeDraft,
    *,
    observed_at: int = NOW + 3,
) -> list[AuthoritativeProjection]:
    return [
        _projection(
            engine,
            draft.scheme_id,
            desired,
            {"exists": desired.desired_exists, **dict(desired.desired_fields)},
            observed_at=observed_at,
            fresh_until=observed_at + 100,
        )
        for desired in draft.desired_objects
    ]


def _interaction(
    summary: v4_planning.FinalIntentSummary,
    requester: AuthenticatedRequester,
    *,
    nonce: str = "nonce-alpha",
    decision: str = "affirm",
) -> VerifiedConfirmationInteraction:
    return VerifiedConfirmationInteraction(
        interaction_ref="interaction-ref-0001",
        interaction_type="authenticated_human_confirmation",
        nonce_digest=canonical_digest(nonce),
        requester_digest=requester.digest,
        audience_ref=summary.audience_ref,
        summary_ref=summary.summary_ref,
        summary_revision=summary.revision,
        summary_digest=summary.summary_digest,
        decision=decision,
        confirmed_at=NOW + 1,
        expires_at=NOW + 200,
    )


def _confirmed_plan(
    draft: SchemeDraft,
) -> tuple[
    M2PlanningEngine,
    AuthenticatedRequester,
    v4_planning.FinalIntentSummary,
    v4_planning.PreparedPlan,
    list[AuthoritativeProjection],
]:
    engine = _engine()
    requester = _requester()
    current = _absent_projections(engine, draft)
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
    return engine, requester, summary, plan, current


@pytest.mark.parametrize("draft", [_access_draft(), _secret_draft()])
def test_m2_compiles_confirmed_non_executable_plan_for_two_schemes(draft: SchemeDraft) -> None:
    engine, _requester_value, summary, plan, current = _confirmed_plan(draft)

    assert summary.as_dict()["state"] == "awaiting_confirmation"
    assert summary.current_state_digest
    assert summary.proposed_changes_digest
    assert summary.expected_state_digest
    assert summary.outcome_code
    assert summary.excluded_scope
    assert summary.verification_codes
    assert summary.stop_codes
    assert plan.state.value == "prepared_non_executable"
    assert plan.dispatchable is False
    assert plan.adapter_registry_bound is False
    assert plan.runtime_packaged is False
    assert plan.mcp_exposed is False
    assert all(line.dispatchable is False and line.adapter == "none" for line in plan.lines)

    reread = [
        AuthoritativeProjection.from_mapping(
            contract=item.contract,
            object_ref=item.object_ref,
            observed_at=NOW + 2,
            fresh_until=NOW + 102,
            fields=item.values,
        )
        for item in current
    ]
    prewrite = engine.evaluate_pre_write(plan.plan_ref, reread, now_epoch=NOW + 3)
    assert prewrite.status is PreWriteStatus.MATCH
    postwrite = engine.evaluate_post_write(
        plan.plan_ref,
        _expected_projections(engine, draft),
        now_epoch=NOW + 4,
    )
    assert postwrite.status is PostWriteStatus.EXPECTED_STATE_MATCHES
    assert postwrite.mutation_observed is False
    assert postwrite.operational_success is False


def test_access_domain_plan_has_folder_before_grant_dependency() -> None:
    _engine, _requester_value, _summary, plan, _current = _confirmed_plan(_access_draft())
    folder = next(line for line in plan.lines if line.target_class is ObjectClass.PUBLIC_FOLDER)
    grant = next(line for line in plan.lines if line.target_class is ObjectClass.ACCESS_GRANT)
    assert grant.depends_on == (folder.line_ref,)


def test_secret_plan_has_bounded_dependency_dag() -> None:
    _engine, _requester_value, _summary, plan, _current = _confirmed_plan(_secret_draft())
    secret = next(line for line in plan.lines if line.target_class is ObjectClass.SECRET_METADATA)
    launch = next(line for line in plan.lines if line.target_class is ObjectClass.LAUNCHER_BINDING)
    assert len(plan.lines) == 5
    assert len(secret.depends_on) == 3
    assert launch.depends_on == (secret.line_ref,)


def test_summary_digest_is_deterministic_for_same_server_refs_and_time() -> None:
    draft = _access_draft()
    requester = _requester()
    one = _engine()
    two = _engine()
    summary_one = one.compile_summary(draft, requester, _absent_projections(one, draft), now_epoch=NOW)
    summary_two = two.compile_summary(draft, requester, _absent_projections(two, draft), now_epoch=NOW)
    assert summary_one.as_dict() == summary_two.as_dict()


def test_canonical_json_normalizes_unicode_and_rejects_control_text() -> None:
    assert canonical_json({"value": "e\u0301"}) == canonical_json({"value": "é"})
    with pytest.raises(v4_planning.CanonicalValueError):
        canonical_json({"value": "unsafe\u0000text"})


def test_automation_principal_cannot_replace_authenticated_human_requester() -> None:
    with pytest.raises(PlanningContractError, match="human operator"):
        AuthenticatedRequester("automation-subject-ref01", "automation")


def test_unknown_projection_fields_and_unsafe_evidence_fail_closed() -> None:
    engine = _engine()
    draft = _access_draft()
    desired = draft.desired_objects[0]
    contract = engine.projection_contract(draft.scheme_id, desired.object_class)
    with pytest.raises(PlanningContractError, match="undeclared field"):
        AuthoritativeProjection.from_mapping(
            contract=contract,
            object_ref=desired.object_ref,
            observed_at=NOW - 1,
            fresh_until=NOW + 100,
            fields={"exists": False, "password": "not-allowed"},
        )
    unsafe = _absent_projections(engine, draft)
    unsafe[0] = _projection(
        engine,
        draft.scheme_id,
        desired,
        {"exists": False},
        c3_included=True,
    )
    with pytest.raises(PlanningDenied, match="unsafe"):
        engine.compile_summary(draft, _requester(), unsafe, now_epoch=NOW)


def test_unresolved_gap_blocks_confirmation() -> None:
    engine = _engine()
    requester = _requester()
    draft = _access_draft(gaps=("owner_relationship_unresolved",))
    summary = engine.compile_summary(
        draft, requester, _absent_projections(engine, draft), now_epoch=NOW
    )
    with pytest.raises(PlanningDenied, match="Unresolved gaps"):
        engine.confirm_intent(
            summary.summary_ref,
            requester,
            _interaction(summary, requester),
            now_epoch=NOW + 1,
        )


def test_wrong_principal_stale_or_replayed_confirmation_is_denied() -> None:
    engine = _engine()
    requester = _requester()
    draft = _access_draft()
    summary = engine.compile_summary(
        draft, requester, _absent_projections(engine, draft), now_epoch=NOW
    )
    with pytest.raises(PlanningDenied, match="not bound"):
        engine.confirm_intent(
            summary.summary_ref,
            _requester("beta"),
            _interaction(summary, requester),
            now_epoch=NOW + 1,
        )
    interaction = _interaction(summary, requester)
    engine.confirm_intent(summary.summary_ref, requester, interaction, now_epoch=NOW + 1)
    with pytest.raises(PlanningDenied, match="already consumed"):
        engine.confirm_intent(summary.summary_ref, requester, interaction, now_epoch=NOW + 1)


def test_summary_decision_is_single_use_even_with_a_different_nonce() -> None:
    engine = _engine()
    requester = _requester()
    draft = _access_draft()
    summary = engine.compile_summary(
        draft, requester, _absent_projections(engine, draft), now_epoch=NOW
    )
    engine.confirm_intent(
        summary.summary_ref,
        requester,
        _interaction(summary, requester),
        now_epoch=NOW + 1,
    )
    with pytest.raises(PlanningDenied, match="already consumed"):
        engine.confirm_intent(
            summary.summary_ref,
            requester,
            _interaction(summary, requester, nonce="nonce-beta"),
            now_epoch=NOW + 1,
        )


def test_unbound_deny_cannot_invalidate_another_requesters_summary() -> None:
    engine = _engine()
    requester = _requester()
    draft = _access_draft()
    summary = engine.compile_summary(
        draft, requester, _absent_projections(engine, draft), now_epoch=NOW
    )
    attacker = _requester("beta")
    with pytest.raises(PlanningDenied, match="not bound"):
        engine.confirm_intent(
            summary.summary_ref,
            attacker,
            replace(
                _interaction(summary, requester, decision="deny"),
                requester_digest=attacker.digest,
            ),
            now_epoch=NOW + 1,
        )
    record = engine.confirm_intent(
        summary.summary_ref,
        requester,
        _interaction(summary, requester, nonce="valid-after-attack"),
        now_epoch=NOW + 1,
    )
    assert record.state == "confirmed"


def test_projection_freshness_caps_confirmation_and_plan_lifetime() -> None:
    engine = _engine()
    requester = _requester()
    draft = _access_draft()
    current = _absent_projections(engine, draft)
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
    assert plan.expires_at == min(item.fresh_until for item in current)

    expired_engine = _engine()
    expired_summary = expired_engine.compile_summary(
        draft,
        requester,
        _absent_projections(expired_engine, draft),
        now_epoch=NOW,
    )
    with pytest.raises(PlanningDenied, match="projection expired"):
        expired_engine.confirm_intent(
            expired_summary.summary_ref,
            requester,
            replace(
                _interaction(expired_summary, requester),
                confirmed_at=NOW + 101,
                expires_at=NOW + 200,
            ),
            now_epoch=NOW + 101,
        )


def test_confirmation_digest_revision_and_interaction_type_are_closed() -> None:
    engine = _engine()
    requester = _requester()
    draft = _access_draft()
    summary = engine.compile_summary(
        draft, requester, _absent_projections(engine, draft), now_epoch=NOW
    )
    with pytest.raises(PlanningContractError, match="interaction type"):
        replace(_interaction(summary, requester), interaction_type="model_boolean")
    with pytest.raises(PlanningDenied, match="not bound"):
        engine.confirm_intent(
            summary.summary_ref,
            requester,
            replace(_interaction(summary, requester), summary_digest="0" * 64),
            now_epoch=NOW + 1,
        )
    with pytest.raises(PlanningDenied, match="not bound"):
        engine.confirm_intent(
            summary.summary_ref,
            requester,
            replace(_interaction(summary, requester), summary_revision=2),
            now_epoch=NOW + 1,
        )


def test_denied_confirmation_invalidates_summary() -> None:
    engine = _engine()
    requester = _requester()
    draft = _access_draft()
    summary = engine.compile_summary(
        draft, requester, _absent_projections(engine, draft), now_epoch=NOW
    )
    with pytest.raises(PlanningDenied, match="denied"):
        engine.confirm_intent(
            summary.summary_ref,
            requester,
            _interaction(summary, requester, decision="deny"),
            now_epoch=NOW + 1,
        )
    with pytest.raises(PlanningDenied, match="unavailable"):
        engine.confirm_intent(
            summary.summary_ref,
            requester,
            _interaction(summary, requester, nonce="second-nonce"),
            now_epoch=NOW + 1,
        )


def test_material_change_revision_invalidates_prior_confirmation_and_plan() -> None:
    engine, requester, summary, plan, _current = _confirmed_plan(_access_draft())
    revised_draft = replace(
        _access_draft(),
        external_effects=("access_scope_change", "user_access_change"),
    )
    revised = engine.compile_summary(
        revised_draft,
        requester,
        _absent_projections(engine, revised_draft),
        now_epoch=NOW + 3,
        prior_summary_ref=summary.summary_ref,
    )
    assert revised.revision == 2
    with pytest.raises(PlanningDenied, match="unavailable"):
        engine.evaluate_pre_write(plan.plan_ref, [], now_epoch=NOW + 4)


def test_revision_cannot_be_taken_over_by_another_requester() -> None:
    engine = _engine()
    draft = _access_draft()
    summary = engine.compile_summary(
        draft, _requester(), _absent_projections(engine, draft), now_epoch=NOW
    )
    with pytest.raises(PlanningDenied, match="revision binding"):
        engine.compile_summary(
            draft,
            _requester("beta"),
            _absent_projections(engine, draft),
            now_epoch=NOW + 1,
            prior_summary_ref=summary.summary_ref,
        )


def test_no_op_is_displayed_but_cannot_prepare() -> None:
    engine = _engine()
    requester = _requester()
    draft = _access_draft()
    current = _expected_projections(engine, draft, observed_at=NOW - 10)
    summary = engine.compile_summary(draft, requester, current, now_epoch=NOW)
    assert all(change.change_kind is ChangeKind.NO_OP for change in summary.object_changes)
    confirmation = engine.confirm_intent(
        summary.summary_ref,
        requester,
        _interaction(summary, requester),
        now_epoch=NOW + 1,
    )
    with pytest.raises(PlanningDenied, match="no-op"):
        engine.prepare_plan(
            summary.summary_ref,
            confirmation.confirmation_ref,
            requester,
            now_epoch=NOW + 2,
        )


def test_prewrite_drift_invalidates_plan() -> None:
    draft = _access_draft()
    engine, _requester_value, _summary, plan, current = _confirmed_plan(draft)
    drifted = list(current)
    desired = draft.desired_objects[0]
    drifted[0] = _projection(
        engine,
        draft.scheme_id,
        desired,
        {"enabled": False, "exists": True, "owner_ref": "owner-ref-team0001"},
        observed_at=NOW + 2,
        fresh_until=NOW + 102,
    )
    result = engine.evaluate_pre_write(plan.plan_ref, drifted, now_epoch=NOW + 3)
    assert result.status is PreWriteStatus.INVALIDATED
    assert result.reason_codes == ("current_state_drift",)
    with pytest.raises(PlanningDenied, match="unavailable"):
        engine.evaluate_pre_write(plan.plan_ref, current, now_epoch=NOW + 4)


def test_unsafe_prewrite_is_unknown_and_never_match() -> None:
    draft = _access_draft()
    engine, _requester_value, _summary, plan, current = _confirmed_plan(draft)
    desired = draft.desired_objects[0]
    current[0] = _projection(
        engine,
        draft.scheme_id,
        desired,
        {"exists": False},
        observed_at=NOW + 2,
        fresh_until=NOW + 102,
        raw_response_included=True,
    )
    result = engine.evaluate_pre_write(plan.plan_ref, current, now_epoch=NOW + 3)
    assert result.status is PreWriteStatus.UNKNOWN


def test_postwrite_requires_prewrite_match_and_exact_expected_state() -> None:
    draft = _access_draft()
    engine, _requester_value, _summary, plan, current = _confirmed_plan(draft)
    result = engine.evaluate_post_write(
        plan.plan_ref, _expected_projections(engine, draft), now_epoch=NOW + 3
    )
    assert result.status is PostWriteStatus.COMPARISON_UNKNOWN

    reread = [
        AuthoritativeProjection.from_mapping(
            contract=item.contract,
            object_ref=item.object_ref,
            observed_at=NOW + 2,
            fresh_until=NOW + 102,
            fields=item.values,
        )
        for item in current
    ]
    assert engine.evaluate_pre_write(plan.plan_ref, reread, now_epoch=NOW + 3).status is PreWriteStatus.MATCH
    mismatch = _expected_projections(engine, draft, observed_at=NOW + 4)
    grant = draft.desired_objects[1]
    mismatch[1] = _projection(
        engine,
        draft.scheme_id,
        grant,
        {
            "exists": True,
            "permission": "manage",
            "subject_class": "group",
            "subject_ref": "group-relation-ref01",
        },
        observed_at=NOW + 4,
        fresh_until=NOW + 104,
    )
    assert engine.evaluate_post_write(plan.plan_ref, mismatch, now_epoch=NOW + 5).status is PostWriteStatus.EXPECTED_STATE_MISMATCH


def test_unsafe_postwrite_is_unknown_not_success() -> None:
    draft = _access_draft()
    engine, _requester_value, _summary, plan, current = _confirmed_plan(draft)
    reread = [
        AuthoritativeProjection.from_mapping(
            contract=item.contract,
            object_ref=item.object_ref,
            observed_at=NOW + 2,
            fresh_until=NOW + 102,
            fields=item.values,
        )
        for item in current
    ]
    assert engine.evaluate_pre_write(plan.plan_ref, reread, now_epoch=NOW + 3).status is PreWriteStatus.MATCH
    post = _expected_projections(engine, draft, observed_at=NOW + 4)
    desired = draft.desired_objects[0]
    post[0] = _projection(
        engine,
        draft.scheme_id,
        desired,
        {"exists": desired.desired_exists, **dict(desired.desired_fields)},
        observed_at=NOW + 4,
        fresh_until=NOW + 104,
        contradictory=True,
    )
    result = engine.evaluate_post_write(plan.plan_ref, post, now_epoch=NOW + 5)
    assert result.status is PostWriteStatus.COMPARISON_UNKNOWN
    assert result.mutation_observed is False
    assert result.operational_success is False


def test_material_availability_must_be_ready_before_plan_preparation() -> None:
    draft = replace(
        _secret_draft(),
        material_reference_metadata=MaterialReferenceMetadata(
            provider_class="external_vault_lease",
            purpose="initial_onboarding",
            lifecycle="pending",
        ),
    )
    engine = _engine()
    requester = _requester()
    summary = engine.compile_summary(
        draft, requester, _absent_projections(engine, draft), now_epoch=NOW
    )
    confirmation = engine.confirm_intent(
        summary.summary_ref,
        requester,
        _interaction(summary, requester),
        now_epoch=NOW + 1,
    )
    with pytest.raises(PlanningDenied, match="not ready"):
        engine.prepare_plan(
            summary.summary_ref,
            confirmation.confirmation_ref,
            requester,
            now_epoch=NOW + 2,
        )


@pytest.mark.parametrize(
    "unissued_reference",
    (
        "vault-path-secret001",
        "account-admin-secret01",
        "binding-password-ref01",
        "https-url-secret-ref01",
    ),
)
def test_unissued_caller_reference_shapes_are_denied_without_keyword_filtering(
    unissued_reference: str,
) -> None:
    draft = replace(_access_draft(), owner_ref=unissued_reference)
    engine = _engine()
    with pytest.raises(PlanningDenied, match="Reference is not authorized"):
        engine.compile_summary(
            draft,
            _requester(),
            _absent_projections(engine, draft),
            now_epoch=NOW,
        )


def test_unissued_desired_and_projection_reference_values_are_denied() -> None:
    draft = _access_draft()
    folder = replace(
        draft.desired_objects[0],
        desired_fields=(
            ("enabled", True),
            ("owner_ref", "unissued-owner-reference01"),
        ),
    )
    modified = replace(draft, desired_objects=(folder, *draft.desired_objects[1:]))
    desired_engine = _engine()
    with pytest.raises(PlanningDenied, match="Reference is not authorized"):
        desired_engine.compile_summary(
            modified,
            _requester(),
            _absent_projections(desired_engine, modified),
            now_epoch=NOW,
        )

    projection_engine = _engine()
    projections = _absent_projections(projection_engine, draft)
    projections[0] = _projection(
        projection_engine,
        draft.scheme_id,
        draft.desired_objects[0],
        {
            "enabled": True,
            "exists": True,
            "owner_ref": "unissued-current-owner01",
        },
    )
    with pytest.raises(PlanningDenied, match="Reference is not authorized"):
        projection_engine.compile_summary(
            draft,
            _requester(),
            projections,
            now_epoch=NOW,
        )


@pytest.mark.parametrize(
    "mode",
    (
        "reference_kind",
        "authority_ref",
        "requester_digest",
        "environment_digest",
        "scope_digest",
        "reference_digest",
        "expired",
    ),
)
def test_reference_authority_type_scope_provenance_and_freshness_are_exact(
    mode: str,
) -> None:
    draft = _access_draft()
    engine = M2PlanningEngine(
        _promoted_registry(),
        Issuer(),
        TamperedAuthorizer((draft,), mode),
    )
    with pytest.raises(PlanningDenied, match="Reference is not authorized"):
        engine.compile_summary(
            draft,
            _requester(),
            _absent_projections(engine, draft),
            now_epoch=NOW,
        )


def test_reference_authorization_expiry_caps_summary_and_plan() -> None:
    draft = _access_draft()
    authorizer = StatefulAuthorizer((draft,), ttl_seconds=10)
    engine = M2PlanningEngine(_promoted_registry(), Issuer(), authorizer)
    requester = _requester()
    summary = engine.compile_summary(
        draft,
        requester,
        _absent_projections(engine, draft),
        now_epoch=NOW,
    )
    assert summary.reference_authority_ref == authorizer.authority_ref
    assert summary.reference_authorization_digest
    assert summary.reference_authorization_expires_at == NOW + 10
    assert summary.expires_at == NOW + 10
    confirmation = engine.confirm_intent(
        summary.summary_ref,
        requester,
        replace(_interaction(summary, requester), expires_at=NOW + 10),
        now_epoch=NOW + 1,
    )
    plan = engine.prepare_plan(
        summary.summary_ref,
        confirmation.confirmation_ref,
        requester,
        now_epoch=NOW + 2,
    )
    assert plan.expires_at == NOW + 10


def test_reference_revocation_invalidates_summary_before_confirmation() -> None:
    draft = _access_draft()
    authorizer = StatefulAuthorizer((draft,))
    engine = M2PlanningEngine(_promoted_registry(), Issuer(), authorizer)
    requester = _requester()
    summary = engine.compile_summary(
        draft,
        requester,
        _absent_projections(engine, draft),
        now_epoch=NOW,
    )
    authorizer.revoked = True
    with pytest.raises(PlanningDenied, match="Reference is not authorized"):
        engine.confirm_intent(
            summary.summary_ref,
            requester,
            _interaction(summary, requester),
            now_epoch=NOW + 1,
        )
    with pytest.raises(PlanningDenied, match="unavailable"):
        engine.confirm_intent(
            summary.summary_ref,
            requester,
            _interaction(summary, requester, nonce="revoked-retry"),
            now_epoch=NOW + 1,
        )


def test_prewrite_reference_revocation_invalidates_the_entire_old_plan() -> None:
    draft = _access_draft()
    authorizer = StatefulAuthorizer((draft,))
    engine = M2PlanningEngine(_promoted_registry(), Issuer(), authorizer)
    requester = _requester()
    current = _absent_projections(engine, draft)
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
    authorizer.revoked = True
    result = engine.evaluate_pre_write(plan.plan_ref, current, now_epoch=NOW + 3)
    assert result.status is PreWriteStatus.UNKNOWN
    assert result.reason_codes == ("current_state_unavailable_or_unsafe",)
    authorizer.revoked = False
    with pytest.raises(PlanningDenied, match="Prepared plan is unavailable"):
        engine.evaluate_pre_write(plan.plan_ref, current, now_epoch=NOW + 4)


def test_postwrite_reference_revocation_is_comparison_unknown() -> None:
    draft = _access_draft()
    authorizer = StatefulAuthorizer((draft,))
    engine = M2PlanningEngine(_promoted_registry(), Issuer(), authorizer)
    requester = _requester()
    current = _absent_projections(engine, draft)
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
    assert (
        engine.evaluate_pre_write(plan.plan_ref, current, now_epoch=NOW + 3).status
        is PreWriteStatus.MATCH
    )
    authorizer.revoked = True
    result = engine.evaluate_post_write(
        plan.plan_ref,
        _expected_projections(engine, draft, observed_at=NOW + 4),
        now_epoch=NOW + 4,
    )
    assert result.status is PostWriteStatus.COMPARISON_UNKNOWN
    assert result.reason_codes == ("post_write_state_unavailable_or_unsafe",)
    assert result.mutation_observed is False
    assert result.operational_success is False


def test_transition_times_are_monotonic_and_prewrite_is_time_bound() -> None:
    draft = _access_draft()
    engine = _engine()
    requester = _requester()
    current = _absent_projections(engine, draft)
    summary = engine.compile_summary(draft, requester, current, now_epoch=NOW)
    with pytest.raises(PlanningDenied, match="time cannot move backwards"):
        engine.compile_summary(
            draft,
            requester,
            current,
            now_epoch=NOW - 1,
            prior_summary_ref=summary.summary_ref,
        )
    confirmation = engine.confirm_intent(
        summary.summary_ref,
        requester,
        _interaction(summary, requester),
        now_epoch=NOW + 1,
    )
    with pytest.raises(PlanningDenied, match="cannot move backwards"):
        engine.prepare_plan(
            summary.summary_ref,
            confirmation.confirmation_ref,
            requester,
            now_epoch=NOW,
        )
    plan = engine.prepare_plan(
        summary.summary_ref,
        confirmation.confirmation_ref,
        requester,
        now_epoch=NOW + 2,
    )
    with pytest.raises(PlanningDenied, match="time cannot move backwards"):
        engine.evaluate_pre_write(plan.plan_ref, current, now_epoch=NOW + 1)
    assert (
        engine.evaluate_pre_write(plan.plan_ref, current, now_epoch=NOW + 3).status
        is PreWriteStatus.MATCH
    )
    with pytest.raises(PlanningDenied, match="cannot precede"):
        engine.evaluate_post_write(plan.plan_ref, current, now_epoch=NOW + 2)
    expected = _expected_projections(engine, draft, observed_at=NOW + 4)
    engine.evaluate_post_write(plan.plan_ref, expected, now_epoch=NOW + 4)
    with pytest.raises(PlanningDenied, match="time cannot move backwards"):
        engine.evaluate_post_write(plan.plan_ref, expected, now_epoch=NOW + 3)


def test_scheme_relation_cardinality_and_required_state_fail_closed() -> None:
    access = _access_draft()
    grants = tuple(
        _desired(
            f"grant-cardinality-ref{index:02d}",
            ObjectClass.ACCESS_GRANT,
            {
                "permission": "use",
                "subject_class": "group",
                "subject_ref": f"group-cardinality-ref{index:02d}",
            },
        )
        for index in range(17)
    )
    excessive = replace(access, desired_objects=(access.desired_objects[0], *grants))
    excessive_engine = _engine(excessive)
    with pytest.raises(PlanningDenied, match="cardinality"):
        excessive_engine.compile_summary(
            excessive,
            _requester(),
            _absent_projections(excessive_engine, excessive),
            now_epoch=NOW,
        )

    secret = _secret_draft()
    removed_required = replace(
        secret,
        desired_objects=tuple(
            replace(item, desired_exists=False, desired_fields=())
            if item.object_class is ObjectClass.TARGET
            else item
            for item in secret.desired_objects
        ),
    )
    removed_engine = _engine(removed_required)
    with pytest.raises(PlanningDenied, match="required relations must exist"):
        removed_engine.compile_summary(
            removed_required,
            _requester(),
            _absent_projections(removed_engine, removed_required),
            now_epoch=NOW,
        )


def test_c3_locator_cannot_enter_material_metadata_or_scheme() -> None:
    with pytest.raises(TypeError):
        MaterialReferenceMetadata(  # type: ignore[call-arg]
            provider_class="external_vault_lease",
            purpose="initial_onboarding",
            lifecycle="available",
            binding_handle="forbidden",
        )
    draft = _secret_draft()
    serialized = json.dumps(asdict(draft))
    for prohibited in ("binding_handle", "vendor_locator", "password", "secret_value"):
        assert prohibited not in serialized


def test_m2_has_no_apply_execute_or_adapter_surface_and_is_not_in_v3_wheel() -> None:
    assert not hasattr(M2PlanningEngine, "apply")
    assert not hasattr(M2PlanningEngine, "execute")
    assert not hasattr(M2PlanningEngine, "register_adapter")
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'packages = ["src/fortipam_mcp"]' in pyproject
    assert "v4_planning" not in pyproject


def test_unpromoted_registry_cannot_construct_m2_engine() -> None:
    registry = copy.deepcopy(load_registry())
    scheme = next(
        item
        for item in registry["schemes"]  # type: ignore[index]
        if item["id"] == "AccessDomainScheme"
    )
    scheme["status"] = "catalogued"
    scheme["maturity"] = "designed"
    scheme["lifecycle"] = "catalogued"
    scheme["implementation_evidence"]["evidence_status"] = "pending"
    with pytest.raises(PlanningDenied, match="not contract-tested"):
        M2PlanningEngine(registry, Issuer(), Authorizer(()))


def test_previous_registry_schema_version_is_denied_after_p01_extension() -> None:
    engine = _engine()
    draft = replace(_access_draft(), registry_schema_version="1.0.0")
    with pytest.raises(PlanningDenied, match="different registry schema version"):
        engine.compile_summary(
            draft,
            _requester(),
            _absent_projections(engine, draft),
            now_epoch=NOW,
        )


def test_uncontracted_blueprint_or_outcome_profile_is_denied() -> None:
    engine = _engine()
    requester = _requester()
    wrong_blueprint = replace(_secret_draft(), blueprint_ref="FPA-BP-006")
    with pytest.raises(PlanningDenied, match="exact fake-only M2 profile"):
        engine.compile_summary(
            wrong_blueprint,
            requester,
            _absent_projections(engine, wrong_blueprint),
            now_epoch=NOW,
        )
    wrong_outcome = replace(_access_draft(), outcome_code="grant_unbounded_access")
    with pytest.raises(PlanningDenied, match="exact fake-only M2 profile"):
        engine.compile_summary(
            wrong_outcome,
            requester,
            _absent_projections(engine, wrong_outcome),
            now_epoch=NOW,
        )


def test_duplicate_server_reference_is_denied_before_record_overwrite() -> None:
    engine = _engine(issuer=DuplicateIssuer())
    draft = _access_draft()
    requester = _requester()
    engine.compile_summary(draft, requester, _absent_projections(engine, draft), now_epoch=NOW)
    with pytest.raises(PlanningDenied, match="duplicate reference"):
        engine.compile_summary(
            draft,
            requester,
            _absent_projections(engine, draft),
            now_epoch=NOW + 1,
        )
