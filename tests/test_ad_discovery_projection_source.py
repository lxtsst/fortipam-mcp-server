"""Five-object BP014 Source planning over fixed synthetic native readers."""

from dataclasses import replace
import json

import pytest

import fortipam_mcp.owner_discovery_runtime as owner_composition
from fortipam_mcp.ad_discovery_projection_source import (
    AdDiscoveryPlanningBinding, AdDiscoveryPlanningSource, OUTCOME, SOURCE_REF,
    ad_discovery_projection_contract,
)
from fortipam_mcp.domain_secret_projection_reader import DomainSecretPlanningBinding
from test_owner_discovery_runtime import _composition, _assert_closed
from test_v4_planning import (
    NOW, Authorizer, Issuer, _desired, _interaction, _promoted_registry, _requester, _secret_draft,
)
from v4_planning import (
    AuthoritativeProjection, ChangeKind, M2PlanningEngine, M3PlanOnlyWorkflowService,
    ObjectClass, PlanningContractError, PlanningDenied, SchemeId,
)
from v4_planning.approval import M3ApprovalGate
from v4_planning.policy import M3PlanPolicy
from v4_planning.store import InMemoryProtectedPlanningStore


def _prepared_source(tmp_path, monkeypatch, *, defect=None):
    runtime, _, source_binding, store, writes, state = _composition(
        tmp_path, monkeypatch, gate_open=False, defect=defect,
    )
    base = _secret_draft()
    domain = DomainSecretPlanningBinding(
        source_binding.domain_binding, _requester().digest, base.environment_ref, base.scope_ref,
        "ad-folder-object-ref01", "ad-folder-ref0001", "ad-target-object-ref01", "ad-target-profile-ref01",
        "ad-template-object-ref01", "ad-template-ref01", "ad-secret-object-ref01",
    )
    binding = AdDiscoveryPlanningBinding(source_binding, domain, "ad-source-object-ref01")
    owner = owner_composition.owner_domain_transport(
        runtime._owner_config, domain.create_binding, runtime._credentials, allow_secret_create=False,
    )
    source = AdDiscoveryPlanningSource(binding, owner, runtime._source_transport)
    draft = replace(base, scheme_id=SchemeId.BULK_ONBOARDING, blueprint_ref="FPA-BP-014",
                    outcome_code=OUTCOME, material_reference_metadata=None, risk_class="medium",
                    desired_objects=tuple(_desired(ref, cls, fields)
                        for ref, (cls, fields) in binding.expected_objects().items()))
    return draft, source, store, writes, state


def _engine(draft):
    # Reuse the established exact reference authority for the four old classes.
    anchors = replace(draft, desired_objects=tuple(item for item in draft.desired_objects
                       if item.object_class is not ObjectClass.DISCOVERY_SOURCE_METADATA))
    authorizer = Authorizer((anchors,), projection_source_ref=SOURCE_REF)
    item = next(item for item in draft.desired_objects if item.object_class is ObjectClass.DISCOVERY_SOURCE_METADATA)
    authorizer._grants.add((item.object_ref, "object_discovery_source_metadata"))
    authorizer._grants.add((dict(item.desired_fields)["domain_secret_ref"], "field_domain_secret_ref"))
    return M2PlanningEngine(_promoted_registry(), Issuer(), authorizer,
        projection_contract_resolver=lambda scheme, cls: ad_discovery_projection_contract(cls))


def test_five_native_projections_compile_cpe_and_m3_non_executable_plan(tmp_path, monkeypatch):
    draft, source, store, writes, state = _prepared_source(tmp_path, monkeypatch)
    requester = _requester()
    projections = source.project(draft, requester, now_epoch=NOW)
    assert len(projections) == 5
    assert next(p.values for p in projections if p.contract.object_class is ObjectClass.DISCOVERY_SOURCE_METADATA) == {"exists": False}
    public = json.dumps([p.as_dict() for p in projections])
    private = source.inspect_private_binding_digest(draft, requester)
    assert private not in public and source._binding.source.parameters_digest not in public
    assert "192.0.2.10" not in public and '"domain-owner"' not in public
    assert '"domain-secret"' not in public and '"domain-target"' not in public
    engine = _engine(draft)
    issuer = Issuer()
    workflow = M3PlanOnlyWorkflowService(engine, InMemoryProtectedPlanningStore(),
                                         M3PlanPolicy(issuer), M3ApprovalGate(issuer))
    summary = workflow.compile_summary(draft, requester, projections, now_epoch=NOW)
    creates = [change for change in summary.object_changes if change.change_kind is ChangeKind.CREATE]
    assert len(creates) == 1 and creates[0].object_class is ObjectClass.DISCOVERY_SOURCE_METADATA
    assert all(change.change_kind is ChangeKind.NO_OP for change in summary.object_changes if change not in creates)
    confirmation = workflow.confirm_intent(summary.summary_ref, requester, _interaction(summary, requester), now_epoch=NOW + 1)
    plan = workflow.prepare_plan(summary.summary_ref, confirmation.confirmation_ref, requester, now_epoch=NOW + 2)
    assert len(plan.lines) == 1 and plan.lines[0].target_class is ObjectClass.DISCOVERY_SOURCE_METADATA
    assert plan.lines[0].depends_on == ()  # The four existing anchors have no dispatchable lines.
    from v4_planning.engine import _depends_on
    assert all(_depends_on(ObjectClass.DISCOVERY_SOURCE_METADATA, item.object_class)
               for item in draft.desired_objects if item.object_class is not ObjectClass.DISCOVERY_SOURCE_METADATA)
    assert not plan.dispatchable and not plan.adapter_registry_bound
    assert not plan.executor_runtime_packaged and not plan.executor_mcp_exposed
    assert summary.material_reference_metadata is None and store.claim_count == writes["posts"] == 0
    _assert_closed(state)


def test_exact_existing_source_is_noop_and_cannot_prepare_a_write(tmp_path, monkeypatch):
    draft, source, store, writes, state = _prepared_source(tmp_path, monkeypatch)
    writes["row"] = {**source._binding.source.request.body(), "last-discovery-time": "0000-00-00 00:00:00", "q_origin_key": source._binding.source.request.source_name}
    engine = _engine(draft)
    requester = _requester()
    summary = engine.compile_summary(draft, requester, source.project(draft, requester, now_epoch=NOW), now_epoch=NOW)
    assert all(change.change_kind is ChangeKind.NO_OP for change in summary.object_changes)
    confirmation = engine.confirm_intent(summary.summary_ref, requester, _interaction(summary, requester), now_epoch=NOW + 1)
    with pytest.raises(PlanningDenied, match="no-op"):
        engine.prepare_plan(summary.summary_ref, confirmation.confirmation_ref, requester, now_epoch=NOW + 2)
    assert store.claim_count == writes["posts"] == 0
    _assert_closed(state)


@pytest.mark.parametrize("defect", ["class", "relation", "scan", "type"])
def test_unqualified_native_dependency_or_source_refuses_projection_without_write(tmp_path, monkeypatch, defect):
    draft, source, store, writes, state = _prepared_source(tmp_path, monkeypatch, defect="class" if defect == "class" else None)
    if defect != "class":
        row = {**source._binding.source.request.body(), "last-discovery-time": "0000-00-00 00:00:00", "q_origin_key": source._binding.source.request.source_name}
        row[{"relation": "discovery-secret", "scan": "schedule-status", "type": "source-type"}[defect]] = (
            24 if defect == "relation" else "enable" if defect == "scan" else "Unix-like")
        writes["row"] = row
    with pytest.raises(PlanningContractError):
        source.project(draft, _requester(), now_epoch=NOW)
    assert store.claim_count == writes["posts"] == 0
    _assert_closed(state)


@pytest.mark.parametrize("defect", ["material", "outcome", "scheme", "relation", "expanded", "disable", "non_bool", "non_bool_exists", "revoke", "missing", "requester"])
def test_closed_five_object_intent_denies_expansion_before_native_reads(tmp_path, monkeypatch, defect):
    draft, source, store, writes, state = _prepared_source(tmp_path, monkeypatch)
    requester = _requester("other") if defect == "requester" else _requester()
    if defect == "material":
        draft = replace(draft, material_reference_metadata=_secret_draft().material_reference_metadata)
    elif defect == "outcome":
        draft = replace(draft, outcome_code="onboard_domain_account")
    elif defect == "scheme":
        draft = replace(draft, scheme_id=SchemeId.SECRET_ONBOARDING)
    elif defect == "missing":
        draft = replace(draft, desired_objects=draft.desired_objects[:-1])
    elif defect == "requester":
        pass
    else:
        item = draft.desired_objects[-1]
        fields = dict(item.desired_fields)
        if defect == "relation":
            fields["domain_secret_ref"] = "different-secret-ref01"
        elif defect == "expanded":
            fields["scan_requested"] = True
        elif defect == "disable":
            fields["auto_onboarding_disabled"] = False
        elif defect == "non_bool":
            fields["account_discovery"] = 1
        item = replace(item, desired_exists=defect != "revoke", desired_fields=tuple(sorted(fields.items())) if defect != "revoke" else ())
        if defect == "non_bool_exists":
            item = replace(item, desired_exists=1)
        draft = replace(draft, desired_objects=(*draft.desired_objects[:-1], item))
    with pytest.raises(PlanningContractError):
        source.project(draft, requester, now_epoch=NOW)
    assert state["credentials"] == 0 and state["calls"] == writes["calls"] == []
    assert store.claim_count == writes["posts"] == 0


@pytest.mark.parametrize("kind", ["anchor_missing", "anchor_update", "source_update"])
def test_planner_rejects_mutable_or_absent_anchors_and_source_update(tmp_path, monkeypatch, kind):
    draft, source, _, _, _ = _prepared_source(tmp_path, monkeypatch)
    projections = source.project(draft, _requester(), now_epoch=NOW)
    changed = []
    for item in projections:
        fields = dict(item.fields)
        if kind.startswith("anchor") and item.contract.object_class is ObjectClass.DOMAIN_SECRET_METADATA:
            fields = {"exists": False} if kind == "anchor_missing" else {**fields, "services_disabled": False}
        if kind == "source_update" and item.contract.object_class is ObjectClass.DISCOVERY_SOURCE_METADATA:
            fields = {"exists": True, **dict(draft.desired_objects[-1].desired_fields), "auto_onboarding_disabled": False}
        changed.append(AuthoritativeProjection.from_mapping(contract=item.contract, object_ref=item.object_ref,
                       observed_at=NOW, fresh_until=NOW + 300, fields=fields))
    with pytest.raises(PlanningDenied):
        _engine(draft).compile_summary(draft, _requester(), changed, now_epoch=NOW)


def test_prewrite_drift_invalidates_source_plan(tmp_path, monkeypatch):
    draft, source, _, writes, _ = _prepared_source(tmp_path, monkeypatch)
    engine, requester = _engine(draft), _requester()
    projections = source.project(draft, requester, now_epoch=NOW)
    summary = engine.compile_summary(draft, requester, projections, now_epoch=NOW)
    confirmation = engine.confirm_intent(summary.summary_ref, requester, _interaction(summary, requester), now_epoch=NOW + 1)
    plan = engine.prepare_plan(summary.summary_ref, confirmation.confirmation_ref, requester, now_epoch=NOW + 2)
    writes["row"] = {**source._binding.source.request.body(), "last-discovery-time": "0000-00-00 00:00:00", "q_origin_key": source._binding.source.request.source_name}
    after = source.project(draft, requester, now_epoch=NOW + 3)
    evaluation = engine.evaluate_pre_write(plan.plan_ref, after, now_epoch=NOW + 3)
    assert evaluation.status.value == "invalidated"
    assert writes["posts"] == 0


@pytest.mark.parametrize("field,value", [("base_url", "https://other.example.test"), ("ca_file", "different-trust.pem"), ("target_owner_name", "other-owner")])
def test_fixed_source_refuses_wrong_device_or_owner_selectors_before_reads(tmp_path, monkeypatch, field, value):
    draft, source, _, writes, state = _prepared_source(tmp_path, monkeypatch)
    if field == "ca_file":
        trust = tmp_path / value
        trust.write_text("synthetic trust boundary", encoding="utf-8")
        value = str(trust)
    if field in {"base_url", "ca_file"}:
        source._source_transport._config = replace(source._source_transport._config, **{field: value})
    else:
        source._owner._owner_name = value
    with pytest.raises(PlanningContractError):
        source.project(draft, _requester(), now_epoch=NOW)
    assert state["credentials"] == 0 and state["calls"] == writes["calls"] == []
