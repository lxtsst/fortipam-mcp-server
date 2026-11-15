"""Persistent AD host planning with genuine local browser intent confirmation."""

import json
import re
from urllib.parse import urlsplit

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from fortipam_mcp.ad_discovery_projection_source import ad_discovery_projection_contract
from fortipam_mcp.v4_confirmation_http import V4ConfirmationHttpError
from fortipam_mcp.v4_runtime_host import ad_discovery_v4_plan_host_factory
from test_ad_discovery_lab_auto_runtime import _context
from test_ad_discovery_v4_host import _host_settings
from test_owner_discovery_runtime import _assert_closed
from test_v4_planning import NOW
from v4_planning import ChangeKind, FieldKind, ObjectClass, PlanningContractError
from v4_planning.engine import _object_kind_code
from v4_planning.persistence import PersistentProtectedPlanningStore


class _Clock:
    def __init__(self):
        self.value = NOW + 5

    def __call__(self):
        return self.value


def _host_context(tmp_path, monkeypatch):
    # The old fixture's fake plan is deliberately discarded. Only its exact
    # private binding and actual synthetic Owner/Source HTTP peers are reused.
    draft, _, principal, fixture_source, _, _, _, execution_store, writes, state = _context(
        tmp_path, monkeypatch, gate=None,
    )
    settings, provider, confirmation_settings = _host_settings(tmp_path)
    clock = _Clock()
    factory = ad_discovery_v4_plan_host_factory(
        settings, binding=fixture_source._binding, owner_transport=fixture_source._owner,
        source_transport=fixture_source._source_transport, clock=clock,
    )
    components = factory(provider, confirmation_settings)
    reference_authority = components.reference_authority
    draft_authority = components.scheme_draft_authority
    source = components.ad_discovery_projection_source
    assert reference_authority is not None and draft_authority is not None and source is not None
    references = {
        (draft.environment_ref, "environment"), (draft.scope_ref, "scope"),
        (draft.owner_ref, "owner"), (draft.audience_ref, "audience"),
        *((ref, "evidence") for ref in draft.evidence_refs),
    }
    for item in draft.desired_objects:
        references.add((item.object_ref, "object_" + _object_kind_code(item.object_class)))
        contract = ad_discovery_projection_contract(item.object_class)
        references.add((contract.source_ref, "projection_source"))
        for field, value in item.desired_fields:
            if contract.rules[field].kind is FieldKind.REFERENCE:
                references.add((value, "field_" + field))
    handles = reference_authority.issue_many(tuple(sorted(references)),
        requester_digest=principal.requester.digest, environment_ref=draft.environment_ref,
        scope_ref=draft.scope_ref, expires_at=clock.value + 300, now_epoch=clock.value)
    assert len(handles) == len(references)
    draft_ref = draft_authority.issue(draft, principal.requester,
        expires_at=clock.value + 300, now_epoch=clock.value)
    assert draft_ref not in {item.object_ref for item in draft.desired_objects}
    assert draft_authority.resolve(draft_ref, principal.requester) == draft
    return (draft, draft_ref, principal, source, factory, provider, confirmation_settings,
            components, clock, settings, execution_store, writes, state)


def _csrf(response):
    assert response.status_code == 200
    found = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert found is not None
    return found.group(1)


def _confirm_and_prepare(context):
    (draft, draft_ref, principal, source, factory, provider, confirmation_settings,
     components, clock, settings, execution_store, writes, state) = context
    preview = components.plan_services.preview(draft_ref, principal)
    assert preview["confirmation_state"] == "awaiting_human_reauthentication"
    assert preview["reference_authority_ref"] == components.reference_authority.authority_ref
    # A recorded browser decision is required, even with an existing M3 fixture
    # confirmation belonging to a different, discarded planner.
    with pytest.raises(V4ConfirmationHttpError):
        components.plan_services.confirm(str(preview["summary_ref"]), preview["revision"], principal)
    path = urlsplit(preview["confirmation_url"]).path
    with TestClient(Starlette(routes=components.confirmation_service.routes()),
                    base_url="https://mcp.example.test") as client:
        page = client.get(path)
        clock.value += 1
        review = client.post(path, data={"csrf_token": _csrf(page), "username": "operator",
            "password": "synthetic-host-password", "action": "review"},
            headers={"origin": "https://mcp.example.test"})
        csrf = _csrf(review)
        clock.value += 1
        affirmative = client.post(path, data={"csrf_token": csrf, "action": "affirm"},
            headers={"origin": "https://mcp.example.test"})
        assert affirmative.status_code == 200
    # Recreate the actual host twice to demonstrate durable confirmation and
    # planning records, rather than relying on transient engine state.
    clock.value += 1
    components = factory(provider, confirmation_settings)
    confirmation = components.plan_services.confirm(str(preview["summary_ref"]),
        preview["revision"], principal)
    clock.value += 1
    components = factory(provider, confirmation_settings)
    plan = components.plan_services.prepare(str(preview["summary_ref"]),
        str(confirmation["confirmation_ref"]), principal)
    return components, preview, confirmation, plan, review.text


def test_persistent_ad_host_browser_confirmation_prepares_only_source_create(tmp_path, monkeypatch):
    context = _host_context(tmp_path, monkeypatch)
    (draft, draft_ref, principal, source, _, _, _, _, clock, settings,
     execution_store, writes, state) = context
    components, preview, confirmation, public_plan, review = _confirm_and_prepare(context)
    store = PersistentProtectedPlanningStore(settings.planning_database_path,
        settings.planning_hmac_key_path, clock=clock)
    summary = store.get_summary(str(preview["summary_ref"]), preview["revision"])
    assert len(summary.object_changes) == 5
    creates = [item for item in summary.object_changes if item.change_kind is ChangeKind.CREATE]
    assert len(creates) == 1 and creates[0].object_class is ObjectClass.DISCOVERY_SOURCE_METADATA
    assert all(item.change_kind is ChangeKind.NO_OP for item in summary.object_changes if item not in creates)
    plan = store.get_plan(str(public_plan["plan_ref"]))
    assert len(plan.lines) == 1 and plan.lines[0].target_ref == source._binding.source_object_ref
    assert plan.lines[0].target_class is ObjectClass.DISCOVERY_SOURCE_METADATA
    assert plan.lines[0].depends_on == ()
    assert not plan.dispatchable and not plan.adapter_registry_bound
    assert not plan.executor_runtime_packaged and not plan.executor_mcp_exposed
    resolved_plan, resolved_draft = components.plan_services.resolve_execution_context(
        plan.plan_ref, draft_ref, principal)
    assert resolved_plan == plan and resolved_draft == draft
    private_digest = source.inspect_private_binding_digest(draft, principal.requester)
    public = json.dumps([preview, confirmation, public_plan]) + review
    assert private_digest not in public and source._binding.source.parameters_digest not in public
    for private_value in ("192.0.2.10", "ad.example.test", "domain-owner", "domain-secret",
                          "Public/domain-folder", source._binding.source.request.source_name,
                          "synthetic-owner-domain-material-must-not-be-decoded"):
        assert private_value not in public
    assert summary.material_reference_metadata is None
    assert execution_store.claim_count == writes["posts"] == 0
    _assert_closed(state)


def test_persistent_ad_host_prewrite_drift_invalidates_without_execution(tmp_path, monkeypatch):
    context = _host_context(tmp_path, monkeypatch)
    (_, draft_ref, principal, source, factory, provider, confirmation_settings,
     _, _, _, execution_store, writes, state) = context
    components, _, _, plan, _ = _confirm_and_prepare(context)
    before = components.plan_services.evaluate_pre_write(str(plan["plan_ref"]), draft_ref, principal)
    assert before["status"] == "match"
    request = source._binding.source.request
    writes["row"] = {**request.body(), "q_origin_key": request.source_name,
                     "last-discovery-time": "0000-00-00 00:00:00"}
    after = components.plan_services.evaluate_pre_write(str(plan["plan_ref"]), draft_ref, principal)
    assert after["status"] == "invalidated"
    with pytest.raises(PlanningContractError):
        components.plan_services.resolve_execution_context(str(plan["plan_ref"]), draft_ref, principal)
    restarted = factory(provider, confirmation_settings)
    with pytest.raises(PlanningContractError):
        restarted.plan_services.resolve_execution_context(str(plan["plan_ref"]), draft_ref, principal)
    assert execution_store.claim_count == writes["posts"] == 0
    _assert_closed(state)
