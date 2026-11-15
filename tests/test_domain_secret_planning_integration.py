from dataclasses import replace
from types import SimpleNamespace

import pytest

from fortipam_mcp.onboarding_action_coordinator import FixedActionResolutionError
from fortipam_mcp.secret_onboarding_action_sequence import SecretOnboardingFixedActionSequenceResolver
from fortipam_mcp.secret_onboarding_projection_source import secret_onboarding_projection_contract
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_domain_secret_projection_reader import ABSENT, PRESENT, Transport, planning_source
from test_v4_planning import Authorizer, Issuer, _interaction, _promoted_registry, _requester
from v4_planning import M2PlanningEngine, ObjectClass, ChangeKind, PlanningDenied


def prepared_domain(inspection=ABSENT):
    draft, source = planning_source(Transport(inspection))
    draft = replace(draft, risk_class='medium')
    authorizer = Authorizer((draft,), projection_source_ref='fortipam-191-secret-onboarding-projection')
    authorizer._grants.add(('fortipam-700-domain-secret-projection', 'projection_source'))
    engine = M2PlanningEngine(
        _promoted_registry(), Issuer(), authorizer,
        projection_contract_resolver=lambda scheme, cls: secret_onboarding_projection_contract(cls),
    )
    requester = _requester()
    summary = engine.compile_summary(draft, requester, source.project(draft, requester, now_epoch=1800000000), now_epoch=1800000000)
    confirmation = engine.confirm_intent(summary.summary_ref, requester, _interaction(summary, requester), now_epoch=1800000001)
    return draft, source, engine, summary, confirmation


def test_domain_plans_one_fixed_create_and_rejects_existing_noop():
    draft, source, engine, summary, confirmation = prepared_domain()
    assert all(c.change_kind is ChangeKind.NO_OP for c in summary.object_changes
               if c.object_class is not ObjectClass.DOMAIN_SECRET_METADATA)
    change = next(c for c in summary.object_changes if c.object_class is ObjectClass.DOMAIN_SECRET_METADATA)
    assert dict(change.expected_fields) == {
        'exists': True, 'inherit_permission': True, 'non_privileged_account': True,
        'services_disabled': True, 'target_association_matches': True,
    }
    plan = engine.prepare_plan(summary.summary_ref, confirmation.confirmation_ref, _requester(), now_epoch=1800000002)
    assert len(plan.lines) == 1 and plan.lines[0].target_class is ObjectClass.DOMAIN_SECRET_METADATA
    assert plan.lines[0].depends_on == ()
    _, _, engine, summary, confirmation = prepared_domain(PRESENT)
    with pytest.raises(PlanningDenied, match='no-op'):
        engine.prepare_plan(summary.summary_ref, confirmation.confirmation_ref, _requester(), now_epoch=1800000002)


@pytest.mark.parametrize('mode', ['wrong_blueprint', 'expanded_fields', 'unverified_target', 'drift'])
def test_domain_rejects_expanded_intent_or_mutable_dependencies(mode):
    draft, source, engine, _, _ = prepared_domain()
    projections = source.project(draft, _requester(), now_epoch=1800000010)
    if mode == 'wrong_blueprint':
        draft = replace(draft, blueprint_ref='FPA-BP-006')
    elif mode in {'expanded_fields', 'unverified_target'}:
        cls = ObjectClass.DOMAIN_SECRET_METADATA if mode == 'expanded_fields' else ObjectClass.DOMAIN_TARGET_BINDING
        key = 'privileged_account' if mode == 'expanded_fields' else 'target_relation_matches'
        draft = replace(draft, desired_objects=tuple(
            replace(item, desired_fields=tuple(sorted({**dict(item.desired_fields), key: False}.items())))
            if item.object_class is cls else item for item in draft.desired_objects))
    else:
        from v4_planning import AuthoritativeProjection
        binding = source._binding
        projections = tuple(AuthoritativeProjection.from_mapping(
            contract=secret_onboarding_projection_contract(ObjectClass.DOMAIN_TARGET_BINDING),
            object_ref=item.object_ref, observed_at=1800000010, fresh_until=1800000310,
            fields={'exists': True, 'profile_ref': binding.target_profile_ref, 'target_relation_matches': False},
        ) if item.object_ref == binding.target_object_ref else item for item in projections)
    with pytest.raises(PlanningDenied):
        engine.compile_summary(draft, _requester(), projections, now_epoch=1800000010)


@pytest.mark.parametrize('mode', ['valid', 'missing_factory', 'digest_mismatch', 'external_dependency'])
def test_domain_fixed_sequence_requires_separate_factory_and_exact_binding(mode):
    draft, source, engine, summary, confirmation = prepared_domain()
    requester = _requester()
    plan = engine.prepare_plan(summary.summary_ref, confirmation.confirmation_ref, requester, now_epoch=1800000002)
    digest = source.inspect_domain_secret_binding_digest(draft, requester)
    runner = SimpleNamespace(onboarding_binding_digest='0' * 64 if mode == 'digest_mismatch' else digest)
    factory = SimpleNamespace(bind=lambda *args, **kwargs: runner)
    resolver = SecretOnboardingFixedActionSequenceResolver(
        None, source, None, domain_secret_runner_factory=None if mode == 'missing_factory' else factory,
    )
    kwargs = {'external_dependency_refs': ('external-dependency-ref01',)} if mode == 'external_dependency' else {}
    if mode == 'valid':
        result = resolver.bind_prepared(plan, draft, V4PlanningPrincipal(requester, 'a' * 64), **kwargs)
        assert result.runners == (runner,)
    else:
        with pytest.raises(FixedActionResolutionError):
            resolver.bind_prepared(plan, draft, V4PlanningPrincipal(requester, 'a' * 64), **kwargs)


def test_persistent_domain_host_previews_registered_profile_without_execution(tmp_path):
    import json
    from fortipam_mcp.linux_onboarding_prepare import _reference_bindings
    from fortipam_mcp.v4_runtime_host import domain_secret_v4_plan_host_factory
    from test_ad_discovery_v4_host import _host_settings
    from test_v4_planning import NOW

    transport = Transport()
    draft, source = planning_source(transport)
    draft = replace(draft, risk_class='medium')
    settings, provider, confirmation = _host_settings(tmp_path)
    binding_path = tmp_path / 'domain-binding.private.json'
    settings = replace(settings, host_mode='source-backed-secret-onboarding',
                       secret_onboarding_binding_path=binding_path)
    components = domain_secret_v4_plan_host_factory(settings, binding=source._binding,
        secret_transport=transport, clock=lambda: NOW)(provider, confirmation)
    assert transport.calls == []
    requester = _requester()
    principal = V4PlanningPrincipal(requester, 'a' * 64)
    references = _reference_bindings(draft, include_access_source=False,
        projection_contract_resolver=secret_onboarding_projection_contract)
    components.reference_authority.issue_many(tuple(
        (item['reference'], item['reference_kind']) for item in references),
        requester_digest=requester.digest, environment_ref=draft.environment_ref,
        scope_ref=draft.scope_ref, expires_at=NOW + 300, now_epoch=NOW)
    draft_ref = components.scheme_draft_authority.issue(draft, requester,
        expires_at=NOW + 300, now_epoch=NOW)
    preview = components.plan_services.preview(draft_ref, principal)
    assert {item['object_class']: item['change_kind'] for item in preview['object_changes']} == {
        'FolderBinding': 'no_op', 'TemplateBinding': 'no_op',
        'DomainTargetBinding': 'no_op', 'DomainSecretMetadata': 'create',
    }
    assert len(transport.calls) == 1
    status = components.plan_services.status()
    assert status['dispatchable'] is False and status['executor_mcp_exposed'] is False
    # The synthetic OAuth origin shares the fixture's DNS suffix legitimately.
    serialized = json.dumps({key: value for key, value in preview.items()
                             if key != 'confirmation_url'})
    for field in ('folder_path', 'secret_name', 'target_name', 'target_ipv4_address', 'domain_dns_root'):
        assert getattr(source._binding.create_binding, field) not in serialized
