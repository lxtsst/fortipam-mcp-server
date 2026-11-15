"""Actual synthetic Owner and Source HTTP through fixed parent-plan promotion."""

from dataclasses import replace

import pytest

import fortipam_mcp.owner_discovery_runtime as owner_module
from fortipam_mcp.ad_discovery_action_sequence import AdDiscoveryFixedActionSequenceResolver
from fortipam_mcp.ad_discovery_lab_auto_runtime import AdDiscoveryLabAutoPromoter, AdDiscoveryLabAutoRunnerFactory
from fortipam_mcp.ad_discovery_projection_source import AdDiscoveryPlanningBinding, AdDiscoveryPlanningSource, OUTCOME
from fortipam_mcp.domain_secret_projection_reader import DomainSecretPlanningBinding
from fortipam_mcp.onboarding_action_coordinator import FixedActionResolutionError, OnboardingActionCoordinator
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_ad_discovery_projection_source import _engine
from test_owner_discovery_runtime import _composition, _assert_closed
from test_v4_planning import NOW, _desired, _interaction, _requester, _secret_draft
from v4_planning import ChangeKind, M4AuthorizationDenied, ObjectClass, SchemeId, canonical_digest


def _context(tmp_path, monkeypatch, *, drift_on=None, standing=True, gate=True):
    runtime, _, private, store, writes, state = _composition(tmp_path, monkeypatch,
        gate_open=False, drift_on=drift_on)
    base = _secret_draft()
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    domain = DomainSecretPlanningBinding(private.domain_binding, principal.requester.digest,
        base.environment_ref, base.scope_ref, "ad-folder-object-ref01", "ad-folder-ref0001",
        "ad-target-object-ref01", "ad-target-profile-ref01", "ad-template-object-ref01",
        "ad-template-ref01", "ad-secret-object-ref01")
    binding = AdDiscoveryPlanningBinding(private, domain, "ad-source-object-ref01")
    owner = owner_module.owner_domain_transport(runtime._owner_config, private.domain_binding,
        runtime._credentials, allow_secret_create=False)
    source = AdDiscoveryPlanningSource(binding, owner, runtime._source_transport)
    draft = replace(base, scheme_id=SchemeId.BULK_ONBOARDING, blueprint_ref="FPA-BP-014",
        outcome_code=OUTCOME, material_reference_metadata=None, risk_class="medium",
        desired_objects=tuple(_desired(ref, cls, fields) for ref, (cls, fields) in binding.expected_objects().items()))
    engine = _engine(draft)
    summary = engine.compile_summary(draft, principal.requester,
        source.project(draft, principal.requester, now_epoch=NOW), now_epoch=NOW)
    confirmation = engine.confirm_intent(summary.summary_ref, principal.requester,
        _interaction(summary, principal.requester), now_epoch=NOW + 1)
    plan = engine.prepare_plan(summary.summary_ref, confirmation.confirmation_ref,
        principal.requester, now_epoch=NOW + 2)
    promoter = AdDiscoveryLabAutoPromoter(b"s" * 32, projection_source=source,
        authorized_environment_ref=draft.environment_ref, authorized_scope_ref=draft.scope_ref,
        standing_lab_authorization=standing)
    factory = AdDiscoveryLabAutoRunnerFactory(promoter=promoter, execution_store=store,
        source_transport=runtime._source_transport, owner_config=runtime._owner_config,
        owner_credentials=runtime._credentials, clock=lambda: NOW + 3,
        **({} if gate is None else {"execution_gate_open": gate}))
    return draft, plan, principal, source, promoter, factory, engine, store, writes, state


def _bind(context):
    draft, plan, principal, source, _, factory, *_ = context
    return factory.bind(plan, plan.lines[0].line_ref, principal,
        draft=draft, discovery_binding=source._binding)


class _Services:
    def __init__(self, context):
        self.draft, self.plan, self.principal, self.source, _, _, self.engine, *_ = context

    def resolve_execution_context(self, plan_ref, draft_ref, principal):
        if plan_ref != self.plan.plan_ref or draft_ref != "fixed-ad-draft-ref01" or principal != self.principal:
            raise ValueError
        return self.plan, self.draft

    def evaluate_pre_write(self, plan_ref, draft_ref, principal):
        self.resolve_execution_context(plan_ref, draft_ref, principal)
        projections = self.source.project(self.draft, principal.requester, now_epoch=NOW + 3)
        result = self.engine.evaluate_pre_write(plan_ref, projections, now_epoch=NOW + 3)
        return {"status": result.status.value}

    def evaluate_post_write(self, plan_ref, draft_ref, principal):
        self.resolve_execution_context(plan_ref, draft_ref, principal)
        projections = self.source.project(self.draft, principal.requester, now_epoch=NOW + 4)
        result = self.engine.evaluate_post_write(plan_ref, projections, now_epoch=NOW + 4)
        return {"status": result.status.value}


def test_actual_http_coordinator_one_source_create_and_independent_readbacks(tmp_path, monkeypatch):
    c = _context(tmp_path, monkeypatch)
    draft, plan, principal, source, promoter, factory, _, store, writes, state = c
    services = _Services(c)
    resolver = AdDiscoveryFixedActionSequenceResolver(services, source, factory)
    coordinator = OnboardingActionCoordinator(services, resolver)
    runner = resolver.bind_prepared(plan, draft, principal).runners[0]
    assert runner.discovery_binding_digest == source.inspect_private_binding_digest(draft, principal.requester)
    assert runner.depends_on == ()
    artifact = promoter.promote(plan, plan.lines[0].line_ref, principal, draft=draft,
        discovery_binding=source._binding, now_epoch=NOW + 3)
    assert artifact.plan.parameters_digest == source._binding.source.parameters_digest
    assert artifact.plan.expected_current_digest != plan.lines[0].expected_current_digest
    assert not plan.dispatchable and draft.material_reference_metadata is None
    result = coordinator.execute(plan.plan_ref, "fixed-ad-draft-ref01", principal)
    assert result.outcome == "succeeded" and result.post_write_status == "expected_state_matches"
    assert result.completed_line_refs == (plan.lines[0].line_ref,)
    assert writes["posts"] == store.claim_count == 1 and writes["reads_after_post"] >= 3
    with pytest.raises(M4AuthorizationDenied):
        runner.execute_bound()
    assert writes["posts"] == store.claim_count == 1
    _assert_closed(state)


@pytest.mark.parametrize("standing,gate", [(True, None), (False, True)])
def test_no_gate_or_no_standing_authority_has_no_reads_or_claim(tmp_path, monkeypatch, standing, gate):
    c = _context(tmp_path, monkeypatch, standing=standing, gate=gate)
    *_, store, writes, state = c
    before = state["credentials"], state["factories"], len(state["calls"]), len(writes["calls"])
    with pytest.raises(FixedActionResolutionError):
        _bind(c)
    assert before == (state["credentials"], state["factories"], len(state["calls"]), len(writes["calls"]))
    assert store.claim_count == writes["posts"] == 0


@pytest.mark.parametrize("mode", ["scope", "requester", "expiry", "current", "expected", "update", "class", "contract", "dependency", "binding", "line_ref"])
def test_promotion_rejects_substitution_before_owner_access(tmp_path, monkeypatch, mode):
    draft, plan, principal, source, promoter, _, _, store, writes, state = _context(tmp_path, monkeypatch)
    binding, line_ref, now = source._binding, plan.lines[0].line_ref, NOW + 3
    if mode == "scope":
        values = {**plan.canonical_content(), "scope_ref": "other-scope-ref01"}
        plan = replace(plan, scope_ref=values["scope_ref"], plan_digest=canonical_digest(values))
    elif mode == "requester":
        principal = V4PlanningPrincipal(_requester("other"), "a" * 64)
    elif mode == "expiry":
        now = plan.expires_at
    elif mode == "binding":
        binding = replace(binding, source=replace(binding.source, private_nonce="b" * 64))
    elif mode == "line_ref":
        line_ref = "other-line-ref01"
    else:
        updates = {"current": {"expected_current_digest": "a" * 64},
            "expected": {"expected_state_digest": "b" * 64}, "update": {"change_kind": ChangeKind.UPDATE},
            "class": {"target_class": ObjectClass.DOMAIN_SECRET_METADATA}, "contract": {"projection_contract_ref": "other-contract"},
            "dependency": {"depends_on": ("other-line-ref01",)}}[mode]
        line = replace(plan.lines[0], **updates)
        plan = replace(plan, lines=(line,), plan_digest=canonical_digest({**plan.canonical_content(), "lines": [line.as_dict()]}))
    before = state["credentials"], len(writes["calls"])
    with pytest.raises(FixedActionResolutionError):
        promoter.promote(plan, line_ref, principal, draft=draft, discovery_binding=binding, now_epoch=now)
    assert before == (state["credentials"], len(writes["calls"]))
    assert store.claim_count == writes["posts"] == 0


@pytest.mark.parametrize("drift_on,claims", [(2, 0), (3, 1)])
def test_initial_or_reserved_dependency_drift_never_posts(tmp_path, monkeypatch, drift_on, claims):
    c = _context(tmp_path, monkeypatch, drift_on=drift_on)
    runner = _bind(c)
    *_, store, writes, state = c
    if claims:
        result = runner.execute_bound()
        assert result["outcome"] != "succeeded"
    else:
        with pytest.raises(M4AuthorizationDenied):
            runner.execute_bound()
    assert store.claim_count == claims and writes["posts"] == 0
    if claims:
        runner.execute_bound()
        assert store.claim_count == claims and writes["posts"] == 0
    _assert_closed(state)


def test_prewrite_source_drift_blocks_coordinator_before_claim(tmp_path, monkeypatch):
    c = _context(tmp_path, monkeypatch)
    _, plan, principal, source, _, factory, _, store, writes, _ = c
    writes["row"] = {**source._binding.source.request.body(), "last-discovery-time": "0000-00-00 00:00:00",
        "q_origin_key": source._binding.source.request.source_name}
    services = _Services(c)
    coordinator = OnboardingActionCoordinator(services,
        AdDiscoveryFixedActionSequenceResolver(services, source, factory))
    result = coordinator.execute(plan.plan_ref, "fixed-ad-draft-ref01", principal)
    assert result.outcome == "precondition_failed" and result.pre_write_status == "invalidated"
    assert store.claim_count == writes["posts"] == 0


def test_parent_line_claim_namespace_is_stable_across_client_contexts(tmp_path, monkeypatch):
    draft, plan, principal, source, promoter, *_ = _context(tmp_path, monkeypatch)
    def issue(who):
        return promoter.promote(plan, plan.lines[0].line_ref, who, draft=draft,
            discovery_binding=source._binding, now_epoch=NOW + 3)
    original = issue(principal)
    assert issue(principal) == original
    changed = issue(replace(principal, transport_namespace_digest="b" * 64))
    assert changed.authorization != original.authorization
    assert changed.policy_decision_digest != original.policy_decision_digest
    assert changed.plan.idempotency_digest == original.plan.idempotency_digest


def test_logout_failure_after_post_preserves_terminal_claim_and_stable_error(tmp_path, monkeypatch):
    c = _context(tmp_path, monkeypatch)
    *_, store, writes, state = c
    scoped = owner_module.owner_domain_transport
    initial_owners = len(state["owners"])

    def revoke_failure(*args, **kwargs):
        owner = scoped(*args, **kwargs)
        create_client = owner._session_factory
        def session(**options):
            client = create_client(**options)
            handler = client._transport.handler
            def respond(request):
                response = handler(request)
                if request.url.path == "/logout":
                    state["active"] = True
                return response
            client._transport.handler = respond
            return client
        owner._session_factory = session
        return owner

    monkeypatch.setattr(owner_module, "owner_domain_transport", revoke_failure)
    runner = _bind(c)
    for _ in range(2):
        with pytest.raises(M4AuthorizationDenied, match="Fixed AD Discovery standing lab authorization is unavailable"):
            runner.execute_bound()
        assert store.claim_count == writes["posts"] == 1
    assert all(not owner.logout_verified for owner in state["owners"][initial_owners:])
    assert all(client.is_closed and not client.cookies for client in state["clients"])
    assert all(owner._client is None for owner in state["owners"])


def test_verifier_failure_retains_uncertain_claim_and_never_reposts(tmp_path, monkeypatch):
    from fortipam_mcp import ad_discovery_lab_auto_runtime as module
    c = _context(tmp_path, monkeypatch)
    runner = _bind(c)
    *_, store, writes, state = c
    def deny(*args, **kwargs):
        raise M4AuthorizationDenied("synthetic authorization failure")
    monkeypatch.setattr(module._StandingLabVerifier, "verify", deny)
    with pytest.raises(M4AuthorizationDenied):
        runner.execute_bound()
    assert store.claim_count == 1 and writes["posts"] == 0
    result = runner.execute_bound()
    assert result["idempotent_replay"] and result["outcome"] == "reconciliation_required"
    assert store.claim_count == 1 and writes["posts"] == 0
    _assert_closed(state)


def test_changed_planning_origin_cannot_promote_to_another_writer_device(tmp_path, monkeypatch):
    c = _context(tmp_path, monkeypatch)
    source = c[3]
    *_, store, writes, state = c
    changed = replace(source._owner._config, base_url="https://different.example.test")
    source._owner._config = changed
    source._source_transport._config = changed
    before = state["credentials"], len(state["calls"]), len(writes["calls"])
    with pytest.raises(FixedActionResolutionError):
        _bind(c)
    assert before == (state["credentials"], len(state["calls"]), len(writes["calls"]))
    assert store.claim_count == writes["posts"] == 0
