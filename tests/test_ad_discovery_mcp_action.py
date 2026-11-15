"""Fixed AD MCP boundary over typed artifacts and the actual synthetic host join."""

from dataclasses import replace
import json

from mcp.server.auth.provider import AccessToken
import pytest

from fortipam_mcp.ad_discovery_lab_auto_runtime import AdDiscoveryLabAutoPromoter, AdDiscoveryLabAutoRunnerFactory
from fortipam_mcp.ad_discovery_mcp_action import (
    ProtectedAdDiscoveryMcpAction, V4_AD_DISCOVERY_EXECUTION_FEATURE_ENV,
    V4_AD_DISCOVERY_EXECUTION_TOOL, V4_AD_DISCOVERY_EXECUTION_UNAVAILABLE,
    V4AdDiscoveryExecutionConfigurationError, V4AdDiscoveryExecutionRuntimeError,
    ad_discovery_execution_principal_from_access_token, load_v4_ad_discovery_execution_feature,
)
from fortipam_mcp.onboarding_action_coordinator import (
    OnboardingActionCoordinator, OnboardingActionCoordinatorError, OnboardingActionSequenceResult,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings
from test_ad_discovery_host_planning import _host_context, _confirm_and_prepare
from test_ad_discovery_lab_auto_runtime import _context
from test_owner_discovery_runtime import _assert_closed
from test_v4_planning import _requester, _secret_draft
from v4_planning import ChangeKind, SchemeId, canonical_digest


_PRIVATE = "private-password-selector-192.0.2.10"


class _TypedServices:
    def __init__(self, plan, draft):
        self.plan, self.draft, self.calls = plan, draft, 0

    def resolve_execution_context(self, *_args):
        self.calls += 1
        return self.plan, self.draft


def _closed_action(context, *, enabled=False, services=None):
    draft, plan, _, _, _, _, *_ = context
    services = services or _TypedServices(plan, draft)
    coordinator = OnboardingActionCoordinator(None)
    action = ProtectedAdDiscoveryMcpAction(services, coordinator,
        authorized_environment_ref=draft.environment_ref,
        authorized_scope_ref=draft.scope_ref, **({} if enabled is None else {"execution_enabled": enabled}))
    return action, services, coordinator


def test_feature_defaults_false_and_accepts_only_exact_boolean_text():
    assert V4_AD_DISCOVERY_EXECUTION_TOOL == "execute_v4_ad_discovery_workflow"
    assert not load_v4_ad_discovery_execution_feature({})
    assert not load_v4_ad_discovery_execution_feature({V4_AD_DISCOVERY_EXECUTION_FEATURE_ENV: "false"})
    assert load_v4_ad_discovery_execution_feature({V4_AD_DISCOVERY_EXECUTION_FEATURE_ENV: "true"})
    for invalid in ("TRUE", " true", "1", "yes", "", True, 1):
        with pytest.raises(V4AdDiscoveryExecutionConfigurationError):
            load_v4_ad_discovery_execution_feature({V4_AD_DISCOVERY_EXECUTION_FEATURE_ENV: invalid})


def test_principal_reuses_existing_plan_and_operate_oauth_requirements():
    resource = "https://mcp.example.test/mcp"
    settings = V4PlanningAuthorizationSettings(resource, b"p" * 32)
    def token(scopes):
        return AccessToken(token="synthetic-sdk-token", client_id="client-0001", scopes=scopes,
            expires_at=2_000_000_000, resource=resource, subject="operator-0001",
            claims={"iss": "https://mcp.example.test/oauth"})
    for denied in (["fortipam:read", "fortipam:plan"], ["fortipam:read", "fortipam:operate"]):
        with pytest.raises(V4AdDiscoveryExecutionRuntimeError, match=V4_AD_DISCOVERY_EXECUTION_UNAVAILABLE):
            ad_discovery_execution_principal_from_access_token(token(denied), settings)
    principal = ad_discovery_execution_principal_from_access_token(
        token(["fortipam:read", "fortipam:plan", "fortipam:operate"]), settings)
    assert principal.requester.principal_class == "operator"


def test_default_wrapper_gate_has_zero_resolver_coordinator_reads_or_claim(tmp_path, monkeypatch):
    context = _context(tmp_path, monkeypatch, gate=None)
    action, services, coordinator = _closed_action(context, enabled=None)
    _, plan, principal, _, _, _, _, store, writes, state = context
    before = state["credentials"], len(writes["calls"]), len(state["calls"])
    def forbidden(*_args):
        pytest.fail("Closed wrapper called its coordinator.")
    monkeypatch.setattr(coordinator, "execute", forbidden)
    assert action.execution_preflight_available() is False
    with pytest.raises(V4AdDiscoveryExecutionRuntimeError):
        action.execute(plan.plan_ref, "ad-draft-ref01", principal)
    assert services.calls == 0 and store.claim_count == writes["posts"] == 0
    assert before == (state["credentials"], len(writes["calls"]), len(state["calls"]))


@pytest.mark.parametrize("mode", ["profile", "version", "outcome", "material", "requester", "scope", "environment", "line_noop", "line_set", "relation", "expanded", "wrong_type"])
def test_typed_profile_or_principal_substitution_never_reaches_coordinator(tmp_path, monkeypatch, mode):
    context = _context(tmp_path, monkeypatch, gate=None)
    draft, plan, principal, _, _, _, _, store, writes, state = context
    if mode == "profile":
        draft = replace(draft, scheme_id=SchemeId.SECRET_ONBOARDING)
    elif mode == "version":
        draft = replace(draft, scheme_version="2.0.0")
    elif mode == "outcome":
        draft = replace(draft, outcome_code="onboard_domain_account")
    elif mode == "material":
        draft = replace(draft, material_reference_metadata=_secret_draft().material_reference_metadata)
    elif mode == "requester":
        principal = replace(principal, requester=_requester("other"))
    elif mode in {"scope", "environment"}:
        field = mode + "_ref"
        plan = replace(plan, **{field: "other-context-ref01", "plan_digest": canonical_digest({
            **plan.canonical_content(), field: "other-context-ref01"})})
    elif mode in {"line_noop", "line_set"}:
        line = replace(plan.lines[0], change_kind=ChangeKind.NO_OP) if mode == "line_noop" else replace(plan.lines[0], line_ref="extra-source-line01")
        lines = (line,) if mode == "line_noop" else (*plan.lines, line)
        plan = replace(plan, lines=lines, plan_digest=canonical_digest({**plan.canonical_content(), "lines": [item.as_dict() for item in lines]}))
    elif mode in {"relation", "expanded"}:
        source = draft.desired_objects[-1]
        fields = dict(source.desired_fields)
        fields.update({"domain_secret_ref": "wrong-domain-secret-ref01"} if mode == "relation" else {"scan_requested": True})
        source = replace(source, desired_fields=tuple(sorted(fields.items())))
        draft = replace(draft, desired_objects=(*draft.desired_objects[:-1], source))
    else:
        plan = object()
    services = _TypedServices(plan, draft)
    action, _, coordinator = _closed_action(context, enabled=True, services=services)
    def forbidden(*_args):
        pytest.fail("Invalid AD artifacts reached the coordinator.")
    monkeypatch.setattr(coordinator, "execute", forbidden)
    before = state["credentials"], len(writes["calls"]), len(state["calls"])
    with pytest.raises(V4AdDiscoveryExecutionRuntimeError) as error:
        action.execute(context[1].plan_ref, "ad-draft-ref01", principal)
    assert str(error.value) == V4_AD_DISCOVERY_EXECUTION_UNAVAILABLE
    assert error.value.__cause__ is None
    assert services.calls == 1 and store.claim_count == writes["posts"] == 0
    assert before == (state["credentials"], len(writes["calls"]), len(state["calls"]))


def test_real_persistent_host_action_dispatch_readback_and_replay(tmp_path, monkeypatch):
    context = _host_context(tmp_path, monkeypatch)
    (draft, draft_ref, principal, source, _, _, _, _, clock, _, store, writes, state) = context
    components, _, _, plan, _ = _confirm_and_prepare(context)
    promoter = AdDiscoveryLabAutoPromoter(b"e" * 32, projection_source=source,
        authorized_environment_ref=draft.environment_ref, authorized_scope_ref=draft.scope_ref,
        standing_lab_authorization=True)
    runner_factory = AdDiscoveryLabAutoRunnerFactory(promoter=promoter, execution_store=store,
        source_transport=source._source_transport, owner_config=source._owner._config,
        owner_credentials=source._owner._credentials, clock=clock, execution_gate_open=True)
    action = ProtectedAdDiscoveryMcpAction(components.plan_services,
        components.bind_ad_discovery_action_coordinator(runner_factory),
        authorized_environment_ref=draft.environment_ref, authorized_scope_ref=draft.scope_ref,
        execution_enabled=True)
    before = state["credentials"], len(state["calls"]), len(writes["calls"])
    assert action.execution_preflight_available() is True
    assert before == (state["credentials"], len(state["calls"]), len(writes["calls"]))
    result = action.execute(str(plan["plan_ref"]), draft_ref, principal)
    assert result["outcome"] == "succeeded" and result["post_write_status"] == "expected_state_matches"
    assert result["authorization_scope"] == "source_bound_ad_discovery"
    assert result["policy_mode"] == "lab_auto" and result["lab_exception_applied"] is True
    assert writes["posts"] == store.claim_count == 1 and writes["reads_after_post"] >= 3
    private_digest = source.inspect_private_binding_digest(draft, principal.requester)
    public = json.dumps(result)
    assert private_digest not in public and source._binding.source.parameters_digest not in public
    assert source._binding.source.request.source_name not in public
    replay = action.execute(str(plan["plan_ref"]), draft_ref, principal)
    assert replay["outcome"] == "precondition_failed" and replay["pre_write_status"] == "invalidated"
    again = action.execute(str(plan["plan_ref"]), draft_ref, principal)
    assert again["outcome"] == "reconciliation_required" and again["failure_stage"] == "fixed_action_context"
    assert writes["posts"] == store.claim_count == 1
    _assert_closed(state)


@pytest.mark.parametrize("mode", ["outcome", "status", "line", "bool", "raw_error", "coordinator_error"])
def test_private_or_malformed_coordinator_output_never_leaks(tmp_path, monkeypatch, mode):
    context = _context(tmp_path, monkeypatch, gate=None)
    _, plan, principal, _, _, _, _, store, writes, _ = context
    action, _, coordinator = _closed_action(context, enabled=True)
    result = OnboardingActionSequenceResult("succeeded", (plan.lines[0].line_ref,), None,
        "match", "expected_state_matches", False)
    if mode in {"outcome", "status", "line", "bool"}:
        result = replace(result, **{"outcome": {"outcome": _PRIVATE}, "status": {"pre_write_status": _PRIVATE},
            "line": {"completed_line_refs": (_PRIVATE,)}, "bool": {"reconciliation_required": 1}}[mode])
    def execute(*_args):
        if mode == "raw_error":
            raise RuntimeError(_PRIVATE)
        if mode == "coordinator_error":
            raise OnboardingActionCoordinatorError(_PRIVATE)
        return result
    monkeypatch.setattr(coordinator, "execute", execute)
    if mode == "coordinator_error":
        response = action.execute(plan.plan_ref, "ad-draft-ref01", principal)
        assert response["outcome"] == "reconciliation_required"
        assert response["failure_stage"] == "fixed_action_resolution"
        assert _PRIVATE not in json.dumps(response)
    else:
        with pytest.raises(V4AdDiscoveryExecutionRuntimeError) as error:
            action.execute(plan.plan_ref, "ad-draft-ref01", principal)
        assert str(error.value) == V4_AD_DISCOVERY_EXECUTION_UNAVAILABLE
        assert _PRIVATE not in str(error.value) and error.value.__cause__ is None
    assert store.claim_count == writes["posts"] == 0


@pytest.mark.parametrize("gate", [None, True])
def test_local_preflight_requires_exact_candidate_gate_and_device_without_reads(tmp_path, monkeypatch, gate):
    from fortipam_mcp.ad_discovery_action_sequence import AdDiscoveryFixedActionSequenceResolver
    context = _context(tmp_path, monkeypatch, gate=gate)
    draft, plan, _, source, _, factory, _, store, writes, state = context
    services = _TypedServices(plan, draft)
    coordinator = OnboardingActionCoordinator(None, AdDiscoveryFixedActionSequenceResolver(services, source, factory))
    action = ProtectedAdDiscoveryMcpAction(services, coordinator,
        authorized_environment_ref=draft.environment_ref, authorized_scope_ref=draft.scope_ref,
        execution_enabled=True)
    before = state["credentials"], len(writes["calls"]), len(state["calls"])
    assert action.execution_preflight_available() is (gate is True)
    source._source_transport._config = replace(source._source_transport._config, base_url="https://other.example.test")
    assert action.execution_preflight_available() is False
    assert services.calls == 0 and store.claim_count == writes["posts"] == 0
    assert before == (state["credentials"], len(writes["calls"]), len(state["calls"]))
