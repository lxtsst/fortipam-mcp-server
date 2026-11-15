from dataclasses import replace
from typing import cast

import pytest

from fortipam_mcp.secret_metadata_http_transport import SecretMetadataInspection
from fortipam_mcp.winrm_collector_projection_reader import ADAPTER_REF, WinrmCollectorProjectionReader
from fortipam_mcp.secret_create_m4_runtime import ProtectedSecretCreateM4Runtime
from test_secret_create_191_http_transport import _winrm_binding
from test_secret_create_m4_runtime import _secret_plan, _binding, _Resolver, _Verifier
from test_v4_execution_kernel import _authorization, NOW
from test_v4_secret_create_runtime import _Provider, _Adapter, _runtime
from v4_planning import InMemoryM4ExecutionStateStore, M4AdapterFailure, M4Outcome, canonical_digest
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome, SecretCreatePrivateAdapter


class Transport:
    def __init__(self, preflight=True, post=True):
        self.preflight, self.post = preflight, post
        self.calls = []

    def inspect(self, *args):
        self.calls.append("inspect")
        return SecretMetadataInspection(False, True, True)

    def verify_winrm_collector_preflight(self, *args):
        self.calls.append("preflight")
        return self.preflight

    def resolve_existing_secret_id(self, *args):
        self.calls.append("resolve")
        return 23

    def verify_winrm_collector(self, *args, expected_secret_id, owner_name, expected_target_address,
                               expected_rdp_event_filter_profile):
        assert expected_target_address == "192.0.2.10"
        assert expected_secret_id == 23 and owner_name == "example-owner"
        assert expected_rdp_event_filter_profile == "mcp-v4-rdp-event-filter-example"
        self.calls.append("post")
        return self.post


def prepared(transport):
    private_binding = _winrm_binding()
    ref = "collector-object-ref01"
    reader = WinrmCollectorProjectionReader(private_binding, ref, transport)
    base = _secret_plan()
    changes = dict(adapter_ref=ADAPTER_REF, target_ref=ref,
                   parameters_digest=reader.inspect_onboarding_binding_digest(),
                   expected_current_digest=reader.state_digest(exists=False),
                   expected_state_digest=reader.state_digest(exists=True))
    content = {**base.canonical_content(), **changes}
    plan = replace(base, **changes, plan_digest=canonical_digest(content))
    reader = WinrmCollectorProjectionReader(replace(private_binding, plan_digest=plan.plan_digest), ref, transport)
    return plan, reader


@pytest.mark.parametrize("preflight, post, succeeds", [
    (True, True, True), (False, True, False), (True, False, False),
])
def test_collector_uses_existing_m4_checks_before_material_and_after_dispatch(preflight, post, succeeds):
    transport = Transport(preflight, post)
    plan, reader = prepared(transport)
    authorization = _authorization(plan)
    provider = _Provider()
    adapter = _Adapter(SecretCreateAdapterOutcome.VERIFIED_CREATED)
    runtime = ProtectedSecretCreateM4Runtime(
        _Resolver(_binding(plan, authorization)), _Verifier(), InMemoryM4ExecutionStateStore(),
        _runtime(provider, cast(SecretCreatePrivateAdapter, adapter)), reader,
        authenticated_requester_digest=plan.requester_digest, clock=lambda: NOW,
    )
    result = runtime.execute_bound(authorization.authorization_ref)
    assert (result.outcome is M4Outcome.SUCCEEDED) is succeeds
    if not preflight:
        assert provider.events == [] and adapter.calls == 0
        assert transport.calls == ["inspect", "preflight"]
    else:
        assert provider.events == ["validate", "acquire", "release"] and adapter.calls == 1
        assert transport.calls == ["inspect", "preflight", "resolve", "post"]


@pytest.mark.parametrize("field, value", [
    ("adapter_ref", "ordinary-secret-create-adapter"),
    ("target_ref", "different-object-ref01"),
    ("parameters_digest", "a" * 64),
    ("expected_current_digest", "b" * 64),
    ("expected_state_digest", "c" * 64),
])
def test_collector_rejects_plan_or_binding_substitution_before_reads(field, value):
    transport = Transport()
    plan, reader = prepared(transport)
    changed = replace(plan, **{field: value}, plan_digest=canonical_digest({
        **plan.canonical_content(), field: value,
    }))
    reader = WinrmCollectorProjectionReader(
        replace(reader._binding, plan_digest=changed.plan_digest), reader._object_ref, transport,
    )
    with pytest.raises(M4AdapterFailure):
        reader.read_current(changed)
    assert transport.calls == []


@pytest.mark.parametrize("mode", ["absent", "existing", "conflict", "wrong_selector", "wrong_provider", "wrong_purpose", "wrong_lifecycle"])
@pytest.mark.parametrize("owner_session", [False, True])
def test_collector_planning_source_produces_only_verified_create_or_noop(mode, owner_session):
    from fortipam_mcp.winrm_collector_projection_reader import (
        WinrmCollectorPlanningSource, winrm_collector_projection_contract,
    )
    from fortipam_mcp.secret_onboarding_projection_source import (
        SecretOnboardingBinding, secret_onboarding_projection_contract,
    )
    from test_v4_planning import _winrm_collector_draft, _promoted_registry, Issuer, Authorizer, _requester
    from v4_planning import M2PlanningEngine, ObjectClass, ChangeKind

    draft = _winrm_collector_draft()
    draft = replace(draft, material_reference_metadata=replace(draft.material_reference_metadata, provider_class="central_lab_inventory_reference"))
    invalid_material = {
        "wrong_provider": {"provider_class": "external_vault_lease"},
        "wrong_purpose": {"purpose": "credential_rotation"},
        "wrong_lifecycle": {"lifecycle": "unavailable"},
    }
    if mode in invalid_material:
        draft = replace(draft, material_reference_metadata=replace(draft.material_reference_metadata, **invalid_material[mode]))
    b = _winrm_binding()
    refs = {o.object_class: o for o in draft.desired_objects}
    bound = SecretOnboardingBinding(
        folder_object_ref=refs[ObjectClass.FOLDER_BINDING].object_ref,
        folder_path=b.folder_path, folder_ref=dict(refs[ObjectClass.FOLDER_BINDING].desired_fields)["folder_ref"],
        target_object_ref=refs[ObjectClass.TARGET].object_ref,
        target_name=b.target_name, target_protocol="rdp",
        connectivity_profile_ref=dict(refs[ObjectClass.TARGET].desired_fields)["connectivity_profile_ref"],
        target_ipv4_address=b.target_ipv4_address,
        template_object_ref=refs[ObjectClass.TEMPLATE_BINDING].object_ref,
        template_name=b.template_name, template_ref=dict(refs[ObjectClass.TEMPLATE_BINDING].desired_fields)["template_ref"],
        secret_object_ref=refs[ObjectClass.WINRM_COLLECTOR_METADATA].object_ref,
        secret_name=b.secret_name if mode != "wrong_selector" else "different-secret",
    )

    class Resolver:
        def resolve(self, requested, requester):
            assert requested is draft and requester == _requester()
            return bound

    class PlanningTransport(Transport):
        def inspect(self, *args):
            self.calls.append("inspect")
            return SecretMetadataInspection(mode == "existing", True, True)

    session_events = []
    if owner_session:
        from contextlib import contextmanager
        from fortipam_mcp.owner_session_metadata import OwnerSessionMetadataTransport
        class OwnerPlanningTransport(PlanningTransport, OwnerSessionMetadataTransport):
            @contextmanager
            def authenticated(self):
                session_events.append("login")
                try:
                    yield self
                finally:
                    session_events.append("logout")
        transport = OwnerPlanningTransport(preflight=mode != "conflict")
    else:
        transport = PlanningTransport(preflight=mode != "conflict")
    source = WinrmCollectorPlanningSource(b, Resolver(), transport)
    if mode in {"conflict", "wrong_selector"} or mode in invalid_material:
        with pytest.raises(M4AdapterFailure):
            source.project(draft, _requester(), now_epoch=NOW)
        assert session_events == (["login", "logout"] if owner_session else [])
        if mode == "wrong_selector" or mode in invalid_material:
            assert transport.calls == []
        return
    projections = source.project(draft, _requester(), now_epoch=NOW)
    assert session_events == (["login", "logout"] if owner_session else [])
    engine = M2PlanningEngine(
        _promoted_registry(), Issuer(), Authorizer((draft,),
            projection_source_ref=winrm_collector_projection_contract().source_ref),
        projection_contract_resolver=lambda scheme, cls: winrm_collector_projection_contract(cls),
    )
    summary = engine.compile_summary(draft, _requester(), projections, now_epoch=NOW)
    mutations = [c for c in summary.object_changes if c.change_kind is not ChangeKind.NO_OP]
    assert len(mutations) == (1 if mode == "absent" else 0)
    if mutations:
        assert mutations[0].object_class is ObjectClass.WINRM_COLLECTOR_METADATA
        assert mutations[0].change_kind is ChangeKind.CREATE
