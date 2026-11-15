"""Source/Target joins and protected account use without material in previews."""
from dataclasses import replace
import hashlib
import json

import httpx
import pytest

from fortipam_mcp import unix_discovery_onboarding_guard as g
from fortipam_mcp.linux_onboarding_prepare import prepare_linux_onboarding_bundle
from fortipam_mcp.secret_create_central_lab_provider import CentralLabInventorySecretCreateProvider
from fortipam_mcp.unix_discovery_onboarding_prepare import prepare_selected_unix_onboarding_bundle
from v4_planning.material_provider import C3MaterialBinding, MaterialAccessDenied, MaterialBindingStatus
from test_discovery_review_http_transport import _response, _Body
from test_target_preservation_contract import row as target_row
from test_secret_create_191_projection_reader import _binding
from test_secret_create_central_lab_provider import _request, NOW
from test_unix_discovery_onboarding_prepare import _fixture, _SelectionReader
from test_secret_create_lab_auto_runtime import _Services, _central_lab_draft, _promoter
from fortipam_mcp.secret_create_lab_auto_runtime import (
    FortiPam191LabAutoSecretCreateRunnerFactory, LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_PROFILE,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from fortipam_mcp.onboarding_action_coordinator import FixedActionResolutionError, OnboardingActionCoordinatorError
from v4_planning import InMemoryM4ExecutionStateStore
from v4_planning.material_runtime import InMemoryMaterialUseStateStore

ACCOUNT = "fpam-bp014-discovery-r3"
SERIAL = "SYNTHETIC"
UUID = "b05f3437-c57d-44b0-8b3a-42d79827b071"
SENTINEL = "MATERIAL_SENTINEL"


class Harness:
    def __init__(self, tmp_path, fault=None):
        self.selection, self.settings = _fixture(tmp_path)
        self.fault, self.now = fault, 10.0
        self.requests, self.clients = [], []
        value = _response(); value["serial"] = SERIAL
        source = value["results"][0]; source["name"] = "bp014-discovery-unix-disabled-r13"
        source["discovery-results"][0]["name"] = ACCOUNT
        self.source = value
        self.secret = {"id": 17, "target": "test-target", "template": "Unix Account (SSH Password)",
            "uuid": UUID, "field": [{"name": "Password", "value": SENTINEL}]}
        self.target = target_row(); self.target.update(name="test-target", address="192.0.2.20", q_origin_key="test-target")

    def handle(self, request):
        index = len(self.requests) % 6; self.requests.append(request)
        if index in (0, 5):
            value = json.loads(json.dumps(self.source))
            if self.fault == "managed": value["results"][0]["discovery-results"][0]["managed-status"] = 42
            elif self.fault == "source-drift" and index == 5: value["results"][0]["last-discovery-time"] = "2026-09-30 02:37:00"
            return httpx.Response(200, headers={"content-type": "application/json"},
                stream=_Body(json.dumps(value).encode(), lambda: None))
        row = dict(self.secret if index in (1, 4) else self.target)
        table = "database" if index in (1, 4) else "target"
        if self.fault == "wrong-relation" and index == 1: row["target"] = "other-target"
        elif self.fault == "secret-drift" and index == 4: row["uuid"] = "44be4815-70f2-4f75-a420-1f44be9f801a"
        elif self.fault == "missing-uuid" and index == 1: del row["uuid"]
        elif self.fault == "target-drift" and index == 3: row["hostkey"] = [{"changed": SENTINEL}]
        elif self.fault == "wrong-address" and index == 2: row["address"] = "192.0.2.99"
        value = dict(version="v7.0.0", build=29, path="secret", name=table, http_method="GET",
            http_status=200, status="OK" if table == "database" else "success", vdom="root", serial=SERIAL, results=[row])
        if self.fault == "wrong-device" and index == 1: value["serial"] = "OTHER"
        if self.fault == "late": self.now += 31
        return httpx.Response(200, headers={"content-type": "application/json"},
            stream=_Body(json.dumps(value).encode(), lambda: None))

    def factory(self, **kwargs):
        client = httpx.Client(transport=httpx.MockTransport(self.handle), **kwargs)
        self.clients.append(client); return client

    def guard(self):
        self.reader = g.UnixDiscoveryOnboardingGuard(g.SecretMetadataHttpTransportConfig(
            "https://synthetic.invalid", "synthetic-token", 10, None),
            selection_binding_path=self.selection, profile_path=self.settings.profile_path,
            clock=lambda: self.now, client_factory=self.factory)
        return self.reader

    def binding(self):
        return replace(_binding(), folder_path="private/folder/test-folder", secret_name="test-secret-r3",
            target_name="test-target", target_ipv4_address="192.0.2.20", template_name="Unix Account (SSH Password)")


class Loader:
    def __init__(self, user=ACCOUNT):
        self.calls = 0
        self.buffers = (bytearray(user.encode()), bytearray(b"SYNTHETIC_PASSWORD"))
    def validate_prebound(self): return MaterialBindingStatus.AVAILABLE
    def load_secret_create_material_once(self): self.calls += 1; return self.buffers


def test_complete_source_relation_brackets_and_opaque_fields_clear(monkeypatch, tmp_path):
    h = Harness(tmp_path); guard = h.guard(); owned = []; original = guard._get
    def tracked(*args):
        raw = original(*args); owned.append(raw)
        if args[1] == guard._secret_path: assert SENTINEL.encode() not in raw
        return raw
    monkeypatch.setattr(guard, "_get", tracked)
    loads = json.loads
    def limited(value, *args, **kwargs):
        if isinstance(value, (bytes, bytearray)): assert SENTINEL.encode() not in value
        return loads(value, *args, **kwargs)
    monkeypatch.setattr(json, "loads", limited)
    relation = guard.observe()
    assert relation.selected_account_unmanaged and len(relation.relation_digest) == 64
    assert len(h.requests) == 6 and all(request.method == "GET" for request in h.requests)
    assert [request.url.path for request in h.requests] == [request.url.path for request in reversed(h.requests)]
    assert all(not raw for raw in owned) and all(client.is_closed for client in h.clients)
    assert ACCOUNT not in repr(guard) and ACCOUNT not in repr(relation)
    guard.close(); assert not guard._key


@pytest.mark.parametrize("fault", ["managed", "source-drift", "wrong-relation", "secret-drift", "missing-uuid",
    "target-drift", "wrong-address", "wrong-device", "late"])
def test_wrong_ineligible_or_drifting_relation_never_loads_material(tmp_path, fault):
    h = Harness(tmp_path, fault); guard = h.guard(); original = Loader()
    loader = guard.material_loader(original, h.binding())
    assert loader.validate_prebound() is MaterialBindingStatus.AVAILABLE and not h.requests
    with pytest.raises(MaterialAccessDenied): loader.load_secret_create_material_once()
    assert original.calls == 0 and all(client.is_closed for client in h.clients)
    assert len(h.requests) == (1 if fault == "managed" else len(h.requests))
    with pytest.raises(MaterialAccessDenied): loader.load_secret_create_material_once()
    assert original.calls == 0


@pytest.mark.parametrize("user", [ACCOUNT, "other-private-account"])
def test_real_provider_releases_only_matching_account_and_clears_on_denial(tmp_path, user):
    h = Harness(tmp_path); guard = h.guard(); original = Loader(user)
    loader = guard.material_loader(original, h.binding())
    opaque = C3MaterialBinding(); request = _request()
    provider = CentralLabInventorySecretCreateProvider(loader, binding=opaque, request=request, clock=lambda: NOW)
    assert provider.validate_binding(opaque, request) is MaterialBindingStatus.AVAILABLE
    assert original.calls == 0 and not h.requests
    if user == ACCOUNT:
        lease = provider.acquire_lease(opaque, request)
        assert original.calls == 1
        provider.release_lease(lease)
    else:
        with pytest.raises(MaterialAccessDenied): provider.acquire_lease(opaque, request)
    assert all(not raw for raw in original.buffers) and original.calls == 1
    with pytest.raises(MaterialAccessDenied): provider.acquire_lease(opaque, request)
    assert original.calls == 1
    guard.close()


@pytest.mark.parametrize("field", ["target_name", "target_ipv4_address", "secret_name", "template_name", "folder_path"])
def test_other_onboarding_subject_is_denied_before_any_io(tmp_path, field):
    h = Harness(tmp_path); guard = h.guard(); binding = replace(h.binding(), **{field: "other" if field != "target_ipv4_address" else "192.0.2.99"})
    with pytest.raises(g.UnixDiscoveryHandoffError): guard.material_loader(Loader(), binding)
    assert not h.requests


def test_preparer_uses_guard_and_same_effective_profile_without_loading_credentials(tmp_path):
    h = Harness(tmp_path); guard = h.guard()
    result = prepare_selected_unix_onboarding_bundle(selection_binding_path=h.selection, settings=h.settings,
        selection_reader=_SelectionReader("prepare_existing_onboarding"), relation_guard=guard)
    assert result["status"] == "prepared" and len(h.requests) == 6
    assert len(list(h.settings.output_directory.iterdir())) == 4
    assert ACCOUNT not in json.dumps(result)
    guard.close()


def test_profile_change_cannot_be_substituted_after_qualified_read(tmp_path):
    h = Harness(tmp_path); guard = h.guard(); before = h.settings.profile_path.read_bytes()
    value = json.loads(before); value["target_name"] = "other-target"
    h.settings.profile_path.write_text(json.dumps(value))
    with pytest.raises(Exception): prepare_linux_onboarding_bundle(h.settings, expected_profile_digest=guard.profile_digest)
    assert not list(h.settings.output_directory.iterdir())
    with pytest.raises(g.UnixDiscoveryHandoffError): guard.observe()
    assert not h.requests


@pytest.mark.parametrize("field", ["selection", "profile", "config", "key", "clock"])
def test_pinned_input_drift_denies_before_network(tmp_path, field):
    h = Harness(tmp_path); guard = h.guard()
    if field == "selection": h.selection.write_bytes(h.selection.read_bytes() + b" ")
    elif field == "profile": h.settings.profile_path.write_bytes(h.settings.profile_path.read_bytes() + b" ")
    elif field == "config": object.__setattr__(guard._config, "bearer_token", "other")
    elif field == "key": guard._key[0] ^= 1
    elif field == "clock": guard._clock = lambda: 10.0
    with pytest.raises(g.UnixDiscoveryHandoffError): guard.observe()
    assert not h.requests


def test_environment_guard_is_explicit_paired_and_default_absent(tmp_path):
    h = Harness(tmp_path); guard = h.guard(); config = guard._config
    assert g.guard_from_environment({}, config) is None
    with pytest.raises(g.UnixDiscoveryHandoffError):
        g.guard_from_environment({g.ENV_PREFIX + "SELECTION_BINDING_FILE": str(h.selection)}, config)
    configured = g.guard_from_environment({g.ENV_PREFIX + "SELECTION_BINDING_FILE": str(h.selection),
        g.ENV_PREFIX + "PROFILE_FILE": str(h.settings.profile_path)}, config)
    assert type(configured) is g.UnixDiscoveryOnboardingGuard and not h.requests
    configured.close(); guard.close()


def factory(h, guard):
    services = _Services()
    path = h.settings.profile_path.parent / "credential-bindings.yaml"
    path.write_text("schema_version: credential-bindings-v1\nbindings:\n  - id: fixed-secret-create\n    provider: env-file\n    variables:\n      username: FIXED_TEST_USERNAME\n      password: FIXED_TEST_PASSWORD\n")
    path.chmod(0o600)
    result = FortiPam191LabAutoSecretCreateRunnerFactory(
        promoter=_promoter(services, LAB_AUTO_SECRET_CREATE_LINUX_700_CANDIDATE_PROFILE),
        credential_bindings_path=path, secret_env_path=path.parent / "must-not-read.env",
        material_binding_ref="private-material-binding-ref01", credential_binding_id="fixed-secret-create",
        transport_config=guard._config, material_state_store=InMemoryMaterialUseStateStore(),
        execution_store=InMemoryM4ExecutionStateStore(), discovery_guard=guard,
        clock=lambda: services.plan.created_at + 1)
    return services, result


@pytest.mark.parametrize("managed", [False, True])
def test_existing_runner_checks_relation_before_m4_derivation_and_does_not_load_credentials(tmp_path, monkeypatch, managed):
    h = Harness(tmp_path, "managed" if managed else None); guard = h.guard(); services, runner = factory(h, guard)
    calls = []; original = type(runner._promoter)._derive_original_artifacts
    def derive(self, *args, **kwargs): calls.append("derive"); return original(self, *args, **kwargs)
    monkeypatch.setattr(type(runner._promoter), "_derive_original_artifacts", derive)
    def bind():
        return runner.bind(services.plan, services.plan.lines[0].line_ref,
            V4PlanningPrincipal(services.requester, "a" * 64), draft=_central_lab_draft(services),
            onboarding_binding=h.binding())
    if managed:
        with pytest.raises(FixedActionResolutionError): bind()
        assert not calls and len(h.requests) == 1
    else:
        result = bind(); assert result.line_ref == services.plan.lines[0].line_ref
        assert calls == ["derive"] and len(h.requests) == 6
        # The actual provider owns the guarded resolver, not the raw resolver.
        provider = result.runtime._material_runtime._coordinator._provider
        assert type(provider._loader).__name__ == "_SelectedAccountLoader"
    assert not (h.settings.profile_path.parent / "must-not-read.env").exists()


def test_unauthenticated_parent_and_other_api_source_cannot_trigger_handoff_reads(tmp_path):
    h = Harness(tmp_path); guard = h.guard(); services, runner = factory(h, guard)
    with pytest.raises(OnboardingActionCoordinatorError):
        runner.bind(services.plan, services.plan.lines[0].line_ref, None,
            draft=_central_lab_draft(services), onboarding_binding=h.binding())
    assert not h.requests
    with pytest.raises(g.UnixDiscoveryHandoffError): guard.check_transport(replace(guard._config))


def test_source_is_rechecked_at_material_use_after_an_earlier_valid_observation(tmp_path):
    h = Harness(tmp_path); guard = h.guard(); guard.observe()
    original = Loader(); loader = guard.material_loader(original, h.binding())
    h.fault = "managed"
    with pytest.raises(MaterialAccessDenied): loader.load_secret_create_material_once()
    assert original.calls == 0 and len(h.requests) == 7


def test_profile_drift_during_delegate_load_erases_both_material_buffers(tmp_path):
    h = Harness(tmp_path); guard = h.guard()
    class DriftingLoader(Loader):
        def load_secret_create_material_once(self):
            result = super().load_secret_create_material_once()
            h.settings.profile_path.write_bytes(h.settings.profile_path.read_bytes() + b" ")
            return result
    original = DriftingLoader(); loader = guard.material_loader(original, h.binding())
    with pytest.raises(MaterialAccessDenied): loader.load_secret_create_material_once()
    assert original.calls == 1 and all(not raw for raw in original.buffers)


def test_resolver_cannot_substitute_a_different_record_for_the_pinned_bytes(tmp_path, monkeypatch):
    h = Harness(tmp_path); original = g._load_review_binding
    def changed(path):
        request, _ = original(path)
        return request, "fpam-bp014-discovery-r4"
    monkeypatch.setattr(g, "_load_review_binding", changed)
    with pytest.raises(g.UnixDiscoveryHandoffError): h.guard()
    assert not h.requests
