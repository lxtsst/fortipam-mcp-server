"""Fixed AD M4 composition with synthetic HTTP responses and local state."""

from dataclasses import replace
import hashlib
import json

import httpx
import pytest

from fortipam_mcp.discovery_entry_create_contract import (
    DisabledAdDiscoveryCreateInput, DisabledUnixDiscoveryCreateInput,
)
from fortipam_mcp.discovery_entry_create_http_transport import (
    DiscoveryEntryCreateHttpTransportError, FortiPamDiscoveryEntryCreateHttpTransport,
)
from fortipam_mcp.discovery_entry_m4_adapter import (
    ACTION_ID, ACTION_VERSION, DiscoveryEntryBinding, DiscoveryEntryM4Adapter,
)
from fortipam_mcp.discovery_entry_m4_runtime import (
    DiscoveryEntryExecutionBinding, ProtectedDiscoveryEntryM4Runtime,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_discovery_entry_create_http_transport import _ad_dependency_fixture
from test_m4_execution_store import _store
from test_v4_execution_kernel import NOW, _authorization, _plan, _Verifier
from v4_planning import M4AuthorizationDenied, M4AdapterDenied, M4Outcome, M4Verification, canonical_digest


def _discovery_plan(source):
    base = _plan()
    changes = {
        "action_id": ACTION_ID, "action_version": ACTION_VERSION,
        "adapter_ref": source.adapter_ref, "target_ref": "discovery-entry",
        "parameters_digest": source.parameters_digest,
        "expected_current_digest": source.state_digest(exists=False),
        "expected_state_digest": source.state_digest(exists=True),
    }
    return replace(base, **changes, plan_digest=canonical_digest({**base.canonical_content(), **changes}))


class _Resolver:
    def __init__(self, source):
        plan = _discovery_plan(source)
        self.binding = DiscoveryEntryExecutionBinding(plan, _authorization(plan), source)

    def resolve_execution_binding(self, authorization_ref):
        assert authorization_ref == self.binding.authorization.authorization_ref
        return self.binding


class _DomainReader:
    """Repeat actual fixed Domain reads over fresh synthetic byte streams."""

    def __init__(self, monkeypatch, *, defect=None, drift_on=None):
        self.monkeypatch = monkeypatch
        self.defect = defect
        self.drift_on = drift_on
        self.inspections = 0
        self.calls = []

    def inspect_domain_account_projection(self, binding, *, expected_secret_id=None):
        self.inspections += 1
        defect = "target:class" if self.drift_on == self.inspections else self.defect
        with self.monkeypatch.context() as local:
            _, native, calls, *_ = _ad_dependency_fixture(local, defect)
            try:
                return native.inspect_domain_account_projection(binding, expected_secret_id=expected_secret_id)
            finally:
                self.calls.extend(calls)


def _synthetic_source_transport(monkeypatch, source, *, ambiguous_ack=False):
    state = {"row": None, "posts": 0, "calls": [], "reads_after_post": 0}

    def envelope(method, status):
        return {"http_method": method, "http_status": status,
                "status": "success" if status == 200 else "error", "path": "secret",
                "name": "discovery", "vdom": "root", "version": "v7.0.0", "build": 29}

    def respond(request):
        state["calls"].append((request.method, request.url.path))
        if request.method == "POST":
            assert request.url.path == "/api/v2/cmdb/secret/discovery"
            assert json.loads(request.content) == source.request.body()
            state["posts"] += 1
            state["row"] = {**source.request.body(), "last-discovery-time": "0000-00-00 00:00:00",
                            "q_origin_key": source.request.source_name}
            return httpx.Response(500 if ambiguous_ack else 200, json={})
        assert request.method == "GET" and request.content == b""
        assert request.url.path == "/api/v2/cmdb/secret/discovery/" + source.request.source_name
        if state["row"] is None:
            return httpx.Response(404, json={**envelope("GET", 404), "results": []})
        state["reads_after_post"] += 1
        row = state["row"]
        if "format" in request.url.params:
            keys = set(request.url.params["format"].split("|")) | {"q_origin_key"}
            row = {key: value for key, value in row.items() if key in keys}
        return httpx.Response(200, json={**envelope("GET", 200), "results": [row]})

    original = httpx.Client
    mock = httpx.MockTransport(respond)
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(
        **{**kwargs, "transport": kwargs.get("transport", mock)},
    ))
    config = SecretMetadataHttpTransportConfig(
        "https://example.test", "synthetic-token", 5, None,
    )
    return FortiPamDiscoveryEntryCreateHttpTransport(config), state


def _ad_binding(monkeypatch):
    with monkeypatch.context() as local:
        domain, *_ = _ad_dependency_fixture(local)
    return DiscoveryEntryBinding(
        DisabledAdDiscoveryCreateInput("bp014-discovery-ad-disabled-20261006-r1", 23),
        "a" * 64, domain,
    )


def _runtime(tmp_path, monkeypatch, source, *, domain_reader=None, ambiguous_ack=False, gate_open=True):
    resolver = _Resolver(source)
    transport, state = _synthetic_source_transport(monkeypatch, source, ambiguous_ack=ambiguous_ack)
    store = _store(tmp_path)
    runtime = ProtectedDiscoveryEntryM4Runtime(
        resolver, _Verifier(), store, transport,
        authenticated_requester_digest=resolver.binding.plan.requester_digest,
        clock=lambda: NOW, execution_gate_open=gate_open, domain_read_transport=domain_reader,
    )
    return runtime, resolver, store, transport, state


@pytest.mark.parametrize("domain", [None, object()])
def test_ad_binding_requires_exact_domain_binding(domain):
    request = DisabledAdDiscoveryCreateInput("bp014-discovery-ad-disabled-20261006-r1", 23)
    with pytest.raises(ValueError):
        DiscoveryEntryBinding(request, "a" * 64, domain)


@pytest.mark.parametrize("field,value", [
    ("plan_digest", "2" * 64), ("folder_path", "Public/other-folder"),
    ("secret_name", "other-secret"), ("target_name", "other-target"),
    ("target_ipv4_address", "192.0.2.11"), ("domain_dns_root", "other.example.test"),
    ("target_owner_name", "other-owner"), ("target_classification_tag", "Other Tag"),
])
def test_ad_parameter_digest_binds_domain_dependencies_and_rejects_old_plan(monkeypatch, field, value):
    source = _ad_binding(monkeypatch)
    plan = _discovery_plan(source)
    changed = replace(source, domain_binding=replace(source.domain_binding, **{field: value}))
    assert changed.parameters_digest != source.parameters_digest
    with pytest.raises(M4AdapterDenied):
        DiscoveryEntryM4Adapter(plan, changed, object(), domain_read_transport=_DomainReader(monkeypatch))


@pytest.mark.parametrize("defect", [None, "template-name", "target:domain", "owner", "target:class", "lookup-id"])
def test_ad_initial_dependency_failure_has_no_claim_or_post(tmp_path, monkeypatch, defect):
    source = _ad_binding(monkeypatch)
    reader = None if defect is None else _DomainReader(monkeypatch, defect=defect)
    runtime, resolver, store, _, state = _runtime(tmp_path, monkeypatch, source, domain_reader=reader)
    with pytest.raises(M4AuthorizationDenied):
        runtime.execute_bound(resolver.binding.authorization.authorization_ref,
                              expected_binding_digest=source.parameters_digest)
    assert store.claim_count == 0 and state["posts"] == 0


@pytest.mark.parametrize("drift_on", [2, 3])
def test_ad_prewrite_drift_preserves_reserved_claim_without_post(tmp_path, monkeypatch, drift_on):
    source = _ad_binding(monkeypatch)
    reader = _DomainReader(monkeypatch, drift_on=drift_on)
    runtime, resolver, store, _, state = _runtime(tmp_path, monkeypatch, source, domain_reader=reader)
    result = runtime.execute_bound(resolver.binding.authorization.authorization_ref,
                                   expected_binding_digest=source.parameters_digest)
    assert result.outcome is M4Outcome.DENIED
    assert result.verification is M4Verification.NOT_STARTED
    assert store.claim_count == 1 and state["posts"] == 0
    assert all(call["method"] == "GET" for call in reader.calls)
    replay = runtime.execute_bound(resolver.binding.authorization.authorization_ref,
                                   expected_binding_digest=source.parameters_digest)
    assert replay.idempotent_replay and replay.outcome is M4Outcome.DENIED
    assert store.claim_count == 1 and state["posts"] == 0


@pytest.mark.parametrize("ambiguous_ack", [False, True])
def test_ad_fixed_dispatch_independent_readback_and_replay_rejection(tmp_path, monkeypatch, ambiguous_ack):
    source = _ad_binding(monkeypatch)
    reader = _DomainReader(monkeypatch)
    runtime, resolver, store, _, state = _runtime(
        tmp_path, monkeypatch, source, domain_reader=reader, ambiguous_ack=ambiguous_ack,
    )
    result = runtime.execute_bound(resolver.binding.authorization.authorization_ref,
                                   expected_binding_digest=source.parameters_digest)
    assert result.outcome is M4Outcome.SUCCEEDED and result.verification is M4Verification.VERIFIED
    assert state["posts"] == 1 and state["reads_after_post"] >= 3
    assert store.claim_count == 1 and reader.inspections == 4
    with pytest.raises(M4AuthorizationDenied):
        runtime.execute_bound(resolver.binding.authorization.authorization_ref,
                              expected_binding_digest=source.parameters_digest)
    assert state["posts"] == 1 and store.claim_count == 1


def test_ad_transport_rejects_generic_guard_and_missing_domain_without_reads(tmp_path, monkeypatch):
    source = _ad_binding(monkeypatch)
    _, _, store, transport, state = _runtime(tmp_path, monkeypatch, source)
    with pytest.raises(DiscoveryEntryCreateHttpTransportError):
        transport.inspect_credential_reference(source.request)
    with pytest.raises(DiscoveryEntryCreateHttpTransportError):
        transport.create_and_readback(source.request)
    assert state["calls"] == [] and store.claim_count == 0


def test_ad_runtime_default_gate_is_closed_without_reads_or_claim(tmp_path, monkeypatch):
    source = _ad_binding(monkeypatch)
    runtime, resolver, store, _, state = _runtime(
        tmp_path, monkeypatch, source, domain_reader=_DomainReader(monkeypatch), gate_open=False,
    )
    with pytest.raises(M4AuthorizationDenied):
        runtime.execute_bound(resolver.binding.authorization.authorization_ref,
                              expected_binding_digest=source.parameters_digest)
    assert state["calls"] == [] and store.claim_count == 0


def test_unix_private_m4_digest_binds_complete_body_with_empty_strings(tmp_path, monkeypatch):
    source = DiscoveryEntryBinding(
        DisabledUnixDiscoveryCreateInput("bp014-discovery-unix-disabled-20261006-r1", 23), "a" * 64,
    )
    assert "" in source.request.body().values()
    body_digest = hashlib.sha256(json.dumps(
        source.request.body(), sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    assert source.parameters_digest == canonical_digest({
        "contract": source.adapter_ref, "body_digest": body_digest,
        "private_nonce": source.private_nonce,
    })
    changed = replace(source, request=replace(source.request, discovery_secret_id=24))
    assert changed.parameters_digest != source.parameters_digest
    runtime, resolver, store, _, state = _runtime(tmp_path, monkeypatch, source)
    monkeypatch.setattr(FortiPamDiscoveryEntryCreateHttpTransport, "inspect_credential_reference", lambda *_: "b" * 64)
    result = runtime.execute_bound(resolver.binding.authorization.authorization_ref,
                                   expected_binding_digest=source.parameters_digest)
    assert result.outcome is M4Outcome.SUCCEEDED
    assert store.claim_count == 1 and state["posts"] == 1
