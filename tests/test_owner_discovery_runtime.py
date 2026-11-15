"""Actual Owner-session lifecycle around synthetic fixed AD M4 execution."""

from dataclasses import replace
import json
import threading

import httpx
import pytest

import fortipam_mcp.owner_discovery_runtime as composition
from fortipam_mcp.owner_domain_runtime import owner_domain_transport
from fortipam_mcp.secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, SecretMetadataHttpTransportError, SYSTEM_STATUS_PATH,
)
from fortipam_mcp.target_contract import DOMAIN_TEMPLATE_FIELD_TYPES
from test_discovery_entry_m4_runtime import _ad_binding, _discovery_plan, _Resolver, _synthetic_source_transport
from test_m4_execution_store import _store
from test_secret_metadata_http_transport import _DetailConnection, _DetailResponse
from test_v4_execution_kernel import NOW, _authorization, _Verifier
from v4_planning import M4AuthorizationDenied, M4Outcome, M4Verification, canonical_digest


class _CountingResolver(_Resolver):
    def __init__(self, source):
        super().__init__(source)
        self.calls = 0

    def resolve_execution_binding(self, authorization_ref):
        self.calls += 1
        return super().resolve_execution_binding(authorization_ref)


def _composition(tmp_path, monkeypatch, *, gate_open=True, defect=None, drift_on=None,
                 logout_failure=False, verifier=None, login_events=None):
    source = _ad_binding(monkeypatch)
    domain = source.domain_binding
    resolver = _CountingResolver(source)
    writer, writes = _synthetic_source_transport(monkeypatch, source)
    store = _store(tmp_path)
    state = {"calls": [], "factories": 0, "credentials": 0, "active": False,
             "target_reads": 0, "owners": [], "clients": [], "raw": []}
    envelope = {"version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
                "status": "success", "path": "secret", "vdom": "root"}
    target = {"name": domain.target_name, "address": domain.target_ipv4_address,
              "domain": domain.domain_dns_root, "template": domain.template_name,
              "class": domain.target_classification_tag, "ldaps-port": 636,
              "user-naming-attribute": "sAMAccountName", "user-base": "", "access": "customized",
              "web-proxy-status": "disable",
              "user-permission": [{"permission": "owner", "user-name": [{"name": domain.target_owner_name}]}]}
    sentinel = "synthetic-owner-domain-material-must-not-be-decoded"
    detail = {"id": source.request.discovery_secret_id, "name": domain.secret_name,
              "folder": 17, "template": domain.template_name, "target": domain.target_name,
              "inherit-permission": "enable", "target-privilege-account": "disable",
              **{service + "-service-status": "down" for service in ("rdp", "ssh", "sftp", "http", "samba", "telnet")},
              "field": [{"name": "Password", "value": sentinel}]}

    def respond(request):
        state["calls"].append((request.method, request.url.path))
        assert "authorization" not in request.headers
        path = request.url.path
        if path == "/remote/login":
            return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH">')
        if path == "/XX/YY/ZZ/AUTH":
            if login_events:
                entered, release = login_events
                entered.set()
                assert release.wait(3)
            state["active"] = True
            return httpx.Response(303, headers={"location": "/", "set-cookie": "testsession=synthetic; Secure; HttpOnly; Path=/"})
        if path == "/":
            return httpx.Response(200)
        if path == "/logout":
            state["active"] = logout_failure
            return httpx.Response(200)
        if not state["active"]:
            return httpx.Response(401, json={})
        assert "testsession=synthetic" in request.headers.get("cookie", "")
        if path == SYSTEM_STATUS_PATH:
            return httpx.Response(200, json={"version": "v7.0.0", "build": 29})
        assert request.method == "GET"
        if path.endswith("/target/" + domain.target_name):
            state["target_reads"] += 1
            row = {**target}
            if defect == "class" or drift_on == state["target_reads"]:
                row["class"] = "Changed Tag"
            return httpx.Response(200, json={**envelope, "name": "target", "results": [row]})
        if path.endswith("/template/Windows Domain Account"):
            row = {"name": domain.template_name,
                   "field": [{"name": name, "type": kind} for name, kind in DOMAIN_TEMPLATE_FIELD_TYPES]}
            return httpx.Response(200, json={**envelope, "name": "template", "results": [row]})
        if request.url.params.get("type") == "folder":
            assert path.endswith("/" + domain.folder_path)
            return httpx.Response(200, json={"results": {"id": 17}})
        assert request.url.params.get("type") == "secret"
        assert path.endswith("/" + domain.folder_path + "/" + domain.secret_name)
        return httpx.Response(200, json={"results": {"id": source.request.discovery_secret_id}})

    http_client = httpx.Client

    def scoped_factory(config, binding, credentials, *, allow_secret_create):
        state["factories"] += 1
        assert binding == domain and allow_secret_create is False
        owner = owner_domain_transport(config, binding, credentials, allow_secret_create=False)

        def session_factory(**kwargs):
            client = http_client(**kwargs, transport=httpx.MockTransport(respond))
            state["clients"].append(client)
            return client

        def raw_factory(*_args, **_kwargs):
            calls = []
            response = _DetailResponse({"results": [detail]})
            raw = _DetailConnection(response, calls)
            state["raw"].append((raw, response, calls))
            return raw

        owner._session_factory = session_factory
        owner._raw_connection_factory = raw_factory
        state["owners"].append(owner)
        return owner

    monkeypatch.setattr(composition, "owner_domain_transport", scoped_factory)
    original_loads = json.loads

    def loads_without_material(value, *args, **kwargs):
        assert sentinel not in str(value)
        return original_loads(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", loads_without_material)

    def credentials():
        state["credentials"] += 1
        return domain.target_owner_name, "synthetic-password"

    runtime = composition.OwnerAuthenticatedAdDiscoveryRuntime(
        resolver, verifier or _Verifier(), store, writer,
        SecretMetadataHttpTransportConfig("https://example.test", "owner-config-unused-token", 5, None),
        credentials, source_binding=source,
        authenticated_requester_digest=resolver.binding.plan.requester_digest,
        clock=lambda: NOW, **({} if gate_open is None else {"execution_gate_open": gate_open}),
    )
    return runtime, resolver, source, store, writes, state


def _execute(runtime, resolver, source):
    return runtime.execute_bound(resolver.binding.authorization.authorization_ref,
                                 expected_binding_digest=source.parameters_digest)


def _assert_closed(state, *, logout_verified=True):
    assert state["owners"] and all(owner._client is None for owner in state["owners"])
    assert all(owner.logout_verified is logout_verified for owner in state["owners"])
    assert all(client.is_closed and not client.cookies for client in state["clients"])
    assert all(raw.closed and response.closed for raw, response, _ in state["raw"])
    for _, _, calls in state["raw"]:
        for call in calls:
            assert call["method"] == "GET" and call["body"] is None
            assert "Authorization" not in call["headers"]
            assert "testsession=synthetic" in call["headers"]["Cookie"]
    assert all(not owner._allow_secret_create for owner in state["owners"])


def test_closed_gate_has_no_resolver_owner_factory_or_credential_access(tmp_path, monkeypatch):
    runtime, resolver, source, store, writes, state = _composition(tmp_path, monkeypatch, gate_open=None)
    with pytest.raises(M4AuthorizationDenied):
        _execute(runtime, resolver, source)
    assert resolver.calls == state["factories"] == state["credentials"] == store.claim_count == 0
    assert writes["calls"] == state["calls"] == []


@pytest.mark.parametrize("mismatch", ["base_url", "ca_file"])
def test_owner_writer_origin_or_trust_drift_rejects_before_resolver_or_login(tmp_path, monkeypatch, mismatch):
    runtime, resolver, source, store, writes, state = _composition(tmp_path, monkeypatch)
    if mismatch == "base_url":
        writer_config = replace(runtime._source_transport._config, base_url="https://different.example.test")
    else:
        ca = tmp_path / "synthetic-ca.pem"
        ca.write_text("synthetic trust configuration; never loaded")
        writer_config = replace(runtime._source_transport._config, ca_file=str(ca))
    runtime._source_transport._config = writer_config
    with pytest.raises(M4AuthorizationDenied):
        _execute(runtime, resolver, source)
    assert resolver.calls == state["factories"] == state["credentials"] == store.claim_count == 0
    assert writes["calls"] == state["calls"] == []


@pytest.mark.parametrize("defect", ["source", "domain", "parameters", "requester", "authorization"])
def test_static_binding_mismatch_rejects_before_owner_login(tmp_path, monkeypatch, defect):
    runtime, resolver, source, store, writes, state = _composition(tmp_path, monkeypatch)
    snapshot = resolver.binding
    if defect in {"source", "domain"}:
        changed = (replace(source, request=replace(source.request, discovery_secret_id=24))
                   if defect == "source" else replace(source, domain_binding=replace(source.domain_binding, target_owner_name="other-owner")))
        plan = _discovery_plan(changed)
        resolver.binding = replace(snapshot, source=changed, plan=plan, authorization=_authorization(plan))
    elif defect == "parameters":
        resolver.binding = replace(snapshot, plan=_discovery_plan(replace(source, private_nonce="b" * 64)))
    elif defect == "requester":
        changed = {"requester_digest": "c" * 64}
        resolver.binding = replace(snapshot, authorization=replace(snapshot.authorization, **changed,
            authorization_digest=canonical_digest({**snapshot.authorization.canonical_content(), **changed})))
    else:
        changed = {"plan_digest": "c" * 64}
        resolver.binding = replace(snapshot, authorization=replace(snapshot.authorization, **changed,
            authorization_digest=canonical_digest({**snapshot.authorization.canonical_content(), **changed})))
    with pytest.raises(M4AuthorizationDenied):
        _execute(runtime, resolver, source)
    assert resolver.calls == 1 and state["factories"] == state["credentials"] == store.claim_count == 0
    assert writes["calls"] == state["calls"] == []


def test_actual_owner_lifecycle_uses_single_immutable_snapshot_and_independent_bearer_writer(tmp_path, monkeypatch):
    runtime, resolver, source, store, writes, state = _composition(tmp_path, monkeypatch)
    original = resolver.resolve_execution_binding

    def resolve_once(authorization_ref):
        assert resolver.calls == 0
        return original(authorization_ref)

    monkeypatch.setattr(resolver, "resolve_execution_binding", resolve_once)
    result = _execute(runtime, resolver, source)
    assert result.outcome is M4Outcome.SUCCEEDED and result.verification is M4Verification.VERIFIED
    assert resolver.calls == state["factories"] == state["credentials"] == store.claim_count == writes["posts"] == 1
    assert state["target_reads"] == 4 and writes["reads_after_post"] >= 3
    assert not any(path.startswith("/api/") and method != "GET" for method, path in state["calls"])
    _assert_closed(state)


def test_initial_domain_drift_logs_out_without_claim_or_post(tmp_path, monkeypatch):
    runtime, resolver, source, store, writes, state = _composition(tmp_path, monkeypatch, defect="class")
    with pytest.raises(SecretMetadataHttpTransportError):
        _execute(runtime, resolver, source)
    assert store.claim_count == writes["posts"] == 0
    _assert_closed(state)


def test_reserved_claim_drift_is_terminal_and_never_redispatches(tmp_path, monkeypatch):
    runtime, resolver, source, store, writes, state = _composition(tmp_path, monkeypatch, drift_on=2)
    denied = _execute(runtime, resolver, source)
    assert denied.outcome is M4Outcome.DENIED
    assert store.claim_count == 1 and writes["posts"] == 0
    replay = _execute(runtime, resolver, source)
    assert replay.idempotent_replay and replay.outcome is M4Outcome.DENIED
    assert store.claim_count == 1 and writes["posts"] == 0
    _assert_closed(state)


def test_verifier_exception_after_claim_revokes_owner_session_and_retains_claim(tmp_path, monkeypatch):
    class RejectingVerifier:
        def verify(self, *_args, **_kwargs):
            raise M4AuthorizationDenied("synthetic verifier refusal")

    runtime, resolver, source, store, writes, state = _composition(tmp_path, monkeypatch, verifier=RejectingVerifier())
    with pytest.raises(SecretMetadataHttpTransportError):
        _execute(runtime, resolver, source)
    assert store.claim_count == 1 and writes["posts"] == 0
    recovered = _execute(runtime, resolver, source)
    assert recovered.idempotent_replay and recovered.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert store.claim_count == 1 and writes["posts"] == 0
    _assert_closed(state)


def test_logout_failure_after_dispatch_preserves_terminal_claim_and_never_redispatches(tmp_path, monkeypatch):
    runtime, resolver, source, store, writes, state = _composition(tmp_path, monkeypatch, logout_failure=True)
    with pytest.raises(SecretMetadataHttpTransportError) as error:
        _execute(runtime, resolver, source)
    assert str(error.value) == "The private Owner metadata session is unavailable."
    assert store.claim_count == writes["posts"] == 1
    with pytest.raises(SecretMetadataHttpTransportError):
        _execute(runtime, resolver, source)
    assert store.claim_count == writes["posts"] == 1
    _assert_closed(state, logout_verified=False)


def test_concurrent_execution_rejects_before_second_resolver_or_login(tmp_path, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    runtime, resolver, source, store, writes, state = _composition(
        tmp_path, monkeypatch, login_events=(entered, release),
    )
    results = []

    def execute_first():
        try:
            results.append(_execute(runtime, resolver, source))
        except Exception as error:
            results.append(error)

    thread = threading.Thread(target=execute_first)
    thread.start()
    try:
        assert entered.wait(3)
        with pytest.raises(M4AuthorizationDenied):
            _execute(runtime, resolver, source)
        assert resolver.calls == state["factories"] == state["credentials"] == 1
    finally:
        release.set()
        thread.join(3)
    assert not thread.is_alive() and len(results) == 1
    assert results[0].outcome is M4Outcome.SUCCEEDED
    assert store.claim_count == writes["posts"] == 1
    _assert_closed(state)
