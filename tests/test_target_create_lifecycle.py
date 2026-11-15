"""Actual creator, namespace readers and durable M4 with synthetic network peers."""
import ssl

import pytest

from fortipam_mcp import target_create_lifecycle as l
from fortipam_mcp.target_namespace_preflight import TargetNamespacePreflight
from fortipam_mcp.target_qualified_namespace_reader import FortiPamTargetQualifiedNamespaceReader
from fortipam_mcp.target_ssh_transport import TargetSshTransportConfig
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_target_namespace_preflight import BracketHarness, DIGEST
from test_target_creation_http_transport import setup as creator_setup
import test_target_creation_evidence as evidence_fixture
import test_target_preservation_contract as state_fixture

NAME = 'mcp-v4-target-synthetic-create'


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    monkeypatch.setattr(evidence_fixture, 'NAME', NAME)
    monkeypatch.setattr(state_fixture, 'NAME', NAME)
    original_ssl = ssl.create_default_context
    monkeypatch.setattr(ssl, 'create_default_context', lambda **kwargs:original_ssl())
    ca = tmp_path/'ca.pem'; ca.write_text('SYNTHETIC_CA')
    directory = tmp_path/'creation'; directory.mkdir(mode=0o700)
    peer, make_creator = creator_setup(directory, ca_file=str(ca))
    factory = peer.factory
    def adapted_factory(*args, **kwargs):
        connection = factory(*args, **kwargs); request = connection.request
        def send(method, path, body, headers):
            if method != 'POST':
                assert path == '/api/v2/cmdb/secret/target/'+NAME+'?with_meta=true&vdom=root'
                path = path.replace(NAME, 'synthetic-target')
            request(method, path, body, headers)
        connection.request = send
        return connection
    peer.factory = adapted_factory
    creator = make_creator(execution_enabled=True)
    h = BracketHarness(); api = h.reader(base_url='https://pam.example', ca_file=str(ca))
    pin = tmp_path/'known_hosts'; pin.write_text('synthetic pin\n'); pin.chmod(0o600)
    ssh_clock = [1000.0]; global_extra = ['Hidden Target']
    namespace = FortiPamTargetQualifiedNamespaceReader(
        TargetSshTransportConfig('synthetic.invalid',22,'synthetic','synthetic',pin,10),
        serial_digest=DIGEST, clock=lambda:ssh_clock[0])
    async def names(witnesses): return witnesses + tuple(global_extra)
    monkeypatch.setattr(namespace, '_bounded_read', names)
    preflight = TargetNamespacePreflight(api, namespace)
    ledger = tmp_path/'ledger'; ledger.mkdir(mode=0o700)
    key = ledger/'key'; key.write_bytes(b'k'*32); key.chmod(0o600)
    store = PersistentM4ExecutionStateStore(ledger/'ledger.sqlite',key)
    def make(**changes):
        args = dict(creator=creator, preflight=preflight, store=store, authority_key=b'a'*32,
            environment_ref='synthetic-environment', scope_ref='synthetic-scope',
            audience_ref='synthetic-audience', requester_digest='1'*64,
            transport_digest='2'*64, execution_enabled=True)
        args.update(changes)
        return l.TargetCreateLifecycle(**args)
    return make, peer, h, creator, preflight, store, directory, global_extra, ssh_clock


def prepare(owner):
    preview = owner.preview()
    return owner.issue(preview)


def test_real_m4_creation_full_original_seal_and_terminal_reopen(fixture):
    make, peer, h, creator, preflight, store, directory, extra, clock = fixture
    owner = make(); issued = prepare(owner); result = owner.execute(issued)
    assert result.as_dict()['outcome'] == 'succeeded'
    assert result.as_dict()['verification'] == 'verified'
    assert peer.calls == ['GET','GET','GET','GET','GET','POST','GET','GET']
    assert len(h.requests) == 60 and store.claim_count == 1
    evidence = creator.load_creation_evidence()
    assert evidence.created.field_digests != creator._proposal.field_digests
    assert l._configured_state_digest(evidence.created) == issued.plan.expected_state_digest
    assert (directory/'create.coordinator.claim.json').exists()
    assert all(not any(body) for body in peer.body_views)
    assert all(obj.closed for obj in peer.connections+peer.responses)
    calls = list(peer.calls)
    for operation in (lambda:owner.execute(issued), owner.preview, make):
        with pytest.raises(l.TargetCreateLifecycleError): operation()
    assert peer.calls == calls


@pytest.mark.parametrize('point', ['preview','issue','execute'])
@pytest.mark.parametrize('fault', ['global_collision','native_present','dependency_drift'])
def test_fresh_drift_denies_before_post(fixture, point, fault):
    make, peer, h, creator, preflight, store, directory, extra, clock = fixture
    owner = make(); preview = owner.preview() if point != 'preview' else None
    issued = owner.issue(preview) if point == 'execute' else None
    if fault == 'global_collision': extra.append(NAME.upper())
    if fault == 'native_present': peer.created = state_fixture.row()
    if fault == 'dependency_drift':
        if point == 'preview':
            for index in (2,5): h.values[index]['results']['secretgrp-permission']['target'] = 'read'
        else:
            for index in (2,5): h.values[index]['results']['extra'] = 'changed'
    with pytest.raises(l.TargetCreateLifecycleError):
        if point == 'preview': owner.preview()
        elif point == 'issue': owner.issue(preview)
        else: owner.execute(issued)
    assert 'POST' not in peer.calls and store.claim_count == 0
    assert not (directory/'create.coordinator.claim.json').exists()


@pytest.mark.parametrize('fault', ['lost_ack','wrong_ack','readback','changed_field','late_post'])
def test_uncertain_creation_is_terminal_and_never_adopted(fixture, fault):
    make, peer, h, creator, preflight, store, directory, extra, clock = fixture
    owner = make(); issued = prepare(owner)
    if fault == 'lost_ack': peer.lost_ack = True
    if fault == 'wrong_ack': peer.wrong_ack = True
    if fault == 'readback': peer.readback_failure = True
    if fault == 'changed_field': peer.drift = True
    if fault == 'late_post':
        original = creator._factory
        def factory(*args, **kwargs):
            conn = original(*args, **kwargs); request = conn.request
            def send(method,*args):
                request(method,*args)
                if method == 'POST': peer.now = 160
            conn.request = send
            return conn
        object.__setattr__(creator, '_factory', factory)
    result = owner.execute(issued)
    assert result.as_dict()['outcome'] == 'reconciliation_required'
    assert peer.calls.count('POST') == 1 and store.claim_count == 1
    assert not (directory/'create.verified.json').exists()
    for operation in (make, owner.preview, lambda:owner.execute(issued)):
        with pytest.raises(l.TargetCreateLifecycleError): operation()
    assert peer.calls.count('POST') == 1


@pytest.mark.parametrize('fault', ['composition_gate','transport_gate','source','closed'])
def test_source_and_independent_gates(fixture, fault):
    make, peer, h, creator, preflight, store, directory, extra, clock = fixture
    if fault == 'source': object.__setattr__(creator, '_source_context_digest', None)
    with pytest.raises(l.TargetCreateLifecycleError):
        owner = make(execution_enabled=False) if fault == 'composition_gate' else make()
        preview = owner.preview()
        if fault == 'closed': owner.close()
        issued = owner.issue(preview)
        if fault == 'transport_gate': object.__setattr__(creator, '_enabled', False)
        owner.execute(issued)
    assert 'POST' not in peer.calls and store.claim_count == 0


def test_failed_m4_read_retains_reservation_before_http_claim(fixture, monkeypatch):
    make, peer, h, creator, preflight, store, directory, extra, clock = fixture
    owner = make(); issued = prepare(owner); original = l._KernelAdapter.read_current
    def fail(adapter, plan):
        peer.created = state_fixture.row()
        return original(adapter, plan)
    monkeypatch.setattr(l._KernelAdapter, 'read_current', fail)
    assert owner.execute(issued).as_dict()['outcome'] == 'denied'
    assert (directory/'create.coordinator.claim.json').exists()
    assert not (directory/'create.claim.json').exists()
    with pytest.raises(l.TargetCreateLifecycleError): make()
    assert 'POST' not in peer.calls


def test_postcondition_requires_full_sealed_identity(fixture, monkeypatch):
    make, peer, h, creator, preflight, store, directory, extra, clock = fixture
    owner = make(); issued = prepare(owner); original = l._KernelAdapter.read_postcondition
    def drift(adapter, plan):
        peer.created['uuid'] = 'replaced-after-seal'
        return original(adapter, plan)
    monkeypatch.setattr(l._KernelAdapter, 'read_postcondition', drift)
    assert owner.execute(issued).as_dict()['outcome'] == 'reconciliation_required'
    assert (directory/'create.verified.json').exists() and peer.calls.count('POST') == 1
    with pytest.raises(l.TargetCreateLifecycleError): make()


@pytest.mark.parametrize('fault', ['ledger_failure','dangling_reservation','expiry_during_tls'])
def test_failed_reservation_or_guard_never_reopens_dispatch(fixture, monkeypatch, fault):
    make, peer, h, creator, preflight, store, directory, extra, clock = fixture
    owner = make(); issued = prepare(owner)
    if fault == 'ledger_failure':
        def fail(*args, **kwargs): raise OSError('PRIVATE_SENTINEL')
        monkeypatch.setattr(store, 'claim', fail)
    elif fault == 'dangling_reservation':
        (directory/'create.coordinator.claim.json').symlink_to(directory/'missing')
    else:
        def expire(): h.now = 40
        peer.hook = expire
    with pytest.raises(l.TargetCreateLifecycleError): owner.execute(issued)
    if fault != 'expiry_during_tls':
        with pytest.raises(l.TargetCreateLifecycleError): make()
    assert 'POST' not in peer.calls and not (directory/'create.claim.json').exists()


def test_global_namespace_fingerprint_drift_revokes_issue(fixture):
    make, peer, h, creator, preflight, store, directory, extra, clock = fixture
    owner = make(); preview = owner.preview(); extra.append('Another Hidden Target')
    with pytest.raises(l.TargetCreateLifecycleError): owner.issue(preview)
    assert 'POST' not in peer.calls and store.claim_count == 0
