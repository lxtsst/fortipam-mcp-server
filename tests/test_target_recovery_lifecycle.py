"""Independent recovery with real ownership, readers, adapters and durable M4."""
from dataclasses import replace
import io
import json

import pytest

from fortipam_mcp import target_recovery_lifecycle as l
from fortipam_mcp.target_qualified_reference_reader import FortiPamTargetQualifiedReferenceReader
from test_target_create_lifecycle import fixture as create_fixture, prepare, NAME
import test_target_preservation_contract as state_fixture


@pytest.fixture
def fixture(create_fixture, monkeypatch):
    make_create, peer, h, creator, preflight, store, directory, extra, clock = create_fixture
    creation = make_create(); assert creation.execute(prepare(creation)).as_dict()['outcome'] == 'succeeded'
    original = creator.load_creation_evidence()
    references = FortiPamTargetQualifiedReferenceReader(preflight._namespace._ssh._config,
        serial_digest=original.created.serial_digest)
    state = dict(count=0, calls=0)
    async def read(name):
        assert name == NAME
        state['calls'] += 1
        return state['count']
    monkeypatch.setattr(references, '_read', read)
    object.__setattr__(creator, '_recovery_enabled', True)
    def make(**changes):
        args = dict(creator=creator, expected_current=original.created, reader=preflight._api,
            references=references, store=store, authority_key=b'r'*32,
            environment_ref='synthetic-environment', scope_ref='synthetic-scope',
            audience_ref='synthetic-audience', requester_digest='1'*64,
            transport_digest='2'*64, execution_enabled=True)
        args.update(changes)
        return l.TargetRecoveryLifecycle(**args)
    return make, peer, h, creator, preflight._api, references, store, directory, state


def test_create_then_independent_recovery_real_m4(fixture):
    make, peer, h, creator, reader, references, store, directory, state = fixture
    owner = make(); result = owner.execute(prepare(owner))
    assert result.as_dict()['outcome'] == 'succeeded' and result.as_dict()['verification'] == 'verified'
    assert peer.created is None and peer.calls.count('POST') == peer.calls.count('DELETE') == 1
    assert state['calls'] == 5 and store.claim_count == 2
    assert (directory/'delete.verified.json').exists() and (directory/'delete.coordinator.claim.json').exists()
    calls = list(peer.calls)
    for operation in (owner.preview, make):
        with pytest.raises(l.TargetRecoveryLifecycleError): operation()
    assert peer.calls == calls and all(obj.closed for obj in peer.connections+peer.responses)


@pytest.mark.parametrize('point', ['preview','issue','execute'])
@pytest.mark.parametrize('fault', ['reference','current','permission'])
def test_each_stage_refreshes_dependencies_references_and_state(fixture, point, fault):
    make, peer, h, creator, reader, references, store, directory, state = fixture
    owner = make(); preview = owner.preview() if point != 'preview' else None
    issued = owner.issue(preview) if point == 'execute' else None
    if fault == 'reference': state['count'] = 1
    if fault == 'current': peer.created['description'] = 'changed'
    if fault == 'permission':
        for index in (2,5): h.values[index]['results']['secretgrp-permission']['target'] = 'read'
    with pytest.raises(l.TargetRecoveryLifecycleError):
        if point == 'preview': owner.preview()
        elif point == 'issue': owner.issue(preview)
        else: owner.execute(issued)
    assert 'DELETE' not in peer.calls and store.claim_count == 1
    assert not (directory/'delete.coordinator.claim.json').exists()


@pytest.mark.parametrize('fault', ['lost_ack','still_present','late_delete','reference_race'])
def test_uncertain_delete_is_terminal_without_retry(fixture, fault):
    make, peer, h, creator, reader, references, store, directory, state = fixture
    owner = make(); issued = prepare(owner)
    if fault == 'lost_ack': peer.lost_delete_ack = True
    if fault == 'still_present': peer.keep_after_delete = True
    if fault == 'late_delete':
        original = creator._factory
        def factory(*args, **kwargs):
            conn = original(*args, **kwargs); request = conn.request
            def send(method,*args):
                request(method,*args)
                if method == 'DELETE': peer.now = 160
            conn.request = send
            return conn
        object.__setattr__(creator, '_factory', factory)
    if fault == 'reference_race':
        original = references._read
        async def read(name):
            value = await original(name)
            return 1 if state['calls'] >= 4 else value
        references._read = read
    result = owner.execute(issued)
    assert result.as_dict()['outcome'] == 'reconciliation_required'
    assert peer.calls.count('DELETE') == (0 if fault == 'reference_race' else 1)
    assert not (directory/'delete.verified.json').exists()
    for operation in (make, owner.preview, lambda:owner.execute(issued)):
        with pytest.raises(l.TargetRecoveryLifecycleError): operation()


@pytest.mark.parametrize('fault', ['missing_seal','tampered_seal','changed_identity','reference_device',
    'api_source','composition_gate','recovery_gate','closed'])
def test_original_ownership_source_and_independent_authority(fixture, fault):
    make, peer, h, creator, reader, references, store, directory, state = fixture
    current = creator.load_creation_evidence().created
    if fault == 'missing_seal': (directory/'create.verified.json').unlink()
    if fault == 'tampered_seal':
        path = directory/'create.verified.json'; value = json.loads(path.read_text())
        value['seal'] = '0'*64; path.write_text(json.dumps(value))
    if fault == 'changed_identity':
        value = dict(peer.created, uuid='another-object'); current = state_fixture.capture(value)
    if fault == 'reference_device': references._serial_digest = '0'*64
    if fault == 'api_source': reader._source = '0'*64
    with pytest.raises(l.TargetRecoveryLifecycleError):
        owner = make(expected_current=current, execution_enabled=fault!='composition_gate')
        preview = owner.preview()
        if fault == 'closed': owner.close()
        issued = owner.issue(preview)
        if fault == 'recovery_gate': object.__setattr__(creator, '_recovery_enabled', False)
        owner.execute(issued)
    assert 'DELETE' not in peer.calls and store.claim_count == 1


@pytest.mark.parametrize('fault', ['ledger','dangling_reservation','kernel_drift'])
def test_reservation_stays_terminal_before_delete_claim(fixture, monkeypatch, fault):
    make, peer, h, creator, reader, references, store, directory, state = fixture
    owner = make(); issued = prepare(owner)
    if fault == 'ledger':
        def fail(*args, **kwargs): raise OSError('PRIVATE_SENTINEL')
        monkeypatch.setattr(store, 'claim', fail)
    if fault == 'dangling_reservation': (directory/'delete.coordinator.claim.json').symlink_to(directory/'missing')
    if fault == 'kernel_drift':
        original = l._KernelAdapter.read_current
        def drift(adapter, plan):
            peer.created['description'] = 'changed after refresh'
            return original(adapter, plan)
        monkeypatch.setattr(l._KernelAdapter, 'read_current', drift)
        assert owner.execute(issued).as_dict()['outcome'] == 'precondition_failed'
    else:
        with pytest.raises(l.TargetRecoveryLifecycleError): owner.execute(issued)
    with pytest.raises(l.TargetRecoveryLifecycleError): make()
    assert 'DELETE' not in peer.calls and not (directory/'delete.claim.json').exists()


def test_reference_read_cannot_extend_execution_deadline(fixture, monkeypatch):
    make, peer, h, creator, reader, references, store, directory, state = fixture
    async def late(name): peer.now = 160; return 0
    monkeypatch.setattr(references, '_read', late)
    with pytest.raises(l.TargetRecoveryLifecycleError): make().preview()
    assert 'DELETE' not in peer.calls


def test_full_create_update_restore_recovery_lifecycle(fixture, tmp_path):
    from fortipam_mcp.target_coordinate_lifecycle import TargetCoordinateLifecycle
    from fortipam_mcp.target_preservation_http_transport import TargetCoordinateHttpTransport
    from test_target_preservation_http_transport import Peer
    make, peer, h, creator, reader, references, store, directory, state = fixture
    original = creator.load_creation_evidence().created
    coordinate_peer = Peer(); coordinate_peer.row = peer.created
    def factory(*args, **kwargs):
        conn = coordinate_peer.factory(*args, **kwargs); request = conn.request
        def send(method,path,body,headers):
            assert NAME in path
            request(method,path.replace(NAME,'synthetic-target'),body,headers)
            if method == 'PUT':
                data = json.loads(conn.response.raw.getvalue()); data['mkey'] = NAME
                conn.response.raw = io.BytesIO(json.dumps(data).encode())
        conn.request = send
        return conn
    coordinate_dir = tmp_path/'coordinates'; coordinate_dir.mkdir(mode=0o700)
    change = l.c.TargetCoordinateChange(original,replace(original.coordinates,address='192.0.2.99'))
    transport = TargetCoordinateHttpTransport(creator._config,change,state_directory=coordinate_dir,
        execution_enabled=True,clock=lambda:peer.now,connection_factory=factory)
    for phase in ('update','restore'):
        owner = TargetCoordinateLifecycle(phase=phase,creator=creator,transport=transport,reader=reader,
            store=store,authority_key=b'c'*32,environment_ref='synthetic-environment',
            scope_ref='synthetic-scope',audience_ref='synthetic-audience',requester_digest='1'*64,
            transport_digest='2'*64,execution_enabled=True)
        assert owner.execute(prepare(owner)).as_dict()['outcome'] == 'succeeded'
    owner = make(); assert owner.execute(prepare(owner)).as_dict()['outcome'] == 'succeeded'
    assert store.claim_count == 4 and coordinate_peer.calls.count('PUT') == 2
    assert peer.calls.count('POST') == peer.calls.count('DELETE') == 1 and peer.created is None


@pytest.mark.parametrize('digest', ['0'*64, 'invalid', True])
def test_transport_checks_pinned_original_digest_under_lock_before_claim(fixture, digest):
    from fortipam_mcp.target_creation_http_transport import TargetCreationTransportError
    make, peer, h, creator, reader, references, store, directory, state = fixture
    current = creator.load_creation_evidence().created; before = list(peer.calls)
    with pytest.raises(TargetCreationTransportError):
        creator.recover(expected_current=current,plan_digest='a'*64,authorization_digest='b'*64,
            expires_at=150,before_send=lambda:None,reference_count=lambda name:0,
            creation_evidence_digest=digest)
    assert peer.calls == before and not (directory/'delete.claim.json').exists()


@pytest.mark.parametrize('count', [True,False,-1])
def test_reference_count_requires_exact_integer_zero(fixture, count):
    make, peer, h, creator, reader, references, store, directory, state = fixture
    state['count'] = count
    with pytest.raises(l.TargetRecoveryLifecycleError): make().preview()
    assert 'DELETE' not in peer.calls


def test_owned_coordinate_change_can_be_explicitly_recovered(fixture):
    make, peer, h, creator, reader, references, store, directory, state = fixture
    peer.created['address'] = '192.0.2.99'
    current = state_fixture.capture(peer.created)
    owner = make(expected_current=current)
    assert owner.execute(prepare(owner)).as_dict()['outcome'] == 'succeeded'
    assert peer.calls.count('DELETE') == 1 and peer.created is None
