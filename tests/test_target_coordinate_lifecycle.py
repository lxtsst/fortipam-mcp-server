"""Real M4/store/HTTP/dependency composition with synthetic network peers."""
from dataclasses import replace
import json
import ssl

import pytest

from fortipam_mcp import target_coordinate_lifecycle as l
from fortipam_mcp import target_preservation_http_transport as t
from fortipam_mcp import target_preservation_contract as c
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_target_creation_http_transport import setup as creation_setup, create
from test_target_preservation_http_transport import Peer
from test_target_api_dependency_reader import Harness


@pytest.fixture
def fixture(tmp_path,monkeypatch):
    original=ssl.create_default_context
    monkeypatch.setattr(ssl,'create_default_context',lambda **kwargs:original())
    ca=tmp_path/'ca.pem';ca.write_text('SYNTHETIC_CA')
    original_dir=tmp_path/'creation';original_dir.mkdir(mode=0o700)
    create_peer,make_creator=creation_setup(original_dir,ca_file=str(ca))
    creator=make_creator(execution_enabled=True);evidence=create(creator)
    peer=Peer();peer.row=dict(create_peer.created)
    directory=tmp_path/'coordinate';directory.mkdir(mode=0o700)
    change=c.TargetCoordinateChange(evidence.created,replace(evidence.created.coordinates,address='192.0.2.99'))
    transport=t.TargetCoordinateHttpTransport(creator._config,change,state_directory=directory,
        execution_enabled=True,clock=lambda:peer.now,connection_factory=peer.factory)
    h=Harness();reader=h.reader(base_url='https://pam.example',ca_file=str(ca))
    ledger_dir=tmp_path/'ledger';ledger_dir.mkdir(mode=0o700)
    key=ledger_dir/'key';key.write_bytes(b'k'*32);key.chmod(0o600)
    store=PersistentM4ExecutionStateStore(ledger_dir/'ledger.sqlite',key)
    def make(phase='update',**changes):
        args=dict(phase=phase,creator=creator,transport=transport,reader=reader,store=store,
            authority_key=b'a'*32,environment_ref='synthetic-environment',scope_ref='synthetic-scope',
            audience_ref='synthetic-audience',requester_digest='1'*64,transport_digest='2'*64,
            execution_enabled=True)
        args.update(changes)
        return l.TargetCoordinateLifecycle(**args)
    return make,peer,h,transport,creator,store,directory


def run(owner):
    preview=owner.preview();issued=owner.issue(preview)
    return owner.execute(issued),issued


def test_full_update_restore_real_m4_and_terminal_reopen(fixture):
    make,peer,h,transport,creator,store,directory=fixture
    update=make();result,issued=run(update)
    assert result.as_dict()['outcome']=='succeeded' and result.as_dict()['verification']=='verified'
    assert peer.row['address']=='192.0.2.99' and peer.calls.count('PUT')==1
    assert store.claim_count==1 and len(h.requests)==24
    calls=list(peer.calls)
    with pytest.raises(l.TargetCoordinateLifecycleError):update.execute(issued)
    with pytest.raises(l.TargetCoordinateLifecycleError):update.preview()
    with pytest.raises(l.TargetCoordinateLifecycleError):make()
    assert peer.calls==calls
    restore=make('restore');result,_=run(restore)
    assert result.as_dict()['outcome']=='succeeded'
    assert peer.row['address']==creator.load_creation_evidence().created.coordinates.address
    assert peer.calls.count('PUT')==2 and store.claim_count==2
    with pytest.raises(l.TargetCoordinateLifecycleError):make('restore')
    assert (directory/'update.coordinator.claim.json').exists()
    assert (directory/'restore.coordinator.claim.json').exists()


@pytest.mark.parametrize('point',['preview','issue','execute'])
def test_external_drift_denies_before_mutation(fixture,point):
    make,peer,h,transport,creator,store,directory=fixture
    owner=make()
    preview=owner.preview() if point!='preview' else None
    issued=owner.issue(preview) if point=='execute' else None
    peer.row['description']='unexpected-preserved-drift'
    with pytest.raises(l.TargetCoordinateLifecycleError):
        if point=='preview':owner.preview()
        elif point=='issue':owner.issue(preview)
        else:owner.execute(issued)
    assert 'PUT' not in peer.calls and store.claim_count==0


@pytest.mark.parametrize('fault',['lost_ack','post_drift','late_put'])
def test_uncertain_dispatch_terminal_never_retried(fixture,fault):
    make,peer,h,transport,creator,store,directory=fixture
    owner=make();preview=owner.preview();issued=owner.issue(preview)
    if fault=='lost_ack':peer.lose_ack=True
    elif fault=='post_drift':peer.side_effect=True
    else:
        factory=transport._factory
        def late(*args,**kwargs):
            conn=factory(*args,**kwargs);request=conn.request
            def send(method,*args):
                request(method,*args)
                if method=='PUT':peer.now=160
            conn.request=send;return conn
        object.__setattr__(transport,'_factory',late)
    result=owner.execute(issued)
    assert result.as_dict()['outcome']=='reconciliation_required'
    assert peer.calls.count('PUT')==1 and store.claim_count==1
    assert not (directory/'update.verified.json').exists()
    with pytest.raises(l.TargetCoordinateLifecycleError):make()
    with pytest.raises(l.TargetCoordinateLifecycleError):owner.execute(issued)
    with pytest.raises(l.TargetCoordinateLifecycleError):make('restore')
    assert peer.calls.count('PUT')==1


@pytest.mark.parametrize('fault',['missing_seal','tampered_seal','foreign_baseline','system_ca','default_gate','closed'])
def test_missing_ownership_source_or_gate_cannot_issue(fixture,fault):
    make,peer,h,transport,creator,store,directory=fixture
    if fault in ('missing_seal','tampered_seal'):
        path=creator._directory/'create.verified.json'
        if fault=='missing_seal':path.unlink()
        else:
            value=json.loads(path.read_text());value['seal']='b'*64;path.write_text(json.dumps(value))
    elif fault=='foreign_baseline':
        object.__setattr__(transport,'_change',c.TargetCoordinateChange(
            replace(transport._change.baseline,name='other'),transport._change.desired))
    elif fault=='system_ca':object.__setattr__(transport,'_source_context_digest',None)
    with pytest.raises(l.TargetCoordinateLifecycleError):
        owner=make(execution_enabled=False) if fault=='default_gate' else make()
        preview=owner.preview()
        if fault=='closed':owner.close()
        owner.issue(preview)
    assert 'PUT' not in peer.calls and store.claim_count==0


@pytest.mark.parametrize('point',['issue','execute'])
def test_new_dependency_permission_or_fingerprint_drift_denied(fixture,point):
    make,peer,h,transport,creator,store,directory=fixture
    owner=make();preview=owner.preview();issued=owner.issue(preview) if point=='execute' else None
    # Change both bracketing profile rows consistently: fresh evidence is valid,
    # but no longer the dependency fingerprint signed in the preview.
    for index in (2,5):h.values[index]['results']['new_setting']='changed'
    with pytest.raises(l.TargetCoordinateLifecycleError):
        if point=='issue':owner.issue(preview)
        else:owner.execute(issued)
    assert 'PUT' not in peer.calls and store.claim_count==0


def test_failed_m4_current_read_reservation_survives_reopen(fixture,monkeypatch):
    make,peer,h,transport,creator,store,directory=fixture
    owner=make();preview=owner.preview();issued=owner.issue(preview)
    original=l._KernelAdapter.read_current
    def drift(adapter,plan):
        peer.row['description']='kernel-current-drift'
        return original(adapter,plan)
    monkeypatch.setattr(l._KernelAdapter,'read_current',drift)
    result=owner.execute(issued)
    assert result.as_dict()['outcome']=='precondition_failed'
    assert store.claim_count==1 and 'PUT' not in peer.calls
    assert (directory/'update.coordinator.claim.json').exists()
    assert not (directory/'update.claim.json').exists()
    with pytest.raises(l.TargetCoordinateLifecycleError):make()


def test_restore_requires_unchanged_update_anchors(fixture):
    make,peer,h,transport,creator,store,directory=fixture
    result,_=run(make());assert result.as_dict()['outcome']=='succeeded'
    owner=make('restore');preview=owner.preview()
    path=directory/'update.ack.json';value=json.loads(path.read_text());value['response_digest']='f'*64
    path.write_text(json.dumps(value))
    with pytest.raises(l.TargetCoordinateLifecycleError):owner.issue(preview)
    assert peer.calls.count('PUT')==1


def test_other_coordinator_cannot_reissue_consumed_phase(fixture):
    make,peer,h,transport,creator,store,directory=fixture
    first,second=make(),make()
    a=first.issue(first.preview());b=second.issue(second.preview())
    assert first.execute(a).as_dict()['outcome']=='succeeded'
    with pytest.raises(l.TargetCoordinateLifecycleError):second.execute(b)
    with pytest.raises(l.TargetCoordinateLifecycleError):second.preview()
    assert peer.calls.count('PUT')==1 and store.claim_count==1


@pytest.mark.parametrize('suffix',['coordinator.claim.json','claim.json','ack.json','verified.json'])
def test_any_phase_artifact_even_dangling_symlink_denies_new_preview(fixture,suffix):
    make,peer,h,transport,creator,store,directory=fixture
    owner=make();(directory/('update.'+suffix)).symlink_to(directory/'missing')
    with pytest.raises(l.TargetCoordinateLifecycleError):owner.preview()
    assert not peer.calls and not h.requests


def test_failed_ledger_reservation_does_not_reopen_phase(fixture,monkeypatch):
    make,peer,h,transport,creator,store,directory=fixture
    owner=make();issued=owner.issue(owner.preview())
    def fail(**kwargs):raise OSError('PRIVATE_SENTINEL')
    monkeypatch.setattr(store,'claim',fail)
    with pytest.raises(l.TargetCoordinateLifecycleError) as caught:owner.execute(issued)
    assert 'PRIVATE_SENTINEL' not in str(caught.value) and 'PUT' not in peer.calls
    assert (directory/'update.coordinator.claim.json').exists()
    with pytest.raises(l.TargetCoordinateLifecycleError):make()


def test_transport_gate_remains_independent(fixture):
    make,peer,h,transport,creator,store,directory=fixture
    owner=make();issued=owner.issue(owner.preview())
    object.__setattr__(transport,'_enabled',False)
    with pytest.raises(l.TargetCoordinateLifecycleError):owner.execute(issued)
    assert 'PUT' not in peer.calls and store.claim_count==0
    assert not (directory/'update.coordinator.claim.json').exists()
