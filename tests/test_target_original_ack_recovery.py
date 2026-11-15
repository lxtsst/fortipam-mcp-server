"""Sealed original-creation cleanup with exact state and zero-reference gates."""
import json

import pytest

from fortipam_mcp import target_creation_http_transport as t
from test_target_preservation_contract import capture
from test_target_creation_http_transport import setup, create


def prepared(tmp_path):
    peer,make=setup(tmp_path)
    original=create(make(execution_enabled=True))
    return peer,make,original


def recover(transport,current,**overrides):
    kwargs=dict(expected_current=current,plan_digest='c'*64,authorization_digest='d'*64,
        expires_at=150,before_send=lambda:None,reference_count=lambda name:0)
    kwargs.update(overrides)
    return transport.recover(**kwargs)


def test_original_ack_cleanup_and_independent_terminal_claim(tmp_path):
    peer,make,original=prepared(tmp_path);names=[]
    recover(make(recovery_enabled=True),original.created,reference_count=lambda name:names.append(name) or 0)
    assert peer.calls==['GET','POST','GET','GET','GET','DELETE','GET']
    assert names==[original.created.name]*2
    assert peer.created is None and (tmp_path/'delete.verified.json').exists()
    saved={p.name:p.read_bytes() for p in tmp_path.iterdir() if p.name.startswith('create.')}
    with pytest.raises(t.TargetCreationTransportError):recover(make(recovery_enabled=True),original.created)
    assert peer.calls.count('DELETE')==1
    assert saved=={p.name:p.read_bytes() for p in tmp_path.iterdir() if p.name.startswith('create.')}
    assert all(item.closed for item in peer.connections+peer.responses)


def test_explicit_cleanup_of_coordinate_changed_owned_fixture(tmp_path):
    peer,make,original=prepared(tmp_path)
    peer.created['address']='192.0.2.99'
    current=capture(peer.created)
    assert current.preserved_digest==original.created.preserved_digest
    recover(make(recovery_enabled=True),current)
    assert peer.created is None


@pytest.mark.parametrize('fault',['disabled','unowned','preserved','current','refs','bool_refs','expired_ref',
    'authority_after_tls','state_after_tls','lost_ack','not_absent','anchor_after_tls'])
def test_recovery_failures_never_repeat_delete(tmp_path,fault):
    peer,make,original=prepared(tmp_path)
    current=original.created;allowed=[True]
    if fault=='unowned':(tmp_path/'create.verified.json').unlink()
    if fault=='preserved':
        peer.created['description']='external modification';current=capture(peer.created)
    if fault=='current':peer.created['address']='changed after preview'
    peer.lost_delete_ack=fault=='lost_ack';peer.keep_after_delete=fault=='not_absent'
    def hook():
        if peer.calls==['GET','POST','GET','GET']:
            if fault=='authority_after_tls':allowed[0]=False
            if fault=='state_after_tls':peer.created['address']='drift during DELETE TLS'
            if fault=='anchor_after_tls':
                path=tmp_path/'create.ack.json';record=json.loads(path.read_text());record['tamper']=True;path.write_text(json.dumps(record))
    peer.hook=hook
    def guard():
        if not allowed[0]:raise ValueError('private authorization revoked')
    def references(name):
        assert name==original.created.name
        if fault=='expired_ref':peer.now=150
        return 1 if fault=='refs' else False if fault=='bool_refs' else 0
    with pytest.raises(t.TargetCreationTransportError):
        recover(make(recovery_enabled=fault!='disabled'),current,before_send=guard,reference_count=references)
    writes=peer.calls.count('DELETE')
    assert writes==(1 if fault in ('lost_ack','not_absent') else 0)
    assert not (tmp_path/'delete.verified.json').exists()
    if (tmp_path/'delete.claim.json').exists():
        with pytest.raises(t.TargetCreationTransportError):recover(make(recovery_enabled=True),current)
        assert peer.calls.count('DELETE')==writes
    assert all(item.closed for item in peer.connections+peer.responses)


def test_recovery_gate_does_not_enable_creation(tmp_path):
    peer,make=setup(tmp_path)
    with pytest.raises(t.TargetCreationTransportError):create(make(recovery_enabled=True))
    assert not peer.calls
