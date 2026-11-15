"""Synthetic exact-input persistence across creator restart and original-ACK recovery."""
import copy
import json
import os
import pickle

import pytest

from fortipam_mcp import target_creation_inputs as p
from fortipam_mcp import target_creation_http_transport as t
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from v4_planning.material_provider import MaterialAccessDenied
from test_target_creation_http_transport import Peer, create
from test_target_original_ack_recovery import recover
from test_target_preservation_contract import row, capture


def request():
    proposal=capture(row())
    body={key:row()[key] for key in t.c.TARGET_STATE_FIELDS-t.e._GENERATED}
    body['$originalName']=proposal.name
    return proposal,bytearray(json.dumps(body,indent=2).encode()+b'\n')


@pytest.fixture
def prepared(tmp_path):
    root=tmp_path/'inputs';root.mkdir(mode=0o700)
    state=tmp_path/'state';state.mkdir(mode=0o700)
    store=p.TargetCreationInputStore(root)
    proposal,body=request();original=bytes(body)
    digest=store.provision(proposal,body)
    assert not any(body)
    peer=Peer()
    config=SecretMetadataHttpTransportConfig('https://pam.example','synthetic-token',5,None)
    def load(**kwargs):
        return p.TargetCreationInputStore(root).open_creator(config,input_digest=digest,
            state_directory=state,clock=lambda:peer.now,connection_factory=peer.factory,**kwargs)
    return store,root,state,digest,peer,load,original


def test_restart_exact_bytes_original_key_and_sealed_recovery(prepared):
    store,root,state,digest,peer,load,original=prepared
    assert (root/p._BODY).read_bytes()==original
    assert all(item.stat().st_mode & 0o777==0o600 for item in root.iterdir())
    saved={item.name:item.read_bytes() for item in root.iterdir()}
    creator=load(execution_enabled=True)
    evidence=create(creator)
    restarted=load(recovery_enabled=True)
    assert restarted.load_creation_evidence()==evidence
    recover(restarted,evidence.created)
    assert peer.created is None and peer.calls.count('POST')==peer.calls.count('DELETE')==1
    assert saved=={item.name:item.read_bytes() for item in root.iterdir()}
    with pytest.raises(t.TargetCreationTransportError):create(load(execution_enabled=True))
    assert peer.calls.count('POST')==1
    assert all(not any(raw) for raw in peer.body_views)


def test_default_gates_and_opaque_store(prepared):
    store,root,state,digest,peer,load,original=prepared
    with pytest.raises(t.TargetCreationTransportError):create(load())
    assert not peer.calls
    assert str(root) not in repr(store) and 'synthetic' not in repr(store)
    for operation in (copy.copy,copy.deepcopy,pickle.dumps):
        with pytest.raises(MaterialAccessDenied):operation(store)


@pytest.mark.parametrize('fault',['body','key','manifest','claim','body-mode','key-mode','key-short','body-symlink','key-hardlink','wrong-digest','directory-mode','directory-replaced'])
def test_corrupt_or_replaced_inputs_deny_before_network(prepared,fault,tmp_path):
    store,root,state,digest,peer,load,original=prepared
    if fault in ('body','key'):
        name=p._BODY if fault=='body' else p._KEY
        raw=bytearray((root/name).read_bytes());raw[0]^=1;(root/name).write_bytes(raw)
    elif fault in ('manifest','claim'):
        path=root/(p._MANIFEST if fault=='manifest' else p._CLAIM)
        value=json.loads(path.read_bytes());value['unexpected']='tamper';path.write_text(json.dumps(value))
    elif fault in ('body-mode','key-mode'):(root/(p._BODY if fault=='body-mode' else p._KEY)).chmod(0o644)
    elif fault=='key-short':(root/p._KEY).write_bytes(b'k')
    elif fault=='body-symlink':
        target=tmp_path/'saved-body';(root/p._BODY).rename(target);(root/p._BODY).symlink_to(target)
    elif fault=='key-hardlink':os.link(root/p._KEY,tmp_path/'other-key')
    elif fault=='wrong-digest':
        with pytest.raises(p.TargetCreationInputsError):
            store.open_creator(SecretMetadataHttpTransportConfig('https://pam.example','synthetic-token',5,None),input_digest='a'*64,state_directory=state)
        assert not peer.calls;return
    elif fault=='directory-mode':root.chmod(0o755)
    elif fault=='directory-replaced':
        root.rename(tmp_path/'old');root.mkdir(mode=0o700)
    with pytest.raises(p.TargetCreationInputsError) as error:load()
    assert str(error.value)==p._ERROR and error.value.__suppress_context__
    assert not peer.calls


def test_partial_provision_is_terminal_and_preserves_original(tmp_path,monkeypatch):
    tmp_path.chmod(0o700);store=p.TargetCreationInputStore(tmp_path)
    original=p._write_binary
    def fail_key(directory,name,content):
        if name==p._KEY:raise OSError('synthetic private failure')
        original(directory,name,content)
    monkeypatch.setattr(p,'_write_binary',fail_key)
    proposal,body=request();exact=bytes(body)
    with pytest.raises(p.TargetCreationInputsError):store.provision(proposal,body)
    assert not any(body) and (tmp_path/p._CLAIM).exists() and not (tmp_path/p._MANIFEST).exists()
    assert (tmp_path/p._BODY).read_bytes()==exact
    monkeypatch.setattr(p,'_write_binary',original)
    proposal,body=request()
    with pytest.raises(p.TargetCreationInputsError):store.provision(proposal,body)
    assert not any(body) and not (tmp_path/p._KEY).exists()
    assert (tmp_path/p._BODY).read_bytes()==exact


def test_load_wipes_owned_buffers_after_transfer(prepared,monkeypatch):
    store,root,state,digest,peer,load,original=prepared
    buffers=[];read=p._read_binary
    def retained(*args):
        value=read(*args);buffers.append(value);return value
    monkeypatch.setattr(p,'_read_binary',retained)
    creator=load()
    assert len(buffers)==2 and all(not any(value) for value in buffers)
    creator.close()


def test_lock_contention_and_untrusted_digest_do_not_read_material(prepared,monkeypatch):
    store,root,state,digest,peer,load,original=prepared
    def forbidden(*args):raise AssertionError('material should not be read')
    monkeypatch.setattr(p,'_read_binary',forbidden)
    with store._lock():
        with pytest.raises(p.TargetCreationInputsError):load()
    config=SecretMetadataHttpTransportConfig('https://pam.example','synthetic-token',5,None)
    with pytest.raises(p.TargetCreationInputsError):store.open_creator(config,input_digest='b'*64,state_directory=state)
    assert not peer.calls


def test_invalid_body_is_consumed_without_provision_claim(tmp_path):
    tmp_path.chmod(0o700);store=p.TargetCreationInputStore(tmp_path)
    proposal,body=request();body[:]=b'{"wrong":"SYNTHETIC_MATERIAL"}'
    with pytest.raises(p.TargetCreationInputsError):store.provision(proposal,body)
    assert not any(body) and not list(tmp_path.iterdir())
