"""Fixed Folder lifecycle uses real sources, original custody and persistent M4."""
import io
import json

import httpx
import pytest
from v4_planning import M4AdapterAmbiguous

from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.windows_execution_folder_authority import WindowsFolderM4Authority
from fortipam_mcp.windows_execution_folder_lifecycle import WindowsExecutionFolderLifecycle, WindowsFolderLifecycleError
from test_m4_execution_store import _ExternalM4Checkpoint
from test_windows_execution_folder_sources import make
from test_windows_execution_policy_contract import envelope

IDENTITY=dict(environment_ref='folder-lab-environment',scope_ref='folder-lab-scope',audience_ref='folder-lab-audience',
    requester_digest='b'*64,transport_digest='c'*64)


class Native:
    def __init__(self,source,api,*,fault=None):
        self.source,self.api,self.fault=source,api,fault
        self.calls=[];self.connections=[];self.responses=[];self.connect_hook=lambda:None
        api.owner_delete_handler=self.owner_delete

    def owner_delete(self,request):
        assert request.method=='DELETE' and request.url.path=='/api/v2/cmdb/secret/folder/41'
        assert 'authorization' not in request.headers and request.headers['x-csrftoken']=='synthetic-csrf'
        assert request.headers['content-length']=='0' and not request.content
        self.calls.append(('DELETE',request.url.path));assert self.api.present
        if self.fault!='owner-http403':self.api.present=False
        if self.fault=='owner-lost-ack':raise OSError('Synthetic lost original Owner DELETE response.')
        raw=envelope([],name='folder',http_method='DELETE',status='OK',mkey=42 if self.fault=='owner-wrong-ack' else 41,error=0)
        return httpx.Response(403 if self.fault=='owner-http403' else 200,stream=httpx.ByteStream(bytes(raw)),headers={'content-type':'application/json'})

    def factory(self,*args,**kwargs):
        peer=self
        class Connection:
            sock=None
            def __init__(self):self.closed=False;self.timeout=kwargs['timeout']
            def connect(self):peer.connect_hook()
            def request(self,method,path,body,headers):
                peer.calls.append((method,path))
                assert headers['Authorization']=='Bearer synthetic-token' and 'Cookie' not in headers
                assert headers['User-Agent']=='fortipam-mcp-explicit-folder-lifecycle/1'
                if method=='POST':
                    assert path=='/api/v2/cmdb/secret/folder' and json.loads(body)==json.loads(peer.source._request.body_json)
                    assert not peer.api.present
                    if peer.fault!='http403':peer.api.present=True
                else:
                    assert method=='DELETE' and path=='/api/v2/cmdb/secret/folder/41' and body is None
                    assert peer.api.present;peer.api.present=False
                raw=envelope([],name='folder',http_method=method,status='OK',mkey=42 if peer.fault=='wrong-ack' else 41,error=0)
                self.response=Response(bytes(raw),403 if peer.fault=='http403' else 200);peer.responses.append(self.response)
            def getresponse(self):
                if peer.fault=='lost-ack':raise OSError('Synthetic lost original Folder response.')
                return self.response
            def close(self):self.closed=True
        class Response:
            def __init__(self,raw,status):self.raw=io.BytesIO(raw);self.status=status;self.closed=False
            def getheader(self,name,default=''):return 'application/json' if name=='Content-Type' else default
            def read(self,size):return self.raw.read(size)
            def close(self):self.closed=True
        item=Connection();self.connections.append(item);return item


def lifecycle(tmp_path,source,native,*,phase='create',original=None,enabled=True,authority_enabled=True):
    root=tmp_path/('folder-'+phase);root.mkdir(mode=0o700);(root/'state').mkdir(mode=0o700)
    execution_key=b't'*32 if phase=='create' else b'r'*32
    witness_key=b'k'*32 if phase=='create' else b'n'*32
    authority_key=b'j'*32 if phase=='create' else b'z'*32
    for name,value in (('execution.key',execution_key),('witness.key',witness_key)):
        (root/name).write_bytes(value);(root/name).chmod(0o600)
    ref='explicit-folder-'+phase+'-checkpoint'
    store=PersistentM4ExecutionStateStore(root/'execution.sqlite',root/'execution.key',
        monotonic_checkpoint=_ExternalM4Checkpoint(ref),checkpoint_store_ref=ref)
    authority=WindowsFolderM4Authority(source,phase=phase,authority_key=authority_key,original=original,
        execution_enabled=authority_enabled,clock=lambda:1000,**IDENTITY)
    owner=WindowsExecutionFolderLifecycle(sources=source,authority=authority,store=store,directory=root/'state',
        witness_key_file=root/'witness.key',execution_enabled=enabled,connection_factory=native.factory,
        owner_client_factory=native.api.base.factory)
    return owner,store,authority


def test_independent_folder_create_and_recovery_preserve_original_policy_and_folder_records(tmp_path,monkeypatch):
    source,api,policy,parent,*_=make(tmp_path,monkeypatch)
    parent_before={p.name:p.read_bytes() for p in parent._directory.iterdir()}
    native=Native(source,api);create,store,_=lifecycle(tmp_path,source,native)
    create.issue(create.preview());result=create.execute()
    assert str(result.outcome)=='succeeded' and str(result.verification)=='verified'
    original=create.original_creation();sealed=original.inspect_created_state()
    assert sealed.native_folder_id==41 and sealed.native_ack_status=='OK'
    before={p.name:p.read_bytes() for p in create._directory.iterdir()}
    create.close()
    recover,recovery_store,_=lifecycle(tmp_path,source,native,phase='recover',original=original)
    recover.issue(recover.preview());result=recover.execute()
    assert str(result.outcome)=='succeeded' and str(result.verification)=='verified'
    assert not api.present and source._current.absent and source._current.policy_reference_count==0
    assert native.calls==[('POST','/api/v2/cmdb/secret/folder'),('DELETE','/api/v2/cmdb/secret/folder/41')]
    assert store.claim_count==recovery_store.claim_count==1
    assert {p.name:p.read_bytes() for p in create._directory.iterdir()}==before
    assert {p.name:p.read_bytes() for p in parent._directory.iterdir()}==parent_before
    assert original.inspect_created_state()==sealed
    assert recover._owner_recovery.logout_verified
    assert set(p.name for p in recover._directory.iterdir())=={'recover.claim.json','recover.response.json','recover.ack.json','recover.verified.json'}
    assert all(item.closed for item in native.connections) and all(item.closed for item in native.responses)
    recover.close();source.close();policy.close()


@pytest.mark.parametrize('fault',['lost-ack','wrong-ack','http403'])
def test_consumed_unknown_folder_creation_never_replays_or_acquires_recovery(tmp_path,monkeypatch,fault):
    source,api,policy,*_=make(tmp_path,monkeypatch)
    native=Native(source,api,fault=fault);create,store,_=lifecycle(tmp_path,source,native)
    create.issue(create.preview());result=create.execute()
    assert str(result.outcome)=='reconciliation_required' and str(result.verification)=='unknown'
    assert len(native.calls)==store.claim_count==1
    with pytest.raises(WindowsFolderLifecycleError):create.execute()
    with pytest.raises(WindowsFolderLifecycleError):create.original_creation()
    assert len(native.calls)==1 and not (create._directory/'created-state.json').exists()
    create.close();source.close();policy.close()


@pytest.mark.parametrize('gate',['transport','authority'])
def test_independent_default_off_boundaries_prevent_claim_and_native_io(tmp_path,monkeypatch,gate):
    source,api,policy,*_=make(tmp_path,monkeypatch)
    native=Native(source,api);owner,store,_=lifecycle(tmp_path,source,native,
        enabled=gate!='transport',authority_enabled=gate!='authority')
    if gate=='authority':
        with pytest.raises(WindowsFolderLifecycleError):owner.issue(owner.preview())
    else:
        owner.issue(owner.preview())
        with pytest.raises(WindowsFolderLifecycleError):owner.execute()
    assert not native.calls and store.claim_count==0
    owner.close();source.close();policy.close()


def test_permission_drift_after_tls_prevents_folder_post(tmp_path,monkeypatch):
    source,api,policy,*_=make(tmp_path,monkeypatch)
    native=Native(source,api);owner,store,_=lifecycle(tmp_path,source,native)
    owner.issue(owner.preview());native.connect_hook=lambda:setattr(api,'failure','folder-role')
    result=owner.execute()
    assert str(result.outcome)!='succeeded' and not native.calls and not api.present
    assert not (owner._directory/'send.claim.json').exists()
    owner.close();source.close();policy.close()


def test_independent_recovery_can_cleanup_full_seal_without_rewriting_unknown_creation(tmp_path,monkeypatch):
    source,api,policy,*_=make(tmp_path,monkeypatch)
    native=Native(source,api);create,store,_=lifecycle(tmp_path,source,native)
    create.issue(create.preview())
    def unavailable(plan):raise M4AdapterAmbiguous('Synthetic postcondition unavailable after original seal.')
    monkeypatch.setattr(create,'read_postcondition',unavailable)
    result=create.execute()
    assert str(result.outcome)=='reconciliation_required'
    original=create.original_creation();assert original.inspect_created_state().original_outcome=='reconciliation_required'
    before={p.name:p.read_bytes() for p in create._directory.iterdir()};create.close()
    recover,_,_=lifecycle(tmp_path,source,native,phase='recover',original=original)
    recover.issue(recover.preview());result=recover.execute()
    assert str(result.outcome)=='succeeded' and not api.present
    assert original.inspect_created_state().original_outcome=='reconciliation_required'
    assert {p.name:p.read_bytes() for p in create._directory.iterdir()}==before
    recover.close();source.close();policy.close()


@pytest.mark.parametrize('fault',['owner-lost-ack','owner-http403','owner-wrong-ack'])
def test_owner_recovery_unknown_never_replays_or_rewrites_original_creation(tmp_path,monkeypatch,fault):
    source,api,policy,*_=make(tmp_path,monkeypatch)
    native=Native(source,api);create,_,_=lifecycle(tmp_path,source,native)
    create.issue(create.preview());assert str(create.execute().outcome)=='succeeded'
    original=create.original_creation();before={p.name:p.read_bytes() for p in create._directory.iterdir()};create.close()
    native.fault=fault
    recover,store,_=lifecycle(tmp_path,source,native,phase='recover',original=original)
    recover.issue(recover.preview());result=recover.execute()
    assert str(result.outcome)=='reconciliation_required' and str(result.verification)=='unknown'
    assert store.claim_count==1 and len(native.calls)==2
    assert not (recover._directory/'recover.verified.json').exists()
    with pytest.raises(WindowsFolderLifecycleError):recover.execute()
    assert len(native.calls)==2 and {p.name:p.read_bytes() for p in create._directory.iterdir()}==before
    recover.close();source.close();policy.close()
