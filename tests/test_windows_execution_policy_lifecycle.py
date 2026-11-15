"""Complete fixed Policy create/recovery with real M4 and synthetic network peers."""
import io
import json

import pytest
from v4_planning import M4AuthorizationDenied

from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.windows_execution_policy_authority import WindowsPolicyM4Authority
from fortipam_mcp.windows_execution_policy_lifecycle import WindowsExecutionPolicyLifecycle, WindowsPolicyLifecycleError
from fortipam_mcp.windows_execution_policy_sources import WindowsExecutionPolicySources
from test_windows_execution_policy_sources import make
from test_windows_execution_policy_contract import BINDING, envelope
from test_m4_execution_store import _ExternalM4Checkpoint

IDENTITY = dict(environment_ref='policy-lab-environment',scope_ref='policy-lab-scope',audience_ref='policy-lab-audience',
    requester_digest='b'*64,transport_digest='c'*64)


class Native:
    def __init__(self,api,ssh,*,fault=None):
        self.api,self.ssh,self.fault=api,ssh,fault
        self.calls=[];self.connections=[];self.responses=[]
        self.connect_hook=lambda:None

    def factory(self,*args,**kwargs):
        peer=self
        class Connection:
            sock=None
            def __init__(self):self.closed=False;self.timeout=kwargs['timeout']
            def connect(self):peer.connect_hook()
            def request(self,method,path,body,headers):
                peer.calls.append((method,path))
                assert 'Cookie' not in headers and headers['Authorization']=='Bearer synthetic-token'
                assert headers['User-Agent']=='fortipam-mcp-policy-lifecycle/1'
                if method=='POST':
                    assert path=='/api/v2/cmdb/secret/policy?with_meta=true'
                    assert json.loads(body)==json.loads(peer.api.request.body_json)
                    assert not peer.api.present
                    if peer.fault!='http403':
                        peer.api.present=True
                        peer.ssh.names=tuple(sorted((*peer.ssh.names,BINDING.name)))
                else:
                    assert method=='DELETE' and path=='/api/v2/cmdb/secret/policy/'+BINDING.name and body is None
                    assert peer.api.present
                    peer.api.present=False
                    peer.ssh.names=tuple(name for name in peer.ssh.names if name!=BINDING.name)
                value=json.loads(envelope([],http_method=method,mkey=BINDING.name,error=0))
                if peer.fault=='wrong-ack':value['mkey']='other'
                status=403 if peer.fault=='http403' else 200
                self.response=Response(json.dumps(value).encode(),status)
                peer.responses.append(self.response)
            def getresponse(self):
                if peer.fault=='lost-ack':raise OSError('synthetic lost original response')
                return self.response
            def close(self):self.closed=True
        class Response:
            def __init__(self,raw,status):self.raw=io.BytesIO(raw);self.status=status;self.closed=False
            def getheader(self,name,default=''):
                return 'application/json' if name=='Content-Type' else default
            def read(self,size):return self.raw.read(size)
            def close(self):self.closed=True
        connection=Connection();self.connections.append(connection)
        return connection


def lifecycle(tmp_path,source,native,*,phase='create',original=None,enabled=True,authority_enabled=True):
    root=tmp_path/phase;root.mkdir(mode=0o700)
    state=root/'state';state.mkdir(mode=0o700)
    execution_key=b'e'*32 if phase=='create' else b'r'*32
    witness_key=b'w'*32 if phase=='create' else b'k'*32
    authority_key=b'a'*32 if phase=='create' else b'z'*32
    for name,value in (('execution.key',execution_key),('witness.key',witness_key)):
        (root/name).write_bytes(value);(root/name).chmod(0o600)
    ref='policy-'+phase+'-checkpoint'
    store=PersistentM4ExecutionStateStore(root/'execution.sqlite',root/'execution.key',
        monotonic_checkpoint=_ExternalM4Checkpoint(ref),checkpoint_store_ref=ref)
    authority=WindowsPolicyM4Authority(source,phase=phase,authority_key=authority_key,original=original,
        execution_enabled=authority_enabled,clock=lambda:1000,**IDENTITY)
    item=WindowsExecutionPolicyLifecycle(sources=source,authority=authority,store=store,directory=state,
        witness_key_file=root/'witness.key',execution_enabled=enabled,connection_factory=native.factory)
    return item,store,authority


def test_independent_create_and_recovery_preserve_original_records_and_leave_no_policy(tmp_path,monkeypatch):
    source,api,ssh,_,_=make(tmp_path,monkeypatch)
    native=Native(api,ssh)
    create,store,authority=lifecycle(tmp_path,source,native)
    preview=create.preview();issued=create.issue(preview)
    result=create.execute()
    assert str(result.outcome)=='succeeded' and str(result.verification)=='verified'
    original=create.original_creation()
    owned=original.inspect_created_state()
    assert owned.created_state_digest and owned.source_context_digest==source.source_context_digest
    old={p.name:p.read_bytes() for p in create._directory.iterdir()}
    assert set(old)=={'send.claim.json','create.response.json','create-ack.json','created-state.json'}
    create.close()
    recover,recovery_store,recovery_authority=lifecycle(tmp_path,source,native,phase='recover',original=original)
    recovery_preview=recover.preview();recover.issue(recovery_preview)
    result=recover.execute()
    assert str(result.outcome)=='succeeded' and str(result.verification)=='verified'
    assert not api.present and native.calls==[('POST','/api/v2/cmdb/secret/policy?with_meta=true'),
        ('DELETE','/api/v2/cmdb/secret/policy/'+BINDING.name)]
    assert store.claim_count==recovery_store.claim_count==1
    assert {p.name:p.read_bytes() for p in create._directory.iterdir()}==old
    assert original.inspect_created_state()==owned
    assert set(p.name for p in recover._directory.iterdir())=={'recover.claim.json','recover.response.json','recover.ack.json','recover.verified.json'}
    recover.close();source.close()
    assert all(c.closed for c in native.connections) and all(r.closed for r in native.responses)


def test_explicit_v2_joins_fresh_defaults_and_seals_backend_normalization_before_recovery(tmp_path,monkeypatch):
    source,api,ssh,_,_=make(tmp_path,monkeypatch,canonical=True)
    native=Native(api,ssh)
    create,store,_=lifecycle(tmp_path,source,native)
    create.issue(create.preview())
    result=create.execute()
    assert str(result.outcome)=='succeeded' and str(result.verification)=='verified'
    original=create.original_creation()
    sealed=original.inspect_created_state()
    before={p.name:p.read_bytes() for p in create._directory.iterdir()}
    create.close()
    recover,recovery_store,_=lifecycle(tmp_path,source,native,phase='recover',original=original)
    recover.issue(recover.preview())
    result=recover.execute()
    assert str(result.outcome)=='succeeded' and str(result.verification)=='verified'
    assert not api.present and store.claim_count==recovery_store.claim_count==1
    assert original.inspect_created_state()==sealed
    assert {p.name:p.read_bytes() for p in create._directory.iterdir()}==before
    recover.close();source.close()


@pytest.mark.parametrize('fault',['wrong-ack','http403','lost-ack'])
def test_one_consumed_unknown_create_never_recovers_or_redispatches(tmp_path,monkeypatch,fault):
    source,api,ssh,_,_=make(tmp_path,monkeypatch)
    native=Native(api,ssh,fault=fault)
    create,store,authority=lifecycle(tmp_path,source,native)
    create.issue(create.preview());result=create.execute()
    assert str(result.outcome)=='reconciliation_required' and str(result.verification)=='unknown'
    assert len(native.calls)==1 and store.claim_count==1
    with pytest.raises(WindowsPolicyLifecycleError):create.original_creation()
    before={p.name:p.read_bytes() for p in create._directory.iterdir()}
    with pytest.raises(WindowsPolicyLifecycleError):create.execute()
    with pytest.raises(WindowsPolicyLifecycleError):create.preview()
    assert len(native.calls)==1 and {p.name:p.read_bytes() for p in create._directory.iterdir()}==before
    if fault!='lost-ack':
        diagnostic=create._record('create.response.json')
        assert diagnostic['http_status']==(403 if fault=='http403' else 200)
        assert diagnostic['success_ack_qualified'] is False
    else:
        failure=create._record('create.failure.json')
        assert failure['stage']=='native_response' and failure['error_class']=='OSError'
        assert failure['success_ack_qualified'] is False
    create.close();source.close()
    assert all(c.closed for c in native.connections)


@pytest.mark.parametrize('gate',['transport','authority'])
def test_default_off_boundaries_prevent_claim_and_native_io(tmp_path,monkeypatch,gate):
    source,api,ssh,_,_=make(tmp_path,monkeypatch)
    native=Native(api,ssh)
    item,store,authority=lifecycle(tmp_path,source,native,enabled=gate!='transport',authority_enabled=gate!='authority')
    preview=item.preview()
    if gate=='authority':
        with pytest.raises(WindowsPolicyLifecycleError):item.issue(preview)
    else:
        item.issue(preview)
        with pytest.raises(WindowsPolicyLifecycleError):item.execute()
    assert store.claim_count==0 and not native.calls and not native.connections
    item.close();source.close()


def test_source_drift_after_tls_prevents_post_and_cannot_form_owned_receipt(tmp_path,monkeypatch):
    source,api,ssh,_,_=make(tmp_path,monkeypatch)
    native=Native(api,ssh)
    item,store,authority=lifecycle(tmp_path,source,native)
    item.issue(item.preview())
    native.connect_hook=lambda:setattr(api,'failure','role')
    result=item.execute()
    assert str(result.outcome)!='succeeded' and not native.calls and not api.present
    with pytest.raises(WindowsPolicyLifecycleError):item.original_creation()
    item.close();source.close()


def test_recovery_cannot_be_issued_without_original_seal(tmp_path,monkeypatch):
    source,api,ssh,_,_=make(tmp_path,monkeypatch)
    with pytest.raises(M4AuthorizationDenied):WindowsPolicyM4Authority(source,phase='recover',authority_key=b'z'*32,
        execution_enabled=True,clock=lambda:1000,**IDENTITY)
    source.close()


def test_expired_post_read_stays_unknown_but_independent_owned_recovery_can_finish(tmp_path,monkeypatch):
    source,api,ssh,now,_=make(tmp_path,monkeypatch)
    native=Native(api,ssh)
    create,store,authority=lifecycle(tmp_path,source,native)
    create.issue(create.preview())
    dispatch=create.dispatch
    def expire_after_full_read(plan):
        dispatch(plan)
        now[0]=130.0
    monkeypatch.setattr(create,'dispatch',expire_after_full_read)
    result=create.execute()
    assert str(result.outcome)=='reconciliation_required' and str(result.verification)=='unknown'
    original=create.original_creation()
    assert original.inspect_created_state().original_outcome=='reconciliation_required'
    before={p.name:p.read_bytes() for p in create._directory.iterdir()}
    create.close();now[0]=131.0
    recover,recovery_store,_=lifecycle(tmp_path,source,native,phase='recover',original=original)
    recover.issue(recover.preview());result=recover.execute()
    assert str(result.outcome)=='succeeded' and not api.present
    assert original.inspect_created_state().original_outcome=='reconciliation_required'
    assert {p.name:p.read_bytes() for p in create._directory.iterdir()}==before
    assert store.claim_count==recovery_store.claim_count==1
    recover.close();source.close()


def test_gate_closed_after_reservation_retains_claim_without_post(tmp_path,monkeypatch):
    source,api,ssh,_,_=make(tmp_path,monkeypatch)
    native=Native(api,ssh)
    item,store,_=lifecycle(tmp_path,source,native)
    item.issue(item.preview())
    write=item._creation._write
    def close_after_claim(name,record):
        write(name,record)
        item._enabled=False
    monkeypatch.setattr(item._creation,'_write',close_after_claim)
    result=item.execute()
    assert str(result.outcome)=='reconciliation_required' and not native.calls
    assert (item._directory/'send.claim.json').exists()
    assert not (item._directory/'create-ack.json').exists()
    item.close();source.close()
