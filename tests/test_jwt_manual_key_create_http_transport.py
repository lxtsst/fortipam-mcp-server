"""Single fixed JWT POST/readback through real persistent M4 and synthetic TLS IO."""
import copy
import io
import json
import ssl
from dataclasses import asdict
import os
from pathlib import Path
import subprocess
import sys

import pytest
from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, M4ExecutionPlan, canonical_digest

from fortipam_mcp import jwt_manual_key_create_http_transport as t
from fortipam_mcp import jwt_manual_key_preflight_reader as r
from fortipam_mcp import jwt_manual_key_response_custody as c
from fortipam_mcp.jwt_manual_key_owned_state import expected_jwt_manual_key_created_state
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_jwt_manual_key_actor_evidence import inputs as actor_inputs
from test_jwt_manual_key_preflight import NAME, SERIAL, SCHEMA_DIGEST, DEFAULTS_DIGEST, inputs, packet, raw
from test_jwt_manual_key_owned_state import request
from test_jwt_manual_key_contract import synthetic_key, public_pem
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF
from test_v4_execution_kernel import _authorization, _Verifier, REQUESTER, CONFIRMATION, APPROVAL


class Lab:
    def __init__(self,root,key,monkeypatch):
        root.chmod(0o700);(root/'custody').mkdir(mode=0o700)
        for name,value in [('execution.key',b'e'*32),('witness.key',b'w'*32),('ca.pem',b'SYNTHETIC_CA_BINDING')]:
            (root/name).write_bytes(value);(root/name).chmod(0o600)
        monkeypatch.setattr(r,'_ssl_context',lambda config:ssl.create_default_context())
        monkeypatch.setattr(t,'_ssl_context',lambda config:ssl.create_default_context())
        self.config=SecretMetadataHttpTransportConfig('https://pam.example.test:9443','synthetic-bearer',30,str(root/'ca.pem'))
        self.request=request(key);self.created=False;self.row=None;self.calls=[];self.resources=[];self.buffers=[]
        self.enabled=self.source=True;self.epoch=1000;self.mono=0;self.fault='none';self.post_count=0;self.drift=False
        self.enabled_guard=lambda:self.enabled;self.source_guard=lambda:self.source
        self.reader=r.JwtManualKeyPreflightReader(self.config,name=NAME,expected_actor='synthetic-api',expected_profile='synthetic-role',
            serial_digest=SERIAL,schema_digest=SCHEMA_DIGEST,defaults_digest=DEFAULTS_DIGEST,source_guard=self.source_guard,
            connection_factory=lambda *args,**kwargs:self.connect('reader',*args,**kwargs),http_clock=lambda:self.mono)
        self.baseline=self.reader.observe()
        self.checkpoint=_ExternalM4Checkpoint()
        self.store=PersistentM4ExecutionStateStore(root/'execution.sqlite',root/'execution.key',
            monotonic_checkpoint=self.checkpoint,checkpoint_store_ref=CHECKPOINT_STORE_REF)
        fields=dict(plan_ref='manual-jwt-original-plan-01',revision=1,action_id=c.ACTION_ID,action_version='1.0.0',
            adapter_ref=c.ADAPTER_REF,target_ref='bound-manual-jwt-public-key',requester_digest=REQUESTER,
            summary_digest='c'*64,confirmation_digest=CONFIRMATION,approval_digest=APPROVAL,parameters_digest=self.request.digest,
            expected_current_digest=r.jwt_manual_create_current_from_preflight(self.request,self.baseline),
            expected_state_digest=expected_jwt_manual_key_created_state(self.request,self.baseline.state),
            idempotency_digest='e'*64,expires_at=1300,compensation_ref=None)
        self.plan=M4ExecutionPlan(**fields,plan_digest=canonical_digest(fields));self.auth=_authorization(self.plan)
        self.custody=c.JwtManualKeyResponseCustody(root/'custody',root/'witness.key',self.request,self.baseline.actor,
            self.baseline.source_digest,self.baseline.state.state_digest,self.plan,self.auth,self.store,
            execution_enabled=self.enabled_guard,source_guard=self.source_guard,actor_reader=self.reader.observe_actor,clock=lambda:self.epoch)
        self.transport=t.JwtManualKeyCreateHttpTransport(self.config,self.custody,self.reader,self.baseline,
            execution_enabled=self.enabled_guard,source_guard=self.source_guard,
            connection_factory=lambda *args,**kwargs:self.connect('writer',*args,**kwargs),http_clock=lambda:self.mono)

    def connect(self,kind,host,port,**kwargs):
        assert(host,port)==('pam.example.test',9443)
        assert kwargs['context'].check_hostname and kwargs['context'].verify_mode==ssl.CERT_REQUIRED
        lab=self
        class Response:
            closed=False
            reads=0
            def __init__(self,body,status,is_post):self.stream=io.BytesIO(body);self.status=status;self.is_post=is_post
            def getheader(self,key,default=None):
                return {'content-type':'text/html'if self.is_post and lab.fault=='html'else'application/json',
                    'content-encoding':'gzip'if self.is_post and lab.fault=='encoded'else'identity'}.get(key.lower(),default)
            def readinto(self,destination):
                lab.buffers.append(destination);self.reads+=1
                if self.is_post and self.reads>1:
                    if lab.fault=='timeout':raise TimeoutError('PRIVATE_SYNTHETIC_DETAIL')
                    if lab.fault=='interrupt':raise KeyboardInterrupt
                with memoryview(destination)[:min(len(destination),73)]as view:count=self.stream.readinto(view)
                if self.is_post and not count:
                    if lab.fault=='source-inflight':lab.source=False
                    if lab.fault=='expire-inflight':lab.epoch=lab.auth.expires_at
                return count
            def close(self):
                self.closed=True
                if self.is_post and lab.fault=='close-post':raise OSError('PRIVATE_SYNTHETIC_DETAIL')
        class Connection:
            closed=False
            response=None
            def connect(self):
                if kind=='writer'and not lab.created:
                    if lab.fault=='source-after-tls':lab.source=False
                    if lab.fault=='state-after-tls':lab.drift=True
            def request(self,method,path,body=None,headers=None):
                assert method in{'GET','POST'}and headers['Authorization']=='Bearer synthetic-bearer'
                lab.calls.append((method,path))
                if method=='POST':
                    lab.post_count+=1
                    assert path=='/api/v2/cmdb/secret/jwt-key?with_meta=true'and body.readonly
                    lab.row=json.loads(body.tobytes());assert len(lab.row)==7
                    lab.row.update({'oidc-discovery-url':'','last-check-time':'synthetic-never','last-update-time':'synthetic-never',
                        'q_global_entry':False,'q_mkey_type':'string','q_name':'jwt-key','q_no_edit':False,'q_no_rename':False,
                        'q_origin_key':NAME,'q_path':'secret','q_ref':0,'q_static':False,'q_type':0})
                    lab.created=True
                    payload=packet('jwt-key',None,http_method='POST',mkey=NAME)
                    status=200
                    if lab.fault=='error':payload.update(status='error',http_status=500,error=-3);status=500
                    body=bytes(raw(payload))
                    if lab.fault=='html':body=b'<html>PRIVATE_SYNTHETIC_DETAIL</html>';status=502
                    if lab.fault=='oversize':body=b'x'*(t._MAX_BYTES+20)
                    self.response=Response(body,status,True)
                else:
                    if path in lab.reader._paths:
                        index=lab.reader._paths.index(path)
                        values=actor_inputs()+inputs()
                        if lab.drift:
                            values[7]['results'].append(dict(name='synthetic-added',type='token',**{'jwt-key':''}))
                            values[7].update(size=2,matched_count=2,next_idx=1)
                        payload=values[index];status=404 if index==8 else 200
                        if lab.created and index==6:
                            payload=packet('jwt-key',[dict(name=NAME,type='manually')],size=1,matched_count=1,next_idx=0)
                    else:
                        assert path=='/api/v2/cmdb/secret/jwt-key/'+NAME+'?with_meta=true'and lab.created
                        if lab.fault=='refs':lab.row['q_ref']=1
                        if lab.fault=='post-drift'and lab.request._closed:lab.row['last-update-time']='changed'
                        payload=packet('jwt-key',[copy.deepcopy(lab.row)],mkey=NAME);status=200
                        if lab.fault=='readback-unknown':status=403
                    self.response=Response(bytes(raw(payload)),status,False)
            def getresponse(self):lab.resources.append(self.response);return self.response
            def close(self):self.closed=True
        result=Connection();lab.resources.append(result);return result

    def execute(self):return M4ExecutionKernel(self.transport,_Verifier(),self.store,clock=lambda:1000).execute(self.plan,self.auth)


def test_single_post_original_ack_complete_state_and_independent_postcondition(tmp_path,monkeypatch,synthetic_key):
    lab=Lab(tmp_path,synthetic_key,monkeypatch);result=lab.execute()
    assert result.outcome=='succeeded'and result.verification=='verified'and lab.post_count==1
    assert all(resource.closed for resource in lab.resources)and all(not any(raw)for raw in lab.buffers)
    assert lab.request._closed and not any(lab.request._body)
    original=lab.custody.inspect_original_owned_state()
    assert original.state.postcondition_digest==lab.plan.expected_state_digest
    assert original.response.original_outcome=='succeeded'
    assert [method for method,path in lab.calls].count('POST')==1 and 'DELETE'not in[method for method,path in lab.calls]
    before=list(lab.calls);assert lab.execute().idempotent_replay
    assert lab.calls==before and lab.store.claim_count==1


@pytest.mark.parametrize('fault',['error','html','encoded','oversize','timeout','close-post','source-inflight','expire-inflight',
    'refs','post-drift','readback-unknown'])
def test_uncertain_create_never_replays_or_removes_an_object(tmp_path,monkeypatch,synthetic_key,fault):
    lab=Lab(tmp_path,synthetic_key,monkeypatch);lab.fault=fault
    result=lab.execute()
    assert result.outcome=='reconciliation_required'and lab.post_count==1
    assert lab.request._closed and not any(lab.request._body)
    assert all(resource.closed for resource in lab.resources)and all(not any(raw)for raw in lab.buffers)
    original=lab.custody.inspect_original_response()
    assert original.original_outcome=='reconciliation_required'and original.original_verification=='unknown'
    if fault=='error':assert original.http_status==500 and original.native_error==-3
    if fault=='encoded':assert original.body_state=='encoded'and not original.success_ack_retained
    if fault in{'error','html','encoded','oversize','timeout','source-inflight','expire-inflight'}:
        assert not original.success_ack_retained
        assert not any(path.endswith('?with_meta=true')and '/'+NAME+'?'in path for method,path in lab.calls)
    before=list(lab.calls);assert lab.execute().idempotent_replay
    assert lab.calls==before and not any(method=='DELETE'for method,path in lab.calls)


@pytest.mark.parametrize('fault',['default-off','source-after-tls','state-after-tls'])
def test_closed_or_drifted_binding_denies_before_any_post(tmp_path,monkeypatch,synthetic_key,fault):
    lab=Lab(tmp_path,synthetic_key,monkeypatch);lab.fault=fault
    if fault=='default-off':lab.enabled=False
    result=lab.execute()
    assert result.outcome in{'denied','reconciliation_required'}and lab.post_count==0
    assert all(resource.closed for resource in lab.resources)


def test_interrupt_keeps_original_partial_response_without_backfill(tmp_path,monkeypatch,synthetic_key):
    lab=Lab(tmp_path,synthetic_key,monkeypatch);lab.fault='interrupt'
    with pytest.raises(KeyboardInterrupt):lab.execute()
    observed=lab.custody.inspect_original_response()
    assert observed.body_state=='partial'and not observed.success_ack_retained and observed.original_outcome=='in_progress'
    assert lab.post_count==1 and lab.request._closed
    assert all(resource.closed for resource in lab.resources)and all(not any(raw)for raw in lab.buffers)


def test_direct_dispatch_without_original_kernel_scope_cannot_open_a_writer_connection(tmp_path,monkeypatch,synthetic_key):
    lab=Lab(tmp_path,synthetic_key,monkeypatch);before=list(lab.calls);resources=len(lab.resources)
    with pytest.raises(M4AdapterAmbiguous):lab.transport.dispatch(lab.plan)
    assert lab.calls==before and len(lab.resources)==resources and lab.post_count==0


def test_original_owned_state_survives_expiry_in_an_independent_readonly_process(tmp_path,monkeypatch,synthetic_key):
    lab=Lab(tmp_path,synthetic_key,monkeypatch);lab.fault='post-drift'
    assert lab.execute().outcome=='reconciliation_required'
    observed=lab.custody.inspect_original_owned_state()
    assert observed.response.original_verification=='unknown'
    metadata=dict(plan=asdict(lab.plan),authorization=asdict(lab.auth),source=lab.baseline.source_digest,
        state=lab.baseline.state.state_digest,actor=lab.baseline.actor.actor_digest,role=lab.baseline.actor.role_digest)
    for name,data in [('original-context.json',json.dumps(metadata).encode()),('original-public.pem',public_pem(synthetic_key))]:
        (tmp_path/name).write_bytes(data);(tmp_path/name).chmod(0o600)
    before={p.name:p.read_bytes()for p in(tmp_path/'custody').iterdir()}
    child='''
import json,sys
from pathlib import Path
from v4_planning import M4ExecutionPlan,M4ExecutionAuthorization
from fortipam_mcp.jwt_manual_key_actor_evidence import JwtManualKeyActorEvidence
from fortipam_mcp.jwt_manual_key_contract import JwtManualCreatePlan,JwtManualPublicKey
from fortipam_mcp.jwt_manual_key_request_contract import JwtManualCreateRequest
from fortipam_mcp.jwt_manual_key_response_custody import JwtManualKeyResponseCustody
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore,M4ExecutionStoreTail
from test_jwt_manual_key_preflight import NAME,SERIAL,SCHEMA_DIGEST
from test_jwt_manual_key_contract import defaults
from test_m4_execution_store import _ExternalM4Checkpoint,CHECKPOINT_STORE_REF
root=Path(sys.argv[1]);data=json.loads((root/'original-context.json').read_bytes())
checkpoint=_ExternalM4Checkpoint();checkpoint.tail=M4ExecutionStoreTail(CHECKPOINT_STORE_REF,int(sys.argv[2]),sys.argv[3])
store=PersistentM4ExecutionStateStore(root/'execution.sqlite',root/'execution.key',monotonic_checkpoint=checkpoint,
    checkpoint_store_ref=CHECKPOINT_STORE_REF,read_only=True)
body_plan=JwtManualCreatePlan(NAME,'a'*64,JwtManualPublicKey((root/'original-public.pem').read_bytes()),defaults(),
    schema_digest=SCHEMA_DIGEST,serial_digest=SERIAL)
request=JwtManualCreateRequest(body_plan,defaults(),schema_digest=SCHEMA_DIGEST,serial_digest=SERIAL)
actor=JwtManualKeyActorEvidence(data['actor'],data['role'],SERIAL)
custody=JwtManualKeyResponseCustody(root/'custody',root/'witness.key',request,actor,data['source'],data['state'],
    M4ExecutionPlan(**data['plan']),M4ExecutionAuthorization(**data['authorization']),store,clock=lambda:2000)
request.close();observed=custody.inspect_original_owned_state()
assert observed.response.original_outcome=='reconciliation_required'and observed.response.original_verification=='unknown'
assert store.claim_count==1
print(observed.custody_digest)
'''
    env={**os.environ,'PYTHONPATH':os.pathsep.join((str(Path(__file__).parent),os.environ.get('PYTHONPATH','')))}
    done=subprocess.run([sys.executable,'-c',child,str(tmp_path),str(lab.checkpoint.tail.sequence),lab.checkpoint.tail.chain_hmac],
        env=env,capture_output=True,text=True,timeout=20)
    assert done.returncode==0,done.stderr
    assert done.stdout.strip()==observed.custody_digest
    assert {p.name:p.read_bytes()for p in(tmp_path/'custody').iterdir()}==before
