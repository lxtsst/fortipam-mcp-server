"""Independent original-ACK JWT recovery; no creation replay or body reload."""
from dataclasses import asdict
import io
import json
import ssl

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest

from fortipam_mcp import jwt_manual_key_recovery as r
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_jwt_manual_key_create_http_transport import Lab
from test_jwt_manual_key_preflight import NAME, packet, raw
from test_jwt_manual_key_contract import synthetic_key, public_pem
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF
from test_v4_execution_kernel import _authorization, _Verifier, CONFIRMATION, APPROVAL


@pytest.fixture(autouse=True)
def synthetic_recovery_tls(monkeypatch):
    monkeypatch.setattr(r,'_ssl_context',lambda config:ssl.create_default_context())


class RecoveryLab:
    def __init__(self,root,lab,*,enabled=True,verifier=True):
        self.lab=lab;self.directory=root/'custody/recovery';self.directory.mkdir(mode=0o700)
        for name,data in[('execution.key',b'r'*32),('witness.key',b'z'*32)]:
            (self.directory/name).write_bytes(data);(self.directory/name).chmod(0o600)
        self.checkpoint=_ExternalM4Checkpoint()
        self.store=PersistentM4ExecutionStateStore(self.directory/'execution.sqlite',self.directory/'execution.key',
            monotonic_checkpoint=self.checkpoint,checkpoint_store_ref=CHECKPOINT_STORE_REF)
        self.source=True;self.now=2000;self.mono=0;self.fault='none';self.deletes=0
        self.guard=lambda:self.source
        self.runtime=r.JwtManualKeyRecovery(lab.config,lab.custody,lab.reader,lab.baseline,
            execution_store=self.store,witness_key_file=self.directory/'witness.key',execution_enabled=enabled,
            authorization_verifier=_Verifier()if verifier else None,source_guard=self.guard,
            connection_factory=self.connect,clock=lambda:self.now,http_clock=lambda:self.mono)

    def connect(self,host,port,**kwargs):
        lab=self.lab;owner=self;connection=lab.connect('recovery',host,port,**kwargs)
        class Response:
            closed=False
            reads=0
            def __init__(self,body,status):self.stream=io.BytesIO(body);self.status=status
            def getheader(self,key,default=None):
                return {'content-type':'text/html'if owner.fault=='html'else'application/json',
                    'content-encoding':'gzip'if owner.fault=='encoded'else'identity'}.get(key.lower(),default)
            def readinto(self,destination):
                lab.buffers.append(destination);self.reads+=1
                if self.reads>1:
                    if owner.fault=='timeout':raise TimeoutError('PRIVATE_SYNTHETIC_DETAIL')
                    if owner.fault=='interrupt':raise KeyboardInterrupt
                with memoryview(destination)[:min(73,len(destination))]as view:count=self.stream.readinto(view)
                if not count:
                    if owner.fault=='source-inflight':owner.source=False
                    if owner.fault=='expired-inflight':owner.now=2100
                return count
            def close(self):
                self.closed=True
                if owner.fault=='close':raise OSError('PRIVATE_SYNTHETIC_DETAIL')
        class Proxy:
            response=None
            def connect(self):
                connection.connect()
                if owner.fault=='refs-after-tls':lab.row['q_ref']=1
                if owner.fault=='source-after-tls':owner.source=False
            def request(self,method,path,body=None,headers=None):
                if method!='DELETE':return connection.request(method,path,body=body,headers=headers)
                assert body is None and '?'not in path and path.endswith('/'+NAME)
                owner.deletes+=1;lab.calls.append((method,path));lab.created=False
                payload=packet('jwt-key',None,http_method='DELETE',mkey=NAME)
                status=200
                if owner.fault=='error':payload.update(status='error',http_status=500,error=-3);status=500
                if owner.fault=='wrong-key':payload['mkey']='mcp-v4-jwt-other'
                data=bytes(raw(payload))
                if owner.fault=='html':data=b'<html>PRIVATE_SYNTHETIC_DETAIL</html>';status=502
                if owner.fault=='oversize':data=b'x'*(r._MAX_BYTES+100)
                self.response=Response(data,status)
            def getresponse(self):
                if self.response is not None:lab.resources.append(self.response);return self.response
                return connection.getresponse()
            def close(self):connection.close()
        return Proxy()

    def issue(self):
        preview=self.runtime.preview()
        fields=dict(plan_ref='manual-jwt-removal-plan-01',revision=1,action_id=r.ACTION_ID,action_version='1.0.0',
            adapter_ref=r.ADAPTER_REF,target_ref=r.TARGET_REF,requester_digest=preview.requester_digest,
            summary_digest='1'*64,confirmation_digest=CONFIRMATION,approval_digest=APPROVAL,
            parameters_digest=preview.parameters_digest,expected_current_digest=preview.current_digest,
            expected_state_digest=preview.expected_digest,idempotency_digest='2'*64,expires_at=self.now+30,compensation_ref=None)
        plan=M4ExecutionPlan(**fields,plan_digest=canonical_digest(fields))
        auth=asdict(_authorization(plan));auth.pop('authorization_digest')
        auth.update(issued_at=self.now-1,expires_at=self.now+30)
        return plan,M4ExecutionAuthorization(**auth,authorization_digest=canonical_digest(auth))


@pytest.mark.parametrize('creation_fault',['none','close-post','post-drift'])
def test_independent_removal_preserves_original_outcome_and_uses_no_live_body(tmp_path,monkeypatch,synthetic_key,creation_fault):
    lab=Lab(tmp_path,synthetic_key,monkeypatch);lab.fault=creation_fault;created=lab.execute()
    original=lab.custody.inspect_original_response();original_tail=lab.checkpoint.tail
    if creation_fault=='post-drift':lab.row['last-update-time']='synthetic-never'
    lab.fault='none';lab.enabled=False
    old_files={p.name:p.read_bytes()for p in(tmp_path/'custody').iterdir()if p.is_file()}
    recovery=RecoveryLab(tmp_path,lab)
    def no_body(self):raise AssertionError('Original body must not be reloaded.')
    monkeypatch.setattr(type(lab.request),'borrow_body',no_body)
    plan,auth=recovery.issue();result=recovery.runtime.execute(plan,auth)
    assert result.outcome=='succeeded'and result.verification=='verified'and recovery.deletes==1 and lab.post_count==1
    assert lab.custody.inspect_original_response()==original and lab.checkpoint.tail==original_tail
    assert {p.name:p.read_bytes()for p in(tmp_path/'custody').iterdir()if p.is_file()}==old_files
    observed=recovery.runtime.inspect_result(plan,auth)
    assert observed.delete_ack_observed and observed.absence_observed and observed.recovery_outcome=='succeeded'
    assert observed.original_creation_outcome==created.outcome
    recovery.now=3000
    assert recovery.runtime.inspect_result(plan,auth)==observed
    before=list(lab.calls)
    with pytest.raises(r.JwtManualKeyRecoveryError):recovery.runtime.execute(plan,auth)
    assert lab.calls==before and recovery.store.claim_count==1
    assert all(resource.closed for resource in lab.resources)and all(not any(value)for value in lab.buffers)


@pytest.mark.parametrize('fault',['error','html','encoded','oversize','timeout','wrong-key','close','source-inflight','expired-inflight'])
def test_uncertain_delete_retains_original_response_and_cannot_be_reissued(tmp_path,monkeypatch,synthetic_key,fault):
    lab=Lab(tmp_path,synthetic_key,monkeypatch);lab.execute();original=lab.custody.inspect_original_response()
    recovery=RecoveryLab(tmp_path,lab);plan,auth=recovery.issue();recovery.fault=fault
    result=recovery.runtime.execute(plan,auth)
    assert result.outcome=='reconciliation_required'and recovery.deletes==1 and lab.post_count==1
    observed=recovery.runtime.inspect_result(plan,auth)
    assert observed.recovery_verification=='unknown'and not observed.absence_observed
    if fault=='error':assert observed.http_status==500 and observed.native_error==-3
    if fault=='wrong-key':assert observed.mkey_observed and not observed.mkey_matches
    if fault not in{'close'}:assert not observed.delete_ack_observed
    assert lab.custody.inspect_original_response()==original
    before=list(lab.calls)
    with pytest.raises(r.JwtManualKeyRecoveryError):recovery.runtime.execute(plan,auth)
    assert lab.calls==before and recovery.store.claim_count==1
    assert all(resource.closed for resource in lab.resources)and all(not any(value)for value in lab.buffers)


@pytest.mark.parametrize('fault',['refs-after-tls','source-after-tls','expired-before'])
def test_changed_precondition_or_expired_grant_cannot_send_delete(tmp_path,monkeypatch,synthetic_key,fault):
    lab=Lab(tmp_path,synthetic_key,monkeypatch);lab.execute()
    recovery=RecoveryLab(tmp_path,lab);plan,auth=recovery.issue();recovery.fault=fault
    if fault=='expired-before':
        recovery.now=2100
        with pytest.raises(r.JwtManualKeyRecoveryError):recovery.runtime.execute(plan,auth)
    else:
        result=recovery.runtime.execute(plan,auth);assert result.outcome in{'denied','precondition_failed','reconciliation_required'}
    assert recovery.deletes==0 and not(recovery.directory/'delete.attempt.json').exists()


@pytest.mark.parametrize('fault',['no-original-ack','default-off','deny-all-verifier'])
def test_missing_authority_stays_closed(tmp_path,monkeypatch,synthetic_key,fault):
    lab=Lab(tmp_path,synthetic_key,monkeypatch)
    if fault=='no-original-ack':lab.fault='error'
    lab.execute();before=list(lab.calls)
    if fault=='no-original-ack':
        with pytest.raises(r.JwtManualKeyRecoveryError):RecoveryLab(tmp_path,lab)
        assert lab.calls==before
    else:
        recovery=RecoveryLab(tmp_path,lab,enabled=fault!='default-off',verifier=fault!='deny-all-verifier')
        if fault=='default-off':
            with pytest.raises(r.JwtManualKeyRecoveryError):recovery.runtime.preview()
            assert lab.calls==before
        else:
            plan,auth=recovery.issue()
            with pytest.raises(r.JwtManualKeyRecoveryError):recovery.runtime.execute(plan,auth)
        assert recovery.deletes==0 and recovery.store.claim_count==0


def test_signal_keeps_partial_delete_observation_without_replaying(tmp_path,monkeypatch,synthetic_key):
    lab=Lab(tmp_path,synthetic_key,monkeypatch);lab.execute()
    recovery=RecoveryLab(tmp_path,lab);plan,auth=recovery.issue();recovery.fault='interrupt'
    with pytest.raises(KeyboardInterrupt):recovery.runtime.execute(plan,auth)
    observed=recovery.runtime.inspect_result(plan,auth)
    assert observed.recovery_outcome=='in_progress'and not observed.delete_ack_observed and not observed.absence_observed
    assert recovery.deletes==1 and all(resource.closed for resource in lab.resources)


def test_missing_original_state_requires_the_original_public_key_commitment(tmp_path,monkeypatch,synthetic_key):
    lab=Lab(tmp_path,synthetic_key,monkeypatch);lab.fault='close-post';lab.execute();lab.fault='none'
    assert not(tmp_path/'custody/original-state.json').exists()and lab.request._closed
    other=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    lab.row['key'][0]['key-name']=public_pem(other).decode()
    recovery=RecoveryLab(tmp_path,lab)
    with pytest.raises(r.JwtManualKeyRecoveryError):recovery.runtime.preview()
    assert recovery.deletes==0 and not(tmp_path/'custody/original-state.json').exists()


def test_reopened_observer_retains_unknown_and_cannot_refresh_a_consumed_remove(tmp_path,monkeypatch,synthetic_key):
    lab=Lab(tmp_path,synthetic_key,monkeypatch);lab.execute()
    recovery=RecoveryLab(tmp_path,lab);plan,auth=recovery.issue();recovery.fault='error'
    assert recovery.runtime.execute(plan,auth).outcome=='reconciliation_required'
    observed=recovery.runtime.inspect_result(plan,auth)
    before=list(lab.calls);tail=recovery.checkpoint.tail
    reopened=PersistentM4ExecutionStateStore(recovery.directory/'execution.sqlite',recovery.directory/'execution.key',
        monotonic_checkpoint=recovery.checkpoint,checkpoint_store_ref=CHECKPOINT_STORE_REF,read_only=True)
    observer=r.JwtManualKeyRecovery(lab.config,lab.custody,lab.reader,lab.baseline,execution_store=reopened,
        witness_key_file=recovery.directory/'witness.key',clock=lambda:3000)
    assert observer.inspect_result(plan,auth)==observed
    assert recovery.checkpoint.tail==tail and lab.calls==before
    with pytest.raises(r.JwtManualKeyRecoveryError):observer.preview()
    assert lab.calls==before


def test_fresh_enabled_instance_cannot_issue_another_remove_after_an_unknown_attempt(tmp_path,monkeypatch,synthetic_key):
    lab=Lab(tmp_path,synthetic_key,monkeypatch);lab.execute()
    recovery=RecoveryLab(tmp_path,lab);plan,auth=recovery.issue();recovery.fault='error'
    recovery.runtime.execute(plan,auth);before=list(lab.calls)
    clone=r.JwtManualKeyRecovery(lab.config,lab.custody,lab.reader,lab.baseline,execution_store=recovery.store,
        witness_key_file=recovery.directory/'witness.key',execution_enabled=True,source_guard=lambda:True,
        authorization_verifier=_Verifier(),connection_factory=recovery.connect,clock=lambda:2000,http_clock=lambda:0)
    with pytest.raises(r.JwtManualKeyRecoveryError):clone.preview()
    assert lab.calls==before and recovery.deletes==1 and recovery.store.claim_count==1
