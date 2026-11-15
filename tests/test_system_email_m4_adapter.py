"""Local-only SMTP configuration state machine through the real M4 kernel."""
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context

import pytest

from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore,PersistentM4ExecutionStoreError
from test_m4_execution_store import _ExternalM4Checkpoint
from fortipam_mcp.system_email_configuration_transition import prepare_system_email_transition
from fortipam_mcp.system_email_m4_adapter import (
    CONTRACT,SystemEmailBackendReceipt,SystemEmailM4Adapter,system_email_execution_digests,
)
from test_system_email_native_source import Peer
from v4_planning import (
    M4AdapterDenied,M4AuthorizationDenied,M4ExecutionAuthorization,M4ExecutionKernel,
    M4ExecutionPlan,canonical_digest,
)

REQUESTER='1'*64
BINDING='2'*64


class Clock:
    value=1000
    def __call__(self):return self.value


class Backend:
    def __init__(self,fault='none',clock=None):
        self.peer=Peer();self.fault=fault;self.reads=0;self.submissions=[];self.clock=clock
        self.send_guards=[]

    def inspect(self):
        self.reads+=1
        if self.fault=='drift'and self.reads==1:self.peer.body['results']['port']=587
        if self.fault=='late-drift'and self.reads==2:self.peer.body['results']['port']=587
        if self.fault=='post-read'and self.submissions:raise TimeoutError('SYNTHETIC_PRIVATE_ERROR')
        return self.peer.source().read_empty_auth_payload()

    def submit(self,draft,*,before_send,timeout_seconds):
        assert type(timeout_seconds)is int and timeout_seconds>0
        self.send_guards.append(before_send)
        if self.fault=='expired-before-send':self.clock.value=2000
        if self.fault in('foreign-guard','copied-guard'):
            with ThreadPoolExecutor(max_workers=1)as pool:
                call=before_send if self.fault=='foreign-guard'else lambda:copy.run(before_send)
                copy=copy_context()
                pool.submit(call).result(timeout=1)
        if self.fault!='skip-guard':assert before_send()>0
        if self.fault=='double-guard':before_send()
        self.submissions.append(draft.request_digest)
        self.peer.body['results'].update(json.loads(draft._encode()))
        if self.fault=='timeout':raise TimeoutError('SYNTHETIC_PRIVATE_ERROR')
        if self.fault=='interrupt':raise KeyboardInterrupt
        if self.fault=='partial':self.peer.body['results']['interface']='synthetic-drift'
        if self.fault=='schema':self.peer.schema['results']['children']['port']['max-value']=65000
        if self.fault=='deadline':self.clock.value=2000
        serial=hashlib.sha256(b'SYNTHETIC01').hexdigest()
        if self.fault=='receipt-device':serial='f'*64
        request='f'*64 if self.fault=='receipt-request'else draft.request_digest
        if self.fault=='receipt-missing':return None
        return SystemEmailBackendReceipt(serial,request)


def store_at(tmp_path,*,checkpointed=True,key_material=b'synthetic-system-email-state-key-01',
        store_ref='system-email-local-test-ledger'):
    root=tmp_path/'email';root.mkdir(mode=0o700)
    key=root/'m4.key';key.write_bytes(key_material);key.chmod(0o600)
    return PersistentM4ExecutionStateStore(root/'m4.db',key,
        monotonic_checkpoint=_ExternalM4Checkpoint(store_ref)if checkpointed else None,
        checkpoint_store_ref=store_ref if checkpointed else None)


def reopen(store):
    return PersistentM4ExecutionStateStore(store._path,store._key_path,
        monotonic_checkpoint=store._monotonic_checkpoint,checkpoint_store_ref=store._checkpoint_store_ref)


def transition(backend):
    original=backend.peer.source().read_empty_auth_payload()
    values={k:v for k,v in backend.peer.body['results'].items()if k not in('username','password')}
    values['server']='capture.example.test'
    return prepare_system_email_transition(original,values)


def grant(change,phase='update',fault=None):
    current,expected,parameters=system_email_execution_digests(change,BINDING)
    fields=dict(plan_ref='system-email-'+phase+'-'+parameters,revision=1,
        action_id='system-email-'+phase,action_version='1.0.0',adapter_ref=CONTRACT,
        target_ref='system-email-singleton-'+change.original.source_serial_digest,
        requester_digest=REQUESTER,summary_digest='3'*64,confirmation_digest='4'*64,
        approval_digest='5'*64,parameters_digest=parameters,
        expected_current_digest=current if phase=='update'else expected,
        expected_state_digest=expected if phase=='update'else current,
        idempotency_digest=canonical_digest({'binding':parameters,'phase':phase}),
        expires_at=2000,compensation_ref=None)
    if fault:fields.update(fault)
    plan=M4ExecutionPlan(**fields,plan_digest=canonical_digest(fields))
    fields=dict(authorization_ref='system-email-auth-'+phase,plan_ref=plan.plan_ref,
        plan_digest=plan.plan_digest,requester_digest=plan.requester_digest,
        confirmation_ref='system-email-intent-'+phase,confirmation_digest=plan.confirmation_digest,
        approval_ref='system-email-approval-'+phase,approval_digest=plan.approval_digest,
        approver_digest='6'*64,issued_at=900,expires_at=2000,one_time=True,execution_authorized=True)
    authorization=M4ExecutionAuthorization(**fields,authorization_digest=canonical_digest(fields))
    return plan,authorization


class Verifier:
    def __init__(self,plan,authorization):self.pair=(plan,authorization)
    def verify(self,plan,authorization,*,now_epoch):
        if plan is not self.pair[0]or authorization is not self.pair[1]:raise M4AuthorizationDenied('denied')


def candidate(tmp_path,fault='none',enabled=True):
    clock=Clock();backend=Backend(fault,clock);change=transition(backend)
    store=store_at(tmp_path);plan,authorization=grant(change);verifier=Verifier(plan,authorization)
    adapter=SystemEmailM4Adapter(change,backend,plan,authorization,store,binding_digest=BINDING,
        allowed_requester_digest=REQUESTER,authorization_verifier=verifier,
        execution_enabled=enabled,clock=clock)
    kernel=M4ExecutionKernel(adapter,verifier,store,clock=clock)
    return backend,change,store,plan,authorization,verifier,adapter,kernel,clock


def test_real_kernel_claims_update_and_separately_authorized_restore_once(tmp_path):
    backend,change,store,plan,authorization,_,adapter,kernel,clock=candidate(tmp_path)
    result=kernel.execute(plan,authorization)
    assert result.outcome=='succeeded'and result.verification=='verified'
    assert kernel.execute(plan,authorization).idempotent_replay
    assert len(backend.submissions)==1
    restore_plan,restore_authorization=grant(change,'restore')
    verifier=Verifier(restore_plan,restore_authorization)
    restore=adapter.bind_restore(restore_plan,restore_authorization,
        authorization_verifier=verifier,execution_enabled=True)
    recovery=M4ExecutionKernel(restore,verifier,store,clock=clock)
    result=recovery.execute(restore_plan,restore_authorization)
    assert result.outcome=='succeeded'and result.verification=='verified'
    assert recovery.execute(restore_plan,restore_authorization).idempotent_replay
    assert len(backend.submissions)==2 and store.claim_count==2
    assert backend.peer.body['results']['server']=='smtp.example.test'
    assert len(kernel.audit_events)==2


@pytest.mark.parametrize('fault',['drift','late-drift'])
def test_drift_prevents_submission_and_consumed_attempt_does_not_restart(tmp_path,fault):
    backend,_,_,plan,authorization,_,_,kernel,_=candidate(tmp_path,fault)
    assert kernel.execute(plan,authorization).outcome!='succeeded'
    assert kernel.execute(plan,authorization).idempotent_replay
    assert backend.submissions==[]


@pytest.mark.parametrize('fault',['timeout','post-read','partial','schema','receipt-device',
    'receipt-request','receipt-missing','deadline'])
def test_unknown_or_failed_postconditions_never_replay_or_qualify_restore(tmp_path,fault):
    backend,change,_,plan,authorization,_,adapter,kernel,_=candidate(tmp_path,fault)
    result=kernel.execute(plan,authorization)
    assert result.outcome!='succeeded'and len(backend.submissions)==1
    assert 'SYNTHETIC_PRIVATE_ERROR'not in json.dumps(result.as_dict())
    if fault!='deadline':assert kernel.execute(plan,authorization).idempotent_replay
    restore_plan,restore_authorization=grant(change,'restore')
    with pytest.raises(M4AdapterDenied):adapter.bind_restore(restore_plan,restore_authorization,execution_enabled=True)
    assert len(backend.submissions)==1


def test_disabled_gate_denies_before_backend_read_or_submission(tmp_path):
    backend,_,_,plan,authorization,_,adapter,_,_=candidate(tmp_path,enabled=False)
    with pytest.raises(M4AdapterDenied):adapter.read_current(plan)
    assert backend.reads==0 and backend.submissions==[]


def test_direct_dispatch_cannot_bypass_kernel_dispatch_ownership(tmp_path):
    backend,_,_,plan,_,_,adapter,_,_=candidate(tmp_path)
    with pytest.raises(M4AuthorizationDenied):adapter.dispatch(plan)
    assert backend.reads==0 and backend.submissions==[]


def test_missing_adapter_verifier_denies_even_with_an_outer_kernel_grant(tmp_path):
    backend,change,store,plan,authorization,verifier,_,_,clock=candidate(tmp_path)
    adapter=SystemEmailM4Adapter(change,backend,plan,authorization,store,binding_digest=BINDING,
        allowed_requester_digest=REQUESTER,execution_enabled=True,clock=clock)
    assert M4ExecutionKernel(adapter,verifier,store,clock=clock).execute(plan,authorization).outcome!='succeeded'
    assert backend.reads==0 and backend.submissions==[]


@pytest.mark.parametrize('fault',[{'parameters_digest':'f'*64},{'expected_current_digest':'f'*64},
    {'expected_state_digest':'f'*64},{'idempotency_digest':'f'*64},{'target_ref':'foreign-target-ref'},
    {'adapter_ref':'foreign-adapter-ref'},{'requester_digest':'f'*64}])
def test_plan_must_match_fixed_source_binding_and_actor(tmp_path,fault):
    backend,change,store,_,_,_,_,_,clock=candidate(tmp_path)
    plan,authorization=grant(change,fault=fault)
    with pytest.raises(M4AdapterDenied):
        SystemEmailM4Adapter(change,backend,plan,authorization,store,binding_digest=BINDING,
            allowed_requester_digest=REQUESTER,execution_enabled=True,clock=clock)
    assert backend.reads==0 and backend.submissions==[]


def test_restart_keeps_in_progress_claim_uncertain_without_another_submission(tmp_path):
    backend,change,store,plan,authorization,verifier,_,kernel,clock=candidate(tmp_path,'interrupt')
    with pytest.raises(KeyboardInterrupt):kernel.execute(plan,authorization)
    reopened=reopen(store)
    adapter=SystemEmailM4Adapter(change,backend,plan,authorization,reopened,binding_digest=BINDING,
        allowed_requester_digest=REQUESTER,authorization_verifier=verifier,execution_enabled=True,clock=clock)
    result=M4ExecutionKernel(adapter,verifier,reopened,clock=clock).execute(plan,authorization)
    assert result.outcome=='reconciliation_required'and len(backend.submissions)==1


def test_cached_success_does_not_reconstruct_receipt_or_restore_rights(tmp_path):
    backend,change,store,plan,authorization,verifier,_,kernel,clock=candidate(tmp_path)
    assert kernel.execute(plan,authorization).outcome=='succeeded'
    reopened=reopen(store)
    adapter=SystemEmailM4Adapter(change,backend,plan,authorization,reopened,binding_digest=BINDING,
        allowed_requester_digest=REQUESTER,authorization_verifier=verifier,execution_enabled=True,clock=clock)
    assert M4ExecutionKernel(adapter,verifier,reopened,clock=clock).execute(plan,authorization).idempotent_replay
    restore_plan,restore_authorization=grant(change,'restore')
    with pytest.raises(M4AdapterDenied):adapter.bind_restore(restore_plan,restore_authorization,execution_enabled=True)
    assert len(backend.submissions)==1


def test_restore_rechecks_drift_and_uses_its_own_closed_gate(tmp_path):
    backend,change,store,plan,authorization,_,adapter,kernel,clock=candidate(tmp_path)
    assert kernel.execute(plan,authorization).outcome=='succeeded'
    restore_plan,restore_authorization=grant(change,'restore');verifier=Verifier(restore_plan,restore_authorization)
    restore=adapter.bind_restore(restore_plan,restore_authorization,authorization_verifier=verifier)
    with pytest.raises(M4AdapterDenied):restore.read_current(restore_plan)
    restore=adapter.bind_restore(restore_plan,restore_authorization,
        authorization_verifier=verifier,execution_enabled=True)
    backend.peer.body['results']['port']=587
    result=M4ExecutionKernel(restore,verifier,store,clock=clock).execute(restore_plan,restore_authorization)
    assert result.outcome=='precondition_failed'and len(backend.submissions)==1


@pytest.mark.parametrize('fault',['expired-before-send','double-guard'])
def test_send_guard_rejects_late_or_repeated_emission_before_submission(tmp_path,fault):
    backend,_,_,plan,authorization,_,_,kernel,_=candidate(tmp_path,fault)
    assert kernel.execute(plan,authorization).outcome!='succeeded'
    assert backend.submissions==[]


def test_backend_cannot_report_success_without_calling_send_guard(tmp_path):
    backend,change,_,plan,authorization,_,adapter,kernel,_=candidate(tmp_path,'skip-guard')
    assert kernel.execute(plan,authorization).outcome=='reconciliation_required'
    restore_plan,restore_authorization=grant(change,'restore')
    with pytest.raises(M4AdapterDenied):adapter.bind_restore(restore_plan,restore_authorization,execution_enabled=True)
    assert len(backend.submissions)==1


def test_saved_send_guard_cannot_be_reused_after_original_dispatch(tmp_path):
    backend,_,_,plan,authorization,_,_,kernel,_=candidate(tmp_path)
    assert kernel.execute(plan,authorization).outcome=='succeeded'
    with pytest.raises(M4AuthorizationDenied):backend.send_guards[0]()
    assert len(backend.submissions)==1


def test_execution_requires_an_external_checkpoint_binding(tmp_path):
    backend=Backend();change=transition(backend);store=store_at(tmp_path,checkpointed=False)
    plan,authorization=grant(change)
    with pytest.raises(M4AdapterDenied):
        SystemEmailM4Adapter(change,backend,plan,authorization,store,binding_digest=BINDING,
            allowed_requester_digest=REQUESTER,execution_enabled=True)
    assert backend.reads==0 and backend.submissions==[]


def test_valid_old_database_and_local_anchor_cannot_clear_consumption(tmp_path):
    backend,_,store,plan,authorization,_,_,kernel,_=candidate(tmp_path)
    saved={p:p.read_bytes()for p in store._path.parent.iterdir()if p.is_file()}
    assert kernel.execute(plan,authorization).outcome=='succeeded'
    for path,raw in saved.items():path.write_bytes(raw)
    with pytest.raises(PersistentM4ExecutionStoreError):kernel.execute(plan,authorization)
    assert len(backend.submissions)==1


@pytest.mark.parametrize('fault',['foreign-guard','copied-guard'])
def test_foreign_or_copied_context_cannot_admit_send_or_deadlock_dispatch(tmp_path,fault):
    backend,_,_,plan,authorization,_,_,kernel,_=candidate(tmp_path,fault)
    assert kernel.execute(plan,authorization).outcome=='reconciliation_required'
    assert backend.submissions==[]and backend.reads==1
