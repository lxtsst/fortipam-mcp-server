"""Synthetic alert lifecycle through the real kernel and checkpointed store.

The injected evidence and merge behavior are explicit test doubles. They do not
qualify a native graph, ACK, certificate merge, mail isolation or real recipient.
"""
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from fortipam_mcp.email_alert_compound_contract import STEPS
from fortipam_mcp.email_alert_compound_source import DETAILS
from fortipam_mcp.email_alert_m4 import (CONTRACT,EmailAlertEvidence,EmailAlertExecutionScope,
    EmailAlertM4Session,EmailAlertReceipt)
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStoreError
from test_email_alert_compound_source import candidate as source_candidate,load_state,CURRENT_PATH
from test_email_alert_general_contract import SERIAL,SENDER,RECIPIENT,PRIVATE
from test_system_email_m4_adapter import Verifier,store_at,reopen
from v4_planning import (M4AdapterDenied,M4AuthorizationDenied,M4ExecutionAuthorization,
    M4ExecutionKernel,M4ExecutionPlan,canonical_digest)


class Evidence:
    def __init__(self,clock): self.clock=clock; self.fault=None; self.calls=[]
    def observe(self,configuration_digest,*,step,restore,original_receipt_digest):
        self.calls.append((step,restore,original_receipt_digest))
        values = dict(source_digest='c'*64,configuration_digest=configuration_digest,effects_digest='d'*64,
            original_receipt_digest=original_receipt_digest,actor_permission_verified=True,complete_native_schema_verified=True,
            critical_graph_qualified=True,object_history_clear_verified=True,native_put_semantics_verified=True,certificate_merge_verified=True,
            reverse_service_preservation_verified=True,certificate_device_model_verified=True,isolated_mail_service_verified=True,
            recipient_scope_verified=True,external_delivery_impact_accepted=True,sender_quiescent=True,independent_recovery_ready=True,
            original_continuity_verified=original_receipt_digest is not None,complete=True,pending_messages=0,
            observed_at=self.clock.value,expires_at=self.clock.value+10)
        if self.fault in values:
            value=values[self.fault]; values[self.fault] = not value if type(value) is bool else ('f'*64 if type(value) is str else 1)
        elif self.fault == 'stale': values.update(observed_at=self.clock.value-10,expires_at=self.clock.value)
        elif self.fault == 'late': self.clock.value+=10
        return EmailAlertEvidence(**values)


class Backend:
    def __init__(self,peer):
        self.peer=peer; self.fault=None; self.sends=[]; self.buffers=[]; self.guards=[]
        self.before=lambda:None; self.after=lambda:None
    def submit(self,body,*,step,restore,parameters_digest,before_send,timeout_seconds):
        assert isinstance(body,memoryview) and body.readonly and type(timeout_seconds) is int and timeout_seconds>0
        self.buffers.append(body.obj); self.guards.append(before_send); wire=json.loads(body.tobytes()); self.before()
        if self.fault == 'expiry': self.peer.clock.value+=60
        if self.fault in ('worker','copied-context'):
            copied=copy_context()
            with ThreadPoolExecutor(max_workers=1) as pool:
                call=before_send if self.fault == 'worker' else lambda:copied.run(before_send)
                pool.submit(call).result(timeout=1)
        assert before_send()>0
        if self.fault == 'double-guard': before_send()
        self.sends.append((step,restore))
        if step == 'general': self.peer.payloads[CURRENT_PATH]['results'].update(wire)
        elif step == 'certificate':
            row=self.peer.payloads[DETAILS[-1][2]]['results']; row['cert-setting']=wire['cert-setting']
            assert wire['reverse-service-setting'] == {}
            # Synthetic positive merge: preserve the nonempty sibling. The
            # negative variant proves a destructive empty merge stays UNKNOWN.
            if self.fault == 'empty-sibling-replaces': row['reverse-service-setting']={}
        else:
            slot,kind=step.split('_'); path=next(path for k,s,path in DETAILS if (k,s)==(kind,slot))
            assert wire.pop('$originalName') == wire['name']; self.peer.payloads[path]['results'].update(wire)
        if self.fault == 'lost-ack': raise TimeoutError('SYNTHETIC_PRIVATE_FAILURE')
        if self.fault == 'interrupt': raise KeyboardInterrupt
        if self.fault == 'late-ack': self.peer.clock.value+=60
        if self.fault == 'partial': self.peer.payloads[CURRENT_PATH]['results']['unrelated-integer']=4
        self.after()
        return EmailAlertReceipt('f'*64 if self.fault == 'foreign-receipt' else 'b'*64,
            'f'*64 if self.fault == 'receipt-parameters' else parameters_digest,
            'certificate' if self.fault == 'receipt-step' else step,
            not restore if self.fault == 'receipt-phase' else restore,
            canonical_digest(dict(ack='synthetic',step=step,restore=restore)))


def candidate(tmp_path,*,state=None,guarded=True,checkpointed=True):
    peer,source,_=source_candidate()
    if state is not None: load_state(peer,state)
    initial=source.prepare_plan(); backend=Backend(peer); evidence=Evidence(peer.clock)
    scope=EmailAlertExecutionScope('1'*64,'2'*64,'3'*64,'4'*64,'b'*64,'c'*64,'d'*64)
    store=store_at(tmp_path,checkpointed=checkpointed)
    session=EmailAlertM4Session(source,initial,scope,backend,evidence,store,
        source_guard=(lambda:True) if guarded else None,clock=peer.clock)
    return session,peer,backend,evidence,store


def bind(session,name='general',*,restore=False,enabled=True,verified=True,plan_fault=None):
    step=session.prepare_step(name,restore=restore); now=session._clock()
    fields=dict(plan_ref=step.action_id+'-'+step.parameters_digest,revision=1,
        action_id=step.action_id,action_version='1.0.0',adapter_ref=CONTRACT,
        target_ref='email-alert-'+canonical_digest(dict(initial=session._initial.digest,step=name)),
        requester_digest=session._scope.requester_digest,summary_digest='5'*64,confirmation_digest='6'*64,
        approval_digest='7'*64,parameters_digest=step.parameters_digest,
        expected_current_digest=step.expected_current_digest,expected_state_digest=step.expected_state_digest,
        idempotency_digest=canonical_digest(dict(action=step.action_id,parameters=step.parameters_digest)),
        expires_at=now+60,compensation_ref=None)
    if plan_fault: fields.update(plan_fault)
    plan=M4ExecutionPlan(**fields,plan_digest=canonical_digest(fields))
    fields=dict(authorization_ref=step.action_id+'-authorization',plan_ref=plan.plan_ref,plan_digest=plan.plan_digest,
        requester_digest=plan.requester_digest,confirmation_ref=step.action_id+'-intent',confirmation_digest=plan.confirmation_digest,
        approval_ref=step.action_id+'-approval',approval_digest=plan.approval_digest,approver_digest='8'*64,
        issued_at=now,expires_at=now+60,one_time=True,execution_authorized=True)
    authorization=M4ExecutionAuthorization(**fields,authorization_digest=canonical_digest(fields)); verifier=Verifier(plan,authorization)
    adapter=session.bind_step(step,plan,authorization,authorization_verifier=verifier if verified else None,execution_enabled=enabled)
    return adapter,M4ExecutionKernel(adapter,verifier,session._store,clock=session._clock),plan,authorization


def execute(bound): return bound[1].execute(bound[2],bound[3])


def test_sixteen_independent_claims_preserve_originals_and_restore_complete_graph(tmp_path):
    session,peer,backend,evidence,store=candidate(tmp_path)
    for name,restore in [*((step,False) for step in STEPS),*((step,True) for step in reversed(STEPS))]:
        bound=bind(session,name,restore=restore); result=execute(bound)
        assert result.outcome=='succeeded' and result.verification=='verified'
        before=list(backend.sends); assert execute(bound).idempotent_replay and backend.sends==before
        assert bound[0]._claim().result.outcome=='succeeded'
        if restore: assert (name,True,session._adapters[(name,False)]._receipt.digest) in evidence.calls
    assert store.claim_count==16 and len(store.audit_events)==16
    assert session._source.read().state.digest==session._initial.baseline.digest
    assert all(not any(raw) for raw in peer.buffers+backend.buffers)
    assert all(resource.closed for resource in peer.resources)
    ledger=store._path.read_bytes()
    assert all(value.encode() not in ledger for value in (SERIAL,SENDER,RECIPIENT,PRIVATE,'old.cert','Original glass'))
    with pytest.raises(M4AdapterDenied): session.prepare_step('general')


def test_partial_prefix_has_independent_reverse_after_prior_grant_expires(tmp_path):
    session,peer,backend,_,store=candidate(tmp_path)
    assert execute(bind(session)).outcome=='succeeded'; peer.clock.value+=100
    assert execute(bind(session,restore=True)).outcome=='succeeded'
    assert backend.sends==[('general',False),('general',True)] and store.claim_count==2
    assert session._source.read().state.digest==session._initial.baseline.digest
    with pytest.raises(M4AdapterDenied): session.prepare_step('glass_action')


def test_noop_steps_are_neither_sent_nor_given_inverse_custody(tmp_path):
    prototype=source_candidate()[1]; proposed=prototype.prepare_plan().expected(1)
    session,_,backend,_,store=candidate(tmp_path,state=proposed)
    assert 'general' not in session._initial.changed_steps
    for restore in (False,True):
        with pytest.raises(M4AdapterDenied): session.prepare_step('general',restore=restore)
    assert execute(bind(session,'glass_action')).outcome=='succeeded'
    assert execute(bind(session,'glass_action',restore=True)).outcome=='succeeded'
    assert backend.sends==[('glass_action',False),('glass_action',True)] and store.claim_count==2


def test_unknown_second_step_freezes_compound_without_adopting_readback_or_replaying(tmp_path):
    session,peer,backend,_,store=candidate(tmp_path)
    assert execute(bind(session)).outcome=='succeeded'; second=bind(session,'glass_action'); backend.fault='lost-ack'
    unknown=execute(second); assert unknown.outcome=='reconciliation_required'; backend.fault=None
    assert session._source.read().state.digest==session._initial.expected(2).digest
    for name,restore in (('glass_action',False),('glass_action',True),('general',True),('license_action',False)):
        with pytest.raises(M4AdapterDenied): session.prepare_step(name,restore=restore)
    assert execute(second).idempotent_replay and second[0]._claim().result==unknown and store.claim_count==2
    assert len(backend.sends)==2


@pytest.mark.parametrize('restore',[False,True])
@pytest.mark.parametrize('fault',['lost-ack','foreign-receipt','receipt-parameters','receipt-step','receipt-phase','partial','late-ack'])
def test_uncertain_write_or_inverse_never_acquires_recovery_or_repeat_rights(tmp_path,restore,fault):
    session,_,backend,_,store=candidate(tmp_path)
    if restore: assert execute(bind(session)).outcome=='succeeded'
    bound=bind(session,restore=restore); backend.fault=fault; result=execute(bound)
    assert result.outcome!='succeeded' and len(backend.sends)==1+restore
    assert 'SYNTHETIC_PRIVATE_FAILURE' not in json.dumps(result.as_dict()); backend.fault=None
    with pytest.raises(M4AdapterDenied): session.prepare_step('general',restore=True)
    assert all(not any(raw) for raw in backend.buffers)


def test_interrupted_claim_remains_unsealed(tmp_path):
    session,_,backend,_,store=candidate(tmp_path); bound=bind(session); backend.fault='interrupt'
    with pytest.raises(KeyboardInterrupt): execute(bound)
    assert bound[0]._claim().result is None and execute(bound).outcome=='reconciliation_required'
    with pytest.raises(M4AdapterDenied): session.prepare_step('general',restore=True)
    assert len(backend.sends)==1 and all(not any(raw) for raw in backend.buffers)


@pytest.mark.parametrize('fault',['actor_permission_verified','complete_native_schema_verified','critical_graph_qualified',
    'object_history_clear_verified',
    'native_put_semantics_verified','isolated_mail_service_verified','recipient_scope_verified','external_delivery_impact_accepted',
    'sender_quiescent','independent_recovery_ready','complete','pending_messages','source_digest','configuration_digest',
    'effects_digest','original_continuity_verified','stale','late'])
def test_config_and_empty_receiver_cannot_substitute_for_independent_fresh_evidence(tmp_path,fault):
    session,_,backend,evidence,store=candidate(tmp_path); bound=bind(session); evidence.fault=fault
    assert execute(bound).outcome!='succeeded' and backend.sends==[] and store.claim_count==1
    assert execute(bound).idempotent_replay


@pytest.mark.parametrize('fault',['certificate_merge_verified','reverse_service_preservation_verified','certificate_device_model_verified','empty-sibling-replaces'])
def test_certificate_requires_its_native_semantics_and_preserves_reverse_service(tmp_path,fault):
    session,_,backend,evidence,_=candidate(tmp_path)
    for name in STEPS[:-1]: assert execute(bind(session,name)).outcome=='succeeded'
    bound=bind(session,'certificate')
    if fault=='empty-sibling-replaces': backend.fault=fault
    else: evidence.fault=fault
    assert execute(bound).outcome!='succeeded'
    assert len(backend.sends)==(8 if fault=='empty-sibling-replaces' else 7)
    with pytest.raises(M4AdapterDenied): session.prepare_step('certificate',restore=True)


@pytest.mark.parametrize('enabled,verified',[(False,True),(True,False)])
def test_execution_gate_and_missing_adapter_verifier_deny(tmp_path,enabled,verified):
    session,_,backend,_,_=candidate(tmp_path); bound=bind(session,enabled=enabled,verified=verified)
    assert execute(bound).outcome!='succeeded' and backend.sends==[]


@pytest.mark.parametrize('fault',['worker','copied-context','double-guard','expiry'])
def test_actual_send_guard_requires_original_thread_once_and_current_authorization(tmp_path,fault):
    session,_,backend,_,_=candidate(tmp_path); bound=bind(session); backend.fault=fault
    assert execute(bound).outcome!='succeeded' and backend.sends==[] and all(not any(raw) for raw in backend.buffers)


def test_direct_dispatch_saved_guard_and_new_source_store_do_not_acquire_original_custody(tmp_path):
    session,_,backend,evidence,store=candidate(tmp_path); bound=bind(session)
    with pytest.raises(M4AuthorizationDenied): bound[0].dispatch(bound[2])
    assert store.claim_count==0 and backend.sends==[]
    assert execute(bound).outcome=='succeeded'
    with pytest.raises(M4AuthorizationDenied): backend.guards[0]()
    with pytest.raises(M4AdapterDenied):
        EmailAlertM4Session(session._source,session._initial,session._scope,backend,evidence,store,
            source_guard=lambda:True,clock=session._clock)
    with pytest.raises(M4AdapterDenied):
        EmailAlertM4Session(session._source,session._initial,session._scope,backend,evidence,reopen(store),
            source_guard=lambda:True,clock=session._clock)


@pytest.mark.parametrize('fault',['drift','guard','scope','clock','key','checkpoint','source-plan'])
def test_last_moment_drift_or_authority_change_prevents_send(tmp_path,fault):
    session,peer,backend,_,store=candidate(tmp_path); bound=bind(session)
    def change():
        if fault=='drift': peer.payloads[DETAILS[-1][2]]['results']['unrelated-global']='drift'
        elif fault=='guard': session._guard=lambda:False
        elif fault=='scope': session._scope=replace(session._scope,effects_digest='f'*64)
        elif fault=='clock': peer.clock.value-=1
        elif fault=='key': store._key_path.write_bytes(b'x'*32)
        elif fault=='checkpoint': store._monotonic_checkpoint=deepcopy(session._checkpoint)
        else: session._source._plan=replace(session._initial)
    backend.before=change
    assert execute(bound).outcome!='succeeded' and backend.sends==[]


@pytest.mark.parametrize('fault',[{'parameters_digest':'f'*64},{'expected_current_digest':'f'*64},
    {'requester_digest':'f'*64},{'target_ref':'wrong-target'},{'action_id':'email-alert-certificate-update'},
    {'compensation_ref':'implicit-rollback'},{'expires_at':1061}])
def test_exact_action_digest_identity_and_lifetime_bindings_refuse_mutated_plans(tmp_path,fault):
    session,_,backend,_,_=candidate(tmp_path)
    with pytest.raises(M4AdapterDenied): bind(session,plan_fault=fault)
    assert backend.sends==[]


def test_only_expired_unused_unclaimed_grant_can_be_refreshed(tmp_path):
    session,peer,backend,_,store=candidate(tmp_path); bound=bind(session)
    with pytest.raises(M4AdapterDenied): session._release_expired_unused(bound[0])
    peer.clock.value+=61; session._release_expired_unused(bound[0])
    assert execute(bind(session)).outcome=='succeeded' and store.claim_count==1
    peer.clock.value+=61
    with pytest.raises(M4AdapterDenied): session._release_expired_unused(bound[0])
    assert len(backend.sends)==1


def test_failed_sealing_after_complete_readback_never_conveys_original_recovery(tmp_path,monkeypatch):
    session,_,backend,_,store=candidate(tmp_path); bound=bind(session)
    def failed_finalize(**kwargs): raise PersistentM4ExecutionStoreError('synthetic sealing failure')
    monkeypatch.setattr(store,'finalize',failed_finalize)
    with pytest.raises(PersistentM4ExecutionStoreError): execute(bound)
    assert bound[0]._receipt is not None and bound[0]._post_verified and bound[0]._claim().result is None
    assert execute(bound).outcome=='reconciliation_required' and len(backend.sends)==1
    with pytest.raises(M4AdapterDenied): session.prepare_step('general',restore=True)


@pytest.mark.parametrize('fault',['guard','checkpoint','clone','stale'])
def test_session_requires_fresh_original_plan_own_guard_and_checkpoint(tmp_path,fault):
    peer,source,_=source_candidate(); initial=source.prepare_plan(); backend=Backend(peer); evidence=Evidence(peer.clock)
    scope=EmailAlertExecutionScope('1'*64,'2'*64,'3'*64,'4'*64,'b'*64,'c'*64,'d'*64)
    store=store_at(tmp_path,checkpointed=fault!='checkpoint')
    if fault=='clone': initial=replace(initial)
    elif fault=='stale': peer.clock.value+=10
    with pytest.raises(M4AdapterDenied):
        EmailAlertM4Session(source,initial,scope,backend,evidence,store,
            source_guard=None if fault=='guard' else lambda:True,clock=peer.clock)
    assert source._m4_session is None and store.claim_count==0 and backend.sends==[]


def test_a_new_source_cannot_adopt_a_reopened_nonempty_execution_ledger(tmp_path):
    session,_,backend,_,store=candidate(tmp_path); assert execute(bind(session)).outcome=='succeeded'
    peer,source,_=source_candidate(); initial=source.prepare_plan()
    with pytest.raises(M4AdapterDenied):
        EmailAlertM4Session(source,initial,session._scope,Backend(peer),Evidence(peer.clock),reopen(store),
            source_guard=lambda:True,clock=peer.clock)
    assert source._m4_session is None and len(backend.sends)==1


def test_ordered_prefix_cannot_skip_or_restore_an_unowned_object(tmp_path):
    session,_,backend,_,_=candidate(tmp_path)
    for name,restore in (('glass_action',False),('general',True),('certificate',False)):
        with pytest.raises(M4AdapterDenied): session.prepare_step(name,restore=restore)
    assert execute(bind(session)).outcome=='succeeded'
    for name,restore in (('license_action',False),('glass_action',True),('general',False)):
        with pytest.raises(M4AdapterDenied): session.prepare_step(name,restore=restore)
    assert execute(bind(session,'glass_action')).outcome=='succeeded'
    with pytest.raises(M4AdapterDenied): session.prepare_step('general',restore=True)
    assert backend.sends==[('general',False),('glass_action',False)]


@pytest.mark.parametrize('fault',['missing-receipt','continuity','restore-gate'])
def test_forward_success_does_not_grant_reverse_custody_gate_or_continuity(tmp_path,fault):
    session,_,backend,evidence,store=candidate(tmp_path); original=bind(session)
    assert execute(original).outcome=='succeeded'
    if fault=='missing-receipt':
        original[0]._receipt=None
        with pytest.raises(M4AdapterDenied): session.prepare_step('general',restore=True)
        assert store.claim_count==1
    else:
        inverse=bind(session,restore=True,enabled=fault!='restore-gate')
        if fault=='continuity': evidence.fault='original_continuity_verified'
        assert execute(inverse).outcome!='succeeded' and store.claim_count==2
    assert backend.sends==[('general',False)]


def test_new_pending_mail_after_ack_is_unknown_even_when_configuration_matches(tmp_path):
    session,_,backend,evidence,_=candidate(tmp_path); bound=bind(session)
    backend.after=lambda:setattr(evidence,'fault','pending_messages')
    assert execute(bound).outcome=='reconciliation_required'
    assert session._source.read().state.digest==session._initial.expected(1).digest
    assert bound[0]._receipt is not None and not bound[0]._post_verified
    with pytest.raises(M4AdapterDenied): session.prepare_step('general',restore=True)
    assert backend.sends==[('general',False)]


def test_reopened_equal_store_cannot_supply_the_original_dispatch_scope(tmp_path):
    session,_,backend,_,store=candidate(tmp_path); adapter,_,plan,authorization=bind(session)
    verifier=Verifier(plan,authorization); kernel=M4ExecutionKernel(adapter,verifier,reopen(store),clock=session._clock)
    with pytest.raises(M4AuthorizationDenied): kernel.execute(plan,authorization)
    assert backend.sends==[] and adapter._claim().result is None
    with pytest.raises(M4AdapterDenied): session.prepare_step('general',restore=True)
