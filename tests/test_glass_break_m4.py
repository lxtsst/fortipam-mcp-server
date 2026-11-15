"""Synthetic elevation/exit through the real kernel and checkpointed ledger.

Positive incident, observer, ACK, notification and native-scope assertions are
test doubles. They do not qualify a shared appliance or independent recovery.
"""
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from fortipam_mcp.glass_break_m4 import (CONTRACT,GlassBreakExecutionScope,GlassBreakEvidence,GlassBreakReceipt,GlassBreakM4Session)
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStoreError
from test_glass_break_source import Peer,construct,COOKIE
from test_glass_break_contract import ACTOR,SERIAL,PRIVATE,REASON
from test_system_email_m4_adapter import Verifier,store_at,reopen
from v4_planning import (M4AdapterDenied,M4AuthorizationDenied,M4ExecutionAuthorization,M4ExecutionKernel,M4ExecutionPlan,canonical_digest)


class Evidence:
    def __init__(self,clock): self.clock=clock; self.fault=None; self.calls=[]
    def observe(self,configuration_digest,*,deactivate,activation_receipt_digest,phase_receipt_digest):
        self.calls.append((deactivate,activation_receipt_digest,phase_receipt_digest))
        values=dict(source_digest='b'*64,configuration_digest=configuration_digest,effects_digest='c'*64,
            activation_receipt_digest=activation_receipt_digest,phase_receipt_digest=phase_receipt_digest,
            actor_permission_verified=True,complete_native_role_schema_verified=True,account_and_session_scope_verified=True,
            object_history_clear_verified=True,isolated_instance_verified=True,incident_drill_scope_authorized=True,
            operator_approver_separation_verified=True,independent_observer_ready=True,native_action_ack_semantics_verified=True,
            audit_recording_preserved=True,log_export_preserved=True,notification_scope_verified=True,reason_audit_supported_verified=True,
            maximum_duration_enforcement_ready=True,out_of_band_deactivation_ready=True,no_secret_access_or_launch_verified=True,
            post_incident_review_rotation_plan_verified=True,
            activation_notification_observed=activation_receipt_digest is not None,reason_retained_verified=activation_receipt_digest is not None,
            deactivation_observed=deactivate and phase_receipt_digest is not None,original_continuity_verified=activation_receipt_digest is not None,
            phase_receipt_correlated=phase_receipt_digest is not None,complete=True,pending_notifications=0,active_uncontrolled_sessions=0,
            observed_at=self.clock.value,expires_at=self.clock.value+10)
        if self.fault in values:
            value=values[self.fault]; values[self.fault]=not value if type(value) is bool else ('f'*64 if type(value) is str or value is None else 1)
        elif self.fault=='stale': values.update(observed_at=self.clock.value-10,expires_at=self.clock.value)
        elif self.fault=='late': self.clock.value+=10
        return GlassBreakEvidence(**values)


class Backend:
    def __init__(self,peer):
        self.peer=peer; self.fault=None; self.sends=[]; self.buffers=[]; self.guards=[]; self.before=lambda:None; self.after=lambda:None
    def submit(self,body,*,deactivate,parameters_digest,before_send,timeout_seconds):
        assert isinstance(body,memoryview) and body.readonly and type(timeout_seconds) is int and timeout_seconds>0
        assert json.loads(body.tobytes())==({} if deactivate else dict(comments=REASON)); self.buffers.append(body.obj); self.guards.append(before_send)
        self.before()
        if self.fault=='expiry': self.peer.clock.value+=60
        if self.fault in ('worker','copied-context'):
            copied=copy_context()
            with ThreadPoolExecutor(max_workers=1) as pool:
                call=before_send if self.fault=='worker' else lambda:copied.run(before_send)
                pool.submit(call).result(timeout=1)
        assert before_send()>0
        if self.fault=='double-guard': before_send()
        self.sends.append(deactivate); self.peer.body['results']['admin']['promoted_admin']=not deactivate
        if self.fault=='lost-ack': raise TimeoutError(PRIVATE)
        if self.fault=='interrupt': raise KeyboardInterrupt
        if self.fault=='late-ack': self.peer.clock.value+=60
        if self.fault=='profile': self.peer.body['results']['admin']['profile']['permissions']['audit']='read-write'
        self.after()
        if self.fault=='missing': return None
        return GlassBreakReceipt('f'*64 if self.fault=='foreign' else '1'*64,
            'f'*64 if self.fault=='parameters' else parameters_digest,not deactivate if self.fault=='phase' else deactivate,
            canonical_digest(dict(ack='synthetic',deactivate=deactivate)))


@pytest.fixture
def candidate():
    created=[]
    def make(root,*,guarded=True,checkpointed=True,maximum=30,reserve=10):
        peer=Peer(); source,owner=construct(peer); created.append((source,owner)); initial=source.prepare_plan()
        backend=Backend(peer); evidence=Evidence(peer.clock); store=store_at(root,checkpointed=checkpointed)
        scope=GlassBreakExecutionScope('1'*64,'2'*64,'3'*64,'4'*64,'1'*64,'b'*64,'c'*64,initial.incident.digest,maximum,reserve)
        session=GlassBreakM4Session(source,initial,scope,backend,evidence,store,source_guard=(lambda:True) if guarded else None)
        return session,peer,owner,backend,evidence,store
    yield make
    for source,owner in created:
        source.close(); owner._client=None
        if owner._session_lock.locked(): owner._session_lock.release()


def bind(session,*,deactivate=False,enabled=True,verified=True,plan_fault=None,authorization_seconds=60):
    step=session.prepare_step(deactivate=deactivate); now=session._now(); expiry=min(now+60,step.expires_at)
    fields=dict(plan_ref=step.action_id+'-'+step.parameters_digest,revision=1,action_id=step.action_id,action_version='1.0.0',adapter_ref=CONTRACT,
        target_ref='glass-break-'+session._initial.baseline.binding_digest,requester_digest=session._scope.requester_digest,
        summary_digest='5'*64,confirmation_digest='6'*64,approval_digest='7'*64,parameters_digest=step.parameters_digest,
        expected_current_digest=step.expected_current_digest,expected_state_digest=step.expected_state_digest,
        idempotency_digest=canonical_digest(dict(action=step.action_id,parameters=step.parameters_digest)),expires_at=expiry,compensation_ref=None)
    if plan_fault: fields.update(plan_fault)
    plan=M4ExecutionPlan(**fields,plan_digest=canonical_digest(fields))
    fields=dict(authorization_ref=step.action_id+'-authorization',plan_ref=plan.plan_ref,plan_digest=plan.plan_digest,
        requester_digest=plan.requester_digest,confirmation_ref=step.action_id+'-intent',confirmation_digest=plan.confirmation_digest,
        approval_ref=step.action_id+'-approval',approval_digest=plan.approval_digest,approver_digest='8'*64,issued_at=now,expires_at=min(expiry,now+authorization_seconds),
        one_time=True,execution_authorized=True)
    authorization=M4ExecutionAuthorization(**fields,authorization_digest=canonical_digest(fields)); verifier=Verifier(plan,authorization)
    adapter=session.bind_step(step,plan,authorization,authorization_verifier=verifier if verified else None,execution_enabled=enabled)
    return adapter,M4ExecutionKernel(adapter,verifier,session._store,clock=session._now),plan,authorization


def execute(bound): return bound[1].execute(bound[2],bound[3])


def advance(peer,seconds): peer.clock.value+=seconds; peer.time+=seconds


def test_two_independent_claims_preserve_roles_and_never_logout_or_access_secrets(candidate,tmp_path):
    session,peer,owner,backend,evidence,store=candidate(tmp_path)
    for deactivate in (False,True):
        bound=bind(session,deactivate=deactivate); result=execute(bound)
        assert result.outcome=='succeeded' and result.verification=='verified'
        sends=list(backend.sends); assert execute(bound).idempotent_replay and backend.sends==sends
    assert backend.sends==[False,True] and store.claim_count==2 and session._duration_verified_locally is True
    assert session._source.read().state.digest==session._initial.baseline.digest
    original=session._adapters[False]._receipt.digest
    assert all(activation==original for deactivate,activation,_ in evidence.calls if deactivate)
    assert peer.credentials==0 and not owner.logout_verified and owner._client is not None
    assert all(not any(raw) for raw in peer.buffers+backend.buffers)
    assert all(marker.encode() not in store._path.read_bytes() for marker in (ACTOR,SERIAL,PRIVATE,REASON,COOKIE))


def test_exit_can_use_a_new_grant_after_activation_authority_expires(candidate,tmp_path):
    session,peer,_,backend,_,store=candidate(tmp_path); original=bind(session)
    assert original[2].expires_at==1020 and execute(original).outcome=='succeeded'
    advance(peer,21); inverse=bind(session,deactivate=True)
    assert inverse[3].issued_at>original[3].expires_at and execute(inverse).outcome=='succeeded'
    assert backend.sends==[False,True] and store.claim_count==2 and session._duration_verified_locally is True


def test_late_exit_is_allowed_but_does_not_claim_the_declared_duration(candidate,tmp_path):
    session,peer,_,backend,_,_=candidate(tmp_path); assert execute(bind(session)).outcome=='succeeded'; advance(peer,40)
    inverse=bind(session,deactivate=True); assert inverse[0]._step.declared_duration_overdue
    assert execute(inverse).outcome=='succeeded' and session._duration_verified_locally is False
    assert backend.sends==[False,True]


def test_activation_requires_window_reserve_and_rechecks_it_at_actual_send(candidate,tmp_path):
    session,peer,_,backend,_,store=candidate(tmp_path); peer.time+=25
    with pytest.raises(M4AdapterDenied): session.prepare_step()
    assert backend.sends==[] and store.claim_count==0


def test_monotonic_window_loss_before_send_cannot_be_hidden_by_unchanged_epoch(candidate,tmp_path):
    session,peer,_,backend,_,_=candidate(tmp_path); bound=bind(session); backend.before=lambda:setattr(peer,'time',peer.time+25)
    assert execute(bound).outcome!='succeeded' and backend.sends==[] and session._activation_epoch is None


@pytest.mark.parametrize('deactivate',[False,True])
@pytest.mark.parametrize('fault',['lost-ack','foreign','parameters','phase','missing','profile','late-ack'])
def test_unknown_activation_or_exit_never_conveys_repeat_or_recovery_rights(candidate,tmp_path,deactivate,fault):
    session,_,_,backend,_,store=candidate(tmp_path)
    if deactivate: assert execute(bind(session)).outcome=='succeeded'
    bound=bind(session,deactivate=deactivate); backend.fault=fault; result=execute(bound)
    assert result.outcome!='succeeded' and len(backend.sends)==1+deactivate and PRIVATE not in json.dumps(result.as_dict())
    if fault!='late-ack': assert execute(bound).idempotent_replay
    with pytest.raises(M4AdapterDenied): session.prepare_step(deactivate=True)
    assert store.claim_count==1+deactivate and all(not any(raw) for raw in backend.buffers)


def test_interrupted_activation_cannot_be_replayed_or_deactivated_from_active_view(candidate,tmp_path):
    session,peer,_,backend,_,store=candidate(tmp_path); bound=bind(session); backend.fault='interrupt'
    with pytest.raises(KeyboardInterrupt): execute(bound)
    assert peer.body['results']['admin']['promoted_admin'] and bound[0]._claim().result is None
    assert execute(bound).outcome=='reconciliation_required'
    with pytest.raises(M4AdapterDenied): session.prepare_step(deactivate=True)
    assert backend.sends==[False] and store.claim_count==1 and all(not any(raw) for raw in backend.buffers)


@pytest.mark.parametrize('fault',['actor_permission_verified','complete_native_role_schema_verified','account_and_session_scope_verified',
    'object_history_clear_verified','isolated_instance_verified','incident_drill_scope_authorized','operator_approver_separation_verified',
    'independent_observer_ready','native_action_ack_semantics_verified','audit_recording_preserved','notification_scope_verified',
    'log_export_preserved',
    'reason_audit_supported_verified','maximum_duration_enforcement_ready','out_of_band_deactivation_ready','no_secret_access_or_launch_verified',
    'post_incident_review_rotation_plan_verified',
    'complete','pending_notifications','active_uncontrolled_sessions','source_digest','configuration_digest','effects_digest',
    'activation_receipt_digest','phase_receipt_digest','original_continuity_verified','phase_receipt_correlated','stale','late'])
def test_visible_flag_cannot_replace_complete_independent_fresh_scope_and_recovery_evidence(candidate,tmp_path,fault):
    session,_,_,backend,evidence,store=candidate(tmp_path); bound=bind(session); evidence.fault=fault
    assert execute(bound).outcome!='succeeded' and backend.sends==[] and store.claim_count==1


@pytest.mark.parametrize('fault',['reason_retained_verified','activation_notification_observed','pending_notifications'])
def test_matching_active_flag_after_ack_is_not_success_without_incident_evidence(candidate,tmp_path,fault):
    session,peer,_,backend,evidence,_=candidate(tmp_path); bound=bind(session); backend.after=lambda:setattr(evidence,'fault',fault)
    assert execute(bound).outcome=='reconciliation_required' and session._source.read().state.digest==session._initial.expected().digest
    with pytest.raises(M4AdapterDenied): session.prepare_step(deactivate=True)
    assert backend.sends==[False]


@pytest.mark.parametrize('enabled,verified',[(False,True),(True,False)])
def test_default_closed_execution_and_missing_inner_verifier_deny(candidate,tmp_path,enabled,verified):
    session,_,_,backend,_,_=candidate(tmp_path); assert execute(bind(session,enabled=enabled,verified=verified)).outcome!='succeeded'
    assert backend.sends==[]


@pytest.mark.parametrize('fault',['worker','copied-context','double-guard','expiry'])
def test_final_guard_requires_original_kernel_thread_once_and_live_grant(candidate,tmp_path,fault):
    session,_,_,backend,_,_=candidate(tmp_path); bound=bind(session); backend.fault=fault
    assert execute(bound).outcome!='succeeded' and backend.sends==[]


def test_original_ack_and_sealed_readback_are_both_required_for_independent_exit(candidate,tmp_path,monkeypatch):
    session,_,_,backend,_,store=candidate(tmp_path); bound=bind(session)
    def failed(**kwargs): raise PersistentM4ExecutionStoreError('synthetic sealing failure')
    monkeypatch.setattr(store,'finalize',failed)
    with pytest.raises(PersistentM4ExecutionStoreError): execute(bound)
    assert bound[0]._receipt is not None and bound[0]._post_verified and bound[0]._claim().result is None
    with pytest.raises(M4AdapterDenied): session.prepare_step(deactivate=True)
    assert backend.sends==[False]


@pytest.mark.parametrize('fault',['cookie','guard','scope','key','checkpoint','source-plan'])
def test_last_moment_window_drift_or_authority_loss_prevents_activation(candidate,tmp_path,fault):
    session,peer,_,backend,_,store=candidate(tmp_path); bound=bind(session)
    def changed():
        if fault=='cookie': peer.cookie='SYNTHETIC_CHANGED_COOKIE'
        elif fault=='guard': session._guard=lambda:False
        elif fault=='scope': session._scope=replace(session._scope,effects_digest='f'*64)
        elif fault=='key': store._key_path.write_bytes(b'x'*32)
        elif fault=='checkpoint': store._monotonic_checkpoint=deepcopy(session._checkpoint)
        else: session._source._plan=replace(session._initial)
    backend.before=changed
    assert execute(bound).outcome!='succeeded' and backend.sends==[]


@pytest.mark.parametrize('fault',[{'parameters_digest':'f'*64},{'requester_digest':'f'*64},{'target_ref':'wrong-target'},
    {'adapter_ref':'wrong-adapter'},{'expected_state_digest':'f'*64},{'compensation_ref':'implicit-exit'},{'expires_at':1021}])
def test_exact_plan_and_window_lifetime_binding(candidate,tmp_path,fault):
    session,_,_,backend,_,_=candidate(tmp_path)
    with pytest.raises(M4AdapterDenied): bind(session,plan_fault=fault)
    assert backend.sends==[]


def test_direct_dispatch_and_foreign_reopened_kernel_do_not_acquire_ownership(candidate,tmp_path):
    session,_,_,backend,_,store=candidate(tmp_path); adapter,_,plan,authorization=bind(session)
    with pytest.raises(M4AuthorizationDenied): adapter.dispatch(plan)
    verifier=Verifier(plan,authorization); kernel=M4ExecutionKernel(adapter,verifier,reopen(store),clock=session._now)
    with pytest.raises(M4AuthorizationDenied): kernel.execute(plan,authorization)
    assert backend.sends==[] and adapter._claim().result is None


def test_only_expired_unused_unclaimed_grant_can_refresh_within_same_cookie_window(candidate,tmp_path):
    session,peer,_,backend,_,store=candidate(tmp_path); bound=bind(session,authorization_seconds=5)
    with pytest.raises(M4AdapterDenied): session._release_expired_unused(bound[0])
    advance(peer,6); session._release_expired_unused(bound[0])
    assert execute(bind(session)).outcome=='succeeded' and store.claim_count==1
    with pytest.raises(M4AdapterDenied): session._release_expired_unused(bound[0])
    assert backend.sends==[False]


@pytest.mark.parametrize('missing',['guard','checkpoint'])
def test_own_source_guard_and_checkpoint_are_mandatory(candidate,tmp_path,missing):
    with pytest.raises(M4AdapterDenied): candidate(tmp_path,guarded=missing!='guard',checkpointed=missing!='checkpoint')


def test_cookie_window_expiry_does_not_log_out_or_pretend_native_deactivation(candidate,tmp_path):
    session,peer,owner,backend,_,_=candidate(tmp_path); assert execute(bind(session)).outcome=='succeeded'
    advance(peer,60)
    with pytest.raises(M4AdapterDenied): session.prepare_step(deactivate=True)
    assert peer.body['results']['admin']['promoted_admin'] and peer.credentials==0 and not owner.logout_verified
    assert backend.sends==[False] and session._duration_verified_locally is None


def test_visible_off_after_exit_ack_requires_independent_deactivation_correlation(candidate,tmp_path):
    session,peer,_,backend,evidence,_=candidate(tmp_path); assert execute(bind(session)).outcome=='succeeded'
    inverse=bind(session,deactivate=True); backend.after=lambda:setattr(evidence,'fault','deactivation_observed')
    assert execute(inverse).outcome=='reconciliation_required' and peer.body['results']['admin']['promoted_admin'] is False
    assert session._duration_verified_locally is None and backend.sends==[False,True]


def test_same_source_or_reopened_nonempty_ledger_cannot_adopt_original_custody(candidate,tmp_path):
    session,peer,owner,backend,evidence,store=candidate(tmp_path)
    with pytest.raises(M4AdapterDenied):
        GlassBreakM4Session(session._source,session._initial,session._scope,backend,evidence,store,source_guard=lambda:True)
    for deactivate in (False,True): assert execute(bind(session,deactivate=deactivate)).outcome=='succeeded'
    from fortipam_mcp.glass_break_source import GlassBreakSource
    fresh=GlassBreakSource(owner,peer.binding,peer.schema,session._initial.incident,source_guard=lambda:True,clock=peer.clock)
    try:
        initial=fresh.prepare_plan()
        with pytest.raises(M4AdapterDenied):
            GlassBreakM4Session(fresh,initial,session._scope,backend,evidence,reopen(store),source_guard=lambda:True)
        assert fresh._m4_session is None
    finally: fresh.close()
