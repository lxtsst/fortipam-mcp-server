"""Synthetic Script lifecycle through the real kernel and persistent claim store.

Positive eligibility and receipts below are test doubles, not device authority.
"""
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from fortipam_mcp.windows_jit_script_m4 import (
    CONTRACT, JitScriptEvidence, JitScriptExecutionScope, JitScriptReceipt,
    WindowsJitScriptM4Session,
)
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStoreError
from test_system_email_m4_adapter import Verifier, store_at, reopen
from test_windows_jit_script_source import Peer, PRIVATE, envelope
from v4_planning import (
    M4AdapterDenied, M4AuthorizationDenied, M4ExecutionAuthorization,
    M4ExecutionKernel, M4ExecutionPlan, canonical_digest,
)


class Evidence:
    def __init__(self, clock):
        self.clock = clock; self.fault = None; self.calls = []

    def observe(self, configuration_digest, *, index, remove, original_receipt_digest):
        self.calls.append((index, remove, original_receipt_digest))
        fields = dict(source_digest='b'*64, configuration_digest=configuration_digest,
            effects_digest='c'*64, original_receipt_digest=original_receipt_digest,
            global_namespace_verified=True, actor_permission_verified=True,
            complete_reference_scope_verified=True, unattached_definition_verified=True,
            native_semantics_verified=True, independent_recovery_ready=True,
            original_continuity_verified=original_receipt_digest is not None,
            complete=True, active_uses=0, observed_at=self.clock.value, expires_at=self.clock.value+10)
        if self.fault in fields:
            value = fields[self.fault]
            fields[self.fault] = not value if type(value) is bool else ('f'*64 if type(value) is str else 1)
        if self.fault == 'stale': fields.update(observed_at=self.clock.value-10, expires_at=self.clock.value)
        if self.fault == 'late': self.clock.value += 10
        return JitScriptEvidence(**fields)


class Backend:
    def __init__(self, peer):
        self.peer = peer; self.fault = None; self.sends = []; self.buffers = []
        self.before = lambda:None; self.after = lambda:None

    def submit(self, body, *, index, remove, parameters_digest, before_send, timeout_seconds):
        assert type(timeout_seconds) is int and timeout_seconds > 0
        if remove: assert body is None
        else:
            assert isinstance(body,memoryview) and body.readonly
            assert json.loads(body.tobytes()) == self.peer.expected[index]
            self.buffers.append(body.obj)
        self.before()
        if self.fault == 'expiry': self.peer.clock.value += 60
        if self.fault in ('worker','copied-context'):
            copied = copy_context()
            with ThreadPoolExecutor(max_workers=1) as pool:
                call = before_send if self.fault == 'worker' else lambda:copied.run(before_send)
                pool.submit(call).result(timeout=1)
        assert before_send() > 0
        if self.fault == 'double-guard': before_send()
        self.sends.append((index,remove))
        name = self.peer.expected[index]['name']; path = self.peer.details[index]
        if remove:
            self.peer.rows[:] = [row for row in self.peer.rows if row['name'] != name]
            self.peer.payloads[path] = envelope(None,status=404,error=-3)
        else:
            row = dict(self.peer.expected[index],q_origin_key=name,q_mkey_type='string',q_name='script',q_path='secret',
                q_ref=0,q_type=1,q_no_edit=False,q_no_rename=False,q_static=False,q_global_entry=False)
            if self.fault == 'reference': row['q_ref'] = 1
            if self.fault == 'metadata': row['q_type'] = 2
            self.peer.rows.append(row); self.peer.payloads[path] = envelope(deepcopy(row),mkey=name)
        self.peer.counts()
        if self.fault == 'lost-ack': raise TimeoutError('SYNTHETIC_PRIVATE_FAILURE')
        if self.fault == 'interrupt': raise KeyboardInterrupt
        if self.fault == 'late-ack': self.peer.clock.value += 60
        self.after()
        return JitScriptReceipt('f'*64 if self.fault == 'foreign-receipt' else 'a'*64,
            'f'*64 if self.fault == 'receipt-parameters' else parameters_digest,
            1-index if self.fault == 'receipt-index' else index,
            not remove if self.fault == 'receipt-phase' else remove,
            canonical_digest(dict(ack='synthetic',index=index,remove=remove)))


def candidate(tmp_path):
    peer = Peer(); source = peer.source(); initial = source.prepare_plan()
    scope = JitScriptExecutionScope('1'*64,'2'*64,'3'*64,'4'*64,'a'*64,'b'*64,'c'*64)
    backend = Backend(peer); evidence = Evidence(peer.clock); store = store_at(tmp_path)
    session = WindowsJitScriptM4Session(source,initial,scope,backend,evidence,store,
        source_guard=lambda:True,clock=peer.clock)
    return session,peer,backend,evidence,store


def bind(session, index=0, *, remove=False, enabled=True, verified=True, plan_fault=None):
    step = session.prepare_step(index,remove=remove)
    now = session._clock()
    fields = dict(plan_ref=step.action_id+'-'+step.parameters_digest,revision=1,
        action_id=step.action_id,action_version='1.0.0',adapter_ref=CONTRACT,
        target_ref='jit-script-'+canonical_digest(dict(definitions=session._source._definition_digest,index=index)),
        requester_digest=session._scope.requester_digest,summary_digest='5'*64,confirmation_digest='6'*64,
        approval_digest='7'*64,parameters_digest=step.parameters_digest,
        expected_current_digest=step.expected_current_digest,expected_state_digest=step.expected_state_digest,
        idempotency_digest=canonical_digest(dict(action=step.action_id,parameters=step.parameters_digest)),
        expires_at=now+60,compensation_ref=None)
    if plan_fault: fields.update(plan_fault)
    plan = M4ExecutionPlan(**fields,plan_digest=canonical_digest(fields))
    fields = dict(authorization_ref=step.action_id+'-authorization',plan_ref=plan.plan_ref,
        plan_digest=plan.plan_digest,requester_digest=plan.requester_digest,
        confirmation_ref=step.action_id+'-intent',confirmation_digest=plan.confirmation_digest,
        approval_ref=step.action_id+'-approval',approval_digest=plan.approval_digest,
        approver_digest='8'*64,issued_at=now,expires_at=now+60,one_time=True,execution_authorized=True)
    authorization = M4ExecutionAuthorization(**fields,authorization_digest=canonical_digest(fields))
    verifier = Verifier(plan,authorization)
    adapter = session.bind_step(step,plan,authorization,authorization_verifier=verifier if verified else None,
        execution_enabled=enabled)
    kernel = M4ExecutionKernel(adapter,verifier,session._store,clock=session._clock)
    return adapter,kernel,plan,authorization


def execute(bound):
    adapter,kernel,plan,authorization = bound
    return kernel.execute(plan,authorization)


def test_four_independent_claims_preserve_original_receipts_and_restore_namespace(tmp_path):
    session,peer,backend,evidence,store = candidate(tmp_path)
    for index,remove in ((0,False),(1,False),(1,True),(0,True)):
        bound = bind(session,index,remove=remove); result = execute(bound)
        assert result.outcome == 'succeeded' and result.verification == 'verified'
        before = list(backend.sends)
        assert execute(bound).idempotent_replay and backend.sends == before
        assert bound[0]._claim().result.outcome == 'succeeded'
    assert store.claim_count == 4 and backend.sends == [(0,False),(1,False),(1,True),(0,True)]
    assert session._source.read().state_digest == session._initial._origin.state_digest
    assert all(not any(raw) for raw in backend.buffers+peer.buffers)
    assert all(resource.closed for resource in peer.resources)
    creates = [session._adapters[(i,False)]._receipt.digest for i in (0,1)]
    assert all(receipt in creates for _,remove,receipt in evidence.calls if remove)
    ledger = store._path.read_bytes()
    assert PRIVATE not in ledger and b'Add-LocalGroupMember' not in ledger
    assert b'MCPV4JitGrant' not in ledger


def test_removal_uses_fresh_independent_grant_after_creation_grant_expires(tmp_path):
    session,peer,backend,_,store = candidate(tmp_path)
    assert execute(bind(session)).outcome == 'succeeded'
    peer.clock.value += 100
    assert execute(bind(session,remove=True)).outcome == 'succeeded'
    assert backend.sends == [(0,False),(0,True)] and store.claim_count == 2


def test_second_unknown_preserves_first_original_and_only_its_cleanup_is_allowed(tmp_path):
    session,_,backend,_,store = candidate(tmp_path)
    first = bind(session); assert execute(first).outcome == 'succeeded'
    second = bind(session,1); backend.fault = 'lost-ack'
    unknown = execute(second); assert unknown.outcome == 'reconciliation_required'
    backend.fault = None
    with pytest.raises(M4AdapterDenied): session.prepare_step(1,remove=True)
    with pytest.raises(M4AdapterDenied): session.prepare_step(1)
    assert execute(bind(session,remove=True)).outcome == 'succeeded'
    assert session._source.read().present == (False,True)
    assert execute(second).idempotent_replay and second[0]._claim().result == unknown
    assert store.claim_count == 3 and backend.sends == [(0,False),(1,False),(0,True)]


@pytest.mark.parametrize('fault',['lost-ack','foreign-receipt','receipt-parameters','receipt-index',
    'receipt-phase','reference','metadata','late-ack'])
def test_uncertain_creation_never_acquires_cleanup_or_replay_rights(tmp_path,fault):
    session,_,backend,_,store = candidate(tmp_path)
    bound = bind(session); backend.fault = fault
    result = execute(bound)
    assert result.outcome != 'succeeded' and store.claim_count == 1 and backend.sends == [(0,False)]
    assert 'SYNTHETIC_PRIVATE_FAILURE' not in json.dumps(result.as_dict())
    backend.fault = None
    with pytest.raises(M4AdapterDenied): session.prepare_step(0,remove=True)
    with pytest.raises(M4AdapterDenied): session.prepare_step(0)
    with pytest.raises(M4AdapterDenied): session.prepare_step(1)
    assert all(not any(raw) for raw in backend.buffers)


def test_absence_after_lost_removal_ack_cannot_repair_unknown_or_authorize_replay(tmp_path):
    session,_,backend,_,store = candidate(tmp_path)
    assert execute(bind(session)).outcome == 'succeeded'
    bound = bind(session,remove=True); backend.fault = 'lost-ack'
    unknown = execute(bound); assert unknown.outcome == 'reconciliation_required'
    backend.fault = None
    assert session._source.read().present == (False,False)
    with pytest.raises(M4AdapterDenied): session.prepare_step(0,remove=True)
    assert execute(bound).idempotent_replay and bound[0]._claim().result == unknown
    assert store.claim_count == 2 and backend.sends == [(0,False),(0,True)]


def test_interrupted_dispatch_remains_in_progress_and_blocks_other_session_steps(tmp_path):
    session,_,backend,_,store = candidate(tmp_path)
    bound = bind(session); backend.fault = 'interrupt'
    with pytest.raises(KeyboardInterrupt): execute(bound)
    assert bound[0]._claim().result is None
    assert execute(bound).outcome == 'reconciliation_required' and execute(bound).idempotent_replay
    for index,remove in ((0,False),(0,True),(1,False)):
        with pytest.raises(M4AdapterDenied): session.prepare_step(index,remove=remove)
    assert store.claim_count == 1 and backend.sends == [(0,False)]
    assert all(not any(raw) for raw in backend.buffers)


@pytest.mark.parametrize('fault',['global_namespace_verified','actor_permission_verified',
    'complete_reference_scope_verified','unattached_definition_verified','native_semantics_verified',
    'independent_recovery_ready','complete','active_uses','source_digest','configuration_digest',
    'effects_digest','original_continuity_verified','stale','late'])
def test_visible_configuration_and_zero_q_ref_cannot_replace_independent_fresh_evidence(tmp_path,fault):
    session,_,backend,evidence,store = candidate(tmp_path)
    bound = bind(session); evidence.fault = fault
    assert execute(bound).outcome != 'succeeded'
    assert backend.sends == [] and store.claim_count == 1
    assert execute(bound).idempotent_replay


@pytest.mark.parametrize('enabled,verified',[(False,True),(True,False)])
def test_default_closed_execution_or_missing_private_verifier_never_submits(tmp_path,enabled,verified):
    session,_,backend,_,_ = candidate(tmp_path)
    bound = bind(session,enabled=enabled,verified=verified)
    assert execute(bound).outcome != 'succeeded' and backend.sends == []


def test_dispatch_without_active_kernel_ownership_cannot_submit(tmp_path):
    session,_,backend,_,store = candidate(tmp_path)
    adapter,_,plan,_ = bind(session)
    with pytest.raises(M4AuthorizationDenied): adapter.dispatch(plan)
    assert backend.sends == [] and store.claim_count == 0


@pytest.mark.parametrize('fault',['worker','copied-context','double-guard','expiry'])
def test_final_send_guard_requires_original_thread_single_admission_and_current_grant(tmp_path,fault):
    session,_,backend,_,_ = candidate(tmp_path)
    bound = bind(session); backend.fault = fault
    assert execute(bound).outcome != 'succeeded' and backend.sends == []
    assert all(not any(raw) for raw in backend.buffers)


@pytest.mark.parametrize('fault',['namespace','revoke','source','clock','key','checkpoint'])
def test_last_moment_drift_or_authority_change_prevents_the_send(tmp_path,fault):
    session,peer,backend,_,_ = candidate(tmp_path)
    bound = bind(session)
    def change():
        if fault == 'namespace': peer.rows.append(dict(name='new-unrelated-name')); peer.counts()
        elif fault == 'revoke': bound[0]._verifier = None
        elif fault == 'source': session._scope = replace(session._scope,effects_digest='f'*64)
        elif fault == 'clock': peer.clock.value -= 1
        elif fault == 'key': session._store._key_path.write_bytes(b'x'*32)
        else: session._store._monotonic_checkpoint = deepcopy(session._checkpoint)
    backend.before = change
    assert execute(bound).outcome != 'succeeded' and backend.sends == []


@pytest.mark.parametrize('field,value',[('parameters_digest','f'*64),('expected_current_digest','f'*64),
    ('expected_state_digest','f'*64),('idempotency_digest','f'*64),('target_ref','foreign-target'),
    ('adapter_ref','foreign-adapter'),('requester_digest','f'*64),('expires_at',1061)])
def test_step_plan_must_match_original_definition_scope_state_and_short_window(tmp_path,field,value):
    session,_,backend,_,store = candidate(tmp_path)
    with pytest.raises(M4AdapterDenied): bind(session,plan_fault={field:value})
    assert backend.sends == [] and store.claim_count == 0


def test_equal_foreign_initial_plan_or_reopened_nonempty_journal_cannot_adopt_custody(tmp_path):
    session,peer,backend,evidence,store = candidate(tmp_path)
    foreign = peer.source().prepare_plan()
    for initial in (foreign,replace(session._initial)):
        with pytest.raises(M4AdapterDenied):
            WindowsJitScriptM4Session(session._source,initial,session._scope,backend,evidence,store,
                source_guard=lambda:True,clock=peer.clock)
    assert execute(bind(session)).outcome == 'succeeded'
    with pytest.raises(M4AdapterDenied):
        WindowsJitScriptM4Session(session._source,session._initial,session._scope,backend,evidence,store,
            source_guard=lambda:True,clock=peer.clock)


def test_removal_needs_original_physical_adapter_sealed_result_and_continuity(tmp_path):
    session,_,backend,evidence,_ = candidate(tmp_path)
    bound = bind(session); assert execute(bound).outcome == 'succeeded'
    original = bound[0]._receipt
    bound[0]._receipt = None
    with pytest.raises(M4AdapterDenied): session.prepare_step(0,remove=True)
    bound[0]._receipt = original
    removal = bind(session,remove=True); evidence.fault = 'original_continuity_verified'
    assert execute(removal).outcome != 'succeeded' and backend.sends == [(0,False)]


def test_clock_rollback_is_sticky_and_unused_step_does_not_allow_a_second_binding(tmp_path):
    session,peer,_,_,_ = candidate(tmp_path)
    bind(session)
    with pytest.raises(M4AdapterDenied): session.prepare_step(0)
    peer.clock.value -= 1
    with pytest.raises(M4AdapterDenied): session.prepare_step(1)
    peer.clock.value += 1
    with pytest.raises(M4AdapterDenied): session.prepare_step(1)


def test_reopened_equal_store_cannot_supply_the_original_dispatch_ownership(tmp_path):
    session,peer,backend,_,store = candidate(tmp_path)
    adapter,_,plan,authorization = bind(session)
    verifier = Verifier(plan,authorization)
    kernel = M4ExecutionKernel(adapter,verifier,reopen(store),clock=peer.clock)
    with pytest.raises(M4AuthorizationDenied): kernel.execute(plan,authorization)
    assert backend.sends == []
    with pytest.raises(M4AdapterDenied): session.prepare_step(0,remove=True)


def test_unsealed_successful_readback_never_conveys_original_cleanup_rights(tmp_path):
    session,_,backend,_,store = candidate(tmp_path)
    bound = bind(session)
    def fail_seal(): store._monotonic_checkpoint.fail_next_advance = True
    backend.after = fail_seal
    with pytest.raises(PersistentM4ExecutionStoreError): execute(bound)
    assert bound[0]._receipt is not None and bound[0]._post_verified
    with pytest.raises(M4AdapterDenied): session.prepare_step(0,remove=True)
    assert backend.sends == [(0,False)]


def test_successful_original_does_not_enable_its_independent_removal_gate(tmp_path):
    session,_,backend,_,store = candidate(tmp_path)
    assert execute(bind(session)).outcome == 'succeeded'
    bound = bind(session,remove=True,enabled=False)
    assert execute(bound).outcome == 'denied'
    with pytest.raises(M4AdapterDenied): session.prepare_step(0,remove=True)
    assert store.claim_count == 2 and backend.sends == [(0,False)]


@pytest.mark.parametrize('missing',['guard','checkpoint'])
def test_session_requires_its_own_source_authority_and_external_checkpoint(tmp_path,missing):
    session,peer,backend,evidence,store = candidate(tmp_path)
    if missing == 'checkpoint':
        (tmp_path/'different').mkdir(mode=0o700)
        store = store_at(tmp_path/'different',checkpointed=False)
    with pytest.raises(M4AdapterDenied):
        WindowsJitScriptM4Session(session._source,session._initial,session._scope,backend,evidence,store,
            source_guard=None if missing == 'guard' else lambda:True,clock=peer.clock)
    assert backend.sends == []
