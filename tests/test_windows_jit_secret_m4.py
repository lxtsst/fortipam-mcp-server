"""Synthetic JIT configuration/restore with actual Script and Secret M4 journals."""
from dataclasses import replace
import json

import pytest

from fortipam_mcp.secret_checkout_association_contract import CONTROLS
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStoreError
from fortipam_mcp.windows_jit_secret_contract import _schema, _types
from fortipam_mcp.windows_jit_secret_m4 import (
    CONTRACT, JitSecretEvidence, JitSecretExecutionScope, JitSecretReceipt, WindowsJitSecretM4Session,
)
from fortipam_mcp.windows_jit_secret_source import WindowsJitSecretSource, SCHEMA_PATH
from test_system_email_m4_adapter import Verifier, store_at
from test_windows_jit_script_m4 import candidate as script_candidate, bind as bind_script, execute
from test_windows_jit_secret_contract import fixture, binding, envelope, SERIAL, SECRET
from v4_planning import (
    M4AdapterDenied, M4AuthorizationDenied, M4ExecutionAuthorization, M4ExecutionKernel,
    M4ExecutionPlan, canonical_digest,
)


class Evidence:
    def __init__(self,clock): self.clock = clock; self.fault = None
    def observe(self,configuration_digest,*,restore,original_update_receipt_digest):
        fields = dict(source_digest='d'*64,configuration_digest=configuration_digest,effects_digest='e'*64,
            original_subject_receipt_digest='f'*64,material_preservation_digest='1'*64,
            original_update_receipt_digest=original_update_receipt_digest,
            actor_permission_verified=True,original_subject_custody_verified=True,associated_admin_verified=True,
            standalone_target_verified=True,complete_reference_scope_verified=True,no_active_checkout_or_session_verified=True,
            native_patch_semantics_verified=True,material_continuity_verified=True,independent_recovery_ready=True,
            script_reference_scope_verified=True,complete=True,observed_at=self.clock.value,expires_at=self.clock.value+10)
        if self.fault in fields:
            current = fields[self.fault]
            fields[self.fault] = not current if type(current) is bool else '9'*64
        if self.fault == 'stale': fields.update(observed_at=self.clock.value-10,expires_at=self.clock.value)
        if self.fault == 'late': self.clock.value += 10
        return JitSecretEvidence(**fields)


class Backend:
    def __init__(self,peer,row):
        self.peer,self.row = peer,row; self.sends = []; self.buffers = []
        self.fault = None; self.before = lambda:None; self.after = lambda:None
    def submit(self,body,*,restore,parameters_digest,before_send,timeout_seconds):
        assert isinstance(body,memoryview) and body.readonly
        patch = json.loads(body.tobytes()); assert set(patch) == CONTROLS
        assert 'field' not in patch and 'totp-setting' not in patch and 'permissions' not in patch
        assert timeout_seconds > 0; self.buffers.append(body.obj); self.before(); assert before_send() > 0
        self.sends.append(restore); self.row.update(patch)
        self.row['permissions'].update(checkout_status='none' if restore else 'required',passwd_change='allowed' if restore else 'forbidden')
        for i,path in enumerate(self.peer.details):
            self.peer.rows[i+1]['q_ref'] = 0 if restore else 1
            self.peer.payloads[path]['results']['q_ref'] = 0 if restore else 1
        if self.fault == 'lost-ack': raise TimeoutError('SYNTHETIC_PRIVATE_FAILURE')
        if self.fault == 'interrupt': raise KeyboardInterrupt
        if self.fault == 'permissions': self.row['permissions']['other'] = 'changed'
        if self.fault == 'missing-inversion': self.row['permissions']['checkout_status'] = 'none'
        if self.fault == 'script-reference':
            self.peer.rows[1]['q_ref'] = 2; self.peer.payloads[self.peer.details[0]]['results']['q_ref'] = 2
        if self.fault == 'deadline': self.peer.clock.value += 60
        self.after()
        return JitSecretReceipt('9'*64 if self.fault == 'foreign-receipt' else 'b'*64,
            parameters_digest,restore,'2'*64)


def candidate(tmp_path):
    scripts,peer,script_backend,_,script_store = script_candidate(tmp_path)
    for index in (0,1): assert execute(bind_script(scripts,index)).outcome == 'succeeded'
    schema,row = fixture(); peer.payloads[SCHEMA_PATH] = schema
    source = WindowsJitSecretSource(scripts._source,binding(),expected_schema_digest=canonical_digest(_types(_schema(schema,SERIAL))),
        source_digest='b'*64,source_guard=lambda:True)
    peer.payloads[source._detail] = envelope(row); plan = source.prepare_plan()
    scope = JitSecretExecutionScope('3'*64,'4'*64,'5'*64,'6'*64,'b'*64,'d'*64,'e'*64,'f'*64,'1'*64)
    (tmp_path/'secret').mkdir(mode=0o700); store = store_at(tmp_path/'secret')
    backend,evidence = Backend(peer,row),Evidence(peer.clock)
    session = WindowsJitSecretM4Session(source,plan,scripts,scope,backend,evidence,store,source_guard=lambda:True)
    return session,peer,backend,evidence,script_backend


def bind(session,*,restore=False,enabled=True,verified=True,plan_fault=None):
    step = session.prepare_step(restore=restore); now = session._scripts._now()
    fields = dict(plan_ref=step.action_id+'-'+step.parameters_digest,revision=1,action_id=step.action_id,
        action_version='1.0.0',adapter_ref=CONTRACT,
        target_ref='jit-secret-'+canonical_digest(session._initial.baseline.binding.identity),
        requester_digest=session._scope.requester_digest,summary_digest='7'*64,confirmation_digest='8'*64,approval_digest='9'*64,
        parameters_digest=step.parameters_digest,expected_current_digest=step.expected_current_digest,
        expected_state_digest=step.expected_state_digest,
        idempotency_digest=canonical_digest(dict(action=step.action_id,parameters=step.parameters_digest)),expires_at=now+60,compensation_ref=None)
    if plan_fault: fields.update(plan_fault)
    plan = M4ExecutionPlan(**fields,plan_digest=canonical_digest(fields))
    fields = dict(authorization_ref=step.action_id+'-authorization',plan_ref=plan.plan_ref,plan_digest=plan.plan_digest,
        requester_digest=plan.requester_digest,confirmation_ref=step.action_id+'-intent',confirmation_digest=plan.confirmation_digest,
        approval_ref=step.action_id+'-approval',approval_digest=plan.approval_digest,approver_digest='a'*64,
        issued_at=now,expires_at=now+60,one_time=True,execution_authorized=True)
    authorization = M4ExecutionAuthorization(**fields,authorization_digest=canonical_digest(fields)); verifier = Verifier(plan,authorization)
    adapter = session.bind_step(step,plan,authorization,authorization_verifier=verifier if verified else None,execution_enabled=enabled)
    return adapter,M4ExecutionKernel(adapter,verifier,session._store,clock=session._scripts._clock),plan,authorization


def test_owned_scripts_configure_restore_and_only_then_independent_script_cleanup(tmp_path):
    session,peer,backend,_,script_backend = candidate(tmp_path)
    for restore in (False,True):
        bound = bind(session,restore=restore); result = execute(bound)
        assert result.outcome == 'succeeded' and result.verification == 'verified'
        assert execute(bound).idempotent_replay
    assert session._source.read().secret.digest == session._initial.baseline.digest
    for index in (1,0): assert execute(bind_script(session._scripts,index,remove=True)).outcome == 'succeeded'
    assert backend.sends == [False,True] and script_backend.sends == [(0,False),(1,False),(1,True),(0,True)]
    assert session._store.claim_count == 2 and session._scripts._store.claim_count == 4
    assert all(not any(raw) for raw in backend.buffers+peer.buffers)
    assert all(resource.closed for resource in peer.resources)
    assert SECRET.encode() not in session._store._path.read_bytes()


def test_restore_after_original_authorization_expiry_still_requires_new_gate(tmp_path):
    session,peer,backend,_,_ = candidate(tmp_path)
    assert execute(bind(session)).outcome == 'succeeded'
    peer.clock.value += 100
    assert execute(bind(session,restore=True)).outcome == 'succeeded'
    assert backend.sends == [False,True]


@pytest.mark.parametrize('fault',['actor_permission_verified','original_subject_custody_verified','associated_admin_verified',
    'standalone_target_verified','complete_reference_scope_verified','no_active_checkout_or_session_verified',
    'native_patch_semantics_verified','material_continuity_verified','independent_recovery_ready',
    'script_reference_scope_verified','complete','source_digest','configuration_digest','effects_digest',
    'original_subject_receipt_digest','material_preservation_digest','stale','late'])
def test_metadata_and_original_script_success_never_replace_secret_material_or_authority_evidence(tmp_path,fault):
    session,_,backend,evidence,_ = candidate(tmp_path)
    bound = bind(session); evidence.fault = fault
    assert execute(bound).outcome != 'succeeded' and backend.sends == []
    assert execute(bound).idempotent_replay


@pytest.mark.parametrize('fault',['lost-ack','foreign-receipt','permissions','missing-inversion','script-reference','deadline'])
def test_uncertain_or_incomplete_update_does_not_allow_inverse_or_replay(tmp_path,fault):
    session,_,backend,_,_ = candidate(tmp_path)
    bound = bind(session); backend.fault = fault; result = execute(bound)
    assert result.outcome != 'succeeded' and backend.sends == [False]
    assert 'SYNTHETIC_PRIVATE_FAILURE' not in json.dumps(result.as_dict())
    with pytest.raises(M4AdapterDenied): session.prepare_step(restore=True)
    with pytest.raises(M4AdapterDenied): session.prepare_step()
    assert all(not any(raw) for raw in backend.buffers)


def test_consumed_uncertain_restore_stays_unknown_after_baseline_is_visible(tmp_path):
    session,_,backend,_,_ = candidate(tmp_path)
    assert execute(bind(session)).outcome == 'succeeded'
    bound = bind(session,restore=True); backend.fault = 'lost-ack'
    result = execute(bound); assert result.outcome == 'reconciliation_required'
    assert session._source.read().secret.digest == session._initial.baseline.digest
    with pytest.raises(M4AdapterDenied): session.prepare_step(restore=True)
    assert execute(bound).idempotent_replay and bound[0]._claim().result == result
    assert backend.sends == [False,True]


def test_interruption_leaves_original_claim_in_progress_without_inverse_or_reset(tmp_path):
    session,_,backend,_,_ = candidate(tmp_path); bound = bind(session); backend.fault = 'interrupt'
    with pytest.raises(KeyboardInterrupt): execute(bound)
    assert bound[0]._claim().result is None and execute(bound).idempotent_replay
    with pytest.raises(M4AdapterDenied): session.prepare_step(restore=True)
    assert backend.sends == [False] and all(not any(raw) for raw in backend.buffers)


@pytest.mark.parametrize('enabled,verified',[(False,True),(True,False)])
def test_configuration_and_restore_each_need_their_own_gate_and_verifier(tmp_path,enabled,verified):
    session,_,backend,_,_ = candidate(tmp_path)
    bound = bind(session,enabled=enabled,verified=verified)
    assert execute(bound).outcome == 'denied' and backend.sends == []


def test_direct_dispatch_cannot_adopt_original_script_authority(tmp_path):
    session,_,backend,_,_ = candidate(tmp_path); adapter,_,plan,_ = bind(session)
    with pytest.raises(M4AuthorizationDenied): adapter.dispatch(plan)
    assert backend.sends == []


@pytest.mark.parametrize('fault',['permissions','references','scope','key','clock'])
def test_final_send_guard_rejects_full_state_original_receipt_or_scope_drift(tmp_path,fault):
    session,peer,backend,_,_ = candidate(tmp_path); bound = bind(session)
    def change():
        if fault == 'permissions': backend.row['permissions']['other'] = 'changed'
        elif fault == 'references':
            peer.rows[1]['q_ref'] = 1; peer.payloads[peer.details[0]]['results']['q_ref'] = 1
        elif fault == 'scope': session._scope = replace(session._scope,material_preservation_digest='9'*64)
        elif fault == 'key': session._store._key_path.write_bytes(b'9'*32)
        else: peer.clock.value -= 1
    backend.before = change
    assert execute(bound).outcome != 'succeeded' and backend.sends == []


def test_matching_foreign_secret_plan_does_not_convey_original_subject_custody(tmp_path):
    session,_,backend,evidence,_ = candidate(tmp_path)
    with pytest.raises(M4AdapterDenied):
        WindowsJitSecretM4Session(session._source,replace(session._initial),session._scripts,session._scope,
            backend,evidence,session._store,source_guard=lambda:True)
    original = session._scripts._adapters[(0,False)]._receipt
    session._scripts._adapters[(0,False)]._receipt = None
    with pytest.raises(M4AdapterDenied): session.prepare_step()
    session._scripts._adapters[(0,False)]._receipt = original
    assert backend.sends == []


@pytest.mark.parametrize('field,value',[('target_ref','foreign-secret'),('parameters_digest','9'*64),('expires_at',1061)])
def test_secret_grant_cannot_select_a_different_identity_parameters_or_window(tmp_path,field,value):
    session,_,backend,_,_ = candidate(tmp_path)
    with pytest.raises(M4AdapterDenied): bind(session,plan_fault={field:value})
    assert backend.sends == [] and session._store.claim_count == 0


def test_update_ack_and_successful_readback_still_need_a_sealed_secret_journal(tmp_path):
    session,_,backend,_,_ = candidate(tmp_path); bound = bind(session)
    def fail_seal(): session._store._monotonic_checkpoint.fail_next_advance = True
    backend.after = fail_seal
    with pytest.raises(PersistentM4ExecutionStoreError): execute(bound)
    assert bound[0]._receipt is not None and bound[0]._post_verified
    with pytest.raises(M4AdapterDenied): session.prepare_step(restore=True)
    assert backend.sends == [False]


def test_restore_evidence_must_cover_this_original_update_receipt(tmp_path):
    session,_,backend,evidence,_ = candidate(tmp_path)
    assert execute(bind(session)).outcome == 'succeeded'
    evidence.fault = 'original_update_receipt_digest'
    with pytest.raises(M4AdapterDenied): session.prepare_step(restore=True)
    assert backend.sends == [False]


def test_script_journal_cannot_be_reused_for_secret_claims_or_reset_its_pending_count(tmp_path):
    session,_,backend,evidence,_ = candidate(tmp_path)
    with pytest.raises(M4AdapterDenied):
        WindowsJitSecretM4Session(session._source,session._initial,session._scripts,session._scope,
            backend,evidence,session._scripts._store,source_guard=lambda:True)
    assert session._scripts._store.claim_count == 2 and backend.sends == []


def test_new_empty_journal_cannot_reset_the_secret_lifecycle_of_this_original_script_session(tmp_path):
    session,_,backend,evidence,_ = candidate(tmp_path)
    (tmp_path/'replacement').mkdir(mode=0o700); replacement = store_at(tmp_path/'replacement')
    with pytest.raises(M4AdapterDenied):
        WindowsJitSecretM4Session(session._source,session._initial,session._scripts,session._scope,
            backend,evidence,replacement,source_guard=lambda:True)
    assert replacement.claim_count == session._store.claim_count == 0
    assert session._scripts._jit_secret_session is session and backend.sends == []
