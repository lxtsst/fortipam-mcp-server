"""Protected activation/exit grants; native incidents and effects are synthetic."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import json

import pytest

from fortipam_mcp.glass_break_authority import GlassBreakProtectedLabAuthority,PURPOSES
from fortipam_mcp.glass_break_local_workflow import GlassBreakLocalWorkflow,PHASES
from fortipam_mcp.glass_break_m4 import GlassBreakExecutionScope,GlassBreakM4Session
from fortipam_mcp.reference_authority_sidecar import UnixReferenceAuthorityClient,UnixReferenceAuthorityClientSettings
from test_glass_break_source import Peer,construct as source_for,COOKIE
from test_glass_break_contract import ACTOR,SERIAL,PRIVATE,REASON
from test_glass_break_m4 import Backend,Evidence,advance
from test_system_email_authority import owner_file
from test_system_email_m4_adapter import store_at
from v4_planning import M4AuthorizationDenied,VerifiedReferenceDecision,canonical_digest

REFERENCE='glass-break-test-reference-authority'
TRANSPORT='9'*64
ENVIRONMENT,SCOPE_REF,AUDIENCE='glass-break-test-environment','glass-break-test-scope','glass-break-test-audience'


def cleanup(value):
    value.source.close(); value.owner._client=None
    if value.owner._session_lock.locked(): value.owner._session_lock.release()


def construct(root,client,*,requester='2'*64,transport=TRANSPORT,policy_enabled=True,workflow_enabled=True,
        policy_source=True,signing_key=b'p'*32,source=None,owner=None,peer=None,store=None,backend_factory=None):
    if source is None: peer=peer or Peer(); source,owner=source_for(peer)
    try:
        initial=source.prepare_plan(); backend=Backend(peer) if backend_factory is None else backend_factory(source,initial)
        evidence=Evidence(peer.clock); store=store or store_at(root)
        scope=GlassBreakExecutionScope('1'*64,requester,canonical_digest(SCOPE_REF),canonical_digest(AUDIENCE),
            '1'*64,'b'*64,'c'*64,initial.incident.digest,30,10)
        session=GlassBreakM4Session(source,initial,scope,backend,evidence,store,source_guard=lambda:True)
        key=owner_file(root/'policy.key',signing_key)
        policy=GlassBreakProtectedLabAuthority(session,reference_authority=client,authority_key_file=key,transport_digest=transport,
            environment_ref=ENVIRONMENT,scope_ref=SCOPE_REF,audience_ref=AUDIENCE,execution_enabled=policy_enabled,
            source_guard=(lambda:True) if policy_source else None)
        workflow=GlassBreakLocalWorkflow(session,allowed_transport_digest=transport,authority=policy,
            enabled_phases=PHASES if workflow_enabled else (),source_guard=lambda:True)
        return SimpleNamespace(source=source,owner=owner,session=session,workflow=workflow,policy=policy,peer=peer,backend=backend,
            evidence=evidence,store=store,clock=peer.clock,requester=requester,transport=transport,key=key)
    except BaseException:
        source.close(); owner._client=None
        if owner._session_lock.locked(): owner._session_lock.release()
        raise


def identity(value): return dict(requester_digest=value.requester,transport_digest=value.transport)


def make(monkeypatch,root,**kwargs):
    client=UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(Path('/private/tmp/glass-break-unit.sock'),REFERENCE))
    monkeypatch.setattr(client,'verify_ready',lambda:None)
    allowed,calls,expiry,faults=set(),[],[2000],[None]
    def authorize(ref,*,reference_kind,requester_digest,environment_ref,scope_ref,now_epoch):
        calls.append((ref,reference_kind)); authorized=(ref,reference_kind) in allowed and now_epoch<expiry[0]
        fields=dict(reference_digest=canonical_digest(ref),reference_kind=reference_kind,authority_ref=REFERENCE,
            requester_digest=requester_digest,environment_digest=canonical_digest(environment_ref),scope_digest=canonical_digest(scope_ref),
            authorized=authorized,checked_at=now_epoch,expires_at=min(now_epoch+60,expiry[0]) if authorized else now_epoch+60)
        if faults[0]: fields.update(faults[0])
        return VerifiedReferenceDecision(**fields)
    monkeypatch.setattr(client,'authorize',authorize); value=construct(root,client,**kwargs)
    for phase in PHASES:
        for purpose in PURPOSES: allowed.add((value.policy.reference_for(phase,purpose),'glass_break_'+purpose))
    value.allowed,value.calls,value.expiry,value.faults,value.client=allowed,calls,expiry,faults,client
    return value


@pytest.fixture
def factory(monkeypatch):
    created=[]
    def create(root,**kwargs):
        value=make(monkeypatch,root,**kwargs); created.append(value); return value
    yield create
    for value in created: cleanup(value)


def prepare(value,phase='activate'):
    preview=value.workflow.preview(phase,**identity(value))
    authorized=value.workflow.authorize(preview['preview_ref'],**identity(value))
    return preview,authorized


def run(value,phase='activate'):
    preview,authorized=prepare(value,phase)
    return value.workflow.execute(authorized['authorization_ref'],**identity(value)),authorized


def test_two_independent_grants_restore_mode_and_keep_historical_query_non_dispatching(factory,tmp_path):
    value=factory(tmp_path)
    for phase in PHASES:
        result,authorized=run(value,phase); assert result['outcome']=='succeeded' and not result['native_backend_qualified']
        before=(len(value.peer.calls),len(value.calls),list(value.backend.sends)); value.workflow._enabled[phase]=False
        assert value.workflow.execute(authorized['authorization_ref'],**identity(value))['idempotent_replay']
        assert (len(value.peer.calls),len(value.calls),value.backend.sends)==before
    outcome=value.workflow.outcome(**identity(value))
    assert outcome['workflow_outcome']=='verified_locally' and outcome['execution_claims']==2 and outcome['declared_duration_verified_locally'] is True
    assert not outcome['live_configuration_verified'] and not outcome['native_backend_qualified'] and not value.owner.logout_verified
    assert all(marker not in json.dumps(outcome) for marker in (ACTOR,SERIAL,PRIVATE,REASON,COOKIE))


@pytest.mark.parametrize('options',[dict(policy_enabled=False),dict(policy_source=False),dict(workflow_enabled=False)])
def test_closed_policy_source_or_phase_gate_precedes_grants_and_mutation(factory,tmp_path,options):
    value=factory(tmp_path,**options); preview=value.workflow.preview('activate',**identity(value))
    with pytest.raises(ValueError): value.workflow.authorize(preview['preview_ref'],**identity(value))
    assert value.calls==value.backend.sends==[] and value.store.claim_count==0


@pytest.mark.parametrize('purpose',PURPOSES)
def test_exit_needs_its_own_permission_intent_and_policy(factory,tmp_path,purpose):
    value=factory(tmp_path); run(value)
    value.allowed.remove((value.policy.reference_for('deactivate',purpose),'glass_break_'+purpose))
    preview=value.workflow.preview('deactivate',**identity(value))
    with pytest.raises(ValueError): value.workflow.authorize(preview['preview_ref'],**identity(value))
    assert value.backend.sends==[False] and value.store.claim_count==1


@pytest.mark.parametrize('field',['requester_digest','transport_digest','root_digest','summary_digest','parameters_digest',
    'expected_current_digest','expected_state_digest','target_ref','adapter_ref','action_id'])
def test_forged_preview_context_is_not_signed(factory,tmp_path,field):
    value=factory(tmp_path); value.workflow.preview('activate',**identity(value))
    with pytest.raises(M4AuthorizationDenied): value.policy.authorize(replace(value.workflow._previews['activate'],**{field:'f'*64}))
    assert value.backend.sends==[] and value.store.claim_count==0


@pytest.mark.parametrize('fault',[dict(reference_digest='f'*64),dict(reference_kind='foreign_kind'),dict(requester_digest='f'*64),
    dict(environment_digest='f'*64),dict(scope_digest='f'*64),dict(authority_ref='foreign-authority'),dict(checked_at=999)])
def test_reference_reply_must_match_original_scope_and_time(factory,tmp_path,fault):
    value=factory(tmp_path); value.faults[0]=fault; preview=value.workflow.preview('activate',**identity(value))
    with pytest.raises(ValueError): value.workflow.authorize(preview['preview_ref'],**identity(value))
    assert value.backend.sends==[] and value.store.claim_count==0


@pytest.mark.parametrize('fault',['lost-ack','interrupt'])
def test_unknown_or_interrupted_activation_freezes_exit_but_queries_stay_available(factory,tmp_path,fault):
    value=factory(tmp_path); _,authorized=prepare(value); value.backend.fault=fault
    if fault=='interrupt':
        with pytest.raises(KeyboardInterrupt): value.workflow.execute(authorized['authorization_ref'],**identity(value))
    else: assert value.workflow.execute(authorized['authorization_ref'],**identity(value))['outcome']=='reconciliation_required'
    value.backend.fault=None
    with pytest.raises(ValueError): value.workflow.preview('deactivate',**identity(value))
    before=(len(value.peer.calls),len(value.calls),list(value.backend.sends))
    outcome=value.workflow.outcome(**identity(value)); assert outcome['workflow_outcome']=='reconciliation_required' and outcome['active_mode_may_remain']
    assert (len(value.peer.calls),len(value.calls),value.backend.sends)==before
    if fault=='interrupt':
        with pytest.raises(ValueError): value.workflow.execute(authorized['authorization_ref'],**identity(value))
    else: assert value.workflow.execute(authorized['authorization_ref'],**identity(value))['idempotent_replay']


def test_final_grant_revocation_prevents_send_and_does_not_hide_owned_outcome(factory,tmp_path):
    value=factory(tmp_path); _,authorized=prepare(value)
    def revoked(): value.allowed.remove((value.policy.reference_for('activate','permission'),'glass_break_permission'))
    value.backend.before=revoked
    assert value.workflow.execute(authorized['authorization_ref'],**identity(value))['outcome']=='reconciliation_required'
    assert value.backend.sends==[]
    before=(len(value.peer.calls),len(value.calls)); assert value.workflow.outcome(**identity(value))['workflow_outcome']=='reconciliation_required'
    assert (len(value.peer.calls),len(value.calls))==before


def test_active_overdue_expired_and_late_exit_outcomes_do_not_infer_native_expiry(factory,tmp_path):
    value=factory(tmp_path); assert value.workflow.outcome(**identity(value))['workflow_outcome']=='not_started'; run(value)
    assert value.workflow.outcome(**identity(value))['workflow_outcome']=='active_locally'
    advance(value.peer,40); assert value.workflow.outcome(**identity(value))['workflow_outcome']=='deactivation_required'
    result,_=run(value,'deactivate')
    assert result['outcome']=='succeeded' and result['declared_duration_verified_locally'] is False
    outcome=value.workflow.outcome(**identity(value))
    assert outcome['workflow_outcome']=='exited_after_declared_duration_locally' and outcome['phase_verified_locally']['deactivate']


def test_expired_window_requires_out_of_band_recovery_without_login_or_actor_read(factory,tmp_path):
    value=factory(tmp_path); run(value); advance(value.peer,60); before=(len(value.peer.calls),len(value.calls))
    outcome=value.workflow.outcome(**identity(value))
    assert outcome['workflow_outcome']=='out_of_band_recovery_required' and outcome['original_window_expired_locally']
    assert outcome['active_mode_may_remain'] and (len(value.peer.calls),len(value.calls))==before
    assert value.peer.credentials==0 and not value.owner.logout_verified


def test_expired_unused_short_grant_refreshes_only_before_claim_or_dispatch(factory,tmp_path):
    value=factory(tmp_path); value.expiry[0]=1005; _,old=prepare(value); advance(value.peer,6)
    with pytest.raises(ValueError): value.workflow.execute(old['authorization_ref'],**identity(value))
    value.expiry[0]=1070; _,new=prepare(value); assert old['authorization_ref']!=new['authorization_ref']
    assert value.workflow.execute(new['authorization_ref'],**identity(value))['outcome']=='succeeded'
    with pytest.raises(ValueError): value.workflow.execute(old['authorization_ref'],**identity(value))
    assert value.store.claim_count==1 and value.backend.sends==[False]


def test_preview_binds_duration_recovery_and_all_resource_impact_without_private_reason(factory,tmp_path):
    value=factory(tmp_path); public=value.workflow.preview('activate',**identity(value)); text=json.dumps(public)
    assert public['Proposed Changes']['maximum_elevation_seconds']==30 and public['Proposed Changes']['exit_reserve_seconds']==10
    assert public['Security Changes']['late_exit_allowed_with_separate_authority'] and not public['Security Changes']['native_automatic_expiry_verified']
    assert public['parent_intent']['Security Changes']['cleartext_access_becomes_possible']
    assert all(marker not in text for marker in (ACTOR,SERIAL,PRIVATE,REASON,COOKIE))


@pytest.mark.parametrize('fault',['rollback','epoch-error','monotonic-error'])
def test_missing_clock_evidence_is_not_reported_as_timely_or_currently_inactive(factory,tmp_path,monkeypatch,fault):
    value=factory(tmp_path); run(value)
    if fault=='rollback': value.clock.value-=1
    else:
        def failed(): raise RuntimeError(PRIVATE)
        monkeypatch.setattr(value.source,'_clock' if fault=='epoch-error' else '_http_clock',failed)
    outcome=value.workflow.outcome(**identity(value))
    assert outcome['workflow_outcome']=='out_of_band_recovery_required' and outcome['original_window_expired_locally'] is None
    assert outcome['declared_duration_verified_locally'] is None and outcome['active_mode_may_remain']


@pytest.mark.parametrize('clock,elapsed',[('epoch',31),('monotonic',31),('both',61)])
def test_query_clock_high_water_and_fault_latch_cannot_restore_active_status(factory,tmp_path,clock,elapsed):
    value=factory(tmp_path); run(value); advance(value.peer,elapsed)
    first=value.workflow.outcome(**identity(value))
    assert first['workflow_outcome']==('out_of_band_recovery_required' if elapsed==61 else 'deactivation_required')
    before=(len(value.peer.calls),len(value.calls),list(value.backend.sends))
    if clock in ('epoch','both'): value.clock.value-=elapsed-20
    if clock in ('monotonic','both'): value.peer.time-=elapsed-20
    for _ in range(2):
        outcome=value.workflow.outcome(**identity(value))
        assert outcome['workflow_outcome']=='out_of_band_recovery_required' and outcome['original_window_expired_locally'] is None
        advance(value.peer,elapsed)
    assert (len(value.peer.calls),len(value.calls),value.backend.sends)==before


@pytest.mark.parametrize('elapsed,expected',[(10,None),(31,False)])
@pytest.mark.parametrize('query_after_rollback',[True,False])
def test_exit_cannot_promote_duration_after_observed_clock_fault_or_deadline(factory,tmp_path,elapsed,expected,query_after_rollback):
    value=factory(tmp_path); run(value); advance(value.peer,elapsed); value.workflow.outcome(**identity(value))
    advance(value.peer,-5 if elapsed==10 else -11)
    if query_after_rollback: assert value.workflow.outcome(**identity(value))['workflow_outcome']=='out_of_band_recovery_required'
    result,authorization=run(value,'deactivate')
    assert value.session._duration_verified_locally is True and result['declared_duration_verified_locally'] is expected
    before=(len(value.peer.calls),len(value.calls),list(value.backend.sends)); advance(value.peer,100)
    outcome=value.workflow.outcome(**identity(value)); replay=value.workflow.execute(authorization['authorization_ref'],**identity(value))
    assert outcome['declared_duration_verified_locally'] is replay['declared_duration_verified_locally'] is expected
    assert outcome['workflow_outcome']==('exited_after_declared_duration_locally' if expected is False else 'reconciliation_required')
    assert not outcome['active_mode_may_remain'] and (len(value.peer.calls),len(value.calls),value.backend.sends)==before


def test_clock_failure_after_sealed_exit_does_not_change_historical_duration(factory,tmp_path,monkeypatch):
    value=factory(tmp_path); run(value); result,authorization=run(value,'deactivate')
    def failed(): raise RuntimeError(PRIVATE)
    monkeypatch.setattr(value.source,'_clock',failed)
    outcome=value.workflow.outcome(**identity(value)); replay=value.workflow.execute(authorization['authorization_ref'],**identity(value))
    assert outcome['workflow_outcome']=='verified_locally' and outcome['original_window_expired_locally'] is None
    assert outcome['declared_duration_verified_locally'] is result['declared_duration_verified_locally'] is replay['declared_duration_verified_locally'] is True


def test_observed_clock_fault_prevents_new_activation_even_after_clock_recovers(factory,tmp_path):
    value=factory(tmp_path); value.clock.value-=1
    assert value.workflow.outcome(**identity(value))['workflow_outcome']=='not_started'
    value.clock.value+=1
    preview=value.workflow.preview('activate',**identity(value))
    with pytest.raises(ValueError): value.workflow.authorize(preview['preview_ref'],**identity(value))
    assert value.calls==value.backend.sends==[] and value.store.claim_count==0


def test_query_still_requires_original_operator_client_and_ledger_integrity(factory,tmp_path):
    value=factory(tmp_path); run(value)
    for caller in (dict(requester_digest='f'*64,transport_digest=value.transport),dict(requester_digest=value.requester,transport_digest='f'*64)):
        with pytest.raises(ValueError): value.workflow.outcome(**caller)
    value.store._key_path.write_bytes(b'x'*32)
    with pytest.raises(ValueError): value.workflow.outcome(**identity(value))


def test_workflow_cannot_be_rebound_to_existing_session(factory,tmp_path):
    value=factory(tmp_path)
    with pytest.raises(ValueError): GlassBreakLocalWorkflow(value.session,allowed_transport_digest=value.transport)
    assert value.session._workflow is value.workflow


def test_signing_key_cannot_reuse_execution_ledger_key(factory,tmp_path):
    with pytest.raises(M4AuthorizationDenied): factory(tmp_path,signing_key=b'synthetic-system-email-state-key-01')
