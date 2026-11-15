"""Protected per-step policy and workflow; product eligibility remains synthetic."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import json

import pytest

from fortipam_mcp.email_alert_authority import EmailAlertProtectedLabAuthority,PURPOSES
from fortipam_mcp.email_alert_local_workflow import EmailAlertLocalWorkflow,PHASES
from fortipam_mcp.email_alert_m4 import EmailAlertExecutionScope,EmailAlertM4Session
from fortipam_mcp.reference_authority_sidecar import UnixReferenceAuthorityClient,UnixReferenceAuthorityClientSettings
from test_email_alert_compound_source import candidate as source_candidate
from test_email_alert_general_contract import SERIAL,SENDER,RECIPIENT,PRIVATE
from test_email_alert_m4 import Backend,Evidence
from test_system_email_authority import owner_file
from test_system_email_m4_adapter import store_at
from v4_planning import M4AuthorizationDenied,VerifiedReferenceDecision,canonical_digest

REFERENCE='email-alert-test-reference-authority'
TRANSPORT='9'*64
ENVIRONMENT,SCOPE_REF,AUDIENCE='email-alert-test-environment','email-alert-test-scope','email-alert-test-audience'


def construct(root,client,*,requester='2'*64,transport=TRANSPORT,policy_enabled=True,workflow_enabled=True,
        policy_source=True,signing_key=b'p'*32,source=None,peer=None,store=None,backend_factory=None):
    if source is None: peer,source,_=source_candidate()
    initial=source.prepare_plan(); backend=Backend(peer) if backend_factory is None else backend_factory(source,initial)
    evidence=Evidence(peer.clock); store=store or store_at(root)
    session=EmailAlertM4Session(source,initial,EmailAlertExecutionScope('1'*64,requester,canonical_digest(SCOPE_REF),canonical_digest(AUDIENCE),
        'b'*64,'c'*64,'d'*64),backend,evidence,store,source_guard=lambda:True,clock=peer.clock)
    key=owner_file(root/'policy.key',signing_key)
    policy=EmailAlertProtectedLabAuthority(session,reference_authority=client,authority_key_file=key,transport_digest=transport,
        environment_ref=ENVIRONMENT,scope_ref=SCOPE_REF,audience_ref=AUDIENCE,execution_enabled=policy_enabled,
        source_guard=(lambda:True) if policy_source else None)
    workflow=EmailAlertLocalWorkflow(session,allowed_transport_digest=transport,authority=policy,
        enabled_phases=PHASES if workflow_enabled else (),source_guard=lambda:True)
    return SimpleNamespace(session=session,workflow=workflow,policy=policy,peer=peer,backend=backend,evidence=evidence,store=store,
        clock=peer.clock,requester=requester,transport=transport,key=key)


def identity(value): return dict(requester_digest=value.requester,transport_digest=value.transport)


def make(monkeypatch,root,**kwargs):
    client=UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(Path('/private/tmp/email-alert-unit.sock'),REFERENCE))
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
        for purpose in PURPOSES: allowed.add((value.policy.reference_for(phase,purpose),'email_alert_'+purpose))
    value.allowed,value.calls,value.expiry,value.faults,value.client=allowed,calls,expiry,faults,client
    return value


def prepare(value,phase=('general',False)):
    preview=value.workflow.preview(phase[0],restore=phase[1],**identity(value))
    authorized=value.workflow.authorize(preview['preview_ref'],**identity(value))
    return preview,authorized


def run(value,phase=('general',False)):
    preview,authorized=prepare(value,phase)
    return value.workflow.execute(authorized['authorization_ref'],**identity(value)),authorized


def test_all_sixteen_independently_authorized_steps_restore_original_graph(monkeypatch,tmp_path):
    value=make(monkeypatch,tmp_path)
    for phase in PHASES:
        result,authorized=run(value,phase); assert result['outcome']=='succeeded' and not result['native_backend_qualified']
        before=(len(value.peer.calls),len(value.calls),list(value.backend.sends)); value.workflow._enabled[phase]=False
        assert value.workflow.execute(authorized['authorization_ref'],**identity(value))['idempotent_replay']
        assert (len(value.peer.calls),len(value.calls),value.backend.sends)==before
    outcome=value.workflow.outcome(**identity(value))
    assert outcome['workflow_outcome']=='verified_locally' and outcome['execution_claims']==16
    assert not outcome['native_backend_qualified'] and not outcome['delivery_verified']
    assert value.session._source.read().state.digest==value.session._initial.baseline.digest
    assert all(marker not in json.dumps(outcome) for marker in (SERIAL,SENDER,RECIPIENT,PRIVATE,'Original glass','old.cert'))


@pytest.mark.parametrize('options',[dict(policy_enabled=False),dict(policy_source=False),dict(workflow_enabled=False)])
def test_closed_policy_source_and_phase_gates_deny_before_grants_or_writes(monkeypatch,tmp_path,options):
    value=make(monkeypatch,tmp_path,**options); preview=value.workflow.preview('general',**identity(value))
    with pytest.raises(ValueError): value.workflow.authorize(preview['preview_ref'],**identity(value))
    assert value.calls==value.backend.sends==[] and value.store.claim_count==0


@pytest.mark.parametrize('purpose',PURPOSES)
def test_next_forward_and_own_reverse_need_their_separate_three_grants(monkeypatch,tmp_path,purpose):
    value=make(monkeypatch,tmp_path); run(value)
    for phase in (('glass_action',False),('general',True)):
        ref=value.policy.reference_for(phase,purpose); value.allowed.remove((ref,'email_alert_'+purpose))
        preview=value.workflow.preview(phase[0],restore=phase[1],**identity(value))
        with pytest.raises(ValueError): value.workflow.authorize(preview['preview_ref'],**identity(value))
    assert value.backend.sends==[('general',False)] and value.store.claim_count==1


@pytest.mark.parametrize('field',['requester_digest','transport_digest','root_digest','summary_digest','parameters_digest',
    'expected_current_digest','expected_state_digest','target_ref','adapter_ref','action_id'])
def test_forged_preview_binding_is_not_signed(monkeypatch,tmp_path,field):
    value=make(monkeypatch,tmp_path); value.workflow.preview('general',**identity(value))
    with pytest.raises(M4AuthorizationDenied):
        value.policy.authorize(replace(value.workflow._previews[('general',False)],**{field:'f'*64}))
    assert value.backend.sends==[] and value.store.claim_count==0


@pytest.mark.parametrize('fault',[dict(reference_digest='f'*64),dict(reference_kind='foreign_kind'),dict(requester_digest='f'*64),
    dict(environment_digest='f'*64),dict(scope_digest='f'*64),dict(authority_ref='foreign-authority'),dict(checked_at=999)])
def test_reference_decision_must_match_full_original_binding(monkeypatch,tmp_path,fault):
    value=make(monkeypatch,tmp_path); value.faults[0]=fault
    preview=value.workflow.preview('general',**identity(value))
    with pytest.raises(ValueError): value.workflow.authorize(preview['preview_ref'],**identity(value))
    assert value.backend.sends==[] and value.store.claim_count==0


def test_last_moment_grant_revocation_blocks_send_but_owned_query_stays_available(monkeypatch,tmp_path):
    value=make(monkeypatch,tmp_path); _,authorized=prepare(value)
    def revoked():
        value.allowed.remove((value.policy.reference_for(('general',False),'permission'),'email_alert_permission'))
    value.backend.before=revoked
    result=value.workflow.execute(authorized['authorization_ref'],**identity(value)); assert result['outcome']=='reconciliation_required'
    assert value.backend.sends==[] and value.store.claim_count==1
    with pytest.raises(ValueError): value.workflow.preview('general',restore=True,**identity(value))
    before=(len(value.peer.calls),len(value.calls))
    assert value.workflow.outcome(**identity(value))['workflow_outcome']=='reconciliation_required'
    assert value.workflow.execute(authorized['authorization_ref'],**identity(value))['idempotent_replay']
    assert (len(value.peer.calls),len(value.calls))==before


@pytest.mark.parametrize('fault',['lost-ack','interrupt'])
def test_unknown_or_interrupted_step_cannot_be_replayed_adopted_or_promoted_by_query(monkeypatch,tmp_path,fault):
    value=make(monkeypatch,tmp_path); _,authorized=prepare(value); value.backend.fault=fault
    if fault=='interrupt':
        with pytest.raises(KeyboardInterrupt): value.workflow.execute(authorized['authorization_ref'],**identity(value))
    else: assert value.workflow.execute(authorized['authorization_ref'],**identity(value))['outcome']=='reconciliation_required'
    value.backend.fault=None
    with pytest.raises(ValueError): value.workflow.preview('general',restore=True,**identity(value))
    before=(len(value.peer.calls),len(value.calls),list(value.backend.sends))
    assert value.workflow.outcome(**identity(value))['workflow_outcome']=='reconciliation_required'
    assert (len(value.peer.calls),len(value.calls),value.backend.sends)==before
    if fault=='interrupt':
        with pytest.raises(ValueError): value.workflow.execute(authorized['authorization_ref'],**identity(value))
    else: assert value.workflow.execute(authorized['authorization_ref'],**identity(value))['idempotent_replay']
    assert value.store.claim_count==1


def test_only_expired_unused_unclaimed_authorization_can_refresh(monkeypatch,tmp_path):
    value=make(monkeypatch,tmp_path); value.expiry[0]=1010; _,old=prepare(value)
    with pytest.raises(ValueError): value.workflow.preview('general',**identity(value))
    value.clock.value=1010
    with pytest.raises(ValueError): value.workflow.execute(old['authorization_ref'],**identity(value))
    value.expiry[0]=1070; _,new=prepare(value)
    assert new['authorization_ref']!=old['authorization_ref']
    assert value.workflow.execute(new['authorization_ref'],**identity(value))['outcome']=='succeeded'
    with pytest.raises(ValueError): value.workflow.execute(old['authorization_ref'],**identity(value))
    assert value.store.claim_count==1 and value.backend.sends==[('general',False)]


def test_parent_preview_explains_mail_effect_and_full_fixed_scope_without_identities(monkeypatch,tmp_path):
    value=make(monkeypatch,tmp_path); public=value.workflow.preview('general',**identity(value)); text=json.dumps(public)
    assert public['authorization_policy_mode']=='lab_auto' and public['parent_intent']['Proposed Changes']['ordered_write_steps']==8
    assert public['Security Changes']['configuration_restore_does_not_recall_mail']
    assert not public['execution_authorized'] and not public['native_backend_qualified'] and not public['delivery_verified']
    assert all(marker not in text for marker in (SERIAL,SENDER,RECIPIENT,PRIVATE,'Original glass','old.cert'))


def test_query_requires_original_operator_client_and_sealed_ledger(monkeypatch,tmp_path):
    value=make(monkeypatch,tmp_path); run(value)
    for changed in (dict(requester_digest='f'*64,transport_digest=value.transport),dict(requester_digest=value.requester,transport_digest='f'*64)):
        with pytest.raises(ValueError): value.workflow.outcome(**changed)
    value.store._key_path.write_bytes(b'x'*32)
    with pytest.raises(ValueError): value.workflow.outcome(**identity(value))


def test_workflow_is_unique_and_cannot_be_rebuilt_from_existing_session(monkeypatch,tmp_path):
    value=make(monkeypatch,tmp_path)
    with pytest.raises(ValueError): EmailAlertLocalWorkflow(value.session,allowed_transport_digest=value.transport)
    assert value.session._workflow is value.workflow and value.store.claim_count==0


def test_partial_prefix_recovery_has_its_own_outcome_without_claiming_full_completion(monkeypatch,tmp_path):
    value=make(monkeypatch,tmp_path); run(value); value.clock.value+=100; run(value,('general',True))
    outcome=value.workflow.outcome(**identity(value))
    assert outcome['workflow_outcome']=='partial_prefix_restored_locally' and outcome['execution_claims']==2
    assert not outcome['live_configuration_verified'] and not outcome['delivery_verified']
    with pytest.raises(ValueError): value.workflow.preview('glass_action',**identity(value))


def test_read_elapsed_time_caps_grant_at_the_actual_step_deadline(monkeypatch,tmp_path):
    value=make(monkeypatch,tmp_path); source=value.session._source; read=source.read
    def elapsed():
        result=read(); value.clock.value+=2; return result
    monkeypatch.setattr(source,'read',elapsed)
    preview,authorized=prepare(value)
    assert preview['created_at']==1002 and preview['expires_at']==authorized['expires_at']==1060
    assert preview['expires_at']<preview['created_at']+60
    assert value.workflow.execute(authorized['authorization_ref'],**identity(value))['outcome']=='succeeded'


def test_signing_key_cannot_reuse_execution_key_material(monkeypatch,tmp_path):
    with pytest.raises(M4AuthorizationDenied):
        make(monkeypatch,tmp_path,signing_key=b'synthetic-system-email-state-key-01')


@pytest.mark.parametrize('field',['scope_digest','audience_digest'])
def test_policy_rejects_scope_or_audience_substitution(monkeypatch,tmp_path,field):
    value=make(monkeypatch,tmp_path); value.session._scope=replace(value.session._scope,**{field:'f'*64})
    with pytest.raises(M4AuthorizationDenied):
        EmailAlertProtectedLabAuthority(value.session,reference_authority=value.client,authority_key_file=value.key,
            transport_digest=value.transport,environment_ref=ENVIRONMENT,scope_ref=SCOPE_REF,audience_ref=AUDIENCE,
            execution_enabled=True,source_guard=lambda:True)
