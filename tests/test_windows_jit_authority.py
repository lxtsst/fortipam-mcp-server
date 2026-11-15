"""Fixed six-step private workflow and protected policy; eligibility is synthetic."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import json

import pytest

from fortipam_mcp.reference_authority_sidecar import UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings
from fortipam_mcp.windows_jit_authority import WindowsJitProtectedLabAuthority, PURPOSES
from fortipam_mcp.windows_jit_local_workflow import WindowsJitLocalBundle, WindowsJitLocalWorkflow, PHASES
from fortipam_mcp.windows_jit_secret_contract import _schema, _types
from fortipam_mcp.windows_jit_secret_m4 import JitSecretExecutionScope
from fortipam_mcp.windows_jit_secret_source import WindowsJitSecretSource, SCHEMA_PATH
from fortipam_mcp.windows_jit_script_m4 import JitScriptExecutionScope, WindowsJitScriptM4Session
from test_system_email_m4_adapter import store_at
from test_system_email_authority import owner_file
from test_windows_jit_script_m4 import Backend as ScriptBackend, Evidence as ScriptEvidence
from test_windows_jit_script_source import Peer
from test_windows_jit_secret_m4 import Backend as SecretBackend, Evidence as SecretEvidence
from test_windows_jit_secret_contract import fixture, binding, envelope, SERIAL, SECRET
from v4_planning import M4AuthorizationDenied, VerifiedReferenceDecision, canonical_digest

REFERENCE = 'windows-jit-test-reference-authority'
TRANSPORT = '9'*64
ENVIRONMENT,SCOPE_REF,AUDIENCE = 'windows-jit-test-environment','windows-jit-test-scope','windows-jit-test-audience'


def construct(root,client,*,transport=TRANSPORT,requester=None,opened=None,policy_enabled=True,workflow_enabled=True,
        policy_source=True,signing_key=b'p'*32,peer=None,source=None,script_backend_factory=None,secret_backend_factory=None):
    peer = peer or Peer(); source = source or peer.source()
    script_store = opened[0] if opened is not None else store_at(root)
    script_backend = ScriptBackend(peer) if script_backend_factory is None else script_backend_factory(source)
    scripts = WindowsJitScriptM4Session(source,source.prepare_plan(),
        JitScriptExecutionScope('1'*64,requester or '2'*64,'3'*64,'4'*64,'a'*64,'b'*64,'c'*64),
        script_backend,ScriptEvidence(peer.clock),script_store,source_guard=lambda:True,clock=peer.clock)
    schema,row = fixture()
    if hasattr(peer,'secret_row'): schema,row = peer.payloads[SCHEMA_PATH],peer.secret_row
    peer.payloads[SCHEMA_PATH] = schema
    secret_source = WindowsJitSecretSource(scripts._source,binding(),expected_schema_digest=canonical_digest(_types(_schema(schema,SERIAL))),
        source_digest='b'*64,source_guard=lambda:True)
    peer.payloads[secret_source._detail] = envelope(row)
    secret_scope = JitSecretExecutionScope('3'*64,scripts._scope.requester_digest,'5'*64,'6'*64,'b'*64,'d'*64,'e'*64,'f'*64,'1'*64)
    if opened is None:
        (root/'secret').mkdir(mode=0o700); secret_store = store_at(root/'secret')
    else: secret_store = opened[1]
    secret_backend,secret_evidence = SecretBackend(peer,row),SecretEvidence(peer.clock)
    created_backends = []
    def backend_for(plan):
        backend = secret_backend if secret_backend_factory is None else secret_backend_factory(secret_source,plan)
        created_backends.append(backend); return backend
    bundle = WindowsJitLocalBundle(scripts,secret_source,secret_scope,secret_evidence,secret_store,
        backend_for,source_guard=lambda:True)
    key = owner_file(root/'policy.key',signing_key)
    policy = WindowsJitProtectedLabAuthority(bundle,reference_authority=client,authority_key_file=key,transport_digest=transport,
        environment_ref=ENVIRONMENT,scope_ref=SCOPE_REF,audience_ref=AUDIENCE,execution_enabled=policy_enabled,
        source_guard=(lambda:True) if policy_source else None)
    workflow = WindowsJitLocalWorkflow(bundle,allowed_transport_digest=transport,authority=policy,
        enabled_phases=PHASES if workflow_enabled else (),source_guard=lambda:True)
    return SimpleNamespace(bundle=bundle,workflow=workflow,policy=policy,peer=peer,script_backend=script_backend,
        secret_backend=secret_backend,secret_evidence=secret_evidence,clock=peer.clock,script_store=script_store,
        secret_store=secret_store,requester=scripts._scope.requester_digest,transport=transport,key=key,created_backends=created_backends)


def identity(value): return dict(requester_digest=value.requester,transport_digest=value.transport)


def make(monkeypatch,root,**kwargs):
    client = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(Path('/private/tmp/windows-jit-unit.sock'),REFERENCE))
    monkeypatch.setattr(client,'verify_ready',lambda:None)
    allowed,calls,expiry,faults = set(),[],[2000],[None]
    def authorize(ref,*,reference_kind,requester_digest,environment_ref,scope_ref,now_epoch):
        calls.append((ref,reference_kind)); authorized = (ref,reference_kind) in allowed and now_epoch < expiry[0]
        fields = dict(reference_digest=canonical_digest(ref),reference_kind=reference_kind,authority_ref=REFERENCE,
            requester_digest=requester_digest,environment_digest=canonical_digest(environment_ref),scope_digest=canonical_digest(scope_ref),
            authorized=authorized,checked_at=now_epoch,expires_at=min(now_epoch+60,expiry[0]) if authorized else now_epoch+60)
        if faults[0]: fields.update(faults[0])
        return VerifiedReferenceDecision(**fields)
    monkeypatch.setattr(client,'authorize',authorize)
    value = construct(root,client,**kwargs)
    for phase in PHASES:
        for purpose in PURPOSES: allowed.add((value.policy.reference_for(phase,purpose),'windows_jit_'+purpose))
    value.allowed,value.calls,value.expiry,value.faults,value.client = allowed,calls,expiry,faults,client
    return value


def run(value,phase):
    preview = value.workflow.preview(phase,**identity(value))
    authorization = value.workflow.authorize(phase,preview['preview_ref'],**identity(value))
    return value.workflow.execute(phase,authorization['authorization_ref'],**identity(value)),authorization


def test_six_independently_authorized_phases_restore_configuration_and_both_original_definitions(monkeypatch,tmp_path):
    value = make(monkeypatch,tmp_path)
    for phase in PHASES:
        result,authorization = run(value,phase)
        assert result['outcome'] == 'succeeded' and not result['native_backend_qualified']
        before = (len(value.peer.calls),len(value.calls))
        value.workflow._enabled[phase] = False
        assert value.workflow.execute(phase,authorization['authorization_ref'],**identity(value))['idempotent_replay']
        assert (len(value.peer.calls),len(value.calls)) == before
    outcome = value.workflow.outcome(**identity(value))
    assert outcome['workflow_outcome'] == 'verified_locally' and not outcome['jit_privilege_effect_verified']
    assert (value.script_store.claim_count,value.secret_store.claim_count) == (4,2)
    assert value.script_backend.sends == [(0,False),(1,False),(1,True),(0,True)] and value.secret_backend.sends == [False,True]
    assert value.peer.rows == [value.peer.rows[0]] and all(not any(raw) for raw in value.script_backend.buffers+value.secret_backend.buffers)
    assert SECRET not in json.dumps(outcome)


@pytest.mark.parametrize('options',[dict(policy_enabled=False),dict(policy_source=False),dict(workflow_enabled=False)])
def test_default_closed_policy_source_and_workflow_gates_precede_authority_and_mutation(monkeypatch,tmp_path,options):
    value = make(monkeypatch,tmp_path,**options); preview = value.workflow.preview('grant_create',**identity(value))
    with pytest.raises(ValueError): value.workflow.authorize('grant_create',preview['preview_ref'],**identity(value))
    assert value.calls == value.script_backend.sends == [] and value.script_store.claim_count == 0


@pytest.mark.parametrize('purpose',PURPOSES)
def test_each_step_needs_separate_permission_intent_and_lab_policy(monkeypatch,tmp_path,purpose):
    value = make(monkeypatch,tmp_path); run(value,'grant_create')
    value.allowed.remove((value.policy.reference_for('revoke_create',purpose),'windows_jit_'+purpose))
    preview = value.workflow.preview('revoke_create',**identity(value))
    with pytest.raises(ValueError): value.workflow.authorize('revoke_create',preview['preview_ref'],**identity(value))
    assert value.script_backend.sends == [(0,False)] and value.secret_store.claim_count == 0


@pytest.mark.parametrize('field',['requester_digest','transport_digest','root_digest','summary_digest','parameters_digest',
    'expected_current_digest','expected_state_digest','target_ref','adapter_ref','action_id'])
def test_forged_preview_binding_is_not_signed(monkeypatch,tmp_path,field):
    value = make(monkeypatch,tmp_path); value.workflow.preview('grant_create',**identity(value))
    with pytest.raises(M4AuthorizationDenied):
        value.policy.authorize(replace(value.workflow._previews['grant_create'],**{field:'f'*64}))
    assert value.calls == value.script_backend.sends == []


@pytest.mark.parametrize('field',['reference_digest','reference_kind','authority_ref','requester_digest','environment_digest','scope_digest'])
def test_foreign_protected_decision_cannot_supply_a_step_grant(monkeypatch,tmp_path,field):
    value = make(monkeypatch,tmp_path); value.faults[0] = {field:'f'*64 if field.endswith('digest') else 'foreign'}
    preview = value.workflow.preview('grant_create',**identity(value))
    with pytest.raises(ValueError): value.workflow.authorize('grant_create',preview['preview_ref'],**identity(value))
    assert value.script_backend.sends == [] and value.script_store.claim_count == 0


def test_final_guard_rechecks_revocation_and_query_cannot_replay_after_regrant(monkeypatch,tmp_path):
    value = make(monkeypatch,tmp_path)
    ref = (value.policy.reference_for('grant_create','permission'),'windows_jit_permission')
    value.script_backend.before = lambda:value.allowed.remove(ref)
    result,authorization = run(value,'grant_create')
    assert result['outcome'] != 'succeeded' and value.script_backend.sends == [] and value.script_store.claim_count == 1
    value.allowed.add(ref)
    assert value.workflow.execute('grant_create',authorization['authorization_ref'],**identity(value))['idempotent_replay']
    with pytest.raises(ValueError): value.workflow.preview('grant_create',**identity(value))


def test_final_guard_checks_the_workflow_gate_after_durable_reservation(monkeypatch,tmp_path):
    value = make(monkeypatch,tmp_path)
    value.script_backend.before = lambda:value.workflow._enabled.update(grant_create=False)
    assert run(value,'grant_create')[0]['outcome'] != 'succeeded' and value.script_backend.sends == []
    assert value.script_store.claim_count == 1


def test_second_unknown_preserves_only_the_first_original_cleanup_and_keeps_its_result(monkeypatch,tmp_path):
    value = make(monkeypatch,tmp_path); run(value,'grant_create'); value.script_backend.fault = 'lost-ack'
    result,authorization = run(value,'revoke_create'); assert result['outcome'] == 'reconciliation_required'
    value.script_backend.fault = None
    for phase in ('configure','revoke_remove'):
        with pytest.raises(ValueError): value.workflow.preview(phase,**identity(value))
    assert run(value,'grant_remove')[0]['outcome'] == 'succeeded'
    assert value.workflow.execute('revoke_create',authorization['authorization_ref'],**identity(value))['idempotent_replay']
    assert value.workflow.outcome(**identity(value))['workflow_outcome'] == 'reconciliation_required'
    assert (value.script_store.claim_count,value.secret_store.claim_count) == (3,0)


def test_interruption_remains_consumed_without_a_live_process_assumption(monkeypatch,tmp_path):
    value = make(monkeypatch,tmp_path); value.script_backend.fault = 'interrupt'
    preview = value.workflow.preview('grant_create',**identity(value))
    authorization = value.workflow.authorize('grant_create',preview['preview_ref'],**identity(value))
    with pytest.raises(KeyboardInterrupt): value.workflow.execute('grant_create',authorization['authorization_ref'],**identity(value))
    with pytest.raises(ValueError): value.workflow.execute('grant_create',authorization['authorization_ref'],**identity(value))
    with pytest.raises(ValueError): value.workflow.preview('grant_remove',**identity(value))
    assert value.workflow.outcome(**identity(value))['workflow_outcome'] == 'reconciliation_required'


def test_preview_can_refresh_after_ten_second_source_ttl_before_any_authorization_or_claim(monkeypatch,tmp_path):
    value = make(monkeypatch,tmp_path); preview = value.workflow.preview('grant_create',**identity(value))
    value.clock.value += 20
    authorization = value.workflow.authorize('grant_create',preview['preview_ref'],**identity(value))
    assert value.workflow.execute('grant_create',authorization['authorization_ref'],**identity(value))['outcome'] == 'succeeded'
    assert value.script_store.claim_count == 1


@pytest.mark.parametrize('fault',['foreign-actor','foreign-client','key','clock'])
def test_changed_identity_or_policy_binding_denies_before_claim(monkeypatch,tmp_path,fault):
    value = make(monkeypatch,tmp_path); selected = identity(value)
    preview = value.workflow.preview('grant_create',**selected)
    if fault == 'foreign-actor': selected['requester_digest'] = 'f'*64
    elif fault == 'foreign-client': selected['transport_digest'] = 'f'*64
    elif fault == 'key': value.key.write_bytes(b'q'*32)
    else: value.clock.value -= 1
    with pytest.raises(ValueError): value.workflow.authorize('grant_create',preview['preview_ref'],**selected)
    assert value.script_backend.sends == [] and value.script_store.claim_count == 0


def test_same_original_session_cannot_bind_another_bundle_or_replace_secret_journal(monkeypatch,tmp_path):
    value = make(monkeypatch,tmp_path); b = value.bundle
    with pytest.raises(ValueError):
        WindowsJitLocalBundle(b._scripts,b._source,b._scope,b._evidence,b._store,b._factory,source_guard=lambda:True)
    assert value.script_store.claim_count == value.secret_store.claim_count == 0


@pytest.mark.parametrize('phase',['grant_create','restore'])
def test_only_expired_unused_grants_can_be_renewed_without_reopening_consumed_positions(monkeypatch,tmp_path,phase):
    value = make(monkeypatch,tmp_path)
    if phase == 'restore':
        for previous in PHASES[:3]: assert run(value,previous)[0]['outcome'] == 'succeeded'
    value.expiry[0] = 1010
    preview = value.workflow.preview(phase,**identity(value))
    authorization = value.workflow.authorize(phase,preview['preview_ref'],**identity(value))
    with pytest.raises(ValueError): value.workflow.preview(phase,**identity(value))
    before = (value.script_store.claim_count,value.secret_store.claim_count)
    value.clock.value = 1010
    with pytest.raises(ValueError): value.workflow.execute(phase,authorization['authorization_ref'],**identity(value))
    assert (value.script_store.claim_count,value.secret_store.claim_count) == before
    value.expiry[0] = 1070
    renewed,updated = run(value,phase)
    assert renewed['outcome'] == 'succeeded' and updated['authorization_ref'] != authorization['authorization_ref']
    with pytest.raises(ValueError): value.workflow.execute(phase,authorization['authorization_ref'],**identity(value))
    adapter,_ = value.workflow._adapters[phase]
    value.clock.value = 1100
    with pytest.raises(ValueError): value.bundle.release_expired_unused(phase,adapter)


@pytest.mark.parametrize('fault',['lost-ack','interrupt'])
def test_consumed_or_interrupted_script_grant_cannot_use_the_unused_expiry_path(monkeypatch,tmp_path,fault):
    value = make(monkeypatch,tmp_path); preview = value.workflow.preview('grant_create',**identity(value))
    authorization = value.workflow.authorize('grant_create',preview['preview_ref'],**identity(value))
    value.script_backend.fault = fault
    if fault == 'interrupt':
        with pytest.raises(KeyboardInterrupt): value.workflow.execute('grant_create',authorization['authorization_ref'],**identity(value))
    else: assert value.workflow.execute('grant_create',authorization['authorization_ref'],**identity(value))['outcome'] == 'reconciliation_required'
    adapter,_ = value.workflow._adapters['grant_create']; value.clock.value = 1100
    with pytest.raises(ValueError): value.bundle.release_expired_unused('grant_create',adapter)
    with pytest.raises(ValueError): value.workflow.preview('grant_create',**identity(value))
    assert value.script_store.claim_count == 1


def test_a_new_directory_cannot_inherit_the_original_reference_grants(monkeypatch,tmp_path):
    original = tmp_path/'original'; original.mkdir(mode=0o700); value = make(monkeypatch,original)
    root = tmp_path/'replacement'; root.mkdir(mode=0o700); replacement = construct(root,value.client)
    assert replacement.policy.reference_for('grant_create','permission') != value.policy.reference_for('grant_create','permission')
    preview = replacement.workflow.preview('grant_create',**identity(replacement))
    with pytest.raises(ValueError): replacement.workflow.authorize('grant_create',preview['preview_ref'],**identity(replacement))
    assert replacement.script_store.claim_count == replacement.secret_store.claim_count == 0
