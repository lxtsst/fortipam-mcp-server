"""Protected local SAML issuance; synthetic product and read-only grant peer."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from fortipam_mcp.reference_authority_sidecar import UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings
from fortipam_mcp.saml_server_authority import SamlProtectedLabAuthority, PURPOSES
from fortipam_mcp.saml_server_local_workflow import SamlLocalWorkflow
from test_saml_server_local_m4 import make as m4_candidate, SCOPE
from test_system_email_authority import owner_file
from v4_planning import M4AuthorizationDenied, VerifiedReferenceDecision, canonical_digest

REFERENCE = 'saml-local-test-reference-authority'
TRANSPORT = '9'*64
ENVIRONMENT,SCOPE_REF,AUDIENCE = 'saml-local-test-environment','saml-local-test-scope','saml-local-test-audience'


def construct(root, client, *, scope=SCOPE, transport=TRANSPORT, candidate=None, policy_enabled=True,
              policy_source=True, workflow_enabled=True, signing_key=b'p'*32):
    value = candidate if candidate is not None else m4_candidate(root)
    key = owner_file(root/'policy.key',signing_key)
    policy = SamlProtectedLabAuthority(value.initial,scope,value.backend,value.store,reference_authority=client,
        authority_key_file=key,transport_digest=transport,environment_ref=ENVIRONMENT,scope_ref=SCOPE_REF,audience_ref=AUDIENCE,
        execution_enabled=policy_enabled,source_guard=(lambda: True) if policy_source else None,clock=value.peer.clock)
    workflow = SamlLocalWorkflow(value.initial,scope,value.backend,value.store,allowed_transport_digest=transport,
        authority=policy,create_enabled=workflow_enabled,remove_enabled=workflow_enabled,source_guard=lambda: True,clock=value.peer.clock)
    return SimpleNamespace(candidate=value,policy=policy,workflow=workflow,scope=scope,transport=transport,key=key)


def make(monkeypatch, root, **kwargs):
    client = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(Path('/private/tmp/saml-authority-unit.sock'),REFERENCE))
    monkeypatch.setattr(client,'verify_ready',lambda: None)
    allowed,calls,expiry,faults = set(),[],[1060],[None]
    def authorize(ref, *, reference_kind, requester_digest, environment_ref, scope_ref, now_epoch):
        calls.append((ref,reference_kind))
        authorized = (ref,reference_kind) in allowed and now_epoch < expiry[0]
        fields = dict(reference_digest=canonical_digest(ref),reference_kind=reference_kind,authority_ref=REFERENCE,
            requester_digest=requester_digest,environment_digest=canonical_digest(environment_ref),scope_digest=canonical_digest(scope_ref),
            authorized=authorized,checked_at=now_epoch,expires_at=min(now_epoch+60,expiry[0]) if authorized else now_epoch+60)
        if faults[0]: fields.update(faults[0])
        return VerifiedReferenceDecision(**fields)
    monkeypatch.setattr(client,'authorize',authorize)
    value = construct(root,client,**kwargs)
    for phase in ('create','remove'):
        for purpose in PURPOSES: allowed.add((value.policy.reference_for(phase,purpose),'saml_'+purpose))
    value.allowed,value.calls,value.expiry,value.faults,value.client = allowed,calls,expiry,faults,client
    return value


def identity(value): return dict(requester_digest=value.scope.requester_digest,transport_digest=value.transport)


def run(value, phase):
    preview = value.workflow.preview(phase,**identity(value))
    authorization = value.workflow.authorize(phase,preview['preview_ref'],**identity(value))
    return value.workflow.execute(phase,authorization['authorization_ref'],**identity(value)),authorization


def test_protected_create_and_separately_authorized_remove_keep_original_ownership(monkeypatch, tmp_path):
    value = make(monkeypatch,tmp_path)
    result,authorization = run(value,'create')
    assert result['outcome'] == 'succeeded'
    assert value.workflow.execute('create',authorization['authorization_ref'],**identity(value))['idempotent_replay']
    assert run(value,'remove')[0]['outcome'] == 'succeeded'
    assert value.workflow.outcome(**identity(value))['workflow_outcome'] == 'verified_locally'
    assert value.candidate.store.claim_count == value.candidate.backend.sends == 2


@pytest.mark.parametrize('options', [dict(policy_enabled=False),dict(policy_source=False),dict(workflow_enabled=False)])
def test_each_gate_denies_before_source_reinspection_or_execution(monkeypatch, tmp_path, options):
    value = make(monkeypatch,tmp_path,**options)
    preview = value.workflow.preview('create',**identity(value)); reads = len(value.candidate.peer.calls)
    with pytest.raises(ValueError): value.workflow.authorize('create',preview['preview_ref'],**identity(value))
    assert len(value.candidate.peer.calls) == reads and value.candidate.backend.sends == value.candidate.store.claim_count == 0


@pytest.mark.parametrize('purpose', PURPOSES)
def test_every_grant_and_a_separate_remove_grant_are_required(monkeypatch, tmp_path, purpose):
    value = make(monkeypatch,tmp_path)
    reference = (value.policy.reference_for('create',purpose),'saml_'+purpose); value.allowed.remove(reference)
    preview = value.workflow.preview('create',**identity(value))
    with pytest.raises(ValueError): value.workflow.authorize('create',preview['preview_ref'],**identity(value))
    value.allowed.add(reference); assert run(value,'create')[0]['outcome'] == 'succeeded'
    value.allowed.remove((value.policy.reference_for('remove',purpose),'saml_'+purpose))
    preview = value.workflow.preview('remove',**identity(value))
    with pytest.raises(ValueError): value.workflow.authorize('remove',preview['preview_ref'],**identity(value))
    assert value.candidate.backend.sends == 1


@pytest.mark.parametrize('field', ['summary_digest','parameters_digest','target_ref','requester_digest','transport_digest','expected_current_digest'])
def test_forged_proposals_are_not_signed(monkeypatch, tmp_path, field):
    value = make(monkeypatch,tmp_path); value.workflow.preview('create',**identity(value))
    request = value.workflow._previews['create']
    with pytest.raises(M4AuthorizationDenied): value.policy.authorize(replace(request,**{field:'f'*64}))
    assert value.calls == []


@pytest.mark.parametrize('field', ['reference_kind','reference_digest','requester_digest','authority_ref','environment_digest','scope_digest'])
def test_foreign_reference_decisions_cannot_grant_permission(monkeypatch, tmp_path, field):
    value = make(monkeypatch,tmp_path)
    value.faults[0] = {field:'f'*64 if field.endswith('digest') else 'foreign-reference'}
    preview = value.workflow.preview('create',**identity(value))
    with pytest.raises(ValueError): value.workflow.authorize('create',preview['preview_ref'],**identity(value))
    assert value.candidate.store.claim_count == value.candidate.backend.sends == 0


def test_unconsumed_expired_authorization_can_renew_without_clearing_consumed_state(monkeypatch, tmp_path):
    value = make(monkeypatch,tmp_path); value.expiry[0] = 1002
    preview = value.workflow.preview('create',**identity(value))
    authorization = value.workflow.authorize('create',preview['preview_ref'],**identity(value))
    value.candidate.peer.clock.value = 1002
    with pytest.raises(ValueError): value.workflow.execute('create',authorization['authorization_ref'],**identity(value))
    assert value.candidate.store.claim_count == 0
    value.expiry[0] = 1060
    assert run(value,'create')[0]['outcome'] == 'succeeded'


def test_revocation_at_last_send_guard_closes_the_consumed_operation(monkeypatch, tmp_path):
    value = make(monkeypatch,tmp_path)
    value.candidate.backend.on_send = lambda: value.allowed.clear()
    result,authorization = run(value,'create')
    assert result['outcome'] != 'succeeded' and value.candidate.backend.sends == 0
    for phase in ('create','remove'):
        for purpose in PURPOSES: value.allowed.add((value.policy.reference_for(phase,purpose),'saml_'+purpose))
    assert value.workflow.execute('create',authorization['authorization_ref'],**identity(value))['idempotent_replay']
    with pytest.raises(ValueError): value.workflow.preview('remove',**identity(value))
    assert value.candidate.store.claim_count == 1 and value.candidate.backend.sends == 0


def test_interruption_and_lost_ack_cannot_be_reentered_or_promoted(monkeypatch, tmp_path):
    value = make(monkeypatch,tmp_path); value.candidate.backend.fault = 'interrupt'
    preview = value.workflow.preview('create',**identity(value))
    authorization = value.workflow.authorize('create',preview['preview_ref'],**identity(value))
    with pytest.raises(KeyboardInterrupt): value.workflow.execute('create',authorization['authorization_ref'],**identity(value))
    assert value.workflow.outcome(**identity(value))['workflow_outcome'] == 'reconciliation_required'
    with pytest.raises(ValueError): value.workflow.execute('create',authorization['authorization_ref'],**identity(value))
    with pytest.raises(ValueError): value.workflow.preview('remove',**identity(value))
    assert value.candidate.store.claim_count == value.candidate.backend.sends == 1


@pytest.mark.parametrize('mismatch', ['actor','client'])
def test_foreign_actor_or_client_cannot_read_owned_state(monkeypatch, tmp_path, mismatch):
    value = make(monkeypatch,tmp_path); identifiers = identity(value)
    identifiers['requester_digest' if mismatch == 'actor' else 'transport_digest'] = 'f'*64
    with pytest.raises(ValueError): value.workflow.preview('create',**identifiers)
    with pytest.raises(ValueError): value.workflow.outcome(**identifiers)
    assert value.calls == []


def test_signer_and_ledger_keys_are_separate_and_key_drift_invalidates_permission(monkeypatch, tmp_path):
    with pytest.raises(M4AuthorizationDenied): make(monkeypatch,tmp_path,signing_key=b'x'*32)
    other = tmp_path/'other'; other.mkdir(mode=0o700)
    value = make(monkeypatch,other); preview = value.workflow.preview('create',**identity(value))
    value.key.write_bytes(b'q'*32)
    with pytest.raises(ValueError): value.workflow.authorize('create',preview['preview_ref'],**identity(value))
    assert value.candidate.store.claim_count == 0
