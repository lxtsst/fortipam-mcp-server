"""Protected FortiToken issuance and owned workflow state; no native sources or material."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from fortipam_mcp.reference_authority_sidecar import UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings
from fortipam_mcp.fortitoken_authority import FortitokenProtectedLabAuthority, PURPOSES
from fortipam_mcp.fortitoken_local_workflow import FortitokenLocalWorkflow
from fortipam_mcp.fortitoken_user_contract import FortitokenUserPlan
from test_fortitoken_user_source import Peer
from test_fortitoken_material import Resolver
from test_fortitoken_local_m4 import SCOPE, stores, Backend, Evidence, fortitoken_execution_digests
from test_system_email_authority import owner_file
from v4_planning import M4AuthorizationDenied, VerifiedReferenceDecision, canonical_digest

REFERENCE = 'fortitoken-test-reference-authority'
TRANSPORT = '9'*64
ENVIRONMENT, SCOPE_REF, AUDIENCE = 'fortitoken-test-environment', 'fortitoken-test-scope', 'fortitoken-test-audience'


def construct(root, client, *, operation='assign', scope=SCOPE, transport=TRANSPORT, opened=None, fault=None,
              policy_enabled=True, policy_source=True, workflow_enabled=True, signing_key=b'p'*32,
              peer=None, source=None, backend_factory=None):
    peer = peer if peer is not None else Peer(operation)
    source = source if source is not None else peer.reader()
    intent = FortitokenUserPlan(source.read().state,operation); clock = peer.clock
    store,material = opened if opened is not None else stores(root)
    if backend_factory is None:
        backend = Backend(peer); backend.fault = fault
    else:
        assert fault is None
        backend = backend_factory(source,intent,fortitoken_execution_digests(intent,scope,store,material)[2])
    evidence = Evidence(peer)
    resolver,recovery = Resolver(),Resolver()
    key = owner_file(root/'policy.key',signing_key)
    policy = FortitokenProtectedLabAuthority(intent,scope,source,backend,evidence,recovery,store,material,
        reference_authority=client,authority_key_file=key,transport_digest=transport,
        environment_ref=ENVIRONMENT,scope_ref=SCOPE_REF,audience_ref=AUDIENCE,
        execution_enabled=policy_enabled,source_guard=(lambda:True) if policy_source else None,clock=clock)
    workflow = FortitokenLocalWorkflow(intent,source,backend,evidence,resolver,recovery,store,material,
        scope=scope,allowed_transport_digest=transport,authority=policy,apply_enabled=workflow_enabled,
        restore_enabled=workflow_enabled,source_guard=lambda:True,clock=clock)
    return SimpleNamespace(workflow=workflow,policy=policy,backend=backend,evidence=evidence,resolver=resolver,
        recovery=recovery,clock=clock,store=store,material=material,scope=scope,transport=transport,key=key,
        intent=intent,peer=peer,source=source)


def identity(value): return dict(requester_digest=value.scope.requester_digest, transport_digest=value.transport)


def make(monkeypatch, root, **kwargs):
    client = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(Path('/private/tmp/fortitoken-authority-unit.sock'), REFERENCE))
    monkeypatch.setattr(client, 'verify_ready', lambda: None)
    allowed, calls, expiry, faults = set(), [], [1060], [None]
    def authorize(ref, *, reference_kind, requester_digest, environment_ref, scope_ref, now_epoch):
        calls.append((ref, reference_kind))
        authorized = (ref, reference_kind) in allowed and now_epoch < expiry[0]
        data = dict(reference_digest=canonical_digest(ref), reference_kind=reference_kind, authority_ref=REFERENCE,
            requester_digest=requester_digest, environment_digest=canonical_digest(environment_ref),
            scope_digest=canonical_digest(scope_ref), authorized=authorized, checked_at=now_epoch,
            expires_at=min(now_epoch+60, expiry[0]) if authorized else now_epoch+60)
        if faults[0]: data.update(faults[0])
        return VerifiedReferenceDecision(**data)
    monkeypatch.setattr(client, 'authorize', authorize)
    value = construct(root, client, **kwargs)
    for phase in ('apply','restore'):
        for purpose in PURPOSES: allowed.add((value.policy.reference_for(phase, purpose), 'fortitoken_'+purpose))
    value.allowed, value.calls, value.expiry, value.faults, value.client = allowed, calls, expiry, faults, client
    return value


def run(value, phase):
    preview = value.workflow.preview(phase, **identity(value))
    authorization = value.workflow.authorize(phase, preview['preview_ref'], **identity(value))
    return value.workflow.execute(phase, authorization['authorization_ref'], **identity(value)), authorization


@pytest.mark.parametrize('operation', ['assign','revoke'])
def test_protected_lab_workflow_updates_and_restores_without_loading_recovery_early(monkeypatch, tmp_path, operation):
    value = make(monkeypatch, tmp_path, operation=operation)
    result, authorization = run(value, 'apply')
    assert result['outcome'] == 'succeeded' and value.recovery.loads == 0
    assert value.workflow.execute('apply', authorization['authorization_ref'], **identity(value))['idempotent_replay']
    assert run(value, 'restore')[0]['outcome'] == 'succeeded'
    assert value.workflow.outcome(**identity(value))['workflow_outcome'] == 'verified_locally'
    assert value.store.claim_count == value.material.claim_count == value.backend.sends == 2
    assert value.recovery.loads == 1


@pytest.mark.parametrize('options', [dict(policy_enabled=False),dict(policy_source=False),dict(workflow_enabled=False)])
def test_separate_source_policy_and_workflow_gates_deny_before_material(monkeypatch, tmp_path, options):
    value = make(monkeypatch, tmp_path, **options); preview = value.workflow.preview('apply', **identity(value))
    calls = value.evidence.calls
    with pytest.raises(ValueError): value.workflow.authorize('apply', preview['preview_ref'], **identity(value))
    assert value.evidence.calls == calls and value.resolver.loads == value.store.claim_count == 0


@pytest.mark.parametrize('purpose', PURPOSES)
def test_each_grant_is_required_and_restore_does_not_inherit_apply_permission(monkeypatch, tmp_path, purpose):
    value = make(monkeypatch, tmp_path)
    value.allowed.remove((value.policy.reference_for('apply', purpose), 'fortitoken_'+purpose))
    preview = value.workflow.preview('apply', **identity(value))
    with pytest.raises(ValueError): value.workflow.authorize('apply', preview['preview_ref'], **identity(value))
    value.allowed.add((value.policy.reference_for('apply', purpose), 'fortitoken_'+purpose))
    assert run(value, 'apply')[0]['outcome'] == 'succeeded'
    value.allowed.remove((value.policy.reference_for('restore', purpose), 'fortitoken_'+purpose))
    preview = value.workflow.preview('restore', **identity(value))
    with pytest.raises(ValueError): value.workflow.authorize('restore', preview['preview_ref'], **identity(value))
    assert value.backend.sends == 1 and value.recovery.loads == 0


@pytest.mark.parametrize('field', ['requester_digest','transport_digest','summary_digest','parameters_digest',
    'expected_current_digest','expected_state_digest','target_ref'])
def test_forged_request_is_never_signed(monkeypatch, tmp_path, field):
    value = make(monkeypatch, tmp_path); value.workflow.preview('apply', **identity(value))
    with pytest.raises(M4AuthorizationDenied): value.policy.authorize(replace(value.workflow._previews['apply'], **{field:'f'*64}))
    assert value.calls == [] and value.store.claim_count == value.resolver.loads == 0


@pytest.mark.parametrize('field', ['reference_digest','reference_kind','authority_ref','requester_digest','environment_digest','scope_digest'])
def test_foreign_reference_decision_is_not_a_permission(monkeypatch, tmp_path, field):
    value = make(monkeypatch, tmp_path); value.faults[0] = {field: 'f'*64 if field.endswith('digest') else 'foreign-authority'}
    preview = value.workflow.preview('apply', **identity(value))
    with pytest.raises(ValueError): value.workflow.authorize('apply', preview['preview_ref'], **identity(value))
    assert value.resolver.loads == value.backend.sends == 0


def test_revocation_after_claim_is_checked_at_send_and_regrant_only_returns_cached_unknown(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path)
    ref = (value.policy.reference_for('apply','permission'), 'fortitoken_permission')
    value.backend.on_submit = lambda: value.allowed.remove(ref)
    result, authorization = run(value, 'apply')
    assert result['outcome'] != 'succeeded' and value.backend.sends == 0 and value.resolver.loads == 1
    value.allowed.add(ref)
    assert value.workflow.execute('apply', authorization['authorization_ref'], **identity(value))['idempotent_replay']
    with pytest.raises(ValueError): value.workflow.preview('restore', **identity(value))
    assert all(not any(buffer) for buffer in value.resolver.buffers + value.backend.buffers)


def test_expired_unused_authorization_can_renew_without_reopening_a_consumed_attempt(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path); value.expiry[0] = 1010
    preview = value.workflow.preview('apply', **identity(value))
    authorization = value.workflow.authorize('apply', preview['preview_ref'], **identity(value))
    assert authorization['expires_at'] == 1010
    value.clock.value = 1010
    with pytest.raises(ValueError): value.workflow.execute('apply', authorization['authorization_ref'], **identity(value))
    assert value.store.claim_count == value.material.claim_count == 0
    value.expiry[0] = 1070
    assert run(value,'apply')[0]['outcome'] == 'succeeded'


@pytest.mark.parametrize('fault', ['key', 'foreign-identity', 'foreign-client', 'clock'])
def test_changed_binding_denies_before_loading_material(monkeypatch, tmp_path, fault):
    value = make(monkeypatch, tmp_path); preview = value.workflow.preview('apply', **identity(value))
    authorization = value.workflow.authorize('apply', preview['preview_ref'], **identity(value))
    selected = identity(value)
    if fault == 'key': value.key.write_bytes(b'q'*32)
    elif fault == 'foreign-identity': selected['requester_digest'] = 'f'*64
    elif fault == 'foreign-client': selected['transport_digest'] = 'f'*64
    else: value.clock.value = 999
    with pytest.raises(ValueError): value.workflow.execute('apply', authorization['authorization_ref'], **selected)
    assert value.resolver.loads == value.backend.sends == 0


def test_interrupted_dispatch_cannot_be_reentered_or_adopted(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path, fault='interrupt'); preview = value.workflow.preview('apply', **identity(value))
    authorization = value.workflow.authorize('apply', preview['preview_ref'], **identity(value))
    with pytest.raises(KeyboardInterrupt): value.workflow.execute('apply', authorization['authorization_ref'], **identity(value))
    with pytest.raises(ValueError): value.workflow.execute('apply', authorization['authorization_ref'], **identity(value))
    assert value.workflow.outcome(**identity(value))['workflow_outcome'] == 'reconciliation_required'
    assert value.backend.sends == value.resolver.loads == 1


def test_a_freshly_shortened_permission_must_survive_the_final_verification_check(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path); preview = value.workflow.preview('apply', **identity(value))
    authorization = value.workflow.authorize('apply', preview['preview_ref'], **identity(value))
    original = value.client.authorize
    def shorten(*args, **kwargs):
        decision = original(*args, **kwargs)
        if kwargs['reference_kind'] == 'fortitoken_permission':
            decision = replace(decision, expires_at=1001)
            value.clock.value = 1001
        return decision
    monkeypatch.setattr(value.client, 'authorize', shorten)
    with pytest.raises(ValueError): value.workflow.execute('apply', authorization['authorization_ref'], **identity(value))
    assert value.store.claim_count == value.material.claim_count == value.resolver.loads == 0


@pytest.mark.parametrize('key', [b'x'*32, b'm'*32])
def test_signing_key_cannot_reuse_either_execution_or_material_ledger_key(monkeypatch, tmp_path, key):
    with pytest.raises(M4AuthorizationDenied): make(monkeypatch, tmp_path, signing_key=key)


def test_a_new_directory_cannot_inherit_grants_from_the_original_namespace(monkeypatch, tmp_path):
    original = tmp_path/'original'; original.mkdir(mode=0o700)
    value = make(monkeypatch, original)
    other = tmp_path/'replacement'; other.mkdir(mode=0o700)
    replacement = construct(other, value.client)
    assert replacement.policy.reference_for('apply','permission') != value.policy.reference_for('apply','permission')
    preview = replacement.workflow.preview('apply', **identity(replacement))
    with pytest.raises(ValueError): replacement.workflow.authorize('apply', preview['preview_ref'], **identity(replacement))
    assert replacement.store.claim_count == replacement.material.claim_count == replacement.resolver.loads == 0


@pytest.mark.parametrize('operation', ['assign','revoke'])
def test_restore_preview_reports_the_actual_inverse_security_change_and_uses_new_authority(monkeypatch,tmp_path,operation):
    value = make(monkeypatch,tmp_path,operation=operation); value.expiry[0] = 1200
    assert run(value,'apply')[0]['outcome'] == 'succeeded'
    value.clock.value = 1070
    preview = value.workflow.preview('restore',**identity(value))
    assert preview['operation'] == operation
    assert preview['effective_operation'] == ('revoke' if operation == 'assign' else 'assign')
    assert preview['Security Changes']['mfa_requirement_removed'] is (operation == 'assign')
    assert not preview['independent_recovery_verified'] and not preview['mfa_login_verified']
    authorization = value.workflow.authorize('restore',preview['preview_ref'],**identity(value))
    assert authorization['expires_at'] == 1130
    assert value.workflow.execute('restore',authorization['authorization_ref'],**identity(value))['outcome'] == 'succeeded'
    assert value.resolver.loads == value.recovery.loads == 1


@pytest.mark.parametrize('fault', [None,'lost-ack'])
def test_new_workflow_cannot_present_consumed_records_as_an_unstarted_scope(monkeypatch,tmp_path,fault):
    value = make(monkeypatch,tmp_path,fault=fault); run(value,'apply')
    with pytest.raises(ValueError): construct(tmp_path,value.client,opened=(value.store,value.material))
    assert value.store.claim_count == value.material.claim_count == value.resolver.loads == 1
