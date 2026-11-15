"""Protected Approval Email issuance and owned workflow state; no native sources or material."""
from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from fortipam_mcp.reference_authority_sidecar import UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings
from fortipam_mcp.approval_delivery_authority import ApprovalDeliveryProtectedLabAuthority, PURPOSES
from fortipam_mcp.approval_delivery_local_workflow import ApprovalDeliveryLocalWorkflow
from fortipam_mcp.approval_delivery_execution_contract import ApprovalDeliveryExecutionIntent
from test_approval_delivery_material import Resolver
from test_approval_delivery_material_contract import BINDINGS
from test_approval_delivery_contract import state
from test_approval_delivery_m4 import SCOPE, NEW_BINDINGS, NEW_MATERIAL, stores, Backend, Evidence
from test_system_email_m4_adapter import Clock
from test_system_email_authority import owner_file
from v4_planning import M4AuthorizationDenied, VerifiedReferenceDecision, canonical_digest

REFERENCE = 'approval_delivery-test-reference-authority'
TRANSPORT = '9'*64
ENVIRONMENT, SCOPE_REF, AUDIENCE = 'approval_delivery-test-environment', 'approval_delivery-test-scope', 'approval_delivery-test-audience'


def construct(root, client, *, protocol='imaps', scope=SCOPE, transport=TRANSPORT, opened=None, fault=None,
              policy_enabled=True, policy_source=True, workflow_enabled=True, signing_key=b'p'*32):
    clock = Clock(); backend = Backend(clock, protocol); backend.fault = fault
    intent = ApprovalDeliveryExecutionIntent(backend.inspect(), {**state('ms-graph' if protocol == 'imaps' else 'imaps'), 'port': 994},
        enabled=True, original_material_bindings=BINDINGS, proposed_material_bindings=NEW_BINDINGS)
    store, material = opened if opened is not None else stores(root)
    evidence = Evidence(backend, intent)
    resolver = Resolver(intent.material_binding().material_binding_digest); resolver.values = NEW_MATERIAL
    recovery = Resolver(intent.material_binding(restore=True).material_binding_digest)
    key = owner_file(root/'policy.key', signing_key)
    policy = ApprovalDeliveryProtectedLabAuthority(intent,scope,backend,evidence,recovery,store,material,
        reference_authority=client,authority_key_file=key,transport_digest=transport,
        environment_ref=ENVIRONMENT,scope_ref=SCOPE_REF,audience_ref=AUDIENCE,
        execution_enabled=policy_enabled,source_guard=(lambda:True) if policy_source else None,clock=clock)
    workflow = ApprovalDeliveryLocalWorkflow(intent,backend,evidence,resolver,recovery,store,material,
        scope=scope,allowed_transport_digest=transport,authority=policy,configure_enabled=workflow_enabled,
        restore_enabled=workflow_enabled,source_guard=lambda:True,clock=clock)
    return SimpleNamespace(workflow=workflow,policy=policy,backend=backend,evidence=evidence,resolver=resolver,
        recovery=recovery,clock=clock,store=store,material=material,scope=scope,transport=transport,key=key,intent=intent)


def identity(value): return dict(requester_digest=value.scope.requester_digest, transport_digest=value.transport)


def make(monkeypatch, root, **kwargs):
    client = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(Path('/private/tmp/approval_delivery-authority-unit.sock'), REFERENCE))
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
    for phase in ('configure','restore'):
        for purpose in PURPOSES: allowed.add((value.policy.reference_for(phase, purpose), 'approval_delivery_'+purpose))
    value.allowed, value.calls, value.expiry, value.faults, value.client = allowed, calls, expiry, faults, client
    return value


def run(value, phase):
    preview = value.workflow.preview(phase, **identity(value))
    authorization = value.workflow.authorize(phase, preview['preview_ref'], **identity(value))
    return value.workflow.execute(phase, authorization['authorization_ref'], **identity(value)), authorization


@pytest.mark.parametrize('protocol', ['imaps','ms-graph'])
def test_protected_lab_workflow_updates_and_restores_without_loading_recovery_early(monkeypatch, tmp_path, protocol):
    value = make(monkeypatch, tmp_path, protocol=protocol)
    result, authorization = run(value, 'configure')
    assert result['outcome'] == 'succeeded' and value.recovery.loads == 0
    assert value.workflow.execute('configure', authorization['authorization_ref'], **identity(value))['idempotent_replay']
    assert run(value, 'restore')[0]['outcome'] == 'succeeded'
    assert value.workflow.outcome(**identity(value))['workflow_outcome'] == 'verified_locally'
    assert value.store.claim_count == value.material.claim_count == value.backend.sends == 2
    assert value.recovery.loads == 1


@pytest.mark.parametrize('options', [dict(policy_enabled=False),dict(policy_source=False),dict(workflow_enabled=False)])
def test_separate_source_policy_and_workflow_gates_deny_before_material(monkeypatch, tmp_path, options):
    value = make(monkeypatch, tmp_path, **options); preview = value.workflow.preview('configure', **identity(value))
    calls = value.backend.reads
    with pytest.raises(ValueError): value.workflow.authorize('configure', preview['preview_ref'], **identity(value))
    assert value.backend.reads == calls and value.resolver.loads == value.store.claim_count == 0


@pytest.mark.parametrize('purpose', PURPOSES)
def test_each_grant_is_required_and_restore_does_not_inherit_apply_permission(monkeypatch, tmp_path, purpose):
    value = make(monkeypatch, tmp_path)
    value.allowed.remove((value.policy.reference_for('configure', purpose), 'approval_delivery_'+purpose))
    preview = value.workflow.preview('configure', **identity(value))
    with pytest.raises(ValueError): value.workflow.authorize('configure', preview['preview_ref'], **identity(value))
    value.allowed.add((value.policy.reference_for('configure', purpose), 'approval_delivery_'+purpose))
    assert run(value, 'configure')[0]['outcome'] == 'succeeded'
    value.allowed.remove((value.policy.reference_for('restore', purpose), 'approval_delivery_'+purpose))
    preview = value.workflow.preview('restore', **identity(value))
    with pytest.raises(ValueError): value.workflow.authorize('restore', preview['preview_ref'], **identity(value))
    assert value.backend.sends == 1 and value.recovery.loads == 0


@pytest.mark.parametrize('field', ['requester_digest','transport_digest','summary_digest','parameters_digest',
    'expected_current_digest','expected_state_digest','target_ref'])
def test_forged_request_is_never_signed(monkeypatch, tmp_path, field):
    value = make(monkeypatch, tmp_path); value.workflow.preview('configure', **identity(value))
    with pytest.raises(M4AuthorizationDenied): value.policy.authorize(replace(value.workflow._previews['configure'], **{field:'f'*64}))
    assert value.calls == [] and value.store.claim_count == value.resolver.loads == 0


@pytest.mark.parametrize('field', ['reference_digest','reference_kind','authority_ref','requester_digest','environment_digest','scope_digest'])
def test_foreign_reference_decision_is_not_a_permission(monkeypatch, tmp_path, field):
    value = make(monkeypatch, tmp_path); value.faults[0] = {field: 'f'*64 if field.endswith('digest') else 'foreign-authority'}
    preview = value.workflow.preview('configure', **identity(value))
    with pytest.raises(ValueError): value.workflow.authorize('configure', preview['preview_ref'], **identity(value))
    assert value.resolver.loads == value.backend.sends == 0


def test_revocation_after_claim_is_checked_at_send_and_regrant_only_returns_cached_unknown(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path)
    ref = (value.policy.reference_for('configure','permission'), 'approval_delivery_permission')
    value.backend.on_submit = lambda: value.allowed.remove(ref)
    result, authorization = run(value, 'configure')
    assert result['outcome'] != 'succeeded' and value.backend.sends == 0 and value.resolver.loads == 1
    value.allowed.add(ref)
    assert value.workflow.execute('configure', authorization['authorization_ref'], **identity(value))['idempotent_replay']
    with pytest.raises(ValueError): value.workflow.preview('restore', **identity(value))
    assert all(not any(buffer) for buffer in value.resolver.buffers + value.backend.buffers)


def test_expired_unused_authorization_can_renew_without_reopening_a_consumed_attempt(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path); value.expiry[0] = 1010
    preview = value.workflow.preview('configure', **identity(value))
    authorization = value.workflow.authorize('configure', preview['preview_ref'], **identity(value))
    assert authorization['expires_at'] == 1010
    value.clock.value = 1010
    with pytest.raises(ValueError): value.workflow.execute('configure', authorization['authorization_ref'], **identity(value))
    assert value.store.claim_count == value.material.claim_count == 0
    value.expiry[0] = 1070
    assert run(value,'configure')[0]['outcome'] == 'succeeded'


@pytest.mark.parametrize('fault', ['key', 'foreign-identity', 'foreign-client', 'clock'])
def test_changed_binding_denies_before_loading_material(monkeypatch, tmp_path, fault):
    value = make(monkeypatch, tmp_path); preview = value.workflow.preview('configure', **identity(value))
    authorization = value.workflow.authorize('configure', preview['preview_ref'], **identity(value))
    selected = identity(value)
    if fault == 'key': value.key.write_bytes(b'q'*32)
    elif fault == 'foreign-identity': selected['requester_digest'] = 'f'*64
    elif fault == 'foreign-client': selected['transport_digest'] = 'f'*64
    else: value.clock.value = 999
    with pytest.raises(ValueError): value.workflow.execute('configure', authorization['authorization_ref'], **selected)
    assert value.resolver.loads == value.backend.sends == 0


def test_interrupted_dispatch_cannot_be_reentered_or_adopted(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path, fault='interrupt'); preview = value.workflow.preview('configure', **identity(value))
    authorization = value.workflow.authorize('configure', preview['preview_ref'], **identity(value))
    with pytest.raises(KeyboardInterrupt): value.workflow.execute('configure', authorization['authorization_ref'], **identity(value))
    with pytest.raises(ValueError): value.workflow.execute('configure', authorization['authorization_ref'], **identity(value))
    assert value.workflow.outcome(**identity(value))['workflow_outcome'] == 'reconciliation_required'
    assert value.backend.sends == value.resolver.loads == 1


def test_a_freshly_shortened_permission_must_survive_the_final_verification_check(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path); preview = value.workflow.preview('configure', **identity(value))
    authorization = value.workflow.authorize('configure', preview['preview_ref'], **identity(value))
    original = value.client.authorize
    def shorten(*args, **kwargs):
        decision = original(*args, **kwargs)
        if kwargs['reference_kind'] == 'approval_delivery_permission':
            decision = replace(decision, expires_at=1001)
            value.clock.value = 1001
        return decision
    monkeypatch.setattr(value.client, 'authorize', shorten)
    with pytest.raises(ValueError): value.workflow.execute('configure', authorization['authorization_ref'], **identity(value))
    assert value.store.claim_count == value.material.claim_count == value.resolver.loads == 0


@pytest.mark.parametrize('key', [b'x'*32, b'm'*32])
def test_signing_key_cannot_reuse_either_execution_or_material_ledger_key(monkeypatch, tmp_path, key):
    with pytest.raises(M4AuthorizationDenied): make(monkeypatch, tmp_path, signing_key=key)


def test_a_new_directory_cannot_inherit_grants_from_the_original_namespace(monkeypatch, tmp_path):
    original = tmp_path/'original'; original.mkdir(mode=0o700)
    value = make(monkeypatch, original)
    other = tmp_path/'replacement'; other.mkdir(mode=0o700)
    replacement = construct(other, value.client)
    assert replacement.policy.reference_for('configure','permission') != value.policy.reference_for('configure','permission')
    preview = replacement.workflow.preview('configure', **identity(replacement))
    with pytest.raises(ValueError): replacement.workflow.authorize('configure', preview['preview_ref'], **identity(replacement))
    assert replacement.store.claim_count == replacement.material.claim_count == replacement.resolver.loads == 0


def test_restore_preview_names_original_configuration_and_requires_new_authority(monkeypatch,tmp_path):
    value = make(monkeypatch,tmp_path); value.expiry[0] = 1200
    assert run(value,'configure')[0]['outcome'] == 'succeeded'
    value.clock.value = 1070
    preview = value.workflow.preview('restore',**identity(value))
    assert preview['Proposed Changes']['restore_original_nonmaterial_configuration']
    assert not preview['independent_restore_authorized'] and not preview['native_backend_qualified']
    authorization = value.workflow.authorize('restore',preview['preview_ref'],**identity(value))
    assert authorization['expires_at'] == 1130
    assert value.workflow.execute('restore',authorization['authorization_ref'],**identity(value))['outcome'] == 'succeeded'
    assert value.resolver.loads == value.recovery.loads == 1


@pytest.mark.parametrize('fault', [None,'lost-ack'])
def test_new_workflow_cannot_present_consumed_records_as_an_unstarted_scope(monkeypatch,tmp_path,fault):
    value = make(monkeypatch,tmp_path,fault=fault); run(value,'configure')
    with pytest.raises(ValueError): construct(tmp_path,value.client,opened=(value.store,value.material))
    assert value.store.claim_count == value.material.claim_count == value.resolver.loads == 1


def test_each_phase_gate_is_rechecked_at_dispatch_and_restore_is_independent(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path)
    preview = value.workflow.preview('configure', **identity(value))
    authorization = value.workflow.authorize('configure', preview['preview_ref'], **identity(value))
    value.workflow._enabled['configure'] = False
    with pytest.raises(ValueError): value.workflow.execute('configure', authorization['authorization_ref'], **identity(value))
    assert value.resolver.loads == value.store.claim_count == 0
    value.workflow._enabled['configure'] = True
    assert value.workflow.execute('configure', authorization['authorization_ref'], **identity(value))['outcome'] == 'succeeded'
    value.workflow._enabled['configure'] = False
    assert run(value, 'restore')[0]['outcome'] == 'succeeded'


@pytest.mark.parametrize('target', ['workflow', 'policy'])
def test_guard_cannot_close_its_own_gate_and_return_ready(monkeypatch, tmp_path, target):
    value = make(monkeypatch, tmp_path)
    preview = value.workflow.preview('configure', **identity(value))
    selected = value.workflow if target == 'workflow' else value.policy
    def guard():
        if target == 'workflow': selected._enabled['configure'] = False
        else: selected._enabled = False
        return True
    selected._guard = selected._guard_pin = guard
    with pytest.raises(ValueError): value.workflow.authorize('configure', preview['preview_ref'], **identity(value))
    assert value.store.claim_count == value.resolver.loads == value.backend.sends == 0


def test_foreign_identity_does_not_consume_clock_or_revoke_owned_workflow(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path); value.clock.value = 999
    with pytest.raises(ValueError): value.workflow.outcome(requester_digest='f'*64, transport_digest=value.transport)
    assert not value.workflow._closed and value.workflow._last_now == -1
    value.clock.value = 1000
    assert run(value, 'configure')[0]['outcome'] == 'succeeded'


def test_reference_callback_cannot_reenter_workflow_or_policy_issuance(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path)
    preview = value.workflow.preview('configure', **identity(value))
    request = value.workflow._previews['configure']
    authorize = value.client.authorize
    nested = []
    def checking(*args, **kwargs):
        with pytest.raises(ValueError): value.workflow.preview('configure', **identity(value))
        with pytest.raises(M4AuthorizationDenied): value.policy.authorize(request)
        nested.append(True)
        return authorize(*args, **kwargs)
    monkeypatch.setattr(value.client, 'authorize', checking)
    authorization = value.workflow.authorize('configure', preview['preview_ref'], **identity(value))
    assert nested and value.workflow._previews['configure'] is request
    assert value.workflow.execute('configure', authorization['authorization_ref'], **identity(value))['outcome'] == 'succeeded'


@pytest.mark.parametrize('fault', [None, 'lost-ack'])
def test_owned_replay_and_query_after_gate_closure_do_not_read_or_authorize(monkeypatch, tmp_path, fault):
    value = make(monkeypatch, tmp_path, fault=fault)
    result, authorization = run(value, 'configure')
    reads, permissions = value.backend.reads, len(value.calls)
    value.workflow._enabled['configure'] = value.policy._enabled = False
    assert value.workflow.execute('configure', authorization['authorization_ref'], **identity(value))['idempotent_replay']
    outcome = value.workflow.outcome(**identity(value))
    assert outcome['workflow_outcome'] == ('applied_locally' if fault is None else 'reconciliation_required')
    assert value.backend.reads == reads and len(value.calls) == permissions and value.resolver.loads == 1
    serialized = json.dumps([result, authorization, outcome])
    assert 'SYNTHETIC_' not in serialized and not outcome['polling_and_approval_effects_verified']


def test_query_checks_journal_integrity_without_device_or_permission_access(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path); run(value, 'configure')
    reads, calls = value.backend.reads, len(value.calls)
    value.store._key_path.write_bytes(b'z'*32)
    with pytest.raises(ValueError): value.workflow.outcome(**identity(value))
    assert value.backend.reads == reads and len(value.calls) == calls


@pytest.mark.parametrize('lost_ack', [None, 'configure', 'restore'])
def test_real_unix_authority_and_both_cas_services_enforce_owned_phases(tmp_path, lost_ack):
    from test_fortitoken_local_mcp_action import unix_services
    with unix_services(tmp_path) as (reference, client, store, material):
        value = construct(tmp_path, client, opened=(store, material))
        reference.issue_many(tuple((value.policy.reference_for(phase, purpose), 'approval_delivery_'+purpose)
            for phase in ('configure', 'restore') for purpose in PURPOSES), requester_digest=value.scope.requester_digest,
            environment_ref=ENVIRONMENT, scope_ref=SCOPE_REF, expires_at=1120, now_epoch=1000)
        if lost_ack == 'configure': value.backend.fault = 'lost-ack'
        result, authorization = run(value, 'configure')
        assert (result['outcome'] == 'succeeded') is (lost_ack != 'configure')
        if lost_ack == 'configure':
            with pytest.raises(ValueError): value.workflow.preview('restore', **identity(value))
        else:
            if lost_ack == 'restore': value.backend.fault = 'lost-ack'
            assert (run(value, 'restore')[0]['outcome'] == 'succeeded') is (lost_ack is None)
        state = value.workflow.outcome(**identity(value))
        assert state['workflow_outcome'] == ('verified_locally' if lost_ack is None else 'reconciliation_required')
        assert value.workflow.execute('configure', authorization['authorization_ref'], **identity(value))['idempotent_replay']
        assert store.claim_count == material.claim_count == value.backend.sends == (1 if lost_ack == 'configure' else 2)
        assert all(not any(raw) for raw in value.backend.buffers + value.resolver.buffers + value.recovery.buffers)
