"""Exact protected lab grants, independent of synthetic product behavior."""
from contextlib import contextmanager
import asyncio
from dataclasses import replace
from pathlib import Path
import socket
import tempfile
from threading import Thread
import time
from types import SimpleNamespace

import pytest
import uvicorn
from starlette.testclient import TestClient

from fortipam_mcp.planning_checkpoint_sidecar import create_checkpoint_sidecar_app, UnixPlanningCheckpointClientSettings
from fortipam_mcp.reference_authority_sidecar import (
    UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings, create_reference_authority_sidecar_app,
)
from fortipam_mcp.system_email_authority import SystemEmailProtectedLabAuthority, PURPOSES
from fortipam_mcp.system_email_delivery_contract import SystemEmailDeliveryBinding
from fortipam_mcp.system_email_local_workflow import SystemEmailLocalWorkflow
from fortipam_mcp.system_email_local_mcp_action import SystemEmailLocalMcpAction, register_system_email_local_candidate_tools
from fortipam_mcp.local_oauth import LocalOAuthProvider
from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
from fortipam_mcp.system_email_m4_adapter import system_email_execution_digests
from fortipam_mcp.system_email_persistence import SystemEmailExecutionStoreSettings, open_system_email_execution_stores
from test_system_email_delivery_workflow import DeliveryBackend
from test_system_email_local_workflow import IDENTITY, run
from test_system_email_local_mcp_action import assemble
from test_ldap_server_mcp_action import _call, _login
from test_system_email_m4_adapter import Backend, Clock, BINDING, REQUESTER, store_at, transition
from v4_planning import (
    M4AuthorizationDenied, PersistentPlanningCheckpointAuthority, PersistentReferenceAuthority,
    PersistentReferenceCheckpointAuthority, VerifiedReferenceDecision, canonical_digest,
)

ENVIRONMENT = 'system-email-test-environment'
SCOPE = 'system-email-test-scope'
AUDIENCE = 'system-email-test-audience'
REFERENCE_AUTHORITY = 'system-email-test-reference-authority'


def owner_file(path, value):
    path.write_bytes(value); path.chmod(0o600); return path


def construct(tmp_path, client, *, identity=IDENTITY, enabled=True, source=True, stores=None, fault='none', key_material=b'p'*32):
    clock = Clock(); backend = Backend(); change = transition(backend)
    if stores is None:
        store = store_at(tmp_path, key_material=b'c'*32)
        root = tmp_path/'delivery'; root.mkdir(mode=0o700)
        delivery_store = store_at(root, key_material=b'd'*32, store_ref='system-email-authority-delivery-store')
    else: store, delivery_store = stores
    context = canonical_digest({'binding': BINDING, 'requester': identity['requester_digest'], 'transport': identity['transport_digest']})
    binding = SystemEmailDeliveryBinding('a'*48, 'b'*64, change.original.source_serial_digest,
        system_email_execution_digests(change, context)[1])
    sender = DeliveryBackend(backend, clock, fault)
    key = owner_file(tmp_path/'policy.key', key_material)
    policy = SystemEmailProtectedLabAuthority(change, backend, store, binding, sender, delivery_store,
        reference_authority=client, authority_key_file=key, binding_digest=BINDING,
        requester_digest=identity['requester_digest'], transport_digest=identity['transport_digest'],
        environment_ref=ENVIRONMENT, scope_ref=SCOPE, audience_ref=AUDIENCE, window_digest='e'*64,
        execution_enabled=enabled, source_guard=(lambda phase: True) if source else None, clock=clock)
    workflow = SystemEmailLocalWorkflow(change, backend, store, binding_digest=BINDING,
        allowed_requester_digest=identity['requester_digest'], allowed_transport_digest=identity['transport_digest'],
        authority=policy, update_enabled=True, restore_enabled=True, clock=clock,
        delivery_binding=binding, delivery_backend=sender, delivery_store=delivery_store, delivery_enabled=True)
    return SimpleNamespace(policy=policy, workflow=workflow, backend=backend, sender=sender,
        store=store, delivery_store=delivery_store, clock=clock, key=key)


def make(monkeypatch, tmp_path, **kwargs):
    client = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(
        Path('/private/tmp/system-email-authority-unit.sock'), REFERENCE_AUTHORITY))
    monkeypatch.setattr(client, 'verify_ready', lambda: None)
    allowed = set(); calls = []; expiration = [1060]; response_fault = [None]
    def authorize(reference, *, reference_kind, requester_digest, environment_ref, scope_ref, now_epoch):
        calls.append((reference, reference_kind))
        authorized = (reference, reference_kind) in allowed and now_epoch < expiration[0]
        values = dict(reference_digest=canonical_digest(reference), reference_kind=reference_kind,
            authority_ref=REFERENCE_AUTHORITY, requester_digest=requester_digest,
            environment_digest=canonical_digest(environment_ref), scope_digest=canonical_digest(scope_ref),
            authorized=authorized, checked_at=now_epoch,
            expires_at=min(now_epoch+60, expiration[0]) if authorized else now_epoch+60)
        if response_fault[0] is not None: values.update(response_fault[0])
        return VerifiedReferenceDecision(**values)
    monkeypatch.setattr(client, 'authorize', authorize)
    value = construct(tmp_path, client, **kwargs)
    for phase in ('update', 'test-delivery', 'restore'):
        for purpose in PURPOSES:
            allowed.add((value.policy.reference_for(phase, purpose), 'system_email_'+purpose))
    value.allowed, value.calls, value.expiration, value.response_fault = allowed, calls, expiration, response_fault
    return value


@pytest.mark.parametrize('enabled,source', [(False, True), (True, False)])
def test_independent_execution_and_source_gates_default_to_deny(monkeypatch, tmp_path, enabled, source):
    value = make(monkeypatch, tmp_path, enabled=enabled, source=source)
    preview = value.workflow.preview('update', **IDENTITY); reads = value.backend.reads
    with pytest.raises(ValueError): value.workflow.authorize('update', preview['preview_ref'], **IDENTITY)
    assert value.calls == [] and value.backend.reads == reads and value.store.claim_count == 0


def test_signing_key_cannot_reuse_execution_ledger_key_material(monkeypatch, tmp_path):
    with pytest.raises(M4AuthorizationDenied): make(monkeypatch, tmp_path, key_material=b'c'*32)


@pytest.mark.parametrize('missing', PURPOSES)
def test_permission_standing_intent_and_lab_policy_are_separate_grants(monkeypatch, tmp_path, missing):
    value = make(monkeypatch, tmp_path)
    value.allowed.remove((value.policy.reference_for('update', missing), 'system_email_'+missing))
    preview = value.workflow.preview('update', **IDENTITY); reads = value.backend.reads
    with pytest.raises(ValueError): value.workflow.authorize('update', preview['preview_ref'], **IDENTITY)
    assert value.backend.reads == reads and not value.backend.submissions and value.store.claim_count == 0


@pytest.mark.parametrize('field', ['requester_digest', 'transport_digest', 'summary_digest', 'target_ref', 'adapter_ref',
    'expected_current_digest', 'expected_state_digest', 'parameters_digest'])
def test_foreign_request_or_preview_is_not_signed(monkeypatch, tmp_path, field):
    value = make(monkeypatch, tmp_path); value.workflow.preview('update', **IDENTITY)
    request = value.workflow._previews['update']; reads = value.backend.reads
    with pytest.raises(M4AuthorizationDenied): value.policy.authorize(replace(request, **{field: 'f'*64}))
    assert value.calls == [] and value.backend.reads == reads and value.store.claim_count == 0


@pytest.mark.parametrize('field', ['reference_digest', 'requester_digest', 'environment_digest', 'scope_digest', 'authority_ref', 'reference_kind'])
def test_mismatched_external_decision_cannot_be_promoted(monkeypatch, tmp_path, field):
    value = make(monkeypatch, tmp_path)
    value.response_fault[0] = {field: 'f'*64 if field.endswith('digest') else 'foreign_decision'}
    preview = value.workflow.preview('update', **IDENTITY)
    with pytest.raises(ValueError): value.workflow.authorize('update', preview['preview_ref'], **IDENTITY)
    assert value.store.claim_count == 0 and not value.backend.submissions


def test_local_three_phase_policy_and_consumed_unknowns_remain_separate(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path, fault='timeout')
    assert run(value.workflow, 'update')[0]['outcome'] == 'succeeded'
    result, authorization = run(value.workflow, 'test-delivery')
    assert result['outcome'] == 'reconciliation_required'
    assert run(value.workflow, 'restore')[0]['outcome'] == 'succeeded'
    assert value.workflow.execute('test-delivery', authorization['authorization_ref'], **IDENTITY)['idempotent_replay']
    assert value.workflow.outcome(**IDENTITY)['workflow_outcome'] == 'reconciliation_required'
    assert value.sender.sends == 1 and len(value.backend.submissions) == 2


def test_revocation_after_claim_is_checked_by_the_original_pre_send_guard(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path)
    original = value.backend.submit
    def submit(*args, **kwargs):
        value.allowed.clear()
        return original(*args, **kwargs)
    value.backend.submit = submit
    result, authorization = run(value.workflow, 'update')
    assert result['outcome'] == 'reconciliation_required' and value.store.claim_count == 1
    assert not value.backend.submissions
    with pytest.raises(ValueError): value.workflow.execute('update', authorization['authorization_ref'], **IDENTITY)
    for purpose in PURPOSES:
        value.allowed.add((value.policy.reference_for('update', purpose), 'system_email_'+purpose))
    assert value.workflow.execute('update', authorization['authorization_ref'], **IDENTITY)['idempotent_replay']
    assert value.store.claim_count == 1 and not value.backend.submissions
    with pytest.raises(ValueError): value.workflow.preview('update', **IDENTITY)


def test_restore_uses_its_own_permission_and_original_verified_update(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path)
    run(value.workflow, 'update')
    for purpose in PURPOSES:
        value.allowed.remove((value.policy.reference_for('update', purpose), 'system_email_'+purpose))
    assert run(value.workflow, 'restore')[0]['outcome'] == 'succeeded'
    assert len(value.backend.submissions) == 2


def test_short_permission_lifetime_is_reflected_in_authorization_response(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path); value.expiration[0] = 1010
    preview = value.workflow.preview('update', **IDENTITY)
    assert preview['authorization_policy_mode'] == 'lab_auto'
    authorization = value.workflow.authorize('update', preview['preview_ref'], **IDENTITY)
    assert preview['expires_at'] == 1060 and authorization['expires_at'] == 1010
    value.clock.value = 1010
    with pytest.raises(ValueError): value.workflow.execute('update', authorization['authorization_ref'], **IDENTITY)
    assert value.store.claim_count == 0 and not value.backend.submissions


def test_a_newly_shortened_permission_must_survive_the_final_check(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path)
    preview = value.workflow.preview('update', **IDENTITY)
    value.workflow.authorize('update', preview['preview_ref'], **IDENTITY)
    plan, authorization = value.workflow._issued['update']
    value.expiration[0] = 1001
    original = value.policy._reference.authorize
    calls = []
    def authorize(*args, **kwargs):
        result = original(*args, **kwargs); calls.append(result)
        if len(calls) == 3: value.clock.value = 1002
        return result
    monkeypatch.setattr(value.policy._reference, 'authorize', authorize)
    with pytest.raises(M4AuthorizationDenied): value.policy.verify(plan, authorization, now_epoch=1000)
    assert value.store.claim_count == 0 and not value.backend.submissions


def test_unused_authorization_and_policy_key_cannot_be_replaced_silently(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path)
    first = value.workflow.preview('update', **IDENTITY)
    issued = value.workflow.authorize('update', first['preview_ref'], **IDENTITY)
    second = value.workflow.preview('update', **IDENTITY)
    value.workflow.authorize('update', second['preview_ref'], **IDENTITY)
    with pytest.raises(ValueError): value.workflow.execute('update', issued['authorization_ref'], **IDENTITY)
    owner_file(value.key, b'q'*32)
    current = value.workflow._issued['update'][1]
    with pytest.raises(ValueError): value.workflow.execute('update', current.authorization_ref, **IDENTITY)
    assert not value.backend.submissions and value.store.claim_count == 0


def test_changed_delivery_window_is_not_covered_by_existing_grants(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path); run(value.workflow, 'update')
    original = value.sender.inspect
    def inspect(binding):
        observed = original(binding)
        return replace(observed, capture=replace(observed.capture, window_digest='f'*64))
    value.sender.inspect = inspect
    preview = value.workflow.preview('test-delivery', **IDENTITY)
    with pytest.raises(ValueError): value.workflow.authorize('test-delivery', preview['preview_ref'], **IDENTITY)
    assert value.delivery_store.claim_count == 0 and value.sender.sends == 0


def test_a_new_directory_does_not_clear_the_original_grant_namespace(monkeypatch, tmp_path):
    value = make(monkeypatch, tmp_path)
    root = tmp_path/'replacement'; root.mkdir(mode=0o700)
    replacement = construct(root, value.policy._reference)
    assert replacement.policy.reference_for('update', 'permission') != value.policy.reference_for('update', 'permission')
    preview = replacement.workflow.preview('update', **IDENTITY)
    with pytest.raises(ValueError): replacement.workflow.authorize('update', preview['preview_ref'], **IDENTITY)
    assert replacement.store.claim_count == 0 and not replacement.backend.submissions


@contextmanager
def unix_app(app, path):
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); listener.bind(str(path)); path.chmod(0o600); listener.listen(8)
    server = uvicorn.Server(uvicorn.Config(app, access_log=False, log_config=None, lifespan='off', timeout_graceful_shutdown=1))
    thread = Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True); thread.start()
    try:
        deadline = time.monotonic()+5
        while not server.started:
            assert thread.is_alive() and time.monotonic() < deadline
            time.sleep(0.01)
        yield
    finally:
        server.should_exit = True; thread.join(timeout=3)
        assert not thread.is_alive()
        listener.close(); path.unlink(missing_ok=True)


def authority_store(root, clock, *, ttl=60):
    checkpoint_root = root/'reference-checkpoint'; checkpoint_root.mkdir(mode=0o700)
    checkpoint = PersistentReferenceCheckpointAuthority(checkpoint_root/'state.db',
        owner_file(checkpoint_root/'key', b'x'*32), authority_ref='email-test-reference-checkpoint')
    reference_root = root/'reference'; reference_root.mkdir(mode=0o700)
    return PersistentReferenceAuthority(reference_root/'state.db', owner_file(reference_root/'key', b'r'*32),
        authority_ref=REFERENCE_AUTHORITY, monotonic_checkpoint=checkpoint,
        checkpoint_store_ref='email-test-reference-state', clock=clock, decision_ttl_seconds=ttl)


@pytest.mark.parametrize('mode', ['normal', 'revoked', 'short'])
def test_real_unix_reference_grants_and_checkpoints_drive_only_the_fixed_workflow(monkeypatch, tmp_path, mode):
    with tempfile.TemporaryDirectory(prefix='emau-', dir=Path("/tmp").resolve()) as directory:
        sockets = Path(directory); clock = Clock()
        reference = authority_store(tmp_path, clock, ttl=10 if mode == 'short' else 60)
        cas_root = tmp_path/'cas'; cas_root.mkdir(mode=0o700)
        cas = PersistentPlanningCheckpointAuthority(cas_root/'state.db', owner_file(cas_root/'key', b'z'*32),
            authority_ref='email-test-execution-checkpoint')
        with unix_app(create_reference_authority_sidecar_app(reference), sockets/'reference.sock'), \
                unix_app(create_checkpoint_sidecar_app(cas), sockets/'execution.sock'):
            client = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(sockets/'reference.sock', REFERENCE_AUTHORITY))
            settings = []
            for name, key in (('configuration', b'c'*32), ('delivery', b'd'*32)):
                root = tmp_path/name; root.mkdir(mode=0o700)
                settings.append(SystemEmailExecutionStoreSettings(root/'state.db', owner_file(root/'key', key),
                    UnixPlanningCheckpointClientSettings(sockets/'execution.sock', cas.authority_ref), 'email-test-'+name))
            http_settings, app, server = assemble(monkeypatch, tmp_path)
            with TestClient(app, base_url='https://mcp.example.com') as mcp:
                headers = _login(mcp, 'fortipam:read fortipam:plan fortipam:operate')
                token = asyncio.run(LocalOAuthProvider(http_settings.local_oauth).load_access_token(headers['authorization'].split(' ', 1)[1]))
                principal = planning_principal_from_access_token(token, http_settings.v4_planning_authorization)
                identity = dict(requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest)
                value = construct(tmp_path, client, stores=open_system_email_execution_stores(*settings), identity=identity)
                register_system_email_local_candidate_tools(server, SystemEmailLocalMcpAction(value.workflow))
                handles = {}
                for phase in ('update', 'test-delivery', 'restore'):
                    for purpose in PURPOSES:
                        handles[phase, purpose] = reference.issue(value.policy.reference_for(phase, purpose),
                            reference_kind='system_email_'+purpose, requester_digest=identity['requester_digest'],
                            environment_ref=ENVIRONMENT, scope_ref=SCOPE, expires_at=1120, now_epoch=1000)
                phases = ('update', 'test_delivery', 'restore') if mode == 'normal' else ('update',)
                for phase in phases:
                    preview = _call(mcp, headers, f'preview_v4_system_email_local_{phase}_700', {})
                    assert not preview['isError']
                    authorization = _call(mcp, headers, f'authorize_v4_system_email_local_{phase}_700',
                        {'preview_ref': preview['structuredContent']['preview_ref']})
                    assert not authorization['isError']
                    if mode == 'revoked': reference.revoke(handles['update', 'standing_intent'], now_epoch=1000)
                    if mode == 'short':
                        assert authorization['structuredContent']['expires_at'] == 1010
                        value.clock.value = 1010
                    result = _call(mcp, headers, f'execute_v4_system_email_local_{phase}_700',
                        {'authorization_ref': authorization['structuredContent']['authorization_ref']})
                    assert result['isError'] is (mode != 'normal')
                    if mode == 'normal': assert result['structuredContent']['outcome'] == 'succeeded'
                if mode == 'normal':
                    outcome = _call(mcp, headers, 'get_v4_system_email_local_outcome_700', {})['structuredContent']
                    assert outcome['workflow_outcome'] == 'verified_locally' and outcome['native_backend_qualified'] is False
                    assert value.store.claim_count == 2 and value.delivery_store.claim_count == 1
                else:
                    assert value.store.claim_count == 0 and not value.backend.submissions
