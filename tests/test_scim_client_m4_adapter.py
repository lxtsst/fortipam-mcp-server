"""Local SCIM M4/C3 boundaries with independent synthetic credential observation."""
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.scim_client_contract import ScimNonmaterialState
from fortipam_mcp.scim_client_m4_adapter import (CONTRACT, ScimLocalM4Adapter, ScimExecutionScope,
    ScimConfigurationReadback, ScimExecutionEvidence, ScimBackendReceipt, scim_execution_digests)
from test_scim_client_contract import prepared, values, CONTEXT, OLD, NEW
from test_scim_client_material import Resolver
from test_system_email_m4_adapter import Clock, Verifier
from test_m4_execution_store import _ExternalM4Checkpoint
from test_v4_material_persistence import _ExternalMaterialCheckpoint
from v4_planning import M4AdapterDenied, M4ExecutionKernel, M4ExecutionPlan, M4ExecutionAuthorization, canonical_digest
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import MaterialBindingStatus

SCOPE = ScimExecutionScope('8'*64, '1'*64, '2'*64, '3'*64, '4'*64, '5'*64, '6'*64, '7'*64)


def grant(transition, store, material, restore=False):
    current, expected, parameters = scim_execution_digests(transition, SCOPE, store, material)
    action = 'scim-client-'+transition.operation+('-restore' if restore else '')
    if restore: current, expected = expected, current
    fields = dict(plan_ref=action+'-'+parameters, revision=1, action_id=action, action_version='1.0.0',
        adapter_ref=CONTRACT, target_ref='scim-singleton-'+json.loads(transition._context)['serial_digest'], requester_digest=SCOPE.requester_digest,
        summary_digest='a'*64, confirmation_digest='b'*64, approval_digest='c'*64, parameters_digest=parameters,
        expected_current_digest=current, expected_state_digest=expected,
        idempotency_digest=canonical_digest(dict(parameters=parameters, action=action)), expires_at=1060, compensation_ref=None)
    plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
    fields = dict(authorization_ref=action+'-synthetic-auth', plan_ref=plan.plan_ref, plan_digest=plan.plan_digest,
        requester_digest=SCOPE.requester_digest, confirmation_ref=action+'-synthetic-intent', confirmation_digest=plan.confirmation_digest,
        approval_ref=action+'-synthetic-approval', approval_digest=plan.approval_digest, approver_digest='d'*64,
        issued_at=1000, expires_at=1060, one_time=True, execution_authorized=True)
    return plan, M4ExecutionAuthorization(**fields, authorization_digest=canonical_digest(fields))


def stores(tmp_path, material_key=b'm'*32, material_checkpointed=True):
    m4_key = tmp_path/'execution.key'; m4_key.write_bytes(b'x'*32); m4_key.chmod(0o600)
    material_path = tmp_path/'material.key'; material_path.write_bytes(material_key); material_path.chmod(0o600)
    store = PersistentM4ExecutionStateStore(tmp_path/'execution.db', m4_key,
        monotonic_checkpoint=_ExternalM4Checkpoint('scim-execution-test'), checkpoint_store_ref='scim-execution-test')
    material = PersistentMaterialUseStateStore(tmp_path/'material.db', material_path,
        monotonic_checkpoint=_ExternalMaterialCheckpoint('scim-material-test') if material_checkpointed else None,
        checkpoint_store_ref='scim-material-test' if material_checkpointed else None)
    return store, material


class Backend:
    def __init__(self, clock, transition, fault='none'):
        self.clock = clock; self.transition = transition; self.fault = fault
        self.config = values(); self.material = 'synthetic-old-secret'; self.sends = 0; self.buffers = []
        self.on_submit = None
    def inspect(self):
        if self.sends and self.fault == 'post-read': raise TimeoutError('SYNTHETIC_PRIVATE_FAILURE')
        return ScimConfigurationReadback(ScimNonmaterialState.from_values(self.config), self.transition._context, SCOPE.configuration_source_digest)
    def submit(self, body, *, parameters_digest, restore, before_send, timeout_seconds):
        assert body.readonly and timeout_seconds > 0
        self.buffers.append(body.obj)
        if self.on_submit: self.on_submit()
        if self.fault == 'expired': self.clock.value = 1060
        if self.fault == 'late-drift': self.config['token-certificate'] = 'synthetic-drift'
        if self.fault in ('foreign', 'copied'):
            context = copy_context()
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(before_send if self.fault == 'foreign' else lambda: context.run(before_send)).result(timeout=1)
        if self.fault != 'skip-guard': assert before_send() > 0
        if self.fault == 'double-guard': before_send()
        wire = json.loads(bytes(body)); self.sends += 1
        self.material = wire.pop('secret'); self.config.update(wire)
        if self.fault == 'wrong-credential': self.material = 'synthetic-wrong-secret'
        if self.fault == 'omitted-drift': self.config['token-certificate'] = 'synthetic-drift'
        if self.fault == 'lost-ack': raise TimeoutError('SYNTHETIC_PRIVATE_FAILURE')
        if self.fault == 'interrupt': raise KeyboardInterrupt
        return ScimBackendReceipt(SCOPE.configuration_source_digest, parameters_digest, restore)


class Evidence:
    def __init__(self, backend): self.backend = backend; self.fault = None; self.calls = 0
    def observe(self, configuration_digest):
        self.calls += 1; backend = self.backend; now = backend.clock()
        # This independent fake authentication probe examines actual stored
        # synthetic material, not the desired binding or configuration status.
        material = {'synthetic-old-secret': OLD, 'synthetic-new-secret': NEW}.get(backend.material, 'f'*64)
        evidence = ScimExecutionEvidence(configuration_digest, SCOPE.credential_source_digest, SCOPE.effects_source_digest,
            material, SCOPE.effects_digest, 0, True, True, now, now+10)
        if self.fault == 'in-flight': evidence = replace(evidence, in_flight=1)
        if self.fault == 'incomplete': evidence = replace(evidence, complete=False)
        if self.fault == 'recovery': evidence = replace(evidence, recovery_ready=False)
        if self.fault == 'stale': evidence = replace(evidence, observed_at=now-11, expires_at=now-1)
        if self.fault in ('credential-source', 'effects-source', 'configuration'):
            field = {'credential-source':'credential_source_digest', 'effects-source':'effects_source_digest',
                'configuration':'configuration_digest'}[self.fault]
            evidence = replace(evidence, **{field:'e'*64})
        if self.fault == 'effects' and backend.sends: evidence = replace(evidence, effects_digest='e'*64)
        return evidence


def make(tmp_path, operation='rotate', fault='none', enabled=True, guard=True, verifier_enabled=True, **store_options):
    change, _, binding = prepared(operation); clock = Clock(); store, material = stores(tmp_path, **store_options)
    backend = Backend(clock, change, fault); evidence = Evidence(backend)
    resolver = Resolver(binding, b'synthetic-new-secret' if operation == 'rotate' else b'synthetic-old-secret')
    recovery = Resolver(OLD, b'synthetic-old-secret'); plan, authorization = grant(change, store, material)
    verifier = Verifier(plan, authorization)
    adapter = ScimLocalM4Adapter(change, backend, evidence, resolver, recovery, plan, authorization, store, material,
        scope=SCOPE, authorization_verifier=verifier if verifier_enabled else None, execution_enabled=enabled,
        source_guard=(lambda: True) if guard else None, clock=clock)
    kernel = M4ExecutionKernel(adapter, verifier, store, clock=clock)
    return SimpleNamespace(change=change, clock=clock, store=store, material=material, backend=backend, evidence=evidence,
        resolver=resolver, recovery=recovery, plan=plan, authorization=authorization, verifier=verifier, adapter=adapter, kernel=kernel)


@pytest.mark.parametrize('operation', ['rotate', 'disable'])
def test_independent_m4_and_material_claims_verify_apply_and_original_instance_restore_once(tmp_path, operation):
    value = make(tmp_path, operation)
    assert value.kernel.execute(value.plan, value.authorization).outcome == 'succeeded'
    assert value.kernel.execute(value.plan, value.authorization).idempotent_replay
    assert value.backend.sends == 1 and value.resolver.loads == 1 and value.recovery.loads == 0
    plan, authorization = grant(value.change, value.store, value.material, True); verifier = Verifier(plan, authorization)
    resolver = Resolver(OLD, b'synthetic-old-secret')
    restore = value.adapter.bind_restore(plan, authorization, resolver=resolver, authorization_verifier=verifier, execution_enabled=True)
    kernel = M4ExecutionKernel(restore, verifier, value.store, clock=value.clock)
    assert kernel.execute(plan, authorization).outcome == 'succeeded'
    assert kernel.execute(plan, authorization).idempotent_replay
    assert value.backend.sends == 2 and value.store.claim_count == value.material.claim_count == 2
    assert value.backend.config == values() and value.backend.material == 'synthetic-old-secret'
    assert all(not any(buffer) for buffer in value.backend.buffers + value.resolver.buffers + resolver.buffers)
    for path in tmp_path.iterdir():
        if path.is_file(): assert b'synthetic-new-secret' not in path.read_bytes()


@pytest.mark.parametrize('options', [dict(enabled=False), dict(guard=False), dict(verifier_enabled=False)])
def test_independent_gates_and_default_verifier_deny_before_material_loading(tmp_path, options):
    value = make(tmp_path, **options)
    assert value.kernel.execute(value.plan, value.authorization).outcome != 'succeeded'
    assert value.backend.sends == value.resolver.loads == value.material.claim_count == 0


@pytest.mark.parametrize('fault', ['in-flight','incomplete','recovery','stale','credential-source','effects-source','configuration'])
def test_missing_or_foreign_independent_evidence_does_not_load_material(tmp_path, fault):
    value = make(tmp_path); value.evidence.fault = fault
    assert value.kernel.execute(value.plan, value.authorization).outcome != 'succeeded'
    assert value.backend.sends == value.resolver.loads == value.material.claim_count == 0


@pytest.mark.parametrize('fault', ['wrong-credential','omitted-drift','lost-ack','post-read','effects','skip-guard'])
def test_post_write_uncertainty_is_consumed_and_does_not_qualify_restore(tmp_path, fault):
    value = make(tmp_path, fault=fault if fault != 'effects' else 'none')
    if fault == 'effects': value.evidence.fault = fault
    result = value.kernel.execute(value.plan, value.authorization)
    assert result.outcome != 'succeeded' and value.backend.sends == 1
    assert value.kernel.execute(value.plan, value.authorization).idempotent_replay
    assert value.backend.sends == value.resolver.loads == 1
    assert all(not any(buffer) for buffer in value.resolver.buffers + value.backend.buffers)
    assert 'SYNTHETIC_PRIVATE_FAILURE' not in json.dumps(result.as_dict())
    plan, authorization = grant(value.change, value.store, value.material, True)
    with pytest.raises(M4AdapterDenied): value.adapter.bind_restore(plan, authorization, resolver=value.recovery)


@pytest.mark.parametrize('fault', ['expired','late-drift','double-guard','foreign','copied','revoked'])
def test_original_final_guard_rejects_deadline_drift_repeat_worker_and_revocation(tmp_path, fault):
    value = make(tmp_path, fault=fault)
    if fault == 'revoked': value.backend.on_submit = lambda: setattr(value.verifier, 'pair', (None, None))
    assert value.kernel.execute(value.plan, value.authorization).outcome != 'succeeded'
    assert value.backend.sends == 0 and value.resolver.loads == 1
    assert all(not any(buffer) for buffer in value.resolver.buffers + value.backend.buffers)


def test_interrupted_material_consumption_remains_uncertain_and_reopen_never_reloads(tmp_path):
    value = make(tmp_path, fault='interrupt')
    with pytest.raises(KeyboardInterrupt): value.kernel.execute(value.plan, value.authorization)
    assert value.backend.sends == 1 and all(not any(buffer) for buffer in value.resolver.buffers + value.backend.buffers)
    store = PersistentM4ExecutionStateStore(value.store._path, value.store._key_path,
        monotonic_checkpoint=value.store._monotonic_checkpoint, checkpoint_store_ref=value.store._checkpoint_store_ref)
    kernel = M4ExecutionKernel(value.adapter, value.verifier, store, clock=value.clock)
    assert kernel.execute(value.plan, value.authorization).outcome != 'succeeded'
    assert value.backend.sends == value.resolver.loads == 1


def test_new_host_can_read_cached_result_but_cannot_adopt_original_restore_receipt(tmp_path):
    value = make(tmp_path)
    assert value.kernel.execute(value.plan, value.authorization).outcome == 'succeeded'
    replacement = ScimLocalM4Adapter(value.change, value.backend, value.evidence, Resolver(NEW), value.recovery,
        value.plan, value.authorization, value.store, value.material, scope=SCOPE,
        authorization_verifier=value.verifier, execution_enabled=True, source_guard=lambda: True, clock=value.clock)
    assert M4ExecutionKernel(replacement, value.verifier, value.store, clock=value.clock).execute(
        value.plan, value.authorization).idempotent_replay
    plan, authorization = grant(value.change, value.store, value.material, True)
    with pytest.raises(M4AdapterDenied): replacement.bind_restore(plan, authorization, resolver=value.recovery)


@pytest.mark.parametrize('store_options', [dict(material_key=b'x'*32), dict(material_checkpointed=False)])
def test_material_and_execution_domains_cannot_share_keys_or_lose_checkpoint_binding(tmp_path, store_options):
    with pytest.raises(M4AdapterDenied): make(tmp_path, **store_options)


def test_create_stays_closed_while_native_id_assignment_and_absence_recovery_are_unqualified(tmp_path):
    transition, _, _ = prepared('create')
    store, material = stores(tmp_path)
    with pytest.raises(M4AdapterDenied): scim_execution_digests(transition, SCOPE, store, material)
    # No plan/grant is fabricated for the unresolved creation contract.


def test_new_state_directory_cannot_reuse_an_existing_grant_to_reopen_consumed_dispatch(tmp_path):
    root = tmp_path/'original'; root.mkdir(mode=0o700)
    value = make(root)
    assert value.kernel.execute(value.plan, value.authorization).outcome == 'succeeded'
    replacement = tmp_path/'replacement'; replacement.mkdir(mode=0o700)
    store, material = stores(replacement)
    resolver = Resolver(NEW)
    with pytest.raises(M4AdapterDenied):
        ScimLocalM4Adapter(value.change, value.backend, value.evidence, resolver, value.recovery,
            value.plan, value.authorization, store, material, scope=SCOPE, authorization_verifier=value.verifier,
            execution_enabled=True, source_guard=lambda: True, clock=value.clock)
    assert resolver.loads == 0 and store.claim_count == material.claim_count == 0


def test_new_material_reference_does_not_reopen_a_workflow_with_an_uncertain_prior_claim(tmp_path):
    value = make(tmp_path, fault='lost-ack')
    assert value.kernel.execute(value.plan, value.authorization).outcome != 'succeeded'
    # Even an unchanged-state observation after external reconciliation cannot
    # reset this workflow's consumed dispatch. A new reference is not recovery.
    value.backend.material = 'synthetic-old-secret'; value.backend.fault = 'none'
    change = replace(value.change, _new_material_binding_digest='9'*64)
    plan, authorization = grant(change, value.store, value.material)
    verifier = Verifier(plan, authorization); resolver = Resolver('9'*64)
    adapter = ScimLocalM4Adapter(change, value.backend, value.evidence, resolver, value.recovery,
        plan, authorization, value.store, value.material, scope=SCOPE,
        authorization_verifier=verifier, execution_enabled=True, source_guard=lambda: True, clock=value.clock)
    assert M4ExecutionKernel(adapter, verifier, value.store, clock=value.clock).execute(plan, authorization).outcome != 'succeeded'
    assert value.backend.sends == 1 and resolver.loads == 0 and value.material.claim_count == 1
