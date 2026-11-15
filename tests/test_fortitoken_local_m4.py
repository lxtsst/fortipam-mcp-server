"""Real M4/C3 stores with synthetic User submission and evidence only."""
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from fortipam_mcp.fortitoken_local_m4 import (CONTRACT, FortitokenLocalM4Adapter, FortitokenExecutionScope,
    FortitokenExecutionEvidence, FortitokenBackendReceipt, fortitoken_execution_digests)
from fortipam_mcp.fortitoken_user_contract import FortitokenUserPlan
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_fortitoken_material import Resolver
from test_fortitoken_user_contract import TOKEN, NAME
from test_fortitoken_user_postcondition import apply
from test_fortitoken_user_source import Peer
from test_m4_execution_store import _ExternalM4Checkpoint
from test_system_email_m4_adapter import Verifier
from test_v4_material_persistence import _ExternalMaterialCheckpoint
from v4_planning import M4AdapterDenied, M4ExecutionKernel, M4ExecutionPlan, M4ExecutionAuthorization, canonical_digest
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import MaterialBindingStatus

SCOPE = FortitokenExecutionScope('1'*64,'2'*64,'3'*64,'4'*64,'c'*64,'d'*64,'e'*64,'f'*64)


def stores(root, *, shared_key=False, checkpointed=True):
    key = root/'execution.key'; key.write_bytes(b'x'*32); key.chmod(0o600)
    material_key = root/'material.key'; material_key.write_bytes((b'x' if shared_key else b'm')*32); material_key.chmod(0o600)
    execution = PersistentM4ExecutionStateStore(root/'execution.db',key,
        monotonic_checkpoint=_ExternalM4Checkpoint('ftk-execution-test'),checkpoint_store_ref='ftk-execution-test')
    material = PersistentMaterialUseStateStore(root/'material.db',material_key,
        monotonic_checkpoint=_ExternalMaterialCheckpoint('ftk-material-test') if checkpointed else None,
        checkpoint_store_ref='ftk-material-test' if checkpointed else None)
    return execution,material


def grant(intent,execution,material,*,restore=False,issued_at=1000):
    current,expected,parameters = fortitoken_execution_digests(intent,SCOPE,execution,material)
    if restore: current,expected = expected,current
    action = 'fortitoken-user-'+intent.operation+('-restore' if restore else '')
    fields = dict(plan_ref=action+'-'+parameters,revision=1,action_id=action,action_version='1.0.0',adapter_ref=CONTRACT,
        target_ref='fortitoken-user-'+intent.current.binding.digest,requester_digest=SCOPE.requester_digest,
        summary_digest='a'*64,confirmation_digest='b'*64,approval_digest='c'*64,parameters_digest=parameters,
        expected_current_digest=current,expected_state_digest=expected,
        idempotency_digest=canonical_digest(dict(parameters=parameters,action=action)),expires_at=issued_at+60,compensation_ref=None)
    plan = M4ExecutionPlan(**fields,plan_digest=canonical_digest(fields))
    fields = dict(authorization_ref=action+'-synthetic-authorization',plan_ref=plan.plan_ref,plan_digest=plan.plan_digest,
        requester_digest=SCOPE.requester_digest,confirmation_ref=action+'-synthetic-intent',confirmation_digest=plan.confirmation_digest,
        approval_ref=action+'-synthetic-approval',approval_digest=plan.approval_digest,approver_digest='d'*64,
        issued_at=issued_at,expires_at=issued_at+60,one_time=True,execution_authorized=True)
    return plan,M4ExecutionAuthorization(**fields,authorization_digest=canonical_digest(fields))


class Backend:
    def __init__(self,peer):
        self.peer = peer; self.sends = 0; self.buffers = []; self.fault = None; self.on_submit = self.on_applied = None
    def submit(self,body,*,parameters_digest,restore,before_send,timeout_seconds):
        assert body.readonly and timeout_seconds > 0; self.buffers.append(body.obj)
        if self.on_submit: self.on_submit()
        if self.fault in ('worker','copied-context'):
            context = copy_context()
            with ThreadPoolExecutor(1) as worker:
                worker.submit(before_send if self.fault == 'worker' else lambda:context.run(before_send)).result(timeout=1)
        if self.fault != 'skip-guard': assert before_send() > 0
        if self.fault == 'double-guard': before_send()
        self.sends += 1; apply(self.peer,bytes(body))
        if self.on_applied: self.on_applied()
        if self.fault == 'wrong-token': self.peer.user['fortitoken'] = 'SYNTHETIC_OTHER_TOKEN'
        if self.fault == 'omitted-field': self.peer.user['two-factor-authentication'] = 'email'
        if self.fault == 'preservation': self.peer.user['gui-custom-conf'] = 'enable'
        if self.fault == 'lost-ack': raise TimeoutError('SYNTHETIC_PRIVATE_ACK_LOSS')
        if self.fault == 'interrupt': raise KeyboardInterrupt
        return FortitokenBackendReceipt(SCOPE.configuration_source_digest,
            'a'*64 if self.fault == 'foreign-receipt' else parameters_digest,restore)


class Evidence:
    def __init__(self,peer): self.peer = peer; self.fault = None; self.calls = 0
    def observe(self,configuration_digest):
        self.calls += 1
        # All readiness declarations here are synthetic. This independent peer
        # inspects actual stored fake selectors; it does not echo desired state.
        value = self.peer.user['fortitoken']; now = self.peer.clock()
        reference = None if not value else 'a'*64 if value.encode() == TOKEN else '0'*64
        evidence = FortitokenExecutionEvidence(configuration_digest,SCOPE.token_source_digest,SCOPE.effects_source_digest,
            reference,SCOPE.effects_digest,0,token_custody_verified=True,material_continuity_verified=True,
            native_semantics_verified=True,inventory_license_verified=True,permission_verified=True,
            delivery_isolation_verified=True,recovery_ready=True,complete=True,observed_at=now,expires_at=now+10)
        if self.fault in ('token_custody_verified','material_continuity_verified','native_semantics_verified',
                'inventory_license_verified','permission_verified','delivery_isolation_verified','recovery_ready','complete'):
            evidence = replace(evidence,**{self.fault:False})
        elif self.fault == 'in-flight': evidence = replace(evidence,in_flight=1)
        elif self.fault == 'stale': evidence = replace(evidence,observed_at=now-11,expires_at=now-1)
        elif self.fault in ('token_source_digest','effects_source_digest','configuration_digest','effects_digest'):
            evidence = replace(evidence,**{self.fault:'0'*64})
        return evidence


def make(root,operation='assign',*,enabled=True,guard=True,authorized=True,shared_key=False,checkpointed=True):
    peer = Peer(operation); source = peer.reader(); intent = FortitokenUserPlan(source.read().state,operation)
    execution,material = stores(root,shared_key=shared_key,checkpointed=checkpointed)
    backend = Backend(peer); evidence = Evidence(peer); resolver = Resolver(); recovery = Resolver()
    plan,authorization = grant(intent,execution,material); verifier = Verifier(plan,authorization)
    adapter = FortitokenLocalM4Adapter(intent,source,backend,evidence,resolver,recovery,plan,authorization,execution,material,
        scope=SCOPE,authorization_verifier=verifier if authorized else None,execution_enabled=enabled,
        source_guard=(lambda:True) if guard else None,clock=peer.clock)
    return SimpleNamespace(peer=peer,source=source,intent=intent,execution=execution,material=material,backend=backend,
        evidence=evidence,resolver=resolver,recovery=recovery,plan=plan,authorization=authorization,verifier=verifier,adapter=adapter,
        kernel=M4ExecutionKernel(adapter,verifier,execution,clock=peer.clock))


def restore(value,*,enabled=True,issued_at=1000):
    plan,authorization = grant(value.intent,value.execution,value.material,restore=True,issued_at=issued_at)
    verifier = Verifier(plan,authorization); resolver = Resolver()
    adapter = value.adapter.bind_restore(plan,authorization,resolver=resolver,authorization_verifier=verifier,execution_enabled=enabled)
    return M4ExecutionKernel(adapter,verifier,value.execution,clock=value.peer.clock),plan,authorization,resolver


@pytest.mark.parametrize('operation', ['assign','revoke'])
def test_real_m4_and_separate_material_claims_apply_and_independently_restore_original_once(tmp_path,operation):
    value = make(tmp_path,operation); original = value.intent.current.digest
    assert value.kernel.execute(value.plan,value.authorization).outcome == 'succeeded'
    calls = len(value.peer.calls)
    assert value.kernel.execute(value.plan,value.authorization).idempotent_replay
    assert len(value.peer.calls) == calls and value.resolver.loads == 1 and value.recovery.loads == 0
    value.peer.clock.value = 1100
    kernel,plan,authorization,resolver = restore(value,issued_at=1100)
    assert kernel.execute(plan,authorization).outcome == 'succeeded'
    assert kernel.execute(plan,authorization).idempotent_replay
    assert value.source.read().state.digest == original
    assert value.backend.sends == value.execution.claim_count == value.material.claim_count == 2 and resolver.loads == 1
    assert all(not any(raw) for raw in value.backend.buffers+value.peer.buffers+value.resolver.buffers+resolver.buffers)
    for path in tmp_path.iterdir():
        if path.is_file():
            raw = path.read_bytes(); assert TOKEN not in raw and NAME.encode() not in raw


@pytest.mark.parametrize('options', [dict(enabled=False),dict(guard=False),dict(authorized=False)])
def test_default_closed_authority_and_gate_fail_before_material(tmp_path,options):
    value = make(tmp_path,**options)
    assert value.kernel.execute(value.plan,value.authorization).outcome != 'succeeded'
    assert value.backend.sends == value.resolver.loads == value.material.claim_count == 0


@pytest.mark.parametrize('fault', ['token_custody_verified','material_continuity_verified','native_semantics_verified',
    'inventory_license_verified','permission_verified','delivery_isolation_verified','recovery_ready','complete',
    'in-flight','stale','token_source_digest','effects_source_digest','configuration_digest','effects_digest'])
def test_missing_or_drifting_independent_evidence_never_loads_material(tmp_path,fault):
    value = make(tmp_path); value.evidence.fault = fault
    assert value.kernel.execute(value.plan,value.authorization).outcome != 'succeeded'
    assert value.backend.sends == value.resolver.loads == value.material.claim_count == 0


@pytest.mark.parametrize('fault', ['wrong-token','omitted-field','preservation','lost-ack','foreign-receipt','skip-guard'])
def test_post_write_uncertainty_is_consumed_without_restore_or_replay(tmp_path,fault):
    value = make(tmp_path); value.backend.fault = fault
    assert value.kernel.execute(value.plan,value.authorization).outcome != 'succeeded'
    assert value.kernel.execute(value.plan,value.authorization).idempotent_replay
    assert value.backend.sends == value.resolver.loads == value.material.claim_count == 1
    with pytest.raises(M4AdapterDenied): restore(value)
    assert all(not any(raw) for raw in value.backend.buffers+value.peer.buffers+value.resolver.buffers)


@pytest.mark.parametrize('fault', ['deadline','drift','revoked','double-guard','worker','copied-context'])
def test_final_send_rechecks_deadline_drift_authority_and_original_kernel_thread(tmp_path,fault):
    value = make(tmp_path)
    if fault == 'deadline': value.backend.on_submit = lambda:setattr(value.peer.clock,'value',1060)
    elif fault == 'drift': value.backend.on_submit = lambda:value.peer.user.update(comments='changed')
    elif fault == 'revoked': value.backend.on_submit = lambda:setattr(value.verifier,'pair',(None,None))
    else: value.backend.fault = fault
    assert value.kernel.execute(value.plan,value.authorization).outcome != 'succeeded'
    assert value.backend.sends == 0 and value.resolver.loads == value.material.claim_count == 1


@pytest.mark.parametrize('options', [dict(shared_key=True),dict(checkpointed=False)])
def test_shared_keys_and_unbound_material_checkpoint_cannot_construct_execution(tmp_path,options):
    with pytest.raises(M4AdapterDenied): make(tmp_path,**options)


def test_known_noninvertible_cached_authentication_is_not_an_execution_candidate(tmp_path):
    peer = Peer(); peer.user['two-factor-authentication'] = 'email'; source = peer.reader()
    intent = FortitokenUserPlan(source.read().state,'assign'); execution,material = stores(tmp_path)
    with pytest.raises(M4AdapterDenied): grant(intent,execution,material)
    assert execution.claim_count == material.claim_count == 0


def test_interrupted_consumption_and_new_adapter_cannot_reacquire_or_adopt_original_receipt(tmp_path):
    value = make(tmp_path); value.backend.fault = 'interrupt'
    with pytest.raises(KeyboardInterrupt): value.kernel.execute(value.plan,value.authorization)
    assert value.backend.sends == value.resolver.loads == value.material.claim_count == 1
    assert all(not any(raw) for raw in value.backend.buffers+value.peer.buffers+value.resolver.buffers)
    with pytest.raises(M4AdapterDenied): restore(value)


def test_new_directory_cannot_reuse_an_existing_execution_grant(tmp_path):
    value = make(tmp_path); new_root = tmp_path/'other'; new_root.mkdir(mode=0o700); execution,material = stores(new_root)
    with pytest.raises(M4AdapterDenied):
        FortitokenLocalM4Adapter(value.intent,value.source,value.backend,value.evidence,value.resolver,value.recovery,
            value.plan,value.authorization,execution,material,scope=SCOPE,authorization_verifier=value.verifier,
            execution_enabled=True,source_guard=lambda:True,clock=value.peer.clock)
    assert execution.claim_count == material.claim_count == value.resolver.loads == 0


@pytest.mark.parametrize('fault', ['material_continuity_verified','effects_digest','in-flight'])
def test_late_effects_or_material_continuity_loss_is_not_hidden_by_a_matching_selector(tmp_path,fault):
    value = make(tmp_path)
    value.backend.on_applied = lambda:setattr(value.evidence,'fault',fault)
    assert value.kernel.execute(value.plan,value.authorization).outcome != 'succeeded'
    assert value.peer.user['fortitoken'].encode() == TOKEN and value.backend.sends == 1
    with pytest.raises(M4AdapterDenied): restore(value)
    assert value.kernel.execute(value.plan,value.authorization).idempotent_replay and value.resolver.loads == 1


def test_missing_independent_recovery_source_denies_before_loading(tmp_path):
    value = make(tmp_path); value.recovery.status = MaterialBindingStatus.UNAVAILABLE
    assert value.kernel.execute(value.plan,value.authorization).outcome != 'succeeded'
    assert value.resolver.loads == value.material.claim_count == value.backend.sends == 0


def test_independent_restore_gate_is_closed_by_default(tmp_path):
    value = make(tmp_path); assert value.kernel.execute(value.plan,value.authorization).outcome == 'succeeded'
    kernel,plan,authorization,resolver = restore(value,enabled=False)
    assert kernel.execute(plan,authorization).outcome != 'succeeded'
    assert resolver.loads == 0 and value.backend.sends == value.material.claim_count == 1


def test_new_adapter_cannot_adopt_a_successful_original_receipt(tmp_path):
    value = make(tmp_path); assert value.kernel.execute(value.plan,value.authorization).outcome == 'succeeded'
    replacement = FortitokenLocalM4Adapter(value.intent,value.source,value.backend,value.evidence,Resolver(),value.recovery,
        value.plan,value.authorization,value.execution,value.material,scope=SCOPE,authorization_verifier=value.verifier,
        execution_enabled=True,source_guard=lambda:True,clock=value.peer.clock)
    assert M4ExecutionKernel(replacement,value.verifier,value.execution,clock=value.peer.clock).execute(
        value.plan,value.authorization).idempotent_replay
    plan,authorization = grant(value.intent,value.execution,value.material,restore=True)
    with pytest.raises(M4AdapterDenied): replacement.bind_restore(plan,authorization,resolver=value.recovery)
    assert value.resolver.loads == value.backend.sends == 1


def test_clock_failure_cannot_be_cleared_by_a_fresh_recovery_grant(tmp_path):
    value = make(tmp_path); assert value.kernel.execute(value.plan,value.authorization).outcome == 'succeeded'
    value.peer.clock.value = 999
    with pytest.raises(M4AdapterDenied): value.adapter.read_current(value.plan)
    value.peer.clock.value = 1100
    with pytest.raises(M4AdapterDenied): restore(value,issued_at=1100)
    assert value.backend.sends == value.resolver.loads == value.material.claim_count == 1
