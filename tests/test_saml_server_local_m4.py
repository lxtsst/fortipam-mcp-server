"""Real M4 persistence/kernel and fixed source, with synthetic product ACKs."""
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.saml_server_local_m4 import (CONTRACT, SamlExecutionScope, SamlLocalM4Adapter,
    SamlBackendReceipt, saml_execution_digests)
from fortipam_mcp.saml_server_native_source import COLLECTION_PATH
from test_m4_execution_store import _ExternalM4Checkpoint
from test_saml_server_contract import created_record
from test_saml_server_native_source import Peer, envelope
from test_system_email_m4_adapter import Verifier
from v4_planning import (M4AdapterDenied, M4AuthorizationDenied, M4ExecutionAuthorization, M4ExecutionKernel,
    M4ExecutionPlan, canonical_digest)

SCOPE = SamlExecutionScope('a'*64,'b'*64,'c'*64,'d'*64,'1'*64,'2'*64)


def grant(initial, store, *, restore=False):
    current,expected,parameters = saml_execution_digests(initial,SCOPE,store)
    if restore: current,expected = expected,current
    action = 'saml-inert-fixture-'+('remove' if restore else 'create')
    fields = dict(plan_ref=action+'-'+parameters,revision=1,action_id=action,action_version='1.0.0',adapter_ref=CONTRACT,
        target_ref='saml-fixture-'+initial.plan.binding.digest,requester_digest=SCOPE.requester_digest,
        summary_digest='3'*64,confirmation_digest='4'*64,approval_digest='5'*64,parameters_digest=parameters,
        expected_current_digest=current,expected_state_digest=expected,
        idempotency_digest=canonical_digest(dict(parameters=parameters,action=action)),expires_at=1060,compensation_ref=None)
    plan = M4ExecutionPlan(**fields,plan_digest=canonical_digest(fields))
    fields = dict(authorization_ref=action+'-synthetic-authorization',plan_ref=plan.plan_ref,plan_digest=plan.plan_digest,
        requester_digest=SCOPE.requester_digest,confirmation_ref=action+'-synthetic-intent',confirmation_digest=plan.confirmation_digest,
        approval_ref=action+'-synthetic-approval',approval_digest=plan.approval_digest,approver_digest='6'*64,
        issued_at=1000,expires_at=1060,one_time=True,execution_authorized=True)
    return plan,M4ExecutionAuthorization(**fields,authorization_digest=canonical_digest(fields))


class Backend:
    def __init__(self, peer, source):
        self.peer,self.source = peer,source
        self.sends = 0; self.buffers = []; self.fault = None; self.on_send = None
    def inspect(self): return self.source.read()
    def submit(self, body, *, parameters_digest, restore, before_send, timeout_seconds):
        assert timeout_seconds > 0
        if self.on_send: self.on_send()
        if self.fault == 'worker':
            with ThreadPoolExecutor(1) as worker: worker.submit(copy_context().run,before_send).result()
        else: assert before_send() > 0
        if self.fault == 'double-guard': before_send()
        self.sends += 1
        self.peer.dependencies.references += -1 if restore else 1
        if restore:
            assert body is None
            rows = self.peer.payloads[COLLECTION_PATH]['results']
            rows[:] = [row for row in rows if row['name'] != self.peer.plan.binding.name]
            self.peer.payloads[self.peer.detail] = envelope(None,status=404)
        else:
            assert body.readonly; self.buffers.append(body.obj)
            native = json.loads(bytes(body))
            assert len(native) == 18 and native['$originalName'] == ''
            candidate = created_record(self.peer.original,self.peer.defaults,self.peer.plan)
            assert all(candidate[name] == value for name,value in native.items() if name != '$originalName')
            if self.fault == 'wrong-record': candidate['user-name'] = 'synthetic-wrong-user'
            if self.fault == 'referenced': candidate['q_ref'] = 1
            self.peer.payloads[COLLECTION_PATH]['results'].append(candidate)
            self.peer.payloads[self.peer.detail] = envelope(candidate)
        size = len(self.peer.payloads[COLLECTION_PATH]['results'])
        self.peer.payloads[COLLECTION_PATH].update(size=size,matched_count=size)
        if self.fault == 'lost-ack': raise RuntimeError('SYNTHETIC_PRIVATE_LOST_ACK')
        if self.fault == 'interrupt': raise KeyboardInterrupt
        if self.fault == 'post-deadline': self.peer.clock.value = 1060
        return SamlBackendReceipt('f'*64 if self.fault == 'foreign-ack' else SCOPE.configuration_source_digest,
            parameters_digest,restore)


def make(root, *, enabled=True, guarded=True, authorized=True, opened=None, peer=None):
    peer = peer if peer is not None else Peer(); observe = peer.dependencies.observe
    peer.dependencies.observe = lambda *args,**kwargs: replace(observe(*args,**kwargs),
        runtime_isolation_verified=True,independent_recovery_ready=True)
    source = peer.source(); initial = source.read(); backend = Backend(peer,source)
    if opened is None:
        key = root/'execution.key'; key.write_bytes(b'x'*32); key.chmod(0o600)
        store = PersistentM4ExecutionStateStore(root/'execution.db',key,
            monotonic_checkpoint=_ExternalM4Checkpoint('saml-local-execution'),checkpoint_store_ref='saml-local-execution')
    else: store = opened
    plan,authorization = grant(initial,store); verifier = Verifier(plan,authorization)
    adapter = SamlLocalM4Adapter(initial,SCOPE,backend,plan,authorization,store,
        authorization_verifier=verifier if authorized else None,execution_enabled=enabled,
        source_guard=(lambda: True) if guarded else None,clock=peer.clock)
    kernel = M4ExecutionKernel(adapter,verifier,store,clock=peer.clock)
    return SimpleNamespace(peer=peer,source=source,initial=initial,backend=backend,store=store,plan=plan,
        authorization=authorization,verifier=verifier,adapter=adapter,kernel=kernel)


def removal(value, *, enabled=True, authorized=True):
    plan,authorization = grant(value.initial,value.store,restore=True); verifier = Verifier(plan,authorization)
    adapter = value.adapter.bind_restore(plan,authorization,authorization_verifier=verifier if authorized else None,
        execution_enabled=enabled)
    return M4ExecutionKernel(adapter,verifier,value.store,clock=value.peer.clock),plan,authorization


def test_creation_and_independent_original_receipt_removal_preserve_the_full_baseline(tmp_path):
    value = make(tmp_path)
    assert value.kernel.execute(value.plan,value.authorization).outcome == 'succeeded'
    assert value.kernel.execute(value.plan,value.authorization).idempotent_replay
    assert value.backend.sends == value.store.claim_count == 1
    kernel,plan,authorization = removal(value)
    assert kernel.execute(plan,authorization).outcome == 'succeeded'
    assert kernel.execute(plan,authorization).idempotent_replay
    assert value.backend.sends == value.store.claim_count == 2
    assert value.source.read()._collection == value.initial._collection
    assert all(not any(raw) for raw in value.backend.buffers+value.peer.buffers)


@pytest.mark.parametrize('options', [dict(enabled=False),dict(guarded=False),dict(authorized=False)])
def test_each_independent_gate_denies_before_a_send(tmp_path, options):
    value = make(tmp_path,**options)
    assert value.kernel.execute(value.plan,value.authorization).outcome != 'succeeded'
    assert value.backend.sends == 0


@pytest.mark.parametrize('missing', ['runtime_isolation_verified','independent_recovery_ready'])
def test_zero_reference_and_invalid_urls_cannot_replace_dependency_proofs(tmp_path, missing):
    value = make(tmp_path); observe = value.peer.dependencies.observe
    value.peer.dependencies.observe = lambda *args,**kwargs: replace(observe(*args,**kwargs),**{missing:False})
    assert value.kernel.execute(value.plan,value.authorization).outcome != 'succeeded'
    assert value.backend.sends == 0


@pytest.mark.parametrize('fault', ['lost-ack','foreign-ack','wrong-record','referenced','post-deadline'])
def test_uncertain_or_wrong_post_state_never_gets_removal_rights_or_replays(tmp_path, fault):
    value = make(tmp_path); value.backend.fault = fault
    result = value.kernel.execute(value.plan,value.authorization)
    assert result.outcome != 'succeeded'
    assert 'SYNTHETIC_PRIVATE_LOST_ACK' not in json.dumps(result.as_dict())
    if fault == 'post-deadline':
        with pytest.raises(M4AuthorizationDenied): value.kernel.execute(value.plan,value.authorization)
    else: assert value.kernel.execute(value.plan,value.authorization).idempotent_replay
    assert value.backend.sends == 1 and all(not any(raw) for raw in value.backend.buffers)
    with pytest.raises(M4AdapterDenied): removal(value)


@pytest.mark.parametrize('fault', ['referenced','metadata-drift','other-record','source-drift','certificate-reference'])
def test_removal_refuses_complete_record_collection_or_dependency_drift(tmp_path, fault):
    value = make(tmp_path); assert value.kernel.execute(value.plan,value.authorization).outcome == 'succeeded'
    candidate = value.peer.payloads[value.peer.detail]['results']
    if fault == 'referenced': candidate['q_ref'] = 1
    elif fault == 'metadata-drift': candidate['q_type'] = 1
    elif fault == 'source-drift': value.peer.original['display-name-attr'] = 'synthetic-source-drift'
    elif fault == 'certificate-reference': value.peer.dependencies.references += 1
    else:
        extra = dict(value.peer.original,name='synthetic-other',q_origin_key='synthetic-other')
        value.peer.payloads[COLLECTION_PATH]['results'].append(extra)
        value.peer.payloads[COLLECTION_PATH].update(size=3,matched_count=3)
    kernel,plan,authorization = removal(value)
    assert kernel.execute(plan,authorization).outcome != 'succeeded'
    assert value.backend.sends == 1


@pytest.mark.parametrize('options', [dict(enabled=False),dict(authorized=False)])
def test_removal_does_not_inherit_creation_gates_or_authorization(tmp_path, options):
    value = make(tmp_path); assert value.kernel.execute(value.plan,value.authorization).outcome == 'succeeded'
    kernel,plan,authorization = removal(value,**options)
    assert kernel.execute(plan,authorization).outcome != 'succeeded'
    assert value.backend.sends == 1


@pytest.mark.parametrize('fault', ['worker','double-guard','expired','revoked'])
def test_last_guard_rejects_worker_context_repeat_deadline_and_revocation(tmp_path, fault):
    value = make(tmp_path)
    if fault == 'expired': value.backend.on_send = lambda: setattr(value.peer.clock,'value',1060)
    elif fault == 'revoked': value.backend.on_send = lambda: setattr(value.verifier,'pair',(None,None))
    else: value.backend.fault = fault
    assert value.kernel.execute(value.plan,value.authorization).outcome != 'succeeded'
    assert value.backend.sends == 0 and all(not any(raw) for raw in value.backend.buffers)


def test_replacement_store_domain_cannot_inherit_a_plan_or_adopt_a_receipt(tmp_path):
    value = make(tmp_path)
    other_root = tmp_path/'other'; other_root.mkdir(mode=0o700); other = make(other_root)
    with pytest.raises(M4AdapterDenied): SamlLocalM4Adapter(value.initial,SCOPE,value.backend,value.plan,
        value.authorization,other.store,clock=value.peer.clock)
    with pytest.raises(M4AuthorizationDenied): value.adapter._before_send()
    with pytest.raises(M4AdapterDenied): removal(value)
    assert value.backend.sends == 0


def test_interruption_keeps_the_claim_and_cannot_adopt_an_observed_candidate(tmp_path):
    value = make(tmp_path); value.backend.fault = 'interrupt'
    with pytest.raises(KeyboardInterrupt): value.kernel.execute(value.plan,value.authorization)
    assert value.backend.sends == value.store.claim_count == 1
    assert all(not any(raw) for raw in value.backend.buffers)
    reopened = PersistentM4ExecutionStateStore(value.store._path,value.store._key_path,
        monotonic_checkpoint=value.store._monotonic_checkpoint,checkpoint_store_ref=value.store._checkpoint_store_ref)
    kernel = M4ExecutionKernel(value.adapter,value.verifier,reopened,clock=value.peer.clock)
    assert kernel.execute(value.plan,value.authorization).outcome != 'succeeded'
    assert value.backend.sends == 1
    with pytest.raises(M4AdapterDenied): removal(value)
    with pytest.raises(M4AdapterDenied): saml_execution_digests(value.source.read(),SCOPE,reopened)


def test_lost_removal_ack_remains_uncertain_even_when_absence_is_observable(tmp_path):
    value = make(tmp_path); assert value.kernel.execute(value.plan,value.authorization).outcome == 'succeeded'
    kernel,plan,authorization = removal(value); value.backend.fault = 'lost-ack'
    assert kernel.execute(plan,authorization).outcome != 'succeeded'
    assert value.source.read()._collection == value.initial._collection
    assert kernel.execute(plan,authorization).idempotent_replay
    assert value.backend.sends == value.store.claim_count == 2


def test_later_absence_does_not_erase_the_original_created_record(tmp_path):
    value = make(tmp_path); assert value.kernel.execute(value.plan,value.authorization).outcome == 'succeeded'
    original = value.adapter._created_record
    value.peer.payloads[COLLECTION_PATH]['results'] = [value.peer.original]
    value.peer.payloads[COLLECTION_PATH].update(size=1,matched_count=1)
    value.peer.payloads[value.peer.detail] = envelope(None,status=404)
    value.peer.dependencies.references -= 1
    assert value.adapter.read_current(value.plan) == value.plan.expected_current_digest
    assert value.adapter._created_record == original and original is not None
    assert value.backend.sends == value.store.claim_count == 1


@pytest.mark.parametrize('mismatch', ['configuration-source','dependency-source','unready','sp-certificate'])
def test_initial_domain_proofs_and_empty_sp_certificate_profile_are_required(tmp_path, mismatch):
    value = make(tmp_path); initial = value.initial
    if mismatch == 'configuration-source': initial = replace(initial,source_digest='f'*64)
    elif mismatch == 'dependency-source': initial = replace(initial,dependencies=replace(initial.dependencies,source_digest='f'*64))
    elif mismatch == 'unready': initial = replace(initial,dependencies=replace(initial.dependencies,runtime_isolation_verified=False))
    else:
        value.peer.original['cert'] = 'synthetic-unqualified-sp-certificate'
        initial = value.source.read()
    with pytest.raises(M4AdapterDenied): saml_execution_digests(initial,SCOPE,value.store)
    assert value.store.claim_count == value.backend.sends == 0
