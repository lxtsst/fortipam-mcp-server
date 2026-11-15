"""Synthetic file consumption through real persistent M4; no product/install adapter."""
import base64
from contextvars import copy_context
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
import json
from types import SimpleNamespace

import pytest

from fortipam_mcp.license_artifact_source import LicenseArtifactSource
from fortipam_mcp.license_upload_material import (
    ACTION, ADAPTER_CONTRACT, LicenseUploadMaterialBinding, LicenseUploadDispatchMaterial,
    license_upload_material_parameters,
)
from test_license_upload_contract import source_for, SCOPE, AUDIENCE
from test_system_email_m4_adapter import Clock, Verifier, store_at, reopen
from v4_planning import M4AdapterAmbiguous, M4ExecutionPlan, M4ExecutionAuthorization, M4ExecutionKernel, canonical_digest
from v4_planning.material_provider import MaterialAccessDenied

SERIAL, REQUESTER = '3'*64, '4'*64


def grant(binding, store):
    parameters = license_upload_material_parameters(binding, store)
    fields = dict(plan_ref=ACTION+'-'+parameters, revision=1, action_id=ACTION, action_version='1.0.0',
        adapter_ref=ADAPTER_CONTRACT, target_ref='license-appliance-'+SERIAL, requester_digest=REQUESTER,
        summary_digest='5'*64, confirmation_digest='6'*64, approval_digest='7'*64, parameters_digest=parameters,
        expected_current_digest='a'*64, expected_state_digest='b'*64,
        idempotency_digest=canonical_digest(dict(action=ACTION, parameters=parameters)), expires_at=1060, compensation_ref=None)
    plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
    fields = dict(authorization_ref='synthetic-license-authorization', plan_ref=plan.plan_ref, plan_digest=plan.plan_digest,
        requester_digest=REQUESTER, confirmation_ref='synthetic-license-intent', confirmation_digest=plan.confirmation_digest,
        approval_ref='synthetic-license-approval', approval_digest=plan.approval_digest, approver_digest='8'*64,
        issued_at=1000, expires_at=1060, one_time=True, execution_authorized=True)
    return plan, M4ExecutionAuthorization(**fields, authorization_digest=canonical_digest(fields))


class Adapter:
    """A test-only body consumer; its postcondition proves no license outcome."""
    def __init__(self, material, plan, authorization, store):
        self.material, self.plan, self.authorization, self.store = material, plan, authorization, store
        self.buffers, self.calls, self.used = [], 0, False
        self.fault = None
        self.on_consume = lambda: None
        self.on_dispatch = lambda: None
    def read_current(self, plan): return plan.expected_current_digest
    def read_postcondition(self, plan): return plan.expected_state_digest if self.used else '0'*64
    def dispatch(self, plan):
        self.calls += 1
        try:
            self.on_dispatch()
            def consume():
                with self.material._compile_once(plan, self.authorization, self.store) as view:
                    self.buffers.extend((view.obj, self.material._binding._source._buffer))
                    assert view.readonly
                    document = json.loads(view.obj)
                    assert set(document) == {'filename', 'file_content'}
                    assert base64.b64decode(document['file_content']) == b'SYNTHETIC_LICENSE\x00\xff'
                    self.on_consume()
                    if self.fault == 'consumer': raise RuntimeError('SYNTHETIC_PRIVATE_FAILURE')
                    if self.fault == 'interrupt': raise KeyboardInterrupt
                    if self.fault == 'system-exit': raise SystemExit
                    self.used = True
            if self.fault in ('worker', 'copied-context'):
                context = copy_context()
                with ThreadPoolExecutor(1) as worker:
                    worker.submit(consume if self.fault == 'worker' else lambda: context.run(consume)).result(timeout=2)
            else: consume()
            if self.fault == 'uncertain': raise TimeoutError('SYNTHETIC_PRIVATE_ACK_LOSS')
        except Exception: raise M4AdapterAmbiguous('The synthetic body consumer is uncertain.') from None


def make(root, *, guarded=True, source_guard=None):
    source, path = source_for(root, guard=(source_guard or (lambda: True)) if guarded else None)
    binding = LicenseUploadMaterialBinding(source, target_serial_digest=SERIAL, requester_digest=REQUESTER)
    clock, store = Clock(), store_at(root)
    plan, authorization = grant(binding, store)
    material = LicenseUploadDispatchMaterial(binding, plan, authorization, store, clock=clock)
    adapter = Adapter(material, plan, authorization, store)
    verifier = Verifier(plan, authorization)
    kernel = M4ExecutionKernel(adapter, verifier, store, clock=clock)
    return SimpleNamespace(source=source, path=path, binding=binding, clock=clock, store=store,
        plan=plan, authorization=authorization, material=material, adapter=adapter, verifier=verifier, kernel=kernel)


def test_original_kernel_consumes_one_body_and_recreated_kernel_does_not_reload(tmp_path):
    value = make(tmp_path)
    assert not value.source._used and value.source._buffer is None
    assert value.kernel.execute(value.plan, value.authorization).outcome == 'succeeded'
    assert value.source._used and value.adapter.calls == value.store.claim_count == 1
    assert all(not any(raw) for raw in value.adapter.buffers)
    replacement = Adapter(value.material, value.plan, value.authorization, reopen(value.store))
    result = M4ExecutionKernel(replacement, value.verifier, replacement.store, clock=value.clock).execute(value.plan, value.authorization)
    assert result.idempotent_replay and replacement.calls == 0
    assert value.path.read_bytes() == b'SYNTHETIC_LICENSE\x00\xff'


@pytest.mark.parametrize('fault', ['consumer', 'uncertain', 'interrupt', 'system-exit'])
def test_uncertain_or_interrupted_consumption_is_not_reopened_by_fresh_source_or_store(tmp_path, fault):
    value = make(tmp_path); value.adapter.fault = fault
    if fault in ('interrupt', 'system-exit'):
        with pytest.raises(KeyboardInterrupt if fault == 'interrupt' else SystemExit): value.kernel.execute(value.plan, value.authorization)
    else: assert value.kernel.execute(value.plan, value.authorization).outcome != 'succeeded'
    assert all(not any(raw) for raw in value.adapter.buffers)
    source = LicenseArtifactSource(value.path, expected_sha256=value.source._sha, scope_digest=SCOPE, audience_digest=AUDIENCE,
        source_guard=lambda: True)
    binding = LicenseUploadMaterialBinding(source, target_serial_digest=SERIAL, requester_digest=REQUESTER)
    store = reopen(value.store)
    material = LicenseUploadDispatchMaterial(binding, value.plan, value.authorization, store, clock=value.clock)
    adapter = Adapter(material, value.plan, value.authorization, store)
    result = M4ExecutionKernel(adapter, value.verifier, store, clock=value.clock).execute(value.plan, value.authorization)
    assert result.idempotent_replay and result.outcome == 'reconciliation_required'
    assert adapter.calls == 0 and not source._used and value.store.claim_count == 1


def test_direct_call_and_foreign_physical_arguments_do_not_consume_source(tmp_path):
    value = make(tmp_path)
    for plan, authorization, store in [(value.plan, value.authorization, value.store),
            (replace(value.plan), value.authorization, value.store), (value.plan, replace(value.authorization), value.store)]:
        with pytest.raises(MaterialAccessDenied):
            with value.material._compile_once(plan, authorization, store): pytest.fail('No original dispatch exists.')
    assert not value.source._used and not value.material._attempted
    assert value.kernel.execute(value.plan, value.authorization).outcome == 'succeeded'


@pytest.mark.parametrize('fault', ['worker', 'copied-context'])
def test_other_thread_cannot_borrow_material_even_with_copied_context(tmp_path, fault):
    value = make(tmp_path); value.adapter.fault = fault
    assert value.kernel.execute(value.plan, value.authorization).outcome != 'succeeded'
    assert not value.source._used and not value.material._attempted and value.adapter.buffers == []


def test_new_helper_and_source_cannot_reset_the_original_kernel_material_slot(tmp_path):
    value = make(tmp_path); denied = []
    def again():
        source = LicenseArtifactSource(value.path, expected_sha256=value.source._sha, scope_digest=SCOPE, audience_digest=AUDIENCE,
            source_guard=lambda: True)
        binding = LicenseUploadMaterialBinding(source, target_serial_digest=SERIAL, requester_digest=REQUESTER)
        other = LicenseUploadDispatchMaterial(binding, value.plan, value.authorization, value.store, clock=value.clock)
        with pytest.raises(MaterialAccessDenied):
            with other._compile_once(value.plan, value.authorization, value.store): pytest.fail('A second kernel slot cannot be reserved.')
        denied.append(True); assert not source._used
    value.adapter.on_consume = again
    assert value.kernel.execute(value.plan, value.authorization).outcome == 'succeeded' and denied


@pytest.mark.parametrize('copied', ['plan', 'authorization', 'both'])
def test_fresh_helper_with_equal_copied_references_cannot_take_original_dispatch_material(tmp_path, copied):
    value = make(tmp_path)
    def first():
        plan = replace(value.plan) if copied in ('plan', 'both') else value.plan
        authorization = replace(value.authorization) if copied in ('authorization', 'both') else value.authorization
        material = LicenseUploadDispatchMaterial(value.binding, plan, authorization, value.store, clock=value.clock)
        with pytest.raises(MaterialAccessDenied):
            with material._compile_once(plan, authorization, value.store): pytest.fail('Copied references cannot acquire the original slot.')
        assert not value.source._used and not material._attempted
    value.adapter.on_dispatch = first
    assert value.kernel.execute(value.plan, value.authorization).outcome == 'succeeded'
    assert value.source._used and all(not any(raw) for raw in value.adapter.buffers)


@pytest.mark.parametrize('change', ['expiry', 'clock', 'close', 'source-close', 'guard', 'key'])
def test_revocation_before_dispatch_refuses_material(tmp_path, change):
    value = make(tmp_path)
    def mutate():
        if change == 'expiry': value.clock.value = 1060
        elif change == 'clock': value.clock.value = -1
        elif change == 'close': value.material.close()
        elif change == 'source-close': value.source.close()
        elif change == 'guard': value.source._guard = lambda: True
        else: value.store._key_path.write_bytes(b'z'*32)
    value.adapter.on_dispatch = mutate
    try: result = value.kernel.execute(value.plan, value.authorization)
    except Exception:
        assert change == 'key'
    else: assert result.outcome != 'succeeded'
    assert not value.source._used and value.adapter.buffers == []


def test_default_source_guard_refuses_under_a_valid_kernel_claim(tmp_path):
    value = make(tmp_path, guarded=False)
    assert value.kernel.execute(value.plan, value.authorization).outcome != 'succeeded'
    assert value.adapter.buffers == []


@pytest.mark.parametrize('field, wrong', [('action_id', 'folder-create'), ('action_version', '1.1.0'),
    ('adapter_ref', 'foreign-adapter'), ('target_ref', 'foreign-appliance'), ('requester_digest', '9'*64),
    ('parameters_digest', '9'*64), ('idempotency_digest', '9'*64), ('plan_ref', 'foreign-plan'), ('revision', 2),
    ('compensation_ref', 'foreign-compensation'), ('expires_at', 1061)])
def test_fixed_context_rejects_otherwise_self_consistent_plan_and_authorization(tmp_path, field, wrong):
    value = make(tmp_path)
    fields = asdict(value.plan); fields.pop('plan_digest'); fields[field] = wrong
    plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
    fields = asdict(value.authorization); fields.pop('authorization_digest')
    fields.update(plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
        confirmation_digest=plan.confirmation_digest, approval_digest=plan.approval_digest)
    if field == 'expires_at': fields['expires_at'] = 1061
    authorization = M4ExecutionAuthorization(**fields, authorization_digest=canonical_digest(fields))
    with pytest.raises(MaterialAccessDenied):
        LicenseUploadDispatchMaterial(value.binding, plan, authorization, value.store, clock=value.clock)
    assert not value.source._used and value.source._buffer is None


@pytest.mark.parametrize('foreign', ['plan', 'authorization', 'store'])
def test_foreign_arguments_inside_original_dispatch_do_not_take_its_material_slot(tmp_path, foreign):
    value = make(tmp_path)
    def first():
        plan = replace(value.plan) if foreign == 'plan' else value.plan
        authorization = replace(value.authorization) if foreign == 'authorization' else value.authorization
        store = reopen(value.store) if foreign == 'store' else value.store
        with pytest.raises(MaterialAccessDenied):
            with value.material._compile_once(plan, authorization, store): pytest.fail('Foreign physical context is unavailable.')
        assert not value.source._used and not value.material._attempted
    value.adapter.on_dispatch = first
    assert value.kernel.execute(value.plan, value.authorization).outcome == 'succeeded'


@pytest.mark.parametrize('change', ['expiry', 'close', 'source-close', 'guard', 'binding'])
def test_revocation_during_consumer_clears_every_buffer_and_prevents_success(tmp_path, change):
    value = make(tmp_path)
    def mutate():
        if change == 'expiry': value.clock.value = 1060
        elif change == 'close': value.material.close()
        elif change == 'source-close': value.source.close()
        elif change == 'guard': value.source._guard = lambda: True
        else:
            other = LicenseArtifactSource(value.path, expected_sha256=value.source._sha, scope_digest=SCOPE, audience_digest=AUDIENCE,
                source_guard=lambda: True)
            value.binding._source = other
    value.adapter.on_consume = mutate
    assert value.kernel.execute(value.plan, value.authorization).outcome != 'succeeded'
    assert value.source._used and all(not any(raw) for raw in value.adapter.buffers)


def test_close_uses_original_owned_source_even_after_binding_replacement(tmp_path):
    value = make(tmp_path)
    other = LicenseArtifactSource(value.path, expected_sha256=value.source._sha, scope_digest=SCOPE, audience_digest=AUDIENCE,
        source_guard=lambda: True)
    value.binding._source = other
    value.material.close()
    assert value.source._closed and not other._closed and not other._used


def test_source_guard_reentry_cannot_borrow_twice_or_load_during_construction(tmp_path, monkeypatch):
    from fortipam_mcp import license_artifact_source as source_module
    holder, calls, reads = [], [], []
    def guard():
        calls.append(True)
        value = holder[0]
        with pytest.raises(MaterialAccessDenied):
            with value.material._compile_once(value.plan, value.authorization, value.store): pytest.fail('Reentrant material use is unavailable.')
        return True
    source, path = source_for(tmp_path, guard=guard)
    binding = LicenseUploadMaterialBinding(source, target_serial_digest=SERIAL, requester_digest=REQUESTER)
    clock, store = Clock(), store_at(tmp_path)
    plan, authorization = grant(binding, store)
    material = LicenseUploadDispatchMaterial(binding, plan, authorization, store, clock=clock)
    assert calls == [] and not source._used
    adapter = Adapter(material, plan, authorization, store)
    holder.append(SimpleNamespace(material=material, plan=plan, authorization=authorization, store=store))
    original_read = source_module._read
    def read(*args): reads.append(True); return original_read(*args)
    monkeypatch.setattr(source_module, '_read', read)
    assert M4ExecutionKernel(adapter, Verifier(plan, authorization), store, clock=clock).execute(plan, authorization).outcome == 'succeeded'
    assert calls and reads == [True] and all(not any(raw) for raw in adapter.buffers)


@pytest.mark.parametrize('callback', ['clock', 'checkpoint'])
def test_callback_revocation_after_encoding_cannot_publish_private_body(tmp_path, monkeypatch, callback):
    from fortipam_mcp import license_upload_contract as codec
    allowed, cleared, clock_calls = [True], [], []
    value = make(tmp_path, source_guard=lambda: allowed[0])
    clear = codec._zeroize_mutable
    def clearing(raw): clear(raw); cleared.append(raw)
    monkeypatch.setattr(codec, '_zeroize_mutable', clearing)
    if callback == 'clock':
        def clock():
            clock_calls.append(True)
            if len(clock_calls) == 2: allowed[0] = False
            return value.clock()
        value.material._clock = clock
    else:
        checkpoint = value.store._monotonic_checkpoint; verify = checkpoint.verify
        def checked(tail):
            result = verify(tail)
            if value.source._buffer is not None: allowed[0] = False
            return result
        monkeypatch.setattr(checkpoint, 'verify', checked)
    assert value.kernel.execute(value.plan, value.authorization).outcome != 'succeeded'
    assert not allowed[0] and value.adapter.buffers == [] and value.source._used and value.source._buffer is None
    assert cleared and all(not any(raw) for raw in cleared)


def test_source_guard_elapsed_time_is_inside_original_material_deadline(tmp_path, monkeypatch):
    from fortipam_mcp import license_upload_material as module
    elapsed, armed, calls = [0.0], [], []
    def guard():
        if armed: elapsed[0] += 61
        return True
    value = make(tmp_path, source_guard=guard)
    def clock():
        calls.append(True)
        if len(calls) == 2: armed.append(True)
        return value.clock()
    value.material._clock = clock
    monkeypatch.setattr(module, 'time', SimpleNamespace(monotonic=lambda: elapsed[0]))
    assert value.kernel.execute(value.plan, value.authorization).outcome != 'succeeded'
    assert armed and value.adapter.buffers == [] and value.source._buffer is None


def test_consumer_cannot_renew_monotonic_deadline_with_a_stalled_epoch_clock(tmp_path, monkeypatch):
    from fortipam_mcp import license_upload_material as module
    elapsed = [0.0]
    value = make(tmp_path)
    monkeypatch.setattr(module, 'time', SimpleNamespace(monotonic=lambda: elapsed[0]))
    value.adapter.on_consume = lambda: elapsed.__setitem__(0, 61.0)
    assert value.kernel.execute(value.plan, value.authorization).outcome != 'succeeded'
    assert value.source._used and all(not any(raw) for raw in value.adapter.buffers)
