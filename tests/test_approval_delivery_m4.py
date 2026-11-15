"""Real M4/material ledgers with synthetic configuration, custody and ACKs."""
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from copy import copy, deepcopy
from dataclasses import replace
import json
import pickle
from types import SimpleNamespace

import pytest

from fortipam_mcp.approval_delivery_execution_contract import (
    ApprovalDeliveryExecutionIntent, ApprovalDeliveryReadback, readback_from_approval_source,
)
from fortipam_mcp.approval_delivery_m4 import (
    CONTRACT, ApprovalDeliveryBackendReceipt, ApprovalDeliveryExecutionEvidence, ApprovalDeliveryExecutionScope,
    ApprovalDeliveryM4Adapter, approval_delivery_execution_digests,
)
from fortipam_mcp.approval_delivery_material_contract import _ROLES
from fortipam_mcp.approval_delivery_contract import _MATERIAL
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_approval_delivery_contract import state
from test_approval_delivery_material_contract import BINDINGS, SYNTHETIC
from test_approval_delivery_material import Resolver
from test_approval_delivery_source import candidate as source_candidate  # noqa: F401
from test_fortitoken_local_m4 import stores
from test_system_email_m4_adapter import Verifier, Clock
from v4_planning import M4AdapterDenied, M4AuthorizationDenied, M4ExecutionKernel, M4ExecutionPlan, M4ExecutionAuthorization, canonical_digest
from v4_planning.material_provider import MaterialAccessDenied, MaterialBindingStatus

SCOPE = ApprovalDeliveryExecutionScope("1"*64, "2"*64, "3"*64, "4"*64, "c"*64, "d"*64, "e"*64, "f"*64)
SERIAL = canonical_digest(dict(serial="SYNTHETIC01"))
NEW_BINDINGS = dict(zip(_ROLES, ("7"*64, "8"*64, "9"*64), strict=True))
NEW_MATERIAL = (b"SYNTHETIC_NEW_USER", b"SYNTHETIC_NEW_PASSWORD", b"SYNTHETIC_NEW_APP_SECRET")


class Backend:
    def __init__(self, clock, protocol):
        self.clock = clock
        self.row = {**state(protocol), **{role: value.decode() for role, value in SYNTHETIC.items()}}
        self.preservation = SCOPE.preservation_digest
        self.reads, self.sends, self.buffers = 0, 0, []
        self.fault = None
        self.on_submit = self.on_applied = None
    def inspect(self):
        self.reads += 1
        return ApprovalDeliveryReadback({key: value for key, value in self.row.items() if key not in _MATERIAL},
            serial_digest=SERIAL, source_digest=SCOPE.configuration_source_digest,
            observed_at=self.clock(), expires_at=self.clock()+5)
    def submit(self, body, *, parameters_digest, restore, before_send, timeout_seconds):
        assert body.readonly and timeout_seconds > 0
        self.buffers.append(body.obj)
        if self.on_submit: self.on_submit()
        if self.fault in ("worker", "copied-context"):
            context = copy_context()
            with ThreadPoolExecutor(1) as worker:
                worker.submit(before_send if self.fault == "worker" else lambda: context.run(before_send)).result(timeout=1)
        if self.fault != "skip-guard": assert before_send() > 0
        if self.fault == "double-guard": before_send()
        self.sends += 1
        self.row = json.loads(body.obj)["approval-email-setting"]
        if self.on_applied: self.on_applied()
        if self.fault == "lost-ack": raise TimeoutError("SYNTHETIC_PRIVATE_ACK_LOSS")
        if self.fault == "interrupt": raise KeyboardInterrupt
        if self.fault == "wrong-role": self.row["client-secret"] = "SYNTHETIC_FOREIGN_INACTIVE_SECRET"
        if self.fault == "nonmaterial-drift": self.row["check-interval"] += 1
        if self.fault == "preservation": self.preservation = "0"*64
        return ApprovalDeliveryBackendReceipt(SCOPE.configuration_source_digest,
            "0"*64 if self.fault == "receipt" else parameters_digest, restore)


class Evidence:
    def __init__(self, backend, intent):
        self.backend, self.intent = backend, intent
        self.fault = None
    def observe(self, configuration_digest):
        # These positive declarations are synthetic. Material identity is read
        # from actual stored fake fields, never copied from the requested state.
        actual = tuple(self.backend.row[role].encode() for role in _ROLES)
        reference = (self.intent.material_binding(restore=True).material_binding_digest
            if actual == tuple(SYNTHETIC[role] for role in _ROLES) else self.intent.material_binding().material_binding_digest
            if actual == NEW_MATERIAL else "0"*64)
        now = self.backend.clock()
        evidence = ApprovalDeliveryExecutionEvidence(configuration_digest, SCOPE.material_source_digest,
            SCOPE.qualification_source_digest, reference, self.backend.preservation, 0,
            complete=True, whole_singleton_verified=True, native_merge_and_material_semantics_verified=True,
            native_ack_qualified=True, material_custody_verified=True, permission_verified=True,
            workload_identity_isolated=True, delivery_isolation_verified=True, object_history_verified=True,
            recovery_ready=True, observed_at=now, expires_at=now+5)
        if self.fault in ("complete", "whole_singleton_verified", "native_merge_and_material_semantics_verified",
                "native_ack_qualified", "material_custody_verified", "permission_verified", "workload_identity_isolated",
                "delivery_isolation_verified", "object_history_verified", "recovery_ready"):
            evidence = replace(evidence, **{self.fault: False})
        elif self.fault == "in-flight": evidence = replace(evidence, in_flight=1)
        elif self.fault == "stale": evidence = replace(evidence, observed_at=now-10, expires_at=now-5)
        elif self.fault in ("material_source_digest", "qualification_source_digest", "configuration_digest"):
            evidence = replace(evidence, **{self.fault: "0"*64})
        return evidence


def grant(intent, execution, material, *, restore=False, issued_at=1000):
    current, expected, parameters = approval_delivery_execution_digests(intent, SCOPE, execution, material)
    if restore: current, expected = expected, current
    action = "approval-delivery-" + ("restore" if restore else "configure")
    fields = dict(plan_ref=action+"-"+parameters, revision=1, action_id=action, action_version="1.0.0", adapter_ref=CONTRACT,
        target_ref="approval-email-singleton-"+intent.original.serial_digest, requester_digest=SCOPE.requester_digest,
        summary_digest="a"*64, confirmation_digest="b"*64, approval_digest="c"*64, parameters_digest=parameters,
        expected_current_digest=current, expected_state_digest=expected,
        idempotency_digest=canonical_digest(dict(parameters=parameters, action=action)), expires_at=issued_at+60, compensation_ref=None)
    plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
    fields = dict(authorization_ref=action+"-synthetic-authorization", plan_ref=plan.plan_ref, plan_digest=plan.plan_digest,
        requester_digest=plan.requester_digest, confirmation_ref=action+"-synthetic-intent", confirmation_digest=plan.confirmation_digest,
        approval_ref=action+"-synthetic-approval", approval_digest=plan.approval_digest, approver_digest="d"*64,
        issued_at=issued_at, expires_at=issued_at+60, one_time=True, execution_authorized=True)
    return plan, M4ExecutionAuthorization(**fields, authorization_digest=canonical_digest(fields))


def make(root, protocol="imaps", *, enabled=True, guarded=True, authorized=True, shared_key=False, checkpointed=True):
    clock = Clock(); backend = Backend(clock, protocol)
    original = backend.inspect()
    proposed = {**state("ms-graph" if protocol == "imaps" else "imaps"), "port": 994}
    intent = ApprovalDeliveryExecutionIntent(original, proposed, enabled=True,
        original_material_bindings=BINDINGS, proposed_material_bindings=NEW_BINDINGS)
    execution, material = stores(root, shared_key=shared_key, checkpointed=checkpointed)
    evidence = Evidence(backend, intent)
    resolver = Resolver(intent.material_binding().material_binding_digest); resolver.values = NEW_MATERIAL
    recovery = Resolver(intent.material_binding(restore=True).material_binding_digest)
    plan, authorization = grant(intent, execution, material)
    verifier = Verifier(plan, authorization)
    adapter = ApprovalDeliveryM4Adapter(intent, backend, evidence, resolver, recovery, plan, authorization, execution, material,
        scope=SCOPE, authorization_verifier=verifier if authorized else None, execution_enabled=enabled,
        source_guard=(lambda: True) if guarded else None, clock=clock)
    return SimpleNamespace(clock=clock, backend=backend, intent=intent, execution=execution, material=material,
        evidence=evidence, resolver=resolver, recovery=recovery, plan=plan, authorization=authorization,
        verifier=verifier, adapter=adapter, kernel=M4ExecutionKernel(adapter, verifier, execution, clock=clock))


def restore(value, *, enabled=True, issued_at=1000):
    plan, authorization = grant(value.intent, value.execution, value.material, restore=True, issued_at=issued_at)
    verifier = Verifier(plan, authorization)
    resolver = Resolver(value.intent.material_binding(restore=True).material_binding_digest)
    adapter = value.adapter.bind_restore(plan, authorization, resolver=resolver, authorization_verifier=verifier,
        execution_enabled=enabled)
    return M4ExecutionKernel(adapter, verifier, value.execution, clock=value.clock), plan, authorization, resolver


@pytest.mark.parametrize("protocol", ["imaps", "ms-graph"])
def test_real_kernel_dual_claims_replace_all_three_roles_and_independently_restore_once(tmp_path, protocol):
    value = make(tmp_path, protocol); original = deepcopy(value.backend.row)
    result = value.kernel.execute(value.plan, value.authorization)
    assert result.outcome == "succeeded" and result.verification == "verified"
    assert value.kernel.execute(value.plan, value.authorization).idempotent_replay
    assert tuple(value.backend.row[role].encode() for role in _ROLES) == NEW_MATERIAL
    assert value.resolver.loads == 1 and value.recovery.loads == 0
    value.clock.value = 1100
    kernel, plan, authorization, resolver = restore(value, issued_at=1100)
    result = kernel.execute(plan, authorization)
    assert result.outcome == "succeeded" and result.verification == "verified"
    assert kernel.execute(plan, authorization).idempotent_replay
    assert value.backend.row == original
    assert value.backend.sends == value.execution.claim_count == value.material.claim_count == 2
    assert resolver.loads == 1
    assert all(not any(buffer) for buffer in value.backend.buffers + value.resolver.buffers + resolver.buffers)
    for path in tmp_path.iterdir():
        if path.is_file():
            assert not any(secret in path.read_bytes() for secret in (*SYNTHETIC.values(), *NEW_MATERIAL))


@pytest.mark.parametrize("options", [dict(enabled=False), dict(guarded=False), dict(authorized=False)])
def test_default_closed_gate_and_authority_refuse_before_material(tmp_path, options):
    value = make(tmp_path, **options)
    assert value.kernel.execute(value.plan, value.authorization).outcome != "succeeded"
    assert value.backend.sends == value.resolver.loads == value.material.claim_count == 0


@pytest.mark.parametrize("fault", ["complete", "whole_singleton_verified", "native_merge_and_material_semantics_verified",
    "native_ack_qualified", "material_custody_verified", "permission_verified", "workload_identity_isolated",
    "delivery_isolation_verified", "object_history_verified", "recovery_ready", "in-flight", "stale",
    "material_source_digest", "qualification_source_digest", "configuration_digest"])
def test_missing_or_foreign_qualification_refuses_before_material(tmp_path, fault):
    value = make(tmp_path); value.evidence.fault = fault
    assert value.kernel.execute(value.plan, value.authorization).outcome != "succeeded"
    assert value.backend.sends == value.resolver.loads == value.material.claim_count == 0


@pytest.mark.parametrize("fault", ["lost-ack", "receipt", "skip-guard", "wrong-role", "nonmaterial-drift", "preservation"])
def test_uncertain_submission_or_incomplete_readback_cannot_create_restore_right_or_repeat(tmp_path, fault):
    value = make(tmp_path); value.backend.fault = fault
    result = value.kernel.execute(value.plan, value.authorization)
    assert result.outcome != "succeeded"
    assert value.kernel.execute(value.plan, value.authorization).idempotent_replay
    assert value.backend.sends == value.resolver.loads == value.material.claim_count == 1
    assert all(not any(buffer) for buffer in value.backend.buffers + value.resolver.buffers)
    with pytest.raises(M4AdapterDenied): restore(value)


@pytest.mark.parametrize("fault", ["deadline", "drift", "revoked", "double-guard", "worker", "copied-context"])
def test_final_send_checks_fresh_state_authority_deadline_and_kernel_worker(tmp_path, fault):
    value = make(tmp_path)
    if fault == "deadline": value.backend.on_submit = lambda: setattr(value.clock, "value", 1060)
    elif fault == "drift": value.backend.on_submit = lambda: value.backend.row.update(port=995)
    elif fault == "revoked": value.backend.on_submit = lambda: setattr(value.verifier, "pair", (None, None))
    else: value.backend.fault = fault
    assert value.kernel.execute(value.plan, value.authorization).outcome != "succeeded"
    assert value.backend.sends == 0 and value.resolver.loads == value.material.claim_count == 1
    assert all(not any(buffer) for buffer in value.backend.buffers + value.resolver.buffers)


@pytest.mark.parametrize("options", [dict(shared_key=True), dict(checkpointed=False)])
def test_execution_cannot_share_ledger_keys_or_omit_material_checkpoint(tmp_path, options):
    with pytest.raises(M4AdapterDenied): make(tmp_path, **options)


def test_interrupted_operation_reopened_stores_cannot_dispatch_or_reacquire(tmp_path):
    value = make(tmp_path); value.backend.fault = "interrupt"
    with pytest.raises(KeyboardInterrupt): value.kernel.execute(value.plan, value.authorization)
    assert value.backend.sends == value.resolver.loads == 1
    assert all(not any(buffer) for buffer in value.backend.buffers + value.resolver.buffers)
    execution = PersistentM4ExecutionStateStore(value.execution._path, value.execution._key_path,
        monotonic_checkpoint=value.execution._monotonic_checkpoint, checkpoint_store_ref=value.execution._checkpoint_store_ref)
    adapter = ApprovalDeliveryM4Adapter(value.intent, value.backend, value.evidence, value.resolver, value.recovery,
        value.plan, value.authorization, execution, value.material, scope=SCOPE, authorization_verifier=value.verifier,
        execution_enabled=True, source_guard=lambda: True, clock=value.clock)
    result = M4ExecutionKernel(adapter, value.verifier, execution, clock=value.clock).execute(value.plan, value.authorization)
    assert result.outcome == "reconciliation_required" and value.backend.sends == value.resolver.loads == 1
    with pytest.raises(M4AdapterDenied): restore(value)


def test_new_directory_cannot_adopt_existing_grant_or_bypass_ledger_domain(tmp_path):
    value = make(tmp_path); other = tmp_path / "other"; other.mkdir(mode=0o700)
    execution, material = stores(other)
    with pytest.raises(M4AdapterDenied):
        ApprovalDeliveryM4Adapter(value.intent, value.backend, value.evidence, value.resolver, value.recovery,
            value.plan, value.authorization, execution, material, scope=SCOPE, authorization_verifier=value.verifier,
            execution_enabled=True, source_guard=lambda: True, clock=value.clock)
    assert value.resolver.loads == execution.claim_count == material.claim_count == 0


def test_missing_independent_original_material_denies_before_loading_new_material(tmp_path):
    value = make(tmp_path); value.recovery.status = MaterialBindingStatus.UNAVAILABLE
    assert value.kernel.execute(value.plan, value.authorization).outcome != "succeeded"
    assert value.resolver.loads == value.backend.sends == 0


def test_given_source_capture_erases_wire_material_and_does_not_relabel_it_as_custody(source_candidate):
    _, source, _ = source_candidate(); source.read()
    buffers = list(source._projection._buffers.values())
    observed = readback_from_approval_source(source, source_digest=SCOPE.configuration_source_digest, clock=Clock())
    intent = ApprovalDeliveryExecutionIntent(observed, {**state(), "port": 994}, enabled=True,
        original_material_bindings=BINDINGS, proposed_material_bindings=NEW_BINDINGS)
    assert source._closed and all(not any(buffer) for buffer in buffers)
    preview = intent.preview()
    assert preview["Proposed Changes"]["changed_protected_roles"] == list(_ROLES)
    assert not preview["material_binding_is_custody_proof"] and not preview["execution_authorized"]
    assert all(secret.decode() not in json.dumps(preview) for secret in SYNTHETIC.values())
    for operation in (copy, deepcopy, pickle.dumps):
        with pytest.raises(MaterialAccessDenied): operation(intent)


def test_normalized_original_cannot_be_mistaken_for_an_exact_inverse():
    observed = ApprovalDeliveryReadback({**state(), "server-cert": "%0%"}, serial_digest=SERIAL,
        source_digest=SCOPE.configuration_source_digest, observed_at=1000, expires_at=1005)
    with pytest.raises(ValueError):
        ApprovalDeliveryExecutionIntent(observed, state(), enabled=True,
            original_material_bindings=BINDINGS, proposed_material_bindings=NEW_BINDINGS)


def test_direct_dispatch_without_original_kernel_ownership_cannot_load_or_send(tmp_path):
    value = make(tmp_path)
    with pytest.raises(M4AuthorizationDenied): value.adapter.dispatch(value.plan)
    assert value.backend.sends == value.resolver.loads == value.execution.claim_count == value.material.claim_count == 0


@pytest.mark.parametrize("fault", ["material_custody_verified", "whole_singleton_verified", "object_history_verified"])
def test_late_qualification_loss_cannot_be_hidden_by_matching_config_and_ack(tmp_path, fault):
    value = make(tmp_path)
    value.backend.on_applied = lambda: setattr(value.evidence, "fault", fault)
    assert value.kernel.execute(value.plan, value.authorization).outcome != "succeeded"
    assert value.backend.sends == 1
    with pytest.raises(M4AdapterDenied): restore(value)
    assert value.kernel.execute(value.plan, value.authorization).idempotent_replay
    assert value.resolver.loads == 1


def test_restore_is_default_closed_and_does_not_load_original_material(tmp_path):
    value = make(tmp_path)
    assert value.kernel.execute(value.plan, value.authorization).outcome == "succeeded"
    kernel, plan, authorization, resolver = restore(value, enabled=False)
    assert kernel.execute(plan, authorization).outcome != "succeeded"
    assert resolver.loads == 0 and value.backend.sends == 1


def test_guard_callback_replacement_cannot_bypass_final_check(tmp_path):
    value = make(tmp_path)
    def guard():
        value.adapter._guard = lambda: True
        return True
    value.adapter._guard = value.adapter._guard_pin = guard
    assert value.kernel.execute(value.plan, value.authorization).outcome != "succeeded"
    assert value.backend.sends == value.resolver.loads == 0


def test_clock_rollback_latches_adapter_and_prevents_later_restore(tmp_path):
    value = make(tmp_path)
    value.adapter.read_current(value.plan)
    value.clock.value = 999
    with pytest.raises(M4AdapterDenied): value.adapter.read_current(value.plan)
    value.clock.value = 1000
    assert value.kernel.execute(value.plan, value.authorization).outcome != "succeeded"
    assert value.backend.sends == value.resolver.loads == 0


def test_expired_source_capture_disposes_material_before_refusing_input(source_candidate):
    peer, source, _ = source_candidate(); source.read()
    owned = list(source._projection._buffers.values())
    peer.time = source._deadline
    with pytest.raises(ValueError):
        readback_from_approval_source(source, source_digest=SCOPE.configuration_source_digest, clock=Clock())
    assert source._closed and all(not any(buffer) for buffer in owned)


@pytest.mark.parametrize("fault", ["gate", "guard", "authorization"])
def test_guard_revocation_after_authorization_check_cannot_pass_admission(tmp_path, monkeypatch, fault):
    value = make(tmp_path)
    armed, triggered = [], []
    verify = value.verifier.verify
    def verified(*args, **kwargs):
        verify(*args, **kwargs)
        armed.append(True)
    def guard():
        if armed and not triggered:
            triggered.append(True)
            if fault == "gate": value.adapter._enabled = False
            elif fault == "guard": value.adapter._guard = lambda: True
            else: value.verifier.pair = (None, None)
        return True
    monkeypatch.setattr(value.verifier, "verify", verified)
    value.adapter._guard = value.adapter._guard_pin = guard
    with pytest.raises(M4AdapterDenied): value.adapter._check(value.plan)
    assert triggered and value.backend.sends == value.resolver.loads == 0


def test_material_source_revocation_before_send_cannot_mutate_product(tmp_path):
    value = make(tmp_path)
    value.backend.on_submit = lambda: setattr(value.resolver, "status", MaterialBindingStatus.UNAVAILABLE)
    assert value.kernel.execute(value.plan, value.authorization).outcome != "succeeded"
    assert value.backend.sends == 0
    assert value.resolver.loads == 1 and all(not any(buffer) for buffer in value.backend.buffers + value.resolver.buffers)


def test_final_guard_revocation_after_material_status_cannot_mutate_product(tmp_path):
    value = make(tmp_path)
    ready = []
    validate = value.resolver.validate_prebound
    def status():
        result = validate()
        if value.adapter._send_admitted: ready.append(True)
        return result
    def guard():
        if ready: value.resolver.status = MaterialBindingStatus.UNAVAILABLE
        return True
    value.resolver.validate_prebound = status
    value.adapter._guard = value.adapter._guard_pin = guard
    assert value.kernel.execute(value.plan, value.authorization).outcome != "succeeded"
    assert value.backend.sends == 0
    assert value.resolver.loads == 1 and all(not any(buffer) for buffer in value.backend.buffers + value.resolver.buffers)
