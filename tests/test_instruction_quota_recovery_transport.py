"""Real protected native custody with synthetic wire/auth; no live authority."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from fortipam_mcp import instruction_quota_recovery_transport as t
from fortipam_mcp.instruction_quota_recovery_contract import (
    ACTION, ADAPTER, VERSION, prepare_instruction_quota_baseline_recovery,
)
from fortipam_mcp.instruction_quota_reconciliation import InstructionQuotaReconciliationError
from test_instruction_quota_contract import SERIAL
from test_instruction_quota_http_transport import Connection, Response, assert_closed
from test_instruction_quota_live_workflow import IDENTITY, REQUESTER, TRANSPORT, Cycle, cycle as cycle
from test_instruction_quota_reconciliation import consumed_restore, retained_files


def prepared(cycle: Cycle, monkeypatch: pytest.MonkeyPatch, *, enabled: bool = True):
    reconciler = consumed_restore(cycle, monkeypatch)
    candidate = prepare_instruction_quota_baseline_recovery(reconciler, **IDENTITY)
    return t.FortiPamInstructionQuotaRecoveryTransport(candidate,
        state_key=b"n" * 32, execution_enabled=enabled)


def synthetic_binding(writer: t.FortiPamInstructionQuotaRecoveryTransport, *, nonce: str = "a"):
    """Unit-test typed binding only; deliberately not a real server policy grant."""
    candidate = writer._candidate
    plan_values: dict[str, Any] = {"plan_ref": "synthetic-incident-plan-" + nonce,
        "revision": 1, "action_id": ACTION, "action_version": VERSION, "adapter_ref": ADAPTER,
        "target_ref": "instruction-quota-" + SERIAL, "requester_digest": REQUESTER,
        "summary_digest": "3" * 64, "confirmation_digest": "4" * 64, "approval_digest": "5" * 64,
        "parameters_digest": candidate.digest, "expected_current_digest": candidate._draft._current,
        "expected_state_digest": candidate._draft._expected, "idempotency_digest": hashlib.sha256(nonce.encode()).hexdigest(),
        "expires_at": candidate._draft._expires, "compensation_ref": None}
    plan = M4ExecutionPlan(**plan_values, plan_digest=canonical_digest(plan_values))
    auth_values: dict[str, Any] = {"authorization_ref": "synthetic-incident-authorization-" + nonce,
        "plan_ref": plan.plan_ref, "plan_digest": plan.plan_digest, "requester_digest": REQUESTER,
        "confirmation_ref": "synthetic-incident-intent", "confirmation_digest": plan.confirmation_digest,
        "approval_ref": "synthetic-incident-policy", "approval_digest": plan.approval_digest,
        "approver_digest": "6" * 64, "issued_at": candidate._draft._observed,
        "expires_at": plan.expires_at, "one_time": True, "execution_authorized": True}
    auth = M4ExecutionAuthorization(**auth_values, authorization_digest=canonical_digest(auth_values))
    return plan, auth


def originals_unchanged(before: dict[str, str]) -> bool:
    return all(hashlib.sha256(Path(name).read_bytes()).hexdigest() == digest for name, digest in before.items())


def test_native_ack_full_readback_custody_preserves_original_unknown(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch) -> None:
    writer = prepared(cycle, monkeypatch)
    plan, auth = synthetic_binding(writer)
    before = retained_files(cycle)
    checks: list[bool] = []
    def verifier() -> None:
        checks.append((cycle.path / (t._PREFIX + ".claim.json")).exists())
    with writer.operation_lock():
        assert writer.inspect_precondition() == plan.expected_current_digest
        writer.dispatch(plan, auth, before_send=verifier)
        # ACK alone has not written the postcondition result.
        assert not writer._exists(t._PREFIX + ".result.json")
        cycle.device.clock += 31
        assert writer.inspect_postcondition(plan, auth) == plan.expected_state_digest
        claim = writer._read(".claim.json")
        ack = writer._read(".ack.json")
        result = writer._read(".result.json")
        assert claim["plan"] == plan.plan_digest and claim["authorization"] == auth.authorization_digest
        assert ack["claim"] == canonical_digest(claim) and result["ack"] == canonical_digest(ack)
    assert checks == [False, False, True]
    assert originals_unchanged(before) and len(cycle.device.requests) == 2
    assert cycle.device.requests[-1] == b'{"secret-instruction-quota":0,"file-storage-quota":5}'
    assert not (cycle.path / "restore.ack.json").exists()
    assert_closed(cycle.device)
    records = [cycle.path / name for name in t._FILES]
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in records)
    for p in records:
        for value in (REQUESTER, TRANSPORT, "synthetic-device", "synthetic-token", "synthetic-private-value", str(cycle.path)):
            assert value not in p.read_text()


@pytest.mark.parametrize("failure", ["gate", "lock", "verifier", "identity", "action", "expiry", "parameters"])
def test_authority_binding_failure_precedes_connection_and_native_claim(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    writer = prepared(cycle, monkeypatch, enabled=failure != "gate")
    plan, auth = synthetic_binding(writer)
    if failure in {"identity", "action", "parameters"}:
        content = plan.canonical_content()
        content[{"identity": "requester_digest", "action": "action_id", "parameters": "parameters_digest"}[failure]] = (
            "instruction-quota-restore" if failure == "action" else "9" * 64)
        plan = M4ExecutionPlan(**content, plan_digest=canonical_digest(content))
    if failure == "expiry":
        cycle.device.clock += 30
    def verifier() -> None:
        if failure == "verifier":
            raise RuntimeError("synthetic-private-verifier-detail")
    before = retained_files(cycle)
    connections = len(cycle.device.connections)
    if failure == "lock":
        with pytest.raises(t.InstructionQuotaRecoveryTransportError):
            writer.dispatch(plan, auth, before_send=verifier)
    else:
        with writer.operation_lock(), pytest.raises(t.InstructionQuotaRecoveryTransportError):
            writer.dispatch(plan, auth, before_send=verifier)
    assert retained_files(cycle) == before and len(cycle.device.requests) == 1
    assert len(cycle.device.connections) == connections


@pytest.mark.parametrize("failure", ["sibling", "usage", "resource", "clock"])
def test_drift_after_connect_refuses_before_claim_and_closes(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    writer = prepared(cycle, monkeypatch)
    plan, auth = synthetic_binding(writer)
    def change() -> None:
        if failure == "sibling": cycle.device.sibling = "synthetic-private-drift"
        elif failure == "usage": cycle.device.used_file += 1
        elif failure == "resource": cycle.device.resource = 1
        else: cycle.device.clock += 30
    cycle.device.on_connect = change
    before = retained_files(cycle)
    with writer.operation_lock(), pytest.raises(t.InstructionQuotaRecoveryTransportError):
        writer.dispatch(plan, auth, before_send=lambda: None)
    assert retained_files(cycle) == before and len(cycle.device.requests) == 1
    assert_closed(cycle.device)


@pytest.mark.parametrize("failure", ["put", "verifier_after_claim", "ack", "http", "partial", "cleanup"])
def test_consumed_dispatch_survives_reopen_new_key_and_nonce_without_replay(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    writer = prepared(cycle, monkeypatch)
    plan, auth = synthetic_binding(writer)
    calls: list[bool] = []
    def verifier() -> None:
        calls.append(True)
        if failure == "verifier_after_claim" and len(calls) == 3:
            raise RuntimeError("synthetic-private-verifier-detail")
    if failure == "put":
        def lost_put(*args: object, **kwargs: object) -> None:
            raise RuntimeError("synthetic-private-native-timeout")
        monkeypatch.setattr(Connection, "request", lost_put)
    elif failure == "ack": cycle.device.ack_changes = {"serial": "synthetic-other-device"}
    elif failure == "http": cycle.device.status = 500
    elif failure == "partial": cycle.device.partial = True
    elif failure == "cleanup": cycle.device.close_error = True
    before = retained_files(cycle)
    with writer.operation_lock():
        if failure == "partial":
            writer.dispatch(plan, auth, before_send=verifier)
            with pytest.raises(t.InstructionQuotaRecoveryTransportError):
                writer.inspect_postcondition(plan, auth)
        else:
            with pytest.raises(t.InstructionQuotaRecoveryTransportError):
                writer.dispatch(plan, auth, before_send=verifier)
        assert writer._exists(t._PREFIX + ".claim.json")
    count = len(cycle.device.requests)
    connections = len(cycle.device.connections)
    reopened = t.FortiPamInstructionQuotaRecoveryTransport(writer._candidate,
        state_key=b"o" * 32, execution_enabled=True)
    new_plan, new_auth = synthetic_binding(reopened, nonce="b")
    with reopened.operation_lock(), pytest.raises(t.InstructionQuotaRecoveryTransportError):
        reopened.dispatch(new_plan, new_auth, before_send=lambda: None)
    assert originals_unchanged(before) and len(cycle.device.requests) == count
    assert len(cycle.device.connections) == connections
    assert not (cycle.path / "restore.ack.json").exists()
    assert_closed(cycle.device)


@pytest.mark.parametrize("failure", ["claim", "ack", "body", "permissions", "symlink"])
def test_native_custody_corruption_rejects_before_post_read(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    writer = prepared(cycle, monkeypatch)
    plan, auth = synthetic_binding(writer)
    with writer.operation_lock():
        writer.dispatch(plan, auth, before_send=lambda: None)
        suffix = ".claim.json" if failure == "claim" else ".ack.json"
        path = cycle.path / (t._PREFIX + suffix)
        if failure == "permissions": path.chmod(0o604)
        elif failure == "symlink":
            private_copy = cycle.path / "synthetic-private-copy"
            path.rename(private_copy)
            path.symlink_to(private_copy)
        else:
            value = writer._read(suffix)
            path.unlink()
            value["expected" if failure == "claim" else "claim" if failure == "ack" else "body_digest"] = "9" * 64
            writer._write_once(suffix, value)
        reads: list[bool] = []
        cycle.device.on_read = lambda: reads.append(True)
        with pytest.raises(t.InstructionQuotaRecoveryTransportError):
            writer.inspect_postcondition(plan, auth)
    assert not reads and len(cycle.device.requests) == 2
    assert not (cycle.path / (t._PREFIX + ".result.json")).exists()


def test_missing_original_lock_is_not_recreated_by_readonly_or_writer(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch) -> None:
    writer = prepared(cycle, monkeypatch)
    original = writer._candidate._reconciler
    path = cycle.path / "operation.lock"
    path.unlink()
    before = retained_files(cycle)
    with pytest.raises(InstructionQuotaReconciliationError):
        original.assess(**IDENTITY)
    with pytest.raises(t.InstructionQuotaRecoveryTransportError):
        with writer.operation_lock():
            pytest.fail("missing original lock was accepted")
    assert not path.exists() and retained_files(cycle) == before
    assert len(cycle.device.requests) == 1


def test_fixed_claim_alone_blocks_any_other_binding_and_shared_lock_excludes_second_instance(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch) -> None:
    writer = prepared(cycle, monkeypatch)
    other = t.FortiPamInstructionQuotaRecoveryTransport(writer._candidate, state_key=b"o" * 32,
        execution_enabled=True)
    plan, auth = synthetic_binding(other)
    with writer.operation_lock():
        with pytest.raises(t.InstructionQuotaRecoveryTransportError):
            with other.operation_lock():
                pytest.fail("competing shared lock accepted")
        fd = os.open(cycle.path / (t._PREFIX + ".claim.json"), os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        os.close(fd)
    with other.operation_lock(), pytest.raises(t.InstructionQuotaRecoveryTransportError):
        other.dispatch(plan, auth, before_send=lambda: None)
    assert len(cycle.device.requests) == 1


@pytest.mark.parametrize("failure", ["build", "method", "error_type", "encoding", "duplicate", "trailing", "oversized"])
def test_native_ack_requires_fixed_bounded_unambiguous_success_envelope(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    writer = prepared(cycle, monkeypatch)
    plan, auth = synthetic_binding(writer)
    if failure == "build": cycle.device.ack_changes = {"build": 30}
    elif failure == "method": cycle.device.ack_changes = {"http_method": "GET"}
    elif failure == "error_type": cycle.device.ack_changes = {"error": True}
    elif failure == "encoding":
        header = Response.getheader
        def encoded(self: Response, name: str, default: str = "") -> str:
            return "gzip" if name == "Content-Encoding" else header(self, name, default)
        monkeypatch.setattr(Response, "getheader", encoded)
    else:
        reply = Response(cycle.device).raw
        if failure == "duplicate":
            reply = reply.replace(b'"status": "success"', b'"status": "success", "status": "success"')
        elif failure == "trailing": reply += b'{}'
        else: reply += b' ' * 262145
        cycle.device.reply = reply
    before = retained_files(cycle)
    with writer.operation_lock(), pytest.raises(t.InstructionQuotaRecoveryTransportError) as error:
        writer.dispatch(plan, auth, before_send=lambda: None)
    assert error.value.stage == "ack_validation"
    assert originals_unchanged(before) and len(cycle.device.requests) == 2
    assert (cycle.path / (t._PREFIX + ".claim.json")).exists()
    assert not (cycle.path / (t._PREFIX + ".ack.json")).exists()
    assert_closed(cycle.device)


def test_default_constructor_is_readonly_and_original_keys_cannot_sign_new_custody(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch) -> None:
    enabled = prepared(cycle, monkeypatch)
    before = retained_files(cycle)
    closed = t.FortiPamInstructionQuotaRecoveryTransport(enabled._candidate, state_key=b"o" * 32)
    plan, auth = synthetic_binding(closed)
    with closed.operation_lock(), pytest.raises(t.InstructionQuotaRecoveryTransportError):
        closed.dispatch(plan, auth, before_send=lambda: None)
    for key in (b"k" * 32, b"m" * 32, b"b" * 32, b"short"):
        with pytest.raises(t.InstructionQuotaRecoveryTransportError):
            t.FortiPamInstructionQuotaRecoveryTransport(enabled._candidate, state_key=key)
    assert retained_files(cycle) == before and len(cycle.device.requests) == 1


@pytest.mark.parametrize("timeout", [30.0, 12.5, True])
def test_float_timeout_is_pinned_without_changing_supported_transport_semantics(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch, timeout: float) -> None:
    initial = prepared(cycle, monkeypatch)
    original = initial._original
    object.__setattr__(original, "_config", replace(original._config, timeout_seconds=timeout))
    before = retained_files(cycle)
    if type(timeout) is bool:
        with pytest.raises(t.InstructionQuotaRecoveryTransportError):
            t.FortiPamInstructionQuotaRecoveryTransport(initial._candidate, state_key=b"o" * 32)
        assert retained_files(cycle) == before
        return
    writer = t.FortiPamInstructionQuotaRecoveryTransport(initial._candidate,
        state_key=b"o" * 32, execution_enabled=True)
    assert (writer._config_pin == initial._config_pin) is (timeout == 30.0)
    plan, auth = synthetic_binding(writer)
    with writer.operation_lock():
        writer.dispatch(plan, auth, before_send=lambda: None)
        writer.inspect_postcondition(plan, auth)
    assert originals_unchanged(before) and cycle.device.connection_options[-1]["timeout"] == min(30.0, timeout)
    assert len(cycle.device.requests) == 2


@pytest.mark.parametrize("stage", ["read", "result_fsync"])
def test_post_read_deadline_covers_final_result_persistence(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch, stage: str) -> None:
    writer = prepared(cycle, monkeypatch)
    plan, auth = synthetic_binding(writer)
    with writer.operation_lock():
        writer.dispatch(plan, auth, before_send=lambda: None)
        if stage == "read":
            cycle.device.on_read = lambda: setattr(cycle.device, "clock", cycle.device.clock + 31)
        else:
            persist = t.FortiPamInstructionQuotaRecoveryTransport._write_once
            def delayed(self, suffix, payload):
                persist(self, suffix, payload)
                if suffix == ".result.json": cycle.device.clock += 31
            monkeypatch.setattr(t.FortiPamInstructionQuotaRecoveryTransport, "_write_once", delayed)
        with pytest.raises(t.InstructionQuotaRecoveryTransportError) as error:
            writer.inspect_postcondition(plan, auth)
        assert error.value.stage == "postcondition"
        assert writer._exists(t._PREFIX + ".result.json") is (stage == "result_fsync")
    assert len(cycle.device.requests) == 2 and not (cycle.path / "restore.ack.json").exists()
