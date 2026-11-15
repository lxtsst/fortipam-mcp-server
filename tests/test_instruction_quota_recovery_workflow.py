"""Synthetic owner-policy records and real durable independent M4 execution."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, cast

import pytest

from fortipam_mcp import instruction_quota_recovery_workflow as w
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_instruction_quota_contract import SERIAL
from test_instruction_quota_http_transport import Connection, assert_closed
from test_instruction_quota_live_workflow import IDENTITY, REQUESTER, TRANSPORT, Cycle, cycle as cycle
from test_instruction_quota_reconciliation import retained_files
from test_instruction_quota_recovery_transport import prepared, originals_unchanged
from v4_planning import canonical_digest


def workflow(cycle: Cycle, monkeypatch: pytest.MonkeyPatch, **overrides: Any) -> w.InstructionQuotaRecoveryWorkflow:
    writer = prepared(cycle, monkeypatch)
    key_path = cycle.path / (w._PREFIX + ".m4.key")
    fd = os.open(key_path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out: out.write(b"q" * 32)
    store = PersistentM4ExecutionStateStore(cycle.path / (w._PREFIX + ".m4.sqlite"), key_path)
    kwargs: dict[str, Any] = {"execution_store": store, "policy_key": b"p" * 32, "authority_key": b"s" * 32,
        "original_key_digests": frozenset(hashlib.sha256(key * 32).hexdigest() for key in (b"k", b"m", b"b", b"a", b"x")),
        "environment_ref": "synthetic-environment", "scope_ref": "synthetic-shared-setting-scope",
        "audience_ref": "synthetic-audience", "execution_enabled": True}
    kwargs.update(overrides)
    return w.InstructionQuotaRecoveryWorkflow(writer, **kwargs)


def policy_for_test(item: w.InstructionQuotaRecoveryWorkflow, **changes: Any) -> Path:
    """Synthetic external provisioner only; not a production admission interface."""
    with item._writer.operation_lock():
        payload = {**item._policy_content(), "owner_decision_digest": hashlib.sha256(b"synthetic-owner-policy-decision").hexdigest(),
            "issued_at": item._local(), "expires_at": item._local() + 1000}
        payload.update(changes)
        value = {"payload": payload, "seal": hmac.new(item._policy_key,
            w._POLICY_DOMAIN + canonical_digest(payload).encode(), hashlib.sha256).hexdigest()}
    path = item._writer._original._directory / (w._PREFIX + ".policy.json")
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as out: json.dump(value, out)
    return path


def authorized(item: w.InstructionQuotaRecoveryWorkflow) -> str:
    preview = item.preview(**IDENTITY)
    return cast(str, item.authorize(cast(str, preview["preview_ref"]), **IDENTITY)["authorization_ref"])


def test_independent_policy_native_ack_readback_and_durable_m4_preserve_original_unknown(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch) -> None:
    item = workflow(cycle, monkeypatch)
    original = retained_files(cycle)
    policy_for_test(item)
    ref = authorized(item)
    result = item.execute(ref, **IDENTITY)
    assert result["outcome"] == "succeeded" and result["verification"] == "verified"
    assert result["original_restore_unknown_preserved"] is True
    for key in ("incident_closed", "original_request_terminal_proven", "forward_resource_work_authorized"):
        assert result[key] is False
    # Only the new ledger is allowed to change.
    assert originals_unchanged(original) and len(cycle.device.requests) == 2
    assert item._store.claim_count == 1 and item._store.audit_events[-1].authorization == "verified"
    count = len(cycle.device.requests)
    assert item.execute(ref, **IDENTITY) == {**result, "idempotent_replay": True}
    assert len(cycle.device.requests) == count
    assert not (cycle.path / "restore.ack.json").exists()
    assert_closed(cycle.device)
    for value in (REQUESTER, TRANSPORT, SERIAL, "synthetic-token", str(cycle.path), "synthetic-private"):
        assert value not in json.dumps(result)


@pytest.mark.parametrize("failure", ["absent", "gate", "scope", "unknown_acceptance", "late_acceptance", "retry", "expiry", "signature"])
def test_target_selection_and_continue_cannot_replace_exact_signed_incident_policy(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    item = workflow(cycle, monkeypatch, execution_enabled=failure != "gate")
    changes = {"scope": {"scope_ref": "synthetic-other-scope"},
        "unknown_acceptance": {"accepts_unresolved_original": False},
        "late_acceptance": {"accepts_late_original_effect": False}, "retry": {"automatic_retry_allowed": True},
        "expiry": {"issued_at": 0, "expires_at": 1}}.get(failure, {})
    if failure != "absent":
        path = policy_for_test(item, **changes)
        if failure == "signature":
            value = json.loads(path.read_text()); value["seal"] = "9" * 64
            path.write_text(json.dumps(value))
    before = retained_files(cycle)
    preview = item.preview(**IDENTITY)
    assert preview["execution_admissible"] is False and preview["policy_status"] == "requires_protected_record"
    with pytest.raises(w.InstructionQuotaRecoveryWorkflowError):
        item.authorize(cast(str, preview["preview_ref"]), **IDENTITY)
    assert item._store.claim_count == 0 and retained_files(cycle) == before
    assert len(cycle.device.requests) == 1


@pytest.mark.parametrize("failure", ["native_key", "old_key", "missing_cohort", "wrong_scope", "wrong_audience"])
def test_key_cohort_and_original_scope_must_be_server_bound(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    overrides = {"native_key": {"authority_key": b"n" * 32}, "old_key": {"authority_key": b"a" * 32},
        "missing_cohort": {"original_key_digests": frozenset({"1" * 64})},
        "wrong_scope": {"scope_ref": "synthetic-other-scope"}, "wrong_audience": {"audience_ref": "synthetic-other-audience"}}[failure]
    with pytest.raises(w.InstructionQuotaRecoveryWorkflowError):
        workflow(cycle, monkeypatch, **overrides)
    assert len(cycle.device.requests) == 1


@pytest.mark.parametrize("failure", ["identity", "preview_tamper", "expired", "policy_changed", "ledger_replaced"])
def test_authorization_tamper_and_drift_never_create_m4_claim_or_put(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    item = workflow(cycle, monkeypatch)
    policy_path = policy_for_test(item)
    preview = item.preview(**IDENTITY)
    if failure == "preview_tamper":
        assert item._preview is not None
        item._preview["nonce"] = "0" * 48
    elif failure == "expired": cycle.device.clock += 30
    elif failure == "ledger_replaced":
        path = item._store._path
        old = path.read_bytes(); path.unlink(); path.write_bytes(old); path.chmod(0o600)
    identity = {**IDENTITY, "requester_digest": "9" * 64} if failure == "identity" else IDENTITY
    if failure in {"identity", "preview_tamper", "expired", "ledger_replaced"}:
        with pytest.raises(w.InstructionQuotaRecoveryWorkflowError):
            item.authorize(cast(str, preview["preview_ref"]), **identity)
    else:
        ref = cast(str, item.authorize(cast(str, preview["preview_ref"]), **IDENTITY)["authorization_ref"])
        value = json.loads(policy_path.read_text()); value["payload"]["owner_decision_digest"] = "9" * 64
        value["seal"] = hmac.new(item._policy_key, w._POLICY_DOMAIN + canonical_digest(value["payload"]).encode(), hashlib.sha256).hexdigest()
        policy_path.write_text(json.dumps(value))
        with pytest.raises(w.InstructionQuotaRecoveryWorkflowError): item.execute(ref, **IDENTITY)
    assert item._store.claim_count == 0 and len(cycle.device.requests) == 1


@pytest.mark.parametrize("failure", ["put", "partial", "read", "policy_after_claim"])
def test_new_failure_is_consumed_unknown_with_no_recursive_compensation_or_rebinding(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    item = workflow(cycle, monkeypatch)
    policy_path = policy_for_test(item)
    ref = authorized(item)
    before = {n: d for n, d in retained_files(cycle).items() if not Path(n).name.startswith(w._PREFIX)}
    if failure == "put":
        def lost(*args: object, **kwargs: object) -> None: raise RuntimeError("synthetic-private-put-detail")
        monkeypatch.setattr(Connection, "request", lost)
    elif failure == "partial": cycle.device.partial = True
    elif failure == "read":
        cycle.device.on_read = lambda: setattr(cycle.device, "used_file", cycle.device.used_file + 1)
    elif failure == "policy_after_claim":
        cycle.device.on_connect = lambda: policy_path.unlink()
    result = item.execute(ref, **IDENTITY)
    assert result["outcome"] == "reconciliation_required" and result["verification"] == "unknown"
    assert result["compensation"] == "not_requested" and item._store.claim_count == 1
    assert originals_unchanged(before)
    count = len(cycle.device.requests)
    # Expired/revoked policy can deny replay; it still cannot dispatch again.
    if failure == "policy_after_claim":
        with pytest.raises(w.InstructionQuotaRecoveryWorkflowError): item.execute(ref, **IDENTITY)
    else: assert item.execute(ref, **IDENTITY)["idempotent_replay"] is True
    with pytest.raises(w.InstructionQuotaRecoveryWorkflowError): item.preview(**IDENTITY)
    assert len(cycle.device.requests) == count
    assert not (cycle.path / "restore.ack.json").exists()
    assert_closed(cycle.device)


def test_new_preview_invalidates_old_authorization_and_expired_intent_can_finish_fresh_readback(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch) -> None:
    item = workflow(cycle, monkeypatch)
    policy_for_test(item, expires_at=1001)
    old = authorized(item)
    fresh = authorized(item)
    with pytest.raises(w.InstructionQuotaRecoveryWorkflowError): item.execute(old, **IDENTITY)
    reads: list[bool] = []
    def on_read() -> None:
        reads.append(True)
        if len(reads) == 3: cycle.device.clock += 2
    cycle.device.on_read = on_read
    result = item.execute(fresh, **IDENTITY)
    assert result["verification"] == "verified" and cycle.device.clock == 1002
    assert len(cycle.device.requests) == 2 and item._store.claim_count == 1


def test_crash_before_m4_claim_leaves_canonical_attempt_and_blocks_new_plan_or_instance(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch) -> None:
    item = workflow(cycle, monkeypatch)
    policy_for_test(item)
    ref = authorized(item)
    kernel_execute = w.M4ExecutionKernel.execute
    def crash(*args: object, **kwargs: object) -> None:
        raise RuntimeError("synthetic-private-process-crash-before-claim")
    monkeypatch.setattr(w.M4ExecutionKernel, "execute", crash)
    with pytest.raises(w.InstructionQuotaRecoveryWorkflowError): item.execute(ref, **IDENTITY)
    assert item._store.claim_count == 0
    attempt = cycle.path / (w._PREFIX + ".m4.attempt.json")
    assert attempt.stat().st_mode & 0o777 == 0o600
    assert len(cycle.device.requests) == 1
    # Restore the kernel: retrying the same authorization must not create a claim.
    monkeypatch.setattr(w.M4ExecutionKernel, "execute", kernel_execute)
    with pytest.raises(w.InstructionQuotaRecoveryWorkflowError): item.execute(ref, **IDENTITY)
    with pytest.raises(w.InstructionQuotaRecoveryWorkflowError): item.preview(**IDENTITY)
    reopened = w.InstructionQuotaRecoveryWorkflow(item._writer, execution_store=item._store,
        policy_key=b"p" * 32, authority_key=b"s" * 32, original_key_digests=item._key_cohort,
        environment_ref="synthetic-environment", scope_ref="synthetic-shared-setting-scope",
        audience_ref="synthetic-audience", execution_enabled=True)
    with pytest.raises(w.InstructionQuotaRecoveryWorkflowError): reopened.preview(**IDENTITY)
    assert len(cycle.device.requests) == 1 and item._store.claim_count == 0


@pytest.mark.parametrize("failure", ["content", "inode"])
def test_attempt_drift_after_m4_claim_consumes_unknown_without_native_put(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    item = workflow(cycle, monkeypatch)
    policy_for_test(item)
    ref = authorized(item)
    before = {n: d for n, d in retained_files(cycle).items() if not Path(n).name.startswith(w._PREFIX)}
    attempt = cycle.path / (w._PREFIX + ".m4.attempt.json")
    def change_attempt() -> None:
        raw = attempt.read_bytes()
        if failure == "content":
            value = json.loads(raw)
            value["payload"]["authorization"] = "9" * 64
            attempt.write_text(json.dumps(value))
        else:
            replacement = attempt.with_suffix(".replacement")
            replacement.write_bytes(raw)
            replacement.chmod(0o600)
            replacement.replace(attempt)
    cycle.device.on_connect = change_attempt
    result = item.execute(ref, **IDENTITY)
    assert result["outcome"] == "reconciliation_required" and result["verification"] == "unknown"
    assert result["compensation"] == "not_requested" and item._store.claim_count == 1
    assert originals_unchanged(before) and len(cycle.device.requests) == 1
    with pytest.raises(w.InstructionQuotaRecoveryWorkflowError): item.execute(ref, **IDENTITY)
    with pytest.raises(w.InstructionQuotaRecoveryWorkflowError): item.preview(**IDENTITY)
    assert len(cycle.device.requests) == 1
    assert_closed(cycle.device)


def test_existing_in_progress_claim_returns_unknown_without_reentering_adapter(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch) -> None:
    item = workflow(cycle, monkeypatch)
    policy_for_test(item)
    ref = authorized(item)
    before = {n: d for n, d in retained_files(cycle).items() if not Path(n).name.startswith(w._PREFIX)}
    verify = w._Verifier.verify
    def crash(*args: object, **kwargs: object) -> None:
        raise RuntimeError("synthetic-private-crash-after-claim")
    monkeypatch.setattr(w._Verifier, "verify", crash)
    with pytest.raises(w.InstructionQuotaRecoveryWorkflowError): item.execute(ref, **IDENTITY)
    assert item._store.claim_count == 1 and len(cycle.device.requests) == 1
    monkeypatch.setattr(w._Verifier, "verify", verify)
    result = item.execute(ref, **IDENTITY)
    assert result["outcome"] == "reconciliation_required" and result["verification"] == "unknown"
    assert result["idempotent_replay"] is True and result["compensation"] == "not_requested"
    assert item._store.claim_count == 1 and len(cycle.device.requests) == 1
    assert originals_unchanged(before)
    assert not (cycle.path / (w._PREFIX + ".claim.json")).exists()


def test_postread_bootstrap_guard_cannot_extend_verification_freshness(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch) -> None:
    item = workflow(cycle, monkeypatch)
    policy_for_test(item)
    ref = authorized(item)
    result_path = cycle.path / (w._PREFIX + ".result.json")
    advanced: list[bool] = []
    def guard() -> None:
        if result_path.exists() and not advanced:
            advanced.append(True)
            cycle.device.clock += 30
    item._bootstrap_guard = guard
    result = item.execute(ref, **IDENTITY)
    assert advanced and result_path.exists()
    assert result["outcome"] == "reconciliation_required" and result["verification"] == "unknown"
    assert result["compensation"] == "not_requested" and len(cycle.device.requests) == 2
    with pytest.raises(w.InstructionQuotaRecoveryWorkflowError): item.execute(ref, **IDENTITY)
    assert len(cycle.device.requests) == 2


@pytest.mark.parametrize("failure, operation, stage, extra_writes", [
    ("status", "dispatch", "ack_validation", 1),
    ("current", "current_read", "precondition", 0),
    ("post", "postcondition_read", "postcondition", 1),
    ("injection", "dispatch", "unavailable", 0),
    ("handler", "dispatch", "ack_validation", 1),
])
def test_safe_diagnostics_preserve_consumed_unknown_and_reject_private_stage_values(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
        failure: str, operation: str, stage: str, extra_writes: int) -> None:
    item = workflow(cycle, monkeypatch)
    policy_for_test(item)
    reference = authorized(item)
    before = {name: digest for name, digest in retained_files(cycle).items()
        if not Path(name).name.startswith(w._PREFIX)}
    writes = len(cycle.device.requests)
    if failure in {"status", "handler"}:
        cycle.device.status = 500
    elif failure == "current":
        cycle.device.used_file += 1
    elif failure == "post":
        cycle.device.partial = True
    else:
        def injected(*args: object, **kwargs: object) -> None:
            error = w.InstructionQuotaRecoveryTransportError("authorization")
            error.stage = "synthetic-private-stage-detail"
            raise error
        monkeypatch.setattr(type(item._writer), "dispatch", injected)
    if failure == "handler":
        def failed_handler(*args: object, **kwargs: object) -> None:
            raise RuntimeError("synthetic-private-handler-detail")
        monkeypatch.setattr(w._LOGGER, "warning", failed_handler)
    caplog.clear()
    caplog.set_level("WARNING", logger=w.__name__)
    result = item.execute(reference, **IDENTITY)
    assert result["outcome"] == "reconciliation_required" and result["verification"] == "unknown"
    assert result["compensation"] == "not_requested" and "diagnostic_stage" not in result
    audit = item._store.audit_events
    assert audit[-1].authorization == {"dispatch": "dispatch_unknown", "current_read": "current_read_unknown",
        "postcondition_read": "post_read_unknown"}[operation]
    records = [record for record in caplog.records if record.name == w.__name__]
    if failure == "handler":
        assert records == []
    else:
        assert len(records) == 1
        assert records[0].getMessage() == f"Instruction quota incident adapter failure: operation={operation} stage={stage}"
        assert records[0].exc_info is None and records[0].stack_info is None
    assert item.execute(reference, **IDENTITY)["idempotent_replay"] is True
    assert item._store.audit_events == audit and len(caplog.records) == len(records)
    assert len(cycle.device.requests) == writes + extra_writes and originals_unchanged(before)
    assert_closed(cycle.device)
