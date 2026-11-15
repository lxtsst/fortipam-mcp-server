"""Independent correction predicates preserve original UNKNOWN; no live I/O."""
from __future__ import annotations

import json

import pytest

from fortipam_mcp import instruction_quota_recovery_contract as r
from fortipam_mcp.instruction_quota_contract import InstructionQuotaContractError
from test_instruction_quota_contract import SERIAL, state, usage
from test_instruction_quota_live_workflow import IDENTITY, REQUESTER, TRANSPORT, Cycle, cycle as cycle
from test_instruction_quota_reconciliation import consumed_restore, retained_files


def test_independent_fixed_body_complete_postcondition_and_immutable_originals(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch) -> None:
    reconciler = consumed_restore(cycle, monkeypatch)
    before = retained_files(cycle)
    reads: list[bool] = []
    cycle.device.on_read = lambda: reads.append(True)
    candidate = r.prepare_instruction_quota_baseline_recovery(reconciler, **IDENTITY)
    summary = candidate.summary()
    current, measured = cycle.device.read(None, serial_digest=SERIAL)
    body = r.build_instruction_quota_recovery_body(candidate, current, measured, **IDENTITY)
    assert body == b'{"secret-instruction-quota":0,"file-storage-quota":5}'
    assert summary["action_id"] != "instruction-quota-restore"
    assert summary["required_policy"] == r.REQUIRED_POLICY
    assert summary["policy_status"] == "not_admitted" and summary["planning_only"] is True
    for key in ("execution_admissible", "redispatch_allowed", "ledger_finalized",
                "incident_closed", "original_request_terminal_proven", "automatic_compensation_allowed"):
        assert summary[key] is False
    assert summary["original_unknown_preserved"] is True
    assert len(reads) == 2
    # A verified state predicate cannot prove that a new or old request ran.
    cycle.device.clock += 31
    r.check_instruction_quota_recovery_postcondition(candidate, reconciler._workflow._transport._baseline,
        measured, **IDENTITY, read_started_at_epoch=cycle.device.clock)
    assert retained_files(cycle) == before and len(cycle.device.requests) == 1
    assert not (cycle.path / "restore.ack.json").exists()
    for value in (REQUESTER, TRANSPORT, SERIAL, "synthetic-token", "synthetic-private", str(cycle.path)):
        assert value not in json.dumps(summary)
    assert not any(hasattr(candidate, name) for name in ("dispatch", "execute", "authorize", "finalize"))
    with pytest.raises(InstructionQuotaContractError):
        candidate.digest = "9" * 64
    with pytest.raises(r.InstructionQuotaRecoveryContractError):
        r.InstructionQuotaBaselineRecoveryCandidate()


@pytest.mark.parametrize("failure", ["baseline", "partial", "sibling_drift", "resource", "identity", "expired"])
def test_preparation_uses_one_fixed_read_and_denies_unqualified_state(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    reconciler = consumed_restore(cycle, monkeypatch)
    if failure == "baseline":
        cycle.device.file, cycle.device.instruction = 5, 0
    elif failure == "partial":
        cycle.device.instruction = 0
    elif failure == "sibling_drift":
        cycle.device.sibling = "synthetic-private-drift"
    elif failure == "resource":
        cycle.device.resource = 1
    reads: list[bool] = []
    def on_read() -> None:
        reads.append(True)
        if failure == "expired":
            cycle.device.clock += 30
    cycle.device.on_read = on_read
    before = retained_files(cycle)
    identity = {**IDENTITY, "requester_digest": "9" * 64} if failure == "identity" else IDENTITY
    with pytest.raises(r.InstructionQuotaRecoveryContractError, match="^The private Instruction quota incident correction contract is unavailable.$"):
        r.prepare_instruction_quota_baseline_recovery(reconciler, **identity)
    assert len(reads) == (0 if failure == "identity" else 1)
    assert retained_files(cycle) == before and len(cycle.device.requests) == 1


@pytest.mark.parametrize("failure", ["config", "schema", "video", "usage", "resource", "expired", "identity", "native", "ledger"])
def test_local_body_compilation_rejects_drift_stale_or_changed_original_evidence(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    reconciler = consumed_restore(cycle, monkeypatch)
    candidate = r.prepare_instruction_quota_baseline_recovery(reconciler, **IDENTITY)
    current, measured = cycle.device.read(None, serial_digest=SERIAL)
    if failure == "config":
        current = state(file=4, instruction=1, other="synthetic-private-drift")
    elif failure == "schema":
        current = state(file=4, instruction=1, schema_extra="changed", other=cycle.device.sibling)
    elif failure == "video":
        current = state(file=4, instruction=1, video=89, other=cycle.device.sibling)
    elif failure == "usage":
        measured = usage(file=351)
    elif failure == "resource":
        measured = usage(resource=1)
    elif failure == "expired":
        cycle.device.clock += 30
    elif failure == "native":
        transport = reconciler._workflow._transport
        with transport.operation_lock():
            claim = transport._claim("restore")
            (cycle.path / "restore.claim.json").unlink()
            claim["expires_at"] += 1
            transport._write_once("restore.claim.json", claim)
    elif failure == "ledger":
        import sqlite3
        with sqlite3.connect(reconciler._workflow._execution_store._path) as connection:
            connection.execute("UPDATE execution_ledger SET context_key = ? WHERE event_type = 'claim'",
                ("9" * 64,))
    identity = {**IDENTITY, "transport_digest": "9" * 64} if failure == "identity" else IDENTITY
    before = retained_files(cycle)
    with pytest.raises(r.InstructionQuotaRecoveryContractError):
        r.build_instruction_quota_recovery_body(candidate, current, measured, **identity)
    assert retained_files(cycle) == before and len(cycle.device.requests) == 1


@pytest.mark.parametrize("failure", ["allocated", "partial", "sibling", "resource", "old_read", "future_read", "bool_time", "identity"])
def test_postcondition_requires_exact_fresh_baseline_and_zero_resources(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    reconciler = consumed_restore(cycle, monkeypatch)
    candidate = r.prepare_instruction_quota_baseline_recovery(reconciler, **IDENTITY)
    current, measured = reconciler._workflow._transport._baseline, usage()
    started = cycle.device.clock
    if failure == "allocated":
        current = state(file=4, instruction=1, other=cycle.device.sibling)
    elif failure == "partial":
        current = state(file=4, instruction=0, other=cycle.device.sibling)
    elif failure == "sibling":
        current = state(other="synthetic-private-drift")
    elif failure == "resource":
        measured = usage(resource=1)
    elif failure == "old_read":
        cycle.device.clock += 31
    elif failure == "future_read":
        started += 1
    elif failure == "bool_time":
        started = True
    identity = {**IDENTITY, "requester_digest": "9" * 64} if failure == "identity" else IDENTITY
    before = retained_files(cycle)
    with pytest.raises(r.InstructionQuotaRecoveryContractError):
        r.check_instruction_quota_recovery_postcondition(candidate, current, measured, **identity,
            read_started_at_epoch=started)
    assert retained_files(cycle) == before and len(cycle.device.requests) == 1


def test_body_deadline_rechecked_after_compilation_and_partial_body_is_cleared(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch) -> None:
    reconciler = consumed_restore(cycle, monkeypatch)
    candidate = r.prepare_instruction_quota_baseline_recovery(reconciler, **IDENTITY)
    current, measured = cycle.device.read(None, serial_digest=SERIAL)
    compile_body = r.build_instruction_quota_body
    retained: list[bytearray] = []
    def slow_compile(*args):
        body = compile_body(*args)
        retained.append(body)
        cycle.device.clock += 30
        return body
    monkeypatch.setattr(r, "build_instruction_quota_body", slow_compile)
    with pytest.raises(r.InstructionQuotaRecoveryContractError):
        r.build_instruction_quota_recovery_body(candidate, current, measured, **IDENTITY)
    assert retained == [bytearray()] and len(cycle.device.requests) == 1
