"""Readonly native/M4 join and snapshot assessment; all devices synthetic."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from fortipam_mcp.instruction_quota_reconciliation import (
    InstructionQuotaBaselineRecoveryDraft, InstructionQuotaReconciliationError, InstructionQuotaRestoreReconciler,
)
from fortipam_mcp.instruction_quota_contract import InstructionQuotaContractError
from test_instruction_quota_live_workflow import (
    IDENTITY, REQUESTER, TRANSPORT, Cycle, authorize, cycle as cycle, workflow,
)
from test_instruction_quota_contract import SERIAL
from test_instruction_quota_http_transport import Connection


def retained_files(cycle: Cycle) -> dict[str, str]:
    files = list(cycle.path.glob("*.json")) + list(cycle.path.parent.glob("m4-*/ledger.sqlite"))
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}


def consumed_restore(cycle: Cycle, monkeypatch: pytest.MonkeyPatch) -> InstructionQuotaRestoreReconciler:
    allocate = workflow(cycle)
    assert allocate.execute(authorize(allocate), **IDENTITY)["verification"] == "verified"
    restore = workflow(cycle, "restore")
    reference = authorize(restore)
    with monkeypatch.context() as patch:
        def lose_put(self: Connection, *args: object, **kwargs: object) -> None:
            raise RuntimeError("synthetic-private-lost-put")
        patch.setattr(Connection, "request", lose_put)
        result = restore.execute(reference, **IDENTITY)
    assert result["outcome"] == "reconciliation_required" and result["verification"] == "unknown"
    readonly = workflow(cycle, "restore", execution_enabled=False, transport_enabled=False, store_read_only=True)
    return InstructionQuotaRestoreReconciler(readonly)


@pytest.mark.parametrize("state, outcome", [
    ("allocated", "not-assessed"), ("baseline", "verified-compensated"),
    ("partial", "partial-or-drifted"), ("sibling_drift", "partial-or-drifted"),
])
def test_bound_readonly_outcomes_preserve_unknown_and_never_write(
    cycle: Cycle, monkeypatch: pytest.MonkeyPatch, state: str, outcome: str,
) -> None:
    reconciler = consumed_restore(cycle, monkeypatch)
    if state == "baseline":
        cycle.device.file, cycle.device.instruction = 5, 0
    elif state == "partial":
        cycle.device.instruction = 0
    elif state == "sibling_drift":
        cycle.device.sibling = "synthetic-other-private-value"
    before = retained_files(cycle)
    reads: list[bool] = []
    cycle.device.on_read = lambda: reads.append(True)
    report = reconciler.assess(**IDENTITY)
    assert report["outcome"] == outcome and len(reads) == 1
    assert report["original_m4_outcome"] == "reconciliation_required"
    assert report["original_m4_verification"] == "unknown"
    assert report["owner_decision_required"] is True
    assert report["original_native_m4_witness_unchanged"] is True
    for key in ("execution_admissible", "redispatch_allowed", "ledger_finalized",
                "original_request_terminal_proven", "action_correlation_absence_qualified"):
        assert report[key] is False
    assert retained_files(cycle) == before and len(cycle.device.requests) == 1
    assert not (cycle.path / "restore.ack.json").exists()
    encoded = json.dumps(report)
    for value in (REQUESTER, TRANSPORT, SERIAL, "synthetic-token", "synthetic-private", str(cycle.path)):
        assert value not in encoded


@pytest.mark.parametrize("state", ["allocated", "baseline", "partial", "resource_used", "wrong_identity"])
def test_fixed_baseline_recovery_draft_is_fresh_bounded_immutable_and_never_grants_execution(
    cycle: Cycle, monkeypatch: pytest.MonkeyPatch, state: str,
) -> None:
    reconciler = consumed_restore(cycle, monkeypatch)
    if state == "baseline":
        cycle.device.file, cycle.device.instruction = 5, 0
    elif state == "partial":
        cycle.device.instruction = 0
    elif state == "resource_used":
        cycle.device.resource = 1
    before = retained_files(cycle)
    reads: list[bool] = []
    cycle.device.on_read = lambda: reads.append(True)
    identity = {**IDENTITY, "requester_digest": "9" * 64} if state == "wrong_identity" else IDENTITY
    if state != "allocated":
        with pytest.raises(InstructionQuotaReconciliationError):
            reconciler.prepare_baseline_recovery(**identity)
    else:
        draft = reconciler.prepare_baseline_recovery(**identity)
        result = draft.summary()
        assert result["current_state_digest"] == reconciler._workflow._binding._current
        assert result["expected_state_digest"] == reconciler._workflow._transport._baseline._state
        assert result["evidence_expires_at_epoch"] == result["evidence_read_started_at_epoch"] + 30
        assert result["instruction_quota_current_percent"] == 1
        assert result["instruction_quota_expected_percent"] == 0
        assert result["file_quota_change_percentage_points"] == 1 and result["planning_only"] is True
        assert result["original_m4_verification"] == "unknown"
        for key in ("execution_admissible", "redispatch_allowed", "ledger_finalized", "original_request_terminal_proven"):
            assert result[key] is False
        assert len(result["required_dependencies"]) == 3
        with pytest.raises(InstructionQuotaContractError):
            draft.digest = "9" * 64
        with pytest.raises(InstructionQuotaReconciliationError):
            InstructionQuotaBaselineRecoveryDraft()
        assert not any(hasattr(draft, name) for name in ("dispatch", "execute", "authorize"))
        for value in (REQUESTER, TRANSPORT, SERIAL, "synthetic-token", str(cycle.path)):
            assert value not in json.dumps(result)
    assert len(reads) == (0 if state == "wrong_identity" else 1)
    assert retained_files(cycle) == before and len(cycle.device.requests) == 1


@pytest.mark.parametrize("expire", [False, True])
def test_draft_deadline_starts_before_read_and_cannot_be_extended(
    cycle: Cycle, monkeypatch: pytest.MonkeyPatch, expire: bool,
) -> None:
    reconciler = consumed_restore(cycle, monkeypatch)
    started = cycle.device.clock
    def read_delay() -> None:
        cycle.device.clock += 29
    cycle.device.on_read = read_delay
    if expire:
        original = reconciler._observe
        def after_read(**kwargs: str):
            result = original(**kwargs)
            cycle.device.clock += 1
            return result
        monkeypatch.setattr(reconciler, "_observe", after_read)
        with pytest.raises(InstructionQuotaReconciliationError):
            reconciler.prepare_baseline_recovery(**IDENTITY)
    else:
        result = reconciler.prepare_baseline_recovery(**IDENTITY).summary()
        assert result["evidence_expires_at_epoch"] == started + 30
        assert result["observed_at_epoch"] == started + 29
    assert len(cycle.device.requests) == 1


@pytest.mark.parametrize("field", ["plan", "authorization", "binding", "anchors"])
def test_wrong_native_to_m4_join_fails_before_context_read(
    cycle: Cycle, monkeypatch: pytest.MonkeyPatch, field: str,
) -> None:
    reconciler = consumed_restore(cycle, monkeypatch)
    transport = reconciler._workflow._transport
    path = cycle.path / "restore.claim.json"
    with transport.operation_lock():
        claim = transport._claim("restore")
        path.unlink()
        claim[field] = {"claim": "9"*64, "ack": "9"*64, "result": "9"*64} if field == "anchors" else "9"*64
        transport._write_once("restore.claim.json", claim)
    reads: list[bool] = []
    cycle.device.on_read = lambda: reads.append(True)
    before = retained_files(cycle)
    with pytest.raises(InstructionQuotaReconciliationError, match="unavailable"):
        reconciler.assess(**IDENTITY)
    assert not reads and retained_files(cycle) == before


@pytest.mark.parametrize("failure", ["identity", "age", "native_drift", "ledger_tamper", "capacity"])
def test_invalid_evidence_never_returns_partial_assessment(
    cycle: Cycle, monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    reconciler = consumed_restore(cycle, monkeypatch)
    reads: list[bool] = []
    def on_read() -> None:
        reads.append(True)
        if failure == "age":
            cycle.device.clock += 31
        elif failure == "native_drift":
            transport = reconciler._workflow._transport
            claim = transport._claim("restore")
            (cycle.path / "restore.claim.json").unlink()
            claim["expires_at"] += 1
            transport._write_once("restore.claim.json", claim)
    cycle.device.on_read = on_read
    identity = {**IDENTITY, "requester_digest": "9"*64} if failure == "identity" else IDENTITY
    if failure == "ledger_tamper":
        ledger = reconciler._workflow._execution_store._path
        with sqlite3.connect(ledger) as connection:
            connection.execute("UPDATE execution_ledger SET context_key = ? WHERE event_type = 'claim'", ("9"*64,))
    elif failure == "capacity":
        cycle.device.resource = 101
    with pytest.raises(InstructionQuotaReconciliationError):
        reconciler.assess(**identity)
    assert len(reads) == (0 if failure in {"identity", "ledger_tamper"} else 1)
    assert len(cycle.device.requests) == 1


@pytest.mark.parametrize("gate", ["workflow", "transport"])
def test_execution_gate_open_is_rejected(cycle: Cycle, gate: str) -> None:
    item = workflow(cycle, "restore", execution_enabled=gate == "workflow", transport_enabled=gate == "transport")
    with pytest.raises(InstructionQuotaReconciliationError):
        InstructionQuotaRestoreReconciler(item)


@pytest.mark.parametrize("reject", [False, True])
def test_reconciliation_snapshot_connections_close_on_success_and_rejection(
    cycle: Cycle, monkeypatch: pytest.MonkeyPatch, reject: bool,
) -> None:
    reconciler = consumed_restore(cycle, monkeypatch)
    transport = reconciler._workflow._transport
    if reject:
        with transport.operation_lock():
            claim = transport._claim("restore")
            (cycle.path / "restore.claim.json").unlink()
            claim["plan"] = "9"*64
            transport._write_once("restore.claim.json", claim)
    store = reconciler._workflow._execution_store
    original = store._connect
    opened: list[sqlite3.Connection] = []
    def connect() -> sqlite3.Connection:
        connection = original()
        opened.append(connection)
        return connection
    monkeypatch.setattr(store, "_connect", connect)
    if reject:
        with pytest.raises(InstructionQuotaReconciliationError):
            reconciler.assess(**IDENTITY)
    else:
        assert reconciler.assess(**IDENTITY)["outcome"] == "not-assessed"
    assert len(opened) == (1 if reject else 2)
    for connection in opened:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")
