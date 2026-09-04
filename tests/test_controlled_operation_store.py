from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import sqlite3
import stat

import pytest

import fortipam_mcp.controlled_operation_store as store_module
from fortipam_mcp.controlled_operation_store import (
    ClaimState,
    ControlledOperationStateStore,
    ControlledOperationStoreError,
    PersistentAuditEvent,
    PersistentControlledOperationEngineStore,
)
from fortipam_mcp.controlled_operations import (
    ActionContract,
    ActionRegistry,
    ApprovalBinding,
    ApprovalRejected,
    AuthenticatedPrincipal,
    ControlledOperationEngine,
    ControlledOperationRequest,
    ControlledOperationResult,
    IdempotencyConflict,
    PublicOutcome,
    RollbackContract,
    RollbackState,
    VerificationState,
)


NOW = 1_777_000_000
KEY = b"controlled-operation-test-key!!!"  # exactly 32 bytes
PRINCIPAL_REF = "operator-subject-reference-one"
OTHER_PRINCIPAL_REF = "operator-subject-reference-two"
TARGET_REF = "sensitive-target-reference-one"
PARAMETER_VALUE = "sensitive-parameter-value-one"
APPROVER_REF = "separate-approver-reference-one"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _binding(
    *,
    principal_ref: str = PRINCIPAL_REF,
    target_ref: str = TARGET_REF,
    purpose: str = "forward",
) -> ApprovalBinding:
    return ApprovalBinding(
        purpose=purpose,
        principal_digest=_digest(principal_ref),
        action_id="fixed-action",
        action_version="1.0.0",
        target_digest=_digest(target_ref),
        parameters_digest=_digest(PARAMETER_VALUE),
        expected_current_digest=_digest("expected-current-state"),
    )


def _paths(tmp_path: Path) -> tuple[Path, Path]:
    state = tmp_path / "state"
    state.mkdir(mode=0o700, parents=True)
    key = state / "operation.key"
    key.write_bytes(KEY)
    os.chmod(key, 0o600)
    return state / "operation.db", key


def _store(tmp_path: Path, *, now: int = NOW) -> ControlledOperationStateStore:
    database, key = _paths(tmp_path) if not (tmp_path / "state").exists() else (
        tmp_path / "state" / "operation.db",
        tmp_path / "state" / "operation.key",
    )
    return ControlledOperationStateStore(database, key, clock=lambda: now)


def _approved(
    store: ControlledOperationStateStore,
    binding: ApprovalBinding,
    *,
    now: int = NOW,
) -> tuple[str, str]:
    issued = store.issue_approval(binding, now_epoch=now)
    store.approve(
        issued.approval_reference,
        issued.approval_nonce,
        APPROVER_REF,
        now_epoch=now + 1,
    )
    claims = store.verify(
        issued.approval_reference,
        AuthenticatedPrincipal(PRINCIPAL_REF, "operator"),
        binding,
        now_epoch=now + 2,
    )
    receipt_digest = _digest(claims.receipt_id + claims.nonce_digest)
    return issued.approval_reference, receipt_digest


def _event(
    binding: ApprovalBinding,
    result: ControlledOperationResult,
    *,
    occurred_at: int = NOW + 3,
) -> PersistentAuditEvent:
    return PersistentAuditEvent(
        event_type="operation_finalized",
        principal_digest=binding.principal_digest,
        principal_class="operator",
        action_id=binding.action_id,
        action_version=binding.action_version,
        target_class="fixed-target",
        purpose=binding.purpose,
        authorization="approved",
        outcome=result.outcome.value,
        verification=result.verification.value,
        rollback=result.rollback.value,
        digest_reference=_digest("closed-result-reference"),
        occurred_at=occurred_at,
    )


def _success() -> ControlledOperationResult:
    return ControlledOperationResult(
        PublicOutcome.SUCCEEDED,
        VerificationState.VERIFIED,
        RollbackState.NOT_REQUESTED,
        False,
    )


def test_owner_only_database_and_key_are_required(tmp_path: Path) -> None:
    store = _store(tmp_path)
    database = tmp_path / "state" / "operation.db"
    key = tmp_path / "state" / "operation.key"
    assert stat.S_IMODE(database.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(database.stat().st_mode) == 0o600
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    with store._connect() as connection:  # noqa: SLF001 - hardening assertion.
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2

    os.chmod(key, 0o644)
    with pytest.raises(ControlledOperationStoreError):
        ControlledOperationStateStore(database, key)

    os.chmod(key, 0o600)
    os.chmod(database, 0o644)
    with pytest.raises(ControlledOperationStoreError):
        ControlledOperationStateStore(database, key)


def test_rejects_symlink_and_non_owner_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database, key = _paths(tmp_path)
    target = tmp_path / "target.key"
    target.write_bytes(KEY)
    os.chmod(target, 0o600)
    key.unlink()
    key.symlink_to(target)
    with pytest.raises(ControlledOperationStoreError):
        ControlledOperationStateStore(database, key)

    key.unlink()
    key.write_bytes(KEY)
    os.chmod(key, 0o600)
    store = ControlledOperationStateStore(database, key)
    real_uid = os.getuid()
    monkeypatch.setattr(store_module.os, "getuid", lambda: real_uid + 1)
    with pytest.raises(ControlledOperationStoreError):
        ControlledOperationStateStore(database, key)
    assert store is not None


def test_approval_issue_approve_verify_survives_restart_and_is_bound(tmp_path: Path) -> None:
    store = _store(tmp_path)
    binding = _binding()
    issued = store.issue_approval(binding, now_epoch=NOW)
    restarted = _store(tmp_path)
    restarted.approve(
        issued.approval_reference,
        issued.approval_nonce,
        APPROVER_REF,
        now_epoch=NOW + 1,
    )
    claims = _store(tmp_path).verify(
        issued.approval_reference,
        AuthenticatedPrincipal(PRINCIPAL_REF, "operator"),
        binding,
        now_epoch=NOW + 2,
    )
    assert claims.binding == binding
    assert claims.receipt_id.startswith("receipt-")
    assert len(claims.nonce_digest) == 64

    wrong_target = _binding(target_ref="different-sensitive-target")
    with pytest.raises(ApprovalRejected, match="approval was rejected"):
        restarted.verify(
            issued.approval_reference,
            AuthenticatedPrincipal(PRINCIPAL_REF, "operator"),
            wrong_target,
            now_epoch=NOW + 2,
        )
    with pytest.raises(ApprovalRejected, match="approval was rejected"):
        restarted.verify(
            issued.approval_reference,
            AuthenticatedPrincipal(OTHER_PRINCIPAL_REF, "operator"),
            binding,
            now_epoch=NOW + 2,
        )


def test_wrong_nonce_deny_and_expiry_fail_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    binding = _binding()
    issued = store.issue_approval(binding, lifetime_seconds=30, now_epoch=NOW)
    with pytest.raises(ApprovalRejected):
        store.approve(
            issued.approval_reference,
            "wrong-nonce-reference-that-is-long-enough",
            APPROVER_REF,
            now_epoch=NOW + 1,
        )
    store.deny(
        issued.approval_reference,
        issued.approval_nonce,
        APPROVER_REF,
        now_epoch=NOW + 2,
    )
    with pytest.raises(ApprovalRejected):
        store.approve(
            issued.approval_reference,
            issued.approval_nonce,
            APPROVER_REF,
            now_epoch=NOW + 3,
        )
    with pytest.raises(ApprovalRejected):
        store.verify(
            issued.approval_reference,
            AuthenticatedPrincipal(PRINCIPAL_REF, "operator"),
            binding,
            now_epoch=NOW + 3,
        )

    expiring = store.issue_approval(binding, lifetime_seconds=30, now_epoch=NOW)
    with pytest.raises(ApprovalRejected):
        store.approve(
            expiring.approval_reference,
            expiring.approval_nonce,
            APPROVER_REF,
            now_epoch=NOW + 30,
        )


def test_claim_consumes_receipt_once_and_persists_final_result(tmp_path: Path) -> None:
    store = _store(tmp_path)
    binding = _binding()
    _, receipt = _approved(store, binding)
    idempotency = _digest("idempotency-key-one")
    context = _digest("verified-context-one")
    claimed = store.claim(
        "forward", binding.principal_digest, idempotency, context, receipt, now_epoch=NOW + 2
    )
    assert claimed.state is ClaimState.NEW

    with pytest.raises(ApprovalRejected):
        store.claim(
            "forward",
            binding.principal_digest,
            _digest("different-idempotency-key"),
            _digest("different-context"),
            receipt,
            now_epoch=NOW + 3,
        )

    result = _success()
    store.finalize(
        "forward",
        binding.principal_digest,
        idempotency,
        context,
        result,
        _event(binding, result),
        now_epoch=NOW + 3,
    )
    replay = _store(tmp_path).get_idempotency(
        "forward", binding.principal_digest, idempotency, context
    )
    assert replay.state is ClaimState.REPLAY
    assert replay.result is not None
    assert replay.result.outcome is PublicOutcome.SUCCEEDED
    assert replay.result.idempotent_replay is True


def test_matching_unfinished_claim_is_unknown_and_never_reclaimed_after_restart(tmp_path: Path) -> None:
    store = _store(tmp_path)
    binding = _binding()
    _, receipt = _approved(store, binding)
    idempotency = _digest("interrupted-idempotency-key")
    context = _digest("interrupted-context")
    assert store.claim(
        "forward", binding.principal_digest, idempotency, context, receipt, now_epoch=NOW + 2
    ).state is ClaimState.NEW
    restarted = _store(tmp_path)
    state = restarted.claim(
        "forward", binding.principal_digest, idempotency, context, receipt, now_epoch=NOW + 3
    )
    assert state.state is ClaimState.IN_PROGRESS
    assert state.result is not None
    assert state.result.outcome is PublicOutcome.VERIFICATION_UNKNOWN


def test_idempotency_conflict_and_cross_principal_isolation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = _binding()
    _, first_receipt = _approved(store, first)
    key = _digest("shared-idempotency-digest")
    first_context = _digest("first-context")
    store.claim("forward", first.principal_digest, key, first_context, first_receipt)
    with pytest.raises(IdempotencyConflict):
        store.get_idempotency(
            "forward", first.principal_digest, key, _digest("wrong-context")
        )

    second = _binding(principal_ref=OTHER_PRINCIPAL_REF)
    issued = store.issue_approval(second, now_epoch=NOW)
    store.approve(
        issued.approval_reference,
        issued.approval_nonce,
        APPROVER_REF,
        now_epoch=NOW + 1,
    )
    claims = store.verify(
        issued.approval_reference,
        AuthenticatedPrincipal(OTHER_PRINCIPAL_REF, "operator"),
        second,
        now_epoch=NOW + 2,
    )
    second_receipt = _digest(claims.receipt_id + claims.nonce_digest)
    assert store.claim(
        "forward",
        second.principal_digest,
        key,
        _digest("second-context"),
        second_receipt,
        now_epoch=NOW + 2,
    ).state is ClaimState.NEW


def test_concurrent_claim_has_one_new_and_one_in_progress(tmp_path: Path) -> None:
    store = _store(tmp_path)
    binding = _binding()
    _, receipt = _approved(store, binding)
    key = _digest("concurrent-idempotency-key")
    context = _digest("concurrent-context")

    def claim() -> ClaimState:
        current = _store(tmp_path)
        return current.claim(
            "forward", binding.principal_digest, key, context, receipt, now_epoch=NOW + 2
        ).state

    with ThreadPoolExecutor(max_workers=2) as executor:
        states = list(executor.map(lambda _: claim(), range(2)))
    assert sorted(states) == [ClaimState.IN_PROGRESS, ClaimState.NEW]


def test_tamper_and_wrong_key_are_detected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    binding = _binding()
    _approved(store, binding)
    database = tmp_path / "state" / "operation.db"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE audit_events SET authorization = 'denied' WHERE sequence = 1"
        )
    with pytest.raises(ControlledOperationStoreError, match="audit chain"):
        _store(tmp_path)

    other = tmp_path / "other"
    other_store = _store(other)
    other_store.issue_approval(binding, now_epoch=NOW)
    (other / "state" / "operation.key").write_bytes(b"b" * 32)
    os.chmod(other / "state" / "operation.key", 0o600)
    with pytest.raises(ControlledOperationStoreError):
        _store(other)


def test_raw_sensitive_inputs_are_absent_from_database(tmp_path: Path) -> None:
    store = _store(tmp_path)
    binding = _binding()
    issued = store.issue_approval(binding, now_epoch=NOW)
    store.approve(
        issued.approval_reference,
        issued.approval_nonce,
        APPROVER_REF,
        now_epoch=NOW + 1,
    )
    claims = store.verify(
        issued.approval_reference,
        AuthenticatedPrincipal(PRINCIPAL_REF, "operator"),
        binding,
        now_epoch=NOW + 2,
    )
    raw_idempotency = "raw-idempotency-value-that-must-not-persist"
    receipt = _digest(claims.receipt_id + claims.nonce_digest)
    store.claim(
        "forward",
        binding.principal_digest,
        _digest(raw_idempotency),
        _digest("closed-context"),
        receipt,
        now_epoch=NOW + 2,
    )
    database = (tmp_path / "state" / "operation.db").read_bytes()
    for raw in (
        PRINCIPAL_REF,
        TARGET_REF,
        PARAMETER_VALUE,
        APPROVER_REF,
        issued.approval_reference,
        issued.approval_nonce,
        raw_idempotency,
        claims.receipt_id,
    ):
        assert raw.encode() not in database


def test_engine_replay_uses_persistent_principal_scoped_state_after_restart(
    tmp_path: Path,
) -> None:
    expected = _digest("engine-expected-current")
    request = ControlledOperationRequest(
        action_id="fixed-action",
        action_version="1.0.0",
        target_ref=TARGET_REF,
        parameters={},
        expected_current_digest=expected,
        idempotency_key="persistent-idempotency-key-0001",
        approval_reference="placeholder-approval-reference",
    )
    binding = ApprovalBinding(
        purpose="forward",
        principal_digest=_digest(PRINCIPAL_REF),
        action_id=request.action_id,
        action_version=request.action_version,
        target_digest=_digest(request.target_ref),
        parameters_digest=_digest("{}"),
        expected_current_digest=expected,
    )
    store = _store(tmp_path)
    issued = store.issue_approval(binding, now_epoch=NOW)
    store.approve(
        issued.approval_reference,
        issued.approval_nonce,
        APPROVER_REF,
        now_epoch=NOW + 1,
    )
    request = ControlledOperationRequest(
        action_id=request.action_id,
        action_version=request.action_version,
        target_ref=request.target_ref,
        parameters=request.parameters,
        expected_current_digest=request.expected_current_digest,
        idempotency_key=request.idempotency_key,
        approval_reference=issued.approval_reference,
    )

    class Adapter:
        def __init__(self) -> None:
            self.execute_calls = 0

        def read_current(self, request: object) -> str:
            return expected

        def execute(self, request: object) -> None:
            self.execute_calls += 1

        def verify_postcondition(self, request: object) -> bool:
            return True

        def rollback(self, request: object) -> None:
            raise AssertionError("rollback is not expected")

        def verify_rollback_postcondition(self, request: object) -> bool:
            raise AssertionError("rollback verification is not expected")

    forward = ActionContract(
        "fixed-action",
        "1.0.0",
        "fixed-target",
        "synthetic-fixture",
        "0.0.0",
        (),
        "fixed-rollback",
        "1.0.0",
    )
    rollback = RollbackContract(
        "fixed-rollback",
        "1.0.0",
        "fixed-target",
        "synthetic-fixture",
        "0.0.0",
        (),
        "fixed-action",
        "1.0.0",
    )
    registry = ActionRegistry((forward,), (rollback,))
    first_adapter = Adapter()
    first = ControlledOperationEngine(
        registry,
        first_adapter,
        store,
        PersistentControlledOperationEngineStore(store),
    )
    result = first.execute(
        request,
        AuthenticatedPrincipal(PRINCIPAL_REF, "operator"),
        now_epoch=NOW + 2,
    )
    assert result.outcome is PublicOutcome.SUCCEEDED
    assert first_adapter.execute_calls == 1

    restarted_store = _store(tmp_path)
    restarted_adapter = Adapter()
    restarted = ControlledOperationEngine(
        registry,
        restarted_adapter,
        restarted_store,
        PersistentControlledOperationEngineStore(restarted_store),
    )
    replay = restarted.execute(
        request,
        AuthenticatedPrincipal(PRINCIPAL_REF, "operator"),
        now_epoch=NOW + 3,
    )
    assert replay.idempotent_replay is True
    assert replay.outcome is PublicOutcome.SUCCEEDED
    assert restarted_adapter.execute_calls == 0
