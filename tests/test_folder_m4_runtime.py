from __future__ import annotations

import inspect
import os
from pathlib import Path

import pytest

from fortipam_mcp.folder_create_contract import FolderCreateRequest
from fortipam_mcp.folder_m4_authorization import (
    FolderM4AuthorizationCheckpointError,
    FolderM4AuthorizationError,
    FolderM4AuthorizationStoreTail,
    MonotonicFolderM4AuthorizationCheckpoint,
    PersistentFolderM4AuthorizationStore,
    ProtectedChildFolderBinding,
    ProtectedFolderM4AuthorizationVerifier,
)
from fortipam_mcp.folder_m4_runtime import ProtectedChildFolderM4Runtime
from fortipam_mcp.m4_execution_store import (
    M4ExecutionStoreTail,
    M4MonotonicCheckpointError,
    MonotonicM4ExecutionCheckpoint,
    PersistentM4ExecutionStateStore,
    PersistentM4ExecutionStoreError,
)
from test_folder_m4_authorization import ACTIVE, _issue
from v4_planning import (
    M4ClaimState,
    M4Outcome,
    M4Verification,
    canonical_digest,
)


AUTHORIZATION_CHECKPOINT_STORE_REF = "m4-folder-runtime-authorization-store"
EXECUTION_CHECKPOINT_STORE_REF = "m4-folder-runtime-execution-store"
AUTHORIZATION_STORE_KEY = b"folder-m4-store-key-000000000000000001"


class _Transport:
    def __init__(
        self,
        request: FolderCreateRequest,
        *,
        fail_phase: str | None = None,
    ) -> None:
        self.request = request
        self.exists = False
        self.fail_phase = fail_phase
        self.calls: list[str] = []

    def read_collection(self) -> dict[str, object]:
        self.calls.append("read")
        if self.fail_phase == "current" and self.calls == ["read"]:
            raise RuntimeError("bounded synthetic current read failure")
        if self.fail_phase == "post" and self.calls[-3:] == ["read", "create", "read"]:
            raise RuntimeError("bounded synthetic post read failure")
        results: list[dict[str, object]] = []
        if self.exists:
            results.append(
                {
                    "id": 77,
                    "name": self.request.name,
                    "parent-folder": self.request.parent_folder_id,
                    "inherit-policy": "enable",
                    "inherit-permission": "enable",
                    "inherit-folder-ztna": "enable",
                    "user-permission": [],
                    "group-permission": [],
                }
            )
        return {"http_status": 200, "results": results}

    def create_child(self, body: object) -> dict[str, object]:
        self.calls.append("create")
        assert body == self.request.body()
        if self.fail_phase == "dispatch":
            raise RuntimeError("bounded synthetic dispatch failure")
        self.exists = True
        return {"http_status": 200, "mkey": 77}


class _ExternalM4Checkpoint:
    authority_ref = "m4-folder-runtime-checkpoint-authority"

    def __init__(self, store_ref: str) -> None:
        self.tail = M4ExecutionStoreTail.empty(store_ref)

    def verify(self, tail: M4ExecutionStoreTail) -> None:
        if tail != self.tail:
            raise M4MonotonicCheckpointError("checkpoint mismatch")

    def advance(
        self,
        previous: M4ExecutionStoreTail,
        current: M4ExecutionStoreTail,
    ) -> None:
        if (
            previous != self.tail
            or current.store_ref != previous.store_ref
            or current.sequence != previous.sequence + 1
        ):
            raise M4MonotonicCheckpointError("checkpoint compare-and-swap failed")
        self.tail = current


class _ExternalAuthorizationCheckpoint:
    authority_ref = "m4-folder-runtime-authorization-checkpoint-authority"

    def __init__(self, store_ref: str) -> None:
        self.tail = FolderM4AuthorizationStoreTail.empty(store_ref)

    def verify(self, tail: FolderM4AuthorizationStoreTail) -> None:
        if tail != self.tail:
            raise FolderM4AuthorizationCheckpointError("checkpoint mismatch")

    def advance(
        self,
        previous: FolderM4AuthorizationStoreTail,
        current: FolderM4AuthorizationStoreTail,
    ) -> None:
        if (
            previous != self.tail
            or current.store_ref != previous.store_ref
            or current.sequence != previous.sequence + 1
        ):
            raise FolderM4AuthorizationCheckpointError(
                "checkpoint compare-and-swap failed"
            )
        self.tail = current


def _authorization_issue(
    root: Path,
) -> tuple[
    PersistentFolderM4AuthorizationStore,
    ProtectedChildFolderBinding,
    Path,
    Path,
    Path,
    MonotonicFolderM4AuthorizationCheckpoint,
]:
    checkpoint_store_ref = AUTHORIZATION_CHECKPOINT_STORE_REF
    checkpoint = _ExternalAuthorizationCheckpoint(checkpoint_store_ref)
    store, binding, database, store_key, promotion_key = _issue(
        root,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=checkpoint_store_ref,
    )
    return store, binding, database, store_key, promotion_key, checkpoint


def _execution_store(
    root: Path,
    *,
    monotonic_checkpoint: MonotonicM4ExecutionCheckpoint | None = None,
    checkpoint_store_ref: str | None = None,
    key_value: bytes = b"folder-runtime-execution-key-000000000001",
) -> tuple[PersistentM4ExecutionStateStore, Path, Path]:
    state = root / "execution-m4"
    state.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(state, 0o700)
    database = state / "execution.sqlite3"
    key = state / "execution.hmac"
    if not key.exists():
        key.write_bytes(key_value)
        os.chmod(key, 0o600)
    return (
        PersistentM4ExecutionStateStore(
            database,
            key,
            monotonic_checkpoint=monotonic_checkpoint,
            checkpoint_store_ref=checkpoint_store_ref,
        ),
        database,
        key,
    )


def _protected_execution_store(
    root: Path,
) -> tuple[
    PersistentM4ExecutionStateStore,
    Path,
    Path,
    MonotonicM4ExecutionCheckpoint,
]:
    checkpoint_store_ref = EXECUTION_CHECKPOINT_STORE_REF
    checkpoint = _ExternalM4Checkpoint(checkpoint_store_ref)
    store, database, key = _execution_store(
        root,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=checkpoint_store_ref,
    )
    return store, database, key, checkpoint


def _runtime(
    authorization_store: PersistentFolderM4AuthorizationStore,
    execution_store: PersistentM4ExecutionStateStore,
    transport: _Transport,
    requester_digest: str,
) -> ProtectedChildFolderM4Runtime:
    return ProtectedChildFolderM4Runtime(
        authorization_store,
        execution_store,
        transport,
        authenticated_requester_digest=requester_digest,
        clock=lambda: ACTIVE + 1,
    )


def test_protected_binding_executes_once_and_terminal_replay_survives_restart(
    tmp_path: Path,
) -> None:
    (
        store,
        binding,
        authorization_db,
        store_key,
        promotion_key,
        authorization_checkpoint,
    ) = _authorization_issue(tmp_path)
    (
        execution,
        execution_db,
        execution_key,
        execution_checkpoint,
    ) = _protected_execution_store(tmp_path)
    transport = _Transport(binding.prepared_action().request)
    runtime = _runtime(store, execution, transport, binding.plan.requester_digest)

    assert runtime.authorization_checkpoint_protocol_bound is True
    assert runtime.execution_checkpoint_protocol_bound is True
    first = runtime.execute_bound(binding.authorization.authorization_ref)
    assert first.outcome is M4Outcome.SUCCEEDED
    assert first.verification is M4Verification.VERIFIED
    assert first.idempotent_replay is False
    assert transport.calls == ["read", "create", "read"]

    restarted_authorization = PersistentFolderM4AuthorizationStore(
        authorization_db,
        store_key,
        promotion_key,
        monotonic_checkpoint=authorization_checkpoint,
        checkpoint_store_ref=AUTHORIZATION_CHECKPOINT_STORE_REF,
        clock=lambda: ACTIVE + 2,
    )
    restarted_execution = PersistentM4ExecutionStateStore(
        execution_db,
        execution_key,
        monotonic_checkpoint=execution_checkpoint,
        checkpoint_store_ref=EXECUTION_CHECKPOINT_STORE_REF,
    )
    replay_transport = _Transport(binding.prepared_action().request)
    replay = _runtime(
        restarted_authorization,
        restarted_execution,
        replay_transport,
        binding.plan.requester_digest,
    ).execute_bound(binding.authorization.authorization_ref)

    assert replay.outcome is M4Outcome.SUCCEEDED
    assert replay.verification is M4Verification.VERIFIED
    assert replay.idempotent_replay is True
    assert replay_transport.calls == []
    assert len(restarted_execution.audit_events) == 1
    assert restarted_execution.audit_events[0].authorization == "verified"


def test_external_execution_checkpoint_survives_runtime_restart_and_rejects_rollback(
    tmp_path: Path,
) -> None:
    (
        store,
        binding,
        authorization_db,
        store_key,
        promotion_key,
        authorization_checkpoint,
    ) = _authorization_issue(tmp_path)
    checkpoint_store_ref = EXECUTION_CHECKPOINT_STORE_REF
    checkpoint = _ExternalM4Checkpoint(checkpoint_store_ref)
    execution, execution_db, execution_key = _execution_store(
        tmp_path,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=checkpoint_store_ref,
    )
    empty_execution_database = execution_db.read_bytes()
    transport = _Transport(binding.prepared_action().request)
    runtime = _runtime(store, execution, transport, binding.plan.requester_digest)

    assert runtime.execution_checkpoint_protocol_bound is True
    result = runtime.execute_bound(binding.authorization.authorization_ref)
    assert result.outcome is M4Outcome.SUCCEEDED
    assert result.verification is M4Verification.VERIFIED
    assert transport.calls == ["read", "create", "read"]
    assert checkpoint.tail.sequence == 2

    restarted_authorization = PersistentFolderM4AuthorizationStore(
        authorization_db,
        store_key,
        promotion_key,
        monotonic_checkpoint=authorization_checkpoint,
        checkpoint_store_ref=AUTHORIZATION_CHECKPOINT_STORE_REF,
        clock=lambda: ACTIVE + 2,
    )
    restarted_execution = PersistentM4ExecutionStateStore(
        execution_db,
        execution_key,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=checkpoint_store_ref,
    )
    replay_transport = _Transport(binding.prepared_action().request)
    replay_runtime = _runtime(
        restarted_authorization,
        restarted_execution,
        replay_transport,
        binding.plan.requester_digest,
    )
    replay = replay_runtime.execute_bound(binding.authorization.authorization_ref)

    assert replay.idempotent_replay is True
    assert replay_transport.calls == []
    assert checkpoint.tail.sequence == 2

    execution_db.write_bytes(empty_execution_database)
    with pytest.raises(PersistentM4ExecutionStoreError, match="verification failed"):
        _runtime(
            restarted_authorization,
            restarted_execution,
            _Transport(binding.prepared_action().request),
            binding.plan.requester_digest,
        )


def test_runtime_requires_both_external_checkpoint_protocols(tmp_path: Path) -> None:
    unbound_authorization, binding, *_authorization_state = _issue(
        tmp_path / "unbound-authorization"
    )
    protected_execution, *_execution_state = _protected_execution_store(
        tmp_path / "protected-execution"
    )
    transport = _Transport(binding.prepared_action().request)

    with pytest.raises(FolderM4AuthorizationError, match="rollback protection"):
        _runtime(
            unbound_authorization,
            protected_execution,
            transport,
            binding.plan.requester_digest,
        )

    protected_authorization, protected_binding, *_protected_state = (
        _authorization_issue(tmp_path / "protected-authorization")
    )
    unbound_execution, *_unbound_execution_state = _execution_store(
        tmp_path / "unbound-execution"
    )
    with pytest.raises(PersistentM4ExecutionStoreError, match="rollback protection"):
        _runtime(
            protected_authorization,
            unbound_execution,
            _Transport(protected_binding.prepared_action().request),
            protected_binding.plan.requester_digest,
        )


def test_runtime_rejects_cross_ledger_key_and_checkpoint_store_reuse(
    tmp_path: Path,
) -> None:
    authorization, binding, *_authorization_state = _authorization_issue(
        tmp_path / "shared-key"
    )
    execution_checkpoint = _ExternalM4Checkpoint(EXECUTION_CHECKPOINT_STORE_REF)
    shared_key_execution, *_execution_state = _execution_store(
        tmp_path / "shared-key-execution",
        monotonic_checkpoint=execution_checkpoint,
        checkpoint_store_ref=EXECUTION_CHECKPOINT_STORE_REF,
        key_value=AUTHORIZATION_STORE_KEY,
    )
    with pytest.raises(FolderM4AuthorizationError, match="not independent"):
        _runtime(
            authorization,
            shared_key_execution,
            _Transport(binding.prepared_action().request),
            binding.plan.requester_digest,
        )

    shared_store_ref = "m4-folder-runtime-shared-checkpoint-store"
    authorization_checkpoint = _ExternalAuthorizationCheckpoint(shared_store_ref)
    authorization, binding, *_authorization_state = _issue(
        tmp_path / "shared-checkpoint",
        monotonic_checkpoint=authorization_checkpoint,
        checkpoint_store_ref=shared_store_ref,
    )
    execution_checkpoint = _ExternalM4Checkpoint(shared_store_ref)
    execution, *_execution_state = _execution_store(
        tmp_path / "shared-checkpoint-execution",
        monotonic_checkpoint=execution_checkpoint,
        checkpoint_store_ref=shared_store_ref,
    )
    with pytest.raises(FolderM4AuthorizationError, match="not independent"):
        _runtime(
            authorization,
            execution,
            _Transport(binding.prepared_action().request),
            binding.plan.requester_digest,
        )


def test_runtime_readiness_rejects_live_authorization_database_rollback(
    tmp_path: Path,
) -> None:
    store, binding, authorization_db, *_authorization_state = _authorization_issue(
        tmp_path
    )
    execution, *_execution_state = _protected_execution_store(tmp_path)
    issued_database = authorization_db.read_bytes()
    transport = _Transport(binding.prepared_action().request)

    result = _runtime(
        store,
        execution,
        transport,
        binding.plan.requester_digest,
    ).execute_bound(binding.authorization.authorization_ref)
    assert result.outcome is M4Outcome.SUCCEEDED

    authorization_db.write_bytes(issued_database)
    with pytest.raises(FolderM4AuthorizationError, match="verification failed"):
        _runtime(
            store,
            execution,
            _Transport(binding.prepared_action().request),
            binding.plan.requester_digest,
        )


def test_unfinished_persistent_claim_never_consumes_authorization_or_dispatches(
    tmp_path: Path,
) -> None:
    store, binding, *_authorization_state = _authorization_issue(tmp_path)
    execution, *_execution_state = _protected_execution_store(tmp_path)
    context = canonical_digest(
        {
            "authorization_digest": binding.authorization.authorization_digest,
            "plan_digest": binding.plan.plan_digest,
            "revision": binding.plan.revision,
        }
    )
    claim = execution.claim(
        plan_ref=binding.plan.plan_ref,
        requester_digest=binding.plan.requester_digest,
        idempotency_digest=binding.plan.idempotency_digest,
        context_digest=context,
        authorization_digest=binding.authorization.authorization_digest,
    )
    assert claim.state is M4ClaimState.NEW
    transport = _Transport(binding.prepared_action().request)

    result = _runtime(
        store,
        execution,
        transport,
        binding.plan.requester_digest,
    ).execute_bound(binding.authorization.authorization_ref)

    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert result.verification is M4Verification.UNKNOWN
    assert result.idempotent_replay is True
    assert transport.calls == []
    # Recovery did not touch the independently protected one-time authority.
    ProtectedFolderM4AuthorizationVerifier(
        store,
        binding.plan.requester_digest,
    ).verify(binding.plan, binding.authorization, now_epoch=ACTIVE + 2)


def test_crash_after_authorization_consumption_recovers_without_redispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        store,
        binding,
        authorization_db,
        store_key,
        promotion_key,
        authorization_checkpoint,
    ) = _authorization_issue(tmp_path)
    (
        execution,
        execution_db,
        execution_key,
        execution_checkpoint,
    ) = _protected_execution_store(tmp_path)
    original_consume = store.consume

    def consume_then_crash(*args: object, **kwargs: object) -> None:
        original_consume(*args, **kwargs)  # type: ignore[arg-type]
        raise RuntimeError("simulated process interruption")

    monkeypatch.setattr(store, "consume", consume_then_crash)
    first_transport = _Transport(binding.prepared_action().request)
    with pytest.raises(RuntimeError, match="interruption"):
        _runtime(
            store,
            execution,
            first_transport,
            binding.plan.requester_digest,
        ).execute_bound(binding.authorization.authorization_ref)
    assert first_transport.calls == []

    restarted_authorization = PersistentFolderM4AuthorizationStore(
        authorization_db,
        store_key,
        promotion_key,
        monotonic_checkpoint=authorization_checkpoint,
        checkpoint_store_ref=AUTHORIZATION_CHECKPOINT_STORE_REF,
        clock=lambda: ACTIVE + 2,
    )
    restarted_execution = PersistentM4ExecutionStateStore(
        execution_db,
        execution_key,
        monotonic_checkpoint=execution_checkpoint,
        checkpoint_store_ref=EXECUTION_CHECKPOINT_STORE_REF,
    )
    recovery_transport = _Transport(binding.prepared_action().request)
    recovery = _runtime(
        restarted_authorization,
        restarted_execution,
        recovery_transport,
        binding.plan.requester_digest,
    ).execute_bound(binding.authorization.authorization_ref)

    assert recovery.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert recovery.verification is M4Verification.UNKNOWN
    assert recovery.idempotent_replay is True
    assert recovery_transport.calls == []


def test_only_protected_binding_ref_and_authenticated_requester_reach_kernel(
    tmp_path: Path,
) -> None:
    store, binding, *_authorization_state = _authorization_issue(tmp_path)
    execution, *_execution_state = _protected_execution_store(tmp_path)
    transport = _Transport(binding.prepared_action().request)

    with pytest.raises(FolderM4AuthorizationError, match="unavailable"):
        _runtime(store, execution, transport, binding.plan.requester_digest).execute_bound(
            "missing-authorization-ref-0001"
        )
    with pytest.raises(FolderM4AuthorizationError, match="authenticated requester"):
        _runtime(store, execution, transport, "f" * 64).execute_bound(
            binding.authorization.authorization_ref
        )
    assert transport.calls == []


@pytest.mark.parametrize(
    ("phase", "expected_outcome", "expected_verification", "expected_audit", "calls"),
    [
        (
            "current",
            M4Outcome.EXECUTION_FAILED,
            M4Verification.NOT_STARTED,
            "current_read_failed",
            ["read"],
        ),
        (
            "dispatch",
            M4Outcome.RECONCILIATION_REQUIRED,
            M4Verification.UNKNOWN,
            "dispatch_unknown",
            ["read", "create"],
        ),
        (
            "post",
            M4Outcome.RECONCILIATION_REQUIRED,
            M4Verification.UNKNOWN,
            "post_read_unknown",
            ["read", "create", "read"],
        ),
    ],
)
def test_transport_failures_have_closed_persistent_outcomes(
    tmp_path: Path,
    phase: str,
    expected_outcome: M4Outcome,
    expected_verification: M4Verification,
    expected_audit: str,
    calls: list[str],
) -> None:
    store, binding, *_authorization_state = _authorization_issue(tmp_path)
    execution, *_execution_state = _protected_execution_store(tmp_path)
    transport = _Transport(binding.prepared_action().request, fail_phase=phase)

    result = _runtime(
        store,
        execution,
        transport,
        binding.plan.requester_digest,
    ).execute_bound(binding.authorization.authorization_ref)

    assert result.outcome is expected_outcome
    assert result.verification is expected_verification
    assert transport.calls == calls
    assert execution.audit_events[-1].authorization == expected_audit


def test_runtime_assembly_has_no_registration_transport_or_credential_surface() -> None:
    assert tuple(
        inspect.signature(ProtectedChildFolderM4Runtime.execute_bound).parameters
    ) == ("self", "authorization_ref")
    source = (
        Path(__file__).parents[1]
        / "src"
        / "fortipam_mcp"
        / "folder_m4_runtime.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "import httpx",
        "import requests",
        "import socket",
        "from mcp",
        "@mcp.tool",
        "Bearer ",
        "/api/v2/",
        "os.environ",
    ):
        assert forbidden not in source
