"""Independent historical cleanup with real M4 and synthetic device behavior."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp.instruction_profile_contract import InstructionProfileCreatePlan
from fortipam_mcp.instruction_profile_historical_cleanup import (
    InstructionProfileHistoricalCleanup, InstructionProfileHistoricalCleanupError, _FILES,
)
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_instruction_profile_http_transport import Fixture, fixture as fixture
from test_instruction_profile_live_workflow import IDENTITY, authorize, make


def setup(tmp_path: Path, fixture: Fixture, **overrides: Any) -> tuple[Any, dict[str, bytes], Any]:
    state, peer, now = fixture
    original = make(tmp_path, fixture)
    result = original.execute(authorize(original), **IDENTITY)
    assert result["outcome"] == "succeeded"
    original.close()
    anchors = {name: (state / name).read_bytes() for name in _FILES}
    directory = tmp_path / "independent-cleanup"
    directory.mkdir(mode=0o700)
    key = directory / "m4.key"
    key.write_bytes(b"fresh-cleanup-ledger-key-material-0001")
    key.chmod(0o600)
    binding = InstructionProfileCreatePlan(peer.binding._name, "b" * 64, peer.binding._content,
        peer.defaults, schema_digest=peer.schema_digest, serial_digest=peer.serial_digest)
    assert binding.digest != peer.binding.digest
    kwargs = dict(original_directory=state,
        original_hashes={name: hashlib.sha256(raw).hexdigest() for name, raw in anchors.items()},
        original_store=original._execution_store, state_directory=directory,
        execution_store=PersistentM4ExecutionStateStore(directory / "m4.sqlite3", key),
        authority_key=b"fresh-independent-authority-key-001", **IDENTITY, execution_enabled=True,
        clock=lambda: now[0], connection_factory=peer.connection)
    kwargs.update(overrides)
    cleanup = InstructionProfileHistoricalCleanup(binding,
        SecretMetadataHttpTransportConfig("https://pam.example", "synthetic-token", 5, None), **kwargs)
    return cleanup, anchors, original


def test_independent_cleanup_preserves_original_evidence_and_never_replays(
        tmp_path: Path, fixture: Fixture) -> None:
    cleanup, anchors, original = setup(tmp_path, fixture)
    state, peer, _ = fixture
    result = cleanup.execute_once(**IDENTITY)
    assert result == {"outcome": "succeeded", "verification": "verified",
        "compensation": "not_requested", "idempotent_replay": False}
    assert peer.writes == ["POST", "DELETE"] and peer.created is None
    assert all((state / name).read_bytes() == raw for name, raw in anchors.items())
    assert original._execution_store.claim_count == 1 and cleanup._store.claim_count == 1
    assert not cleanup._enabled and not cleanup._transport._enabled
    with pytest.raises(InstructionProfileHistoricalCleanupError):
        cleanup.execute_once(**IDENTITY)
    assert peer.writes == ["POST", "DELETE"]
    assert peer.binding._name not in json.dumps(result)


@pytest.mark.parametrize("fault", ["gate", "requester", "transport", "reference", "content", "original_bytes", "original_mode"])
def test_denial_before_new_claim_or_delete(tmp_path: Path, fixture: Fixture, fault: str) -> None:
    cleanup, _, _ = setup(tmp_path, fixture)
    state, peer, _ = fixture
    identity = dict(IDENTITY)
    assert peer.created is not None
    if fault == "gate": cleanup.close()
    elif fault in {"requester", "transport"}: identity[fault + "_digest"] = "9" * 64
    elif fault == "reference": peer.created["q_ref"] = 1
    elif fault == "content": peer.created["brief"] += " changed"
    elif fault == "original_bytes":
        path = state / "created.json"
        path.write_bytes(path.read_bytes() + b" ")
    elif fault == "original_mode": (state / "created.json").chmod(0o644)
    with pytest.raises(InstructionProfileHistoricalCleanupError):
        cleanup.execute_once(**identity)
    assert peer.writes == ["POST"] and cleanup._store.claim_count == 0
    assert not cleanup._enabled and not cleanup._transport._enabled


@pytest.mark.parametrize("fault", ["reference", "original", "expiry"])
def test_tls_time_drift_prevents_delete(tmp_path: Path, fixture: Fixture, fault: str) -> None:
    cleanup, _, _ = setup(tmp_path, fixture)
    state, peer, now = fixture
    def change() -> None:
        assert peer.created is not None
        if fault == "reference": peer.created["q_ref"] = 1
        elif fault == "original":
            path = state / "create-ack.json"
            path.write_bytes(path.read_bytes() + b" ")
        else: now[0] += 61
    peer.on_connect = change
    result = cleanup.execute_once(**IDENTITY)
    assert result["outcome"] != "succeeded" and peer.writes == ["POST"]
    assert cleanup._store.claim_count == 1 and not cleanup._enabled


@pytest.mark.parametrize("fault", ["lost_ack", "postread"])
def test_unknown_delete_result_cannot_repeat(tmp_path: Path, fixture: Fixture, fault: str) -> None:
    cleanup, _, _ = setup(tmp_path, fixture)
    _, peer, _ = fixture
    if fault == "lost_ack": peer.lose_ack_at = 2
    else: peer.fail_detail_after_write = True
    result = cleanup.execute_once(**IDENTITY)
    assert result["outcome"] != "succeeded" and peer.writes == ["POST", "DELETE"]
    with pytest.raises(InstructionProfileHistoricalCleanupError): cleanup.execute_once(**IDENTITY)
    assert peer.writes == ["POST", "DELETE"]


@pytest.mark.parametrize("fault", ["wrong_requester", "bad_chain", "missing_original"])
def test_historical_custody_cannot_be_adopted(tmp_path: Path, fixture: Fixture, fault: str) -> None:
    cleanup, _, original = setup(tmp_path, fixture)
    state, peer, _ = fixture
    if fault == "wrong_requester": cleanup._requester = "8" * 64
    elif fault == "bad_chain":
        with original._execution_store._connect() as connection:
            connection.execute("UPDATE execution_ledger SET chain_hmac = ? WHERE sequence = 1", ("0" * 64,))
    else: (state / "creation.plan.json").unlink()
    with pytest.raises(InstructionProfileHistoricalCleanupError): cleanup.execute_once(**IDENTITY)
    assert peer.writes == ["POST"] and cleanup._store.claim_count == 0


def test_unknown_cleanup_cannot_reopen_with_new_directory_or_normal_lifecycle(
        tmp_path: Path, fixture: Fixture) -> None:
    cleanup, anchors, original = setup(tmp_path, fixture)
    state, peer, now = fixture
    peer.reject_write = True
    peer.lose_ack_at = 2
    first = cleanup.execute_once(**IDENTITY)
    assert first["outcome"] == "reconciliation_required" and peer.created is not None
    assert (state / "historical-cleanup.consumed.json").is_file()
    peer.reject_write = False
    peer.lose_ack_at = 0
    directory = tmp_path / "another-cleanup"
    directory.mkdir(mode=0o700)
    key = directory / "m4.key"
    key.write_bytes(b"another-distinct-synthetic-ledger-key")
    key.chmod(0o600)
    second = InstructionProfileHistoricalCleanup(cleanup._binding, cleanup._config,
        original_directory=state,
        original_hashes={name: hashlib.sha256(raw).hexdigest() for name, raw in anchors.items()},
        original_store=original._execution_store, state_directory=directory,
        execution_store=PersistentM4ExecutionStateStore(directory / "m4.sqlite3", key),
        authority_key=b"another-independent-authority-key-01", **IDENTITY,
        execution_enabled=True, clock=lambda: now[0], connection_factory=peer.connection)
    with pytest.raises(InstructionProfileHistoricalCleanupError): second.execute_once(**IDENTITY)
    normal = make(tmp_path, fixture, "delete")
    with pytest.raises(RuntimeError): authorize(normal)
    assert peer.writes == ["POST", "DELETE"]
    assert second._store.claim_count == normal._execution_store.claim_count == 0
    assert all((state / name).read_bytes() == raw for name, raw in anchors.items())


def test_rich_native_record_enters_planning_as_digest_only(tmp_path: Path, fixture: Fixture) -> None:
    from fortipam_mcp.instruction_profile_contract import (
        InstructionRichText, InstructionDocument, InstructionNode, InstructionHttpsLink,
    )
    _, peer, _ = fixture
    content = InstructionRichText("Synthetic brief", InstructionDocument((
        InstructionNode("heading", level=2, children=(InstructionNode("text", text="Synthetic heading"),)),
        InstructionNode("paragraph", children=(InstructionNode("text", text="Long synthetic instructions. " * 20,
            link=InstructionHttpsLink("https://example.com/")),)),
    )))
    peer.binding = InstructionProfileCreatePlan(peer.binding._name, "a" * 64, content,
        peer.defaults, schema_digest=peer.schema_digest, serial_digest=peer.serial_digest)
    cleanup, anchors, _ = setup(tmp_path, fixture)
    assert len(cleanup._record["detail"]) > 256
    assert cleanup.execute_once(**IDENTITY)["outcome"] == "succeeded"
    assert peer.writes == ["POST", "DELETE"] and peer.created is None
    assert all((fixture[0] / name).read_bytes() == raw for name, raw in anchors.items())
