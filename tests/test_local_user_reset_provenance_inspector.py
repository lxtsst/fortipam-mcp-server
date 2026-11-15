"""Protected independent provenance seal and drift checks, without a device."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat

import pytest

from fortipam_mcp.local_user_reset_creation_audit_projection import LocalUserResetCreationAuditObservation
from fortipam_mcp.local_user_reset_metadata_reader import LocalUserResetMetadataObservation
from fortipam_mcp.local_user_reset_projection import LocalUserResetUserProjection
from fortipam_mcp.local_user_reset_provenance_inspector import (
    FortiPamLocalUserResetProvenanceInspector, LocalUserResetProvenanceError,
)
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from v4_planning import M4AuditEvent, M4Compensation, M4ExecutionResult, M4Outcome, M4Verification

CREATED = 1_790_000_000
NAME = f"mcp-v4-user-reset-{CREATED}-abcdef"
PLAN = "bp002-fixture-create-test-plan"
REQUESTER = "1" * 64
IDEMPOTENCY = "2" * 64
CONTEXT = "3" * 64
AUTHORIZATION = "4" * 64
AUDIT = "5" * 64


def _write(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(0o600)


def _setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *,
           issue_enabled: bool = True) -> FortiPamLocalUserResetProvenanceInspector:
    directory = tmp_path / "retained"
    directory.mkdir(mode=0o700)
    binding = directory / "binding.json"
    _write(binding, json.dumps({"username": NAME,
                                "purpose": "new_disabled_reset_fixture"}).encode())
    os.utime(binding, (CREATED, CREATED))
    material = directory / "initial-password"
    _write(material, b"Aa7!syntheticinitialpasswordvalue")
    os.utime(material, (CREATED + 1, CREATED + 1))
    key = directory / "execution.key"
    _write(key, b"0123456789abcdef0123456789abcdef")
    store = PersistentM4ExecutionStateStore(directory / "execution.sqlite3", key)
    store.claim(plan_ref=PLAN, requester_digest=REQUESTER,
                idempotency_digest=IDEMPOTENCY, context_digest=CONTEXT,
                authorization_digest=AUTHORIZATION)
    store.finalize(plan_ref=PLAN, requester_digest=REQUESTER,
        idempotency_digest=IDEMPOTENCY, context_digest=CONTEXT,
        result=M4ExecutionResult(M4Outcome.RECONCILIATION_REQUIRED,
            M4Verification.UNKNOWN, M4Compensation.UNKNOWN, False),
        event=M4AuditEvent(0, "intent_bound", M4Outcome.RECONCILIATION_REQUIRED,
            M4Verification.UNKNOWN, M4Compensation.UNKNOWN, AUDIT))
    config = SecretMetadataHttpTransportConfig(
        base_url="https://synthetic.example", bearer_token="synthetic-token",
        timeout_seconds=3, ca_file=None,
    )
    inspector = FortiPamLocalUserResetProvenanceInspector(
        config, fixture_directory=directory, api_principal="synthetic-api",
        issue_enabled=issue_enabled,
    )
    event = LocalUserResetCreationAuditObservation("a" * 64, CREATED * 1000,
                                                   (CREATED + 600) * 1000)
    monkeypatch.setattr(inspector._reader, "read_creation_event", lambda: event)
    monkeypatch.setattr(inspector, "_created_detail_digest", lambda: "b" * 64)
    user = LocalUserResetUserProjection(
        username=NAME, status="disable", is_local=True, access_profile="Guest",
        sponsor_group="", schedule="", guest_auth="disable",
        nonmaterial_state_digest="c" * 64, reported_reference_count=0,
    )
    monkeypatch.setattr(inspector, "_current_user", lambda: LocalUserResetMetadataObservation(user, 0))
    monkeypatch.setattr(inspector, "_actor_is_current", lambda: None)
    return inspector


def test_issue_seals_independent_evidence_and_reads_stable_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspector = _setup(tmp_path, monkeypatch)
    first = inspector.issue()
    receipt = tmp_path / "retained" / "creation-provenance.json"
    assert stat.S_IMODE(receipt.stat().st_mode) == 0o600
    assert len(first.fixture_creation_digest) == 64
    assert first.nonmaterial_state_digest == "c" * 64
    assert inspector.read_nonmaterial_baseline() == first

    # A new process can verify the durable receipt without reissuing it.
    restarted = FortiPamLocalUserResetProvenanceInspector(
        inspector._config, fixture_directory=tmp_path / "retained",
        api_principal="synthetic-api", issue_enabled=False,
    )
    monkeypatch.setattr(restarted, "_current_user", inspector._current_user)
    monkeypatch.setattr(restarted, "_actor_is_current", lambda: None)
    assert restarted.read_nonmaterial_baseline() == first
    with pytest.raises(LocalUserResetProvenanceError):
        inspector.issue()
    assert inspector.read_nonmaterial_baseline() == first


def test_gate_tamper_material_and_user_drift_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspector = _setup(tmp_path, monkeypatch, issue_enabled=False)
    with pytest.raises(LocalUserResetProvenanceError):
        inspector.issue()
    assert not (tmp_path / "retained" / "creation-provenance.json").exists()
    inspector._issue_enabled = True
    inspector.issue()
    receipt = tmp_path / "retained" / "creation-provenance.json"
    document = json.loads(receipt.read_text())
    document["body"]["full_user_digest"] = "d" * 64
    _write(receipt, json.dumps(document).encode())
    with pytest.raises(LocalUserResetProvenanceError):
        inspector.read_nonmaterial_baseline()

def test_initial_material_drift_rejects_post_claim_material_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspector = _setup(tmp_path, monkeypatch)
    baseline = inspector.issue()
    material = tmp_path / "retained" / "initial-password"
    original = bytearray(material.read_bytes())
    with memoryview(original) as view:
        assert inspector.verify_initial_material_view(
            view, expected_fixture_digest=baseline.fixture_creation_digest,
        ) is True
    material.write_bytes(b"Aa7!modifiedinitialpasswordvalue")
    os.utime(material, (CREATED + 1, CREATED + 1))
    assert inspector.read_nonmaterial_baseline() == baseline
    changed = bytearray(material.read_bytes())
    with memoryview(changed) as view:
        with pytest.raises(LocalUserResetProvenanceError):
            inspector.verify_initial_material_view(
                view, expected_fixture_digest=baseline.fixture_creation_digest,
            )
    original[:] = b"\x00" * len(original)
    changed[:] = b"\x00" * len(changed)


def test_material_verification_does_not_repeat_network_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspector = _setup(tmp_path, monkeypatch)
    baseline = inspector.issue()
    monkeypatch.setattr(inspector, "_current_user", lambda: pytest.fail("No network read after C3 acquisition"))
    material = bytearray((tmp_path / "retained" / "initial-password").read_bytes())
    with memoryview(material) as view:
        assert inspector.verify_initial_material_view(
            view, expected_fixture_digest=baseline.fixture_creation_digest,
        ) is True
    material[:] = b"\x00" * len(material)


def test_full_user_drift_rejects_sealed_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspector = _setup(tmp_path, monkeypatch)
    inspector.issue()
    changed = LocalUserResetUserProjection(
        username=NAME, status="disable", is_local=True, access_profile="Guest",
        sponsor_group="", schedule="", guest_auth="disable",
        nonmaterial_state_digest="d" * 64, reported_reference_count=0,
    )
    monkeypatch.setattr(inspector, "_current_user", lambda: LocalUserResetMetadataObservation(changed, 0))
    with pytest.raises(LocalUserResetProvenanceError):
        inspector.read_nonmaterial_baseline()


def test_issue_rejects_user_drift_before_any_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspector = _setup(tmp_path, monkeypatch)
    changed = LocalUserResetUserProjection(
        username=NAME, status="enable", is_local=True, access_profile="Guest",
        sponsor_group="unexpected", schedule="", guest_auth="disable",
        nonmaterial_state_digest="d" * 64, reported_reference_count=0,
    )
    monkeypatch.setattr(inspector, "_current_user", lambda: LocalUserResetMetadataObservation(changed, 0))
    with pytest.raises(LocalUserResetProvenanceError):
        inspector.issue()
    assert not (tmp_path / "retained" / "creation-provenance.json").exists()
