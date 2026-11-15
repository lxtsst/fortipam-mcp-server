"""Real M4 authority and durable ledgers joined to a synthetic owned Instruction Profile."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

from fortipam_mcp.instruction_profile_live_workflow import InstructionProfileLiveWorkflow, InstructionProfileLiveWorkflowError
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from v4_planning import M4AuthorizationDenied

from test_instruction_profile_http_transport import Fixture, fixture as fixture, run

REQUESTER, TRANSPORT = "1" * 64, "2" * 64
IDENTITY = {"requester_digest": REQUESTER, "transport_digest": TRANSPORT}


@pytest.fixture
def owned(fixture: Fixture) -> Fixture:
    return fixture


def make(tmp_path: Path, context: Fixture, phase: str = "create", **overrides: Any) -> InstructionProfileLiveWorkflow:
    state, peer, now = context
    directory = tmp_path / ("m4-" + phase)
    directory.mkdir(mode=0o700, exist_ok=True)
    key = directory / "key"
    if not key.exists():
        key.write_bytes(hashlib.sha256(("synthetic-store-" + phase).encode()).digest())
        key.chmod(0o600)
    kwargs: dict[str, Any] = {"serial_digest": peer.serial_digest, "schema_digest": peer.schema_digest,
        "state_directory": state, "phase": phase,
        "execution_store": PersistentM4ExecutionStateStore(directory / "ledger.sqlite", key),
        "authority_key": hashlib.sha256(("synthetic-authority-" + phase).encode()).digest(),
        "environment_ref": "synthetic-environment", "scope_ref": "synthetic-lab-scope", "audience_ref": "synthetic-audience",
        "allowed_requester_digest": REQUESTER, "allowed_transport_digest": TRANSPORT,
        "execution_enabled": True, "clock": lambda: now[0], "connection_factory": peer.connection}
    kwargs.update(overrides)
    if kwargs["execution_enabled"] is None:
        del kwargs["execution_enabled"]
    return InstructionProfileLiveWorkflow(peer.binding,
        SecretMetadataHttpTransportConfig("https://pam.example", "synthetic-token", 5, None), **kwargs)


def authorize(workflow: InstructionProfileLiveWorkflow) -> str:
    preview = workflow.preview(**IDENTITY)
    return cast(str, workflow.authorize(cast(str, preview["preview_ref"]), **IDENTITY)["authorization_ref"])


def test_actual_m4_roundtrip_preserves_creation_and_returns_only_categories(tmp_path: Path, owned: Fixture) -> None:
    state, peer, _ = owned
    original = {path.name: path.read_bytes() for path in state.iterdir()}
    public: list[dict[str, object]] = []
    for phase in ("create", "delete"):
        workflow = make(tmp_path, owned, phase)
        preview = workflow.preview(**IDENTITY)
        assert preview["Proposed Changes"] == {"operation": phase + "_plain_text_instruction_profile",
            "content_privately_bound": True, "resource_upload": False, "secret_attachment": False, "feature_change": False}
        issued = workflow.authorize(cast(str, preview["preview_ref"]), **IDENTITY)
        result = workflow.execute(cast(str, issued["authorization_ref"]), **IDENTITY)
        assert result["outcome"] == "succeeded" and result["verification"] == "verified"
        assert result["compensation"] == "not_requested" and result["idempotent_replay"] is False
        authorization = workflow._authority._issued
        assert authorization is not None
        claim = json.loads((state / (phase + ".claim.json")).read_text())
        assert claim["plan_digest"] == authorization.plan.plan_digest
        assert claim["authorization_digest"] == authorization.authorization.authorization_digest
        assert workflow._execution_store.claim_count == 1
        count = len(peer.calls)
        assert workflow.execute(cast(str, issued["authorization_ref"]), **IDENTITY) == {**result, "idempotent_replay": True}
        assert len(peer.calls) == count
        public.extend((preview, issued, result))
    assert peer.created is None
    assert peer.writes == ["POST", "DELETE"]
    assert all((state / name).read_bytes() == value for name, value in original.items())
    serialized = json.dumps(public)
    for value in (peer.binding._name, peer.brief, peer.text, REQUESTER, TRANSPORT, "synthetic-token"):
        assert value not in serialized



def test_close_disables_immutable_transport_and_preserves_creation_custody(
        tmp_path: Path, owned: Fixture) -> None:
    state, peer, _ = owned
    workflow = make(tmp_path, owned)
    result = workflow.execute(authorize(workflow), **IDENTITY)
    assert result["outcome"] == "succeeded"
    original = {path.name: path.read_bytes() for path in state.iterdir()}
    calls = len(peer.calls)

    workflow.close()
    workflow.close()

    assert workflow._enabled is False and workflow._transport._enabled is False
    workflow.check_original_creation(**IDENTITY)
    with pytest.raises(InstructionProfileLiveWorkflowError):
        workflow.preview(**IDENTITY)
    assert len(peer.calls) == calls and peer.writes == ["POST"]
    assert all((state / name).read_bytes() == value for name, value in original.items())


@pytest.mark.parametrize("stage", ["preview", "authorize", "execute"])
@pytest.mark.parametrize("field", ["requester_digest", "transport_digest"])
def test_identity_mismatch_precedes_device_or_ledger_effects(tmp_path: Path, owned: Fixture, stage: str, field: str) -> None:
    workflow = make(tmp_path, owned)
    preview = workflow.preview(**IDENTITY)
    auth = workflow.authorize(cast(str, preview["preview_ref"]), **IDENTITY)
    args = () if stage == "preview" else (preview["preview_ref"] if stage == "authorize" else auth["authorization_ref"],)
    count = len(owned[1].calls)
    with pytest.raises(InstructionProfileLiveWorkflowError):
        getattr(workflow, stage)(*args, **{**IDENTITY, field: "9" * 64})
    assert len(owned[1].calls) == count and workflow._execution_store.claim_count == 0


@pytest.mark.parametrize("phase", ["create", "delete"])
def test_signed_preview_cannot_cross_phase_or_authority(tmp_path: Path, owned: Fixture, phase: str) -> None:
    workflow = make(tmp_path, owned)
    preview = workflow.preview(**IDENTITY)
    other = make(tmp_path, owned, phase, authority_key=workflow._authority._key if phase == "delete" else b"x" * 32)
    other._preview = workflow._preview
    count = len(owned[1].calls)
    with pytest.raises(InstructionProfileLiveWorkflowError):
        other.authorize(cast(str, preview["preview_ref"]), **IDENTITY)
    assert len(owned[1].calls) == count


def test_tampered_plan_does_not_consume_execution(tmp_path: Path, owned: Fixture) -> None:
    workflow = make(tmp_path, owned)
    ref = authorize(workflow)
    issued = workflow._authority._issued
    assert issued is not None
    object.__setattr__(issued.plan, "expected_state_digest", "f" * 64)
    with pytest.raises(M4AuthorizationDenied):
        workflow._authority.verify(issued.plan, issued.authorization, now_epoch=100)
    with pytest.raises(InstructionProfileLiveWorkflowError):
        workflow.execute(ref, **IDENTITY)
    assert workflow._execution_store.claim_count == 0 and owned[1].writes == []


@pytest.mark.parametrize("enabled", [None, False])
def test_default_closed_gate_cannot_authorize(tmp_path: Path, owned: Fixture, enabled: bool | None) -> None:
    workflow = make(tmp_path, owned, execution_enabled=enabled)
    preview = workflow.preview(**IDENTITY)
    with pytest.raises(InstructionProfileLiveWorkflowError):
        workflow.authorize(cast(str, preview["preview_ref"]), **IDENTITY)
    assert workflow._execution_store.claim_count == 0 and owned[1].writes == []


@pytest.mark.parametrize("lost_ack", [False, True])
def test_consumed_m4_cannot_be_reauthorized_after_restart(tmp_path: Path, owned: Fixture, lost_ack: bool) -> None:
    workflow = make(tmp_path, owned)
    ref = authorize(workflow)
    peer = owned[1]
    peer.lose_ack_at = 1 if lost_ack else 0
    result = workflow.execute(ref, **IDENTITY)
    assert result["outcome"] == ("reconciliation_required" if lost_ack else "succeeded")
    assert workflow.execute(ref, **IDENTITY)["idempotent_replay"] is True
    restarted = make(tmp_path, owned)
    count = len(peer.calls)
    with pytest.raises(InstructionProfileLiveWorkflowError): restarted.preview(**IDENTITY)
    with pytest.raises(InstructionProfileLiveWorkflowError): restarted.execute(ref, **IDENTITY)
    assert len(peer.calls) == count and peer.writes == ["POST"]


@pytest.mark.parametrize("where", ["authorize", "execute"])
def test_full_state_drift_prevents_http_claim(tmp_path: Path, owned: Fixture, where: str) -> None:
    workflow = make(tmp_path, owned)
    preview = workflow.preview(**IDENTITY)
    ref = cast(str, preview["preview_ref"])
    if where == "execute": ref = cast(str, workflow.authorize(ref, **IDENTITY)["authorization_ref"])
    owned[1].defaults["brief"] = "changed"
    if where == "authorize":
        with pytest.raises(InstructionProfileLiveWorkflowError): workflow.authorize(ref, **IDENTITY)
    else:
        assert workflow.execute(ref, **IDENTITY)["outcome"] == "reconciliation_required"
    assert not (owned[0] / "create.claim.json").exists() and owned[1].writes == []


def test_expiry_and_clock_rollback_are_terminal(tmp_path: Path, owned: Fixture) -> None:
    workflow = make(tmp_path, owned)
    ref = authorize(workflow)
    count = len(owned[1].calls)
    for now in (160, 99, 161):
        owned[2][0] = now
        with pytest.raises(InstructionProfileLiveWorkflowError): workflow.execute(ref, **IDENTITY)
    assert len(owned[1].calls) == count and owned[1].writes == []
