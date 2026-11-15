"""Actual signed M4/persistent-store joins to the synthetic native LDAP peer."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

from fortipam_mcp.ldap_server_update_live_workflow import (
    LdapServerUpdateLiveWorkflow, LdapServerUpdateLiveWorkflowError,
)
from fortipam_mcp.ldap_server_update_http_transport import FortiPamLdapServerUpdateHttpTransport
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from v4_planning import M4AuthorizationDenied

from test_ldap_server_update_http_transport import UpdatePeer, fixture as fixture

REQUESTER, TRANSPORT = "1" * 64, "2" * 64
IDENTITY = {"requester_digest": REQUESTER, "transport_digest": TRANSPORT}
Fixture = tuple[Path, Path, UpdatePeer, list[int]]


def make(tmp_path: Path, context: Fixture, phase: str = "update", **overrides: Any) -> LdapServerUpdateLiveWorkflow:
    creation, state, peer, now = context
    directory = tmp_path / ("m4-" + phase)
    directory.mkdir(mode=0o700, exist_ok=True)
    key = directory / "key"
    if not key.exists():
        key.write_bytes(hashlib.sha256(("synthetic-store-" + phase).encode()).digest())
        key.chmod(0o600)
    kwargs: dict[str, Any] = {
        "expected_serial": "SYNTHETIC_DEVICE", "creation_state_directory": creation,
        "state_directory": state, "phase": phase,
        "execution_store": PersistentM4ExecutionStateStore(directory / "ledger.sqlite", key),
        "authority_key": hashlib.sha256(("synthetic-authority-" + phase).encode()).digest(),
        "environment_ref": "synthetic-lab-environment", "scope_ref": "synthetic-lab-scope",
        "audience_ref": "synthetic-lab-audience", "allowed_requester_digest": REQUESTER,
        "allowed_transport_digest": TRANSPORT, "execution_enabled": True,
        "clock": lambda: now[0], "connection_factory": peer.connection,
    }
    kwargs.update(overrides)
    if kwargs["execution_enabled"] is None:
        del kwargs["execution_enabled"]
    return LdapServerUpdateLiveWorkflow(peer.binding,
        SecretMetadataHttpTransportConfig("https://pam.example", "synthetic-token", 5, None), **kwargs)


def authorize(workflow: LdapServerUpdateLiveWorkflow) -> str:
    preview = workflow.preview(**IDENTITY)
    return cast(str, workflow.authorize(cast(str, preview["preview_ref"]), **IDENTITY)["authorization_ref"])


def test_real_m4_update_and_independent_restore_preserve_creation_and_secrets(tmp_path: Path, fixture: Fixture) -> None:
    creation, state, peer, _ = fixture
    original = {path.name: path.read_bytes() for path in creation.iterdir()}
    public: list[dict[str, object]] = []
    for phase in ("update", "restore"):
        count = len(peer.connections)
        workflow = make(tmp_path, fixture, phase)
        assert workflow.phase == phase and len(peer.connections) == count
        preview = workflow.preview(**IDENTITY)
        authorization = workflow.authorize(cast(str, preview["preview_ref"]), **IDENTITY)
        result = workflow.execute(cast(str, authorization["authorization_ref"]), **IDENTITY)
        assert result["outcome"] == "succeeded" and result["verification"] == "verified"
        assert result["compensation"] == "not_requested" and result["idempotent_replay"] is False
        issued = workflow._authority._issued
        assert issued is not None
        claim = json.loads((state / (phase + ".claim.json")).read_text())
        assert claim["plan_digest"] == issued.plan.plan_digest
        assert claim["authorization_digest"] == issued.authorization.authorization_digest
        assert workflow._execution_store.claim_count == 1
        count = len(peer.connections)
        assert workflow.execute(cast(str, authorization["authorization_ref"]), **IDENTITY) == {
            **result, "idempotent_replay": True}
        assert len(peer.connections) == count
        public.extend((preview, authorization, result))
    assert peer.puts == 2 and peer.info_tests == 3
    assert peer.row is not None and peer.row["group-filter"] == ""
    assert original == {path.name: path.read_bytes() for path in creation.iterdir()}
    assert all(not body for body in peer.bodies)
    rendered = json.dumps(public)
    for value in (peer.binding.name, peer.binding.server, peer.binding.dn, peer.binding.username,
                  peer.binding.ca_name, peer.binding.private_nonce, "synthetic-token", REQUESTER, TRANSPORT):
        assert value not in rendered


@pytest.mark.parametrize("stage", ["preview", "authorize", "execute"])
@pytest.mark.parametrize("field", ["requester_digest", "transport_digest"])
def test_actor_mismatch_precedes_effects(tmp_path: Path, fixture: Fixture, stage: str, field: str) -> None:
    workflow = make(tmp_path, fixture)
    preview = workflow.preview(**IDENTITY)
    auth = workflow.authorize(cast(str, preview["preview_ref"]), **IDENTITY)
    args = () if stage == "preview" else (preview["preview_ref"] if stage == "authorize" else auth["authorization_ref"],)
    peer = fixture[2]
    count = len(peer.connections)
    with pytest.raises(LdapServerUpdateLiveWorkflowError):
        getattr(workflow, stage)(*args, **{**IDENTITY, field: "9" * 64})
    assert len(peer.connections) == count and peer.puts == peer.info_tests == 0


@pytest.mark.parametrize("phase", ["update", "restore"])
def test_signed_preview_cannot_cross_phase_or_authority(tmp_path: Path, fixture: Fixture, phase: str) -> None:
    original = make(tmp_path, fixture)
    preview = original.preview(**IDENTITY)
    other = make(tmp_path, fixture, phase,
                 authority_key=original._authority._key if phase == "restore" else b"x" * 32)
    other._preview = original._preview
    count = len(fixture[2].connections)
    with pytest.raises(LdapServerUpdateLiveWorkflowError):
        other.authorize(cast(str, preview["preview_ref"]), **IDENTITY)
    assert len(fixture[2].connections) == count


def test_tampered_expected_state_cannot_execute(tmp_path: Path, fixture: Fixture) -> None:
    workflow = make(tmp_path, fixture)
    ref = authorize(workflow)
    issued = workflow._authority._issued
    assert issued is not None
    object.__setattr__(issued.plan, "expected_state_digest", "f" * 64)
    with pytest.raises(M4AuthorizationDenied):
        workflow._authority.verify(issued.plan, issued.authorization, now_epoch=100)
    with pytest.raises(LdapServerUpdateLiveWorkflowError):
        workflow.execute(ref, **IDENTITY)
    assert workflow._execution_store.claim_count == fixture[2].puts == 0


@pytest.mark.parametrize("enabled", [None, False])
def test_default_closed_gate_does_not_authorize(tmp_path: Path, fixture: Fixture, enabled: bool | None) -> None:
    workflow = make(tmp_path, fixture, execution_enabled=enabled)
    preview = workflow.preview(**IDENTITY)
    with pytest.raises(LdapServerUpdateLiveWorkflowError):
        workflow.authorize(cast(str, preview["preview_ref"]), **IDENTITY)
    assert fixture[2].puts == fixture[2].info_tests == workflow._execution_store.claim_count == 0


@pytest.mark.parametrize("lost_ack", [False, True])
def test_consumed_m4_restart_cannot_issue_or_redispatch(tmp_path: Path, fixture: Fixture, lost_ack: bool) -> None:
    workflow = make(tmp_path, fixture)
    ref = authorize(workflow)
    peer = fixture[2]
    peer.lose_ack_at = 1 if lost_ack else None
    result = workflow.execute(ref, **IDENTITY)
    assert result["outcome"] == ("reconciliation_required" if lost_ack else "succeeded")
    assert workflow.execute(ref, **IDENTITY)["idempotent_replay"] is True
    restarted = make(tmp_path, fixture)
    count = len(peer.connections)
    with pytest.raises(LdapServerUpdateLiveWorkflowError):
        restarted.preview(**IDENTITY)
    with pytest.raises(LdapServerUpdateLiveWorkflowError):
        restarted.execute(ref, **IDENTITY)
    assert len(peer.connections) == count and peer.puts == 1


@pytest.mark.parametrize("where", ["authorize", "execute"])
def test_full_current_drift_prevents_put(tmp_path: Path, fixture: Fixture, where: str) -> None:
    workflow = make(tmp_path, fixture)
    preview = workflow.preview(**IDENTITY)
    ref = cast(str, preview["preview_ref"])
    if where == "execute":
        ref = cast(str, workflow.authorize(ref, **IDENTITY)["authorization_ref"])
    peer = fixture[2]
    assert peer.row is not None
    peer.row["password"] = "changed-synthetic-token"
    if where == "authorize":
        with pytest.raises(LdapServerUpdateLiveWorkflowError):
            workflow.authorize(ref, **IDENTITY)
    else:
        # A complete-state projection refusal is ambiguous to the M4 kernel;
        # it must retain that result without acquiring an HTTP dispatch claim.
        assert workflow.execute(ref, **IDENTITY)["outcome"] == "reconciliation_required"
        assert not (fixture[1] / "update.claim.json").exists()
    assert peer.puts == peer.info_tests == 0


def test_expiry_and_clock_rollback_refuse_before_device_work(tmp_path: Path, fixture: Fixture) -> None:
    workflow = make(tmp_path, fixture)
    ref = authorize(workflow)
    peer, now = fixture[2:]
    count = len(peer.connections)
    now[0] = 160
    with pytest.raises(LdapServerUpdateLiveWorkflowError):
        workflow.execute(ref, **IDENTITY)
    now[0] = 99
    with pytest.raises(LdapServerUpdateLiveWorkflowError):
        workflow.preview(**IDENTITY)
    now[0] = 161
    with pytest.raises(LdapServerUpdateLiveWorkflowError):
        workflow.preview(**IDENTITY)
    assert len(peer.connections) == count and peer.puts == 0


def test_cross_instance_object_lock_covers_m4_dispatch(tmp_path: Path, fixture: Fixture) -> None:
    workflow = make(tmp_path, fixture)
    ref = authorize(workflow)
    other = make(tmp_path, fixture)
    with other._transport.operation_lock(), pytest.raises(LdapServerUpdateLiveWorkflowError):
        workflow.execute(ref, **IDENTITY)
    assert workflow._started is False
    assert workflow._execution_store.claim_count == fixture[2].puts == 0
    assert workflow.execute(ref, **IDENTITY)["outcome"] == "succeeded"


@pytest.mark.parametrize("stage", ["preview", "authorize"])
def test_new_claim_between_initial_check_and_object_lock_blocks_reissue(
    tmp_path: Path, fixture: Fixture, monkeypatch: pytest.MonkeyPatch, stage: str,
) -> None:
    workflow = make(tmp_path, fixture)
    preview = workflow.preview(**IDENTITY)
    original_lock = FortiPamLdapServerUpdateHttpTransport.operation_lock

    @contextmanager
    def claimed_before_lock(transport: FortiPamLdapServerUpdateHttpTransport) -> Iterator[None]:
        workflow._execution_store.claim(plan_ref="synthetic-concurrent-plan", requester_digest=REQUESTER,
            idempotency_digest="a" * 64, context_digest="b" * 64, authorization_digest="c" * 64)
        with original_lock(transport):
            yield

    monkeypatch.setattr(FortiPamLdapServerUpdateHttpTransport, "operation_lock", claimed_before_lock)
    count = len(fixture[2].connections)
    with pytest.raises(LdapServerUpdateLiveWorkflowError):
        if stage == "preview":
            workflow.preview(**IDENTITY)
        else:
            workflow.authorize(cast(str, preview["preview_ref"]), **IDENTITY)
    assert len(fixture[2].connections) == count and fixture[2].puts == 0
