"""Synthetic C3/M4/HTTP joins; no remote fixture or production material access."""
from __future__ import annotations

import copy
from dataclasses import replace
import json
import os
from pathlib import Path
import pickle
from typing import Any

import pytest

from fortipam_mcp.radius_server_contract import RadiusServerCreateOutcome
from fortipam_mcp.radius_server_live_workflow import RadiusServerLiveWorkflow, RadiusServerLiveWorkflowError
from fortipam_mcp import radius_server_live_workflow as live_module
from fortipam_mcp.radius_server_material_provider import RadiusServerMaterialProvider, RadiusServerLeaseTransport
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from v4_planning import M4AuthorizationDenied
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import (
    MaterialAccessDenied, MaterialBindingStatus, MaterialContractError, MaterialLease, MaterialLeaseCompletion,
    MaterialProviderClass, MaterialRevocationReason,
)
from v4_planning.material_runtime import (
    MaterialLeaseCoordinator, MaterialRuntimeOutcome, MaterialUseOutcome,
)
from test_radius_server_contract import binding
from test_radius_server_http_transport import Peer as HttpPeer, Response, TABLE, request as http_request
from test_radius_server_projection import SERIAL, envelope

MATERIAL = b"synthetic-radius-material-012345"
IDENTITY = {"requester_digest": "1"*64, "transport_digest": "2"*64}
AUTHORITY_KEY = b"synthetic-radius-authority-key-01"


def request() -> Any:
    return replace(http_request(), provider_class=MaterialProviderClass.OWNED_LAB_FIXTURE_REFERENCE)


class Loader:
    def __init__(self, selected: Any) -> None:
        self.binding, self.loads, self.validations = selected, 0, 0
        self.buffer: bytearray | None = None
        self.on_load: Any = None
        self.on_validate: Any = None
        self.status = MaterialBindingStatus.AVAILABLE

    def validate_prebound(self, selected: Any, req: Any) -> MaterialBindingStatus:
        assert selected is self.binding and req.provider_class is MaterialProviderClass.OWNED_LAB_FIXTURE_REFERENCE
        self.validations += 1
        if self.on_validate: self.on_validate()
        return self.status

    def load_radius_material_once(self, selected: Any, req: Any) -> bytearray:
        assert selected is self.binding
        self.loads += 1
        self.buffer = bytearray(MATERIAL)
        if self.on_load: self.on_load()
        return self.buffer


class Peer(HttpPeer):
    def handle(self, method: str, path: str, body: memoryview | None) -> Response:
        if method != "POST":
            return super().handle(method, path, body)
        assert path == TABLE and body is not None
        submitted = json.loads(bytes(body))
        assert set(submitted) == {"name", "$originalName", "auth-type", "server", "secret",
                                  "secondary-server", "secondary-secret"}
        assert submitted.pop("secret").encode() == MATERIAL
        assert submitted.pop("$originalName") == submitted.pop("secondary-secret") == ""
        self.posts += 1
        self.row = self.defaults | submitted | {"q_ref": 0, "secret": "SYNTHETIC_STORED_OPAQUE"}
        if self.lost_post_ack: raise TimeoutError("Synthetic response lost.")
        response = Response(envelope(http_method="POST", mkey=self.binding.name))
        self.responses.append(response)
        return response


class Consumer:
    def __init__(self, outcome: object = RadiusServerCreateOutcome.VERIFIED_CREATED) -> None:
        self.calls, self.outcome = 0, outcome
        self.callback: Any = None
        self.child: memoryview | None = None

    def _create_and_verify_with_material(self, selected: Any, req: Any, secret: memoryview) -> Any:
        self.calls += 1
        assert secret.readonly and bytes(secret) == MATERIAL
        if self.callback: self.callback(secret)
        if isinstance(self.outcome, Exception): raise self.outcome
        return self.outcome


def provider(now: list[int] | None = None) -> Any:
    selected, req = binding(), request()
    now = [100] if now is None else now
    loader = Loader(selected)
    return RadiusServerMaterialProvider(loader, binding=selected, request=req, clock=lambda: now[0]), loader, selected, req


def stores(root: Path) -> tuple[PersistentM4ExecutionStateStore, PersistentMaterialUseStateStore]:
    for name in ("execution", "material"):
        directory = root / name
        directory.mkdir(mode=0o700, exist_ok=True)
        key = directory / "key"
        if not key.exists():
            key.write_bytes(os.urandom(32)); key.chmod(0o600)
    return (PersistentM4ExecutionStateStore(root/"execution/ledger.sqlite", root/"execution/key"),
            PersistentMaterialUseStateStore(root/"material/ledger.sqlite", root/"material/key"))


def workflow(root: Path, peer: Peer, now: list[int], *, enabled: bool | None = True,
             loader: Loader | None = None, **overrides: Any) -> tuple[RadiusServerLiveWorkflow, Loader]:
    state = root / "http"
    state.mkdir(mode=0o700, exist_ok=True)
    execution, material = stores(root)
    loader = Loader(peer.binding) if loader is None else loader
    values: dict[str, Any] = {"expected_serial": SERIAL, "state_directory": state, "loader": loader,
        "execution_store": execution, "material_store": material, "authority_key": AUTHORITY_KEY,
        "environment_ref": "synthetic-radius-environment", "scope_ref": "synthetic-radius-scope",
        "audience_ref": "synthetic-radius-audience", "allowed_requester_digest": IDENTITY["requester_digest"],
        "allowed_transport_digest": IDENTITY["transport_digest"], "clock": lambda: now[0],
        "connection_factory": peer.connection}
    if enabled is not None: values["execution_enabled"] = enabled
    values.update(overrides)
    return RadiusServerLiveWorkflow(peer.binding,
        SecretMetadataHttpTransportConfig("https://pam.example", "synthetic-token", 1, None), **values), loader


def authorized(selected: RadiusServerLiveWorkflow) -> str:
    preview = selected.preview(**IDENTITY)
    return selected.authorize(preview["preview_ref"], **IDENTITY)["authorization_ref"]  # type: ignore[arg-type,return-value]


def test_single_opaque_lease_clears_retained_views_and_denies_reuse() -> None:
    selected, loader, bound, req = provider()
    consumer = Consumer()
    consumer.callback = lambda view: setattr(consumer, "child", view[:])
    lease = selected.acquire_lease(bound, req)
    for value in (selected, lease, bound):
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(MaterialAccessDenied): operation(value)
    outcome = RadiusServerLeaseTransport(selected, consumer).consume(lease)
    assert outcome is MaterialUseOutcome.VERIFIED and consumer.child is not None
    assert not any(consumer.child) and loader.buffer is not None and not any(loader.buffer)
    assert RadiusServerLeaseTransport(selected, consumer).consume(lease) is MaterialUseOutcome.FAILED
    assert selected.release_lease(lease) is MaterialLeaseCompletion.RELEASED
    with pytest.raises(MaterialAccessDenied): selected.acquire_lease(bound, req)
    assert loader.loads == consumer.calls == 1
    consumer.child.release()


@pytest.mark.parametrize("outcome,expected", [
    (RadiusServerCreateOutcome.RECONCILIATION_REQUIRED, MaterialRuntimeOutcome.RECONCILIATION_REQUIRED),
    (TimeoutError("Synthetic timeout."), MaterialRuntimeOutcome.RECONCILIATION_REQUIRED),
    (RuntimeError("Synthetic failure."), MaterialRuntimeOutcome.RECONCILIATION_REQUIRED),
    ("verified_created", MaterialRuntimeOutcome.RECONCILIATION_REQUIRED),
])
def test_ambiguous_or_wrong_transport_results_never_release_as_success(outcome: Any, expected: Any) -> None:
    selected, loader, bound, req = provider()
    consumer = Consumer(outcome)
    actual = MaterialLeaseCoordinator(selected).execute_once(bound, req,
        RadiusServerLeaseTransport(selected, consumer).consume, now_epoch=100)
    assert actual is expected and loader.buffer is not None and not any(loader.buffer)
    assert loader.loads == consumer.calls == 1


@pytest.mark.parametrize("fault", ["short", "excess", "control", "wrong_type", "expired", "clock_rollback"])
def test_failed_material_intake_is_consumed_and_wiped(fault: str) -> None:
    now = [100]
    selected, loader, bound, req = provider(now)
    def alter() -> None:
        assert loader.buffer is not None
        if fault == "short": del loader.buffer[-1:]
        elif fault == "excess": loader.buffer.extend(b"x")
        elif fault == "control": loader.buffer[0] = 10
        elif fault == "expired": now[0] = 160
        elif fault == "clock_rollback": now[0] = 99
    loader.on_load = alter
    if fault == "wrong_type":
        original = loader.load_radius_material_once
        loader.load_radius_material_once = lambda *args: [original(*args)]  # type: ignore[method-assign,assignment]
    with pytest.raises(MaterialAccessDenied): selected.acquire_lease(bound, req)
    assert loader.buffer is not None and not any(loader.buffer)
    now[0] = 101
    with pytest.raises(MaterialAccessDenied): selected.acquire_lease(bound, req)
    assert loader.loads == 1


def test_expired_validation_and_foreign_lease_preserve_correct_buffer_ownership() -> None:
    now = [100]
    selected, loader, bound, req = provider(now)
    lease = selected.acquire_lease(bound, req)
    assert selected._consume_for_radius_transport(bound, MaterialLease(), req, Consumer()) is MaterialUseOutcome.FAILED
    assert loader.buffer == MATERIAL
    with pytest.raises(MaterialAccessDenied): selected.release_lease(MaterialLease())
    assert loader.buffer == MATERIAL
    now[0] = 160
    assert selected.validate_binding(bound, req) is MaterialBindingStatus.EXPIRED
    assert loader.buffer is not None and not any(loader.buffer)
    assert selected.revoke_lease(lease, reason=MaterialRevocationReason.LEASE_EXPIRED) is MaterialLeaseCompletion.REVOKED


@pytest.mark.parametrize("field,value", [
    ("action_id", "ldap-server-create"), ("action_version", "2.0.0"),
    ("provider_class", MaterialProviderClass.EXTERNAL_VAULT_LEASE), ("expires_at", 161),
    ("provider_class", MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE),
])
def test_provider_denies_wrong_contract_without_source_access(field: str, value: Any) -> None:
    selected, loader, bound, req = provider()
    with pytest.raises((MaterialAccessDenied, MaterialContractError)):
        RadiusServerMaterialProvider(loader, binding=bound, request=replace(req, **{field: value}))
    assert loader.loads == loader.validations == 0


def test_real_hmac_authority_http_join_minimized_results_and_persistent_replay(tmp_path: Path) -> None:
    root, peer, now = tmp_path.resolve(), Peer(), [100]
    selected, loader = workflow(root, peer, now)
    assert not peer.connections and loader.loads == loader.validations == 0
    preview = selected.preview(**IDENTITY)
    assert preview["Expected State"]["connectivity_qualified"] is False  # type: ignore[index]
    auth = selected.authorize(preview["preview_ref"], **IDENTITY)  # type: ignore[arg-type]
    assert loader.loads == loader.validations == 0
    result = selected.execute(auth["authorization_ref"], **IDENTITY)  # type: ignore[arg-type]
    assert result["outcome"] == "succeeded" and result["verification"] == "verified"
    assert selected._execution_store.claim_count == selected._material_store.claim_count == 1
    assert loader.loads == peer.posts == 1 and peer.deletes == 0
    assert loader.buffer is not None and not any(loader.buffer) and all(not body for body in peer.bodies)
    count = len(peer.connections)
    replay = selected.execute(auth["authorization_ref"], **IDENTITY)  # type: ignore[arg-type]
    assert replay == result | {"idempotent_replay": True}
    assert len(peer.connections) == count and loader.loads == 1
    rendered = json.dumps([preview, auth, result])
    for private in (peer.binding.name, peer.binding.server, peer.binding.private_nonce, MATERIAL.decode(),
                    SERIAL, "synthetic-token", "synthetic-radius-environment", "synthetic-radius-scope"):
        assert private not in rendered
    restarted, fresh = workflow(root, peer, now)
    with pytest.raises(RadiusServerLiveWorkflowError): restarted.preview(**IDENTITY)
    assert fresh.loads == 0 and len(peer.connections) == count


@pytest.mark.parametrize("fault", ["lost_ack", "readback"])
def test_unknown_execution_remains_terminal_and_does_not_reacquire(tmp_path: Path, fault: str) -> None:
    root, peer, now = tmp_path.resolve(), Peer(), [100]
    selected, loader = workflow(root, peer, now)
    ref = authorized(selected)
    peer.lost_post_ack = fault == "lost_ack"
    peer.failed_readback = fault == "readback"
    result = selected.execute(ref, **IDENTITY)
    assert result["outcome"] == "reconciliation_required" and result["verification"] == "unknown"
    count = len(peer.connections)
    assert selected.execute(ref, **IDENTITY)["idempotent_replay"] is True
    assert len(peer.connections) == count and loader.loads == peer.posts == 1
    assert loader.buffer is not None and not any(loader.buffer)
    restarted, fresh = workflow(root, peer, now)
    with pytest.raises(RadiusServerLiveWorkflowError): restarted.preview(**IDENTITY)
    assert fresh.loads == peer.deletes == 0


@pytest.mark.parametrize("stage", ["authorize", "execute"])
@pytest.mark.parametrize("fault", ["identity", "expired", "drift", "gate"])
def test_nonmaterial_gates_deny_before_intake(tmp_path: Path, stage: str, fault: str) -> None:
    root, peer, now = tmp_path.resolve(), Peer(), [100]
    selected, loader = workflow(root, peer, now)
    preview = selected.preview(**IDENTITY)
    ref = None if stage == "authorize" else selected.authorize(preview["preview_ref"], **IDENTITY)["authorization_ref"]  # type: ignore[arg-type]
    if fault == "expired": now[0] = 160
    elif fault == "drift": peer.defaults["timeout"] += 1
    elif fault == "gate": selected._enabled = False
    identity = IDENTITY | {"requester_digest": "9"*64} if fault == "identity" else IDENTITY
    if stage == "authorize" or fault != "drift":
        with pytest.raises(RadiusServerLiveWorkflowError):
            (selected.authorize(preview["preview_ref"], **identity) if stage == "authorize"  # type: ignore[arg-type]
             else selected.execute(ref, **identity))  # type: ignore[arg-type]
    else:
        assert selected.execute(ref, **identity)["outcome"] != "succeeded"  # type: ignore[arg-type]
    assert loader.loads == peer.posts == 0


def test_default_gate_and_tampered_hmac_plan_fail_closed(tmp_path: Path) -> None:
    root, peer, now = tmp_path.resolve(), Peer(), [100]
    closed, loader = workflow(root, peer, now, enabled=None)
    preview = closed.preview(**IDENTITY)
    with pytest.raises(RadiusServerLiveWorkflowError): closed.authorize(preview["preview_ref"], **IDENTITY)  # type: ignore[arg-type]
    opened, _ = workflow(root, peer, now, loader=loader)
    ref = authorized(opened)
    issued = opened._authority._issued
    assert issued is not None
    object.__setattr__(issued.plan, "summary_digest", "f"*64)
    with pytest.raises(M4AuthorizationDenied): opened._authority.verify(issued.plan, issued.authorization, now_epoch=100)
    with pytest.raises(RadiusServerLiveWorkflowError): opened.execute(ref, **IDENTITY)
    assert opened._execution_store.claim_count == loader.loads == peer.posts == 0


def test_lease_expiry_during_loader_clears_material_without_http_claim(tmp_path: Path) -> None:
    root, peer, now = tmp_path.resolve(), Peer(), [100]
    selected, loader = workflow(root, peer, now)
    ref = authorized(selected)
    loader.on_load = lambda: now.__setitem__(0, 160)
    result = selected.execute(ref, **IDENTITY)
    assert result["outcome"] == "reconciliation_required" and peer.posts == 0
    assert loader.loads == 1 and loader.buffer is not None and not any(loader.buffer)
    assert not (root/"http/create.claim.json").exists()


def test_signed_preview_cannot_cross_authority_namespace(tmp_path: Path) -> None:
    root, peer, now = tmp_path.resolve(), Peer(), [100]
    original, loader = workflow(root, peer, now)
    preview = original.preview(**IDENTITY)
    other, _ = workflow(root, peer, now, loader=loader, scope_ref="other-radius-scope")
    other._preview = original._preview
    count = len(peer.connections)
    with pytest.raises(RadiusServerLiveWorkflowError): other.authorize(preview["preview_ref"], **IDENTITY)  # type: ignore[arg-type]
    assert len(peer.connections) == count and loader.loads == peer.posts == 0


def test_gate_revoked_during_intake_clears_material_before_transport(tmp_path: Path) -> None:
    root, peer, now = tmp_path.resolve(), Peer(), [100]
    selected, loader = workflow(root, peer, now)
    ref = authorized(selected)
    loader.on_load = lambda: setattr(selected, "_enabled", False)
    result = selected.execute(ref, **IDENTITY)
    assert result["outcome"] == "reconciliation_required"
    assert loader.loads == 1 and peer.posts == 0 and loader.buffer is not None and not any(loader.buffer)
    assert not (root/"http/create.claim.json").exists()


def test_final_hmac_authorizer_crossing_expiry_cannot_send_material(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, peer, now = tmp_path.resolve(), Peer(), [100]
    selected, loader = workflow(root, peer, now)
    ref = authorized(selected)
    original = live_module._LabAutoAuthority.verify
    after_claim = [0]

    def verify(self: Any, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        if (root/"http/create.claim.json").exists():
            after_claim[0] += 1
            now[0] = 159 if after_claim[0] == 1 else 160

    monkeypatch.setattr(live_module._LabAutoAuthority, "verify", verify)
    result = selected.execute(ref, **IDENTITY)
    assert result["outcome"] == "reconciliation_required" and after_claim[0] == 2
    assert loader.loads == 1 and peer.posts == 0 and loader.buffer is not None and not any(loader.buffer)
    assert (root/"http/create.claim.json").exists()


@pytest.mark.parametrize('executed', [False, True])
def test_workflow_close_revokes_issued_dispatch_without_resetting_claims(tmp_path: Path,
                                                                      executed: bool) -> None:
    peer, now = Peer(), [100]
    selected, loader = workflow(tmp_path, peer, now)
    reference = authorized(selected)
    runtime = selected._runtime
    assert runtime is not None
    if executed:
        assert selected.execute(reference, **IDENTITY)['outcome'] == 'succeeded'
    counts = (selected._execution_store.claim_count, selected._material_store.claim_count,
              loader.loads, len(peer.connections), peer.posts)
    selected.close()
    selected.close()
    with pytest.raises(RadiusServerLiveWorkflowError):
        selected.execute(reference, **IDENTITY)
    assert not selected._enabled and not runtime._enabled and not runtime._transport._execution_enabled
    assert selected._authority._key == b'' and selected._authority._issued is None
    assert counts == (selected._execution_store.claim_count, selected._material_store.claim_count,
                      loader.loads, len(peer.connections), peer.posts)
