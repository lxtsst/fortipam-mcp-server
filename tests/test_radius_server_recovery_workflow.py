"""Separate M4 authority and original-ACK recovery; synthetic HTTP only."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp.radius_server_recovery_workflow import RadiusServerRecoveryWorkflow, RadiusServerRecoveryError
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from v4_planning import canonical_digest
from test_radius_server_material_runtime import (
    AUTHORITY_KEY, IDENTITY, Peer, authorized, stores, workflow,
)
from test_radius_server_projection import SERIAL


def recovery(root: Path, peer: Peer, now: list[int], *, enabled: bool | None = True,
             store: PersistentM4ExecutionStateStore | None = None, **overrides: Any) -> RadiusServerRecoveryWorkflow:
    ledger = root / "recovery"
    ledger.mkdir(mode=0o700, exist_ok=True)
    if store is None: store, _ = stores(ledger)
    values: dict[str, Any] = dict(expected_serial=SERIAL,state_directory=root/"http",execution_store=store,
        authority_key=AUTHORITY_KEY,environment_ref="synthetic-radius-environment",scope_ref="synthetic-radius-recovery",
        audience_ref="synthetic-radius-audience",allowed_requester_digest=IDENTITY["requester_digest"],
        allowed_transport_digest=IDENTITY["transport_digest"],clock=lambda:now[0],connection_factory=peer.connection)
    if enabled is not None: values["execution_enabled"] = enabled
    values.update(overrides)
    return RadiusServerRecoveryWorkflow(peer.binding,
        SecretMetadataHttpTransportConfig("https://pam.example","synthetic-token",1,None),**values)


def setup(root: Path, **faults: Any) -> tuple[Any, Any, Any, Any]:
    peer, now = Peer(), [100]
    create, loader = workflow(root,peer,now)
    for name, value in faults.items(): setattr(peer,name,value)
    result = create.execute(authorized(create),**IDENTITY)
    return peer, now, loader, result


def grant(selected: RadiusServerRecoveryWorkflow) -> str:
    p = selected.preview(**IDENTITY)
    return selected.authorize(p["preview_ref"],**IDENTITY)["authorization_ref"]  # type: ignore[arg-type,return-value]


def test_separate_authority_m4_and_exact_lifecycle(tmp_path: Path) -> None:
    peer, now, loader, created = setup(tmp_path)
    selected = recovery(tmp_path,peer,now)
    connections = len(peer.connections)
    assert selected._store.claim_count == 0 and loader.loads == 1
    p = selected.preview(**IDENTITY)
    assert p["Current State"] == {"original_creation_ack_verified":True,"full_state_unchanged":True,"zero_references":True}
    auth = selected.authorize(p["preview_ref"],**IDENTITY)  # type: ignore[arg-type]
    assert len(peer.connections)>connections and peer.deletes==0 and loader.loads==1
    result = selected.execute(auth["authorization_ref"],**IDENTITY)  # type: ignore[arg-type]
    assert result["outcome"]=="succeeded" and result["verification"]=="verified"
    assert peer.row is None and peer.posts==peer.deletes==loader.loads==selected._store.claim_count==1
    assert (tmp_path/"http/delete-ack.json").exists() and (tmp_path/"http/deleted.json").exists()
    connections = len(peer.connections)
    replay = selected.execute(auth["authorization_ref"],**IDENTITY)  # type: ignore[arg-type]
    assert replay["idempotent_replay"] is True and len(peer.connections)==connections and peer.deletes==1
    fresh = recovery(tmp_path,peer,now)
    with pytest.raises(RadiusServerRecoveryError): fresh.preview(**IDENTITY)
    assert len(peer.connections)==connections
    encoded = json.dumps([p,auth,result])
    for value in (peer.binding.name,peer.binding.server,peer.binding.private_nonce,SERIAL,"SYNTHETIC_STORED_OPAQUE"):
        assert value not in encoded


def test_default_closed_and_create_authorization_cannot_delete(tmp_path: Path) -> None:
    peer,now,_,_ = setup(tmp_path)
    closed = recovery(tmp_path,peer,now,enabled=None)
    p = closed.preview(**IDENTITY)
    with pytest.raises(RadiusServerRecoveryError): closed.authorize(p["preview_ref"],**IDENTITY)
    selected = recovery(tmp_path,peer,now)
    grant(selected)
    with pytest.raises(RadiusServerRecoveryError): selected.execute("radius-auth-"+"a"*64,**IDENTITY)
    assert peer.deletes==selected._store.claim_count==0


@pytest.mark.parametrize("fault",["lost_post_ack","failed_readback"])
def test_only_original_success_ack_can_reconcile_creation_for_recovery(tmp_path: Path,fault: str) -> None:
    peer,now,loader,result = setup(tmp_path,**{fault:True})
    assert result["outcome"]=="reconciliation_required"
    selected = recovery(tmp_path,peer,now)
    if fault=="lost_post_ack":
        with pytest.raises(RadiusServerRecoveryError): grant(selected)
        assert peer.deletes==0
    else:
        assert selected.execute(grant(selected),**IDENTITY)["outcome"]=="succeeded"
        assert peer.deletes==1
    assert loader.loads==1


@pytest.mark.parametrize("fault",["q_ref","scalar","opaque","defaults"])
def test_full_state_drift_or_reference_blocks_recovery(tmp_path: Path,fault: str) -> None:
    peer,now,loader,_ = setup(tmp_path)
    selected = recovery(tmp_path,peer,now)
    ref = grant(selected)
    if fault=="q_ref": peer.row["q_ref"] = 1
    elif fault=="scalar": peer.row["timeout"] = 9
    elif fault=="opaque": peer.row["secret"] = "SYNTHETIC_CHANGED_OPAQUE"
    else: peer.defaults["timeout"] = 9
    assert selected.execute(ref,**IDENTITY)["outcome"]!="succeeded"
    assert peer.deletes==0 and loader.loads==1 and not (tmp_path/"http/delete.claim.json").exists()


@pytest.mark.parametrize("fault",["expired","clock_rollback","identity","gate","tampered_plan","wrong_namespace"])
def test_invalid_authority_never_claims_or_dispatches(tmp_path: Path,fault: str) -> None:
    peer,now,_,_ = setup(tmp_path)
    selected = recovery(tmp_path,peer,now)
    ref = grant(selected)
    identity = dict(IDENTITY)
    if fault=="expired": now[0]=160
    elif fault=="clock_rollback": now[0]=99
    elif fault=="identity": identity["transport_digest"]="3"*64
    elif fault=="gate": selected.close()
    elif fault=="tampered_plan": object.__setattr__(selected._issued.plan,"summary_digest","f"*64)
    else: selected._namespace["scope_ref"]="different-radius-scope"
    with pytest.raises(RadiusServerRecoveryError): selected.execute(ref,**identity)
    assert peer.deletes==selected._store.claim_count==0
    if fault=="clock_rollback":
        now[0]=100
        with pytest.raises(RadiusServerRecoveryError): selected.execute(ref,**identity)


def test_original_create_ledger_cannot_be_reused_as_recovery_ledger(tmp_path: Path) -> None:
    peer,now,_,_ = setup(tmp_path)
    store,_ = stores(tmp_path)
    selected = recovery(tmp_path,peer,now,store=store)
    before = len(peer.connections)
    with pytest.raises(RadiusServerRecoveryError): selected.preview(**IDENTITY)
    assert len(peer.connections)==before and peer.deletes==0


@pytest.mark.parametrize("fault",["lost_ack","absence_failure"])
def test_uncertain_delete_never_replays_and_can_only_observe_absence(tmp_path: Path,fault: str) -> None:
    peer,now,loader,_ = setup(tmp_path)
    selected = recovery(tmp_path,peer,now)
    ref = grant(selected)
    if fault=="lost_ack": peer.lost_delete_ack=True
    else: peer.bad_absence=True
    assert selected.execute(ref,**IDENTITY)["outcome"]=="reconciliation_required"
    assert peer.deletes==1 and (tmp_path/"http/delete.claim.json").exists()
    count = len(peer.connections)
    assert selected.execute(ref,**IDENTITY)["idempotent_replay"] is True
    assert len(peer.connections)==count and peer.deletes==loader.loads==1
    fresh = recovery(tmp_path,peer,now)
    with pytest.raises(RadiusServerRecoveryError): fresh.preview(**IDENTITY)
    peer.bad_absence=False
    assert selected._transport.inspect_deleted()
    assert peer.deletes==1


@pytest.mark.parametrize("fault",["expiry","gate"])
def test_final_authorizer_after_delete_connection_prevents_send(tmp_path: Path,fault: str) -> None:
    peer,now,_,_ = setup(tmp_path)
    selected = recovery(tmp_path,peer,now)
    ref = grant(selected)
    def on_connect() -> None:
        if (tmp_path/"http/delete.claim.json").exists():
            if fault=="expiry": now[0]=160
            else: selected._enabled=False
    peer.on_connect=on_connect
    assert selected.execute(ref,**IDENTITY)["outcome"]=="reconciliation_required"
    assert peer.deletes==0 and (tmp_path/"http/delete.claim.json").exists()
    assert selected._store.claim_count==1


def test_authorizer_requires_in_progress_m4_claim(tmp_path: Path) -> None:
    peer,now,_,_ = setup(tmp_path)
    selected = recovery(tmp_path,peer,now)
    grant(selected)
    selected._started=True
    p=selected._preview
    assert not selected._authorize_delete(peer.binding,p.owned_digest,p.state_digest)
    assert peer.deletes==selected._store.claim_count==0


def test_orphaned_in_progress_claim_is_not_dispatch_ownership(tmp_path: Path) -> None:
    peer,now,_,_ = setup(tmp_path)
    selected = recovery(tmp_path,peer,now)
    ref=grant(selected)
    issued=selected._issued
    plan,auth=issued.plan,issued.authorization
    selected._store.claim(plan_ref=plan.plan_ref,requester_digest=plan.requester_digest,
        idempotency_digest=plan.idempotency_digest,authorization_digest=auth.authorization_digest,
        context_digest=canonical_digest({"plan_digest":plan.plan_digest,"revision":plan.revision,
                                        "authorization_digest":auth.authorization_digest}))
    selected._started=True
    p=selected._preview
    assert not selected._authorize_delete(peer.binding,p.owned_digest,p.state_digest)
    assert selected.execute(ref,**IDENTITY)["outcome"]=="reconciliation_required"
    assert peer.deletes==0 and not (tmp_path/"http/delete.claim.json").exists()


def test_empty_journal_recovery_observation_cannot_initialize_it(tmp_path: Path) -> None:
    peer,now=Peer(),[100]
    (tmp_path/"http").mkdir(mode=0o700)
    selected=recovery(tmp_path,peer,now)
    with pytest.raises(RadiusServerRecoveryError): selected.preview(**IDENTITY)
    assert not list((tmp_path/"http").iterdir()) and not peer.connections


@pytest.mark.parametrize('populated', [False, True])
def test_detail_empty_array_format_preserves_original_baseline_and_recovery(
    tmp_path: Path, populated: bool,
) -> None:
    import io
    peer, now = Peer(), [100]
    original = peer.handle
    detail_count = 0
    def formatted(method: str, path: str, body: Any) -> Any:
        nonlocal detail_count
        response = original(method, path, body)
        raw = response.content.getvalue()
        if method == 'GET' and 'action=default' in path:
            raw = raw.replace(b'"class": []', b'"class": [ ]')
            raw = raw.replace(b'"accounting-server": []', b'"accounting-server": [\n]')
        elif method == 'GET' and path.endswith('/' + peer.binding.name + '?with_meta=true') and response.status == 200:
            detail_count += 1
            whitespace = b'\n  ' if detail_count % 2 else b'\t'
            for field in (b'class', b'accounting-server'):
                raw = raw.replace(b'"' + field + b'": []', b'"' + field + b'": [' +
                                  (b'{}' if populated else whitespace) + b']')
        response.content = io.BytesIO(raw)
        return response
    peer.handle = formatted  # type: ignore[method-assign]
    create, loader = workflow(tmp_path, peer, now)
    reference = authorized(create)
    current_digest = create._authority._issued.plan.expected_current_digest
    result = create.execute(reference, **IDENTITY)
    selected = recovery(tmp_path, peer, now)
    if populated:
        assert result['outcome'] == 'reconciliation_required'
        with pytest.raises(RadiusServerRecoveryError):
            grant(selected)
        assert peer.deletes == 0
    else:
        assert result['outcome'] == 'succeeded'
        assert selected.execute(grant(selected), **IDENTITY)['outcome'] == 'succeeded'
        claim = json.loads((tmp_path / 'http/create.claim.json').read_bytes())
        assert claim['current_digest'] == current_digest
        assert peer.row is None and peer.deletes == loader.loads == 1
