"""Server-held exact scope signs one original-owned reset M4, not caller hashes."""
from dataclasses import replace

import pytest
from v4_planning import M4AuthorizationDenied,M4ExecutionKernel

from fortipam_mcp.local_user_reset_owned_authority import LocalResetOwnedM4Authority
from test_local_user_reset_owned_material import Harness
from test_v4_execution_kernel import REQUESTER

IDENTITY=dict(environment_ref="owned-reset-lab-environment",scope_ref="owned-reset-lab-scope",
    audience_ref="owned-reset-lab-audience",requester_digest=REQUESTER,transport_digest="c"*64)
ARGS={key:IDENTITY[key] for key in ("requester_digest","transport_digest")}


def authority(h,*,enabled=True,**changes):
    return LocalResetOwnedM4Authority(h.material,authority_key=b"j"*32,execution_enabled=enabled,
        clock=lambda:h.now,**{**IDENTITY,**changes})


def issue(h,issuer):
    preview=issuer.preview(**ARGS);packet=issuer.issue(preview,**ARGS)
    h.plan,h.auth=packet.plan,packet.authorization
    return preview,packet


def test_server_authorized_actual_m4_loads_one_pair_and_replay_never_reloads(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch);h.stage();issuer=authority(h);_,packet=issue(h,issuer)
    result=M4ExecutionKernel(h,issuer,h.store,clock=lambda:h.now).execute(packet.plan,packet.authorization)
    assert str(result.outcome)=="succeeded" and h.seen and h.store.claim_count==1
    repeated=M4ExecutionKernel(h,issuer,h.store,clock=lambda:h.now).execute(packet.plan,packet.authorization)
    assert repeated.idempotent_replay and repeated.outcome==result.outcome and h.store.claim_count==1
    assert all(not any(raw) for raw in h.material._buffers)
    with pytest.raises(M4AuthorizationDenied):issuer.preview(**ARGS)
    issuer.close();h.material.close()


@pytest.mark.parametrize("fault",["gate","copy-preview","tamper","requester","transport","expiry","copy-plan","copy-auth","policy","state","source-closed"])
def test_stale_or_foreign_scope_cannot_issue_or_verify(tmp_path,monkeypatch,fault):
    h=Harness(tmp_path,monkeypatch);h.stage();issuer=authority(h,enabled=fault!="gate")
    preview=issuer.preview(**ARGS);args=dict(ARGS)
    if fault=="copy-preview":preview=replace(preview)
    elif fault=="tamper":object.__setattr__(preview,"current_digest","f"*64)
    elif fault=="requester":args["requester_digest"]="f"*64
    elif fault=="transport":args["transport_digest"]="f"*64
    elif fault=="expiry":h.now=preview.expires_at
    elif fault=="policy":h.h.rules["minimum-length"]=64
    elif fault=="state":h.h.network.record["comments"]="foreign"
    elif fault=="source-closed":h.h.source.close()
    if fault in {"copy-plan","copy-auth"}:
        packet=issuer.issue(preview,**args)
        with pytest.raises(M4AuthorizationDenied):issuer.verify(
            replace(packet.plan) if fault=="copy-plan" else packet.plan,
            replace(packet.authorization) if fault=="copy-auth" else packet.authorization,now_epoch=h.now)
    else:
        with pytest.raises(M4AuthorizationDenied):issuer.issue(preview,**args)
    assert h.store.claim_count==0 and not h.seen


def test_policy_drift_after_issuance_is_rejected_before_material_or_dispatch(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch);h.stage();issuer=authority(h);_,packet=issue(h,issuer)
    h.h.rules["minimum-length"]=64
    with pytest.raises(M4AuthorizationDenied):M4ExecutionKernel(h,issuer,h.store,clock=lambda:h.now).execute(packet.plan,packet.authorization)
    assert h.store.claim_count==1 and not h.seen and not h.material._consumed


def test_cached_source_expiry_is_rejected_after_issuance(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch);h.stage();issuer=authority(h);_,packet=issue(h,issuer)
    h.h.network.now=1060
    with pytest.raises(M4AuthorizationDenied):issuer.check_active(packet)
    assert h.store.claim_count==0 and not h.seen


def test_material_and_server_authority_keys_are_distinct(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch);h.stage()
    with pytest.raises(M4AuthorizationDenied):LocalResetOwnedM4Authority(h.material,authority_key=h.material._key,
        execution_enabled=True,clock=lambda:h.now,**IDENTITY)
    assert h.store.claim_count==0
