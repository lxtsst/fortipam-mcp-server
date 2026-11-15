"""Server-held scope signs real-source plans; only original full custody recovers."""
from dataclasses import asdict, replace
import json

import pytest
from v4_planning import M4AdapterAmbiguous, M4AuthorizationDenied, M4ExecutionKernel

from fortipam_mcp.local_user_reset_fixture_authority import LocalResetFixtureM4Authority, RECOVER_ACTION
from fortipam_mcp.local_user_reset_fixture_custody import LocalResetFixtureAckCustody, LocalResetFixtureAckPins
from fortipam_mcp.secret_metadata_http_transport import _zeroize_mutable
from test_local_user_reset_fixture_material import Harness as MaterialHarness
from test_local_user_reset_fixture_custody import response
from test_v4_execution_kernel import REQUESTER

IDENTITY = dict(environment_ref="reset-fixture-lab-environment",scope_ref="reset-fixture-lab-scope",
    audience_ref="reset-fixture-lab-audience",requester_digest=REQUESTER,transport_digest="c"*64)


def authority(h, *, phase="create", original=None, enabled=True, **changes):
    return LocalResetFixtureM4Authority(h.source,phase=phase,original=original,
        material=h.material if phase=="create" else None,authority_key=b"j"*32,
        execution_enabled=enabled,clock=lambda:h.now,**{**IDENTITY,**changes})


def issue(h, issuer):
    args={key:IDENTITY[key] for key in ("requester_digest","transport_digest")}
    preview=issuer.preview(h.source._current,**args)
    packet=issuer.issue(preview,h.source.observe_absence(),**args)
    return preview,packet


def custody(h, packet):
    directory=h.root/"custody";directory.mkdir(mode=0o700)
    key=h.root/"custody.key";key.write_bytes(b"w"*32);key.chmod(0o600)
    state=h.source._state
    pins=LocalResetFixtureAckPins(state._draft.username,state._serial,REQUESTER,state._actor,
        packet.plan.expected_current_digest,state._draft.nonmaterial_request_digest,h.material.reference,
        packet.plan.plan_digest,packet.authorization.authorization_digest,"7"*64)
    path=h.root/"constructor.private.json"
    path.write_text(json.dumps(dict(pins=asdict(pins),plan=asdict(packet.plan),authorization=asdict(packet.authorization),vdom="root")))
    path.chmod(0o600)
    return LocalResetFixtureAckCustody(directory=directory,packet_file=path,witness_key_file=key,
        plan=packet.plan,authorization=packet.authorization,store=h.store,expected_vdom="root",
        execution_enabled=True,clock=lambda:h.now)


def creation(root,monkeypatch,*,unknown=False,seal=True,baseline=True,inside_probe=False):
    h=MaterialHarness(root,monkeypatch);h.stage();issuer=authority(h)
    _,packet=issue(h,issuer);original=custody(h,packet)
    class Adapter:
        def read_current(self,plan):
            issuer.check_current(packet,h.source._current)
            return h.source._current.current_digest
        def dispatch(self,plan):
            lease=None;wire=bytearray()
            try:
                if baseline:original.capture_original_absence(h.source)
                lease=h.material.acquire_original(plan,packet.authorization)
                wire=h.network.draft._encode(lease._consume())
                original.begin_original_send()
                original.capture_original_ack(response(),http_status=200,content_type="application/json")
                h.network.present=True
                if seal:original.capture_original_full_state(h.source._state)
                observed=h.source.observe_presence()
                if baseline:assert observed.namespace_digest==original.inspect_original_absence().presence_namespace_digest
                if inside_probe:
                    with pytest.raises(M4AuthorizationDenied):authority(h,phase="recover",original=original)
            finally:
                if lease is not None:lease.close()
                _zeroize_mutable(wire)
        def read_postcondition(self,plan):
            if unknown:raise M4AdapterAmbiguous("Synthetic postcondition unavailable.")
            return plan.expected_state_digest
    result=M4ExecutionKernel(Adapter(),issuer,h.store,clock=lambda:h.now).execute(packet.plan,packet.authorization)
    assert str(result.outcome)==("reconciliation_required" if unknown else "succeeded")
    return h,issuer,packet,original


@pytest.mark.parametrize("unknown",[False,True])
def test_create_and_separate_recovery_authority_keep_original_terminal_result(tmp_path,monkeypatch,unknown):
    h,create,packet,original=creation(tmp_path,monkeypatch,unknown=unknown,inside_probe=True)
    before={p.name:p.read_bytes() for p in original._directory.iterdir()}
    issuer=authority(h,phase="recover",original=original)
    args={key:IDENTITY[key] for key in ("requester_digest","transport_digest")}
    preview=issuer.preview(h.source._current,**args)
    issued=issuer.issue(preview,h.source.observe_presence(),**args)
    issuer.verify(issued.plan,issued.authorization,now_epoch=h.now)
    issuer.check_current(issued,h.source._current)
    assert issued.plan.action_id==RECOVER_ACTION and issued.plan.parameters_digest!=packet.plan.parameters_digest
    assert original.inspect_original_full_state().original_ack.original_verification==("unknown" if unknown else "verified")
    assert before=={p.name:p.read_bytes() for p in original._directory.iterdir()} and h.store.claim_count==1
    issuer.close();create.close();h.material.close();original.close();h.source.close()


@pytest.mark.parametrize("seal,baseline",[(False,True),(True,False)])
def test_ack_only_or_missing_original_namespace_cannot_authorize_recovery(tmp_path,monkeypatch,seal,baseline):
    h,_,_,original=creation(tmp_path,monkeypatch,seal=seal,baseline=baseline)
    with pytest.raises(M4AuthorizationDenied):authority(h,phase="recover",original=original)


@pytest.mark.parametrize("fault",["gate","copy-preview","tamper","requester","transport","expiry","copy-plan","policy"])
def test_fresh_intent_scope_policy_and_object_identity_are_required(tmp_path,monkeypatch,fault):
    h=MaterialHarness(tmp_path,monkeypatch);h.stage();issuer=authority(h,enabled=fault!="gate")
    args={key:IDENTITY[key] for key in ("requester_digest","transport_digest")}
    preview=issuer.preview(h.source._current,**args)
    if fault=="copy-preview":preview=replace(preview)
    elif fault=="tamper":object.__setattr__(preview,"current_digest","f"*64)
    elif fault=="requester":args["requester_digest"]="f"*64
    elif fault=="transport":args["transport_digest"]="f"*64
    elif fault=="expiry":h.now=preview.expires_at
    elif fault=="policy":h.rules["minimum-length"]=64
    if fault=="copy-plan":
        packet=issuer.issue(preview,h.source._current,**args)
        with pytest.raises(M4AuthorizationDenied):issuer.verify(replace(packet.plan),packet.authorization,now_epoch=h.now)
    else:
        with pytest.raises(M4AuthorizationDenied):issuer.issue(preview,h.source._current,**args)
    assert h.store.claim_count==0


def test_recovery_rejects_unrelated_global_namespace_drift(tmp_path,monkeypatch):
    h,_,_,original=creation(tmp_path,monkeypatch)
    issuer=authority(h,phase="recover",original=original)
    # A newly observed extra peer is unrelated even if the selected User is exact.
    from fortipam_mcp.local_user_reset_fixture_sources import _NAMESPACE_CONTRACT, _digest
    from v4_planning import canonical_digest
    h.source._admin_names+=("foreign-synthetic-peer",)
    observed=replace(h.source._current,admin_count=len(h.source._admin_names),namespace_digest=canonical_digest(
        dict(contract=_NAMESPACE_CONTRACT,admin_names=sorted(h.source._admin_names),api_names=sorted(h.source._api_names))))
    h.source._current=observed;h.source._seal=_digest(asdict(observed))
    with pytest.raises(M4AuthorizationDenied):issuer.preview(observed,requester_digest=REQUESTER,transport_digest=IDENTITY["transport_digest"])


def test_missing_initial_material_and_shared_server_keys_cannot_sign(tmp_path,monkeypatch):
    h=MaterialHarness(tmp_path,monkeypatch)
    with pytest.raises(M4AuthorizationDenied):authority(h)
    h.stage()
    with pytest.raises(M4AuthorizationDenied):
        LocalResetFixtureM4Authority(h.source,phase="create",material=h.material,authority_key=h.material._key,
            execution_enabled=True,clock=lambda:h.now,**IDENTITY)
    assert h.store.claim_count==0
