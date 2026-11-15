"""Successful original full custody is distinct from legacy/UNKNOWN evidence."""
import json

import pytest
from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan

from fortipam_mcp.local_user_reset_fixture_custody import LocalResetFixtureAckCustody
from fortipam_mcp.local_user_reset_fixture_material import LocalResetInitialMaterialSource
from fortipam_mcp.local_user_reset_owned_inspector import LocalResetFixtureOwnedInspector
from fortipam_mcp.local_user_reset_http_transport import LocalUserResetBinding
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_local_user_reset_fixture_authority import creation
from test_m4_execution_store import CHECKPOINT_STORE_REF


def readonly(h,original):
    store=PersistentM4ExecutionStateStore(h.root/"ledger.sqlite",h.root/"store.key",read_only=True,
        monotonic_checkpoint=h.cp,checkpoint_store_ref=CHECKPOINT_STORE_REF)
    packet=json.loads((h.root/"constructor.private.json").read_bytes())
    custody=LocalResetFixtureAckCustody(directory=original._directory,packet_file=h.root/"constructor.private.json",
        witness_key_file=h.root/"custody.key",plan=M4ExecutionPlan(**packet["plan"]),
        authorization=M4ExecutionAuthorization(**packet["authorization"]),store=store,expected_vdom="root",clock=lambda:5000)
    initial=LocalResetInitialMaterialSource(h.source,h.policy,store,directory=h.directory,
        witness_key_file=h.root/"material.key",clock=lambda:5000)
    return custody,initial


def test_readonly_original_owned_baseline_after_creation_expiry_requires_no_material_read(tmp_path,monkeypatch):
    h,_,_,original=creation(tmp_path,monkeypatch)
    custody,initial=readonly(h,original)
    before={p.name:p.read_bytes() for p in original._directory.iterdir()}
    inspector=LocalResetFixtureOwnedInspector(h.source,custody,initial)
    import fortipam_mcp.local_user_reset_fixture_material as material_module
    read=material_module._read
    def metadata_only(path,limit):
        assert path.name!="initial-password"
        return read(path,limit)
    monkeypatch.setattr(material_module,"_read",metadata_only)
    baseline=inspector.read_nonmaterial_baseline();LocalUserResetBinding(baseline)
    assert baseline.status=="enable" and baseline.access_profile=="Guest" and baseline.fixture_creation_digest
    assert "username" not in repr(baseline) and not hasattr(inspector,"verify_initial_material_view")
    assert baseline==inspector.read_nonmaterial_baseline()
    assert before=={p.name:p.read_bytes() for p in original._directory.iterdir()} and h.store.claim_count==1
    inspector.close()
    with pytest.raises(ValueError):inspector.read_nonmaterial_baseline()


@pytest.mark.parametrize("unknown,seal,baseline",[(True,True,True),(False,False,True),(False,True,False)])
def test_unknown_ack_only_or_no_original_namespace_does_not_become_reset_provenance(tmp_path,monkeypatch,unknown,seal,baseline):
    h,_,_,original=creation(tmp_path,monkeypatch,unknown=unknown,seal=seal,baseline=baseline)
    custody,initial=readonly(h,original)
    with pytest.raises(ValueError):LocalResetFixtureOwnedInspector(h.source,custody,initial)


@pytest.mark.parametrize("fault",["mutable-original","enabled-material","used-record","material-key","packet","user-state","deleted","expired","source-closed"])
def test_original_context_material_use_and_live_complete_state_cannot_drift(tmp_path,monkeypatch,fault):
    h,_,_,original=creation(tmp_path,monkeypatch)
    custody,initial=readonly(h,original)
    if fault=="mutable-original":custody=original
    elif fault=="enabled-material":initial._enabled=True
    if fault in {"mutable-original","enabled-material"}:
        with pytest.raises(ValueError):LocalResetFixtureOwnedInspector(h.source,custody,initial)
        return
    inspector=LocalResetFixtureOwnedInspector(h.source,custody,initial)
    if fault=="used-record":
        path=h.directory/"initial-material.used.json";value=json.loads(path.read_bytes());value["claimed_at"]+=1;path.write_text(json.dumps(value))
    elif fault=="material-key":(h.root/"material.key").write_bytes(b"q"*32)
    elif fault=="packet":
        path=h.root/"constructor.private.json";value=json.loads(path.read_bytes());value["pins"]["private_nonce"]="6"*64;path.write_text(json.dumps(value))
    elif fault=="user-state":h.network.record["comments"]="foreign"
    elif fault=="deleted":h.network.present=False;h.source.observe_absence()
    elif fault=="expired":h.network.now=1060
    elif fault=="source-closed":h.source.close()
    with pytest.raises(ValueError):inspector.read_nonmaterial_baseline()
    assert inspector._failed
    calls=len(h.network.calls)+len(h.network.http_calls)
    with pytest.raises(ValueError):inspector.read_nonmaterial_baseline()
    assert calls==len(h.network.calls)+len(h.network.http_calls)
