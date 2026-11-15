"""Only actual original reset M4 can load one private pair for an owned User."""
from dataclasses import asdict
import json

import pytest
from v4_planning import M4AdapterAmbiguous,M4ExecutionAuthorization,M4ExecutionKernel,M4ExecutionPlan,canonical_digest

import fortipam_mcp.local_user_reset_owned_material as module
from fortipam_mcp.local_user_reset_owned_material import LocalResetOwnedMaterialSource,ACTION_ID,ADAPTER_REF,ACTION_VERSION
from fortipam_mcp.local_user_reset_owned_inspector import LocalResetFixtureOwnedInspector
from fortipam_mcp.local_user_reset_http_transport import _dispose_password, LocalUserResetHttpTransportError
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_local_user_reset_fixture_authority import creation
from test_local_user_reset_owned_inspector import readonly
from test_m4_execution_store import _ExternalM4Checkpoint,CHECKPOINT_STORE_REF
from test_v4_execution_kernel import _authorization,_Verifier,REQUESTER,CONFIRMATION,APPROVAL


def authorization(plan):
    values=asdict(_authorization(plan));values.pop("authorization_digest");values["expires_at"]=plan.expires_at
    return M4ExecutionAuthorization(**values,authorization_digest=canonical_digest(values))


class Harness:
    def __init__(self,root,monkeypatch,*,enabled=True,verify_login=False):
        self.verify_login=verify_login
        self.h,_,_,original=creation(root,monkeypatch)
        custody,initial=readonly(self.h,original)
        self.inspector=LocalResetFixtureOwnedInspector(self.h.source,custody,initial)
        self.root=root/"reset";self.root.mkdir(mode=0o700);(self.root/"material").mkdir(mode=0o700)
        for name,value in (("store.key",b"r"*32),("material.key",b"z"*32)):
            path=self.root/name;path.write_bytes(value);path.chmod(0o600)
        self.cp=_ExternalM4Checkpoint()
        self.store=PersistentM4ExecutionStateStore(self.root/"ledger.sqlite",self.root/"store.key",
            monotonic_checkpoint=self.cp,checkpoint_store_ref=CHECKPOINT_STORE_REF)
        self.now=1000;self.seen=False;self.after_acquire=None
        self.material=self.reopen(enabled=enabled)

    def reopen(self,*,enabled=False):
        return LocalResetOwnedMaterialSource(self.inspector,self.h.policy,self.store,directory=self.root/"material",
            witness_key_file=self.root/"material.key",execution_enabled=enabled,verify_login=self.verify_login,clock=lambda:self.now)

    def stage(self):
        self.reference=self.material.stage_once()
        action,adapter,version=self.material._action_contract
        values=dict(plan_ref="owned-reset-material-plan-01",revision=1,action_id=action,action_version=version,
            adapter_ref=adapter,target_ref="bound-local-reset-fixture",requester_digest=REQUESTER,summary_digest="9"*64,
            confirmation_digest=CONFIRMATION,approval_digest=APPROVAL,parameters_digest=self.material.parameters_digest,
            expected_current_digest=self.material.current_digest(),expected_state_digest="2"*64,idempotency_digest="3"*64,
            expires_at=1060,compensation_ref=None)
        self.plan=M4ExecutionPlan(**values,plan_digest=canonical_digest(values));self.auth=authorization(self.plan)

    def read_current(self,plan):return plan.expected_current_digest
    def read_postcondition(self,plan):return plan.expected_state_digest

    def dispatch(self,plan):
        old=new=None
        try:
            lease=self.material.acquire_original(plan,self.auth)
            if self.after_acquire:self.after_acquire()
            old,new=lease._consume()
            assert not old.readonly and not new.readonly and old.obj is not new.obj
            assert old.nbytes>=32 and new.nbytes>=32 and old!=new
            self.seen=True
            with pytest.raises(Exception):lease._consume()
        except (ValueError,LocalUserResetHttpTransportError):raise M4AdapterAmbiguous("Synthetic reset material unavailable.") from None
        finally:
            for view in (old,new):
                if view is not None:_dispose_password(view)

    def execute(self):
        return M4ExecutionKernel(self,_Verifier(),self.store,clock=lambda:self.now).execute(self.plan,self.auth)


def test_original_pair_loaded_only_in_real_m4_and_cleared_without_touching_creation(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch)
    original=h.inspector._original
    before={p.name:p.read_bytes() for p in original._directory.iterdir()}
    reads=[];read=module._read
    def selected(path,limit):reads.append(path.name);return read(path,limit)
    monkeypatch.setattr(module,"_read",selected)
    h.stage()
    assert "initial-password" not in reads and "next-password" not in reads
    assert h.reference not in repr(h.material)
    result=h.execute()
    assert str(result.outcome)=="succeeded" and h.seen and h.store.claim_count==1
    assert reads.count("initial-password")==reads.count("next-password")==1
    assert all(not any(raw) for raw in h.material._buffers)
    assert before=={p.name:p.read_bytes() for p in original._directory.iterdir()}
    assert (h.h.directory/module._FIXTURE_CLAIM).exists()
    assert (h.root/"material"/module._USED).exists()
    h.material.close()
    with pytest.raises(ValueError):h.reopen(enabled=True)
    assert h.reopen().reference==h.reference


def test_default_off_cannot_generate_or_claim(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch,enabled=False)
    with pytest.raises(ValueError):h.material.stage_once()
    assert not list((h.root/"material").iterdir()) and h.store.claim_count==0
    assert not (h.h.directory/module._FIXTURE_CLAIM).exists()


def test_detached_acquisition_never_reads_material_or_writes_fixture_claim(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch);h.stage()
    with pytest.raises(ValueError):h.material.acquire_original(h.plan,h.auth)
    assert h.store.claim_count==0 and not (h.h.directory/module._FIXTURE_CLAIM).exists()
    assert str(h.execute().verification)=="unknown" and not h.seen


@pytest.mark.parametrize("fault",["initial-password","next-password","manifest","key","policy","policy-route","policy-tls","source-expiry","material-expiry","claim"])
def test_tampering_drift_and_expiry_never_deliver_pair(tmp_path,monkeypatch,fault):
    h=Harness(tmp_path,monkeypatch);h.stage()
    if fault=="initial-password":(h.h.directory/"initial-password").write_bytes(b"ForeignSyntheticMaterial123!")
    elif fault=="next-password":(h.root/"material"/"next-password").write_bytes(b"ForeignSyntheticMaterial123!")
    elif fault=="manifest":
        path=h.root/"material"/module._MANIFEST;value=json.loads(path.read_bytes());value["reference"]+="-foreign";path.write_text(json.dumps(value))
    elif fault=="key":(h.root/"material.key").write_bytes(b"q"*32)
    elif fault=="policy":h.h.rules["minimum-length"]=64
    elif fault=="policy-route":h.h.policy._host="foreign.example.test"
    elif fault=="policy-tls":h.h.policy._context.check_hostname=False
    elif fault=="source-expiry":h.h.network.now=1060
    elif fault=="material-expiry":
        h.now=1900
        with pytest.raises(ValueError):h.material.check_staged()
        return
    elif fault=="claim":h.after_acquire=lambda:(h.h.directory/module._FIXTURE_CLAIM).write_text('{}')
    assert str(h.execute().verification)=="unknown" and not h.seen
    assert all(not any(raw) for raw in h.material._buffers)


def test_staged_restart_before_claim_keeps_opaque_reference(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch);h.stage();h.material.close();h.material=h.reopen(enabled=True)
    assert h.material.reference==h.reference and str(h.execute().outcome)=="succeeded"


def test_new_directory_and_new_ledger_cannot_clear_fixture_consumption(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch);h.stage();assert str(h.execute().outcome)=="succeeded"
    root=tmp_path/"different-reset";root.mkdir(mode=0o700);(root/"material").mkdir(mode=0o700)
    for name,value in (("store.key",b"a"*32),("material.key",b"b"*32)):
        path=root/name;path.write_bytes(value);path.chmod(0o600)
    store=PersistentM4ExecutionStateStore(root/"ledger.sqlite",root/"store.key",
        monotonic_checkpoint=_ExternalM4Checkpoint(),checkpoint_store_ref=CHECKPOINT_STORE_REF)
    with pytest.raises(ValueError):LocalResetOwnedMaterialSource(h.inspector,h.h.policy,store,
        directory=root/"material",witness_key_file=root/"material.key",execution_enabled=True)
    assert store.claim_count==0 and not list((root/"material").iterdir())


@pytest.mark.parametrize("field,value",[("parameters_digest","0"*64),("expected_current_digest","0"*64),
    ("action_id","foreign-reset-action"),("adapter_ref","foreign-reset-adapter"),("target_ref","foreign-target")])
def test_actual_m4_cannot_substitute_target_parameters_or_action(tmp_path,monkeypatch,field,value):
    h=Harness(tmp_path,monkeypatch);h.stage();values=asdict(h.plan);values.pop("plan_digest");values[field]=value
    h.plan=M4ExecutionPlan(**values,plan_digest=canonical_digest(values));h.auth=authorization(h.plan)
    assert str(h.execute().verification)=="unknown" and not h.seen
    assert not (h.h.directory/module._FIXTURE_CLAIM).exists()


def test_acquired_but_unused_lease_remains_consumed_across_new_process_inputs(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch);h.stage()
    def interrupt():raise KeyboardInterrupt
    h.after_acquire=interrupt
    with pytest.raises(KeyboardInterrupt):h.execute()
    assert h.store.claim_count==1 and (h.h.directory/module._FIXTURE_CLAIM).exists()
    assert not h.material._buffers
    with pytest.raises(ValueError):h.reopen(enabled=True)
