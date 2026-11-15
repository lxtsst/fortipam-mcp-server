"""Initial custody uses concrete sources and real M4; product IO is synthetic."""
from dataclasses import asdict, replace
import json
import os

import pytest
from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, M4ExecutionPlan, canonical_digest

from fortipam_mcp.local_user_reset_fixture_custody import ACTION_ID, ACTION_VERSION, ADAPTER_REF
from fortipam_mcp.local_user_reset_fixture_material import LocalResetInitialMaterialSource, _generate
from fortipam_mcp.local_user_reset_policy_reader import FortiPamLocalUserResetPolicyReader, LocalUserResetPolicySnapshot
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.secret_metadata_http_transport import _zeroize_mutable
from test_local_user_reset_fixture_sources import make
from test_local_user_reset_policy_reader import Response, Connection, _body
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF
from test_v4_execution_kernel import _authorization, _Verifier, REQUESTER, CONFIRMATION, APPROVAL


class Harness:
    def __init__(self, root, monkeypatch, *, enabled=True):
        self.source, self.network, _ = make(root, monkeypatch)
        self.source.observe_absence()
        self.root = root
        self.directory = self.network.material_directory
        self.rules = {"status": "enable", "min-upper-case-letter": 2, "min-number": 3}
        self.policy_resources = []
        def factory(*args, **kwargs):
            response = Response(_body(fields=self.rules))
            connection = Connection(response)
            self.policy_resources.extend((connection, response))
            return connection
        self.policy = FortiPamLocalUserResetPolicyReader(self.network.config, connection_factory=factory)
        for name, value in (("material.key", b"m" * 32), ("store.key", b"s" * 32)):
            path = root / name; path.write_bytes(value); path.chmod(0o600)
        self.cp = _ExternalM4Checkpoint()
        self.store = PersistentM4ExecutionStateStore(root / "ledger.sqlite", root / "store.key",
            monotonic_checkpoint=self.cp, checkpoint_store_ref=CHECKPOINT_STORE_REF)
        self.now = 1000
        self.material = self.reopen(enabled=enabled)
        self.seen = False
        self.after_acquire = None
        self.wire = self.raw = bytearray()

    def reopen(self, *, enabled=False):
        return LocalResetInitialMaterialSource(self.source, self.policy, self.store, directory=self.directory,
            witness_key_file=self.root / "material.key", execution_enabled=enabled, clock=lambda:self.now)

    def stage(self):
        self.reference = self.material.stage_once()
        values = dict(plan_ref="reset-initial-material-plan-01", revision=1, action_id=ACTION_ID,
            action_version=ACTION_VERSION, adapter_ref=ADAPTER_REF, target_ref="bound-local-reset-fixture",
            requester_digest=REQUESTER, summary_digest="9" * 64, confirmation_digest=CONFIRMATION,
            approval_digest=APPROVAL, parameters_digest=self.material.parameters_digest,
            expected_current_digest=self.source._current.current_digest, expected_state_digest="2" * 64,
            idempotency_digest="3" * 64, expires_at=1060, compensation_ref=None)
        self.plan = M4ExecutionPlan(**values, plan_digest=canonical_digest(values))
        self.auth = _authorization(self.plan)

    def read_current(self, plan): return plan.expected_current_digest

    def dispatch(self, plan):
        lease = None
        try:
            lease = self.material.acquire_original(plan, self.auth)
            self.raw = lease._raw
            if self.after_acquire is not None: self.after_acquire()
            self.wire = self.network.draft._encode(lease._consume())
            self.seen = True
            with pytest.raises(ValueError): lease._consume()
        except ValueError:
            raise M4AdapterAmbiguous("Synthetic material unavailable.") from None
        finally:
            if lease is not None: lease.close()
            _zeroize_mutable(self.wire)

    def read_postcondition(self, plan): return plan.expected_state_digest

    def execute(self):
        return M4ExecutionKernel(self, _Verifier(), self.store, clock=lambda:self.now).execute(self.plan,self.auth)


def test_original_material_is_opaque_one_use_m4_bound_and_cleared(tmp_path, monkeypatch):
    h = Harness(tmp_path,monkeypatch); h.stage()
    assert h.reference.startswith("reset-initial-material-") and len(h.reference) < 128
    assert set(p.name for p in h.directory.iterdir()) == {"initial-password","initial-material.json"}
    assert not hasattr(h.material, "password") and h.reference not in repr(h.material)
    assert h.reopen().reference == h.reference
    result = h.execute()
    assert str(result.outcome) == "succeeded" and h.seen and h.store.claim_count == 1
    assert not any(h.raw) and not any(h.wire)
    assert all(resource.closed for resource in h.policy_resources)
    before = {p.name:p.read_bytes() for p in h.directory.iterdir()}
    h.material.close()
    with pytest.raises(ValueError): h.reopen(enabled=True)
    assert h.reopen().reference == h.reference
    assert before == {p.name:p.read_bytes() for p in h.directory.iterdir()}
    assert all((p.stat().st_mode & 0o777) == 0o600 for p in h.directory.iterdir())


def test_default_off_does_not_generate_files_or_policy_reads(tmp_path, monkeypatch):
    h = Harness(tmp_path,monkeypatch,enabled=False)
    with pytest.raises(ValueError): h.material.stage_once()
    assert not list(h.directory.iterdir()) and not h.policy_resources and h.store.claim_count == 0


def test_detached_acquisition_is_consumed_and_cannot_be_replayed_in_real_dispatch(tmp_path, monkeypatch):
    h = Harness(tmp_path,monkeypatch); h.stage()
    with pytest.raises(ValueError): h.material.acquire_original(h.plan,h.auth)
    assert not (h.directory/"initial-material.used.json").exists()
    assert str(h.execute().verification) == "unknown" and not h.seen


@pytest.mark.parametrize("fault", ["password", "manifest", "key", "mode", "symlink", "hardlink", "policy", "expiry", "source-expiry", "factory", "policy-route", "policy-tls"])
def test_tamper_drift_or_expiry_cannot_deliver_a_lease(tmp_path, monkeypatch, fault):
    h = Harness(tmp_path,monkeypatch); h.stage()
    path = h.directory/"initial-password"
    if fault == "password": path.write_bytes(b"ForeignSyntheticValue123!")
    elif fault == "manifest":
        value=json.loads((h.directory/"initial-material.json").read_bytes()); value["reference"] += "-foreign"
        (h.directory/"initial-material.json").write_text(json.dumps(value))
    elif fault == "key": (h.root/"material.key").write_bytes(b"z"*32)
    elif fault == "mode": path.chmod(0o644)
    elif fault in {"symlink","hardlink"}:
        saved=h.root/"saved";path.rename(saved)
        if fault=="symlink": path.symlink_to(saved)
        else: os.link(saved,path)
    elif fault == "policy": h.rules["minimum-length"] = 64
    elif fault == "expiry": h.now=2800
    elif fault == "source-expiry": h.network.now=1060
    elif fault == "factory": h.policy._factory=lambda *args,**kwargs:None
    elif fault == "policy-route": h.policy._host="foreign.example.test"
    elif fault == "policy-tls": h.policy._context.check_hostname=False
    if fault == "expiry":
        with pytest.raises(ValueError): h.material.check_staged()
    else:
        result=h.execute()
        assert str(result.verification) == "unknown"
    assert not h.seen and not any(h.raw)


@pytest.mark.parametrize("field,value", [("parameters_digest","0"*64), ("action_version","1.0.0"),
    ("adapter_ref","foreign-adapter"), ("target_ref","foreign-target"), ("expected_current_digest","0"*64)])
def test_even_actual_m4_rejects_foreign_plan_binding(tmp_path, monkeypatch, field, value):
    h=Harness(tmp_path,monkeypatch);h.stage()
    values=asdict(h.plan);values.pop("plan_digest");values[field]=value
    h.plan=M4ExecutionPlan(**values,plan_digest=canonical_digest(values));h.auth=_authorization(h.plan)
    assert str(h.execute().verification)=="unknown" and not h.seen


def test_policy_drift_after_acquire_clears_retained_view_before_wire_encoding(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch);h.stage()
    h.after_acquire=lambda:h.rules.update({"minimum-length":64})
    assert str(h.execute().verification)=="unknown" and not h.seen and not any(h.raw)
    assert (h.directory/"initial-material.used.json").exists()


def test_staged_material_restart_before_claim_retains_original_reference(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch);h.stage();h.material.close()
    h.material=h.reopen(enabled=True)
    assert h.material.reference==h.reference
    assert str(h.execute().outcome)=="succeeded" and h.seen


def test_partial_generation_and_policy_read_drift_remain_unusable(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch)
    original=h.policy.read_policy_snapshot;calls=0
    def drift():
        nonlocal calls
        calls+=1
        if calls==2:h.rules["minimum-length"]=64
        return original()
    monkeypatch.setattr(h.policy,"read_policy_snapshot",drift)
    with pytest.raises(ValueError):h.material.stage_once()
    assert not list(h.directory.iterdir()) and h.material._closed and h.store.claim_count==0


@pytest.mark.parametrize("counts", [(1,2,3,4), (20,20,20,20), (100,1,1,1), (200,0,0,0)])
def test_generation_respects_bounded_native_rules_without_decoding(counts):
    policy=LocalUserResetPolicySnapshot(8,0,*counts,"enable","enable","disable")
    if sum(max(1,c) for c in counts)>128:
        with pytest.raises(ValueError):_generate(policy)
    else:
        raw=_generate(policy)
        try:
            assert 32<=len(raw)<=128
            assert all(sum(value in group for value in raw)>=minimum for group,minimum in zip(
                (b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",b"abcdefghijklmnopqrstuvwxyz",b"0123456789",b"!@#%^*-_"),counts,strict=True))
        finally:_zeroize_mutable(raw)


def test_opaque_reference_changes_parameters_without_material_hash(tmp_path,monkeypatch):
    from fortipam_mcp.local_user_reset_fixture_custody import initial_create_parameters_digest
    h=Harness(tmp_path,monkeypatch);h.stage()
    assert h.material.parameters_digest != initial_create_parameters_digest(h.network.draft.nonmaterial_request_digest,h.reference+"-other")
