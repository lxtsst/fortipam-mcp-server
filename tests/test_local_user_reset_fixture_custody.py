"""Original reset-fixture ACK custody uses the real persistent M4 boundary."""
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, M4ExecutionPlan, canonical_digest

from fortipam_mcp.local_user_reset_fixture_custody import (
    ACTION_ID, ADAPTER_REF, ACTION_VERSION, LocalResetFixtureAckCustody, LocalResetFixtureAckPins,
    initial_create_parameters_digest,
)
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF
from test_v4_execution_kernel import _authorization, _Verifier, REQUESTER, CONFIRMATION, APPROVAL

NAME = "mcp-v4-user-reset-original-fixture"
SERIAL = "SYNTHETIC01"


class Harness:
    def __init__(self, root, *, enabled=True, request_digest="f" * 64, actor_context_digest="8" * 64):
        self.root = root
        (root / "state").mkdir(mode=0o700)
        for name, value in (("store.key", b"e" * 32), ("witness.key", b"w" * 32)):
            (root / name).write_bytes(value); (root / name).chmod(0o600)
        self.cp = _ExternalM4Checkpoint()
        self.store = PersistentM4ExecutionStateStore(root / "ledger.sqlite", root / "store.key",
            monotonic_checkpoint=self.cp, checkpoint_store_ref=CHECKPOINT_STORE_REF)
        material_ref = "reset-initial-material-synthetic"
        fields = dict(plan_ref="reset-fixture-original-plan-01", revision=1, action_id=ACTION_ID, action_version=ACTION_VERSION,
            adapter_ref=ADAPTER_REF, target_ref="bound-local-reset-fixture", requester_digest=REQUESTER,
            summary_digest="9" * 64, confirmation_digest=CONFIRMATION, approval_digest=APPROVAL,
            parameters_digest=initial_create_parameters_digest(request_digest, material_ref), expected_current_digest="1" * 64, expected_state_digest="2" * 64,
            idempotency_digest="3" * 64, expires_at=1300, compensation_ref=None)
        self.plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
        self.auth = _authorization(self.plan)
        self.pins = LocalResetFixtureAckPins(NAME, hashlib.sha256(SERIAL.encode()).hexdigest(), REQUESTER,
            actor_context_digest, self.plan.expected_current_digest, request_digest, material_ref,
            self.plan.plan_digest, self.auth.authorization_digest, "7" * 64)
        self.pin_path = root / "constructor.private.json"
        self.pin_path.write_text(json.dumps(dict(pins=asdict(self.pins), plan=asdict(self.plan), authorization=asdict(self.auth), vdom="root"))); self.pin_path.chmod(0o600)
        self.now = 1000
        self.custody = self.reopen(enabled=enabled)
        self.sends = 0
        self.raw = bytearray()

    def reopen(self, *, enabled=False):
        return LocalResetFixtureAckCustody(directory=self.root / "state", packet_file=self.pin_path,
            witness_key_file=self.root / "witness.key", plan=self.plan, authorization=self.auth,
            store=self.store, expected_vdom="root", execution_enabled=enabled, clock=lambda: self.now)

    def read_current(self, plan):
        return plan.expected_current_digest

    def dispatch(self, plan):
        try:
            self.custody.begin_original_send(); self.sends += 1
            self.raw = response()
            self.custody.capture_original_ack(self.raw, http_status=200, content_type="application/json; charset=UTF-8")
        except ValueError:
            raise M4AdapterAmbiguous("Synthetic original ACK unavailable.") from None

    def read_postcondition(self, plan):
        if self.unknown: raise M4AdapterAmbiguous("Synthetic postcondition unavailable.")
        return plan.expected_state_digest

    def execute(self, *, unknown=False):
        self.unknown = unknown
        return M4ExecutionKernel(self, _Verifier(), self.store, clock=lambda: self.now).execute(self.plan, self.auth)


def response(**updates):
    value = dict(version="v7.0.0", build=29, http_method="POST", http_status=200,
        status="success", path="system", name="admin", vdom="root", serial=SERIAL,
        mkey=NAME, revision_changed=True, old_revision="synthetic-before", revision="synthetic-after")
    value.update(updates)
    return bytearray(json.dumps(value, separators=(",", ":")).encode())


@pytest.mark.parametrize("unknown", [False, True])
def test_persisted_constructor_and_original_ack_survive_expiry_without_promoting_result(tmp_path, unknown):
    h = Harness(tmp_path)
    result = h.execute(unknown=unknown)
    assert str(result.outcome) == ("reconciliation_required" if unknown else "succeeded")
    original = h.custody.inspect_original_ack()
    assert original.original_verification == ("unknown" if unknown else "verified")
    before = {p.name: p.read_bytes() for p in (tmp_path / "state").iterdir()}
    assert set(before) == {"original-send.json", "original-ack.json"}
    assert NAME.encode() not in b"".join(before.values()) and SERIAL.encode() not in b"".join(before.values())
    assert not h.raw and h.sends == h.store.claim_count == 1
    h.now = 5000; h.custody.close()
    reopened = h.reopen()
    assert reopened.inspect_original_ack() == original
    assert {p.name: p.read_bytes() for p in (tmp_path / "state").iterdir()} == before
    with pytest.raises(ValueError): reopened.begin_original_send()
    assert h.store.claim_count == 1
    with pytest.raises(ValueError): reopened.inspect_original_full_state()


def test_default_off_and_detached_dispatch_cannot_write_custody(tmp_path):
    h = Harness(tmp_path, enabled=False)
    enabled = h.reopen(enabled=True)
    with pytest.raises(ValueError): enabled.begin_original_send()
    result = h.execute()
    assert str(result.outcome) != "succeeded" and h.sends == 0 and not list((tmp_path / "state").iterdir())
    with pytest.raises(ValueError): h.reopen(enabled=True)
    assert not list((tmp_path / "state").iterdir())


@pytest.mark.parametrize("fault", ["missing", "mode", "symlink", "hardlink", "nonce", "foreign-plan", "extra", "duplicate"])
def test_missing_unsafe_changed_or_foreign_constructor_pins_fail_before_claim(tmp_path, fault):
    h = Harness(tmp_path)
    if fault == "missing": h.pin_path.unlink()
    elif fault == "mode": h.pin_path.chmod(0o644)
    elif fault in {"symlink", "hardlink"}:
        target = h.pin_path.with_suffix(".saved"); h.pin_path.rename(target)
        if fault == "symlink": h.pin_path.symlink_to(target)
        else: os.link(target, h.pin_path)
    else:
        value = json.loads(h.pin_path.read_bytes())
        if fault == "nonce": value["pins"]["private_nonce"] = "invalid"
        if fault == "foreign-plan": value["pins"]["plan_digest"] = "0" * 64
        if fault == "extra": value["unqualified"] = "private-value"
        wire = json.dumps(value)
        if fault == "duplicate": wire = wire[:-1] + ',"username":"another"}'
        h.pin_path.write_text(wire)
    with pytest.raises(ValueError): h.reopen()
    assert h.store.claim_count == 0
    with pytest.raises(ValueError): h.custody.inspect_original_ack()


@pytest.mark.parametrize("updates", [dict(mkey=NAME + "-other"), dict(serial="OTHER"), dict(status="OK"),
    dict(http_method="DELETE"), dict(results={}), dict(action=""), dict(error=0), dict(revision_changed=False)])
def test_wrong_or_ambiguous_original_response_is_consumed_without_ack(tmp_path, monkeypatch, updates):
    h = Harness(tmp_path)
    monkeypatch.setitem(globals(), "response", lambda: response_original(**updates))
    result = h.execute()
    assert str(result.verification) == "unknown" and h.sends == h.store.claim_count == 1 and not h.raw
    assert (tmp_path / "state/original-send.json").exists()
    assert not (tmp_path / "state/original-ack.json").exists()
    with pytest.raises(ValueError): h.custody.inspect_original_ack()
    with pytest.raises(ValueError): h.reopen(enabled=True).begin_original_send()


response_original = response


def test_staged_key_or_constructor_tampering_blocks_original_capture(tmp_path, monkeypatch):
    h = Harness(tmp_path)
    begin = h.custody.begin_original_send
    def corrupt_after_claim():
        begin()
        (tmp_path / "witness.key").write_bytes(b"z" * 32)
    monkeypatch.setattr(h.custody, "begin_original_send", corrupt_after_claim)
    result = h.execute()
    assert str(result.verification) == "unknown" and h.sends == 1 and not h.raw
    assert not (tmp_path / "state/original-ack.json").exists()


def test_serialized_pins_reconstruct_only_original_context_not_authority(tmp_path):
    h = Harness(tmp_path)
    h.execute()
    before = h.custody.inspect_original_ack()
    value = json.loads(h.pin_path.read_bytes()); value["pins"]["private_nonce"] = "6" * 64
    h.pin_path.write_text(json.dumps(value))
    with pytest.raises(ValueError): h.custody.inspect_original_ack()
    changed = h.reopen()
    with pytest.raises(ValueError): changed.inspect_original_ack()
    assert before.original_outcome == "succeeded" and h.store.claim_count == 1


@pytest.mark.parametrize("after_ack", [False, True])
def test_interruption_cannot_be_completed_by_a_restarted_custodian(tmp_path, after_ack):
    h = Harness(tmp_path)
    def interrupted(plan):
        h.custody.begin_original_send(); h.sends += 1
        if after_ack:
            h.custody.capture_original_ack(response(), http_status=200, content_type="application/json")
        raise KeyboardInterrupt
    h.dispatch = interrupted
    with pytest.raises(KeyboardInterrupt): h.execute()
    assert h.store.claim_count == h.sends == 1
    restarted = h.reopen()
    if after_ack:
        observed = restarted.inspect_original_ack()
        assert observed.original_outcome == "in_progress" and observed.original_verification == "unknown"
    else:
        with pytest.raises(ValueError): restarted.inspect_original_ack()
    raw = response()
    with pytest.raises(ValueError): restarted.capture_original_ack(raw, http_status=200, content_type="application/json")
    assert not raw
    with pytest.raises(ValueError): h.reopen(enabled=True)


def test_independent_process_reconstructs_only_persisted_packet_and_reads_original_unknown(tmp_path):
    h = Harness(tmp_path)
    h.execute(unknown=True)
    original = h.custody.inspect_original_ack()
    script = '''
import json,sys
from pathlib import Path
from v4_planning import M4ExecutionPlan,M4ExecutionAuthorization
from fortipam_mcp.local_user_reset_fixture_custody import LocalResetFixtureAckCustody
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore,M4ExecutionStoreTail
from test_m4_execution_store import _ExternalM4Checkpoint,CHECKPOINT_STORE_REF
root=Path(sys.argv[1]);packet=json.loads((root/'constructor.private.json').read_bytes())
cp=_ExternalM4Checkpoint();cp.tail=M4ExecutionStoreTail(cp.tail.store_ref,int(sys.argv[2]),sys.argv[3])
store=PersistentM4ExecutionStateStore(root/'ledger.sqlite',root/'store.key',read_only=True,
    monotonic_checkpoint=cp,checkpoint_store_ref=CHECKPOINT_STORE_REF)
custody=LocalResetFixtureAckCustody(directory=root/'state',packet_file=root/'constructor.private.json',
    witness_key_file=root/'witness.key',plan=M4ExecutionPlan(**packet['plan']),
    authorization=M4ExecutionAuthorization(**packet['authorization']),store=store,expected_vdom=packet['vdom'],clock=lambda:5000)
observed=custody.inspect_original_ack()
assert observed.original_outcome=='reconciliation_required' and observed.original_verification=='unknown'
assert store.claim_count==1 and not custody._enabled
print(observed.custody_digest)
'''
    env = {**os.environ, "PYTHONPATH": os.pathsep.join((str(Path(__file__).parent), os.environ.get("PYTHONPATH", "")))}
    child = subprocess.run([sys.executable, "-c", script, str(tmp_path), str(h.cp.tail.sequence), h.cp.tail.chain_hmac],
        env=env, text=True, capture_output=True, timeout=20)
    assert child.returncode == 0, child.stderr
    assert child.stdout.strip() == original.custody_digest
    assert h.store.claim_count == 1
