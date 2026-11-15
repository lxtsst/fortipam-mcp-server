"""Synthetic original Job ACK custody through the real persistent M4 kernel."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from threading import Event, Thread

import pytest
from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, M4ExecutionPlan, canonical_digest

from fortipam_mcp.job_definition_ack_custody import (
    ACTION_ID, ADAPTER_REF, JobDefinitionAckCustody, JobDefinitionAckCustodyError,
)
from fortipam_mcp.job_definition_create_contract import DisabledJobCreateAckPins
from fortipam_mcp.m4_execution_store import M4ExecutionStoreTail, PersistentM4ExecutionStateStore
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF
from test_v4_execution_kernel import _authorization, _Verifier, REQUESTER, CONFIRMATION, APPROVAL


def components(root, checkpoint=None, *, now=1000, read_only=False,
               body_digest="8" * 64, serial_digest=None, job_name="mcp-v4-bp008-job-20261021-r99",
               expected_state_digest="2" * 64, expected_current_digest="1" * 64):
    checkpoint = checkpoint or _ExternalM4Checkpoint()
    store = PersistentM4ExecutionStateStore(root / "execution.sqlite", root / "execution.key",
        monotonic_checkpoint=checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF, read_only=read_only)
    fields = dict(plan_ref="disabled-job-original-plan-01", revision=1, action_id=ACTION_ID,
        action_version="1.0.0", adapter_ref=ADAPTER_REF, target_ref="bound-disabled-job",
        requester_digest=REQUESTER, summary_digest="9" * 64, confirmation_digest=CONFIRMATION,
        approval_digest=APPROVAL, parameters_digest=body_digest, expected_current_digest=expected_current_digest,
        expected_state_digest=expected_state_digest, idempotency_digest="3" * 64, expires_at=1300,
        compensation_ref=None)
    plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
    auth = _authorization(plan)
    pins = DisabledJobCreateAckPins(job_name,
        serial_digest or hashlib.sha256(b"synthetic-appliance").hexdigest(), REQUESTER, plan.parameters_digest,
        plan.plan_digest, auth.authorization_digest, "7" * 64)
    custody = JobDefinitionAckCustody(root / "custody", root / "ack.key", pins, plan, auth, store,
                                    clock=lambda: now)
    return custody, store, plan, auth, pins, checkpoint


def create(root):
    root.chmod(0o700)
    (root / "custody").mkdir(mode=0o700)
    for name, value in (("execution.key", b"e" * 32), ("ack.key", b"a" * 32)):
        (root / name).write_bytes(value)
        (root / name).chmod(0o600)
    return components(root)


def ack(pins, *, serial="synthetic-appliance"):
    return bytearray(json.dumps(dict(version="v7.0.0", build=29, http_method="POST", http_status=200,
        status="success", path="secret", name="job", vdom="root", serial=serial,
        mkey=pins.job_name, error=0), separators=(",", ":")).encode())


class Adapter:
    def __init__(self, custody, pins, *, fault="none", serial="synthetic-appliance"):
        self.custody, self.pins, self.fault = custody, pins, fault
        self.serial = serial
        self.sends = 0
        self.raw = None

    def read_current(self, plan): return plan.expected_current_digest

    def dispatch(self, plan):
        try:
            self.custody.begin_original_send()
            self.sends += 1
            if self.fault == "crash-before-ack": raise KeyboardInterrupt
            self.raw = ack(self.pins, serial=self.serial)
            if self.fault == "wrong-ack": self.raw = bytearray(b'{"status":"error"}')
            self.custody.capture_original_ack(self.raw, http_status=200, content_type="application/json")
            if self.fault == "crash-after-ack": raise KeyboardInterrupt
        except JobDefinitionAckCustodyError:
            raise M4AdapterAmbiguous("Synthetic custody failure.") from None

    def read_postcondition(self, plan):
        if self.fault == "post-read-unknown": raise M4AdapterAmbiguous("Synthetic unavailable read.")
        return plan.expected_state_digest


def execute(c, store, plan, auth, pins, *, fault="none", serial="synthetic-appliance"):
    adapter = Adapter(c, pins, fault=fault, serial=serial)
    result = M4ExecutionKernel(adapter, _Verifier(), store, clock=lambda: 1000).execute(plan, auth)
    return adapter, result


def test_original_ack_survives_independent_process_after_expiry_without_replay_or_promotion(tmp_path):
    c, store, p, a, pins, checkpoint = create(tmp_path)
    adapter, result = execute(c, store, p, a, pins)
    assert result.outcome == "succeeded" and adapter.sends == 1 and not any(adapter.raw)
    original = c.inspect_original_ack()
    before = {f.name: f.read_bytes() for f in (tmp_path / "custody").iterdir()}
    assert set(before) == {"send.claim.json", "create-ack.json"}
    assert b"20261021" not in b"".join(before.values()) and b"synthetic-appliance" not in b"".join(before.values())
    script = """
import sys
from pathlib import Path
from test_job_definition_ack_custody import components
from test_m4_execution_store import _ExternalM4Checkpoint
from fortipam_mcp.m4_execution_store import M4ExecutionStoreTail
checkpoint = _ExternalM4Checkpoint()
checkpoint.tail = M4ExecutionStoreTail(checkpoint.tail.store_ref, int(sys.argv[2]), sys.argv[3])
c, store, *_ = components(Path(sys.argv[1]), checkpoint, now=2000, read_only=True)
observed = c.inspect_original_ack()
assert observed.original_outcome == "succeeded" and observed.original_verification == "verified"
assert store.claim_count == 1
print(observed.custody_digest)
"""
    env = {**os.environ, "PYTHONPATH": os.pathsep.join((str(Path(__file__).parent), os.environ.get("PYTHONPATH", "")))}
    child = subprocess.run([sys.executable, "-c", script, str(tmp_path), str(checkpoint.tail.sequence),
        checkpoint.tail.chain_hmac], env=env, text=True, capture_output=True, timeout=20)
    assert child.returncode == 0, child.stderr
    assert child.stdout.strip() == original.custody_digest
    rebuilt, reopened, *_ = components(tmp_path, checkpoint)
    replay_adapter, replay = execute(rebuilt, reopened, p, a, pins)
    assert replay.idempotent_replay is True and replay_adapter.sends == 0 and store.claim_count == 1
    assert {f.name: f.read_bytes() for f in (tmp_path / "custody").iterdir()} == before


@pytest.mark.parametrize("fault", ["wrong-ack", "crash-before-ack", "crash-after-ack", "post-read-unknown"])
def test_interrupted_create_stays_unknown_and_cannot_capture_ack_after_restart(tmp_path, fault):
    c, store, p, a, pins, checkpoint = create(tmp_path)
    if fault.startswith("crash"):
        with pytest.raises(KeyboardInterrupt): execute(c, store, p, a, pins, fault=fault)
    else:
        _, result = execute(c, store, p, a, pins, fault=fault)
        assert result.outcome == "reconciliation_required"
    rebuilt, reopened, *_ = components(tmp_path, checkpoint, now=2000, read_only=True)
    if fault in {"crash-after-ack", "post-read-unknown"}:
        observed = rebuilt.inspect_original_ack()
        assert observed.original_outcome == ("in_progress" if fault.startswith("crash") else "reconciliation_required")
        assert observed.original_verification == "unknown"
    else:
        with pytest.raises(JobDefinitionAckCustodyError): rebuilt.inspect_original_ack()
    raw = ack(pins)
    with pytest.raises(JobDefinitionAckCustodyError):
        rebuilt.capture_original_ack(raw, http_status=200, content_type="application/json")
    assert not any(raw) and reopened.claim_count == 1


def test_reservation_or_matching_ack_without_original_active_dispatch_cannot_write(tmp_path):
    c, store, p, a, pins, checkpoint = create(tmp_path)
    store.claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest, idempotency_digest=p.idempotency_digest,
        authorization_digest=a.authorization_digest, context_digest=canonical_digest({"plan_digest": p.plan_digest,
            "authorization_digest": a.authorization_digest, "revision": p.revision}))
    with pytest.raises(JobDefinitionAckCustodyError): c.begin_original_send()
    raw = ack(pins)
    with pytest.raises(JobDefinitionAckCustodyError):
        c.capture_original_ack(raw, http_status=200, content_type="application/json")
    assert not any(raw) and list((tmp_path / "custody").iterdir()) == []


def test_second_instance_cannot_adopt_original_send_even_inside_same_dispatch(tmp_path):
    c, store, p, a, pins, checkpoint = create(tmp_path)
    clone, *_ = components(tmp_path, checkpoint)

    class CloningAdapter(Adapter):
        def dispatch(self, plan):
            c.begin_original_send()
            with pytest.raises(JobDefinitionAckCustodyError): clone.begin_original_send()
            raw = ack(pins)
            with pytest.raises(JobDefinitionAckCustodyError):
                clone.capture_original_ack(raw, http_status=200, content_type="application/json")
            assert not any(raw)
            c.capture_original_ack(ack(pins), http_status=200, content_type="application/json")

    result = M4ExecutionKernel(CloningAdapter(c, pins), _Verifier(), store, clock=lambda: 1000).execute(p, a)
    assert result.outcome == "succeeded" and c.inspect_original_ack().original_outcome == "succeeded"


@pytest.mark.parametrize("fault", ["tamper", "duplicate", "missing-ack", "unsafe-mode", "hardlink",
    "symlink", "different-key", "replaced-directory", "rolled-back-checkpoint"])
def test_untrusted_or_incomplete_custody_is_never_original_ack_evidence(tmp_path, fault):
    c, store, p, a, pins, checkpoint = create(tmp_path)
    execute(c, store, p, a, pins)
    path = tmp_path / "custody" / "create-ack.json"
    if fault == "tamper":
        record = json.loads(path.read_text()); record["acknowledgement_digest"] = "f" * 64
        path.write_text(json.dumps(record))
    if fault == "duplicate": path.write_bytes(path.read_bytes()[:-1] + b',"signature":"duplicate"}')
    if fault == "missing-ack": path.unlink()
    if fault == "unsafe-mode": path.chmod(0o644)
    if fault == "hardlink": os.link(path, tmp_path / "duplicate")
    if fault == "symlink":
        path.rename(tmp_path / "moved"); path.symlink_to(tmp_path / "moved")
    if fault == "different-key": (tmp_path / "ack.key").write_bytes(b"x" * 32)
    if fault == "replaced-directory":
        (tmp_path / "custody").rename(tmp_path / "old")
        (tmp_path / "custody").mkdir(mode=0o700)
        for old in (tmp_path / "old").iterdir():
            new = tmp_path / "custody" / old.name; new.write_bytes(old.read_bytes()); new.chmod(0o600)
    if fault == "rolled-back-checkpoint": checkpoint.tail = M4ExecutionStoreTail.empty(CHECKPOINT_STORE_REF)
    with pytest.raises(JobDefinitionAckCustodyError): c.inspect_original_ack()


def test_parent_fsync_failure_preserves_consumed_send_and_prevents_ack_fill(tmp_path, monkeypatch):
    c, store, p, a, pins, checkpoint = create(tmp_path)
    original = os.fsync
    def fail_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode): raise OSError("Synthetic directory sync failure")
        return original(fd)
    monkeypatch.setattr(os, "fsync", fail_directory)
    _, result = execute(c, store, p, a, pins)
    assert result.outcome == "reconciliation_required"
    assert (tmp_path / "custody" / "send.claim.json").exists()
    assert not (tmp_path / "custody" / "create-ack.json").exists()
    with pytest.raises(JobDefinitionAckCustodyError): c.inspect_original_ack()


def test_ack_directory_fsync_failure_keeps_unknown_without_rewriting_receipt(tmp_path, monkeypatch):
    c, store, p, a, pins, checkpoint = create(tmp_path)
    original, directory_syncs = os.fsync, []
    def fail_second_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_syncs.append(fd)
            if len(directory_syncs) == 2: raise OSError("Synthetic ACK directory sync failure")
        return original(fd)
    monkeypatch.setattr(os, "fsync", fail_second_directory)
    adapter, result = execute(c, store, p, a, pins)
    assert result.outcome == "reconciliation_required" and not any(adapter.raw)
    before = (tmp_path / "custody" / "create-ack.json").read_bytes()
    observed = c.inspect_original_ack()
    assert observed.original_outcome == "reconciliation_required" and observed.original_verification == "unknown"
    raw = ack(pins)
    with pytest.raises(JobDefinitionAckCustodyError):
        c.capture_original_ack(raw, http_status=200, content_type="application/json")
    assert not any(raw) and (tmp_path / "custody" / "create-ack.json").read_bytes() == before
    assert store.claim_count == 1


def test_expired_capture_closes_writer_even_if_clock_later_moves_back(tmp_path):
    c, store, p, a, pins, checkpoint = create(tmp_path)

    class ExpiringAdapter(Adapter):
        def dispatch(self, plan):
            c.begin_original_send()
            c._clock = lambda: 2000
            raw = ack(pins)
            with pytest.raises(JobDefinitionAckCustodyError):
                c.capture_original_ack(raw, http_status=200, content_type="application/json")
            assert not any(raw)
            c._clock = lambda: 1000
            with pytest.raises(JobDefinitionAckCustodyError):
                c.capture_original_ack(ack(pins), http_status=200, content_type="application/json")
            raise M4AdapterAmbiguous("Synthetic expired ACK capture.")

    result = M4ExecutionKernel(ExpiringAdapter(c, pins), _Verifier(), store, clock=lambda: 1000).execute(p, a)
    assert result.outcome == "reconciliation_required"
    assert not (tmp_path / "custody" / "create-ack.json").exists()


def test_custody_rejects_wrong_m4_context_and_key_reuse(tmp_path):
    c, store, p, a, pins, checkpoint = create(tmp_path)
    for bad in (replace(pins, body_digest="f" * 64), replace(pins, requester_digest="f" * 64),
                replace(pins, plan_digest="f" * 64), replace(pins, authorization_digest="f" * 64)):
        with pytest.raises(JobDefinitionAckCustodyError):
            JobDefinitionAckCustody(tmp_path / "custody", tmp_path / "ack.key", bad, p, a, store)
    with pytest.raises(JobDefinitionAckCustodyError):
        JobDefinitionAckCustody(tmp_path / "custody", tmp_path / "execution.key", pins, p, a, store)


def joined_components(root, reader, *, expected_state=None, **changes):
    create(root)
    body, serial, timeout = reader._bound_definition_digests()
    expected = canonical_digest({"contract": "disabled-job-pristine-state-build29/v1",
        "body_digest": body, "serial_digest": serial, "timeout_digest": timeout})
    options = dict(body_digest=body, serial_digest=serial, job_name=reader._name,
                   expected_state_digest=expected if expected_state is None else expected_state)
    options.update(changes)
    return components(root, **options)


@pytest.mark.parametrize("fault", ["none", "post-read-unknown"])
def test_original_ack_joins_real_owner_pristine_reader_without_promoting_unknown(tmp_path, fault):
    from test_job_definition_detail_reader import _reader, SERIAL
    reader, owner, calls = _reader(pristine=True)
    c, store, p, a, pins, _ = joined_components(tmp_path, reader)
    _, result = execute(c, store, p, a, pins, fault=fault, serial=SERIAL)
    audits = store.audit_events
    records = {f.name: f.read_bytes() for f in (tmp_path / "custody").iterdir()}
    joined = c.inspect_acknowledged_pristine(reader)
    assert joined.state_digest == p.expected_state_digest
    assert joined.original_ack.original_outcome == str(result.outcome)
    assert joined.original_ack.original_verification == str(result.verification)
    assert owner.logout_verified and store.claim_count == 1 and store.audit_events == audits
    assert not any(method == "DELETE" for method, _ in calls)
    assert {f.name: f.read_bytes() for f in (tmp_path / "custody").iterdir()} == records


@pytest.mark.parametrize("fault", ["different-body", "different-device", "different-job", "unbound-timeout",
    "changed-timeout", "changed-approval", "changed-expected-body", "missing-ack"])
def test_matching_state_without_original_exact_context_refuses_before_owner_login(tmp_path, fault):
    from test_job_definition_detail_reader import _reader, SERIAL
    reader, _, calls = _reader(pristine=True)
    changes = {}
    if fault == "different-body": changes["body_digest"] = "f" * 64
    if fault == "different-device":
        changes["serial_digest"] = hashlib.sha256(b"synthetic-appliance").hexdigest()
    if fault == "different-job": changes["job_name"] = "mcp-v4-bp008-job-20261021-r98"
    if fault == "unbound-timeout": changes["expected_state"] = "f" * 64
    c, store, p, a, pins, _ = joined_components(tmp_path, reader, **changes)
    native_serial = "synthetic-appliance" if fault == "different-device" else SERIAL
    if fault != "missing-ack":
        execute(c, store, p, a, pins, serial=native_serial)
    if fault == "changed-timeout": reader._expected_tokens["max-timeout"] = b"1"
    if fault == "changed-approval": reader._expected_tokens["approval-status"] = b'"pending"'
    if fault == "changed-expected-body": reader._expected_tokens["status"] = b'"enable"'
    with pytest.raises(JobDefinitionAckCustodyError): c.inspect_acknowledged_pristine(reader)
    assert calls == []


@pytest.mark.parametrize("field,value", [("q_ref", 1), ("q_static", True), ("status", "enable"),
    ("max-timeout", 1), ("secret", 1000)])
def test_ack_provenance_does_not_override_current_job_drift(tmp_path, field, value):
    from test_job_definition_detail_reader import _reader, _payload, SERIAL
    payload = _payload(); payload["results"][field] = value
    reader, owner, _ = _reader(payload=payload, pristine=True)
    c, store, p, a, pins, _ = joined_components(tmp_path, reader)
    execute(c, store, p, a, pins, serial=SERIAL)
    original = c.inspect_original_ack()
    with pytest.raises(JobDefinitionAckCustodyError): c.inspect_acknowledged_pristine(reader)
    assert owner.logout_verified and c.inspect_original_ack() == original and store.claim_count == 1


def test_original_m4_transition_during_pristine_read_invalidates_join(tmp_path, monkeypatch):
    from test_job_definition_detail_reader import _reader, SERIAL
    reader, owner, _ = _reader(pristine=True)
    c, store, p, a, pins, _ = joined_components(tmp_path, reader)
    captured, release = Event(), Event()
    results = []
    class DelayedAdapter(Adapter):
        def read_postcondition(self, plan):
            captured.set()
            assert release.wait(5)
            return plan.expected_state_digest
    adapter = DelayedAdapter(c, pins, serial=SERIAL)
    worker = Thread(target=lambda: results.append(M4ExecutionKernel(adapter, _Verifier(), store,
        clock=lambda: 1000).execute(p, a)))
    original = reader.read_pristine
    def read_and_finish():
        state = original()
        release.set(); worker.join(5)
        assert not worker.is_alive() and results[0].outcome == "succeeded"
        return state
    monkeypatch.setattr(reader, "read_pristine", read_and_finish)
    worker.start()
    try:
        assert captured.wait(5)
        with pytest.raises(JobDefinitionAckCustodyError): c.inspect_acknowledged_pristine(reader)
        assert owner.logout_verified and c.inspect_original_ack().original_outcome == "succeeded"
    finally:
        release.set(); worker.join(5)
