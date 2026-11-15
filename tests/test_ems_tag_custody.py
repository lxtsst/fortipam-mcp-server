"""Real durable M4 with synthetic EMS replies; never device acceptance."""
from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest
from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, M4ExecutionPlan, canonical_digest

from fortipam_mcp.ems_tag_contract import (
    DisabledLinuxProcessTag, EmsTagFullScope, create_current_digest, create_expected_digest,
    qualify_tag_catalog, qualify_tag_detail,
)
from fortipam_mcp.ems_tag_custody import (
    ACTION_ID, ADAPTER_REF, TARGET_REF, EmsTagOriginalCustody, EmsTagCustodyError, EmsTagOriginalActorBinding,
)
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_ems_tag_contract import detail, envelope, full_scope
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF
from test_v4_execution_kernel import _authorization, _Verifier, REQUESTER, CONFIRMATION, APPROVAL


def components(root: Path, *, checkpoint=None, read_only: bool = False, now: int = 1000,
               baseline: EmsTagFullScope | None = None, source: str = "7" * 64):
    baseline = baseline or full_scope()
    checkpoint = checkpoint or _ExternalM4Checkpoint()
    store = PersistentM4ExecutionStateStore(root / "execution.sqlite", root / "execution.key",
        monotonic_checkpoint=checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF, read_only=read_only)
    draft = DisabledLinuxProcessTag("a" * 32)
    fields = dict(plan_ref="ems-disabled-tag-original-plan-01", revision=1, action_id=ACTION_ID,
        action_version="1.0.0", adapter_ref=ADAPTER_REF, target_ref=TARGET_REF,
        requester_digest=REQUESTER, summary_digest="9" * 64, confirmation_digest=CONFIRMATION,
        approval_digest=APPROVAL, parameters_digest=draft.parameters_digest,
        expected_current_digest=create_current_digest(draft, baseline.digest, source),
        expected_state_digest=create_expected_digest(draft, baseline.digest, source),
        idempotency_digest="3" * 64, expires_at=1300, compensation_ref=None)
    plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
    auth = _authorization(plan)
    custody = EmsTagOriginalCustody(root / "custody", root / "custody.key", draft, baseline.digest,
        plan, auth, store, source_context_digest=source, actor_binding=EmsTagOriginalActorBinding("5"*64,"6"*64,"9"*64), clock=lambda: now)
    return custody, store, plan, auth, baseline, checkpoint


def create(root: Path, *, baseline: EmsTagFullScope | None = None):
    root.chmod(0o700)
    (root / "custody").mkdir(mode=0o700)
    for name, value in (("execution.key", b"e" * 32), ("custody.key", b"a" * 32)):
        (root / name).write_bytes(value)
        (root / name).chmod(0o600)
    return components(root, baseline=baseline)


class Adapter:
    def __init__(self, custody, baseline, fault: str = "none", ack_data: object = None):
        self.custody, self.baseline, self.fault, self.ack_data = custody, baseline, fault, ack_data
        self.sends = 0
        self.buffers: list[bytearray] = []

    def read_current(self, plan):
        return plan.expected_current_digest

    def dispatch(self, plan):
        try:
            self.custody.begin_original_send(self.baseline)
            self.sends += 1
            if self.fault == "missing_ack":
                raise M4AdapterAmbiguous("Synthetic lost ACK.")
            raw = bytearray(json.dumps(envelope(self.ack_data)).encode())
            if self.fault == "duplicate_ack":
                raw = bytearray(b'{"data":null,"result":{"retval":1,"retval":0,"message":null}}')
            self.buffers.append(raw)
            self.custody.capture_original_ack(raw, http_status=200, content_type="application/json",
                                              complete=self.fault != "partial_ack")
            if self.fault == "missing_birth":
                raise M4AdapterAmbiguous("Synthetic unavailable original postcondition.")
            created = full_scope(add=True)
            if self.fault == "old_rule_drift":
                created = full_scope(prior_change=True, add=True)
            elif self.fault == "shared_rule_set":
                created = full_scope(add=True, shared_rule_set=True)
            elif self.fault == "assigned":
                draft = DisabledLinuxProcessTag("a" * 32)
                raw_detail = detail(draft)
                raw_detail["client_count"] = 1
                replacement = qualify_tag_detail(envelope(raw_detail))
                created = EmsTagFullScope(created.catalog, (created.details[0], replacement))
            self.custody.capture_created_scope(self.baseline, created)
            if self.fault == "post_birth_unknown":
                raise M4AdapterAmbiguous("Synthetic failure after sealing birth.")
        except EmsTagCustodyError:
            raise M4AdapterAmbiguous("Synthetic original custody refusal.") from None

    def read_postcondition(self, plan):
        assert self.custody.inspect_created_scope(require_verified_original=False).created_state_digest
        return plan.expected_state_digest


def execute(custody, store, plan, auth, baseline, *, fault: str = "none", ack_data: object = None):
    adapter = Adapter(custody, baseline, fault, ack_data)
    result = M4ExecutionKernel(adapter, _Verifier(), store, clock=lambda: 1000).execute(plan, auth)
    return adapter, result


@pytest.mark.parametrize("ack_data", [None, 101, {"tag_id": 101}, {"id": 101}, {"tag_id": 101, "metadata": None}])
def test_original_ack_and_same_dispatch_full_birth_reopen_without_replay(tmp_path, ack_data):
    custody, store, plan, auth, before, checkpoint = create(tmp_path)
    adapter, result = execute(custody, store, plan, auth, before, ack_data=ack_data)
    assert result.outcome == "succeeded" and result.verification == "verified" and adapter.sends == 1
    observed = custody.inspect_created_scope(require_verified_original=True)
    assert observed.created_state_digest and observed.created_scope_digest
    records = {p.name: p.read_bytes() for p in (tmp_path / "custody").iterdir()}
    assert set(records) == {"send.claim.json", "ack.attempt.json", "create-ack.json", "birth.attempt.json", "created-scope.json"}
    assert DisabledLinuxProcessTag("a" * 32)._name.encode() not in b"".join(records.values())
    assert all(not raw for raw in adapter.buffers)
    reopened, _, *_ = components(tmp_path, checkpoint=checkpoint, read_only=True, now=2000)
    assert reopened.inspect_created_scope(require_verified_original=True) == observed
    replay, replayed = execute(custody, store, plan, auth, before)
    assert replayed.idempotent_replay and replay.sends == 0 and store.claim_count == 1
    with pytest.raises(EmsTagCustodyError):
        reopened.capture_created_scope(before, full_scope(add=True))
    assert records == {p.name: p.read_bytes() for p in (tmp_path / "custody").iterdir()}


@pytest.mark.parametrize("fault", ["missing_ack", "partial_ack", "duplicate_ack", "missing_birth",
                                   "old_rule_drift", "shared_rule_set", "assigned", "post_birth_unknown"])
def test_unknown_never_allows_late_birth_or_original_ownership(tmp_path, fault):
    custody, store, plan, auth, before, checkpoint = create(tmp_path)
    adapter, result = execute(custody, store, plan, auth, before, fault=fault)
    assert result.outcome == "reconciliation_required" and result.verification == "unknown" and adapter.sends == 1
    assert all(not raw for raw in adapter.buffers)
    with pytest.raises(EmsTagCustodyError):
        custody.inspect_created_scope(require_verified_original=True)
    if fault == "post_birth_unknown":
        with pytest.raises(EmsTagCustodyError):
            custody.inspect_created_scope()
        assert custody.inspect_created_scope(require_verified_original=False).created_state_digest
    records = {p.name: p.read_bytes() for p in (tmp_path / "custody").iterdir()}
    reopened, store, plan, auth, before, _ = components(tmp_path, checkpoint=checkpoint)
    retry, replay = execute(reopened, store, plan, auth, before)
    assert replay.idempotent_replay and retry.sends == 0
    with pytest.raises(EmsTagCustodyError):
        reopened.capture_created_scope(before, full_scope(add=True))
    raw = bytearray(json.dumps(envelope(None)).encode())
    with pytest.raises(EmsTagCustodyError):
        reopened.capture_original_ack(raw, http_status=200, content_type="application/json", complete=True)
    assert not raw and records == {p.name: p.read_bytes() for p in (tmp_path / "custody").iterdir()}


@pytest.mark.parametrize("ack_data", [{"tag_id": 102}, {"tag_id": 102, "metadata": None},
                                      {"tag_id": "101"}, {"id": 0}, {"id": True}, -1])
def test_bad_explicit_selectors_are_not_downgraded_to_selectorless_ack(tmp_path, ack_data):
    custody, store, plan, auth, before, _ = create(tmp_path)
    _, result = execute(custody, store, plan, auth, before, ack_data=ack_data)
    assert result.outcome == "reconciliation_required"
    with pytest.raises(EmsTagCustodyError):
        custody.inspect_created_scope(require_verified_original=True)


def test_custody_cannot_write_without_real_kernel_dispatch_ownership(tmp_path):
    custody, store, _, _, before, _ = create(tmp_path)
    with pytest.raises(EmsTagCustodyError):
        custody.begin_original_send(before)
    assert not list((tmp_path / "custody").iterdir()) and store.claim_count == 0


def test_copied_directory_or_store_namespace_cannot_supply_original_ownership(tmp_path):
    original = tmp_path / "original"
    original.mkdir(mode=0o700)
    custody, store, plan, auth, before, checkpoint = create(original)
    execute(custody, store, plan, auth, before)
    copied = tmp_path / "copied"
    shutil.copytree(original, copied)
    other, *_ = components(copied, checkpoint=checkpoint, read_only=True)
    with pytest.raises(EmsTagCustodyError):
        other.inspect_created_scope(require_verified_original=True)


def test_tampered_record_and_changed_source_context_fail_closed(tmp_path):
    custody, store, plan, auth, before, checkpoint = create(tmp_path)
    execute(custody, store, plan, auth, before)
    record = tmp_path / "custody" / "created-scope.json"
    raw = json.loads(record.read_text())
    raw["created_state_digest"] = "0" * 64
    record.write_text(json.dumps(raw))
    with pytest.raises(EmsTagCustodyError):
        custody.inspect_created_scope(require_verified_original=True)
    changed, *_ = components(tmp_path, checkpoint=checkpoint, read_only=True, source="8" * 64)
    with pytest.raises(EmsTagCustodyError):
        changed.inspect_original_ack()


def test_wrong_plan_binding_is_rejected_before_records(tmp_path):
    custody, store, plan, auth, before, _ = create(tmp_path)
    fields = plan.canonical_content()
    fields["parameters_digest"] = "0" * 64
    changed = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
    with pytest.raises(EmsTagCustodyError):
        EmsTagOriginalCustody(tmp_path / "custody", tmp_path / "custody.key", DisabledLinuxProcessTag("a" * 32),
            before.digest, changed, _authorization(changed), store, source_context_digest="7" * 64, actor_binding=EmsTagOriginalActorBinding("5"*64,"6"*64,"9"*64))
    assert not list((tmp_path / "custody").iterdir())


def test_another_custody_directory_cannot_rearm_the_same_original_send(tmp_path):
    custody, store, plan, auth, before, _ = create(tmp_path)
    other_dir = tmp_path / "other-custody"
    other_dir.mkdir(mode=0o700)
    other = EmsTagOriginalCustody(other_dir, tmp_path / "custody.key", DisabledLinuxProcessTag("a" * 32),
        before.digest, plan, auth, store, source_context_digest="7" * 64, actor_binding=EmsTagOriginalActorBinding("5"*64,"6"*64,"9"*64), clock=lambda: 1000)

    class SecondDirectoryAdapter(Adapter):
        def dispatch(self, current_plan):
            self.custody.begin_original_send(self.baseline)
            self.sends += 1
            with pytest.raises(EmsTagCustodyError):
                other.begin_original_send(before)
            raw = bytearray(json.dumps(envelope(None)).encode())
            self.custody.capture_original_ack(raw, http_status=200, content_type="application/json", complete=True)
            self.custody.capture_created_scope(before, full_scope(add=True))

    adapter = SecondDirectoryAdapter(custody, before)
    result = M4ExecutionKernel(adapter, _Verifier(), store, clock=lambda: 1000).execute(plan, auth)
    assert result.outcome == "succeeded" and adapter.sends == 1 and not list(other_dir.iterdir())


def test_complete_json_with_failed_framing_retains_original_witness_without_ack(tmp_path):
    custody, store, plan, auth, before, checkpoint = create(tmp_path)
    _, result = execute(custody, store, plan, auth, before, fault="partial_ack")
    assert result.verification == "unknown"
    expected = {"http_status": 200, "reply_complete": False, "json_content_type": True,
                "json_object_complete": True, "native_envelope_valid": True, "data_field_present": True}
    assert custody.inspect_ack_attempt() == expected
    reopened, *_ = components(tmp_path, checkpoint=checkpoint, read_only=True, now=2000)
    assert reopened.inspect_ack_attempt() == expected
    with pytest.raises(EmsTagCustodyError):
        reopened.inspect_original_ack()


def test_void_success_without_data_still_requires_original_full_birth_and_verified_m4(tmp_path):
    custody, store, plan, auth, before, _ = create(tmp_path)
    class VoidAdapter(Adapter):
        def dispatch(self, current_plan):
            self.custody.begin_original_send(self.baseline)
            self.sends += 1
            raw = bytearray(json.dumps({"result": {"retval": 1, "message": "Created"}}).encode())
            self.custody.capture_original_ack(raw, http_status=200, content_type="application/json", complete=True)
            assert not raw
            with pytest.raises(EmsTagCustodyError): self.custody.inspect_created_scope()
            self.custody.capture_created_scope(self.baseline, full_scope(add=True))
    adapter = VoidAdapter(custody, before)
    result = M4ExecutionKernel(adapter, _Verifier(), store, clock=lambda: 1000).execute(plan, auth)
    assert result.outcome == "succeeded" and custody.inspect_created_scope().created_state_digest
    assert custody.inspect_ack_attempt()["data_field_present"] is False
