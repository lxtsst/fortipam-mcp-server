"""Original Policy custody requires the real M4 dispatch and immutable records."""
from dataclasses import replace
import json

import pytest
from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, M4ExecutionPlan, canonical_digest

from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.windows_execution_policy_custody import (
    ACTION_ID, ADAPTER_REF, WindowsExecutionPolicyCustody, WindowsExecutionPolicyCustodyError,
)
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF
from test_v4_execution_kernel import _authorization, _Verifier, REQUESTER, CONFIRMATION, APPROVAL
from test_windows_execution_policy_contract import compile_request, envelope, state, BINDING


def components(root, *, checkpoint=None, read_only=False, now=1000):
    checkpoint = checkpoint or _ExternalM4Checkpoint()
    store = PersistentM4ExecutionStateStore(root/"execution.sqlite", root/"execution.key",
        monotonic_checkpoint=checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF, read_only=read_only)
    request = compile_request()
    fields = dict(plan_ref="inactive-policy-original-plan-01", revision=1, action_id=ACTION_ID,
        action_version="1.0.0", adapter_ref=ADAPTER_REF, target_ref="bound-inactive-windows-policy",
        requester_digest=REQUESTER, summary_digest="9"*64, confirmation_digest=CONFIRMATION,
        approval_digest=APPROVAL, parameters_digest=request.request_digest, expected_current_digest="1"*64,
        expected_state_digest=request.expected_state_digest, idempotency_digest="3"*64,
        expires_at=1300, compensation_ref=None)
    plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
    auth = _authorization(plan)
    custody = WindowsExecutionPolicyCustody(root/"custody", root/"custody.key", request, "1"*64,
    plan, auth, store, source_context_digest="7"*64, clock=lambda:now)
    return custody, store, plan, auth, request, checkpoint


def create(root):
    root.chmod(0o700)
    (root/"custody").mkdir(mode=0o700)
    for name, value in (("execution.key", b"e"*32), ("custody.key", b"a"*32)):
        (root/name).write_bytes(value)
        (root/name).chmod(0o600)
    return components(root)


def absence():
    value = json.loads(envelope(None, http_status=404, status="error", mkey=BINDING.name))
    del value["results"]
    return bytearray(json.dumps(value).encode())


def ack():
    return envelope([], http_method="POST", mkey=BINDING.name, error=0)


class Adapter:
    def __init__(self, custody, request, fault):
        self.custody, self.request, self.fault = custody, request, fault
        self.sends = 0
        self.buffers = []

    def read_current(self, plan):return plan.expected_current_digest

    def dispatch(self, plan):
        try:
            raw = absence();self.buffers.append(raw)
            self.custody.begin_original_send(raw, http_status=404)
            self.sends += 1
            if self.fault == "missing-ack":raise M4AdapterAmbiguous("Synthetic missing original ACK.")
            raw = ack() if self.fault != "wrong-ack" else bytearray(b'{"status":"error"}')
            self.buffers.append(raw)
            self.custody.capture_original_ack(raw, http_status=200, content_type="application/json")
            if self.fault == "unknown-after-ack":raise M4AdapterAmbiguous("Synthetic unavailable state.")
            raw = state(self.request, **({"q_ref":1} if self.fault == "referenced" else {}))
            self.buffers.append(raw)
            self.custody.capture_created_state(raw)
        except WindowsExecutionPolicyCustodyError:
            raise M4AdapterAmbiguous("Synthetic original custody failure.") from None

    def read_postcondition(self, plan):
        assert self.custody.inspect_created_state().created_state_digest
        return plan.expected_state_digest


def execute(custody, store, plan, auth, request, fault="none"):
    adapter = Adapter(custody, request, fault)
    result = M4ExecutionKernel(adapter, _Verifier(), store, clock=lambda:1000).execute(plan, auth)
    return adapter, result


def test_original_ack_and_full_state_reopen_after_expiry_without_replay(tmp_path):
    custody, store, plan, auth, request, checkpoint = create(tmp_path)
    adapter, result = execute(custody, store, plan, auth, request)
    assert result.outcome == "succeeded" and adapter.sends == 1
    assert all(not any(raw) for raw in adapter.buffers)
    observed = custody.inspect_created_state()
    assert observed.created_state_digest and observed.original_outcome == "succeeded"
    records = {path.name:path.read_bytes() for path in (tmp_path/"custody").iterdir()}
    assert set(records) == {"send.claim.json", "create-ack.json", "created-state.json"}
    assert BINDING.name.encode() not in b"".join(records.values())
    reopened, _, *_ = components(tmp_path, checkpoint=checkpoint, read_only=True, now=2000)
    assert reopened.inspect_created_state() == observed
    replay, result = execute(custody, store, plan, auth, request)
    assert result.idempotent_replay is True and replay.sends == 0 and store.claim_count == 1
    raw = state(request)
    with pytest.raises(WindowsExecutionPolicyCustodyError):reopened.capture_created_state(raw)
    assert not any(raw)
    assert {path.name:path.read_bytes() for path in (tmp_path/"custody").iterdir()} == records


@pytest.mark.parametrize("fault", ["missing-ack", "wrong-ack", "unknown-after-ack", "referenced"])
def test_uncertain_original_result_cannot_be_repaired_or_replayed(tmp_path, fault):
    custody, store, plan, auth, request, checkpoint = create(tmp_path)
    adapter, result = execute(custody, store, plan, auth, request, fault)
    assert result.outcome == "reconciliation_required" and result.verification == "unknown" and adapter.sends == 1
    assert all(not any(raw) for raw in adapter.buffers)
    if fault in ("unknown-after-ack", "referenced"):
        original = custody.inspect_original_ack()
        assert original.original_outcome == "reconciliation_required" and original.created_state_digest is None
    else:
        with pytest.raises(WindowsExecutionPolicyCustodyError):custody.inspect_original_ack()
    with pytest.raises(WindowsExecutionPolicyCustodyError):custody.inspect_created_state()
    records = {path.name:path.read_bytes() for path in (tmp_path/"custody").iterdir()}
    reopened, store, plan, auth, request, _ = components(tmp_path, checkpoint=checkpoint)
    retry, replay = execute(reopened, store, plan, auth, request)
    assert replay.idempotent_replay is True and retry.sends == 0
    raw = state(request)
    with pytest.raises(WindowsExecutionPolicyCustodyError):reopened.capture_created_state(raw)
    assert not any(raw)
    assert {path.name:path.read_bytes() for path in (tmp_path/"custody").iterdir()} == records


def test_no_outside_kernel_reservation_or_ack_capture(tmp_path):
    custody, store, plan, auth, request, _ = create(tmp_path)
    raw = absence()
    with pytest.raises(WindowsExecutionPolicyCustodyError):custody.begin_original_send(raw, http_status=404)
    assert not any(raw) and not list((tmp_path/"custody").iterdir()) and store.claim_count == 0
    raw = ack()
    with pytest.raises(WindowsExecutionPolicyCustodyError):custody.capture_original_ack(raw,
        http_status=200, content_type="application/json")
    assert not any(raw) and not list((tmp_path/"custody").iterdir())


@pytest.mark.parametrize("record", ["send.claim.json", "create-ack.json", "created-state.json"])
def test_tampered_custody_refuses_original_ownership(tmp_path, record):
    custody, store, plan, auth, request, _ = create(tmp_path)
    _, result = execute(custody, store, plan, auth, request)
    assert result.outcome == "succeeded"
    path = tmp_path/"custody"/record
    values = json.loads(path.read_bytes());values["context_digest"] = "e"*64
    path.write_text(json.dumps(values))
    with pytest.raises(WindowsExecutionPolicyCustodyError):custody.inspect_created_state()


def test_changed_expected_state_or_shared_store_key_refuses_constructor(tmp_path):
    custody, store, plan, auth, request, _ = create(tmp_path)
    fields = {key:getattr(plan,key) for key in plan.__dataclass_fields__ if key != "plan_digest"}
    fields["expected_state_digest"] = "d"*64
    changed = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
    with pytest.raises(WindowsExecutionPolicyCustodyError):WindowsExecutionPolicyCustody(tmp_path/"custody",
        tmp_path/"custody.key", request, "1"*64, changed, _authorization(changed), store, source_context_digest="7"*64)
    with pytest.raises(WindowsExecutionPolicyCustodyError):WindowsExecutionPolicyCustody(tmp_path/"custody",
        tmp_path/"execution.key", request, "1"*64, plan, auth, store, source_context_digest="7"*64)


def test_original_records_cannot_rebind_to_a_different_writer_source(tmp_path):
    custody, store, plan, auth, request, _ = create(tmp_path)
    _, result = execute(custody, store, plan, auth, request)
    assert result.outcome == "succeeded"
    assert custody.inspect_created_state().source_context_digest == "7"*64
    changed = WindowsExecutionPolicyCustody(tmp_path/"custody",tmp_path/"custody.key",request,"1"*64,
        plan,auth,store,source_context_digest="8"*64)
    with pytest.raises(WindowsExecutionPolicyCustodyError):changed.inspect_created_state()
