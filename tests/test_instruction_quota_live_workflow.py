"""Real durable M4 kernel with synthetic quota allocation and restoration."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from typing import Any, cast

import pytest

from fortipam_mcp.instruction_quota_live_workflow import (
    InstructionQuotaLiveWorkflow, InstructionQuotaLiveWorkflowError,
)
from fortipam_mcp.instruction_quota_http_transport import InstructionQuotaTransportError
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_instruction_quota_contract import SERIAL, state
from test_instruction_quota_http_transport import Cycle, Device, assert_closed

REQUESTER, TRANSPORT = "1"*64,"2"*64
IDENTITY = {"requester_digest":REQUESTER,"transport_digest":TRANSPORT}


@pytest.fixture
def cycle(tmp_path: Path) -> Cycle:
    path = tmp_path/("instruction-quota-"+SERIAL)
    path.mkdir(mode=0o700)
    return Cycle(path,Device())


def workflow(cycle: Cycle, phase: str = "allocate", *, transport_enabled: bool = True,
             store_read_only: bool = False,
             **overrides: Any) -> InstructionQuotaLiveWorkflow:
    path = cycle.path.parent/("m4-"+phase)
    path.mkdir(mode=0o700,exist_ok=True)
    key = path/"key"
    if not key.exists():
        key.write_bytes(b"m"*32)
        key.chmod(0o600)
    kwargs: dict[str,Any] = {"canonical_state_directory":cycle.path,
        "execution_store":PersistentM4ExecutionStateStore(path/"ledger.sqlite",key,read_only=store_read_only),
        "authority_key":(b"a" if phase=="allocate" else b"b")*32,
        "environment_ref":"synthetic-environment","scope_ref":"synthetic-shared-setting-scope",
        "audience_ref":"synthetic-audience","allowed_requester_digest":REQUESTER,
        "allowed_transport_digest":TRANSPORT,"execution_enabled":True,"clock":lambda:cycle.device.clock}
    kwargs.update(overrides)
    if phase=="restore" and "original_allocate_store" not in overrides:
        original = cycle.path.parent/"m4-allocate"
        original.mkdir(mode=0o700,exist_ok=True)
        original_key = original/"key"
        if not original_key.exists():
            original_key.write_bytes(b"m"*32)
            original_key.chmod(0o600)
        kwargs["original_allocate_store"] = PersistentM4ExecutionStateStore(original/"ledger.sqlite",original_key,
                                                                         read_only=store_read_only)
    return InstructionQuotaLiveWorkflow(cycle.transport(phase, execution_enabled=transport_enabled),**kwargs)


def authorize(item: InstructionQuotaLiveWorkflow) -> str:
    preview = item.preview(**IDENTITY)
    return cast(str,item.authorize(cast(str,preview["preview_ref"]),**IDENTITY)["authorization_ref"])


def test_real_m4_cycle_original_ack_binding_and_idempotent_results(cycle: Cycle) -> None:
    outputs: list[dict[str,object]] = []
    for phase in ("allocate","restore"):
        item = workflow(cycle,phase)
        preview = item.preview(**IDENTITY)
        assert preview["Proposed Changes"] == {"operation":phase+"_instruction_quota",
            "file_storage_delta_percent":1 if phase=="restore" else -1,
            "instruction_delta_percent":-1 if phase=="restore" else 1,
            "video_and_software_preserved":True,"other_setting_fields_preserved":True}
        issued = item.authorize(cast(str,preview["preview_ref"]),**IDENTITY)
        reference = cast(str,issued["authorization_ref"])
        result = item.execute(reference,**IDENTITY)
        assert result["outcome"] == "succeeded" and result["verification"] == "verified"
        assert result["idempotent_replay"] is False
        count = len(cycle.device.requests)
        assert item.execute(reference,**IDENTITY) == {**result,"idempotent_replay":True}
        assert len(cycle.device.requests)==count and item._execution_store.claim_count==1
        claim = json.loads((cycle.path/(phase+".claim.json")).read_bytes())["payload"]
        assert item._authority._issued is not None
        assert claim["plan"] == item._authority._issued.plan.plan_digest
        assert claim["authorization"] == item._authority._issued.authorization.authorization_digest
        outputs.extend((preview,issued,result))
    assert cycle.device.instruction == 0 and len(cycle.device.requests)==2
    assert state(other=cycle.device.sibling)._state==cycle.baseline._state
    assert_closed(cycle.device)
    encoded = json.dumps(outputs)
    for value in (REQUESTER,TRANSPORT,SERIAL,"synthetic-token","synthetic-private-value",str(cycle.path)):
        assert value not in encoded


@pytest.mark.parametrize("stage",["preview","authorize","execute"])
@pytest.mark.parametrize("field",["requester_digest","transport_digest"])
def test_wrong_identity_precedes_reads_and_claims(cycle: Cycle, stage: str, field: str) -> None:
    item = workflow(cycle)
    preview = item.preview(**IDENTITY)
    issued = item.authorize(cast(str,preview["preview_ref"]),**IDENTITY)
    reads: list[bool] = []
    cycle.device.on_read = lambda:reads.append(True)
    arguments = () if stage=="preview" else (preview["preview_ref"] if stage=="authorize" else issued["authorization_ref"],)
    with pytest.raises(InstructionQuotaLiveWorkflowError):
        getattr(item,stage)(*arguments,**{**IDENTITY,field:"9"*64})
    assert not reads and not cycle.device.requests and item._execution_store.claim_count==0


def test_gate_closed_allows_preview_but_not_authorization(cycle: Cycle) -> None:
    item = workflow(cycle,execution_enabled=False)
    preview = item.preview(**IDENTITY)
    with pytest.raises(InstructionQuotaLiveWorkflowError):
        item.authorize(cast(str,preview["preview_ref"]),**IDENTITY)
    assert not cycle.device.requests and item._execution_store.claim_count==0


def test_expired_preview_and_new_preview_invalidate_authorizations(cycle: Cycle) -> None:
    item = workflow(cycle)
    old = authorize(item)
    item.preview(**IDENTITY)
    with pytest.raises(InstructionQuotaLiveWorkflowError):
        item.execute(old,**IDENTITY)
    preview = item.preview(**IDENTITY)
    cycle.device.clock = cast(int,preview["expires_at"])
    with pytest.raises(InstructionQuotaLiveWorkflowError):
        item.authorize(cast(str,preview["preview_ref"]),**IDENTITY)
    assert not cycle.device.requests and item._execution_store.claim_count==0


def test_tampered_preview_or_cross_authority_ref_is_denied(cycle: Cycle) -> None:
    item = workflow(cycle)
    preview = item.preview(**IDENTITY)
    assert item._preview is not None
    item._preview = replace(item._preview,expected_digest="f"*64)
    with pytest.raises(InstructionQuotaLiveWorkflowError):
        item.authorize(cast(str,preview["preview_ref"]),**IDENTITY)
    original = workflow(cycle)
    reference = authorize(original)
    different = workflow(cycle,authority_key=b"c"*32)
    with pytest.raises(InstructionQuotaLiveWorkflowError):
        different.execute(reference,**IDENTITY)
    assert not cycle.device.requests


def test_drift_after_authorization_consumes_m4_without_put(cycle: Cycle) -> None:
    item = workflow(cycle)
    reference = authorize(item)
    cycle.device.sibling = "changed"
    result = item.execute(reference,**IDENTITY)
    assert result["outcome"] == "reconciliation_required" and result["verification"] == "unknown"
    assert item.execute(reference,**IDENTITY)["idempotent_replay"] is True
    assert not cycle.device.requests and item._execution_store.claim_count==1
    fresh = workflow(cycle)
    with pytest.raises(InstructionQuotaLiveWorkflowError):
        fresh.preview(**IDENTITY)










def test_unknown_dispatch_has_one_put_and_blocks_restore(cycle: Cycle) -> None:
    item = workflow(cycle)
    reference = authorize(item)
    cycle.device.status = 500
    result = item.execute(reference,**IDENTITY)
    assert result["outcome"] == "reconciliation_required" and result["verification"] == "unknown"
    item.execute(reference,**IDENTITY)
    assert len(cycle.device.requests)==1
    with pytest.raises(InstructionQuotaLiveWorkflowError):
        workflow(cycle,"restore").preview(**IDENTITY)
    assert not (cycle.path/"allocate.result.json").exists()
    assert_closed(cycle.device)


def test_diagnostic_handler_failure_preserves_durable_unknown(cycle: Cycle, monkeypatch: pytest.MonkeyPatch) -> None:
    item = workflow(cycle)
    reference = authorize(item)
    cycle.device.status = 500
    def fail_log(message: str, *args: object) -> None:
        raise RuntimeError("synthetic-private-log-handler-detail")
    monkeypatch.setattr("fortipam_mcp.instruction_quota_live_workflow._LOGGER.warning", fail_log)
    result = item.execute(reference, **IDENTITY)
    assert result["outcome"] == "reconciliation_required" and result["verification"] == "unknown"
    assert item._execution_store.audit_events[-1].authorization == "dispatch_unknown"
    assert item.execute(reference, **IDENTITY)["idempotent_replay"] is True
    assert len(cycle.device.requests) == 1
    with pytest.raises(InstructionQuotaLiveWorkflowError):
        workflow(cycle).preview(**IDENTITY)
    assert_closed(cycle.device)


@pytest.mark.parametrize("phase", ["allocate", "restore"])
@pytest.mark.parametrize("failure, operation, stage, writes", [
    ("status", "dispatch", "ack_validation", 1),
    ("partial", "postcondition_read", "postcondition", 1),
    ("drift", "current_read", "precondition", 0),
    ("exception", "dispatch", "unavailable", 0),
    ("stage_injection", "dispatch", "unavailable", 0),
])
def test_unknown_failure_logs_only_fixed_categories_without_replay_authority(
    cycle: Cycle, phase: str, failure: str, operation: str, stage: str, writes: int,
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:
    if phase == "restore":
        allocate = workflow(cycle)
        assert allocate.execute(authorize(allocate), **IDENTITY)["verification"] == "verified"
    item = workflow(cycle, phase)
    reference = authorize(item)
    before = len(cycle.device.requests)
    if failure == "status":
        cycle.device.status = 500
    elif failure == "partial":
        cycle.device.partial = True
    elif failure == "drift":
        cycle.device.used_file += 1
    else:
        def fail_dispatch(self: object, **kwargs: object) -> None:
            if failure == "stage_injection":
                raise InstructionQuotaTransportError("synthetic-private-stage")
            raise RuntimeError("synthetic-private-exception-detail")
        monkeypatch.setattr(type(item._transport), "dispatch", fail_dispatch)
    caplog.set_level("WARNING", logger="fortipam_mcp.instruction_quota_live_workflow")
    result = item.execute(reference, **IDENTITY)
    assert result["outcome"] == "reconciliation_required" and result["verification"] == "unknown"
    records = [record for record in caplog.records
               if record.name == "fortipam_mcp.instruction_quota_live_workflow"]
    assert len(records) == 1
    assert records[0].getMessage() == (
        f"Instruction quota adapter failure: phase={phase} operation={operation} stage={stage}")
    assert records[0].exc_info is None and records[0].stack_info is None
    assert "diagnostic_stage" not in result
    retained_audit = item._execution_store.audit_events
    assert retained_audit[-1].authorization == {
        "current_read": "current_read_unknown", "dispatch": "dispatch_unknown",
        "postcondition_read": "post_read_unknown",
    }[operation]
    assert item.execute(reference, **IDENTITY)["idempotent_replay"] is True
    assert item._execution_store.audit_events == retained_audit
    assert len(cycle.device.requests) == before + writes
    assert len(caplog.records) == len(records)
    with pytest.raises(InstructionQuotaLiveWorkflowError):
        workflow(cycle, phase).preview(**IDENTITY)
    encoded = caplog.text + json.dumps(result)
    for value in (REQUESTER, TRANSPORT, SERIAL, "synthetic-token", "synthetic-private",
                  str(cycle.path)):
        assert value not in encoded
    assert_closed(cycle.device)


def test_restore_rejects_missing_original_proof_and_cross_phase_refs(cycle: Cycle) -> None:
    restore = workflow(cycle,"restore")
    with pytest.raises(InstructionQuotaLiveWorkflowError):
        restore.preview(**IDENTITY)
    enable = workflow(cycle)
    reference = authorize(enable)
    assert enable.execute(reference,**IDENTITY)["verification"]=="verified"
    restore.preview(**IDENTITY)
    with pytest.raises(InstructionQuotaLiveWorkflowError):
        restore.execute(reference,**IDENTITY)
    assert len(cycle.device.requests)==1 and restore._execution_store.claim_count==0


def test_canonical_directory_and_independent_key_are_required(cycle: Cycle) -> None:
    for overrides in ({"canonical_state_directory":cycle.path.parent},
                      {"authority_key":b"k"*32}):
        with pytest.raises(InstructionQuotaLiveWorkflowError):
            workflow(cycle,**overrides)
    assert not cycle.device.connections


def test_m4_finalize_failure_blocks_restore_even_after_native_verified_readback(
        cycle: Cycle, monkeypatch: pytest.MonkeyPatch) -> None:
    item = workflow(cycle)
    reference = authorize(item)
    def fail_finalize(**kwargs: object) -> None:
        raise OSError("synthetic-finalize-failure")
    with monkeypatch.context() as patch:
        patch.setattr(item._execution_store,"finalize",fail_finalize)
        with pytest.raises(InstructionQuotaLiveWorkflowError):
            item.execute(reference,**IDENTITY)
    assert (cycle.path/"allocate.result.json").exists()
    assert not (cycle.path/"allocate.m4.json").exists()
    result = item.execute(reference,**IDENTITY)
    assert result["outcome"]=="reconciliation_required" and result["verification"]=="unknown"
    with pytest.raises(InstructionQuotaLiveWorkflowError):
        workflow(cycle,"restore").preview(**IDENTITY)
    assert len(cycle.device.requests)==1


def test_restore_rechecks_original_ledger_before_send(cycle: Cycle, monkeypatch: pytest.MonkeyPatch) -> None:
    enable = workflow(cycle)
    assert enable.execute(authorize(enable),**IDENTITY)["verification"]=="verified"
    restore = workflow(cycle,"restore")
    reference = authorize(restore)
    assert restore._original_store is not None
    original_inspect = restore._original_store.inspect_claim
    invalid = [False]
    def inspect(**kwargs: str) -> Any:
        if invalid[0]:
            raise ValueError("synthetic-ledger-unavailable")
        return original_inspect(**kwargs)
    monkeypatch.setattr(restore._original_store,"inspect_claim",inspect)
    cycle.device.on_connect = lambda:invalid.__setitem__(0,True)
    result = restore.execute(reference,**IDENTITY)
    assert result["outcome"]=="reconciliation_required" and result["verification"]=="unknown"
    assert len(cycle.device.requests)==1 and not (cycle.path/"restore.claim.json").exists()


def test_usage_drift_after_authorization_consumes_only_m4_claim(cycle: Cycle) -> None:
    item = workflow(cycle)
    reference = authorize(item)
    cycle.device.used_file += 1
    result = item.execute(reference,**IDENTITY)
    assert result["outcome"] == "reconciliation_required" and result["verification"] == "unknown"
    assert item.execute(reference,**IDENTITY)["idempotent_replay"] is True
    assert not cycle.device.requests and not (cycle.path/"allocate.claim.json").exists()
    assert item._execution_store.claim_count == 1
    with pytest.raises(InstructionQuotaLiveWorkflowError):
        workflow(cycle).preview(**IDENTITY)


def test_partial_write_is_unknown_and_has_no_native_or_m4_restore_proof(cycle: Cycle) -> None:
    item = workflow(cycle)
    reference = authorize(item)
    cycle.device.partial = True
    result = item.execute(reference,**IDENTITY)
    assert result["outcome"] == "reconciliation_required" and result["verification"] == "unknown"
    assert (cycle.path/"allocate.claim.json").exists() and (cycle.path/"allocate.ack.json").exists()
    assert not (cycle.path/"allocate.result.json").exists() and not (cycle.path/"allocate.m4.json").exists()
    assert item.execute(reference,**IDENTITY)["idempotent_replay"] is True
    with pytest.raises(InstructionQuotaLiveWorkflowError):
        workflow(cycle,"restore").preview(**IDENTITY)
    assert len(cycle.device.requests) == 1


def test_restore_preview_requires_zero_resource_usage_and_reports_exact_quota_change(cycle: Cycle) -> None:
    item = workflow(cycle)
    preview = item.preview(**IDENTITY)
    assert preview["Current State"]["file_storage_quota_percent"] == 5
    assert preview["Current State"]["instruction_quota_percent"] == 0
    assert preview["Expected State"]["file_storage_quota_percent"] == 4
    assert preview["Expected State"]["instruction_quota_percent"] == 1
    assert item.execute(authorize(item),**IDENTITY)["verification"] == "verified"
    restore = workflow(cycle,"restore")
    cycle.device.resource = 1
    with pytest.raises(InstructionQuotaLiveWorkflowError):
        restore.preview(**IDENTITY)
    assert restore._execution_store.claim_count == 0
    cycle.device.resource = 0
    preview = restore.preview(**IDENTITY)
    assert preview["Current State"]["instruction_quota_percent"] == 1
    assert preview["Expected State"]["instruction_quota_percent"] == 0
    assert preview["Current State"]["original_allocate_native_and_m4_verified"] is True
    assert len(cycle.device.requests) == 1
