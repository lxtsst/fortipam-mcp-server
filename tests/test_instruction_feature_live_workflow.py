"""Real durable M4 kernel with synthetic shared-setting enable and restoration."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from typing import Any, cast

import pytest

from fortipam_mcp.instruction_feature_live_workflow import (
    InstructionFeatureLiveWorkflow, InstructionFeatureLiveWorkflowError,
)
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_instruction_feature_contract import SERIAL, state
from test_instruction_feature_http_transport import Cycle, Device, assert_closed

REQUESTER, TRANSPORT = "1"*64,"2"*64
IDENTITY = {"requester_digest":REQUESTER,"transport_digest":TRANSPORT}


@pytest.fixture
def cycle(tmp_path: Path) -> Cycle:
    path = tmp_path/("instruction-feature-"+SERIAL)
    path.mkdir(mode=0o700)
    return Cycle(path,Device())


def workflow(cycle: Cycle, phase: str = "enable", **overrides: Any) -> InstructionFeatureLiveWorkflow:
    path = cycle.path.parent/("m4-"+phase)
    path.mkdir(mode=0o700,exist_ok=True)
    key = path/"key"
    if not key.exists():
        key.write_bytes(b"m"*32)
        key.chmod(0o600)
    kwargs: dict[str,Any] = {"canonical_state_directory":cycle.path,
        "execution_store":PersistentM4ExecutionStateStore(path/"ledger.sqlite",key),
        "authority_key":(b"a" if phase=="enable" else b"b")*32,
        "environment_ref":"synthetic-environment","scope_ref":"synthetic-shared-setting-scope",
        "audience_ref":"synthetic-audience","allowed_requester_digest":REQUESTER,
        "allowed_transport_digest":TRANSPORT,"execution_enabled":True,"clock":lambda:cycle.device.clock}
    kwargs.update(overrides)
    if phase=="restore" and "original_enable_store" not in overrides:
        original = cycle.path.parent/"m4-enable"
        original.mkdir(mode=0o700,exist_ok=True)
        original_key = original/"key"
        if not original_key.exists():
            original_key.write_bytes(b"m"*32)
            original_key.chmod(0o600)
        kwargs["original_enable_store"] = PersistentM4ExecutionStateStore(original/"ledger.sqlite",original_key)
    return InstructionFeatureLiveWorkflow(cycle.transport(phase),**kwargs)


def authorize(item: InstructionFeatureLiveWorkflow) -> str:
    preview = item.preview(**IDENTITY)
    return cast(str,item.authorize(cast(str,preview["preview_ref"]),**IDENTITY)["authorization_ref"])


def test_real_m4_cycle_original_ack_binding_and_idempotent_results(cycle: Cycle) -> None:
    outputs: list[dict[str,object]] = []
    for phase in ("enable","restore"):
        item = workflow(cycle,phase)
        preview = item.preview(**IDENTITY)
        assert preview["Proposed Changes"] == {"operation":phase+"_instruction_feature",
            "shared_setting_change":True,"other_setting_fields_preserved":True}
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
    assert not cycle.device.enabled and len(cycle.device.requests)==2
    assert state()._state==cycle.baseline._state
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
    with pytest.raises(InstructionFeatureLiveWorkflowError):
        getattr(item,stage)(*arguments,**{**IDENTITY,field:"9"*64})
    assert not reads and not cycle.device.requests and item._execution_store.claim_count==0


def test_gate_closed_allows_preview_but_not_authorization(cycle: Cycle) -> None:
    item = workflow(cycle,execution_enabled=False)
    preview = item.preview(**IDENTITY)
    with pytest.raises(InstructionFeatureLiveWorkflowError):
        item.authorize(cast(str,preview["preview_ref"]),**IDENTITY)
    assert not cycle.device.requests and item._execution_store.claim_count==0


def test_expired_preview_and_new_preview_invalidate_authorizations(cycle: Cycle) -> None:
    item = workflow(cycle)
    old = authorize(item)
    item.preview(**IDENTITY)
    with pytest.raises(InstructionFeatureLiveWorkflowError):
        item.execute(old,**IDENTITY)
    preview = item.preview(**IDENTITY)
    cycle.device.clock = cast(int,preview["expires_at"])
    with pytest.raises(InstructionFeatureLiveWorkflowError):
        item.authorize(cast(str,preview["preview_ref"]),**IDENTITY)
    assert not cycle.device.requests and item._execution_store.claim_count==0


def test_tampered_preview_or_cross_authority_ref_is_denied(cycle: Cycle) -> None:
    item = workflow(cycle)
    preview = item.preview(**IDENTITY)
    assert item._preview is not None
    item._preview = replace(item._preview,expected_digest="f"*64)
    with pytest.raises(InstructionFeatureLiveWorkflowError):
        item.authorize(cast(str,preview["preview_ref"]),**IDENTITY)
    original = workflow(cycle)
    reference = authorize(original)
    different = workflow(cycle,authority_key=b"c"*32)
    with pytest.raises(InstructionFeatureLiveWorkflowError):
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
    with pytest.raises(InstructionFeatureLiveWorkflowError):
        fresh.preview(**IDENTITY)


def test_restore_read_failure_reconciles_without_reopening_dispatch(cycle: Cycle) -> None:
    enable = workflow(cycle)
    assert enable.execute(authorize(enable), **IDENTITY)["verification"] == "verified"
    restore = workflow(cycle, "restore")
    reference = authorize(restore)

    def unavailable() -> None:
        raise RuntimeError("synthetic-current-read-unavailable")

    cycle.device.on_read = unavailable
    result = restore.execute(reference, **IDENTITY)
    assert result["outcome"] == "reconciliation_required"
    assert restore._execution_store.audit_events[-1].authorization == "current_read_unknown"
    cycle.device.on_read = lambda: None
    closed = workflow(cycle, "restore", execution_enabled=False)
    events = closed._execution_store.audit_events
    report = closed.reconcile_restore(**IDENTITY)
    assert report["outcome"] == "not-applied-observed"
    assert report["retained_prewrite_claim_count"] == 1
    assert report["new_plan_and_authorization_required"] is True
    assert report["execution_authorized"] is report["device_write_executed"] is False
    assert closed._execution_store.audit_events == events
    assert len(cycle.device.requests) == 1 and cycle.device.enabled
    with pytest.raises(InstructionFeatureLiveWorkflowError):
        closed.preview(**IDENTITY)
    with pytest.raises(InstructionFeatureLiveWorkflowError):
        closed.reconcile_restore(**{**IDENTITY, "requester_digest": "9" * 64})
    cycle.device.sibling = "changed-after-reconciliation"
    with pytest.raises(InstructionFeatureLiveWorkflowError):
        closed.reconcile_restore(**IDENTITY)
    with pytest.raises(InstructionFeatureLiveWorkflowError):
        closed.preview_reconciled_restore(**IDENTITY)


def test_fresh_reconciled_restore_preserves_failed_claim_and_restores_once(cycle: Cycle) -> None:
    enable = workflow(cycle)
    assert enable.execute(authorize(enable), **IDENTITY)["verification"] == "verified"
    first = workflow(cycle, "restore")
    old = authorize(first)

    def unavailable() -> None:
        raise RuntimeError("synthetic-prewrite-read-unavailable")

    cycle.device.on_read = unavailable
    assert first.execute(old, **IDENTITY)["outcome"] == "reconciliation_required"
    cycle.device.on_read = lambda: None
    original_events = first._execution_store.audit_events
    recovered = workflow(cycle, "restore")
    preview = recovered.preview_reconciled_restore(**IDENTITY)
    cycle.device.clock = cast(int, preview["expires_at"])
    with pytest.raises(InstructionFeatureLiveWorkflowError):
        recovered.authorize(cast(str, preview["preview_ref"]), **IDENTITY)
    preview = recovered.preview_reconciled_restore(**IDENTITY)
    issued = recovered.authorize(cast(str, preview["preview_ref"]), **IDENTITY)
    reference = cast(str, issued["authorization_ref"])
    assert reference != old and recovered._authority._issued is not None
    plan = recovered._authority._issued.plan
    assert plan.revision == 2 and plan.action_version == "2.1.0"
    with pytest.raises(InstructionFeatureLiveWorkflowError):
        recovered.execute(old, **IDENTITY)
    assert recovered.execute(reference, **IDENTITY)["verification"] == "verified"
    assert recovered.execute(reference, **IDENTITY)["idempotent_replay"] is True
    assert recovered._execution_store.claim_count == 2
    assert recovered._execution_store.audit_events[:1] == original_events
    assert len(cycle.device.requests) == 2 and not cycle.device.enabled
    with pytest.raises(InstructionFeatureLiveWorkflowError):
        workflow(cycle, "restore").preview_reconciled_restore(**IDENTITY)


def test_reconciled_restore_rejects_unfinished_claim(cycle: Cycle) -> None:
    enable = workflow(cycle)
    assert enable.execute(authorize(enable), **IDENTITY)["verification"] == "verified"
    restore = workflow(cycle, "restore")
    restore._execution_store.claim(plan_ref="synthetic-unfinished-plan", requester_digest=REQUESTER,
        idempotency_digest="4" * 64, context_digest="5" * 64, authorization_digest="6" * 64)
    with pytest.raises(InstructionFeatureLiveWorkflowError):
        restore.preview_reconciled_restore(**IDENTITY)
    assert len(cycle.device.requests) == 1


def test_restore_reconciliation_rejects_dispatch_uncertainty(cycle: Cycle) -> None:
    enable = workflow(cycle)
    assert enable.execute(authorize(enable), **IDENTITY)["verification"] == "verified"
    restore = workflow(cycle, "restore")
    reference = authorize(restore)
    cycle.device.status = 500
    assert restore.execute(reference, **IDENTITY)["outcome"] == "reconciliation_required"
    assert (cycle.path / "restore.claim.json").exists()
    with pytest.raises(InstructionFeatureLiveWorkflowError):
        workflow(cycle, "restore", execution_enabled=False).reconcile_restore(**IDENTITY)
    with pytest.raises(InstructionFeatureLiveWorkflowError):
        workflow(cycle, "restore").preview_reconciled_restore(**IDENTITY)
    assert len(cycle.device.requests) == 2


def test_unknown_dispatch_has_one_put_and_blocks_restore(cycle: Cycle) -> None:
    item = workflow(cycle)
    reference = authorize(item)
    cycle.device.status = 500
    result = item.execute(reference,**IDENTITY)
    assert result["outcome"] == "reconciliation_required" and result["verification"] == "unknown"
    item.execute(reference,**IDENTITY)
    assert len(cycle.device.requests)==1
    with pytest.raises(InstructionFeatureLiveWorkflowError):
        workflow(cycle,"restore").preview(**IDENTITY)
    assert not (cycle.path/"enable.result.json").exists()
    assert_closed(cycle.device)


def test_restore_rejects_missing_original_proof_and_cross_phase_refs(cycle: Cycle) -> None:
    restore = workflow(cycle,"restore")
    with pytest.raises(InstructionFeatureLiveWorkflowError):
        restore.preview(**IDENTITY)
    enable = workflow(cycle)
    reference = authorize(enable)
    assert enable.execute(reference,**IDENTITY)["verification"]=="verified"
    restore.preview(**IDENTITY)
    with pytest.raises(InstructionFeatureLiveWorkflowError):
        restore.execute(reference,**IDENTITY)
    assert len(cycle.device.requests)==1 and restore._execution_store.claim_count==0


def test_canonical_directory_and_independent_key_are_required(cycle: Cycle) -> None:
    for overrides in ({"canonical_state_directory":cycle.path.parent},
                      {"authority_key":b"k"*32}):
        with pytest.raises(InstructionFeatureLiveWorkflowError):
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
        with pytest.raises(InstructionFeatureLiveWorkflowError):
            item.execute(reference,**IDENTITY)
    assert (cycle.path/"enable.result.json").exists()
    assert not (cycle.path/"enable.m4.json").exists()
    result = item.execute(reference,**IDENTITY)
    assert result["outcome"]=="reconciliation_required" and result["verification"]=="unknown"
    with pytest.raises(InstructionFeatureLiveWorkflowError):
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
