"""Real persistent M4 composition retains complete original pins before send."""
from dataclasses import asdict
import json

import pytest

from fortipam_mcp.job_definition_owned_workflow import JobDefinitionOwnedWorkflow, CONTRACT
from fortipam_mcp.job_definition_sources import JobDefinitionSources
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_job_definition_sources import make
from test_job_definition_create_m4_adapter import Native as CreateNative
from test_job_definition_recovery_m4_adapter import Native as RecoverNative
from test_job_definition_authority import IDENTITY
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF

CALLER = {k:IDENTITY[k] for k in ("requester_digest", "transport_digest")}


def prepared(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    source,api,*_ = make(tmp_path,monkeypatch)
    root = tmp_path/"owned";root.mkdir(mode=0o700)
    for i,phase in enumerate(("create","recover")):
        directory = root/phase;directory.mkdir(mode=0o700);(directory/"native").mkdir(mode=0o700)
        for j,name in enumerate(("authority","witness","execution")):
            path = directory/(name+".key");path.write_bytes(bytes([70+i*3+j])*32);path.chmod(0o600)
    checkpoints = {p:_ExternalM4Checkpoint() for p in ("create","recover")}
    def store(phase, read_only):
        return PersistentM4ExecutionStateStore(root/phase/"execution.sqlite3",root/phase/"execution.key",
            monotonic_checkpoint=checkpoints[phase],checkpoint_store_ref=CHECKPOINT_STORE_REF,read_only=read_only)
    def graph(phase="create", *, fault=None, clock=lambda:1000, guard=lambda:True, enabled=True, binding="d"*64):
        nonlocal source
        if source._closed:
            source = JobDefinitionSources(candidate=source._candidate,anchor=source._anchor,ssh=source._ssh,
                client_factory=api.factory,clock=lambda:api.now)
        native = []
        def factory(*args,**kwargs):
            if not native:
                native.append(CreateNative(api,workflow._original,workflow._original._pins,fault=fault)
                    if phase == "create" else RecoverNative(api,fault=fault))
            if phase == "create":
                packet = workflow._records["create"].read("constructor.json")
                assert packet["pins"] == asdict(workflow._original._pins)
                assert packet["source_context_digest"] == source.source_context_digest
            return native[0].factory(*args,**kwargs)
        elapsed=[0.0]
        def wait(seconds):elapsed[0]+=seconds
        workflow = JobDefinitionOwnedWorkflow(source,root=root,phase=phase,source_binding_digest=binding,
            identity=IDENTITY,store_factory=store,source_guard=guard,execution_enabled=enabled,
            clock=clock,connection_factory=factory,publication_wait=wait,publication_clock=lambda:elapsed[0])
        return workflow,native
    return source,api,root,graph,store


def invoke(workflow):
    preview = workflow.preview(**CALLER)
    grant = workflow.authorize(preview["preview_ref"],**CALLER)
    return workflow.execute(grant["authorization_ref"],**CALLER)


def test_normal_create_then_recomposed_readonly_original_recovery(tmp_path,monkeypatch):
    source,api,root,graph,store = prepared(tmp_path,monkeypatch)
    workflow,native = graph();created = invoke(workflow)
    assert created["outcome"] == "succeeded" and created["complete_pristine_state_or_global_absence"]
    assert created["all_candidate_gates_closed"] and api.present
    before = {p:p.read_bytes() for p in (root/"create").rglob("*") if p.is_file()}
    with pytest.raises(ValueError):graph()
    recovery,deleted = graph("recover");result = invoke(recovery)
    assert result["outcome"] == "succeeded" and result["verification"] == "verified"
    assert result["original_records_preserved"] and result["original_store_read_only"]
    assert result["native_claim_count"] == 1 and not api.present
    assert all(p.read_bytes() == raw for p,raw in before.items())
    assert len(native[0].calls) == len(deleted[0].calls) == 1
    with pytest.raises(ValueError):graph("recover")


@pytest.mark.parametrize("fault", ["lost-ack","readback","close"])
def test_unknown_is_never_replayed_or_late_sealed(tmp_path,monkeypatch,fault):
    source,api,root,graph,store = prepared(tmp_path,monkeypatch)
    workflow,native = graph(fault=fault);result = invoke(workflow)
    assert result["outcome"] == "reconciliation_required" and result["verification"] == "unknown"
    before = {p:p.read_bytes() for p in (root/"create").rglob("*") if p.is_file()}
    with pytest.raises(ValueError):graph()
    with pytest.raises(Exception):graph("recover")
    assert all(p.read_bytes() == raw for p,raw in before.items()) and len(native[0].calls) == 1


@pytest.mark.parametrize("fault", ["missing","tamper","changed-source"])
def test_missing_or_changed_constructor_never_becomes_recovery_authority(tmp_path,monkeypatch,fault):
    source,api,root,graph,store = prepared(tmp_path,monkeypatch)
    workflow,_ = graph();invoke(workflow)
    path = root/"create"/"constructor.json"
    if fault == "missing":path.unlink()
    elif fault == "tamper":
        packet = json.loads(path.read_bytes());packet["pins"]["private_nonce"] = "a"*64;path.write_text(json.dumps(packet))
    calls = len(api.calls)
    with pytest.raises(Exception):graph("recover",binding="e"*64 if fault == "changed-source" else "d"*64)
    assert len(api.calls) == calls and api.present


def test_failed_constructor_retention_prevents_m4_reservation_and_network(tmp_path,monkeypatch):
    source,api,root,graph,store = prepared(tmp_path,monkeypatch)
    workflow,native = graph()
    def unavailable(*args):raise OSError("synthetic persistence failure")
    monkeypatch.setattr(workflow._records["create"],"write",unavailable)
    with pytest.raises(OSError):invoke(workflow)
    assert not native and store("create",False).claim_count == 0 and not api.present
    assert not(root/"create"/"native"/"send.claim.json").exists()
