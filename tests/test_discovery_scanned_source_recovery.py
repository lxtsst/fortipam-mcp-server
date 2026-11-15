"""Independent original stores and fixed recovery peers through real M4 kernels."""
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import subprocess
import sys

import httpx
import pytest

from v4_planning import M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionPlan, canonical_digest
from fortipam_mcp.discovery_scanned_source_recovery import (
    ACTION_ID, ACTION_VERSION, ADAPTER_REF, ScannedSourceRecoveryError, ScannedSourceRecoveryM4Adapter,
    ScannedSourceRecoveryReader, scanned_recovery_parameters_digest, scanned_recovery_state_digest, scanned_recovery_summary,
)
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.unix_discovery_source_runtime import open_original_unix_source_custody
from fortipam_mcp.unix_discovery_account_run_runtime import open_original_unix_account_run_custody
from fortipam_mcp.unix_discovery_onboarding_guard import UnixDiscoveryOnboardingGuard
from test_unix_discovery_account_run_runtime import composition, authorize
from test_discovery_account_run_custody import FIXTURE, RUN_STORE, scanned_source
from test_discovery_source_create_custody import ACCOUNT, CONFIG, SOURCE, envelope
from test_discovery_review_http_transport import _Body
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF
from test_v4_execution_kernel import _Verifier

RECOVERY_STORE = "scanned-source-recovery-test01"


def setup(tmp_path, monkeypatch, *, fault="none", run_fault="none", guarded=True):
    original_client = httpx.Client
    runtime, principal, _, run_checkpoint, state, _, source_checkpoint, _ = composition(tmp_path, monkeypatch, with_guard=guarded, fault=run_fault)
    authorization, _ = authorize(runtime, principal); runtime.execute(authorization, principal)
    source_root = tmp_path / "source"
    source_store = PersistentM4ExecutionStateStore(source_root / "execution.sqlite", source_root / "execution.key",
        monotonic_checkpoint=source_checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF, read_only=True)
    creation = open_original_unix_source_custody(source_root / "custody", source_root / "authority.key", source_root / "source.key", SOURCE, source_store, CONFIG)
    run_store = PersistentM4ExecutionStateStore(tmp_path / "run.sqlite", tmp_path / "run-store.key",
        monotonic_checkpoint=run_checkpoint, checkpoint_store_ref=RUN_STORE, read_only=True)
    original = open_original_unix_account_run_custody(source_root / "custody-account-run", tmp_path / "run-authority.key",
        tmp_path / "run-witness.key", creation, run_store, CONFIG, selected_account=ACCOUNT, fixture_birth_digest=FIXTURE)
    if not guarded or run_fault != "none": return original, state
    state.update(exists=True, recovery_gets=0, deletes=0, reference_gets=0, reference_clients=[])
    def source_peer(request):
        assert request.url.path == "/api/v2/cmdb/secret/discovery/" + SOURCE.request.source_name
        if request.method == "DELETE":
            state["deletes"] += 1
            state["exists"] = fault == "still_present"
            if fault == "lost": raise httpx.ReadTimeout("Synthetic original DELETE ACK loss")
            if fault == "post_target": state["relation_target"]["description"] = "Changed after DELETE"
            if fault == "post_invalid_target": state["relation_target"].pop("address")
            if fault == "duplicate":
                return httpx.Response(200, content='{"status":"success","status":"error"}', headers={"content-type": "application/json"})
            if fault == "large": return httpx.Response(200, content=b"x" * 20_000, headers={"content-type": "application/json"})
            body = {**envelope("DELETE"), "mkey": SOURCE.request.source_name, "error": 0}
            if fault == "partial":
                class Partial(httpx.SyncByteStream):
                    def __iter__(self):
                        yield json.dumps(body).encode()
                        raise httpx.ReadTimeout("Synthetic response stream loss after JSON")
                return httpx.Response(200, headers={"content-type": "application/json"}, stream=Partial())
            if fault == "foreign_ack": body["serial"] = "OTHER-SYNTHETIC"
            return httpx.Response(200, json=body)
        assert request.method == "GET"
        state["recovery_gets"] += 1
        if not state["exists"]: return httpx.Response(404, json={**envelope(status=404), "results": []})
        row = scanned_source()
        if state.get("source_drift"): row["extra-native-state"] = {"changed": True}
        return httpx.Response(200, json={**envelope(), "results": [row]})
    def references_peer(request):
        index = state["reference_gets"] % 4; state["reference_gets"] += 1
        assert request.method == "GET"
        table = "database" if index in (0, 3) else "target"
        assert request.url.path.endswith("/" + ("17" if table == "database" else "SyntheticTarget"))
        row = state["relation_secret"] if table == "database" else state["relation_target"]
        body = {**envelope(), "name": table, "status": "OK" if table == "database" else "success", "results": [row]}
        return httpx.Response(200, headers={"content-type": "application/json"}, stream=_Body(json.dumps(body).encode(), lambda: None))
    def reference_factory(**kwargs):
        client = original_client(**kwargs, transport=httpx.MockTransport(references_peer)); state["reference_clients"].append(client)
        return client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original_client(**kwargs, transport=httpx.MockTransport(source_peer)))
    monkeypatch.setattr("fortipam_mcp.discovery_scanned_source_recovery._ssl_context", lambda _: True)
    guard = UnixDiscoveryOnboardingGuard(CONFIG, selection_binding_path=runtime._guard._selection_path, profile_path=runtime._guard._profile_path,
        client_factory=reference_factory, original_run_enabled=True)
    reader = ScannedSourceRecoveryReader(original, guard)
    directory = original._directory.with_name(original._directory.name + "-recovery"); directory.mkdir(mode=0o700)
    for name, data in (("recovery-witness.key", b"w" * 32), ("recovery-store.key", b"v" * 32)):
        path = tmp_path / name; path.write_bytes(data); path.chmod(0o600)
    checkpoint = _ExternalM4Checkpoint(); checkpoint.tail = replace(checkpoint.tail, store_ref=RECOVERY_STORE)
    store = PersistentM4ExecutionStateStore(tmp_path / "recovery.sqlite", tmp_path / "recovery-store.key",
        monotonic_checkpoint=checkpoint, checkpoint_store_ref=RECOVERY_STORE)
    fields = {**original._plan.canonical_content(), "plan_ref": "scanned-source-recovery-plan-test01", "action_id": ACTION_ID,
        "action_version": ACTION_VERSION, "adapter_ref": ADAPTER_REF, "expires_at": 3060,
        "summary_digest": canonical_digest(scanned_recovery_summary()), "parameters_digest": scanned_recovery_parameters_digest(original),
        "expected_current_digest": scanned_recovery_state_digest(original, exists=True),
        "expected_state_digest": scanned_recovery_state_digest(original, exists=False)}
    plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
    values = asdict(runtime._issued[1]); values.pop("authorization_digest")
    values.update(authorization_ref="scanned-source-recovery-auth-test01", plan_ref=plan.plan_ref, plan_digest=plan.plan_digest,
        issued_at=3000, expires_at=3060)
    auth = M4ExecutionAuthorization(**values, authorization_digest=canonical_digest(values))
    clock = {"now": 3000}
    adapter = ScannedSourceRecoveryM4Adapter(reader, plan, auth, store, directory, tmp_path / "recovery-witness.key", clock=lambda: clock["now"])
    return adapter, reader, original, store, plan, auth, checkpoint, state, clock


def execute(adapter, store, plan, auth, clock):
    return M4ExecutionKernel(adapter, _Verifier(), store, clock=lambda: clock["now"]).execute(plan, auth)


def test_scoped_recovery_after_original_expiry_preserves_references_and_original_records(tmp_path, monkeypatch):
    adapter, reader, original, store, plan, auth, checkpoint, state, clock = setup(tmp_path, monkeypatch)
    before = {p: p.read_bytes() for folder in (original._directory, original._creation._directory) for p in folder.iterdir()}
    assert clock["now"] > original._authorization.expires_at
    preview = reader.preview()
    assert preview["Current State"]["exclusive_lab_operator_required"] and not preview["Expected State"]["general_activity_or_timezone_qualified"]
    result = execute(adapter, store, plan, auth, clock)
    assert result.outcome == "succeeded" and result.verification == "verified"
    assert state["deletes"] == store.claim_count == 1 and not state["exists"]
    observed = adapter.inspect_original_result()
    assert observed.acknowledgement_qualified and observed.original_verification == "verified" and not observed.general_activity_or_timezone_qualified
    assert {p: p.read_bytes() for p in before} == before
    assert all(client.is_closed for client in state["reference_clients"])
    counts = (state["deletes"], state["reference_gets"], state["recovery_gets"])
    assert execute(adapter, store, plan, auth, clock).idempotent_replay
    assert (state["deletes"], state["reference_gets"], state["recovery_gets"]) == counts
    adapter.close(); assert not adapter._key
    readonly = PersistentM4ExecutionStateStore(tmp_path / "recovery.sqlite", tmp_path / "recovery-store.key",
        monotonic_checkpoint=checkpoint, checkpoint_store_ref=RECOVERY_STORE, read_only=True)
    reopened = ScannedSourceRecoveryM4Adapter(reader, plan, auth, readonly, adapter._directory, adapter._key_file, clock=lambda: 5000)
    assert reopened.inspect_original_result() == observed
    with pytest.raises(ValueError): reopened._delete_http()
    assert state["deletes"] == 1


@pytest.mark.parametrize("fault", ["lost", "partial", "foreign_ack", "duplicate", "large", "post_target", "still_present"])
def test_uncertain_or_unpreserved_recovery_retains_original_ack_category_and_unknown(tmp_path, monkeypatch, fault):
    adapter, _, _, store, plan, auth, _, state, clock = setup(tmp_path, monkeypatch, fault=fault)
    result = execute(adapter, store, plan, auth, clock)
    assert result.verification == "unknown" and state["deletes"] == store.claim_count == 1
    original = adapter.inspect_original_result()
    assert original.acknowledgement_qualified is (fault in {"post_target", "still_present"})
    assert original.original_verification == "unknown"
    counts = (state["deletes"], state["reference_gets"], state["recovery_gets"])
    assert execute(adapter, store, plan, auth, clock).idempotent_replay
    assert counts == (state["deletes"], state["reference_gets"], state["recovery_gets"])


@pytest.mark.parametrize("fault", ["source", "reference", "already_absent"])
def test_fresh_source_reference_or_absence_drift_refuses_before_delete(tmp_path, monkeypatch, fault):
    adapter, _, _, store, plan, auth, _, state, clock = setup(tmp_path, monkeypatch)
    if fault == "source": state["source_drift"] = True
    elif fault == "reference": state["relation_target"]["description"] = "Changed before recovery"
    else: state["exists"] = False
    result = execute(adapter, store, plan, auth, clock)
    assert result.outcome == ("denied" if fault == "source" else "precondition_failed") and state["deletes"] == 0
    assert not adapter._object_claim.exists()


@pytest.mark.parametrize("run_fault,guarded", [("pending", True), ("lost", True), ("none", False)])
def test_original_unknown_pending_or_missing_baseline_never_qualifies_recovery(tmp_path, monkeypatch, run_fault, guarded):
    original, state = setup(tmp_path, monkeypatch, run_fault=run_fault, guarded=guarded)
    with pytest.raises(ScannedSourceRecoveryError): scanned_recovery_parameters_digest(original)
    assert state["posts"] == 1


def test_direct_or_reserved_dispatch_cannot_delete_or_write_original_records(tmp_path, monkeypatch):
    adapter, reader, _, store, plan, auth, _, state, _ = setup(tmp_path, monkeypatch)
    with pytest.raises(Exception): adapter.dispatch(plan)
    with pytest.raises(ValueError): reader._http("DELETE", 16_384)
    store.claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest, idempotency_digest=plan.idempotency_digest,
        authorization_digest=auth.authorization_digest, context_digest=canonical_digest(dict(plan_digest=plan.plan_digest, authorization_digest=auth.authorization_digest, revision=plan.revision)))
    with pytest.raises(Exception): adapter.dispatch(plan)
    assert state["deletes"] == 0 and not adapter._object_claim.exists()


def test_retained_object_claim_blocks_another_dispatch_without_reconstructing_receipt(tmp_path, monkeypatch):
    adapter, _, _, store, plan, auth, _, state, clock = setup(tmp_path, monkeypatch)
    adapter._object_claim.write_text("retained prior object dispatch"); adapter._object_claim.chmod(0o600)
    result = execute(adapter, store, plan, auth, clock)
    assert result.verification == "unknown" and state["deletes"] == 0
    assert not (adapter._directory / "recovery-delete-ack.json").exists()


def test_independent_process_performs_recovery_after_original_expiry_without_original_writes(tmp_path, monkeypatch):
    adapter, _, original, _, plan, auth, checkpoint, state, _ = setup(tmp_path, monkeypatch)
    before = {p: p.read_bytes() for folder in (original._directory, original._creation._directory) for p in folder.iterdir()}
    for name, value in (("recovery-plan.json", asdict(plan)), ("recovery-auth.json", asdict(auth)),
            ("reference-peer.json", {"secret": state["relation_secret"], "target": state["relation_target"]})):
        path = tmp_path / name; path.write_text(json.dumps(value)); path.chmod(0o600)
    source_tail = original._creation._store._monotonic_checkpoint.tail
    run_tail = original._store._monotonic_checkpoint.tail
    script = """
from pathlib import Path
from dataclasses import replace
import json,sys,httpx
from fortipam_mcp import discovery_scanned_source_recovery as recovery
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.unix_discovery_source_runtime import open_original_unix_source_custody
from fortipam_mcp.unix_discovery_account_run_runtime import open_original_unix_account_run_custody
from fortipam_mcp.unix_discovery_onboarding_guard import UnixDiscoveryOnboardingGuard
from v4_planning import M4ExecutionPlan,M4ExecutionAuthorization,M4ExecutionKernel
from test_m4_execution_store import _ExternalM4Checkpoint,CHECKPOINT_STORE_REF
from test_discovery_scanned_source_recovery import RECOVERY_STORE
from test_discovery_account_run_custody import RUN_STORE,FIXTURE,scanned_source
from test_discovery_source_create_custody import SOURCE,CONFIG,ACCOUNT,envelope
from test_discovery_review_http_transport import _Body
from test_v4_execution_kernel import _Verifier
root=Path(sys.argv[1]);src=root/'source'
cp=_ExternalM4Checkpoint();cp.tail=replace(cp.tail,sequence=int(sys.argv[2]),chain_hmac=sys.argv[3])
source_store=PersistentM4ExecutionStateStore(src/'execution.sqlite',src/'execution.key',monotonic_checkpoint=cp,checkpoint_store_ref=CHECKPOINT_STORE_REF,read_only=True)
creation=open_original_unix_source_custody(src/'custody',src/'authority.key',src/'source.key',SOURCE,source_store,CONFIG)
cp2=_ExternalM4Checkpoint();cp2.tail=replace(cp2.tail,store_ref=RUN_STORE,sequence=int(sys.argv[4]),chain_hmac=sys.argv[5])
run_store=PersistentM4ExecutionStateStore(root/'run.sqlite',root/'run-store.key',monotonic_checkpoint=cp2,checkpoint_store_ref=RUN_STORE,read_only=True)
original=open_original_unix_account_run_custody(src/'custody-account-run',root/'run-authority.key',root/'run-witness.key',creation,run_store,CONFIG,selected_account=ACCOUNT,fixture_birth_digest=FIXTURE)
peer=json.loads((root/'reference-peer.json').read_bytes());counts={'delete':0};real_client=httpx.Client
def respond(request):
    if '/discovery/' in request.url.path:
        if request.method=='DELETE':
            counts['delete']+=1;(root/'source-deleted.private').write_text('deleted')
            return httpx.Response(200,json={**envelope('DELETE'),'error':0,'mkey':SOURCE.request.source_name})
        assert request.method=='GET'
        if (root/'source-deleted.private').exists():return httpx.Response(404,json={**envelope(status=404),'results':[]})
        return httpx.Response(200,json={**envelope(),'results':[scanned_source()]})
    assert request.method=='GET'
    table='database' if '/database/' in request.url.path else 'target'
    body={**envelope(),'name':table,'status':'OK' if table=='database' else 'success','results':[peer['secret' if table=='database' else 'target']]}
    return httpx.Response(200,headers={'content-type':'application/json'},stream=_Body(json.dumps(body).encode(),lambda:None))
def factory(**kwargs):return real_client(**kwargs,transport=httpx.MockTransport(respond))
httpx.Client=factory;recovery._ssl_context=lambda _:True
guard=UnixDiscoveryOnboardingGuard(CONFIG,selection_binding_path=root/'guard-inputs/private/selection.json',profile_path=root/'guard-inputs/private/profile.json',client_factory=factory,original_run_enabled=True)
reader=recovery.ScannedSourceRecoveryReader(original,guard)
cp3=_ExternalM4Checkpoint();cp3.tail=replace(cp3.tail,store_ref=RECOVERY_STORE)
store=PersistentM4ExecutionStateStore(root/'recovery.sqlite',root/'recovery-store.key',monotonic_checkpoint=cp3,checkpoint_store_ref=RECOVERY_STORE)
p=M4ExecutionPlan(**json.loads((root/'recovery-plan.json').read_bytes()));a=M4ExecutionAuthorization(**json.loads((root/'recovery-auth.json').read_bytes()))
adapter=recovery.ScannedSourceRecoveryM4Adapter(reader,p,a,store,src/'custody-account-run-recovery',root/'recovery-witness.key',clock=lambda:3000)
result=M4ExecutionKernel(adapter,_Verifier(),store,clock=lambda:3000).execute(p,a)
assert result.verification=='verified' and counts['delete']==1 and store.claim_count==1
assert adapter.inspect_original_result().general_activity_or_timezone_qualified is False
(root/'child-recovery-tail.json').write_text(json.dumps({'sequence':cp3.tail.sequence,'chain_hmac':cp3.tail.chain_hmac}))
adapter.close();reader.close();guard.close();original.close();creation.close()
print('independent scoped Source recovery verified')
"""
    env = {**os.environ, "PYTHONPATH": os.pathsep.join((str(Path(__file__).parent), os.environ.get("PYTHONPATH", "")))}
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path), str(source_tail.sequence), source_tail.chain_hmac,
        str(run_tail.sequence), run_tail.chain_hmac], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "independent scoped Source recovery verified" and (tmp_path / "source-deleted.private").exists()
    assert {p: p.read_bytes() for p in before} == before
    tail = json.loads((tmp_path / "child-recovery-tail.json").read_bytes()); checkpoint.tail = replace(checkpoint.tail, **tail)
    readonly = PersistentM4ExecutionStateStore(tmp_path / "recovery.sqlite", tmp_path / "recovery-store.key",
        monotonic_checkpoint=checkpoint, checkpoint_store_ref=RECOVERY_STORE, read_only=True)
    observed = ScannedSourceRecoveryM4Adapter(adapter._reader, plan, auth, readonly, adapter._directory, adapter._key_file, clock=lambda: 5000)
    assert observed.inspect_original_result().original_verification == "verified"


def test_pinned_source_route_drift_refuses_before_network(tmp_path, monkeypatch):
    _, reader, _, _, _, _, _, state, _ = setup(tmp_path, monkeypatch)
    reader._path = "/api/v2/cmdb/secret/discovery/other?vdom=root"
    with pytest.raises(ScannedSourceRecoveryError): reader.read()
    assert state["deletes"] == state["recovery_gets"] == state["reference_gets"] == 0


def test_original_delete_receipt_tamper_cannot_be_promoted_by_terminal_m4_success(tmp_path, monkeypatch):
    adapter, _, _, store, plan, auth, _, _, clock = setup(tmp_path, monkeypatch)
    assert execute(adapter, store, plan, auth, clock).verification == "verified"
    path = adapter._directory / "recovery-delete-ack.json"
    receipt = json.loads(path.read_bytes()); receipt["acknowledgement_qualified"] = False
    path.write_text(json.dumps(receipt))
    with pytest.raises(ScannedSourceRecoveryError): adapter.inspect_original_result()


def test_original_receipt_survives_poisoned_live_reference_reader(tmp_path, monkeypatch):
    adapter, reader, _, store, plan, auth, _, state, clock = setup(tmp_path, monkeypatch, fault="post_invalid_target")
    assert execute(adapter, store, plan, auth, clock).verification == "unknown"
    assert not reader._guard._key
    original = adapter.inspect_original_result()
    assert original.acknowledgement_qualified and original.original_verification == "unknown"
    with pytest.raises(ScannedSourceRecoveryError): reader.preview()
    assert state["deletes"] == 1
