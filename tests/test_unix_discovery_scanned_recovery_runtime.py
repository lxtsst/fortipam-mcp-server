"""Trusted scoped recovery authority, durable preparation and opaque MCP DI."""
import asyncio
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from v4_planning import M4AuthorizationDenied
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.server import MCP_SERVER_CLASS
from fortipam_mcp.unix_discovery_scanned_recovery_runtime import (
    UnixScannedSourceRecoveryMcpAction, UnixScannedSourceRecoveryRuntime,
    open_original_scanned_source_recovery, register_unix_scanned_source_recovery_tools,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_discovery_scanned_source_recovery import RECOVERY_STORE, setup
from test_m4_execution_store import _ExternalM4Checkpoint
from test_v4_planning import _requester


def composition(tmp_path, monkeypatch, *, enabled=True, fault="none"):
    unused, reader, original, store, _, _, checkpoint, state, clock = setup(tmp_path, monkeypatch, fault=fault)
    unused.close()
    authority = tmp_path / "recovery-authority.key"
    authority.write_bytes(b"z" * 32); authority.chmod(0o600)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    options = dict(authority_key_file=authority, witness_key_file=tmp_path / "recovery-witness.key",
        environment_ref="scanned-recovery-environment01", scope_ref="scanned-recovery-scope01", audience_ref="scanned-recovery-audience01",
        requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest, clock=lambda: clock["now"],
        **({} if enabled is None else {"execution_enabled": enabled}))
    runtime = UnixScannedSourceRecoveryRuntime(reader, store, unused._directory, **options)
    return runtime, principal, reader, original, store, checkpoint, state, clock, options


def authorize(runtime, principal):
    preview = runtime.preview(principal)
    assert preview["Current State"]["exclusive_lab_operator_required"]
    assert not preview["Expected State"]["general_activity_or_timezone_qualified"]
    grant = runtime.issue(preview["preview_ref"], principal)
    assert grant["expires_at"] == 3060 and not grant["device_write_executed"]
    return grant["authorization_ref"]


def readonly_store(store):
    return PersistentM4ExecutionStateStore(store._path, store._key_path, monotonic_checkpoint=store._monotonic_checkpoint,
        checkpoint_store_ref=RECOVERY_STORE, read_only=True)


def test_trusted_issuer_owns_one_delete_and_terminal_replay_has_no_network(tmp_path, monkeypatch):
    runtime, principal, reader, original, store, checkpoint, state, clock, options = composition(tmp_path, monkeypatch)
    before = {p: p.read_bytes() for folder in (original._directory, original._creation._directory) for p in folder.iterdir()}
    auth = authorize(runtime, principal)
    assert store.claim_count == state["deletes"] == 0
    path = runtime._directory / "source-recovery-execution-context.json"
    assert path.stat().st_mode & 0o777 == 0o600
    prepared = path.read_bytes()
    result = runtime.execute(auth, principal)
    assert result.verification == "verified" and result.outcome == "succeeded"
    assert store.claim_count == state["deletes"] == 1 and not state["exists"]
    counts = state["deletes"], state["reference_gets"], state["recovery_gets"]
    assert runtime.execute(auth, principal).idempotent_replay
    assert counts == (state["deletes"], state["reference_gets"], state["recovery_gets"])
    assert {p: p.read_bytes() for p in before} == before and path.read_bytes() == prepared
    runtime.close(); assert not runtime._key and not runtime._adapter._key
    readonly = PersistentM4ExecutionStateStore(tmp_path / "recovery.sqlite", tmp_path / "recovery-store.key",
        monotonic_checkpoint=checkpoint, checkpoint_store_ref=RECOVERY_STORE, read_only=True)
    observed = open_original_scanned_source_recovery(runtime._directory, options["authority_key_file"], options["witness_key_file"],
        reader, readonly, clock=lambda: 9000)
    assert observed.inspect_original_result().original_verification == "verified"
    with pytest.raises(ValueError): observed._delete_http()
    assert state["deletes"] == 1 and all(client.is_closed for client in state["reference_clients"])


@pytest.mark.parametrize("enabled", [None, False])
def test_default_closed_previews_but_cannot_issue(tmp_path, monkeypatch, enabled):
    runtime, principal, _, _, store, _, state, _, _ = composition(tmp_path, monkeypatch, enabled=enabled)
    preview = runtime.preview(principal)
    with pytest.raises(M4AuthorizationDenied): runtime.issue(preview["preview_ref"], principal)
    assert store.claim_count == state["deletes"] == 0
    assert not (runtime._directory / "source-recovery-execution-context.json").exists()


@pytest.mark.parametrize("identity", ["requester", "transport"])
def test_wrong_identity_cannot_preview_or_consume_authority(tmp_path, monkeypatch, identity):
    runtime, principal, _, _, store, _, state, _, _ = composition(tmp_path, monkeypatch)
    other = V4PlanningPrincipal(_requester("other") if identity == "requester" else principal.requester,
        "b" * 64 if identity == "transport" else principal.transport_namespace_digest)
    with pytest.raises(M4AuthorizationDenied): runtime.preview(other)
    auth = authorize(runtime, principal)
    with pytest.raises(M4AuthorizationDenied): runtime.execute(auth, other)
    assert store.claim_count == state["deletes"] == 0


def test_equal_value_clones_are_not_the_issued_authority(tmp_path, monkeypatch):
    runtime, principal, _, _, store, _, state, _, _ = composition(tmp_path, monkeypatch)
    authorize(runtime, principal); plan, auth = runtime._issued
    with pytest.raises(M4AuthorizationDenied): runtime.verify(replace(plan), auth, now_epoch=3000)
    with pytest.raises(M4AuthorizationDenied): runtime.verify(plan, replace(auth), now_epoch=3000)
    runtime.verify(plan, auth, now_epoch=3000)
    assert store.claim_count == state["deletes"] == 0


@pytest.mark.parametrize("fault", ["context", "authority", "witness", "store_key", "checkpoint", "reader", "clock"])
def test_bound_execution_context_drift_refuses_before_claim(tmp_path, monkeypatch, fault):
    runtime, principal, reader, _, store, _, state, _, _ = composition(tmp_path, monkeypatch)
    auth = authorize(runtime, principal)
    if fault == "context": (runtime._directory / "source-recovery-execution-context.json").write_text("{}")
    elif fault in {"authority", "witness", "store_key"}:
        path = {"authority": runtime._authority_file, "witness": runtime._witness_file, "store_key": store._key_path}[fault]
        path.write_bytes(b"x" * 32)
    elif fault == "checkpoint": store._monotonic_checkpoint = _ExternalM4Checkpoint()
    elif fault == "reader": runtime._reader = SimpleNamespace(_validate=reader._validate)
    else: runtime._clock = lambda: 3000
    with pytest.raises(M4AuthorizationDenied): runtime.execute(auth, principal)
    assert state["deletes"] == 0
    if fault not in {"store_key", "checkpoint"}: assert store.claim_count == 0
    assert not (runtime._directory / "recovery-send.claim.json").exists()


@pytest.mark.parametrize("stage", ["preview", "issued"])
def test_expired_authority_never_dispatches(tmp_path, monkeypatch, stage):
    runtime, principal, _, _, store, _, state, clock, _ = composition(tmp_path, monkeypatch)
    ref = runtime.preview(principal)["preview_ref"]
    auth = runtime.issue(ref, principal)["authorization_ref"] if stage == "issued" else None
    clock["now"] = 3060
    with pytest.raises(M4AuthorizationDenied):
        if auth is None: runtime.issue(ref, principal)
        else: runtime.execute(auth, principal)
    assert store.claim_count == state["deletes"] == 0


def test_partial_preparation_poisoned_without_claim_or_restart(tmp_path, monkeypatch):
    runtime, principal, reader, _, store, _, state, _, options = composition(tmp_path, monkeypatch)
    ref = runtime.preview(principal)["preview_ref"]
    with monkeypatch.context() as patch:
        patch.setattr("fortipam_mcp.unix_discovery_scanned_recovery_runtime.os.fsync", lambda _: (_ for _ in ()).throw(OSError()))
        with pytest.raises(M4AuthorizationDenied): runtime.issue(ref, principal)
    assert store.claim_count == state["deletes"] == 0 and runtime._failed
    with pytest.raises(M4AuthorizationDenied): runtime.issue(ref, principal)
    with pytest.raises(M4AuthorizationDenied): UnixScannedSourceRecoveryRuntime(reader, store, runtime._directory, **options)


def test_prepared_context_is_not_original_receipt_or_resumable_authority(tmp_path, monkeypatch):
    runtime, principal, reader, _, store, _, state, _, options = composition(tmp_path, monkeypatch)
    authorize(runtime, principal)
    with pytest.raises(M4AuthorizationDenied):
        open_original_scanned_source_recovery(runtime._directory, options["authority_key_file"], options["witness_key_file"], reader, store)
    original = open_original_scanned_source_recovery(runtime._directory, options["authority_key_file"], options["witness_key_file"], reader, readonly_store(store))
    with pytest.raises(Exception): original.inspect_original_result()
    with pytest.raises(ValueError): original._delete_http()
    with pytest.raises(M4AuthorizationDenied): UnixScannedSourceRecoveryRuntime(reader, store, runtime._directory, **options)
    assert state["deletes"] == store.claim_count == 0


@pytest.mark.parametrize("fault", ["source", "reference"])
def test_fresh_relation_drift_denies_before_delete(tmp_path, monkeypatch, fault):
    runtime, principal, _, _, _, _, state, _, _ = composition(tmp_path, monkeypatch)
    auth = authorize(runtime, principal)
    if fault == "source": state["source_drift"] = True
    else: state["relation_target"]["description"] = "Changed before dispatch"
    result = runtime.execute(auth, principal)
    assert result.outcome in {"denied", "precondition_failed"} and state["deletes"] == 0


def test_authority_changed_during_final_read_refuses_object_claim(tmp_path, monkeypatch):
    runtime, principal, reader, original, _, _, state, _, _ = composition(tmp_path, monkeypatch)
    auth = authorize(runtime, principal); read = reader.read
    def changed_read():
        result = read(); runtime._authority_file.write_bytes(b"x" * 32); return result
    monkeypatch.setattr(reader, "read", changed_read)
    result = runtime.execute(auth, principal)
    assert result.verification == "unknown" and state["deletes"] == 0
    assert not (original._creation._directory / "source-scanned-recovery.claim.json").exists()


def test_authority_drift_after_send_seal_never_sends_delete(tmp_path, monkeypatch):
    from fortipam_mcp.discovery_scanned_source_recovery import ScannedSourceRecoveryM4Adapter
    runtime, principal, _, _, store, _, state, _, _ = composition(tmp_path, monkeypatch)
    auth = authorize(runtime, principal); write = ScannedSourceRecoveryM4Adapter._write
    def changed_write(adapter, directory, name, body):
        write(adapter, directory, name, body)
        if name == "recovery-send.claim.json": runtime._authority_file.write_bytes(b"x" * 32)
    monkeypatch.setattr(ScannedSourceRecoveryM4Adapter, "_write", changed_write)
    assert runtime.execute(auth, principal).verification == "unknown"
    assert state["deletes"] == 0 and store.claim_count == 1
    assert runtime._adapter._object_claim.exists()


@pytest.mark.parametrize("fault", ["lost", "partial", "post_target"])
def test_original_unknown_is_retained_and_cannot_repeat(tmp_path, monkeypatch, fault):
    runtime, principal, reader, _, store, _, state, _, options = composition(tmp_path, monkeypatch, fault=fault)
    auth = authorize(runtime, principal)
    assert runtime.execute(auth, principal).verification == "unknown"
    counts = state["deletes"], state["reference_gets"], state["recovery_gets"]
    assert runtime.execute(auth, principal).idempotent_replay
    assert counts == (state["deletes"], state["reference_gets"], state["recovery_gets"])
    original = open_original_scanned_source_recovery(runtime._directory, options["authority_key_file"], options["witness_key_file"], reader, readonly_store(store))
    observed = original.inspect_original_result()
    assert observed.original_verification == "unknown" and observed.acknowledgement_qualified is (fault == "post_target")
    assert state["deletes"] == store.claim_count == 1


def test_separate_mcp_contract_only_accepts_opaque_refs_and_has_own_gate(tmp_path, monkeypatch):
    runtime, principal, _, _, store, _, state, _, _ = composition(tmp_path, monkeypatch)
    action = UnixScannedSourceRecoveryMcpAction(runtime)
    server = SimpleNamespace(mcp=MCP_SERVER_CLASS("scanned-recovery-candidate"))
    register_unix_scanned_source_recovery_tools(server, action)
    schemas = {tool.name: tool.input_schema for tool in asyncio.run(server.mcp.list_tools())}
    assert schemas["preview_v4_unix_scanned_source_recovery_700"].get("properties", {}) == {}
    assert set(schemas["confirm_v4_unix_scanned_source_recovery_700"]["properties"]) == {"preview_ref"}
    assert set(schemas["execute_confirmed_v4_unix_scanned_source_recovery_700"]["properties"]) == {"authorization_ref"}
    auth = action.confirm(action.preview(principal)["preview_ref"], principal)["authorization_ref"]
    with pytest.raises(M4AuthorizationDenied): action.execute(auth, principal)
    assert state["deletes"] == store.claim_count == 0
    enabled = UnixScannedSourceRecoveryMcpAction(runtime, execution_enabled=True)
    assert enabled.execute(auth, principal)["verification"] == "verified"


def test_new_process_issues_recovery_after_original_expiry_and_original_records_stay_fixed(tmp_path, monkeypatch):
    runtime, _, reader, original, _, checkpoint, state, _, options = composition(tmp_path, monkeypatch)
    before = {p: p.read_bytes() for folder in (original._directory, original._creation._directory) for p in folder.iterdir()}
    peer_path = tmp_path / "reference-peer.json"
    peer_path.write_text(json.dumps({"secret": state["relation_secret"], "target": state["relation_target"]})); peer_path.chmod(0o600)
    source_tail = original._creation._store._monotonic_checkpoint.tail
    run_tail = original._store._monotonic_checkpoint.tail
    runtime.close()
    script = """
from pathlib import Path
from dataclasses import replace
import json,sys,httpx
from fortipam_mcp import discovery_scanned_source_recovery as recovery
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.unix_discovery_source_runtime import open_original_unix_source_custody
from fortipam_mcp.unix_discovery_account_run_runtime import open_original_unix_account_run_custody
from fortipam_mcp.unix_discovery_onboarding_guard import UnixDiscoveryOnboardingGuard
from fortipam_mcp.unix_discovery_scanned_recovery_runtime import UnixScannedSourceRecoveryRuntime
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_v4_planning import _requester
from test_m4_execution_store import _ExternalM4Checkpoint,CHECKPOINT_STORE_REF
from test_discovery_scanned_source_recovery import RECOVERY_STORE
from test_discovery_account_run_custody import RUN_STORE,FIXTURE,scanned_source
from test_discovery_source_create_custody import SOURCE,CONFIG,ACCOUNT,envelope
from test_discovery_review_http_transport import _Body
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
principal=V4PlanningPrincipal(_requester(),'a'*64)
runtime=UnixScannedSourceRecoveryRuntime(reader,store,src/'custody-account-run-recovery',authority_key_file=root/'recovery-authority.key',witness_key_file=root/'recovery-witness.key',environment_ref='scanned-recovery-environment01',scope_ref='scanned-recovery-scope01',audience_ref='scanned-recovery-audience01',requester_digest=principal.requester.digest,transport_digest=principal.transport_namespace_digest,execution_enabled=True,clock=lambda:3000)
assert original._authorization.expires_at<3000
grant=runtime.issue(runtime.preview(principal)['preview_ref'],principal)
result=runtime.execute(grant['authorization_ref'],principal)
assert result.verification=='verified' and counts['delete']==1 and store.claim_count==1
(root/'child-recovery-tail.json').write_text(json.dumps(asdict(cp3.tail)))
runtime.close();reader.close();guard.close();original.close();creation.close()
print('independent trusted scoped recovery verified')
""".replace("import json,sys,httpx", "import json,sys,httpx\nfrom dataclasses import asdict")
    env = {**os.environ, "PYTHONPATH": os.pathsep.join((str(Path(__file__).parent), os.environ.get("PYTHONPATH", "")))}
    child = subprocess.run([sys.executable, "-c", script, str(tmp_path), str(source_tail.sequence), source_tail.chain_hmac,
        str(run_tail.sequence), run_tail.chain_hmac], env=env, capture_output=True, text=True, timeout=30)
    assert child.returncode == 0, child.stderr
    assert child.stdout.strip() == "independent trusted scoped recovery verified"
    assert {p: p.read_bytes() for p in before} == before
    tail = json.loads((tmp_path / "child-recovery-tail.json").read_bytes()); checkpoint.tail = replace(checkpoint.tail, **tail)
    readonly = PersistentM4ExecutionStateStore(tmp_path / "recovery.sqlite", tmp_path / "recovery-store.key",
        monotonic_checkpoint=checkpoint, checkpoint_store_ref=RECOVERY_STORE, read_only=True)
    observed = open_original_scanned_source_recovery(runtime._directory, options["authority_key_file"], options["witness_key_file"], reader, readonly, clock=lambda: 9000)
    assert observed.inspect_original_result().original_verification == "verified"
