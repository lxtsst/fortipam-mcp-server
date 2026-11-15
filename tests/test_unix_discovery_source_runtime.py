"""Real Unix C/P/E, scoped lab verifier, durable kernel and fixed synthetic HTTP."""
from dataclasses import replace
import asyncio
import hashlib
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from v4_planning import M4AuthorizationDenied

from fortipam_mcp.discovery_entry_create_http_transport import FortiPamDiscoveryEntryCreateHttpTransport
from fortipam_mcp.discovery_entry_live_workflow import UnixDiscoveryCreateLiveWorkflow
from fortipam_mcp.unix_discovery_source_runtime import UnixDiscoverySourceMcpAction, UnixDiscoverySourceRuntime, open_original_unix_source_custody
from fortipam_mcp.discovery_entry_mcp_action import register_unix_discovery_candidate_tools
from fortipam_mcp.server import MCP_SERVER_CLASS
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_discovery_source_create_custody import CONFIG, SERIAL, SOURCE, create, native_transport
from test_v4_planning import _requester


def composition(tmp_path, monkeypatch, *, enabled=True, fault="none"):
    unused, store, _, _, checkpoint = create(tmp_path)
    unused.close()
    authority = tmp_path / "authority.key"
    authority.write_bytes(b"a" * 32)
    authority.chmod(0o600)
    transport, state = native_transport(monkeypatch, None, fault=fault)
    time = {"now": 1000}
    clock = lambda: time["now"]
    workflow = UnixDiscoveryCreateLiveWorkflow(transport, SOURCE.request, tmp_path / "legacy-claim.json", clock=clock)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    runtime = UnixDiscoverySourceRuntime(workflow, store, tmp_path / "custody", authority_key_file=authority,
        witness_key_file=tmp_path / "source.key", source_binding=SOURCE,
        environment_ref="unix-lab-environment01", scope_ref="unix-source-scope01", audience_ref="unix-source-audience01",
        requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest,
        serial_digest=hashlib.sha256(SERIAL.encode()).hexdigest(), clock=clock,
        **({} if enabled is None else {"execution_enabled": enabled}))
    return runtime, principal, store, checkpoint, state, time


def authorize(runtime, principal):
    preview = runtime.preview(principal)
    assert preview["scan_import_or_recovery_authorized"] is False
    return runtime.issue(preview["preview_ref"], principal)["authorization_ref"]


def test_actual_composition_owns_one_post_and_original_custody_survives_independent_process(tmp_path, monkeypatch):
    runtime, principal, store, checkpoint, state, time = composition(tmp_path, monkeypatch)
    auth = authorize(runtime, principal)
    result = runtime.execute(auth, principal)
    assert result.outcome == "succeeded" and result.verification == "verified"
    assert state["posts"] == store.claim_count == 1
    assert (tmp_path / "legacy-claim.json").exists()
    files = {p.name: p.read_bytes() for p in (tmp_path / "custody").iterdir()}
    assert set(files) == {"source-execution-context.json", "source-send.claim.json", "source-create-ack.json", "source-created-state.json"}
    assert all(value not in b"".join(files.values()) for value in (SOURCE.request.source_name.encode(), SERIAL.encode(), b"synthetic-token"))
    assert runtime._custody is not None and not runtime._custody._key
    replay = runtime.execute(auth, principal)
    assert replay.idempotent_replay and state["posts"] == store.claim_count == 1
    time["now"] = 5000
    with pytest.raises(M4AuthorizationDenied): runtime.execute(auth, principal)
    runtime.close()
    assert not runtime._key
    script = """
import sys
from pathlib import Path
from test_discovery_source_create_custody import CONFIG, SOURCE
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF
from fortipam_mcp.m4_execution_store import M4ExecutionStoreTail, PersistentM4ExecutionStateStore
from fortipam_mcp.unix_discovery_source_runtime import open_original_unix_source_custody
root = Path(sys.argv[1])
checkpoint = _ExternalM4Checkpoint()
checkpoint.tail = M4ExecutionStoreTail(checkpoint.tail.store_ref, int(sys.argv[2]), sys.argv[3])
store = PersistentM4ExecutionStateStore(root / 'execution.sqlite', root / 'execution.key',
    monotonic_checkpoint=checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF, read_only=True)
custody = open_original_unix_source_custody(root / 'custody', root / 'authority.key', root / 'source.key', SOURCE, store, CONFIG)
observed = custody.inspect_original_state()
assert observed.acknowledgement_qualified and observed.original_outcome == 'succeeded'
assert observed.original_verification == 'verified' and store.claim_count == 1
custody.close()
print('independent original custody verified')
"""
    env = {**os.environ, "PYTHONPATH": os.pathsep.join((str(Path(__file__).parent), os.environ.get("PYTHONPATH", "")))}
    child = subprocess.run([sys.executable, "-c", script, str(tmp_path), str(checkpoint.tail.sequence), checkpoint.tail.chain_hmac],
        env=env, capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, child.stderr
    assert child.stdout.strip() == "independent original custody verified"
    assert {p.name: p.read_bytes() for p in (tmp_path / "custody").iterdir()} == files
    assert state["posts"] == 1


@pytest.mark.parametrize("enabled", [None, False])
def test_default_closed_cannot_issue_or_write(tmp_path, monkeypatch, enabled):
    runtime, principal, store, _, state, _ = composition(tmp_path, monkeypatch, enabled=enabled)
    preview = runtime.preview(principal)
    with pytest.raises(M4AuthorizationDenied): runtime.issue(preview["preview_ref"], principal)
    assert list((tmp_path / "custody").iterdir()) == []
    assert state["posts"] == store.claim_count == 0


def test_identity_and_same_value_authorization_clone_cannot_cross_server_binding(tmp_path, monkeypatch):
    runtime, principal, store, _, state, _ = composition(tmp_path, monkeypatch)
    other = V4PlanningPrincipal(principal.requester, "b" * 64)
    with pytest.raises(M4AuthorizationDenied): runtime.preview(other)
    preview = runtime.preview(principal)
    with pytest.raises(M4AuthorizationDenied): runtime.issue(preview["preview_ref"], other)
    auth = runtime.issue(preview["preview_ref"], principal)["authorization_ref"]
    issued = runtime._issued
    with pytest.raises(M4AuthorizationDenied):
        runtime.verify(issued.plan, replace(issued.authorization), now_epoch=1000)
    with pytest.raises(M4AuthorizationDenied): runtime.execute(auth, other)
    assert state["posts"] == store.claim_count == 0


def test_reference_drift_refuses_before_claim_and_cannot_revive_authority(tmp_path, monkeypatch):
    runtime, principal, store, _, state, _ = composition(tmp_path, monkeypatch)
    auth = authorize(runtime, principal)
    monkeypatch.setattr(FortiPamDiscoveryEntryCreateHttpTransport, "inspect_credential_reference", lambda *args: "9" * 64)
    with pytest.raises(M4AuthorizationDenied): runtime.execute(auth, principal)
    assert state["posts"] == store.claim_count == 0
    assert not (tmp_path / "legacy-claim.json").exists()
    assert not (tmp_path / "custody/source-send.claim.json").exists()
    with pytest.raises(M4AuthorizationDenied): runtime.execute(auth, principal)
    assert state["posts"] == 0


@pytest.mark.parametrize("fault", ["wrong_ack", "lost_ack"])
def test_original_unqualified_ack_stays_unqualified_under_real_lab_authority(tmp_path, monkeypatch, fault):
    runtime, principal, store, _, state, _ = composition(tmp_path, monkeypatch, fault=fault)
    runtime.execute(authorize(runtime, principal), principal)
    custody = open_original_unix_source_custody(tmp_path / "custody", tmp_path / "authority.key", tmp_path / "source.key", SOURCE, store, CONFIG)
    assert custody.inspect_original_state().acknowledgement_qualified is False
    custody.close()
    assert state["posts"] == store.claim_count == 1


@pytest.mark.parametrize("fault", ["context", "authority", "witness", "clock", "config"])
def test_retained_context_or_source_pin_drift_refuses_before_new_claim(tmp_path, monkeypatch, fault):
    runtime, principal, store, _, state, time = composition(tmp_path, monkeypatch)
    auth = authorize(runtime, principal)
    if fault == "context":
        (tmp_path / "custody/source-execution-context.json").write_text("{}")
    elif fault in {"authority", "witness"}:
        (tmp_path / ("authority.key" if fault == "authority" else "source.key")).write_bytes(b"z" * 32)
    elif fault == "clock":
        time["now"] = 999
    else:
        runtime._workflow._claim = tmp_path / "different-claim.json"
    with pytest.raises(M4AuthorizationDenied): runtime.execute(auth, principal)
    assert state["posts"] == store.claim_count == 0
    assert not (tmp_path / "legacy-claim.json").exists()


def test_prepared_context_is_not_original_creation_custody(tmp_path, monkeypatch):
    runtime, principal, store, _, state, _ = composition(tmp_path, monkeypatch)
    authorize(runtime, principal)
    reader = open_original_unix_source_custody(tmp_path / "custody", tmp_path / "authority.key", tmp_path / "source.key", SOURCE, store, CONFIG)
    with pytest.raises(ValueError): reader.inspect_original_state()
    reader.close()
    assert state["posts"] == store.claim_count == 0


def test_expired_or_regressed_clock_does_not_revive_authority(tmp_path, monkeypatch):
    runtime, principal, store, _, state, time = composition(tmp_path, monkeypatch)
    auth = authorize(runtime, principal)
    time["now"] = 999
    with pytest.raises(M4AuthorizationDenied): runtime.execute(auth, principal)
    time["now"] = 1001
    with pytest.raises(M4AuthorizationDenied): runtime.execute(auth, principal)
    assert state["posts"] == store.claim_count == 0


def test_consumed_legacy_object_claim_remains_a_barrier_to_any_new_post(tmp_path, monkeypatch):
    runtime, principal, store, _, state, _ = composition(tmp_path, monkeypatch)
    auth = authorize(runtime, principal)
    (tmp_path / "legacy-claim.json").write_text("retained competing dispatch")
    result = runtime.execute(auth, principal)
    assert result.outcome == "reconciliation_required"
    assert state["posts"] == 0 and store.claim_count == 1
    assert (tmp_path / "legacy-claim.json").read_text() == "retained competing dispatch"


def test_key_or_claim_path_cannot_collide_with_original_record(tmp_path, monkeypatch):
    runtime, principal, store, _, state, _ = composition(tmp_path, monkeypatch)
    collision = tmp_path / "custody/source-created-state.json"
    collision.write_bytes(b"a" * 32)
    collision.chmod(0o600)
    with pytest.raises(M4AuthorizationDenied):
        UnixDiscoverySourceRuntime(runtime._workflow, store, tmp_path / "custody", authority_key_file=collision,
            witness_key_file=tmp_path / "source.key", source_binding=SOURCE,
            environment_ref="unix-lab-environment01", scope_ref="unix-source-scope01", audience_ref="unix-source-audience01",
            requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest,
            serial_digest=hashlib.sha256(SERIAL.encode()).hexdigest())
    assert state["posts"] == store.claim_count == 0


def test_reference_appliance_mismatch_is_rejected_before_original_post(tmp_path, monkeypatch):
    runtime, principal, store, _, state, _ = composition(tmp_path, monkeypatch)
    auth = authorize(runtime, principal)
    state["reference_serial"] = "SYNTHETIC-OTHER-APPLIANCE"
    with pytest.raises(M4AuthorizationDenied): runtime.execute(auth, principal)
    assert state["posts"] == store.claim_count == 0
    assert not (tmp_path / "legacy-claim.json").exists()
    assert not (tmp_path / "custody/source-send.claim.json").exists()


def test_existing_mcp_entrypoint_keeps_opaque_inputs_and_separate_default_gate(tmp_path, monkeypatch):
    runtime, principal, store, _, state, _ = composition(tmp_path, monkeypatch)
    action = UnixDiscoverySourceMcpAction(runtime)
    server = SimpleNamespace(mcp=MCP_SERVER_CLASS("unix-original-custody"))
    register_unix_discovery_candidate_tools(server, action)
    schemas = {tool.name: tool.input_schema for tool in asyncio.run(server.mcp.list_tools())}
    assert schemas["preview_v4_unix_discovery_create_700"].get("properties", {}) == {}
    assert set(schemas["confirm_v4_unix_discovery_create_700"]["properties"]) == {"preview_ref"}
    assert set(schemas["execute_confirmed_v4_unix_discovery_create_700"]["properties"]) == {"authorization_ref"}
    preview = action.preview(principal)
    auth = action.confirm(preview["preview_ref"], principal)
    with pytest.raises(M4AuthorizationDenied): action.execute(auth["authorization_ref"], principal)
    assert store.claim_count == state["posts"] == 0
    enabled = UnixDiscoverySourceMcpAction(runtime, execution_enabled=True)
    result = enabled.execute(auth["authorization_ref"], principal)
    assert result["outcome"] == "succeeded" and state["posts"] == store.claim_count == 1


@pytest.mark.parametrize("fault", ["unselected_reference_duplicate", "selected_reference_duplicate", "nonfinite_reference"])
def test_native_reference_projection_accepts_only_unselected_duplicate_metadata(tmp_path, monkeypatch, fault):
    runtime, principal, store, _, state, _ = composition(tmp_path, monkeypatch, fault=fault)
    auth = authorize(runtime, principal)
    if fault == "unselected_reference_duplicate":
        result = runtime.execute(auth, principal)
        assert result.outcome == "succeeded" and state["posts"] == store.claim_count == 1
    else:
        with pytest.raises(M4AuthorizationDenied): runtime.execute(auth, principal)
        assert state["posts"] == store.claim_count == 0
