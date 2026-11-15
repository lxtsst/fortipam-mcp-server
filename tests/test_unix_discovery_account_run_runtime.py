"""Real scoped Source/Run issuers and persistent kernels with fixed HTTP peers."""
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys

import httpx
import pytest

from v4_planning import M4AuthorizationDenied, canonical_digest
from fortipam_mcp.discovery_entry_create_http_transport import FortiPamDiscoveryEntryCreateHttpTransport
from fortipam_mcp.discovery_run_http_transport import FortiPamDiscoveryRunHttpTransport
from fortipam_mcp.discovery_run_mcp_action import UnixDiscoveryRunLiveWorkflow
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.unix_discovery_account_run_runtime import UnixDiscoveryAccountRunRuntime, UnixDiscoveryOriginalRunMcpAction, open_original_unix_account_run_custody
from fortipam_mcp.unix_discovery_source_runtime import open_original_unix_source_custody
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from fortipam_mcp import unix_discovery_onboarding_guard as relation_module
from test_discovery_account_run_custody import FIXTURE, RUN_STORE, scanned_source
from test_discovery_source_create_custody import ACCOUNT, CONFIG, SERIAL, SOURCE, envelope, full_source
from test_m4_execution_store import _ExternalM4Checkpoint
from test_unix_discovery_source_runtime import authorize as source_authorize, composition as source_composition
from test_v4_planning import _requester
from test_unix_discovery_onboarding_prepare import _fixture as relation_inputs
from test_target_preservation_contract import row as target_row
from test_discovery_review_http_transport import _Body


def composition(tmp_path, monkeypatch, *, enabled=True, fault="none", with_guard=False):
    original_client = httpx.Client
    source_root = tmp_path / "source"; source_root.mkdir(mode=0o700)
    source, principal, source_store, source_checkpoint, _, _ = source_composition(source_root, monkeypatch)
    assert source.execute(source_authorize(source, principal), principal).outcome == "succeeded"
    source.close()
    creation = open_original_unix_source_custody(source_root / "custody", source_root / "authority.key",
        source_root / "source.key", SOURCE, source_store, CONFIG, clock=lambda: 1000)
    directory = source_root / "custody-account-run"; directory.mkdir(mode=0o700)
    for name, value in (("run-authority.key", b"q" * 32), ("run-witness.key", b"r" * 32), ("run-store.key", b"u" * 32)):
        path = tmp_path / name; path.write_bytes(value); path.chmod(0o600)
    checkpoint = _ExternalM4Checkpoint(); checkpoint.tail = replace(checkpoint.tail, store_ref=RUN_STORE)
    store = PersistentM4ExecutionStateStore(tmp_path / "run.sqlite", tmp_path / "run-store.key",
        monotonic_checkpoint=checkpoint, checkpoint_store_ref=RUN_STORE)
    state = dict(posts=0, gets=0, reference="Synthetic Secret", before_drift=False, after_drift=False)
    def respond(request):
        if request.method == "POST":
            assert request.url.path == "/api/v2/internal/secret-discovery"
            assert json.loads(request.content) == {"discovery-name": SOURCE.request.source_name, "type": "discovery"}
            state["posts"] += 1
            if fault == "lost": raise httpx.ReadTimeout("Synthetic original Run ACK loss")
            return httpx.Response(200, json={"ongoing_requests": 2 if fault == "pending" else 0, "failed_requests": 0})
        assert request.method == "GET"
        state["gets"] += 1
        if request.url.path == "/api/v2/cmdb/secret/database/17":
            return httpx.Response(200, json={**envelope(), "name": "database",
                "results": [dict(id=17, name=state["reference"], target="SyntheticTarget")]})
        if request.url.path == "/api/v2/cmdb/secret/target/SyntheticTarget":
            return httpx.Response(200, json={**envelope(), "name": "target", "results": [dict(name="SyntheticTarget")]})
        assert request.url.path == "/api/v2/cmdb/secret/discovery/" + SOURCE.request.source_name
        row = scanned_source() if state["posts"] else full_source()
        if state["before_drift"] or state["after_drift"] and state["posts"]: row["extra-native-state"] = {"changed": True}
        if "format" in request.url.params:
            fields = set(request.url.params["format"].split("|")) | {"q_origin_key"}
            row = {k: v for k, v in row.items() if k in fields}
        return httpx.Response(200, json={**envelope(), "results": [row]})
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original_client(**kwargs, transport=httpx.MockTransport(respond)))
    monkeypatch.setattr("fortipam_mcp.discovery_run_http_transport._ssl_context", lambda _: True)
    time = {"now": 1000}; clock = lambda: time["now"]
    workflow = UnixDiscoveryRunLiveWorkflow(FortiPamDiscoveryRunHttpTransport(CONFIG), FortiPamDiscoveryEntryCreateHttpTransport(CONFIG),
        SOURCE.request, creation._directory / "source-account-run.claim.json", clock=clock)
    options = dict(authority_key_file=tmp_path / "run-authority.key", witness_key_file=tmp_path / "run-witness.key",
        selected_account=ACCOUNT, fixture_birth_digest=FIXTURE, environment_ref="unix-lab-environment01",
        scope_ref="unix-account-run-scope01", audience_ref="unix-account-run-audience01",
        requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest, clock=clock)
    if with_guard:
        inputs = tmp_path / "guard-inputs"; inputs.mkdir(mode=0o700)
        selection, settings = relation_inputs(inputs)
        binding = json.loads(selection.read_bytes()); binding.update(source_name=SOURCE.request.source_name, selected_account=ACCOUNT)
        selection.write_text(json.dumps(binding))
        profile = json.loads(settings.profile_path.read_bytes()); profile.update(target_name="SyntheticTarget")
        settings.profile_path.write_text(json.dumps(profile))
        state.update(relation_requests=[], relation_clients=[], relation_fault=None, guard_now=10.0)
        state["relation_secret"] = dict(id=17, target="SyntheticTarget", template="Unix Account (SSH Password)",
            uuid="b05f3437-c57d-44b0-8b3a-42d79827b071", field=[dict(name="Password", value="MATERIAL_SENTINEL")])
        state["relation_target"] = target_row(); state["relation_target"].update(name="SyntheticTarget", q_origin_key="SyntheticTarget", address="192.0.2.20")
        def relation_peer(request):
            index = len(state["relation_requests"]) % 6; state["relation_requests"].append(request)
            assert request.method == "GET" and request.url.params.get("vdom") == "root"
            if index in (0, 5):
                assert request.url.path.endswith("/discovery/" + SOURCE.request.source_name)
                row = scanned_source() if state["posts"] else full_source()
                if state["relation_fault"] == "source_bracket" and index == 5: row["extra-native-state"] = {"changed": True}
                if "format" in request.url.params:
                    fields = set(request.url.params["format"].split("|")) | {"q_origin_key"}
                    row = {k: v for k, v in row.items() if k in fields}
                payload = {**envelope(), "results": [row]}
            else:
                table = "database" if index in (1, 4) else "target"
                assert request.url.path.endswith("/" + ("17" if table == "database" else "SyntheticTarget"))
                row = json.loads(json.dumps(state["relation_secret"] if table == "database" else state["relation_target"]))
                if state["relation_fault"] == "target_bracket" and index == 3: row["description"] = "Changed inside bracket"
                if state["relation_fault"] == "wrong_device" and index == 1:
                    serial = "OTHER-SYNTHETIC"
                else: serial = SERIAL
                if state["posts"] and state["relation_fault"] == "post_target" and table == "target": row["description"] = "Changed after original Scan"
                if state["posts"] and state["relation_fault"] == "post_secret" and table == "database": row["uuid"] = "44be4815-70f2-4f75-a420-1f44be9f801a"
                payload = {**envelope(), "serial": serial, "name": table, "status": "OK" if table == "database" else "success", "results": [row]}
            if state["relation_fault"] == "late": state["guard_now"] += 31
            return httpx.Response(200, headers={"content-type": "application/json"}, stream=_Body(json.dumps(payload).encode(), lambda: None))
        def relation_factory(**kwargs):
            client = original_client(**kwargs, transport=httpx.MockTransport(relation_peer)); state["relation_clients"].append(client)
            return client
        options["relation_guard"] = relation_module.UnixDiscoveryOnboardingGuard(CONFIG, selection_binding_path=selection,
            profile_path=settings.profile_path, clock=lambda: state["guard_now"], client_factory=relation_factory, original_run_enabled=True)
    runtime = UnixDiscoveryAccountRunRuntime(workflow, creation, store, directory, **options,
        **({} if enabled is None else {"execution_enabled": enabled}))
    return runtime, principal, store, checkpoint, state, time, source_checkpoint, options


def authorize(runtime, principal):
    preview = runtime.preview(principal)
    assert preview["native_scope_qualified"] is False and preview["expires_at"] == 1060
    assert preview["Expected State"]["current_activity_latest_or_recovery_qualified"] is False
    grant = runtime.issue(preview["preview_ref"], principal)
    assert grant["native_scope_qualified"] is False
    return grant["authorization_ref"], preview


def reader(runtime, store=None):
    return open_original_unix_account_run_custody(runtime._directory, runtime._authority_file, runtime._witness_file,
        runtime._creation, store or runtime._store, CONFIG, selected_account=ACCOUNT, fixture_birth_digest=FIXTURE, clock=lambda: 5000)


def test_original_run_uses_existing_mcp_action_with_separate_default_gate(tmp_path, monkeypatch):
    runtime, principal, store, _, state, _, _, _ = composition(tmp_path, monkeypatch, with_guard=True)
    action = UnixDiscoveryOriginalRunMcpAction(runtime)
    preview = action.preview(principal)
    auth = action.confirm(preview["preview_ref"], principal)["authorization_ref"]
    with pytest.raises(M4AuthorizationDenied): action.execute(auth, principal)
    assert state["posts"] == store.claim_count == 0
    enabled = UnixDiscoveryOriginalRunMcpAction(runtime, execution_enabled=True)
    assert enabled.execute(auth, principal)["verification"] == "verified"
    assert state["posts"] == store.claim_count == 1


def test_actual_issuer_persists_exact_preview_before_claim_and_owns_one_scan(tmp_path, monkeypatch):
    r, principal, store, _, state, _, _, _ = composition(tmp_path, monkeypatch)
    auth, preview = authorize(r, principal)
    plan, grant = r._issued
    assert plan.summary_digest == canonical_digest({k: preview[k] for k in ("Current State", "Proposed Changes", "Expected State")})
    assert grant.expires_at - grant.issued_at == 60
    claim = store.claim
    def claim_after_original_preparation(**kwargs):
        r._check_record()
        assert (r._directory / "account-run-execution-context.json").stat().st_mode & 0o777 == 0o600
        return claim(**kwargs)
    monkeypatch.setattr(store, "claim", claim_after_original_preparation)
    result = r.execute(auth, principal)
    assert result.outcome == "succeeded" and result.verification == "verified"
    assert state["posts"] == store.claim_count == 1 and r._claim.exists()
    observed = reader(r)
    assert observed.inspect_original_state().current_activity_or_recovery_qualified is False
    files = {p.name: p.read_bytes() for p in r._directory.iterdir()}
    assert len(files) == 4
    assert all(value not in b"".join(files.values()) for value in (ACCOUNT.encode(), SERIAL.encode(), SOURCE.request.source_name.encode(), b"synthetic-token"))
    gets = state["gets"]
    assert r.execute(auth, principal).idempotent_replay
    assert state["posts"] == 1 and state["gets"] == gets
    observed.close(); r.close()
    assert not r._key and not r._custody._key and r._creation._key


@pytest.mark.parametrize("with_guard", [False, True])
def test_independent_process_reads_original_preparation_counts_and_unknown_after_expiry(tmp_path, monkeypatch, with_guard):
    r, principal, store, checkpoint, state, _, source_checkpoint, _ = composition(tmp_path, monkeypatch, fault="pending", with_guard=with_guard)
    auth, _ = authorize(r, principal)
    assert r.execute(auth, principal).verification == "unknown"
    if with_guard:
        assert len(state["relation_requests"]) == 18
        assert all(client.is_closed for client in state["relation_clients"])
    before = {p: p.read_bytes() for folder in (r._directory, r._creation._directory) for p in folder.iterdir()}
    script = """
import sys
from pathlib import Path
from dataclasses import replace
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.unix_discovery_source_runtime import open_original_unix_source_custody
from fortipam_mcp.unix_discovery_account_run_runtime import open_original_unix_account_run_custody
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF
from test_discovery_source_create_custody import SOURCE, CONFIG, ACCOUNT
from test_discovery_account_run_custody import RUN_STORE, FIXTURE
root=Path(sys.argv[1]);src=root/'source'
cp=_ExternalM4Checkpoint();cp.tail=replace(cp.tail,sequence=int(sys.argv[2]),chain_hmac=sys.argv[3])
source_store=PersistentM4ExecutionStateStore(src/'execution.sqlite',src/'execution.key',monotonic_checkpoint=cp,checkpoint_store_ref=CHECKPOINT_STORE_REF,read_only=True)
creation=open_original_unix_source_custody(src/'custody',src/'authority.key',src/'source.key',SOURCE,source_store,CONFIG)
cp2=_ExternalM4Checkpoint();cp2.tail=replace(cp2.tail,store_ref=RUN_STORE,sequence=int(sys.argv[4]),chain_hmac=sys.argv[5])
store=PersistentM4ExecutionStateStore(root/'run.sqlite',root/'run-store.key',monotonic_checkpoint=cp2,checkpoint_store_ref=RUN_STORE,read_only=True)
reader=open_original_unix_account_run_custody(src/'custody-account-run',root/'run-authority.key',root/'run-witness.key',creation,store,CONFIG,selected_account=ACCOUNT,fixture_birth_digest=FIXTURE,clock=lambda:5000)
observed=reader.inspect_original_state()
assert observed.native_reply_valid and observed.ongoing_requests==2 and observed.failed_requests==0
assert observed.original_outcome=='reconciliation_required' and observed.original_verification=='unknown'
assert observed.current_activity_or_recovery_qualified is False and store.claim_count==1
reader.close();creation.close()
print('original account Run context and pending outcome preserved')
"""
    env = {**os.environ, "PYTHONPATH": os.pathsep.join((str(Path(__file__).parent), os.environ.get("PYTHONPATH", "")))}
    run = subprocess.run([sys.executable, "-c", script, str(tmp_path), str(source_checkpoint.tail.sequence), source_checkpoint.tail.chain_hmac,
        str(checkpoint.tail.sequence), checkpoint.tail.chain_hmac], env=env, capture_output=True, text=True, timeout=20)
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "original account Run context and pending outcome preserved"
    assert {p: p.read_bytes() for p in before} == before and state["posts"] == 1


@pytest.mark.parametrize("enabled", [None, False])
def test_default_closed_previews_without_issuing_or_claiming(tmp_path, monkeypatch, enabled):
    r, principal, store, _, state, _, _, _ = composition(tmp_path, monkeypatch, enabled=enabled)
    p = r.preview(principal)
    with pytest.raises(M4AuthorizationDenied): r.issue(p["preview_ref"], principal)
    assert list(r._directory.iterdir()) == [] and store.claim_count == state["posts"] == 0


@pytest.mark.parametrize("other", ["transport", "requester"])
def test_foreign_identity_and_equal_value_grant_clone_cannot_consume(tmp_path, monkeypatch, other):
    r, principal, store, _, state, _, _, _ = composition(tmp_path, monkeypatch)
    foreign = V4PlanningPrincipal(principal.requester, "b" * 64) if other == "transport" else V4PlanningPrincipal(_requester("other"), principal.transport_namespace_digest)
    with pytest.raises(M4AuthorizationDenied): r.preview(foreign)
    preview = r.preview(principal)
    with pytest.raises(M4AuthorizationDenied): r.issue(preview["preview_ref"], foreign)
    auth = r.issue(preview["preview_ref"], principal)["authorization_ref"]
    with pytest.raises(M4AuthorizationDenied): r.execute(auth, foreign)
    plan, grant = r._issued
    with pytest.raises(M4AuthorizationDenied): r.verify(plan, replace(grant), now_epoch=1000)
    with pytest.raises(M4AuthorizationDenied): r.verify(replace(plan), grant, now_epoch=1000)
    assert state["posts"] == store.claim_count == 0 and not r._claim.exists()


@pytest.mark.parametrize("fault", ["context", "authority", "witness", "store_key", "checkpoint", "claim_path", "clock", "transport"])
def test_original_preparation_and_startup_drift_refuse_before_run_claim(tmp_path, monkeypatch, fault):
    r, principal, store, _, state, time, _, _ = composition(tmp_path, monkeypatch)
    auth, _ = authorize(r, principal)
    if fault == "context": (r._directory / "account-run-execution-context.json").write_text("{}")
    elif fault in {"authority", "witness", "store_key"}:
        path = {"authority": r._authority_file, "witness": r._witness_file, "store_key": store._key_path}[fault]
        path.write_bytes(b"z" * 32)
    elif fault == "claim_path": r._workflow._claim = r._directory / "different-claim.json"
    elif fault == "clock": time["now"] = 999
    elif fault == "checkpoint":
        replacement = _ExternalM4Checkpoint(); replacement.tail = store._monotonic_checkpoint.tail
        store._monotonic_checkpoint = replacement
    else: r._workflow._transport = FortiPamDiscoveryRunHttpTransport(CONFIG)
    with pytest.raises(M4AuthorizationDenied): r.execute(auth, principal)
    if fault != "store_key": assert store.claim_count == 0
    assert state["posts"] == 0 and not r._claim.exists()


@pytest.mark.parametrize("fault", ["pending", "lost", "after_drift"])
def test_unknown_is_retained_and_replay_never_sends_again(tmp_path, monkeypatch, fault):
    r, principal, store, _, state, _, _, _ = composition(tmp_path, monkeypatch, fault=fault)
    auth, _ = authorize(r, principal)
    state["after_drift"] = fault == "after_drift"
    result = r.execute(auth, principal)
    assert result.outcome == "reconciliation_required" and result.verification == "unknown"
    assert r.execute(auth, principal).idempotent_replay and state["posts"] == store.claim_count == 1
    observed = reader(r); original = observed.inspect_original_state()
    assert original.original_verification == "unknown" and original.current_activity_or_recovery_qualified is False
    observed.close()


@pytest.mark.parametrize("drift", ["reference", "full_source", "object_claim"])
def test_fresh_pre_dispatch_scope_drift_blocks_post_and_consumes_kernel_only(tmp_path, monkeypatch, drift):
    r, principal, store, _, state, _, _, _ = composition(tmp_path, monkeypatch)
    auth, _ = authorize(r, principal)
    if drift == "reference": state["reference"] = "Changed Secret"
    elif drift == "full_source": state["before_drift"] = True
    else: r._claim.write_text("retained competing original Run"); r._claim.chmod(0o600)
    result = r.execute(auth, principal)
    assert result.outcome == ("precondition_failed" if drift == "full_source" else "reconciliation_required")
    assert store.claim_count == 1 and state["posts"] == 0
    assert not (r._directory / "account-run-send.claim.json").exists()
    assert r.execute(auth, principal).idempotent_replay and state["posts"] == 0


def test_prepared_context_has_no_original_ack_and_cannot_restart_forward(tmp_path, monkeypatch):
    r, principal, store, _, state, _, _, options = composition(tmp_path, monkeypatch)
    authorize(r, principal)
    observed = reader(r)
    with pytest.raises(ValueError): observed.inspect_original_state()
    with pytest.raises(ValueError): observed.capture_original_ack(bytearray(b"{}"), http_status=200, content_type="application/json", complete=True)
    with pytest.raises(M4AuthorizationDenied):
        UnixDiscoveryAccountRunRuntime(r._workflow, r._creation, store, r._directory, **options, execution_enabled=True)
    assert store.claim_count == state["posts"] == 0


def test_context_fsync_failure_keeps_preparation_without_execution_or_retry(tmp_path, monkeypatch):
    r, principal, store, _, state, _, _, _ = composition(tmp_path, monkeypatch)
    preview = r.preview(principal)
    def fail_fsync(_): raise OSError("Synthetic context fsync failure")
    with monkeypatch.context() as local:
        local.setattr("fortipam_mcp.unix_discovery_account_run_runtime.os.fsync", fail_fsync)
        with pytest.raises(M4AuthorizationDenied): r.issue(preview["preview_ref"], principal)
    assert (r._directory / "account-run-execution-context.json").exists() and r._issued is None
    with pytest.raises(M4AuthorizationDenied): r.issue(preview["preview_ref"], principal)
    assert store.claim_count == state["posts"] == 0 and not r._claim.exists()


def test_before_dispatch_callback_cannot_reserve_object_without_active_original_m4(tmp_path, monkeypatch):
    r, principal, store, _, state, _, _, _ = composition(tmp_path, monkeypatch)
    authorize(r, principal)
    r._custody = reader(r)
    with pytest.raises(ValueError): r._before_dispatch()
    assert store.claim_count == state["posts"] == 0 and not r._claim.exists()


@pytest.mark.parametrize("fault", ["account", "fixture", "ledger"])
def test_original_reader_refuses_foreign_binding_without_issuing_authority(tmp_path, monkeypatch, fault):
    r, principal, store, checkpoint, state, _, _, _ = composition(tmp_path, monkeypatch)
    authorize(r, principal)
    if fault == "ledger":
        store = PersistentM4ExecutionStateStore(tmp_path / "different-run.sqlite", tmp_path / "run-store.key",
            monotonic_checkpoint=checkpoint, checkpoint_store_ref=RUN_STORE)
    with pytest.raises(M4AuthorizationDenied):
        open_original_unix_account_run_custody(r._directory, r._authority_file, r._witness_file, r._creation, store, CONFIG,
            selected_account="fpam-bp014-discovery-r987654321" if fault == "account" else ACCOUNT,
            fixture_birth_digest="d" * 64 if fault == "fixture" else FIXTURE)
    assert store.claim_count == state["posts"] == 0


@pytest.mark.parametrize("fault", ["directory", "claim_path", "parent_key", "retained_claim"])
def test_fixed_source_namespace_and_distinct_keys_prevent_rebinding(tmp_path, monkeypatch, fault):
    r, _, store, _, state, _, _, options = composition(tmp_path, monkeypatch)
    directory = r._directory
    if fault == "directory": directory = tmp_path / "different-run"
    elif fault == "claim_path": r._workflow._claim = directory / "different-claim.json"
    elif fault == "parent_key": options["authority_key_file"] = r._creation._key_file
    else: r._claim.write_text("retained original Run"); r._claim.chmod(0o600)
    with pytest.raises(M4AuthorizationDenied): UnixDiscoveryAccountRunRuntime(r._workflow, r._creation, store, directory, **options, execution_enabled=True)
    assert state["posts"] == store.claim_count == 0


def test_expiry_and_clock_regression_never_revive_original_authority(tmp_path, monkeypatch):
    r, principal, store, _, state, time, _, _ = composition(tmp_path, monkeypatch)
    auth, _ = authorize(r, principal)
    time["now"] = 1060
    with pytest.raises(M4AuthorizationDenied): r.execute(auth, principal)
    time["now"] = 1001
    with pytest.raises(M4AuthorizationDenied): r.execute(auth, principal)
    assert state["posts"] == store.claim_count == 0


def test_original_relation_brackets_pin_full_target_without_decoding_material_or_claiming_activity(tmp_path, monkeypatch):
    r, principal, store, _, state, _, _, _ = composition(tmp_path, monkeypatch, with_guard=True)
    buffers = []; get = r._guard._get
    def tracked(*args):
        raw = get(*args); buffers.append(raw)
        if args[1] == r._guard._secret_path: assert b"MATERIAL_SENTINEL" not in raw
        return raw
    monkeypatch.setattr(r._guard, "_get", tracked)
    loads = json.loads
    def protected_loads(value, *args, **kwargs):
        if isinstance(value, (bytes, bytearray)): assert b"MATERIAL_SENTINEL" not in value
        return loads(value, *args, **kwargs)
    # The synthetic peer may serialize its prebuilt rows but never parses the
    # protected wire. Its object copy uses strings, as opposed to byte decoders.
    monkeypatch.setattr(json, "loads", protected_loads)
    auth, preview = authorize(r, principal)
    assert preview["Current State"]["complete_reference_bracket_verified"] is True
    assert preview["Expected State"]["complete_reference_bracket_preserved"] is True
    prepared = json.loads((r._directory / "account-run-execution-context.json").read_bytes())
    assert prepared["relation_guard_contract"] == relation_module.ORIGINAL_RUN_STABLE_RELATION_CONTRACT
    assert prepared["relation_digest"] == r._preview[5] and prepared["relation_context_digest"] == r._guard._source
    assert r.execute(auth, principal).verification == "verified"
    assert state["posts"] == store.claim_count == 1 and len(state["relation_requests"]) == 24
    assert all(not raw for raw in buffers) and all(client.is_closed for client in state["relation_clients"])
    for offset in range(0, 24, 6):
        paths = [request.url.path for request in state["relation_requests"][offset:offset + 6]]
        assert paths == list(reversed(paths))
        assert all("format" not in state["relation_requests"][offset + index].url.params for index in (0, 5))
    observed = reader(r); assert observed.inspect_original_state().current_activity_or_recovery_qualified is False
    count = len(state["relation_requests"])
    assert r.execute(auth, principal).idempotent_replay and len(state["relation_requests"]) == count
    with pytest.raises(relation_module.UnixDiscoveryHandoffError):
        r._guard.observe_original_run(r._creation, selected_account=ACCOUNT, fixture_birth_digest=FIXTURE)
    observed.close(); r.close(); r._guard.close()
    assert not r._key and not r._guard._key


@pytest.mark.parametrize("fault", ["source_bracket", "target_bracket", "wrong_device", "late"])
def test_original_relation_incomplete_brackets_refuse_before_authority_and_never_load_material(tmp_path, monkeypatch, fault):
    r, principal, store, _, state, _, _, _ = composition(tmp_path, monkeypatch, with_guard=True)
    state["relation_fault"] = fault
    with pytest.raises(M4AuthorizationDenied): r.preview(principal)
    assert store.claim_count == state["posts"] == 0 and not r._claim.exists()
    assert not r._guard._key and all(client.is_closed for client in state["relation_clients"])
    previous = len(state["relation_requests"])
    with pytest.raises(M4AuthorizationDenied): r.preview(principal)
    assert len(state["relation_requests"]) == previous


@pytest.mark.parametrize("stage", ["issue", "dispatch"])
def test_complete_target_drift_after_preview_refuses_before_scan(tmp_path, monkeypatch, stage):
    r, principal, store, _, state, _, _, _ = composition(tmp_path, monkeypatch, with_guard=True)
    preview = r.preview(principal)
    auth = r.issue(preview["preview_ref"], principal)["authorization_ref"] if stage == "dispatch" else None
    state["relation_target"]["hostkey"] = [{"hostkey-data": "CHANGED_OPAQUE_MATERIAL"}]
    if stage == "issue":
        with pytest.raises(M4AuthorizationDenied): r.issue(preview["preview_ref"], principal)
        assert store.claim_count == 0 and not (r._directory / "account-run-execution-context.json").exists()
    else:
        result = r.execute(auth, principal)
        assert result.verification == "unknown" and store.claim_count == 1
        assert r.execute(auth, principal).idempotent_replay
    assert state["posts"] == 0 and not r._claim.exists()


@pytest.mark.parametrize("fault", ["post_target", "post_secret"])
def test_post_scan_relation_drift_retains_original_ack_and_unknown_without_replay(tmp_path, monkeypatch, fault):
    r, principal, store, _, state, _, _, _ = composition(tmp_path, monkeypatch, with_guard=True)
    auth, _ = authorize(r, principal); state["relation_fault"] = fault
    result = r.execute(auth, principal)
    assert result.verification == "unknown" and state["posts"] == store.claim_count == 1
    observed = reader(r); original = observed.inspect_original_state()
    assert original.native_reply_valid and original.original_configuration_preserved
    assert original.original_verification == "unknown" and original.current_activity_or_recovery_qualified is False
    before = len(state["relation_requests"])
    assert r.execute(auth, principal).idempotent_replay and len(state["relation_requests"]) == before
    assert all(client.is_closed for client in state["relation_clients"])
    observed.close()


def test_original_relation_does_not_relax_existing_post_scan_selection_requirement(tmp_path, monkeypatch):
    r, principal, store, _, state, _, _, _ = composition(tmp_path, monkeypatch, with_guard=True)
    original = r._guard.observe_original_run(r._creation, selected_account=ACCOUNT, fixture_birth_digest=FIXTURE)
    assert original.native_fixture_or_activity_qualified is False and original.stable_reference_digest is None
    # Existing onboarding observe still requires a scanned account table.
    with pytest.raises(relation_module.UnixDiscoveryHandoffError): r._guard.observe()
    assert store.claim_count == state["posts"] == 0


@pytest.mark.parametrize("fault", ["account", "fixture", "phase_path"])
def test_original_relation_wrong_binding_or_phase_path_refuses_without_io(tmp_path, monkeypatch, fault):
    r, _, store, _, state, _, _, _ = composition(tmp_path, monkeypatch, with_guard=True)
    if fault == "phase_path": r._guard._original_source_path = r._guard._source_path
    with pytest.raises(relation_module.UnixDiscoveryHandoffError):
        r._guard.observe_original_run(r._creation, selected_account="other" if fault == "account" else ACCOUNT,
            fixture_birth_digest="invalid" if fault == "fixture" else FIXTURE)
    assert not state["relation_requests"] and store.claim_count == state["posts"] == 0


@pytest.mark.parametrize("fault", ["pending", "lost", "after_drift"])
def test_reference_guard_cannot_promote_incomplete_original_scan(tmp_path, monkeypatch, fault):
    r, principal, store, _, state, _, _, _ = composition(tmp_path, monkeypatch, with_guard=True, fault=fault)
    auth, _ = authorize(r, principal); state["after_drift"] = fault == "after_drift"
    assert r.execute(auth, principal).verification == "unknown"
    assert state["posts"] == store.claim_count == 1 and len(state["relation_requests"]) == 18
    observed = reader(r); original = observed.inspect_original_state()
    assert original.original_verification == "unknown" and not original.current_activity_or_recovery_qualified
    before = len(state["relation_requests"])
    assert r.execute(auth, principal).idempotent_replay and len(state["relation_requests"]) == before
    observed.close()


@pytest.mark.parametrize("fault", ["mode", "account", "origin", "replacement"])
def test_original_guard_startup_binding_cannot_be_swapped_or_relaxed(tmp_path, monkeypatch, fault):
    r, principal, store, _, state, _, _, options = composition(tmp_path, monkeypatch, with_guard=True)
    if fault == "replacement":
        auth, _ = authorize(r, principal)
        old = r._guard
        r._guard = relation_module.UnixDiscoveryOnboardingGuard(CONFIG, selection_binding_path=old._selection_path,
            profile_path=old._profile_path, clock=old._clock, client_factory=old._factory, original_run_enabled=True)
        with pytest.raises(M4AuthorizationDenied): r.execute(auth, principal)
        assert len(state["relation_requests"]) == 12
    else:
        if fault == "mode": r._guard._original_source_path = None
        elif fault == "account": r._guard._account = "other"
        else: r._guard._config = replace(CONFIG, base_url="https://other.synthetic.invalid")
        with pytest.raises(M4AuthorizationDenied):
            UnixDiscoveryAccountRunRuntime(r._workflow, r._creation, store, r._directory, **options, execution_enabled=True)
        assert not state["relation_requests"]
    assert store.claim_count == state["posts"] == 0 and not r._claim.exists()


@pytest.mark.parametrize("fault", [None, "target", "secret", "key", "profile", "unselected_material"])
def test_retained_reference_witness_survives_fresh_guard_identity_and_detects_scoped_drift(tmp_path, monkeypatch, fault):
    r, principal, store, _, state, _, _, _ = composition(tmp_path, monkeypatch, with_guard=True)
    auth, _ = authorize(r, principal)
    assert r.execute(auth, principal).verification == "verified"
    original = reader(r); baseline = original.inspect_reference_baseline()
    assert baseline == r._preview[5]
    if fault == "target": state["relation_target"]["hostkey"] = [{"hostkey-data": "changed opaque token"}]
    elif fault == "secret": state["relation_secret"]["uuid"] = "44be4815-70f2-4f75-a420-1f44be9f801a"
    elif fault == "profile":
        profile = json.loads(r._guard._profile_path.read_bytes()); profile["secret_name"] = "different prospective secret"
        r._guard._profile_path.write_text(json.dumps(profile))
    elif fault == "unselected_material": state["relation_secret"]["field"][0]["value"] = "different unselected rendering"
    fresh = relation_module.UnixDiscoveryOnboardingGuard(CONFIG, selection_binding_path=r._guard._selection_path,
        profile_path=r._guard._profile_path, clock=r._guard._clock, client_factory=r._guard._factory, original_run_enabled=True)
    assert fresh._source != r._guard._source
    key = bytearray(b"d" * 32 if fault == "key" else r._witness_file.read_bytes()); before = bytes(key)
    current = fresh.observe_original_run(r._creation, selected_account=ACCOUNT, fixture_birth_digest=FIXTURE,
        original_run=original, reference_witness_key=key)
    assert (current.stable_reference_digest == baseline) is (fault in (None, "unselected_material"))
    assert not current.native_fixture_or_activity_qualified and bytes(key) == before
    assert store.claim_count == state["posts"] == 1
    fresh.close(); original.close(); key.clear()


def test_independent_process_rebuilds_original_reference_baseline_after_expiry_without_writes(tmp_path, monkeypatch):
    r, principal, store, checkpoint, state, _, source_checkpoint, _ = composition(tmp_path, monkeypatch, with_guard=True)
    auth, _ = authorize(r, principal); assert r.execute(auth, principal).verification == "verified"
    before = {p: p.read_bytes() for folder in (r._directory, r._creation._directory) for p in folder.iterdir()}
    script = """
import sys,json
from pathlib import Path
from dataclasses import replace
import httpx
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.unix_discovery_source_runtime import open_original_unix_source_custody
from fortipam_mcp.unix_discovery_account_run_runtime import open_original_unix_account_run_custody
from fortipam_mcp.unix_discovery_onboarding_guard import UnixDiscoveryOnboardingGuard
from test_m4_execution_store import _ExternalM4Checkpoint,CHECKPOINT_STORE_REF
from test_discovery_source_create_custody import SOURCE,CONFIG,ACCOUNT,SERIAL,envelope
from test_discovery_account_run_custody import RUN_STORE,FIXTURE,scanned_source
from test_target_preservation_contract import row as target_row
from test_discovery_review_http_transport import _Body
root=Path(sys.argv[1]);src=root/'source'
cp=_ExternalM4Checkpoint();cp.tail=replace(cp.tail,sequence=int(sys.argv[2]),chain_hmac=sys.argv[3])
source_store=PersistentM4ExecutionStateStore(src/'execution.sqlite',src/'execution.key',monotonic_checkpoint=cp,checkpoint_store_ref=CHECKPOINT_STORE_REF,read_only=True)
creation=open_original_unix_source_custody(src/'custody',src/'authority.key',src/'source.key',SOURCE,source_store,CONFIG)
cp2=_ExternalM4Checkpoint();cp2.tail=replace(cp2.tail,store_ref=RUN_STORE,sequence=int(sys.argv[4]),chain_hmac=sys.argv[5])
store=PersistentM4ExecutionStateStore(root/'run.sqlite',root/'run-store.key',monotonic_checkpoint=cp2,checkpoint_store_ref=RUN_STORE,read_only=True)
original=open_original_unix_account_run_custody(src/'custody-account-run',root/'run-authority.key',root/'run-witness.key',creation,store,CONFIG,selected_account=ACCOUNT,fixture_birth_digest=FIXTURE,clock=lambda:5000)
requests=[];clients=[]
def respond(request):
    assert request.method=='GET';requests.append(request)
    if '/discovery/' in request.url.path:payload={**envelope(),'results':[scanned_source()]}
    elif '/database/' in request.url.path:
        payload={**envelope(),'name':'database','status':'OK','results':[dict(id=17,target='SyntheticTarget',template='Unix Account (SSH Password)',uuid='b05f3437-c57d-44b0-8b3a-42d79827b071')]}
    else:
        row=target_row();row.update(name='SyntheticTarget',q_origin_key='SyntheticTarget',address='192.0.2.20')
        payload={**envelope(),'name':'target','results':[row]}
    return httpx.Response(200,headers={'content-type':'application/json'},stream=_Body(json.dumps(payload).encode(),lambda:None))
def factory(**kwargs):
    client=httpx.Client(**kwargs,transport=httpx.MockTransport(respond));clients.append(client);return client
guard=UnixDiscoveryOnboardingGuard(CONFIG,selection_binding_path=root/'guard-inputs/private/selection.json',profile_path=root/'guard-inputs/private/profile.json',client_factory=factory,original_run_enabled=True)
prepared=json.loads((src/'custody-account-run/account-run-execution-context.json').read_bytes())
assert guard._source!=prepared['relation_context_digest']
key=bytearray((root/'run-witness.key').read_bytes())
observed=guard.observe_original_run(creation,selected_account=ACCOUNT,fixture_birth_digest=FIXTURE,original_run=original,reference_witness_key=key)
assert observed.stable_reference_digest==original.inspect_reference_baseline()==prepared['relation_digest']
assert observed.native_fixture_or_activity_qualified is False and len(requests)==6 and all(client.is_closed for client in clients)
assert original.inspect_original_state().current_activity_or_recovery_qualified is False and store.claim_count==1
guard.close();original.close();creation.close();key.clear()
print('independent retained reference baseline verified')
"""
    env = {**os.environ, "PYTHONPATH": os.pathsep.join((str(Path(__file__).parent), os.environ.get("PYTHONPATH", "")))}
    run = subprocess.run([sys.executable, "-c", script, str(tmp_path), str(source_checkpoint.tail.sequence), source_checkpoint.tail.chain_hmac,
        str(checkpoint.tail.sequence), checkpoint.tail.chain_hmac], env=env, capture_output=True, text=True, timeout=20)
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "independent retained reference baseline verified"
    assert {p: p.read_bytes() for p in before} == before and state["posts"] == 1


@pytest.mark.parametrize("bad_key", [b"w" * 32, bytearray(b"w" * 31)])
def test_invalid_reference_witness_refuses_before_any_get(tmp_path, monkeypatch, bad_key):
    r, _, store, _, state, _, _, _ = composition(tmp_path, monkeypatch, with_guard=True)
    with pytest.raises(relation_module.UnixDiscoveryHandoffError):
        r._guard.observe_original_run(r._creation, selected_account=ACCOUNT, fixture_birth_digest=FIXTURE, reference_witness_key=bad_key)
    assert not state["relation_requests"] and store.claim_count == state["posts"] == 0


def test_original_reference_baseline_cannot_be_replaced_on_reopened_custody(tmp_path, monkeypatch):
    r, principal, _, _, _, _, _, _ = composition(tmp_path, monkeypatch, with_guard=True)
    auth, _ = authorize(r, principal); r.execute(auth, principal)
    original = reader(r)
    original._reference_digest = "e" * 64
    with pytest.raises(ValueError, match="Original account Discovery Run custody is unavailable"):
        original.inspect_reference_baseline()
