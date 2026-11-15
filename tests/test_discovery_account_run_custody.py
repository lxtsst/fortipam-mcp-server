"""Original Source + original Run through real durable kernels and fixed HTTP."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import httpx
import pytest

from v4_planning import M4AdapterAmbiguous, M4AdapterDenied, M4ExecutionKernel, M4ExecutionPlan, canonical_digest
from fortipam_mcp.discovery_account_run_custody import (
    ACTION_ID, ACTION_VERSION, ADAPTER_REF, AccountDiscoveryRunCustody, AccountDiscoveryRunM4Adapter, AccountRunCustodyError,
    account_run_parameters_digest, account_run_state_digest,
)
from fortipam_mcp.discovery_entry_m4_adapter import DiscoveryEntryM4Adapter
from fortipam_mcp.discovery_run_http_transport import AccountDiscoveryAck, DiscoveryRunResult, FortiPamDiscoveryRunHttpTransport
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_discovery_source_create_custody import ACCOUNT, CONFIG, SERIAL, SOURCE, create, envelope, full_source, native_transport
from test_m4_execution_store import _ExternalM4Checkpoint
from test_v4_execution_kernel import _Verifier, _authorization

FIXTURE = "b" * 64
RUN_STORE = "account-run-test-store01"
STAMP = "2026-10-24 03:04:05"


def scanned_source():
    return {**full_source(), "last-discovery-time": STAMP,
        "discovery-results": [{"name": ACCOUNT, "managed-status": 0, "last-scanned-time": STAMP, "q_origin_key": ACCOUNT}]}


def components(root, creation, checkpoint=None, *, now=1000, readonly=False):
    checkpoint = checkpoint or _ExternalM4Checkpoint()
    if checkpoint.tail.sequence == 0:
        checkpoint.tail = replace(checkpoint.tail, store_ref=RUN_STORE)
    store = PersistentM4ExecutionStateStore(root / "run.sqlite", root / "run-store.key",
        monotonic_checkpoint=checkpoint, checkpoint_store_ref=RUN_STORE, read_only=readonly)
    base = creation._plan
    fields = {**base.canonical_content(), "plan_ref": "account-run-plan-fixture01", "action_id": ACTION_ID,
        "action_version": ACTION_VERSION, "adapter_ref": ADAPTER_REF, "compensation_ref": None,
        "parameters_digest": account_run_parameters_digest(creation, ACCOUNT, FIXTURE),
        "expected_current_digest": account_run_state_digest(creation, ACCOUNT, FIXTURE, scanned=False),
        "expected_state_digest": account_run_state_digest(creation, ACCOUNT, FIXTURE, scanned=True)}
    plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
    authorization = _authorization(plan)
    custody = AccountDiscoveryRunCustody(root / "run-custody", root / "run-witness.key", creation, plan, authorization, store, CONFIG,
        selected_account=ACCOUNT, fixture_birth_digest=FIXTURE, clock=lambda: now)
    return custody, store, plan, authorization, checkpoint


def prepared(tmp_path, monkeypatch, *, fault="zero"):
    original_client = httpx.Client
    source_dir = tmp_path / "source"; source_dir.mkdir(mode=0o700)
    creation, source_store, plan, auth, _ = create(source_dir)
    transport, _ = native_transport(monkeypatch, creation)
    M4ExecutionKernel(DiscoveryEntryM4Adapter(plan, SOURCE, transport), _Verifier(), source_store, clock=lambda: 1000).execute(plan, auth)
    (tmp_path / "run-custody").mkdir(mode=0o700)
    for name, value in (("run-witness.key", b"r" * 32), ("run-store.key", b"u" * 32)):
        path = tmp_path / name; path.write_bytes(value); path.chmod(0o600)
    custody, store, p, a, checkpoint = components(tmp_path, creation)
    state = dict(posts=0, result=None, post_full_reads=0)
    def respond(request):
        if request.method == "POST":
            assert request.url.path == "/api/v2/internal/secret-discovery"
            assert json.loads(request.content) == {"discovery-name": SOURCE.request.source_name, "type": "discovery"}
            state["posts"] += 1
            if fault == "lost": raise httpx.ReadTimeout("Synthetic lost original Run ACK")
            if fault in {"partial", "close_failure"}:
                class Partial(httpx.SyncByteStream):
                    def __iter__(self):
                        yield b'{"ongoing_requests":0,"failed_requests":0}'
                        if fault == "partial": raise httpx.ReadTimeout("Synthetic loss after complete JSON")
                    def close(self):
                        if fault == "close_failure": raise httpx.ReadTimeout("Synthetic failure closing reply stream")
                return httpx.Response(200, stream=Partial(), headers={"content-type": "application/json"})
            body = {"pending": '{"ongoing_requests":3,"failed_requests":0}',
                "numeric_text": '{"ongoing_requests":"0","failed_requests":"0"}',
                "failed": '{"ongoing_requests":0,"failed_requests":2}',
                "duplicate": '{"ongoing_requests":1,"ongoing_requests":0,"failed_requests":0}',
                "target_progress": '{"status":"idle","completed":1,"total":1}'}
            return httpx.Response(200, content=body.get(fault, '{"ongoing_requests":0,"failed_requests":0}'), headers={"content-type": "application/json"})
        assert request.method == "GET" and request.url.path.endswith("/" + SOURCE.request.source_name)
        row = scanned_source() if state["posts"] else full_source()
        if state["posts"] and "format" not in request.url.params: state["post_full_reads"] += 1
        if fault == "before_drift" or fault == "after_drift" and state["posts"]:
            row["extra-native-state"] = {"flag": "changed"}
        if fault == "post_read_drift" and state["post_full_reads"] >= 2:
            row["extra-native-state"] = {"flag": "changed-after-original-capture"}
        if "format" in request.url.params:
            selected = set(request.url.params["format"].split("|")) | {"q_origin_key"}
            row = {k: v for k, v in row.items() if k in selected}
        return httpx.Response(200, json={**envelope(), "results": [row]})
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original_client(**kwargs, transport=httpx.MockTransport(respond)))
    monkeypatch.setattr("fortipam_mcp.discovery_run_http_transport._ssl_context", lambda _: True)
    return custody, store, p, a, checkpoint, creation, state


def execute(custody, store, plan, auth, state, *, terminal_unknown=False):
    transport = FortiPamDiscoveryRunHttpTransport(CONFIG, original_custody=custody)
    class Adapter:
        def read_current(self, _): return plan.expected_current_digest
        def dispatch(self, _):
            try: state["result"] = transport.run_once(SOURCE.request)
            except Exception: raise M4AdapterAmbiguous("Synthetic fixed Run producer refused.") from None
        def read_postcondition(self, _):
            if terminal_unknown: raise M4AdapterAmbiguous("Synthetic postcondition unavailable.")
            return plan.expected_state_digest
    return M4ExecutionKernel(Adapter(), _Verifier(), store, clock=lambda: 1000).execute(plan, auth)


@pytest.mark.parametrize("fault", ["zero", "numeric_text"])
def test_actual_run_producer_preserves_original_counts_full_content_and_readonly_restart(tmp_path, monkeypatch, fault):
    c, store, p, a, checkpoint, parent, state = prepared(tmp_path, monkeypatch, fault=fault)
    result = execute(c, store, p, a, state)
    assert result.outcome == "succeeded" and state["posts"] == store.claim_count == 1
    observed = c.inspect_original_state()
    assert observed.native_reply_valid and observed.ongoing_requests == observed.failed_requests == 0
    assert observed.reply_shape.response_complete and observed.reply_shape.json_category == "object"
    assert observed.reply_shape.ongoing_kind == observed.reply_shape.failed_kind == ("decimal_text" if fault == "numeric_text" else "integer")
    assert observed.original_configuration_preserved and observed.original_outcome == "succeeded"
    assert observed.current_activity_or_recovery_qualified is False
    files = {path.name: path.read_bytes() for path in (tmp_path / "run-custody").iterdir()}
    assert set(files) == {"account-run-send.claim.json", "account-run-ack.json", "account-run-state.json"}
    assert all(value not in b"".join(files.values()) for value in (SOURCE.request.source_name.encode(), SERIAL.encode(), ACCOUNT.encode(), b"synthetic-token", b"extra-native-state"))
    c.close(); assert not c._key
    reader, readonly, *_ = components(tmp_path, parent, checkpoint, now=5000, readonly=True)
    assert reader.inspect_original_state() == observed
    with pytest.raises(AccountRunCustodyError):
        reader.begin_original_send(SOURCE.request, CONFIG, {**envelope(), "results": [full_source()]})
    assert readonly.claim_count == 1 and {path.name: path.read_bytes() for path in (tmp_path / "run-custody").iterdir()} == files
    fresh, reopened, fresh_plan, fresh_auth, _ = components(tmp_path, parent, checkpoint)
    replay = execute(fresh, reopened, fresh_plan, fresh_auth, state)
    assert replay.idempotent_replay and state["posts"] == 1


@pytest.mark.parametrize("fault", ["zero", "pending", "lost", "before_drift", "after_drift", "post_read_drift"])
def test_exact_m4_adapter_requires_original_zero_reply_and_preserved_complete_source(tmp_path, monkeypatch, fault):
    c, store, p, a, _, _, state = prepared(tmp_path, monkeypatch, fault=fault)
    transport = FortiPamDiscoveryRunHttpTransport(CONFIG, original_custody=c)
    adapter = AccountDiscoveryRunM4Adapter(c, transport)
    result = M4ExecutionKernel(adapter, _Verifier(), store, clock=lambda: 1000).execute(p, a)
    if fault == "zero":
        assert result.outcome == "succeeded" and result.verification == "verified"
        assert c.inspect_original_state().current_activity_or_recovery_qualified is False
    elif fault == "before_drift":
        assert result.outcome == "precondition_failed" and state["posts"] == 0
    else:
        assert result.outcome == "reconciliation_required" and result.verification == "unknown"
        if fault == "post_read_drift":
            assert c.inspect_original_state().original_configuration_preserved
    before = state["posts"]
    with pytest.raises(M4AdapterDenied): adapter.dispatch(p)
    assert state["posts"] == before


def test_independent_process_reads_original_counts_after_expiry_without_writes(tmp_path, monkeypatch):
    c, store, p, a, checkpoint, parent, state = prepared(tmp_path, monkeypatch)
    execute(c, store, p, a, state)
    before = {path.name: path.read_bytes() for path in (tmp_path / "run-custody").iterdir()}
    source_tail = parent._store._monotonic_checkpoint.tail
    script = """
import sys
from pathlib import Path
from dataclasses import replace
from test_m4_execution_store import _ExternalM4Checkpoint
from test_discovery_source_create_custody import components as source_components
from test_discovery_account_run_custody import components, RUN_STORE
root=Path(sys.argv[1])
source_checkpoint=_ExternalM4Checkpoint()
source_checkpoint.tail=replace(source_checkpoint.tail,sequence=int(sys.argv[2]),chain_hmac=sys.argv[3])
parent, *_=source_components(root/'source',source_checkpoint,now=5000,read_only=True)
run_checkpoint=_ExternalM4Checkpoint()
run_checkpoint.tail=replace(run_checkpoint.tail,store_ref=RUN_STORE,sequence=int(sys.argv[4]),chain_hmac=sys.argv[5])
reader,store,*_=components(root,parent,run_checkpoint,now=5000,readonly=True)
observed=reader.inspect_original_state()
assert observed.native_reply_valid and observed.ongoing_requests==observed.failed_requests==0
assert observed.original_configuration_preserved and observed.original_outcome=='succeeded'
assert observed.current_activity_or_recovery_qualified is False and store.claim_count==1
reader.close();parent.close()
print('independent original Run custody verified')
"""
    env = {**os.environ, "PYTHONPATH": os.pathsep.join((str(Path(__file__).parent), os.environ.get("PYTHONPATH", "")))}
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path), str(source_tail.sequence), source_tail.chain_hmac,
        str(checkpoint.tail.sequence), checkpoint.tail.chain_hmac], env=env, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "independent original Run custody verified"
    assert {path.name: path.read_bytes() for path in (tmp_path / "run-custody").iterdir()} == before


@pytest.mark.parametrize("fault,counts", [("pending", (3, 0)), ("failed", (0, 2)), ("lost", None), ("duplicate", None), ("target_progress", None)])
def test_parent_m4_success_or_later_timestamp_cannot_promote_original_reply(tmp_path, monkeypatch, fault, counts):
    c, store, p, a, checkpoint, parent, state = prepared(tmp_path, monkeypatch, fault=fault)
    execute(c, store, p, a, state)
    reader, *_ = components(tmp_path, parent, checkpoint, now=5000, readonly=True)
    observed = reader.inspect_original_state()
    assert observed.original_outcome == "succeeded"  # The generic kernel's original status is preserved.
    assert observed.native_reply_valid is (counts is not None)
    assert (observed.ongoing_requests, observed.failed_requests) == (counts if counts else (None, None))
    assert observed.original_configuration_preserved is observed.current_activity_or_recovery_qualified is False
    assert state["posts"] == 1


@pytest.mark.parametrize("fault", ["partial", "close_failure"])
def test_complete_json_with_failed_stream_is_original_unknown_not_a_positive_ack(tmp_path, monkeypatch, fault):
    c, store, p, a, checkpoint, parent, state = prepared(tmp_path, monkeypatch, fault=fault)
    adapter = AccountDiscoveryRunM4Adapter(c, FortiPamDiscoveryRunHttpTransport(CONFIG, original_custody=c))
    kernel = M4ExecutionKernel(adapter, _Verifier(), store, clock=lambda: 1000)
    result = kernel.execute(p, a)
    assert result.verification == "unknown" and state["posts"] == store.claim_count == 1
    observed = c.inspect_original_state()
    assert not observed.native_reply_valid and observed.ongoing_requests is observed.failed_requests is None
    assert not observed.original_configuration_preserved
    assert not observed.reply_shape.response_complete and observed.reply_shape.json_category == "incomplete"
    assert observed.reply_shape.ongoing_kind == observed.reply_shape.failed_kind == "unobserved"
    files = {path.name: path.read_bytes() for path in c._directory.iterdir()}
    c.close()
    reader, *_ = components(tmp_path, parent, checkpoint, now=5000, readonly=True)
    assert reader.inspect_original_state() == observed
    assert {path.name: path.read_bytes() for path in reader._directory.iterdir()} == files
    assert state["posts"] == 1


def test_signed_reply_shape_tamper_is_denied(tmp_path, monkeypatch):
    c, store, p, a, _, _, state = prepared(tmp_path, monkeypatch)
    execute(c, store, p, a, state)
    path = c._directory / "account-run-ack.json"
    body = json.loads(path.read_bytes()); body["reply_shape"]["ongoing_kind"] = "decimal_text"
    path.write_text(json.dumps(body))
    with pytest.raises(AccountRunCustodyError): c.inspect_original_state()


@pytest.mark.parametrize("fault", ["before_drift", "after_drift"])
def test_full_source_drift_does_not_gain_original_preservation(tmp_path, monkeypatch, fault):
    c, store, p, a, _, _, state = prepared(tmp_path, monkeypatch, fault=fault)
    execute(c, store, p, a, state)
    if fault == "before_drift":
        assert state["posts"] == 0
        assert list((tmp_path / "run-custody").iterdir()) == []
    else:
        assert state["posts"] == 1 and not c.inspect_original_state().original_configuration_preserved


def test_terminal_unknown_remains_unknown_with_positive_original_reply_and_content(tmp_path, monkeypatch):
    c, store, p, a, _, _, state = prepared(tmp_path, monkeypatch)
    result = execute(c, store, p, a, state, terminal_unknown=True)
    observed = c.inspect_original_state()
    assert result.outcome == observed.original_outcome == "reconciliation_required"
    assert observed.original_verification == "unknown" and observed.native_reply_valid
    assert observed.original_configuration_preserved and not observed.current_activity_or_recovery_qualified


@pytest.mark.parametrize("phase", ["before_ack", "after_ack", "after_state"])
def test_crash_cannot_backfill_missing_original_phases(tmp_path, monkeypatch, phase):
    c, store, p, a, checkpoint, parent, _ = prepared(tmp_path, monkeypatch)
    class Adapter:
        def read_current(self, _): return p.expected_current_digest
        def dispatch(self, _):
            c.begin_original_send(SOURCE.request, CONFIG, {**envelope(), "results": [full_source()]})
            if phase == "before_ack": raise KeyboardInterrupt
            raw = bytearray(b'{"ongoing_requests":0,"failed_requests":0}')
            c.capture_original_ack(raw, http_status=200, content_type="application/json", complete=True); assert not raw
            if phase == "after_ack": raise KeyboardInterrupt
            c.capture_original_state(SOURCE.request, {**envelope(), "results": [scanned_source()]},
                DiscoveryRunResult("accepted", 200, True, True, account_ack=AccountDiscoveryAck(0, 0)))
            raise KeyboardInterrupt
        def read_postcondition(self, _): return p.expected_state_digest
    with pytest.raises(KeyboardInterrupt): M4ExecutionKernel(Adapter(), _Verifier(), store, clock=lambda: 1000).execute(p, a)
    reader, *_ = components(tmp_path, parent, checkpoint, now=5000, readonly=True)
    if phase == "after_state":
        assert reader.inspect_original_state().original_outcome == "in_progress"
    else:
        with pytest.raises(AccountRunCustodyError): reader.inspect_original_state()
    before = {path.name: path.read_bytes() for path in (tmp_path / "run-custody").iterdir()}
    with pytest.raises(AccountRunCustodyError): reader.capture_original_ack(bytearray(), http_status=None, content_type="", complete=False)
    assert {path.name: path.read_bytes() for path in (tmp_path / "run-custody").iterdir()} == before


def test_clone_cannot_adopt_original_send(tmp_path, monkeypatch):
    c, store, p, a, checkpoint, parent, state = prepared(tmp_path, monkeypatch)
    clone, *_ = components(tmp_path, parent, checkpoint)
    class Adapter:
        def read_current(self, _): return p.expected_current_digest
        def dispatch(self, _):
            c.begin_original_send(SOURCE.request, CONFIG, {**envelope(), "results": [full_source()]})
            with pytest.raises(AccountRunCustodyError): clone.begin_original_send(SOURCE.request, CONFIG, {**envelope(), "results": [full_source()]})
            raw = bytearray(b'{"ongoing_requests":0,"failed_requests":0}')
            with pytest.raises(AccountRunCustodyError): clone.capture_original_ack(raw, http_status=200, content_type="application/json", complete=True)
            assert not raw
        def read_postcondition(self, _): return p.expected_state_digest
    M4ExecutionKernel(Adapter(), _Verifier(), store, clock=lambda: 1000).execute(p, a)
    assert state["posts"] == 0 and not (tmp_path / "run-custody/account-run-ack.json").exists()


def test_reserved_claim_without_actual_dispatch_ownership_cannot_write(tmp_path, monkeypatch):
    c, store, p, a, _, _, state = prepared(tmp_path, monkeypatch)
    store.claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest, idempotency_digest=p.idempotency_digest,
        authorization_digest=a.authorization_digest, context_digest=canonical_digest(dict(plan_digest=p.plan_digest, authorization_digest=a.authorization_digest, revision=p.revision)))
    with pytest.raises(AccountRunCustodyError):
        c.begin_original_send(SOURCE.request, CONFIG, {**envelope(), "results": [full_source()]})
    assert state["posts"] == 0 and list((tmp_path / "run-custody").iterdir()) == []


@pytest.mark.parametrize("fault", ["action", "actor", "witness"])
def test_foreign_action_actor_or_parent_signing_key_cannot_bind_run(tmp_path, monkeypatch, fault):
    c, store, p, a, _, parent, state = prepared(tmp_path, monkeypatch)
    fields = p.canonical_content()
    if fault == "action": fields["action_id"] = "discovery-entry-create"
    elif fault == "actor": fields["requester_digest"] = "c" * 64
    else: (tmp_path / "run-witness.key").write_bytes(bytes(parent._key))
    plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields)); authorization = _authorization(plan)
    with pytest.raises(AccountRunCustodyError):
        AccountDiscoveryRunCustody(tmp_path / "run-custody", tmp_path / "run-witness.key", parent, plan, authorization, store, CONFIG,
            selected_account=ACCOUNT, fixture_birth_digest=FIXTURE, clock=lambda: 1000)
    assert state["posts"] == store.claim_count == 0 and list((tmp_path / "run-custody").iterdir()) == []


@pytest.mark.parametrize("field", ["signature", "context_digest", "ongoing_requests"])
def test_original_record_tamper_refuses_independent_inspection(tmp_path, monkeypatch, field):
    c, store, p, a, checkpoint, parent, state = prepared(tmp_path, monkeypatch)
    execute(c, store, p, a, state)
    path = tmp_path / "run-custody/account-run-ack.json"; body = json.loads(path.read_bytes())
    body[field] = 7 if field == "ongoing_requests" else "0" * 64
    path.write_text(json.dumps(body))
    reader, *_ = components(tmp_path, parent, checkpoint, now=5000, readonly=True)
    with pytest.raises(AccountRunCustodyError): reader.inspect_original_state()
