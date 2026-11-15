"""Original Source custody through the real kernel and synthetic fixed HTTP."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import httpx
import pytest

from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, canonical_digest

from fortipam_mcp.discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from fortipam_mcp.discovery_entry_create_http_transport import FortiPamDiscoveryEntryCreateHttpTransport
from fortipam_mcp.discovery_entry_m4_adapter import DiscoveryEntryBinding, DiscoveryEntryM4Adapter
from fortipam_mcp.discovery_source_create_custody import DiscoverySourceCreateCustody, DiscoverySourceCustodyError
from fortipam_mcp.discovery_run_http_transport import AccountDiscoveryAck, DiscoveryRunResult
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_discovery_entry_m4_runtime import _discovery_plan
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF
from test_v4_execution_kernel import _authorization, _Verifier


SERIAL = "SYNTHETIC-SOURCE-APPLIANCE"
SOURCE = DiscoveryEntryBinding(DisabledUnixDiscoveryCreateInput("bp014-discovery-unix-disabled-20261024-r901", 17), "a" * 64)
CONFIG = SecretMetadataHttpTransportConfig("https://example.test", "synthetic-token", 5, None)
REFERENCE = hashlib.sha256(json.dumps(dict(secret_id=17, secret_name="Synthetic Secret", target_name="SyntheticTarget"),
    sort_keys=True, separators=(",", ":")).encode()).hexdigest()
ACCOUNT = "fpam-bp014-discovery-r123456789"


def components(root: Path, checkpoint=None, *, now=1000, read_only=False):
    checkpoint = checkpoint or _ExternalM4Checkpoint()
    store = PersistentM4ExecutionStateStore(root / "execution.sqlite", root / "execution.key",
        monotonic_checkpoint=checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF, read_only=read_only)
    base = _discovery_plan(SOURCE)
    fields = {**base.canonical_content(), "compensation_ref": None}
    plan = replace(base, compensation_ref=None, plan_digest=canonical_digest(fields))
    authorization = _authorization(plan)
    custody = DiscoverySourceCreateCustody(root / "custody", root / "source.key", SOURCE, plan,
        authorization, store, CONFIG, serial_digest=hashlib.sha256(SERIAL.encode()).hexdigest(),
        reference_digest=REFERENCE, clock=lambda: now)
    return custody, store, plan, authorization, checkpoint


def create(root):
    root.chmod(0o700)
    (root / "custody").mkdir(mode=0o700)
    for name, value in (("execution.key", b"e" * 32), ("source.key", b"s" * 32)):
        (root / name).write_bytes(value)
        (root / name).chmod(0o600)
    return components(root)


def envelope(method="GET", status=200):
    return dict(version="v7.0.0", build=29, http_method=method, http_status=status,
        status="success" if status == 200 else "error", path="secret", name="discovery", vdom="root", serial=SERIAL)


def full_source():
    return {**SOURCE.request.body(), "q_origin_key": SOURCE.request.source_name,
        "last-discovery-time": "0000-00-00 00:00:00", "discovery-results": [],
        "extra-native-state": {"flag": "preserve", "values": [1, True, None]}}


def ack(**changes):
    return bytearray(json.dumps({**envelope("POST"), "mkey": SOURCE.request.source_name, "error": 0, **changes}).encode())


def native_transport(monkeypatch, custody, *, fault="none"):
    state = dict(posts=0, row=None, gets=0, reference_serial=SERIAL)

    def respond(request):
        if request.method == "POST":
            state["posts"] += 1
            assert json.loads(request.content) == SOURCE.request.body()
            state["row"] = full_source()
            if fault == "lost_ack":
                raise httpx.ReadTimeout("Synthetic lost ACK")
            body = bytes(ack(serial="SYNTHETIC-WRONG")) if fault == "wrong_ack" else bytes(ack())
            return httpx.Response(200, content=body, headers={"content-type": "application/json"})
        state["gets"] += 1
        if request.url.path == "/api/v2/cmdb/secret/database/17":
            payload = {**envelope(), "name": "database", "serial": state["reference_serial"],
                "results": [dict(id=17, name="Synthetic Secret", target="SyntheticTarget")]}
            if fault in {"unselected_reference_duplicate", "selected_reference_duplicate", "nonfinite_reference"}:
                raw = json.dumps(payload)
                extra = {"unselected_reference_duplicate": '"unused":1,"unused":2,',
                    "selected_reference_duplicate": '"id":17,', "nonfinite_reference": '"unused":NaN,'}[fault]
                raw = raw.replace('"id": 17', extra + '"id":17')
                return httpx.Response(200, content=raw, headers={"content-type": "application/json"})
            return httpx.Response(200, json=payload)
        if request.url.path == "/api/v2/cmdb/secret/target/SyntheticTarget":
            return httpx.Response(200, json={**envelope(), "name": "target", "serial": state["reference_serial"],
                "results": [dict(name="SyntheticTarget")]})
        if state["row"] is None:
            return httpx.Response(404, json={**envelope(status=404), "results": []})
        row = state["row"]
        if "format" in request.url.params:
            keys = set(request.url.params["format"].split("|")) | {"q_origin_key"}
            row = {k: v for k, v in row.items() if k in keys}
        elif fault in {"duplicate_state", "nonfinite_state"}:
            content = json.dumps({**envelope(), "results": [row]})
            if fault == "duplicate_state":
                content = content.replace('"extra-native-state":', '"extra-native-state": 1,"extra-native-state":')
            else:
                content = content.replace('"extra-native-state":', '"extra-native-state": NaN,"unused-state":')
            return httpx.Response(200, content=content, headers={"content-type": "application/json"})
        return httpx.Response(200, json={**envelope(), "results": [row]})

    original = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(respond)))
    monkeypatch.setattr("fortipam_mcp.discovery_entry_create_http_transport._ssl_context", lambda _: True)
    transport = FortiPamDiscoveryEntryCreateHttpTransport(CONFIG, original_custody=custody)
    return transport, state


def test_actual_transport_producer_seals_original_ack_and_complete_state(monkeypatch, tmp_path):
    c, store, p, a, checkpoint = create(tmp_path)
    transport, state = native_transport(monkeypatch, c)
    result = M4ExecutionKernel(DiscoveryEntryM4Adapter(p, SOURCE, transport), _Verifier(), store, clock=lambda: 1000).execute(p, a)
    assert result.outcome == "succeeded" and state["posts"] == 1
    observation = c.inspect_original_state()
    assert observation.acknowledgement_qualified is True
    assert observation.original_outcome == "succeeded" and observation.original_verification == "verified"
    assert observation.legacy_row_sha256 == hashlib.sha256(json.dumps(full_source(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    before = {f.name: f.read_bytes() for f in (tmp_path / "custody").iterdir()}
    assert set(before) == {"source-send.claim.json", "source-create-ack.json", "source-created-state.json"}
    joined = b"".join(before.values())
    assert SOURCE.request.source_name.encode() not in joined and SERIAL.encode() not in joined
    assert b"extra-native-state" not in joined and b"synthetic-token" not in joined
    c.close()
    assert not c._key
    reader, reopened, *_ = components(tmp_path, checkpoint, now=5000, read_only=True)
    assert reader.inspect_original_state() == observation
    with pytest.raises(DiscoverySourceCustodyError):
        reader.begin_original_send(SOURCE.request, CONFIG, REFERENCE)
    assert reopened.claim_count == 1 and {f.name: f.read_bytes() for f in (tmp_path / "custody").iterdir()} == before


@pytest.mark.parametrize("fault", ["lost_ack", "wrong_ack"])
def test_lost_or_wrong_ack_preserves_original_unqualified_observation(monkeypatch, tmp_path, fault):
    c, store, p, a, checkpoint = create(tmp_path)
    transport, state = native_transport(monkeypatch, c, fault=fault)
    result = M4ExecutionKernel(DiscoveryEntryM4Adapter(p, SOURCE, transport), _Verifier(), store, clock=lambda: 1000).execute(p, a)
    # The existing adapter's independent postcondition semantics stay intact.
    assert result.outcome == "succeeded" and state["posts"] == 1
    observed = c.inspect_original_state()
    assert observed.acknowledgement_qualified is False
    assert (tmp_path / "custody/source-ack-unqualified.json").exists()
    assert not (tmp_path / "custody/source-create-ack.json").exists()
    reopened, *_ = components(tmp_path, checkpoint, now=5000, read_only=True)
    assert reopened.inspect_original_state() == observed
    with pytest.raises(DiscoverySourceCustodyError):
        reopened.bind_scan_preservation({**envelope(), "results": [full_source()]}, ACCOUNT, fixture_birth_digest="b" * 64)


def test_no_original_dispatch_owner_or_reserved_claim_can_write(tmp_path):
    c, store, p, a, _ = create(tmp_path)
    store.claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest, idempotency_digest=p.idempotency_digest,
        authorization_digest=a.authorization_digest, context_digest=canonical_digest({"plan_digest": p.plan_digest,
            "authorization_digest": a.authorization_digest, "revision": p.revision}))
    with pytest.raises(DiscoverySourceCustodyError):
        c.begin_original_send(SOURCE.request, CONFIG, REFERENCE)
    assert list((tmp_path / "custody").iterdir()) == []


@pytest.mark.parametrize("fault", ["before_ack", "after_ack", "after_state"])
def test_crash_cannot_backfill_any_missing_original_record(tmp_path, fault):
    c, store, p, a, checkpoint = create(tmp_path)

    class Adapter:
        def read_current(self, plan): return plan.expected_current_digest
        def dispatch(self, plan):
            c.begin_original_send(SOURCE.request, CONFIG, REFERENCE)
            if fault == "before_ack": raise KeyboardInterrupt
            raw = ack()
            assert c.capture_original_ack(raw, http_status=200, content_type="application/json")
            assert not any(raw)
            if fault == "after_ack": raise KeyboardInterrupt
            c.capture_original_state(SOURCE.request, {**envelope(), "results": [full_source()]})
            raise KeyboardInterrupt
        def read_postcondition(self, plan): return plan.expected_state_digest

    with pytest.raises(KeyboardInterrupt):
        M4ExecutionKernel(Adapter(), _Verifier(), store, clock=lambda: 1000).execute(p, a)
    reader, reopened, *_ = components(tmp_path, checkpoint, now=5000, read_only=True)
    if fault == "after_state":
        observed = reader.inspect_original_state()
        assert observed.original_outcome == "in_progress" and observed.original_verification == "unknown"
        with pytest.raises(DiscoverySourceCustodyError):
            reader.bind_scan_preservation({**envelope(), "results": [full_source()]}, ACCOUNT, fixture_birth_digest="b" * 64)
    else:
        with pytest.raises(DiscoverySourceCustodyError): reader.inspect_original_state()
    before = {f.name: f.read_bytes() for f in (tmp_path / "custody").iterdir()}
    with pytest.raises(DiscoverySourceCustodyError):
        reader.capture_original_state(SOURCE.request, {**envelope(), "results": [full_source()]})
    assert reopened.claim_count == 1 and {f.name: f.read_bytes() for f in (tmp_path / "custody").iterdir()} == before


@pytest.mark.parametrize("mutation", ["row", "signature", "context"])
def test_original_signed_state_mutation_is_rejected(monkeypatch, tmp_path, mutation):
    c, store, p, a, _ = create(tmp_path)
    transport, _ = native_transport(monkeypatch, c)
    M4ExecutionKernel(DiscoveryEntryM4Adapter(p, SOURCE, transport), _Verifier(), store, clock=lambda: 1000).execute(p, a)
    path = tmp_path / "custody/source-created-state.json"
    body = json.loads(path.read_text())
    body[{"row": "row_digest", "signature": "signature", "context": "context_digest"}[mutation]] = "0" * 64
    path.write_text(json.dumps(body))
    with pytest.raises(DiscoverySourceCustodyError): c.inspect_original_state()


def test_independent_process_reads_after_expiry_and_replay_never_resends(monkeypatch, tmp_path):
    c, store, p, a, checkpoint = create(tmp_path)
    transport, state = native_transport(monkeypatch, c)
    M4ExecutionKernel(DiscoveryEntryM4Adapter(p, SOURCE, transport), _Verifier(), store, clock=lambda: 1000).execute(p, a)
    original = c.inspect_original_state()
    before = {f.name: f.read_bytes() for f in (tmp_path / "custody").iterdir()}
    script = """
import sys
from pathlib import Path
from test_discovery_source_create_custody import components, envelope, full_source, ACCOUNT
from test_m4_execution_store import _ExternalM4Checkpoint
from fortipam_mcp.m4_execution_store import M4ExecutionStoreTail
checkpoint = _ExternalM4Checkpoint()
checkpoint.tail = M4ExecutionStoreTail(checkpoint.tail.store_ref, int(sys.argv[2]), sys.argv[3])
c, store, *_ = components(Path(sys.argv[1]), checkpoint, now=5000, read_only=True)
observed = c.inspect_original_state()
assert observed.acknowledgement_qualified and observed.original_outcome == 'succeeded'
assert store.claim_count == 1
pin = c.bind_scan_preservation({**envelope(), 'results': [full_source()]}, ACCOUNT, fixture_birth_digest='b' * 64)
pin.close()
print(observed.custody_digest)
"""
    env = {**os.environ, "PYTHONPATH": os.pathsep.join((str(Path(__file__).parent), os.environ.get("PYTHONPATH", "")))}
    child = subprocess.run([sys.executable, "-c", script, str(tmp_path), str(checkpoint.tail.sequence),
        checkpoint.tail.chain_hmac], env=env, capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, child.stderr
    assert child.stdout.strip() == original.custody_digest
    fresh, reopened, *_ = components(tmp_path, checkpoint)
    other, new_state = native_transport(monkeypatch, fresh)
    replay = M4ExecutionKernel(DiscoveryEntryM4Adapter(p, SOURCE, other), _Verifier(), reopened, clock=lambda: 1000).execute(p, a)
    assert replay.idempotent_replay and new_state["posts"] == 0 and state["posts"] == 1
    assert {f.name: f.read_bytes() for f in (tmp_path / "custody").iterdir()} == before


def test_second_instance_cannot_adopt_original_send_inside_same_m4(tmp_path):
    c, store, p, a, checkpoint = create(tmp_path)
    clone, *_ = components(tmp_path, checkpoint)

    class Adapter:
        def read_current(self, plan): return plan.expected_current_digest
        def dispatch(self, plan):
            c.begin_original_send(SOURCE.request, CONFIG, REFERENCE)
            with pytest.raises(DiscoverySourceCustodyError): clone.begin_original_send(SOURCE.request, CONFIG, REFERENCE)
            raw = ack()
            with pytest.raises(DiscoverySourceCustodyError): clone.capture_original_ack(raw, http_status=200, content_type="application/json")
            assert not any(raw)
            assert c.capture_original_ack(ack(), http_status=200, content_type="application/json")
            c.capture_original_state(SOURCE.request, {**envelope(), "results": [full_source()]})
        def read_postcondition(self, plan): return plan.expected_state_digest

    result = M4ExecutionKernel(Adapter(), _Verifier(), store, clock=lambda: 1000).execute(p, a)
    assert result.outcome == "succeeded" and c.inspect_original_state().acknowledgement_qualified


@pytest.mark.parametrize("field,value", [("_reference", "9" * 64), ("_serial", "9" * 64),
    ("_config", SecretMetadataHttpTransportConfig("https://example.test", "different-synthetic-token", 5, None))])
def test_pinned_source_context_drift_cannot_write(tmp_path, field, value):
    c, store, p, a, _ = create(tmp_path)
    setattr(c, field, value)

    class Adapter:
        def read_current(self, plan): return plan.expected_current_digest
        def dispatch(self, plan):
            with pytest.raises(DiscoverySourceCustodyError): c.begin_original_send(SOURCE.request, CONFIG, REFERENCE)
        def read_postcondition(self, plan): return plan.expected_current_digest

    M4ExecutionKernel(Adapter(), _Verifier(), store, clock=lambda: 1000).execute(p, a)
    assert list((tmp_path / "custody").iterdir()) == []


@pytest.mark.parametrize("mutate", [
    lambda raw: ack(error=True),
    lambda raw: ack(status="error"),
    lambda raw: ack(mkey="other-source"),
    lambda raw: bytearray(raw[:-1] + b',"http_status":200}'),
    lambda raw: bytearray(b'{"status":NaN}'),
])
def test_invalid_original_ack_never_becomes_qualified_from_full_state(tmp_path, mutate):
    c, store, p, a, _ = create(tmp_path)

    class Adapter:
        def read_current(self, plan): return plan.expected_current_digest
        def dispatch(self, plan):
            c.begin_original_send(SOURCE.request, CONFIG, REFERENCE)
            raw = mutate(ack())
            assert c.capture_original_ack(raw, http_status=200, content_type="application/json") is False
            assert not any(raw)
            c.capture_original_state(SOURCE.request, {**envelope(), "results": [full_source()]})
        def read_postcondition(self, plan): return plan.expected_state_digest

    M4ExecutionKernel(Adapter(), _Verifier(), store, clock=lambda: 1000).execute(p, a)
    assert c.inspect_original_state().acknowledgement_qualified is False


def test_full_state_does_not_promote_original_unknown_terminal_status(monkeypatch, tmp_path):
    c, store, p, a, checkpoint = create(tmp_path)
    transport, state = native_transport(monkeypatch, c)

    class PostReadUnknown(DiscoveryEntryM4Adapter):
        def read_postcondition(self, plan):
            raise M4AdapterAmbiguous("Synthetic independent post-read unavailable.")

    result = M4ExecutionKernel(PostReadUnknown(p, SOURCE, transport), _Verifier(), store, clock=lambda: 1000).execute(p, a)
    assert result.outcome == "reconciliation_required" and state["posts"] == 1
    reader, *_ = components(tmp_path, checkpoint, now=5000, read_only=True)
    observed = reader.inspect_original_state()
    assert observed.acknowledgement_qualified and observed.original_outcome == "reconciliation_required"
    assert observed.original_verification == "unknown"
    with pytest.raises(DiscoverySourceCustodyError):
        reader.bind_scan_preservation({**envelope(), "results": [full_source()]}, ACCOUNT, fixture_birth_digest="b" * 64)


def test_original_custody_joins_complete_scan_content_without_granting_authority(monkeypatch, tmp_path):
    c, store, p, a, _ = create(tmp_path)
    transport, state = native_transport(monkeypatch, c)
    M4ExecutionKernel(DiscoveryEntryM4Adapter(p, SOURCE, transport), _Verifier(), store, clock=lambda: 1000).execute(p, a)
    original = {**envelope(), "results": [full_source()]}
    pin = c.bind_scan_preservation(original, ACCOUNT, fixture_birth_digest="b" * 64)
    stamp = "2026-10-24 03:04:05"
    row = {**full_source(), "last-discovery-time": stamp,
        "discovery-results": [{"name": ACCOUNT, "managed-status": 0, "last-scanned-time": stamp, "q_origin_key": ACCOUNT}]}
    scope = dict(actor_digest=p.requester_digest, device_digest=hashlib.sha256(SERIAL.encode()).hexdigest(), fixture_birth_digest="b" * 64)
    summary = pin.accept_completed_scan({**envelope(), "results": [row]},
        DiscoveryRunResult("accepted", 200, True, True, account_ack=AccountDiscoveryAck(0, 0)), **scope)
    assert summary["source_recovery_authorized"] is summary["latest_run_or_timezone_qualified"] is False
    assert state["posts"] == 1 and store.claim_count == 1
    pin.close()
    drifted = full_source()
    drifted["extra-native-state"] = {"flag": "changed"}
    with pytest.raises(DiscoverySourceCustodyError):
        c.bind_scan_preservation({**envelope(), "results": [drifted]}, ACCOUNT, fixture_birth_digest="b" * 64)


@pytest.mark.parametrize("fault", ["duplicate_state", "nonfinite_state"])
def test_invalid_original_full_row_cannot_seal_or_be_backfilled(monkeypatch, tmp_path, fault):
    c, store, p, a, checkpoint = create(tmp_path)
    transport, state = native_transport(monkeypatch, c, fault=fault)
    M4ExecutionKernel(DiscoveryEntryM4Adapter(p, SOURCE, transport), _Verifier(), store, clock=lambda: 1000).execute(p, a)
    assert state["posts"] == 1 and not (tmp_path / "custody/source-created-state.json").exists()
    reader, *_ = components(tmp_path, checkpoint, now=5000, read_only=True)
    with pytest.raises(DiscoverySourceCustodyError): reader.inspect_original_state()
    with pytest.raises(DiscoverySourceCustodyError):
        reader.capture_original_state(SOURCE.request, {**envelope(), "results": [full_source()]})
    assert not (tmp_path / "custody/source-created-state.json").exists()
