"""Separate real M4 recovery preserves original receipts and consumed failures."""
import io
import json

import pytest
from v4_planning import M4AdapterDenied, M4ExecutionKernel

from fortipam_mcp.job_definition_recovery_m4_adapter import JobDefinitionRecoveryM4Adapter
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_job_definition_authority import creation, authority, IDENTITY
from test_job_definition_sources import SERIAL, CANDIDATE
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF
import fortipam_mcp.job_namespace_ssh_reader as namespace
from test_job_namespace_ssh_reader import names_frame
from test_job_definition_sources import SOURCE, TARGET


class Native:
    def __init__(self, api, *, fault=None):
        self.api, self.fault = api, fault
        self.calls, self.connections, self.responses = [], [], []
        self.hook = lambda: None

    def factory(self, *args, **kwargs):
        peer = self
        class Connection:
            sock = None
            closed = False
            def connect(self): peer.hook()
            def request(self, method, path, body, headers):
                assert method == "DELETE" and path == "/api/v2/cmdb/secret/job/" + CANDIDATE + "?vdom=root" and body is None
                assert headers["Content-Length"] == "0" and headers["Authorization"] == "Bearer synthetic-token"
                assert headers["User-Agent"] == "fortipam-mcp-disabled-job-recover/1" and "Cookie" not in headers
                peer.calls.append((method, path))
                if peer.fault != "http403": peer.api.present = False
                if peer.fault == "absence": peer.api.failure = "role"
            def getresponse(self):
                if peer.fault == "lost-ack": raise OSError("Synthetic lost DELETE response.")
                raw = dict(version="v7.0.0", build=29, http_method="DELETE", http_status=200, status="success",
                    path="secret", name="job", vdom="root", serial=SERIAL, mkey=CANDIDATE, error=0)
                if peer.fault == "http403": raw.update(http_status=403, status="error", error=2)
                if peer.fault == "wrong-ack": raw["mkey"] += "-other"
                response = Response(json.dumps(raw).encode()); peer.responses.append(response)
                return response
            def close(self): self.closed = True
        class Response:
            closed = False
            status = 403 if peer.fault == "http403" else 200
            def __init__(self, raw): self.body = io.BytesIO(raw)
            def getheader(self, name, default=""):
                if name == "Content-Type": return "application/json"
                if name == "Content-Encoding": return "gzip" if peer.fault == "encoded" else "identity"
                return default
            def read(self, size): return self.body.read(size)
            def close(self):
                if peer.fault == "close": raise OSError("Synthetic close failure.")
                self.closed = True
        item = Connection(); self.connections.append(item)
        return item


def prepare(tmp_path, monkeypatch, *, unknown=False, fault=None, enabled=True):
    source, creator, original, create_store, create_adapter = creation(tmp_path, monkeypatch, unknown=unknown)
    api = source._factory.__self__
    issuer = authority(source, phase="recover", original=original)
    observed = source.observe_candidate_presence()
    args = dict(requester_digest=IDENTITY["requester_digest"], transport_digest=IDENTITY["transport_digest"])
    preview = issuer.preview(observed, **args)
    packet = issuer.issue(preview, observed, **args)
    root = tmp_path / "recovery"; root.mkdir(mode=0o700); (root / "state").mkdir(mode=0o700)
    for name, value in (("execution.key", b"r" * 32), ("witness.key", b"z" * 32)):
        (root / name).write_bytes(value); (root / name).chmod(0o600)
    store = PersistentM4ExecutionStateStore(root / "execution.sqlite", root / "execution.key",
        monotonic_checkpoint=_ExternalM4Checkpoint(), checkpoint_store_ref=CHECKPOINT_STORE_REF)
    native = Native(api, fault=fault)
    kwargs = dict(directory=root / "state", witness_key_file=root / "witness.key",
        execution_enabled=enabled, connection_factory=native.factory)
    adapter = JobDefinitionRecoveryM4Adapter(source, original, issuer, packet, store, **kwargs)
    return source, creator, original, create_store, create_adapter, issuer, packet, store, native, adapter, kwargs


@pytest.mark.parametrize("unknown", [False, True])
def test_independent_source_bound_recovery_deletes_only_original_and_preserves_creation(tmp_path, monkeypatch, unknown):
    source, creator, original, create_store, create_adapter, issuer, packet, store, native, adapter, _ = prepare(tmp_path, monkeypatch, unknown=unknown)
    before = {p.name: p.read_bytes() for p in original._directory.iterdir()}
    original_state = original.inspect_original_full_state()
    result = M4ExecutionKernel(adapter, issuer, store, clock=issuer._now).execute(packet.plan, packet.authorization)
    assert str(result.outcome) == "succeeded" and str(result.verification) == "verified"
    assert store.claim_count == len(native.calls) == create_store.claim_count == 1
    assert source._current.absent and not native.api.present and source.logout_verified
    assert original.inspect_original_full_state() == original_state
    assert before == {p.name: p.read_bytes() for p in original._directory.iterdir()}
    assert all(item.closed for item in native.connections + native.responses)
    assert set(p.name for p in adapter._directory.iterdir()) == {"recover.claim.json", "recover.response.json",
        "recover.body-shape.json", "recover.ack.json", "recover.absence.json"}
    adapter.close(); issuer.close(); create_adapter.close(); creator.close(); source.close()


@pytest.mark.parametrize("fault", ["http403", "lost-ack", "wrong-ack", "encoded", "absence", "close"])
def test_consumed_recovery_never_replays_or_promotes_unknown(tmp_path, monkeypatch, fault):
    source, creator, original, _, create_adapter, issuer, packet, store, native, adapter, kwargs = prepare(tmp_path, monkeypatch, fault=fault)
    before = {p.name: p.read_bytes() for p in original._directory.iterdir()}
    result = M4ExecutionKernel(adapter, issuer, store, clock=issuer._now).execute(packet.plan, packet.authorization)
    assert str(result.outcome) == "reconciliation_required" and str(result.verification) == "unknown"
    assert store.claim_count == len(native.calls) == 1
    assert before == {p.name: p.read_bytes() for p in original._directory.iterdir()}
    calls = len(native.api.calls)
    with pytest.raises(M4AdapterDenied): JobDefinitionRecoveryM4Adapter(source, original, issuer, packet, store, **kwargs)
    assert len(native.api.calls) == calls and len(native.calls) == 1
    if fault == "http403":
        shape = json.loads((adapter._directory / "recover.body-shape.json").read_bytes())
        assert shape["status_category"] == "error" and shape["error_code"] == 2
    if fault == "absence": assert (adapter._directory / "recover.failure.json").is_file()
    adapter.close(); issuer.close(); create_adapter.close(); creator.close(); source.close()


@pytest.mark.parametrize("fault", ["role", "store-key"])
def test_after_tls_drift_prevents_delete_and_original_http_claim(tmp_path, monkeypatch, fault):
    source, creator, original, _, create_adapter, issuer, packet, store, native, adapter, kwargs = prepare(tmp_path, monkeypatch)
    if fault == "role": native.hook = lambda: setattr(native.api, "failure", "role")
    else: native.hook = lambda: store._key_path.write_bytes(b"t" * 32)
    result = M4ExecutionKernel(adapter, issuer, store, clock=issuer._now).execute(packet.plan, packet.authorization)
    assert str(result.outcome) != "succeeded" and not native.calls and native.api.present
    assert not list(adapter._directory.iterdir())
    assert all(item.closed for item in native.connections)
    adapter.close(); issuer.close(); create_adapter.close(); creator.close(); source.close()


def test_independent_adapter_default_off_and_detached_dispatch_cannot_delete(tmp_path, monkeypatch):
    source, creator, original, _, create_adapter, issuer, packet, store, native, adapter, kwargs = prepare(tmp_path, monkeypatch, enabled=False)
    before = len(native.api.calls)
    result = M4ExecutionKernel(adapter, issuer, store, clock=issuer._now).execute(packet.plan, packet.authorization)
    assert str(result.outcome) == "denied" and len(native.api.calls) == before and not native.calls
    assert not list(adapter._directory.iterdir())
    adapter.close(); issuer.close(); create_adapter.close(); creator.close(); source.close()


def test_post_delete_namespace_must_remove_only_the_original_job(tmp_path, monkeypatch):
    source, creator, original, _, create_adapter, issuer, packet, store, native, adapter, _ = prepare(tmp_path, monkeypatch)
    read = namespace._send_and_read
    async def changed(process, command, prompt, deadline):
        raw = await read(process, command, prompt, deadline)
        if not native.api.present and command == namespace._NAME_PROJECTION:
            return names_frame((SOURCE, TARGET, "Other concurrent Job"))
        return raw
    monkeypatch.setattr(namespace, "_send_and_read", changed)
    result = M4ExecutionKernel(adapter, issuer, store, clock=issuer._now).execute(packet.plan, packet.authorization)
    assert str(result.outcome) == "reconciliation_required" and not native.api.present
    assert len(native.calls) == store.claim_count == 1 and not (adapter._directory / "recover.absence.json").exists()
    assert (adapter._directory / "recover.ack.json").is_file()
    adapter.close(); issuer.close(); create_adapter.close(); creator.close(); source.close()


def test_global_absence_read_requires_delete_channel_closed(tmp_path,monkeypatch):
    source,creator,original,_,create_adapter,issuer,packet,store,native,adapter,_=prepare(tmp_path,monkeypatch)
    observe=source.observe_absence
    def independent_read():
        assert native.connections and all(v.closed for v in native.connections+native.responses)
        return observe()
    monkeypatch.setattr(source,"observe_absence",independent_read)
    result=M4ExecutionKernel(adapter,issuer,store,clock=issuer._now).execute(packet.plan,packet.authorization)
    assert str(result.outcome)=="succeeded" and adapter._readback_after_channel_closure
