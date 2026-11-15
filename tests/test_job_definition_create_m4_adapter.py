"""Actual persistent M4 plus fixed HTTP/source mocks preserve original failures."""
import http.client
import io
import json

import pytest
from v4_planning import M4AdapterDenied, M4ExecutionKernel

from fortipam_mcp.job_definition_ack_custody import JobDefinitionAckCustodyError
from fortipam_mcp.job_definition_create_m4_adapter import JobDefinitionCreateM4Adapter
from test_job_definition_ack_custody import ack
from test_job_definition_original_state import prepared
from test_job_definition_sources import SERIAL
from test_v4_execution_kernel import _Verifier


class Native:
    def __init__(self, api, custody, pins, *, fault=None):
        self.api, self.custody, self.pins, self.fault = api, custody, pins, fault
        self.connections, self.responses, self.calls, self.buffers = [], [], [], []
        self.hook = lambda: None

    def factory(self, *args, **kwargs):
        peer = self
        class Connection:
            sock = None
            closed = False
            def connect(self): peer.hook()
            def request(self, method, path, body, headers):
                assert method == "POST" and path == "/api/v2/cmdb/secret/job?with_meta=true&vdom=root"
                assert headers["Content-Length"] == str(len(body)) and headers["Authorization"] == "Bearer synthetic-token"
                assert headers["User-Agent"] == "fortipam-mcp-disabled-job-create/1" and "Cookie" not in headers
                assert json.loads(body.tobytes())["status"] == "disable"
                peer.calls.append((method, path)); peer.buffers.append(body.obj)
                if peer.fault != "http403": peer.api.present = True
                if peer.fault == "readback": peer.api.failure = "candidate-ref"
            def getresponse(self):
                if peer.fault == "lost-ack": raise http.client.RemoteDisconnected("Synthetic lost response.")
                if peer.fault == "expiry": peer.custody._clock = lambda: 1300
                raw = ack(peer.pins, serial=SERIAL)
                if peer.fault == "bad-ack": raw = bytearray(b'{"status":"success"}')
                if peer.fault == "oversize": raw = bytearray(b"x" * 16385)
                response = Response(raw); peer.responses.append(response)
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


def execute(cmp, native, *, enabled=True):
    source, api, custody, store, plan, authorization, pins = cmp
    adapter = JobDefinitionCreateM4Adapter(source, custody, execution_enabled=enabled, connection_factory=native.factory)
    result = M4ExecutionKernel(adapter, _Verifier(), store, clock=lambda: 1000).execute(plan, authorization)
    return adapter, result


def test_actual_original_http_is_bound_to_source_m4_ack_and_complete_state(tmp_path, monkeypatch):
    cmp = prepared(tmp_path, monkeypatch)
    source, api, custody, store, plan, authorization, pins = cmp
    native = Native(api, custody, pins)
    adapter, result = execute(cmp, native)
    assert str(result.outcome) == "succeeded" and str(result.verification) == "verified"
    assert len(native.calls) == store.claim_count == 1 and api.present
    original = custody.inspect_original_full_state()
    assert original.state_digest == source._current.state_digest
    assert all(item.closed for item in native.connections + native.responses)
    assert all(not any(buffer) for buffer in native.buffers)
    response = json.loads((custody._directory / "create-response.json").read_bytes())
    assert response["http_status"] == 200 and response["exact_json"] and not response["raw_values_stored"]
    before = list(native.calls), len(api.calls)
    replay = M4ExecutionKernel(adapter, _Verifier(), store, clock=lambda: 1000).execute(plan, authorization)
    assert replay.idempotent_replay and before == (native.calls, len(api.calls))
    adapter.close(); source.close()
    assert custody.inspect_original_full_state() == original


@pytest.mark.parametrize("fault", ["http403", "lost-ack", "bad-ack", "encoded", "oversize", "readback", "expiry"])
def test_consumed_native_failure_keeps_unknown_diagnostics_and_never_replays(tmp_path, monkeypatch, fault):
    cmp = prepared(tmp_path, monkeypatch)
    source, api, custody, store, plan, authorization, pins = cmp
    native = Native(api, custody, pins, fault=fault)
    adapter, result = execute(cmp, native)
    assert str(result.outcome) == "reconciliation_required" and str(result.verification) == "unknown"
    assert len(native.calls) == store.claim_count == 1
    with pytest.raises(JobDefinitionAckCustodyError): custody.inspect_original_full_state()
    marker = json.loads((custody._directory / "create-failure.json").read_bytes())
    assert marker["original_request_replayable"] is False
    if fault == "readback":
        assert marker["source_reader_phase"] == "candidate_before"
        assert marker["reader_failure_stage"] == "detail_control"
        from fortipam_mcp.job_definition_sources import JobDefinitionSourceError
        original_diagnostics = source._failure_diagnostics()
        reads = len(api.calls)
        with pytest.raises(JobDefinitionSourceError):
            source.observe_candidate_presence()
        assert len(api.calls) == reads and source._failure_diagnostics() == original_diagnostics
        source._last_reader_failure_stage = "SYNTHETIC_PRIVATE_UPSTREAM_VALUE"
        source._last_failure_stage = "SYNTHETIC_PRIVATE_SELECTOR"
        assert source._failure_diagnostics() == {
            "source_reader_phase": None, "reader_failure_stage": None}
        assert "SYNTHETIC_PRIVATE" not in json.dumps(marker)
    else:
        assert marker["source_reader_phase"] is marker["reader_failure_stage"] is None
    before = len(api.calls), list(native.calls)
    with pytest.raises(M4AdapterDenied): JobDefinitionCreateM4Adapter(source, custody, execution_enabled=True, connection_factory=native.factory)
    assert before == (len(api.calls), native.calls)
    assert all(item.closed for item in native.connections + native.responses)
    assert all(not any(buffer) for buffer in native.buffers)
    adapter.close(); source.close()


def test_drift_after_tls_denies_before_post_and_original_http_claim(tmp_path, monkeypatch):
    cmp = prepared(tmp_path, monkeypatch)
    source, api, custody, store, _, _, pins = cmp
    native = Native(api, custody, pins)
    native.hook = lambda: setattr(api, "failure", "role")
    adapter, result = execute(cmp, native)
    assert str(result.outcome) != "succeeded" and not native.calls and not api.present
    assert not (custody._directory / "send.claim.json").exists()
    assert all(item.closed for item in native.connections)
    adapter.close(); source.close()


def test_default_off_and_detached_dispatch_do_not_send_http_or_acquire_http_claim(tmp_path, monkeypatch):
    cmp = prepared(tmp_path, monkeypatch)
    source, api, custody, store, plan, _, pins = cmp
    native = Native(api, custody, pins)
    before = len(api.calls)
    adapter, result = execute(cmp, native, enabled=False)
    assert str(result.outcome) == "denied" and str(result.verification) == "not_started"
    assert not native.calls and store.claim_count == 1 and len(api.calls) == before
    adapter.close()
    adapter = JobDefinitionCreateM4Adapter(source, custody, execution_enabled=True, connection_factory=native.factory)
    with pytest.raises(M4AdapterDenied): adapter.dispatch(plan)
    assert not native.connections and not list(custody._directory.iterdir()) and store.claim_count == 1
    adapter.close(); source.close()


def test_close_failure_keeps_ack_unknown_before_full_state_readback(tmp_path, monkeypatch):
    cmp = prepared(tmp_path, monkeypatch)
    source, api, custody, store, _, _, pins = cmp
    native = Native(api, custody, pins, fault="close")
    adapter, result = execute(cmp, native)
    assert str(result.outcome) == "reconciliation_required" and str(result.verification) == "unknown"
    assert custody.inspect_original_ack().original_verification == "unknown" and not adapter._resources_closed
    with pytest.raises(JobDefinitionAckCustodyError): custody.inspect_original_full_state()
    assert not adapter._readback_after_channel_closure
    assert json.loads((custody._directory/"create-failure.json").read_bytes())["stage"] == "original_channel_closure"
    assert store.claim_count == len(native.calls) == 1
    adapter.close(); source.close()


def test_complete_readback_requires_original_writer_channel_closed(tmp_path,monkeypatch):
    cmp=prepared(tmp_path,monkeypatch)
    source,api,custody,store,_,_,pins=cmp
    native=Native(api,custody,pins)
    observe=source.observe_candidate_presence
    def independent_read():
        assert native.connections and all(v.closed for v in native.connections+native.responses)
        return observe()
    monkeypatch.setattr(source,"observe_candidate_presence",independent_read)
    adapter,result=execute(cmp,native)
    assert str(result.outcome)=="succeeded" and adapter._readback_after_channel_closure


@pytest.mark.parametrize("fault", ["none","short-wait","rollback","nonfinite","deadline-before","deadline-after"])
def test_native_wad_delay_is_fixed_and_cannot_extend_authority(fault):
    from fortipam_mcp.job_definition_create_m4_adapter import _wait_for_job_wad_publication
    times=[10.0];waits=[];guards=[]
    def clock():return float('nan') if fault=="nonfinite" else times[0]
    def wait(seconds):
        waits.append(seconds);times[0]+=2.9 if fault=="short-wait" else -1 if fault=="rollback" else seconds
    def guard():
        guards.append(True)
        if fault=="deadline-after" and len(guards)>1:raise ValueError("synthetic expired authority")
        return 2.0 if fault=="deadline-before" else 60.0
    if fault=="none":
        _wait_for_job_wad_publication(guard,wait,clock)
        assert waits==[3.0] and len(guards)==2
    else:
        with pytest.raises(ValueError):_wait_for_job_wad_publication(guard,wait,clock)
        assert waits==([] if fault in {"nonfinite","deadline-before"} else [3.0])
