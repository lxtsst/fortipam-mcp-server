"""Fixed candidate HTTP routes with real M4/C3/custody and synthetic sockets."""
from dataclasses import replace
import ssl

import pytest

from fortipam_mcp import windows_execution_secret_http_transport as h
from fortipam_mcp import windows_execution_secret_ack as a
from fortipam_mcp.secret_create_m4_runtime import ProtectedSecretCreateM4Runtime
from fortipam_mcp.windows_execution_secret_material import windows_execution_secret_material_runtime
from test_windows_execution_secret_ack import fixture
from test_windows_execution_secret_contract import SERIAL, postcondition, raw
from test_windows_execution_secret_material import execute
from test_secret_create_m4_runtime import _Resolver, _Verifier
from test_web_secret_create_ack import AckResponse, _envelope
from v4_planning import M4Outcome


class Connection:
    def __init__(self, response, failure=None):
        self.response, self.failure = response, failure
        self.calls = []
        self.closed = False
        self.body = None

    def connect(self):
        if self.failure == 'connect': raise OSError('Synthetic TLS connection failure.')

    def request(self, method, path, *, body=None, headers=None):
        self.calls.append((method, path, headers))
        self.body = body.obj if body is not None else None
        if method == "POST":
            assert body.readonly and b'synthetic-credential' in body.obj
        else:
            assert method == "GET" and body is None and '/43?' in path
            assert 'field' not in path and 'totp' not in path
        if self.failure == "request": raise OSError("Synthetic send uncertainty.")

    def getresponse(self):
        if self.failure == "getresponse": raise OSError("Synthetic response uncertainty.")
        return self.response

    def close(self):
        self.closed = True
        if self.failure == "close": raise OSError("Synthetic connection closure uncertainty.")


def setup(tmp_path, monkeypatch, *, enabled=True, fault=None, source_guard=lambda:True):
    cmp = fixture(tmp_path)
    responses = [AckResponse(raw(_envelope(serial=SERIAL, identifier=43))), AckResponse(raw(postcondition()))]
    connections = [Connection(response) for response in responses]
    if fault == "status": responses[0].status = 302
    if fault == "content-type": responses[0].headers["Content-Type"] = "text/html"
    if fault == "encoding": responses[0].headers["Content-Encoding"] = "gzip"
    if fault == "chunked": responses[0].headers["Transfer-Encoding"] = "chunked"
    if fault == "oversize": responses[0].payload = bytearray(b"x"*16385)
    if fault == "read": responses[0].failure = "read"
    if fault == "ack-response-close": responses[0].failure = "response_close"
    if fault == "detail-response-close": responses[1].failure = "response_close"
    if fault == "request": connections[0].failure = "request"
    if fault == "getresponse": connections[0].failure = "getresponse"
    if fault == "connection-close": connections[0].failure = "close"
    if fault == "foreign-detail":
        value = postcondition();value["results"]["target"] = "foreign-target"
        responses[1].payload = raw(value)
    created = []
    def factory(host, port, **kwargs):
        assert host == "lab.example.test" and port == 443
        assert kwargs["context"].check_hostname and kwargs["context"].verify_mode == ssl.CERT_REQUIRED
        assert 0 < kwargs["timeout"] <= 10
        connection = connections[len(created)]
        created.append(connection)
        return connection
    monkeypatch.setattr(h, "_ssl_context", lambda config: ssl.create_default_context())
    transport = h.WindowsExecutionSecretHttpTransport(cmp["custody_kwargs"]["config"], cmp["custody"],
        execution_enabled=enabled, source_guard=source_guard, connection_factory=factory, http_clock=lambda: 0)
    values = {**cmp["kwargs"], "transport": transport}
    material = windows_execution_secret_material_runtime(**values)
    cmp["outer"] = ProtectedSecretCreateM4Runtime(_Resolver(cmp["bound"]), _Verifier(), cmp["execution"],
        material, cmp["reader"], authenticated_requester_digest=cmp["bound"].plan.requester_digest, clock=lambda: 1000)
    cmp.update(transport=transport, responses=responses, connections=connections, created=created)
    return cmp


def test_fixed_original_post_ack_and_exact_id_metadata_read_complete_with_closed_resources(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    assert len(cmp["created"]) == 2
    first, second = cmp["created"]
    assert first.calls[0][:2] == ("POST", "/api/v2/cmdb/secret/database?vdom=root")
    assert second.calls[0][0] == "GET" and second.calls[0][1].endswith("&with_meta=true&vdom=root")
    assert "force" not in second.calls[0][1] and "delegate" not in second.calls[0][1]
    assert all(conn.closed and conn.response.closed for conn in cmp["created"])
    assert not any(first.body) and not any(cmp["loader"].password)
    assert all(not any(buffer) for response in cmp["responses"] for buffer in response.buffers)
    observed = cmp["custody"].inspect_original_creation()
    assert observed.original_outcome == "succeeded" and observed.native_uuid is not None
    execute(cmp)
    assert len(cmp["created"]) == 2 and cmp["loader"].loads == 1


@pytest.mark.parametrize('guard', [None, lambda:False, lambda:1])
def test_missing_or_unqualified_source_guard_denies_before_c3_acquisition(tmp_path, monkeypatch, guard):
    cmp=setup(tmp_path, monkeypatch, source_guard=guard)
    assert execute(cmp).outcome is not M4Outcome.SUCCEEDED
    assert cmp['loader'].loads==cmp['material'].claim_count==0 and not cmp['created']


def test_source_drift_at_original_send_boundary_retains_marker_without_wire_post(tmp_path, monkeypatch):
    allowed=[True]
    cmp=setup(tmp_path, monkeypatch, source_guard=lambda:allowed[0])
    original=cmp['custody'].begin_original_send
    def change_after_send(body):
        original(body)
        allowed[0]=False
    monkeypatch.setattr(cmp['custody'], 'begin_original_send', change_after_send)
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert (cmp['directory']/a._SEND).exists() and not (cmp['directory']/a._ACK).exists()
    assert len(cmp['created'])==1 and not cmp['created'][0].calls
    assert cmp['created'][0].closed and cmp['loader'].loads==cmp['material'].claim_count==1
    assert not any(cmp['loader'].password)


def test_source_drift_during_tls_handshake_stops_before_send_record_and_wire_post(tmp_path, monkeypatch):
    allowed=[True]
    cmp=setup(tmp_path, monkeypatch, source_guard=lambda:allowed[0])
    monkeypatch.setattr(cmp['connections'][0], 'connect', lambda:allowed.__setitem__(0,False))
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert len(cmp['created'])==1 and not cmp['created'][0].calls and cmp['created'][0].closed
    assert not (cmp['directory']/a._SEND).exists() and not (cmp['directory']/a._ACK).exists()
    assert cmp['loader'].loads==1 and not any(cmp['loader'].password)


@pytest.mark.parametrize("fault", ["status", "content-type", "encoding", "chunked", "oversize", "read",
    "ack-response-close", "detail-response-close", "request", "getresponse", "connection-close", "foreign-detail"])
def test_uncertain_http_or_cleanup_never_succeeds_or_retries_and_erases_material(tmp_path, monkeypatch, fault):
    cmp = setup(tmp_path, monkeypatch, fault=fault)
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert cmp["loader"].loads == 1 and not any(cmp["loader"].password)
    assert all(conn.closed for conn in cmp["created"])
    assert not any(cmp["created"][0].body)
    if fault in ("status", "content-type", "encoding", "chunked"):
        assert cmp["responses"][0].reads == []
    assert cmp["reader"].calls == ["current"]
    count = len(cmp["created"])
    execute(cmp)
    assert len(cmp["created"]) == count and cmp["loader"].loads == 1
    if fault in ("ack-response-close", "detail-response-close", "connection-close", "foreign-detail"):
        original = cmp["custody"].inspect_original_creation()
        assert original.original_outcome == "reconciliation_required"


@pytest.mark.parametrize("blocked", ["disabled", "orphan", "source-drift"])
def test_closed_or_consumed_binding_blocks_before_central_material_and_http(tmp_path, monkeypatch, blocked):
    cmp = setup(tmp_path, monkeypatch, enabled=blocked != "disabled")
    if blocked == "orphan":
        path = cmp["directory"]/a._ACK;path.write_text('{}');path.chmod(0o600)
    if blocked == "source-drift":
        cmp["custody"]._config = replace(cmp["custody"]._config, bearer_token="changed-synthetic-token")
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert cmp["loader"].loads == cmp["material"].claim_count == len(cmp["created"]) == 0


def test_invalid_monotonic_clock_blocks_before_send_and_consumes_without_retry(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    cmp["transport"]._clock = lambda: float("nan")
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert len(cmp["created"]) == 0 and not any(cmp["loader"].password)
    assert not list(cmp["directory"].iterdir())
