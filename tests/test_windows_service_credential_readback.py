"""Seven bounded HTTP reads, original birth and independent pristine comparison."""
import json
from dataclasses import replace
import ssl

import pytest

from fortipam_mcp import windows_service_credential_readback as r
from fortipam_mcp.windows_service_credential_birth import WindowsServiceCredentialBirthCustody
from test_windows_service_credential_lifecycle import Peer, fixture, execute, raw
from test_windows_service_credential_contract import postcondition, SERIAL
from test_web_secret_create_ack import AckResponse
from v4_planning import M4Outcome
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome


class Source:
    def __init__(self, fault=None, token="synthetic-token"):
        self.fault = fault
        self.token = token
        self.available = True
        self.requests = []
        self.connections = []
        self.responses = []
        self.gets = self.passwords = 0

    def guard(self): return self.available

    def factory(self, host, port, **kwargs):
        assert host == "lab.example.test" and port == 443
        assert kwargs["context"].check_hostname and kwargs["context"].verify_mode == ssl.CERT_REQUIRED
        assert 0 < kwargs["timeout"] <= 10
        connection = Connection(self)
        self.connections.append(connection)
        return connection


class Connection:
    def __init__(self, source):
        self.source = source
        self.closed = False
        self.response = None

    def connect(self):
        if self.source.fault == "handshake-source": self.source.available = False
        if self.source.fault == "connect": raise OSError("Synthetic connection failure")

    def request(self, method, path, *, body=None, headers=None):
        source = self.source
        source.requests.append((method,path,body))
        assert headers["Authorization"] == "Bearer " + source.token
        if method == "GET":
            assert path == "/api/v2/cmdb/secret/database/70?with_meta=true&vdom=root" and body is None
            value = postcondition(); source.gets += 1
            value["results"]["totp-setting"]["shared-key"] = None if source.gets % 2 else "SYNTHETIC_VOLATILE_RENDER"
            if source.fault == "missing-field": del value["results"]["future-setting"]
            if source.fault == "row-drift" and source.gets == 2:
                value["results"]["future-setting"]["nested-secret-render"] = "changed"
            if source.fault == "stable-row-drift":
                value["results"]["future-setting"]["nested-secret-render"] = "changed"
        else:
            assert method == "POST" and path == "/api/v2/internal/secret-clear-text"
            request = json.loads(body)
            assert request["secret-id"] == 70
            value = dict(version="v7.0.0", build=29, serial=SERIAL, http_method="POST", http_status=200,
                         status="OK", **{"secret-id":70}, msg="Success")
            if "field-id" in request:
                assert request == {"secret-id":70,"field-id":1}
                source.passwords += 1
                value.update({"field-id":1,"results":"synthetic-credential"})
                if source.fault == "password": value["results"] = "different"
                if source.fault == "foreign-envelope": value["secret-id"] = 71
            else:
                assert request == {"secret-id":70,"totp-share-key":1}
                value["results"] = "ABCD2345" if source.fault == "totp" else ""
        response = AckResponse(raw(value)); self.response=response; source.responses.append(response)
        response.headers["Content-Length"] = str(len(response.payload))
        if source.fault == "content-length": response.headers["Content-Length"] = str(len(response.payload)+1)
        if source.fault == "invalid-length": response.headers["Content-Length"] = "-1"
        if source.fault == "encoding": response.headers["Content-Encoding"] = "gzip"
        if source.fault == "chunked": response.headers["Transfer-Encoding"] = "chunked"
        if source.fault == "read": response.failure = "read"
        if source.fault == "response-close": response.failure = "response_close"
        if source.fault == "trailing": response.payload.extend(b" trailing"); response.headers.pop("Content-Length")

    def getresponse(self): return self.response

    def close(self):
        self.closed = True
        if self.source.fault == "connection-close": raise OSError("Synthetic close failure")


class ReaderPeer(Peer):
    def __init__(self, source):
        super().__init__(); self.source = source; self.reader = None

    def _create_windows_service_credential(self, profile, request, body):
        self.custody.begin_original_send(body)
        self.calls += 1; self.body = body.obj
        self.ack = raw(dict(version="v7.0.0", build=29, http_method="POST", http_status=200,
            status="success", path="secret", name="database", vdom="root", serial=SERIAL, mkey=70))
        self.custody.capture_original_ack(self.ack, http_status=200, content_type="application/json")
        self.reader = r.WindowsServiceCredentialFullReader(self.custody, phase="original", read_enabled=True,
            source_guard=self.source.guard, connection_factory=self.source.factory, http_clock=lambda:0)
        self.reader.read_once()
        return SecretCreateAdapterOutcome.VERIFIED_CREATED


def setup(tmp_path, monkeypatch, *, fault=None):
    monkeypatch.setattr(r,"_ssl_context",lambda config:ssl.create_default_context())
    source=Source(fault); cmp=fixture(tmp_path,peer=ReaderPeer(source))
    cmp["source"]=source
    return cmp


def test_original_full_rows_and_material_brackets_seal_and_compare_independently(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    original=cmp["custody"].inspect_original_creation()
    assert original.state_digest and original.native_uuid
    source=cmp["source"]
    assert len(source.requests)==7 and source.gets==3 and source.passwords==2
    assert all(conn.closed and conn.response.closed for conn in source.connections)
    assert all(not any(buffer) for response in source.responses for buffer in response.buffers)
    cmp["custody"].close(); cmp["now"][0]=9999
    independent=WindowsServiceCredentialBirthCustody(cmp["directory"],cmp["key"],**cmp["birth_kwargs"])
    current=Source()
    reader=r.WindowsServiceCredentialFullReader(independent,phase="recovery-preview",read_enabled=True,
        source_guard=current.guard,connection_factory=current.factory,http_clock=lambda:0)
    observed=reader.read_once()
    assert observed.original==original and observed.current_state_digest==original.state_digest
    assert observed.original_material_seal_present and len(current.requests)==7
    with pytest.raises(r.WindowsServiceCredentialReadbackError): reader.read_once()
    with pytest.raises(r.WindowsServiceCredentialReadbackError):
        r.WindowsServiceCredentialFullReader(independent,phase="recovery-preview",read_enabled=True,
            source_guard=current.guard,connection_factory=current.factory,http_clock=lambda:0).read_once()
    assert len(current.requests)==7
    assert independent.inspect_original_creation()==original
    data=b"".join(p.read_bytes() for p in cmp["directory"].iterdir())
    for marker in (b"labuser",b"synthetic-credential",b"SYNTHETIC_",b"Success",b"MCPV4"):
        assert marker not in data
    independent.close()


@pytest.mark.parametrize("fault",["missing-field","row-drift","password","foreign-envelope","totp",
    "content-length","invalid-length","encoding","chunked","read","response-close","connection-close","trailing"])
def test_partial_invalid_or_foreign_read_never_seals_or_replays_birth(tmp_path, monkeypatch, fault):
    cmp=setup(tmp_path,monkeypatch,fault=fault)
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    source=cmp["source"]
    assert cmp["custody"].inspect_original_creation().state_digest is None
    assert (cmp["directory"]/"full-read.original.attempt.json").exists()
    assert not (cmp["directory"]/"create.full-birth.json").exists()
    assert not (cmp["directory"]/"full-read.original.result.json").exists()
    if fault=="missing-field": assert source.passwords==0 and len(source.requests)==1
    assert all(connection.closed for connection in source.connections)
    assert all(response.closed for response in source.responses)
    assert all(not any(buffer) for response in source.responses for buffer in response.buffers)
    count=len(source.requests)
    execute(cmp)
    assert len(source.requests)==count and cmp["peer"].calls==1
    with pytest.raises(r.WindowsServiceCredentialReadbackError): cmp["peer"].reader.read_once()
    assert len(source.requests)==count


def test_drift_during_tls_handshake_closes_before_a_material_request(tmp_path,monkeypatch):
    cmp=setup(tmp_path,monkeypatch,fault="handshake-source")
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert len(cmp["source"].connections)==1 and not cmp["source"].requests
    assert cmp["source"].connections[0].closed


@pytest.mark.parametrize("fault",["disabled","phase","host","tls","guard","stable-drift"])
def test_pristine_source_and_phase_controls_refuse_without_changing_original_birth(tmp_path,monkeypatch,fault):
    cmp=setup(tmp_path,monkeypatch)
    assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    original=cmp["custody"].inspect_original_creation()
    snapshot={p.name:p.read_bytes() for p in cmp["directory"].iterdir()}
    source=Source("stable-row-drift" if fault=="stable-drift" else None)
    reader=r.WindowsServiceCredentialFullReader(cmp["custody"],phase="recovery-preview",
        read_enabled=fault!="disabled",source_guard=source.guard,connection_factory=source.factory,http_clock=lambda:0)
    if fault=="phase": reader._phase="recovery-dispatch"
    if fault=="host": reader._host="other.example.test"
    if fault=="tls": reader._tls.check_hostname=False
    if fault=="guard": source.available=False
    with pytest.raises(r.WindowsServiceCredentialReadbackError): reader.read_once()
    assert len(source.requests)==(1 if fault=="stable-drift" else 0)
    assert source.passwords==0
    assert cmp["custody"].inspect_original_creation()==original
    assert all((cmp["directory"]/name).read_bytes()==value for name,value in snapshot.items())


def test_original_frame_survives_material_failure_and_independent_current_proof_never_late_seals(tmp_path,monkeypatch):
    cmp=setup(tmp_path,monkeypatch,fault="password")
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    original=cmp["custody"].inspect_original_creation()
    assert original.native_uuid and original.state_digest is None
    assert (cmp["directory"]/"create.original-frame.json").exists()
    assert not (cmp["directory"]/"create.full-birth.json").exists()
    snapshot={p.name:p.read_bytes() for p in cmp["directory"].iterdir()}
    cmp["custody"].close(); cmp["now"][0]=9999
    independent=WindowsServiceCredentialBirthCustody(cmp["directory"],cmp["key"],**cmp["birth_kwargs"])
    recovery_config=replace(cmp["birth_kwargs"]["config"],bearer_token="independent-synthetic-token")
    source=Source(token="independent-synthetic-token")
    reader=r.WindowsServiceCredentialFullReader(independent,phase="recovery-preview",config=recovery_config,
        read_enabled=True,source_guard=source.guard,connection_factory=source.factory,http_clock=lambda:0)
    observed=reader.read_once()
    assert observed.original==original and observed.current_state_digest
    assert not observed.original_material_seal_present
    assert observed.original.original_outcome=="reconciliation_required" and observed.original.state_digest is None
    assert observed.source_context_digest!=cmp["peer"].reader._source
    assert len(source.requests)==7 and independent.inspect_original_creation()==original
    assert not (cmp["directory"]/"create.full-birth.json").exists()
    assert all((cmp["directory"]/name).read_bytes()==value for name,value in snapshot.items())
    independent.close()


@pytest.mark.parametrize("change",["origin","token-drift"])
def test_independent_read_config_cannot_change_device_or_drift_after_binding(tmp_path,monkeypatch,change):
    cmp=setup(tmp_path,monkeypatch)
    assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    source=Source(token="independent-synthetic-token")
    config=replace(cmp["birth_kwargs"]["config"],bearer_token="independent-synthetic-token")
    if change=="origin":
        config=replace(config,base_url="https://other.example.test")
        with pytest.raises(r.WindowsServiceCredentialReadbackError):
            r.WindowsServiceCredentialFullReader(cmp["custody"],phase="recovery-preview",config=config,
                read_enabled=True,source_guard=source.guard,connection_factory=source.factory,http_clock=lambda:0)
    else:
        reader=r.WindowsServiceCredentialFullReader(cmp["custody"],phase="recovery-preview",config=config,
            read_enabled=True,source_guard=source.guard,connection_factory=source.factory,http_clock=lambda:0)
        reader._config=replace(config,bearer_token="different-synthetic-token")
        with pytest.raises(r.WindowsServiceCredentialReadbackError): reader.read_once()
    assert not source.requests


@pytest.mark.parametrize("change",["unchanged","removed","added","changed"])
def test_schema_minimum_preserves_every_first_observed_runtime_decoration_before_material(tmp_path,monkeypatch,change):
    import sys
    current_module=sys.modules[__name__]
    native_postcondition=postcondition
    state={"mode":"original"}
    def decorated():
        value=native_postcondition()
        if state["mode"]!="removed":
            value["results"]["native-runtime-extra"]={"opaque":"first" if state["mode"]!="changed" else "different"}
        if state["mode"]=="added": value["results"]["later-runtime-extra"]={"opaque":"additional"}
        return value
    monkeypatch.setattr(current_module,"postcondition",decorated)
    cmp=setup(tmp_path,monkeypatch)
    # The constructor's schema-qualified minimum predates these runtime extras.
    assert "native-runtime-extra" not in cmp["custody"]._row_fields
    assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    original=cmp["custody"].inspect_original_creation()
    snapshot={p.name:p.read_bytes() for p in cmp["directory"].iterdir()}
    source=Source(); state["mode"]=change
    reader=r.WindowsServiceCredentialFullReader(cmp["custody"],phase="recovery-preview",read_enabled=True,
        source_guard=source.guard,connection_factory=source.factory,http_clock=lambda:0)
    if change=="unchanged":
        assert reader.read_once().original==original and len(source.requests)==7
    else:
        with pytest.raises(r.WindowsServiceCredentialReadbackError): reader.read_once()
        assert len(source.requests)==1 and source.passwords==0
    assert all((cmp["directory"]/name).read_bytes()==value for name,value in snapshot.items())
    assert cmp["custody"].inspect_original_creation()==original
