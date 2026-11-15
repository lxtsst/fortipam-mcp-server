"""One fixed create plus seven complete readbacks through real local M4/C3."""
import ssl

import pytest

from fortipam_mcp import windows_service_credential_http_transport as h
from fortipam_mcp import windows_service_credential_readback as r
from fortipam_mcp.windows_service_credential_material import windows_service_credential_material_runtime
from fortipam_mcp.secret_create_m4_runtime import ProtectedSecretCreateM4Runtime
from test_secret_create_m4_runtime import _Resolver, _Verifier, _Reader
from test_windows_service_credential_lifecycle import fixture, execute, raw, SERIAL
from test_windows_service_credential_readback import Source as ReadSource
from test_web_secret_create_ack import AckResponse
from v4_planning import M4Outcome


class Source(ReadSource):
    def __init__(self,create_fault=None,read_fault=None):
        super().__init__(read_fault)
        self.create_fault=create_fault

    def factory(self,host,port,**kwargs):
        if self.connections: return super().factory(host,port,**kwargs)
        assert host=="lab.example.test" and port==443
        assert kwargs["context"].check_hostname and kwargs["context"].verify_mode==ssl.CERT_REQUIRED
        connection=CreateConnection(self)
        self.connections.append(connection)
        return connection


class CreateConnection:
    def __init__(self,source):
        self.source=source; self.closed=False; self.body=None
        self.response=AckResponse(raw(dict(version="v7.0.0",build=29,http_method="POST",http_status=200,
            status="success",path="secret",name="database",vdom="root",serial=SERIAL,mkey=70)))
        self.source.responses.append(self.response)
        self.response.headers["Content-Length"]=str(len(self.response.payload))
        fault=source.create_fault
        if fault=="response-close": self.response.failure="response_close"
        if fault=="length": self.response.headers["Content-Length"]=str(len(self.response.payload)+1)
        if fault=="read": self.response.failure="read"

    def connect(self):
        if self.source.create_fault=="handshake-source": self.source.available=False

    def request(self,method,path,*,body,headers):
        assert (method,path)==("POST","/api/v2/cmdb/secret/database?vdom=root")
        assert headers["Authorization"]=="Bearer synthetic-token"
        assert type(body) is memoryview and body.readonly and type(body.obj) is bytearray
        assert b'"target-privilege-account":"disable"' in body.obj and b'synthetic-credential' in body.obj
        self.body=body.obj
        self.source.requests.append((method,path,None))
        if self.source.create_fault=="request": raise OSError("Synthetic send uncertainty")

    def getresponse(self): return self.response

    def close(self):
        self.closed=True
        if self.source.create_fault=="connection-close": raise OSError("Synthetic close failure")


def setup(tmp_path,monkeypatch,*,enabled=True,guard=True,create_fault=None,read_fault=None):
    monkeypatch.setattr(h,"_ssl_context",lambda config:ssl.create_default_context())
    monkeypatch.setattr(r,"_ssl_context",lambda config:ssl.create_default_context())
    cmp=fixture(tmp_path); source=Source(create_fault,read_fault)
    source_guard=source.guard if guard is True else guard
    transport=h.WindowsServiceCredentialHttpTransport(cmp["birth_kwargs"]["config"],cmp["custody"],
        execution_enabled=enabled,source_guard=source_guard,connection_factory=source.factory,http_clock=lambda:0)
    runtime=windows_service_credential_material_runtime(**{**cmp["kwargs"],"transport":transport})
    cmp["outer"]=ProtectedSecretCreateM4Runtime(_Resolver(cmp["bound"]),_Verifier(),cmp["execution"],runtime,_Reader(),
        authenticated_requester_digest=cmp["bound"].plan.requester_digest,clock=lambda:cmp["now"][0])
    cmp.update(source=source,transport=transport)
    return cmp


def test_one_fixed_post_and_complete_readback_seal_original_state_without_material_leak(tmp_path,monkeypatch):
    cmp=setup(tmp_path,monkeypatch)
    assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    source=cmp["source"]
    assert len(source.requests)==8 and source.gets==3 and source.passwords==2
    assert all(connection.closed and connection.response.closed for connection in source.connections)
    assert not source.connections[0].body and not cmp["loader"].username and not cmp["loader"].password
    assert all(not any(buffer) for response in source.responses for buffer in response.buffers)
    original=cmp["custody"].inspect_original_creation()
    assert original.native_uuid and original.state_digest and original.original_outcome=="succeeded"
    assert execute(cmp).idempotent_replay and len(source.requests)==8
    assert cmp["loader"].loads==cmp["execution"].claim_count==cmp["material"].claim_count==1


@pytest.mark.parametrize("enabled,guard",[(False,True),(True,None),(True,lambda:False),(True,lambda:1)])
def test_disabled_or_unqualified_source_never_loads_material_or_opens_connection(tmp_path,monkeypatch,enabled,guard):
    cmp=setup(tmp_path,monkeypatch,enabled=enabled,guard=guard)
    assert execute(cmp).outcome is not M4Outcome.SUCCEEDED
    assert cmp["loader"].loads==cmp["material"].claim_count==0
    assert not cmp["source"].connections and not list(cmp["directory"].iterdir())


@pytest.mark.parametrize("fault",["request","read","length","response-close","connection-close"])
def test_uncertain_original_http_retains_available_ack_and_never_reposts(tmp_path,monkeypatch,fault):
    cmp=setup(tmp_path,monkeypatch,create_fault=fault)
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert (cmp["directory"]/"create.send.json").exists()
    assert (cmp["directory"]/"create.ack.json").exists()==(fault in {"response-close","connection-close"})
    assert not (cmp["directory"]/"create.original-frame.json").exists()
    count=len(cmp["source"].requests)
    execute(cmp)
    assert len(cmp["source"].requests)==count==1 and cmp["loader"].loads==1
    assert cmp["source"].connections[0].closed and not cmp["source"].connections[0].body
    assert all(not any(buffer) for response in cmp["source"].responses for buffer in response.buffers)


def test_readback_failure_retains_first_original_frame_but_no_material_seal(tmp_path,monkeypatch):
    cmp=setup(tmp_path,monkeypatch,read_fault="password")
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    original=cmp["custody"].inspect_original_creation()
    assert original.native_uuid and original.state_digest is None
    assert (cmp["directory"]/"create.original-frame.json").exists()
    assert not (cmp["directory"]/"create.full-birth.json").exists()
    count=len(cmp["source"].requests); execute(cmp)
    assert len(cmp["source"].requests)==count and cmp["loader"].loads==1


def test_source_drift_in_handshake_stops_before_send_marker_and_wire_post(tmp_path,monkeypatch):
    cmp=setup(tmp_path,monkeypatch,create_fault="handshake-source")
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert len(cmp["source"].connections)==1 and not cmp["source"].requests
    assert cmp["source"].connections[0].closed
    assert not list(cmp["directory"].iterdir()) and not cmp["loader"].password
