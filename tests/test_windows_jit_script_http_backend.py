"""Fixed HTTP candidate with synthetic peers, ACK privacy and real M4 claims."""
from copy import deepcopy
import hashlib
import json

import pytest

from fortipam_mcp.windows_jit_script_http_backend import (
    WindowsJitScriptHttpBackend, WindowsJitScriptHttpError,
)
from fortipam_mcp.windows_jit_script_m4 import JitScriptExecutionScope, WindowsJitScriptM4Session
from fortipam_mcp.windows_jit_script_source import COLLECTION_PATH
from test_system_email_m4_adapter import store_at
from test_windows_jit_script_m4 import Backend, Evidence, bind, execute
from test_windows_jit_script_source import Peer, PRIVATE, envelope
from v4_planning import M4AdapterDenied


class HttpPeer(Peer):
    def __init__(self):
        super().__init__(); self.writes = []; self.ack_fault = None
        self.on_connect = lambda:None; self.on_close = lambda:None

    def mutate(self, method, path, body):
        assert method in ('POST','DELETE')
        if method == 'POST':
            assert path == COLLECTION_PATH
            decoded = json.loads(bytes(body)); index = next(i for i,row in enumerate(self.expected) if row == decoded)
        else:
            assert body is None; index = self.details.index(path)
        backend = Backend(self)
        backend.submit(None if method == 'DELETE' else memoryview(bytearray(body)).toreadonly(),
            index=index,remove=method == 'DELETE',parameters_digest='1'*64,before_send=lambda:60,timeout_seconds=5)
        self.writes.append((method,index))
        ack = envelope(None,method=method,mkey=self.expected[index]['name'],revision=PRIVATE.decode(),revision_changed=True)
        if self.ack_fault in ('method','device','build','mkey','status'):
            field = dict(method='http_method',device='serial').get(self.ack_fault,self.ack_fault)
            ack[field] = True if field == 'build' else 'foreign'
        elif self.ack_fault == 'echo': ack['results'] = dict(script=PRIVATE.decode())
        elif self.ack_fault == 'extra': ack['password'] = PRIVATE.decode()
        elif self.ack_fault == 'error': ack['error'] = -1
        return ack

    def factory(self, host, port, **kwargs):
        connection = super().factory(host,port,**kwargs)
        request, response, connect, close = connection.request,connection.getresponse,connection.connect,connection.close
        connection.write_ack = None
        def connected(): connect(); self.on_connect()
        def closed(): close(); self.on_close()
        def requested(method,path,*,body=None,headers):
            if method == 'DELETE' or method == 'POST' and 'X-HTTP-Method-Override' not in headers:
                assert headers['Authorization'] == 'Bearer synthetic-api-token'
                assert headers['Content-Type'] == 'application/json'
                connection.write_ack = self.mutate(method,path,body)
            else: request(method,path,body=body,headers=headers)
        def responded():
            if connection.write_ack is None: return response()
            raw = json.dumps(connection.write_ack).encode(); peer = self
            class Response:
                status = 200
                def __init__(self): self.offset = 0; self.closed = False
                def getheader(self,name,default=None):
                    return {'content-type':'application/json','content-length':str(len(raw))}.get(name.lower(),default)
                def isclosed(self): return self.offset >= len(raw)
                def readinto(self,view):
                    if not peer.buffers or peer.buffers[-1] is not view.obj: peer.buffers.append(view.obj)
                    count = min(len(view),len(raw)-self.offset,113)
                    view[:count] = raw[self.offset:self.offset+count]; self.offset += count
                    return count
                def close(self): self.closed = True
            result = Response(); self.resources.append(result); return result
        connection.connect,connection.close,connection.request,connection.getresponse = connected,closed,requested,responded
        return connection


def session_for(tmp_path,peer,source,*,enabled=True):
    initial = source.prepare_plan()
    scope = JitScriptExecutionScope('1'*64,'2'*64,'3'*64,'4'*64,'a'*64,'b'*64,'c'*64)
    backend = WindowsJitScriptHttpBackend(source,execution_enabled=(lambda:True) if enabled else None,
        source_guard=lambda:True)
    session = WindowsJitScriptM4Session(source,initial,scope,backend,Evidence(peer.clock),store_at(tmp_path),
        source_guard=lambda:True,clock=peer.clock)
    return session,backend


def test_fixed_four_step_http_lifecycle_never_hashes_or_decodes_ack_revision(monkeypatch,tmp_path):
    peer = HttpPeer(); session,backend = session_for(tmp_path,peer,peer.source())
    decode,digest = json.loads,hashlib.sha256
    def checked_decode(raw,*args,**kwargs):
        assert PRIVATE not in (raw.encode() if isinstance(raw,str) else raw)
        return decode(raw,*args,**kwargs)
    def checked_digest(raw=b'',*args,**kwargs):
        assert PRIVATE not in raw
        return digest(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',checked_decode); monkeypatch.setattr(hashlib,'sha256',checked_digest)
    for index,remove in ((0,False),(1,False),(0,True),(1,True)):
        bound = bind(session,index,remove=remove)
        assert execute(bound).outcome == 'succeeded'
        assert execute(bound).idempotent_replay
    assert peer.writes == [('POST',0),('POST',1),('DELETE',0),('DELETE',1)]
    assert len(backend._attempted) == 4 and session._store.claim_count == 4
    assert all(not any(raw) for raw in peer.buffers) and all(resource.closed for resource in peer.resources)


@pytest.mark.parametrize('fault',['method','device','build','mkey','status','echo','extra','error'])
def test_wrong_or_echoing_ack_is_consumed_without_receipt_or_recovery(tmp_path,fault):
    peer = HttpPeer(); session,backend = session_for(tmp_path,peer,peer.source())
    bound = bind(session); peer.ack_fault = fault
    assert execute(bound).outcome == 'reconciliation_required'
    assert backend._acks == {} and peer.writes == [('POST',0)]
    assert execute(bound).idempotent_replay
    with pytest.raises(M4AdapterDenied): session.prepare_step(0,remove=True)
    assert all(not any(raw) for raw in peer.buffers) and all(resource.closed for resource in peer.resources)


def test_backend_is_independently_closed_and_rechecks_after_tls_before_egress(tmp_path):
    peer = HttpPeer(); session,backend = session_for(tmp_path,peer,peer.source(),enabled=False)
    assert execute(bind(session)).outcome != 'succeeded' and peer.writes == []
    assert backend._attempted == set()


@pytest.mark.parametrize('fault',['gate','namespace','deadline','cleanup'])
def test_tls_setup_drift_and_cleanup_failure_do_not_convey_success(tmp_path,fault):
    peer = HttpPeer(); source = peer.source(); session,backend = session_for(tmp_path,peer,source)
    bound = bind(session)
    writes_started = [False]
    original_factory = source._factory
    def factory(*args,**kwargs):
        connection = original_factory(*args,**kwargs)
        # Only this outer mutation connection triggers the fault. Inner fixed
        # reads in before_send retain the unchanged source factory.
        if not writes_started[0]:
            writes_started[0] = True; connected,closed = connection.connect,connection.close
            def connect():
                connected()
                if fault == 'gate': backend._enabled = lambda:False
                elif fault == 'namespace': peer.rows.append(dict(name='new-name')); peer.counts()
                elif fault == 'deadline': peer.time += 5
            def close():
                closed()
                if fault == 'cleanup' and peer.writes: raise RuntimeError('SYNTHETIC_PRIVATE_CLOSE')
            connection.connect,connection.close = connect,close
        return connection
    # The kernel's first current read happens before backend setup; arm the
    # wrapper only when the backend is entered, not at that first read.
    submit = backend.submit
    def armed(*args,**kwargs):
        source._factory = factory
        try: return submit(*args,**kwargs)
        finally: source._factory = original_factory
    backend.submit = armed
    assert execute(bound).outcome != 'succeeded'
    assert peer.writes == ([('POST',0)] if fault == 'cleanup' else [])
    assert backend._acks == {} and all(not any(raw) for raw in peer.buffers)


def test_attempted_http_slot_and_cleanup_are_not_reset_by_matching_visible_state(tmp_path):
    peer = HttpPeer(); source = peer.source(); _,backend = session_for(tmp_path,peer,source)
    body = bytearray(json.dumps(peer.expected[0],sort_keys=True,separators=(',',':')).encode())
    with memoryview(body).toreadonly() as view:
        assert backend.submit(view,index=0,remove=False,parameters_digest='1'*64,
            before_send=lambda:60,timeout_seconds=5).index == 0
        with pytest.raises(WindowsJitScriptHttpError):
            backend.submit(view,index=0,remove=False,parameters_digest='2'*64,before_send=lambda:60,timeout_seconds=5)
    assert peer.writes == [('POST',0)]


def test_real_loopback_https_m4_four_step_candidate_with_synthetic_eligibility(tmp_path):
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from fortipam_mcp.windows_jit_script_source import WindowsJitScriptSource
    from test_secret_bulk_import_action_process import tls_material
    from test_windows_jit_script_source import NONCE, SERIAL

    certificate,key = tls_material(tmp_path); peer = HttpPeer(); connections = []; buffers = []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self,*_): pass
        def send(self,payload):
            raw = json.dumps(payload).encode()
            self.send_response(payload['http_status']); self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw))); self.send_header('Connection','close')
            self.end_headers(); self.wfile.write(raw)
        def do_GET(self): self.send(peer.payloads[self.path])
        def do_POST(self):
            assert self.headers['Authorization'] == 'Bearer synthetic-api-token'
            body = self.rfile.read(int(self.headers['Content-Length']))
            if self.headers.get('X-HTTP-Method-Override') == 'GET':
                assert self.path == COLLECTION_PATH and body == b'{"json_filter":[]}'
                self.send(peer.payloads[self.path])
            else: self.send(peer.mutate('POST',self.path,body))
        def do_DELETE(self): self.send(peer.mutate('DELETE',self.path,None))
    server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(certificate,key)
    server.socket = tls.wrap_socket(server.socket,server_side=True)
    thread = Thread(target=server.serve_forever,daemon=True); thread.start()
    def factory(host,port,**kwargs):
        connection = http.client.HTTPSConnection(host,port,**kwargs)
        connection._create_connection = lambda address,timeout,source_address:socket.create_connection(
            ('127.0.0.1',server.server_port),timeout,source_address)
        connections.append(connection); return connection
    source = WindowsJitScriptSource(SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-api-token',5,str(certificate)),
        nonce=NONCE,expected_serial=SERIAL,expected_schema_digest=peer.pin,source_digest='a'*64,
        source_guard=lambda:True,connection_factory=factory,clock=peer.clock)
    receive = source._receive
    def tracked(*args,**kwargs):
        status,raw = receive(*args,**kwargs); buffers.append(raw); return status,raw
    source._receive = tracked
    try:
        session,backend = session_for(tmp_path,peer,source)
        for index,remove in ((0,False),(1,False),(1,True),(0,True)):
            assert execute(bind(session,index,remove=remove)).outcome == 'succeeded'
        assert peer.writes == [('POST',0),('POST',1),('DELETE',1),('DELETE',0)]
        assert session._store.claim_count == 4 and len(backend._acks) == 4
        assert all(connection.sock is None for connection in connections) and all(not any(raw) for raw in buffers)
    finally:
        source.close(); server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
