"""Fixed local Secret PUT and restore; all eligibility/material proof is synthetic."""
import hashlib
import json

import pytest

from fortipam_mcp.windows_jit_script_m4 import JitScriptExecutionScope, WindowsJitScriptM4Session
from fortipam_mcp.windows_jit_secret_contract import _schema, _types
from fortipam_mcp.windows_jit_secret_http_backend import WindowsJitSecretHttpBackend, WindowsJitSecretHttpError
from fortipam_mcp.windows_jit_secret_m4 import JitSecretExecutionScope, WindowsJitSecretM4Session
from fortipam_mcp.windows_jit_secret_source import WindowsJitSecretSource, SCHEMA_PATH
from test_system_email_m4_adapter import store_at
from test_windows_jit_script_http_backend import HttpPeer
from test_windows_jit_script_m4 import Backend as ScriptBackend, Evidence as ScriptEvidence, bind as bind_script, execute
from test_windows_jit_secret_contract import fixture, binding, envelope, SERIAL, SECRET
from test_windows_jit_secret_m4 import Backend as SecretBackend, Evidence, bind
from v4_planning import M4AdapterDenied, canonical_digest


class SecretHttpPeer(HttpPeer):
    def __init__(self):
        super().__init__(); schema,self.secret_row = fixture(); self.payloads[SCHEMA_PATH] = schema
        self.secret_path = '/api/v2/cmdb/secret/database/17?with_meta=true&vdom=root'
        self.payloads[self.secret_path] = envelope(self.secret_row)
        self.secret_writes = []; self.secret_fault = None; self.on_write = lambda:None
    def mutate_secret(self,path,body):
        assert path == self.secret_path
        patch = json.loads(bytes(body)); restore = patch['checkout'] == 'disable'
        backend = SecretBackend(self,self.secret_row)
        backend.submit(memoryview(bytearray(body)).toreadonly(),restore=restore,parameters_digest='1'*64,
            before_send=lambda:60,timeout_seconds=5)
        self.secret_writes.append(restore); self.on_write()
        ack = envelope(None); ack.update(http_method='PUT',revision=SECRET,revision_changed=True)
        if self.secret_fault == 'echo': ack['results'] = dict(password=SECRET)
        elif self.secret_fault == 'mkey': ack['mkey'] = '17'
        elif self.secret_fault == 'status': ack['status'] = 'success'
        elif self.secret_fault == 'method': ack['http_method'] = 'POST'
        elif self.secret_fault == 'extra': ack['password'] = SECRET
        return ack
    def factory(self,*args,**kwargs):
        connection = super().factory(*args,**kwargs); request = connection.request
        def requested(method,path,*,body=None,headers):
            if method == 'PUT':
                assert headers['Authorization'] == 'Bearer synthetic-api-token'
                assert 'X-HTTP-Method-Override' not in headers
                connection.write_ack = self.mutate_secret(path,body)
            else: request(method,path,body=body,headers=headers)
        connection.request = requested; return connection


def candidate(tmp_path,peer=None,source=None):
    peer = peer or SecretHttpPeer(); source = source or peer.source()
    scripts = WindowsJitScriptM4Session(source,source.prepare_plan(),
        JitScriptExecutionScope('1'*64,'2'*64,'3'*64,'4'*64,'a'*64,'b'*64,'c'*64),
        ScriptBackend(peer),ScriptEvidence(peer.clock),store_at(tmp_path),source_guard=lambda:True,clock=peer.clock)
    for index in (0,1): assert execute(bind_script(scripts,index)).outcome == 'succeeded'
    schema = peer.payloads[SCHEMA_PATH]
    secret = WindowsJitSecretSource(source,binding(),expected_schema_digest=canonical_digest(_types(_schema(schema,SERIAL))),
        source_digest='b'*64,source_guard=lambda:True)
    plan = secret.prepare_plan()
    backend = WindowsJitSecretHttpBackend(secret,plan,execution_enabled=lambda:True,source_guard=lambda:True)
    evidence = Evidence(peer.clock); (tmp_path/'secret').mkdir(mode=0o700)
    session = WindowsJitSecretM4Session(secret,plan,scripts,
        JitSecretExecutionScope('3'*64,'4'*64,'5'*64,'6'*64,'b'*64,'d'*64,'e'*64,'f'*64,'1'*64),
        backend,evidence,store_at(tmp_path/'secret'),source_guard=lambda:True)
    return session,peer,backend,evidence


def test_fixed_control_only_put_and_independent_restore_keep_original_metadata_and_material_opaque(monkeypatch,tmp_path):
    session,peer,backend,_ = candidate(tmp_path); decode,digest = json.loads,hashlib.sha256
    def checked_decode(raw,*args,**kwargs):
        assert SECRET.encode() not in (raw.encode() if isinstance(raw,str) else raw)
        return decode(raw,*args,**kwargs)
    def checked_digest(raw=b'',*args,**kwargs):
        assert SECRET.encode() not in raw
        return digest(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',checked_decode); monkeypatch.setattr(hashlib,'sha256',checked_digest)
    for restore in (False,True):
        bound = bind(session,restore=restore); assert execute(bound).outcome == 'succeeded'
        assert execute(bound).idempotent_replay
    assert peer.secret_writes == [False,True] and backend._attempted == {False,True}
    assert session._source.read().secret.digest == session._initial.baseline.digest
    assert all(not any(raw) for raw in peer.buffers) and all(resource.closed for resource in peer.resources)


@pytest.mark.parametrize('fault',['echo','mkey','status','method','extra'])
def test_ack_echo_or_wrong_secret_identity_and_status_never_provide_a_restore_receipt(tmp_path,fault):
    session,peer,backend,_ = candidate(tmp_path); peer.secret_fault = fault; bound = bind(session)
    assert execute(bound).outcome == 'reconciliation_required' and backend._acks == {}
    assert peer.secret_writes == [False] and execute(bound).idempotent_replay
    with pytest.raises(M4AdapterDenied): session.prepare_step(restore=True)
    assert all(not any(raw) for raw in peer.buffers)


def test_unchanged_redacted_metadata_cannot_mask_failed_post_update_material_continuity(tmp_path):
    session,peer,backend,evidence = candidate(tmp_path)
    def changed():
        peer.secret_row['field'][1]['value'] = 'SYNTHETIC_CHANGED_MATERIAL'
        evidence.fault = 'material_preservation_digest'
    peer.on_write = changed; bound = bind(session)
    assert execute(bound).outcome == 'reconciliation_required'
    assert session._source.read().secret.digest == session._initial.expected().digest
    assert False in backend._acks
    with pytest.raises(M4AdapterDenied): session.prepare_step(restore=True)


def test_local_backend_default_gate_denies_before_connection_or_write(tmp_path):
    session,peer,_,_ = candidate(tmp_path)
    backend = WindowsJitSecretHttpBackend(session._source,session._initial)
    body = bytearray(json.dumps(session._initial.compile_metadata_patch(session._initial.baseline)).encode())
    before = len(peer.calls)
    with memoryview(body).toreadonly() as view:
        with pytest.raises(WindowsJitSecretHttpError):
            backend.submit(view,restore=False,parameters_digest='1'*64,before_send=lambda:60,timeout_seconds=5)
    assert peer.secret_writes == [] and len(peer.calls) == before and backend._attempted == set()


def test_post_tls_authority_loss_blocks_the_fixed_put_and_consumes_the_claim(tmp_path):
    session,peer,backend,_ = candidate(tmp_path); bound = bind(session)
    submit = backend.submit
    def armed(*args,**kwargs):
        peer.on_connect = lambda:setattr(backend,'_guard',None)
        try: return submit(*args,**kwargs)
        finally: peer.on_connect = lambda:None
    backend.submit = armed
    assert execute(bound).outcome == 'reconciliation_required' and peer.secret_writes == []
    assert backend._attempted == {False} and execute(bound).idempotent_replay


def test_real_loopback_https_secret_configure_restore_with_synthetic_independent_material_proof(tmp_path):
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from fortipam_mcp.windows_jit_script_source import WindowsJitScriptSource, COLLECTION_PATH
    from test_secret_bulk_import_action_process import tls_material
    from test_windows_jit_script_source import NONCE

    certificate,key = tls_material(tmp_path); peer = SecretHttpPeer(); connections = []; buffers = []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self,*_): pass
        def send(self,payload):
            raw = json.dumps(payload).encode()
            self.send_response(payload['http_status']); self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw))); self.send_header('Connection','close')
            self.end_headers(); self.wfile.write(raw)
        def do_GET(self):
            assert self.headers['Authorization'] == 'Bearer synthetic-api-token'
            self.send(peer.payloads[self.path])
        def do_POST(self):
            assert self.path == COLLECTION_PATH and self.headers['X-HTTP-Method-Override'] == 'GET'
            assert self.rfile.read(int(self.headers['Content-Length'])) == b'{"json_filter":[]}'
            self.send(peer.payloads[self.path])
        def do_PUT(self):
            assert self.headers['Authorization'] == 'Bearer synthetic-api-token'
            self.send(peer.mutate_secret(self.path,self.rfile.read(int(self.headers['Content-Length']))))
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
        session,_,backend,_ = candidate(tmp_path,peer,source)
        for restore in (False,True): assert execute(bind(session,restore=restore)).outcome == 'succeeded'
        assert peer.secret_writes == [False,True] and len(backend._acks) == 2
        assert session._store.claim_count == 2 and session._scripts._store.claim_count == 2
        assert all(connection.sock is None for connection in connections) and all(not any(raw) for raw in buffers)
    finally:
        source.close(); server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
