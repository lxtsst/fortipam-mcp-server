"""Fixed HTTP SAML candidate, exact M4 ownership and synthetic TLS/MCP."""
from dataclasses import replace
import json

import pytest

from fortipam_mcp.saml_server_contract import build_saml_create_body
from fortipam_mcp.saml_server_http_backend import SamlConfigurationHttpBackend
from fortipam_mcp.saml_server_local_m4 import SamlLocalM4Adapter
from fortipam_mcp.saml_server_native_source import BASE_PATH, COLLECTION_PATH
from test_saml_server_contract import created_record
from test_saml_server_local_m4 import make as m4_candidate, removal, SCOPE
from test_saml_server_native_source import Peer, Socket, envelope
from v4_planning import M4AdapterDenied, M4ExecutionKernel


class HttpPeer(Peer):
    def __init__(self):
        super().__init__()
        self.writes = []; self.write_buffers = []; self.write_fault = None; self.connects = 0; self.on_connect = None
    def apply(self, method, path, body):
        restore = method == 'DELETE'
        assert path == (BASE_PATH+'/'+self.plan.binding.name if restore else BASE_PATH)
        if restore:
            assert body is None
            self.payloads[COLLECTION_PATH]['results'] = [self.original]
            self.payloads[self.detail] = envelope(None,status=404)
        else:
            self.write_buffers.append(body); decoded = json.loads(body)
            assert len(decoded) == 18 and decoded['$originalName'] == ''
            candidate = created_record(self.original,self.defaults,self.plan)
            assert all(candidate[name] == value for name,value in decoded.items() if name != '$originalName')
            if self.write_fault == 'wrong-record': candidate['user-name'] = 'synthetic-wrong-attribute'
            if self.write_fault == 'referenced': candidate['q_ref'] = 1
            self.payloads[COLLECTION_PATH]['results'].append(candidate)
            self.payloads[self.detail] = envelope(candidate)
        self.writes.append((method,path)); self.dependencies.references += -1 if restore else 1
        count = len(self.payloads[COLLECTION_PATH]['results']); self.payloads[COLLECTION_PATH].update(size=count,matched_count=count)
        ack = dict(http_method=method,http_status=200,status='success',serial='SYNTHETIC01',version='v7.0.0',build=29,
            path='user',name='saml',mkey=self.plan.binding.name)
        if self.write_fault == 'foreign-ack': ack['mkey'] = 'synthetic-other'
        if self.write_fault == 'wrong-method': ack['http_method'] = 'PUT'
        if self.write_fault == 'material-echo': ack['secret'] = 'SYNTHETIC_UNEXPECTED_MATERIAL'
        return ack
    def factory(self, host, port, **kwargs):
        peer = self
        class Connection:
            def __init__(self): self.sock = Socket(); self.closed = False; self.path = self.method = None; self.ack = None; peer.resources.append(self)
            def set_debuglevel(self, level): assert level == 0
            def connect(self):
                assert host == 'pam.example.test'; peer.connects += 1
                if peer.on_connect: peer.on_connect()
            def request(self, method, path, *, headers, body=None):
                assert headers['Authorization'] == 'Bearer synthetic-api-token'
                self.path,self.method = path,method
                if method == 'GET': peer.calls.append(path)
                else: self.ack = peer.apply(method,path,body)
            def getresponse(self):
                if self.method != 'GET' and peer.write_fault == 'lost-ack': raise ConnectionError('SYNTHETIC_PRIVATE_LOST_ACK')
                payload = peer.payloads[self.path] if self.method == 'GET' else self.ack
                return Response(json.dumps(payload).encode(),payload['http_status'],self.method != 'GET')
            def close(self):
                self.closed = True
                if self.method in ('POST','DELETE') and peer.write_fault == 'close': raise RuntimeError('SYNTHETIC_PRIVATE_CLOSE')
        class Response:
            def __init__(self, raw, status, write): self.raw,self.status,self.write = raw,status,write; self.offset = 0; self.closed = False; peer.resources.append(self)
            def getheader(self, name, default=None):
                return {'content-type':'application/json',
                    'content-length':str(len(self.raw)+(1 if self.write and peer.write_fault == 'truncated' else 0))}.get(name.lower(),default)
            def isclosed(self): return self.offset >= len(self.raw)
            def readinto(self, view):
                if not peer.buffers or peer.buffers[-1] is not view.obj: peer.buffers.append(view.obj)
                count = min(len(view),len(self.raw)-self.offset,113)
                view[:count] = self.raw[self.offset:self.offset+count]; self.offset += count
                if self.write and peer.write_fault == 'post-deadline': peer.time += 6
                return count
            def close(self): self.closed = True
        return Connection()


def make(root, *, enabled=True, guard=True, peer=None):
    value = m4_candidate(root,peer=peer if peer is not None else HttpPeer())
    backend = SamlConfigurationHttpBackend(value.source,value.initial,value.plan.parameters_digest,
        execution_enabled=enabled,source_guard=(lambda: True) if guard else None)
    value.backend = backend
    value.adapter = SamlLocalM4Adapter(value.initial,SCOPE,backend,value.plan,value.authorization,value.store,
        authorization_verifier=value.verifier,execution_enabled=True,source_guard=lambda: True,clock=value.peer.clock)
    value.kernel = M4ExecutionKernel(value.adapter,value.verifier,value.store,clock=value.peer.clock)
    return value


def test_fixed_post_and_owned_delete_use_original_m4_guards_and_restore_full_baseline(tmp_path):
    value = make(tmp_path)
    assert value.kernel.execute(value.plan,value.authorization).outcome == 'succeeded'
    assert value.kernel.execute(value.plan,value.authorization).idempotent_replay
    kernel,plan,authorization = removal(value)
    assert kernel.execute(plan,authorization).outcome == 'succeeded'
    assert kernel.execute(plan,authorization).idempotent_replay
    assert value.peer.writes == [('POST',BASE_PATH),('DELETE',BASE_PATH+'/'+value.initial.plan.binding.name)]
    assert value.source.read()._collection == value.initial._collection
    assert all(not any(raw) for raw in value.peer.buffers+value.peer.write_buffers)
    assert all(resource.closed for resource in value.peer.resources)
    value.backend.close()
    assert value.source.read()._candidate is None  # The backend borrows the source.


@pytest.mark.parametrize('fault', ['lost-ack','foreign-ack','wrong-method','material-echo','wrong-record','referenced','close','truncated','post-deadline'])
def test_uncertain_ack_or_full_readback_never_acquires_removal_rights(tmp_path, fault, monkeypatch):
    value = make(tmp_path); value.peer.write_fault = fault
    original_decode = json.loads
    def decode(raw,*args,**kwargs):
        marker = b'SYNTHETIC_UNEXPECTED_MATERIAL' if isinstance(raw,(bytes,bytearray)) else 'SYNTHETIC_UNEXPECTED_MATERIAL'
        assert marker not in raw
        return original_decode(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',decode)
    result = value.kernel.execute(value.plan,value.authorization)
    assert result.outcome != 'succeeded' and 'SYNTHETIC_PRIVATE' not in json.dumps(result.as_dict())
    assert value.kernel.execute(value.plan,value.authorization).idempotent_replay
    assert len(value.peer.writes) == value.store.claim_count == 1
    with pytest.raises(M4AdapterDenied): removal(value)
    assert all(not any(raw) for raw in value.peer.buffers+value.peer.write_buffers)


@pytest.mark.parametrize('options', [dict(enabled=False),dict(guard=False)])
def test_write_gates_close_before_write_tls_or_request(tmp_path, options):
    value = make(tmp_path,**options); before = value.peer.connects
    assert value.kernel.execute(value.plan,value.authorization).outcome != 'succeeded'
    assert value.peer.connects == before+4 and value.peer.writes == []


def test_foreign_source_snapshot_parameters_callback_and_body_cannot_dispatch(tmp_path):
    value = make(tmp_path); initial = value.initial
    with pytest.raises(ValueError): SamlConfigurationHttpBackend(value.source,replace(initial),value.plan.parameters_digest)
    plan = initial.plan; body = build_saml_create_body(plan,plan._source,plan._defaults,**plan._context)
    try:
        with memoryview(body).toreadonly() as view:
            for parameters,callback in (('f'*64,value.adapter._before_send),(value.plan.parameters_digest,lambda: 5)):
                with pytest.raises(ValueError): value.backend.submit(view,parameters_digest=parameters,restore=False,
                    before_send=callback,timeout_seconds=5)
        body[0] = 91
        with memoryview(body).toreadonly() as view:
            with pytest.raises(ValueError): value.backend.submit(view,parameters_digest=value.plan.parameters_digest,restore=False,
                before_send=value.adapter._before_send,timeout_seconds=5)
    finally: body[:] = b'\0'*len(body)
    assert value.peer.writes == [] and not value.backend._attempted


def test_nested_final_guard_is_capped_by_the_original_write_deadline(tmp_path):
    value = make(tmp_path)
    def cost():
        # Four startup reads, four kernel reads, then the write connection.
        if value.peer.connects >= 9: value.peer.time += 2
    value.peer.on_connect = cost
    assert value.kernel.execute(value.plan,value.authorization).outcome != 'succeeded'
    assert value.peer.writes == [] and value.backend._attempted == {False}
    # The outer write budget stops the nested read before its second GET,
    # rather than allowing a new five-second source-read window.
    assert len(value.peer.calls) == 9 and value.source._deadline_cap is None


def test_lost_delete_ack_stays_consumed_even_after_fixed_absence_read(tmp_path):
    value = make(tmp_path); assert value.kernel.execute(value.plan,value.authorization).outcome == 'succeeded'
    kernel,plan,authorization = removal(value); value.peer.write_fault = 'lost-ack'
    assert kernel.execute(plan,authorization).outcome != 'succeeded'
    assert value.source.read()._collection == value.initial._collection
    assert kernel.execute(plan,authorization).idempotent_replay and len(value.peer.writes) == value.store.claim_count == 2


def test_accepted_body_snapshot_is_not_replaced_by_a_later_borrowed_buffer_change(monkeypatch, tmp_path):
    value = make(tmp_path); buffers = []; original = value.backend._body
    def remember(body, restore):
        if body is not None: buffers.append(body.obj)
        return original(body,restore)
    monkeypatch.setattr(value.backend,'_body',remember)
    def change():
        if value.peer.connects == 9:
            for raw in buffers: raw[:] = b'\0'*len(raw)
    value.peer.on_connect = change
    assert value.kernel.execute(value.plan,value.authorization).outcome == 'succeeded'
    assert len(value.peer.writes) == 1 and all(not any(raw) for raw in buffers+value.peer.write_buffers)


@pytest.mark.parametrize('fault', [None,'create-lost-ack','delete-lost-ack'])
def test_real_loopback_https_unix_authority_and_normal_mcp_lifecycle(tmp_path, fault):
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from types import SimpleNamespace
    from starlette.testclient import TestClient
    from fortipam_mcp.http_server import create_http_app
    from fortipam_mcp.saml_server_native_source import SamlNativeSource
    from fortipam_mcp.saml_server_local_m4 import saml_execution_digests
    from fortipam_mcp.saml_server_local_mcp_action import SamlLocalMcpAction
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from test_saml_server_authority import construct, PURPOSES, ENVIRONMENT, SCOPE_REF
    from test_saml_server_local_mcp_action import bootstrap, rpc_phase, saml_unix_services
    from test_ldap_server_mcp_action import _call
    from test_secret_bulk_import_action_process import tls_material
    from fortipam_mcp.saml_idp_metadata_probe import SamlIdpMetadataProbe, SamlMetadataBinding
    from fortipam_mcp.saml_server_dependency_source import SamlDependencySource, CERTIFICATES_PATH
    from test_saml_idp_metadata_probe import signing_certificate, document
    from test_saml_server_dependency_source import dependency_payloads
    from xml.etree import ElementTree as ET

    certificate,key = tls_material(tmp_path); peer = HttpPeer(); observe = peer.dependencies.observe
    public_signing,signing_pin = signing_certificate()
    metadata_root = document(peer.original,public_signing); metadata_requests = []
    peer.payloads.update(dependency_payloads(peer.original,signing_pin))
    peer.dependencies.observe = lambda *args,**kwargs: replace(observe(*args,**kwargs),
        runtime_isolation_verified=True,independent_recovery_ready=True)
    if fault == 'create-lost-ack': peer.write_fault = 'lost-ack'
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self,*_): pass
        def send(self, payload):
            raw = json.dumps(payload).encode()
            self.send_response(payload['http_status']); self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw))); self.send_header('Connection','close')
            self.end_headers(); self.wfile.write(raw)
        def do_GET(self):
            if self.path == '/idp/metadata':
                assert 'Authorization' not in self.headers and 'Cookie' not in self.headers
                metadata_requests.append(self.path); raw = ET.tostring(metadata_root,encoding='utf-8')
                self.send_response(200); self.send_header('Content-Type','application/samlmetadata+xml')
                self.send_header('Content-Length',str(len(raw))); self.send_header('Connection','close')
                self.end_headers(); self.wfile.write(raw)
                return
            assert self.headers['Authorization'] == 'Bearer synthetic-api-token'
            if self.path == CERTIFICATES_PATH:
                peer.payloads[self.path]['results'][0]['q_ref'] = peer.dependencies.references
            peer.calls.append(self.path); self.send(peer.payloads[self.path])
        def write(self, method):
            assert self.headers['Authorization'] == 'Bearer synthetic-api-token'
            raw = bytearray(self.rfile.read(int(self.headers['Content-Length']))) if method == 'POST' else None
            try:
                ack = peer.apply(method,self.path,raw)
                if peer.write_fault == 'lost-ack': self.close_connection = True
                else: self.send(ack)
            finally:
                if raw is not None: raw[:] = b'\0'*len(raw)
        def do_POST(self): self.write('POST')
        def do_DELETE(self): self.write('DELETE')
    server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(certificate,key)
    server.socket = tls.wrap_socket(server.socket,server_side=True)
    thread = Thread(target=server.serve_forever,daemon=True); thread.start()
    connections = []; responses = []; source = backend = metadata_probe = dependency_source = None
    def factory(host,port,**kwargs):
        connection = http.client.HTTPSConnection(host,port,**kwargs)
        connection._create_connection = lambda address, timeout, source_address: socket.create_connection(
            ('127.0.0.1',server.server_port),timeout,source_address)
        connections.append(connection); return connection
    try:
        if fault is None:
            metadata_binding = SamlMetadataBinding(peer.original,metadata_url='https://pam.example.test/idp/metadata',
                signing_certificate_sha256=signing_pin)
            metadata_probe = SamlIdpMetadataProbe(metadata_binding,source_digest='c'*64,ca_file=str(certificate),enabled=True,
                source_guard=lambda: True,connection_factory=factory,clock=peer.clock)
            dependency_source = SamlDependencySource(
                SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-api-token',5,str(certificate)),
                peer.original,expected_serial='SYNTHETIC01',proxy_name='synthetic-proxy',source_digest='2'*64,
                metadata_source_digest='c'*64,metadata_probe=metadata_probe,source_guard=lambda: True,
                connection_factory=factory,clock=peer.clock)
            get_dependency = dependency_source._get
            def dependency_bytes(*args,**kwargs):
                raw = get_dependency(*args,**kwargs); responses.append(raw); return raw
            dependency_source._get = dependency_bytes
            def metadata_dependencies(record_digest, *, timeout_seconds):
                observed = dependency_source.observe(record_digest,timeout_seconds=timeout_seconds)
                # Only environment isolation/recovery remain synthetic. Fixed
                # configuration/certificate GETs and metadata parsing are real
                # producers connected to a synthetic HTTPS product peer.
                assert not observed.runtime_isolation_verified and not observed.independent_recovery_ready
                return replace(observed,runtime_isolation_verified=True,independent_recovery_ready=True)
            peer.dependencies.observe = metadata_dependencies
        source = SamlNativeSource(SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-api-token',5,str(certificate)),
            peer.plan.binding,expected_serial='SYNTHETIC01',source_digest='1'*64,dependency_source_digest='2'*64,
            dependencies=peer.dependencies,source_guard=lambda: True,connection_factory=factory,clock=peer.clock)
        receive = source._receive
        def received(*args,**kwargs):
            status,raw = receive(*args,**kwargs); responses.append(raw); return status,raw
        source._receive = received
        initial = source.read(); settings,headers,scope,transport = bootstrap(tmp_path)
        with saml_unix_services(tmp_path) as (reference,reference_client,store):
            parameters = saml_execution_digests(initial,scope,store)[2]
            backend = SamlConfigurationHttpBackend(source,initial,parameters,execution_enabled=True,source_guard=lambda: True)
            candidate = SimpleNamespace(initial=initial,peer=peer,source=source,backend=backend,store=store)
            value = construct(tmp_path,reference_client,candidate=candidate,scope=scope,transport=transport)
            reference.issue_many(tuple((value.policy.reference_for(phase,purpose),'saml_'+purpose)
                for phase in ('create','remove') for purpose in PURPOSES),requester_digest=scope.requester_digest,
                environment_ref=ENVIRONMENT,scope_ref=SCOPE_REF,expires_at=1120,now_epoch=1000)
            with TestClient(create_http_app(settings,v4_saml_local_candidate_action=SamlLocalMcpAction(value.workflow)),
                    base_url='https://mcp.example.com') as client:
                result,authorization = rpc_phase(client,headers,'create')
                assert not result['isError'] and (result['structuredContent']['outcome'] == 'succeeded') is (fault != 'create-lost-ack')
                assert len(peer.writes) == store.claim_count == 1
                metadata_reads_before_replay = len(metadata_requests)
                configuration_reads_before_replay = len(peer.calls)
                replay = _call(client,headers,'execute_v4_saml_local_create_700',
                    {'authorization_ref':authorization['structuredContent']['authorization_ref']})
                assert replay['structuredContent']['idempotent_replay'] and len(peer.writes) == 1
                assert len(metadata_requests) == metadata_reads_before_replay
                assert len(peer.calls) == configuration_reads_before_replay
                if fault == 'create-lost-ack':
                    assert _call(client,headers,'preview_v4_saml_local_remove_700',{})['isError']
                else:
                    if fault == 'delete-lost-ack': peer.write_fault = 'lost-ack'
                    result,authorization = rpc_phase(client,headers,'remove')
                    assert not result['isError'] and (result['structuredContent']['outcome'] == 'succeeded') is (fault is None)
                    replay = _call(client,headers,'execute_v4_saml_local_remove_700',
                        {'authorization_ref':authorization['structuredContent']['authorization_ref']})
                    assert replay['structuredContent']['idempotent_replay']
                    assert source.read()._collection == initial._collection
                outcome = _call(client,headers,'get_v4_saml_local_outcome_700',{})['structuredContent']
                assert outcome['workflow_outcome'] == ('verified_locally' if fault is None else 'reconciliation_required')
                assert outcome['native_backend_qualified'] is outcome['saml_login_verified'] is False
                assert len(peer.writes) == store.claim_count == (1 if fault == 'create-lost-ack' else 2)
                assert all(connection.sock is None for connection in connections)
                assert all(not any(raw) for raw in responses+peer.write_buffers)
                assert bool(metadata_requests) is (fault is None)
    finally:
        if dependency_source is not None: dependency_source.close()
        if metadata_probe is not None: metadata_probe.close()
        if backend is not None: backend.close()
        if source is not None: source.close()
        server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
