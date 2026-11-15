"""Fixed SCIM HTTP candidate through M4 and actual loopback TLS/OAuth/MCP."""
from dataclasses import replace
from contextlib import ExitStack
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import ssl
from threading import Thread

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.http_server import create_http_app
from fortipam_mcp.scim_client_central_lab_resolver import ScimCentralLabMaterialResolver
from fortipam_mcp.scim_client_http_backend import ScimConfigurationHttpBackend
from fortipam_mcp.scim_client_native_source import (ScimNativeSource, ScimTlsTrustProbe,
    DETAIL_PATH, CURRENT_PATH, GLOBAL_PATH)
from fortipam_mcp.scim_client_contract import prepare_scim_rotate, prepare_scim_disable, ScimNonmaterialState, build_scim_request_with_material
from fortipam_mcp.scim_client_local_mcp_action import ScimLocalMcpAction
from fortipam_mcp.scim_client_m4_adapter import ScimLocalM4Adapter, ScimExecutionEvidence, scim_execution_digests
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_scim_client_native_source import Peer
from test_scim_client_m4_adapter import SCOPE, stores, grant
from test_scim_client_material import Resolver
from test_scim_client_contract import OLD, NEW
from test_scim_client_authority import construct, PURPOSES, ENVIRONMENT, SCOPE_REF
from test_scim_client_central_lab_resolver import inputs as material_inputs, resolver as file_resolver, track_buffers
from test_scim_client_local_mcp_action import bootstrap, rpc_phase, scim_unix_services
from test_ldap_server_mcp_action import _call
from test_system_email_m4_adapter import Verifier
from test_secret_bulk_import_action_process import tls_material
from v4_planning import M4AdapterDenied, M4ExecutionKernel


class Evidence:
    """Independent fake authentication/effects; not a product qualification."""
    def __init__(self, peer, scope=SCOPE, bindings=None):
        self.peer, self.scope = peer, scope
        self.bindings = bindings if bindings is not None else {'synthetic-old-secret':OLD,'synthetic-new-secret':NEW}
    def observe(self, configuration_digest):
        binding = self.bindings.get(self.peer.material,'f'*64)
        now = self.peer.clock()
        return ScimExecutionEvidence(configuration_digest,self.scope.credential_source_digest,self.scope.effects_source_digest,
            binding,self.scope.effects_digest,0,True,True,now,now+10)


class TlsService:
    """Disposable SCIM listener, independent of the CMDB API listener."""
    def __init__(self, certificate, key):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); self.context.load_cert_chain(certificate,key)
        self.server = self.thread = None; self.port = 0; self.http_requests = 0
    def start(self):
        if self.server is not None: return
        service = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*_): pass
            def do_GET(self):
                service.http_requests += 1
                self.send_response(400); self.end_headers()
        server = ThreadingHTTPServer(('127.0.0.1',self.port),Handler)
        self.port = server.server_port
        server.socket = self.context.wrap_socket(server.socket,server_side=True)
        thread = Thread(target=server.serve_forever,daemon=True); thread.start()
        self.server,self.thread = server,thread
    def stop(self):
        if self.server is None: return
        server,thread = self.server,self.thread
        server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
        self.server = self.thread = None


def transition(source, operation='rotate', *, old_binding=OLD, new_binding=NEW):
    original = source.read()
    options = dict(context=json.loads(original.context),current_material_binding_digest=old_binding)
    if operation == 'rotate': return prepare_scim_rotate(original.state,replacement_material_binding_digest=new_binding,**options)
    return prepare_scim_disable(original.state,**options)


def make(root, operation='rotate', enabled=True, guard=True):
    peer = Peer(); source = peer.source(); change = transition(source,operation); store, material = stores(root)
    plan, authorization = grant(change,store,material); verifier = Verifier(plan,authorization)
    backend = ScimConfigurationHttpBackend(source,change,plan.parameters_digest,execution_enabled=enabled,
        source_guard=(lambda: True) if guard else None)
    resolver = Resolver(change._new_material_binding_digest,b'synthetic-new-secret' if operation == 'rotate' else b'synthetic-old-secret')
    recovery = Resolver(OLD,b'synthetic-old-secret')
    adapter = ScimLocalM4Adapter(change,backend,Evidence(peer),resolver,recovery,plan,authorization,store,material,
        scope=SCOPE,authorization_verifier=verifier,execution_enabled=True,source_guard=lambda: True,clock=peer.clock)
    kernel = M4ExecutionKernel(adapter,verifier,store,clock=peer.clock)
    return peer, source, change, store, material, backend, resolver, adapter, kernel, plan, authorization


@pytest.mark.parametrize('operation',['rotate','disable'])
def test_fixed_put_and_owned_ack_allow_only_original_independent_restore(tmp_path, operation):
    peer, source, change, store, material, backend, resolver, adapter, kernel, plan, authorization = make(tmp_path,operation)
    assert kernel.execute(plan,authorization).outcome == 'succeeded'
    restore_plan,restore_auth = grant(change,store,material,True); verifier = Verifier(restore_plan,restore_auth)
    restore = adapter.bind_restore(restore_plan,restore_auth,resolver=Resolver(OLD,b'synthetic-old-secret'),
        authorization_verifier=verifier,execution_enabled=True)
    assert M4ExecutionKernel(restore,verifier,store,clock=peer.clock).execute(restore_plan,restore_auth).outcome == 'succeeded'
    assert backend._acks == {False,True} and peer.puts == store.claim_count == material.claim_count == 2
    assert all(path == DETAIL_PATH for method,path in peer.calls if method == 'PUT')
    assert all(not any(buffer) for buffer in peer.buffers+peer.put_buffers+resolver.buffers)
    assert all(resource.closed for resource in peer.resources)
    backend.close()
    # The source is a borrowed input and remains usable by its other consumer.
    assert source.read().state._values() == change._original._values()


@pytest.mark.parametrize('fault',['write-timeout','wrong-material','omitted-drift','post-deadline','truncated','close',
    'ack-target','ack-method','ack-version','ack-error','ack-extra'])
def test_uncertain_ack_or_readback_has_no_restore_or_replay_rights(tmp_path, fault):
    peer, _, change, store, material, backend, resolver, adapter, kernel, plan, authorization = make(tmp_path)
    if fault.startswith('ack-'):
        key,value = {'ack-target':('mkey','synthetic-other'),'ack-method':('http_method','POST'),
            'ack-version':('build',30),'ack-error':('error',-1),'ack-extra':('secret','SYNTHETIC_C3_SENTINEL')}[fault]
        peer.ack[key] = value
    else: peer.fault = 'write-'+fault if fault in ('truncated','close') else fault
    result = kernel.execute(plan,authorization)
    assert result.outcome != 'succeeded'
    assert peer.puts == 1
    assert kernel.execute(plan,authorization).idempotent_replay
    assert all(not any(buffer) for buffer in peer.buffers+peer.put_buffers+resolver.buffers)
    if fault in ('wrong-material','omitted-drift'): assert backend._acks == {False}
    else: assert not backend._acks
    restore_plan,restore_auth = grant(change,store,material,True)
    with pytest.raises(M4AdapterDenied): adapter.bind_restore(restore_plan,restore_auth,resolver=Resolver(OLD))


@pytest.mark.parametrize('enabled,guard',[(False,True),(True,False)])
def test_backend_write_gates_close_before_egress(tmp_path, enabled, guard):
    peer, _, _, _, _, backend, resolver, _, kernel, plan, authorization = make(tmp_path,enabled=enabled,guard=guard)
    assert kernel.execute(plan,authorization).outcome != 'succeeded' and peer.puts == 0 and not backend._attempted
    assert all(not any(buffer) for buffer in resolver.buffers)


def test_foreign_source_join_parameters_and_restore_without_ack_cannot_send(tmp_path):
    peer, source, change, _, _, backend, _, _, _, plan, _ = make(tmp_path)
    with pytest.raises(ValueError): ScimConfigurationHttpBackend(source,
        replace(change,_original=ScimNonmaterialState.from_values(change._original._values())),plan.parameters_digest)
    material = bytearray(b'synthetic-old-secret')
    try:
        with memoryview(material) as view:
            body = build_scim_request_with_material(change,view,current=change._proposed,context=json.loads(change._context),
                material_binding_digest=OLD,restore=True)
        try:
            with memoryview(body) as view:
                with pytest.raises(ValueError): backend.submit(view,parameters_digest=plan.parameters_digest,
                    restore=True,before_send=lambda: 5,timeout_seconds=5)
                with pytest.raises(ValueError): backend.submit(view,parameters_digest='f'*64,
                    restore=False,before_send=lambda: 5,timeout_seconds=5)
        finally: body[:] = b'\0'*len(body)
    finally: material[:] = b'\0'*len(material)
    assert peer.puts == 0


def test_request_material_and_rejected_ack_echo_never_enter_json_scalar_decoding(monkeypatch, tmp_path):
    peer, _, _, _, _, backend, resolver, _, kernel, plan, authorization = make(tmp_path)
    resolver.material = b'SYNTHETIC_C3_SENTINEL'; peer.ack['secret'] = 'SYNTHETIC_C3_SENTINEL'
    original = json.loads
    def decode(raw,*args,**kwargs):
        marker = b'SYNTHETIC_C3_SENTINEL' if isinstance(raw,(bytes,bytearray)) else 'SYNTHETIC_C3_SENTINEL'
        assert marker not in raw
        return original(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',decode)
    assert kernel.execute(plan,authorization).outcome != 'succeeded'
    assert peer.puts == 1 and not backend._acks
    assert all(not any(buffer) for buffer in peer.buffers+peer.put_buffers+resolver.buffers)


@pytest.mark.parametrize('operation,fault',[('rotate','none'),('disable','none'),('rotate','lost-ack'),('rotate','wrong-material')])
def test_real_loopback_tls_probe_rest_and_protected_oauth_mcp(monkeypatch, tmp_path, operation, fault):
    paths = material_inputs(tmp_path); file_buffers = track_buffers(monkeypatch); loaded = []
    original_load = ScimCentralLabMaterialResolver.load_scim_material_once
    def load(value):
        buffer = original_load(value); loaded.append(buffer); return buffer
    monkeypatch.setattr(ScimCentralLabMaterialResolver,'load_scim_material_once',load)
    resolver = file_resolver(paths,'scim-new' if operation == 'rotate' else 'scim-old')
    recovery = file_resolver(paths,'scim-old')
    old_binding, new_binding = recovery.binding_digest, resolver.binding_digest
    if fault == 'wrong-material':
        paths[1].write_bytes(b'SCIM_OLD=synthetic-old-secret\nSCIM_NEW=synthetic-unexpected-secret\n')
        assert file_resolver(paths).binding_digest == new_binding
    certificate,key = tls_material(tmp_path); peer = Peer()
    service = TlsService(certificate,key); service.start()
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self,*_): pass
        def send(self,value):
            raw = json.dumps(value).encode(); self.send_response(200)
            self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(raw)))
            self.send_header('Connection','close'); self.end_headers(); self.wfile.write(raw)
        def do_GET(self):
            assert self.headers['Authorization'] == 'Bearer synthetic-api-token'
            self.send(peer.payloads[self.path])
        def do_PUT(self):
            assert self.path == DETAIL_PATH and self.headers['Authorization'] == 'Bearer synthetic-api-token'
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            assert set(body) == {'id','name','status','base-url','auth-method','secret','client-identity-check','certificate'}
            peer.material = body.pop('secret'); peer.payloads[CURRENT_PATH]['results'][0].update(body); peer.puts += 1
            if body['status'] == 'disable': service.stop()
            else: service.start()
            if fault == 'lost-ack': self.close_connection = True
            else: self.send(peer.ack)
    product = ThreadingHTTPServer(('127.0.0.1',0),Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(certificate,key)
    product.socket = tls.wrap_socket(product.socket,server_side=True)
    thread = Thread(target=product.serve_forever,daemon=True); thread.start()
    connections = []; services = ExitStack(); probe_attempts = []
    def factory(host,port,**kwargs):
        connection = http.client.HTTPSConnection(host,port,**kwargs)
        connection._create_connection = lambda address, timeout, source_address: socket.create_connection(('127.0.0.1',product.server_port),timeout,source_address)
        connections.append(connection); return connection
    def probe_connection(address,timeout):
        assert address == ('pam.example.test',service.port)
        probe_attempts.append(address)
        return socket.create_connection(('127.0.0.1',service.port),timeout)
    try:
        base_url = 'https://pam.example.test/api/v1/scim/v2'
        peer.payloads[CURRENT_PATH]['results'][0]['base-url'] = base_url
        peer.payloads[GLOBAL_PATH]['results']['scim-https-port'] = service.port
        fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate.read_text())).hexdigest()
        probe = ScimTlsTrustProbe(base_url,service.port,'synthetic-cert',ca_file=str(certificate),
            certificate_sha256=fingerprint,source_digest='a'*64,enabled=True,connection_factory=probe_connection,clock=peer.clock)
        config = SecretMetadataHttpTransportConfig('https://pam.example.test:'+str(product.server_port),'synthetic-api-token',5,str(certificate))
        source = ScimNativeSource(config,expected_serial='SYNTHETIC01',source_digest=SCOPE.configuration_source_digest,
            trust_source_digest='a'*64,trust_reader=probe,connection_factory=factory,clock=peer.clock)
        change = transition(source,operation,old_binding=old_binding,new_binding=new_binding)
        settings,headers,scope,transport = bootstrap(tmp_path)
        reference, reference_client, store, material = services.enter_context(scim_unix_services(tmp_path))
        parameters = scim_execution_digests(change,scope,store,material)[2]
        backend = ScimConfigurationHttpBackend(source,change,parameters,execution_enabled=True,source_guard=lambda: True)
        options = dict(operation=operation,scope=scope,transport=transport,opened=(store,material),change=change,
            backend=backend,evidence=Evidence(peer,scope,{'synthetic-old-secret':old_binding,'synthetic-new-secret':new_binding}),
            clock=peer.clock,resolver=resolver,recovery=recovery)
        value = construct(tmp_path,reference_client,**options)
        reference.issue_many(tuple((value.policy.reference_for(phase,purpose),'scim_'+purpose)
            for phase in ('apply','restore') for purpose in PURPOSES), requester_digest=scope.requester_digest,
            environment_ref=ENVIRONMENT,scope_ref=SCOPE_REF,expires_at=1120,now_epoch=1000)
        app = create_http_app(settings,v4_scim_local_candidate_action=ScimLocalMcpAction(value.workflow))
        with TestClient(app,base_url='https://mcp.example.com') as client:
            result, authorization = rpc_phase(client,headers,operation)
            assert not result['isError'] and (result['structuredContent']['outcome'] == 'succeeded') is (fault == 'none')
            assert resolver._attempted and not recovery._attempted and len(loaded) == peer.puts == 1
            replay = _call(client,headers,'execute_v4_scim_local_'+operation+'_700',
                {'authorization_ref':authorization['structuredContent']['authorization_ref']})
            assert not replay['isError'] and replay['structuredContent']['idempotent_replay']
            assert len(loaded) == peer.puts == 1
            if operation == 'disable':
                assert service.server is None and source._last_trust.active_tls_verified is False
                attempts_before = len(probe_attempts)
                assert source.read().state._values()['status'] == 'disable'
                assert len(probe_attempts) == attempts_before
            if fault == 'none': assert rpc_phase(client,headers,operation,True)[0]['structuredContent']['outcome'] == 'succeeded'
            else:
                result = _call(client,headers,'preview_v4_scim_local_rotate_restore_700',{})
                assert result['isError']
            outcome = _call(client,headers,'get_v4_scim_local_outcome_700',{})['structuredContent']
            assert outcome['native_backend_qualified'] is False
            assert outcome['workflow_outcome'] == ('verified_locally' if fault == 'none' else 'reconciliation_required')
            assert peer.puts == store.claim_count == material.claim_count == (2 if fault == 'none' else 1)
            assert all(connection.sock is None for connection in connections)
            assert len(loaded) == peer.puts and recovery._attempted is (fault == 'none')
            assert all(not any(buffer) for buffer in file_buffers+loaded)
            assert service.http_requests == 0
        # A mismatching pin fails even with a valid trusted TLS certificate.
        if operation == 'rotate' and fault == 'none':
            # Disabled probes and changed private selectors must not connect.
            attempts = []
            def no_connection(*args,**kwargs): attempts.append(True); raise AssertionError('Unexpected connection.')
            disabled = ScimTlsTrustProbe(base_url,service.port,'synthetic-cert',ca_file=str(certificate),
                certificate_sha256=fingerprint,source_digest='a'*64,connection_factory=no_connection)
            with pytest.raises(ValueError): disabled.observe(base_url,service.port,'synthetic-cert',timeout_seconds=2.0)
            bound = ScimTlsTrustProbe(base_url,service.port,'synthetic-cert',ca_file=str(certificate),
                certificate_sha256=fingerprint,source_digest='a'*64,enabled=True,connection_factory=no_connection)
            with pytest.raises(ValueError): bound.observe(base_url,service.port,'other-selector',timeout_seconds=2.0)
            inactive = bound.observe(base_url,service.port,'synthetic-cert',timeout_seconds=2.0,service_enabled=False)
            assert inactive.active_tls_verified is False
            assert attempts == []
            bad = ScimTlsTrustProbe(base_url,service.port,'synthetic-cert',ca_file=str(certificate),
                certificate_sha256='f'*64,source_digest='a'*64,enabled=True,connection_factory=probe_connection)
            with pytest.raises(ValueError): bad.observe(base_url,service.port,'synthetic-cert',timeout_seconds=2.0)
            # An enabled CMDB record with an unreachable listener is an error,
            # never evidence that the service is intentionally disabled.
            service.stop()
            with pytest.raises(ValueError): source.read()
            service.start()
    finally:
        product.shutdown(); product.server_close(); thread.join(timeout=2)
        service.stop()
        services.close()
        assert not thread.is_alive()
