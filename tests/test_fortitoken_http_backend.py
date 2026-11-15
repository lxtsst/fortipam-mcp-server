"""Fixed HTTP submission with synthetic product, material and qualifications."""
import json
from types import SimpleNamespace

import pytest

from fortipam_mcp.fortitoken_http_backend import FortitokenConfigurationHttpBackend, _candidate_ack
from fortipam_mcp.fortitoken_local_m4 import FortitokenLocalM4Adapter
from fortipam_mcp.fortitoken_user_contract import FortitokenUserPlan
from test_fortitoken_local_m4 import SCOPE, stores, grant, Evidence, restore
from test_fortitoken_material import Resolver
from test_fortitoken_user_contract import NAME, SERIAL, TOKEN
from test_fortitoken_user_postcondition import apply
from test_fortitoken_user_source import Peer as ReadPeer
from test_saml_server_native_source import Socket
from test_system_email_m4_adapter import Verifier
from v4_planning import M4AdapterDenied, M4ExecutionKernel

DETAIL = '/api/v2/cmdb/system/admin/'+NAME


def ack():
    return dict(http_method='PUT',http_status=200,status='success',serial=SERIAL,version='v7.0.0',build=29,
        path='system',name='admin',mkey=NAME,vdom='root',error=0,revision_changed=True,revision='synthetic-revision')


class Peer(ReadPeer):
    def __init__(self, operation='assign'):
        super().__init__(operation)
        self.writes = []; self.write_buffers = []; self.write_fault = None; self.connects = 0; self.on_connect = None
    def apply(self, method, path, body):
        assert method == 'PUT' and path == DETAIL
        self.write_buffers.append(body); apply(self,body); self.writes.append((method,path))
        if self.write_fault == 'wrong-token': self.user['fortitoken'] = 'SYNTHETIC_OTHER_TOKEN'
        if self.write_fault == 'omitted-field': self.user['two-factor-authentication'] = 'email'
        if self.write_fault == 'preservation': self.user['gui-custom-conf'] = 'enable'
        value = ack()
        if self.write_fault == 'foreign-ack': value['mkey'] = 'synthetic-other'
        if self.write_fault == 'wrong-method': value['http_method'] = 'POST'
        if self.write_fault == 'material-echo': value['fortitoken'] = 'SYNTHETIC_UNEXPECTED_MATERIAL'
        if self.write_fault == 'oversize': value['revision'] = 'x'*16385
        return value
    def factory(self, host, port, **kwargs):
        peer = self
        class Connection:
            def __init__(self):
                self.sock = Socket(); self.closed = False; self.path = self.method = self.ack = None; peer.resources.append(self)
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
                if self.method == 'PUT' and peer.write_fault == 'lost-ack': raise ConnectionError('SYNTHETIC_PRIVATE_ACK_LOSS')
                payload = peer.payloads[self.path] if self.method == 'GET' else self.ack
                return Response(json.dumps(payload).encode(),payload['http_status'],self.method == 'PUT')
            def close(self):
                self.closed = True
                if self.method == 'PUT' and peer.write_fault == 'close': raise RuntimeError('SYNTHETIC_PRIVATE_CLOSE')
        class Response:
            def __init__(self, raw, status, write):
                self.raw,self.status,self.write = raw,status,write; self.offset = 0; self.closed = False; peer.resources.append(self)
            def getheader(self, name, default=None):
                return {'content-type':'text/html' if self.write and peer.write_fault == 'html' else 'application/json',
                    'content-length':str(len(self.raw)+(1 if self.write and peer.write_fault == 'truncated' else 0))}.get(name.lower(),default)
            def isclosed(self): return self.offset >= len(self.raw)
            def readinto(self, view):
                if not peer.buffers or peer.buffers[-1] is not view.obj: peer.buffers.append(view.obj)
                count = min(len(view),len(self.raw)-self.offset,113)
                view[:count] = self.raw[self.offset:self.offset+count]; self.offset += count
                if self.write and peer.write_fault == 'post-deadline': peer.time += 6
                return count
            def close(self):
                self.closed = True
                if self.write and peer.write_fault == 'response-close': raise RuntimeError('SYNTHETIC_PRIVATE_CLOSE')
        return Connection()


def make(root, operation='assign', *, enabled=True, guard=True):
    peer = Peer(operation); source = peer.reader(); intent = FortitokenUserPlan(source.read().state,operation)
    execution,material = stores(root); plan,authorization = grant(intent,execution,material)
    backend = FortitokenConfigurationHttpBackend(source,intent,plan.parameters_digest,
        execution_enabled=enabled,source_guard=(lambda:True) if guard else None)
    evidence = Evidence(peer); resolver,recovery = Resolver(),Resolver(); verifier = Verifier(plan,authorization)
    adapter = FortitokenLocalM4Adapter(intent,source,backend,evidence,resolver,recovery,plan,authorization,execution,material,
        scope=SCOPE,authorization_verifier=verifier,execution_enabled=True,source_guard=lambda:True,clock=peer.clock)
    return SimpleNamespace(peer=peer,source=source,intent=intent,execution=execution,material=material,plan=plan,
        authorization=authorization,backend=backend,evidence=evidence,resolver=resolver,recovery=recovery,verifier=verifier,
        adapter=adapter,kernel=M4ExecutionKernel(adapter,verifier,execution,clock=peer.clock))


@pytest.mark.parametrize('operation', ['assign','revoke'])
def test_fixed_put_and_independent_restore_preserve_full_original_once(tmp_path,operation):
    value = make(tmp_path,operation); original = value.intent.current.digest
    assert value.kernel.execute(value.plan,value.authorization).outcome == 'succeeded'
    assert value.kernel.execute(value.plan,value.authorization).idempotent_replay
    value.peer.clock.value = 1100
    kernel,plan,authorization,resolver = restore(value,issued_at=1100)
    assert kernel.execute(plan,authorization).outcome == 'succeeded'
    assert kernel.execute(plan,authorization).idempotent_replay
    assert value.source.read().state.digest == original
    assert value.peer.writes == [('PUT',DETAIL)]*2
    assert value.execution.claim_count == value.material.claim_count == 2 and resolver.loads == 1
    assert all(not any(raw) for raw in value.peer.buffers+value.peer.write_buffers+value.resolver.buffers+resolver.buffers)
    assert all(resource.closed for resource in value.peer.resources)
    value.backend.close(); assert value.source.read().state.digest == original


@pytest.mark.parametrize('fault', ['lost-ack','foreign-ack','wrong-method','material-echo','wrong-token',
    'omitted-field','preservation','close','response-close','truncated','html','oversize','post-deadline'])
def test_uncertain_put_is_consumed_and_cannot_restore_or_resubmit(tmp_path,fault):
    value = make(tmp_path); value.peer.write_fault = fault
    assert value.kernel.execute(value.plan,value.authorization).outcome != 'succeeded'
    assert value.kernel.execute(value.plan,value.authorization).idempotent_replay
    assert len(value.peer.writes) == value.execution.claim_count == value.material.claim_count == value.resolver.loads == 1
    with pytest.raises(M4AdapterDenied): restore(value)
    assert all(not any(raw) for raw in value.peer.buffers+value.peer.write_buffers+value.resolver.buffers)
    assert all(resource.closed for resource in value.peer.resources)


@pytest.mark.parametrize('options', [dict(enabled=False),dict(guard=False)])
def test_default_closed_backend_never_connects_for_a_write(tmp_path,options):
    value = make(tmp_path,**options)
    assert value.kernel.execute(value.plan,value.authorization).outcome != 'succeeded'
    assert value.peer.writes == [] and value.backend._attempted == set()


@pytest.mark.parametrize('fault', ['drift','revoked','epoch','gate','tls'])
def test_final_bound_guard_rejects_changed_state_or_authority_before_send(tmp_path,fault):
    value = make(tmp_path)
    def change():
        if value.peer.connects != 7: return
        if fault == 'drift': value.peer.user['comments'] = 'changed'
        elif fault == 'revoked': value.verifier.pair = (None,None)
        elif fault == 'epoch': value.peer.clock.value = 1060
        elif fault == 'gate': value.backend._enabled = False
        else: value.source._tls.check_hostname = False
    value.peer.on_connect = change
    assert value.kernel.execute(value.plan,value.authorization).outcome != 'succeeded'
    assert value.peer.writes == [] and value.backend._attempted == {False}
    assert value.source._deadline_cap is None


def test_outer_put_deadline_caps_nested_read_and_clears_all_owned_buffers(tmp_path):
    value = make(tmp_path)
    def cost():
        if value.peer.connects >= 7: value.peer.time += 2
    value.peer.on_connect = cost
    assert value.kernel.execute(value.plan,value.authorization).outcome != 'succeeded'
    assert value.peer.writes == [] and value.backend._attempted == {False}
    assert len(value.peer.calls) == 7 and value.source._deadline_cap is None
    assert all(not any(raw) for raw in value.peer.buffers+value.peer.write_buffers+value.resolver.buffers)


@pytest.mark.parametrize('fault', ['extra','preservation','username','token','password','trailing','writable'])
def test_exact_private_body_rejected_before_connection(tmp_path,monkeypatch,fault):
    value = make(tmp_path); compile_body = value.source.compile_body; captured = []
    def changed(*args,**kwargs):
        raw = compile_body(*args,**kwargs)
        if fault == 'trailing': raw.extend(b' {}')
        elif fault != 'writable':
            body = json.loads(raw)
            if fault == 'extra': body['extra'] = False
            elif fault == 'preservation': body['comments'] = 'changed'
            elif fault == 'username': body['$originalName'] = 'synthetic-other'
            elif fault == 'token': body['fortitoken'] = 'bad token'
            else: body['password'] = 'SYNTHETIC_FORBIDDEN_PASSWORD'
            raw[:] = json.dumps(body,sort_keys=True,separators=(',',':')).encode()
        captured.append(raw); return raw
    monkeypatch.setattr(value.source,'compile_body',changed)
    if fault == 'writable':
        method = value.backend.submit
        def writable(body,**kwargs):
            with memoryview(body.obj) as view: return method(view,**kwargs)
        monkeypatch.setattr(value.backend,'submit',writable)
    assert value.kernel.execute(value.plan,value.authorization).outcome != 'succeeded'
    assert value.peer.writes == [] and value.peer.connects == 6 and value.backend._attempted == set()
    assert all(not any(raw) for raw in captured+value.peer.buffers+value.resolver.buffers)


def test_accepted_owned_body_survives_borrowed_buffer_change_without_decoding_selector(tmp_path,monkeypatch):
    value = make(tmp_path); captured = []; original_body = value.backend._body
    def remember(body,intent): captured.append(body.obj); return original_body(body,intent)
    monkeypatch.setattr(value.backend,'_body',remember)
    decode = json.loads
    def no_material(raw,*args,**kwargs):
        # The synthetic product alone is allowed to inspect its private request.
        if not any(raw is buffer for buffer in value.peer.write_buffers):
            assert TOKEN not in (raw.encode() if isinstance(raw,str) else raw)
        return decode(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',no_material)
    def change():
        if value.peer.connects == 7:
            for raw in captured: raw[:] = b'\0'*len(raw)
    value.peer.on_connect = change
    assert value.kernel.execute(value.plan,value.authorization).outcome == 'succeeded'
    assert len(value.peer.writes) == 1 and all(not any(raw) for raw in captured+value.peer.write_buffers)


def test_plain_callback_cannot_supply_original_kernel_dispatch_authority(tmp_path):
    value = make(tmp_path)
    with memoryview(TOKEN) as token: body = value.source.compile_body(value.intent,token_reference_digest='a'*64,token=token)
    count = value.peer.connects
    try:
        with memoryview(body).toreadonly() as view:
            for guard in (lambda:60,value.adapter._before_send):
                with pytest.raises(ValueError,match='unavailable'):
                    value.backend.submit(view,parameters_digest=value.plan.parameters_digest,restore=False,before_send=guard,timeout_seconds=5)
    finally: body[:] = b'\0'*len(body)
    assert value.peer.writes == []
    # A real method without a kernel claim reaches TLS, then fails ownership.
    assert value.peer.connects == count+1 and value.backend._attempted == {False}


@pytest.mark.parametrize('field,bad', [('http_method','POST'),('http_status',201),('status','error'),('serial','OTHER'),
    ('version','v1.9.1'),('build',True),('path','user'),('name','fortitoken'),('mkey','OTHER'),('vdom','other'),
    ('revision_changed',False),('error',False),('revision',''),('fortitoken','SYNTHETIC_PRIVATE_ECHO')])
def test_candidate_ack_requires_exact_bounded_native_envelope(field,bad):
    payload = ack(); payload[field] = bad; raw = bytearray(json.dumps(payload).encode())
    with pytest.raises(ValueError): _candidate_ack(raw,SERIAL,NAME)


def test_lost_restore_ack_stays_consumed_even_when_original_state_is_later_equal(tmp_path):
    value = make(tmp_path); assert value.kernel.execute(value.plan,value.authorization).outcome == 'succeeded'
    kernel,plan,authorization,resolver = restore(value); value.peer.write_fault = 'lost-ack'
    assert kernel.execute(plan,authorization).outcome != 'succeeded'
    assert value.source.read().state.digest == value.intent.current.digest
    assert kernel.execute(plan,authorization).idempotent_replay
    assert len(value.peer.writes) == value.execution.claim_count == value.material.claim_count == 2


@pytest.mark.parametrize('operation,fault', [('assign',None),('revoke',None),('assign','apply-lost-ack'),('revoke','restore-lost-ack')])
def test_real_loopback_https_put_unix_authority_dual_cas_and_normal_mcp(tmp_path,operation,fault):
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from starlette.testclient import TestClient
    from fortipam_mcp.fortitoken_user_source import FortitokenUserSource, SCHEMA_PATH
    from fortipam_mcp.fortitoken_local_mcp_action import FortitokenLocalMcpAction
    from fortipam_mcp.http_server import create_http_app
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from test_fortitoken_user_contract import binding
    from test_fortitoken_authority import construct, PURPOSES, ENVIRONMENT, SCOPE_REF
    from test_fortitoken_local_mcp_action import bootstrap, rpc_phase, unix_services
    from test_ldap_server_mcp_action import _call
    from test_secret_bulk_import_action_process import tls_material

    certificate,key = tls_material(tmp_path); peer = Peer(operation); requests = []; connections = []; buffers = []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self,*_): pass
        def send(self, payload):
            raw = json.dumps(payload).encode()
            self.send_response(200); self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw))); self.send_header('Connection','close')
            self.end_headers(); self.wfile.write(raw)
        def do_GET(self):
            assert self.path in (SCHEMA_PATH,peer.detail) and self.headers['Authorization'] == 'Bearer synthetic-api-token'
            requests.append(('GET',self.path)); self.send(peer.payloads[self.path])
        def do_PUT(self):
            assert self.path == DETAIL and self.headers['Authorization'] == 'Bearer synthetic-api-token'
            requests.append(('PUT',self.path)); raw = bytearray(self.rfile.read(int(self.headers['Content-Length'])))
            try:
                payload = peer.apply('PUT',self.path,raw)
                if peer.write_fault == 'lost-ack': self.close_connection = True
                else: self.send(payload)
            finally: raw[:] = b'\0'*len(raw)
        def do_POST(self): requests.append(('POST',self.path)); self.send_error(405)
        def do_DELETE(self): requests.append(('DELETE',self.path)); self.send_error(405)
    server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(certificate,key)
    server.socket = tls.wrap_socket(server.socket,server_side=True)
    thread = Thread(target=server.serve_forever,daemon=True); thread.start()
    def factory(host,port,**kwargs):
        connection = http.client.HTTPSConnection(host,port,**kwargs)
        connection._create_connection = lambda address,timeout,source_address:socket.create_connection(
            ('127.0.0.1',server.server_port),timeout,source_address)
        connections.append(connection); return connection
    source = FortitokenUserSource(SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-api-token',5,str(certificate)),
        binding(),expected_serial=SERIAL,expected_schema_digest=peer.schema_pin,source_digest='c'*64,
        source_guard=lambda:True,connection_factory=factory,clock=peer.clock)
    receive = source._receive
    def tracked(*args,**kwargs):
        raw = receive(*args,**kwargs); buffers.append(raw); return raw
    source._receive = tracked
    try:
        settings,headers,scope,transport = bootstrap(tmp_path)
        with unix_services(tmp_path) as (reference,client,store,material):
            value = construct(tmp_path,client,operation=operation,scope=scope,transport=transport,
                opened=(store,material),peer=peer,source=source,
                backend_factory=lambda *args:FortitokenConfigurationHttpBackend(*args,execution_enabled=True,source_guard=lambda:True))
            reference.issue_many(tuple((value.policy.reference_for(phase,purpose),'fortitoken_'+purpose)
                for phase in ('apply','restore') for purpose in PURPOSES),requester_digest=scope.requester_digest,
                environment_ref=ENVIRONMENT,scope_ref=SCOPE_REF,expires_at=1120,now_epoch=1000)
            if fault == 'apply-lost-ack': peer.write_fault = 'lost-ack'
            with TestClient(create_http_app(settings,v4_fortitoken_local_candidate_action=FortitokenLocalMcpAction(value.workflow)),
                    base_url='https://mcp.example.com') as mcp:
                result,authorization = rpc_phase(mcp,headers,'apply')
                assert (result['structuredContent']['outcome'] == 'succeeded') is (fault != 'apply-lost-ack')
                count = len(requests); loads = value.resolver.loads
                cached = _call(mcp,headers,'execute_v4_fortitoken_local_apply_700',
                    {'authorization_ref':authorization['structuredContent']['authorization_ref']})
                assert cached['structuredContent']['idempotent_replay'] and len(requests) == count and value.resolver.loads == loads == 1
                if fault != 'apply-lost-ack':
                    if fault == 'restore-lost-ack': peer.write_fault = 'lost-ack'
                    restored,authorization = rpc_phase(mcp,headers,'restore')
                    assert (restored['structuredContent']['outcome'] == 'succeeded') is (fault is None)
                    count = len(requests)
                    assert _call(mcp,headers,'execute_v4_fortitoken_local_restore_700',
                        {'authorization_ref':authorization['structuredContent']['authorization_ref']})['structuredContent']['idempotent_replay']
                    assert len(requests) == count and source.read().state.digest == value.intent.current.digest
                else: assert _call(mcp,headers,'preview_v4_fortitoken_local_restore_700',{})['isError']
                outcome = _call(mcp,headers,'get_v4_fortitoken_local_outcome_700',{})['structuredContent']
                assert outcome['workflow_outcome'] == ('verified_locally' if fault is None else 'reconciliation_required')
                assert not outcome['native_backend_qualified'] and not outcome['mfa_login_verified']
                assert len(peer.writes) == store.claim_count == material.claim_count == (1 if fault == 'apply-lost-ack' else 2)
                assert all(method in ('GET','PUT') for method,path in requests)
                assert all(connection.sock is None for connection in connections)
                assert all(not any(raw) for raw in buffers+peer.write_buffers+value.resolver.buffers+value.recovery.buffers)
                public = json.dumps((result,cached,outcome))
                assert NAME not in public and TOKEN.decode('ascii') not in public
    finally:
        source.close(); server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
