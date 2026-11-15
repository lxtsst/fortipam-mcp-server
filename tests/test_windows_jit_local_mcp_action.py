"""Normal controlled OAuth/MCP with fixed JIT phases and protected local services."""
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from pathlib import Path
import json
import tempfile

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.http_server import create_http_app, HttpConfigurationError
from fortipam_mcp.m4_checkpoint_client import UnixM4ExecutionCheckpoint
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.planning_checkpoint_sidecar import UnixPlanningCheckpointClient, UnixPlanningCheckpointClientSettings, create_checkpoint_sidecar_app
from fortipam_mcp.reference_authority_sidecar import UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings, create_reference_authority_sidecar_app
from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp.windows_jit_local_mcp_action import WindowsJitLocalMcpAction
from fortipam_mcp.windows_jit_local_workflow import PHASES
from test_fortitoken_local_mcp_action import bootstrap
from test_ldap_server_mcp_action import _call, _login
from test_system_email_authority import owner_file, unix_app
from test_system_email_m4_adapter import Clock
from test_windows_jit_authority import make, construct, PURPOSES, REFERENCE, ENVIRONMENT, SCOPE_REF
from test_windows_jit_secret_contract import SECRET
from test_windows_jit_script_source import NONCE, SERIAL, PRIVATE
from v4_planning import PersistentReferenceAuthority, PersistentReferenceCheckpointAuthority, PersistentPlanningCheckpointAuthority


def rpc_phase(client,headers,phase):
    preview = _call(client,headers,'preview_v4_windows_jit_local_'+phase+'_700',{})
    assert not preview['isError'] and preview['structuredContent']['authorization_policy_mode'] == 'lab_auto'
    authorization = _call(client,headers,'authorize_v4_windows_jit_local_'+phase+'_700',{'preview_ref':preview['structuredContent']['preview_ref']})
    assert not authorization['isError']
    result = _call(client,headers,'execute_v4_windows_jit_local_'+phase+'_700',{'authorization_ref':authorization['structuredContent']['authorization_ref']})
    return result,authorization


@pytest.mark.parametrize('fault',[None,'second-unknown'])
def test_normal_mcp_fixed_six_steps_or_original_only_cleanup_never_replay(monkeypatch,tmp_path,fault):
    settings,headers,scope,transport = bootstrap(tmp_path)
    value = make(monkeypatch,tmp_path,requester=scope.requester_digest,transport=transport)
    with TestClient(create_http_app(settings,v4_windows_jit_local_candidate_action=WindowsJitLocalMcpAction(value.workflow)),
            base_url='https://mcp.example.com') as client:
        baseline = len(value.peer.calls)
        for field in ('script','nonce','user','secret_id','group','target','credential','endpoint','body'):
            result = _call(client,headers,'preview_v4_windows_jit_local_grant_create_700',{field:'SYNTHETIC_FORBIDDEN_INPUT'})
            assert result['isError'] and 'SYNTHETIC_FORBIDDEN_INPUT' not in json.dumps(result)
        assert len(value.peer.calls) == baseline and value.calls == []
        assert rpc_phase(client,headers,'grant_create')[0]['structuredContent']['outcome'] == 'succeeded'
        if fault: value.script_backend.fault = 'lost-ack'
        result,authorization = rpc_phase(client,headers,'revoke_create')
        assert (result['structuredContent']['outcome'] == 'succeeded') is (fault is None)
        reads,calls,sends = len(value.peer.calls),len(value.calls),list(value.script_backend.sends)
        value.workflow._enabled['revoke_create'] = False
        replay = _call(client,headers,'execute_v4_windows_jit_local_revoke_create_700',
            {'authorization_ref':authorization['structuredContent']['authorization_ref']})
        assert replay['structuredContent']['idempotent_replay']
        assert (len(value.peer.calls),len(value.calls),value.script_backend.sends) == (reads,calls,sends)
        if fault:
            value.script_backend.fault = None
            for phase in ('configure','revoke_remove'):
                assert _call(client,headers,'preview_v4_windows_jit_local_'+phase+'_700',{})['isError']
            assert rpc_phase(client,headers,'grant_remove')[0]['structuredContent']['outcome'] == 'succeeded'
        else:
            for phase in PHASES[2:]: assert rpc_phase(client,headers,phase)[0]['structuredContent']['outcome'] == 'succeeded'
        outcome = _call(client,headers,'get_v4_windows_jit_local_outcome_700',{})['structuredContent']
        assert outcome['workflow_outcome'] == ('verified_locally' if fault is None else 'reconciliation_required')
        assert not outcome['native_backend_qualified'] and not outcome['jit_privilege_effect_verified']
        public = json.dumps((result,replay,outcome))
        assert all(marker not in public for marker in (NONCE,SERIAL,PRIVATE.decode(),SECRET,'$USER'))
        assert (value.script_store.claim_count,value.secret_store.claim_count) == ((4,2) if fault is None else (3,0))


@pytest.mark.parametrize('scopes',['fortipam:read','fortipam:read fortipam:plan'])
def test_missing_scope_refuses_before_sources_or_authority_for_the_bound_client(monkeypatch,tmp_path,scopes):
    settings,headers,scope,transport = bootstrap(tmp_path,scopes if 'fortipam:plan' in scopes else 'fortipam:read fortipam:plan fortipam:operate')
    if 'fortipam:plan' not in scopes:
        with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client: headers = _login(client,scopes)
    value = make(monkeypatch,tmp_path,requester=scope.requester_digest,transport=transport)
    with TestClient(create_http_app(settings,v4_windows_jit_local_candidate_action=WindowsJitLocalMcpAction(value.workflow)),
            base_url='https://mcp.example.com') as client:
        calls = len(value.peer.calls); preview = _call(client,headers,'preview_v4_windows_jit_local_grant_create_700',{})
        if 'fortipam:plan' not in scopes: assert preview['isError'] and len(value.peer.calls) == calls
        else:
            assert not preview['isError']
            before = len(value.peer.calls)
            assert _call(client,headers,'authorize_v4_windows_jit_local_grant_create_700',
                {'preview_ref':preview['structuredContent']['preview_ref']})['isError']
            assert len(value.peer.calls) == before
        assert value.calls == []
        assert value.script_store.claim_count == 0


def test_fully_scoped_foreign_client_cannot_use_the_fixed_workflow_namespace(monkeypatch,tmp_path):
    settings,headers,scope,transport = bootstrap(tmp_path)
    value = make(monkeypatch,tmp_path,requester=scope.requester_digest,transport=transport)
    with TestClient(create_http_app(settings,v4_windows_jit_local_candidate_action=WindowsJitLocalMcpAction(value.workflow)),
            base_url='https://mcp.example.com') as client:
        foreign = _login(client,'fortipam:read fortipam:plan fortipam:operate'); calls = len(value.peer.calls)
        assert _call(client,foreign,'preview_v4_windows_jit_local_grant_create_700',{})['isError']
        assert len(value.peer.calls) == calls and value.calls == [] and value.script_store.claim_count == 0


def test_normal_mcp_renews_only_an_expired_unconsumed_grant(monkeypatch,tmp_path):
    settings,headers,scope,transport = bootstrap(tmp_path)
    value = make(monkeypatch,tmp_path,requester=scope.requester_digest,transport=transport); value.expiry[0] = 1010
    with TestClient(create_http_app(settings,v4_windows_jit_local_candidate_action=WindowsJitLocalMcpAction(value.workflow)),
            base_url='https://mcp.example.com') as client:
        preview = _call(client,headers,'preview_v4_windows_jit_local_grant_create_700',{})['structuredContent']
        old = _call(client,headers,'authorize_v4_windows_jit_local_grant_create_700',{'preview_ref':preview['preview_ref']})['structuredContent']
        value.clock.value = 1010
        assert _call(client,headers,'execute_v4_windows_jit_local_grant_create_700',{'authorization_ref':old['authorization_ref']})['isError']
        assert value.script_store.claim_count == 0
        value.expiry[0] = 1070
        result,new = rpc_phase(client,headers,'grant_create'); assert result['structuredContent']['outcome'] == 'succeeded'
        assert new['structuredContent']['authorization_ref'] != old['authorization_ref']
        assert _call(client,headers,'execute_v4_windows_jit_local_grant_create_700',{'authorization_ref':old['authorization_ref']})['isError']
        assert value.script_store.claim_count == 1 and value.script_backend.sends == [(0,False)]


def test_registered_schemas_expose_only_fixed_refs_and_default_factory_has_no_jit_execution(monkeypatch,tmp_path):
    settings,headers,scope,transport = bootstrap(tmp_path)
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client:
        response = client.post('/fpamcp',headers=headers,json=dict(jsonrpc='2.0',id='list',method='tools/list',params={})).json()
        assert not any('_windows_jit_local_' in t['name'] for t in response['result']['tools'])
    value = make(monkeypatch,tmp_path,requester=scope.requester_digest,transport=transport)
    with TestClient(create_http_app(settings,v4_windows_jit_local_candidate_action=WindowsJitLocalMcpAction(value.workflow)),
            base_url='https://mcp.example.com') as client:
        tools = client.post('/fpamcp',headers=headers,json=dict(jsonrpc='2.0',id='list',method='tools/list',params={})).json()['result']['tools']
        selected = [t for t in tools if '_windows_jit_local_' in t['name']]
        assert len(selected) == 19
        for tool in selected:
            keys = set(tool['inputSchema'].get('properties',{}))
            assert keys == ({'preview_ref'} if tool['name'].startswith('authorize_') else
                {'authorization_ref'} if tool['name'].startswith('execute_') else set())


def test_factory_rejects_wrong_profile_or_action_before_extra_reads(monkeypatch,tmp_path):
    settings,headers,scope,transport = bootstrap(tmp_path)
    value = make(monkeypatch,tmp_path,requester=scope.requester_digest,transport=transport); before = len(value.peer.calls)
    with pytest.raises(HttpConfigurationError): create_http_app(settings,v4_windows_jit_local_candidate_action=object())
    with pytest.raises(HttpConfigurationError):
        create_http_app(replace(settings,runtime_profile=RuntimeProfile.READONLY),
            v4_windows_jit_local_candidate_action=WindowsJitLocalMcpAction(value.workflow))
    assert len(value.peer.calls) == before and value.calls == []


@contextmanager
def unix_services(root):
    clock = Clock()
    reference_tail = PersistentReferenceCheckpointAuthority(root/'reference-tail.db',owner_file(root/'reference-tail.key',b's'*32),
        authority_ref='jit-reference-checkpoint')
    reference = PersistentReferenceAuthority(root/'reference.db',owner_file(root/'reference.key',b'r'*32),authority_ref=REFERENCE,
        monotonic_checkpoint=reference_tail,checkpoint_store_ref='jit-reference-state',clock=clock)
    execution = PersistentPlanningCheckpointAuthority(root/'execution-tail.db',owner_file(root/'execution-tail.key',b'z'*32),
        authority_ref='jit-execution-checkpoint')
    with ExitStack() as stack:
        sockets = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='jitcp-',dir='/private/tmp')))
        stack.enter_context(unix_app(create_reference_authority_sidecar_app(reference),sockets/'r.sock'))
        stack.enter_context(unix_app(create_checkpoint_sidecar_app(execution),sockets/'e.sock'))
        client = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(sockets/'r.sock',REFERENCE))
        def store(phase,key):
            store_ref = 'jit-'+phase+'-execution-state'
            return PersistentM4ExecutionStateStore(root/(phase+'.db'),owner_file(root/(phase+'.key'),key),
                monotonic_checkpoint=UnixM4ExecutionCheckpoint(UnixPlanningCheckpointClient(UnixPlanningCheckpointClientSettings(
                    sockets/'e.sock',execution.authority_ref)),store_ref),checkpoint_store_ref=store_ref)
        yield reference,client,(store('script',b'e'*32),store('secret',b'm'*32))


def test_real_unix_authority_and_two_checkpointed_journals_drive_six_normal_mcp_phases(tmp_path):
    settings,headers,scope,transport = bootstrap(tmp_path)
    with unix_services(tmp_path) as (reference,client,stores):
        value = construct(tmp_path,client,requester=scope.requester_digest,transport=transport,opened=stores)
        reference.issue_many(tuple((value.policy.reference_for(phase,purpose),'windows_jit_'+purpose)
            for phase in PHASES for purpose in PURPOSES),requester_digest=value.requester,
            environment_ref=ENVIRONMENT,scope_ref=SCOPE_REF,expires_at=1120,now_epoch=1000)
        with TestClient(create_http_app(settings,v4_windows_jit_local_candidate_action=WindowsJitLocalMcpAction(value.workflow)),
                base_url='https://mcp.example.com') as mcp:
            for phase in PHASES: assert rpc_phase(mcp,headers,phase)[0]['structuredContent']['outcome'] == 'succeeded'
            outcome = _call(mcp,headers,'get_v4_windows_jit_local_outcome_700',{})['structuredContent']
            assert outcome['workflow_outcome'] == 'verified_locally' and not outcome['native_backend_qualified']
            assert (stores[0].claim_count,stores[1].claim_count) == (4,2)


def test_real_loopback_https_fixed_writers_unix_authority_and_normal_mcp_six_phases(tmp_path):
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from fortipam_mcp.windows_jit_script_source import WindowsJitScriptSource, COLLECTION_PATH
    from fortipam_mcp.windows_jit_script_http_backend import WindowsJitScriptHttpBackend
    from fortipam_mcp.windows_jit_secret_http_backend import WindowsJitSecretHttpBackend
    from test_windows_jit_secret_http_backend import SecretHttpPeer
    from test_secret_bulk_import_action_process import tls_material

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
            assert self.headers['Authorization'] == 'Bearer synthetic-api-token'
            body = self.rfile.read(int(self.headers['Content-Length']))
            if self.headers.get('X-HTTP-Method-Override') == 'GET':
                assert self.path == COLLECTION_PATH and body == b'{"json_filter":[]}'
                self.send(peer.payloads[self.path])
            else: self.send(peer.mutate('POST',self.path,body))
        def do_PUT(self): self.send(peer.mutate_secret(self.path,self.rfile.read(int(self.headers['Content-Length']))))
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
        settings,headers,scope,transport = bootstrap(tmp_path)
        with unix_services(tmp_path) as (reference,client,stores):
            value = construct(tmp_path,client,requester=scope.requester_digest,transport=transport,opened=stores,peer=peer,source=source,
                script_backend_factory=lambda s:WindowsJitScriptHttpBackend(s,execution_enabled=lambda:True,source_guard=lambda:True),
                secret_backend_factory=lambda s,p:WindowsJitSecretHttpBackend(s,p,execution_enabled=lambda:True,source_guard=lambda:True))
            reference.issue_many(tuple((value.policy.reference_for(phase,purpose),'windows_jit_'+purpose)
                for phase in PHASES for purpose in PURPOSES),requester_digest=value.requester,
                environment_ref=ENVIRONMENT,scope_ref=SCOPE_REF,expires_at=1120,now_epoch=1000)
            with TestClient(create_http_app(settings,v4_windows_jit_local_candidate_action=WindowsJitLocalMcpAction(value.workflow)),
                    base_url='https://mcp.example.com') as mcp:
                for phase in PHASES: assert rpc_phase(mcp,headers,phase)[0]['structuredContent']['outcome'] == 'succeeded'
                outcome = _call(mcp,headers,'get_v4_windows_jit_local_outcome_700',{})['structuredContent']
                assert outcome['workflow_outcome'] == 'verified_locally' and not outcome['jit_privilege_effect_verified']
            assert peer.writes == [('POST',0),('POST',1),('DELETE',1),('DELETE',0)] and peer.secret_writes == [False,True]
            assert (stores[0].claim_count,stores[1].claim_count) == (4,2)
            assert all(connection.sock is None for connection in connections) and all(not any(raw) for raw in buffers)
    finally:
        source.close(); server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
