"""Protected local MFA phases through actual OAuth/MCP and optional Unix services."""
import asyncio
from contextlib import ExitStack, contextmanager
from dataclasses import replace
import json
from pathlib import Path
import tempfile

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.fortitoken_local_mcp_action import FortitokenLocalMcpAction
from fortipam_mcp.http_server import create_http_app, HttpConfigurationError
from fortipam_mcp.local_oauth import LocalOAuthProvider
from fortipam_mcp.m4_checkpoint_client import UnixM4ExecutionCheckpoint
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.material_checkpoint_sidecar import (UnixMaterialCheckpointClient, UnixMaterialCheckpointClientSettings,
    create_material_checkpoint_sidecar_app)
from fortipam_mcp.planning_checkpoint_sidecar import (UnixPlanningCheckpointClient, UnixPlanningCheckpointClientSettings,
    create_checkpoint_sidecar_app)
from fortipam_mcp.reference_authority_sidecar import (UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings,
    create_reference_authority_sidecar_app)
from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
from test_fortitoken_authority import make, construct, REFERENCE, ENVIRONMENT, SCOPE_REF, PURPOSES
from test_fortitoken_local_m4 import SCOPE
from test_fortitoken_user_contract import NAME, TOKEN
from test_ldap_server_mcp_action import _settings, _login, _call
from test_system_email_authority import owner_file, unix_app
from test_system_email_m4_adapter import Clock
from v4_planning import (PersistentReferenceAuthority, PersistentReferenceCheckpointAuthority,
    PersistentPlanningCheckpointAuthority, PersistentMaterialUseCheckpointAuthority)
from v4_planning.material_persistence import PersistentMaterialUseStateStore


def bootstrap(root,scopes='fortipam:read fortipam:plan fortipam:operate'):
    settings = _settings(root)
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client: headers = _login(client,scopes)
    token = asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(headers['authorization'].split(' ',1)[1]))
    principal = planning_principal_from_access_token(token,settings.v4_planning_authorization)
    return settings,headers,replace(SCOPE,requester_digest=principal.requester.digest),principal.transport_namespace_digest


def rpc_phase(client,headers,phase):
    preview = _call(client,headers,'preview_v4_fortitoken_local_'+phase+'_700',{})
    assert not preview['isError'] and preview['structuredContent']['authorization_policy_mode'] == 'lab_auto'
    authorization = _call(client,headers,'authorize_v4_fortitoken_local_'+phase+'_700',
        {'preview_ref':preview['structuredContent']['preview_ref']})
    assert not authorization['isError']
    result = _call(client,headers,'execute_v4_fortitoken_local_'+phase+'_700',
        {'authorization_ref':authorization['structuredContent']['authorization_ref']})
    return result,authorization


@pytest.mark.parametrize('operation,fault', [('assign',None),('revoke',None),('assign','lost-ack')])
def test_normal_mcp_local_apply_restore_or_unknown_queries_never_reload(monkeypatch,tmp_path,operation,fault):
    settings,headers,scope,transport = bootstrap(tmp_path)
    value = make(monkeypatch,tmp_path,operation=operation,fault=fault,scope=scope,transport=transport)
    with TestClient(create_http_app(settings,v4_fortitoken_local_candidate_action=FortitokenLocalMcpAction(value.workflow)),
            base_url='https://mcp.example.com') as client:
        calls = len(value.peer.calls)
        for key in ('token','user','body','endpoint','material'):
            result = _call(client,headers,'preview_v4_fortitoken_local_apply_700',{key:'SYNTHETIC_PRIVATE_INPUT'})
            assert result['isError'] and 'SYNTHETIC_PRIVATE_INPUT' not in json.dumps(result)
        assert len(value.peer.calls) == calls and value.calls == [] and value.resolver.loads == 0
        result,authorization = rpc_phase(client,headers,'apply')
        assert not result['isError'] and (result['structuredContent']['outcome'] == 'succeeded') is (fault is None)
        value.workflow._enabled['apply'] = False; reads = len(value.peer.calls)
        replay = _call(client,headers,'execute_v4_fortitoken_local_apply_700',
            {'authorization_ref':authorization['structuredContent']['authorization_ref']})
        assert replay['structuredContent']['idempotent_replay'] and len(value.peer.calls) == reads
        if fault is None: assert rpc_phase(client,headers,'restore')[0]['structuredContent']['outcome'] == 'succeeded'
        else: assert _call(client,headers,'preview_v4_fortitoken_local_restore_700',{})['isError']
        outcome = _call(client,headers,'get_v4_fortitoken_local_outcome_700',{})['structuredContent']
        assert outcome['workflow_outcome'] == ('verified_locally' if fault is None else 'reconciliation_required')
        assert not outcome['native_backend_qualified'] and not outcome['mfa_login_verified']
        assert value.backend.sends == value.store.claim_count == value.material.claim_count == (2 if fault is None else 1)
        assert value.resolver.loads == 1 and value.recovery.loads == int(fault is None)
        public = json.dumps((result,replay,outcome))
        assert NAME not in public and TOKEN.decode('ascii') not in public


@pytest.mark.parametrize('scopes', ['fortipam:read','fortipam:read fortipam:plan'])
def test_missing_plan_or_operate_is_rejected_before_sources_or_authority(monkeypatch,tmp_path,scopes):
    settings,headers,scope,transport = bootstrap(tmp_path,scopes if 'fortipam:plan' in scopes else 'fortipam:read fortipam:plan fortipam:operate')
    if 'fortipam:plan' not in scopes:
        with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client: headers = _login(client,scopes)
    value = make(monkeypatch,tmp_path,scope=scope,transport=transport); calls = len(value.peer.calls)
    with TestClient(create_http_app(settings,v4_fortitoken_local_candidate_action=FortitokenLocalMcpAction(value.workflow)),
            base_url='https://mcp.example.com') as client:
        preview = _call(client,headers,'preview_v4_fortitoken_local_apply_700',{})
        if 'fortipam:plan' not in scopes: assert preview['isError'] and len(value.peer.calls) == calls
        else:
            assert not preview['isError']
            assert _call(client,headers,'authorize_v4_fortitoken_local_apply_700',
                {'preview_ref':preview['structuredContent']['preview_ref']})['isError']
        assert value.calls == [] and value.resolver.loads == value.store.claim_count == 0


@pytest.mark.parametrize('invalid', ['readonly','plan-only','bearer','authority','type'])
def test_factory_requires_exact_controlled_oauth_candidate(monkeypatch,tmp_path,invalid):
    settings = _settings(tmp_path); value = make(monkeypatch,tmp_path); action = FortitokenLocalMcpAction(value.workflow)
    if invalid == 'readonly': settings = replace(settings,runtime_profile=RuntimeProfile.READONLY)
    elif invalid == 'plan-only': settings = replace(settings,runtime_profile=RuntimeProfile.V4_PLAN_ONLY)
    elif invalid == 'bearer': settings = replace(settings,auth_mode='bearer',bearer_token='synthetic-token')
    elif invalid == 'authority': settings = replace(settings,v4_planning_authorization=None)
    else: action = object()
    with pytest.raises(HttpConfigurationError): create_http_app(settings,v4_fortitoken_local_candidate_action=action)
    assert value.resolver.loads == value.evidence.calls == 0


def test_default_app_registers_no_local_fortitoken_execution_candidate(tmp_path):
    settings,headers,_,_ = bootstrap(tmp_path)
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client:
        response = client.post('/fpamcp',headers=headers,json=dict(jsonrpc='2.0',id='list',method='tools/list',params={})).json()
        assert not any('_fortitoken_local_' in tool['name'] for tool in response['result']['tools'])


@contextmanager
def unix_services(root):
    clock = Clock()
    reference_tail = PersistentReferenceCheckpointAuthority(root/'reference-tail.db',owner_file(root/'reference-tail.key',b's'*32),
        authority_ref='ftk-reference-checkpoint')
    reference = PersistentReferenceAuthority(root/'reference.db',owner_file(root/'reference.key',b'r'*32),authority_ref=REFERENCE,
        monotonic_checkpoint=reference_tail,checkpoint_store_ref='ftk-reference-state',clock=clock)
    execution = PersistentPlanningCheckpointAuthority(root/'execution-tail.db',owner_file(root/'execution-tail.key',b'z'*32),
        authority_ref='ftk-execution-checkpoint')
    material = PersistentMaterialUseCheckpointAuthority(root/'material-tail.db',owner_file(root/'material-tail.key',b'q'*32),
        authority_ref='ftk-material-checkpoint')
    with ExitStack() as stack:
        sockets = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='ftkcp-',dir='/private/tmp')))
        stack.enter_context(unix_app(create_reference_authority_sidecar_app(reference),sockets/'r.sock'))
        stack.enter_context(unix_app(create_checkpoint_sidecar_app(execution),sockets/'e.sock'))
        stack.enter_context(unix_app(create_material_checkpoint_sidecar_app(material),sockets/'m.sock'))
        client = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(sockets/'r.sock',REFERENCE))
        store = PersistentM4ExecutionStateStore(root/'execution.db',owner_file(root/'execution.key',b'e'*32),
            monotonic_checkpoint=UnixM4ExecutionCheckpoint(UnixPlanningCheckpointClient(UnixPlanningCheckpointClientSettings(
                sockets/'e.sock',execution.authority_ref)),'ftk-execution-state'),checkpoint_store_ref='ftk-execution-state')
        material_store = PersistentMaterialUseStateStore(root/'material.db',owner_file(root/'material.key',b'm'*32),
            monotonic_checkpoint=UnixMaterialCheckpointClient(UnixMaterialCheckpointClientSettings(sockets/'m.sock',material.authority_ref)),
            checkpoint_store_ref='ftk-material-state')
        yield reference,client,store,material_store


@pytest.mark.parametrize('operation,fault', [('assign',None),('revoke',None),('assign','lost-ack')])
def test_real_unix_reference_and_both_checkpoint_services_drive_normal_mcp(tmp_path,operation,fault):
    settings,headers,scope,transport = bootstrap(tmp_path)
    with unix_services(tmp_path) as (reference,client,store,material):
        value = construct(tmp_path,client,operation=operation,scope=scope,transport=transport,opened=(store,material),fault=fault)
        reference.issue_many(tuple((value.policy.reference_for(phase,purpose),'fortitoken_'+purpose)
            for phase in ('apply','restore') for purpose in PURPOSES),requester_digest=scope.requester_digest,
            environment_ref=ENVIRONMENT,scope_ref=SCOPE_REF,expires_at=1120,now_epoch=1000)
        with TestClient(create_http_app(settings,v4_fortitoken_local_candidate_action=FortitokenLocalMcpAction(value.workflow)),
                base_url='https://mcp.example.com') as mcp:
            result,_ = rpc_phase(mcp,headers,'apply')
            assert (result['structuredContent']['outcome'] == 'succeeded') is (fault is None)
            if fault is None: assert rpc_phase(mcp,headers,'restore')[0]['structuredContent']['outcome'] == 'succeeded'
            else: assert _call(mcp,headers,'preview_v4_fortitoken_local_restore_700',{})['isError']
            outcome = _call(mcp,headers,'get_v4_fortitoken_local_outcome_700',{})['structuredContent']
            assert outcome['workflow_outcome'] == ('verified_locally' if fault is None else 'reconciliation_required')
            assert not outcome['native_backend_qualified'] and value.backend.sends == store.claim_count == material.claim_count
        assert all(not any(raw) for raw in value.peer.buffers+value.backend.buffers+value.resolver.buffers+value.recovery.buffers)


def test_real_loopback_https_source_unix_authority_dual_cas_and_normal_mcp(tmp_path):
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from fortipam_mcp.fortitoken_user_source import FortitokenUserSource, SCHEMA_PATH
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from test_fortitoken_user_contract import binding, SERIAL
    from test_fortitoken_user_source import Peer
    from test_secret_bulk_import_action_process import tls_material

    certificate,key = tls_material(tmp_path); peer = Peer(); requests = []; connections = []; buffers = []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self,*_): pass
        def do_GET(self):
            assert self.path in (SCHEMA_PATH,peer.detail) and self.headers['Authorization'] == 'Bearer synthetic-api-token'
            requests.append(('GET',self.path)); raw = json.dumps(peer.payloads[self.path]).encode()
            self.send_response(200); self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw))); self.send_header('Connection','close')
            self.end_headers(); self.wfile.write(raw)
        def do_POST(self): requests.append(('POST',self.path)); self.send_error(405)
        def do_PUT(self): requests.append(('PUT',self.path)); self.send_error(405)
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
    fetch = source._fetch
    def tracked(*args,**kwargs):
        raw = fetch(*args,**kwargs); buffers.append(raw); return raw
    source._fetch = tracked
    try:
        settings,headers,scope,transport = bootstrap(tmp_path)
        with unix_services(tmp_path) as (reference,client,store,material):
            value = construct(tmp_path,client,scope=scope,transport=transport,opened=(store,material),peer=peer,source=source)
            reference.issue_many(tuple((value.policy.reference_for(phase,purpose),'fortitoken_'+purpose)
                for phase in ('apply','restore') for purpose in PURPOSES),requester_digest=scope.requester_digest,
                environment_ref=ENVIRONMENT,scope_ref=SCOPE_REF,expires_at=1120,now_epoch=1000)
            with TestClient(create_http_app(settings,v4_fortitoken_local_candidate_action=FortitokenLocalMcpAction(value.workflow)),
                    base_url='https://mcp.example.com') as mcp:
                assert rpc_phase(mcp,headers,'apply')[0]['structuredContent']['outcome'] == 'succeeded'
                assert rpc_phase(mcp,headers,'restore')[0]['structuredContent']['outcome'] == 'succeeded'
                outcome = _call(mcp,headers,'get_v4_fortitoken_local_outcome_700',{})['structuredContent']
                assert outcome['workflow_outcome'] == 'verified_locally' and not outcome['native_backend_qualified']
                assert value.backend.sends == store.claim_count == material.claim_count == 2
                assert requests and all(method == 'GET' for method,path in requests)
                assert all(connection.sock is None for connection in connections)
                assert all(not any(raw) for raw in buffers+value.backend.buffers+value.resolver.buffers+value.recovery.buffers)
    finally:
        source.close(); server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
