"""Normal OAuth/MCP with synthetic incidents; optional real local TLS/Unix services."""
from contextlib import ExitStack,contextmanager
from dataclasses import replace
from pathlib import Path
import json
import tempfile

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.glass_break_local_mcp_action import GlassBreakLocalMcpAction
from fortipam_mcp.glass_break_local_workflow import PHASES
from fortipam_mcp.http_server import create_http_app,HttpConfigurationError
from fortipam_mcp.m4_checkpoint_client import UnixM4ExecutionCheckpoint
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.planning_checkpoint_sidecar import UnixPlanningCheckpointClient,UnixPlanningCheckpointClientSettings,create_checkpoint_sidecar_app
from fortipam_mcp.reference_authority_sidecar import UnixReferenceAuthorityClient,UnixReferenceAuthorityClientSettings,create_reference_authority_sidecar_app
from fortipam_mcp.runtime_profile import RuntimeProfile
from test_glass_break_authority import make,construct,cleanup,REFERENCE,ENVIRONMENT,SCOPE_REF,PURPOSES
from test_glass_break_contract import ACTOR,SERIAL,PRIVATE,REASON
from test_glass_break_source import COOKIE
from test_fortitoken_local_mcp_action import bootstrap
from test_ldap_server_mcp_action import _call,_login
from test_system_email_authority import owner_file,unix_app
from test_system_email_m4_adapter import Clock
from v4_planning import PersistentReferenceAuthority,PersistentReferenceCheckpointAuthority,PersistentPlanningCheckpointAuthority

PREVIEW='preview_v4_glass_break_step_local_700'
AUTHORIZE='authorize_v4_glass_break_step_local_700'
EXECUTE='execute_v4_glass_break_step_local_700'
OUTCOME='get_v4_glass_break_local_outcome_700'


def rpc_phase(client,headers,phase):
    preview=_call(client,headers,PREVIEW,dict(phase=phase))
    assert not preview['isError'] and preview['structuredContent']['authorization_policy_mode']=='lab_auto'
    authorized=_call(client,headers,AUTHORIZE,dict(preview_ref=preview['structuredContent']['preview_ref']))
    assert not authorized['isError']
    result=_call(client,headers,EXECUTE,dict(authorization_ref=authorized['structuredContent']['authorization_ref']))
    return result,authorized


@pytest.mark.parametrize('fault',[None,'lost-ack','late-exit','expired-window'])
def test_normal_mcp_independent_exit_or_owned_non_dispatching_queries(monkeypatch,tmp_path,fault):
    from test_glass_break_m4 import advance
    settings,headers,scope,transport=bootstrap(tmp_path)
    value=make(monkeypatch,tmp_path,requester=scope.requester_digest,transport=transport)
    try:
        with TestClient(create_http_app(settings,v4_glass_break_local_candidate_action=GlassBreakLocalMcpAction(value.workflow)),
                base_url='https://mcp.example.com') as client:
            before=len(value.peer.calls)
            for field in ('reason','incident','actor','cookie','endpoint','body','reference_kind'):
                bad=_call(client,headers,PREVIEW,dict(phase='activate',**{field:'SYNTHETIC_FORBIDDEN_INPUT'}))
                assert bad['isError'] and 'SYNTHETIC_FORBIDDEN_INPUT' not in json.dumps(bad)
            for phase in ('SYNTHETIC_FORBIDDEN_INPUT',True,None,1):
                assert _call(client,headers,PREVIEW,dict(phase=phase))['isError']
            assert len(value.peer.calls)==before and value.calls==[]
            if fault=='lost-ack': value.backend.fault='lost-ack'
            result,authorized=rpc_phase(client,headers,'activate')
            assert result['structuredContent']['outcome']==('reconciliation_required' if fault=='lost-ack' else 'succeeded')
            if fault=='late-exit': advance(value.peer,31)
            elif fault=='expired-window': advance(value.peer,61)
            active=_call(client,headers,OUTCOME,{})['structuredContent']
            assert active['workflow_outcome']=={'lost-ack':'reconciliation_required','late-exit':'deactivation_required',
                'expired-window':'out_of_band_recovery_required',None:'active_locally'}[fault]
            if fault in (None,'late-exit'):
                result,authorized=rpc_phase(client,headers,'deactivate'); assert result['structuredContent']['outcome']=='succeeded'
            else:
                value.backend.fault=None
                assert _call(client,headers,PREVIEW,dict(phase='deactivate'))['isError']
            before=(len(value.peer.calls),len(value.calls),list(value.backend.sends)); value.source.close()
            value.workflow._enabled={phase:False for phase in PHASES}; value.policy.close()
            replay=_call(client,headers,EXECUTE,dict(authorization_ref=authorized['structuredContent']['authorization_ref']))
            assert replay['structuredContent']['idempotent_replay']
            outcome=_call(client,headers,OUTCOME,{})['structuredContent']
            assert (len(value.peer.calls),len(value.calls),value.backend.sends)==before
            expected={None:'verified_locally','late-exit':'exited_after_declared_duration_locally',
                'lost-ack':'reconciliation_required','expired-window':'out_of_band_recovery_required'}[fault]
            assert outcome['workflow_outcome']==expected and not outcome['live_configuration_verified'] and not outcome['native_backend_qualified']
            assert outcome['declared_duration_verified_locally']==(True if fault is None else False if fault=='late-exit' else None)
            assert all(marker not in json.dumps((result,replay,outcome)) for marker in (ACTOR,SERIAL,PRIVATE,REASON,COOKIE))
        assert value.store.claim_count==len(value.backend.sends)==(2 if fault in (None,'late-exit') else 1)
        assert value.peer.credentials==0 and not value.owner.logout_verified
    finally: cleanup(value)


@pytest.mark.parametrize('scopes',['fortipam:read','fortipam:read fortipam:plan'])
def test_missing_plan_or_operate_is_rejected_before_sources_and_grants(monkeypatch,tmp_path,scopes):
    settings,headers,scope,transport=bootstrap(tmp_path,scopes if 'fortipam:plan' in scopes else 'fortipam:read fortipam:plan fortipam:operate')
    if 'fortipam:plan' not in scopes:
        with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client: headers=_login(client,scopes)
    value=make(monkeypatch,tmp_path,requester=scope.requester_digest,transport=transport)
    try:
        with TestClient(create_http_app(settings,v4_glass_break_local_candidate_action=GlassBreakLocalMcpAction(value.workflow)),
                base_url='https://mcp.example.com') as client:
            before=len(value.peer.calls); preview=_call(client,headers,PREVIEW,dict(phase='activate'))
            if 'fortipam:plan' not in scopes: assert preview['isError'] and len(value.peer.calls)==before
            else:
                assert not preview['isError']; before=len(value.peer.calls)
                assert _call(client,headers,AUTHORIZE,dict(preview_ref=preview['structuredContent']['preview_ref']))['isError']
                assert len(value.peer.calls)==before
            assert value.calls==[] and value.store.claim_count==0 and value.backend.sends==[]
    finally: cleanup(value)


def test_foreign_operator_cannot_use_bound_source_or_query(monkeypatch,tmp_path):
    settings,headers,scope,transport=bootstrap(tmp_path); value=make(monkeypatch,tmp_path,requester=scope.requester_digest,transport=transport)
    try:
        with TestClient(create_http_app(settings,v4_glass_break_local_candidate_action=GlassBreakLocalMcpAction(value.workflow)),
                base_url='https://mcp.example.com') as client:
            foreign=_login(client,'fortipam:read fortipam:plan fortipam:operate'); before=len(value.peer.calls)
            assert _call(client,foreign,PREVIEW,dict(phase='activate'))['isError'] and _call(client,foreign,OUTCOME,{})['isError']
            assert len(value.peer.calls)==before and value.calls==[] and value.store.claim_count==0
    finally: cleanup(value)


def test_factory_default_profile_and_four_fixed_tool_boundaries(monkeypatch,tmp_path):
    settings,headers,scope,transport=bootstrap(tmp_path); value=make(monkeypatch,tmp_path,requester=scope.requester_digest,transport=transport)
    try:
        for action in (None,GlassBreakLocalMcpAction(value.workflow)):
            with TestClient(create_http_app(settings,v4_glass_break_local_candidate_action=action),base_url='https://mcp.example.com') as client:
                tools=client.post('/fpamcp',headers=headers,json=dict(jsonrpc='2.0',id='list',method='tools/list',params={})).json()['result']['tools']
                selected={t['name']:t for t in tools if t['name'] in (PREVIEW,AUTHORIZE,EXECUTE,OUTCOME)}
                assert len(selected)==(0 if action is None else 4)
                if action is not None:
                    assert set(selected[PREVIEW]['inputSchema']['properties'])=={'phase'}
                    assert set(selected[AUTHORIZE]['inputSchema']['properties'])=={'preview_ref'}
                    assert set(selected[EXECUTE]['inputSchema']['properties'])=={'authorization_ref'}
                    assert selected[OUTCOME]['inputSchema'].get('properties',{})=={}
                    assert selected[PREVIEW]['annotations']['readOnlyHint'] and selected[OUTCOME]['annotations']['readOnlyHint']
        with pytest.raises(HttpConfigurationError): create_http_app(settings,v4_glass_break_local_candidate_action=object())
        with pytest.raises(HttpConfigurationError):
            create_http_app(replace(settings,runtime_profile=RuntimeProfile.READONLY),v4_glass_break_local_candidate_action=GlassBreakLocalMcpAction(value.workflow))
    finally: cleanup(value)


@contextmanager
def unix_services(root):
    reference_tail=PersistentReferenceCheckpointAuthority(root/'reference-tail.db',owner_file(root/'reference-tail.key',b's'*32),
        authority_ref='glass-break-reference-checkpoint')
    reference=PersistentReferenceAuthority(root/'reference.db',owner_file(root/'reference.key',b'r'*32),authority_ref=REFERENCE,
        monotonic_checkpoint=reference_tail,checkpoint_store_ref='glass-break-reference-state',clock=Clock())
    execution=PersistentPlanningCheckpointAuthority(root/'execution-tail.db',owner_file(root/'execution-tail.key',b'z'*32),
        authority_ref='glass-break-execution-checkpoint')
    with ExitStack() as stack:
        sockets=Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='gbcp-',dir=Path("/tmp").resolve())))
        stack.enter_context(unix_app(create_reference_authority_sidecar_app(reference),sockets/'r.sock'))
        stack.enter_context(unix_app(create_checkpoint_sidecar_app(execution),sockets/'e.sock'))
        client=UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(sockets/'r.sock',REFERENCE))
        store_ref='glass-break-execution-state'
        store=PersistentM4ExecutionStateStore(root/'execution.db',owner_file(root/'execution.key',b'e'*32),
            monotonic_checkpoint=UnixM4ExecutionCheckpoint(UnixPlanningCheckpointClient(UnixPlanningCheckpointClientSettings(
                sockets/'e.sock',execution.authority_ref)),store_ref),checkpoint_store_ref=store_ref)
        yield reference,client,store


@pytest.mark.parametrize('fault',[None,'lost-ack'])
def test_real_loopback_cookie_https_unix_reference_checkpoint_and_normal_mcp(tmp_path,fault):
    import http.client
    from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from fortipam_mcp.glass_break_contract import STATE_PATH,ACTIVATE_PATH,DEACTIVATE_PATH
    from fortipam_mcp.glass_break_http_backend import GlassBreakHttpBackend
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from test_glass_break_http_backend import HttpPeer,COOKIE_HEADER,CSRF,OPAQUE
    from test_glass_break_source import construct as source_for
    from test_secret_bulk_import_action_process import tls_material

    certificate,key=tls_material(tmp_path); peer=HttpPeer(); requests=[]; connections=[]; buffers=[]
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self,*_): pass
        def send(self,payload):
            raw=json.dumps(payload).encode(); self.send_response(200); self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw))); self.send_header('Connection','close'); self.end_headers(); self.wfile.write(raw)
        def do_GET(self):
            assert self.path==STATE_PATH and self.headers['Cookie']==COOKIE_HEADER and self.headers.get('Authorization') is None
            requests.append(('GET',self.path)); self.send(peer.body)
        def do_POST(self):
            assert self.path in (ACTIVATE_PATH,DEACTIVATE_PATH) and self.headers['Cookie']==COOKIE_HEADER and self.headers['X-CSRFTOKEN']==CSRF
            assert self.headers.get('Authorization') is None
            requests.append(('POST',self.path)); ack=peer.mutate(self.path,self.rfile.read(int(self.headers['Content-Length'])))
            if fault and len(peer.writes)==2:
                self.close_connection=True; self.connection.shutdown(socket.SHUT_RDWR); self.connection.close(); return
            self.send(ack)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(certificate,key); server.socket=tls.wrap_socket(server.socket,server_side=True)
    thread=Thread(target=server.serve_forever,daemon=True); thread.start()
    def factory(host,port,**kwargs):
        connection=http.client.HTTPSConnection(host,port,**kwargs)
        connection._create_connection=lambda address,timeout,source_address:socket.create_connection(('127.0.0.1',server.server_port),timeout,source_address)
        connections.append(connection); return connection
    source=owner=None
    try:
        source,owner=source_for(peer,config=SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-unused-bearer',5,str(certificate)),
            connection_factory=factory)
        receive=source._receive
        def tracked(*args,**kwargs):
            raw=receive(*args,**kwargs); buffers.append(raw); return raw
        source._receive=tracked
        settings,headers,scope,transport=bootstrap(tmp_path)
        with unix_services(tmp_path) as (reference,client,store):
            value=construct(tmp_path,client,requester=scope.requester_digest,transport=transport,source=source,owner=owner,peer=peer,store=store,
                backend_factory=lambda s,p:GlassBreakHttpBackend(s,p,execution_enabled=lambda:True,source_guard=lambda:True))
            reference.issue_many(tuple((value.policy.reference_for(phase,purpose),'glass_break_'+purpose) for phase in PHASES for purpose in PURPOSES),
                requester_digest=value.requester,environment_ref=ENVIRONMENT,scope_ref=SCOPE_REF,expires_at=1120,now_epoch=1000)
            with TestClient(create_http_app(settings,v4_glass_break_local_candidate_action=GlassBreakLocalMcpAction(value.workflow)),
                    base_url='https://mcp.example.com') as mcp:
                for phase in PHASES:
                    result,authorized=rpc_phase(mcp,headers,phase)
                    assert result['structuredContent']['outcome']==('reconciliation_required' if fault and phase=='deactivate' else 'succeeded')
                before=list(requests); source.close(); value.policy.close()
                replay=_call(mcp,headers,EXECUTE,dict(authorization_ref=authorized['structuredContent']['authorization_ref']))
                assert replay['structuredContent']['idempotent_replay']
                outcome=_call(mcp,headers,OUTCOME,{})['structuredContent']
                assert requests==before and outcome['workflow_outcome']==('reconciliation_required' if fault else 'verified_locally')
                assert not outcome['native_backend_qualified'] and not outcome['live_configuration_verified']
                assert all(marker not in json.dumps((result,replay,outcome)) for marker in (ACTOR,SERIAL,PRIVATE,REASON,COOKIE_HEADER,CSRF,OPAQUE))
            assert [r for r in requests if r[0]=='POST']==[('POST',ACTIVATE_PATH),('POST',DEACTIVATE_PATH)]
            assert store.claim_count==len(peer.writes)==2 and peer.credentials==0 and not owner.logout_verified
            assert all(connection.sock is None for connection in connections) and all(not any(raw) for raw in buffers)
    finally:
        if source is not None: source.close()
        if owner is not None:
            owner._client=None
            if owner._session_lock.locked(): owner._session_lock.release()
        server.shutdown(); server.server_close(); thread.join(timeout=2); assert not thread.is_alive()
