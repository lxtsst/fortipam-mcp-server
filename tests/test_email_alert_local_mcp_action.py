"""Normal OAuth/MCP and optional real local protected services; no appliance."""
from contextlib import ExitStack,contextmanager
from dataclasses import replace
from pathlib import Path
import json
import tempfile

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.email_alert_local_mcp_action import EmailAlertLocalMcpAction
from fortipam_mcp.email_alert_local_workflow import PHASES
from fortipam_mcp.http_server import create_http_app,HttpConfigurationError
from fortipam_mcp.m4_checkpoint_client import UnixM4ExecutionCheckpoint
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.planning_checkpoint_sidecar import UnixPlanningCheckpointClient,UnixPlanningCheckpointClientSettings,create_checkpoint_sidecar_app
from fortipam_mcp.reference_authority_sidecar import UnixReferenceAuthorityClient,UnixReferenceAuthorityClientSettings,create_reference_authority_sidecar_app
from fortipam_mcp.runtime_profile import RuntimeProfile
from test_email_alert_authority import make,construct,REFERENCE,ENVIRONMENT,SCOPE_REF,PURPOSES
from test_email_alert_general_contract import SERIAL,SENDER,RECIPIENT,PRIVATE
from test_fortitoken_local_mcp_action import bootstrap
from test_ldap_server_mcp_action import _call,_login
from test_system_email_authority import owner_file,unix_app
from test_system_email_m4_adapter import Clock
from v4_planning import PersistentReferenceAuthority,PersistentReferenceCheckpointAuthority,PersistentPlanningCheckpointAuthority

PREVIEW='preview_v4_email_alert_step_local_700'
AUTHORIZE='authorize_v4_email_alert_step_local_700'
EXECUTE='execute_v4_email_alert_step_local_700'
OUTCOME='get_v4_email_alert_local_outcome_700'


def rpc_phase(client,headers,phase):
    preview=_call(client,headers,PREVIEW,dict(step=phase[0],restore=phase[1]))
    assert not preview['isError'] and preview['structuredContent']['authorization_policy_mode']=='lab_auto'
    authorized=_call(client,headers,AUTHORIZE,dict(preview_ref=preview['structuredContent']['preview_ref']))
    assert not authorized['isError']
    result=_call(client,headers,EXECUTE,dict(authorization_ref=authorized['structuredContent']['authorization_ref']))
    return result,authorized


@pytest.mark.parametrize('fault',[None,'second-unknown'])
def test_normal_mcp_sixteen_steps_or_unknown_query_without_redispatch(monkeypatch,tmp_path,fault):
    settings,headers,scope,transport=bootstrap(tmp_path)
    value=make(monkeypatch,tmp_path,requester=scope.requester_digest,transport=transport)
    with TestClient(create_http_app(settings,v4_email_alert_local_candidate_action=EmailAlertLocalMcpAction(value.workflow)),
            base_url='https://mcp.example.com') as client:
        baseline=len(value.peer.calls)
        for field in ('sender','recipient','emailAlertOn','body','endpoint','password','certificate','reference_kind'):
            bad=_call(client,headers,PREVIEW,dict(step='general',**{field:'SYNTHETIC_FORBIDDEN_INPUT'}))
            assert bad['isError'] and 'SYNTHETIC_FORBIDDEN_INPUT' not in json.dumps(bad)
        for wrong in ('true',1,None): assert _call(client,headers,PREVIEW,dict(step='general',restore=wrong))['isError']
        assert _call(client,headers,PREVIEW,dict(step='SYNTHETIC_FORBIDDEN_INPUT'))['isError']
        assert len(value.peer.calls)==baseline and value.calls==[]
        assert rpc_phase(client,headers,PHASES[0])[0]['structuredContent']['outcome']=='succeeded'
        if fault: value.backend.fault='lost-ack'
        result,authorized=rpc_phase(client,headers,PHASES[1])
        assert result['structuredContent']['outcome']==('reconciliation_required' if fault else 'succeeded')
        before=(len(value.peer.calls),len(value.calls),list(value.backend.sends)); value.workflow._enabled[PHASES[1]]=False
        replay=_call(client,headers,EXECUTE,dict(authorization_ref=authorized['structuredContent']['authorization_ref']))
        assert replay['structuredContent']['idempotent_replay'] and (len(value.peer.calls),len(value.calls),value.backend.sends)==before
        if fault:
            value.backend.fault=None
            for phase in (PHASES[2],('glass_action',True),('general',True)):
                assert _call(client,headers,PREVIEW,dict(step=phase[0],restore=phase[1]))['isError']
        else:
            for phase in PHASES[2:]: assert rpc_phase(client,headers,phase)[0]['structuredContent']['outcome']=='succeeded'
        before=(len(value.peer.calls),len(value.calls)); outcome=_call(client,headers,OUTCOME,{})['structuredContent']
        assert (len(value.peer.calls),len(value.calls))==before
        assert outcome['workflow_outcome']==('reconciliation_required' if fault else 'verified_locally')
        assert outcome['execution_claims']==(2 if fault else 16) and not outcome['native_backend_qualified'] and not outcome['delivery_verified']
        assert all(marker not in json.dumps((result,replay,outcome)) for marker in (SERIAL,SENDER,RECIPIENT,PRIVATE,'old.cert','Original glass'))


@pytest.mark.parametrize('scopes',['fortipam:read','fortipam:read fortipam:plan'])
def test_missing_oauth_scopes_refuse_before_sources_or_authority(monkeypatch,tmp_path,scopes):
    settings,headers,scope,transport=bootstrap(tmp_path,scopes if 'fortipam:plan' in scopes else 'fortipam:read fortipam:plan fortipam:operate')
    if 'fortipam:plan' not in scopes:
        with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client: headers=_login(client,scopes)
    value=make(monkeypatch,tmp_path,requester=scope.requester_digest,transport=transport)
    with TestClient(create_http_app(settings,v4_email_alert_local_candidate_action=EmailAlertLocalMcpAction(value.workflow)),
            base_url='https://mcp.example.com') as client:
        baseline=len(value.peer.calls); preview=_call(client,headers,PREVIEW,dict(step='general'))
        if 'fortipam:plan' not in scopes: assert preview['isError'] and len(value.peer.calls)==baseline
        else:
            assert not preview['isError']; baseline=len(value.peer.calls)
            assert _call(client,headers,AUTHORIZE,dict(preview_ref=preview['structuredContent']['preview_ref']))['isError']
            assert len(value.peer.calls)==baseline
        assert value.calls==[] and value.store.claim_count==0


def test_scoped_foreign_client_cannot_use_bound_operator_or_outcome(monkeypatch,tmp_path):
    settings,headers,scope,transport=bootstrap(tmp_path); value=make(monkeypatch,tmp_path,requester=scope.requester_digest,transport=transport)
    with TestClient(create_http_app(settings,v4_email_alert_local_candidate_action=EmailAlertLocalMcpAction(value.workflow)),
            base_url='https://mcp.example.com') as client:
        foreign=_login(client,'fortipam:read fortipam:plan fortipam:operate'); before=len(value.peer.calls)
        assert _call(client,foreign,PREVIEW,dict(step='general'))['isError']
        assert _call(client,foreign,OUTCOME,{})['isError']
        assert len(value.peer.calls)==before and value.calls==[] and value.store.claim_count==0


def test_factory_default_profile_and_four_typed_tool_boundaries(monkeypatch,tmp_path):
    settings,headers,scope,transport=bootstrap(tmp_path); value=make(monkeypatch,tmp_path,requester=scope.requester_digest,transport=transport)
    for action in (None,EmailAlertLocalMcpAction(value.workflow)):
        with TestClient(create_http_app(settings,v4_email_alert_local_candidate_action=action),base_url='https://mcp.example.com') as client:
            tools=client.post('/fpamcp',headers=headers,json=dict(jsonrpc='2.0',id='list',method='tools/list',params={})).json()['result']['tools']
            selected={t['name']:t for t in tools if t['name'] in (PREVIEW,AUTHORIZE,EXECUTE,OUTCOME)}
            assert len(selected)==(0 if action is None else 4)
            if action is not None:
                assert set(selected[PREVIEW]['inputSchema']['properties'])=={'step','restore'}
                assert set(selected[AUTHORIZE]['inputSchema']['properties'])=={'preview_ref'}
                assert set(selected[EXECUTE]['inputSchema']['properties'])=={'authorization_ref'}
                assert selected[OUTCOME]['inputSchema'].get('properties',{})=={}
                assert selected[PREVIEW]['annotations']['readOnlyHint'] and selected[OUTCOME]['annotations']['readOnlyHint']
    with pytest.raises(HttpConfigurationError): create_http_app(settings,v4_email_alert_local_candidate_action=object())
    with pytest.raises(HttpConfigurationError):
        create_http_app(replace(settings,runtime_profile=RuntimeProfile.READONLY),v4_email_alert_local_candidate_action=EmailAlertLocalMcpAction(value.workflow))


@contextmanager
def unix_services(root):
    clock=Clock()
    reference_tail=PersistentReferenceCheckpointAuthority(root/'reference-tail.db',owner_file(root/'reference-tail.key',b's'*32),
        authority_ref='email-alert-reference-checkpoint')
    reference=PersistentReferenceAuthority(root/'reference.db',owner_file(root/'reference.key',b'r'*32),authority_ref=REFERENCE,
        monotonic_checkpoint=reference_tail,checkpoint_store_ref='email-alert-reference-state',clock=clock)
    execution=PersistentPlanningCheckpointAuthority(root/'execution-tail.db',owner_file(root/'execution-tail.key',b'z'*32),
        authority_ref='email-alert-execution-checkpoint')
    with ExitStack() as stack:
        sockets=Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='eacp-',dir=Path("/tmp").resolve())))
        stack.enter_context(unix_app(create_reference_authority_sidecar_app(reference),sockets/'r.sock'))
        stack.enter_context(unix_app(create_checkpoint_sidecar_app(execution),sockets/'e.sock'))
        client=UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(sockets/'r.sock',REFERENCE))
        store_ref='email-alert-execution-state'
        store=PersistentM4ExecutionStateStore(root/'execution.db',owner_file(root/'execution.key',b'e'*32),
            monotonic_checkpoint=UnixM4ExecutionCheckpoint(UnixPlanningCheckpointClient(UnixPlanningCheckpointClientSettings(
                sockets/'e.sock',execution.authority_ref)),store_ref),checkpoint_store_ref=store_ref)
        yield reference,client,store


@pytest.mark.parametrize('fault',[None,'lost-ack'])
def test_real_loopback_https_unix_authority_checkpoint_and_normal_mcp(tmp_path,monkeypatch,fault):
    import http.client as http_client
    from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from fortipam_mcp.email_alert_compound_source import EmailAlertCompoundSource
    from fortipam_mcp.email_alert_general_source import EmailAlertGeneralSource
    from fortipam_mcp.email_alert_http_backend import EmailAlertHttpBackend,_route
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from test_email_alert_http_backend import HttpPeer
    from test_secret_bulk_import_action_process import tls_material
    import fortipam_mcp.email_alert_general_source as source_module
    import fortipam_mcp.email_alert_http_backend as http_module

    certificate,key=tls_material(tmp_path); http=HttpPeer(); peer=http.peer; connections=[]; buffers=[]; requests=[]
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self,*_): pass
        def send(self,payload):
            raw=json.dumps(payload).encode(); self.send_response(200); self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw))); self.send_header('Connection','close'); self.end_headers(); self.wfile.write(raw)
        def do_GET(self):
            assert self.headers['Authorization']=='Bearer synthetic-api-token'; requests.append(('GET',self.path)); self.send(peer.payloads[self.path])
        def do_PUT(self):
            assert self.headers['Authorization']=='Bearer synthetic-api-token' and self.path in {_route(phase[0])[0] for phase in PHASES}
            requests.append(('PUT',self.path)); ack=http.mutate(self.path,self.rfile.read(int(self.headers['Content-Length'])))
            if fault and len(http.writes)==2:
                self.close_connection=True; self.connection.shutdown(socket.SHUT_RDWR); self.connection.close(); return
            self.send(ack)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(certificate,key); server.socket=tls.wrap_socket(server.socket,server_side=True)
    thread=Thread(target=server.serve_forever,daemon=True); thread.start()
    def factory(host,port,**kwargs):
        connection=http_client.HTTPSConnection(host,port,**kwargs)
        connection._create_connection=lambda address,timeout,source_address:socket.create_connection(('127.0.0.1',server.server_port),timeout,source_address)
        connections.append(connection); return connection
    receive=source_module._read_alert_response
    def tracked(*args,**kwargs):
        raw=receive(*args,**kwargs); buffers.append(raw); return raw
    monkeypatch.setattr(source_module,'_read_alert_response',tracked); monkeypatch.setattr(http_module,'_read_alert_response',tracked)
    general=EmailAlertGeneralSource(SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-api-token',5,str(certificate)),
        http.prototype._general._scope,expected_serial=SERIAL,expected_schema_digest=http.prototype._general._schema_pin,
        source_digest='a'*64,source_guard=lambda:True,connection_factory=factory,clock=peer.clock)
    source=EmailAlertCompoundSource(general,expected_schema_digests=http.prototype._schema_pins,source_digest='b'*64,source_guard=lambda:True)
    try:
        settings,headers,scope,transport=bootstrap(tmp_path)
        with unix_services(tmp_path) as (reference,client,store):
            value=construct(tmp_path,client,requester=scope.requester_digest,transport=transport,source=source,peer=peer,store=store,
                backend_factory=lambda s,p:EmailAlertHttpBackend(s,p,execution_enabled=lambda:True,source_guard=lambda:True))
            reference.issue_many(tuple((value.policy.reference_for(phase,purpose),'email_alert_'+purpose) for phase in PHASES for purpose in PURPOSES),
                requester_digest=value.requester,environment_ref=ENVIRONMENT,scope_ref=SCOPE_REF,expires_at=1120,now_epoch=1000)
            with TestClient(create_http_app(settings,v4_email_alert_local_candidate_action=EmailAlertLocalMcpAction(value.workflow)),
                    base_url='https://mcp.example.com') as mcp:
                selected=PHASES[:2] if fault else PHASES
                for phase in selected:
                    result,authorized=rpc_phase(mcp,headers,phase)
                    assert result['structuredContent']['outcome']==('reconciliation_required' if fault and phase==PHASES[1] else 'succeeded')
                if fault:
                    assert _call(mcp,headers,PREVIEW,dict(step='general',restore=True))['isError']
                    before=list(requests)
                    assert _call(mcp,headers,EXECUTE,dict(authorization_ref=authorized['structuredContent']['authorization_ref']))['structuredContent']['idempotent_replay']
                    assert requests==before
                before=list(requests); outcome=_call(mcp,headers,OUTCOME,{})['structuredContent']; assert requests==before
                assert outcome['workflow_outcome']==('reconciliation_required' if fault else 'verified_locally')
                assert not outcome['native_backend_qualified'] and not outcome['delivery_verified']
                assert all(marker not in json.dumps(outcome) for marker in (SERIAL,SENDER,RECIPIENT,PRIVATE,'old.cert'))
            assert store.claim_count==len(http.writes)==(2 if fault else 16)
            assert all(connection.sock is None for connection in connections) and all(not any(raw) for raw in buffers)
            if not fault: assert source.read().state.digest==value.session._initial.baseline.digest
    finally:
        source.close(); general.close(); server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
