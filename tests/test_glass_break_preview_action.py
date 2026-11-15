"""Optional fixed readonly MCP preview over a synthetic borrowed Owner window."""
from dataclasses import replace
import json

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.glass_break_preview_action import GlassBreakPreviewAction
from fortipam_mcp.http_server import create_http_app,HttpConfigurationError
from fortipam_mcp.runtime_profile import RuntimeProfile
from test_fortitoken_local_preview_action import bootstrap
from test_ldap_server_mcp_action import _call,_login
from test_glass_break_source import candidate,construct,Peer,COOKIE
from test_glass_break_contract import ACTOR,SERIAL,PRIVATE,REASON
from fortipam_mcp.glass_break_contract import STATE_PATH

TOOL='preview_v4_glass_break_local_700'


def action_for(source,principal):
    return GlassBreakPreviewAction(source,requester_digest=principal.requester.digest,transport_digest=principal.transport_namespace_digest)


def test_fixed_no_input_preview_rejects_reason_account_endpoint_and_authority(candidate,tmp_path):
    settings,headers,principal=bootstrap(tmp_path); peer,source,owner=candidate()
    with TestClient(create_http_app(settings,v4_glass_break_preview_action=action_for(source,principal)),base_url='https://mcp.example.com') as client:
        for field in ('reason','comments','actor','role','endpoint','incident','activate','deactivate','cookie','password'):
            result=_call(client,headers,TOOL,{field:'SYNTHETIC_FORBIDDEN_INPUT'})
            assert result['isError'] and 'SYNTHETIC_FORBIDDEN_INPUT' not in json.dumps(result)
        assert peer.calls==[] and peer.credentials==0
        result=_call(client,headers,TOOL,{}); assert not result['isError']; public=result['structuredContent']
        assert public['source_state_read_locally'] and public['source_role_shape_pin_matched']
        assert not public['activation_ready'] and not public['execution_authorized'] and not public['activation_sent']
        assert not public['native_subject_or_session_scope_verified'] and not public['native_ack_qualified']
        assert peer.calls==[('GET',STATE_PATH)] and not owner.logout_verified
        assert all(marker not in json.dumps(result) for marker in (ACTOR,SERIAL,PRIVATE,REASON,COOKIE))
        tools=client.post('/fpamcp',headers=headers,json=dict(jsonrpc='2.0',id='list',method='tools/list',params={})).json()['result']['tools']
        selected=[tool for tool in tools if tool['name']==TOOL]
        assert len(selected)==1 and selected[0]['inputSchema'].get('properties',{})=={} and selected[0]['annotations']['readOnlyHint']


@pytest.mark.parametrize('fault',['read-scope','foreign-client','source-gate','active-mode'])
def test_wrong_principal_scope_gate_or_active_view_never_produces_activation_draft(candidate,tmp_path,fault):
    settings,headers,principal=bootstrap(tmp_path); peer,source,owner=candidate(guarded=fault!='source-gate')
    if fault=='active-mode': peer.body['results']['admin']['promoted_admin']=True
    with TestClient(create_http_app(settings,v4_glass_break_preview_action=action_for(source,principal)),base_url='https://mcp.example.com') as client:
        if fault in ('read-scope','foreign-client'): headers=_login(client,'fortipam:read' if fault=='read-scope' else 'fortipam:read fortipam:plan')
        assert _call(client,headers,TOOL,{})['isError']
        assert peer.calls==([('GET',STATE_PATH)] if fault=='active-mode' else []) and peer.credentials==0
        assert source._plan is None


def test_default_factory_and_wrong_profile_or_action_type_keep_preview_unloaded(candidate,tmp_path):
    settings,headers,principal=bootstrap(tmp_path); peer,source,owner=candidate()
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client:
        tools=client.post('/fpamcp',headers=headers,json=dict(jsonrpc='2.0',id='list',method='tools/list',params={})).json()['result']['tools']
        assert TOOL not in {tool['name'] for tool in tools}
    with pytest.raises(HttpConfigurationError): create_http_app(settings,v4_glass_break_preview_action=object())
    with pytest.raises(HttpConfigurationError):
        create_http_app(replace(settings,runtime_profile=RuntimeProfile.READONLY),v4_glass_break_preview_action=action_for(source,principal))
    assert peer.calls==[]


def test_real_loopback_cookie_https_and_normal_oauth_mcp_perform_only_one_get(tmp_path):
    import http.client
    from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from test_secret_bulk_import_action_process import tls_material

    certificate,key=tls_material(tmp_path); peer=Peer(); requests=[]; connections=[]; buffers=[]
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self,*_): pass
        def do_GET(self):
            assert self.path==STATE_PATH and self.headers['Cookie']==COOKIE and self.headers.get('Authorization') is None
            requests.append(('GET',self.path)); raw=json.dumps(peer.body).encode()
            self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(raw)))
            self.send_header('Connection','close'); self.end_headers(); self.wfile.write(raw)
        def do_POST(self): requests.append(('POST',self.path)); self.send_error(405)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(certificate,key); server.socket=tls.wrap_socket(server.socket,server_side=True)
    thread=Thread(target=server.serve_forever,daemon=True); thread.start()
    def factory(host,port,**kwargs):
        connection=http.client.HTTPSConnection(host,port,**kwargs)
        connection._create_connection=lambda address,timeout,source_address:socket.create_connection(('127.0.0.1',server.server_port),timeout,source_address)
        connections.append(connection); return connection
    source=owner=None
    try:
        source,owner=construct(peer,config=SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-unused-bearer',5,str(certificate)),
            connection_factory=factory)
        fetch=source._fetch
        def tracked(*args,**kwargs):
            raw=fetch(*args,**kwargs); buffers.append(raw); return raw
        source._fetch=tracked
        settings,headers,principal=bootstrap(tmp_path)
        with TestClient(create_http_app(settings,v4_glass_break_preview_action=action_for(source,principal)),base_url='https://mcp.example.com') as mcp:
            result=_call(mcp,headers,TOOL,{}); assert not result['isError']
            assert not result['structuredContent']['activation_sent'] and not result['structuredContent']['access_elevated']
            assert requests==[('GET',STATE_PATH)] and peer.credentials==0 and not owner.logout_verified
            assert all(connection.sock is None for connection in connections) and all(not any(raw) for raw in buffers)
            assert all(marker not in json.dumps(result) for marker in (ACTOR,SERIAL,PRIVATE,REASON,COOKIE))
    finally:
        if source is not None: source.close(); assert not any(source._cookie)
        if owner is not None:
            owner._client=None
            if owner._session_lock.locked(): owner._session_lock.release()
        server.shutdown(); server.server_close(); thread.join(timeout=2); assert not thread.is_alive()
