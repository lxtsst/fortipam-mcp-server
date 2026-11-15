"""Opt-in compound preview through normal MCP; synthetic fixed HTTPS product."""
import json

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.email_alert_general_preview_action import EmailAlertGeneralPreviewAction
from fortipam_mcp.http_server import create_http_app
from test_email_alert_compound_source import candidate,EXPECTED
from test_email_alert_general_contract import SERIAL,SENDER,RECIPIENT,PRIVATE
from test_fortitoken_local_preview_action import bootstrap
from test_ldap_server_mcp_action import _call,_login

TOOL = 'preview_v4_email_alert_compound_local_700'


def action_for(source,principal):
    return EmailAlertGeneralPreviewAction(source._general,requester_digest=principal.requester.digest,
        transport_digest=principal.transport_namespace_digest,compound_source=source)


def test_normal_mcp_compound_preview_accepts_no_arguments_and_exposes_no_private_identity(tmp_path):
    settings,headers,principal = bootstrap(tmp_path); peer,source,state = candidate()
    with TestClient(create_http_app(settings,v4_email_alert_general_preview_action=action_for(source,principal)),
            base_url='https://mcp.example.com') as client:
        for field in ('sender','recipient','endpoint','body','emailAlertOn','step','restore','password'):
            result = _call(client,headers,TOOL,{field:'SYNTHETIC_FORBIDDEN_VALUE'})
            assert result['isError'] and 'SYNTHETIC_FORBIDDEN_VALUE' not in json.dumps(result)
        assert peer.calls == []
        result = _call(client,headers,TOOL,{}); assert not result['isError']; public = result['structuredContent']
        assert public['fixed_get_count'] == 16 and public['existing_graph_observed_locally']
        assert not public['execution_authorized'] and not public['native_put_qualified'] and not public['delivery_verified']
        assert not public['certificate_merge_qualified'] and not public['critical_graph_native_qualified']
        assert all(marker not in json.dumps(result) for marker in (SERIAL,SENDER,RECIPIENT,PRIVATE,'Original glass','old.cert'))
        assert peer.calls == EXPECTED
        tools = client.post('/fpamcp',headers=headers,json=dict(jsonrpc='2.0',id='list',method='tools/list',params={})).json()['result']['tools']
        selected = [tool for tool in tools if 'email_alert_' in tool['name'] and '_local_' in tool['name']]
        assert {tool['name'] for tool in selected} == {TOOL,'preview_v4_email_alert_general_local_700'}
        assert all(tool['inputSchema'].get('properties',{}) == {} and tool['annotations']['readOnlyHint'] for tool in selected)


@pytest.mark.parametrize('fault',['read-scope','foreign-client','source-gate'])
def test_subject_namespace_scope_and_closed_source_refuse_before_any_get(fault,tmp_path):
    settings,headers,principal = bootstrap(tmp_path); peer,source,state = candidate(guarded=fault != 'source-gate')
    with TestClient(create_http_app(settings,v4_email_alert_general_preview_action=action_for(source,principal)),
            base_url='https://mcp.example.com') as client:
        if fault != 'source-gate': headers = _login(client,'fortipam:read' if fault == 'read-scope' else 'fortipam:read fortipam:plan')
        assert _call(client,headers,TOOL,{})['isError'] and peer.calls == []


def test_compound_factory_refuses_a_different_physical_general_source():
    peer,source,state = candidate(); other = candidate()[1]._general
    with pytest.raises(ValueError,match='unavailable'):
        EmailAlertGeneralPreviewAction(other,requester_digest='1'*64,transport_digest='2'*64,compound_source=source)


def test_existing_general_only_factory_does_not_register_compound_tool(tmp_path):
    settings,headers,principal = bootstrap(tmp_path); peer,source,state = candidate()
    action = EmailAlertGeneralPreviewAction(source._general,requester_digest=principal.requester.digest,
        transport_digest=principal.transport_namespace_digest)
    with TestClient(create_http_app(settings,v4_email_alert_general_preview_action=action),base_url='https://mcp.example.com') as client:
        tools = client.post('/fpamcp',headers=headers,json=dict(jsonrpc='2.0',id='list',method='tools/list',params={})).json()['result']['tools']
        assert TOOL not in {tool['name'] for tool in tools} and peer.calls == []


def test_real_loopback_https_sixteen_gets_and_normal_oauth_mcp_preview(tmp_path,monkeypatch):
    import http.client
    from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from fortipam_mcp.email_alert_compound_source import EmailAlertCompoundSource
    from fortipam_mcp.email_alert_general_source import EmailAlertGeneralSource
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from test_secret_bulk_import_action_process import tls_material
    import fortipam_mcp.email_alert_general_source as general_module
    import fortipam_mcp.email_alert_compound_source as compound_module

    certificate,key = tls_material(tmp_path); peer,prototype,state = candidate(); connections=[]; buffers=[]; requests=[]
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self,*_): pass
        def do_GET(self):
            assert self.path in peer.payloads and self.headers['Authorization'] == 'Bearer synthetic-api-token'
            requests.append(('GET',self.path)); raw = json.dumps(peer.payloads[self.path]).encode()
            self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(raw)))
            self.send_header('Connection','close'); self.end_headers(); self.wfile.write(raw)
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
    fetch = general_module._fetch_fixed_alert
    def tracked(*args,**kwargs):
        raw = fetch(*args,**kwargs); buffers.append(raw); return raw
    monkeypatch.setattr(general_module,'_fetch_fixed_alert',tracked)
    monkeypatch.setattr(compound_module,'_fetch_fixed_alert',tracked)
    general = EmailAlertGeneralSource(SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-api-token',5,str(certificate)),
        prototype._general._scope,expected_serial=SERIAL,expected_schema_digest=prototype._general._schema_pin,source_digest='a'*64,
        source_guard=lambda:True,connection_factory=factory,clock=peer.clock)
    source = EmailAlertCompoundSource(general,expected_schema_digests=prototype._schema_pins,source_digest='b'*64,source_guard=lambda:True)
    try:
        settings,headers,principal = bootstrap(tmp_path)
        with TestClient(create_http_app(settings,v4_email_alert_general_preview_action=action_for(source,principal)),
                base_url='https://mcp.example.com') as client:
            result = _call(client,headers,TOOL,{}); assert not result['isError']
            assert result['structuredContent']['fixed_get_count'] == 16 and requests == EXPECTED
            assert not result['structuredContent']['configuration_written'] and not result['structuredContent']['delivery_verified']
            assert len(buffers) == 16 and all(not any(raw) for raw in buffers) and all(connection.sock is None for connection in connections)
            assert all(marker not in json.dumps(result) for marker in (SERIAL,SENDER,RECIPIENT,PRIVATE,'old.cert','Original glass'))
    finally:
        source.close(); general.close(); server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
