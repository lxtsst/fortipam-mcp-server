"""Normal OAuth/MCP fixed preview; synthetic C4 identities stay inside the source."""
from dataclasses import replace
import json

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.email_alert_general_preview_action import EmailAlertGeneralPreviewAction
from fortipam_mcp.http_server import create_http_app,HttpConfigurationError
from fortipam_mcp.runtime_profile import RuntimeProfile
from test_fortitoken_local_preview_action import bootstrap
from test_ldap_server_mcp_action import _call,_login
from test_email_alert_general_source import candidate,SCHEMA_PATH,CURRENT_PATH
from test_email_alert_general_contract import SENDER,RECIPIENT,SERIAL,PRIVATE

TOOL = 'preview_v4_email_alert_general_local_700'


def action_for(source,principal):
    return EmailAlertGeneralPreviewAction(source,requester_digest=principal.requester.digest,
        transport_digest=principal.transport_namespace_digest)


def test_fixed_no_input_mcp_preview_excludes_mail_identity_and_execution(monkeypatch,tmp_path):
    settings,headers,principal = bootstrap(tmp_path); peer,source,schema,row = candidate()
    with TestClient(create_http_app(settings,v4_email_alert_general_preview_action=action_for(source,principal)),
            base_url='https://mcp.example.com') as client:
        for field in ('sender','recipient','endpoint','body','emailAlertOn','password'):
            result = _call(client,headers,TOOL,{field:'SYNTHETIC_FORBIDDEN_VALUE'})
            assert result['isError'] and 'SYNTHETIC_FORBIDDEN_VALUE' not in json.dumps(result)
        assert peer.calls == []
        result = _call(client,headers,TOOL,{}); assert not result['isError']; public = result['structuredContent']
        assert public['source_configuration_observed_locally'] and not public['execution_authorized']
        assert not public['native_put_qualified'] and not public['global_master_state_verified'] and not public['delivery_verified']
        assert peer.calls == [('GET',SCHEMA_PATH),('GET',CURRENT_PATH)]
        assert all(marker not in json.dumps(result) for marker in (SENDER,RECIPIENT,row['username'],SERIAL,PRIVATE))
        tools = client.post('/fpamcp',headers=headers,json=dict(jsonrpc='2.0',id='list',method='tools/list',params={})).json()['result']['tools']
        selected = [tool for tool in tools if 'email_alert_general_local' in tool['name']]
        assert len(selected) == 1 and selected[0]['inputSchema'].get('properties',{}) == {}
        assert selected[0]['annotations']['readOnlyHint'] is True


@pytest.mark.parametrize('fault',['read-scope','foreign-client','source-gate'])
def test_missing_plan_wrong_namespace_or_source_gate_refuses_before_read(fault,tmp_path):
    settings,headers,principal = bootstrap(tmp_path); peer,source,schema,row = candidate(guarded=fault != 'source-gate')
    with TestClient(create_http_app(settings,v4_email_alert_general_preview_action=action_for(source,principal)),
            base_url='https://mcp.example.com') as client:
        if fault != 'source-gate': headers = _login(client,'fortipam:read' if fault == 'read-scope' else 'fortipam:read fortipam:plan')
        assert _call(client,headers,TOOL,{})['isError'] and peer.calls == []


def test_default_factory_has_no_general_preview_and_wrong_profile_type_refuses(tmp_path):
    settings,headers,principal = bootstrap(tmp_path); peer,source,schema,row = candidate()
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client:
        tools = client.post('/fpamcp',headers=headers,json=dict(jsonrpc='2.0',id='list',method='tools/list',params={})).json()['result']['tools']
        assert TOOL not in {tool['name'] for tool in tools}
    with pytest.raises(HttpConfigurationError): create_http_app(settings,v4_email_alert_general_preview_action=object())
    with pytest.raises(HttpConfigurationError):
        create_http_app(replace(settings,runtime_profile=RuntimeProfile.READONLY),v4_email_alert_general_preview_action=action_for(source,principal))
    assert peer.calls == []


def test_real_loopback_https_two_gets_and_normal_mcp_preview_never_write_or_send(tmp_path):
    import http.client
    from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from fortipam_mcp.email_alert_general_source import EmailAlertGeneralSource
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from test_secret_bulk_import_action_process import tls_material

    certificate,key = tls_material(tmp_path); peer,prototype,schema,row = candidate(); connections = []; buffers = []; requests = []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self,*_): pass
        def do_GET(self):
            assert self.path in (SCHEMA_PATH,CURRENT_PATH) and self.headers['Authorization'] == 'Bearer synthetic-api-token'
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
    source = EmailAlertGeneralSource(SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-api-token',5,str(certificate)),
        prototype._scope,expected_serial=SERIAL,expected_schema_digest=prototype._schema_pin,source_digest='a'*64,
        source_guard=lambda:True,connection_factory=factory,clock=peer.clock)
    fetch = source._fetch
    def tracked(*args,**kwargs):
        raw = fetch(*args,**kwargs); buffers.append(raw); return raw
    source._fetch = tracked
    try:
        settings,headers,principal = bootstrap(tmp_path)
        with TestClient(create_http_app(settings,v4_email_alert_general_preview_action=action_for(source,principal)),
                base_url='https://mcp.example.com') as client:
            result = _call(client,headers,TOOL,{}); assert not result['isError']
            assert not result['structuredContent']['native_put_qualified'] and not result['structuredContent']['delivery_verified']
            assert requests == [('GET',SCHEMA_PATH),('GET',CURRENT_PATH)]
            assert all(connection.sock is None for connection in connections) and all(not any(raw) for raw in buffers)
            assert all(marker not in json.dumps(result) for marker in (SENDER,RECIPIENT,row['username'],SERIAL,PRIVATE))
    finally:
        source.close(); server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
