"""Normal OAuth/MCP readonly JIT previews, with private fixed source inputs."""
from dataclasses import replace
import json

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.http_server import create_http_app, HttpConfigurationError
from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp.windows_jit_script_preview_action import WindowsJitScriptPreviewAction
from test_fortitoken_local_preview_action import bootstrap
from test_ldap_server_mcp_action import _call, _login
from test_windows_jit_script_source import Peer, NONCE, SERIAL, PRIVATE, SCHEMA_PATH, DEFAULT_PATH, COLLECTION_PATH

TOOL = 'preview_v4_windows_jit_script_pair_local_700'
SECRET_TOOL = 'preview_v4_windows_jit_secret_local_700'


def action_for(source,principal,secret_source=None):
    return WindowsJitScriptPreviewAction(source,requester_digest=principal.requester.digest,
        transport_digest=principal.transport_namespace_digest,secret_source=secret_source)


def test_normal_mcp_reads_only_fixed_pair_and_no_command_or_material_input(tmp_path):
    settings,headers,principal = bootstrap(tmp_path); peer = Peer(); source = peer.source()
    with TestClient(create_http_app(settings,v4_windows_jit_script_preview_action=action_for(source,principal)),
            base_url='https://mcp.example.com') as client:
        for field in ('nonce','script','user','group','target','credential','endpoint'):
            result = _call(client,headers,TOOL,{field:'SYNTHETIC_FORBIDDEN_INPUT'})
            assert result['isError'] and 'SYNTHETIC_FORBIDDEN_INPUT' not in json.dumps(result)
        assert peer.calls == []
        result = _call(client,headers,TOOL,{}); assert not result['isError']; public = result['structuredContent']
        assert public['candidate_names_absent_in_visible_view'] and not public['configuration_ready']
        assert not public['execution_authorized'] and not public['product_actor_verified']
        assert not public['global_namespace_qualified'] and not public['jit_privilege_effect_verified']
        assert peer.calls == [('GET',SCHEMA_PATH),('GET',DEFAULT_PATH),('POST',COLLECTION_PATH),*[('GET',path) for path in peer.details]]
        listing = client.post('/fpamcp',headers=headers,json=dict(jsonrpc='2.0',id='list',method='tools/list',params={})).json()['result']['tools']
        tools = [tool for tool in listing if 'windows_jit' in tool['name']]
        assert len(tools) == 1 and tools[0]['name'] == TOOL and tools[0]['annotations']['readOnlyHint']
        assert tools[0]['inputSchema'].get('properties',{}) == {}
        text = json.dumps(public)
        assert all(value not in text for value in (NONCE,SERIAL,PRIVATE.decode(),'$USER','synthetic-unrelated-script'))


@pytest.mark.parametrize('fault', ['read-scope','foreign-client','source-gate','existing-pair'])
def test_actor_scope_source_and_existing_objects_never_derive_new_pair_authority(tmp_path,fault):
    settings,headers,principal = bootstrap(tmp_path); peer = Peer(2 if fault == 'existing-pair' else 0)
    source = peer.source(guarded=fault != 'source-gate')
    with TestClient(create_http_app(settings,v4_windows_jit_script_preview_action=action_for(source,principal)),
            base_url='https://mcp.example.com') as client:
        if fault in ('read-scope','foreign-client'):
            headers = _login(client,'fortipam:read' if fault == 'read-scope' else 'fortipam:read fortipam:plan')
        result = _call(client,headers,TOOL,{})
        assert result['isError'] and PRIVATE.decode() not in json.dumps(result)
        assert bool(peer.calls) is (fault == 'existing-pair')


@pytest.mark.parametrize('invalid', ['readonly','plan-only','bearer','authority','type'])
def test_factory_accepts_only_explicit_controlled_local_oauth_preview(tmp_path,invalid):
    settings,headers,principal = bootstrap(tmp_path); peer = Peer(); action = action_for(peer.source(),principal)
    if invalid == 'readonly': settings = replace(settings,runtime_profile=RuntimeProfile.READONLY)
    elif invalid == 'plan-only': settings = replace(settings,runtime_profile=RuntimeProfile.V4_PLAN_ONLY)
    elif invalid == 'bearer': settings = replace(settings,auth_mode='bearer',bearer_token='synthetic-token')
    elif invalid == 'authority': settings = replace(settings,v4_planning_authorization=None)
    else: action = object()
    with pytest.raises(HttpConfigurationError): create_http_app(settings,v4_windows_jit_script_preview_action=action)
    assert peer.calls == []


def test_default_startup_registers_no_local_jit_candidate(tmp_path):
    settings,headers,principal = bootstrap(tmp_path)
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client:
        result = client.post('/fpamcp',headers=headers,json=dict(jsonrpc='2.0',id='list',method='tools/list',params={})).json()['result']['tools']
        assert not any('windows_jit' in tool['name'] for tool in result)


def test_normal_mcp_secret_preview_reads_fixed_seven_without_material_or_command_arguments(tmp_path):
    from test_windows_jit_secret_source import candidate
    from test_windows_jit_secret_contract import SECRET
    settings,headers,principal = bootstrap(tmp_path); peer,scripts,source,schema,row = candidate()
    with TestClient(create_http_app(settings,v4_windows_jit_script_preview_action=action_for(scripts,principal,source)),
            base_url='https://mcp.example.com') as client:
        for field in ('secret_id','script','user','group','credential','schema'):
            result = _call(client,headers,SECRET_TOOL,{field:'SYNTHETIC_FORBIDDEN_INPUT'})
            assert result['isError'] and 'SYNTHETIC_FORBIDDEN_INPUT' not in json.dumps(result)
        assert peer.calls == []
        result = _call(client,headers,SECRET_TOOL,{}); assert not result['isError']; public = result['structuredContent']
        assert public['nonmaterial_configuration_observed_locally'] and public['metadata_patch_only']
        assert not public['configuration_ready'] and not public['execution_authorized']
        assert not public['material_preservation_qualified'] and not public['associated_admin_qualified']
        assert len(peer.calls) == 7 and SECRET not in json.dumps(public)
        listing = client.post('/fpamcp',headers=headers,json=dict(jsonrpc='2.0',id='list',method='tools/list',params={})).json()['result']['tools']
        added = [tool for tool in listing if 'windows_jit' in tool['name']]
        assert {tool['name'] for tool in added} == {TOOL,SECRET_TOOL}
        assert all(tool['annotations']['readOnlyHint'] and tool['inputSchema'].get('properties',{}) == {} for tool in added)


@pytest.mark.parametrize('fault', ['read-scope','foreign-client','secret-gate','already-applied'])
def test_secret_preview_identity_source_or_existing_configuration_cannot_supply_authority(tmp_path,fault):
    from test_windows_jit_secret_source import candidate
    settings,headers,principal = bootstrap(tmp_path); peer,scripts,source,schema,row = candidate(guarded=fault != 'secret-gate')
    if fault == 'already-applied':
        row['checkout'] = 'enable'; row['permissions'].update(checkout_status='required',passwd_change='forbidden')
    with TestClient(create_http_app(settings,v4_windows_jit_script_preview_action=action_for(scripts,principal,source)),
            base_url='https://mcp.example.com') as client:
        if fault in ('read-scope','foreign-client'):
            headers = _login(client,'fortipam:read' if fault == 'read-scope' else 'fortipam:read fortipam:plan')
        result = _call(client,headers,SECRET_TOOL,{})
        assert result['isError'] and bool(peer.calls) is (fault == 'already-applied')


def test_secret_preview_rejects_equal_foreign_script_reader_before_network(tmp_path):
    from test_windows_jit_secret_source import candidate
    settings,headers,principal = bootstrap(tmp_path); peer,scripts,source,schema,row = candidate()
    with pytest.raises(ValueError,match='unavailable'): action_for(peer.source(),principal,source)
    assert peer.calls == []


@pytest.mark.parametrize('present,include_secret,applied', [(0,False,False),(2,False,False),(2,True,False),(2,True,True)])
def test_real_loopback_https_five_reads_and_normal_mcp_never_create_or_adopt_script(tmp_path,present,include_secret,applied):
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from fortipam_mcp.windows_jit_script_source import WindowsJitScriptSource
    from fortipam_mcp.windows_jit_secret_source import WindowsJitSecretSource, SCHEMA_PATH as SECRET_SCHEMA_PATH
    from test_windows_jit_secret_source import candidate
    from test_windows_jit_secret_contract import binding, SECRET
    from test_secret_bulk_import_action_process import tls_material

    certificate,key = tls_material(tmp_path); peer = Peer(present); requests = []; connections = []; buffers = []
    if include_secret:
        peer,_,secret_prototype,schema,row = candidate()
        if applied:
            row.update(checkout='enable',**{'checkout-script':peer.expected[0]['name'],'checkin-script':peer.expected[1]['name'],'checkout-duration':5})
            row['permissions'].update(checkout_status='required',passwd_change='forbidden')
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self,*_): pass
        def send(self):
            payload = peer.payloads[self.path]; raw = json.dumps(payload).encode()
            self.send_response(payload['http_status']); self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw))); self.send_header('Connection','close')
            self.end_headers(); self.wfile.write(raw)
        def do_GET(self):
            assert self.path in ((SCHEMA_PATH,DEFAULT_PATH,*peer.details,SECRET_SCHEMA_PATH,secret_prototype._detail)
                if include_secret else (SCHEMA_PATH,DEFAULT_PATH,*peer.details))
            assert self.headers['Authorization'] == 'Bearer synthetic-api-token'
            requests.append(('GET',self.path)); self.send()
        def do_POST(self):
            assert self.path == COLLECTION_PATH and self.headers['X-HTTP-Method-Override'] == 'GET'
            assert self.headers['Authorization'] == 'Bearer synthetic-api-token'
            assert self.rfile.read(int(self.headers['Content-Length'])) == b'{"json_filter":[]}'
            requests.append(('POST',self.path)); self.send()
        def do_PUT(self): requests.append(('PUT',self.path)); self.send_error(405)
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
    source = WindowsJitScriptSource(SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-api-token',5,str(certificate)),
        nonce=NONCE,expected_serial=SERIAL,expected_schema_digest=peer.pin,source_digest='a'*64,
        source_guard=lambda:True,connection_factory=factory,clock=peer.clock)
    receive = source._receive
    def tracked(*args,**kwargs):
        status,raw = receive(*args,**kwargs); buffers.append(raw); return status,raw
    source._receive = tracked
    secret = WindowsJitSecretSource(source,binding(),expected_schema_digest=secret_prototype._schema_pin,
        source_digest='b'*64,source_guard=lambda:True) if include_secret else None
    try:
        settings,headers,principal = bootstrap(tmp_path)
        with TestClient(create_http_app(settings,v4_windows_jit_script_preview_action=action_for(source,principal,secret)),
                base_url='https://mcp.example.com') as client:
            result = _call(client,headers,SECRET_TOOL if include_secret else TOOL,{})
            expected_error = applied if include_secret else bool(present)
            assert result['isError'] is expected_error
            if not expected_error:
                public = result['structuredContent']
                if include_secret:
                    assert public['nonmaterial_configuration_observed_locally'] and public['metadata_patch_only']
                    assert not public['material_preservation_qualified'] and not public['original_subject_custody_verified']
                else: assert public['candidate_names_absent_in_visible_view'] and not public['global_namespace_qualified']
                assert not public['execution_authorized'] and not public['jit_privilege_effect_verified']
            elif include_secret: assert secret._plan is None
            else: assert source._plan is None and source._latest.present == (True,True)
            expected = [('GET',SCHEMA_PATH),('GET',DEFAULT_PATH),('POST',COLLECTION_PATH),*[('GET',path) for path in peer.details]]
            if include_secret: expected.extend([('GET',SECRET_SCHEMA_PATH),('GET',secret._detail)])
            assert requests == expected
            assert all(connection.sock is None for connection in connections) and all(not any(raw) for raw in buffers)
            text = json.dumps(result)
            assert all(value not in text for value in (NONCE,SERIAL,PRIVATE.decode(),SECRET,'$USER'))
    finally:
        if secret is not None: secret.close()
        source.close(); server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
