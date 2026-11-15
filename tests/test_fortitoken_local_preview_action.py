"""Factory-only readonly FortiToken previews through real OAuth/MCP handling."""
import asyncio
from dataclasses import replace
import json

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.fortitoken_local_preview_action import FortitokenLocalPreviewAction
from fortipam_mcp.fortitoken_user_source import FortitokenUserSource, SCHEMA_PATH
from fortipam_mcp.http_server import create_http_app, HttpConfigurationError
from fortipam_mcp.local_oauth import LocalOAuthProvider
from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
from test_fortitoken_user_contract import binding, NAME, SERIAL, TOKEN
from test_fortitoken_user_source import Peer
from test_ldap_server_mcp_action import _settings, _login, _call

TOOLS = {'preview_v4_fortitoken_local_assign_700','preview_v4_fortitoken_local_revoke_700'}


def bootstrap(root):
    settings = _settings(root)
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client:
        headers = _login(client,'fortipam:read fortipam:plan')
    token = asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(headers['authorization'].split(' ',1)[1]))
    principal = planning_principal_from_access_token(token,settings.v4_planning_authorization)
    return settings,headers,principal


def action_for(source,principal,inventory_source=None,binding_source=None):
    return FortitokenLocalPreviewAction(source,requester_digest=principal.requester.digest,
        transport_digest=principal.transport_namespace_digest,inventory_source=inventory_source,binding_source=binding_source)


@pytest.mark.parametrize('operation', ['assign','revoke'])
def test_normal_mcp_preview_is_source_bound_private_and_readonly(tmp_path, operation):
    settings,headers,principal = bootstrap(tmp_path); peer = Peer(operation); source = peer.reader()
    with TestClient(create_http_app(settings,v4_fortitoken_local_preview_action=action_for(source,principal)),
            base_url='https://mcp.example.com') as client:
        for key in ('token','user','endpoint','body'):
            result = _call(client,headers,'preview_v4_fortitoken_local_'+operation+'_700',{key:'SYNTHETIC_PRIVATE_INPUT'})
            assert result['isError'] and 'SYNTHETIC_PRIVATE_INPUT' not in json.dumps(result)
        assert peer.calls == []
        result = _call(client,headers,'preview_v4_fortitoken_local_'+operation+'_700',{})
        public = result['structuredContent']; assert not result['isError']
        assert public['configuration_observed_locally'] and not public['source_qualified']
        assert not public['native_backend_qualified'] and not public['configuration_write_authorized']
        assert not public['complete_postcondition_qualified'] and not public['mfa_login_verified']
        assert peer.calls == [SCHEMA_PATH,peer.detail]
        for value in (NAME,SERIAL,TOKEN.decode('ascii'),'a'*64): assert value not in json.dumps(public)
        listing = client.post('/fpamcp',headers=headers,json=dict(jsonrpc='2.0',id='list',method='tools/list',params={})).json()['result']['tools']
        added = [tool for tool in listing if '_fortitoken_local_' in tool['name']]
        assert {tool['name'] for tool in added} == TOOLS and all(tool['annotations']['readOnlyHint'] for tool in added)
        assert all(tool['inputSchema'].get('properties',{}) == {} for tool in added)
        assert not any(tool['name'].startswith(('execute_v4_fortitoken','authorize_v4_fortitoken')) for tool in listing)
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('fault', ['read-scope','foreign-client','source-gate','wrong-transition'])
def test_scope_identity_source_or_transition_failure_never_produces_readiness(tmp_path, fault):
    settings,headers,principal = bootstrap(tmp_path); peer = Peer(); source = peer.reader(guarded=fault != 'source-gate')
    with TestClient(create_http_app(settings,v4_fortitoken_local_preview_action=action_for(source,principal)),
            base_url='https://mcp.example.com') as client:
        if fault in ('read-scope','foreign-client'):
            headers = _login(client,'fortipam:read' if fault == 'read-scope' else 'fortipam:read fortipam:plan')
        name = 'preview_v4_fortitoken_local_'+('revoke' if fault == 'wrong-transition' else 'assign')+'_700'
        result = _call(client,headers,name,{})
        assert result['isError'] and NAME not in json.dumps(result) and TOKEN.decode('ascii') not in json.dumps(result)
        assert bool(peer.calls) is (fault == 'wrong-transition')


@pytest.mark.parametrize('invalid', ['readonly','plan-only','bearer','authority','type'])
def test_factory_requires_explicit_controlled_oauth_preview(tmp_path, invalid):
    settings,_,principal = bootstrap(tmp_path); peer = Peer(); action = action_for(peer.reader(),principal)
    if invalid == 'readonly': settings = replace(settings,runtime_profile=RuntimeProfile.READONLY)
    elif invalid == 'plan-only': settings = replace(settings,runtime_profile=RuntimeProfile.V4_PLAN_ONLY)
    elif invalid == 'bearer': settings = replace(settings,auth_mode='bearer',bearer_token='synthetic-token')
    elif invalid == 'authority': settings = replace(settings,v4_planning_authorization=None)
    else: action = object()
    with pytest.raises(HttpConfigurationError): create_http_app(settings,v4_fortitoken_local_preview_action=action)
    assert peer.calls == []


def test_default_app_has_no_local_preview_tools(tmp_path):
    settings,headers,_ = bootstrap(tmp_path)
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client:
        result = client.post('/fpamcp',headers=headers,json=dict(jsonrpc='2.0',id='list',method='tools/list',params={})).json()
        assert not any('_fortitoken_local_' in tool['name'] for tool in result['result']['tools'])


@pytest.mark.parametrize('operation', ['assign','revoke'])
def test_optional_inventory_reuses_existing_readonly_tools_without_qualifying_execution(tmp_path,operation):
    from fortipam_mcp.fortitoken_inventory_source import FortitokenInventorySource, INVENTORY_PATH
    from test_fortitoken_inventory_source import envelope
    settings,headers,principal = bootstrap(tmp_path); peer = Peer(operation); source = peer.reader()
    peer.payloads[INVENTORY_PATH] = envelope(disclosed=False)
    inventory = FortitokenInventorySource(source,source_digest='d'*64,source_guard=lambda:True)
    with TestClient(create_http_app(settings,v4_fortitoken_local_preview_action=action_for(source,principal,inventory)),
            base_url='https://mcp.example.com') as client:
        result = _call(client,headers,'preview_v4_fortitoken_local_'+operation+'_700',{})
        assert not result['isError']; public = result['structuredContent']; aggregate = public['Inventory Observation']
        assert aggregate['token_count'] == 2 and aggregate['license_field_count'] == 1
        assert not aggregate['counts_reported_for_each_view'] and not aggregate['no_truncation_reported_for_each_view']
        assert not aggregate['license_validity_verified'] and not aggregate['complete_inventory_qualified']
        assert not aggregate['token_ownership_verified'] and not public['configuration_write_authorized']
        assert peer.calls == [SCHEMA_PATH,peer.detail,INVENTORY_PATH]
        text = json.dumps(public)
        assert 'SYNTHETIC_PRIVATE' not in text and NAME not in text and TOKEN.decode() not in text and SERIAL not in text


def test_inventory_from_another_source_object_is_not_adopted_by_equal_configuration(tmp_path):
    from fortipam_mcp.fortitoken_inventory_source import FortitokenInventorySource
    settings,headers,principal = bootstrap(tmp_path); peer = Peer(); source = peer.reader()
    foreign = FortitokenInventorySource(peer.reader(),source_digest='d'*64,source_guard=lambda:True)
    with pytest.raises(ValueError,match='unavailable'): action_for(source,principal,foreign)
    assert peer.calls == []


@pytest.mark.parametrize('fault', ['inventory-gate','incomplete','total-deadline','expired-user-read'])
def test_inventory_failure_never_returns_partial_user_preview_or_renewed_read_budget(tmp_path,fault):
    from fortipam_mcp.fortitoken_inventory_source import FortitokenInventorySource, INVENTORY_PATH
    from test_fortitoken_inventory_source import envelope
    settings,headers,principal = bootstrap(tmp_path); peer = Peer(); source = peer.reader()
    peer.payloads[INVENTORY_PATH] = envelope(); inventory = FortitokenInventorySource(source,source_digest='d'*64,
        source_guard=None if fault == 'inventory-gate' else lambda:True)
    if fault == 'incomplete': peer.payloads[INVENTORY_PATH]['limit_reached'] = True
    elif fault in ('total-deadline','expired-user-read'):
        factory = source._factory
        def changed(*args,**kwargs):
            connection = factory(*args,**kwargs); connect = connection.connect
            def delayed():
                connect()
                if fault == 'total-deadline': peer.time += 2
                elif len(peer.calls) == 2: peer.clock.value = 1011
            connection.connect = delayed; return connection
        source._factory = changed
    with TestClient(create_http_app(settings,v4_fortitoken_local_preview_action=action_for(source,principal,inventory)),
            base_url='https://mcp.example.com') as client:
        result = _call(client,headers,'preview_v4_fortitoken_local_assign_700',{})
        assert result['isError'] and 'Inventory Observation' not in json.dumps(result) and NAME not in json.dumps(result)
    assert peer.calls[:2] == [SCHEMA_PATH,peer.detail] and source._deadline_cap is None
    if fault == 'total-deadline': assert peer.calls == [SCHEMA_PATH,peer.detail]
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('operation', ['assign','revoke'])
def test_optional_visible_binding_join_reuses_existing_preview_without_owner_or_execution_claim(tmp_path,operation):
    from fortipam_mcp.fortitoken_binding_source import USER_BINDINGS_PATH
    from fortipam_mcp.fortitoken_inventory_source import INVENTORY_PATH
    from test_fortitoken_binding_source import candidate
    settings,headers,principal = bootstrap(tmp_path); peer,source,_,inventory,bindings = candidate(operation,baseline=False)
    with TestClient(create_http_app(settings,v4_fortitoken_local_preview_action=action_for(source,principal,binding_source=bindings)),
            base_url='https://mcp.example.com') as client:
        result = _call(client,headers,'preview_v4_fortitoken_local_'+operation+'_700',{})
        assert not result['isError']; public = result['structuredContent']; joined = public['User Binding Observation']
        assert joined['visible_user_count'] == 5 and joined['selected_user_mfa_projection_matches_detail']
        assert joined['bindings_to_observed_inventory_count'] == (2 if operation == 'assign' else 3)
        assert not joined['product_actor_verified'] and not joined['global_unassigned_ownership_verified']
        assert not joined['atomic_snapshot_qualified'] and not joined['configuration_write_authorized']
        assert not public['source_qualified'] and not public['configuration_write_authorized']
        assert public['Inventory Observation']['token_count'] == 2
        assert peer.calls == [SCHEMA_PATH,peer.detail,USER_BINDINGS_PATH,INVENTORY_PATH]
        text = json.dumps(public)
        assert 'SYNTHETIC_PRIVATE' not in text and NAME not in text and TOKEN.decode() not in text and SERIAL not in text


@pytest.mark.parametrize('fault', ['foreign-user-source','different-inventory','type'])
def test_binding_source_cannot_adopt_another_physical_preview_source(tmp_path,fault):
    from fortipam_mcp.fortitoken_inventory_source import FortitokenInventorySource
    from test_fortitoken_binding_source import candidate
    settings,headers,principal = bootstrap(tmp_path); peer,source,_,inventory,bindings = candidate(baseline=False)
    if fault == 'foreign-user-source': source = peer.reader()
    elif fault == 'different-inventory': inventory = FortitokenInventorySource(source,source_digest='f'*64,source_guard=lambda:True)
    else: bindings = object()
    with pytest.raises(ValueError,match='unavailable'): action_for(source,principal,inventory,bindings)
    assert peer.calls == []


@pytest.mark.parametrize('fault', ['binding-gate','counts','ignored-format','selected-drift','total-deadline'])
def test_binding_failure_never_publishes_partial_counts_or_reopens_four_read_budget(tmp_path,fault):
    from fortipam_mcp.fortitoken_binding_source import USER_BINDINGS_PATH
    from test_fortitoken_binding_source import candidate
    settings,headers,principal = bootstrap(tmp_path)
    peer,source,_,inventory,bindings = candidate(baseline=False,guarded=fault != 'binding-gate')
    if fault == 'counts': peer.payloads[USER_BINDINGS_PATH]['matched_count'] = 6
    elif fault == 'ignored-format': peer.payloads[USER_BINDINGS_PATH]['results'][0]['password'] = 'SYNTHETIC_PRIVATE_PASSWORD'
    elif fault == 'selected-drift': peer.payloads[USER_BINDINGS_PATH]['results'][0]['fortitoken'] = TOKEN.decode()
    elif fault == 'total-deadline':
        factory = source._factory
        def changed(*args,**kwargs):
            connection = factory(*args,**kwargs); connect = connection.connect
            def delayed(): connect(); peer.time += 1.5
            connection.connect = delayed; return connection
        source._factory = changed
    with TestClient(create_http_app(settings,v4_fortitoken_local_preview_action=action_for(source,principal,binding_source=bindings)),
            base_url='https://mcp.example.com') as client:
        result = _call(client,headers,'preview_v4_fortitoken_local_assign_700',{})
        assert result['isError'] and 'User Binding Observation' not in json.dumps(result) and NAME not in json.dumps(result)
    assert peer.calls[:2] == [SCHEMA_PATH,peer.detail] and source._deadline_cap is None
    if fault == 'total-deadline': assert peer.calls == [SCHEMA_PATH,peer.detail,USER_BINDINGS_PATH]
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('operation', ['assign','revoke'])
def test_real_loopback_https_reader_and_normal_oauth_mcp_preview(tmp_path, operation):
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from test_secret_bulk_import_action_process import tls_material

    certificate,key = tls_material(tmp_path); peer = Peer(operation); requests = []; connections = []; buffers = []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self,*_): pass
        def do_GET(self):
            assert self.headers['Authorization'] == 'Bearer synthetic-api-token'
            assert self.path in (SCHEMA_PATH,peer.detail)
            requests.append(('GET',self.path)); raw = json.dumps(peer.payloads[self.path]).encode()
            self.send_response(200); self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw))); self.send_header('Connection','close')
            self.end_headers(); self.wfile.write(raw)
        def do_POST(self):
            requests.append(('POST',self.path)); self.send_error(405)
    server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(certificate,key)
    server.socket = tls.wrap_socket(server.socket,server_side=True)
    thread = Thread(target=server.serve_forever,daemon=True); thread.start()
    def factory(host,port,**kwargs):
        connection = http.client.HTTPSConnection(host,port,**kwargs)
        connection._create_connection = lambda address, timeout, source_address: socket.create_connection(
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
        settings,headers,principal = bootstrap(tmp_path)
        with TestClient(create_http_app(settings,v4_fortitoken_local_preview_action=action_for(source,principal)),
                base_url='https://mcp.example.com') as client:
            result = _call(client,headers,'preview_v4_fortitoken_local_'+operation+'_700',{})
            assert not result['isError'] and result['structuredContent']['configuration_observed_locally']
            assert not result['structuredContent']['configuration_write_authorized']
            assert requests == [('GET',SCHEMA_PATH),('GET',peer.detail)]
            assert all(connection.sock is None for connection in connections) and all(not any(raw) for raw in buffers)
            assert NAME not in json.dumps(result) and TOKEN.decode('ascii') not in json.dumps(result)
    finally:
        source.close(); server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()


@pytest.mark.parametrize('operation,wrapped,include_bindings', [
    pytest.param('assign',False,False,id='inventory-assign'),pytest.param('revoke',True,False,id='inventory-revoke'),
    pytest.param('assign',False,True,id='bindings-assign'),pytest.param('revoke',True,True,id='bindings-revoke')])
def test_real_loopback_https_inventory_and_normal_oauth_mcp_preview(tmp_path,operation,wrapped,include_bindings):
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from fortipam_mcp.fortitoken_inventory_source import FortitokenInventorySource, INVENTORY_PATH
    from fortipam_mcp.fortitoken_binding_source import FortitokenBindingSource, USER_BINDINGS_PATH
    from test_fortitoken_binding_source import envelope as user_envelope
    from test_fortitoken_inventory_source import envelope
    from test_secret_bulk_import_action_process import tls_material

    certificate,key = tls_material(tmp_path); peer = Peer(operation); requests = []; connections = []; buffers = []
    peer.payloads[INVENTORY_PATH] = [envelope()] if wrapped else envelope(disclosed=False)
    if include_bindings: peer.payloads[USER_BINDINGS_PATH] = user_envelope(peer)
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self,*_): pass
        def do_GET(self):
            assert self.path in ((SCHEMA_PATH,peer.detail,USER_BINDINGS_PATH,INVENTORY_PATH) if include_bindings
                else (SCHEMA_PATH,peer.detail,INVENTORY_PATH))
            assert self.headers['Authorization'] == 'Bearer synthetic-api-token'
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
    receive = source._receive
    def tracked(*args,**kwargs):
        raw = receive(*args,**kwargs); buffers.append(raw); return raw
    source._receive = tracked
    inventory = FortitokenInventorySource(source,source_digest='d'*64,source_guard=lambda:True)
    bindings = FortitokenBindingSource(inventory,source_digest='e'*64,source_guard=lambda:True) if include_bindings else None
    try:
        settings,headers,principal = bootstrap(tmp_path)
        with TestClient(create_http_app(settings,v4_fortitoken_local_preview_action=action_for(source,principal,inventory,bindings)),
                base_url='https://mcp.example.com') as client:
            result = _call(client,headers,'preview_v4_fortitoken_local_'+operation+'_700',{})
            assert not result['isError']; public = result['structuredContent']; aggregate = public['Inventory Observation']
            assert aggregate['token_count'] == 2 and aggregate['license_field_count'] == 1
            assert aggregate['counts_reported_for_each_view'] is wrapped
            assert aggregate['no_truncation_reported_for_each_view'] is wrapped
            assert not aggregate['complete_inventory_qualified'] and not aggregate['license_validity_verified']
            assert not aggregate['token_ownership_verified'] and not public['configuration_write_authorized']
            expected = [('GET',SCHEMA_PATH),('GET',peer.detail)]
            if include_bindings:
                expected.append(('GET',USER_BINDINGS_PATH)); joined = public['User Binding Observation']
                assert joined['visible_user_count'] == 5 and joined['selected_user_mfa_projection_matches_detail']
                assert not joined['product_actor_verified'] and not joined['global_unassigned_ownership_verified']
                assert not joined['exact_selected_selector_continuity_verified'] and not joined['atomic_snapshot_qualified']
            expected.append(('GET',INVENTORY_PATH)); assert requests == expected
            assert all(connection.sock is None for connection in connections) and all(not any(raw) for raw in buffers)
            text = json.dumps(public)
            assert 'SYNTHETIC_PRIVATE' not in text and NAME not in text and SERIAL not in text and TOKEN.decode() not in text
    finally:
        if bindings is not None: bindings.close()
        inventory.close(); source.close(); server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
