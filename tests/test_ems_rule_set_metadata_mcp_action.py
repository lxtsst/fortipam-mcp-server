"""Optional readonly OAuth/MCP metadata plus synthetic verified-TLS composition."""
from dataclasses import replace
import json

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.ems_rule_set_metadata_mcp_action import EmsRuleSetMetadataAction
from fortipam_mcp.ems_rule_set_metadata_source import EmsRuleSetMetadataSource
from fortipam_mcp.http_server import create_http_app,HttpConfigurationError
from fortipam_mcp.runtime_profile import RuntimeProfile
from test_ems_rule_set_metadata_source import assemble,payload,PRIVATE
from test_fortitoken_local_mcp_action import bootstrap
from test_ldap_server_mcp_action import _call,_login

TOOL='preview_v4_ems_rule_set_metadata_local_748'


@pytest.fixture
def candidate(monkeypatch,tmp_path):
    settings,headers,scope,transport=bootstrap(tmp_path,'fortipam:read fortipam:plan'); value=assemble(tmp_path,monkeypatch)
    action=EmsRuleSetMetadataAction(value.metadata,requester_digest=scope.requester_digest,transport_digest=transport)
    yield settings,headers,value,action
    value.fault[0]=None; value.owner._connect=value.metadata._connect
    action.close(); value.source.close(); value.owner.close()


def test_normal_no_input_mcp_returns_only_types_and_counters_with_no_cleanup_authority(candidate):
    settings,headers,value,action=candidate
    with TestClient(create_http_app(settings,v4_ems_rule_set_metadata_action=action),base_url='https://mcp.example.com') as client:
        before=len(value.connections)
        for key in ('id','tag','path','body','account','token','rules','filters'):
            result=_call(client,headers,TOOL,{key:'SYNTHETIC_FORBIDDEN_INPUT'})
            assert result['isError'] and 'SYNTHETIC_FORBIDDEN_INPUT' not in json.dumps(result)
        assert len(value.connections)==before and not value.metadata._used
        result=_call(client,headers,TOOL,{})
        assert not result['isError']
        public=result['structuredContent']
        assert public['metadata_read_count']==len(value.calls) and not public['cleanup_authorized'] and not public['native_response_contract_verified']
        assert all(text not in json.dumps(result) for text in (PRIVATE,'synthetic_owner','synthetic-only','sessionid','csrftoken'))
        assert value.metadata._closed and not any(value.metadata._cookie) and value.owner._live and not value.source._closed
        before=list(value.calls)
        assert _call(client,headers,TOOL,{})['isError'] and value.calls==before


def test_missing_plan_and_foreign_client_refuse_before_source(candidate):
    settings,_,value,action=candidate
    with TestClient(create_http_app(settings,v4_ems_rule_set_metadata_action=action),base_url='https://mcp.example.com') as client:
        for scopes in ('fortipam:read','fortipam:read fortipam:plan'):
            headers=_login(client,scopes); before=len(value.connections)
            assert _call(client,headers,TOOL,{})['isError']
            assert len(value.connections)==before and not value.metadata._used


def test_factory_default_fixed_schema_and_controlled_oauth_boundary(candidate):
    settings,headers,value,action=candidate
    for option in (None,action):
        with TestClient(create_http_app(settings,v4_ems_rule_set_metadata_action=option),base_url='https://mcp.example.com') as client:
            tools=client.post('/fpamcp',headers=headers,json=dict(jsonrpc='2.0',id='list',method='tools/list',params={})).json()['result']['tools']
            selected=[tool for tool in tools if tool['name']==TOOL]
            assert len(selected)==int(option is not None)
            if option is not None:
                assert selected[0]['inputSchema'].get('properties',{})=={} and selected[0]['annotations']['readOnlyHint']
    assert value.metadata._closed and not any(value.metadata._cookie) and value.owner._live
    with pytest.raises(HttpConfigurationError): create_http_app(settings,v4_ems_rule_set_metadata_action=object())
    with pytest.raises(HttpConfigurationError):
        create_http_app(replace(settings,runtime_profile=RuntimeProfile.READONLY),v4_ems_rule_set_metadata_action=action)
    with pytest.raises(HttpConfigurationError):
        create_http_app(replace(settings,v4_planning_authorization=replace(settings.v4_planning_authorization,insecure_private_ip_lab=True)),
            v4_ems_rule_set_metadata_action=action)
    from fortipam_mcp.ems_tag_mcp_action import EmsTagMcpAction
    with pytest.raises(HttpConfigurationError):
        create_http_app(settings,v4_ems_rule_set_metadata_action=action,v4_ems_tag_candidate_action=object.__new__(EmsTagMcpAction))
    assert not value.metadata._used


@pytest.mark.parametrize('fault',['source','identity'])
def test_action_binding_drift_refuses_before_source(candidate,fault):
    settings,headers,value,action=candidate
    if fault=='source': action._source=object()
    else: action._identity=('f'*64,'e'*64)
    with TestClient(create_http_app(settings,v4_ems_rule_set_metadata_action=action),base_url='https://mcp.example.com') as client:
        before=len(value.connections); result=_call(client,headers,TOOL,{})
        assert result['isError'] and len(value.connections)==before and not value.metadata._used


@pytest.mark.parametrize('fault',[None,'detail-lost-response'])
def test_real_loopback_verified_tls_borrowed_cookie_and_normal_oauth_mcp(tmp_path,monkeypatch,fault):
    import hashlib
    import http.client
    from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from fortipam_mcp.ems_rule_set_contract import INDEX_PATH,rule_set_detail_path
    from fortipam_mcp.ems_tag_contract import DisabledLinuxProcessTag
    from fortipam_mcp.ems_tag_http_transport import EmsTagHttpConfig,NativeEmsTagHttpTransport
    from test_ems_tag_sources import Channel
    from test_ems_tag_contract import envelope
    from test_secret_bulk_import_action_process import tls_material
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    certificate,key=tls_material(tmp_path); channel=Channel(); requests=[]; connections=[]; buffers=[]
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self,*_): pass
        def send(self,data,*,code=200,media='application/json',cookie=None):
            raw=json.dumps(data).encode() if media=='application/json' else data
            self.send_response(code); self.send_header('Content-Type',media); self.send_header('Content-Length',str(len(raw)))
            self.send_header('Connection','close')
            if cookie: self.send_header('Set-Cookie',cookie)
            self.end_headers(); self.wfile.write(raw)
        def do_GET(self):
            requests.append(('GET',self.path)); assert self.headers.get('Authorization') is None
            if self.path=='/': return self.send(b'<html></html>',media='text/html',cookie='csrftoken=SYNTHETIC_CSRF; Path=/; Secure')
            if self.path=='/api/v1/session/check': return self.send(None,code=401)
            assert 'sessionid=SYNTHETIC_SESSION' in self.headers['Cookie']
            if self.path==INDEX_PATH: return self.send(payload({'rule_sets':[{'id':735,'value':PRIVATE}],'total':1}))
            if self.path.startswith('/api/v1/tag_rules/zero_trust/'):
                identifiers={v for v in channel.scope._rule_sets().values() if v is not None}
                assert self.path in {rule_set_detail_path(identifier) for identifier in identifiers}
                if fault:
                    self.close_connection=True; self.connection.shutdown(socket.SHUT_RDWR); self.connection.close(); return
                return self.send(payload())
            return self.send(channel.get(self.path))
        def do_POST(self):
            requests.append(('POST',self.path)); assert self.path in ('/api/v1/auth/signin','/api/v1/auth/signout')
            if self.path.endswith('signin'):
                body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                assert body['name']=='synthetic_owner' and body['password']=='synthetic-only'
                return self.send(envelope(None),cookie='sessionid=SYNTHETIC_SESSION; Path=/; Secure; HttpOnly')
            self.send({'result':{'retval':1,'message':'Signed out'}})
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(certificate,key); server.socket=tls.wrap_socket(server.socket,server_side=True)
    thread=Thread(target=server.serve_forever,daemon=True); thread.start(); owner=source=metadata_source=None
    try:
        settings,headers,scope,transport=bootstrap(tmp_path)
        peer_pin=hashlib.sha256(x509.load_pem_x509_certificate(certificate.read_bytes()).public_bytes(Encoding.DER)).hexdigest()
        config=EmsTagHttpConfig('pam.example.test','192.0.2.19','192.0.2.2',5,certificate,
            hashlib.sha256(certificate.read_bytes()).hexdigest(),peer_pin)
        owner=NativeEmsTagHttpTransport(config,owner_credentials=lambda:('synthetic_owner','synthetic-only'))
        def connector(*,timeout_seconds=10):
            connection=http.client.HTTPSConnection(config.hostname,443,timeout=timeout_seconds,context=owner._tls)
            connection._create_connection=lambda address,timeout,source_address:socket.create_connection(('127.0.0.1',server.server_port),timeout,source_address)
            connection.connect()
            assert hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()==peer_pin
            connections.append(connection); return connection
        monkeypatch.setattr(owner,'_connect',connector); owner.authenticate()
        source=owner.make_sources(DisabledLinuxProcessTag('a'*32),source_key=b's'*32); current=source.observe()
        metadata_source=EmsRuleSetMetadataSource(owner,source,current,source_guard=lambda:True)
        fetch=metadata_source._fetch
        def tracked(*args):
            raw=fetch(*args); buffers.append(raw); return raw
        monkeypatch.setattr(metadata_source,'_fetch',tracked)
        action=EmsRuleSetMetadataAction(metadata_source,requester_digest=scope.requester_digest,transport_digest=transport)
        with TestClient(create_http_app(settings,v4_ems_rule_set_metadata_action=action),base_url='https://mcp.example.com') as mcp:
            result=_call(mcp,headers,TOOL,{})
            assert result['isError']==(fault is not None)
            if not fault:
                public=result['structuredContent']; assert public['metadata_read_count']==2 and not public['cleanup_authorized']
            assert all(marker not in json.dumps(result) for marker in (PRIVATE,'SYNTHETIC_SESSION','SYNTHETIC_CSRF','synthetic_owner'))
            before=list(requests); assert _call(mcp,headers,TOOL,{})['isError'] and requests==before
        assert metadata_source._closed and not any(metadata_source._cookie) and owner._live
        assert all(not any(raw) for raw in buffers) and all(connection.sock is None for connection in connections)
        assert [path for method,path in requests if method=='POST']==['/api/v1/auth/signin']
        source.close(); closure=owner.close(); assert closure.own_logout_verified and closure.next_session_check_401
    finally:
        if metadata_source is not None: metadata_source.close()
        if source is not None: source.close()
        if owner is not None: owner.close()
        server.shutdown(); server.server_close(); thread.join(timeout=2); assert not thread.is_alive()
