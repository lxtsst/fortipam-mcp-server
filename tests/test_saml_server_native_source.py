"""Fixed SAML reads with synthetic HTTP/dependency peers, no device access."""
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from fortipam_mcp import saml_server_native_source as native
from fortipam_mcp.saml_server_contract import CONFIG_FIELDS
from fortipam_mcp.saml_server_native_source import (SamlNativeSource, SamlDependencyObservation,
    SCHEMA_PATH, DEFAULT_PATH, COLLECTION_PATH)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_saml_server_contract import fixture, created_record
from test_system_email_m4_adapter import Clock


def envelope(results, *, status=200):
    return dict(http_method='GET',http_status=status,status='success' if status == 200 else 'error',
        serial='SYNTHETIC01',version='v7.0.0',build=29,path='user',name='saml',results=results)


def schema():
    result = {name:dict(type='string',size=35 if name == 'name' else 8192,
        default='SYNTHETIC_UNEXPECTED_MATERIAL') for name in CONFIG_FIELDS}
    for name in ('adfs-claim','limit-relaystate','require-signed-resp-and-asrt'):
        result[name] = dict(type='option',options=[dict(name='enable'),dict(name='disable')])
    for name in ('group-claim-type','user-claim-type'): result[name] = dict(type='option',options=[dict(name='')])
    result['clock-tolerance'] = dict(type='integer',**{'min-value':0,'max-value':300})
    return result


class Dependencies:
    def __init__(self, clock): self.clock = clock; self.calls = []; self.fault = None; self.references = 7
    def observe(self, record_digest, *, timeout_seconds):
        self.calls.append(record_digest); assert 0 < timeout_seconds <= 5
        now = self.clock()
        result = SamlDependencyObservation('2'*64,record_digest,'3'*64,'4'*64,'5'*64,self.references,True,False,False,now,now+10)
        if self.fault == 'exception': raise RuntimeError('SYNTHETIC_PRIVATE_DEPENDENCY')
        if self.fault == 'source': result = replace(result,source_digest='f'*64)
        if self.fault == 'record': result = replace(result,record_digest='f'*64)
        if self.fault == 'incomplete': result = replace(result,complete=False)
        if self.fault == 'stale': result = replace(result,observed_at=now-11,expires_at=now-1)
        return result


class Socket:
    def settimeout(self, timeout): assert 0 < timeout <= 5


class Peer:
    def __init__(self, present=False):
        self.original,self.defaults,self.plan = fixture()
        self.clock = Clock(); self.time = 10.0; self.dependencies = Dependencies(self.clock)
        self.detail = native.BASE_PATH+'/'+self.plan.binding.name+'?with_meta=true'
        self.payloads = {SCHEMA_PATH:envelope(dict(children=schema())), DEFAULT_PATH:envelope(self.defaults),
            COLLECTION_PATH:envelope([self.original]),self.detail:envelope(None,status=404)}
        self.payloads[COLLECTION_PATH].update(size=1,matched_count=1,limit_reached=False)
        self.buffers = []; self.resources = []; self.calls = []; self.fault = None
        if present:
            self.dependencies.references += 1
            candidate = created_record(self.original,self.defaults,self.plan)
            self.payloads[COLLECTION_PATH]['results'].append(candidate)
            self.payloads[COLLECTION_PATH].update(size=2,matched_count=2)
            self.payloads[self.detail] = envelope(candidate)
    def http_clock(self): return self.time
    def factory(self, host, port, **kwargs):
        peer = self
        class Connection:
            def __init__(self): self.sock = Socket(); self.closed = False; self.path = None; peer.resources.append(self)
            def set_debuglevel(self, value): assert value == 0
            def connect(self): assert host == 'pam.example.test'
            def request(self, method, path, *, headers):
                assert method == 'GET' and headers['Authorization'] == 'Bearer synthetic-api-token'
                self.path = path; peer.calls.append(path)
            def getresponse(self):
                payload = peer.payloads[self.path]
                raw = json.dumps(payload,separators=(',',':')).encode()
                if peer.fault == 'duplicate-json': raw = raw.replace(b'"name":"saml"',b'"name":"saml","name":"saml"')
                if peer.fault == 'oversize': raw += b' '*131072
                return Response(raw,payload['http_status'])
            def close(self):
                self.closed = True
                if peer.fault == 'close': raise RuntimeError('SYNTHETIC_PRIVATE_CLOSE')
        class Response:
            def __init__(self, raw, status): self.raw = raw; self.status = status; self.offset = 0; self.closed = False; peer.resources.append(self)
            def getheader(self, name, default=None):
                return {'content-type':'text/html' if peer.fault == 'html' else 'application/json',
                    'content-length':str(len(self.raw)+(1 if peer.fault == 'truncated' else 0))}.get(name.lower(),default)
            def isclosed(self): return self.offset >= len(self.raw)
            def readinto(self, view):
                if not peer.buffers or peer.buffers[-1] is not view.obj: peer.buffers.append(view.obj)
                count = min(len(view),len(self.raw)-self.offset,113)
                view[:count] = self.raw[self.offset:self.offset+count]; self.offset += count
                if peer.fault == 'deadline': peer.time += 1
                return count
            def close(self): self.closed = True
        return Connection()
    def source(self, *, guarded=True, dependencies=True):
        return SamlNativeSource(SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-api-token',5,None),
            self.plan.binding,expected_serial='SYNTHETIC01',source_digest='1'*64,dependency_source_digest='2'*64,
            dependencies=self.dependencies if dependencies else None,source_guard=(lambda: True) if guarded else None,
            connection_factory=self.factory,http_clock=self.http_clock,clock=self.clock)


@pytest.mark.parametrize('present', [False, True])
def test_four_fixed_reads_join_full_collection_detail_and_independent_dependencies(monkeypatch, present):
    peer = Peer(present); source = peer.source(); original_decode = json.loads
    def decode(raw,*args,**kwargs):
        sentinel = b'SYNTHETIC_UNEXPECTED_MATERIAL' if isinstance(raw,(bytes,bytearray)) else 'SYNTHETIC_UNEXPECTED_MATERIAL'
        assert sentinel not in raw
        return original_decode(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',decode)
    observation = source.read()
    assert peer.calls == [SCHEMA_PATH,DEFAULT_PATH,COLLECTION_PATH,peer.detail]
    assert observation.plan._source == peer.original and observation.plan._defaults == peer.defaults
    assert observation.summary()['candidate_present'] is present
    assert observation.summary()['native_backend_qualified'] is False
    assert observation.summary()['runtime_isolation_reported'] is False
    assert observation.summary()['independent_recovery_reported'] is False
    assert len(observation.digest) == 64 and len(peer.dependencies.calls) == 1
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)
    assert 'example' not in repr(observation) and 'example' not in json.dumps(observation.summary())


@pytest.mark.parametrize('fault', ['wrong-device','wrong-version','wrong-build','wrong-route','schema-field','schema-type',
    'default-field','record-field','source-missing','duplicate-record','incomplete','count','foreign-404',
    'unexpected-material','duplicate-json','html','truncated','close','deadline','oversize'])
def test_incomplete_foreign_or_unsafe_read_never_publishes_a_partial_snapshot(monkeypatch, fault):
    peer = Peer(); source = peer.source()
    if fault in ('wrong-device','wrong-version','wrong-build','wrong-route'):
        key,value = {'wrong-device':('serial','OTHER'),'wrong-version':('version','v7.0.1'),
            'wrong-build':('build',30),'wrong-route':('name','other')}[fault]
        peer.payloads[SCHEMA_PATH][key] = value
    elif fault == 'schema-field': del peer.payloads[SCHEMA_PATH]['results']['children']['idp-cert']
    elif fault == 'schema-type': peer.payloads[SCHEMA_PATH]['results']['children']['idp-cert']['type'] = 'password'
    elif fault == 'default-field': peer.payloads[DEFAULT_PATH]['results']['status'] = 'disable'
    elif fault == 'record-field': del peer.original['q_ref']
    elif fault == 'source-missing': peer.original['name'] = 'synthetic-other'
    elif fault == 'duplicate-record':
        peer.payloads[COLLECTION_PATH]['results'].append(deepcopy(peer.original))
        peer.payloads[COLLECTION_PATH].update(size=2,matched_count=2)
    elif fault == 'incomplete': peer.payloads[COLLECTION_PATH]['limit_reached'] = True
    elif fault == 'count': peer.payloads[COLLECTION_PATH]['matched_count'] = True
    elif fault == 'foreign-404': peer.payloads[peer.detail]['name'] = 'other'
    elif fault == 'unexpected-material': peer.original['secret'] = 'SYNTHETIC_UNEXPECTED_MATERIAL'
    else: peer.fault = fault
    original_decode = json.loads
    def decode(raw,*args,**kwargs):
        sentinel = b'SYNTHETIC_UNEXPECTED_MATERIAL' if isinstance(raw,(bytes,bytearray)) else 'SYNTHETIC_UNEXPECTED_MATERIAL'
        assert sentinel not in raw
        return original_decode(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',decode)
    with pytest.raises(ValueError,match='unavailable'): source.read()
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('fault', ['exception','source','record','incomplete','stale'])
def test_dependencies_must_be_complete_fresh_and_bound_to_the_exact_source_record(fault):
    peer = Peer(); peer.dependencies.fault = fault
    with pytest.raises(ValueError,match='unavailable'): peer.source().read()
    assert all(resource.closed for resource in peer.resources) and all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('fault', ['collection-only','detail-only','different-record'])
def test_collection_and_detail_disagreement_never_proves_absence_or_owned_presence(fault):
    peer = Peer(present=True)
    if fault == 'collection-only': peer.payloads[peer.detail] = envelope(None,status=404)
    elif fault == 'detail-only':
        peer.payloads[COLLECTION_PATH]['results'] = [peer.original]
        peer.payloads[COLLECTION_PATH].update(size=1,matched_count=1)
    else:
        peer.payloads[peer.detail]['results'] = dict(peer.payloads[peer.detail]['results'],**{'group-name':'synthetic-drift'})
    with pytest.raises(ValueError,match='unavailable'): peer.source().read()


@pytest.mark.parametrize('option', ['guard','dependencies','closed','tls'])
def test_default_missing_binding_and_closed_or_weakened_tls_never_connect(option):
    peer = Peer(); source = peer.source(guarded=option != 'guard',dependencies=option != 'dependencies')
    if option == 'closed': source.close()
    if option == 'tls': source._tls.check_hostname = False
    with pytest.raises(ValueError,match='unavailable'): source.read()
    assert peer.calls == []


def test_configuration_drift_changes_state_and_makes_an_old_plan_incompatible():
    peer = Peer(); source = peer.source(); before = source.read()
    peer.original['display-name-attr'] = 'synthetic-changed-display'
    after = source.read()
    assert before.digest != after.digest and before.plan.digest != after.plan.digest
    assert before.dependencies.record_digest != after.dependencies.record_digest


def test_unrelated_record_url_credentials_never_enter_preservation_fingerprints():
    peer = Peer()
    other = dict(peer.original,name='synthetic-other',q_origin_key='synthetic-other',
        **{'idp-single-sign-on-url':'https://synthetic-user:synthetic-password@idp.example/login/'})
    peer.payloads[COLLECTION_PATH]['results'].append(other)
    peer.payloads[COLLECTION_PATH].update(size=2,matched_count=2)
    with pytest.raises(ValueError,match='unavailable'): peer.source().read()
    assert peer.dependencies.calls == []
    assert all(not any(raw) for raw in peer.buffers)


@pytest.mark.parametrize('clock', ['monotonic','epoch'])
def test_clock_rollback_is_sticky(clock):
    peer = Peer(); source = peer.source(); source.read()
    if clock == 'monotonic': peer.time -= 1
    else: peer.clock.value -= 1
    with pytest.raises(ValueError,match='unavailable'): source.read()
    peer.time = 20.0; peer.clock.value = 1010
    with pytest.raises(ValueError,match='unavailable'): source.read()


def test_declarations_reject_non_boolean_evidence_and_shared_source_domains():
    peer = Peer(); observed = peer.source().read().dependencies
    with pytest.raises(ValueError): replace(observed,complete=1)
    with pytest.raises(ValueError): replace(observed,certificate_reference_count=True)
    with pytest.raises(ValueError): replace(observed,expires_at=observed.observed_at+11)
    config = SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-api-token',5,None)
    with pytest.raises(ValueError): SamlNativeSource(config,peer.plan.binding,expected_serial='SYNTHETIC01',
        source_digest='1'*64,dependency_source_digest='1'*64)


def test_real_loopback_tls_four_reads_close_connections_and_keep_absence_non_authoritative(tmp_path):
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from test_secret_bulk_import_action_process import tls_material

    certificate,key = tls_material(tmp_path); peer = Peer(); requests = []; connections = []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self,*_): pass
        def do_GET(self):
            assert self.headers['Authorization'] == 'Bearer synthetic-api-token'
            requests.append(self.path); payload = peer.payloads[self.path]
            raw = json.dumps(payload).encode()
            self.send_response(payload['http_status']); self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw))); self.send_header('Connection','close')
            self.end_headers(); self.wfile.write(raw)
    server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(certificate,key)
    server.socket = tls.wrap_socket(server.socket,server_side=True)
    thread = Thread(target=server.serve_forever,daemon=True); thread.start()
    def factory(host,port,**kwargs):
        connection = http.client.HTTPSConnection(host,port,**kwargs)
        connection._create_connection = lambda address, timeout, source_address: socket.create_connection(
            ('127.0.0.1',server.server_port),timeout,source_address)
        connections.append(connection); return connection
    source = SamlNativeSource(SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-api-token',5,str(certificate)),
        peer.plan.binding,expected_serial='SYNTHETIC01',source_digest='1'*64,dependency_source_digest='2'*64,
        dependencies=peer.dependencies,source_guard=lambda: True,connection_factory=factory,clock=peer.clock)
    try:
        observed = source.read()
        assert requests == [SCHEMA_PATH,DEFAULT_PATH,COLLECTION_PATH,peer.detail]
        assert all(connection.sock is None for connection in connections)
        assert observed._candidate is None and observed.summary()['configuration_write_authorized'] is False
        assert observed.summary()['runtime_isolation_reported'] is False
    finally:
        source.close(); server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
