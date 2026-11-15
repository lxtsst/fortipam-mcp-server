"""Fixed local HTTP candidate and real loopback TLS; no FortiPAM or SMTP."""
from dataclasses import replace
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import socket
import ssl
from threading import Thread

import pytest

from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.system_email_configuration_http_backend import (
    SystemEmailConfigurationHttpBackend, SystemEmailConfigurationHttpError,
)
from fortipam_mcp.system_email_configuration_transition import prepare_system_email_transition
from fortipam_mcp.system_email_local_workflow import SystemEmailLocalWorkflow
from fortipam_mcp.system_email_native_source import SystemEmailNativeSource, _PATH, _SCHEMA
from test_secret_bulk_import_action_process import tls_material
from test_system_email_local_workflow import Authority, IDENTITY, run
from test_system_email_m4_adapter import BINDING, REQUESTER, Clock, store_at
from test_system_email_native_source import Peer


def acknowledgement():
    # Local candidate fixture only; not an observed native email-server ACK.
    return dict(http_method='PUT', version='v7.0.0', build=29, http_status=200,
        path='system', name='email-server', serial='SYNTHETIC01', status='success',
        vdom='root', revision='synthetic-revision', revision_changed=True, mkey='')


class HttpClock:
    value = 1.0
    def __call__(self): return self.value


class HttpPeer(Peer):
    def __init__(self, fault='none'):
        super().__init__()
        self.fault = fault
        self.ack = acknowledgement()
        self.puts = []
        self.http_resources = []
        self.http_buffers = []
        self.body_buffers = []
        self.timeouts = []
        self.connected = 0
        self.http_clock = HttpClock()
        self.gate = True

    def write_factory(self, host, port, *, context, timeout):
        assert host == 'pam.example.test' and port == 443
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        assert context.minimum_version >= ssl.TLSVersion.TLSv1_2 and 0 < timeout <= 5
        peer = self
        class Socket:
            def settimeout(self, value):
                assert value > 0
                peer.timeouts.append(value)
        class Response:
            closed = False
            status = 302 if peer.fault == 'redirect' else 500 if peer.fault == 'status' else 200
            def __init__(self):
                raw = json.dumps(peer.ack).encode()
                if peer.fault == 'partial': raw = raw[:-2]
                if peer.fault == 'oversize': raw += b' ' * 16384
                if peer.fault == 'duplicate': raw = raw.replace(b'"build": 29', b'"build":29,"build":29')
                if peer.fault == 'trailing': raw += b'{}'
                self.stream = io.BytesIO(raw)
            def getheader(self, name, default=None):
                values = {'content-type': 'text/plain' if peer.fault == 'content-type' else 'application/json',
                    'content-encoding': 'gzip' if peer.fault == 'encoding' else 'identity'}
                if peer.fault == 'truncated-length': values['content-length'] = str(len(self.stream.getvalue()) + 1)
                return values.get(name.lower(), default)
            def isclosed(self): return self.closed
            def readinto(self, target):
                peer.http_buffers.append(target.obj)
                if peer.fault == 'read-timeout': raise TimeoutError('SYNTHETIC_PRIVATE_ACK')
                if peer.fault == 'slow-read': peer.http_clock.value += 5
                return self.stream.readinto(target)
            def close(self):
                self.closed = True
                if peer.fault == 'slow-close': peer.http_clock.value += 5
                if peer.fault == 'gate-after-close': peer.gate = False
                if peer.fault == 'response-close': raise OSError('SYNTHETIC_PRIVATE_CLOSE')
        class Connection:
            closed = False
            sock = Socket()
            def set_debuglevel(self, level): assert level == 0
            def connect(self):
                peer.connected += 1
                if peer.fault == 'connect': raise TimeoutError('SYNTHETIC_PRIVATE_CONNECT')
                if peer.fault == 'gate-after-connect': peer.gate = False
                if peer.fault == 'late-drift': peer.body['results']['port'] = 587
                if peer.fault == 'slow-connect': peer.http_clock.value += 5
                if peer.fault == 'backwards-clock': peer.http_clock.value = 0.0
            def request(self, method, path, *, body, headers):
                assert method == 'PUT' and path == _PATH
                assert headers['Authorization'] == 'Bearer synthetic-token'
                peer.body_buffers.append(body)
                value = json.loads(body)
                assert len(value) == 12 and value['username'] == value['password'] == ''
                assert not {'interface', 'interface-select-method', 'ssl-min-proto-version'} & value.keys()
                peer.puts.append((method, path, value))
                peer.body['results'].update(value)
                if peer.fault == 'write-timeout': raise TimeoutError('SYNTHETIC_PRIVATE_WRITE')
                if peer.fault == 'partial-state': peer.body['results']['interface'] = 'synthetic-drift'
            def getresponse(self):
                # http.client clears connection.sock for Connection: close.
                self.sock = None
                result = Response(); peer.http_resources.append(result); return result
            def close(self):
                self.closed = True
                if peer.fault == 'connection-close': raise OSError('SYNTHETIC_PRIVATE_CLOSE')
        result = Connection(); self.http_resources.append(result); return result


def make_http(tmp_path, fault='none', *, enabled=True, source_qualified=True):
    peer = HttpPeer(fault)
    source = peer.source()
    original = source.read_empty_auth_payload()
    values = {key: value for key, value in peer.body['results'].items() if key not in ('username', 'password')}
    values['server'] = 'capture.example.test'
    change = prepare_system_email_transition(original, values)
    backend = SystemEmailConfigurationHttpBackend(source, change,
        execution_enabled=(lambda: peer.gate) if enabled else None,
        source_guard=(lambda: True) if source_qualified else None,
        connection_factory=peer.write_factory, http_clock=peer.http_clock)
    store = store_at(tmp_path)
    workflow = SystemEmailLocalWorkflow(change, backend, store, binding_digest=BINDING,
        allowed_requester_digest=REQUESTER, allowed_transport_digest=IDENTITY['transport_digest'],
        authority=Authority(), update_enabled=True, restore_enabled=True, clock=Clock())
    return peer, backend, workflow, store, change


def test_fixed_put_and_same_instance_restore_through_real_local_m4(tmp_path):
    peer, backend, workflow, store, change = make_http(tmp_path)
    for phase in ('update', 'restore'):
        assert run(workflow, phase)[0]['outcome'] == 'succeeded'
    assert len(peer.puts) == 2 and store.claim_count == 2
    assert peer.puts[0][2]['server'] == 'capture.example.test'
    assert peer.puts[1][2]['server'] == 'smtp.example.test'
    assert set(backend._acks) == {'update', 'restore'}
    assert backend._acks['update'].request_digest == change.proposed.request_digest
    assert backend._acks['update'].response_digest == hashlib.sha256(json.dumps(peer.ack).encode()).hexdigest()
    assert all(resource.closed for resource in peer.http_resources)
    assert all(not any(raw) for raw in peer.http_buffers + peer.body_buffers)
    assert 'synthetic-revision' not in repr(backend._acks['update'])
    assert workflow.outcome(**IDENTITY)['native_backend_qualified'] is False


@pytest.mark.parametrize('enabled,qualified', [(False, True), (True, False)])
def test_transport_defaults_deny_without_both_exact_gates(tmp_path, enabled, qualified):
    peer, _, workflow, store, _ = make_http(tmp_path, enabled=enabled, source_qualified=qualified)
    assert run(workflow, 'update')[0]['outcome'] != 'succeeded'
    assert peer.connected == 0 and peer.puts == [] and store.claim_count == 1


@pytest.mark.parametrize('fault', [
    'connect', 'slow-connect', 'backwards-clock', 'gate-after-connect', 'late-drift',
    'write-timeout', 'read-timeout', 'slow-read', 'status', 'redirect', 'content-type',
    'encoding', 'partial', 'oversize', 'duplicate', 'trailing', 'response-close',
    'connection-close', 'partial-state', 'truncated-length', 'slow-close', 'gate-after-close',
])
def test_failed_or_uncertain_http_never_qualifies_or_retries(tmp_path, fault):
    peer, backend, workflow, store, change = make_http(tmp_path, fault)
    result, authorization = run(workflow, 'update')
    assert result['outcome'] != 'succeeded'
    assert workflow.execute('update', authorization['authorization_ref'], **IDENTITY)['idempotent_replay']
    with pytest.raises(ValueError): workflow.preview('update', **IDENTITY)
    with pytest.raises(ValueError): workflow.preview('restore', **IDENTITY)
    with pytest.raises(SystemEmailConfigurationHttpError):
        backend.submit(change.proposed, before_send=lambda: 5, timeout_seconds=5)
    assert len(peer.puts) <= 1 and peer.connected == 1 and store.claim_count == 1
    assert all(resource.closed for resource in peer.http_resources)
    assert all(not any(raw) for raw in peer.http_buffers + peer.body_buffers)


@pytest.mark.parametrize('field,value', [
    ('serial', 'FOREIGN01'), ('version', 'v7.0.1'), ('build', True), ('http_method', 'POST'),
    ('http_status', 201), ('path', 'secret'), ('name', 'approval-email'), ('status', 'error'),
    ('error', -7), ('revision_changed', False), ('mkey', 'foreign'), ('vdom', 'foreign'),
    ('revision', ''), ('results', {'password': 'SYNTHETIC_C3_SENTINEL'}),
])
def test_foreign_or_unclassified_ack_cannot_be_adopted(tmp_path, field, value, monkeypatch):
    peer, backend, workflow, _, _ = make_http(tmp_path)
    peer.ack[field] = value
    decode = json.loads
    def private_decoder(raw, *args, **kwargs):
        assert 'SYNTHETIC_C3_SENTINEL' not in str(raw)
        return decode(raw, *args, **kwargs)
    monkeypatch.setattr(json, 'loads', private_decoder)
    assert run(workflow, 'update')[0]['outcome'] != 'succeeded'
    assert backend._acks == {} and len(peer.puts) == 1
    assert all(not any(raw) for raw in peer.http_buffers)


def test_payload_identity_original_ack_and_close_are_enforced_before_connect(tmp_path):
    peer, backend, _, _, change = make_http(tmp_path)
    for draft in (change.original.draft, replace(change.proposed)):
        with pytest.raises(SystemEmailConfigurationHttpError):
            backend.submit(draft, before_send=lambda: 5, timeout_seconds=5)
    backend.close()
    with pytest.raises(SystemEmailConfigurationHttpError): backend.inspect()
    with pytest.raises(SystemEmailConfigurationHttpError):
        backend.submit(change.proposed, before_send=lambda: 5, timeout_seconds=5)
    assert peer.connected == 0 and peer.puts == []


@pytest.mark.parametrize('fault', ['none', 'lost-ack', 'truncated-length'])
def test_real_loopback_https_configuration_and_original_ack_ownership(tmp_path, fault):
    ca, key = tls_material(tmp_path)
    peer = Peer(); puts = []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *_): pass
        def send(self, value):
            raw = json.dumps(value).encode()
            self.send_response(200); self.send_header('Content-Type', 'application/json')
            declared = len(raw) + int(fault == 'truncated-length' and self.command == 'PUT')
            self.send_header('Content-Length', str(declared)); self.send_header('Connection', 'close')
            self.end_headers(); self.wfile.write(raw)
        def do_GET(self):
            assert self.headers['Authorization'] == 'Bearer synthetic-token'
            assert self.path in (_PATH, _SCHEMA)
            self.send(peer.schema if self.path == _SCHEMA else peer.body)
        def do_PUT(self):
            assert self.path == _PATH and self.headers['Authorization'] == 'Bearer synthetic-token'
            value = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            puts.append(value); peer.body['results'].update(value)
            if fault == 'lost-ack':
                self.close_connection = True
            else:
                self.send(acknowledgement())
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(ca, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True); thread.start()
    connections = []
    def connection_factory(host, port, **kwargs):
        connection = http.client.HTTPSConnection(host, port, **kwargs)
        connection._create_connection = lambda address, timeout, source_address: socket.create_connection(
            ('127.0.0.1', server.server_port), timeout, source_address)
        connections.append(connection)
        return connection
    try:
        config = SecretMetadataHttpTransportConfig(f'https://pam.example.test:{server.server_port}',
            'synthetic-token', 5, str(ca))
        source = SystemEmailNativeSource(config, expected_serial='SYNTHETIC01', connection_factory=connection_factory)
        original = source.read_empty_auth_payload()
        values = {k: v for k, v in peer.body['results'].items() if k not in ('username', 'password')}
        change = prepare_system_email_transition(original, {**values, 'server': 'capture.example.test'})
        backend = SystemEmailConfigurationHttpBackend(source, change, execution_enabled=lambda: True,
            source_guard=lambda: True, connection_factory=connection_factory)
        store = store_at(tmp_path)
        workflow = SystemEmailLocalWorkflow(change, backend, store, binding_digest=BINDING,
            allowed_requester_digest=REQUESTER, allowed_transport_digest=IDENTITY['transport_digest'],
            authority=Authority(), update_enabled=True, restore_enabled=True, clock=Clock())
        result, authorization = run(workflow, 'update')
        if fault == 'none':
            assert result['outcome'] == 'succeeded'
            assert run(workflow, 'restore')[0]['outcome'] == 'succeeded'
            assert len(puts) == 2 and workflow.outcome(**IDENTITY)['workflow_outcome'] == 'verified_locally'
        else:
            assert result['outcome'] != 'succeeded' and backend._acks == {}
            assert workflow.execute('update', authorization['authorization_ref'], **IDENTITY)['idempotent_replay']
            with pytest.raises(ValueError): workflow.preview('restore', **IDENTITY)
            assert len(puts) == 1
        assert all(connection.sock is None for connection in connections)
        assert result['native_backend_qualified'] is False
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)
