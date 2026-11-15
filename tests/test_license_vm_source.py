"""Synthetic fixed license GET and borrowed Owner lifecycle; no product reads."""
from copy import copy, deepcopy
import hashlib
import gzip
import json
import pickle
import zlib

import pytest
import httpx

from fortipam_mcp import license_vm_source as module
from fortipam_mcp.owner_session_metadata import OwnerSessionMetadataTransport
from fortipam_mcp.secret_metadata_http_transport import (
    FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig,
)
from test_license_vm_projection import frame, SERIAL, PRIVATE
from v4_planning.material_provider import MaterialAccessDenied

COOKIE = "SYNTHETIC_LICENSE_SESSION=SYNTHETIC_LICENSE_COOKIE_MUST_NOT_BE_HASHED"
ACTOR = "synthetic-owner"


class Peer:
    def __init__(self, protocol="imaps"):
        self.payload = frame()
        self.clients = []
        self.time, self.cookie = 10.0, COOKIE
        self.calls, self.resources, self.buffers = [], [], []
        self.fault = None
        self.static_payload, self.static_encoding = None, 'identity'
        self.credentials = 0
        self.hook = lambda phase: None

    def clock(self):
        return self.time

    def login(self):
        self.credentials += 1
        raise AssertionError("The source must not resolve credentials or log in.")

    @property
    def cookie(self):
        return self._cookie

    @cookie.setter
    def cookie(self, value):
        self._cookie = value
        for client in self.clients:
            client.cookies.clear()
            name, separator, material = value.partition('=')
            client.cookies.set(name if separator else 'SYNTHETIC_LICENSE_SESSION', material if separator else value)

    def client(self):
        client = httpx.Client()
        self.clients.append(client)
        self.cookie = self._cookie
        return client

    def factory(self, host, port, **options):
        peer = self
        assert host == "pam.example.test" and port == 443
        assert options["context"].check_hostname and 0 < options["timeout"] <= 5
        class Socket:
            def settimeout(self, timeout):
                assert 0 < timeout <= 5
        class Connection:
            def __init__(self):
                self.sock, self.closed = Socket(), False
                peer.resources.append(self)
            def set_debuglevel(self, value):
                assert value == 0
            def connect(self):
                peer.hook("connect")
            def request(self, method, path, *, headers):
                assert method == "GET" and (path == module.STATUS_PATH
                    or path == module.BUILD_PATH and peer.static_payload is not None)
                self.path = path
                assert headers["Cookie"] == peer.cookie and "Authorization" not in headers
                assert headers["Accept-Encoding"] == "identity"
                peer.calls.append((method, path))
            def getresponse(self):
                result = Response(self.path)
                if peer.fault == "detached":
                    self.sock = None
                return result
            def close(self):
                self.closed = True
                peer.hook("connection-close")
        class Response:
            def __init__(self, path):
                self.static = path == module.BUILD_PATH
                self.raw = json.dumps(peer.static_payload if self.static else peer.payload, separators=(",", ":")).encode()
                if self.static and peer.static_encoding == 'gzip': self.raw = gzip.compress(self.raw)
                elif self.static and peer.static_encoding == 'deflate': self.raw = zlib.compress(self.raw)
                self.offset, self.closed = 0, False
                self.status = 302 if peer.fault == "redirect" else 200
                peer.resources.append(self)
            def getheader(self, name, default=None):
                return {"content-type": "text/html" if peer.fault == "html" else "application/json",
                    "content-encoding": peer.static_encoding if self.static else "gzip" if peer.fault == "gzip" else "identity",
                    "content-length": ("1048577" if peer.fault == "oversize" else
                        str(len(self.raw) + (1 if peer.fault == "truncated" else 0))),
                    "transfer-encoding": "chunked" if peer.fault == "ambiguous-length" else None}.get(name.lower(), default)
            def isclosed(self):
                return self.offset >= len(self.raw)
            def readinto(self, view):
                if not peer.buffers or peer.buffers[-1] is not view.obj:
                    peer.buffers.append(view.obj)
                count = min(len(view), len(self.raw) - self.offset, 173)
                view[:count] = self.raw[self.offset:self.offset + count]
                self.offset += count
                peer.hook("read")
                if peer.fault == "invalid-count":
                    return True
                return count
            def close(self):
                self.closed = True
                peer.hook("response-close")
        return Connection()


@pytest.fixture
def candidate():
    owners, sources, peers = [], [], []
    def make(guard=True, include_static_symbols=False):
        peer = Peer()
        peers.append(peer)
        config = SecretMetadataHttpTransportConfig("https://pam.example.test", "synthetic-unused-bearer", 5, None)
        owner = OwnerSessionMetadataTransport(config, owner_name=ACTOR, credentials=peer.login,
            folder_path="synthetic", secret_name="synthetic", target_name="synthetic",
            witness=FortiPamSecretMetadataHttpTransport(config), connection_factory=peer.factory, clock=peer.clock)
        owner._client, owner._expires_at = peer.client(), 70.0
        owner._session_lock.acquire()
        owners.append(owner)
        source = module.LicenseVmSource(owner, expected_actor=ACTOR, expected_serial=SERIAL,
            source_guard=(lambda: True) if guard else None, include_static_symbols=include_static_symbols)
        sources.append(source)
        assert not peer.calls and peer.credentials == 0
        return peer, source, owner
    yield make
    for source in sources:
        source.close()
    for peer in peers:
        for client in peer.clients: client.close()
    for owner in owners:
        owner._client = None
        if owner._session_lock.locked():
            owner._session_lock.release()


def assert_clean(peer, source, owner):
    assert all(not any(buffer) for buffer in [*peer.buffers, source._cookie])
    assert all(resource.closed for resource in peer.resources)
    assert peer.credentials == 0
    assert owner._client is not None and owner._session_lock.locked()


@pytest.mark.parametrize('detached', [False, True])
def test_fixed_get_keeps_values_private_and_retains_original_owner(candidate, detached):
    peer, source, owner = candidate()
    if detached: peer.fault = 'detached'
    result = source.read()
    assert source._current()._values[1] == ('expires', 2200000000)
    assert result['fixed_get_completed']
    assert result['projection']['classified_field_count'] == 10
    assert not result['whole_license_state_verified'] and not result['installation_authorized']
    assert not result['frontend_polling_helper_invoked'] and not result['fortiguard_update_requested']
    assert all(value not in repr(result) for value in (COOKIE, SERIAL, PRIVATE, ACTOR, '2200000000'))
    assert peer.calls == [('GET', module.STATUS_PATH)]
    source.close()
    assert source._projection is None
    assert_clean(peer, source, owner)
    with pytest.raises(ValueError): source.read()
    assert len(peer.calls) == 1


def test_missing_guard_denies_before_network_and_is_not_reusable(candidate):
    peer, source, owner = candidate(guard=False)
    with pytest.raises(ValueError): source.read()
    assert not peer.calls and not peer.resources
    assert_clean(peer, source, owner)
    source._guard = lambda: True
    with pytest.raises(ValueError): source.read()


@pytest.mark.parametrize('deadline', [False, float('nan'), float('inf'), 0.0, 'synthetic-invalid'])
def test_invalid_or_expired_combined_deadline_refuses_before_http(candidate, deadline):
    peer, source, owner = candidate()
    with pytest.raises(ValueError): source.read(monotonic_deadline=deadline)
    assert not peer.calls and not peer.resources
    assert_clean(peer, source, owner)


@pytest.mark.parametrize('fault', ['redirect', 'html', 'gzip', 'oversize', 'truncated', 'ambiguous-length', 'invalid-count'])
def test_bad_http_contract_cleans_and_never_retries(candidate, fault):
    peer, source, owner = candidate()
    peer.fault = fault
    with pytest.raises(ValueError, match='private license VM source'): source.read()
    assert source._projection is None and len(peer.calls) == 1
    assert_clean(peer, source, owner)
    with pytest.raises(ValueError): source.read()
    assert len(peer.calls) == 1


@pytest.mark.parametrize('phase', ['connect', 'read', 'response-close', 'connection-close'])
@pytest.mark.parametrize('exception', [ValueError, KeyboardInterrupt, SystemExit])
def test_io_and_cleanup_interruptions_never_publish(candidate, phase, exception):
    peer, source, owner = candidate()
    def hook(at):
        if at == phase: raise exception('synthetic failure')
    peer.hook = hook
    with pytest.raises(exception): source.read()
    assert source._projection is None
    assert_clean(peer, source, owner)


@pytest.mark.parametrize('change', ['actor', 'client', 'config', 'expiry', 'clock', 'factory', 'lock', 'cookie', 'guard', 'tls'])
def test_original_window_and_trust_bindings_cannot_be_replaced(candidate, change):
    import threading
    peer, source, owner = candidate()
    original_lock = owner._session_lock
    def guard():
        if change == 'actor': owner._owner_name = 'another-owner'
        elif change == 'client': owner._client = peer.client()
        elif change == 'config': owner._config = copy(owner._config)
        elif change == 'expiry': owner._expires_at += 60
        elif change == 'clock': owner._clock = lambda: 10.0
        elif change == 'factory': owner._raw_connection_factory = lambda *a, **k: None
        elif change == 'lock':
            owner._session_lock = threading.Lock(); owner._session_lock.acquire()
        elif change == 'cookie': peer.cookie = 'SYNTHETIC_REPLACED_COOKIE'
        elif change == 'guard': source._guard = lambda: True
        else: source._tls.check_hostname = False
        return True
    source._guard = source._guard_pin = guard
    try:
        with pytest.raises(ValueError): source.read()
        assert not peer.calls and source._projection is None
        assert_clean(peer, source, owner)
    finally:
        if owner._session_lock is not original_lock:
            owner._session_lock.release(); owner._session_lock = original_lock


@pytest.mark.parametrize('phase', ['connect', 'read', 'response-close', 'connection-close'])
def test_one_total_deadline_includes_network_and_cleanup(candidate, phase):
    peer, source, owner = candidate()
    def hook(at):
        if at == phase: peer.time += 5
    peer.hook = hook
    with pytest.raises(ValueError): source.read()
    assert source._projection is None
    assert_clean(peer, source, owner)


def test_initial_guard_cannot_renew_the_total_read_budget(candidate, monkeypatch):
    peer, source, owner = candidate()
    monotonic = [10.0]
    monkeypatch.setattr(module, "_monotonic", lambda: monotonic[0])
    def guard():
        peer.time += 5
        monotonic[0] += 5
        return True
    source._guard = source._guard_pin = guard
    with pytest.raises(ValueError): source.read()
    assert not peer.resources and not peer.calls
    assert_clean(peer, source, owner)


@pytest.mark.parametrize('time', [15.0, 70.0, 9.0, float('nan')])
def test_private_consumption_rechecks_deadline_and_clock(candidate, time):
    peer, source, owner = candidate()
    source.read(); peer.time = time
    with pytest.raises(ValueError): source._current()
    assert source._projection is None
    assert_clean(peer, source, owner)


def test_clock_callback_cannot_close_source_and_still_publish(candidate):
    peer, source, owner = candidate()
    original = source._clock
    def clock():
        source.close()
        return original()
    owner._clock = source._clock = clock
    with pytest.raises(ValueError): source.read()
    assert not peer.calls
    assert_clean(peer, source, owner)


def test_last_clock_callback_cookie_change_denies_before_request(candidate):
    peer, source, owner = candidate()
    original_clock, original_factory = source._clock, source._factory
    ticks, requests = [], []
    def clock():
        ticks.append(True)
        if len(ticks) == 3: peer.cookie = 'SYNTHETIC_REVOKED_COOKIE'
        return original_clock()
    def factory(*args, **kwargs):
        connection = original_factory(*args, **kwargs)
        request = connection.request
        def send(*args, **kwargs):
            requests.append(True)
            return request(*args, **kwargs)
        connection.request = send
        return connection
    owner._clock = source._clock = clock
    owner._raw_connection_factory = source._factory = factory
    with pytest.raises(ValueError): source.read()
    assert not requests
    assert_clean(peer, source, owner)


def test_last_clock_callback_guard_revocation_denies_before_request(candidate):
    peer, source, owner = candidate()
    original = source._clock
    ticks, permission = [], [True]
    def guard(): return permission[0]
    def clock():
        ticks.append(True)
        if len(ticks) == 3: permission[0] = False
        return original()
    source._guard = source._guard_pin = guard
    owner._clock = source._clock = clock
    with pytest.raises(ValueError): source.read()
    assert not peer.calls
    assert_clean(peer, source, owner)


def test_final_guard_cookie_mutation_denies_without_callback_recheck(candidate):
    peer, source, owner = candidate()
    def guard():
        peer.cookie = 'SYNTHETIC_REPLACED_AFTER_CHECK'
        return True
    source._guard = source._guard_pin = guard
    with pytest.raises(ValueError): source.read()
    assert not peer.calls
    assert_clean(peer, source, owner)


def test_equal_cookie_replacement_cannot_adopt_the_original_jar_objects(candidate):
    peer, source, owner = candidate()
    def guard():
        peer.cookie = COOKIE
        return True
    source._guard = source._guard_pin = guard
    with pytest.raises(ValueError): source.read()
    assert not peer.calls and not source._cookie_anchors
    assert_clean(peer, source, owner)


@pytest.mark.parametrize('replace', [False, True])
def test_final_guard_cannot_override_jar_cookie_with_client_default_header(candidate, replace):
    peer, source, owner = candidate()
    guards = []
    def guard():
        guards.append(True)
        if len(guards) == 2:
            if replace: owner._client.headers = {'Cookie': 'SYNTHETIC_HEADER_OVERRIDE'}
            else: owner._client.headers['Cookie'] = 'SYNTHETIC_HEADER_OVERRIDE'
        return True
    source._guard = source._guard_pin = guard
    with pytest.raises(ValueError): source.read()
    assert not peer.calls
    assert_clean(peer, source, owner)


def test_existing_client_default_cookie_header_is_not_a_supported_source(candidate):
    peer, source, owner = candidate()
    source.close()
    owner._client.headers['Cookie'] = COOKIE
    with pytest.raises(ValueError):
        module.LicenseVmSource(owner, expected_actor=ACTOR, expected_serial=SERIAL, source_guard=lambda: True)
    assert not peer.calls
    assert_clean(peer, source, owner)


def test_different_tls_context_with_valid_flags_is_rejected(candidate):
    import ssl
    peer, source, owner = candidate()
    def guard():
        source._tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        return True
    source._guard = source._guard_pin = guard
    with pytest.raises(ValueError): source.read()
    assert not peer.calls
    assert_clean(peer, source, owner)


def test_frozen_owner_clock_cannot_extend_monotonic_total_budget(candidate, monkeypatch):
    peer, source, owner = candidate()
    monotonic = [10.0]
    monkeypatch.setattr(module, '_monotonic', lambda: monotonic[0])
    def hook(phase):
        if phase == 'connect': monotonic[0] += 5
    peer.hook = hook
    with pytest.raises(ValueError): source.read()
    assert not peer.calls
    assert_clean(peer, source, owner)


def test_failed_projection_and_final_revocation_release_all_owned_bytes(candidate, monkeypatch):
    peer, source, owner = candidate()
    project = module.project_provided_license_vm
    def revoke(raw, **kwargs):
        result = project(raw, **kwargs)
        source.close()
        return result
    monkeypatch.setattr(module, 'project_provided_license_vm', revoke)
    with pytest.raises(ValueError): source.read()
    assert source._projection is None
    assert_clean(peer, source, owner)


def test_unknown_license_material_never_reaches_decode_or_digest(candidate, monkeypatch):
    peer, source, owner = candidate()
    decode, digest = json.loads, hashlib.sha256
    def check(value):
        raw = value.encode() if isinstance(value, str) else value
        assert COOKIE.encode() not in raw and PRIVATE.encode() not in raw
    def safe_decode(value, *args, **kwargs):
        check(value); return decode(value, *args, **kwargs)
    def safe_digest(value=b'', *args, **kwargs):
        check(value); return digest(value, *args, **kwargs)
    monkeypatch.setattr(json, 'loads', safe_decode)
    monkeypatch.setattr(hashlib, 'sha256', safe_digest)
    source.read(); source._current().digest
    source.close(); assert_clean(peer, source, owner)


def test_opaque_source_cannot_be_copied_or_serialized(candidate):
    _, source, _ = candidate()
    for operation in (copy, deepcopy, pickle.dumps):
        with pytest.raises(MaterialAccessDenied): operation(source)


@pytest.mark.parametrize('close_failure', [False, True])
def test_actual_local_tls_uses_only_fixed_get_and_original_cookie(tmp_path, close_failure):
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import ssl
    import threading
    from test_secret_bulk_import_action_process import tls_material
    ca, private = tls_material(tmp_path)
    calls, connections = [], []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *_): pass
        def do_GET(self):
            calls.append((self.command, self.path, self.headers.get('Cookie'), self.headers.get('Authorization')))
            raw = json.dumps(frame()).encode()
            self.send_response(200); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw))); self.send_header('Connection', 'close')
            self.end_headers(); self.wfile.write(raw)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(ca, private)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    peer = Peer()
    class Connection(http.client.HTTPSConnection):
        def connect(self):
            sock = socket.create_connection(('127.0.0.1', server.server_port), self.timeout)
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        def close(self):
            super().close()
            if close_failure: raise ValueError('synthetic close failure')
    def factory(*args, **kwargs):
        connection = Connection(*args, **kwargs); connections.append(connection); return connection
    config = SecretMetadataHttpTransportConfig('https://pam.example.test', 'synthetic-unused-bearer', 5, str(ca))
    owner = OwnerSessionMetadataTransport(config, owner_name=ACTOR, credentials=peer.login,
        folder_path='synthetic', secret_name='synthetic', target_name='synthetic',
        witness=FortiPamSecretMetadataHttpTransport(config), connection_factory=factory, clock=peer.clock)
    owner._client, owner._expires_at = peer.client(), 70.0
    owner._session_lock.acquire()
    source = module.LicenseVmSource(owner, expected_actor=ACTOR, expected_serial=SERIAL, source_guard=lambda: True)
    try:
        if close_failure:
            with pytest.raises(ValueError): source.read()
            assert source._projection is None
        else: assert source.read()['fixed_get_completed']
        assert calls == [('GET', module.STATUS_PATH, COOKIE, None)]
        assert len(connections) == 1 and connections[0].sock is None
        assert peer.credentials == 0 and owner._client is not None and owner._session_lock.locked()
    finally:
        source.close(); owner._client = None; owner._session_lock.release()
        for client in peer.clients: client.close()
        server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
