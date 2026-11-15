"""Synthetic private status pairing through the original no-input MCP path."""
import hashlib
import json

import pytest
from starlette.testclient import TestClient

from fortipam_mcp import license_status_symbols as symbols
from fortipam_mcp import license_vm_projection as projection
from fortipam_mcp import license_vm_source as source_module
from fortipam_mcp.http_server import create_http_app
from fortipam_mcp.license_vm_preview_action import LicenseVmPreviewAction, TOOL_NAME
from test_fortitoken_local_preview_action import bootstrap
from test_ldap_server_mcp_action import _call
from test_license_vm_projection import frame, SERIAL, PRIVATE
from test_license_vm_source import candidate as source_candidate, assert_clean  # noqa: F401

MATCH = 'LICENSE_STATUS_VM_VALID'


def table():
    return dict(SYMBOLS={name: PRIVATE + str(index) for index, name in enumerate(symbols._NAMES)}, unknown=PRIVATE)


def pair(status, data=None):
    payload = frame(); payload['results']['vm']['status'] = status
    raw = bytearray(json.dumps(payload, ensure_ascii=False).encode())
    static = bytearray(json.dumps(table() if data is None else data, ensure_ascii=True).encode())
    return raw, static


@pytest.mark.parametrize('value', ['1', 'SYNTHETIC', 'é', '许可', '😀', '\\/\n\t\b\f\r"', 'e\u0301'])
def test_private_json_strings_match_across_unicode_and_escape_encodings(value):
    data = table(); data['SYMBOLS'][MATCH] = value
    raw, static = pair(value, data)
    result = projection.project_provided_license_vm(raw, expected_serial=SERIAL, static_symbols=static)
    public = result.summary()
    assert public['status_enum_classified'] and public['status_string_compared']
    assert public['status_symbol_matches'] == [MATCH] and not public['status_symbol_ambiguous']
    assert not public['native_status_mapping_qualified'] and not public['installation_authorized']
    assert PRIVATE not in repr((public, result.digest)) and not any(raw) and not any(static)


def test_aliases_are_reported_without_choosing_a_status():
    data = table(); data['SYMBOLS'][symbols._NAMES[0]] = data['SYMBOLS'][MATCH]
    raw, static = pair(data['SYMBOLS'][MATCH], data)
    result = projection.project_provided_license_vm(raw, expected_serial=SERIAL, static_symbols=static).summary()
    assert result['status_symbol_ambiguous'] and not result['status_enum_classified']
    assert result['status_symbol_matches'] == [symbols._NAMES[0], MATCH]
    assert not any(raw) and not any(static)


@pytest.mark.parametrize('value', [None, 1, True, [], {}, 'SYNTHETIC_UNMATCHED'])
def test_unknown_or_non_string_status_is_not_coerced(value):
    raw, static = pair(value)
    result = projection.project_provided_license_vm(raw, expected_serial=SERIAL, static_symbols=static).summary()
    assert not result['status_enum_classified'] and result['status_symbol_matches'] == []
    assert result['status_string_compared'] is isinstance(value, str)
    assert not any(raw) and not any(static)


@pytest.mark.parametrize('fault', ['missing', 'number', 'null', 'array', 'surrogate', 'low-surrogate', 'invalid-json', 'alias-input'])
def test_invalid_pair_refuses_and_erases_both_owned_frames(fault):
    data = table()
    if fault == 'missing': data['SYMBOLS'].pop(symbols._NAMES[0])
    elif fault in ('number', 'null', 'array'): data['SYMBOLS'][symbols._NAMES[0]] = {'number': 1, 'null': None, 'array': []}[fault]
    elif fault == 'surrogate': data['SYMBOLS'][symbols._NAMES[0]] = '\ud800'
    elif fault == 'low-surrogate': data['SYMBOLS'][symbols._NAMES[0]] = '\udc00'
    raw, static = pair(PRIVATE, data)
    if fault == 'invalid-json': static[:] = b'{"SYMBOLS":invalid}'
    if fault == 'alias-input': static = raw
    with pytest.raises(ValueError): projection.project_provided_license_vm(raw, expected_serial=SERIAL, static_symbols=static)
    assert not any(raw) and not any(static)


def test_private_symbols_and_status_never_reach_text_decoder_or_hash(monkeypatch):
    data = table(); raw, static = pair(data['SYMBOLS'][MATCH], data)
    decode, digest = json.loads, hashlib.sha256
    def check(value):
        value = value.encode() if isinstance(value, str) else value
        assert PRIVATE.encode() not in value
    def checked_decode(value, *args, **kwargs): check(value); return decode(value, *args, **kwargs)
    def checked_digest(value=b'', *args, **kwargs): check(value); return digest(value, *args, **kwargs)
    monkeypatch.setattr(json, 'loads', checked_decode); monkeypatch.setattr(hashlib, 'sha256', checked_digest)
    result = projection.project_provided_license_vm(raw, expected_serial=SERIAL, static_symbols=static)
    assert result.summary()['status_symbol_matches'] == [MATCH]
    assert PRIVATE not in result.digest and not any(raw) and not any(static)


@pytest.mark.parametrize('error_type', [MemoryError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_first_frame_cleanup_failure_still_erases_static_symbols(monkeypatch, error_type):
    data = table(); raw, static = pair(data['SYMBOLS'][MATCH], data); calls = []
    erase = projection._erase_transfer_storage
    def clearing(buffer):
        calls.append(buffer); erase(buffer)
        if len(calls) == 1: raise error_type()
    monkeypatch.setattr(projection, '_erase_transfer_storage', clearing)
    with pytest.raises(error_type): projection.project_provided_license_vm(raw, expected_serial=SERIAL, static_symbols=static)
    assert len(calls) == 2 and not any(raw) and not any(static)


def paired_source(make, encoding='gzip'):
    peer, source, owner = make(include_static_symbols=True)
    peer.static_payload, peer.static_encoding = table(), encoding
    peer.payload['results']['vm']['status'] = peer.static_payload['SYMBOLS'][MATCH]
    return peer, source, owner


@pytest.mark.parametrize('encoding', ['identity', 'gzip', 'deflate'])
def test_two_fixed_reads_share_original_window_and_clean_private_symbols(source_candidate, monkeypatch, encoding):
    peer, source, owner = paired_source(source_candidate, encoding)
    decoded = []; decode = source_module._decode_static_symbols
    def tracked(raw, kind):
        result = decode(raw, kind); decoded.append(result); return result
    monkeypatch.setattr(source_module, '_decode_static_symbols', tracked)
    result = source.read()
    assert result['static_symbol_get_completed'] and not result['observations_are_atomic']
    assert result['projection']['status_symbol_matches'] == [MATCH]
    assert peer.calls == [('GET', source_module.STATUS_PATH), ('GET', source_module.BUILD_PATH)]
    assert decoded and all(not any(raw) for raw in decoded)
    source.close(); assert_clean(peer, source, owner)


def test_additional_read_scope_cannot_be_enabled_after_construction(source_candidate):
    peer, source, owner = source_candidate()
    source._static_symbols = True
    with pytest.raises(ValueError): source.read()
    assert peer.calls == []
    assert_clean(peer, source, owner)


@pytest.mark.parametrize('fault', ['window-after-first', 'total-deadline', 'unsupported-encoding', 'decompression-bound'])
def test_paired_failures_do_not_publish_or_extend_window(source_candidate, fault):
    peer, source, owner = paired_source(source_candidate)
    if fault == 'unsupported-encoding': peer.static_encoding = 'br'
    if fault == 'decompression-bound': peer.static_payload['unknown'] = PRIVATE * 30000
    def hook(phase):
        if phase != 'connection-close': return
        if fault == 'window-after-first': owner._expires_at = 1
        if fault == 'total-deadline': peer.time += 4 if len(peer.calls) == 1 else 2
    peer.hook = hook
    with pytest.raises(ValueError): source.read()
    assert source._projection is None and source._closed
    assert len(peer.calls) == (1 if fault == 'window-after-first' else 2)
    assert_clean(peer, source, owner)


@pytest.mark.parametrize('error_type', [MemoryError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_compressed_buffer_cleanup_failure_cannot_abandon_decoded_table(source_candidate, monkeypatch, error_type):
    peer, source, owner = paired_source(source_candidate); decoded = []; failed = []
    erase, decode = source_module._erase_transfer_storage, source_module._decode_static_symbols
    def tracked(raw, encoding):
        result = decode(raw, encoding); decoded.append(result); return result
    def clearing(raw):
        fail = not failed and len(raw) > 2 and raw[0] == 31 and raw[1] == 139
        erase(raw)
        if fail: failed.append(True); raise error_type()
    monkeypatch.setattr(source_module, '_decode_static_symbols', tracked)
    monkeypatch.setattr(source_module, '_erase_transfer_storage', clearing)
    with pytest.raises(ValueError if issubclass(error_type, Exception) else error_type): source.read()
    assert failed and decoded and all(not any(raw) for raw in decoded)
    assert source._projection is None and source._closed
    assert_clean(peer, source, owner)


def test_existing_normal_mcp_preview_delivers_only_fixed_matched_name(source_candidate, tmp_path):
    settings, headers, principal = bootstrap(tmp_path)
    peer, source, owner = paired_source(source_candidate)
    action = LicenseVmPreviewAction(source, requester_digest=principal.requester.digest,
        transport_digest=principal.transport_namespace_digest)
    with TestClient(create_http_app(settings, v4_license_vm_preview_action=action), base_url='https://mcp.example.com') as client:
        result = _call(client, headers, TOOL_NAME, {})
        assert not result['isError']
        public = result['structuredContent']
        assert public['observation']['projection']['status_symbol_matches'] == [MATCH]
        assert public['private_source_copy_disposed'] and not public['native_license_state_qualified']
        assert not public['configuration_written'] and PRIVATE not in json.dumps(public)
        assert _call(client, headers, TOOL_NAME, {})['isError']
        assert len(peer.calls) == 2
    assert_clean(peer, source, owner)


@pytest.mark.parametrize('truncated', [False, True])
def test_actual_tls_gzip_pair_and_original_oauth_mcp(tmp_path, monkeypatch, truncated):
    import gzip
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import ssl
    import threading
    from fortipam_mcp.owner_session_metadata import OwnerSessionMetadataTransport
    from fortipam_mcp.secret_metadata_http_transport import FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig
    from test_license_vm_source import ACTOR, COOKIE, Peer
    from test_secret_bulk_import_action_process import tls_material
    settings, headers, principal = bootstrap(tmp_path)
    ca, private = tls_material(tmp_path)
    peer = Peer(); data = table(); calls, connections, buffers = [], [], []
    peer.payload['results']['vm']['status'] = data['SYMBOLS'][MATCH]
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *_): pass
        def do_GET(self):
            calls.append((self.command, self.path, self.headers.get('Cookie'), self.headers.get('Authorization')))
            assert self.path in (source_module.STATUS_PATH, source_module.BUILD_PATH)
            static = self.path == source_module.BUILD_PATH
            raw = json.dumps(data if static else peer.payload).encode()
            if static:
                raw = gzip.compress(raw)
                if truncated: raw = raw[:-3]
            self.send_response(200); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Encoding', 'gzip' if static else 'identity')
            self.send_header('Content-Length', str(len(raw))); self.send_header('Connection', 'close')
            self.end_headers(); self.wfile.write(raw)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(ca, private)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    class Connection(http.client.HTTPSConnection):
        def connect(self):
            sock = socket.create_connection(('127.0.0.1', server.server_port), self.timeout)
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
    def factory(*args, **kwargs):
        connection = Connection(*args, **kwargs); connections.append(connection); return connection
    config = SecretMetadataHttpTransportConfig('https://pam.example.test', 'synthetic-unused-bearer', 5, str(ca))
    owner = OwnerSessionMetadataTransport(config, owner_name=ACTOR, credentials=peer.login,
        folder_path='synthetic', secret_name='synthetic', target_name='synthetic',
        witness=FortiPamSecretMetadataHttpTransport(config), connection_factory=factory, clock=peer.clock)
    owner._client, owner._expires_at = peer.client(), 70.0; owner._session_lock.acquire()
    source = source_module.LicenseVmSource(owner, expected_actor=ACTOR, expected_serial=SERIAL,
        source_guard=lambda: True, include_static_symbols=True)
    erase = source_module._erase_transfer_storage
    def clearing(raw): erase(raw); buffers.append(raw)
    monkeypatch.setattr(source_module, '_erase_transfer_storage', clearing)
    action = LicenseVmPreviewAction(source, requester_digest=principal.requester.digest,
        transport_digest=principal.transport_namespace_digest)
    try:
        with TestClient(create_http_app(settings, v4_license_vm_preview_action=action), base_url='https://mcp.example.com') as client:
            result = _call(client, headers, TOOL_NAME, {})
            assert result['isError'] is truncated
            if not truncated:
                assert result['structuredContent']['observation']['projection']['status_symbol_matches'] == [MATCH]
            assert PRIVATE not in json.dumps(result)
        assert calls == [('GET', source_module.STATUS_PATH, COOKIE, None), ('GET', source_module.BUILD_PATH, COOKIE, None)]
        assert len(connections) == 2 and all(connection.sock is None for connection in connections)
        assert buffers and all(not any(raw) for raw in buffers)
        assert source._closed and source._projection is None and owner._client is not None
        assert peer.credentials == 0 and owner._session_lock.locked()
    finally:
        action.close(); owner._client = None; owner._session_lock.release()
        for client in peer.clients: client.close()
        server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
