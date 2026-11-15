"""Normal OAuth/MCP fixed VM observation with synthetic Owner and peer."""
from dataclasses import replace
import asyncio
import json
from threading import Event
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.http_server import create_http_app, HttpConfigurationError
from fortipam_mcp.license_vm_preview_action import (
    LicenseVmPreviewAction, TOOL_NAME, register_license_vm_preview_tool, wrap_license_vm_preview_shutdown,
)
from fortipam_mcp.license_vm_source import LicenseVmSource, STATUS_PATH
from fortipam_mcp.runtime_profile import RuntimeProfile
from test_fortitoken_local_preview_action import bootstrap
from test_ldap_server_mcp_action import _call, _login
from test_license_vm_source import ACTOR, COOKIE, candidate as source_candidate  # noqa: F401
from test_license_vm_projection import SERIAL, PRIVATE


def action_for(source, principal):
    return LicenseVmPreviewAction(source, requester_digest=principal.requester.digest,
        transport_digest=principal.transport_namespace_digest)


@pytest.fixture
def candidate(source_candidate, tmp_path):
    settings, headers, principal = bootstrap(tmp_path)
    peer, source, owner = source_candidate()
    action = action_for(source, principal)
    yield settings, headers, principal, peer, source, owner, action
    action.close()


def assert_private(result):
    assert all(value not in json.dumps(result) for value in (COOKIE, SERIAL, PRIVATE, ACTOR, '2200000000'))


def assert_disposed(peer, source, owner):
    assert source._closed and source._projection is None and not source._cookie_anchors
    assert all(not any(buffer) for buffer in [source._cookie, *peer.buffers])
    assert all(resource.closed for resource in peer.resources)
    assert peer.credentials == 0 and owner._client is not None and owner._session_lock.locked()


def test_normal_no_input_mcp_observation_is_private_once_without_installation(candidate):
    settings, headers, _, peer, source, owner, action = candidate
    with TestClient(create_http_app(settings, v4_license_vm_preview_action=action), base_url='https://mcp.example.com') as client:
        for key in ('endpoint', 'path', 'serial', 'owner', 'cookie', 'token', 'filename', 'file_content', 'body'):
            result = _call(client, headers, TOOL_NAME, {key: 'SYNTHETIC_FORBIDDEN_INPUT'})
            assert result['isError'] and 'SYNTHETIC_FORBIDDEN_INPUT' not in json.dumps(result)
        assert not peer.calls and not source._attempted
        result = _call(client, headers, TOOL_NAME, {})
        assert not result['isError']
        public = result['structuredContent']
        assert public['fixed_get_completed']
        assert public['private_source_copy_disposed'] and 'closed' not in public['observation']
        assert public['observation']['projection']['classified_field_count'] == 10
        for key in ('private_license_values_returned', 'license_material_loaded', 'installation_proposal_created',
                'authorization_or_operation_created', 'native_license_state_qualified', 'execution_authorized', 'configuration_written'):
            assert public[key] is False
        assert not public['observation']['fortiguard_update_requested']
        assert peer.calls == [('GET', STATUS_PATH)]
        assert_disposed(peer, source, owner); assert_private(result)
        assert _call(client, headers, TOOL_NAME, {})['isError']
        assert len(peer.calls) == 1


@pytest.mark.parametrize('fault', ['read-scope', 'foreign-client', 'anonymous'])
def test_unrelated_caller_cannot_consume_or_close_rightful_window(candidate, fault):
    settings, headers, _, peer, source, owner, action = candidate
    with TestClient(create_http_app(settings, v4_license_vm_preview_action=action), base_url='https://mcp.example.com') as client:
        if fault == 'anonymous':
            response = client.post('/fpamcp', json=dict(jsonrpc='2.0', id='read', method='tools/call',
                params=dict(name=TOOL_NAME, arguments={})))
            assert response.status_code == 401
        else:
            denied = _login(client, 'fortipam:read' if fault == 'read-scope' else 'fortipam:read fortipam:plan')
            result = _call(client, denied, TOOL_NAME, {})
            assert result['isError']; assert_private(result)
        assert not peer.calls and not source._attempted and not source._closed
        assert not _call(client, headers, TOOL_NAME, {})['isError']
        assert_disposed(peer, source, owner)


@pytest.mark.parametrize('fault', ['gate', 'expired', 'cookie', 'html', 'close'])
def test_invalid_window_or_cleanup_returns_no_partial_observation(candidate, fault):
    settings, headers, _, peer, source, owner, action = candidate
    if fault == 'gate': source._guard = source._guard_pin = None
    elif fault == 'expired': peer.time = source._expiry
    elif fault == 'cookie': peer.cookie = 'SYNTHETIC_REPLACED_COOKIE'
    elif fault == 'html': peer.fault = 'html'
    else:
        def hook(phase):
            if phase == 'response-close': raise RuntimeError(PRIVATE)
        peer.hook = hook
    with TestClient(create_http_app(settings, v4_license_vm_preview_action=action), base_url='https://mcp.example.com') as client:
        result = _call(client, headers, TOOL_NAME, {})
        assert result['isError'] and 'observation' not in result.get('structuredContent', {})
        assert_private(result); assert_disposed(peer, source, owner)
        assert len(peer.calls) == int(fault in ('html', 'close'))


@pytest.mark.parametrize('fault', ['readonly', 'plan-only', 'bearer', 'authority', 'type'])
def test_factory_requires_explicit_controlled_oauth_planning_binding(candidate, fault):
    settings, _, _, peer, _, _, action = candidate
    if fault == 'readonly': settings = replace(settings, runtime_profile=RuntimeProfile.READONLY)
    elif fault == 'plan-only': settings = replace(settings, runtime_profile=RuntimeProfile.V4_PLAN_ONLY)
    elif fault == 'bearer': settings = replace(settings, auth_mode='bearer', bearer_token='synthetic-bearer')
    elif fault == 'authority': settings = replace(settings, v4_planning_authorization=None)
    else: action = object()
    with pytest.raises(HttpConfigurationError): create_http_app(settings, v4_license_vm_preview_action=action)
    assert not peer.calls


def test_default_absence_empty_schema_and_unused_app_shutdown_cleanup(candidate):
    settings, headers, _, peer, source, owner, action = candidate
    def tools(client):
        return client.post('/fpamcp', headers=headers,
            json=dict(jsonrpc='2.0', id='list', method='tools/list', params={})).json()['result']['tools']
    with TestClient(create_http_app(settings), base_url='https://mcp.example.com') as client:
        assert TOOL_NAME not in {tool['name'] for tool in tools(client)}
    with TestClient(create_http_app(settings, v4_license_vm_preview_action=action), base_url='https://mcp.example.com') as client:
        selected = [tool for tool in tools(client) if tool['name'] == TOOL_NAME]
        assert len(selected) == 1 and selected[0]['inputSchema'].get('properties', {}) == {}
        assert selected[0]['annotations']['readOnlyHint'] is True
        assert not peer.calls and not source._closed
    assert_disposed(peer, source, owner)


@pytest.mark.parametrize('binding', ['source', 'identity'])
def test_changed_action_binding_refuses_before_read_and_cleans_only_original(candidate, source_candidate, binding):
    settings, headers, _, peer, source, owner, action = candidate
    foreign_peer, foreign_source, _ = source_candidate()
    if binding == 'source': action._source = foreign_source
    else: action._identity = ('f' * 64, 'e' * 64)
    with TestClient(create_http_app(settings, v4_license_vm_preview_action=action), base_url='https://mcp.example.com') as client:
        assert _call(client, headers, TOOL_NAME, {})['isError']
        assert not peer.calls and not source._attempted
        assert not foreign_peer.calls and not foreign_source._closed
    assert_disposed(peer, source, owner)
    assert not foreign_source._closed


@pytest.mark.parametrize('error_type', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_cleanup_failure_prevents_public_handoff(candidate, monkeypatch, error_type):
    _, _, principal, peer, source, owner, action = candidate
    original = source.close
    def close():
        original()
        raise error_type(PRIVATE)
    with monkeypatch.context() as patch:
        patch.setattr(source, 'close', close)
        with pytest.raises(error_type): action.preview(principal)
    assert_disposed(peer, source, owner)


def test_owned_cleanup_latency_cannot_publish_expired_bare_vm_observation(candidate, monkeypatch):
    from fortipam_mcp import license_vm_source, license_vm_preview_action
    _, _, principal, peer, source, owner, action = candidate
    now = [10.0]
    monkeypatch.setattr(license_vm_source, '_monotonic', lambda: now[0])
    monkeypatch.setattr(license_vm_preview_action, '_monotonic', lambda: now[0])
    close = source.close
    def delayed(): close(); now[0] += 5
    with monkeypatch.context() as patch:
        patch.setattr(source, 'close', delayed)
        with pytest.raises(RuntimeError): action.preview(principal)
    assert_disposed(peer, source, owner)


def registered_preview(action, principal):
    callbacks = []
    def tool(**_):
        def capture(callback): callbacks.append(callback); return callback
        return capture
    server = SimpleNamespace(_runtime_profile=RuntimeProfile.V4_CONTROLLED,
        _v4_planning_principal=lambda: principal, mcp=SimpleNamespace(tool=tool))
    register_license_vm_preview_tool(server, action)
    return callbacks[0]


@pytest.mark.parametrize('repeat', [False, True])
def test_cancelled_read_waits_for_worker_cleanup_and_preserves_owner(candidate, repeat):
    _, _, principal, peer, source, owner, action = candidate
    started, release = Event(), Event()
    def hook(phase):
        if phase == 'read' and not started.is_set():
            started.set(); assert release.wait(3)
    peer.hook = hook
    async def scenario():
        task = asyncio.create_task(registered_preview(action, principal)())
        try:
            assert await asyncio.to_thread(started.wait, 2)
            task.cancel(); await asyncio.sleep(.02)
            if repeat: task.cancel(); await asyncio.sleep(.02)
            assert not task.done()
            release.set()
            with pytest.raises(asyncio.CancelledError): await task
            assert_disposed(peer, source, owner)
        finally:
            release.set()
            try: await task
            except asyncio.CancelledError: pass
    asyncio.run(scenario())


@pytest.mark.parametrize('foreign', [None, 'requester', 'client'])
def test_queued_cancellation_disposal_requires_original_principal(candidate, foreign):
    from concurrent.futures import ThreadPoolExecutor
    _, _, principal, peer, source, owner, action = candidate
    caller = principal
    if foreign == 'requester': caller = replace(principal, requester=replace(principal.requester, subject_ref='synthetic-foreign'))
    elif foreign == 'client': caller = replace(principal, transport_namespace_digest='f' * 64)
    release = Event()
    async def scenario():
        loop = asyncio.get_running_loop(); loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
        entered = asyncio.Event()
        def occupy(): loop.call_soon_threadsafe(entered.set); assert release.wait(3)
        busy = loop.run_in_executor(None, occupy)
        task = None
        try:
            await asyncio.wait_for(entered.wait(), 1)
            task = asyncio.create_task(registered_preview(action, caller)())
            await asyncio.sleep(.02); task.cancel(); await asyncio.sleep(.02)
            assert not peer.calls
            if foreign:
                assert not source._closed and not source._attempted
            else: assert not task.done()
            release.set(); await busy
            with pytest.raises(RuntimeError if foreign else asyncio.CancelledError): await task
            if foreign:
                assert not source._closed
                assert (await registered_preview(action, principal)())['fixed_get_completed']
            assert_disposed(peer, source, owner)
        finally:
            release.set(); await busy
            if task is not None:
                try: await task
                except (RuntimeError, asyncio.CancelledError): pass
    asyncio.run(scenario())


def test_lifespan_repeat_cancel_waits_for_unused_cookie_disposal(candidate, monkeypatch):
    _, _, _, peer, source, owner, action = candidate
    started, release = Event(), Event()
    original, calls = source.close, []
    def close():
        calls.append(True)
        if len(calls) == 1: started.set(); assert release.wait(3)
        original()
    monkeypatch.setattr(source, 'close', close)
    async def scenario():
        async def receive(): return {'type': 'lifespan.shutdown'}
        async def send(_): pass
        async def app(scope, receive, send): await receive()
        task = asyncio.create_task(wrap_license_vm_preview_shutdown(app, action)({'type': 'lifespan'}, receive, send))
        try:
            assert await asyncio.to_thread(started.wait, 2)
            task.cancel(); await asyncio.sleep(.02); task.cancel(); await asyncio.sleep(.02)
            assert not task.done()
            release.set()
            with pytest.raises(asyncio.CancelledError): await task
            assert not peer.calls; assert_disposed(peer, source, owner)
        finally:
            release.set()
            try: await task
            except asyncio.CancelledError: pass
    asyncio.run(scenario())


@pytest.mark.parametrize('truncated', [False, True])
def test_actual_loopback_tls_get_and_normal_oauth_mcp_without_writes(candidate, tmp_path, truncated):
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import ssl
    import threading
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from test_secret_bulk_import_action_process import tls_material
    settings, headers, principal, peer, prototype, owner, _ = candidate
    prototype.close()
    ca, private = tls_material(tmp_path)
    calls, connections, buffers = [], [], []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *_): pass
        def do_GET(self):
            calls.append((self.command, self.path, self.headers.get('Cookie'), self.headers.get('Authorization')))
            raw = json.dumps(peer.payload).encode()
            self.send_response(200); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw) + int(truncated)))
            self.send_header('Connection', 'close'); self.end_headers(); self.wfile.write(raw)
        def do_POST(self): calls.append(('POST', self.path)); self.send_error(405)
        def do_PUT(self): calls.append(('PUT', self.path)); self.send_error(405)
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
    owner._config = SecretMetadataHttpTransportConfig('https://pam.example.test', 'synthetic-unused-bearer', 5, str(ca))
    owner._raw_connection_factory = factory
    source = LicenseVmSource(owner, expected_actor=ACTOR, expected_serial=SERIAL, source_guard=lambda: True)
    fetch = source._fetch
    def tracked(*args, **kwargs):
        raw = fetch(*args, **kwargs); buffers.append(raw); return raw
    source._fetch = tracked
    try:
        action = action_for(source, principal)
        with TestClient(create_http_app(settings, v4_license_vm_preview_action=action), base_url='https://mcp.example.com') as client:
            result = _call(client, headers, TOOL_NAME, {})
            assert result['isError'] is truncated
            if not truncated: assert result['structuredContent']['fixed_get_completed']
            assert_private(result)
            assert source._closed and source._projection is None and not any(source._cookie)
            assert all(not any(buffer) for buffer in buffers)
            assert all(connection.sock is None for connection in connections)
            assert calls == [('GET', STATUS_PATH, COOKIE, None)]
            assert peer.credentials == 0 and owner._client is not None and owner._session_lock.locked()
    finally:
        source.close(); server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
