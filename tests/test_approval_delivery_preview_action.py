"""Normal OAuth/MCP previews with synthetic borrowed-window configuration."""
from dataclasses import replace
import asyncio
import json
from threading import Event
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.approval_delivery_preview_action import (
    ApprovalDeliveryPreviewAction, TOOL_NAME, register_approval_delivery_preview_tool,
    wrap_approval_delivery_preview_shutdown,
)
from fortipam_mcp.approval_delivery_source import ApprovalDeliverySource, CURRENT_PATH
from fortipam_mcp.http_server import create_http_app, HttpConfigurationError
from fortipam_mcp.runtime_profile import RuntimeProfile
from test_approval_delivery_contract import state
from test_approval_delivery_material_contract import BINDINGS, SYNTHETIC
from test_approval_delivery_projection import CANARY, SERIAL
from test_approval_delivery_source import ACTOR, COOKIE, candidate as source_candidate  # noqa: F401
from test_fortitoken_local_preview_action import bootstrap
from test_ldap_server_mcp_action import _call, _login


def action_for(source, principal, proposed=None):
    return ApprovalDeliveryPreviewAction(source, state() if proposed is None else proposed, enabled=False,
        requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest)


@pytest.fixture
def candidate(source_candidate, tmp_path):
    settings, headers, principal = bootstrap(tmp_path)
    peer, source, owner = source_candidate()
    action = action_for(source, principal)
    yield settings, headers, principal, peer, source, owner, action
    action.close()


def assert_private(result):
    public = json.dumps(result)
    assert all(value not in public for value in [COOKIE, CANARY, SERIAL, ACTOR, "example.test",
        *BINDINGS.values(), *(value.decode() for value in SYNTHETIC.values())])


def test_normal_no_input_preview_is_private_once_and_never_encodes_or_writes(candidate, monkeypatch):
    settings, headers, _, peer, source, owner, action = candidate
    monkeypatch.setattr(ApprovalDeliverySource, "_compile_once",
        lambda *_args: pytest.fail("Readonly preview must not encode a request body."))
    with TestClient(create_http_app(settings, v4_approval_delivery_preview_action=action),
            base_url="https://mcp.example.com") as client:
        for key in ("username", "credential", "client-secret", "mailbox", "path", "endpoint", "body", "proposal", "enabled"):
            result = _call(client, headers, TOOL_NAME, {key: "SYNTHETIC_FORBIDDEN_INPUT"})
            assert result["isError"] and "SYNTHETIC_FORBIDDEN_INPUT" not in json.dumps(result)
        assert not peer.calls and not source._attempted
        result = _call(client, headers, TOOL_NAME, {})
        assert not result["isError"]
        public = result["structuredContent"]
        assert public["fixed_get_completed"] and not public["private_request_body_compiled"]
        assert public["Proposed Changes"]["changed_nonmaterial_fields"] == ["email-pulling-server", "server"]
        assert not public["Expected State"]["backend_material_preservation_qualified"]
        assert not public["execution_authorized"] and not public["independent_restore_authorized"]
        assert not public["authorization_or_operation_created"] and not public["configuration_written"]
        assert peer.calls == [("GET", CURRENT_PATH)]
        assert source._closed and not any(source._cookie)
        assert all(not any(buffer) for buffer in [*peer.buffers, *source._projection._buffers.values()])
        assert all(resource.closed for resource in peer.resources)
        assert owner._client is not None and owner._session_lock.locked()
        assert_private(result)
        assert _call(client, headers, TOOL_NAME, {})["isError"]
        assert len(peer.calls) == 1


@pytest.mark.parametrize("fault", ["read-scope", "foreign-client", "anonymous"])
def test_unauthorized_caller_cannot_read_or_consume_rightful_window(candidate, fault):
    settings, headers, _, peer, source, _, action = candidate
    with TestClient(create_http_app(settings, v4_approval_delivery_preview_action=action),
            base_url="https://mcp.example.com") as client:
        if fault == "anonymous":
            response = client.post("/fpamcp", json=dict(jsonrpc="2.0", id="read", method="tools/call",
                params=dict(name=TOOL_NAME, arguments={})))
            assert response.status_code == 401
        else:
            denied = _login(client, "fortipam:read" if fault == "read-scope" else "fortipam:read fortipam:plan")
            result = _call(client, denied, TOOL_NAME, {})
            assert result["isError"]
            assert_private(result)
        assert not peer.calls and not source._attempted and not source._closed
        assert not _call(client, headers, TOOL_NAME, {})["isError"]
        assert len(peer.calls) == 1


@pytest.mark.parametrize("fault", ["source-gate", "expired", "cookie", "html", "close"])
def test_invalid_source_window_or_response_returns_no_partial_preview(candidate, fault):
    settings, headers, _, peer, source, _, action = candidate
    if fault == "source-gate": source._guard = source._guard_pin = None
    elif fault == "expired": peer.time = source._expiry
    elif fault == "cookie": peer.cookie = "SYNTHETIC_REPLACED_COOKIE"
    elif fault == "html": peer.fault = "html"
    else:
        def hook(phase):
            if phase == "response-close": raise RuntimeError(CANARY)
        peer.hook = hook
    with TestClient(create_http_app(settings, v4_approval_delivery_preview_action=action),
            base_url="https://mcp.example.com") as client:
        result = _call(client, headers, TOOL_NAME, {})
        assert result["isError"] and "Current State" not in json.dumps(result)
        assert_private(result)
        assert len(peer.calls) == int(fault in ("html", "close"))
        assert source._closed and not any(source._cookie)
        assert all(not any(buffer) for buffer in peer.buffers)


@pytest.mark.parametrize("invalid", ["readonly", "plan-only", "bearer", "authority", "type"])
def test_factory_requires_explicit_controlled_oauth_binding(candidate, invalid):
    settings, _, _, peer, _, _, action = candidate
    if invalid == "readonly": settings = replace(settings, runtime_profile=RuntimeProfile.READONLY)
    elif invalid == "plan-only": settings = replace(settings, runtime_profile=RuntimeProfile.V4_PLAN_ONLY)
    elif invalid == "bearer": settings = replace(settings, auth_mode="bearer", bearer_token="synthetic-bearer")
    elif invalid == "authority": settings = replace(settings, v4_planning_authorization=None)
    else: action = object()
    with pytest.raises(HttpConfigurationError):
        create_http_app(settings, v4_approval_delivery_preview_action=action)
    assert not peer.calls


def test_default_absence_readonly_schema_and_unused_shutdown_disposal(candidate):
    settings, headers, _, peer, source, owner, action = candidate
    def tools(client):
        return client.post("/fpamcp", headers=headers,
            json=dict(jsonrpc="2.0", id="list", method="tools/list", params={})).json()["result"]["tools"]
    with TestClient(create_http_app(settings), base_url="https://mcp.example.com") as client:
        assert TOOL_NAME not in {tool["name"] for tool in tools(client)}
    with TestClient(create_http_app(settings, v4_approval_delivery_preview_action=action),
            base_url="https://mcp.example.com") as client:
        listing = tools(client)
        selected = [tool for tool in listing if tool["name"] == TOOL_NAME]
        assert len(selected) == 1 and selected[0]["inputSchema"].get("properties", {}) == {}
        assert selected[0]["annotations"]["readOnlyHint"] is True
        assert not any(tool["name"].startswith(("execute_v4_approval_delivery", "authorize_v4_approval_delivery")) for tool in listing)
        assert not source._closed and not peer.calls
    assert source._closed and not any(source._cookie) and not peer.calls
    assert owner._client is not None and owner._session_lock.locked()


@pytest.mark.parametrize("binding", ["source", "identity", "proposal", "roles"])
def test_relabelled_action_binding_denies_before_read(candidate, binding):
    settings, headers, _, peer, source, _, action = candidate
    if binding == "source": action._source = object()
    elif binding == "identity": action._identity = ("f" * 64, "e" * 64)
    elif binding == "proposal": action._proposal = tuple({**state(), "server": "SYNTHETIC_REPLACEMENT"}.items())
    else: source._bindings = {**source._bindings, "credential": "f" * 64}
    with TestClient(create_http_app(settings, v4_approval_delivery_preview_action=action),
            base_url="https://mcp.example.com") as client:
        result = _call(client, headers, TOOL_NAME, {})
        assert result["isError"] and not peer.calls and not source._attempted
        assert_private(result)


def test_host_proposal_is_snapshotted_before_mcp_use(candidate):
    settings, headers, principal, peer, source, _, _ = candidate
    proposal = state()
    action = action_for(source, principal, proposal)
    proposal["server"] = "SYNTHETIC_CHANGED_AFTER_CONSTRUCTION"
    proposal["port"] = 994
    with TestClient(create_http_app(settings, v4_approval_delivery_preview_action=action),
            base_url="https://mcp.example.com") as client:
        result = _call(client, headers, TOOL_NAME, {})
        assert not result["isError"]
        assert "port" not in result["structuredContent"]["Proposed Changes"]["changed_nonmaterial_fields"]
        assert "SYNTHETIC_CHANGED_AFTER_CONSTRUCTION" not in json.dumps(result)
    assert len(peer.calls) == 1


@pytest.mark.parametrize("protocol", ["imaps", "ms-graph"])
def test_host_enable_intent_for_both_protocols_stays_a_readonly_unqualified_preview(candidate, protocol):
    settings, headers, principal, peer, source, _, _ = candidate
    peer.payload["results"]["approval-email-setting"]["approval-email-protocol"] = protocol
    proposed = {**state(protocol), "port": 994}
    action = ApprovalDeliveryPreviewAction(source, proposed, enabled=True,
        requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest)
    with TestClient(create_http_app(settings, v4_approval_delivery_preview_action=action),
            base_url="https://mcp.example.com") as client:
        result = _call(client, headers, TOOL_NAME, {})
        assert not result["isError"]
        public = result["structuredContent"]
        assert public["Proposed Changes"]["enabled_intent"] is True
        assert public["Proposed Changes"]["protocol"] == protocol
        assert public["Proposed Changes"]["changed_nonmaterial_fields"] == ["port"]
        assert not public["execution_authorized"] and not public["native_current_response_or_ack_qualified"]
        assert_private(result)
    assert peer.calls == [("GET", CURRENT_PATH)] and source._closed


def test_lock_acquisition_cancellation_disposes_unused_cookie(candidate):
    _, _, principal, peer, source, _, action = candidate
    actual = source._lock
    class InterruptedLock:
        armed = True
        def __enter__(self):
            if self.armed:
                self.armed = False
                raise KeyboardInterrupt
            return actual.__enter__()
        def __exit__(self, *args):
            return actual.__exit__(*args)
    source._lock = InterruptedLock()
    with pytest.raises(KeyboardInterrupt):
        action.preview(principal)
    assert not peer.calls and source._closed and not any(source._cookie)


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_cleanup_error_before_public_handoff_disposes_material_and_returns_no_preview(candidate, monkeypatch, error_type):
    _, _, principal, peer, source, _, action = candidate
    original, calls = source.close, []
    def close():
        original()
        calls.append(True)
        if len(calls) == 1:
            raise error_type(CANARY)
    monkeypatch.setattr(source, "close", close)
    with pytest.raises(error_type) as error:
        action.preview(principal)
    if error_type is RuntimeError:
        assert CANARY not in str(error.value)
    assert source._closed and not any(source._cookie)
    assert all(not any(buffer) for buffer in [*peer.buffers, *source._projection._buffers.values()])
    monkeypatch.setattr(source, "close", original)


@pytest.mark.parametrize("truncated", [False, True])
def test_loopback_verified_tls_cookie_get_and_normal_oauth_mcp_never_write(candidate, tmp_path, monkeypatch, truncated):
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from test_secret_bulk_import_action_process import tls_material

    settings, headers, principal, peer, prototype, owner, _ = candidate
    certificate, key = tls_material(tmp_path)
    connections, buffers, requests = [], [], []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *_): pass
        def do_GET(self):
            requests.append(("GET", self.path))
            assert self.path == CURRENT_PATH and self.headers["Cookie"] == COOKIE
            assert self.headers.get("Authorization") is None
            raw = json.dumps(peer.payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw) + int(truncated)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)
        def do_PUT(self):
            requests.append(("PUT", self.path)); self.send_error(405)
        def do_POST(self):
            requests.append(("POST", self.path)); self.send_error(405)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(certificate, key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    source = None
    original_readinto = http.client.HTTPResponse.readinto
    def tracked_readinto(response, view):
        if not any(buffer is view.obj for buffer in buffers):
            buffers.append(view.obj)
        return original_readinto(response, view)
    monkeypatch.setattr(http.client.HTTPResponse, "readinto", tracked_readinto)
    def factory(host, port, **options):
        connection = http.client.HTTPSConnection(host, port, **options)
        connection._create_connection = lambda address, timeout, source_address: socket.create_connection(
            ("127.0.0.1", server.server_port), timeout, source_address)
        connections.append(connection)
        return connection
    try:
        prototype.close()
        owner._config = SecretMetadataHttpTransportConfig("https://pam.example.test", "synthetic-unused-bearer", 5, str(certificate))
        owner._raw_connection_factory = factory
        source = ApprovalDeliverySource(owner, expected_actor=ACTOR, expected_serial=SERIAL,
            material_binding_digests=BINDINGS, source_guard=lambda: True)
        action = action_for(source, principal)
        with TestClient(create_http_app(settings, v4_approval_delivery_preview_action=action),
                base_url="https://mcp.example.com") as client:
            result = _call(client, headers, TOOL_NAME, {})
            assert result["isError"] is truncated
            assert_private(result)
            if not truncated:
                assert not result["structuredContent"]["execution_authorized"]
            assert requests == [("GET", CURRENT_PATH)]
            assert source._closed and not any(source._cookie)
            assert buffers and all(not any(buffer) for buffer in buffers)
            assert all(connection.sock is None for connection in connections)
            assert _call(client, headers, TOOL_NAME, {})["isError"] and len(requests) == 1
        assert owner._client is not None and owner._session_lock.locked()
    finally:
        if source is not None: source.close()
        server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()


def registered_preview(action, principal):
    callbacks = []
    def tool(**_):
        def capture(callback):
            callbacks.append(callback)
            return callback
        return capture
    server = SimpleNamespace(_runtime_profile=RuntimeProfile.V4_CONTROLLED,
        _v4_planning_principal=lambda: principal, mcp=SimpleNamespace(tool=tool))
    register_approval_delivery_preview_tool(server, action)
    return callbacks[0]


@pytest.mark.parametrize("repeat", [False, True])
def test_async_cancellation_waits_for_blocked_read_disposal(candidate, repeat):
    _, _, principal, peer, source, _, action = candidate
    started, release = Event(), Event()
    def hook(phase):
        if (phase == "read" and not started.is_set()
                and all(secret in peer.buffers[0] for secret in SYNTHETIC.values())):
            started.set()
            assert release.wait(3)
    peer.hook = hook
    async def scenario():
        task = asyncio.create_task(registered_preview(action, principal)())
        try:
            assert await asyncio.to_thread(started.wait, 2)
            task.cancel()
            await asyncio.sleep(.02)
            if repeat:
                task.cancel()
                await asyncio.sleep(.02)
            assert not task.done(), "Cancellation must wait for the material-owning worker."
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert source._closed and not any(source._cookie)
            assert all(not any(buffer) for buffer in peer.buffers)
        finally:
            release.set()
            try: await task
            except asyncio.CancelledError: pass
    asyncio.run(scenario())


def test_queued_async_cancellation_drains_source_without_starting_a_get(candidate):
    from concurrent.futures import ThreadPoolExecutor
    _, _, principal, peer, source, _, action = candidate
    release = Event()
    async def scenario():
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
        entered = asyncio.Event()
        def occupy():
            loop.call_soon_threadsafe(entered.set)
            assert release.wait(3)
        busy = loop.run_in_executor(None, occupy)
        task = None
        try:
            await asyncio.wait_for(entered.wait(), 1)
            task = asyncio.create_task(registered_preview(action, principal)())
            await asyncio.sleep(.02)
            task.cancel()
            await asyncio.sleep(.02)
            assert not task.done() and not peer.calls
            release.set()
            with pytest.raises(asyncio.CancelledError): await task
            await busy
            assert not peer.calls and source._closed and not any(source._cookie)
        finally:
            release.set()
            await busy
            if task is not None:
                try: await task
                except asyncio.CancelledError: pass
    asyncio.run(scenario())


def test_async_cancel_with_cleanup_error_retrieves_worker_failure_and_disposes(candidate, monkeypatch):
    _, _, principal, peer, source, _, action = candidate
    started, release = Event(), Event()
    original = source.close
    def hook(phase):
        if phase == "read" and not started.is_set():
            started.set()
            assert release.wait(3)
    def close():
        original()
        raise RuntimeError(CANARY)
    peer.hook = hook
    monkeypatch.setattr(source, "close", close)
    async def scenario():
        errors = []
        asyncio.get_running_loop().set_exception_handler(lambda _loop, context: errors.append(context))
        task = asyncio.create_task(registered_preview(action, principal)())
        try:
            assert await asyncio.to_thread(started.wait, 2)
            task.cancel()
            await asyncio.sleep(.02)
            assert not task.done()
            release.set()
            with pytest.raises(asyncio.CancelledError): await task
            assert not errors and source._closed and not any(source._cookie)
            assert all(not any(buffer) for buffer in peer.buffers)
        finally:
            release.set()
            try: await task
            except asyncio.CancelledError: pass
    try:
        asyncio.run(scenario())
    finally:
        monkeypatch.setattr(source, "close", original)


def test_lifespan_cancel_waits_for_cookie_cleanup_even_after_repeated_cancellation(candidate, monkeypatch):
    _, _, _, peer, source, _, action = candidate
    started, release = Event(), Event()
    original, calls = source.close, []
    def close():
        calls.append(True)
        if len(calls) == 1:
            started.set()
            assert release.wait(3)
        original()
    monkeypatch.setattr(source, "close", close)
    async def scenario():
        async def receive(): return {"type": "lifespan.shutdown"}
        async def send(_): pass
        async def app(scope, receive, send): await receive()
        wrapped = wrap_approval_delivery_preview_shutdown(app, action)
        task = asyncio.create_task(wrapped({"type": "lifespan"}, receive, send))
        try:
            assert await asyncio.to_thread(started.wait, 2)
            task.cancel()
            await asyncio.sleep(.02)
            task.cancel()
            await asyncio.sleep(.02)
            assert not task.done()
            release.set()
            with pytest.raises(asyncio.CancelledError): await task
            assert not peer.calls and source._closed and not any(source._cookie)
        finally:
            release.set()
            try: await task
            except asyncio.CancelledError: pass
    asyncio.run(scenario())


@pytest.mark.parametrize("identity", ["requester", "client"])
def test_foreign_cancel_cannot_revoke_or_consume_rightful_window(candidate, identity):
    from concurrent.futures import ThreadPoolExecutor
    _, _, principal, peer, source, _, action = candidate
    foreign = (replace(principal, requester=replace(principal.requester, subject_ref="synthetic-foreign-requester"))
        if identity == "requester" else replace(principal, transport_namespace_digest="f" * 64))
    release = Event()
    async def scenario():
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
        entered = asyncio.Event()
        def occupy():
            loop.call_soon_threadsafe(entered.set)
            assert release.wait(3)
        busy = loop.run_in_executor(None, occupy)
        task = None
        try:
            await asyncio.wait_for(entered.wait(), 1)
            task = asyncio.create_task(registered_preview(action, foreign)())
            await asyncio.sleep(.02)
            task.cancel()
            await asyncio.sleep(.02)
            assert not source._closed and any(source._cookie)
            assert not peer.calls and not source._attempted
            release.set()
            await busy
            with pytest.raises(RuntimeError, match="^The private approval-delivery preview is unavailable.$"):
                await task
            result = await registered_preview(action, principal)()
            assert result["fixed_get_completed"] and source._closed and not any(source._cookie)
        finally:
            release.set()
            await busy
            if task is not None:
                try: await task
                except (RuntimeError, asyncio.CancelledError): pass
    asyncio.run(scenario())


def test_authorized_binding_cancel_after_queueing_still_disposes_its_source(candidate):
    from concurrent.futures import ThreadPoolExecutor
    _, _, principal, peer, source, _, action = candidate
    release = Event()
    async def scenario():
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
        entered = asyncio.Event()
        def occupy():
            loop.call_soon_threadsafe(entered.set)
            assert release.wait(3)
        busy = loop.run_in_executor(None, occupy)
        task = None
        try:
            await asyncio.wait_for(entered.wait(), 1)
            task = asyncio.create_task(registered_preview(action, principal)())
            await asyncio.sleep(.02)
            action._identity = ("f" * 64, "e" * 64)
            task.cancel()
            await asyncio.sleep(.02)
            release.set()
            with pytest.raises(asyncio.CancelledError): await task
            assert not peer.calls and source._closed and not any(source._cookie)
        finally:
            release.set()
            await busy
            if task is not None:
                try: await task
                except (RuntimeError, asyncio.CancelledError): pass
    asyncio.run(scenario())


def test_readonly_mcp_keeps_unrepresentable_inverse_visible_without_write_readiness(candidate):
    settings, headers, _, peer, source, _, action = candidate
    peer.payload["results"]["approval-email-setting"]["server-cert"] = "%0%"
    with TestClient(create_http_app(settings, v4_approval_delivery_preview_action=action),
            base_url="https://mcp.example.com") as client:
        result = _call(client, headers, TOOL_NAME, {})
        assert not result["isError"]
        public = result["structuredContent"]
        assert public["Expected State"]["local_sdk_inverse_available"] is False
        assert public["execution_authorized"] is False and public["independent_restore_authorized"] is False
        assert public["private_request_body_compiled"] is False
        assert_private(result)
    assert len(peer.calls) == 1 and source._closed and not any(source._cookie)
