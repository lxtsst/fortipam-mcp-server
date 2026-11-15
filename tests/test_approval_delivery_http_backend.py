"""Fixed Cookie/CSRF PUTs through actual M4; product/ACK/qualification are synthetic."""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from fortipam_mcp.approval_delivery_http_backend import ApprovalDeliveryHttpBackend
from fortipam_mcp.approval_delivery_execution_contract import ApprovalDeliveryExecutionIntent, readback_from_approval_source
from fortipam_mcp.approval_delivery_source import ApprovalDeliverySource, CURRENT_PATH
from fortipam_mcp.approval_delivery_m4 import ApprovalDeliveryM4Adapter
from test_approval_delivery_source import Peer as ReadPeer, ACTOR, candidate as source_candidate  # noqa: F401
from test_approval_delivery_material_contract import BINDINGS, SYNTHETIC
from test_approval_delivery_material import Resolver
from test_approval_delivery_contract import state
from test_approval_delivery_m4 import SCOPE, NEW_BINDINGS, NEW_MATERIAL, Evidence, grant
from test_fortitoken_local_m4 import stores
from test_system_email_m4_adapter import Clock, Verifier
from v4_planning import M4AdapterDenied, M4ExecutionKernel
from v4_planning.material_provider import MaterialBindingStatus

CSRF = "SYNTHETIC_CSRF_DO_NOT_HASH"
COOKIE = "APSCOOKIE=SYNTHETIC_COOKIE_DO_NOT_HASH; ccsrftoken=" + CSRF
OPAQUE = "SYNTHETIC_ACK_REVISION_DO_NOT_DECODE_OR_HASH"


class Peer(ReadPeer):
    def __init__(self, protocol="imaps"):
        super().__init__(protocol)
        self.cookie, self.epoch = COOKIE, Clock()
        self.preservation = SCOPE.preservation_digest
        self.writes, self.write_buffers = [], []
        self.write_fault = None
        self.on_connect = self.on_request = lambda: None
    @property
    def row(self): return self.payload["results"]["approval-email-setting"]
    def factory(self, *args, **kwargs):
        peer = self
        connection = super().factory(*args, **kwargs)
        connect, request, getresponse, close = connection.connect, connection.request, connection.getresponse, connection.close
        def connected():
            connect(); self.on_connect()
        def requested(method, path, *, body=None, headers):
            if method != "PUT": return request(method, path, headers=headers)
            self.on_request()
            assert path == CURRENT_PATH and headers["Cookie"] == COOKIE and headers["X-CSRFTOKEN"] == CSRF
            assert "Authorization" not in headers and "X-HTTP-Method-Override" not in headers
            self.writes.append((method, path)); self.write_buffers.append(body)
            self.row.clear(); self.row.update(json.loads(body)["approval-email-setting"])
            connection.write = True
        def response():
            if not getattr(connection, "write", False): return getresponse()
            if self.write_fault == "lost-ack": raise TimeoutError(OPAQUE)
            if self.write_fault == "interrupt": raise KeyboardInterrupt
            document = dict(http_method="PUT", http_status=200, status="success", serial="SYNTHETIC01",
                version="v7.0.0", build=29, path="secret", name="setting", revision=OPAQUE, revision_changed=True)
            if self.write_fault == "foreign-ack": document["serial"] = "SYNTHETIC_FOREIGN_DEVICE"
            elif self.write_fault == "wrong-method": document["http_method"] = "POST"
            elif self.write_fault == "bool-build": document["build"] = True
            elif self.write_fault == "material-echo": document["credential"] = "SYNTHETIC_ECHO_MUST_NOT_BE_DECODED"
            elif self.write_fault == "wrong-role": peer.row["client-secret"] = "SYNTHETIC_OTHER_SLOT"
            elif self.write_fault == "preservation": peer.preservation = "0"*64
            raw = json.dumps(document, separators=(",", ":")).encode()
            if self.write_fault == "duplicate": raw = raw.replace(b'"name":"setting"', b'"name":"setting","name":"setting"')
            if self.write_fault == "oversize": raw += b" "*16385
            class Response:
                status = 200
                def __init__(self): self.offset, self.closed = 0, False; peer.resources.append(self)
                def getheader(self, name, default=None):
                    return {"content-type": "text/html" if peer.write_fault == "html" else "application/json",
                        "content-encoding": "gzip" if peer.write_fault == "gzip" else "identity",
                        "content-length": str(len(raw)+(1 if peer.write_fault == "truncated" else 0))}.get(name.lower(), default)
                def isclosed(self): return self.offset >= len(raw)
                def readinto(self, view):
                    if not peer.buffers or peer.buffers[-1] is not view.obj: peer.buffers.append(view.obj)
                    count = min(len(view), len(raw)-self.offset, 113)
                    view[:count] = raw[self.offset:self.offset+count]; self.offset += count
                    if peer.write_fault == "post-deadline": peer.time += 6
                    return count
                def close(self):
                    self.closed = True
                    if peer.write_fault == "response-close": raise RuntimeError(OPAQUE)
                    if peer.write_fault == "late-close": peer.time += 6
            result = Response()
            if self.write_fault == "detached": connection.sock = None
            return result
        def closed():
            close()
            if getattr(connection, "write", False) and peer.write_fault == "connection-close": raise RuntimeError(OPAQUE)
        connection.connect, connection.request, connection.getresponse, connection.close = connected, requested, response, closed
        return connection


class Witness:
    def __init__(self, peer): self.peer = peer
    @property
    def row(self): return self.peer.row
    @property
    def preservation(self): return self.peer.preservation
    def clock(self): return self.peer.epoch()


@pytest.fixture
def candidate(source_candidate):
    created = []
    def make(root, protocol="imaps", *, enabled=True, guarded=True, cookie=COOKIE, configure_owner=None):
        _, prototype, owner = source_candidate(protocol); prototype.close()
        peer = Peer(protocol); peer.cookie = cookie
        owner._client, owner._clock, owner._raw_connection_factory = peer.client(), peer.clock, peer.factory
        if configure_owner is not None: configure_owner(owner)
        source = ApprovalDeliverySource(owner, expected_actor=ACTOR, expected_serial="SYNTHETIC01",
            material_binding_digests=BINDINGS, source_guard=lambda: True)
        source.read()
        original = readback_from_approval_source(source, source_digest=SCOPE.configuration_source_digest, clock=peer.epoch)
        intent = ApprovalDeliveryExecutionIntent(original, {**state("ms-graph" if protocol == "imaps" else "imaps"), "port": 994},
            enabled=True, original_material_bindings=BINDINGS, proposed_material_bindings=NEW_BINDINGS)
        execution, material = stores(root); plan, authorization = grant(intent, execution, material)
        backend = ApprovalDeliveryHttpBackend(owner, intent, plan.parameters_digest, expected_actor=ACTOR,
            expected_serial="SYNTHETIC01", source_digest=SCOPE.configuration_source_digest, clock=peer.epoch,
            execution_enabled=enabled, source_guard=(lambda: True) if guarded else None)
        created.append(backend)
        evidence = Evidence(Witness(peer), intent)
        resolver = Resolver(intent.material_binding().material_binding_digest); resolver.values = NEW_MATERIAL
        recovery = Resolver(intent.material_binding(restore=True).material_binding_digest)
        verifier = Verifier(plan, authorization)
        adapter = ApprovalDeliveryM4Adapter(intent, backend, evidence, resolver, recovery, plan, authorization, execution, material,
            scope=SCOPE, authorization_verifier=verifier, execution_enabled=True, source_guard=lambda: True, clock=peer.epoch)
        return SimpleNamespace(peer=peer, owner=owner, backend=backend, intent=intent, execution=execution, material=material,
            plan=plan, authorization=authorization, verifier=verifier, resolver=resolver, recovery=recovery, evidence=evidence,
            adapter=adapter, kernel=M4ExecutionKernel(adapter, verifier, execution, clock=peer.epoch))
    yield make
    for backend in created: backend.close()


def restore(value, *, enabled=True):
    plan, authorization = grant(value.intent, value.execution, value.material, restore=True, issued_at=value.peer.epoch())
    verifier = Verifier(plan, authorization)
    resolver = Resolver(value.intent.material_binding(restore=True).material_binding_digest)
    adapter = value.adapter.bind_restore(plan, authorization, resolver=resolver, authorization_verifier=verifier, execution_enabled=enabled)
    return M4ExecutionKernel(adapter, verifier, value.execution, clock=value.peer.epoch), plan, authorization, resolver


@pytest.mark.parametrize("protocol", ["imaps", "ms-graph"])
def test_fixed_cookie_puts_replace_all_slots_and_independently_restore_once(candidate, tmp_path, protocol):
    value = candidate(tmp_path, protocol); original = deepcopy(value.peer.row)
    assert value.kernel.execute(value.plan, value.authorization).outcome == "succeeded"
    assert value.kernel.execute(value.plan, value.authorization).idempotent_replay
    value.peer.epoch.value = 1010
    kernel, plan, authorization, resolver = restore(value)
    assert kernel.execute(plan, authorization).outcome == "succeeded"
    assert kernel.execute(plan, authorization).idempotent_replay
    assert value.peer.row == original and value.peer.writes == [("PUT", CURRENT_PATH)]*2
    assert value.execution.claim_count == value.material.claim_count == 2 and resolver.loads == 1
    assert all(not any(buffer) for buffer in value.peer.buffers + value.peer.write_buffers + value.resolver.buffers + resolver.buffers)
    assert all(resource.closed for resource in value.peer.resources)
    assert value.owner._client is not None and value.owner._session_lock.locked() and value.peer.credentials == 0


@pytest.mark.parametrize("fault", ["lost-ack", "foreign-ack", "wrong-method", "bool-build", "material-echo", "duplicate",
    "wrong-role", "preservation", "html", "gzip", "truncated", "oversize", "response-close", "connection-close", "post-deadline", "late-close"])
def test_uncertain_put_or_ack_cleanup_cannot_restore_or_repeat(candidate, tmp_path, fault):
    value = candidate(tmp_path); value.peer.write_fault = fault
    assert value.kernel.execute(value.plan, value.authorization).outcome != "succeeded"
    assert value.kernel.execute(value.plan, value.authorization).idempotent_replay
    assert len(value.peer.writes) == value.execution.claim_count == value.material.claim_count == value.resolver.loads == 1
    with pytest.raises(M4AdapterDenied): restore(value)
    assert all(not any(buffer) for buffer in value.peer.buffers + value.peer.write_buffers + value.resolver.buffers)


@pytest.mark.parametrize("options", [dict(enabled=False), dict(guarded=False), dict(cookie="APSCOOKIE=SYNTHETIC_WITHOUT_CSRF")])
def test_closed_write_gate_source_guard_or_missing_csrf_never_sends(candidate, tmp_path, options):
    value = candidate(tmp_path, **options)
    assert value.kernel.execute(value.plan, value.authorization).outcome != "succeeded"
    assert value.peer.writes == []


def test_detached_http_connection_keeps_original_handle_for_bounded_ack_read(candidate, tmp_path):
    value = candidate(tmp_path); value.peer.write_fault = "detached"
    assert value.kernel.execute(value.plan, value.authorization).outcome == "succeeded"
    assert len(value.peer.writes) == 1


def test_interrupted_ack_does_not_supply_restore_rights_or_new_dispatch(candidate, tmp_path):
    value = candidate(tmp_path); value.peer.write_fault = "interrupt"
    with pytest.raises(KeyboardInterrupt): value.kernel.execute(value.plan, value.authorization)
    assert len(value.peer.writes) == value.resolver.loads == 1
    assert all(not any(buffer) for buffer in value.peer.buffers + value.peer.write_buffers + value.resolver.buffers)
    with pytest.raises(M4AdapterDenied): restore(value)


def test_before_send_gets_share_http_total_deadline(candidate, tmp_path):
    value = candidate(tmp_path)
    def consume_budget():
        # Reads before dispatch do not consume the HTTP submission's budget.
        # Once the write claim exists, the final GETs share that same budget.
        if value.backend._attempted: value.peer.time += 3
    value.peer.on_connect = consume_budget
    assert value.kernel.execute(value.plan, value.authorization).outcome != "succeeded"
    assert value.peer.writes == []


def test_foreign_body_cannot_substitute_material_outside_original_active_lease(candidate, tmp_path, monkeypatch):
    value = candidate(tmp_path)
    submit = value.backend.submit
    foreign = bytearray()
    def replaced(body, **kwargs):
        foreign.extend(body)
        position = foreign.find(NEW_MATERIAL[1])
        assert position >= 0
        foreign[position] ^= 1
        with memoryview(foreign).toreadonly() as view: return submit(view, **kwargs)
    monkeypatch.setattr(value.backend, "submit", replaced)
    try:
        assert value.kernel.execute(value.plan, value.authorization).outcome != "succeeded"
        assert value.peer.writes == [] and value.resolver.loads == 1
    finally:
        foreign[:] = b"\0"*len(foreign)


def test_generic_callback_or_original_callback_outside_kernel_cannot_consume_phase(candidate, tmp_path):
    value = candidate(tmp_path)
    for callback in (lambda: 5, value.adapter._before_send):
        with memoryview(bytearray(b"{}" )).toreadonly() as view, pytest.raises(ValueError):
            value.backend.submit(view, parameters_digest=value.plan.parameters_digest,
                restore=False, before_send=callback, timeout_seconds=5)
    assert not value.backend._attempted and value.peer.writes == [] and value.resolver.loads == 0
    assert value.kernel.execute(value.plan, value.authorization).outcome == "succeeded"


@pytest.mark.parametrize("mutation", ["backend-gate", "adapter-gate", "guard", "cookie", "owner-client"])
def test_final_connect_callback_revocation_never_sends(candidate, tmp_path, mutation):
    value = candidate(tmp_path)
    def revoke():
        if not value.backend._attempted: return
        if mutation == "backend-gate": value.backend._enabled = False
        elif mutation == "adapter-gate": value.adapter._enabled = False
        elif mutation == "guard": value.adapter._guard = lambda: True
        elif mutation == "cookie": value.peer.cookie = "SYNTHETIC_REPLACEMENT_COOKIE"
        else: value.owner._client = value.peer.client()
    value.peer.on_connect = revoke
    assert value.kernel.execute(value.plan, value.authorization).outcome != "succeeded"
    assert value.peer.writes == []
    assert all(not any(buffer) for buffer in value.resolver.buffers)


@pytest.mark.parametrize("revoke", ["source", "close", "authorization"])
def test_final_guard_cannot_revoke_material_after_its_availability_check(candidate, tmp_path, revoke):
    value = candidate(tmp_path)
    ready = []
    validate = value.resolver.validate_prebound
    def status():
        result = validate()
        if value.adapter._send_admitted: ready.append(True)
        return result
    def guard():
        if ready:
            if revoke == "source": value.resolver.status = MaterialBindingStatus.UNAVAILABLE
            elif revoke == "close": value.adapter._provider.close()
            else: value.verifier.pair = (None, None)
        return True
    value.resolver.validate_prebound = status
    value.adapter._guard = value.adapter._guard_pin = guard
    assert value.kernel.execute(value.plan, value.authorization).outcome != "succeeded"
    assert value.peer.writes == []
    assert value.resolver.loads == 1 and all(not any(buffer) for buffer in value.resolver.buffers)


@pytest.mark.parametrize("revoke", ["provider", "request", "source-guard", "deadline", "owner-client", "cookie"])
def test_last_http_guard_keeps_active_lease_and_owner_window_pinned(candidate, tmp_path, revoke):
    from dataclasses import replace
    value = candidate(tmp_path)
    def guard():
        if value.adapter._send_verified:
            if revoke == "provider": value.adapter._provider.close()
            elif revoke == "request":
                value.adapter._material_request = replace(value.adapter._material_request, audience_digest="0"*64)
            elif revoke == "source-guard": value.backend._window._guard = None
            elif revoke == "deadline": value.peer.time += 6
            elif revoke == "cookie": value.peer.cookie = "SYNTHETIC_REPLACEMENT_COOKIE"
            else: value.owner._client = value.peer.client()
        return True
    value.adapter._guard = value.adapter._guard_pin = guard
    assert value.kernel.execute(value.plan, value.authorization).outcome != "succeeded"
    assert value.peer.writes == []
    assert value.resolver.loads == 1 and all(not any(buffer) for buffer in value.resolver.buffers)


def test_final_material_status_callback_cannot_revoke_checked_authorization(candidate, tmp_path):
    value = candidate(tmp_path)
    validate = value.resolver.validate_prebound
    def status():
        result = validate()
        if value.adapter._send_verified: value.verifier.pair = (None, None)
        return result
    value.resolver.validate_prebound = status
    assert value.kernel.execute(value.plan, value.authorization).outcome != "succeeded"
    assert value.peer.writes == []
    assert value.resolver.loads == 1 and all(not any(buffer) for buffer in value.resolver.buffers)


@pytest.mark.parametrize("lost_ack", [None, "configure", "restore"])
def test_real_loopback_verified_tls_cookie_put_and_independent_restore(candidate, tmp_path, monkeypatch, lost_ack):
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import ssl
    from threading import Thread
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from test_secret_bulk_import_action_process import tls_material

    certificate, key = tls_material(tmp_path)
    requests, connections, buffers = [], [], []
    payload = ReadPeer().payload
    writes = []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *_): pass
        def reply(self, document):
            raw = json.dumps(document).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers(); self.wfile.write(raw)
        def do_GET(self):
            requests.append(("GET", self.path))
            assert self.path == CURRENT_PATH and self.headers["Cookie"] == COOKIE
            assert self.headers.get("Authorization") is None
            self.reply(payload)
        def do_PUT(self):
            requests.append(("PUT", self.path))
            assert self.path == CURRENT_PATH and self.headers["Cookie"] == COOKIE
            assert self.headers["X-CSRFTOKEN"] == CSRF and self.headers.get("Authorization") is None
            assert self.headers["Content-Type"] == "application/json"
            payload["results"]["approval-email-setting"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))['approval-email-setting']
            writes.append(True)
            if lost_ack == ("configure" if len(writes) == 1 else "restore"):
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            self.reply(dict(http_method="PUT", http_status=200, status="success", serial="SYNTHETIC01",
                version="v7.0.0", build=29, path="secret", name="setting", revision=OPAQUE))
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(certificate, key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True); thread.start()
    original_readinto = http.client.HTTPResponse.readinto
    def tracked_readinto(response, view):
        if not any(buffer is view.obj for buffer in buffers): buffers.append(view.obj)
        return original_readinto(response, view)
    monkeypatch.setattr(http.client.HTTPResponse, "readinto", tracked_readinto)
    def factory(host, port, **options):
        assert host == "pam.example.test" and options['context'].check_hostname
        connection = http.client.HTTPSConnection(host, port, **options)
        connection._create_connection = lambda address, timeout, source_address: socket.create_connection(
            ("127.0.0.1", server.server_port), timeout, source_address)
        connections.append(connection)
        return connection
    def configure(owner):
        owner._config = SecretMetadataHttpTransportConfig("https://pam.example.test", "synthetic-unused-bearer", 5, str(certificate))
        owner._raw_connection_factory = factory
    try:
        value = candidate(tmp_path, configure_owner=configure)
        # Independent evidence observes the same synthetic peer served over TLS.
        value.peer.payload = payload
        original = deepcopy(value.peer.row)
        result = value.kernel.execute(value.plan, value.authorization)
        assert (result.outcome == "succeeded") is (lost_ack != "configure")
        assert value.kernel.execute(value.plan, value.authorization).idempotent_replay
        if lost_ack == "configure":
            with pytest.raises(M4AdapterDenied): restore(value)
        else:
            kernel, plan, authorization, resolver = restore(value)
            result = kernel.execute(plan, authorization)
            assert (result.outcome == "succeeded") is (lost_ack is None)
            assert kernel.execute(plan, authorization).idempotent_replay
            assert resolver.loads == 1 and all(not any(buffer) for buffer in resolver.buffers)
            assert value.peer.row == original
        assert len(writes) == (1 if lost_ack == "configure" else 2)
        assert all(path == CURRENT_PATH for _, path in requests)
        assert all(connection.sock is None for connection in connections)
        assert buffers and all(not any(buffer) for buffer in buffers + value.resolver.buffers)
        assert value.owner._session_lock.locked() and value.peer.credentials == 0
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
