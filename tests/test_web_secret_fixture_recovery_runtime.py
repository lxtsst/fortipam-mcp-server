"""Real original/M4 custody and complete producers; every device is synthetic."""
from dataclasses import replace
import os
import ssl
from types import SimpleNamespace

import pytest

from fortipam_mcp import web_secret_fixture_recovery_runtime as w
from fortipam_mcp import web_secret_fixture_recovery_guard as g
from v4_planning import M4ExecutionPlan, M4ExecutionAuthorization, M4ClaimState, canonical_digest
from test_instruction_feature_http_reader import Client, Response
from test_web_secret_fixture_recovery_guard import _fixture as guard_fixture
from test_web_secret_create_ack import _raw


class NativeResponse:
    def __init__(self, method):
        self.status = 404 if method == 'GET' else 200
        value = {'version': 'v7.0.0', 'build': 29, 'path': 'secret', 'name': 'database',
            'vdom': 'root', 'serial': 'unit-appliance', 'http_method': method,
            'http_status': self.status, 'status': 'Not Found' if method == 'GET' else 'success',
            'error': 2 if method == 'GET' else 0}
        if method == 'DELETE': value['mkey'] = 37
        self.raw, self.offset = _raw(value), 0
        self.headers = {'Content-Type': 'application/json'}
        self.closed, self.fail_close = False, False
        self.buffers = []
    def getheader(self, name, default=None): return self.headers.get(name, default)
    def isclosed(self): return self.closed or self.offset == len(self.raw)
    def readinto1(self, view):
        self.buffers.append(view.obj)
        size = min(len(view), len(self.raw) - self.offset)
        view[:size] = memoryview(self.raw)[self.offset:self.offset + size]
        self.offset += size
        return size
    def close(self):
        self.closed = True
        if self.fail_close: raise OSError('must-not-surface-private-value')


class NativeConnection:
    def __init__(self, method, events):
        self.response = NativeResponse(method)
        self.sock = SimpleNamespace(settimeout=lambda timeout: None)
        self.events, self.calls = events, []
        self.closed, self.fail_close = False, False
        self.on_connect = lambda: None
    def connect(self):
        self.events.append('tls')
        self.on_connect()
    def request(self, method, path, **kwargs):
        assert set(kwargs) == {'headers'}
        self.events.append(method)
        self.calls.append((method, path, kwargs))
    def getresponse(self): return self.response
    def close(self):
        self.closed = True
        self.sock = None
        if self.fail_close: raise OSError('must-not-surface-private-value')


class SyntheticVerifier:
    """A test-only exact recovery grant; no product authorization issuer."""
    def __init__(self): self.expected, self.calls, self.store, self.fail = None, 0, None, False
    def verify(self, plan, authorization, *, now_epoch):
        self.calls += 1
        assert self.calls == 1
        assert self.expected is not None and (plan, authorization) == self.expected
        assert authorization.issued_at <= now_epoch < plan.expires_at
        claim = self.store.inspect_claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
            idempotency_digest=plan.idempotency_digest, authorization_digest=authorization.authorization_digest,
            context_digest=canonical_digest({'authorization_digest': authorization.authorization_digest,
                'plan_digest': plan.plan_digest, 'revision': plan.revision}))
        assert claim.state is M4ClaimState.IN_PROGRESS
        if self.fail: raise ValueError('Synthetic verifier unavailable')


def fixture(tmp_path, monkeypatch, *, default_verifier=False, enabled=True):
    guard, record, inputs, clients, _, _, _, now = guard_fixture(tmp_path, monkeypatch)
    clients.append(Client([Response(bytearray(item.content)) for item in clients[0].responses]))
    events = []
    pending = iter(clients)
    def producer(**kwargs):
        events.append('full-read')
        return next(pending)
    guard._factory = producer
    for reader in (guard._baseline, guard._recovery, guard._dispatch): reader._factory = producer
    connections = [NativeConnection('DELETE', events), NativeConnection('GET', events)]
    native_pending = iter(connections)
    def factory(*args, **kwargs):
        assert kwargs['context'].verify_mode == ssl.CERT_REQUIRED and kwargs['context'].check_hostname
        assert kwargs['timeout'] <= 10
        return next(native_pending)
    monkeypatch.setattr(w, '_ssl_context', lambda _: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    verifier = SyntheticVerifier()
    verifier.store = record._execution_store
    runtime = w.WebSecretFixtureRecoveryRuntime(guard, delete_status='success', execution_enabled=enabled,
        authorization_verifier=None if default_verifier else verifier, connection_factory=factory)
    return runtime, guard, record, inputs, clients, connections, events, verifier, now


def issue(runtime, record, verifier):
    preview = runtime.preview()
    values = record._execution_binding.plan.canonical_content()
    values.update(plan_ref='synthetic-web-recovery-plan', action_id=w.ACTION, action_version='1.0.0',
        adapter_ref=w.ADAPTER, target_ref=preview.target_ref, expected_current_digest=preview.current_digest,
        expected_state_digest=preview.expected_digest, parameters_digest=preview.parameters_digest,
        expires_at=preview.expires_at, compensation_ref=None, idempotency_digest='8' * 64)
    plan = M4ExecutionPlan(**values, plan_digest=canonical_digest(values))
    values = record._execution_binding.authorization.canonical_content()
    values.update(authorization_ref='synthetic-web-recovery-auth', plan_ref=plan.plan_ref,
        plan_digest=plan.plan_digest, issued_at=100, expires_at=preview.expires_at)
    authorization = M4ExecutionAuthorization(**values, authorization_digest=canonical_digest(values))
    verifier.expected = plan, authorization
    return plan, authorization


def test_complete_fixed_recovery_joins_original_and_fresh_producers_to_m4(tmp_path, monkeypatch):
    runtime, guard, record, inputs, clients, connections, events, verifier, _ = fixture(tmp_path, monkeypatch)
    original = record.read_acknowledged_creation()
    connections[0].response.raw = connections[0].response.raw[:-1] + b',"results":{"field":"must-not-decode"}}'
    scalar = w.m._scalar
    def selected(raw, span):
        assert b'must-not-decode' not in raw[slice(*span)]
        return scalar(raw, span)
    monkeypatch.setattr(w.m, '_scalar', selected)
    plan, authorization = issue(runtime, record, verifier)
    result = runtime.execute(plan, authorization)
    assert verifier.calls == 1
    assert result.as_dict() == {'outcome': 'succeeded', 'verification': 'verified',
        'compensation': 'not_requested', 'idempotent_replay': False}
    assert events == ['full-read', 'full-read', 'tls', 'full-read', 'DELETE', 'tls', 'GET']
    assert connections[0].calls[0][1] == '/api/v2/cmdb/secret/database/37'
    assert connections[1].calls[0][1] == '/api/v2/cmdb/secret/database/37?format=id'
    assert all(len(client.calls) == 7 and client.is_closed and not client.cookies for client in clients)
    assert all(connection.closed and connection.response.closed for connection in connections)
    assert all(not any(buffer) for connection in connections for buffer in connection.response.buffers)
    assert record.read_acknowledged_creation() == original
    assert (inputs['directory'] / w._ATTEMPT).exists() and (inputs['directory'] / w._ACK).exists()
    assert (inputs['directory'] / 'api-preservation.recovery-dispatch.attempt').exists()
    with pytest.raises(w.WebSecretFixtureRecoveryError): runtime.execute(plan, authorization)
    with pytest.raises(w.WebSecretFixtureRecoveryError):
        w.WebSecretFixtureRecoveryRuntime(guard, delete_status='success', execution_enabled=True)
    assert all(len(connection.calls) == 1 for connection in connections)
    runtime.close()


def test_native_completed_response_does_not_reset_a_closed_socket_timeout(tmp_path, monkeypatch):
    import http.client
    from io import BytesIO
    runtime, _, record, _, _, connections, _, verifier, _ = fixture(tmp_path, monkeypatch)
    for connection in connections:
        payload = bytes(connection.response.raw)
        packet = (f"HTTP/1.1 {connection.response.status} Synthetic\r\nContent-Type: application/json\r\n"
                  f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n").encode() + payload
        socket = SimpleNamespace(makefile=lambda *args, packet=packet: BytesIO(packet))
        response = http.client.HTTPResponse(socket)
        response.begin()
        assert not response.isclosed()
        connection.response = response
        def settimeout(timeout, response=response):
            if response.isclosed():
                raise OSError("Synthetic socket closed after complete HTTP body")
        connection.sock = SimpleNamespace(settimeout=settimeout)
    plan, authorization = issue(runtime, record, verifier)
    assert runtime.execute(plan, authorization).as_dict()["outcome"] == "succeeded"
    assert all(connection.response.isclosed() for connection in connections)


def test_native_api_requires_user_agent_before_returning_a_response(tmp_path, monkeypatch):
    import http.client
    runtime, _, record, _, _, connections, _, verifier, _ = fixture(tmp_path, monkeypatch)
    for connection in connections:
        def response(connection=connection):
            if not connection.calls[-1][2]["headers"].get("User-Agent"):
                raise http.client.RemoteDisconnected("Synthetic missing User-Agent")
            return connection.response
        connection.getresponse = response
    plan, authorization = issue(runtime, record, verifier)
    assert runtime.execute(plan, authorization).as_dict()["outcome"] == "succeeded"


@pytest.mark.parametrize('fault', ['default-verifier', 'verifier-failure', 'claim-failure', 'foreign-plan', 'expired', 'password-drift', 'totp-drift', 'unknown-drift', 'marker', 'close'])
def test_prewrite_denial_never_deletes_or_retries(tmp_path, monkeypatch, fault):
    runtime, guard, record, inputs, clients, connections, _, verifier, now = fixture(tmp_path, monkeypatch,
        default_verifier=fault == 'default-verifier')
    plan, authorization = issue(runtime, record, verifier)
    if fault == 'verifier-failure': verifier.fail = True
    if fault == 'claim-failure':
        def fail_claim(**kwargs): raise ValueError('Synthetic claim unavailable')
        monkeypatch.setattr(record._execution_store, 'claim', fail_claim)
    if fault == 'foreign-plan':
        values = plan.canonical_content(); values['action_id'] = 'synthetic-wrong-action'
        plan = M4ExecutionPlan(**values, plan_digest=canonical_digest(values))
    elif fault == 'expired': now[0] = 160
    elif fault == 'password-drift':
        def drift():
            for i in (1, 5): clients[2].responses[i].content = clients[2].responses[i].content.replace(b'synthetic-password', b'changed-password')
        connections[0].on_connect = drift
    elif fault == 'totp-drift':
        for i in (2, 4): clients[2].responses[i].content = clients[2].responses[i].content.replace(b'"results":""', b'"results":"changed-key"')
    elif fault == 'unknown-drift':
        for i in (0, 3, 6): clients[2].responses[i].content = clients[2].responses[i].content.replace(b'"instruction-profile":""', b'"future-config":true,"instruction-profile":""')
    elif fault == 'marker':
        connections[0].on_connect = lambda: (inputs['directory'] / w._ATTEMPT).write_bytes(b'changed')
    elif fault == 'close':
        connections[0].on_connect = lambda: (_ for _ in ()).throw(ValueError())
        connections[0].fail_close = True
    if fault in {'default-verifier', 'verifier-failure', 'claim-failure', 'foreign-plan', 'expired', 'close'}:
        with pytest.raises(w.WebSecretFixtureRecoveryError) as caught: runtime.execute(plan, authorization)
        assert str(caught.value) == w._ERROR
    else:
        assert runtime.execute(plan, authorization).as_dict()['outcome'] == 'denied'
    assert not any(connection.calls for connection in connections)
    if fault == 'claim-failure': assert verifier.calls == 0
    if fault == 'verifier-failure': assert verifier.calls == 1
    if fault not in {'default-verifier', 'foreign-plan', 'expired'}:
        with pytest.raises(w.WebSecretFixtureRecoveryError): runtime.execute(plan, authorization)
        assert (inputs['directory'] / w._ATTEMPT).exists()


@pytest.mark.parametrize('fault', ['ack-id', 'ack-status', 'ack-chunked', 'ack-close', 'absence-results', 'absence-serial', 'ack-removed'])
def test_ambiguous_delete_or_absence_keeps_terminal_claim(tmp_path, monkeypatch, fault):
    runtime, _, record, inputs, _, connections, _, verifier, _ = fixture(tmp_path, monkeypatch)
    plan, authorization = issue(runtime, record, verifier)
    ack, absent = connections[0].response, connections[1].response
    if fault == 'ack-id': ack.raw = ack.raw.replace(b'"mkey":37', b'"mkey":38')
    elif fault == 'ack-status': ack.raw = ack.raw.replace(b'"status":"success"', b'"status":"OK"')
    elif fault == 'ack-chunked': ack.headers['Transfer-Encoding'] = 'chunked'
    elif fault == 'ack-close': ack.fail_close = True
    elif fault == 'absence-results': absent.raw = absent.raw[:-1] + b',"results":[{"field":"must-not-decode"}]}'
    elif fault == 'absence-serial': absent.raw = absent.raw.replace(b'unit-appliance', b'foreign-device')
    else: connections[1].on_connect = lambda: (inputs['directory'] / w._ACK).unlink()
    result = runtime.execute(plan, authorization)
    assert result.as_dict()['outcome'] == 'reconciliation_required'
    assert result.as_dict()['verification'] == 'unknown'
    assert len(connections[0].calls) == 1
    assert len(connections[1].calls) == (1 if fault.startswith('absence-') else 0)
    with pytest.raises(w.WebSecretFixtureRecoveryError): runtime.execute(plan, authorization)
    assert (inputs['directory'] / w._ATTEMPT).exists()
    assert all(connection.closed for connection in connections if connection.calls or fault == 'ack-removed')


def test_default_gate_refuses_preview_before_material_http(tmp_path, monkeypatch):
    runtime, _, _, _, clients, connections, _, _, _ = fixture(tmp_path, monkeypatch, enabled=False)
    with pytest.raises(w.WebSecretFixtureRecoveryError): runtime.preview()
    assert all(not client.calls for client in clients) and all(not connection.calls for connection in connections)


def test_outer_deadline_also_bounds_fresh_full_reader(tmp_path, monkeypatch):
    runtime, guard, record, _, clients, connections, _, verifier, _ = fixture(tmp_path, monkeypatch)
    ticks = [0.]
    clock = lambda: ticks[0]
    guard._http_clock = clock
    for reader in (guard._baseline, guard._recovery, guard._dispatch): reader._clock = clock
    plan, authorization = issue(runtime, record, verifier)
    limit = min(30., runtime._config.timeout_seconds)
    connections[0].on_connect = lambda: ticks.__setitem__(0, limit - 1)
    response = clients[2].responses[0]
    def chunks():
        yield bytes(response.content)
        ticks[0] = limit + 1
    response.iter_raw = chunks
    assert runtime.execute(plan, authorization).as_dict()['outcome'] == 'denied'
    assert len(clients[2].calls) == 1 and clients[2].is_closed
    assert not any(connection.calls for connection in connections)


@pytest.mark.parametrize('name', [w._ATTEMPT, w._ACK])
def test_normal_access_time_change_does_not_invalidate_custody(tmp_path, monkeypatch, name):
    runtime, _, record, inputs, _, _, _, verifier, _ = fixture(tmp_path, monkeypatch)
    plan, authorization = issue(runtime, record, verifier)
    assert runtime.execute(plan, authorization).as_dict()['outcome'] == 'succeeded'
    path = inputs['directory'] / name
    initial = path.stat()
    os.utime(path, ns=(1, initial.st_mtime_ns))
    before = path.stat()
    identity, payload = ((runtime._marker_identity, runtime._marker_payload) if name == w._ATTEMPT
        else (runtime._ack_identity, runtime._ack_payload))
    runtime._check_file(name, identity, payload)
    after = path.stat()
    assert (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_nlink,
        after.st_size, after.st_mtime_ns, after.st_ctime_ns) == (
        before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_nlink,
        before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    assert path.read_bytes() == payload


def test_shorter_authorization_expiry_during_fresh_read_prevents_delete(tmp_path, monkeypatch):
    runtime, _, record, inputs, clients, connections, _, verifier, now = fixture(tmp_path, monkeypatch)
    plan, authorization = issue(runtime, record, verifier)
    values = authorization.canonical_content()
    values['expires_at'] = 110
    authorization = M4ExecutionAuthorization(**values, authorization_digest=canonical_digest(values))
    verifier.expected = plan, authorization
    final = clients[2].responses[6]
    def chunks():
        yield bytes(final.content)
        now[0] = 110
    final.iter_raw = chunks
    assert runtime.execute(plan, authorization).as_dict()['outcome'] == 'denied'
    assert verifier.calls == 1 and now[0] < plan.expires_at
    assert len(clients[2].calls) == 7 and clients[2].is_closed
    assert not any(connection.calls for connection in connections)
    assert (inputs['directory'] / w._ATTEMPT).exists()
    with pytest.raises(w.WebSecretFixtureRecoveryError): runtime.execute(plan, authorization)
