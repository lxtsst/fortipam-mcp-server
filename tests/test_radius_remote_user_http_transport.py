"""Fixed disabled-user lifecycle with real target M4 provenance and synthetic HTTP."""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp.radius_remote_user_contract import RadiusRemoteUserError
from fortipam_mcp.radius_remote_user_http_transport import FortiPamRadiusRemoteUserHttpTransport, _create_error_code
from fortipam_mcp.local_user_reset_projection import _WEBAUTHN_EXTRA_FIELDS
from test_radius_remote_user_contract import fixture
from test_radius_remote_user_owned_target import prepared
from test_radius_server_http_transport import Connection as BaseConnection, Response as BaseResponse

TABLE = '/api/v2/cmdb/system/admin'


@pytest.mark.parametrize('fault', [None, 'serial', 'scope', 'status', 'method', 'boolean', 'positive', 'nested'])
def test_error_diagnostic_never_decodes_response_messages_or_qualifies_foreign_envelopes(
        monkeypatch: pytest.MonkeyPatch, fault: str | None) -> None:
    body = dict(build=29, version='v7.0.0', serial='SYNTHETIC_SERIAL', path='system', name='admin',
        http_method='POST', http_status=500, status='error', vdom='synthetic-scope', error=-4,
        results={'password': 'NEVER_DECODE_RESPONSE'})
    if fault == 'serial': body['serial'] = 'FOREIGN'
    elif fault == 'scope': body['vdom'] = 'foreign'
    elif fault == 'status': body['status'] = 'success'
    elif fault == 'method': body['http_method'] = 'GET'
    elif fault == 'boolean': body['error'] = True
    elif fault == 'positive': body['error'] = 4
    elif fault == 'nested': body['error'] = {'password': 'NEVER_DECODE_RESPONSE'}
    loads = json.loads
    def scalar(value: Any, *a: Any, **k: Any) -> Any:
        assert 'NEVER_DECODE_RESPONSE' not in str(value)
        return loads(value, *a, **k)
    raw = bytearray(json.dumps(body).encode())
    monkeypatch.setattr(json, 'loads', scalar)
    assert _create_error_code(raw, 500, 'SYNTHETIC_SERIAL', 'synthetic-scope') == (-4 if fault is None else None)


class Response(BaseResponse):
    def getheader(self, name: str, default: str = '') -> str:
        return 'application/json' if name.lower() == 'content-type' else default


class Connection(BaseConnection):
    def request(self, method: str, path: str, body: memoryview | None, headers: dict[str, str]) -> None:
        assert headers['User-Agent'] == 'fortipam-private-radius-remote-user/1'
        assert headers['Accept-Encoding'] == 'identity'
        if body is not None:
            assert body.readonly and isinstance(body.obj, bytearray)
            self.peer.bodies.append(body.obj)
        self.response = self.peer.handle(method, path, body)
        self.sock = None


class Peer:
    def __init__(self, guard: Any, radius: Any) -> None:
        self.guard, self.radius = guard, radius
        self.schema, self.defaults = fixture()
        self.schema['serial'] = guard._target._serial
        self.serial = guard._target._serial
        self.username = guard._binding.username
        self.row: dict[str, Any] | None = None
        self.posts = self.deletes = 0
        self.bodies: list[bytearray] = []
        self.connections: list[Any] = []
        self.responses: list[Any] = []
        self.on_connect: Any = None
        self.lost_post_ack = self.foreign_ack = self.lost_delete_ack = False
        self.failed_readback = self.truncated_collection = False
        self.bad_absence = self.empty_collection = False

    def envelope(self, **overrides: Any) -> dict[str, Any]:
        values = dict(build=29, version='v7.0.0', http_method='GET', http_status=200,
            path='system', name='admin', serial=self.serial, status='success', vdom='synthetic-scope')
        values.update(overrides)
        return values

    def connection(self, host: str, port: int, **kwargs: Any) -> Connection:
        assert host == 'pam.example' and port == 443 and kwargs['context'].check_hostname
        selected = Connection(self)
        self.connections.append(selected)
        return selected

    def handle(self, method: str, path: str, body: memoryview | None) -> Response:
        if method == 'POST':
            assert path == TABLE and body is not None
            values = json.loads(bytes(body))
            assert values['status'] == 'disable' and values['accprofile'] == 'pam_standard_user'
            assert values['password'] == '' and values['remote-auth'] == 'enable'
            assert values['remote-server'] == self.guard._binding.radius.name and values['remote-group'] == ''
            self.posts += 1
            self.row = self.defaults | values | {'id': 29, 'q_ref': 0, 'q_origin_key': self.username,
                'password': 'SYNTHETIC_STORED_PASSWORD'}
            self.row['webauthn'] = {'status': 'disable', 'create-time': '', **{
                k: 0 if v['type'] == 'integer' else '' for k, v in _WEBAUTHN_EXTRA_FIELDS.items()}}
            self.radius.row['q_ref'] += 1
            if self.lost_post_ack:
                raise TimeoutError('SYNTHETIC_LOST_ACK')
            response = Response(self.envelope(http_method='POST',
                mkey='foreign' if self.foreign_ack else self.username))
        elif method == 'DELETE':
            assert path == TABLE + '/' + self.username and body is None
            self.deletes += 1
            self.row = None
            self.radius.row['q_ref'] -= 1
            if self.lost_delete_ack:
                raise TimeoutError('SYNTHETIC_LOST_DELETE_ACK')
            response = Response(self.envelope(http_method='DELETE', mkey=self.username))
        elif path == TABLE + '?action=schema&with_meta=true':
            response = Response(self.schema)
        elif path == TABLE + '?action=default&with_meta=true':
            response = Response(self.envelope(action='default', results=self.defaults))
        elif path == TABLE + '?format=name&with_meta=true':
            if self.empty_collection:
                return Response({}, 200)
            response = Response(self.envelope(results=[] if self.row is None else [{'name': self.username}],
                limit_reached=self.truncated_collection))
        elif path == TABLE + '/' + self.username + '?with_meta=true':
            if self.row is None:
                response = Response(self.envelope(status='error', http_status=404,
                    serial='FOREIGN' if self.bad_absence else self.serial), 404)
            elif self.failed_readback:
                self.failed_readback = False
                raise TimeoutError('SYNTHETIC_LOST_READBACK')
            else:
                response = Response(self.envelope(results=[self.row], mkey=self.username))
        else:
            raise AssertionError('Unexpected route')
        self.responses.append(response)
        return response


def setup(root: Path) -> tuple[Any, ...]:
    pair = root / 'pair'; pair.mkdir(mode=0o700)
    guard, workflow, radius, now, factory, _, _ = prepared(pair)
    workflow.close()
    peer = Peer(guard, radius)
    directory = root / 'user'; directory.mkdir(mode=0o700)
    values = dict(target=guard, state_directory=directory, clock=lambda: now[0], connection_factory=peer.connection)
    def transport(**kwargs: Any) -> FortiPamRadiusRemoteUserHttpTransport:
        return FortiPamRadiusRemoteUserHttpTransport(guard._target._config, guard._binding, **(values | ({'execution_context_digest': 'e' * 64} if kwargs.get('execution_enabled') else {}) | kwargs))
    return transport, peer, guard, directory, factory


def create(transport: Any) -> Any:
    current = transport().inspect_create()
    selected = transport(execution_enabled=True, expected_current_digest=current.state_digest,
        create_authorizer=lambda *args: True)
    assert selected.create_and_verify() == 'verified_created'
    return selected


def test_disabled_user_create_close_recompose_and_original_ack_independent_removal(tmp_path: Path) -> None:
    transport, peer, target, directory, source = setup(tmp_path)
    before = len(source.calls)
    writer = create(transport)
    assert peer.posts == 1 and peer.radius.row['q_ref'] == 1
    assert all(not any(body) for body in peer.bodies)
    writer.close()
    with pytest.raises(RadiusRemoteUserError):
        writer.create_and_verify()
    recovery = transport(recovery_enabled=True, recovery_authorizer=lambda *args: True)
    assert len(recovery.inspect_recovery()) == 2
    assert recovery.delete_owned() and recovery.inspect_deleted()
    assert peer.posts == peer.deletes == 1 and peer.row is None and peer.radius.row['q_ref'] == 0
    assert target.inspect() and len(source.calls) == before
    assert all(c.closed for c in peer.connections) and all(r.closed for r in peer.responses)
    assert (directory / 'create-ack.json').is_file() and (directory / 'delete-ack.json').is_file()
    with pytest.raises(RadiusRemoteUserError):
        transport(recovery_enabled=True, recovery_authorizer=lambda *args: True).delete_owned()
    assert peer.deletes == 1


@pytest.mark.parametrize('fault', ['lost', 'foreign', 'readback'])
def test_post_uncertainty_never_replays_and_only_original_ack_can_reconcile(tmp_path: Path, fault: str) -> None:
    transport, peer, _, directory, source = setup(tmp_path)
    current = transport().inspect_create()
    peer.lost_post_ack = fault == 'lost'
    peer.foreign_ack = fault == 'foreign'
    peer.failed_readback = fault == 'readback'
    writer = transport(execution_enabled=True, expected_current_digest=current.state_digest, create_authorizer=lambda *args: True)
    assert writer.create_and_verify() == 'reconciliation_required'
    assert peer.posts == 1 and peer.row is not None
    assert json.loads((directory / 'create-diagnostic.json').read_text()) == {
        'stage': {'lost': 'post', 'foreign': 'ack_validate', 'readback': 'readback'}[fault],
        'http_status': 200 if fault == 'foreign' else None}
    before = len(source.calls)
    with pytest.raises(RadiusRemoteUserError):
        writer.create_and_verify()
    with pytest.raises(RadiusRemoteUserError):
        transport().inspect_create()
    recovery = transport(recovery_enabled=True, recovery_authorizer=lambda *args: True)
    if fault == 'readback':
        assert (directory / 'create-ack.json').exists() and recovery.inspect_recovery()
        assert recovery.delete_owned()
    else:
        with pytest.raises(RadiusRemoteUserError):
            recovery.delete_owned()
        assert not (directory / 'create-ack.json').exists() and peer.deletes == 0
    assert peer.posts == 1 and len(source.calls) == before and all(not any(b) for b in peer.bodies)


@pytest.mark.parametrize('diagnostic_failure', [False, True])
def test_rejected_create_retains_only_stage_status_and_never_replays(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, diagnostic_failure: bool) -> None:
    transport, peer, _, directory, _ = setup(tmp_path)
    current = transport().inspect_create()
    original = peer.handle
    def reject(method: str, path: str, body: Any) -> Any:
        if method == 'POST':
            peer.posts += 1
            return Response(peer.envelope(http_method='POST', http_status=500, status='error',
                results={'private': 'NEVER_RETAIN_RESPONSE'}), 500)
        return original(method, path, body)
    peer.handle = reject
    write_once = FortiPamRadiusRemoteUserHttpTransport._write_once
    def retain(self: Any, name: str, value: Any) -> None:
        if name == 'create-diagnostic.json' and diagnostic_failure:
            raise OSError('NEVER_RETAIN_ERROR')
        write_once(self, name, value)
    monkeypatch.setattr(FortiPamRadiusRemoteUserHttpTransport, '_write_once', retain)
    writer = transport(execution_enabled=True, expected_current_digest=current.state_digest,
        create_authorizer=lambda *args: True)
    assert writer.create_and_verify() == 'reconciliation_required'
    assert (directory / 'create.claim.json').exists() and not (directory / 'create-ack.json').exists()
    if diagnostic_failure:
        assert not (directory / 'create-diagnostic.json').exists()
    else:
        assert json.loads((directory / 'create-diagnostic.json').read_text()) == {
            'stage': 'ack_validate', 'http_status': 500}
    with pytest.raises(RadiusRemoteUserError):
        writer.create_and_verify()
    assert peer.posts == 1 and peer.row is None and all(not any(b) for b in peer.bodies)
    assert all('NEVER_RETAIN' not in p.read_text() for p in directory.glob('*.json'))


def test_consumed_delete_missing_ack_allows_only_fresh_absence_readback(tmp_path: Path) -> None:
    transport, peer, _, directory, _ = setup(tmp_path)
    create(transport)
    peer.lost_delete_ack = True
    recovery = transport(recovery_enabled=True, recovery_authorizer=lambda *args: True)
    with pytest.raises(RadiusRemoteUserError):
        recovery.delete_owned()
    assert peer.row is None and peer.deletes == 1 and not (directory / 'delete-ack.json').exists()
    assert transport().inspect_deleted()
    with pytest.raises(RadiusRemoteUserError):
        transport(recovery_enabled=True, recovery_authorizer=lambda *args: True).delete_owned()
    assert peer.deletes == 1


@pytest.mark.parametrize('fault', ['default', 'radius', 'user', 'close', 'callback', 'expected', 'deny'])
def test_prewrite_drift_gate_or_authority_refusal_prevents_post(tmp_path: Path, fault: str) -> None:
    transport, peer, _, directory, _ = setup(tmp_path)
    current = transport().inspect_create()
    writer = transport(execution_enabled=True, expected_current_digest='f' * 64 if fault == 'expected' else current.state_digest,
        create_authorizer=lambda *args: fault != 'deny')
    if fault in {'default', 'radius', 'user', 'close', 'callback'}:
        done = []
        def on_connect() -> None:
            if (directory / 'create.claim.json').exists() and not done:
                done.append(True)
                if fault == 'default':
                    peer.defaults['comments'] = 'changed'
                elif fault == 'radius':
                    peer.radius.row['q_ref'] = 1
                elif fault == 'user':
                    peer.row = {'name': peer.username}
                elif fault == 'close':
                    writer.close()
                else:
                    writer._authorize_create = lambda *args: True
        peer.on_connect = on_connect
        assert writer.create_and_verify() == 'reconciliation_required'
        assert (directory / 'create.claim.json').exists()
    else:
        with pytest.raises(RadiusRemoteUserError):
            writer.create_and_verify()
        assert not (directory / 'create.claim.json').exists()
    assert peer.posts == 0


@pytest.mark.parametrize('fault', ['status', 'role', 'server', 'reference', 'id', 'webauthn', 'schema', 'defaults', 'missing_ack'])
def test_recovery_refuses_changed_full_state_or_missing_original_ack(tmp_path: Path, fault: str) -> None:
    transport, peer, _, directory, _ = setup(tmp_path)
    create(transport)
    if fault == 'schema':
        peer.schema['results']['children']['comments']['type'] = 'option'
    elif fault == 'defaults':
        peer.defaults['comments'] = 'changed'
    elif fault == 'missing_ack':
        (directory / 'create-ack.json').unlink()
    else:
        field, value = {'status': ('status', 'enable'), 'role': ('accprofile', 'super_admin'),
            'server': ('remote-server', 'foreign'), 'reference': ('q_ref', 1), 'id': ('id', 30),
            'webauthn': ('webauthn', {'status': 'enable'})}[fault]
        peer.row[field] = value
    recovery = transport(recovery_enabled=True, recovery_authorizer=lambda *args: True)
    with pytest.raises(RadiusRemoteUserError):
        recovery.delete_owned()
    assert peer.deletes == 0 and not (directory / 'delete.claim.json').exists()


@pytest.mark.parametrize('fault', ['closed', 'reject', 'truncated', 'foreign', 'empty', 'route', 'directory', 'namespace'])
def test_default_closed_and_fixed_routes_absence_and_namespace_fail_closed(tmp_path: Path, fault: str) -> None:
    transport, peer, _, directory, _ = setup(tmp_path)
    selected = transport()
    if fault == 'closed':
        with pytest.raises(RadiusRemoteUserError):
            selected.create_and_verify()
    elif fault == 'reject':
        with pytest.raises(RadiusRemoteUserError):
            selected.delete_owned()
    elif fault == 'route':
        import time
        with pytest.raises(RadiusRemoteUserError):
            selected._exchange('GET', '/api/v2/monitor/system/login', stop=time.monotonic() + 1)
        assert not peer.connections
    else:
        if fault == 'truncated': peer.truncated_collection = True
        elif fault == 'foreign': peer.bad_absence = True
        elif fault == 'empty': peer.empty_collection = True
        elif fault == 'directory': os.chmod(directory, 0o755)
        elif fault == 'namespace':
            (directory / 'namespace.json').write_text('{}'); os.chmod(directory / 'namespace.json', 0o600)
        with pytest.raises(RadiusRemoteUserError): selected.inspect_create()
    assert peer.posts == peer.deletes == 0


def test_material_tokens_are_not_decoded_or_persisted_in_user_journal(tmp_path: Path, monkeypatch: Any) -> None:
    transport, peer, _, directory, _ = setup(tmp_path)
    peer.defaults['password'] = 'NEVER_DECODE_DEFAULT_PASSWORD'
    peer.defaults['history19'] = 'NEVER_DECODE_HISTORY'
    peer.defaults['shared-key'] = 'NEVER_DECODE_SHARED_KEY'
    loads = json.loads
    def checked(value: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(value, (str, bytes, bytearray)):
            assert 'NEVER_DECODE' not in str(value) and 'SYNTHETIC_STORED_PASSWORD' not in str(value)
        return loads(value, *args, **kwargs)
    monkeypatch.setattr(json, 'loads', checked)
    create(transport)
    assert transport(recovery_enabled=True, recovery_authorizer=lambda *args: True).delete_owned()
    for path in directory.iterdir():
        assert b'NEVER_DECODE' not in path.read_bytes() and b'SYNTHETIC_STORED_PASSWORD' not in path.read_bytes()


def test_closed_or_initially_disabled_adapter_cannot_be_armed_by_flag_change(tmp_path: Path) -> None:
    transport, peer, _, _, _ = setup(tmp_path)
    current = transport().inspect_create()
    disabled = transport(expected_current_digest=current.state_digest, create_authorizer=lambda *args: True)
    disabled._execution_enabled = True
    with pytest.raises(RadiusRemoteUserError): disabled.create_and_verify()
    writer = transport(execution_enabled=True, expected_current_digest=current.state_digest, create_authorizer=lambda *args: True)
    writer.close(); writer._execution_enabled = True
    with pytest.raises(RadiusRemoteUserError): writer.create_and_verify()
    assert peer.posts == 0


@pytest.mark.parametrize('fault', ['state', 'close', 'deny'])
def test_delete_connection_drift_consumes_claim_without_sending_delete(tmp_path: Path, fault: str) -> None:
    transport, peer, _, directory, _ = setup(tmp_path)
    create(transport)
    allowed = [True]
    recovery = transport(recovery_enabled=True, recovery_authorizer=lambda *args: allowed[0])
    done = []
    def on_connect() -> None:
        if (directory / 'delete.claim.json').exists() and not done:
            done.append(True)
            if fault == 'state': peer.row['comments'] = 'changed'
            elif fault == 'close': recovery.close()
            else: allowed[0] = False
    peer.on_connect = on_connect
    with pytest.raises(RadiusRemoteUserError): recovery.delete_owned()
    assert (directory / 'delete.claim.json').exists() and peer.deletes == 0
    with pytest.raises(RadiusRemoteUserError):
        transport(recovery_enabled=True, recovery_authorizer=lambda *args: True).delete_owned()
    assert peer.deletes == 0


def test_deadline_interrupts_detached_socket_and_releases_response(tmp_path: Path) -> None:
    import threading
    import time
    transport, _, _, _, _ = setup(tmp_path)
    stopped = threading.Event()
    class Socket:
        def shutdown(self, how: int) -> None: stopped.set()
    class BlockingResponse:
        status = 200
        closed = False
        def getheader(self, name: str, default: str = '') -> str:
            return 'application/json' if name.lower() == 'content-type' else default
        def readinto(self, value: memoryview) -> int:
            assert stopped.wait(2)
            return 0
        def close(self) -> None: self.closed = True
    response = BlockingResponse()
    class BlockingConnection:
        def __init__(self, *args: Any, **kwargs: Any) -> None: self.sock: Any = Socket()
        def connect(self) -> None: pass
        def request(self, *args: Any, **kwargs: Any) -> None: self.sock = None
        def getresponse(self) -> Any: return response
        def close(self) -> None: pass
    selected = transport(connection_factory=BlockingConnection)
    start = time.monotonic()
    with pytest.raises(RadiusRemoteUserError):
        selected._exchange('GET', TABLE + '?action=schema&with_meta=true', stop=start + .04)
    assert stopped.is_set() and response.closed and time.monotonic() - start < 1


@pytest.mark.parametrize('fault', ['context', 'hardlink', 'symlink', 'mode', 'clock'])
def test_private_dispatch_and_journal_preconditions_are_not_replaceable(tmp_path: Path, fault: str) -> None:
    transport, peer, _, directory, _ = setup(tmp_path)
    current = transport().inspect_create()
    if fault == 'context':
        with pytest.raises(RadiusRemoteUserError):
            transport(execution_enabled=True, expected_current_digest=current.state_digest,
                execution_context_digest=None, create_authorizer=lambda *args: True)
        assert peer.posts == 0
        return
    writer = transport(execution_enabled=True, expected_current_digest=current.state_digest, create_authorizer=lambda *args: True)
    namespace = directory / 'namespace.json'
    if fault == 'hardlink': os.link(namespace, tmp_path / 'namespace-link')
    elif fault == 'symlink':
        copy = tmp_path / 'namespace-copy'; namespace.rename(copy); namespace.symlink_to(copy)
    elif fault == 'mode': os.chmod(namespace, 0o644)
    else:
        writer._last_clock = 1000
    with pytest.raises(RadiusRemoteUserError): writer.create_and_verify()
    assert peer.posts == 0 and not (directory / 'create.claim.json').exists()


@pytest.mark.parametrize('state', ['present', 'absent', 'partial', 'truncated', 'deleted'])
def test_consumed_post_can_be_observed_without_adoption_or_record_repair(tmp_path: Path, state: str) -> None:
    transport, peer, _, directory, source = setup(tmp_path)
    current = transport().inspect_create()
    writer = transport(execution_enabled=True, expected_current_digest=current.state_digest, create_authorizer=lambda *args: True)
    peer.lost_post_ack = True
    assert writer.create_and_verify() == 'reconciliation_required'
    before_sources = len(source.calls)
    if state in {'absent', 'truncated'}: peer.row = None
    elif state == 'partial': peer.row['status'] = 'enable'
    elif state == 'deleted':
        (directory / 'delete.claim.json').write_text('{}'); os.chmod(directory / 'delete.claim.json', 0o600)
    if state == 'truncated': peer.truncated_collection = True
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    observed = transport().inspect_uncertain_create()
    assert observed == {'present': 'present_observed', 'absent': 'absent_observed',
        'partial': 'not_assessed', 'truncated': 'not_assessed', 'deleted': 'not_assessed'}[state]
    assert before == {p.name: p.read_bytes() for p in directory.iterdir()}
    assert peer.posts == 1 and peer.deletes == 0 and len(source.calls) == before_sources


def test_clock_exception_permanently_closes_time_validation(tmp_path: Path) -> None:
    transport, peer, _, _, _ = setup(tmp_path)
    attempts = []
    def clock() -> int:
        if not attempts:
            attempts.append(True)
            raise ValueError('SYNTHETIC_CLOCK_FAILURE')
        return 100
    selected = transport(clock=clock)
    for _ in range(2):
        with pytest.raises(RadiusRemoteUserError): selected._now()
    assert peer.posts == 0


def test_cancelled_response_clears_partial_buffer_and_closes_resources(tmp_path: Path) -> None:
    import time
    transport, peer, _, _, _ = setup(tmp_path)
    buffers = []
    class CancelledResponse(Response):
        def readinto(self, destination: memoryview) -> int:
            destination[:12] = b'SYNTHETIC_C3'
            buffers.append(destination.obj)
            raise KeyboardInterrupt()
    response = CancelledResponse({})
    peer.handle = lambda *args: response
    selected = transport()
    with pytest.raises(KeyboardInterrupt):
        selected._exchange('GET', TABLE + '?action=schema&with_meta=true', stop=time.monotonic() + 1)
    assert buffers and all(not any(b) for b in buffers)
    assert response.closed and all(c.closed for c in peer.connections) and peer.posts == 0
