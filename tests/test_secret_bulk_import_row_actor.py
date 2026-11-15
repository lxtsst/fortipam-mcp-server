"""Existing exact API Role guard joined to original dispatch, synthetic I/O."""

from dataclasses import replace
import json
import time

import pytest

from fortipam_mcp import secret_bulk_import_row_actor as boundary
from fortipam_mcp.secret_bulk_import_file import PinnedBulkImportFile
from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
from fortipam_mcp.secret_bulk_import_row_http_transport import _Build29OriginalRowHttpTransport
from fortipam_mcp.secret_bulk_import_row_wire import _Build29OriginalRowWireEncoder
from fortipam_mcp.web_secret_create_ack import WebSecretCreateAckCapture
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_dlp_api_actor_guard import Harness, _role, _envelope, _ACTOR
from test_secret_bulk_import_row_http_transport import configured, assert_cleanup
from test_secret_bulk_import_row_provider import execute, assert_reopened_no_dispatch
from v4_planning import M4Verification


def actor_harness(monkeypatch, config=None, *, role=None, fault=None):
    role = role or _role()
    role['secretgrp-permission']['secret-table'] = 'read-write'
    if fault == 'secret-read': role['secretgrp-permission']['secret-table'] = 'read'
    if fault == 'folder-denied': role['secretgrp-permission']['folder-table'] = 'none'
    fixture = Harness(role)
    config = config or SecretMetadataHttpTransportConfig(fixture.config.base_url, fixture.config.bearer_token, 5, None)
    original = fixture.connect
    def connect(host, port, **kwargs):
        # Reuse the qualified guard fixture while testing the supplied writer config.
        kwargs['timeout'] = 5
        connection = original('pam.example.test', 9443, **kwargs)
        request = connection.request
        def send(method, path, *, headers):
            if fault == 'actor-after' and len(fixture.calls) == 3:
                fixture.bodies[_ACTOR] = _envelope('state', {'admin': {'name': 'different', 'login_name': 'different',
                    'guest_admin': False, 'sponsored_group_name': ''}}, monitor=True)
            request(method, path, headers=headers)
        connection.request = send
        if fault == 'close':
            connection.close = lambda: (_ for _ in ()).throw(OSError('Synthetic actor close failure'))
        return connection
    if fault == 'guest':
        fixture.bodies[_ACTOR] = _envelope('state', {'admin': {'name': fixture.binding.expected_actor,
            'login_name': fixture.binding.expected_actor, 'guest_admin': True, 'sponsored_group_name': ''}}, monitor=True)
    if fault == 'http': fixture.status = 403
    guard = boundary._OriginalRowApiActorGuard(config, fixture.binding, connection_factory=connect)
    return fixture, guard, config


@pytest.mark.parametrize('fault', [None, 'secret-read', 'folder-denied', 'guest', 'http', 'actor-after', 'close'])
def test_actual_guard_boundary_precedes_decode_and_later_drift_never_replays(tmp_path, monkeypatch, fault, capfd):
    loader, session, state, reference, bridge, native, runtime, exchange, config = configured(tmp_path, monkeypatch)
    fixture, guard, _ = actor_harness(monkeypatch, config, fault=fault)
    # Both synthetic product replies and actor guard qualify the same device.
    defaults = replace(native._encoder._defaults, serial_digest=guard.serial_digest)
    encoder = _Build29OriginalRowWireEncoder(native._encoder._converter, defaults,
        expected_defaults_digest=defaults.digest(), expected_serial_digest=guard.serial_digest)
    def factory(*args, **kwargs):
        assert kwargs['context'] is guard._tls_for_transport(config)
        class SyntheticContext: protocols = ['http/1.1']
        kwargs['context'] = SyntheticContext()
        connection = exchange.factory(*args, **kwargs)
        original = connection.request
        def send(*values):
            original(*values)
            payload = json.loads(connection.response.payload)
            payload['serial'] = fixture.binding.expected_serial
            connection.response.payload[:] = json.dumps(payload).encode()
            connection.response.headers['Content-Length'] = str(len(connection.response.payload))
        connection.request = send
        return connection
    native = _Build29OriginalRowHttpTransport(config, encoder, WebSecretCreateAckCapture(guard.serial_digest, 'success'),
        connection_factory=factory, actor_guard=guard)
    bridge._transport = native
    reads = []
    decode = PinnedBulkImportFile.decode
    def observe(self, **options):
        assert len(fixture.calls) == 3
        reads.append(True)
        return decode(self, **options)
    monkeypatch.setattr(PinnedBulkImportFile, 'decode', observe)
    try:
        with reference:
            assert execute(loader, state, runtime).verification is (M4Verification.VERIFIED if fault is None else M4Verification.UNKNOWN)
            assert_reopened_no_dispatch(loader, state, runtime, M4Verification.VERIFIED if fault is None else M4Verification.UNKNOWN)
        before_failed = fault in {'secret-read', 'folder-denied', 'guest', 'http', 'close'}
        assert len(reads) == (0 if before_failed else 1)
        assert sum(method == 'POST' for method, _ in exchange.requests) == (0 if before_failed else 1)
        assert len(fixture.calls) == (6 if fault is None else 4 if fault == 'actor-after' else 1 if fault in {'guest', 'http', 'close'} else 3)
        if fault != 'close': fixture.disposed()
        if bridge._owned is not None: assert_cleanup(bridge, exchange)
        assert native._failure_stage == (None if fault is None else 'actor_after' if fault == 'actor-after' else 'actor_before')
        assert capfd.readouterr() == ('', '')
    finally:
        session.close()


@pytest.mark.parametrize('fault', ['foreign-config', 'different-token', 'different-origin', 'boolean-timeout', 'nan', 'expired', 'ca-drift'])
def test_source_substitution_deadline_and_ca_drift_refuse_before_network(tmp_path, monkeypatch, fault):
    fixture, guard, config = actor_harness(monkeypatch)
    try:
        if fault == 'foreign-config':
            with pytest.raises(BulkImportIntakeError): guard._require_config(replace(config))
        elif fault in {'different-token', 'different-origin'}:
            changed = replace(config, **({'bearer_token': 'another'} if fault == 'different-token' else {'base_url': 'https://other.invalid'}))
            with pytest.raises(BulkImportIntakeError): guard._require_config(changed)
        elif fault == 'boolean-timeout':
            with pytest.raises(BulkImportIntakeError): boundary._OriginalRowApiActorGuard(replace(config, timeout_seconds=True), fixture.binding)
        elif fault == 'ca-drift':
            monkeypatch.setattr(guard, '_ca_snapshot', lambda: 'changed')
            with pytest.raises(BulkImportIntakeError): guard._require_config(config)
        else:
            with pytest.raises(BulkImportIntakeError): guard._observe(completed=False,
                deadline=float('nan') if fault == 'nan' else time.monotonic() - 1)
        assert not fixture.calls
    finally:
        fixture.disposed()


def test_real_transport_constructor_requires_actor_and_identity_cannot_be_replaced(tmp_path, monkeypatch):
    _, session, _, _, _, native, _, exchange, config = configured(tmp_path, monkeypatch)
    fixture, guard, _ = actor_harness(monkeypatch, config)
    try:
        with pytest.raises(BulkImportIntakeError):
            _Build29OriginalRowHttpTransport(config, native._encoder, native._capture)
        with pytest.raises(BulkImportIntakeError):
            _Build29OriginalRowHttpTransport(config, native._encoder, native._capture, actor_guard=guard)
        assert not fixture.calls and not exchange.requests
    finally:
        session.close()
