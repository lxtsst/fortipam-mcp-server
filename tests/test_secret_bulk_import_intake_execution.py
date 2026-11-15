"""Real HTTP/session/parent admission; only the material execution is synthetic."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
from pathlib import Path
import socket
import tempfile
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest
from starlette.testclient import TestClient

from fortipam_mcp import secret_bulk_import_intake_execution as boundary
from fortipam_mcp import secret_bulk_import_submission as submission
from fortipam_mcp.secret_bulk_import_row_action_worker import _receive, _send
from fortipam_mcp.secret_bulk_import_row_authority import _OriginalRowPermissionPins
from fortipam_mcp.secret_bulk_import_row_channel import (
    OriginalRowChannelBinding, UnixOriginalRowChannelClient, _OriginalRowAckPins,
)
from fortipam_mcp.secret_bulk_import_session import _OwnerFileSourceSession
from fortipam_mcp.secret_bulk_import_source_catalog import _TextOnlyImportSource
from fortipam_mcp.web_secret_create_ack import WebSecretCreateAckCapture
from test_secret_bulk_import_file import csv_bytes
from test_secret_bulk_import_parent_handoff import configured
from test_secret_bulk_import_row_channel import write
from test_secret_bulk_import_row_namespace import child_plan
from test_secret_bulk_import_row_wire import project
from test_secret_bulk_import_session_authority import capture_sessions, session_authority
from test_secret_bulk_import_submission import frame, send
from test_secret_bulk_import_text_source import _source_fixtures, _text_row
import test_m4_execution_store as m4_fixture
from v4_planning import M4ExecutionPlan, canonical_digest
from v4_planning.material_runtime import MaterialRuntimeOutcome


def _row_header(fixture, original, parent, index, defaults, capture):
    """Original-parent C2 fixtures; these are not a material dispatch grant."""
    row = original.row(index)
    line = next(line for line in parent.lines if line.kind == 'secret' and line.index == index)
    fields = child_plan(row).canonical_content()
    fields.update(summary_digest=parent.plan_digest, target_ref=line.line_ref,
        expected_current_digest=line.current_digest, expected_state_digest=line.expected_digest,
        expires_at=parent.expires_at)
    plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
    authorization = m4_fixture._authorization(plan)
    pins = _OriginalRowPermissionPins(plan, authorization, '5' * 64, parent.scope_digest, parent.audience_digest)
    return OriginalRowChannelBinding(fixture['owner_binding'], plan, authorization,
        parent.plan_digest, fixture['receiver']._key_digest, pins,
        fixture['clocks'][0], min(fixture['clocks'][0] + 60, parent.expires_at),
        _OriginalRowAckPins(row, defaults.digest(), capture).digest())


def _authenticated_text_session_starts_existing_projection_and_stops_at_first_control_failure(
        tmp_path, monkeypatch, capfd, scenario):
    source_parts, _, _ = _source_fixtures(tmp_path, monkeypatch, None,
        template_name='Synthetic Note', field_name='Contents')
    source = _TextOnlyImportSource(*source_parts)
    values = [_text_row('First', template_name='Synthetic Note'), _text_row('Second', template_name='Synthetic Note')]
    snapshot = source.prepare_catalog(expected_file_digest=hashlib.sha256(csv_bytes(values)).hexdigest(),
        scope_digest='1' * 64)
    fixture = configured(tmp_path, monkeypatch, values=values, snapshot=snapshot,
        file_parent=True, text_source=source)
    receiver, sender = fixture['receiver'], fixture['sender']
    defaults = replace(project(), serial_digest=source_parts[1].serial_digest)
    capture = WebSecretCreateAckCapture(defaults.serial_digest, 'success')
    monkeypatch.setattr(m4_fixture, 'NOW', fixture['clocks'][0])
    sessions = capture_sessions(monkeypatch)
    projections, starts, served, headers = [], [], [], []
    project_once = _OwnerFileSourceSession.project_dependencies_once
    start_once = boundary._OriginalTextIntakeWorker.start_once

    def retain_projection(session, catalog):
        assert sessions == [session] and catalog is snapshot and not projections
        result = project_once(session, catalog)
        projections.append(result)
        return result

    def retain_start(worker, session, catalog, projected):
        assert session is sessions[0] and catalog is snapshot and projected is projections[0]
        assert not starts and receiver._qualified is source._current
        assert fixture['store'].get_import_parent(receiver._plan_ref).row_count == 2
        starts.append(projected)
        start_once(worker, session, catalog, projected)

    def synthetic_material(peer, session, catalog, projected, client, selected_defaults, selected_capture,
                           *, index, namespace_key_path, now_epoch):
        try:
            assert session is sessions[0] and catalog is snapshot and projected is projections[0]
            assert selected_defaults is defaults and selected_capture is capture
            assert type(client) is UnixOriginalRowChannelClient
            assert client._binding == headers[index] and client._binding.source is fixture['owner_binding']
            assert client._socket == worker._settings['socket_path']
            assert client._request.path == worker._settings['request_key_path']
            assert client._request.digest == worker._settings['request_key_sha256']
            assert client._public.path == worker._settings['public_key_path']
            assert client._public.digest == worker._settings['public_key_sha256']
            assert namespace_key_path == receiver._key_path and now_epoch == fixture['clocks'][0]
            assert index == len(served) and not session._transaction._closed.is_set()
            served.append(index)
            _send(peer, worker._deadline, b'V' + client._binding.context_digest().encode('ascii'))
            return MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
        finally:
            peer.close()

    monkeypatch.setattr(_OwnerFileSourceSession, 'project_dependencies_once', retain_projection)
    monkeypatch.setattr(boundary._OriginalTextIntakeWorker, 'start_once', retain_start)
    monkeypatch.setattr(boundary, '_serve_original_text_row_once', synthetic_material)
    # No row RPC or product channel runs here; only the fixed client pins are constructed.
    monkeypatch.setattr(UnixOriginalRowChannelClient, '_post',
        lambda *_: pytest.fail('Material execution must remain isolated in this control test'))
    control, worker_peer = socket.socketpair()
    with tempfile.TemporaryDirectory(prefix='fp-text-intake-', dir=Path("/tmp").resolve()) as directory:
        root = Path(directory)
        row_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        row_socket.bind(str(root / 'row.sock'))
        (root / 'row.sock').chmod(0o600)
        public = Ed25519PrivateKey.from_private_bytes(b'k' * 32).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        settings = dict(socket_path=root / 'row.sock', request_key_path=root / 'request.key',
            request_key_sha256=write(root / 'request.key', b'r' * 32), public_key_path=root / 'public.key',
            public_key_sha256=write(root / 'public.key', public))
        worker = boundary._OriginalTextIntakeWorker(worker_peer, fixture['owner_binding'], defaults, capture,
            namespace_key_path=receiver._key_path, namespace_key_sha256=receiver._key_digest,
            **settings, clock=lambda: fixture['clocks'][0])
        try:
            with fixture['reference_transport'], ThreadPoolExecutor(max_workers=1) as pool:
                authority, _ = session_authority(tmp_path, fixture)
                app = submission.create_owner_file_session_submission_app(fixture['owner_binding'],
                    session_authority=authority, **fixture['options'], parent_handoff=sender,
                    execution_worker=worker)
                with TestClient(app) as client:
                    parent_future = pool.submit(receiver.receive_once)
                    response = send(client, frame(fixture))
                    original, owner_projected, _ = parent_future.result(timeout=5)
                    assert response.status_code == 200
                    assert response.json() == {'status': 'projected', 'rows': 2, 'targets': 0}
                    assert len(sessions) == len(projections) == len(starts) == 1 and not served
                    assert worker._session is sessions[0] and starts[0] is projections[0]
                    assert source._current.projected is owner_projected
                    assert owner_projected is not projections[0]
                    if scenario == 'idle':
                        original_deadline = worker._deadline
                        idle_started = time.monotonic()
                        assert not worker._closed.wait(10.2)
                        assert time.monotonic() - idle_started > 10
                        assert worker._thread.is_alive() and not served
                        assert not sessions[0]._transaction._closed.is_set()
                        assert worker._deadline == original_deadline and sessions[0]._remaining() > 0
                    parent = fixture['store'].get_import_parent(receiver._plan_ref)
                    headers.extend(_row_header(fixture, original, parent, i, defaults, capture) for i in range(2))
                    boundary._send_original_text_row(control, headers[0], 0, deadline=worker._deadline)
                    assert _receive(control, worker._deadline, 65) == b'V' + headers[0].context_digest().encode('ascii')
                    if scenario == 'eof':
                        control.shutdown(socket.SHUT_WR)
                    else:
                        index = 1 if scenario in ('success', 'idle') else 0
                        boundary._send_original_text_row(control, headers[index], index, deadline=worker._deadline)
                        if scenario in ('success', 'idle'):
                            assert _receive(control, worker._deadline, 65) == (
                                b'V' + headers[1].context_digest().encode('ascii'))
                    worker._thread.join(timeout=3)
                    assert not worker._thread.is_alive() and worker._closed.is_set()
                    assert worker._completed is (scenario in ('success', 'idle'))
                    assert served == ([0, 1] if scenario in ('success', 'idle') else [0])
                    assert worker._peer.fileno() == -1 and sessions[0]._transaction._closed.is_set()
                    assert not sessions[0]._watchdog.is_alive() and not any(sessions[0]._password)
                    with pytest.raises(ValueError):
                        _receive(control, worker._deadline, 65)
                    assert send(client, frame(fixture)).status_code == 409
                    assert len(sessions) == len(projections) == len(starts) == 1
        finally:
            worker.close()
            control.close()
            row_socket.close()
            sender.close()
            receiver.close()
    assert capfd.readouterr() == ('', '')


@pytest.mark.parametrize('scenario', ['success', 'wrong-order', 'eof'])
def test_authenticated_text_session_starts_existing_projection_and_stops_at_first_control_failure(
        tmp_path, monkeypatch, capfd, scenario):
    _authenticated_text_session_starts_existing_projection_and_stops_at_first_control_failure(
        tmp_path, monkeypatch, capfd, scenario)


def test_idle_control_wait_keeps_original_session_and_rejects_deadline_peer_close_and_cancellation(
        tmp_path, monkeypatch, capfd):
    _authenticated_text_session_starts_existing_projection_and_stops_at_first_control_failure(
        tmp_path, monkeypatch, capfd, 'idle')
    for ending in ('deadline', 'peer-close', 'cancel'):
        control, peer = socket.socketpair()
        closed = threading.Event()
        deadline = time.monotonic() + (0.1 if ending == 'deadline' else 2)

        def receive():
            boundary._wait_original_text_row(peer, deadline, closed)
            return _receive(peer, deadline, 65)

        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                waiting = pool.submit(receive)
                if ending == 'peer-close':
                    control.close()
                elif ending == 'cancel':
                    closed.set()
                with pytest.raises(ValueError):
                    waiting.result(timeout=1)
                if ending == 'deadline':
                    assert time.monotonic() >= deadline
        finally:
            closed.set()
            control.close()
            peer.close()
    assert capfd.readouterr() == ('', '')
