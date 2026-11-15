"""Synthetic original export, artifact metadata and borrowed VM prerequisites."""
import asyncio
import json
from threading import Event
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from fortipam_mcp import license_install_preflight as module
from fortipam_mcp.license_install_preflight import LicenseInstallPreflight
from fortipam_mcp.license_vm_source import LicenseVmSource, STATUS_PATH
from fortipam_mcp.license_vm_preview_action import LicenseVmPreviewAction, TOOL_NAME
from fortipam_mcp.http_server import create_http_app
from fortipam_mcp.owner_session_metadata import OwnerSessionMetadataTransport
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig, FortiPamSecretMetadataHttpTransport
from test_license_backup_source import make as backup_for, IDENTITY, OWNER, SERIAL
from test_license_vm_source import Peer, COOKIE
from test_license_vm_projection import PRIVATE
from test_fortitoken_local_preview_action import bootstrap
from test_ldap_server_mcp_action import _call, _login
from v4_planning.material_provider import MaterialAccessDenied


@pytest.fixture
def candidate(tmp_path):
    instances = []
    def make(identity=None, fault='none', vm_options=None, owner_expiry=70.0):
        identity = IDENTITY if identity is None else identity
        root = tmp_path/f'fixture-{len(instances)}'; root.mkdir(mode=0o700)
        backup = backup_for(root, identity=identity, fault=fault)
        peer = Peer(); peer.payload['serial'] = SERIAL
        ca, factory = vm_options if vm_options is not None else (None, peer.factory)
        config = SecretMetadataHttpTransportConfig('https://pam.example.test', 'synthetic-unused-bearer', 5, str(ca) if ca else None)
        owner = OwnerSessionMetadataTransport(config, owner_name=OWNER, credentials=peer.login,
            folder_path='synthetic', secret_name='synthetic', target_name='synthetic',
            witness=FortiPamSecretMetadataHttpTransport(config), connection_factory=factory, clock=peer.clock)
        owner._client, owner._expires_at = peer.client(), owner_expiry; owner._session_lock.acquire()
        vm = LicenseVmSource(owner, expected_actor=OWNER, expected_serial=SERIAL, source_guard=lambda: True)
        preflight = LicenseInstallPreflight(vm, backup.license, backup.source, **identity)
        result = SimpleNamespace(backup=backup, peer=peer, owner=owner, vm=vm, preflight=preflight, identity=identity)
        instances.append(result); return result
    yield make
    for value in instances:
        value.preflight.close(); value.backup.artifact.close(); value.backup.workflow.close()
        value.owner._client = None; value.owner._session_lock.release()
        for client in value.peer.clients: client.close()


def preview(value): return value.preflight.preview(**value.identity)


def assert_read_copies_disposed(value):
    assert value.vm._closed and value.vm._projection is None and value.backup.source._closed
    assert all(not any(raw) for raw in [value.vm._cookie, *value.peer.buffers])
    assert value.owner._client is not None and value.owner._session_lock.locked()
    assert not value.backup.artifact._used and not value.backup.artifact._closed


def test_one_preflight_joins_original_sources_without_consuming_artifact_or_reexport(candidate, monkeypatch):
    value = candidate(); sessions = value.backup.peer.sessions
    from fortipam_mcp import license_artifact_source
    monkeypatch.setattr(license_artifact_source, '_read', lambda *_: pytest.fail('Preview must not read license bytes.'))
    result = preview(value)
    assert result['artifact_metadata_available'] and not result['license_material_loaded']
    assert result['original_backup_execution_verified'] and result['retained_backup_files_intact']
    assert result['sources_bound_to_original_target_requester_client'] and result['private_read_sources_disposed']
    assert result['planning_status'] == 'incomplete_evidence' and len(result['missing_requirements']) == 11
    assert not result['observations_are_atomic'] and not result['execution_authorized'] and not result['license_execution_ready']
    assert not result['backup_restore_tested'] and not result['native_backup_encryption_verified']
    assert value.peer.calls == [('GET', STATUS_PATH)] and value.peer.credentials == 0
    assert value.backup.peer.sessions == sessions and value.backup.peer.exports == 1
    assert_read_copies_disposed(value)
    assert value.backup.artifact._path.exists() and value.backup.workflow._closed is False
    text = json.dumps(result)
    assert all(private not in text for private in (PRIVATE, COOKIE, SERIAL, OWNER, str(value.backup.artifact._path),
        value.backup.artifact._sha, value.backup.license._digest, str(value.backup.vault)))
    with pytest.raises(MaterialAccessDenied): preview(value)
    assert len(value.peer.calls) == 1 and value.backup.peer.exports == 1


@pytest.mark.parametrize('identity', ['requester', 'transport'])
def test_foreign_identity_does_not_acquire_consumption_or_disposal(candidate, identity):
    value = candidate(); foreign = dict(value.identity)
    foreign[identity+'_digest'] = 'f'*64
    with pytest.raises(MaterialAccessDenied): value.preflight.preview(**foreign)
    assert not value.preflight._attempted and not value.vm._closed and not value.backup.source._closed
    assert not value.peer.calls
    assert preview(value)['private_read_sources_disposed']


@pytest.mark.parametrize('fault', ['artifact-gate', 'backup-gate', 'vm-gate', 'artifact-used', 'backup-unknown'])
def test_missing_source_eligibility_never_produces_a_partial_result(candidate, fault):
    value = candidate(fault='file-drift' if fault == 'backup-unknown' else 'none')
    if fault == 'artifact-gate': value.backup.artifact._guard = value.backup.artifact._guard_pin = None
    elif fault == 'backup-gate': value.backup.source._guard = value.backup.source._guard_pin = None
    elif fault == 'vm-gate': value.vm._guard = value.vm._guard_pin = None
    elif fault == 'artifact-used': value.backup.artifact._used = True
    with pytest.raises(MaterialAccessDenied): preview(value)
    assert value.vm._closed and value.backup.source._closed
    assert not value.backup.artifact._closed and value.backup.peer.exports == 1


@pytest.mark.parametrize('binding', ['vm', 'license', 'backup', 'identity', 'target', 'owner'])
def test_changed_original_relationship_denies_before_vm_get(candidate, binding):
    value = candidate()
    if binding in ('vm', 'license', 'backup'): setattr(value.preflight, '_'+binding, object())
    elif binding == 'identity': value.preflight._identity = ('e'*64, 'f'*64)
    elif binding == 'target': value.vm._serial = 'SYNTHETIC_OTHER_TARGET'
    else: value.vm._actor = 'SYNTHETIC_OTHER_OWNER'
    with pytest.raises(MaterialAccessDenied): preview(value)
    assert not value.peer.calls and not value.vm._attempted


def install_clocks(value, monkeypatch):
    from fortipam_mcp import license_vm_source, license_backup_source, license_vm_preview_action
    now = [10.0]
    monkeypatch.setattr(module, '_monotonic', lambda: now[0])
    monkeypatch.setattr(license_vm_source, '_monotonic', lambda: now[0])
    monkeypatch.setattr(license_vm_preview_action, '_monotonic', lambda: now[0])
    monkeypatch.setattr(license_backup_source, 'time', SimpleNamespace(monotonic=lambda: now[0], time=lambda: value.backup.peer.now))
    return now


def test_initial_artifact_latency_reduces_vm_budget_instead_of_starting_a_new_one(candidate, monkeypatch):
    value = candidate(); now = install_clocks(value, monkeypatch)
    def guard(): now[0] += 4; return True
    value.backup.artifact._guard = value.backup.artifact._guard_pin = value.backup.license._guard_pin = guard
    value.preflight = LicenseInstallPreflight(value.vm, value.backup.license, value.backup.source, **value.identity)
    def hook(phase):
        if phase == 'connect': now[0] += 2
    value.peer.hook = hook
    with pytest.raises(MaterialAccessDenied): preview(value)
    assert not value.peer.calls and not value.backup.source._attempted
    assert_read_copies_disposed(value)


def test_remaining_global_budget_limits_backup_before_private_configuration_reads(candidate, monkeypatch):
    from fortipam_mcp import license_backup_source, backup_artifact_custody
    value = candidate(); now = install_clocks(value, monkeypatch)
    def hook(phase):
        if phase == 'connection-close': now[0] += 4
    value.peer.hook = hook
    read = license_backup_source._read
    def claim(*args):
        raw = read(*args); now[0] += 2; return raw
    monkeypatch.setattr(license_backup_source, '_read', claim)
    monkeypatch.setattr(backup_artifact_custody, '_read', lambda *_: pytest.fail('Global deadline must stop backup material reads.'))
    with pytest.raises(MaterialAccessDenied): preview(value)
    assert value.peer.calls == [('GET', STATUS_PATH)]
    assert_read_copies_disposed(value)


@pytest.mark.parametrize('phase', ['artifact-guard', 'final-metadata'])
def test_short_backup_retention_still_bounds_last_callback_and_metadata(candidate, monkeypatch, phase):
    value = candidate(); now = install_clocks(value, monkeypatch)
    value.backup.peer.now = value.backup.source._binding._retain_until - 1
    calls = []
    def guard():
        calls.append(True)
        if phase == 'artifact-guard' and len(calls) == 2:
            value.backup.peer.now += 2; now[0] += 2
        return True
    value.backup.artifact._guard = value.backup.artifact._guard_pin = value.backup.license._guard_pin = guard
    value.preflight = LicenseInstallPreflight(value.vm, value.backup.license, value.backup.source, **value.identity)
    metadata = value.preflight._metadata
    def delayed():
        metadata()
        if phase == 'final-metadata' and len(calls) == 2: now[0] += 2
    monkeypatch.setattr(value.preflight, '_metadata', delayed)
    with pytest.raises(MaterialAccessDenied): preview(value)
    assert now[0] == 12.0 and value.backup.source._attempted
    assert_read_copies_disposed(value)


@pytest.mark.parametrize('phase', ['artifact-guard', 'final-metadata'])
def test_short_owner_window_still_bounds_last_callback_and_metadata(candidate, monkeypatch, phase):
    value = candidate(owner_expiry=11.0); now = install_clocks(value, monkeypatch)
    calls = []
    def guard():
        calls.append(True)
        if phase == 'artifact-guard' and len(calls) == 2:
            value.peer.time += 2; now[0] += 2
        return True
    value.backup.artifact._guard = value.backup.artifact._guard_pin = value.backup.license._guard_pin = guard
    value.preflight = LicenseInstallPreflight(value.vm, value.backup.license, value.backup.source, **value.identity)
    metadata = value.preflight._metadata
    def delayed():
        metadata()
        if phase == 'final-metadata' and len(calls) == 2: now[0] += 2
    monkeypatch.setattr(value.preflight, '_metadata', delayed)
    with pytest.raises(MaterialAccessDenied): preview(value)
    assert_read_copies_disposed(value)


def test_owned_cleanup_cannot_outlive_original_short_backup_deadline(candidate, monkeypatch):
    value = candidate(); now = install_clocks(value, monkeypatch)
    value.backup.peer.now = value.backup.source._binding._retain_until - 1
    close = value.vm.close
    def delayed(): close(); now[0] += 2
    with monkeypatch.context() as patch:
        patch.setattr(value.vm, 'close', delayed)
        with pytest.raises(MaterialAccessDenied): preview(value)
    assert_read_copies_disposed(value)


@pytest.mark.parametrize('error_type', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_first_read_source_close_failure_still_closes_other_source(candidate, monkeypatch, error_type):
    value = candidate(); close = value.vm.close
    def fail(): close(); raise error_type()
    with monkeypatch.context() as patch:
        patch.setattr(value.vm, 'close', fail)
        with pytest.raises(MaterialAccessDenied if error_type is RuntimeError else error_type): preview(value)
    assert_read_copies_disposed(value)


def test_normal_oauth_mcp_tool_can_join_host_bound_prerequisites_without_new_input_or_write(candidate, tmp_path):
    settings, headers, principal = bootstrap(tmp_path)
    identity = dict(requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest)
    value = candidate(identity=identity)
    action = LicenseVmPreviewAction(value.vm, **identity, preflight=value.preflight)
    with TestClient(create_http_app(settings, v4_license_vm_preview_action=action), base_url='https://mcp.example.com') as client:
        foreign = _login(client, 'fortipam:read fortipam:plan')
        assert _call(client, foreign, TOOL_NAME, {})['isError']
        assert not value.peer.calls and not value.backup.source._attempted
        assert not value.preflight._closed and not value.backup.source._closed
        result = _call(client, headers, TOOL_NAME, {})
        assert not result['isError']
        public = result['structuredContent']; joined = public['installation_prerequisites']
        assert joined['private_read_sources_disposed'] and public['private_source_copy_disposed']
        assert not joined['execution_authorized'] and not public['authorization_or_operation_created']
        assert_read_copies_disposed(value)


def test_mcp_outer_cleanup_also_retains_original_short_backup_deadline(candidate, tmp_path, monkeypatch):
    settings, headers, principal = bootstrap(tmp_path)
    identity = dict(requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest)
    value = candidate(identity=identity); now = install_clocks(value, monkeypatch)
    value.backup.peer.now = value.backup.source._binding._retain_until - 1
    action = LicenseVmPreviewAction(value.vm, **identity, preflight=value.preflight)
    close = action.close
    def delayed(): close(); now[0] += 2
    monkeypatch.setattr(action, 'close', delayed)
    with TestClient(create_http_app(settings, v4_license_vm_preview_action=action), base_url='https://mcp.example.com') as client:
        result = _call(client, headers, TOOL_NAME, {})
        assert result['isError'] and 'installation_prerequisites' not in json.dumps(result)
    assert_read_copies_disposed(value)


@pytest.mark.parametrize('drift', ['backup-file', 'backup-expiry', 'artifact-file', 'backup-guard'])
def test_drift_after_backup_observation_is_rejected_before_public_handoff(candidate, drift):
    value = candidate()
    def guard():
        if value.backup.source._attempted:
            if drift == 'backup-file': (value.backup.vault/'backup.conf').write_bytes(b'SYNTHETIC_CHANGED_BACKUP')
            elif drift == 'backup-expiry': value.backup.peer.now += 10
            elif drift == 'artifact-file': value.backup.artifact._path.write_bytes(b'SYNTHETIC_CHANGED_LICENSE')
            else: value.backup.source._guard = None
        return True
    value.vm._guard = value.vm._guard_pin = guard
    value.preflight = LicenseInstallPreflight(value.vm, value.backup.license, value.backup.source, **value.identity)
    with pytest.raises(MaterialAccessDenied): preview(value)
    assert_read_copies_disposed(value)


@pytest.mark.parametrize('repeat', [False, True])
def test_mcp_cancellation_drains_backup_read_and_preserves_original_artifact(candidate, tmp_path, monkeypatch, repeat):
    from fortipam_mcp import backup_artifact_custody
    from test_license_vm_preview_action import registered_preview
    _, _, principal = bootstrap(tmp_path)
    identity = dict(requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest)
    value = candidate(identity=identity)
    action = LicenseVmPreviewAction(value.vm, **identity, preflight=value.preflight)
    started, release, retained = Event(), Event(), []
    read = backup_artifact_custody._read
    def blocked(path, limit):
        raw = read(path, limit); retained.append(raw)
        if path.name == 'backup.conf': started.set(); assert release.wait(3)
        return raw
    monkeypatch.setattr(backup_artifact_custody, '_read', blocked)
    async def scenario():
        task = asyncio.create_task(registered_preview(action, principal)())
        try:
            assert await asyncio.to_thread(started.wait, 2)
            task.cancel(); await asyncio.sleep(.02)
            if repeat: task.cancel(); await asyncio.sleep(.02)
            assert not task.done()
            release.set()
            with pytest.raises(asyncio.CancelledError): await task
            assert_read_copies_disposed(value)
            assert retained and all(not any(raw) for raw in retained)
        finally:
            release.set()
            try: await task
            except asyncio.CancelledError: pass
    asyncio.run(scenario())


def test_unused_mcp_shutdown_disposes_both_read_sources_without_loading_material(candidate, tmp_path):
    settings, _, principal = bootstrap(tmp_path)
    identity = dict(requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest)
    value = candidate(identity=identity)
    action = LicenseVmPreviewAction(value.vm, **identity, preflight=value.preflight)
    with TestClient(create_http_app(settings, v4_license_vm_preview_action=action), base_url='https://mcp.example.com'):
        assert not value.vm._closed and not value.backup.source._closed
    assert not value.peer.calls and not value.backup.source._attempted
    assert_read_copies_disposed(value)


def test_actual_loopback_tls_and_original_backup_custody_join_through_normal_mcp(candidate, tmp_path):
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import ssl
    import threading
    from test_secret_bulk_import_action_process import tls_material
    settings, headers, principal = bootstrap(tmp_path)
    identity = dict(requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest)
    ca, key = tls_material(tmp_path)
    calls, connections, received, holder = [], [], [], {}
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *_): pass
        def do_GET(self):
            calls.append((self.command, self.path, self.headers.get('Cookie'), self.headers.get('Authorization')))
            raw = json.dumps(holder['peer'].payload).encode()
            self.send_response(200); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw))); self.send_header('Connection', 'close')
            self.end_headers(); self.wfile.write(raw)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(ca, key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    class Connection(http.client.HTTPSConnection):
        def connect(self):
            raw = socket.create_connection(('127.0.0.1', server.server_port), self.timeout)
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
    def factory(*args, **kwargs):
        connection = Connection(*args, **kwargs); connections.append(connection); return connection
    try:
        value = candidate(identity=identity, vm_options=(ca, factory)); holder['peer'] = value.peer
        fetch = value.vm._fetch
        def tracked(*args, **kwargs):
            raw = fetch(*args, **kwargs); received.append(raw); return raw
        value.vm._fetch = tracked
        action = LicenseVmPreviewAction(value.vm, **identity, preflight=value.preflight)
        with TestClient(create_http_app(settings, v4_license_vm_preview_action=action), base_url='https://mcp.example.com') as client:
            result = _call(client, headers, TOOL_NAME, {})
            assert not result['isError']
            joined = result['structuredContent']['installation_prerequisites']
            assert joined['original_backup_execution_verified'] and joined['retained_backup_files_intact']
            assert joined['artifact_metadata_available'] and not joined['license_execution_ready']
            assert calls == [('GET', STATUS_PATH, COOKIE, None)] and all(connection.sock is None for connection in connections)
            assert received and all(not any(raw) for raw in received)
            assert_read_copies_disposed(value)
            assert value.backup.peer.exports == 1
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
