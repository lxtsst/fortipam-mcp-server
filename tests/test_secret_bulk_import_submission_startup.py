"""Pinned metadata startup; synthetic grants, no live Owner activation."""

from dataclasses import asdict
import copy
import hashlib
import json
from pathlib import Path
import pickle
import socket
import time

import pytest
from starlette.testclient import TestClient

from fortipam_mcp import secret_bulk_import_intake as intake
from fortipam_mcp import secret_bulk_import_submission_startup as startup
from test_secret_bulk_import_submission import configured, frame, send


def profile_value(fixture):
    options = fixture['options']
    verifier, authority = options['planning_verifier'], options['authority']
    permission = authority._human_owner_verifier
    source, catalog = asdict(fixture['owner_binding']), asdict(options['catalog'])
    source['path'] = str(source['path'])
    for field in ('coverage', 'service_types'):
        catalog[field] = sorted(catalog[field])
    return dict(contract=startup.CONTRACT, purpose='private-dependency-projection-only', source=source,
        channel=asdict(verifier._binding), catalog=catalog,
        channel_options=dict(socket_path=str(verifier._socket), request_key_path=str(verifier._request.path),
            request_key_sha256=verifier._request.digest, public_key_path=str(verifier._public.path), public_key_sha256=verifier._public.digest),
        permission=dict(authority_ref=permission._authority_ref, reference=permission._reference,
            requester_digest=permission._requester, scope_key_path=str(permission._key.path),
            scope_key_sha256=permission._key.digest, socket_path=str(permission._authority._settings.socket_path)),
        policy=dict(policy_path=str(authority._policy), policy_sha256=authority._policy_digest,
                    key_path=str(authority._key), key_sha256=authority._key_digest))


def write_profile(tmp_path, value=None, *, raw=None):
    path = tmp_path / 'private-startup.json'
    content = raw if raw is not None else json.dumps(value).encode()
    path.write_bytes(content)
    path.chmod(0o600)
    return dict(profile_path=path, profile_sha256=hashlib.sha256(content).hexdigest())


def test_pinned_startup_joins_actual_protocol_without_reading_source(tmp_path, monkeypatch, capfd):
    fixture = configured(tmp_path, monkeypatch)
    subject = startup.PinnedOwnerFileSubmissionStartup(fixture['owner_binding'], **write_profile(tmp_path, profile_value(fixture)))
    assert repr(subject) == '<PinnedOwnerFileSubmissionStartup redacted>'
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(RuntimeError):
            operation(subject)
    original = intake.PinnedBulkImportFile
    monkeypatch.setattr(intake, 'PinnedBulkImportFile', lambda *a, **kw: pytest.fail('Startup read source'))
    with fixture['reference_transport']:
        app = subject.create_app_once()
        with pytest.raises(intake.BulkImportIntakeError):
            subject.create_app_once()
        monkeypatch.setattr(intake, 'PinnedBulkImportFile', original)
        with TestClient(app) as client:
            assert send(client, frame(fixture)).json() == {'status': 'projected', 'rows': 1, 'targets': 1}
    assert capfd.readouterr() == ('', '')


def test_failed_session_startup_consumes_the_same_creation_slot(tmp_path, monkeypatch):
    fixture = configured(tmp_path, monkeypatch)
    subject = startup.PinnedOwnerFileSubmissionStartup(fixture['owner_binding'], **write_profile(tmp_path, profile_value(fixture)))
    # A projection policy never promotes itself to source-session authority.
    with pytest.raises(intake.BulkImportIntakeError):
        subject.create_source_session_app_once(fixture['options']['authority'])
    with pytest.raises(intake.BulkImportIntakeError):
        subject.create_app_once()


@pytest.mark.parametrize('fault', ['expired-peer', 'profile-drift', 'used-slot'])
def test_parent_startup_failure_closes_inherited_peer_and_cannot_reset_creation(tmp_path, monkeypatch, fault):
    fixture = configured(tmp_path, monkeypatch)
    settings = write_profile(tmp_path, profile_value(fixture))
    subject = startup.PinnedOwnerFileSubmissionStartup(fixture['owner_binding'], **settings)
    local, remote = socket.socketpair()
    monkeypatch.setattr(intake, 'PinnedBulkImportFile', lambda *a, **kw: pytest.fail('Startup read source'))
    try:
        with fixture['reference_transport']:
            if fault == 'used-slot':
                subject.create_app_once()
            elif fault == 'profile-drift':
                create = startup.create_owner_file_submission_app
                def changed(*args, **kwargs):
                    app = create(*args, **kwargs)
                    settings['profile_path'].chmod(0o644)
                    return app
                monkeypatch.setattr(startup, 'create_owner_file_submission_app', changed)
            with pytest.raises(intake.BulkImportIntakeError):
                subject.create_original_parent_app_once(local, context_digest='8' * 64,
                    deadline=time.monotonic() + (-1 if fault == 'expired-peer' else 30))
            assert local.fileno() == -1
            remote.settimeout(1)
            assert remote.recv(1) == b''
            with pytest.raises(intake.BulkImportIntakeError):
                subject.create_app_once()
    finally:
        local.close()
        remote.close()


@pytest.mark.parametrize('fault', ['contract', 'purpose', 'unknown', 'token', 'database', 'source', 'float-time',
    'workload', 'catalog-scope', 'catalog-expired', 'catalog-field', 'key-alias', 'missing-permission', 'clock', 'oversize', 'duplicates'])
def test_invalid_profile_denies_before_constructing_dependencies(tmp_path, monkeypatch, fault):
    fixture = configured(tmp_path, monkeypatch)
    value = profile_value(fixture)
    if fault in ('contract', 'purpose'):
        value[fault] = 'other-contract-purpose'
    elif fault in ('unknown', 'token', 'database'):
        value['unexpected' if fault == 'unknown' else ('token' if fault == 'token' else 'database_path')] = 'synthetic-private-field'
    elif fault == 'source':
        value['source']['subject'] = 'other-human'
    elif fault == 'float-time':
        value['source']['issued_at'] = float(value['source']['issued_at'])
    elif fault == 'workload':
        value['channel']['workload_digest'] = '8' * 64
    elif fault == 'catalog-scope':
        value['catalog']['scope_digest'] = '8' * 64
    elif fault == 'catalog-expired':
        value['catalog']['expires_at'] = 0
    elif fault == 'catalog-field':
        value['catalog']['templates'][0]['fields'][0]['password'] = 'synthetic-forbidden-value'
    elif fault == 'key-alias':
        value['policy']['key_path'] = '/' + value['source']['path']
    elif fault == 'missing-permission':
        del value['permission']['reference']
    settings = write_profile(tmp_path, value, raw=b'x' * 65537 if fault == 'oversize' else (
        b'{"contract":"first","contract":"second"}' if fault == 'duplicates' else None))
    monkeypatch.setattr(startup, 'UnixIntakeTokenVerifier', lambda *a, **kw: pytest.fail('Invalid profile reached a verifier'))
    with pytest.raises(intake.BulkImportIntakeError):
        startup.PinnedOwnerFileSubmissionStartup(fixture['owner_binding'], **settings,
            **({'clock': lambda: fixture['owner_binding'].expires_at} if fault == 'clock' else {}))


@pytest.mark.parametrize('fault', ['mode', 'content', 'inode', 'wall-rollback', 'mono-rollback', 'expiry'])
def test_profile_drift_and_time_failure_consume_startup_before_dependency_construction(tmp_path, monkeypatch, fault):
    fixture = configured(tmp_path, monkeypatch)
    wall, mono = fixture['clocks'][0], fixture['clocks'][1]
    clocks = [wall, mono]
    settings = write_profile(tmp_path, profile_value(fixture))
    subject = startup.PinnedOwnerFileSubmissionStartup(fixture['owner_binding'], **settings,
        clock=lambda: clocks[0], monotonic=lambda: clocks[1])
    path = settings['profile_path']
    if fault == 'mode':
        path.chmod(0o644)
    elif fault == 'content':
        path.write_bytes(path.read_bytes() + b' ')
    elif fault == 'inode':
        other = path.with_name('replacement.json')
        other.write_bytes(path.read_bytes()); other.chmod(0o600); other.replace(path)
    elif fault == 'wall-rollback':
        clocks[0] -= 1
    elif fault == 'mono-rollback':
        clocks[1] -= 1
    else:
        clocks[0] = fixture['owner_binding'].expires_at
    monkeypatch.setattr(startup, 'UnixIntakeTokenVerifier', lambda *a, **kw: pytest.fail('Drift reached a verifier'))
    with pytest.raises(intake.BulkImportIntakeError):
        subject.create_app_once()
    clocks[:] = [wall, mono]
    with pytest.raises(intake.BulkImportIntakeError):
        subject.create_app_once()


def test_source_alias_is_rejected_before_profile_bytes_read(tmp_path, monkeypatch):
    fixture = configured(tmp_path, monkeypatch)
    binding = fixture['owner_binding']
    monkeypatch.setattr(startup, '_read_owned', lambda *a: pytest.fail('Unauthenticated source alias read'))
    with pytest.raises(intake.BulkImportIntakeError):
        startup.PinnedOwnerFileSubmissionStartup(binding, profile_path=Path('/' + str(binding.path)), profile_sha256=binding.file_sha256)


def test_profile_changes_during_reference_readiness_reject_the_built_app(tmp_path, monkeypatch):
    fixture = configured(tmp_path, monkeypatch)
    settings = write_profile(tmp_path, profile_value(fixture))
    subject = startup.PinnedOwnerFileSubmissionStartup(fixture['owner_binding'], **settings)
    original = startup.UnixReferenceAuthorityClient.verify_ready
    def changed(self):
        original(self)
        settings['profile_path'].chmod(0o644)
    monkeypatch.setattr(startup.UnixReferenceAuthorityClient, 'verify_ready', changed)
    with fixture['reference_transport'], pytest.raises(intake.BulkImportIntakeError):
        subject.create_app_once()


def test_successful_startup_does_not_replace_revocable_permission(tmp_path, monkeypatch):
    fixture = configured(tmp_path, monkeypatch)
    subject = startup.PinnedOwnerFileSubmissionStartup(fixture['owner_binding'], **write_profile(tmp_path, profile_value(fixture)))
    monkeypatch.setattr(intake, 'PinnedBulkImportFile', lambda *a, **kw: pytest.fail('Revoked permission read source'))
    with fixture['reference_transport']:
        app = subject.create_app_once()
        fixture['root_authority'].revoke(fixture['handle'], now_epoch=fixture['clocks'][0])
        with TestClient(app) as client:
            response = send(client, frame(fixture, b'synthetic-private-unlock'))
    assert response.status_code == 409 and response.json() == {'status': 'unavailable'}


@pytest.mark.parametrize('valid', [True, False])
def test_owned_profile_buffer_is_cleared_on_valid_and_invalid_composition(tmp_path, monkeypatch, valid):
    fixture = configured(tmp_path, monkeypatch)
    value = profile_value(fixture)
    if not valid:
        value['purpose'] = 'forbidden-purpose'
    buffers = []
    read = startup._read_owned
    def captured(*args):
        raw, identity = read(*args)
        buffers.append(raw)
        return raw, identity
    monkeypatch.setattr(startup, '_read_owned', captured)
    settings = write_profile(tmp_path, value)
    if valid:
        subject = startup.PinnedOwnerFileSubmissionStartup(fixture['owner_binding'], **settings)
        with fixture['reference_transport']:
            subject.create_app_once()
    else:
        with pytest.raises(intake.BulkImportIntakeError):
            startup.PinnedOwnerFileSubmissionStartup(fixture['owner_binding'], **settings)
    assert buffers and all(not any(raw) for raw in buffers)
