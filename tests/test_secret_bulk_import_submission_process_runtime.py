"""Production restricted source module with real local signed admission services."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx
from mcp.server.auth.provider import ProviderTokenVerifier
import pytest

from fortipam_mcp import secret_bulk_import_submission_process as boundary
from fortipam_mcp.reference_authority_sidecar import UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings
from fortipam_mcp.secret_bulk_import_intake_authority import (
    PinnedOwnerFileIntakeAuthority, issue_prebound_owner_file_policy_once,
)
from fortipam_mcp.secret_bulk_import_parent_handoff import _OriginalParentReceiver
from fortipam_mcp.secret_bulk_import_reference_eligibility import ReferenceOwnerFileEligibility
from fortipam_mcp.secret_bulk_import_session_authority import (
    PinnedOwnerFileSessionAuthority, ReferenceOwnerFileSessionEligibility,
    REFERENCE_KIND as SESSION_KIND, issue_prebound_owner_file_session_policy_once, source_session_scope_ref,
)
from fortipam_mcp.secret_bulk_import_source_catalog import _TextOnlyImportSource
from fortipam_mcp.secret_bulk_import_submission import CONTENT_TYPE, PATH
from fortipam_mcp.secret_bulk_import_submission_startup import CONTRACT, PinnedOwnerFileSubmissionStartup
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, planning_principal_from_access_token
from fortipam_mcp.web_secret_create_ack import WebSecretCreateAckCapture
from test_secret_bulk_import_file import csv_bytes, encrypted_bytes, workbook_bytes
from test_secret_bulk_import_intake import prepared
from test_secret_bulk_import_reference_eligibility import AUTHORITY, CHECKPOINT, REFERENCE, STORE, source
from test_secret_bulk_import_row_wire import project
from test_secret_bulk_import_submission import frame
from test_secret_bulk_import_submission_process import CHECKPOINT_SERVER, REFERENCE_SERVER, paths, running
from test_secret_bulk_import_text_source import _source_fixtures, _text_row
from test_secret_bulk_import_token_channel import SERVER, setup, write
from test_v4_persistence import CHECKPOINT_STORE_REF, _ExternalCheckpoint, _new_store


@pytest.mark.skipif(sys.platform != 'darwin', reason='Native source workload restriction')
@pytest.mark.parametrize('ending', ['close', 'control-eof', 'deadline'])
def test_fixed_source_module_admits_original_session_then_closes_without_authority_inputs(
        monkeypatch, capfd, ending):
    with tempfile.TemporaryDirectory(prefix='fp-src-', dir='/private/tmp') as directory, ExitStack() as stack:
        root = Path(directory)
        fixture = setup(root)
        binding, _, _ = prepared(root, 'encrypted' if ending == 'close' else 'csv')
        values = [_text_row('First'), _text_row('Second')]
        raw = encrypted_bytes(workbook_bytes(values)) if ending == 'close' else csv_bytes(values)
        binding.path.write_bytes(raw)
        channel = fixture['binding']
        binding = replace(binding, file_sha256=hashlib.sha256(raw).hexdigest(), issuer=channel.issuer,
            subject='operator', planning_resource=channel.planning_resource, intake_resource=channel.intake_resource,
            planning_client=fixture['planning_client'], intake_client=fixture['intake_client'],
            deployment_digest=channel.deployment_digest, workload_digest=channel.workload_digest,
            issued_at=channel.issued_at, expires_at=channel.expires_at)
        token = asyncio.run(ProviderTokenVerifier(fixture['issuer']).verify_token(fixture['planning_token']))
        principal = planning_principal_from_access_token(token, V4PlanningAuthorizationSettings(
            expected_resource=channel.planning_resource, namespace_hmac_key=b'N' * 32))
        authority, permission, grant, _ = source(root, binding, [int(time.time())], requester=principal.requester.digest)
        authority.issue(REFERENCE, **grant)
        session_reference = 'owner-file-source-session-reference-02'
        authority.issue(session_reference, **dict(grant, reference_kind=SESSION_KIND,
            scope_ref=source_session_scope_ref(binding, bytearray(b'e' * 32))))
        permission = {name: value for name, value in permission.items() if name not in {'authority', 'clock'}}
        checkpoint_input = dict(database=str(root / 'checkpoint/state.sqlite'), key=str(root / 'checkpoint/checkpoint.key'),
            authority=CHECKPOINT, socket_path=str(root / 'checkpoint.sock'))
        reference_input = dict(database=str(root / 'reference/state.sqlite'), key=str(root / 'reference/reference.key'),
            checkpoint_socket=checkpoint_input['socket_path'], checkpoint_authority=CHECKPOINT,
            authority=AUTHORITY, store=STORE, socket_path=str(root / 'reference.sock'))
        settings = asdict(fixture['issuer'].settings)
        settings['database_path'] = str(settings['database_path'])
        token_input = dict(settings=settings, binding=asdict(channel),
            request_key_path=str(fixture['options']['request_key_path']),
            request_key_sha256=fixture['options']['request_key_sha256'],
            signing_key_path=str(fixture['signing_key']), signing_key_sha256=fixture['signing_sha'],
            socket_path=str(fixture['options']['socket_path']))
        stack.enter_context(running(CHECKPOINT_SERVER, checkpoint_input, root))
        stack.enter_context(running(REFERENCE_SERVER, reference_input, root))
        stack.enter_context(running(SERVER, token_input, root))
        remote = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(Path(reference_input['socket_path']), AUTHORITY))
        eligibility = ReferenceOwnerFileEligibility(binding, authority=remote, **permission)
        policy = dict(policy_path=root / 'admission.json', key_path=root / 'admission.key',
            key_sha256=write(root / 'admission.key', b'p' * 32))
        policy['policy_sha256'] = issue_prebound_owner_file_policy_once(binding, eligibility=eligibility, **policy)
        projection_authority = PinnedOwnerFileIntakeAuthority(binding, human_owner_verifier=eligibility, **policy)
        session_eligibility = ReferenceOwnerFileSessionEligibility(binding, authority=remote,
            **dict(permission, reference=session_reference))
        session_policy = dict(policy_path=root / 'session-admission.json', key_path=root / 'session-admission.key',
            key_sha256=write(root / 'session-admission.key', b's' * 32))
        session_policy['policy_sha256'] = issue_prebound_owner_file_session_policy_once(
            binding, eligibility=session_eligibility, **session_policy)
        session_authority = PinnedOwnerFileSessionAuthority(binding, human_owner_verifier=session_eligibility, **session_policy)
        # These native-source observations are explicit fixtures; admission itself uses real signed services.
        sources, _, _ = _source_fixtures(root, monkeypatch, None)
        profile = _TextOnlyImportSource(*sources)
        catalog = profile.prepare_catalog(expected_file_digest=binding.file_sha256, scope_digest=binding.scope_digest)
        defaults = replace(project(), serial_digest=sources[1].serial_digest)
        capture = WebSecretCreateAckCapture(defaults.serial_digest, 'success')
        metadata = asdict(catalog)
        for name in ('coverage', 'service_types'):
            metadata[name] = sorted(metadata[name])
        profile_path = root / 'startup.json'
        profile_digest = write(profile_path, json.dumps(dict(contract=CONTRACT,
            purpose='private-dependency-projection-only', source=paths(asdict(binding)), channel=asdict(channel),
            channel_options=paths(fixture['options']), catalog=metadata, policy=paths(policy),
            permission=dict(paths(permission), socket_path=reference_input['socket_path']))).encode())
        startup = PinnedOwnerFileSubmissionStartup(binding, profile_path=profile_path, profile_sha256=profile_digest)
        store, database, store_key = _new_store(root, now_epoch=int(time.time()),
            monotonic_checkpoint=_ExternalCheckpoint(), checkpoint_store_ref=CHECKPOINT_STORE_REF)
        monkeypatch.setattr(store, '_clock', lambda: int(time.time()))
        namespace_key = root / 'namespace.key'
        namespace_digest = write(namespace_key, b'n' * 32)
        parent, source_parent = socket.socketpair()
        stack.callback(parent.close)
        stack.callback(source_parent.close)
        receiver = _OriginalParentReceiver(parent, binding, catalog, store=store, authority=projection_authority,
            plan_ref='original-text-file-01', plan_digest=None, requester_digest=principal.requester.digest,
            parent_idempotency_digest='8' * 64, key_path=namespace_key, key_sha256=namespace_digest,
            standing_lab_authorization=True, text_source=profile)
        stack.callback(receiver.close)
        if ending == 'deadline':
            receiver._endpoint._deadline = min(receiver._endpoint._deadline, time.monotonic() + 4)
        deadline = receiver._endpoint._deadline
        row_dir = root / 'row'
        row_dir.mkdir(mode=0o700)
        public = Ed25519PrivateKey.from_private_bytes(b'k' * 32).public_key().public_bytes_raw()
        row_settings = dict(row_socket_path=row_dir / 'row.sock', row_request_key_path=row_dir / 'request.key',
            row_request_key_sha256=write(row_dir / 'request.key', b'q' * 32), row_public_key_path=row_dir / 'public.key',
            row_public_key_sha256=write(row_dir / 'public.key', public))
        assert not row_settings['row_socket_path'].exists()
        launches = []
        popen = boundary.subprocess.Popen

        def capture_process(command, **options):
            if 'fortipam_mcp.secret_bulk_import_submission_process' in command:
                assert command[:2] == ['/usr/bin/sandbox-exec', '-p']
                assert command[4:6] == ['-m', 'fortipam_mcp.secret_bulk_import_submission_process']
                assert len(options['pass_fds']) == 3 and set(options['env']) == {
                    'PATH', 'PYTHONDONTWRITEBYTECODE', 'PYTHONPATH'}
                assert options['stdin'] == options['stdout'] == options['stderr'] == subprocess.DEVNULL
                sandbox = command[2]
                for forbidden in (fixture['signing_key'], fixture['issuer'].settings.database_path,
                                  root / 'reference/reference.key', root / 'checkpoint/checkpoint.key',
                                  database, store_key, root / 'ca.pem', root / 'known_hosts'):
                    assert str(forbidden) not in sandbox
                for allowed in (binding.path, namespace_key, row_settings['row_request_key_path'],
                                row_settings['row_public_key_path'], row_settings['row_socket_path']):
                    assert str(allowed) in sandbox
                launches.append(command)
            return popen(command, **options)

        monkeypatch.setattr(boundary.subprocess, 'Popen', capture_process)
        original_open = os.open

        def deny_owner_source(path, *args, **kwargs):
            assert os.fsdecode(path) not in {str(binding.path), binding.path.name}, 'Owner opened the source'
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr(os, 'open', deny_owner_source)
        process = boundary._launch_original_text_submission_process(startup, session_authority, receiver,
            source_parent, defaults, capture, socket_path=root / 'intake.sock', **row_settings)
        stack.callback(process.close)
        assert len(launches) == 1 and process.deadline <= deadline
        assert process.parent_peer is parent and source_parent.fileno() == -1
        assert process._process.poll() is None and process.socket_path.exists()
        assert not row_settings['row_socket_path'].exists()
        assert startup._used
        with ThreadPoolExecutor(max_workers=1) as pool, httpx.Client(
                transport=httpx.HTTPTransport(uds=str(process.socket_path)), base_url='http://private-intake',
                timeout=5, trust_env=False, follow_redirects=False) as client:
            future = pool.submit(receiver.receive_once)
            invalid = dict(fixture, planning_token=fixture['intake_token'], intake_token=fixture['planning_token'])
            assert client.post(PATH, content=frame(invalid), headers={'Content-Type': CONTENT_TYPE}).status_code == 409
            assert not future.done()
            response = client.post(PATH, content=frame(fixture, b'synthetic-password' if ending == 'close' else b''),
                headers={'Content-Type': CONTENT_TYPE})
            original, projected, compiled = future.result(timeout=5)
            assert response.status_code == 200 and response.json() == {'status': 'projected', 'rows': 2, 'targets': 0}
            assert receiver._qualified.projected is projected and receiver._qualified is profile._current
            original._verify_dependencies_binding(binding, projected, catalog,
                authenticated_requester_digest=principal.requester.digest)
            assert len(compiled.steps) == 2 and not process._closed.is_set()
            assert client.post(PATH, content=frame(fixture), headers={'Content-Type': CONTENT_TYPE}).status_code == 409
            if ending == 'close':
                process.close()
            elif ending == 'control-eof':
                process.control_peer.shutdown(socket.SHUT_WR)
            process._watcher.join(timeout=6)
            assert not process._watcher.is_alive() and process._closed.is_set()
            # Zero exit includes verified child worker/watchdog disposal, not row success.
            assert process._process.returncode == 0
        assert not process.socket_path.exists() and process.control_peer.fileno() == -1
        assert hashlib.sha256(binding.path.read_bytes()).hexdigest() == binding.file_sha256
    assert capfd.readouterr() == ('', '')
