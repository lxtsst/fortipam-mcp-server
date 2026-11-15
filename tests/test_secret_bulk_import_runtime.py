"""Real local startup/admission/handoff; synthetic sources and no device I/O."""

import asyncio
from contextlib import ExitStack
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID
import httpx
from mcp.server.auth.provider import ProviderTokenVerifier
import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient
import uvicorn

from fortipam_mcp import secret_bulk_import_runtime as boundary
from fortipam_mcp.http_server import create_http_app
from fortipam_mcp.m4_execution_store import M4ExecutionStoreTail, M4MonotonicCheckpointError
from fortipam_mcp.planning_checkpoint_sidecar import UnixPlanningCheckpointClient, UnixPlanningCheckpointClientSettings
from fortipam_mcp.reference_authority_sidecar import UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings
from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp.secret_bulk_import_intake_authority import issue_prebound_owner_file_policy_once
from fortipam_mcp.secret_bulk_import_issuer_runtime import _PrivateChannelConfig, build_owner_file_intake_issuer
from fortipam_mcp.secret_bulk_import_reference_eligibility import ReferenceOwnerFileEligibility
from fortipam_mcp.secret_bulk_import_row_wire import _project_build29_secret_wire_defaults
from fortipam_mcp.secret_bulk_import_session_authority import (
    REFERENCE_KIND as SESSION_KIND, ReferenceOwnerFileSessionEligibility,
    issue_prebound_owner_file_session_policy_once, source_session_scope_ref,
)
from fortipam_mcp.secret_bulk_import_submission import CONTENT_TYPE, PATH
from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
from fortipam_mcp.web_secret_create_ack import WebSecretCreateAckCapture
from test_dlp_api_actor_guard import ACTOR, SERIAL
from test_ldap_server_mcp_action import _call
from test_material_checkpoint_sidecar import _start_sidecar as start_material, _stop_sidecar as stop_material
from test_planning_checkpoint_sidecar import _start_sidecar as start_planning, _stop_sidecar as stop_planning
from test_secret_bulk_import_file import csv_bytes
from test_secret_bulk_import_intake import prepared
from test_secret_bulk_import_issuer_runtime import configured
from test_secret_bulk_import_mcp_action import _NAMES, _PREVIEW, _tools
from test_secret_bulk_import_oauth import PRIMARY, PRIVATE, authorize, exchange, issue, register
from test_secret_bulk_import_reference_eligibility import AUTHORITY, CHECKPOINT, REFERENCE, STORE, source
from test_secret_bulk_import_row_current import NativeSources
from test_secret_bulk_import_row_wire import defaults_response
from test_secret_bulk_import_submission import frame
from test_secret_bulk_import_submission_process import CHECKPOINT_SERVER, REFERENCE_SERVER, paths, running
from test_secret_bulk_import_text_source import _text_row
from test_secret_bulk_import_token_channel import write


def _wait(predicate, seconds=8):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < deadline, 'Synthetic local runtime did not reach its bounded state'
        time.sleep(0.02)


def _tls(root):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'mcp.example.com')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('mcp.example.com')]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
    ca, private = root / 'main-ca.pem', root / 'main.key'
    write(ca, cert.public_bytes(serialization.Encoding.PEM))
    write(private, key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return ca, private


def test_native_ssh_owner_provider_is_explicit_and_keeps_password_in_memory(tmp_path, capsys):
    """Use real protected-file loaders with synthetic credentials and no device I/O."""
    login, known_hosts, legacy = (tmp_path / name for name in ('owner.env', 'known_hosts', 'legacy.password'))
    write(login, b'SYNTHETIC_OWNER=namespace-owner\nSYNTHETIC_PASSWORD=synthetic-owner-password\n')
    write(known_hosts, b'Synthetic pinned SSH host\n')
    environment = {
        boundary.SSH_PREFIX + 'ENABLED': 'true',
        boundary.SSH_PREFIX + 'SSH_HOST': 'synthetic.invalid',
        boundary.SSH_PREFIX + 'SSH_USERNAME': 'namespace-owner',
        boundary.SSH_PREFIX + 'SSH_KNOWN_HOSTS_FILE': str(known_hosts),
        boundary.OWNER_PREFIX + 'SESSION_ENABLED': 'true',
        boundary.OWNER_PREFIX + 'LOGIN_ENV_FILE': str(login),
        boundary.OWNER_PREFIX + 'USERNAME_VARIABLE': 'SYNTHETIC_OWNER',
        boundary.OWNER_PREFIX + 'PASSWORD_VARIABLE': 'SYNTHETIC_PASSWORD',
    }
    # Owner settings alone cannot replace the dedicated password-file branch.
    with pytest.raises(ValueError):
        boundary._load_native_ssh_config(environment)
    write(legacy, b'synthetic-dedicated-password')
    password_file_environment = {**environment, boundary.SSH_PREFIX + 'SSH_PASSWORD_FILE': str(legacy)}
    assert boundary._load_native_ssh_config(password_file_environment).password == 'synthetic-dedicated-password'

    original_files = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    selected = {**environment, boundary.SSH_PREFIX + 'OWNER_LOGIN_ENABLED': 'true'}
    config = boundary._load_native_ssh_config(selected)
    assert (config.host, config.port, config.username, config.password, config.known_hosts_file,
        config.timeout_seconds) == ('synthetic.invalid', 22, 'namespace-owner', 'synthetic-owner-password', known_hosts, 15)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == original_files

    # A mismatched or unavailable selected Owner never falls back to a password file.
    for changed in ({boundary.SSH_PREFIX + 'SSH_USERNAME': 'other-owner'},
                    {boundary.OWNER_PREFIX + 'SESSION_ENABLED': 'false'}):
        with pytest.raises(ValueError, match='^Protected Text import runtime is unavailable\\.$'):
            boundary._load_native_ssh_config({**password_file_environment,
                boundary.SSH_PREFIX + 'OWNER_LOGIN_ENABLED': 'true', **changed})
    captured = capsys.readouterr()
    assert not captured.out and not captured.err


def _configured(root, monkeypatch, stack, *, operate=False):
    environment, settings, channel, options = configured(root)
    issuer = build_owner_file_intake_issuer(environment,
        settings=settings.local_oauth, runtime_profile=settings.runtime_profile)
    stack.callback(issuer.close)
    # Register the original clients through the real provider before sealing the
    # file policy. Fresh tokens for those same clients are obtained from main.
    with TestClient(Starlette(routes=issuer.provider.authorization_routes()),
                    base_url='https://mcp.example.com') as client:
        if operate:
            scope = 'fortipam:read fortipam:plan fortipam:operate'
            registration = register(client, scope=scope)
            assert registration.status_code == 201
            planner = registration.json()['client_id']
            code = authorize(client, planner, resource=PRIMARY, scope=scope)
            planner_token = exchange(client, planner, code, PRIMARY).json()
        else:
            planner, planner_token, _ = issue(client)
        intake, _, _ = issue(client, private=True)
    token = asyncio.run(ProviderTokenVerifier(issuer.provider).verify_token(planner_token['access_token']))
    principal = planning_principal_from_access_token(token, settings.v4_planning_authorization)
    binding, _, _ = prepared(root)
    raw = csv_bytes([_text_row('First'), _text_row('Second')])
    binding.path.write_bytes(raw)
    binding = replace(binding, file_sha256=hashlib.sha256(raw).hexdigest(), issuer=channel.issuer,
        subject='operator', planning_resource=channel.planning_resource, intake_resource=channel.intake_resource,
        planning_client=planner, intake_client=intake, deployment_digest=channel.deployment_digest,
        workload_digest=channel.workload_digest, issued_at=channel.issued_at, expires_at=channel.expires_at)
    authority, permission, grant, _ = source(root, binding, [int(time.time())], requester=principal.requester.digest)
    authority.issue(REFERENCE, **grant)
    session_reference = 'runtime-original-source-session-01'
    authority.issue(session_reference, **dict(grant, reference_kind=SESSION_KIND,
        scope_ref=source_session_scope_ref(binding, bytearray(b'e' * 32))))
    permission = {key: value for key, value in permission.items() if key not in {'authority', 'clock'}}
    checkpoint = dict(database=str(root / 'checkpoint/state.sqlite'), key=str(root / 'checkpoint/checkpoint.key'),
        authority=CHECKPOINT, socket_path=str(root / 'reference-checkpoint.sock'))
    reference = dict(database=str(root / 'reference/state.sqlite'), key=str(root / 'reference/reference.key'),
        checkpoint_socket=checkpoint['socket_path'], checkpoint_authority=CHECKPOINT,
        authority=AUTHORITY, store=STORE, socket_path=str(root / 'reference.sock'))
    stack.enter_context(running(CHECKPOINT_SERVER, checkpoint, root))
    stack.enter_context(running(REFERENCE_SERVER, reference, root))
    remote = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(Path(reference['socket_path']), AUTHORITY))
    checker = ReferenceOwnerFileEligibility(binding, authority=remote, **permission)
    policy = dict(policy_path=root / 'admission.json', key_path=root / 'admission.key',
        key_sha256=write(root / 'admission.key', b'p' * 32))
    policy['policy_sha256'] = issue_prebound_owner_file_policy_once(binding, eligibility=checker, **policy)
    session_permission = dict(permission, reference=session_reference)
    session_checker = ReferenceOwnerFileSessionEligibility(binding, authority=remote, **session_permission)
    session_policy = dict(policy_path=root / 'session-policy.json', key_path=root / 'session-policy.key',
        key_sha256=write(root / 'session-policy.key', b's' * 32))
    session_policy['policy_sha256'] = issue_prebound_owner_file_session_policy_once(
        binding, eligibility=session_checker, **session_policy)

    stores = {}
    sidecar_environment = {'PATH': os.defpath, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')
        + os.pathsep + str(Path(__file__).resolve().parents[1]), 'PYTHONDONTWRITEBYTECODE': '1'}
    for kind, start, stop, prefix in (
        ('planning', start_planning, stop_planning, 'FORTIPAM_MCP_V4_CHECKPOINT_'),
        ('material', start_material, stop_material, 'FORTIPAM_MCP_V4_MATERIAL_CHECKPOINT_'),
    ):
        directory = root / (kind + '-checkpoint')
        directory.mkdir(mode=0o700)
        key = directory / 'key'
        write(key, (b'g' if kind == 'planning' else b'd') * 32)
        socket_path = root / (kind + '-checkpoint.sock')
        authority_ref = 'runtime-' + kind + '-checkpoint-01'
        process = start({**sidecar_environment, prefix + 'DATABASE': str(directory / 'state.sqlite'),
            prefix + 'HMAC_KEY_FILE': str(key), prefix + 'SOCKET': str(socket_path),
            prefix + 'AUTHORITY_REF': authority_ref}, socket_path)
        stack.callback(process.stderr.close)
        stack.callback(stop, process, socket_path)
        for store_kind in (('planning', 'execution') if kind == 'planning' else ('material',)):
            directory = root / (store_kind + '-store')
            directory.mkdir(mode=0o700)
            key = directory / 'key'
            write(key, {'planning': b'P', 'execution': b'E', 'material': b'M'}[store_kind] * 32)
            stores[store_kind] = dict(database_path=str(directory / 'state.sqlite'), hmac_key_path=str(key),
                checkpoint_socket_path=str(socket_path), checkpoint_authority_ref=authority_ref,
                checkpoint_store_ref='runtime-' + store_kind + '-store-01')

    native = NativeSources(root, monkeypatch)
    if operate:
        from test_secret_bulk_import_action_process import tls_material
        ca, _ = tls_material(root)
        Path(native.config.ca_file).write_bytes(ca.read_bytes())
    payload = defaults_response(); payload['serial'] = SERIAL
    defaults = _project_build29_secret_wire_defaults(bytearray(json.dumps(payload).encode()),
        serial_digest=hashlib.sha256(SERIAL.encode()).hexdigest())
    capture = WebSecretCreateAckCapture(defaults.serial_digest, 'success')
    product_env, product = root / 'product.env', root / 'product.json'
    write(product_env, ('SYNTHETIC_TOKEN=' + native.config.bearer_token + '\nSYNTHETIC_USERNAME=' + ACTOR + '\n').encode())
    product_sha = write(product, json.dumps(dict(contract='fortipam-original-row-product-source-v1',
        base_url=native.config.base_url, connect_ip='127.0.0.1', env_file=str(product_env),
        api_token_variable='SYNTHETIC_TOKEN', username_variable='SYNTHETIC_USERNAME', expected_username=ACTOR,
        ca_file=native.config.ca_file, actor=asdict(native.actor.binding))).encode())
    row = root / 'row'; row.mkdir(mode=0o700)
    signing = b'z' * 32
    public = ed25519.Ed25519PrivateKey.from_private_bytes(signing).public_key().public_bytes_raw()
    work = root / 'bootstrap'; work.mkdir(mode=0o700)
    manifest = dict(contract='fortipam-original-text-import-runtime-v1', source=paths(asdict(binding)),
        channel_options=paths(options), permission={**paths(permission), 'socket_path': reference['socket_path']},
        policy=paths(policy), session_permission={**paths(session_permission), 'socket_path': reference['socket_path']},
        session_policy=paths(session_policy), actor=asdict(native.actor.binding), ack_success_status='success',
        submission_profile_path=str(root / 'submission.json'), submission_socket_path=str(root / 'intake.sock'),
        parent=dict(plan_ref='runtime-original-text-parent-01', requester_digest=principal.requester.digest,
            parent_idempotency_digest='8' * 64, namespace_key_path=str(root / 'namespace.key'),
            namespace_key_sha256=write(root / 'namespace.key', b'n' * 32)), stores=stores,
        row=dict(authority_key_path=str(row / 'authority.key'), authority_key_sha256=write(row / 'authority.key', b'j' * 32),
            transport_digest=principal.transport_namespace_digest, scope_key_path=str(permission['scope_key_path']),
            scope_key_sha256=permission['scope_key_sha256'], socket_path=str(row / 'row.sock'),
            request_key_path=str(row / 'request.key'), request_key_sha256=write(row / 'request.key', b'q' * 32),
            signing_key_path=str(row / 'signing.key'), signing_key_sha256=write(row / 'signing.key', signing),
            public_key_path=str(row / 'public.key'), public_key_sha256=write(row / 'public.key', public),
            product_source_path=str(product), product_source_digest=product_sha,
            references=['runtime-original-row-reference-0', 'runtime-original-row-reference-1']),
        bootstrap=dict(database_path=reference['database'], hmac_key_path=reference['key'], authority_ref=AUTHORITY,
            checkpoint_socket_path=checkpoint['socket_path'], checkpoint_authority_ref=CHECKPOINT,
            checkpoint_store_ref=STORE, work_directory=str(work)))
    profile = root / 'runtime.json'
    environment.update({boundary.PREFIX + 'ENABLED': 'true', boundary.PREFIX + 'PROFILE_FILE': str(profile),
        boundary.PREFIX + 'PROFILE_SHA256': write(profile, json.dumps(manifest).encode()),
        boundary.PREFIX + 'EXECUTION_ENABLED': 'true'})
    return environment, settings, issuer, binding, native, defaults, capture, manifest, planner, intake


@pytest.mark.skipif(sys.platform != 'darwin', reason='Production source subprocess uses native restrictions')
@pytest.mark.parametrize('ending', ['ready', 'deadline', 'handoff'])
def test_main_starts_before_original_intake_and_registers_only_after_independent_grants(monkeypatch, capfd, ending):
    assert boundary.build_secret_bulk_import_runtime({}, issuer=None, runtime_profile=RuntimeProfile.READONLY) is None
    with tempfile.TemporaryDirectory(prefix='fp-run-', dir='/private/tmp') as temporary, ExitStack() as stack:
        root = Path(temporary)
        environment, settings, issuer, binding, native, defaults, capture, manifest, planner, intake = _configured(
            root, monkeypatch, stack, operate=ending == 'handoff')
        if ending == 'ready':
            mismatched = boundary.build_secret_bulk_import_runtime(environment,
                issuer=issuer, runtime_profile=settings.runtime_profile)
            stack.callback(mismatched.close)
            other_namespace = replace(settings, v4_planning_authorization=replace(
                settings.v4_planning_authorization, namespace_hmac_key=b'B' * 32))
            with pytest.raises(ValueError, match='Protected Text import runtime is unavailable'):
                create_http_app(other_namespace, owner_file_intake_issuer=issuer,
                    secret_bulk_import_runtime=mismatched)
            assert mismatched._server is None and mismatched._thread is None
            assert mismatched._source is None and mismatched._process is None and mismatched._owner is None
            assert not issuer._socket.exists() and not Path(manifest['submission_profile_path']).exists()
            assert not list(Path(manifest['bootstrap']['work_directory']).iterdir())
            mismatched.close()
        runtime = boundary.build_secret_bulk_import_runtime(environment, issuer=issuer, runtime_profile=settings.runtime_profile)
        stack.callback(runtime.close)
        events, processes, product_processes, product_connections = [], [], [], []
        if ending == 'handoff':
            def deny_product_connection(address, *args, **options):
                assert address == ('127.0.0.1', 9443)
                product_connections.append(address)
                raise ConnectionRefusedError('Synthetic product endpoint is intentionally closed')

            monkeypatch.setattr(socket, 'create_connection', deny_product_connection)
        from fortipam_mcp.secret_bulk_import_row_current import _OriginalRowNativeCurrent
        native_reads = []
        read_current = _OriginalRowNativeCurrent.read_current

        def count_current(reader, plan):
            native_reads.append(True)
            return read_current(reader, plan)

        monkeypatch.setattr(_OriginalRowNativeCurrent, 'read_current', count_current)
        popen = boundary.subprocess.Popen
        register = boundary.register_secret_bulk_import_candidate_tools

        def launch(command, *args, **options):
            if 'fortipam_mcp.secret_bulk_import_submission_process' in command:
                assert events == ['native'] and runner.started
                events.append('source')
            if 'fortipam_mcp.reference_grant_bootstrap' in command:
                assert runtime._receiver._qualified is not None and runtime._owner is not None
                assert not _NAMES.intersection(tool.name for tool in runtime._server.mcp._tool_manager.list_tools())
                assert options['stdin'] == options['stdout'] == options['stderr'] == subprocess.DEVNULL
                events.append('bootstrap')
            process = popen(command, *args, **options)
            processes.append(process)
            if 'fortipam_mcp.secret_bulk_import_action_process' in command:
                product_processes.append(process)
            return process

        def registered(server, action):
            assert threading.get_ident() == thread.ident
            assert events == ['native', 'source', 'bootstrap', 'bootstrap']
            assert not native_reads
            events.append('tools')
            return register(server, action)

        monkeypatch.setattr(boundary.subprocess, 'Popen', launch)
        monkeypatch.setattr(boundary, 'register_secret_bulk_import_candidate_tools', registered)
        if ending == 'deadline':
            receiver_init = boundary._OriginalParentReceiver.__init__

            def short_original_deadline(self, *args, **kwargs):
                receiver_init(self, *args, **kwargs)
                self._endpoint._deadline = min(self._endpoint._deadline, time.monotonic() + 4)

            monkeypatch.setattr(boundary._OriginalParentReceiver, '__init__', short_original_deadline)

        def native_source(environment, actor, status):
            assert runner.started and issuer._thread.is_alive() and issuer._socket.exists()
            assert actor == native.actor.binding and status == 'success'
            events.append('native')
            return native.profile(), defaults, capture

        monkeypatch.setattr(boundary, '_load_native_source', native_source)
        app = create_http_app(settings, owner_file_intake_issuer=issuer, secret_bulk_import_runtime=runtime)
        ca, key = _tls(root)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(root / 'main.sock')); (root / 'main.sock').chmod(0o600); listener.listen(8)
        stack.callback(listener.close)
        runner = uvicorn.Server(_PrivateChannelConfig(app, log_config=None, access_log=False, lifespan='on',
            ssl_certfile=str(ca), ssl_keyfile=str(key), timeout_graceful_shutdown=1))
        runtime.bind_runner(runner)
        thread = threading.Thread(target=runner.run, kwargs={'sockets': [listener]}, daemon=True)
        thread.start()

        def stop():
            runner.should_exit = True
            thread.join(timeout=8)
            assert not thread.is_alive()

        stack.callback(stop)
        _wait(lambda: runner.started)
        trust = ssl.create_default_context(cafile=str(ca))
        client = stack.enter_context(httpx.Client(transport=httpx.HTTPTransport(uds=str(root / 'main.sock'), verify=trust),
            base_url='https://mcp.example.com', trust_env=False, timeout=8))
        scope = 'fortipam:read fortipam:plan' + (' fortipam:operate' if ending == 'handoff' else '')
        code = authorize(client, planner, resource=PRIMARY, scope=scope)
        planner_token = exchange(client, planner, code, PRIMARY).json()['access_token']
        code = authorize(client, intake, resource=PRIVATE, scope='fortipam:bulk-import-intake')
        intake_token = exchange(client, intake, code, PRIVATE).json()['access_token']
        headers = {'accept': 'application/json, text/event-stream', 'authorization': 'Bearer ' + planner_token}
        assert not _NAMES.intersection(_tools(client, headers))
        _wait(lambda: Path(manifest['submission_socket_path']).exists())
        assert events == ['native', 'source'] and not Path(manifest['row']['socket_path']).exists()
        # The handoff case reaches C3 through the real restricted source, then
        # fails at an explicitly blocked synthetic product connection.
        if ending in {'ready', 'handoff'}:
            with httpx.Client(transport=httpx.HTTPTransport(uds=manifest['submission_socket_path']),
                    base_url='http://private-intake', trust_env=False, timeout=8) as intake_client:
                response = intake_client.post(PATH, content=frame(dict(planning_token=planner_token,
                    intake_token=intake_token)), headers={'Content-Type': CONTENT_TYPE})
            assert response.status_code == 200 and response.json() == {'status': 'projected', 'rows': 2, 'targets': 0}
            _wait(lambda: _NAMES <= _tools(client, headers).keys())
            result = _call(client, headers, _PREVIEW, {})
            assert len(native_reads) == 2
            assert not result.get('isError') and '"rows":2' in json.dumps(result, separators=(',', ':'))
            assert runtime._ready.is_set() and not runtime._failed
            assert runtime._owner._execution.claim_count == 0
            assert events == ['native', 'source', 'bootstrap', 'bootstrap', 'tools']
            assert len(list(Path(manifest['bootstrap']['work_directory']).glob('row-*-grants.json'))) == 2
            assert not Path(manifest['row']['socket_path']).exists()
            # Exercise the new tail conversion over the real CAS sidecar using
            # an independent namespace; the Owner execution ledger stays empty.
            execution = manifest['stores']['execution']
            store_ref = 'runtime-independent-m4-cas-01'
            checkpoint = boundary._M4PlanningCheckpoint(UnixPlanningCheckpointClient(
                UnixPlanningCheckpointClientSettings(Path(execution['checkpoint_socket_path']),
                    execution['checkpoint_authority_ref'])), store_ref)
            empty = M4ExecutionStoreTail.empty(store_ref)
            first, second = (M4ExecutionStoreTail(store_ref, sequence, digest * 64)
                             for sequence, digest in ((1, 'a'), (2, 'b')))
            checkpoint.verify(empty)
            checkpoint.advance(empty, first); checkpoint.verify(first)
            checkpoint.advance(first, second); checkpoint.verify(second)
            with pytest.raises(M4MonotonicCheckpointError):
                checkpoint.verify(first)
            with pytest.raises(M4MonotonicCheckpointError):
                checkpoint.verify(M4ExecutionStoreTail('runtime-other-m4-cas-01', 2, 'b' * 64))
            assert runtime._owner._execution.claim_count == 0
            if ending == 'handoff':
                authorized = _call(client, headers, 'authorize_v4_secret_bulk_import_text_700',
                    {'preview_ref': result['structuredContent']['preview_ref']})
                assert not authorized.get('isError')
                executed = _call(client, headers, 'execute_v4_secret_bulk_import_text_700',
                    {'authorization_ref': authorized['structuredContent']['authorization_ref']})
                assert not executed.get('isError') and executed['structuredContent'] == {
                    'status': 'reconciliation_required', 'verified_lines': 0, 'total_lines': 2, 'completed': False}
                assert runtime._owner._execution.claim_count == runtime._owner._material.claim_count == 1
                assert product_connections == [('127.0.0.1', 9443)]
                assert len(product_processes) == 1 and product_processes[0].poll() == 17
        else:
            # The source and parent inherit the same shortened original
            # deadline; no file or child grant is fabricated or renewed.
            _wait(lambda: not Path(manifest['submission_socket_path']).exists())
            _wait(runtime._done.is_set)
            assert runtime._failed and not runtime._ready.is_set()
            assert runtime._owner is None and events == ['native', 'source']
            assert not _NAMES.intersection(_tools(client, headers))
        runtime.close()
        _wait(lambda: not Path(manifest['submission_socket_path']).exists())
        _wait(lambda: not _NAMES.intersection(_tools(client, headers)))
        assert runtime._done.is_set() and not runtime._thread.is_alive()
        assert processes and all(process.poll() is not None for process in processes)
        assert not Path(manifest['row']['socket_path']).exists()
        assert hashlib.sha256(binding.path.read_bytes()).hexdigest() == binding.file_sha256
        stop()
        assert not issuer._socket.exists()
        assert not issuer._thread.is_alive() and not issuer._watcher.is_alive()
        native.disposed()
    output = capfd.readouterr()
    assert all(token not in output.out + output.err for token in (planner_token, intake_token))
