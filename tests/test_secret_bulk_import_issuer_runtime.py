"""Normal HTTP OAuth wiring with a real private Unix channel; synthetic identities."""

import asyncio
from dataclasses import asdict, replace
import hashlib
import json
import logging
import os
from pathlib import Path
import socket
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest
from starlette.testclient import TestClient

from fortipam_mcp.http_server import (
    HTTP_ENV_FILE_VARIABLE, HttpConfigurationError, HttpServerSettings, create_http_app, load_http_runtime_environment,
)
from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV, RuntimeProfile
from fortipam_mcp.secret_bulk_import_issuer_runtime import CONTRACT, PREFIX, build_owner_file_intake_issuer
from fortipam_mcp.secret_bulk_import_token_channel import IntakeTokenChannelBinding, UnixIntakeTokenVerifier
from test_http_server import _initialize_payload, _v4_environment
from test_secret_bulk_import_oauth import PRIMARY, PRIVATE, issue


def configured(root):
    environment = _v4_environment(root)
    environment[RUNTIME_PROFILE_ENV] = 'v4-controlled'
    settings = HttpServerSettings.from_environment(environment)
    directory = root / 'channel'
    directory.mkdir(mode=0o700)
    material = {'request.key': b'R' * 32, 'signing.key': b'S' * 32,
        'public.key': Ed25519PrivateKey.from_private_bytes(b'S' * 32).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)}
    for name, content in material.items():
        path = directory / name
        path.write_bytes(content); path.chmod(0o600)
    now = int(time.time())
    binding = IntakeTokenChannelBinding(settings.local_oauth.issuer, PRIMARY, PRIVATE, '1' * 64, '2' * 64,
        now - 1, now + 120)
    options = dict(socket_path=directory / 'verify.sock', request_key_path=directory / 'request.key',
        request_key_sha256=hashlib.sha256(material['request.key']).hexdigest(),
        public_key_path=directory / 'public.key', public_key_sha256=hashlib.sha256(material['public.key']).hexdigest())
    profile = directory / 'issuer.json'
    value = dict(contract=CONTRACT, binding=asdict(binding), socket_path=str(options['socket_path']),
        request_key_path=str(options['request_key_path']), request_key_sha256=options['request_key_sha256'],
        signing_key_path=str(directory / 'signing.key'), signing_key_sha256=hashlib.sha256(material['signing.key']).hexdigest())
    profile.write_text(json.dumps(value)); profile.chmod(0o600)
    environment.update({PREFIX + 'ENABLED': 'true', PREFIX + 'PROFILE_FILE': str(profile),
        PREFIX + 'PROFILE_SHA256': hashlib.sha256(profile.read_bytes()).hexdigest()})
    return environment, settings, binding, options


def test_normal_http_issuer_keeps_resources_separate_and_closes_private_channel(capfd):
    with tempfile.TemporaryDirectory(prefix='fpi-') as temporary:
        environment, settings, binding, options = configured(Path(temporary).resolve())
        loggers = [logging.getLogger(name) for name in ('uvicorn', 'uvicorn.error', 'uvicorn.access')]
        before = [(item.level, tuple(item.handlers), item.propagate) for item in loggers]
        runtime = build_owner_file_intake_issuer(environment, settings=settings.local_oauth, runtime_profile=settings.runtime_profile)
        assert runtime is not None and not options['socket_path'].exists()
        app = create_http_app(settings, owner_file_intake_issuer=runtime)
        with TestClient(app, base_url='https://mcp.example.com') as client:
            planner_id, planner, _ = issue(client)
            intake_id, intake, _ = issue(client, private=True)
            private = UnixIntakeTokenVerifier(binding, planning=False, **options)
            planning = UnixIntakeTokenVerifier(binding, planning=True, **options)
            actual_private = asyncio.run(private.verify_token(intake['access_token']))
            actual_planning = asyncio.run(planning.verify_token(planner['access_token']))
            assert actual_private and actual_planning
            assert actual_private.subject == actual_planning.subject == 'operator'
            assert actual_private.resource == PRIVATE and actual_planning.resource == PRIMARY
            assert asyncio.run(private.verify_token(planner['access_token'])) is None
            assert asyncio.run(planning.verify_token(intake['access_token'])) is None
            headers = {'accept': 'application/json, text/event-stream', 'authorization': 'Bearer ' + intake['access_token']}
            assert client.post('/fpamcp', json=_initialize_payload(), headers=headers).status_code == 401
            headers['authorization'] = 'Bearer ' + planner['access_token']
            assert client.post('/fpamcp', json=_initialize_payload(), headers=headers).status_code == 200
            assert client.post('/v1/owner-file-token/intake', json={}).status_code == 404
            for identifier, issued, verifier in ((intake_id, intake, private), (planner_id, planner, planning)):
                assert client.post('/fpamcp/oauth/revoke', data={'token': issued['access_token'],
                    'client_id': identifier, 'client_secret': '', 'token_type_hint': 'access_token'}).status_code == 200
                assert asyncio.run(verifier.verify_token(issued['access_token'])) is None
        assert not options['socket_path'].exists()
        assert not runtime._thread.is_alive() and not runtime._watcher.is_alive()
        assert [(item.level, tuple(item.handlers), item.propagate) for item in loggers] == before
        with pytest.raises(ValueError, match='unavailable'):
            runtime.start_once()
        captured = capfd.readouterr()
        assert all(issued['access_token'] not in captured.out + captured.err for issued in (planner, intake))


def test_closed_defaults_invalid_host_and_existing_listener_do_not_gain_authority(monkeypatch):
    assert build_owner_file_intake_issuer({}, settings=None, runtime_profile=RuntimeProfile.READONLY) is None
    with tempfile.TemporaryDirectory(prefix='fpi-') as temporary:
        environment, settings, _, options = configured(Path(temporary).resolve())
        selected = {key: value for key, value in environment.items() if key.startswith(PREFIX)}
        env_file = Path(temporary).resolve() / 'http.env'
        env_file.write_text(''.join(f'{key}={value}\n' for key, value in selected.items()))
        env_file.chmod(0o600)
        for key in selected:
            monkeypatch.setenv(key, '')
            monkeypatch.delenv(key)
        monkeypatch.setenv(HTTP_ENV_FILE_VARIABLE, str(env_file))
        assert load_http_runtime_environment()
        assert {key: os.environ.get(key) for key in selected} == selected
        with pytest.raises(ValueError, match='unavailable'):
            build_owner_file_intake_issuer({**environment, PREFIX + 'ENABLED': 'false'},
                settings=settings.local_oauth, runtime_profile=settings.runtime_profile)
        with pytest.raises(ValueError, match='unavailable'):
            build_owner_file_intake_issuer(environment, settings=settings.local_oauth, runtime_profile=RuntimeProfile.V4_PLAN_ONLY)
        runtime = build_owner_file_intake_issuer(environment, settings=settings.local_oauth, runtime_profile=settings.runtime_profile)
        with pytest.raises(HttpConfigurationError):
            create_http_app(replace(settings, runtime_profile=RuntimeProfile.V4_PLAN_ONLY), owner_file_intake_issuer=runtime)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(options['socket_path'])); options['socket_path'].chmod(0o600)
            original = options['socket_path'].lstat().st_ino
            with pytest.raises(ValueError, match='unavailable'):
                runtime.start_once()
            assert options['socket_path'].lstat().st_ino == original
        finally:
            listener.close()
            options['socket_path'].unlink()
