from dataclasses import replace
import hashlib
import json
import os
import ssl

import pytest

from fortipam_mcp import secret_create_191_http_transport as http
from fortipam_mcp import web_secret_fixture_creation_reader as metadata_reader
from fortipam_mcp.secret_create_191_private_adapter import SecretCreate191WebBinding
from fortipam_mcp.secret_create_191_projection_reader import SecretCreate191ProjectionReader
from fortipam_mcp.secret_create_lab_auto_runtime import FortiPam191LabAutoSecretCreateRunnerFactory, LabAutoSecretCreatePromoter
from fortipam_mcp.secret_metadata_http_transport import (FortiPamSecretMetadataHttpTransport,
    SecretMetadataHttpTransportConfig, SecretMetadataProjectionInspection)
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from fortipam_mcp.onboarding_action_coordinator import FixedActionResolutionError, OnboardingActionCoordinatorError
from fortipam_mcp.web_secret_fixture_creation_capture import WebSecretFixtureCaptureSettings, WebSecretFixtureCaptureError
from test_m4_execution_store import _store
from test_secret_onboarding_action_sequence import _Services
from test_secret_onboarding_projection_source import _web_binding, _web_draft
from test_instruction_feature_http_reader import Client, Response
from test_web_secret_create_dispatch_observation import _Connection
from test_web_secret_fixture_creation import _response, SERIAL_DIGEST
from v4_planning import ChangeKind, MaterialReferenceMetadata, ObjectClass, SchemeId, canonical_digest
from v4_planning.material_runtime import InMemoryMaterialUseStateStore


def _fixture(tmp_path, monkeypatch, mode='success'):
    services = _Services()
    onboarding = _web_binding()
    draft = replace(_web_draft(), material_reference_metadata=MaterialReferenceMetadata(
        provider_class='central_lab_inventory_reference', purpose='initial_onboarding', lifecycle='available'))
    desired = next(item for item in draft.desired_objects if item.object_class is ObjectClass.WEB_SECRET_METADATA)
    placeholder = SecretCreate191WebBinding('fortipam-700-build29-web-secret-create-candidate-v1', '7.0.0',
        '1' * 64, onboarding.folder_path, onboarding.secret_name, 'Web Account', onboarding.web_url, True, 29)
    config = SecretMetadataHttpTransportConfig('https://fortipam.example.test', 'unit-test-token', 5, None)
    transport = FortiPamSecretMetadataHttpTransport(config)
    projection = SecretCreate191ProjectionReader(onboarding, placeholder, transport)
    line = replace(services.plan.lines[0], target_ref=desired.object_ref, target_class=ObjectClass.WEB_SECRET_METADATA,
        change_kind=ChangeKind.CREATE, depends_on=(), expected_current_digest=projection._state_digest(exists=False),
        expected_state_digest=projection._state_digest(exists=True))
    content = dict(services.plan.canonical_content())
    content.update(lines=[line.as_dict()], scheme_id=SchemeId.SECRET_ONBOARDING.value)
    plan = replace(services.plan, lines=(line,), scheme_id=SchemeId.SECRET_ONBOARDING, plan_digest=canonical_digest(content))
    credentials = tmp_path / 'bindings.yaml'
    credentials.write_text('schema_version: credential-bindings-v1\nbindings:\n  - id: fixed-secret-create\n    provider: env-file\n    variables:\n      username: UNIT_USERNAME\n      password: UNIT_PASSWORD\n')
    credentials.chmod(0o600)
    material = tmp_path / 'material.env'
    material.write_text('UNIT_USERNAME=unit-user\nUNIT_PASSWORD=unit-password\n')
    material.chmod(0o600)
    store = _store(tmp_path / 'ledger')
    digest = canonical_digest({'database': str(store._path), 'key_file': str(store._key_path),
                              'key_digest': hashlib.sha256(store._key).hexdigest()})
    directory = tmp_path / 'capture'
    directory.mkdir(mode=0o700)
    key = tmp_path / 'capture.key'
    key.write_bytes(b'unit-web-capture-key-000000000001')
    key.chmod(0o600)
    settings = WebSecretFixtureCaptureSettings(SERIAL_DIGEST, digest, directory, key)
    connection = _Connection()
    body_buffers = []
    native_reads = []
    actual_request = connection.request
    def post(method, path, body, headers):
        assert (directory / 'creation.attempt').exists()
        assert json.loads(bytes(body))['uuid'] == '00000000-0000-0000-0000-000000000000'
        body_buffers.append(body.obj)
        actual_request(method, path, body, headers)
    connection.request = post
    monkeypatch.setattr(http.http.client, 'HTTPSConnection', lambda *_args, **_kwargs: connection)
    monkeypatch.setattr(http, '_ssl_context', lambda _: object())
    metadata = FortiPamSecretMetadataHttpTransport
    def inspect(*args):
        native_reads.append('projection')
        present = connection.posts > 0 or mode == 'existing'
        return SecretMetadataProjectionInspection(present, True, True, present, present, present, present, False,
                                                  recording_matches=present, http_service_enabled=present)
    monkeypatch.setattr(metadata, 'inspect_web_projection', inspect)
    monkeypatch.setattr(metadata, 'read_product_version_and_build', lambda *_args: ('7.0.0', 29))
    monkeypatch.setattr(metadata, 'resolve_folder_id', lambda *_args: 17)
    monkeypatch.setattr(metadata, 'resolve_secret_create_uuid', lambda *_args: '00000000-0000-0000-0000-000000000000')
    response = Response(_response(placeholder), 403 if mode == 'capture_failure' else 200)
    client = Client([response])
    monkeypatch.setattr(metadata_reader, '_ssl_context', lambda _: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    # The reader default factory is frozen at definition time; retain the real
    # function and inject only its synthetic HTTP client through the record seam.
    from fortipam_mcp import web_secret_fixture_creation_record as record
    real_read = metadata_reader.read_web_secret_fixture_creation
    monkeypatch.setattr(record, 'read_web_secret_fixture_creation',
        lambda *args, **kwargs: real_read(*args, **kwargs, client_factory=lambda **_kwargs: client))
    factory = FortiPam191LabAutoSecretCreateRunnerFactory(
        promoter=LabAutoSecretCreatePromoter(b'a' * 32, authorized_environment_ref=plan.environment_ref,
            authorized_scope_ref=plan.scope_ref, product_profile='fortipam-700-build29-web-create-candidate'),
        credential_bindings_path=credentials, secret_env_path=material, material_binding_ref='unit-material-binding-ref01',
        credential_binding_id='fixed-secret-create', transport_config=config,
        material_state_store=InMemoryMaterialUseStateStore(), execution_store=store,
        web_fixture_capture=settings, clock=lambda: plan.created_at + 1)
    def bind():
        return factory.bind(plan, line.line_ref, V4PlanningPrincipal(services.requester, 'a' * 64),
                            draft=draft, onboarding_binding=onboarding)
    return bind, factory, directory, store, connection, client, body_buffers, native_reads


def test_real_factory_original_c3_m4_and_fixed_reader_seal_once(tmp_path, monkeypatch):
    bind, factory, directory, store, connection, client, buffers, reads = _fixture(tmp_path, monkeypatch)
    runner = bind()
    assert not reads and not connection.posts and not client.calls
    result = runner.execute_bound()
    assert result['outcome'] == 'succeeded' and result['verification'] == 'verified'
    assert result['idempotent_replay'] is False
    evidence = runner.read_creation()
    assert evidence.native_secret_id == 37 and store.claim_count == 1
    assert len(client.calls) == connection.posts == 1
    assert client.is_closed and connection.closed and not client.cookies
    assert buffers and all(not any(raw) for raw in buffers)
    before = store._path.read_bytes()
    assert runner.execute_bound()['idempotent_replay'] is True
    assert store._path.read_bytes() == before and len(client.calls) == connection.posts == 1
    with pytest.raises(WebSecretFixtureCaptureError): bind().execute_bound()
    assert len(client.calls) == connection.posts == 1
    assert (directory / 'creation.attempt').exists() and (directory / 'creation.record').exists()
    assert factory._owner_credentials is None


def test_capture_failure_preserves_successful_m4_and_never_repeats_post_or_read(tmp_path, monkeypatch):
    bind, _, directory, store, connection, client, _, _ = _fixture(tmp_path, monkeypatch, 'capture_failure')
    runner = bind()
    with pytest.raises(WebSecretFixtureCaptureError): runner.execute_bound()
    assert store.audit_events[-1].outcome.value == 'succeeded'
    original = store._path.read_bytes()
    with pytest.raises(WebSecretFixtureCaptureError): runner.execute_bound()
    with pytest.raises(WebSecretFixtureCaptureError): bind().execute_bound()
    assert store._path.read_bytes() == original and len(client.calls) == connection.posts == 1
    assert (directory / 'creation.pending').exists() and not (directory / 'creation.record').exists()


def test_existing_native_secret_is_not_adopted_or_dispatched(tmp_path, monkeypatch):
    bind, _, directory, _, connection, client, _, _ = _fixture(tmp_path, monkeypatch, 'existing')
    result = bind().execute_bound()
    assert result['outcome'] != 'succeeded'
    assert not connection.posts and not client.calls
    assert (directory / 'creation.attempt').exists() and not (directory / 'creation.record').exists()


@pytest.mark.parametrize('defect', ['store_pin', 'current_digest', 'directory', 'userinfo'])
def test_bad_startup_or_absent_projection_binding_refuses_before_native_creation(tmp_path, monkeypatch, defect):
    bind, factory, directory, _, connection, client, _, reads = _fixture(tmp_path, monkeypatch)
    if defect == 'store_pin':
        factory._web_fixture_capture = replace(factory._web_fixture_capture, expected_store_digest='e' * 64)
    elif defect == 'current_digest':
        monkeypatch.setattr(SecretCreate191ProjectionReader, '_state_digest', lambda *_args, **_kwargs: 'e' * 64)
    elif defect == 'directory':
        directory.chmod(0o755)
    else:
        factory._transport_config = replace(factory._transport_config, base_url='https://unit:password@fortipam.example.test')
    with pytest.raises(FixedActionResolutionError): bind()
    assert not reads and not connection.posts and not client.calls and not (directory / 'creation.attempt').exists()


@pytest.mark.parametrize('point', [1, 2])
def test_attempt_sync_failure_and_restart_stop_before_native_dispatch(tmp_path, monkeypatch, point):
    bind, _, directory, _, connection, client, _, _ = _fixture(tmp_path, monkeypatch)
    runner = bind()
    original_sync = os.fsync
    calls = 0
    def sync(descriptor):
        nonlocal calls
        calls += 1
        if calls == point: raise OSError('Synthetic reserve storage failure')
        original_sync(descriptor)
    with monkeypatch.context() as patch:
        patch.setattr(os, 'fsync', sync)
        with pytest.raises(WebSecretFixtureCaptureError): runner.execute_bound()
    with pytest.raises(WebSecretFixtureCaptureError): bind().execute_bound()
    assert (directory / 'creation.attempt').exists() and not connection.posts and not client.calls


@pytest.mark.parametrize('defect', ['default', 'profile', 'memory_store', 'owner'])
def test_capture_is_opt_in_and_requires_the_exact_bearer_web_persistent_profile(tmp_path, monkeypatch, defect):
    _, original, _, _, connection, client, _, _ = _fixture(tmp_path, monkeypatch)
    promoter = original._promoter
    if defect == 'profile':
        promoter = LabAutoSecretCreatePromoter(b'a' * 32,
            authorized_environment_ref=promoter._environment_ref, authorized_scope_ref=promoter._scope_ref,
            product_profile='fortipam-191')
    from v4_planning import InMemoryM4ExecutionStateStore
    kwargs = dict(promoter=promoter, credential_bindings_path=original._credential_bindings_path,
        secret_env_path=original._secret_env_path, material_binding_ref=original._material_binding_ref,
        credential_binding_id=original._credential_binding_id, transport_config=original._transport_config,
        material_state_store=original._material_state_store,
        execution_store=InMemoryM4ExecutionStateStore() if defect == 'memory_store' else original._execution_store,
        clock=original._clock)
    if defect != 'default': kwargs['web_fixture_capture'] = original._web_fixture_capture
    if defect == 'owner': kwargs['owner_credentials'] = lambda: pytest.fail('No device password authentication.')
    if defect == 'default':
        factory = FortiPam191LabAutoSecretCreateRunnerFactory(**kwargs)
        assert factory._web_fixture_capture is None
    else:
        with pytest.raises(OnboardingActionCoordinatorError): FortiPam191LabAutoSecretCreateRunnerFactory(**kwargs)
    assert not connection.posts and not client.calls


def test_wrong_original_transport_is_rejected_before_any_native_call(tmp_path, monkeypatch):
    bind, factory, _, store, connection, client, _, reads = _fixture(tmp_path, monkeypatch)
    runner = bind()
    actual = runner._runner
    runtime = actual.runtime
    execution = runtime._resolve_binding(actual.authorization_ref)
    reader = runtime._projection_reader
    with pytest.raises(WebSecretFixtureCaptureError):
        factory._web_fixture_capture.bind(config=factory._transport_config,
            transport=http.FortiPam191SecretCreateHttpTransport(factory._transport_config),
            create_binding=reader._target_binding, execution_binding=execution, execution_store=store,
            onboarding_binding=reader._binding, runner=actual, reader=reader)
    assert not reads and not connection.posts and not client.calls
