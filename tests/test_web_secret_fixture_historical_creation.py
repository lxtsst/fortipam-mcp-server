"""Original factory/M4/signed ACK restart custody with synthetic native I/O."""
from dataclasses import replace
import hashlib
import shutil

import pytest

from v4_planning import canonical_digest

from fortipam_mcp import web_secret_fixture_historical_creation as historical
from fortipam_mcp.web_secret_create_ack import WebSecretCreateAckCapture
from test_web_secret_create_ack import AckResponse
from test_web_secret_fixture_creation import SERIAL_DIGEST
from test_web_secret_fixture_creation_capture import _fixture as creation_fixture


def fixture(tmp_path, monkeypatch, *, source=True):
    bind, factory, directory, store, connection, client, _, _ = creation_fixture(tmp_path, monkeypatch)
    factory._web_fixture_capture = replace(factory._web_fixture_capture,
        ack_capture=WebSecretCreateAckCapture(SERIAL_DIGEST, None if source else "success", observe_source=source))
    connection.response = AckResponse()
    calls = []
    actual_bind = type(factory).bind
    def observe(owner, *args, **kwargs):
        calls.append((args, kwargs))
        return actual_bind(owner, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(type(factory), 'bind', observe)
        runner = bind()
    assert runner.execute_bound()['outcome'] == 'succeeded'
    args, values = calls[0]
    settings = factory._web_fixture_capture
    inputs = dict(original_plan=args[0], original_draft=values['draft'],
        onboarding_binding=values['onboarding_binding'], original_promoter=factory._promoter,
        execution_store=store, expected_store_digest=settings.expected_store_digest,
        serial_digest=settings.serial_digest, directory=directory, key_file=settings.key_file)
    return factory._transport_config, inputs, runner._record, connection, client


def test_historical_custody_keeps_original_expiry_and_does_not_promote_or_dispatch(tmp_path, monkeypatch):
    config, inputs, record, connection, client = fixture(tmp_path, monkeypatch)
    store = inputs['execution_store']
    before = (store._path.read_bytes(), store.claim_count, store.audit_events)
    files = {name: (inputs['directory'] / name).read_bytes() for name in ('creation.record', 'creation.ack')}
    original = record.read_acknowledged_creation()
    def refuse(*args, **kwargs):
        pytest.fail('Historical custody must not promote current authorization or read native state.')
    monkeypatch.setattr(type(inputs['original_promoter']), 'promote', refuse)
    monkeypatch.setattr(type(record._transport), 'read_web_create_dispatch_observation', refuse)
    custody = historical.read_historical_web_fixture_creation(config, **inputs)
    assert custody.read_original() == original
    assert custody._record._execution_binding.plan == record._execution_binding.plan
    assert custody._record._execution_binding.authorization == record._execution_binding.authorization
    assert custody._record._execution_binding.lease_request == record._execution_binding.lease_request
    assert custody._record._transport is not record._transport
    assert custody._record._transport._web_create_observation is None
    assert (store._path.read_bytes(), store.claim_count, store.audit_events) == before
    assert {name: (inputs['directory'] / name).read_bytes() for name in files} == files
    assert connection.posts == len(client.calls) == 1
    assert repr(custody) == str(custody) == '<WebSecretFixtureHistoricalCreation redacted>'


@pytest.mark.parametrize('fault', ['record', 'ack', 'ledger', 'key', 'store-pin', 'directory', 'promoter', 'binding', 'draft', 'plan'])
def test_changed_or_missing_original_custody_refuses_without_recreation(tmp_path, monkeypatch, fault):
    config, inputs, _, connection, client = fixture(tmp_path, monkeypatch)
    if fault in {'record', 'ack'}:
        (inputs['directory'] / ('creation.' + fault)).unlink()
    elif fault == 'ledger':
        inputs['execution_store']._path.unlink()
    elif fault == 'key':
        inputs['key_file'].write_bytes(b'changed-original-capture-key-001')
    elif fault == 'store-pin':
        inputs['expected_store_digest'] = 'e' * 64
    elif fault == 'directory':
        target = tmp_path / 'copied'
        target.mkdir(mode=0o700)
        for name in ('creation.record', 'creation.ack'):
            shutil.copyfile(inputs['directory'] / name, target / name)
            (target / name).chmod(0o600)
        inputs['directory'] = target
    elif fault == 'promoter':
        inputs['original_promoter']._authority_key = b'wrong-original-authority-key-001'
    elif fault == 'binding':
        inputs['onboarding_binding'] = replace(inputs['onboarding_binding'], web_url='https://other.example.test/')
    elif fault == 'draft':
        inputs['original_draft'] = replace(inputs['original_draft'], audience_ref='changed-original-audience')
    else:
        content = {**inputs['original_plan'].canonical_content(), 'requester_digest': 'e' * 64}
        inputs['original_plan'] = replace(inputs['original_plan'], requester_digest='e' * 64,
            plan_digest=canonical_digest(content))
    with pytest.raises(historical.WebSecretFixtureHistoricalCreationError) as caught:
        historical.read_historical_web_fixture_creation(config, **inputs)
    assert str(caught.value) == historical._ERROR
    assert connection.posts == len(client.calls) == 1
    if fault == 'ledger': assert not inputs['execution_store']._path.exists()


def test_later_record_changes_cannot_reuse_a_historical_custody_handle(tmp_path, monkeypatch):
    config, inputs, _, connection, client = fixture(tmp_path, monkeypatch)
    custody = historical.read_historical_web_fixture_creation(config, **inputs)
    path = inputs['directory'] / 'creation.ack'
    before = hashlib.sha256(path.read_bytes()).digest()
    path.write_bytes(path.read_bytes() + b'changed')
    with pytest.raises(historical.WebSecretFixtureHistoricalCreationError): custody.read_original()
    assert hashlib.sha256(path.read_bytes()).digest() != before
    assert connection.posts == len(client.calls) == 1


def test_normal_capture_restart_requires_exact_original_ack_source(tmp_path, monkeypatch):
    config, inputs, record, connection, client = fixture(tmp_path, monkeypatch, source=False)
    original = record.read_acknowledged_creation()
    baseline = (inputs['execution_store'].claim_count, connection.posts, len(client.calls))
    with pytest.raises(historical.WebSecretFixtureHistoricalCreationError):
        historical.read_historical_web_fixture_creation(config, **inputs)
    with pytest.raises(historical.WebSecretFixtureHistoricalCreationError):
        historical.read_historical_web_fixture_creation(config, **inputs,
            original_ack_capture=WebSecretCreateAckCapture(SERIAL_DIGEST, 'OK'))
    custody = historical.read_historical_web_fixture_creation(config, **inputs,
        original_ack_capture=WebSecretCreateAckCapture(SERIAL_DIGEST, 'success'))
    assert custody.read_original() == original
    assert custody._record._transport._web_create_observation is None
    assert baseline == (inputs['execution_store'].claim_count, connection.posts, len(client.calls))
