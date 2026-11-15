"""Existing factory/C3/M4/ACK plus original baseline and recovery, synthetic I/O."""
from dataclasses import replace
import json
import ssl

import pytest

from fortipam_mcp import web_secret_fixture_lifecycle as l
from fortipam_mcp import web_secret_fixture_api_preservation_reader as r
from fortipam_mcp import web_secret_fixture_recovery_runtime as w
from fortipam_mcp.onboarding_action_coordinator import FixedActionResolutionError
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from fortipam_mcp.web_secret_create_ack import WebSecretCreateAckCapture
from test_web_secret_fixture_creation_capture import _fixture as creation_fixture
from test_web_secret_fixture_creation import SERIAL_DIGEST
from test_web_secret_create_ack import AckResponse
from test_web_secret_fixture_recovery_runtime import NativeConnection
from test_instruction_feature_http_reader import Client, Response
from test_secret_instruction_build29_api_preservation import _source, _raw, PASSWORD


def fixture(tmp_path, monkeypatch, *, enabled=True, ack=True, bad_pins=False):
    bind_original, original, directory, store, create, metadata, buffers, reads = creation_fixture(tmp_path, monkeypatch)
    original._web_fixture_capture = replace(original._web_fixture_capture,
        ack_capture=WebSecretCreateAckCapture(SERIAL_DIGEST, 'success') if ack else None)
    create.response = AckResponse()
    baseline = {key: value for key, value in json.loads(metadata.responses[0].content)['results'][0].items()
        if key not in {'field', 'totp'}}
    row = _source('')
    row['serial'] = 'unit-appliance'
    row['results'][0].update(baseline)
    password_pin = dict(http_method='POST', http_status=200, status='OK', msg='Synthetic Password source')
    totp_pin = {**password_pin, 'msg': 'Synthetic TOTP source'}
    password = _raw({**password_pin, 'secret-id': 37, 'results': PASSWORD})
    totp = _raw({**totp_pin, 'secret-id': 37, 'results': ''})
    def client():
        return Client([Response(_raw(row)), Response(password), Response(totp), Response(_raw(row)),
            Response(totp), Response(password), Response(_raw(row))])
    clients = [client(), client(), client()]
    events = []
    pending = iter(clients)
    def producer(**kwargs):
        events.append('full-read')
        return next(pending)
    connections = [NativeConnection('DELETE', events), NativeConnection('GET', events)]
    native = iter(connections)
    monkeypatch.setattr(r, '_ssl_context', lambda _: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    monkeypatch.setattr(w, '_ssl_context', lambda _: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    if bad_pins: password_pin['secret-id'] = 99
    kwargs = dict(authority_key=b'synthetic-lifecycle-authority-key',
        environment_ref=original._promoter._environment_ref, scope_ref=original._promoter._scope_ref,
        audience_ref='synthetic-oauth-client', credential_envelope=password_pin, totp_envelope=totp_pin,
        delete_status='success', execution_enabled=enabled, client_factory=producer,
        connection_factory=lambda *args, **kwargs: next(native))
    def construct(): return l.WebSecretFixtureLifecycleFactory(original, **kwargs)
    def bind(lifecycle):
        # Reuse the actual original bind inputs, without executing its runner.
        seen = []
        real_bind = type(original).bind
        def observe(instance, *args, **kwargs):
            seen.append((args, kwargs))
            return real_bind(instance, *args, **kwargs)
        with monkeypatch.context() as patch:
            patch.setattr(type(original), 'bind', observe)
            bind_original()
        args, kwargs = seen[0]
        return lifecycle.bind(*args, **kwargs), args[2]
    return construct, bind, original, directory, store, create, metadata, clients, connections, events


def test_original_factory_and_recovery_preserve_custody_and_never_redispatch(tmp_path, monkeypatch):
    construct, bind, original, directory, store, create, metadata, clients, connections, events = fixture(tmp_path, monkeypatch)
    lifecycle = construct()
    runner, principal = bind(lifecycle)
    assert not events and not create.posts and not metadata.calls
    result = runner.execute_bound()
    assert result['outcome'] == 'succeeded' and result['idempotent_replay'] is False
    assert events == ['full-read'] and create.posts == len(metadata.calls) == 1
    record = runner._capture._record
    seals = [(directory / name).read_bytes() for name in ('creation.record', 'creation.ack')]
    original_creation = record.read_acknowledged_creation()
    assert runner.execute_bound()['idempotent_replay'] is True
    assert events == ['full-read'] and create.posts == 1
    recovered = lifecycle.recover_once(principal)
    assert recovered['outcome'] == 'succeeded' and recovered['verification'] == 'verified'
    assert store.claim_count == 2
    assert events == ['full-read', 'full-read', 'tls', 'full-read', 'DELETE', 'tls', 'GET']
    assert record.read_acknowledged_creation() == original_creation
    assert [(directory / name).read_bytes() for name in ('creation.record', 'creation.ack')] == seals
    assert all(len(client.calls) == 7 and client.is_closed for client in clients)
    assert all(len(connection.calls) == 1 and connection.closed for connection in connections)
    with pytest.raises(l.WebSecretFixtureLifecycleError): lifecycle.recover_once(principal)
    assert runner.execute_bound()['idempotent_replay'] is True and create.posts == 1
    lifecycle.close()


@pytest.mark.parametrize('fault', ['disabled', 'missing-ack', 'selector-pin'])
def test_incomplete_startup_stops_before_creation_or_material_reads(tmp_path, monkeypatch, fault):
    construct, bind, _, _, _, create, metadata, clients, connections, _ = fixture(tmp_path, monkeypatch,
        enabled=fault != 'disabled', ack=fault != 'missing-ack', bad_pins=fault == 'selector-pin')
    if fault == 'disabled':
        lifecycle = construct()
        assert lifecycle.execution_preflight_available() is False
        with pytest.raises(FixedActionResolutionError): bind(lifecycle)
    else:
        with pytest.raises(l.WebSecretFixtureLifecycleError): construct()
    assert not create.posts and not metadata.calls
    assert not any(client.calls for client in clients) and not any(connection.calls for connection in connections)


def test_wrong_recovery_transport_cannot_consume_original_cleanup(tmp_path, monkeypatch):
    construct, bind, _, _, _, _, _, clients, connections, _ = fixture(tmp_path, monkeypatch)
    lifecycle = construct()
    runner, principal = bind(lifecycle)
    runner.execute_bound()
    with pytest.raises(l.WebSecretFixtureLifecycleError):
        lifecycle.recover_once(V4PlanningPrincipal(principal.requester, 'b' * 64))
    assert not clients[1].calls and not any(connection.calls for connection in connections)
    assert lifecycle.recover_once(principal)['outcome'] == 'succeeded'


@pytest.mark.parametrize('fault', ['baseline-denied', 'recovery-password-drift', 'delete-ack-id'])
def test_failed_stage_keeps_original_creation_and_consumed_attempts(tmp_path, monkeypatch, fault):
    construct, bind, _, directory, store, create, _, clients, connections, _ = fixture(tmp_path, monkeypatch)
    lifecycle = construct()
    runner, principal = bind(lifecycle)
    if fault == 'baseline-denied': clients[0].responses[0].status_code = 403
    if fault == 'baseline-denied':
        with pytest.raises(l.WebSecretFixtureLifecycleError): runner.execute_bound()
        with pytest.raises(l.WebSecretFixtureLifecycleError): runner.execute_bound()
    else:
        runner.execute_bound()
        if fault == 'recovery-password-drift':
            for index in (1, 5): clients[1].responses[index].content = clients[1].responses[index].content.replace(
                b'synthetic-password', b'changed-password')
            with pytest.raises(l.WebSecretFixtureLifecycleError): lifecycle.recover_once(principal)
        else:
            connections[0].response.raw = connections[0].response.raw.replace(b'"mkey":37', b'"mkey":38')
            assert lifecycle.recover_once(principal)['outcome'] == 'reconciliation_required'
    assert create.posts == 1 and (directory / 'creation.record').exists() and (directory / 'creation.ack').exists()
    assert runner._capture._record.read_acknowledged_creation().creation.native_secret_id == 37
    assert store.claim_count == (2 if fault == 'delete-ack-id' else 1)
    with pytest.raises(l.WebSecretFixtureLifecycleError): lifecycle.recover_once(principal)
    assert len(connections[0].calls) == (1 if fault == 'delete-ack-id' else 0)
    assert not connections[1].calls


def test_factory_drift_and_restart_do_not_adopt_created_fixture(tmp_path, monkeypatch):
    construct, bind, original, _, _, create, _, clients, connections, _ = fixture(tmp_path, monkeypatch)
    lifecycle = construct()
    runner, principal = bind(lifecycle)
    runner.execute_bound()
    config = original._transport_config
    original._transport_config = replace(config, bearer_token='changed-synthetic-token')
    with pytest.raises(l.WebSecretFixtureLifecycleError): lifecycle.recover_once(principal)
    assert not clients[1].calls and not any(connection.calls for connection in connections)
    original._transport_config = config
    with pytest.raises((FixedActionResolutionError, l.WebSecretFixtureLifecycleError)):
        rebound, _ = bind(construct())
        rebound.execute_bound()
    assert create.posts == 1 and not clients[1].calls


def http_fixture(tmp_path, monkeypatch):
    from fortipam_mcp.secret_metadata_http_transport import FortiPamSecretMetadataHttpTransport
    from fortipam_mcp.secret_onboarding_projection_source import FortiPamSecretOnboardingProjectionSource
    from fortipam_mcp.v4_runtime_host import V4PlanHostComponents
    from test_secret_onboarding_action_sequence import _Services
    from test_secret_onboarding_projection_source import WebResolver, TargetTransport

    result = fixture(tmp_path, monkeypatch)
    construct, bind, original = result[:3]
    lifecycle = construct()
    inputs = []
    with monkeypatch.context() as patch:
        patch.setattr(lifecycle, 'bind', lambda *args, **kwargs: inputs.append((args, kwargs)))
        _, principal = bind(lifecycle)
    args, kwargs = inputs[0]
    services = _Services()
    services.plan, services.draft = args[0], kwargs['draft']
    probes = []
    monkeypatch.setattr(services, 'bind_secret_create_execution_preflight_probe', probes.append, raising=False)
    transport = FortiPamSecretMetadataHttpTransport(original._transport_config)
    source = FortiPamSecretOnboardingProjectionSource(transport, TargetTransport(), None, WebResolver())
    components = V4PlanHostComponents(services, None, secret_onboarding_projection_source=source)
    return lifecycle, components, principal, probes, result


def test_existing_protected_action_reaches_original_creation_baseline_and_recovery(tmp_path, monkeypatch):
    from fortipam_mcp.onboarding_execution_mcp_action import V4OnboardingExecutionRuntimeError
    from test_secret_onboarding_action_sequence import PLAN_REF, DRAFT_REF

    lifecycle, components, principal, probes, result = http_fixture(tmp_path, monkeypatch)
    _, _, _, directory, store, create, _, clients, connections, events = result
    access, action = lifecycle.bind_http_actions(components)
    assert access is None and probes == [lifecycle.execution_preflight_available]
    assert not events and not create.posts
    response = action.execute(PLAN_REF, DRAFT_REF, principal)
    assert response['outcome'] == 'succeeded', response
    assert create.posts == 1 and store.claim_count == 1 and events == ['full-read']
    assert (directory / 'creation.ack').exists()
    assert lifecycle.recover_once(principal)['outcome'] == 'succeeded'
    assert store.claim_count == 2 and all(client.is_closed for client in clients)
    assert all(connection.closed for connection in connections)
    lifecycle.close()
    assert action._execution_enabled is False and probes[0]() is False
    with pytest.raises(V4OnboardingExecutionRuntimeError): action.execute(PLAN_REF, DRAFT_REF, principal)
    assert create.posts == 1


@pytest.mark.parametrize('fault', ['wrong-source', 'foreign-config', 'access-domain', 'duplicate'])
def test_http_factory_refuses_unbound_or_repeated_composition_before_io(tmp_path, monkeypatch, fault):
    lifecycle, components, _, probes, result = http_fixture(tmp_path, monkeypatch)
    _, _, _, _, _, create, metadata, clients, connections, _ = result
    if fault == 'wrong-source': components = replace(components, secret_onboarding_projection_source=object())
    elif fault == 'foreign-config':
        source = components.secret_onboarding_projection_source
        source._secret_transport._config = replace(source._secret_transport._config, bearer_token='foreign-synthetic-token')
    elif fault == 'access-domain': components = replace(components, access_domain_projection_source=object())
    else: lifecycle.bind_http_actions(components)
    with pytest.raises(l.WebSecretFixtureLifecycleError): lifecycle.bind_http_actions(components)
    assert len(probes) == (1 if fault == 'duplicate' else 0)
    assert not create.posts and not metadata.calls
    assert not any(client.calls for client in clients) and not any(connection.calls for connection in connections)


def test_http_source_drift_stops_the_bound_action_before_create(tmp_path, monkeypatch):
    from test_secret_onboarding_action_sequence import PLAN_REF, DRAFT_REF
    lifecycle, components, principal, probes, result = http_fixture(tmp_path, monkeypatch)
    _, action = lifecycle.bind_http_actions(components)
    source = components.secret_onboarding_projection_source
    source._secret_transport._config = replace(source._secret_transport._config, bearer_token='changed-synthetic-token')
    assert probes[0]() is False
    assert action.execute(PLAN_REF, DRAFT_REF, principal)['outcome'] == 'reconciliation_required'
    assert not result[5].posts and not result[6].calls and not result[-1]


def test_existing_http_injection_registers_only_the_bounded_onboarding_tool(tmp_path, monkeypatch):
    import asyncio
    from mcp import Client
    from fortipam_mcp import http_server, server
    from fortipam_mcp.onboarding_execution_mcp_action import (
        V4_ONBOARDING_EXECUTION_FEATURE_ENV, V4_ACCESS_DOMAIN_EXECUTION_TOOL,
        V4_SECRET_ONBOARDING_EXECUTION_TOOL)
    from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
    from fortipam_mcp.v4_runtime_host import synthetic_v4_plan_host_factory, V4_SYNTHETIC_HOST_MODE_ENV
    from test_http_server import _v4_bound_environment

    lifecycle, source_components, _, _, result = http_fixture(tmp_path, monkeypatch)
    environment, settings = _v4_bound_environment(tmp_path)
    environment.update({RUNTIME_PROFILE_ENV: 'v4-controlled',
        V4_SYNTHETIC_HOST_MODE_ENV: 'source-backed-secret-onboarding'})
    host_base = synthetic_v4_plan_host_factory(settings)
    def host(provider, confirmation):
        return replace(host_base(provider, confirmation),
            secret_onboarding_projection_source=source_components.secret_onboarding_projection_source)
    disabled = http_server.HttpServerSettings.from_environment(environment)
    with pytest.raises(http_server.HttpConfigurationError, match='feature is disabled'):
        http_server.create_http_app(disabled, v4_plan_host_factory=host,
            v4_onboarding_execution_factory=lifecycle.bind_http_actions)
    servers = []
    original = server.FortiPamMcpServer
    def capture(**kwargs):
        created = original(**kwargs)
        servers.append(created)
        return created
    monkeypatch.setattr(http_server, 'FortiPamMcpServer', capture)
    enabled = http_server.HttpServerSettings.from_environment({**environment, V4_ONBOARDING_EXECUTION_FEATURE_ENV: 'true'})
    http_server.create_http_app(enabled, v4_plan_host_factory=host,
        v4_onboarding_execution_factory=lifecycle.bind_http_actions)
    async def names():
        async with Client(servers[0].mcp) as client:
            return {tool.name for tool in (await client.list_tools()).tools}
    tools = asyncio.run(names())
    assert V4_SECRET_ONBOARDING_EXECUTION_TOOL in tools and V4_ACCESS_DOMAIN_EXECUTION_TOOL not in tools
    assert not result[5].posts and not result[6].calls and not result[-1]
    lifecycle.close()


def instruction_fixture(tmp_path, monkeypatch):
    result = fixture(tmp_path, monkeypatch)
    construct, bind, _, _, _, _, _, clients, _, _ = result
    reference = 'mcp-v4-ip-transition-r1'
    def clone(reference):
        responses = []
        for index, response in enumerate(clients[1].responses):
            raw = response.content
            if index in (0, 3, 6):
                document = json.loads(raw)
                document['results'][0]['instruction-profile'] = reference
                raw = _raw(document)
            responses.append(Response(raw))
        return Client(responses)
    clients[1:1] = [clone(reference), clone('')]
    lifecycle = construct()
    runner, principal = bind(lifecycle)
    runner.execute_bound()
    return lifecycle, runner, principal, reference, result


def test_applied_and_restored_reads_keep_original_baseline_before_fixed_recovery(tmp_path, monkeypatch):
    lifecycle, runner, principal, reference, result = instruction_fixture(tmp_path, monkeypatch)
    _, _, _, directory, store, create, _, clients, connections, events = result
    baseline = runner._guard_source._witness
    seals = [(directory / name).read_bytes() for name in ('creation.record', 'creation.ack')]
    source = runner._guard_source._source
    wrong = V4PlanningPrincipal(principal.requester, 'b' * 64)
    with pytest.raises(l.WebSecretFixtureLifecycleError): lifecycle.bind_instruction_profile(reference, wrong)
    lifecycle.bind_instruction_profile(reference, principal)
    with pytest.raises(l.WebSecretFixtureLifecycleError): lifecycle.bind_instruction_profile(reference, principal)
    with pytest.raises(l.WebSecretFixtureLifecycleError): lifecycle.check_instruction_applied_once(wrong)
    assert events == ['full-read']
    lifecycle.check_instruction_applied_once(principal)
    with pytest.raises(l.WebSecretFixtureLifecycleError): lifecycle.recover_once(principal)
    with pytest.raises(l.WebSecretFixtureLifecycleError): lifecycle.check_instruction_applied_once(principal)
    assert len(events) == 2 and not any(connection.calls for connection in connections)
    lifecycle.check_instruction_restored_once(principal)
    assert store.claim_count == 1 and runner._guard_source._witness is baseline
    assert runner._guard_source._source == source
    assert lifecycle.recover_once(principal)['outcome'] == 'succeeded'
    assert events == ['full-read', 'full-read', 'full-read', 'full-read', 'tls', 'full-read', 'DELETE', 'tls', 'GET']
    assert store.claim_count == 2 and create.posts == 1
    assert [(directory / name).read_bytes() for name in ('creation.record', 'creation.ack')] == seals
    assert all(len(client.calls) == 7 and client.is_closed for client in clients)
    assert (directory / 'api-preservation.applied.attempt').exists()
    assert (directory / 'api-preservation.restored.attempt').exists()
    lifecycle.close()


@pytest.mark.parametrize('fault', ['applied-password', 'restored-password', 'applied-permission',
    'restored-unknown-config', 'restored-reference'])
def test_instruction_phase_drift_never_allows_delete_or_phase_replay(tmp_path, monkeypatch, fault):
    lifecycle, runner, principal, reference, result = instruction_fixture(tmp_path, monkeypatch)
    _, _, _, directory, store, create, _, clients, connections, events = result
    lifecycle.bind_instruction_profile(reference, principal)
    restored = fault.startswith('restored')
    if restored: lifecycle.check_instruction_applied_once(principal)
    client = clients[2 if restored else 1]
    if fault.endswith('password'):
        for index in (1, 5):
            client.responses[index].content = client.responses[index].content.replace(b'synthetic-password', b'changed-password')
    else:
        for index in (0, 3, 6):
            row = json.loads(client.responses[index].content)
            if fault.endswith('reference'): row['results'][0]['instruction-profile'] = reference
            elif fault.endswith('permission'): row['results'][0]['future-permission'] = 'changed'
            else: row['results'][0]['instruction-profile-extra'] = 'must-remain-in-full-digest'
            client.responses[index].content = _raw(row)
    check = lifecycle.check_instruction_restored_once if restored else lifecycle.check_instruction_applied_once
    with pytest.raises(l.WebSecretFixtureLifecycleError): check(principal)
    calls = len(client.calls)
    with pytest.raises(l.WebSecretFixtureLifecycleError): check(principal)
    with pytest.raises(l.WebSecretFixtureLifecycleError): lifecycle.recover_once(principal)
    assert len(client.calls) == calls and client.is_closed
    assert create.posts == 1 and store.claim_count == 1 and not any(connection.calls for connection in connections)
    assert runner._capture._record.read_acknowledged_creation().creation.native_secret_id == 37
    assert (directory / 'creation.ack').exists()


@pytest.mark.parametrize('fault', ['reader-reference', 'reader-envelope', 'missing-applied-marker', 'missing-ack'])
def test_instruction_phase_custody_loss_denies_next_source_before_io(tmp_path, monkeypatch, fault):
    lifecycle, runner, principal, reference, result = instruction_fixture(tmp_path, monkeypatch)
    lifecycle.bind_instruction_profile(reference, principal)
    guard = runner._guard_source
    if fault in {'missing-applied-marker', 'missing-ack'}:
        lifecycle.check_instruction_applied_once(principal)
        directory = result[3]
        (directory / ('creation.ack' if fault == 'missing-ack' else 'api-preservation.applied.attempt')).unlink()
        check, client = lifecycle.check_instruction_restored_once, result[7][2]
    else:
        if fault == 'reader-reference': guard._applied._reference = 'mcp-v4-ip-foreign'
        else: guard._applied._credential_envelope['msg'] = 'Changed synthetic source'
        check, client = lifecycle.check_instruction_applied_once, result[7][1]
    with pytest.raises(l.WebSecretFixtureLifecycleError): check(principal)
    assert not client.calls and not any(connection.calls for connection in result[8])


def test_invalid_instruction_request_does_not_consume_legitimate_fixture_recovery(tmp_path, monkeypatch):
    result = fixture(tmp_path, monkeypatch)
    construct, bind = result[:2]
    lifecycle = construct()
    runner, principal = bind(lifecycle)
    runner.execute_bound()
    with pytest.raises(l.WebSecretFixtureLifecycleError): lifecycle.check_instruction_applied_once(principal)
    with pytest.raises(l.WebSecretFixtureLifecycleError): lifecycle.bind_instruction_profile('', principal)
    assert result[-1] == ['full-read']
    assert lifecycle.recover_once(principal)['outcome'] == 'succeeded'
    assert result[4].claim_count == 2
