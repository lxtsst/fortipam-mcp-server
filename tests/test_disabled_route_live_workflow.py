"""Combined actual M4 policy, fixed HTTP peer and OAuth/MCP lifecycle checks."""
import asyncio
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import time

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.disabled_route_contract import DisabledRouteBinding, qualify_schema
from fortipam_mcp.disabled_route_live_workflow import DisabledRouteLiveWorkflow
from fortipam_mcp.disabled_route_mcp_action import DisabledRouteMcpAction
from fortipam_mcp.disabled_route_runtime import PREFIX, CONTRACT as STARTUP_CONTRACT, build_disabled_route_candidate
from fortipam_mcp.http_server import HttpConfigurationError, create_http_app
from fortipam_mcp.local_oauth import LocalOAuthProvider
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp.secret_metadata_http_transport import ENV_PREFIX, SecretMetadataHttpTransportConfig
from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
from test_disabled_route_contract import SERIAL, envelope, metadata
from test_disabled_route_m4_adapter import Peer
from test_ldap_server_mcp_action import _call, _login, _settings

IDENTITY = dict(requester_digest='1' * 64, transport_digest='2' * 64)


def make(tmp_path, peer, **changes):
    tmp_path.mkdir(mode=0o700, exist_ok=True)
    tmp_path.chmod(0o700)
    key = tmp_path / 'key'
    if not key.exists():
        key.write_bytes(b'k' * 32); key.chmod(0o600)
    store = PersistentM4ExecutionStateStore(tmp_path / 'm4.sqlite', key)
    options = dict(authority_key=b'a' * 32, serial_digest=SERIAL,
        schema_digest=qualify_schema(peer.schema, serial_digest=SERIAL), environment_ref='synthetic-environment',
        scope_ref='synthetic-scope', audience_ref='synthetic-audience',
        allowed_requester_digest=IDENTITY['requester_digest'], allowed_transport_digest=IDENTITY['transport_digest'],
        create_enabled=True, recovery_enabled=True, clock=lambda: 1000, client_factory=peer.client)
    options.update(changes)
    return DisabledRouteLiveWorkflow(SecretMetadataHttpTransportConfig('https://synthetic.example', 'synthetic', 5, None),
                                    peer.binding, store, **options)


def run(workflow, phase):
    preview = workflow.preview(phase, **IDENTITY)
    auth = workflow.authorize(phase, preview['preview_ref'], **IDENTITY)
    result = workflow.execute(phase, auth['authorization_ref'], **IDENTITY)
    return result, auth


@pytest.mark.parametrize('benchmark_host', [1, 2])
def test_real_policy_roundtrip_and_original_identity_survive_reconstruction(tmp_path, benchmark_host):
    peer = Peer()
    if benchmark_host == 2:
        peer.table = envelope([*peer.table['results'], metadata(peer.binding.body)])
        peer.binding = DisabledRouteBinding(100002, 'b' * 32, benchmark_host=2)
    before = deepcopy(peer.table)
    workflow = make(tmp_path, peer)
    create, auth = run(workflow, 'create')
    assert create['outcome'] == 'succeeded'
    assert workflow.execute('create', auth['authorization_ref'], **IDENTITY)['idempotent_replay']
    replacement = make(tmp_path, peer)
    with pytest.raises(ValueError): replacement.preview('create', **IDENTITY)
    with pytest.raises(ValueError): replacement.preview('recover', **IDENTITY)
    recovered, _ = run(workflow, 'recover')
    assert recovered['outcome'] == 'succeeded' and peer.table == before
    assert peer.writes == ['POST', 'DELETE'] and workflow._store.claim_count == 2
    workflow.close()
    with pytest.raises(ValueError): workflow.execute('create', auth['authorization_ref'], **IDENTITY)


@pytest.mark.parametrize('fault', ['identity', 'gate', 'drift', 'expired', 'rollback', 'lost-ack'])
def test_combined_policy_failure_stops_the_affected_phase_without_new_dispatch(tmp_path, fault):
    peer = Peer('lost-ack' if fault == 'lost-ack' else 'none')
    now = [1000]
    workflow = make(tmp_path, peer, clock=lambda: now[0], create_enabled=fault != 'gate')
    if fault == 'identity':
        with pytest.raises(ValueError): workflow.preview('create', **{**IDENTITY, 'requester_digest': 'f' * 64})
        assert workflow._store.claim_count == 0 and peer.writes == []
        return
    preview = workflow.preview('create', **IDENTITY)
    if fault == 'drift': peer.table['results'][0]['distance'] = 20
    if fault == 'expired': now[0] += 60
    if fault == 'rollback': now[0] -= 1
    if fault != 'lost-ack':
        with pytest.raises(ValueError): workflow.authorize('create', preview['preview_ref'], **IDENTITY)
        assert workflow._store.claim_count == 0 and peer.writes == []
    else:
        auth = workflow.authorize('create', preview['preview_ref'], **IDENTITY)
        result = workflow.execute('create', auth['authorization_ref'], **IDENTITY)
        assert result['verification'] == 'unknown'
        with pytest.raises(ValueError): workflow.preview('recover', **IDENTITY)
        with pytest.raises(ValueError): workflow.preview('create', **IDENTITY)
        assert peer.writes == ['POST'] and workflow._store.claim_count == 1


def test_actual_oauth_mcp_roundtrip_uses_fixed_schemas_and_real_policy(tmp_path):
    peer = Peer(); before = deepcopy(peer.table)
    settings = _settings(tmp_path)
    workflow = make(tmp_path / 'route', peer, clock=lambda: int(time.time()))
    app = create_http_app(settings, v4_disabled_route_candidate_action=DisabledRouteMcpAction(workflow))
    with TestClient(app, base_url='https://mcp.example.com') as client:
        headers = _login(client, 'fortipam:read fortipam:plan fortipam:operate')
        access = asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(headers['authorization'].split(' ')[1]))
        assert access is not None
        principal = planning_principal_from_access_token(access, settings.v4_planning_authorization)
        # Trusted test-owner bootstrap supplies the same actual OAuth identity.
        workflow._namespace.update(requester_digest=principal.requester.digest,
                                   transport_digest=principal.transport_namespace_digest)
        for phase in ('create', 'recover'):
            preview_name = f'preview_v4_disabled_route_{phase}_700'
            rejected = _call(client, headers, preview_name, {'body': 'private-marker'})
            assert rejected['isError'] and 'private-marker' not in json.dumps(rejected)
            preview = _call(client, headers, preview_name, {})['structuredContent']
            authorized = _call(client, headers, f'authorize_v4_disabled_route_{phase}_700',
                {'preview_ref': preview['preview_ref']})['structuredContent']
            result = _call(client, headers, f'execute_v4_disabled_route_{phase}_700',
                {'authorization_ref': authorized['authorization_ref']})['structuredContent']
            assert result['outcome'] == 'succeeded' and result['verification'] == 'verified'
            assert 'synthetic-appliance' not in json.dumps((preview, authorized, result))
    assert peer.writes == ['POST', 'DELETE'] and peer.table == before


def test_default_off_startup_and_invalid_http_profile_do_not_contact_device(tmp_path):
    assert build_disabled_route_candidate({}) is None
    with pytest.raises(ValueError): build_disabled_route_candidate({PREFIX + 'CREATE_ENABLED': 'true'})
    peer = Peer(); workflow = make(tmp_path / 'route', peer)
    settings = replace(_settings(tmp_path), runtime_profile=RuntimeProfile.READONLY)
    with pytest.raises(HttpConfigurationError):
        create_http_app(settings, v4_disabled_route_candidate_action=DisabledRouteMcpAction(workflow))
    assert peer.writes == []


def test_startup_pins_original_namespace_and_preserves_claims(tmp_path):
    tmp_path.chmod(0o700)
    peer = Peer()
    for name, content in (('execution', b'k' * 32), ('authority', b'a' * 32), ('token', b'synthetic-token')):
        path = tmp_path / name; path.write_bytes(content); path.chmod(0o600)
    manifest = dict(contract=STARTUP_CONTRACT, binding=dict(sequence=peer.binding.sequence, nonce=peer.binding.nonce),
        identity=dict(serial_digest=SERIAL, schema_digest=qualify_schema(peer.schema, serial_digest=SERIAL),
            environment_ref='synthetic-environment', scope_ref='synthetic-scope', audience_ref='synthetic-audience',
            allowed_requester_digest=IDENTITY['requester_digest'], allowed_transport_digest=IDENTITY['transport_digest']),
        paths=dict(execution_database_file=str(tmp_path / 'm4.sqlite'), execution_hmac_key_file=str(tmp_path / 'execution'),
                   authority_hmac_key_file=str(tmp_path / 'authority')))
    path = tmp_path / 'startup.json'; path.write_text(json.dumps(manifest)); path.chmod(0o600)
    env = {PREFIX + 'ENABLED': 'true', PREFIX + 'CREATE_ENABLED': 'true', PREFIX + 'RECOVERY_ENABLED': 'true',
        PREFIX + 'STARTUP_MANIFEST_FILE': str(path), ENV_PREFIX + 'ENABLED': 'true',
        ENV_PREFIX + 'BASE_URL': 'https://synthetic.example', ENV_PREFIX + 'API_TOKEN': 'synthetic-token'}
    first = build_disabled_route_candidate(env)
    assert first is not None
    first._workflow._clock = lambda: 1000
    first._workflow._http._factory = peer.client
    assert run(first._workflow, 'create')[0]['outcome'] == 'succeeded'
    assert run(first._workflow, 'recover')[0]['outcome'] == 'succeeded'
    assert first._workflow._store.claim_count == 2
    assert build_disabled_route_candidate(env) is not None
    manifest['identity']['allowed_requester_digest'] = '3' * 64
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError): build_disabled_route_candidate(env)
    manifest['identity']['allowed_requester_digest'] = IDENTITY['requester_digest']
    path.write_text(json.dumps(manifest))
    database = tmp_path / 'm4.sqlite'
    database.unlink()
    with pytest.raises(ValueError): build_disabled_route_candidate(env)
    assert not database.exists()
