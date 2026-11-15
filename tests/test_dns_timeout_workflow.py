"""Combined DNS-specific preservation, durable M4, startup and MCP checks."""
import asyncio
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import time

import httpx
import pytest
from starlette.testclient import TestClient

from fortipam_mcp.dns_timeout_contract import DnsTimeoutBinding, _digest, prepare_dns_timeout, qualify_schema
from fortipam_mcp.dns_timeout_live_workflow import DnsTimeoutLiveWorkflow
from fortipam_mcp.dns_timeout_mcp_action import DnsTimeoutMcpAction
from fortipam_mcp.dns_timeout_runtime import PREFIX, CONTRACT as STARTUP, build_dns_timeout_candidate
from fortipam_mcp.http_server import create_http_app, HttpConfigurationError
from fortipam_mcp.local_oauth import LocalOAuthProvider
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp.secret_metadata_http_transport import ENV_PREFIX, SecretMetadataHttpTransportConfig
from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
from test_ldap_server_mcp_action import _settings, _login, _call

SERIAL = hashlib.sha256(b'synthetic-appliance').hexdigest()
IDENTITY = dict(requester_digest='1' * 64, transport_digest='2' * 64)


def envelope(results, action=None, method='GET'):
    value = dict(version='v7.0.0', build=29, path='system', name='dns', http_method=method,
                 http_status=200, status='success', serial='synthetic-appliance', results=deepcopy(results))
    if action is not None: value['action'] = action
    return value


class Peer:
    def __init__(self, fault='none'):
        fields = {f'preserved-{i}': {'type': 'string'} for i in range(19)}
        fields['timeout'] = dict(type='integer', default=5, **{'min-value': 1, 'max-value': 10})
        self.schema = envelope(dict(name='dns', path='system', category='complex', children=fields), 'schema')
        self.state = envelope({**{f'preserved-{i}': 'synthetic' for i in range(19)}, 'timeout': 5})
        self.binding = DnsTimeoutBinding('a' * 32, _digest(self.state['results']))
        self.writes = []
        self.fault = fault

    def client(self):
        return httpx.Client(base_url='https://synthetic.example', transport=httpx.MockTransport(self.handle))

    def handle(self, request):
        assert request.url.path == '/api/v2/cmdb/system/dns'
        if request.method == 'GET':
            value = self.schema if request.url.params.get('action') == 'schema' else self.state
            if self.writes and self.fault == 'partial':
                value = deepcopy(value); value['results'].pop('preserved-0', None)
            return httpx.Response(200, json=value)
        assert request.method == 'PUT'
        self.writes.append(request.method)
        self.state = envelope(json.loads(request.content))
        if self.fault == 'lost-ack': raise httpx.ReadError('synthetic')
        if self.fault == 'unrelated-change': self.state['results']['preserved-1'] = 'drift'
        ack = envelope({}, method='PUT')
        if self.fault == 'wrong-ack': ack['build'] = 30
        return httpx.Response(200, json=ack)


def make(tmp_path, peer, **changes):
    tmp_path.mkdir(mode=0o700, exist_ok=True); tmp_path.chmod(0o700)
    key = tmp_path / 'key'
    if not key.exists(): key.write_bytes(b'k' * 32); key.chmod(0o600)
    store = PersistentM4ExecutionStateStore(tmp_path / 'm4.sqlite', key)
    options = dict(authority_key=b'a' * 32, serial_digest=SERIAL,
        schema_digest=qualify_schema(peer.schema, serial_digest=SERIAL), environment_ref='synthetic-environment',
        scope_ref='synthetic-scope', audience_ref='synthetic-audience',
        allowed_requester_digest=IDENTITY['requester_digest'], allowed_transport_digest=IDENTITY['transport_digest'],
        update_enabled=True, recovery_enabled=True, clock=lambda: 1000, client_factory=peer.client)
    options.update(changes)
    return DnsTimeoutLiveWorkflow(SecretMetadataHttpTransportConfig('https://synthetic.example', 'synthetic', 5, None),
                                 peer.binding, store, **options)


def run(workflow, phase):
    preview = workflow.preview(phase, **IDENTITY)
    auth = workflow.authorize(phase, preview['preview_ref'], **IDENTITY)
    return workflow.execute(phase, auth['authorization_ref'], **IDENTITY), auth


def test_full_roundtrip_preserves_all_other_fields_and_original_consumption(tmp_path):
    peer = Peer(); before = deepcopy(peer.state); workflow = make(tmp_path, peer)
    result, auth = run(workflow, 'update')
    assert result['outcome'] == 'succeeded' and peer.state['results']['timeout'] == 6
    assert workflow.execute('update', auth['authorization_ref'], **IDENTITY)['idempotent_replay']
    replacement = make(tmp_path, peer)
    for phase in ('update', 'recover'):
        with pytest.raises(ValueError): replacement.preview(phase, **IDENTITY)
    assert run(workflow, 'recover')[0]['outcome'] == 'succeeded'
    assert peer.state == before and peer.writes == ['PUT', 'PUT'] and workflow._store.claim_count == 2
    workflow.close()
    with pytest.raises(ValueError): workflow.execute('update', auth['authorization_ref'], **IDENTITY)


@pytest.mark.parametrize('fault', ['lost-ack', 'wrong-ack', 'partial', 'unrelated-change'])
def test_unknown_or_mismatched_readback_never_authorizes_recovery_or_new_update(tmp_path, fault):
    peer = Peer(fault); workflow = make(tmp_path, peer)
    result, auth = run(workflow, 'update')
    assert result['outcome'] != 'succeeded'
    assert workflow.execute('update', auth['authorization_ref'], **IDENTITY)['idempotent_replay']
    for phase in ('update', 'recover'):
        with pytest.raises(ValueError): workflow.preview(phase, **IDENTITY)
    assert peer.writes == ['PUT'] and workflow._store.claim_count == 1


def test_drifted_baseline_and_incomplete_or_protected_schema_fail_before_dispatch(tmp_path):
    peer = Peer(); workflow = make(tmp_path, peer)
    preview = workflow.preview('update', **IDENTITY)
    peer.state['results']['preserved-1'] = 'drift'
    with pytest.raises(ValueError): workflow.authorize('update', preview['preview_ref'], **IDENTITY)
    assert peer.writes == [] and workflow._store.claim_count == 0
    for kind in ('missing', 'protected', 'wrong-version'):
        other = Peer()
        if kind == 'missing': other.schema['results']['children'].pop('preserved-0')
        if kind == 'protected': other.schema['results']['children']['preserved-0']['type'] = 'password'
        if kind == 'wrong-version': other.schema['build'] = 30
        with pytest.raises(ValueError): prepare_dns_timeout(other.schema, other.state, serial_digest=SERIAL, binding=other.binding)


def test_mcp_one_session_update_and_recover_preserves_complete_configuration(tmp_path):
    peer = Peer(); before = deepcopy(peer.state); workflow = make(tmp_path / 'dns', peer, clock=lambda: int(time.time()))
    settings = replace(_settings(tmp_path), runtime_profile=RuntimeProfile.V4_CONTROLLED)
    with TestClient(create_http_app(settings, v4_dns_timeout_candidate_action=DnsTimeoutMcpAction(workflow)), base_url='https://mcp.example.com') as client:
        headers = _login(client, 'fortipam:read fortipam:plan fortipam:operate')
        token = asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(headers['authorization'].split(' ', 1)[1]))
        principal = planning_principal_from_access_token(token, settings.v4_planning_authorization)
        workflow._namespace.update(requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest)
        for phase in ('update', 'recover'):
            name = f'preview_v4_dns_timeout_{phase}_700'
            denied = _call(client, headers, name, {'body': 'private-marker'})
            assert denied['isError'] and 'private-marker' not in json.dumps(denied)
            preview = _call(client, headers, name, {})['structuredContent']
            auth = _call(client, headers, f'authorize_v4_dns_timeout_{phase}_700', {'preview_ref': preview['preview_ref']})['structuredContent']
            result = _call(client, headers, f'execute_v4_dns_timeout_{phase}_700', {'authorization_ref': auth['authorization_ref']})['structuredContent']
            assert result['outcome'] == 'succeeded' and 'synthetic-appliance' not in json.dumps((preview, auth, result))
    assert peer.state == before and peer.writes == ['PUT', 'PUT']


def test_startup_default_closed_and_missing_consumed_database_cannot_be_recreated(tmp_path):
    assert build_dns_timeout_candidate({}) is None
    with pytest.raises(ValueError): build_dns_timeout_candidate({PREFIX + 'UPDATE_ENABLED': 'true'})
    tmp_path.chmod(0o700); peer = Peer()
    for name, content in [('execution', b'k' * 32), ('authority', b'a' * 32)]:
        path = tmp_path / name; path.write_bytes(content); path.chmod(0o600)
    manifest = dict(contract=STARTUP, binding=dict(nonce=peer.binding.nonce, baseline_digest=peer.binding.baseline_digest),
        identity=dict(serial_digest=SERIAL, schema_digest=qualify_schema(peer.schema, serial_digest=SERIAL),
            environment_ref='synthetic-environment', scope_ref='synthetic-scope', audience_ref='synthetic-audience',
            allowed_requester_digest=IDENTITY['requester_digest'], allowed_transport_digest=IDENTITY['transport_digest']),
        paths=dict(execution_database_file=str(tmp_path / 'm4.sqlite'), execution_hmac_key_file=str(tmp_path / 'execution'),
                   authority_hmac_key_file=str(tmp_path / 'authority')))
    path = tmp_path / 'startup.json'; path.write_text(json.dumps(manifest)); path.chmod(0o600)
    env = {PREFIX + 'ENABLED': 'true', PREFIX + 'UPDATE_ENABLED': 'true', PREFIX + 'RECOVERY_ENABLED': 'true',
        PREFIX + 'STARTUP_MANIFEST_FILE': str(path), ENV_PREFIX + 'ENABLED': 'true',
        ENV_PREFIX + 'BASE_URL': 'https://synthetic.example', ENV_PREFIX + 'API_TOKEN': 'synthetic-token'}
    action = build_dns_timeout_candidate(env); assert action is not None
    workflow = action._workflow; workflow._clock = lambda: 1000; workflow._http._factory = peer.client
    for phase in ('update', 'recover'): assert run(workflow, phase)[0]['outcome'] == 'succeeded'
    assert build_dns_timeout_candidate(env) is not None
    database = tmp_path / 'm4.sqlite'; database.unlink()
    with pytest.raises(ValueError): build_dns_timeout_candidate(env)
    assert not database.exists()
    with pytest.raises(HttpConfigurationError):
        create_http_app(replace(_settings(tmp_path), runtime_profile=RuntimeProfile.READONLY), v4_dns_timeout_candidate_action=action)
