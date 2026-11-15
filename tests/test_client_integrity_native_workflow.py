"""Exercise exact native workflow intent through real local MCP messages."""
import asyncio
import json
from types import SimpleNamespace

import anyio
from mcp import ClientSession
from mcp.server.auth.provider import AccessToken
from mcp.shared.memory import create_client_server_memory_streams
import pytest

from fortipam_mcp.client_integrity_http_transport import CONTRACT as BINDING_CONTRACT, HASH_CONTRACT
from fortipam_mcp.client_integrity_native_workflow import NativeClientIntegrityWorkflow, NativeClientIntegrityWorkflowError
from fortipam_mcp.client_integrity_native_mcp_action import (
    PREFIX, HASH_PREFIX, NativeClientIntegrityActions, NativeClientIntegrityMcpAction,
    build_native_client_integrity_candidate, register_native_client_integrity_tools,
)
from fortipam_mcp.folder_mcp_action import folder_action_principal_from_access_token
from fortipam_mcp.server import MCP_SERVER_CLASS
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, planning_principal_from_access_token
from test_client_integrity_http_transport import Appliance, adapter, NAME, FOREIGN, hash_appliance

REQUESTER = 'a' * 64


def authorize(flow, requester=REQUESTER):
    preview = flow.preview(requester_digest=requester)
    return flow.confirm(preview['preview_ref'], requester_digest=requester)['authorization_ref']


def test_requester_drift_and_recovery_ownership_are_rechecked(tmp_path):
    device = Appliance(); binding = device.binding()
    transport = adapter(tmp_path, device, binding=binding)
    flow = NativeClientIntegrityWorkflow(transport, clock=lambda: 100)
    preview = flow.preview(requester_digest=REQUESTER)
    assert NAME not in json.dumps(preview)
    before = len(device.calls)
    with pytest.raises(NativeClientIntegrityWorkflowError):
        flow.confirm(preview['preview_ref'], requester_digest='b' * 64)
    assert len(device.calls) == before
    auth = flow.confirm(preview['preview_ref'], requester_digest=REQUESTER)['authorization_ref']
    with pytest.raises(NativeClientIntegrityWorkflowError):
        flow.confirm(preview['preview_ref'], requester_digest=REQUESTER)
    device.rows[FOREIGN]['new-field'] = 'drift'
    with pytest.raises(NativeClientIntegrityWorkflowError):
        flow.execute(auth, requester_digest=REQUESTER)
    assert not (tmp_path / 'create.intent.json').exists()
    del device.rows[FOREIGN]['new-field']
    assert flow.execute(auth, requester_digest=REQUESTER)['verification'] == 'verified'
    before = len(device.calls)
    with pytest.raises(NativeClientIntegrityWorkflowError):
        NativeClientIntegrityWorkflow(adapter(tmp_path, device, binding=binding)).preview(requester_digest=REQUESTER)
    assert len(device.calls) == before
    recovery = NativeClientIntegrityWorkflow(transport, recovery=True, clock=lambda: 100)
    auth = authorize(recovery)
    device.references = [{'name': 'synthetic-new-reference'}]
    with pytest.raises(NativeClientIntegrityWorkflowError):
        recovery.execute(auth, requester_digest=REQUESTER)
    assert not (tmp_path / 'recover.intent.json').exists()


@pytest.mark.parametrize('phase', ['confirm', 'execute'])
def test_expiry_during_read_cannot_issue_or_reserve_execution(tmp_path, monkeypatch, phase):
    device = Appliance(); clock = [100]
    transport = adapter(tmp_path, device, clock=lambda: clock[0])
    flow = NativeClientIntegrityWorkflow(transport, clock=lambda: clock[0])
    preview = flow.preview(requester_digest=REQUESTER)
    ref = preview['preview_ref'] if phase == 'confirm' else flow.confirm(preview['preview_ref'], requester_digest=REQUESTER)['authorization_ref']
    inspect = transport.inspect
    def slow_inspect(**kwargs):
        result = inspect(**kwargs); clock[0] = 700
        return result
    monkeypatch.setattr(transport, 'inspect', slow_inspect)
    with pytest.raises(NativeClientIntegrityWorkflowError):
        getattr(flow, phase)(ref, requester_digest=REQUESTER)
    assert not (tmp_path / 'create.intent.json').exists()
    assert all(request.method == 'GET' for request in device.calls)


def test_uncertain_result_consumes_intent_and_cannot_create_cleanup_authority(tmp_path):
    device = Appliance(); binding = device.binding()
    transport = adapter(tmp_path, device, binding=binding)
    flow = NativeClientIntegrityWorkflow(transport, clock=lambda: 100)
    auth = authorize(flow); device.lose_post = True
    assert flow.execute(auth, requester_digest=REQUESTER)['outcome'] == 'reconciliation_required'
    intent = json.loads((tmp_path / 'create.intent.json').read_bytes())
    assert intent['requester_digest'] == REQUESTER and intent['expires_at'] == 700
    assert (tmp_path / 'create.claim.json').exists() and not (tmp_path / 'create.verified.json').exists()
    before = len(device.calls)
    for recovery in (False, True):
        with pytest.raises(NativeClientIntegrityWorkflowError):
            NativeClientIntegrityWorkflow(adapter(tmp_path, device, binding=binding), recovery=recovery).preview(requester_digest=REQUESTER)
    with pytest.raises(NativeClientIntegrityWorkflowError):
        flow.execute(auth, requester_digest=REQUESTER)
    assert len(device.calls) == before


def test_closed_action_does_not_reserve_an_intent_and_builder_requires_private_binding(tmp_path):
    device = Appliance(); transport = adapter(tmp_path, device)
    flow = NativeClientIntegrityWorkflow(transport, clock=lambda: 100)
    action = NativeClientIntegrityMcpAction(flow)
    with pytest.raises(RuntimeError):
        action.execute('opaque', None)
    with pytest.raises(RuntimeError):
        action.preview(object())
    assert device.calls == []
    assert build_native_client_integrity_candidate({}) is None
    for key in ('ENABLED', 'EXECUTION_ENABLED', 'RECOVERY_EXECUTION_ENABLED'):
        with pytest.raises(ValueError):
            build_native_client_integrity_candidate({PREFIX + key: 'true'})
    binding = device.binding()
    path = tmp_path / 'binding.private.json'
    path.write_text(json.dumps({'contract': BINDING_CONTRACT, **{k: getattr(binding, k) for k in binding.__slots__}}))
    path.chmod(0o600)
    from fortipam_mcp.secret_metadata_http_transport import ENV_PREFIX
    env = {PREFIX + 'ENABLED': 'true', PREFIX + 'BINDING_FILE': str(path),
           PREFIX + 'STATE_DIRECTORY': str(tmp_path), PREFIX + 'AUTHORIZATION_KEY_FILE': str(tmp_path / 'authorization.key'),
           ENV_PREFIX + 'ENABLED': 'true', ENV_PREFIX + 'BASE_URL': 'https://pam.example.test',
           ENV_PREFIX + 'API_TOKEN': 'synthetic-only-token'}
    assert build_native_client_integrity_candidate(env) is not None
    env[PREFIX + 'BINDING_FILE'] = 'relative-private-path.json'
    with pytest.raises(ValueError):
        build_native_client_integrity_candidate(env)
    assert device.calls == []


def test_hash_builder_requires_explicit_exclusive_profile_and_refuses_binding_swaps(tmp_path):
    from fortipam_mcp.secret_metadata_http_transport import ENV_PREFIX
    device = hash_appliance(); binding = device.binding()
    (tmp_path / 'authorization.key').write_bytes(b'k' * 32)
    (tmp_path / 'authorization.key').chmod(0o600)
    tmp_path.chmod(0o700)
    path = tmp_path / 'hash-binding.private.json'
    path.write_text(json.dumps({'contract': HASH_CONTRACT, **{k: getattr(binding, k) for k in binding.__slots__}}))
    path.chmod(0o600)
    env = {HASH_PREFIX + 'ENABLED': 'true', HASH_PREFIX + 'BINDING_FILE': str(path),
           HASH_PREFIX + 'STATE_DIRECTORY': str(tmp_path), HASH_PREFIX + 'AUTHORIZATION_KEY_FILE': str(tmp_path / 'authorization.key'),
           ENV_PREFIX + 'ENABLED': 'true', ENV_PREFIX + 'BASE_URL': 'https://pam.example.test',
           ENV_PREFIX + 'API_TOKEN': 'synthetic-only-token'}
    assert build_native_client_integrity_candidate(env) is not None
    for extra in ({PREFIX + 'ENABLED': 'true'}, {PREFIX + 'EXECUTION_ENABLED': 'true'},
                  {HASH_PREFIX + 'RECOVERY_EXECUTION_ENABLED': '1'},
                  {HASH_PREFIX + 'BINDING_FILE': 'relative-private-path.json'}):
        with pytest.raises(ValueError):
            build_native_client_integrity_candidate({**env, **extra})
    cert_env = {k.replace(HASH_PREFIX, PREFIX): v for k, v in env.items()}
    with pytest.raises(ValueError):
        build_native_client_integrity_candidate(cert_env)
    certificate = Appliance().binding()
    path.write_text(json.dumps({'contract': BINDING_CONTRACT,
                               **{k: getattr(certificate, k) for k in certificate.__slots__}}))
    with pytest.raises(ValueError):
        build_native_client_integrity_candidate(env)
    assert device.calls == []


def test_boolean_lookalikes_in_readback_cannot_report_success(tmp_path, monkeypatch):
    transport = adapter(tmp_path, Appliance())
    flow = NativeClientIntegrityWorkflow(transport, clock=lambda: 100)
    auth = authorize(flow)
    monkeypatch.setattr(transport, 'execute', lambda **kwargs: {'verified': 1, 'software_present': True,
        'visible_collection_preserved': True, 'upload_or_download_dispatched': False})
    assert flow.execute(auth, requester_digest=REQUESTER)['verification'] == 'unknown'
    assert (tmp_path / 'create.intent.json').exists()


@pytest.mark.parametrize('enabled', [False, True])
@pytest.mark.parametrize('hash_profile', [False, True])
def test_local_mcp_protocol_scopes_closed_gate_and_owned_recovery(tmp_path, enabled, hash_profile):
    device = hash_appliance() if hash_profile else Appliance(); transport = adapter(tmp_path, device)
    actions = NativeClientIntegrityActions(
        NativeClientIntegrityMcpAction(NativeClientIntegrityWorkflow(transport, clock=lambda: 100), execution_enabled=enabled),
        NativeClientIntegrityMcpAction(NativeClientIntegrityWorkflow(transport, recovery=True, clock=lambda: 100), execution_enabled=enabled),
    )
    authority = V4PlanningAuthorizationSettings('https://mcp.example.test/fpamcp-v4', b'p' * 32)
    token = AccessToken(token='synthetic-validated-token', client_id='client-0001', subject='operator-0001',
        scopes=['fortipam:read', 'fortipam:plan'], expires_at=2_000_000_000,
        resource=authority.expected_resource, claims={'iss': 'https://mcp.example.test/oauth'})
    server = SimpleNamespace(mcp=MCP_SERVER_CLASS('native-client-integrity'),
        _v4_planning_principal=lambda: planning_principal_from_access_token(token, authority),
        _v4_password_policy_action_principal=lambda: folder_action_principal_from_access_token(token, authority))
    register_native_client_integrity_tools(server, actions)

    async def run():
        async with create_client_server_memory_streams() as (client_streams, server_streams):
            async with anyio.create_task_group() as group:
                low = server.mcp._lowlevel_server
                group.start_soon(low.run, *server_streams, low.create_initialization_options())
                async with ClientSession(*client_streams) as session:
                    await session.initialize()
                    tools = (await session.list_tools()).tools
                    assert len(tools) == 6
                    for tool in tools:
                        expected = set() if tool.name.startswith('preview') else {'preview_ref'} if tool.name.startswith('confirm') else {'authorization_ref'}
                        assert set(tool.input_schema.get('properties', {})) == expected
                    name = 'v4_client_integrity_native_700'
                    preview = await session.call_tool('preview_' + name, {})
                    assert not preview.is_error
                    content = preview.structured_content
                    if hash_profile:
                        assert content['contract'] == 'fortipam_v4_client_integrity_native_hash_700_workflow_v1'
                        assert content['Proposed Changes']['configuration_profile'] == 'native-x64-external-executable-sha256-700-v1'
                        assert content['Expected State']['hash_enforcement_verified'] is False
                    else:
                        assert content['contract'] == 'fortipam_v4_client_integrity_native_700_workflow_v3'
                        assert content['Proposed Changes']['configuration_profile'] == 'native-x64-external-local-ca-700-v3'
                        assert 'hash_enforcement_verified' not in content['Expected State']
                    ref = preview.structured_content['preview_ref']
                    before = len(device.calls)
                    denied = await session.call_tool('confirm_' + name, {'preview_ref': ref})
                    assert denied.is_error and len(device.calls) == before
                    token.scopes.append('fortipam:operate')
                    auth = await session.call_tool('confirm_' + name, {'preview_ref': ref})
                    assert not auth.is_error
                    result = await session.call_tool('execute_confirmed_' + name,
                        {'authorization_ref': auth.structured_content['authorization_ref']})
                    if enabled:
                        assert not result.is_error and result.structured_content['verification'] == 'verified'
                        recovery_name = 'v4_client_integrity_native_recovery_700'
                        recovery = await session.call_tool('preview_' + recovery_name, {})
                        auth = await session.call_tool('confirm_' + recovery_name,
                            {'preview_ref': recovery.structured_content['preview_ref']})
                        result = await session.call_tool('execute_confirmed_' + recovery_name,
                            {'authorization_ref': auth.structured_content['authorization_ref']})
                        assert not result.is_error and result.structured_content['verification'] == 'verified'
                    else:
                        assert result.is_error and not (tmp_path / 'create.intent.json').exists()
                group.cancel_scope.cancel()
    asyncio.run(run())
    assert [r.method for r in device.calls if r.method != 'GET'] == (['POST', 'DELETE'] if enabled else [])
    assert device.name not in device.rows


@pytest.mark.parametrize('operate', [False, True])
@pytest.mark.parametrize('hash_profile', [False, True])
def test_http_oauth_pkce_registration_and_operation_policy(tmp_path, operate, hash_profile):
    from starlette.testclient import TestClient
    from fortipam_mcp.http_server import HttpServerSettings, create_http_app
    from test_http_server import RUNTIME_PROFILE_ENV, _v4_environment, _register_public_client, _authorize_and_login, _request_headers
    environment = _v4_environment(tmp_path)
    environment[RUNTIME_PROFILE_ENV] = 'v4-controlled'
    state = tmp_path / 'native'; state.mkdir(mode=0o700)
    device = hash_appliance() if hash_profile else Appliance(); transport = adapter(state, device, create=False, recover=False)
    actions = NativeClientIntegrityActions(
        NativeClientIntegrityMcpAction(NativeClientIntegrityWorkflow(transport, clock=lambda: 100)),
        NativeClientIntegrityMcpAction(NativeClientIntegrityWorkflow(transport, recovery=True, clock=lambda: 100)),
    )
    app = create_http_app(HttpServerSettings.from_environment(environment), v4_client_integrity_native_actions=actions)
    scope = 'fortipam:read fortipam:plan' + (' fortipam:operate' if operate else '')
    with TestClient(app, base_url='https://mcp.example.com') as client:
        client_id = _register_public_client(client, scope)
        code, verifier = _authorize_and_login(client, client_id, scope)
        response = client.post('/fpamcp/oauth/token', data={
            'grant_type': 'authorization_code', 'client_id': client_id, 'code': code, 'code_verifier': verifier,
            'redirect_uri': 'https://client.example/callback', 'resource': 'https://mcp.example.com/fpamcp'})
        assert response.status_code == 200
        token = response.json()['access_token']; headers = _request_headers(token); headers['host'] = 'mcp.example.com'
        def rpc(method, params):
            result = client.post('/fpamcp', headers=headers,
                json={'jsonrpc':'2.0', 'id':1, 'method':method, 'params':params})
            assert result.status_code == 200
            return result.json()['result']
        tools = rpc('tools/list', {})['tools']
        assert len([t for t in tools if 'client_integrity_native' in t['name']]) == 6
        preview = rpc('tools/call', {'name':'preview_v4_client_integrity_native_700', 'arguments':{}})
        assert not preview['isError']
        auth = rpc('tools/call', {'name':'confirm_v4_client_integrity_native_700',
            'arguments':{'preview_ref':preview['structuredContent']['preview_ref']}})
        if operate:
            assert not auth['isError']
            result = rpc('tools/call', {'name':'execute_confirmed_v4_client_integrity_native_700',
                'arguments':{'authorization_ref':auth['structuredContent']['authorization_ref']}})
            assert result['isError']
        else:
            assert auth['isError']
        client.post('/fpamcp/oauth/revoke', data={'token': token, 'client_id': client_id})
    assert all(request.method == 'GET' for request in device.calls)
    assert not (state / 'create.intent.json').exists()
