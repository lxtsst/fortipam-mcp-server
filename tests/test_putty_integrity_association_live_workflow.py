"""Authenticated opaque-only intent retains the exact one-reference boundary."""
import asyncio
import json
from types import SimpleNamespace

import anyio
from mcp import ClientSession
from mcp.server.auth.provider import AccessToken
from mcp.shared.memory import create_client_server_memory_streams
import pytest

from fortipam_mcp.putty_integrity_association_live_workflow import PuttyIntegrityAssociationWorkflow, PuttyIntegrityAssociationWorkflowError
from fortipam_mcp.putty_integrity_association_mcp_action import (
    PREFIX, PuttyIntegrityAssociationActions, PuttyIntegrityAssociationMcpAction,
    build_putty_integrity_association_candidate, register_putty_integrity_association_tools,
)
from fortipam_mcp.putty_integrity_association_http_transport import CONTRACT as BINDING_CONTRACT
from fortipam_mcp.launcher_clone_http_transport import WINDOWS_CONTRACT
from fortipam_mcp.client_integrity_http_transport import HASH_CONTRACT
from fortipam_mcp.folder_mcp_action import folder_action_principal_from_access_token
from fortipam_mcp.server import MCP_SERVER_CLASS
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, planning_principal_from_access_token
from test_putty_integrity_association_http_transport import prepared

REQUESTER = 'a'*64


def actions_for(transport, enabled=False):
    return PuttyIntegrityAssociationActions(
        PuttyIntegrityAssociationMcpAction(PuttyIntegrityAssociationWorkflow(transport,clock=lambda:100),execution_enabled=enabled),
        PuttyIntegrityAssociationMcpAction(PuttyIntegrityAssociationWorkflow(transport,recovery=True,clock=lambda:100),execution_enabled=enabled),
    )


def test_requester_and_drift_refuse_intent_then_lost_result_cannot_restore(tmp_path):
    device,launcher,software,binding,state,key,adapter = prepared(tmp_path)
    flow = PuttyIntegrityAssociationWorkflow(adapter(association_enabled=True),clock=lambda:100)
    preview = flow.preview(requester_digest=REQUESTER)
    assert 'executable_path' not in json.dumps(preview) and preview['Expected State']['hash_enforcement_verified'] is False
    with pytest.raises(PuttyIntegrityAssociationWorkflowError): flow.confirm(preview['preview_ref'],requester_digest='b'*64)
    auth = flow.confirm(preview['preview_ref'],requester_digest=REQUESTER)['authorization_ref']
    device.launcher.rows[launcher._binding.destination_name]['launch-timeout'] += 1
    with pytest.raises(PuttyIntegrityAssociationWorkflowError): flow.execute(auth,requester_digest=REQUESTER)
    assert not (state/'associate.intent.json').exists()
    device.launcher.rows[launcher._binding.destination_name]['launch-timeout'] -= 1
    device.lose_put = True
    assert flow.execute(auth,requester_digest=REQUESTER)['outcome'] == 'reconciliation_required'
    with pytest.raises(PuttyIntegrityAssociationWorkflowError): flow.execute(auth,requester_digest=REQUESTER)
    with pytest.raises(PuttyIntegrityAssociationWorkflowError):
        PuttyIntegrityAssociationWorkflow(adapter(restore_enabled=True),recovery=True).preview(requester_digest=REQUESTER)
    assert len(device.puts) == 1


def test_default_closed_builder_exact_private_domains_and_orphan_gates(tmp_path):
    device,launcher,software,binding,state,key,adapter = prepared(tmp_path)
    assert build_putty_integrity_association_candidate({}) is None
    for suffix in ('ENABLED','EXECUTION_ENABLED','RESTORE_EXECUTION_ENABLED'):
        with pytest.raises(ValueError): build_putty_integrity_association_candidate({PREFIX+suffix:'true'})
    def save(path,contract,b):
        path.write_text(json.dumps({'contract':contract,**{k:getattr(b,k) for k in b.__slots__}}));path.chmod(0o600);return str(path)
    from fortipam_mcp.secret_metadata_http_transport import ENV_PREFIX
    env = {PREFIX+'ENABLED':'true',PREFIX+'BINDING_FILE':save(state/'binding.private.json',BINDING_CONTRACT,binding),
        PREFIX+'STATE_DIRECTORY':str(state),PREFIX+'AUTHORIZATION_KEY_FILE':str(key),
        PREFIX+'LAUNCHER_BINDING_FILE':save(launcher._state/'binding.private.json',WINDOWS_CONTRACT,launcher._binding),
        PREFIX+'LAUNCHER_STATE_DIRECTORY':str(launcher._state),
        PREFIX+'SOFTWARE_BINDING_FILE':save(software._state/'binding.private.json',HASH_CONTRACT,software._binding),
        PREFIX+'SOFTWARE_STATE_DIRECTORY':str(software._state),
        PREFIX+'SOFTWARE_AUTHORIZATION_KEY_FILE':str(software._state/'authorization.key'),
        ENV_PREFIX+'ENABLED':'true',ENV_PREFIX+'BASE_URL':'https://pam.example.test',ENV_PREFIX+'API_TOKEN':'synthetic-token'}
    actions = build_putty_integrity_association_candidate(env); assert actions is not None
    t = actions.association._workflow._transport
    assert not actions.association._enabled and not actions.restore._enabled
    assert not t._launcher._clone_enabled and not t._software._create and not t._software._recovery
    wrong = dict(env); wrong[PREFIX+'SOFTWARE_BINDING_FILE'] = env[PREFIX+'LAUNCHER_BINDING_FILE']
    with pytest.raises(ValueError): build_putty_integrity_association_candidate(wrong)
    with pytest.raises(RuntimeError): actions.association.preview(object())


@pytest.mark.parametrize('enabled',[False,True])
def test_real_local_mcp_schema_scope_gates_association_and_restore(tmp_path,enabled):
    device,launcher,software,binding,state,key,adapter = prepared(tmp_path)
    actions = actions_for(adapter(association_enabled=enabled,restore_enabled=enabled),enabled)
    authority = V4PlanningAuthorizationSettings('https://mcp.example.test/fpamcp-v4',b'p'*32)
    token = AccessToken(token='synthetic-token',client_id='client-0001',subject='operator-0001',
        scopes=['fortipam:read','fortipam:plan'],expires_at=2_000_000_000,resource=authority.expected_resource,
        claims={'iss':'https://mcp.example.test/oauth'})
    server = SimpleNamespace(mcp=MCP_SERVER_CLASS('putty-integrity-association'),
        _v4_planning_principal=lambda:planning_principal_from_access_token(token,authority),
        _v4_password_policy_action_principal=lambda:folder_action_principal_from_access_token(token,authority))
    register_putty_integrity_association_tools(server,actions)
    async def run():
        async with create_client_server_memory_streams() as (client_streams,server_streams):
            async with anyio.create_task_group() as group:
                low = server.mcp._lowlevel_server;group.start_soon(low.run,*server_streams,low.create_initialization_options())
                async with ClientSession(*client_streams) as session:
                    await session.initialize(); tools=(await session.list_tools()).tools;assert len(tools)==6
                    for tool in tools:
                        expected=set() if tool.name.startswith('preview') else {'preview_ref'} if tool.name.startswith('confirm') else {'authorization_ref'}
                        assert set(tool.input_schema.get('properties',{})) == expected
                    name='v4_putty_integrity_association_700'
                    preview=await session.call_tool('preview_'+name,{})
                    assert not preview.is_error and preview.structured_content['Expected State']['hash_enforcement_verified'] is False
                    denied=await session.call_tool('confirm_'+name,{'preview_ref':preview.structured_content['preview_ref']})
                    assert denied.is_error and not (state/'associate.intent.json').exists()
                    token.scopes.append('fortipam:operate')
                    auth=await session.call_tool('confirm_'+name,{'preview_ref':preview.structured_content['preview_ref']})
                    result=await session.call_tool('execute_confirmed_'+name,{'authorization_ref':auth.structured_content['authorization_ref']})
                    if enabled:
                        assert not result.is_error and result.structured_content['verification']=='verified'
                        name='v4_putty_integrity_association_restore_700'
                        preview=await session.call_tool('preview_'+name,{})
                        auth=await session.call_tool('confirm_'+name,{'preview_ref':preview.structured_content['preview_ref']})
                        result=await session.call_tool('execute_confirmed_'+name,{'authorization_ref':auth.structured_content['authorization_ref']})
                        assert not result.is_error and result.structured_content['verification']=='verified'
                    else:
                        assert result.is_error and not (state/'associate.intent.json').exists()
                group.cancel_scope.cancel()
    asyncio.run(run());assert len(device.puts)==(2 if enabled else 0)


@pytest.mark.parametrize('operate',[False,True])
def test_http_oauth_pkce_registration_policy_and_closed_gate(tmp_path,operate):
    from starlette.testclient import TestClient
    from fortipam_mcp.http_server import HttpServerSettings,create_http_app
    from test_http_server import RUNTIME_PROFILE_ENV,_v4_environment,_register_public_client,_authorize_and_login,_request_headers
    environment=_v4_environment(tmp_path);environment[RUNTIME_PROFILE_ENV]='v4-controlled'
    device,launcher,software,binding,state,key,adapter = prepared(tmp_path)
    app=create_http_app(HttpServerSettings.from_environment(environment),v4_putty_integrity_association_actions=actions_for(adapter()))
    scope='fortipam:read fortipam:plan'+(' fortipam:operate' if operate else '')
    with TestClient(app,base_url='https://mcp.example.com') as client:
        client_id=_register_public_client(client,scope);code,verifier=_authorize_and_login(client,client_id,scope)
        response=client.post('/fpamcp/oauth/token',data={'grant_type':'authorization_code','client_id':client_id,
            'code':code,'code_verifier':verifier,'redirect_uri':'https://client.example/callback','resource':'https://mcp.example.com/fpamcp'})
        assert response.status_code==200;token=response.json()['access_token'];headers=_request_headers(token);headers['host']='mcp.example.com'
        def rpc(method,params):
            result=client.post('/fpamcp',headers=headers,json={'jsonrpc':'2.0','id':1,'method':method,'params':params})
            assert result.status_code==200;return result.json()['result']
        assert len([t for t in rpc('tools/list',{})['tools'] if 'putty_integrity_association' in t['name']])==6
        preview=rpc('tools/call',{'name':'preview_v4_putty_integrity_association_700','arguments':{}})
        assert not preview['isError']
        auth=rpc('tools/call',{'name':'confirm_v4_putty_integrity_association_700','arguments':{'preview_ref':preview['structuredContent']['preview_ref']}})
        if operate:
            assert not auth['isError']
            result=rpc('tools/call',{'name':'execute_confirmed_v4_putty_integrity_association_700','arguments':{'authorization_ref':auth['structuredContent']['authorization_ref']}})
            assert result['isError']
        else: assert auth['isError']
        assert client.post('/fpamcp/oauth/revoke',data={'token':token,'client_id':client_id,'client_secret':''}).status_code==200
        assert client.post('/fpamcp',headers=headers,json={'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}}).status_code==401
    assert not device.puts and not (state/'associate.intent.json').exists()


@pytest.mark.parametrize('phase',['confirm','execute'])
def test_expiry_during_fresh_read_cannot_issue_or_reserve_intent(tmp_path,monkeypatch,phase):
    device,launcher,software,binding,state,key,adapter = prepared(tmp_path)
    clock=[100]; t=adapter(association_enabled=True)
    flow=PuttyIntegrityAssociationWorkflow(t,clock=lambda:clock[0])
    preview=flow.preview(requester_digest=REQUESTER)
    ref=preview['preview_ref'] if phase=='confirm' else flow.confirm(preview['preview_ref'],requester_digest=REQUESTER)['authorization_ref']
    original=t.inspect
    def slow_read(**kwargs):
        result=original(**kwargs);clock[0]=700;return result
    monkeypatch.setattr(t,'inspect',slow_read)
    with pytest.raises(PuttyIntegrityAssociationWorkflowError): getattr(flow,phase)(ref,requester_digest=REQUESTER)
    assert not device.puts and not (state/'associate.intent.json').exists()


def test_http_host_refuses_association_outside_controlled_profile(tmp_path):
    from fortipam_mcp.http_server import HttpServerSettings,create_http_app,HttpConfigurationError
    from test_http_server import RUNTIME_PROFILE_ENV,_v4_environment
    environment=_v4_environment(tmp_path);environment[RUNTIME_PROFILE_ENV]='readonly'
    device,launcher,software,binding,state,key,adapter = prepared(tmp_path)
    with pytest.raises(HttpConfigurationError,match='controlled OAuth'):
        create_http_app(HttpServerSettings.from_environment(environment),v4_putty_integrity_association_actions=actions_for(adapter()))
    assert not device.puts
