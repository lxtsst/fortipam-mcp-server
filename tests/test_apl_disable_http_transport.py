"""REST APL disable behavior and preserved pre-write dependencies."""
import copy
import json

import httpx
import pytest

from fortipam_mcp import apl_disable_http_transport as module
from fortipam_mcp.apl_disable_live_workflow import AplDisableLiveWorkflow
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig

RULE='mcp-v4-apl-rest-test'
GROUP='mcp-v4-user-group-test'
ROLE='mcp-v4-role-test'

@pytest.fixture
def harness(monkeypatch):
    monkeypatch.setattr(module,'_ssl_context',lambda _: True)
    records={
        'auto-provision-rule':{'name':RULE,'status':'enable','remote-group':GROUP,'accprofile':ROLE,'priority':1},
        'group':{'name':GROUP,'match':[{'server-name':'ldap-fixture','group-name':'isolated-fixture'}]},
        'accprofile':{'name':ROLE,'secretgrp':'read'},
    }
    calls=[]
    controls={}
    def handler(request):
        table=request.url.path.split('/')[-2]
        calls.append((request.method,table,json.loads(request.content) if request.content else None))
        if request.method=='PUT':
            records[table]['status']='disable'
            if controls.get('ambiguous'):raise httpx.ReadTimeout('private material',request=request)
            if controls.get('post_drift'):records[table]['priority']=2
        path='system' if table=='accprofile' else 'user'
        payload={'status':'success','http_status':200,'http_method':request.method,'path':path,'name':table,'version':'v7.0.0','build':29,'results':[copy.deepcopy(records[table])]}
        if controls.get('wrong_version'):payload['build']=30
        if controls.get('multiple'):payload['results']*=2
        return httpx.Response(200,json=payload)
    def factory(**kwargs):
        assert kwargs['follow_redirects'] is False and kwargs['trust_env'] is False
        return httpx.Client(transport=httpx.MockTransport(handler),**kwargs)
    adapter=module.FortiPamAplDisableHttpTransport(
        SecretMetadataHttpTransportConfig('https://fixture.example','private-token',15,None),
        module.AplDisableHttpBinding(RULE,GROUP,ROLE),client_factory=factory)
    return adapter,records,calls,controls

def test_workflow_disables_once_and_preserves_relationships(harness):
    adapter,records,calls,_=harness
    before=copy.deepcopy(records)
    workflow=AplDisableLiveWorkflow(adapter,write_transport="rest_700")
    preview=workflow.preview(auto_provision_rule_name=RULE,remote_user_group_name=GROUP,role_name=ROLE,requester_digest='a'*64)
    assert preview['Current State']['write_transport']=='rest_700'
    assert preview['Expected State']['readback_transport']=='rest_700'
    authorized=workflow.confirm(preview['preview_ref'],requester_digest='a'*64)
    result=workflow.execute(authorized['authorization_ref'],requester_digest='a'*64)
    assert result['verification']=='verified'
    workflow.execute(authorized['authorization_ref'],requester_digest='a'*64)
    assert [c for c in calls if c[0]=='PUT']==[('PUT','auto-provision-rule',{'status':'disable'})]
    before['auto-provision-rule']['status']='disable'
    assert records==before

@pytest.mark.parametrize('surface',['auto-provision-rule','group','accprofile'])
def test_pre_write_drift_prevents_dispatch(harness,surface):
    adapter,records,calls,_=harness
    assert adapter.inspect_disable(RULE,GROUP,ROLE).disable_baseline_verified
    records[surface]['unexpected-drift']=True
    with pytest.raises(module.AplDisableHttpTransportError):adapter.disable_and_readback(RULE,GROUP,ROLE)
    assert not any(c[0]=='PUT' for c in calls)

@pytest.mark.parametrize('failure',['ambiguous','post_drift'])
def test_failed_dispatch_is_not_repeated(harness,failure):
    adapter,_,calls,controls=harness
    adapter.inspect_disable(RULE,GROUP,ROLE)
    controls[failure]=True
    for _ in range(2):
        with pytest.raises(module.AplDisableHttpTransportError,match='unavailable'):
            adapter.disable_and_readback(RULE,GROUP,ROLE)
    assert sum(c[0]=='PUT' for c in calls)==1

@pytest.mark.parametrize('failure',['wrong_version','multiple'])
def test_unqualified_detail_is_rejected(harness,failure):
    adapter,_,calls,controls=harness
    controls[failure]=True
    with pytest.raises(module.AplDisableHttpTransportError):adapter.inspect_disable(RULE,GROUP,ROLE)
    assert not any(c[0]=='PUT' for c in calls)

def test_binding_and_unprepared_dispatch_are_rejected(harness):
    adapter,_,calls,_=harness
    for args in ((RULE,GROUP,ROLE),(RULE+'-other',GROUP,ROLE)):
        with pytest.raises(module.AplDisableHttpTransportError):adapter.disable_and_readback(*args)
    assert not calls


def test_concurrent_dispatches_still_write_once(harness):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    adapter,_,calls,_=harness
    adapter.inspect_disable(RULE,GROUP,ROLE)
    start=Barrier(2)
    def dispatch():
        start.wait(timeout=5)
        try:return adapter.disable_and_readback(RULE,GROUP,ROLE).verified
        except module.AplDisableHttpTransportError:return False
    with ThreadPoolExecutor(max_workers=2) as executor:
        results=list(executor.map(lambda _:dispatch(),range(2)))
    assert sorted(results)==[False,True]
    assert sum(c[0]=='PUT' for c in calls)==1


@pytest.fixture
def rest_environment(tmp_path):
    path=tmp_path/'binding.json'
    path.write_text(json.dumps({'contract':module.BINDING_CONTRACT,'rule_name':RULE,'group_name':GROUP,'role_name':ROLE}))
    path.chmod(0o600)
    return {module.REST_ENV_PREFIX+'BINDING_FILE':str(path),
            module.REST_ENV_PREFIX+'BASE_URL':'https://fixture.example',
            module.REST_ENV_PREFIX+'API_TOKEN':'private-token'},path


def test_rest_builder_uses_dedicated_binding_and_closed_gate(rest_environment):
    from fortipam_mcp.apl_disable_mcp_action import build_v4_apl_disable_action, V4AplDisableActionRuntimeError
    env,_=rest_environment
    action=build_v4_apl_disable_action({**env,'FORTIPAM_MCP_V4_APL_DISABLE_TRANSPORT':'rest_700'})
    assert action._workflow._write_transport=='rest_700'
    with pytest.raises(V4AplDisableActionRuntimeError):action.execute('opaque',object())


@pytest.mark.parametrize('failure',['permissions','symlink','generic_token','unknown_transport'])
def test_rest_builder_rejects_unsafe_or_incomplete_configuration(rest_environment,failure):
    from fortipam_mcp.apl_disable_mcp_action import build_v4_apl_disable_action,V4AplDisableActionConfigurationError
    env,path=rest_environment
    env['FORTIPAM_MCP_V4_APL_DISABLE_TRANSPORT']='rest_700'
    if failure=='permissions':path.chmod(0o644)
    if failure=='symlink':
        link=path.with_name('link.json');link.symlink_to(path);env[module.REST_ENV_PREFIX+'BINDING_FILE']=str(link)
    if failure=='generic_token':
        del env[module.REST_ENV_PREFIX+'API_TOKEN'];env['FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_API_TOKEN']='private-token'
    if failure=='unknown_transport':env['FORTIPAM_MCP_V4_APL_DISABLE_TRANSPORT']='rest'
    with pytest.raises(V4AplDisableActionConfigurationError):build_v4_apl_disable_action(env)


def test_registered_mcp_tools_use_rest_adapter_and_rest_acceptance_contract(harness,monkeypatch):
    import asyncio
    from mcp import Client
    from fortipam_mcp.server import FortiPamMcpServer,RuntimeProfile
    from fortipam_mcp.apl_disable_mcp_action import ProtectedAplDisableMcpAction
    from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
    from test_v4_m3 import _requester
    from scripts.v4_apl_disable_mcp_oauth_acceptance import _validate_preview,_validate_execution,AplDisableMcpOAuthAcceptanceError
    adapter,_,calls,_=harness
    action=ProtectedAplDisableMcpAction(AplDisableLiveWorkflow(adapter,write_transport='rest_700'))
    class FolderAction:
        pass
    principal=V4PlanningPrincipal(_requester(),'a'*64)
    server=FortiPamMcpServer(runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=FolderAction(),v4_folder_action_enabled=True,
        v4_apl_disable_action=action,v4_apl_disable_action_enabled=True,v4_http_oauth=True)
    monkeypatch.setattr(server,'_v4_planning_principal',lambda:principal)
    monkeypatch.setattr(server,'_v4_apl_disable_action_principal',lambda:principal)
    async def exercise():
        async with Client(server.mcp) as client:
            preview=await client.call_tool('preview_v4_auto_provision_rule_disable',{'auto_provision_rule_name':RULE,'remote_user_group_name':GROUP,'role_name':ROLE})
            _validate_preview(preview.structured_content,RULE,GROUP,ROLE,preview.is_error,write_transport='rest_700')
            with pytest.raises(AplDisableMcpOAuthAcceptanceError):
                _validate_preview(preview.structured_content,RULE,GROUP,ROLE,preview.is_error)
            confirmation=await client.call_tool('confirm_v4_auto_provision_rule_disable',{'preview_ref':preview.structured_content['preview_ref']})
            result=await client.call_tool('execute_confirmed_v4_auto_provision_rule_disable',{'authorization_ref':confirmation.structured_content['authorization_ref']})
            _validate_execution(result.structured_content,result.is_error,write_transport='rest_700')
    asyncio.run(exercise())
    assert sum(c[0]=='PUT' for c in calls)==1
