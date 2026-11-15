"""Controlled OAuth/MCP discovery, scopes, immutable action and actual parent."""
from __future__ import annotations

from dataclasses import replace
import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient
from fortipam_mcp.http_server import create_http_app, HttpConfigurationError
from fortipam_mcp.radius_remote_user_lifecycle_mcp_action import RadiusRemoteUserLifecycleMcpAction
from fortipam_mcp.radius_remote_user_lifecycle_workflow import RadiusRemoteUserLifecycleWorkflow
from test_radius_server_pair_lifecycle_mcp_action import _settings, _login, _call
from test_http_server import _v4_environment
from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV, RuntimeProfile

PREVIEW = 'preview_v4_radius_user_lifecycle_700'
AUTHORIZE = 'authorize_v4_radius_user_lifecycle_700'
EXECUTE = 'execute_v4_radius_user_lifecycle_700'
TOOLS = {PREVIEW, AUTHORIZE, EXECUTE}


def action(monkeypatch: Any, enabled: bool = True) -> tuple[Any, list[str]]:
    calls = []
    monkeypatch.setattr(RadiusRemoteUserLifecycleWorkflow, 'preview', lambda self,**k: calls.append('preview') or {'preview_ref':'synthetic-preview'})
    monkeypatch.setattr(RadiusRemoteUserLifecycleWorkflow, 'authorize', lambda self,r,**k: calls.append('authorize') or {'authorization_ref':'synthetic-auth'})
    monkeypatch.setattr(RadiusRemoteUserLifecycleWorkflow, 'execute', lambda self,r,**k: calls.append('execute') or {'outcome':'succeeded'})
    monkeypatch.setattr(RadiusRemoteUserLifecycleWorkflow, 'close', lambda self: calls.append('close'))
    return RadiusRemoteUserLifecycleMcpAction(object.__new__(RadiusRemoteUserLifecycleWorkflow), execution_enabled=enabled), calls


@pytest.mark.parametrize('plan,operate,gate', [(False,False,False),(True,False,True),(True,True,False),(True,True,True)])
def test_real_oauth_scopes_and_execution_gate(tmp_path: Path, monkeypatch: Any, plan: bool, operate: bool, gate: bool) -> None:
    selected, calls = action(monkeypatch, gate)
    with TestClient(create_http_app(_settings(tmp_path),v4_radius_user_lifecycle_candidate_action=selected),base_url='https://mcp.example.com') as client:
        headers = _login(client,'fortipam:read'+(' fortipam:plan' if plan else '')+(' fortipam:operate' if operate else ''))
        assert _call(client, headers, PREVIEW, {})['isError'] is not plan
        assert _call(client, headers, AUTHORIZE, {'preview_ref':'synthetic-preview'})['isError'] is (not operate or not gate)
        assert _call(client, headers, EXECUTE, {'authorization_ref':'synthetic-auth'})['isError'] is (not operate or not gate)
        assert calls == (['preview'] if plan else []) + (['authorize','execute'] if operate and gate else [])
    assert calls[-1] == 'close'


@pytest.mark.parametrize('fault', ['profile','auth','authority','type','legacy_pair'])
def test_injection_rejects_wrong_host_or_profile(tmp_path: Path, monkeypatch: Any, fault: str) -> None:
    selected, calls = action(monkeypatch)
    settings = _settings(tmp_path); kwargs = {'v4_radius_user_lifecycle_candidate_action':selected}
    if fault == 'profile': settings = replace(settings,runtime_profile=RuntimeProfile.V4_PLAN_ONLY)
    elif fault == 'auth': settings = replace(settings,auth_mode='bearer',bearer_token='synthetic-token')
    elif fault == 'authority': settings = replace(settings,v4_planning_authorization=None)
    elif fault == 'type': kwargs['v4_radius_user_lifecycle_candidate_action'] = object()
    else: kwargs['v4_radius_server_pair_lifecycle_candidate_action'] = object()
    with pytest.raises(HttpConfigurationError): create_http_app(settings,**kwargs)
    assert not calls


def test_tool_schemas_are_reference_only_and_default_profile_has_none(tmp_path: Path, monkeypatch: Any) -> None:
    selected, calls = action(monkeypatch)
    settings = _settings(tmp_path)
    for present in (False, True):
        kwargs = {'v4_radius_user_lifecycle_candidate_action': selected} if present else {}
        with TestClient(create_http_app(settings,**kwargs),base_url='https://mcp.example.com') as client:
            headers = _login(client,'fortipam:read fortipam:plan fortipam:operate')
            result = client.post('/fpamcp',headers=headers,json={'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}})
            data = result.json() if result.headers.get('content-type','').startswith('application/json') else json.loads(result.text.split('data: ',1)[1])
            tools = {t['name']:t for t in data['result']['tools']}
            assert (TOOLS <= tools.keys()) is present
            if not present: continue
            assert set(tools[PREVIEW]['inputSchema'].get('properties',{})) == set()
            assert set(tools[AUTHORIZE]['inputSchema']['properties']) == {'preview_ref'}
            assert set(tools[EXECUTE]['inputSchema']['properties']) == {'authorization_ref'}
            assert not any('radius_pair_configure' in name or 'radius_pair_lifecycle' in name for name in tools)
            for name, arguments in ((PREVIEW,{'username':'admin'}),(AUTHORIZE,{'preview_ref':'x','secret':'NEVER_ACCEPT'}),
                (EXECUTE,{'authorization_ref':'x','source_host':'foreign'})):
                assert _call(client,headers,name,arguments)['isError']
    assert calls == ['close']


def test_actual_parent_runs_six_kernels_through_oauth_mcp(tmp_path: Path, monkeypatch: Any) -> None:
    from scripts.v4_radius_remote_user_lifecycle_mcp_oauth_acceptance import _validate_preview, _validate_authorization, _validate_execution
    from fortipam_mcp.local_oauth import LocalOAuthProvider
    from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
    from test_radius_remote_user_lifecycle_workflow import setup
    monkeypatch.setattr(time,'time',lambda:100.0)
    settings = _settings(tmp_path)
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client:
        headers = _login(client,'fortipam:read fortipam:plan fortipam:operate')
    bearer = next(v for k,v in headers.items() if k.lower() == 'authorization').removeprefix('Bearer ')
    token = asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(bearer))
    principal = planning_principal_from_access_token(token,settings.v4_planning_authorization)
    identity = {'requester_digest':principal.requester.digest,'transport_digest':principal.transport_namespace_digest}
    root = tmp_path/'candidate'; root.mkdir(mode=0o700)
    workflow,radius,user,_,source,_,mutations = setup(root,identity=identity)
    selected = RadiusRemoteUserLifecycleMcpAction(workflow,execution_enabled=True)
    with TestClient(create_http_app(settings,v4_radius_user_lifecycle_candidate_action=selected),base_url='https://mcp.example.com') as client:
        p = _call(client,headers,PREVIEW,{})
        assert not p['isError']
        _validate_preview(p['structuredContent'])
        a = _call(client,headers,AUTHORIZE,{'preview_ref':p['structuredContent']['preview_ref']})
        assert not a['isError']
        _validate_authorization(a['structuredContent'],p['structuredContent'])
        r = _call(client,headers,EXECUTE,{'authorization_ref':a['structuredContent']['authorization_ref']})
        assert not r['isError'] and r['structuredContent']['outcome'] == 'succeeded'
        _validate_execution(r['structuredContent'])
        assert r['structuredContent']['all_candidate_gates_closed']
        assert r['structuredContent']['user_absence_verified'] and r['structuredContent']['pair_absence_verified']
        assert not r['structuredContent']['user_authentication_qualified']
    assert radius.row is user.row is None and len(mutations) == 6 and len(source.calls) == 4
    assert workflow._closed()


def test_normal_main_injects_and_closes_candidate(tmp_path: Path, monkeypatch: Any) -> None:
    import uvicorn
    from fortipam_mcp import http_server, radius_remote_user_lifecycle_runtime
    selected, calls = action(monkeypatch)
    environment = _v4_environment(tmp_path/'oauth'); environment[RUNTIME_PROFILE_ENV]='v4-controlled'
    monkeypatch.setattr(os,'environ',environment)
    monkeypatch.setattr(http_server,'load_http_runtime_environment',lambda:False)
    monkeypatch.setattr(radius_remote_user_lifecycle_runtime,'build_radius_remote_user_lifecycle_candidate',lambda _:selected)
    seen = []
    def create(settings: Any, **kwargs: Any) -> object:
        assert kwargs['v4_radius_user_lifecycle_candidate_action'] is selected
        seen.append('injected'); return object()
    async def serve(self: Any, sockets: Any = None) -> None: seen.append('served')
    monkeypatch.setattr(http_server,'create_http_app',create);monkeypatch.setattr(uvicorn.Server,'serve',serve)
    http_server.main()
    assert seen == ['injected','served'] and calls == ['close']


def test_normal_main_closes_candidate_if_app_creation_fails(tmp_path: Path, monkeypatch: Any) -> None:
    from fortipam_mcp import http_server, radius_remote_user_lifecycle_runtime
    selected, calls = action(monkeypatch)
    environment = _v4_environment(tmp_path/'oauth'); environment[RUNTIME_PROFILE_ENV]='v4-controlled'
    monkeypatch.setattr(os,'environ',environment)
    monkeypatch.setattr(http_server,'load_http_runtime_environment',lambda:False)
    monkeypatch.setattr(radius_remote_user_lifecycle_runtime,'build_radius_remote_user_lifecycle_candidate',lambda _:selected)
    def fail(*args: Any, **kwargs: Any) -> None: raise HttpConfigurationError('Synthetic startup failure.')
    monkeypatch.setattr(http_server,'create_http_app',fail)
    with pytest.raises(SystemExit): http_server.main()
    assert calls == ['close']


def test_actual_startup_manifest_builder_then_oauth_parent(tmp_path: Path, monkeypatch: Any) -> None:
    from types import SimpleNamespace
    from v4_planning import canonical_digest
    from fortipam_mcp import radius_remote_user_lifecycle_runtime as runtime, radius_server_pair_lifecycle_runtime as pair_runtime
    from fortipam_mcp.local_oauth import LocalOAuthProvider
    from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
    from fortipam_mcp.radius_server_pair_contract import RadiusServerPairBinding
    from fortipam_mcp.radius_remote_user_contract import RadiusRemoteUserBinding
    from test_radius_remote_user_lifecycle_runtime import setup as startup
    from test_radius_server_pair_http_transport import Peer as RadiusPeer, Response
    from test_radius_server_projection import envelope
    from test_radius_remote_user_http_transport import Peer as UserPeer
    from test_radius_pair_fixture_material_worker import fixture, write
    from test_radius_pair_fixture_material_loader import Factory, peer_script
    monkeypatch.setattr(time,'time',lambda:100.0)
    settings = _settings(tmp_path)
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client:
        headers = _login(client,'fortipam:read fortipam:plan fortipam:operate')
    bearer = next(v for k,v in headers.items() if k.lower()=='authorization').removeprefix('Bearer ')
    token = asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(bearer))
    principal = planning_principal_from_access_token(token,settings.v4_planning_authorization)
    root = tmp_path/'candidate';root.mkdir(mode=0o700)
    env,manifest,path,paths,pair_manifest,pair_paths = startup(root)
    pair_manifest['identity'].update(allowed_requester_digest=principal.requester.digest,
        allowed_transport_digest=principal.transport_namespace_digest)
    _,inspections,policy = fixture(root/'worker')
    policy['scope_digest']=canonical_digest(pair_manifest['identity']['create_scope_ref'])
    policy['audience_digest']=canonical_digest(pair_manifest['identity']['audience_ref'])
    write(root/'worker/pair-material-policy.json',policy)
    from fortipam_mcp.radius_pair_fixture_material_worker import _digest
    pair_manifest['source']['source_policy_digest']=_digest(policy)
    pair_path=Path(manifest['pair_manifest_file']);pair_path.write_text(json.dumps(pair_manifest))
    source=Factory(peer_script(root/'worker',inspections))
    radius=RadiusPeer();original=radius.handle
    from fortipam_mcp.radius_server_pair_owned_connect_contract import CONNECT_PATH
    def handle(method: str, url: str, body: Any) -> Any:
        if method=='POST'and url==CONNECT_PATH:
            return Response(envelope(http_method='POST',action='test-connect',mkey=radius.binding.name,
                results={'status':'ok','access_status':'Access-Reject','access_message':'SYNTHETIC'}))
        return original(method,url,body)
    radius.handle=handle
    b=RadiusRemoteUserBinding(radius=RadiusServerPairBinding(**pair_manifest['binding']),**manifest['binding'])
    user=UserPeer(SimpleNamespace(_target=SimpleNamespace(_serial=pair_manifest['identity']['expected_serial']),_binding=b),radius)
    create_class=pair_runtime.RadiusServerPairLiveWorkflow
    native_class=pair_runtime.RadiusServerPairOwnedConnectWorkflow
    recovery_class=pair_runtime.RadiusServerPairRecoveryWorkflow
    parent_class=runtime.RadiusRemoteUserLifecycleWorkflow
    monkeypatch.setattr(pair_runtime,'RadiusServerPairLiveWorkflow',lambda *a,**k:create_class(*a,**k,
        connection_factory=radius.connection,source_process_factory=source))
    monkeypatch.setattr(pair_runtime,'RadiusServerPairOwnedConnectWorkflow',lambda *a,**k:native_class(*a,**k,connection_factory=radius.connection))
    monkeypatch.setattr(pair_runtime,'RadiusServerPairRecoveryWorkflow',lambda *a,**k:recovery_class(*a,**k,connection_factory=radius.connection))
    monkeypatch.setattr(runtime,'RadiusRemoteUserLifecycleWorkflow',lambda *a,**k:parent_class(*a,**k,user_connection_factory=user.connection))
    env[runtime.PREFIX+'EXECUTION_ENABLED']='true'
    selected=runtime.build_radius_remote_user_lifecycle_candidate(env)
    assert selected is not None and not source.calls and not radius.connections and not user.connections
    with TestClient(create_http_app(settings,v4_radius_user_lifecycle_candidate_action=selected),base_url='https://mcp.example.com')as client:
        p=_call(client,headers,PREVIEW,{})
        assert not p['isError']
        a=_call(client,headers,AUTHORIZE,{'preview_ref':p['structuredContent']['preview_ref']})
        assert not a['isError']
        r=_call(client,headers,EXECUTE,{'authorization_ref':a['structuredContent']['authorization_ref']})
        assert not r['isError']and r['structuredContent']['outcome']=='succeeded'
    assert radius.row is user.row is None and radius.posts==radius.deletes==user.posts==user.deletes==1
    assert len(source.calls)==4 and selected._workflow._closed()


def test_standard_environment_file_loads_only_fixed_profile_flags(tmp_path: Path, monkeypatch: Any) -> None:
    from fortipam_mcp import http_server
    from fortipam_mcp.radius_remote_user_lifecycle_runtime import PREFIX
    path=tmp_path/'runtime.env'
    path.write_text(PREFIX+'ENABLED=true\n'+PREFIX+'EXECUTION_ENABLED=false\n'+PREFIX+'STARTUP_MANIFEST_FILE=/synthetic/startup.json\n')
    path.chmod(0o600)
    monkeypatch.setattr(os,'environ',{http_server.HTTP_ENV_FILE_VARIABLE:str(path)})
    assert http_server.load_http_runtime_environment()
    assert os.environ[PREFIX+'ENABLED']=='true'and os.environ[PREFIX+'EXECUTION_ENABLED']=='false'


def test_action_is_private_immutable_and_requires_exact_principal(monkeypatch: Any) -> None:
    import pickle
    selected,calls=action(monkeypatch)
    with pytest.raises(ValueError): selected._enabled=False
    with pytest.raises(ValueError): del selected._workflow
    with pytest.raises(Exception): pickle.dumps(selected)
    with pytest.raises(RuntimeError) as error: selected.preview({})
    assert str(error.value)=='FortiPAM RADIUS User lifecycle is unavailable.'and not calls
