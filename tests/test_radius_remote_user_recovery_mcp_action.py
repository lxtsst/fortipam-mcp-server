"""Actual OAuth/MCP original-User recovery, scopes, selectors and closure."""
from __future__ import annotations

import asyncio
from dataclasses import replace
import json
import os
from pathlib import Path
import time
from typing import Any
import pytest
from starlette.testclient import TestClient
from fortipam_mcp.http_server import create_http_app, HttpConfigurationError
from fortipam_mcp.radius_remote_user_live_workflow import RadiusRemoteUserLiveWorkflow
from fortipam_mcp.radius_remote_user_recovery_mcp_action import RadiusRemoteUserRecoveryMcpAction
from fortipam_mcp.radius_server_pair_recovery_workflow import RadiusServerPairRecoveryWorkflow
from fortipam_mcp.radius_remote_user_absence_guard import RadiusRemoteUserAbsenceGuard
from fortipam_mcp.runtime_profile import RuntimeProfile, RUNTIME_PROFILE_ENV
from fortipam_mcp import radius_remote_user_recovery_runtime as runtime
from test_radius_remote_user_recovery_runtime import prepared
from test_radius_server_pair_lifecycle_mcp_action import _settings, _login, _call
from test_http_server import _v4_environment

PREVIEW = 'preview_v4_radius_user_recovery_700'
AUTHORIZE = 'authorize_v4_radius_user_recovery_700'
EXECUTE = 'execute_v4_radius_user_recovery_700'
RECONCILE = 'reconcile_v4_radius_user_recovery_700'
INSPECT = 'inspect_v4_radius_user_cleanup_700'
TOOLS = {PREVIEW, AUTHORIZE, EXECUTE, RECONCILE, INSPECT}
PAIR_PREVIEW = 'preview_v4_radius_associated_pair_recovery_700'
PAIR_AUTHORIZE = 'authorize_v4_radius_associated_pair_recovery_700'
PAIR_EXECUTE = 'execute_v4_radius_associated_pair_recovery_700'
PAIR_RECONCILE = 'reconcile_v4_radius_associated_pair_recovery_700'
PAIR_TOOLS = {PAIR_PREVIEW,PAIR_AUTHORIZE,PAIR_EXECUTE,PAIR_RECONCILE}


def fake(monkeypatch: Any, enabled: bool = True, *, with_pair: bool = False) -> tuple[Any, list[str]]:
    calls: list[str] = []
    w = object.__new__(RadiusRemoteUserLiveWorkflow)
    w._operation = 'remove'
    from types import SimpleNamespace
    w._target = SimpleNamespace(_recovery_only=True)
    monkeypatch.setattr(RadiusRemoteUserLiveWorkflow, 'preview', lambda self,**k: calls.append('preview') or {})
    monkeypatch.setattr(RadiusRemoteUserLiveWorkflow, 'authorize', lambda self,r,**k: calls.append('authorize') or {})
    monkeypatch.setattr(RadiusRemoteUserLiveWorkflow, 'execute', lambda self,r,**k: calls.append('execute') or {})
    monkeypatch.setattr(RadiusRemoteUserLiveWorkflow, 'reconcile', lambda self,**k: calls.append('reconcile') or {})
    monkeypatch.setattr(RadiusRemoteUserLiveWorkflow, 'inspect_cleanup_state', lambda self,**k: calls.append('inspect') or {})
    monkeypatch.setattr(RadiusRemoteUserLiveWorkflow, 'close', lambda self: calls.append('close'))
    monkeypatch.setattr(RadiusRemoteUserLiveWorkflow, 'revoke', lambda self: None)
    pair = None
    if with_pair:
        w._binding=object(); w._store=object()
        pair=object.__new__(RadiusServerPairRecoveryWorkflow)
        guard=object.__new__(RadiusRemoteUserAbsenceGuard)
        object.__setattr__(guard,'_reader',w)
        pair._user_absence=guard
        monkeypatch.setattr(RadiusServerPairRecoveryWorkflow,'preview',lambda self,**k:calls.append('pair_preview')or{})
        monkeypatch.setattr(RadiusServerPairRecoveryWorkflow,'authorize',lambda self,r,**k:calls.append('pair_authorize')or{})
        monkeypatch.setattr(RadiusServerPairRecoveryWorkflow,'execute',lambda self,r,**k:calls.append('pair_execute')or{})
        monkeypatch.setattr(RadiusServerPairRecoveryWorkflow,'reconcile',lambda self,**k:calls.append('pair_reconcile')or{})
        monkeypatch.setattr(RadiusServerPairRecoveryWorkflow,'close',lambda self:calls.append('pair_close'))
        monkeypatch.setattr(RadiusServerPairRecoveryWorkflow,'revoke',lambda self:None)
    return RadiusRemoteUserRecoveryMcpAction(w, pair_recovery=pair, execution_enabled=enabled), calls


@pytest.mark.parametrize('plan,operate,gate', [(False,False,False),(True,False,True),(True,True,False),(True,True,True)])
def test_scopes_gate_discovery_and_shutdown(tmp_path: Path, monkeypatch: Any, plan: bool, operate: bool, gate: bool) -> None:
    selected, calls = fake(monkeypatch, gate)
    with TestClient(create_http_app(_settings(tmp_path), v4_radius_user_recovery_candidate_action=selected), base_url='https://mcp.example.com') as client:
        headers = _login(client, 'fortipam:read'+(' fortipam:plan' if plan else '')+(' fortipam:operate' if operate else ''))
        for name, args, permitted in ((PREVIEW,{},plan),(AUTHORIZE,{'preview_ref':'synthetic-ref'},operate and gate),
                (EXECUTE,{'authorization_ref':'synthetic-ref'},operate and gate),(RECONCILE,{},plan),(INSPECT,{},plan)):
            assert _call(client,headers,name,args)['isError'] is not permitted
        for name in TOOLS:
            assert _call(client,headers,name,{'password':'SYNTHETIC_REJECTED'})['isError']
    assert calls == (['preview'] if plan else [])+(['authorize','execute'] if operate and gate else [])+(['reconcile','inspect'] if plan else [])+['close']


@pytest.mark.parametrize('fault', ['profile','auth','authority','type','forward','pair'])
def test_injection_requires_exclusive_controlled_oauth(tmp_path: Path, monkeypatch: Any, fault: str) -> None:
    selected, calls = fake(monkeypatch)
    settings = _settings(tmp_path)
    kwargs = {'v4_radius_user_recovery_candidate_action':selected}
    if fault == 'profile': settings = replace(settings,runtime_profile=RuntimeProfile.V4_PLAN_ONLY)
    elif fault == 'auth': settings = replace(settings,auth_mode='bearer',bearer_token='synthetic')
    elif fault == 'authority': settings = replace(settings,v4_planning_authorization=None)
    elif fault == 'type': kwargs['v4_radius_user_recovery_candidate_action'] = object()
    elif fault == 'forward': kwargs['v4_radius_user_lifecycle_candidate_action'] = object()
    else: kwargs['v4_radius_server_pair_lifecycle_candidate_action'] = object()
    with pytest.raises(HttpConfigurationError): create_http_app(settings,**kwargs)
    assert not calls


def test_actual_manifest_recovery_through_oauth_mcp(tmp_path: Path, monkeypatch: Any) -> None:
    from fortipam_mcp.local_oauth import LocalOAuthProvider
    from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
    monkeypatch.setattr(time,'time',lambda:100.0)
    settings = _settings(tmp_path)
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as client:
        headers = _login(client,'fortipam:read fortipam:plan fortipam:operate')
        reply = client.post('/fpamcp', headers=headers, json={'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}})
        body = reply.json() if reply.headers.get('content-type','').startswith('application/json') else json.loads(reply.text.split('data: ',1)[1])
        assert not TOOLS & {t['name'] for t in body['result']['tools']}
    bearer = next(v for k,v in headers.items() if k.lower()=='authorization').removeprefix('Bearer ')
    token = asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(bearer))
    principal = planning_principal_from_access_token(token,settings.v4_planning_authorization)
    root = tmp_path/'candidate'; root.mkdir(mode=0o700)
    env, _, _, _, _, _, radius, user, source, _, _ = prepared(root,monkeypatch,
        identity=dict(requester_digest=principal.requester.digest,transport_digest=principal.transport_namespace_digest))
    env[runtime.PREFIX+'EXECUTION_ENABLED'] = 'true'
    selected = runtime.build_radius_remote_user_recovery_candidate(env)
    counts = len(radius.connections),len(source.calls)
    with TestClient(create_http_app(settings,v4_radius_user_recovery_candidate_action=selected),base_url='https://mcp.example.com') as client:
        p = _call(client,headers,PREVIEW,{})
        assert not p['isError']
        a = _call(client,headers,AUTHORIZE,{'preview_ref':p['structuredContent']['preview_ref']})
        assert not a['isError']
        r = _call(client,headers,EXECUTE,{'authorization_ref':a['structuredContent']['authorization_ref']})
        assert not r['isError'] and r['structuredContent']['outcome']=='succeeded'
        assert _call(client,headers,RECONCILE,{})['structuredContent']['prior_m4_outcome_unchanged']
    assert selected._workflow._closed and not selected._workflow._enabled
    assert user.row is None and radius.row is not None and user.deletes==1 and radius.deletes==0
    assert counts == (len(radius.connections),len(source.calls))


@pytest.mark.parametrize('fail', [False,True])
def test_normal_main_injects_and_closes_on_success_or_failure(tmp_path: Path, monkeypatch: Any, fail: bool) -> None:
    import uvicorn
    from fortipam_mcp import http_server
    selected, calls = fake(monkeypatch)
    environment = _v4_environment(tmp_path/'oauth'); environment[RUNTIME_PROFILE_ENV]='v4-controlled'
    monkeypatch.setattr(os,'environ',environment)
    monkeypatch.setattr(http_server,'load_http_runtime_environment',lambda:False)
    monkeypatch.setattr(runtime,'build_radius_remote_user_recovery_candidate',lambda _:selected)
    def create(settings: Any, **kwargs: Any) -> object:
        assert kwargs['v4_radius_user_recovery_candidate_action'] is selected
        if fail: raise HttpConfigurationError('Synthetic failure.')
        return object()
    async def serve(self: Any, sockets: Any = None) -> None: pass
    monkeypatch.setattr(http_server,'create_http_app',create); monkeypatch.setattr(uvicorn.Server,'serve',serve)
    if fail:
        with pytest.raises(SystemExit): http_server.main()
    else: http_server.main()
    assert calls == ['close']


def test_environment_file_loads_recovery_flags(tmp_path: Path, monkeypatch: Any) -> None:
    from fortipam_mcp import http_server
    path = tmp_path/'runtime.env'
    path.write_text(runtime.PREFIX+'ENABLED=true\n'+runtime.PREFIX+'EXECUTION_ENABLED=false\n'+runtime.PREFIX+'STARTUP_MANIFEST_FILE=/synthetic/original.json\n')
    path.chmod(0o600)
    monkeypatch.setattr(os,'environ',{http_server.HTTP_ENV_FILE_VARIABLE:str(path)})
    assert http_server.load_http_runtime_environment()
    assert os.environ[runtime.PREFIX+'ENABLED']=='true' and os.environ[runtime.PREFIX+'EXECUTION_ENABLED']=='false'


@pytest.mark.parametrize('plan,operate,gate', [(False,False,False),(True,False,True),(True,True,False),(True,True,True)])
def test_pair_tools_keep_scopes_gate_and_reference_only_inputs(tmp_path: Path, monkeypatch: Any, plan: bool, operate: bool, gate: bool) -> None:
    selected,calls=fake(monkeypatch,gate,with_pair=True)
    with TestClient(create_http_app(_settings(tmp_path),v4_radius_user_recovery_candidate_action=selected),base_url='https://mcp.example.com')as client:
        headers=_login(client,'fortipam:read'+(' fortipam:plan'if plan else'')+(' fortipam:operate'if operate else''))
        for name,args,permitted in ((PAIR_PREVIEW,{},plan),(PAIR_AUTHORIZE,{'preview_ref':'synthetic'},operate and gate),
                (PAIR_EXECUTE,{'authorization_ref':'synthetic'},operate and gate),(PAIR_RECONCILE,{},plan)):
            assert _call(client,headers,name,args)['isError']is not permitted
        for name in PAIR_TOOLS:
            assert _call(client,headers,name,{'username':'SYNTHETIC_REJECTED'})['isError']
    assert calls==(['pair_preview']if plan else[])+(['pair_authorize','pair_execute']if operate and gate else[])+(['pair_reconcile']if plan else[])+['close','pair_close']


@pytest.mark.parametrize('lost_ack', [False,True])
def test_actual_ordered_user_then_pair_recovery_and_recomposition_through_oauth(tmp_path: Path, monkeypatch: Any, lost_ack: bool) -> None:
    from fortipam_mcp.local_oauth import LocalOAuthProvider
    from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
    monkeypatch.setattr(time,'time',lambda:100.0)
    settings=_settings(tmp_path)
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com')as client:
        headers=_login(client,'fortipam:read fortipam:plan fortipam:operate')
        for name in PAIR_TOOLS: assert _call(client,headers,name,{})['isError']
    bearer=next(v for k,v in headers.items()if k.lower()=='authorization').removeprefix('Bearer ')
    token=asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(bearer))
    principal=planning_principal_from_access_token(token,settings.v4_planning_authorization)
    root=tmp_path/'candidate';root.mkdir(mode=0o700)
    env,_,_,_,_,_,radius,user,source,identity,_=prepared(root,monkeypatch,
        identity=dict(requester_digest=principal.requester.digest,transport_digest=principal.transport_namespace_digest))
    env[runtime.PREFIX+'EXECUTION_ENABLED']='true'
    selected=runtime.build_radius_remote_user_recovery_candidate(env)
    radius.lost_delete_ack=lost_ack
    with TestClient(create_http_app(settings,v4_radius_user_recovery_candidate_action=selected),base_url='https://mcp.example.com')as client:
        # Pair q_ref is deliberately misleading; the owned User dependency wins.
        radius.row['q_ref']=0
        assert _call(client,headers,PAIR_PREVIEW,{})['isError']
        # This synthetic peer decrements its counter on User DELETE.
        radius.row['q_ref']=1
        for preview,authorize,execute in ((PREVIEW,AUTHORIZE,EXECUTE),(PAIR_PREVIEW,PAIR_AUTHORIZE,PAIR_EXECUTE)):
            p=_call(client,headers,preview,{});assert not p['isError'],(preview,p)
            a=_call(client,headers,authorize,{'preview_ref':p['structuredContent']['preview_ref']});assert not a['isError']
            r=_call(client,headers,execute,{'authorization_ref':a['structuredContent']['authorization_ref']})
            assert not r['isError']
            expected='reconciliation_required'if execute==PAIR_EXECUTE and lost_ack else'succeeded'
            assert r['structuredContent']['outcome']==expected
        assert _call(client,headers,PAIR_RECONCILE,{})['structuredContent']['pair_absence_verified']
    assert radius.row is user.row is None and radius.deletes==user.deletes==1 and len(source.calls)==4
    audit=tuple(selected._pair._store.audit_events)
    assert audit[0].verification.value==('unknown'if lost_ack else'verified')
    env[runtime.PREFIX+'EXECUTION_ENABLED']='false'
    repeated=runtime.build_radius_remote_user_recovery_candidate(env)
    with TestClient(create_http_app(settings,v4_radius_user_recovery_candidate_action=repeated),base_url='https://mcp.example.com')as client:
        assert _call(client,headers,PAIR_PREVIEW,{})['isError']
        assert _call(client,headers,PAIR_RECONCILE,{})['structuredContent']['prior_m4_outcome_unchanged']
    assert tuple(repeated._pair._store.audit_events)==audit and radius.deletes==1


@pytest.mark.parametrize('mode', ['unattempted','no_ack_absent','no_ack_present','terminal_no_http_claim'])
def test_actual_cleanup_observation_through_plan_only_oauth_grants_no_user_delete(tmp_path: Path, monkeypatch: Any, mode: str) -> None:
    from fortipam_mcp.local_oauth import LocalOAuthProvider
    from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
    monkeypatch.setattr(time,'time',lambda:100.0)
    settings=_settings(tmp_path)
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com')as client:
        headers=_login(client,'fortipam:read fortipam:plan')
    bearer=next(v for k,v in headers.items()if k.lower()=='authorization').removeprefix('Bearer ')
    token=asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(bearer))
    principal=planning_principal_from_access_token(token,settings.v4_planning_authorization)
    root=tmp_path/'candidate';root.mkdir(mode=0o700)
    env,_,_,_,_,_,radius,user,source,identity,original=prepared(root,monkeypatch,mode=mode,
        identity=dict(requester_digest=principal.requester.digest,transport_digest=principal.transport_namespace_digest))
    selected=runtime.build_radius_remote_user_recovery_candidate(env)
    before=tuple(selected._workflow._original_store.audit_events)
    with TestClient(create_http_app(settings,v4_radius_user_recovery_candidate_action=selected),base_url='https://mcp.example.com')as client:
        result=_call(client,headers,INSPECT,{})
        assert not result['isError']
        body=result['structuredContent']
        assert body['user_absence_verified'] is (mode!='no_ack_present')
        assert not body['user_ownership_or_delete_authority_granted'] and not body['dispatch_retry_allowed']
        assert _call(client,headers,AUTHORIZE,{'preview_ref':'untrusted'})['isError']
        assert _call(client,headers,PREVIEW,{})['isError']
        assert _call(client,headers,PAIR_PREVIEW,{})['isError'] is (mode=='no_ack_present')
    assert radius.deletes==user.deletes==0 and len(source.calls)==4
    assert tuple(selected._workflow._original_store.audit_events)==before
