"""Exact associated client contracts, terminal dispatch and OAuth cleanup."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from scripts import v4_radius_remote_user_lifecycle_mcp_oauth_acceptance as client
from v4_planning import canonical_digest


@pytest.fixture(autouse=True)
def clock(monkeypatch: Any) -> None: monkeypatch.setattr(client.time,'time',lambda:100.0)


def payloads() -> dict[str, Any]:
    preview={'contract':client.CONTRACT,'policy_mode':'lab_auto','summary_revision':1,
        'preview_ref':'radius-user-lifecycle-preview-'+'a'*64,'expires_at':160,'requester_digest':'1'*64,
        'Current State':{'pair_create_summary_digest':'2'*64,'fresh_unclaimed_user_journal':True,
            'dependent_user_preflight':'after_owned_pair_before_user_dispatch'},
        'Proposed Changes':{'scope':'one_fresh_pair_and_one_disabled_remote_user','child_m4_actions':6,
            'user_status':'disable','user_profile':'Standard','user_wildcard':False,'group_association':False,'login_or_credential_probe':False},
        'Expected State':{'original_child_m4_required':True,'user_removed_before_pair':True,'both_final_dual_absence_required':True,
            'all_candidate_gates_closed':True,'user_authentication_qualified':False,'automatic_failover_qualified':False},
        'authorization_and_approval':{'mode':'standing_owner_lab_authority','parent_grants_no_child_dispatch':True},
        'risk_and_effects':{'class':'C3','effect':'one_bounded_pair_and_disabled_user_lifecycle'},
        'unresolved_gaps':['user_enable','user_authentication','automatic_failover','group_mapping','version_1_9_1'],
        'compensation_and_stop':{'order':['original_owned_user','original_owned_pair'],
            'missing_ack_or_uncertain_delete':'retain_claims_read_only_reconcile_no_replay'},'device_write_executed':False}
    preview['summary_digest']=canonical_digest(preview)
    authorization={'contract':client.CONTRACT,'policy_mode':'lab_auto','authorization_ref':'radius-user-lifecycle-auth-'+'b'*64,'expires_at':160}
    result={'contract':client.CONTRACT,'outcome':'succeeded','verification':'verified','idempotent_replay':False,
        'pair_configure_verified':True,'user_create_verified':True,'user_remove_verified':True,'user_absence_verified':True,
        'pair_remove_verified':True,'pair_absence_verified':True,'all_candidate_gates_closed':True,
        'user_authentication_qualified':False,'automatic_failover_qualified':False,'failure_stage':None}
    return {client.PREVIEW_TOOL:preview,client.AUTHORIZE_TOOL:authorization,client.EXECUTE_TOOL:result}


def test_lifecycle_wait_reaches_real_session_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    timeouts: list[float] = []

    class HttpClient:
        def __init__(self, **kwargs: Any) -> None:
            timeouts.append(kwargs['timeout'])

        async def aclose(self) -> None:
            pass

    @asynccontextmanager
    async def stream(url: str, **kwargs: Any) -> Any:
        yield object(), object()

    @asynccontextmanager
    async def session(*args: Any) -> Any:
        yield object()

    monkeypatch.setattr(client.oauth.httpx2, 'AsyncClient', HttpClient)
    monkeypatch.setattr(client.oauth, 'streamable_http_client', stream)
    monkeypatch.setattr(client.oauth, 'ClientSession', session)

    async def run() -> None:
        async with client.oauth._mcp_session('https://mcp.example/fpamcp', 'synthetic-token',
                True, timeout_seconds=client.MCP_TIMEOUT_SECONDS):
            pass

    asyncio.run(run())
    assert timeouts == [480.0]
    with pytest.raises(client.oauth.V4HttpsOAuthAcceptanceError, match='MCP timeout is invalid'):
        client.oauth._mcp_session('https://mcp.example/fpamcp', 'synthetic-token',
            True, timeout_seconds=480.001)
    assert timeouts == [480.0]


@pytest.mark.parametrize('failure',[None,'oauth','registered','tools','preview','digest','authorization','execute','result','cancelled','cleanup','cleanup_exception','reserve_file','reserve_directory'])
def test_once_only_with_revocation_on_success_failure_or_cancel(tmp_path: Path, monkeypatch: Any, failure: str | None) -> None:
    tmp_path.chmod(0o700)
    login=tmp_path/'login.json'; login.write_text(json.dumps({'username':'private-login','password':'private-password'}));login.chmod(0o600)
    state=tmp_path/'client.json';state.write_text('synthetic-existing-client');state.chmod(0o600)
    marker=tmp_path/'dispatch.json'; data=payloads();calls=[];revocations=[];syncs=[]
    if failure=='preview':data[client.PREVIEW_TOOL]['Proposed Changes']['user_status']='enable'
    elif failure=='digest':data[client.PREVIEW_TOOL]['summary_digest']='f'*64
    elif failure=='authorization':data[client.AUTHORIZE_TOOL]['expires_at']=159
    elif failure=='result':data[client.EXECUTE_TOOL]['user_absence_verified']=False
    class Session:
        async def initialize(self) -> None: calls.append('initialize')
        async def list_tools(self) -> Any:
            names=client.TOOLS-({client.EXECUTE_TOOL}if failure=='tools'else set())
            return SimpleNamespace(tools=[SimpleNamespace(name=n) for n in names])
        async def call_tool(self,name: str,args: Any) -> Any:
            calls.append(name)
            if name==client.PREVIEW_TOOL:assert args=={}
            elif name==client.AUTHORIZE_TOOL:assert args=={'preview_ref':data[client.PREVIEW_TOOL]['preview_ref']}
            else:
                assert args=={'authorization_ref':data[client.AUTHORIZE_TOOL]['authorization_ref']}
                assert marker.exists() and marker.stat().st_mode&0o777==0o600 and syncs==['file','directory']
                assert json.loads(marker.read_text())=={'contract':client.DISPATCH_CONTRACT,'dispatch_reserved':True,'retry_allowed':False}
                if failure=='execute':raise RuntimeError('private-reference')
                if failure=='cancelled':raise asyncio.CancelledError('private-reference')
            return SimpleNamespace(is_error=False,structured_content=data[name])
    @asynccontextmanager
    async def session(*a: Any,**k: Any) -> Any:
        assert k['timeout_seconds']==480.0
        yield Session()
    async def token(*a: Any,**k: Any) -> Any:
        assert k['require_existing_client']is True and k['include_operation_scope']is True
        if failure=='oauth':raise ValueError('private-password')
        return 'private-token',failure=='registered',failure!='registered','private-client'
    async def revoke(*a: Any,**k: Any) -> bool:
        revocations.append(True)
        if failure=='cleanup_exception':raise ValueError('private-token')
        return failure!='cleanup'
    def fsync(fd: int) -> None:
        import stat
        which='directory'if stat.S_ISDIR(os.fstat(fd).st_mode)else 'file';syncs.append(which)
        if failure=='reserve_'+which:raise OSError('private-marker')
    monkeypatch.setattr(client.oauth,'_oauth_token',token);monkeypatch.setattr(client.oauth,'_mcp_session',session)
    monkeypatch.setattr(client.oauth,'_revoke_and_prove_401',revoke);monkeypatch.setattr(client.os,'fsync',fsync)
    run=lambda:asyncio.run(client.run_radius_remote_user_lifecycle_mcp_oauth_acceptance('https://mcp.example/fpamcp',login,state,marker))
    if failure is None:
        proof=run()
        assert proof['both_dual_absence_reported_verified']and not proof['user_authentication_qualified']
        assert proof['token_revoked']and proof['revoked_access_rejected']and not proof['retry_allowed']
        assert 'private-'not in json.dumps(proof)and 'radius-user-lifecycle-'not in json.dumps(proof)
    else:
        with pytest.raises(client.RadiusUserLifecycleAcceptanceError)as error:run()
        assert 'private-'not in str(error.value)and 'radius-user-lifecycle-'not in str(error.value)
        assert 'retry_allowed=false'in str(error.value)and f'dispatch_reserved={str(marker.exists()).lower()}'in str(error.value)
    assert revocations==([]if failure=='oauth'else[True])
    assert calls.count(client.EXECUTE_TOOL)==int(failure in {None,'execute','result','cancelled','cleanup','cleanup_exception'})
    if marker.exists():
        before=list(calls)
        with pytest.raises(client.RadiusUserLifecycleAcceptanceError):run()
        assert calls==before


@pytest.mark.parametrize('field',['pair_configure_verified','user_create_verified','user_remove_verified','user_absence_verified',
    'pair_remove_verified','pair_absence_verified','all_candidate_gates_closed','user_authentication_qualified',
    'automatic_failover_qualified','idempotent_replay','verification','failure_stage','extra'])
def test_execution_cannot_weaken_success_or_promote_authentication(field: str) -> None:
    body=payloads()[client.EXECUTE_TOOL]
    body[field]='changed'if field=='verification'else 'unexpected'if field=='failure_stage'else False if body.get(field)is True else True
    with pytest.raises(client.RadiusUserLifecycleAcceptanceError):client._validate_execution(body)


@pytest.mark.parametrize('fault',['status','profile','wildcard','group','probe','order','children','gap','grant','typed_bool','future','expired','extra'])
def test_recomputed_summary_cannot_approve_different_intent(fault: str) -> None:
    p=payloads()[client.PREVIEW_TOOL]
    if fault=='status':p['Proposed Changes']['user_status']='enable'
    elif fault=='profile':p['Proposed Changes']['user_profile']='Administrator'
    elif fault=='wildcard':p['Proposed Changes']['user_wildcard']=True
    elif fault=='group':p['Proposed Changes']['group_association']=True
    elif fault=='probe':p['Proposed Changes']['login_or_credential_probe']=True
    elif fault=='order':p['compensation_and_stop']['order'].reverse()
    elif fault=='children':p['Proposed Changes']['child_m4_actions']=5
    elif fault=='gap':p['unresolved_gaps'].remove('user_authentication')
    elif fault=='grant':p['authorization_and_approval']['parent_grants_no_child_dispatch']=False
    elif fault=='typed_bool':p['summary_revision']=True
    elif fault=='future':p['expires_at']=161
    elif fault=='expired':p['expires_at']=100
    else:p['private']='NEVER_RETURN'
    p['summary_digest']=canonical_digest({k:v for k,v in p.items()if k!='summary_digest'})
    with pytest.raises(client.RadiusUserLifecycleAcceptanceError):client._validate_preview(p)


@pytest.mark.parametrize('fault',['missing_client','unsafe_login','symlink','consumed','collision','http'])
def test_bad_inputs_refuse_before_oauth(tmp_path: Path,monkeypatch: Any,fault: str) -> None:
    login=tmp_path/'login.json';login.write_text(json.dumps({'username':'synthetic','password':'synthetic'}));login.chmod(0o600)
    state=tmp_path/'client.json';state.write_text('synthetic');state.chmod(0o600)
    marker=tmp_path/'dispatch.json';url='https://mcp.example/fpamcp'
    if fault=='missing_client':state.unlink()
    elif fault=='unsafe_login':login.chmod(0o644)
    elif fault=='symlink':old=login;login=tmp_path/'link';login.symlink_to(old)
    elif fault=='consumed':marker.write_text('{}');marker.chmod(0o600)
    elif fault=='collision':state=login
    else:url='http://mcp.example/fpamcp'
    monkeypatch.setattr(client.oauth,'_oauth_token',lambda *a,**k:pytest.fail('Unexpected OAuth call'))
    with pytest.raises(client.RadiusUserLifecycleAcceptanceError):
        asyncio.run(client.run_radius_remote_user_lifecycle_mcp_oauth_acceptance(url,login,state,marker))
