"""Original recovery client ordering, exact contracts and terminal dispatch."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
import pytest
from scripts import v4_radius_remote_user_recovery_mcp_oauth_acceptance as client
from v4_planning import canonical_digest


@pytest.fixture(autouse=True)
def clock(monkeypatch: Any) -> None: monkeypatch.setattr(client.time, 'time', lambda: 100.0)


def payloads(*, preparation: bool = False) -> dict[str, Any]:
    # Use real summary projections here; integration below exercises real grants.
    from fortipam_mcp.radius_remote_user_live_workflow import _summary_values
    from fortipam_mcp.radius_server_pair_recovery_workflow import RadiusServerPairRecoveryWorkflow
    from fortipam_mcp.radius_remote_user_preparation_reader import RadiusRemoteUserPreparationReader
    user = _summary_values('remove', client.USER_CONTRACT, '1'*64,
        SimpleNamespace(preview_ref='radius-user-preview-'+'a'*64, created_at=100, expires_at=160))
    pair = object.__new__(RadiusServerPairRecoveryWorkflow)
    pair._namespace = {'requester_digest':'1'*64}
    pair._user_absence = SimpleNamespace(_reader=object.__new__(RadiusRemoteUserPreparationReader) if preparation else object())
    pair = pair._summary(SimpleNamespace(preview_ref='radius-pair-recovery-preview-'+'b'*64, created_at=100, expires_at=160))
    for p in (user, pair): p['summary_digest'] = canonical_digest(p)
    mode = 'preparation_only_zero_claim' if preparation else 'consumed_delete'
    data = {client.USER_PREVIEW:user, client.PAIR_PREVIEW:pair,
        client.INSPECT:{'contract':'fortipam-radius-user-cleanup-observation-private-v1','evidence_mode':mode,
            'observation':'absent_observed','user_absence_verified':True,'mutation_executed':False,
            'prior_m4_outcome_unchanged':True,'dispatch_retry_allowed':False,'user_ownership_or_delete_authority_granted':False}}
    for is_pair in (False, True):
        contract = client.PAIR_CONTRACT if is_pair else client.USER_CONTRACT
        data[client.PAIR_AUTHORIZE if is_pair else client.USER_AUTHORIZE] = {'contract':contract,'policy_mode':'lab_auto',
            'authorization_ref':('radius-pair-recovery-auth-' if is_pair else 'radius-user-auth-')+'c'*64,'expires_at':160}
        data[client.PAIR_EXECUTE if is_pair else client.USER_EXECUTE] = {'contract':contract,'outcome':'succeeded',
            'verification':'verified','compensation':'not_requested','idempotent_replay':False}
        data[client.PAIR_RECONCILE if is_pair else client.USER_RECONCILE] = {
            'contract':'fortipam-radius-associated-pair-delete-reconciliation-private-v1' if is_pair else
                'fortipam-radius-user-delete-reconciliation-private-v1','user_absence_verified':True,
            'mutation_executed':False,'prior_m4_outcome_unchanged':True,'dispatch_retry_allowed':False,
            **({'pair_absence_verified':True} if is_pair else {'pair_cleanup_performed':False})}
    return data


def inputs(root: Path) -> tuple[Path, Path, Path]:
    root.chmod(0o700)
    login=root/'login.json';login.write_text(json.dumps({'username':'private-user','password':'private-password'}));login.chmod(0o600)
    state=root/'client.json';state.write_text('synthetic-existing-client');state.chmod(0o600)
    return login,state,root/'dispatch.json'


@pytest.mark.parametrize('mode', client.MODES)
@pytest.mark.parametrize('failure', [None,'oauth','registered','tools','cleanup','cleanup_exception'])
def test_modes_use_only_required_scopes_and_tools_and_revoke(tmp_path: Path, monkeypatch: Any, mode: str, failure: str | None) -> None:
    login,state,marker=inputs(tmp_path); data=payloads();calls=[];revocations=[]
    mutation=mode in client.MUTATING
    class Session:
        async def initialize(self) -> None: pass
        async def list_tools(self) -> Any:
            return SimpleNamespace(tools=[SimpleNamespace(name=n) for n in (set() if failure=='tools' else client.MODE_TOOLS[mode])])
        async def call_tool(self,name: str,args: Any) -> Any:
            calls.append(name)
            if name in {client.USER_EXECUTE,client.PAIR_EXECUTE}:
                assert marker.exists() and marker.stat().st_mode&0o777==0o600
                assert json.loads(marker.read_text())=={'contract':client.DISPATCH_CONTRACT,'mode':mode,'dispatch_reserved':True,'retry_allowed':False}
            if name in {client.USER_AUTHORIZE,client.PAIR_AUTHORIZE}:
                preview=client.USER_PREVIEW if name==client.USER_AUTHORIZE else client.PAIR_PREVIEW
                assert args=={'preview_ref':data[preview]['preview_ref']}
            elif name in {client.USER_EXECUTE,client.PAIR_EXECUTE}:
                authorization=client.USER_AUTHORIZE if name==client.USER_EXECUTE else client.PAIR_AUTHORIZE
                assert args=={'authorization_ref':data[authorization]['authorization_ref']}
            else: assert args=={}
            return SimpleNamespace(is_error=False,structured_content=data[name])
    @asynccontextmanager
    async def session(*a: Any,**k: Any) -> Any:
        assert k['timeout_seconds']==180.0
        yield Session()
    async def token(*a: Any,**k: Any) -> Any:
        assert k['require_existing_client'] is True and k['include_operation_scope'] is mutation
        if failure=='oauth':raise ValueError('private-password')
        return 'private-token',failure=='registered',failure!='registered','private-client'
    async def revoke(*a: Any,**k: Any) -> bool:
        revocations.append(True)
        if failure=='cleanup_exception':raise ValueError('private-token')
        return failure!='cleanup'
    monkeypatch.setattr(client.oauth,'_oauth_token',token);monkeypatch.setattr(client.oauth,'_mcp_session',session)
    monkeypatch.setattr(client.oauth,'_revoke_and_prove_401',revoke)
    run=lambda:asyncio.run(client.run_radius_remote_user_recovery_mcp_oauth_acceptance('https://mcp.example/fpamcp',login,state,
        mode=mode,dispatch_state_file=marker if mutation else None))
    if failure is None:
        result=run()
        assert result['dispatch_reserved'] is mutation and result['user_remove_reported_verified'] is (mode=='recover-user-pair')
        assert result['pair_remove_reported_verified'] is mutation
        assert result['read_only_reconciliation_verified'] is (mode!='inspect-user')
        assert not result['retry_allowed'] and not result['user_authentication_qualified']
        assert 'private-' not in json.dumps(result)
    else:
        with pytest.raises(client.RadiusUserRecoveryAcceptanceError) as error:run()
        assert 'private-' not in str(error.value) and 'retry_allowed=false' in str(error.value)
    assert revocations==([] if failure=='oauth' else [True])
    if failure in {None,'cleanup','cleanup_exception'}:
        assert calls==({
            'recover-user-pair':[client.USER_PREVIEW,client.USER_AUTHORIZE,client.USER_EXECUTE,client.USER_RECONCILE,
                client.INSPECT,client.PAIR_PREVIEW,client.PAIR_AUTHORIZE,client.PAIR_EXECUTE,client.PAIR_RECONCILE],
            'recover-pair':[client.INSPECT,client.PAIR_PREVIEW,client.PAIR_AUTHORIZE,client.PAIR_EXECUTE,client.PAIR_RECONCILE],
            'inspect-user':[client.INSPECT],'reconcile-user':[client.USER_RECONCILE],'reconcile-pair':[client.PAIR_RECONCILE]})[mode]
    else:assert not calls
    assert marker.exists() is (mutation and failure in {None,'cleanup','cleanup_exception'})
    if marker.exists():
        before=list(calls)
        with pytest.raises(client.RadiusUserRecoveryAcceptanceError):run()
        assert calls==before


@pytest.mark.parametrize('failure', ['user_preview','user_authorization','user_execution','user_reconciliation','user_inspection',
    'pair_preview','pair_authorization','pair_execution','pair_reconciliation','unknown_user','unknown_pair',
    'file_fsync','directory_fsync','partial_marker','cancel_user','cancel_pair','expired_user','expired_pair','foreign_requester'])
def test_partial_runs_stop_without_retry_or_later_dispatch(tmp_path: Path, monkeypatch: Any, failure: str) -> None:
    login,state,marker=inputs(tmp_path);data=payloads();calls=[];revoked=[];syncs=[]
    stage_tools={'user_preview':client.USER_PREVIEW,'user_authorization':client.USER_AUTHORIZE,'user_execution':client.USER_EXECUTE,
        'user_reconciliation':client.USER_RECONCILE,'user_inspection':client.INSPECT,'pair_preview':client.PAIR_PREVIEW,
        'pair_authorization':client.PAIR_AUTHORIZE,'pair_execution':client.PAIR_EXECUTE,'pair_reconciliation':client.PAIR_RECONCILE}
    sync=os.fsync
    dump=json.dump
    def dumping(value: Any, stream: Any, **kwargs: Any) -> None:
        if failure=='partial_marker':
            stream.write('{')
            raise OSError('private-partial-marker')
        dump(value,stream,**kwargs)
    def syncing(fd: int) -> None:
        import stat
        which='directory_fsync' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file_fsync';syncs.append(which)
        if failure==which:raise OSError('private-fsync')
        sync(fd)
    class Session:
        async def initialize(self) -> None: pass
        async def list_tools(self) -> Any:return SimpleNamespace(tools=[SimpleNamespace(name=n) for n in client.MODE_TOOLS['recover-user-pair']])
        async def call_tool(self,name: str,args: Any) -> Any:
            calls.append(name)
            if name==client.PAIR_PREVIEW and failure=='foreign_requester':
                data[name]['requester_digest']='f'*64
                data[name]['summary_digest']=canonical_digest({k:v for k,v in data[name].items() if k!='summary_digest'})
            if name==stage_tools.get(failure):raise RuntimeError('private-tool')
            pair=name in {client.PAIR_EXECUTE,client.PAIR_AUTHORIZE}
            if name in {client.USER_EXECUTE,client.PAIR_EXECUTE}:
                assert syncs==['file_fsync','directory_fsync'] and marker.exists()
                if failure==('cancel_pair' if pair else 'cancel_user'):raise asyncio.CancelledError('private-cancel')
                if failure==('unknown_pair' if pair else 'unknown_user'):data[name]['outcome']='reconciliation_required'
            if name in {client.USER_AUTHORIZE,client.PAIR_AUTHORIZE} and failure==('expired_pair' if pair else 'expired_user'):
                data[name]['expires_at']=100
            return SimpleNamespace(is_error=False,structured_content=data[name])
    @asynccontextmanager
    async def session(*a: Any,**k: Any) -> Any:yield Session()
    async def token(*a: Any,**k: Any) -> Any:return 'private-token',False,True,'private-client'
    async def revoke(*a: Any,**k: Any) -> bool:revoked.append(True);return True
    monkeypatch.setattr(client.oauth,'_mcp_session',session);monkeypatch.setattr(client.oauth,'_oauth_token',token)
    monkeypatch.setattr(client.oauth,'_revoke_and_prove_401',revoke);monkeypatch.setattr(os,'fsync',syncing);monkeypatch.setattr(json,'dump',dumping)
    run=lambda:asyncio.run(client.run_radius_remote_user_recovery_mcp_oauth_acceptance('https://mcp.example/fpamcp',login,state,
        mode='recover-user-pair',dispatch_state_file=marker))
    with pytest.raises(client.RadiusUserRecoveryAcceptanceError) as error:run()
    assert revoked==[True] and 'private-' not in str(error.value)
    if failure.startswith('user_') or failure in {'unknown_user','cancel_user','expired_user','file_fsync','directory_fsync','partial_marker','foreign_requester'}:
        assert client.PAIR_EXECUTE not in calls
    assert calls.count(client.USER_EXECUTE)<=1 and calls.count(client.PAIR_EXECUTE)<=1
    if marker.exists():
        before=list(calls)
        with pytest.raises(client.RadiusUserRecoveryAcceptanceError):run()
        assert calls==before


@pytest.mark.parametrize('pair', [False,True])
@pytest.mark.parametrize('fault', ['digest','intent','guard','expiry','revision','extra'])
def test_valid_digest_never_approves_weaker_recovery(pair: bool, fault: str) -> None:
    p=payloads()[client.PAIR_PREVIEW if pair else client.USER_PREVIEW]
    if fault=='digest':p['summary_digest']='f'*64
    elif fault=='intent':p['Proposed Changes']['operation']='create'
    elif fault=='guard':p['Current State']['associated_user_dual_absence_verified' if pair else 'original_user_ack_and_context_required']=False
    elif fault=='expiry':p['expires_at']=161
    elif fault=='revision':p['summary_revision']=True
    else:p['private']='NEVER_RETURN'
    if fault!='digest':p['summary_digest']=canonical_digest({k:v for k,v in p.items() if k!='summary_digest'})
    with pytest.raises(RuntimeError):client._validate_preview(p,pair=pair)


@pytest.mark.parametrize('fault', ['missing_client','unsafe_login','symlink','consumed','collision','http','missing_marker','readonly_marker','mode'])
def test_invalid_input_refuses_before_oauth(tmp_path: Path, monkeypatch: Any, fault: str) -> None:
    login,state,marker=inputs(tmp_path);mode='recover-pair';url='https://mcp.example/fpamcp'
    if fault=='missing_client':state.unlink()
    elif fault=='unsafe_login':login.chmod(0o644)
    elif fault=='symlink':original=login;login=tmp_path/'link';login.symlink_to(original)
    elif fault=='consumed':marker.write_bytes(b'');marker.chmod(0o600)
    elif fault=='collision':state=login
    elif fault=='http':url='http://mcp.example/fpamcp'
    elif fault=='missing_marker':marker=None
    elif fault=='readonly_marker':mode='inspect-user'
    else:mode='unsupported'
    monkeypatch.setattr(client.oauth,'_oauth_token',lambda *a,**k:pytest.fail('Unexpected OAuth request.'))
    with pytest.raises(client.RadiusUserRecoveryAcceptanceError):
        asyncio.run(client.run_radius_remote_user_recovery_mcp_oauth_acceptance(url,login,state,mode=mode,dispatch_state_file=marker))


@pytest.mark.parametrize('state,mode', [('created','recover-user-pair'),('unattempted','recover-pair'),
    ('pre_kernel_marker','recover-pair'),('no_ack_absent','recover-pair'),('terminal_no_http_claim','recover-pair'),
    ('no_ack_present','inspect-user'),('unknown_user_delete','reconcile-user'),('unknown_pair_delete','reconcile-pair')])
def test_client_against_actual_oauth_mcp_and_original_stores(tmp_path: Path, monkeypatch: Any, state: str, mode: str) -> None:
    from starlette.testclient import TestClient
    from fortipam_mcp.http_server import create_http_app
    from fortipam_mcp.local_oauth import LocalOAuthProvider
    from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
    from fortipam_mcp import radius_remote_user_recovery_runtime as runtime
    from test_radius_remote_user_recovery_runtime import prepared
    from test_radius_server_pair_lifecycle_mcp_action import _settings,_login,_call
    login,client_file,marker=inputs(tmp_path)
    settings=_settings(tmp_path)
    scope='fortipam:read fortipam:plan'+(' fortipam:operate' if mode in client.MUTATING else '')
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com') as http:
        headers=_login(http,scope)
    bearer=next(v for k,v in headers.items() if k.lower()=='authorization').removeprefix('Bearer ')
    token=asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(bearer))
    principal=planning_principal_from_access_token(token,settings.v4_planning_authorization)
    root=tmp_path/'candidate';root.mkdir(mode=0o700)
    env,_,_,paths,_,_,radius,user,source,identity,original=prepared(root,monkeypatch,
        mode='created' if state.startswith('unknown_') else state,
        identity=dict(requester_digest=principal.requester.digest,transport_digest=principal.transport_namespace_digest))
    env[runtime.PREFIX+'EXECUTION_ENABLED']='true'
    selected=runtime.build_radius_remote_user_recovery_candidate(env)
    if state.startswith('unknown_'):
        if state=='unknown_user_delete':user.lost_delete_ack=True
        p=selected._workflow.preview(**identity);a=selected._workflow.authorize(p['preview_ref'],**identity)
        r=selected._workflow.execute(a['authorization_ref'],**identity)
        assert r['outcome']==('reconciliation_required' if state=='unknown_user_delete' else 'succeeded')
        if state=='unknown_pair_delete':
            radius.lost_delete_ack=True
            p=selected._pair.preview(**identity);a=selected._pair.authorize(p['preview_ref'],**identity)
            assert selected._pair.execute(a['authorization_ref'],**identity)['outcome']=='reconciliation_required'
        selected.close();env[runtime.PREFIX+'EXECUTION_ENABLED']='false'
        selected=runtime.build_radius_remote_user_recovery_candidate(env)
    before_user=tuple(original._workflow._user_stores[0].audit_events)
    before_remove=tuple(original._workflow._user_stores[1].audit_events)
    before_pair=tuple(original._workflow._pair._recovery._store.audit_events)
    directory=paths['user_state_directory']
    before_files={p:p.read_bytes() for p in directory.iterdir()}
    calls=[];revocations=[]
    revoke_and_prove=client.oauth._revoke_and_prove_401
    with TestClient(create_http_app(settings,v4_radius_user_recovery_candidate_action=selected),base_url='https://mcp.example.com') as http:
        class Session:
            async def initialize(self) -> None: pass
            async def list_tools(self) -> Any:
                reply=http.post('/fpamcp',headers=headers,json={'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}})
                data=reply.json() if reply.headers.get('content-type','').startswith('application/json') else json.loads(reply.text.split('data: ',1)[1])
                return SimpleNamespace(tools=[SimpleNamespace(name=t['name']) for t in data['result']['tools']])
            async def call_tool(self,name: str,args: Any) -> Any:
                calls.append(name);reply=_call(http,headers,name,args)
                return SimpleNamespace(is_error=reply.get('isError',False),structured_content=reply.get('structuredContent'))
        @asynccontextmanager
        async def session(*a: Any,**k: Any) -> Any:yield Session()
        async def existing_token(*a: Any,**k: Any) -> Any:return bearer,False,True,token.client_id
        class HttpAdapter:
            async def post(self,url: str,**kwargs: Any) -> Any:return http.post(url,**kwargs)
        async def revoke(*a: Any,**k: Any) -> bool:
            result=await revoke_and_prove(HttpAdapter(),a[1],a[2],a[3],a[4]);revocations.append(result);return result
        monkeypatch.setattr(client.oauth,'_mcp_session',session);monkeypatch.setattr(client.oauth,'_oauth_token',existing_token)
        monkeypatch.setattr(client.oauth,'_revoke_and_prove_401',revoke)
        proof=asyncio.run(client.run_radius_remote_user_recovery_mcp_oauth_acceptance('https://mcp.example.com/fpamcp',login,client_file,
            mode=mode,dispatch_state_file=marker if mode in client.MUTATING else None))
    assert proof['token_revoked'] and revocations==[True] and 'radius-user-auth-' not in json.dumps(proof)
    assert tuple(original._workflow._user_stores[0].audit_events)==before_user
    assert len(source.calls)==4 and radius.posts==1
    if mode in {'recover-pair','inspect-user','reconcile-user','reconcile-pair'}:
        assert before_files=={p:p.read_bytes() for p in directory.iterdir()}
        assert tuple(original._workflow._user_stores[1].audit_events)==before_remove
        assert client.USER_EXECUTE not in calls
    if mode.startswith('reconcile-'):
        assert tuple(original._workflow._pair._recovery._store.audit_events)==before_pair
        assert not marker.exists() and not {client.USER_EXECUTE,client.PAIR_EXECUTE}&set(calls)
    if mode in client.MUTATING:assert radius.row is None and user.row is None and radius.deletes==1
