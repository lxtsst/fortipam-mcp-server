"""Early intent is durable provenance, not an ACK or dispatch capability."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import pytest
from fortipam_mcp import radius_remote_user_lifecycle_workflow as parent_module
from fortipam_mcp import radius_remote_user_recovery_runtime as runtime
from fortipam_mcp.radius_remote_user_preparation import NAME, load_radius_user_preparation
from fortipam_mcp.radius_remote_user_preparation_reader import RadiusRemoteUserPreparationReader
from test_radius_remote_user_recovery_runtime import prepared


def partial(root: Path, monkeypatch: Any, boundary: str, *, identity: dict[str, str] | None = None) -> tuple[Any, ...]:
    # The original parent stops at an actual preparation boundary; no test
    # deletes the missing declarations and no recovery writes replacements.
    original = parent_module.RadiusRemoteUserLifecycleWorkflow._build_users
    def stop(workflow: Any) -> None:
        if boundary == 'pre_kernel_marker':
            original(workflow)
            return
        if boundary == 'before_handoff':
            workflow._user_prepare_started=True
            raise RuntimeError('Synthetic stop before User preparation.')
        from fortipam_mcp.radius_remote_user_live_workflow import RadiusRemoteUserLiveWorkflow
        constructor=RadiusRemoteUserLiveWorkflow.__init__
        def initialize(self: Any,*a: Any,**k: Any) -> None:
            if k.get('operation','create')==('create' if boundary=='before_create_runtime' else 'remove'):
                raise RuntimeError('Synthetic User declaration failure.')
            constructor(self,*a,**k)
        with monkeypatch.context() as local:
            local.setattr(RadiusRemoteUserLiveWorkflow,'__init__',initialize)
            original(workflow)
    with monkeypatch.context() as scoped:
        scoped.setattr(parent_module.RadiusRemoteUserLifecycleWorkflow,'_build_users',stop)
        # This mode already expects zero User dispatch and both stores unused.
        values=prepared(root,scoped,mode='pre_kernel_marker' if boundary=='pre_kernel_marker' else 'unattempted',identity=identity)
    # Reinstall only the synthetic product connection for the new read-only role.
    user=values[7];radius=values[6]
    preparation=runtime.RadiusRemoteUserPreparationReader
    recovery=runtime.RadiusServerPairRecoveryWorkflow
    monkeypatch.setattr(runtime,'RadiusRemoteUserPreparationReader',lambda *a,**k:preparation(*a,**k,connection_factory=user.connection))
    monkeypatch.setattr(runtime,'RadiusServerPairRecoveryWorkflow',lambda *a,**k:recovery(*a,**k,connection_factory=radius.connection))
    return values


@pytest.mark.parametrize('boundary', ['before_handoff','before_create_runtime','before_remove_runtime','pre_kernel_marker'])
def test_partial_preparation_only_observes_and_removes_original_pair(tmp_path: Path, monkeypatch: Any, boundary: str) -> None:
    env,_,_,paths,_,pair_paths,radius,user,source,identity,original=partial(tmp_path,monkeypatch,boundary)
    directory=paths['user_state_directory']
    assert (directory/NAME).exists() and radius.row is not None
    if boundary=='before_handoff':assert not (directory/'radius-target.handoff.json').exists()
    before={p:p.read_bytes() for p in directory.iterdir()}
    counts=len(radius.connections),len(user.connections),len(source.calls)
    env[runtime.PREFIX+'EXECUTION_ENABLED']='true'
    selected=runtime.build_radius_remote_user_recovery_candidate(env)
    assert type(selected._workflow) is RadiusRemoteUserPreparationReader
    assert counts==(len(radius.connections),len(user.connections),len(source.calls))
    assert selected._workflow.inspect_cleanup_state(**identity)['evidence_mode']=='preparation_only_zero_claim'
    w=selected._pair;p=w.preview(**identity);a=w.authorize(p['preview_ref'],**identity)
    assert w.execute(a['authorization_ref'],**identity)['outcome']=='succeeded'
    assert w.reconcile(**identity)['pair_absence_verified']
    selected.close()
    assert user.posts==user.deletes==0 and radius.deletes==1 and radius.row is None and len(source.calls)==4
    assert before=={p:p.read_bytes() for p in directory.iterdir()}
    assert original._workflow._user_stores[0].claim_count==original._workflow._user_stores[1].claim_count==0
    assert original._workflow._pair._recovery._store.claim_count==1


def test_early_receipt_precedes_first_pair_source_or_dispatch(tmp_path: Path,monkeypatch: Any) -> None:
    from test_radius_remote_user_lifecycle_workflow import setup, IDENTITY, grant
    selected,radius,user,_,source,_,_=setup(tmp_path)
    original=selected._pair.execute
    observed=[]
    def execute(self: Any,ref: str,**identity: str) -> Any:
        path=selected._directory/NAME
        assert path.exists() and not source.calls and radius.posts==user.posts==0
        packet=json.loads(path.read_text())
        assert 'ownership_digest' not in packet['payload'] and 'original_execution_digest' not in packet['payload']
        c=selected._pair._create
        with pytest.raises(RuntimeError):
            load_radius_user_preparation(c._config,selected._binding,user_state_directory=selected._directory,
                radius_state_directory=c._directory,expected_serial=c._serial,original_radius_store=c._execution_store,
                user_stores=selected._user_stores,user_authority_keys=selected._user_keys,identity=packet['payload']['identity'])
        assert c._execution_store.claim_count==0 and not source.calls and radius.posts==0
        observed.append(True)
        return original(ref,**identity)
    monkeypatch.setattr(type(selected._pair),'execute',execute)
    result=selected.execute(grant(selected),**IDENTITY)
    assert observed and result['outcome']=='succeeded'


@pytest.mark.parametrize('fault', ['missing','signature','wrong_domain','identity','user_key','pair_key','original_m4',
    'creator_claim','remover_claim','foreign_runtime','foreign_file','copied_state'])
def test_preparation_recovery_refuses_foreign_or_uncertain_inputs_without_repair(tmp_path: Path,monkeypatch: Any,fault: str) -> None:
    env,manifest,path,paths,_,pair_paths,radius,user,source,_,original=partial(tmp_path,monkeypatch,'before_handoff')
    directory=paths['user_state_directory'];receipt=directory/NAME
    if fault=='missing':receipt.unlink()
    elif fault in {'signature','wrong_domain','identity'}:
        packet=json.loads(receipt.read_text())
        if fault=='signature':packet['signature']='f'*64
        elif fault=='identity':packet['payload']['identity']['user_create_scope_ref']='foreign-scope'
        else:
            from fortipam_mcp.radius_remote_user_pair_handoff import _signature
            packet['signature']=_signature(packet['payload'],paths['user_create_authority_key_file'].read_bytes())
        receipt.write_text(json.dumps(packet))
    elif fault=='user_key':paths['user_create_execution_key_file'].write_bytes(b'x'*32)
    elif fault=='pair_key':pair_paths['create_execution_key_file'].write_bytes(b'x'*32)
    elif fault=='original_m4':pair_paths['create_database_file'].write_bytes(b'CORRUPT_SYNTHETIC_M4')
    elif fault in {'creator_claim','remover_claim'}:
        selected=original._workflow._user_stores[int(fault=='remover_claim')]
        selected.claim(plan_ref='synthetic-foreign',requester_digest='1'*64,idempotency_digest='2'*64,
            context_digest='3'*64,authorization_digest='4'*64)
    elif fault=='foreign_runtime':
        target=directory/'user-create.runtime.json';target.write_text('{}');target.chmod(0o600)
    elif fault=='foreign_file':
        target=directory/'foreign.json';target.write_text('{}');target.chmod(0o600)
    else:
        copied=tmp_path/'copied';copied.mkdir(mode=0o700)
        for source_path in directory.iterdir():
            target=copied/source_path.name;target.write_bytes(source_path.read_bytes());target.chmod(0o600)
        manifest['paths']['user_state_directory']=str(copied);path.write_text(json.dumps(manifest))
    before={p:p.read_bytes() for p in directory.iterdir()}
    counts=len(radius.connections),len(user.connections),len(source.calls)
    with pytest.raises(ValueError):runtime.build_radius_remote_user_recovery_candidate(env)
    assert before=={p:p.read_bytes() for p in directory.iterdir()}
    assert counts==(len(radius.connections),len(user.connections),len(source.calls)) and radius.deletes==user.posts==user.deletes==0


@pytest.mark.parametrize('fault', ['present','collection','creator_claim','target_flag','key_drift'])
def test_preparation_drift_denies_before_pair_delete(tmp_path: Path,monkeypatch: Any,fault: str) -> None:
    env,_,_,paths,_,_,radius,user,source,identity,original=partial(tmp_path,monkeypatch,'before_handoff')
    env[runtime.PREFIX+'EXECUTION_ENABLED']='true'
    selected=runtime.build_radius_remote_user_recovery_candidate(env)
    p=selected._pair.preview(**identity)
    if fault=='present':user.row=user.defaults|{'name':user.username,'password':'SYNTHETIC_FOREIGN'}
    elif fault=='collection':user.empty_collection=True
    elif fault=='creator_claim':
        original._workflow._user_stores[0].claim(plan_ref='synthetic-foreign',requester_digest='1'*64,
            idempotency_digest='2'*64,context_digest='3'*64,authorization_digest='4'*64)
    elif fault=='target_flag':selected._workflow._target._recovery_only=False
    else:paths['user_create_execution_key_file'].write_bytes(b'x'*32)
    with pytest.raises(Exception):selected._pair.authorize(p['preview_ref'],**identity)
    assert radius.deletes==user.posts==user.deletes==0 and len(source.calls)==4
    selected.close()


@pytest.mark.parametrize('fault', ['write','file_fsync','directory_fsync','readback'])
def test_preparation_durability_failure_stops_before_pair_or_material_claim(tmp_path: Path,monkeypatch: Any,fault: str) -> None:
    import os,stat
    from test_radius_remote_user_lifecycle_workflow import setup, IDENTITY, grant
    from fortipam_mcp.radius_remote_user_http_transport import FortiPamRadiusRemoteUserHttpTransport
    selected,radius,user,_,source,_,_=setup(tmp_path)
    authorization=grant(selected)
    write=FortiPamRadiusRemoteUserHttpTransport._write_once
    read=FortiPamRadiusRemoteUserHttpTransport._read_state
    sync=os.fsync
    def writing(reader: Any,name: str,value: Any) -> None:
        if name==NAME and fault=='write':raise OSError('Synthetic preparation write failure.')
        write(reader,name,value)
    def reading(reader: Any,name: str) -> Any:
        if name==NAME and fault=='readback':raise OSError('Synthetic preparation readback failure.')
        return read(reader,name)
    def syncing(fd: int) -> None:
        kind='directory_fsync'if stat.S_ISDIR(os.fstat(fd).st_mode)else'file_fsync'
        if fault==kind:raise OSError('Synthetic preparation fsync failure.')
        sync(fd)
    monkeypatch.setattr(FortiPamRadiusRemoteUserHttpTransport,'_write_once',writing)
    monkeypatch.setattr(FortiPamRadiusRemoteUserHttpTransport,'_read_state',reading)
    monkeypatch.setattr(os,'fsync',syncing)
    result=selected.execute(authorization,**IDENTITY)
    assert result['outcome']=='reconciliation_required' and result['all_candidate_gates_closed']
    assert not source.calls and radius.posts==user.posts==radius.deletes==user.deletes==0
    assert selected._pair._create._execution_store.claim_count==selected._pair._create._material_store.claim_count==0
    assert selected._pair._create._group_store.claim_count==0


@pytest.mark.parametrize('boundary', ['before_handoff','before_create_runtime','before_remove_runtime','pre_kernel_marker'])
def test_partial_profile_exposes_only_observation_and_pair_tools_through_oauth(tmp_path: Path,monkeypatch: Any,boundary: str) -> None:
    import asyncio,time
    from starlette.testclient import TestClient
    from fortipam_mcp.http_server import create_http_app
    from fortipam_mcp.local_oauth import LocalOAuthProvider
    from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
    from test_radius_server_pair_lifecycle_mcp_action import _settings,_login,_call
    from test_radius_remote_user_recovery_mcp_action import INSPECT,PREVIEW,AUTHORIZE,EXECUTE,RECONCILE,PAIR_PREVIEW,PAIR_AUTHORIZE,PAIR_EXECUTE,PAIR_RECONCILE
    monkeypatch.setattr(time,'time',lambda:100.0)
    settings=_settings(tmp_path)
    with TestClient(create_http_app(settings),base_url='https://mcp.example.com')as client:
        headers=_login(client,'fortipam:read fortipam:plan fortipam:operate')
    bearer=next(v for k,v in headers.items()if k.lower()=='authorization').removeprefix('Bearer ')
    token=asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(bearer))
    principal=planning_principal_from_access_token(token,settings.v4_planning_authorization)
    root=tmp_path/'candidate';root.mkdir(mode=0o700)
    env,_,_,paths,_,_,radius,user,source,_,_=partial(root,monkeypatch,boundary,
        identity=dict(requester_digest=principal.requester.digest,transport_digest=principal.transport_namespace_digest))
    env[runtime.PREFIX+'EXECUTION_ENABLED']='true'
    before={p:p.read_bytes()for p in paths['user_state_directory'].iterdir()}
    selected=runtime.build_radius_remote_user_recovery_candidate(env)
    with TestClient(create_http_app(settings,v4_radius_user_recovery_candidate_action=selected),base_url='https://mcp.example.com')as client:
        listing=client.post('/fpamcp',headers=headers,json={'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}})
        data=listing.json()if listing.headers.get('content-type','').startswith('application/json')else json.loads(listing.text.split('data: ',1)[1])
        names={item['name']for item in data['result']['tools']}
        assert {INSPECT,PAIR_PREVIEW,PAIR_AUTHORIZE,PAIR_EXECUTE,PAIR_RECONCILE}<=names
        assert not {PREVIEW,AUTHORIZE,EXECUTE,RECONCILE}&names
        assert _call(client,headers,INSPECT,{})['structuredContent']['evidence_mode']=='preparation_only_zero_claim'
        p=_call(client,headers,PAIR_PREVIEW,{})['structuredContent']
        assert p['Current State']['user_preparation_only_zero_claim']
        a=_call(client,headers,PAIR_AUTHORIZE,{'preview_ref':p['preview_ref']})['structuredContent']
        r=_call(client,headers,PAIR_EXECUTE,{'authorization_ref':a['authorization_ref']})['structuredContent']
        assert r['outcome']=='succeeded'
    assert before=={p:p.read_bytes()for p in paths['user_state_directory'].iterdir()}
    assert radius.deletes==1 and user.posts==user.deletes==0 and len(source.calls)==4


@pytest.mark.parametrize('boundary', ['before_handoff','before_remove_runtime'])
def test_separate_process_recovers_partial_preparation_without_creating_declarations(tmp_path: Path,monkeypatch: Any,boundary: str) -> None:
    import subprocess,sys
    env,_,_,paths,_,pair_paths,radius,user,source,identity,original=partial(tmp_path,monkeypatch,boundary)
    env[runtime.PREFIX+'EXECUTION_ENABLED']='true'
    before={p:p.read_bytes()for p in paths['user_state_directory'].iterdir()}
    keys={p:p.read_bytes()for p in (*paths.values(),*pair_paths.values())if p.name.endswith('key_file.fixture')}
    packet=tmp_path/'restart.json'
    packet.write_text(json.dumps({'env':env,'identity':identity,'user':{'schema':user.schema,'defaults':user.defaults},
        'radius':{'row':radius.row,'defaults':radius.defaults}}));packet.chmod(0o600)
    code=r'''
import json,sys,time
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,sys.argv[2]);time.time=lambda:1000.0
from fortipam_mcp import radius_remote_user_recovery_runtime as runtime
from fortipam_mcp.radius_remote_user_contract import RadiusRemoteUserBinding
from fortipam_mcp.radius_server_pair_contract import RadiusServerPairBinding
from test_radius_remote_user_http_transport import Peer as UserPeer
from test_radius_server_pair_http_transport import Peer as RadiusPeer
m=json.loads(Path(sys.argv[1]).read_bytes())
manifest=json.loads(Path(m['env'][runtime.PREFIX+'STARTUP_MANIFEST_FILE']).read_bytes())
pair=json.loads(Path(manifest['pair_manifest_file']).read_bytes())
binding=RadiusRemoteUserBinding(radius=RadiusServerPairBinding(**pair['binding']),**manifest['binding'])
radius=RadiusPeer()
for k,v in m['radius'].items():setattr(radius,k,v)
user=UserPeer(SimpleNamespace(_binding=binding,_target=SimpleNamespace(_serial=pair['identity']['expected_serial'])),radius)
for k,v in m['user'].items():setattr(user,k,v)
probe=runtime.RadiusRemoteUserPreparationReader;recovery=runtime.RadiusServerPairRecoveryWorkflow
runtime.RadiusRemoteUserPreparationReader=lambda *a,**k:probe(*a,**k,connection_factory=user.connection)
runtime.RadiusServerPairRecoveryWorkflow=lambda *a,**k:recovery(*a,**k,connection_factory=radius.connection)
selected=runtime.build_radius_remote_user_recovery_candidate(m['env'])
assert selected._workflow.inspect_cleanup_state(**m['identity'])['evidence_mode']=='preparation_only_zero_claim'
p=selected._pair.preview(**m['identity']);a=selected._pair.authorize(p['preview_ref'],**m['identity'])
assert selected._pair.execute(a['authorization_ref'],**m['identity'])['outcome']=='succeeded'
assert selected._pair.reconcile(**m['identity'])['pair_absence_verified']
assert radius.posts==user.posts==user.deletes==0 and radius.deletes==1
selected.close();print('partial-preparation-recovery-verified')
'''
    result=subprocess.run([sys.executable,'-c',code,str(packet),str(Path(__file__).parent)],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='partial-preparation-recovery-verified'
    assert before=={p:p.read_bytes()for p in paths['user_state_directory'].iterdir()}
    assert all(p.read_bytes()==value for p,value in keys.items())
    assert all(store.claim_count==0 for store in original._workflow._user_stores)
    assert original._workflow._pair._recovery._store.claim_count==1 and len(source.calls)==4


@pytest.mark.parametrize('content', ['original', 'empty', 'partial'])
def test_zero_claim_signing_marker_never_becomes_user_authority(tmp_path: Path, monkeypatch: Any, content: str) -> None:
    env,_,_,paths,_,_,radius,user,source,identity,original=prepared(tmp_path,monkeypatch,mode='pre_kernel_marker')
    directory=paths['user_state_directory'];marker=directory/'user-create.authority.json'
    if content!='original':marker.write_bytes(b'' if content=='empty' else b'{"plan":')
    before={p:p.read_bytes() for p in directory.iterdir()}
    env[runtime.PREFIX+'EXECUTION_ENABLED']='true'
    selected=runtime.build_radius_remote_user_recovery_candidate(env)
    assert type(selected._workflow) is RadiusRemoteUserPreparationReader
    assert selected._workflow.inspect_cleanup_state(**identity)['evidence_mode']=='preparation_only_zero_claim'
    p=selected._pair.preview(**identity);a=selected._pair.authorize(p['preview_ref'],**identity)
    assert selected._pair.execute(a['authorization_ref'],**identity)['outcome']=='succeeded'
    selected.close()
    assert before=={p:p.read_bytes() for p in directory.iterdir()}
    assert all(s.claim_count==len(s.audit_events)==0 for s in original._workflow._user_stores)
    assert radius.deletes==1 and user.posts==user.deletes==0 and len(source.calls)==4


@pytest.mark.parametrize('fault', ['permissions','symlink','hardlink','oversize','creator_claim','remover_claim','http_claim'])
def test_zero_claim_marker_cannot_bypass_protected_files_or_consumed_user(tmp_path: Path, monkeypatch: Any, fault: str) -> None:
    env,_,_,paths,_,_,radius,user,source,_,original=prepared(tmp_path,monkeypatch,mode='pre_kernel_marker')
    directory=paths['user_state_directory'];marker=directory/'user-create.authority.json'
    if fault=='permissions':marker.chmod(0o644)
    elif fault=='symlink':
        target=tmp_path/'marker.fixture';marker.rename(target);marker.symlink_to(target)
    elif fault=='hardlink':
        import os
        os.link(marker,tmp_path/'marker.fixture')
    elif fault=='oversize':marker.write_bytes(b'x'*32769)
    elif fault in {'creator_claim','remover_claim'}:
        original._workflow._user_stores[int(fault=='remover_claim')].claim(plan_ref='synthetic-foreign',
            requester_digest='1'*64,idempotency_digest='2'*64,context_digest='3'*64,authorization_digest='4'*64)
    else:
        path=directory/'create.claim.json';path.write_bytes(b'{}');path.chmod(0o600)
    before=marker.read_bytes();counts=len(radius.connections),len(user.connections),len(source.calls)
    with pytest.raises(ValueError):runtime.build_radius_remote_user_recovery_candidate(env)
    assert marker.read_bytes()==before and counts==(len(radius.connections),len(user.connections),len(source.calls))
    assert radius.deletes==user.posts==user.deletes==0


def test_zero_claim_marker_drift_invalidates_prepared_pair_recovery(tmp_path: Path, monkeypatch: Any) -> None:
    env,_,_,paths,_,_,radius,user,source,identity,_=prepared(tmp_path,monkeypatch,mode='pre_kernel_marker')
    env[runtime.PREFIX+'EXECUTION_ENABLED']='true'
    selected=runtime.build_radius_remote_user_recovery_candidate(env)
    p=selected._pair.preview(**identity);a=selected._pair.authorize(p['preview_ref'],**identity)
    marker=paths['user_state_directory']/'user-create.authority.json'
    marker.write_bytes(b'{"partial":')
    with pytest.raises(Exception):selected._pair.execute(a['authorization_ref'],**identity)
    assert marker.read_bytes()==b'{"partial":' and radius.deletes==user.posts==user.deletes==0
    assert len(source.calls)==4
