"""Exact external-client contract, one terminal dispatch and OAuth cleanup."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import stat
import time
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import v4_radius_server_pair_lifecycle_mcp_oauth_acceptance as acceptance
from scripts import v4_https_oauth_acceptance as oauth
from v4_planning import canonical_digest


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time,'time',lambda:100.0)


def payloads(mode: str='disposable') -> dict[str,Any]:
    preview={'contract':acceptance.CONTRACT,'policy_mode':'lab_auto','summary_revision':1,
        'preview_ref':'radius-pair-lifecycle-preview-'+'a'*64,'expires_at':160,
        'Current State':{'bound_entry_absent':True,'schema_defaults_qualified':True,'dual_absence_verified':True,'child_dispatches_unconsumed':True},
        'Proposed Changes':{'operation':'qualify_disposable_radius_pair','fixed_sequence':['create','observe_primary','observe_secondary','original_ack_remove'],
            'material_endpoint_acquisitions_maximum':2,'material_pair_leases_maximum':1,'user_group_associations':False},
        'Expected State':{'original_child_m4_success_required':True,'both_ordinal_observations_recorded':True,
            'full_created_state_preserved':True,'final_dual_absence_required':True,'all_candidate_gates_closed':True,'connectivity_qualified':False},
        'authorization_and_approval':{'mode':'standing_owner_lab_authority','child_authorizations_independent':True},
        'unresolved_gaps':['protocol_and_material_application','automatic_failover','user_login'],
        'compensation_and_stop':{'failure':'stop_remaining_observations_and_attempt_qualified_original_ack_recovery','uncertain_result':'retain_consumed_claims_without_replay'},
        'device_write_executed':False}
    preview['summary_digest']=canonical_digest(preview)
    authorization={'contract':acceptance.CONTRACT,'policy_mode':'lab_auto','authorization_ref':'radius-pair-lifecycle-auth-'+'b'*64,'expires_at':160}
    result={'contract':acceptance.CONTRACT,'outcome':'succeeded','verification':'verified','idempotent_replay':False,
        'execution_scope':'disposable_pair_lifecycle','create_verified':True,'ordinal_observations_verified':{'primary':True,'secondary':True},
        'original_ack_removal_verified':True,'connectivity_qualified':False,'user_authentication_verified':False,
        'all_candidate_gates_closed':True,'failure_stage':None}
    tools=(acceptance.PREVIEW_TOOL,acceptance.AUTHORIZE_TOOL,acceptance.EXECUTE_TOOL)
    if mode=='configure':
        tools=acceptance.CONFIGURE_TOOLS
        for item in(preview,authorization,result):item['contract']=acceptance.PERSISTENT_CONTRACT
        preview['Proposed Changes']['operation']='configure_radius_pair'
        preview['Proposed Changes']['fixed_sequence']=['create','observe_primary','observe_secondary']
        preview['Expected State'].pop('final_dual_absence_required')
        preview['Expected State'].update(exact_reject_only_response_required=True,owned_entry_retained=True,independent_original_ack_removal_available=True)
        result.update(execution_scope='persistent_pair_configure',owned_entry_retained=True,exact_reject_only_responses_verified=True,original_ack_removal_verified=False)
    elif mode=='remove':
        tools=acceptance.REMOVE_TOOLS
        preview={'contract':acceptance.REMOVAL_CONTRACT,'policy_mode':'lab_auto','summary_revision':1,
            'preview_ref':'radius-pair-recovery-preview-'+'a'*64,'expires_at':160,'requester_digest':'1'*64,
            'environment':'privately_bound_disposable_lab','unchanged_boundary':['other_identity_servers','users_groups_and_roles'],
            'Current State':{'original_creation_ack_verified':True,'full_state_unchanged':True,'zero_references':True,'observed_at':100},
            'Proposed Changes':{'operation':'remove_original_owned_radius_pair_row','material_access':False},
            'Expected State':{'exact_detail_absent':True,'complete_collection_absent':True},
            'dependencies':['original_pair_creation_ack','fresh_complete_unchanged_state','independent_recovery_ledger'],
            'risk_and_effects':{'effect':'remove_one_unassociated_owned_lab_row'},
            'authorization_and_approval':{'mode':'standing_owner_lab_authority','independent_human_approval':False},
            'facts':{'source':'original_pair_ack_and_fresh_full_cmdb_state','freshness_seconds':60},
            'assumptions':['owner_authorized_disposable_lab_scope'],'unresolved_gaps':[],
            'verification':['original_delete_ack','dual_absence'],
            'compensation_and_stop':{'uncertain_result':'retain_claims_and_reconcile_without_replay'},'device_write_executed':False}
        authorization={'contract':acceptance.REMOVAL_CONTRACT,'policy_mode':'lab_auto','authorization_ref':'radius-pair-recovery-auth-'+'b'*64,'expires_at':160}
        result={'contract':acceptance.REMOVAL_CONTRACT,'outcome':'succeeded','verification':'verified','compensation':'not_requested','idempotent_replay':False}
    preview['summary_digest']=canonical_digest({k:v for k,v in preview.items()if k!='summary_digest'})
    return dict(zip(tools,(preview,authorization,result)))


@pytest.mark.parametrize('mode',['disposable','configure','remove'])
@pytest.mark.parametrize('failure',[None,'oauth','new_client','tools','preview','summary','authorization','execute','cancelled','result',
    'cleanup','cleanup_exception','file_fsync','directory_fsync','expired_before_execute','error_reply','removal_tools'])
def test_one_shot_dispatch_cleanup_and_scrubbed_failure(tmp_path: Path,monkeypatch: pytest.MonkeyPatch,failure: str | None,mode: str) -> None:
    tmp_path.chmod(0o700)
    marker=tmp_path/'dispatch.json';login=tmp_path/'login.json';client_state=tmp_path/'client.json'
    login.write_text(json.dumps({'username':'private-login','password':'private-login'}));login.chmod(0o600)
    client_state.write_text('synthetic-existing-client');client_state.chmod(0o600)
    data=payloads(mode);calls=[];cleanups=[];syncs=[]
    preview_tool,authorize_tool,execute_tool=tuple(data)
    selected_tools=set(acceptance.CONFIGURE_TOOLS)|set(acceptance.REMOVE_TOOLS)if mode!='disposable'else acceptance.TOOLS
    if failure=='preview':data[preview_tool]['raw']='private-source-value'
    elif failure=='summary':data[preview_tool]['summary_digest']='f'*64
    elif failure=='authorization':data[authorize_tool]['expires_at']=159
    elif failure=='result':data[execute_tool]['verification']='unknown'
    class Session:
        async def initialize(self) -> None:calls.append('initialize')
        async def list_tools(self) -> Any:
            names=selected_tools-({execute_tool}if failure=='tools'else {acceptance.REMOVE_TOOLS[-1]}if failure=='removal_tools'and mode=='configure'else set())
            return SimpleNamespace(tools=[SimpleNamespace(name=n) for n in names])
        async def call_tool(self,name: str,arguments: Any) -> Any:
            calls.append(name)
            if name==preview_tool:assert arguments=={}
            elif name==authorize_tool:assert arguments=={'preview_ref':data[preview_tool]['preview_ref']}
            else:
                assert arguments=={'authorization_ref':data[authorize_tool]['authorization_ref']}
                assert marker.exists() and marker.stat().st_mode & 0o777==0o600 and syncs==['file','directory']
                assert json.loads(marker.read_text())=={'contract':acceptance.DISPATCH_CONTRACT,'dispatch_reserved':True,'retry_allowed':False}
                if failure=='execute':raise RuntimeError('private-source-value')
                if failure=='cancelled':raise asyncio.CancelledError('private-source-value')
            return SimpleNamespace(is_error=failure=='error_reply',structured_content=data[name])
    @asynccontextmanager
    async def session(*a: Any,**k: Any) -> Any:
        assert k['timeout_seconds']==300.0
        yield Session()
    async def token(*a: Any,**k: Any) -> Any:
        calls.append('token')
        assert k['include_operation_scope'] and k['require_existing_client']
        if failure=='oauth':raise RuntimeError('private-login')
        return 'private-token',failure=='new_client',failure!='new_client','private-client'
    async def revoke(*a: Any) -> bool:
        cleanups.append(True)
        if failure=='cleanup_exception':raise RuntimeError('private-source-value')
        return failure!='cleanup'
    real_fsync=os.fsync
    def fsync(fd: int) -> None:
        kind='directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file';syncs.append(kind)
        if failure==kind+'_fsync':raise OSError('private-source-value')
        real_fsync(fd)
        if failure=='expired_before_execute' and kind=='directory':monkeypatch.setattr(time,'time',lambda:160.0)
    monkeypatch.setattr(os,'fsync',fsync);monkeypatch.setattr(oauth,'_mcp_session',session)
    monkeypatch.setattr(oauth,'_oauth_token',token);monkeypatch.setattr(oauth,'_revoke_and_prove_401',revoke)
    def run() -> Any:
        return asyncio.run(acceptance.run_radius_server_pair_lifecycle_mcp_oauth_acceptance('https://synthetic.example.test/mcp',login,client_state,marker,persistent_pair=mode=='configure',remove_owned_pair=mode=='remove'))
    if failure is None or failure=='removal_tools'and mode!='configure':
        result=run()
        assert result['token_revoked']and result['revoked_access_rejected']and not result['dynamic_client_registration_performed']
        assert not result['retry_allowed']and not result['references_returned']
        if mode=='configure':
            assert result['owned_entry_retained_reported']and result['exact_reject_only_responses_reported_verified']
            assert not result['final_dual_absence_reported_verified']and not result['original_ack_removal_reported_verified']
            assert not result['retained_pair_qualified']and not result['connectivity_qualified']
        elif mode=='remove':
            assert result['original_ack_cpe_and_summary_verified']and result['independent_authorization_verified']
            assert result['original_ack_removal_reported_verified']and result['final_dual_absence_reported_verified']
        else:
            assert result['parent_cpe_and_summary_verified']and result['both_ordinal_observations_reported_verified']
            assert result['original_ack_removal_reported_verified']and result['final_dual_absence_reported_verified']
            assert not result['connectivity_qualified']and not result['retained_pair_qualified']
        assert 'private-'not in json.dumps(result)and 'radius-pair-'not in json.dumps(result)
    else:
        with pytest.raises(acceptance.RadiusPairLifecycleMcpOAuthAcceptanceError) as error:run()
        assert 'private-' not in str(error.value) and 'radius-pair-lifecycle-' not in str(error.value)
        assert 'retry_allowed=false' in str(error.value) and f'dispatch_reserved={str(marker.exists()).lower()}' in str(error.value)
    assert cleanups==([] if failure=='oauth' else [True])
    assert calls.count(execute_tool)==int(failure in {None,'execute','cancelled','result','cleanup','cleanup_exception'}or failure=='removal_tools'and mode!='configure')
    if marker.exists():
        before=list(calls)
        with pytest.raises(acceptance.RadiusPairLifecycleMcpOAuthAcceptanceError):run()
        assert calls==before


@pytest.mark.parametrize('field',['create_verified','primary','secondary','original_ack_removal_verified','all_candidate_gates_closed',
    'connectivity_qualified','user_authentication_verified','idempotent_replay','verification','extra'])
def test_result_cannot_drop_child_success_or_promote_connectivity(field: str) -> None:
    result=payloads()[acceptance.EXECUTE_TOOL]
    if field in {'primary','secondary'}:result['ordinal_observations_verified'][field]=False
    elif field in {'connectivity_qualified','user_authentication_verified','idempotent_replay'}:result[field]=True
    elif field=='verification':result[field]='unknown'
    elif field=='extra':result['raw']='private-source-value'
    else:result[field]=False
    with pytest.raises(acceptance.RadiusPairLifecycleMcpOAuthAcceptanceError):acceptance._validate_execution(result)


@pytest.mark.parametrize('change',['sequence','extra','boolean_count','scope','summary','gaps','revision','primary_contract'])
def test_preview_cannot_change_intent_even_with_recomputed_digest(change: str) -> None:
    preview=payloads()[acceptance.PREVIEW_TOOL]
    if change=='sequence':preview['Proposed Changes']['fixed_sequence'].reverse()
    elif change=='extra':preview['Proposed Changes']['raw']='private-source-value'
    elif change=='boolean_count':preview['Proposed Changes']['material_pair_leases_maximum']=True
    elif change=='scope':preview['Proposed Changes']['user_group_associations']=True
    elif change=='summary':preview['summary_digest']='f'*64
    elif change=='gaps':preview['unresolved_gaps']=[]
    elif change=='revision':preview['summary_revision']=True
    else:preview['contract']='fortipam-v4-radius-primary-lifecycle-candidate-v1'
    if change!='summary':preview['summary_digest']=canonical_digest({k:v for k,v in preview.items() if k!='summary_digest'})
    with pytest.raises(acceptance.RadiusPairLifecycleMcpOAuthAcceptanceError):acceptance._validate_preview(preview)


@pytest.mark.parametrize('fault',['missing_client','symlink_login','public_parent','same_path','consumed_marker','http'])
def test_protected_inputs_or_consumed_dispatch_refuse_before_oauth(tmp_path: Path,monkeypatch: pytest.MonkeyPatch,fault: str) -> None:
    tmp_path.chmod(0o700);login=tmp_path/'login.json';client=tmp_path/'client.json';marker=tmp_path/'dispatch.json'
    login.write_text('{}');login.chmod(0o600);client.write_text('{}');client.chmod(0o600)
    url='https://synthetic.example.test/mcp'
    if fault=='missing_client':client.unlink()
    elif fault=='symlink_login':login.unlink();login.symlink_to(client)
    elif fault=='public_parent':tmp_path.chmod(0o755)
    elif fault=='same_path':client=login
    elif fault=='consumed_marker':marker.write_text('partial');marker.chmod(0o600)
    else:url='http://synthetic.example.test/mcp'
    monkeypatch.setattr(oauth,'_oauth_token',lambda *a,**k:pytest.fail('Preflight reached OAuth'))
    with pytest.raises(acceptance.RadiusPairLifecycleMcpOAuthAcceptanceError):
        asyncio.run(acceptance.run_radius_server_pair_lifecycle_mcp_oauth_acceptance(url,login,client,marker))


def test_ambiguous_login_json_is_rejected_and_its_mutable_input_cleared(monkeypatch: pytest.MonkeyPatch) -> None:
    raw=bytearray(b'{"username":"synthetic","password":"first-synthetic","password":"second-synthetic"}')
    monkeypatch.setattr(acceptance,'_read',lambda *a:raw)
    with pytest.raises(acceptance.RadiusPairLifecycleMcpOAuthAcceptanceError):acceptance._login(Path('/synthetic'))
    assert not raw


@pytest.mark.parametrize('fault',['contract','sequence','retention','shape','removal','connectivity','ordinal','extra'])
def test_configure_cannot_accept_disposable_or_weaken_retention_contract(fault: str) -> None:
    preview,authorization,result=payloads('configure').values()
    if fault=='contract':preview['contract']=acceptance.CONTRACT
    elif fault=='sequence':preview['Proposed Changes']['fixed_sequence'].append('original_ack_remove')
    elif fault=='retention':preview['Expected State']['owned_entry_retained']=False
    elif fault=='shape':result['exact_reject_only_responses_verified']=False
    elif fault=='removal':result['original_ack_removal_verified']=True
    elif fault=='connectivity':result['connectivity_qualified']=True
    elif fault=='ordinal':result['ordinal_observations_verified']['secondary']=False
    else:result['raw']='private-source-value'
    preview['summary_digest']=canonical_digest({k:v for k,v in preview.items()if k!='summary_digest'})
    with pytest.raises(acceptance.RadiusPairLifecycleMcpOAuthAcceptanceError):
        acceptance._validate_preview(preview,persistent_pair=True)
        acceptance._validate_authorization(authorization,preview,persistent_pair=True)
        acceptance._validate_execution(result,persistent_pair=True)


@pytest.mark.parametrize('fault',['contract','material','reference','state','summary','future','stale','boolean_time',
    'requester','boundary','freshness','extra','authorization','result','replay'])
def test_removal_requires_exact_original_ack_cpe_freshness_and_final_dual_absence(fault: str) -> None:
    preview,authorization,result=payloads('remove').values()
    if fault=='contract':preview['contract']='fortipam-radius-owned-recovery-private-v1'
    elif fault=='material':preview['Proposed Changes']['material_access']=True
    elif fault=='reference':preview['Current State']['zero_references']=False
    elif fault=='state':preview['Current State']['full_state_unchanged']=False
    elif fault=='summary':preview['summary_digest']='f'*64
    elif fault=='future':preview['Current State']['observed_at']=101
    elif fault=='stale':preview['Current State']['observed_at']=40
    elif fault=='boolean_time':preview['Current State']['observed_at']=True
    elif fault=='requester':preview['requester_digest']='private-requester'
    elif fault=='boundary':preview['unchanged_boundary']=[]
    elif fault=='freshness':preview['facts']['freshness_seconds']=True
    elif fault=='extra':preview['raw']='private-source-value'
    elif fault=='authorization':authorization['expires_at']=159
    elif fault=='result':result['verification']='unknown'
    else:result['idempotent_replay']=True
    if fault!='summary':preview['summary_digest']=canonical_digest({k:v for k,v in preview.items()if k!='summary_digest'})
    with pytest.raises(acceptance.RadiusPairLifecycleMcpOAuthAcceptanceError):
        acceptance._validate_removal_preview(preview)
        acceptance._validate_removal_authorization(authorization,preview)
        acceptance._validate_removal_execution(result)


@pytest.mark.parametrize('values',[(True,True),(1,False),(False,'true')])
def test_invalid_completion_modes_reject_before_oauth(tmp_path: Path,monkeypatch: pytest.MonkeyPatch,values: tuple[Any,Any]) -> None:
    monkeypatch.setattr(oauth,'_oauth_token',lambda *a,**k:pytest.fail('Invalid mode reached OAuth'))
    with pytest.raises(acceptance.RadiusPairLifecycleMcpOAuthAcceptanceError):
        asyncio.run(acceptance.run_radius_server_pair_lifecycle_mcp_oauth_acceptance('https://synthetic.example.test/mcp',
            tmp_path/'login.json',tmp_path/'client.json',tmp_path/'dispatch.json',persistent_pair=values[0],remove_owned_pair=values[1]))
    assert not (tmp_path/'dispatch.json').exists()
