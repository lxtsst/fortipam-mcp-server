"""One parent, four original child M4 scopes and actual synthetic source pipes."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp.radius_server_pair_lifecycle_workflow import RadiusServerPairLifecycleWorkflow
from fortipam_mcp.radius_server_pair_owned_connect_contract import CONNECT_PATH
from test_radius_server_pair_live_workflow import setup as create_setup, IDENTITY, grant
from test_radius_server_pair_owned_connect_workflow import connect
from test_radius_server_pair_recovery_workflow import recovery
from test_radius_server_pair_http_transport import Response
from test_radius_server_projection import envelope
from v4_planning import canonical_digest

KEY=b'synthetic-pair-parent-key-0000001'
SECONDARY_KEY=b'synthetic-pair-second-key-0000001'


def setup(root: Path,*,fault: str | None=None,enabled: bool=True,identity: dict[str,str] | None=None,retain: bool=False) -> tuple[Any,...]:
    selected=IDENTITY if identity is None else identity
    overrides={"allowed_requester_digest":selected["requester_digest"],"allowed_transport_digest":selected["transport_digest"]}
    create,peer,now,factory,values=create_setup(root,**overrides)
    primary=connect(root,peer,now,'primary',**overrides)
    secondary=connect(root,peer,now,'secondary',authority_key=SECONDARY_KEY,**overrides)
    restore=recovery(root,peer,now,**overrides)
    old=peer.handle;peer.native_posts=[]
    def handle(method: str,path: str,body: Any) -> Any:
        if method=='POST' and path==CONNECT_PATH:
            selected=json.loads(bytes(body));ordinal=selected['ordinal']
            assert selected=={'mkey':peer.binding.name,'server':peer.binding.server if ordinal=='primary' else peer.binding.secondary_server,
                'auth_type':'auto','ordinal':ordinal}
            peer.native_posts.append(ordinal)
            if fault==ordinal+'_lost':raise TimeoutError('Synthetic private reply lost.')
            if fault=='primary_drift' and ordinal=='primary':peer.row['timeout']=99
            if fault=='create_expiry_after_primary' and ordinal=='primary':now[0]=170
            if fault=='primary_record_lost'and ordinal=='secondary':(root/'http/pair-native-primary.result.json').unlink()
            result={'status':'reachable'}
            if retain and fault!=ordinal+'_shape':
                result={'status':'ok','access_status':'Access-Reject','access_message':'SYNTHETIC_PRIVATE'}
            return Response(envelope(http_method='POST',action='test-connect',mkey=peer.binding.name,results=result))
        return old(method,path,body)
    peer.handle=handle
    if fault=='create_lost':peer.lost_post_ack=True
    if fault=='create_readback':peer.failed_readback=True
    if fault=='recovery_lost':peer.lost_delete_ack=True
    parent=RadiusServerPairLifecycleWorkflow(create,primary,secondary,restore,authority_key=KEY,execution_enabled=enabled,retain_on_success=retain)
    return parent,peer,now,factory,values


def test_one_parent_runs_original_children_and_closes_every_gate(tmp_path: Path) -> None:
    p,peer,now,factory,_=setup(tmp_path)
    preview=p.preview(**IDENTITY)
    assert preview['summary_digest']==canonical_digest({k:v for k,v in preview.items() if k!='summary_digest'})
    auth=p.authorize(preview['preview_ref'],**IDENTITY)
    assert not factory.calls and peer.posts==peer.deletes==0
    result=p.execute(auth['authorization_ref'],**IDENTITY)
    assert result['outcome']=='succeeded' and result['verification']=='verified'
    assert result['ordinal_observations_verified']=={'primary':True,'secondary':True}
    assert result['original_ack_removal_verified'] and result['all_candidate_gates_closed']
    assert not result['connectivity_qualified'] and result['failure_stage'] is None
    assert peer.row is None and peer.posts==peer.deletes==1 and peer.native_posts==['primary','secondary']
    assert len(factory.calls)==4
    assert all(w.claim_count==1 for w in (p._create._execution_store,p._primary._store,p._secondary._store,
        p._recovery._store,p._create._material_store,p._create._group_store))
    before=len(peer.connections)
    with pytest.raises(RuntimeError):p.execute(auth['authorization_ref'],**IDENTITY)
    assert len(peer.connections)==before and len(factory.calls)==4
    encoded=json.dumps([preview,auth,result])
    for private in (peer.binding.name,peer.binding.server,peer.binding.secondary_server,peer.binding.private_nonce,
                    'A'*32,'B'*32,str(tmp_path),'synthetic-token'):
        assert private not in encoded


@pytest.mark.parametrize('fault',['create_lost','create_readback','primary_lost','secondary_lost','primary_drift','recovery_lost'])
def test_failed_child_stops_observations_and_attempts_only_original_ack_recovery(tmp_path: Path,fault: str) -> None:
    p,peer,now,factory,_=setup(tmp_path,fault=fault)
    result=p.execute(grant(p),**IDENTITY)
    assert result['outcome']=='reconciliation_required' and result['all_candidate_gates_closed']
    assert peer.posts==1 and len(factory.calls)==4
    if fault.startswith('create'):assert not peer.native_posts
    elif fault.startswith('primary'):assert peer.native_posts==['primary']
    else:assert peer.native_posts==['primary','secondary']
    assert peer.deletes==int(fault not in {'create_lost','primary_drift'})
    assert result['failure_stage']==('create' if fault.startswith('create') else 'recovery' if fault=='recovery_lost'
        else 'native_secondary' if fault.startswith('secondary') else 'native_primary')
    before=len(peer.connections)
    with pytest.raises(RuntimeError):p.preview(**IDENTITY)
    assert len(peer.connections)==before


@pytest.mark.parametrize('fault',['gate','identity','expiry','key','native_key','native_ordinal','source','child_consumed'])
def test_parent_drift_or_stale_child_cannot_start_first_write(tmp_path: Path,fault: str) -> None:
    p,peer,now,factory,_=setup(tmp_path);ref=grant(p);identity=dict(IDENTITY)
    if fault=='gate':p._enabled=False
    elif fault=='identity':identity['transport_digest']='f'*64
    elif fault=='expiry':now[0]=160
    elif fault=='key':p._key=b'x'*32
    elif fault=='native_key':p._secondary._key=b'x'*32
    elif fault=='native_ordinal':p._secondary._transport._ordinal='primary'
    elif fault=='source':p._create._source._host='other.example'
    else:
        p._secondary._store.claim(plan_ref='synthetic-other',requester_digest='1'*64,idempotency_digest='2'*64,
            authorization_digest='3'*64,context_digest='4'*64)
    with pytest.raises(RuntimeError):p.execute(ref,**identity)
    assert not factory.calls and peer.posts==peer.deletes==0 and not peer.native_posts


def test_parent_close_during_create_connection_prevents_send_and_closes_children(tmp_path: Path) -> None:
    p,peer,now,factory,_=setup(tmp_path);ref=grant(p)
    def on_connect() -> None:
        if (tmp_path/'http/create.claim.json').exists():p.close()
    peer.on_connect=on_connect
    result=p.execute(ref,**IDENTITY)
    assert result['outcome']=='reconciliation_required' and result['all_candidate_gates_closed']
    assert peer.posts==peer.deletes==0 and not peer.native_posts and len(factory.calls)==4


def test_recovery_receives_fresh_authority_when_prior_native_expires(tmp_path: Path) -> None:
    p,peer,now,factory,_=setup(tmp_path,fault='create_expiry_after_primary')
    result=p.execute(grant(p),**IDENTITY)
    assert result['outcome']=='reconciliation_required' and result['original_ack_removal_verified']
    assert peer.native_posts==['primary'] and peer.deletes==1 and peer.row is None and now[0]==170
    assert len(factory.calls)==4 and p._recovery._store.claim_count==1


def test_reconstruction_cannot_reopen_consumed_children(tmp_path: Path) -> None:
    p,peer,now,factory,values=setup(tmp_path)
    assert p.execute(grant(p),**IDENTITY)['outcome']=='succeeded'
    from fortipam_mcp.radius_server_pair_live_workflow import RadiusServerPairLiveWorkflow
    from test_radius_server_pair_live_workflow import CONFIG
    create=RadiusServerPairLiveWorkflow(peer.binding,CONFIG,**values)
    fresh=RadiusServerPairLifecycleWorkflow(create,connect(tmp_path,peer,now,'primary'),
        connect(tmp_path,peer,now,'secondary',authority_key=SECONDARY_KEY),recovery(tmp_path,peer,now),
        authority_key=KEY,execution_enabled=True)
    before=len(peer.connections)
    with pytest.raises(RuntimeError):fresh.preview(**IDENTITY)
    assert len(peer.connections)==before and len(factory.calls)==4


def test_closed_parent_execution_gate_still_allows_readonly_preview(tmp_path: Path) -> None:
    p,peer,now,factory,_=setup(tmp_path,enabled=False)
    preview=p.preview(**IDENTITY)
    assert preview['device_write_executed'] is False and peer.connections
    with pytest.raises(RuntimeError):p.authorize(preview['preview_ref'],**IDENTITY)
    assert not factory.calls and peer.posts==peer.deletes==0 and not peer.native_posts


@pytest.mark.parametrize('fault',[None,'primary_shape','secondary_shape','primary_lost','secondary_lost',
    'create_lost','create_readback','primary_drift','primary_record_lost'])
def test_persistent_pair_retains_only_both_original_m4_and_exact_reject_shapes(tmp_path: Path,fault: str | None) -> None:
    p,peer,now,factory,_=setup(tmp_path,fault=fault,retain=True)
    preview=p.preview(**IDENTITY)
    assert preview['contract']=='fortipam-v4-radius-pair-configure-candidate-v1'
    assert preview['Proposed Changes']['fixed_sequence']==['create','observe_primary','observe_secondary']
    assert preview['Expected State']['independent_original_ack_removal_available']
    assert 'final_dual_absence_required' not in preview['Expected State']
    result=p.execute(p.authorize(preview['preview_ref'],**IDENTITY)['authorization_ref'],**IDENTITY)
    assert result['owned_entry_retained'] is (fault is None)
    assert result['outcome']==('succeeded' if fault is None else 'reconciliation_required')
    assert result['all_candidate_gates_closed'] and not result['connectivity_qualified']
    assert peer.posts==1 and len(factory.calls)==4
    if fault is None:
        assert peer.row is not None and peer.deletes==p._recovery._store.claim_count==0
        assert result['exact_reject_only_responses_verified'] and not result['original_ack_removal_verified']
    elif fault not in {'create_lost','primary_drift'}:
        assert peer.row is None and peer.deletes==p._recovery._store.claim_count==1
    else:assert peer.deletes==0
    with pytest.raises(ValueError):p.preview_removal(**IDENTITY)
    assert 'SYNTHETIC_PRIVATE' not in json.dumps([preview,result])


def restart_retained(parent: Any,root: Path,peer: Any,now: list[int],values: dict[str,Any]) -> Any:
    from fortipam_mcp.radius_server_pair_live_workflow import RadiusServerPairLiveWorkflow
    from test_radius_server_pair_live_workflow import CONFIG
    identity={name:values[name]for name in('allowed_requester_digest','allowed_transport_digest')}
    return RadiusServerPairLifecycleWorkflow(RadiusServerPairLiveWorkflow(peer.binding,CONFIG,**values),
        connect(root,peer,now,'primary',**identity),connect(root,peer,now,'secondary',authority_key=SECONDARY_KEY,**identity),
        recovery(root,peer,now,**identity),authority_key=KEY,execution_enabled=True,retain_on_success=True)


@pytest.mark.parametrize('fault',[None,'state','reference','lost_ack'])
def test_recomposed_pair_removal_uses_original_ack_without_reacquiring_or_reobserving(tmp_path: Path,fault: str | None) -> None:
    p,peer,now,factory,values=setup(tmp_path,retain=True)
    assert p.execute(grant(p),**IDENTITY)['owned_entry_retained']
    fresh=restart_retained(p,tmp_path,peer,now,values)
    if fault=='state':peer.row['timeout']=99
    elif fault=='reference':peer.row['q_ref']=1
    elif fault=='lost_ack':peer.lost_delete_ack=True
    before=len(peer.connections)
    with pytest.raises(RuntimeError):fresh.preview(**IDENTITY)
    assert len(peer.connections)==before
    if fault in {'state','reference'}:
        with pytest.raises(RuntimeError):fresh.preview_removal(**IDENTITY)
        assert peer.deletes==fresh._recovery._store.claim_count==0
        fresh.close()
    else:
        preview=fresh.preview_removal(**IDENTITY);auth=fresh.authorize_removal(preview['preview_ref'],**IDENTITY)
        result=fresh.execute_removal(auth['authorization_ref'],**IDENTITY)
        assert result['outcome']==('succeeded' if fault is None else 'reconciliation_required')
        assert fresh._closed()and peer.deletes==fresh._recovery._store.claim_count==1
        with pytest.raises(ValueError):fresh.preview_removal(**IDENTITY)
    assert peer.posts==1 and peer.native_posts==['primary','secondary']and len(factory.calls)==4


@pytest.mark.parametrize('retain',[False,True])
def test_pair_completion_mode_is_part_of_authorized_summary_namespace(tmp_path: Path,retain: bool) -> None:
    p,peer,now,factory,_=setup(tmp_path,retain=retain);ref=grant(p)
    p._retain_on_success=not retain
    with pytest.raises(RuntimeError):p.execute(ref,**IDENTITY)
    assert peer.posts==peer.deletes==0 and not factory.calls
