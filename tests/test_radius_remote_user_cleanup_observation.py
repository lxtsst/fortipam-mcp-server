"""Cleanup proof never upgrades an absent ACK or repairs a consumed operation."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import pytest
from fortipam_mcp import radius_remote_user_recovery_runtime as runtime
from test_radius_remote_user_recovery_runtime import prepared


@pytest.mark.parametrize('mode', ['referenced_ack','no_ack_present'])
def test_referenced_consumed_create_is_readable_without_adoption_or_cleanup(tmp_path: Path, monkeypatch: Any, mode: str) -> None:
    env,_,_,paths,_,pair_paths,radius,user,source,identity,original=prepared(tmp_path,monkeypatch,mode=mode)
    user.row['q_ref']=1
    env[runtime.PREFIX+'EXECUTION_ENABLED']='true'
    selected=runtime.build_radius_remote_user_recovery_candidate(env);w=selected._workflow
    before={p:p.read_bytes()for directory in(paths['user_state_directory'],pair_paths['state_directory'])for p in directory.iterdir()}
    audit=tuple(w._original_store.audit_events);source_calls=len(source.calls)
    result=w.inspect_cleanup_state(**identity)
    assert result['evidence_mode']=='consumed_create'and result['observation']=='present_observed'
    assert not result['user_absence_verified']and not result['user_ownership_or_delete_authority_granted']
    assert result['prior_m4_outcome_unchanged']and not result['dispatch_retry_allowed']
    with pytest.raises(Exception):w.preview(**identity)
    with pytest.raises(Exception):selected._pair.preview(**identity)
    assert user.deletes==radius.deletes==w._store.claim_count==0
    assert tuple(w._original_store.audit_events)==audit and audit[0].verification.value=='unknown'
    assert len(source.calls)==source_calls and all(p.read_bytes()==raw for p,raw in before.items())
    assert (paths['user_state_directory']/'create-ack.json').exists()is(mode=='referenced_ack')
    assert not(paths['user_state_directory']/'created.json').exists()
    selected.close()


@pytest.mark.parametrize('mode', ['unattempted','no_ack_absent','no_ack_present','terminal_no_http_claim'])
def test_original_runtime_observation_and_only_qualified_pair_cleanup(tmp_path: Path, monkeypatch: Any, mode: str) -> None:
    env,_,_,paths,_,_,radius,user,source,identity,original=prepared(tmp_path,monkeypatch,mode=mode)
    env[runtime.PREFIX+'EXECUTION_ENABLED']='true'
    selected=runtime.build_radius_remote_user_recovery_candidate(env)
    w=selected._workflow
    keys={p:p.read_bytes() for p in paths.values() if p.name.endswith('key_file.fixture')}
    before=tuple(w._original_store.audit_events)
    result=w.inspect_cleanup_state(**identity)
    expected_mode=mode if mode in {'unattempted','terminal_no_http_claim'} else 'consumed_create'
    assert result['evidence_mode']==expected_mode
    assert result['user_absence_verified'] is (mode!='no_ack_present')
    assert result['observation']==('present_observed'if mode=='no_ack_present'else'absent_observed')
    assert not result['user_ownership_or_delete_authority_granted'] and not result['mutation_executed']
    assert not result['dispatch_retry_allowed'] and result['prior_m4_outcome_unchanged']
    with pytest.raises(Exception): w.preview(**identity)
    if mode=='no_ack_present':
        with pytest.raises(Exception): selected._pair.preview(**identity)
        assert radius.deletes==0
    else:
        p=selected._pair.preview(**identity);a=selected._pair.authorize(p['preview_ref'],**identity)
        assert selected._pair.execute(a['authorization_ref'],**identity)['outcome']=='succeeded'
        assert selected._pair.reconcile(**identity)['pair_absence_verified']
        assert radius.deletes==1
    assert user.deletes==0 and w._store.claim_count==0 and len(source.calls)==4
    assert tuple(w._original_store.audit_events)==before
    assert w._original_store.claim_count==int(mode!='unattempted')
    assert not (paths['user_state_directory']/'create-ack.json').exists()
    assert not (paths['user_state_directory']/'delete.claim.json').exists()
    if before: assert before[0].verification.value=='unknown'
    selected.close()
    repeated=runtime.build_radius_remote_user_recovery_candidate(env)
    assert repeated._workflow.inspect_cleanup_state(**identity)['observation']==result['observation']
    assert all(p.read_bytes()==v for p,v in keys.items())
    repeated.close()


@pytest.mark.parametrize('fault', ['signature','runtime','original_m4','claim','actor','claim_time','defaults','collection','foreign_scope','no_claim_but_m4'])
def test_cleanup_observation_refuses_missing_or_inconsistent_provenance(tmp_path: Path, monkeypatch: Any, fault: str) -> None:
    mode='unattempted'if fault=='no_claim_but_m4'else'no_ack_absent'
    env,_,_,paths,_,_,radius,user,source,identity,original=prepared(tmp_path,monkeypatch,mode=mode)
    selected=runtime.build_radius_remote_user_recovery_candidate(env)
    directory=paths['user_state_directory']
    if fault=='signature':
        path=directory/'user-create.authority.json';packet=json.loads(path.read_text());packet['preview']['signature']='f'*64;path.write_text(json.dumps(packet))
    elif fault=='runtime': (directory/'user-create.runtime.json').write_text('{}')
    elif fault=='original_m4': paths['user_create_database_file'].write_bytes(b'CORRUPT_SYNTHETIC_M4')
    elif fault=='claim': (directory/'create.claim.json').write_text('{}')
    elif fault in {'actor','claim_time'}:
        path=directory/'create.claim.json';claim=json.loads(path.read_text())
        claim['actor_digest' if fault == 'actor' else 'claimed_at'] = 'f' * 64 if fault == 'actor' else 1000
        path.write_text(json.dumps(claim))
    elif fault=='defaults': user.defaults['comments']='changed'
    elif fault=='collection': user.truncated_collection=True
    elif fault=='foreign_scope': identity=identity|{'requester_digest':'f'*64}
    else:
        original._workflow._user_stores[0].claim(plan_ref='synthetic-foreign',requester_digest='1'*64,
            idempotency_digest='2'*64,context_digest='3'*64,authorization_digest='4'*64)
    with pytest.raises(Exception): selected._workflow.inspect_cleanup_state(**identity)
    with pytest.raises(Exception): selected._pair.preview(**identity)
    assert user.deletes==radius.deletes==0 and len(source.calls)==4
    selected.close()


def test_unattempted_absence_rejection_clears_all_mutable_response_buffers(tmp_path: Path, monkeypatch: Any) -> None:
    env,_,_,_,_,_,radius,user,_,identity,_=prepared(tmp_path,monkeypatch,mode='unattempted')
    selected=runtime.build_radius_remote_user_recovery_candidate(env)
    user.row=user.defaults|{'name':user.username,'password':'SYNTHETIC_NEVER_DECODED'}
    reader=selected._workflow._reader;exchange=reader._exchange
    buffers: list[bytearray]=[]
    def observe(*a: Any, **k: Any) -> Any:
        code,raw=exchange(*a,**k);buffers.append(raw);return code,raw
    monkeypatch.setattr(reader,'_exchange',observe)
    with pytest.raises(Exception):selected._workflow.inspect_cleanup_state(**identity)
    assert buffers and all(not any(raw) for raw in buffers)
    assert radius.deletes==user.deletes==0
    selected.close()


@pytest.mark.parametrize('fault', ['signature','runtime','original_m4','claim','ack','defaults','present','removal_claim'])
def test_terminal_without_http_claim_cannot_bypass_provenance_or_draft(tmp_path: Path, monkeypatch: Any, fault: str) -> None:
    env,_,_,paths,_,_,radius,user,source,identity,original=prepared(tmp_path,monkeypatch,mode='terminal_no_http_claim')
    selected=runtime.build_radius_remote_user_recovery_candidate(env)
    directory=paths['user_state_directory']
    if fault=='signature':
        path=directory/'user-create.authority.json';packet=json.loads(path.read_text())
        packet['preview']['signature']='f'*64;path.write_text(json.dumps(packet))
    elif fault=='runtime':(directory/'user-create.runtime.json').write_text('{}')
    elif fault=='original_m4':paths['user_create_database_file'].write_bytes(b'CORRUPT_SYNTHETIC_M4')
    elif fault=='claim':(directory/'create.claim.json').write_text('{}')
    elif fault=='ack':(directory/'create-ack.json').write_text('{}')
    elif fault=='defaults':user.defaults['comments']='changed'
    elif fault=='present':user.row=user.defaults|{'name':user.username,'password':'SYNTHETIC_UNOWNED'}
    else:
        original._workflow._user_stores[1].claim(plan_ref='synthetic-conflict',requester_digest='1'*64,
            idempotency_digest='2'*64,context_digest='3'*64,authorization_digest='4'*64)
    with pytest.raises(Exception):selected._workflow.inspect_cleanup_state(**identity)
    with pytest.raises(Exception):selected._pair.preview(**identity)
    assert radius.deletes==user.deletes==0 and len(source.calls)==4
    selected.close()


def test_actual_in_progress_without_http_claim_is_denied_until_terminal(tmp_path: Path, monkeypatch: Any) -> None:
    import threading
    from fortipam_mcp.radius_remote_user_live_workflow import _Adapter, _execution_context
    from v4_planning import M4ClaimState, M4AdapterAmbiguous
    from test_radius_remote_user_lifecycle_workflow import setup, IDENTITY, grant
    selected,radius,user,_,source,_,_=setup(tmp_path)
    retained=threading.Event();release=threading.Event()
    original=_Adapter.read_current
    def hold(adapter: Any,plan: Any) -> Any:
        if adapter._workflow._operation!='create':return original(adapter,plan)
        retained.set()
        if not release.wait(5):raise TimeoutError('Synthetic test release expired.')
        raise M4AdapterAmbiguous('Synthetic current-read failure after reservation.')
    monkeypatch.setattr(_Adapter,'read_current',hold)
    authorization=grant(selected);outcomes=[];errors=[]
    def execute() -> None:
        try:outcomes.append(selected.execute(authorization,**IDENTITY))
        except BaseException as error:errors.append(error)
    worker=threading.Thread(target=execute,daemon=True);worker.start()
    try:
        assert retained.wait(5)
        creator=selected._user_create;issued=creator._issued
        plan,auth=issued.plan,issued.authorization
        claim=creator._store.inspect_claim(plan_ref=plan.plan_ref,requester_digest=plan.requester_digest,
            idempotency_digest=plan.idempotency_digest,authorization_digest=auth.authorization_digest,
            context_digest=_execution_context(plan,auth))
        assert claim.state is M4ClaimState.IN_PROGRESS and not creator._store.audit_events
        assert not (selected._directory/'create.claim.json').exists()
        with pytest.raises(Exception):selected._pair_remove._user_absence.inspect()
        with pytest.raises(Exception):selected._pair_remove.preview(**IDENTITY)
        assert radius.deletes==user.posts==user.deletes==0
    finally:
        release.set();worker.join(5)
    assert not worker.is_alive() and not errors
    result=outcomes[0]
    assert result['outcome']=='reconciliation_required' and result['all_candidate_gates_closed']
    assert result['pair_absence_verified'] and result['user_absence_verified']
    assert radius.deletes==1 and user.posts==user.deletes==0 and len(source.calls)==4
    assert creator._store.claim_count==len(creator._store.audit_events)==1
    assert creator._store.audit_events[0].verification.value=='unknown'
