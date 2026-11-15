"""Associated pair removal cannot rely on q_ref or a stale User absence."""
from __future__ import annotations

import json
from pathlib import Path
import pickle
from typing import Any
import pytest
from v4_planning import canonical_digest
from fortipam_mcp import radius_remote_user_recovery_runtime as runtime
from fortipam_mcp.radius_remote_user_absence_guard import RadiusRemoteUserAbsenceGuard
from test_radius_remote_user_recovery_runtime import prepared


def ready(root: Path, monkeypatch: Any, *, remove_user: bool = True) -> tuple[Any, ...]:
    values = prepared(root, monkeypatch)
    env, _, _, _, _, _, _, user, _, identity, _ = values
    env[runtime.PREFIX+'EXECUTION_ENABLED'] = 'true'
    selected = runtime.build_radius_remote_user_recovery_candidate(env)
    saved = dict(user.row)
    if remove_user:
        w = selected._workflow
        p = w.preview(**identity); a = w.authorize(p['preview_ref'],**identity)
        assert w.execute(a['authorization_ref'],**identity)['outcome']=='succeeded'
    return selected, values, saved


def grant(w: Any, identity: Any) -> str:
    p = w.preview(**identity)
    assert p['Current State']['associated_user_dual_absence_verified'] is True
    assert p['summary_digest']==canonical_digest({k:v for k,v in p.items() if k!='summary_digest'})
    return w.authorize(p['preview_ref'],**identity)['authorization_ref']


def test_independent_pair_recovery_after_user_and_both_readonly_reconciliations(tmp_path: Path, monkeypatch: Any) -> None:
    selected, values, _ = ready(tmp_path,monkeypatch)
    env, _, _, paths, _, pair_paths, radius, user, source, identity, original = values
    w = selected._pair
    assert w is not None and type(w._user_absence) is RadiusRemoteUserAbsenceGuard
    assert w._user_absence._reader._enabled is False
    count = len(source.calls)
    result = w.execute(grant(w,identity),**identity)
    assert result['outcome']=='succeeded' and result['verification']=='verified'
    assert user.deletes==radius.deletes==1 and radius.row is user.row is None
    assert selected._workflow.reconcile(**identity)['prior_m4_outcome_unchanged']
    assert w.reconcile(**identity)['pair_absence_verified']
    assert len(source.calls)==count and w._store.claim_count==len(w._store.audit_events)==1
    assert original._workflow._pair._create._execution_store.claim_count==1
    keys = {p:p.read_bytes() for p in (*paths.values(),*pair_paths.values()) if p.name.endswith('key_file.fixture')}
    selected.close()
    env[runtime.PREFIX+'EXECUTION_ENABLED']='false'
    repeated = runtime.build_radius_remote_user_recovery_candidate(env)
    assert repeated._pair.reconcile(**identity)['prior_m4_outcome_unchanged']
    with pytest.raises(Exception): repeated._pair.preview(**identity)
    assert radius.deletes==user.deletes==1 and all(p.read_bytes()==v for p,v in keys.items())
    repeated.close()


def test_zero_pair_reference_count_does_not_prove_user_absence(tmp_path: Path, monkeypatch: Any) -> None:
    selected, values, _ = ready(tmp_path,monkeypatch,remove_user=False)
    _, _, _, _, _, _, radius, user, source, identity, _ = values
    radius.row['q_ref']=0
    with pytest.raises(Exception): selected._pair.preview(**identity)
    assert user.row is not None and user.deletes==radius.deletes==0 and len(source.calls)==4
    assert selected._pair._store.claim_count==0
    selected.close()


@pytest.mark.parametrize('fault', ['present','empty_collection','truncated_collection','bad_absence','user_key',
    'pair_key','pair_creator_store','guard_closed','guard_replaced','user_runtime','handoff','identity'])
def test_dependency_drift_before_authorization_denies_without_pair_dispatch(tmp_path: Path, monkeypatch: Any, fault: str) -> None:
    selected, values, saved = ready(tmp_path,monkeypatch)
    _, _, _, paths, _, pair_paths, radius, user, source, identity, _ = values
    w = selected._pair; p = w.preview(**identity)
    if fault=='present': user.row=saved; radius.row['q_ref']=0
    elif fault in {'empty_collection','truncated_collection','bad_absence'}: setattr(user,fault,True)
    elif fault=='user_key': paths['user_create_execution_key_file'].write_bytes(b'x'*32)
    elif fault=='pair_key': pair_paths['recovery_execution_key_file'].write_bytes(b'x'*32)
    elif fault=='pair_creator_store': pair_paths['create_database_file'].write_bytes(b'CORRUPT_SYNTHETIC_STORE')
    elif fault=='guard_closed': w._user_absence.close()
    elif fault=='guard_replaced': w._user_absence=None
    elif fault=='user_runtime': (paths['user_state_directory']/'user-remove.runtime.json').write_text('{}')
    elif fault=='handoff': (paths['user_state_directory']/'radius-target.handoff.json').write_text('{}')
    else: identity=identity|{'requester_digest':'f'*64}
    with pytest.raises(Exception): w.authorize(p['preview_ref'],**identity)
    assert radius.deletes==0 and w._store.claim_count==0 and len(source.calls)==4
    selected.close()


@pytest.mark.parametrize('fault', ['present','unproven_absence','expire','close','pair_key','user_key'])
def test_final_connect_dependency_drift_consumes_without_delete_or_replay(tmp_path: Path, monkeypatch: Any, fault: str) -> None:
    selected, values, saved = ready(tmp_path,monkeypatch)
    _, _, _, paths, _, pair_paths, radius, user, source, identity, _ = values
    w = selected._pair; auth = grant(w,identity)
    changed: list[bool] = []
    def on_connect() -> None:
        if (pair_paths['state_directory']/'delete.claim.json').exists() and not changed:
            changed.append(True)
            if fault=='present': user.row=saved; radius.row['q_ref']=0
            elif fault=='unproven_absence': user.empty_collection=True
            elif fault=='expire': monkeypatch.setattr('time.time',lambda:200.0)
            elif fault=='close': w.close()
            elif fault=='pair_key': pair_paths['recovery_execution_key_file'].write_bytes(b'x'*32)
            else: paths['user_create_execution_key_file'].write_bytes(b'x'*32)
    radius.on_connect=on_connect
    result = w.execute(auth,**identity)
    assert changed and result['outcome']=='reconciliation_required' and radius.deletes==0
    assert w._store.claim_count==1 and len(source.calls)==4
    with pytest.raises(Exception): w.preview(**identity)
    assert radius.deletes==0
    selected.close()


def test_lost_pair_delete_ack_keeps_unknown_but_allows_readonly_dual_absence(tmp_path: Path, monkeypatch: Any) -> None:
    selected, values, _ = ready(tmp_path,monkeypatch)
    _, _, _, _, _, _, radius, user, source, identity, _ = values
    radius.lost_delete_ack=True
    w = selected._pair
    result = w.execute(grant(w,identity),**identity)
    assert result['outcome']=='reconciliation_required' and result['verification']=='unknown'
    before = tuple(w._store.audit_events)
    assert w.reconcile(**identity)['pair_absence_verified']
    assert tuple(w._store.audit_events)==before and before[0].verification.value=='unknown'
    with pytest.raises(Exception): w.preview(**identity)
    assert radius.deletes==user.deletes==1 and len(source.calls)==4
    selected.close()


def test_active_claim_is_rechecked_after_final_user_network_reads(tmp_path: Path, monkeypatch: Any) -> None:
    selected,values,_=ready(tmp_path,monkeypatch)
    _,_,_,_,_,pair_paths,radius,user,source,identity,_=values
    w=selected._pair;auth=grant(w,identity)
    inspect=w._store.inspect_claim
    changed: list[bool]=[]
    def require_claim(**kwargs: Any) -> Any:
        if changed: raise ValueError('Synthetic reservation became unavailable.')
        return inspect(**kwargs)
    def on_user_connect() -> None:
        if (pair_paths['state_directory']/'delete.claim.json').exists(): changed.append(True)
    monkeypatch.setattr(w._store,'inspect_claim',require_claim)
    user.on_connect=on_user_connect
    result=w.execute(auth,**identity)
    assert changed and radius.deletes==0 and result['verification']=='unknown'
    assert w._store.claim_count==1 and len(source.calls)==4
    selected.close()


def test_cross_thread_close_revokes_before_waiting_for_pair_lock(tmp_path: Path, monkeypatch: Any) -> None:
    import threading
    import time
    selected,values,_=ready(tmp_path,monkeypatch)
    _,_,_,_,_,pair_paths,radius,user,source,identity,_=values
    w=selected._pair;auth=grant(w,identity)
    workers: list[threading.Thread]=[]
    revoked: list[bool]=[]
    def on_user_connect() -> None:
        if (pair_paths['state_directory']/'delete.claim.json').exists() and not workers:
            worker=threading.Thread(target=selected.close,daemon=True);workers.append(worker);worker.start()
            stop=time.monotonic()+1
            while w._enabled and time.monotonic()<stop: time.sleep(.001)
            revoked.append(not w._enabled and not w._transport._recovery_enabled)
    user.on_connect=on_user_connect
    result=w.execute(auth,**identity)
    for worker in workers:
        worker.join(2);assert not worker.is_alive()
    assert revoked==[True] and result['verification']=='unknown'
    assert radius.deletes==0 and w._store.claim_count==1 and len(source.calls)==4


def test_guard_is_private_immutable_and_cannot_replace_dispatch_authority(tmp_path: Path, monkeypatch: Any) -> None:
    selected, values, _ = ready(tmp_path,monkeypatch)
    *_, radius, user, source, identity, original = values
    guard = selected._pair._user_absence
    assert user.username not in repr(guard)
    with pytest.raises(ValueError): guard._pin='f'*64
    with pytest.raises(ValueError): del guard._reader
    with pytest.raises(Exception): pickle.dumps(guard)
    with pytest.raises(Exception): json.dumps(guard)
    w = selected._pair
    auth = grant(w,identity)
    assert w._authorize_delete(w._binding,w._preview.owned_digest,w._preview.state_digest) is False
    assert w._store.claim_count==0 and radius.deletes==0
    selected.close()
