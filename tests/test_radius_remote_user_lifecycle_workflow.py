"""Six original child M4s and ordered user/pair recovery with synthetic peers."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from fortipam_mcp.radius_remote_user_contract import RadiusRemoteUserBinding
from fortipam_mcp.radius_remote_user_lifecycle_workflow import RadiusRemoteUserLifecycleWorkflow
from test_radius_server_pair_lifecycle_workflow import setup as pair_setup
from test_radius_server_pair_live_workflow import IDENTITY, grant
from test_radius_remote_user_http_transport import Peer as UserPeer
from test_radius_remote_user_live_workflow import CREATE_KEY, REMOVE_KEY
from test_radius_server_pair_m4_runtime import store
from v4_planning import canonical_digest

KEY = b'synthetic-associated-parent-key-0001'


def setup(root: Path, *, pair_fault: str | None = None, enabled: bool = True, identity: dict[str, str] | None = None) -> tuple[Any, ...]:
    task = root / 'pair'; task.mkdir(mode=0o700)
    pair, radius, now, source, values = pair_setup(task, retain=True, fault=pair_fault, identity=identity)
    binding = RadiusRemoteUserBinding('mcp-v4-radius-user-01234567', radius.binding, 'c' * 64)
    # This view configures only the synthetic HTTP peer, never an authority.
    view = SimpleNamespace(_target=SimpleNamespace(_serial=pair._create._serial), _binding=binding)
    user = UserPeer(view, radius)
    directory = root / 'user'; directory.mkdir(mode=0o700)
    arguments = dict(user_state_directory=directory, user_create_store=store(root, 'user-create', True),
        user_remove_store=store(root, 'user-remove', True), user_create_authority_key=CREATE_KEY,
        user_remove_authority_key=REMOVE_KEY, authority_key=KEY,
        user_create_scope_ref='synthetic-associated-user-create', user_remove_scope_ref='synthetic-associated-user-remove',
        execution_enabled=enabled, user_connection_factory=user.connection)
    selected = RadiusRemoteUserLifecycleWorkflow(pair, binding, **arguments)
    mutations = []
    radius_handle, user_handle = radius.handle, user.handle
    def radius_call(method: str, path: str, body: Any) -> Any:
        if method in {'POST', 'DELETE'}: mutations.append(('radius', method, path))
        return radius_handle(method, path, body)
    def user_call(method: str, path: str, body: Any) -> Any:
        if method in {'POST', 'DELETE'}: mutations.append(('user', method, path))
        return user_handle(method, path, body)
    radius.handle, user.handle = radius_call, user_call
    return selected, radius, user, now, source, arguments, mutations


def test_six_child_m4s_and_user_before_pair_original_ack_recovery(tmp_path: Path) -> None:
    selected, radius, user, _, source, _, mutations = setup(tmp_path)
    preview = selected.preview(**IDENTITY)
    assert preview['summary_digest'] == canonical_digest({k:v for k,v in preview.items() if k != 'summary_digest'})
    result = selected.execute(selected.authorize(preview['preview_ref'], **IDENTITY)['authorization_ref'], **IDENTITY)
    assert result['outcome'] == 'succeeded' and result['verification'] == 'verified', result
    assert all(result[k] for k in ('pair_configure_verified', 'user_create_verified', 'user_remove_verified',
        'user_absence_verified', 'pair_remove_verified', 'all_candidate_gates_closed'))
    assert not result['user_authentication_qualified'] and not result['automatic_failover_qualified']
    assert radius.row is user.row is None and radius.posts == radius.deletes == user.posts == user.deletes == 1
    assert [m[:2] for m in mutations] == [('radius','POST'), ('radius','POST'), ('radius','POST'),
        ('user','POST'), ('user','DELETE'), ('radius','DELETE')]
    assert len(source.calls) == 4
    pair = selected._pair
    stores = (pair._create._execution_store, pair._primary._store, pair._secondary._store,
        pair._recovery._store, *selected._user_stores)
    assert all(s.claim_count == len(s.audit_events) == 1 for s in stores)
    assert all(e.outcome.value == 'succeeded' and e.verification.value == 'verified' for s in stores for e in s.audit_events)
    assert pair._create._material_store.claim_count == pair._create._group_store.claim_count == 1
    output = json.dumps([preview, result, repr(selected)])
    for private in (user.username, user.serial, str(tmp_path), radius.binding.name): assert private not in output
    with pytest.raises(RuntimeError): selected.execute('replay', **IDENTITY)
    assert len(mutations) == 6


@pytest.mark.parametrize('fault', ['create_lost', 'create_readback', 'primary_lost', 'secondary_shape'])
def test_failed_pair_never_starts_user_and_does_not_replay_pair_recovery(tmp_path: Path, fault: str) -> None:
    selected, radius, user, _, source, _, mutations = setup(tmp_path, pair_fault=fault)
    result = selected.execute(grant(selected), **IDENTITY)
    assert result['outcome'] == 'reconciliation_required' and result['failure_stage'] == 'pair_configure'
    assert user.posts == user.deletes == 0 and not user.connections and result['all_candidate_gates_closed']
    assert not result['user_create_verified'] and len(source.calls) == 4
    assert radius.deletes == int(fault != 'create_lost')
    assert selected._pair._recovery._store.claim_count == int(fault != 'create_lost')
    assert not any(m[0] == 'user' for m in mutations)


@pytest.mark.parametrize('fault', ['collision', 'lost_ack', 'foreign_ack', 'readback', 'user_delete_lost', 'pair_delete_lost'])
def test_unknown_user_paths_preserve_status_and_only_qualified_ordered_recovery(tmp_path: Path, fault: str) -> None:
    selected, radius, user, _, source, _, mutations = setup(tmp_path)
    old = None
    if fault == 'collision':
        old = {'name': user.username, 'id': 99, 'status': 'enable', 'password': 'SYNTHETIC_UNRELATED'}
        user.row = dict(old)
    elif fault == 'lost_ack': user.lost_post_ack = True
    elif fault == 'foreign_ack': user.foreign_ack = True
    elif fault == 'readback': user.failed_readback = True
    elif fault == 'user_delete_lost': user.lost_delete_ack = True
    else: radius.lost_delete_ack = True
    result = selected.execute(grant(selected), **IDENTITY)
    assert result['outcome'] == 'reconciliation_required' and result['all_candidate_gates_closed']
    if fault in {'lost_ack', 'foreign_ack'}:
        assert user.posts == 1 and user.deletes == radius.deletes == 0 and radius.row['q_ref'] == 1
        assert not result['user_absence_verified'] and not result['pair_absence_verified']
        assert selected._pair._recovery._store.claim_count == selected._user_stores[1].claim_count == 0
    elif fault == 'collision':
        assert user.row == old and user.posts == user.deletes == radius.deletes == 0
        assert selected._pair._recovery._store.claim_count == 0
        assert not result['user_create_verified'] and not result['user_absence_verified']
    else:
        assert radius.row is user.row is None and user.deletes == radius.deletes == 1
        assert result['user_absence_verified'] and result['pair_absence_verified']
        assert result['user_create_verified'] == (fault != 'readback')
        assert result['user_remove_verified'] == (fault != 'user_delete_lost')
        assert result['pair_remove_verified'] == (fault != 'pair_delete_lost')
        assert [m[:2] for m in mutations][-2:] == [('user','DELETE'), ('radius','DELETE')]
    assert len(source.calls) == 4


@pytest.mark.parametrize('fault', ['identity', 'expiry', 'scope', 'key', 'store', 'factory', 'directory', 'parent_auth', 'pair_recovery_key'])
def test_parent_authority_and_composition_drift_stop_before_mutation(tmp_path: Path, fault: str) -> None:
    import os
    selected, radius, user, now, source, _, _ = setup(tmp_path)
    reference = grant(selected)
    identity = dict(IDENTITY)
    if fault == 'identity': identity['requester_digest'] = 'f' * 64
    elif fault == 'expiry': now[0] = 160
    elif fault == 'scope': selected._scopes = ('foreign-scope', selected._scopes[1])
    elif fault == 'key': selected._key = b'x' * 32
    elif fault == 'store': selected._user_stores = (selected._pair._create._execution_store, selected._user_stores[1])
    elif fault == 'factory': selected._factory = lambda *args, **kwargs: None
    elif fault == 'directory':
        moved = tmp_path / 'old-user'; selected._directory.rename(moved); selected._directory.mkdir(mode=0o700)
    elif fault == 'parent_auth':
        selected._authorization = (reference, 'foreign-child-authorization')
    else: selected._pair_remove._key = b'x' * 32
    with pytest.raises(RuntimeError): selected.execute(reference, **identity)
    assert not source.calls and radius.posts == user.posts == 0
    selected.close()
    assert selected._closed()


@pytest.mark.parametrize('boundary', ['user_create', 'user_remove'])
def test_parent_revocation_on_connect_closes_children_without_new_cleanup_dispatch(tmp_path: Path, boundary: str) -> None:
    selected, radius, user, _, _, _, mutations = setup(tmp_path)
    reference = grant(selected)
    marker = 'create.claim.json' if boundary == 'user_create' else 'delete.claim.json'
    done = []
    def on_connect() -> None:
        if not done and (selected._directory / marker).exists():
            done.append(True); selected.close()
    user.on_connect = on_connect
    result = selected.execute(reference, **IDENTITY)
    assert done and result['outcome'] == 'reconciliation_required' and result['all_candidate_gates_closed']
    assert user.posts == int(boundary == 'user_remove') and user.deletes == radius.deletes == 0
    assert not any(m[1] == 'DELETE' for m in mutations)


def test_default_off_parent_can_preview_but_cannot_authorize_or_be_rearmed(tmp_path: Path) -> None:
    selected, radius, user, _, source, _, _ = setup(tmp_path, enabled=False)
    preview = selected.preview(**IDENTITY)
    with pytest.raises(RuntimeError): selected.authorize(preview['preview_ref'], **IDENTITY)
    selected._enabled = True
    with pytest.raises(RuntimeError): selected.authorize(preview['preview_ref'], **IDENTITY)
    assert radius.posts == user.posts == 0 and not source.calls
    selected.close(); assert selected._closed()


@pytest.mark.parametrize('fault', ['key', 'scope', 'state', 'store'])
def test_constructor_refuses_crossed_keys_scopes_journals_and_stores(tmp_path: Path, fault: str) -> None:
    selected, _, _, _, source, arguments, _ = setup(tmp_path)
    altered = dict(arguments)
    if fault == 'key': altered['user_remove_authority_key'] = CREATE_KEY
    elif fault == 'scope': altered['user_create_scope_ref'] = selected._pair._primary._namespace['scope_ref']
    elif fault == 'state': altered['user_state_directory'] = selected._pair._create._directory
    else: altered['user_remove_store'] = altered['user_create_store']
    with pytest.raises(RuntimeError): RadiusRemoteUserLifecycleWorkflow(selected._pair, selected._binding, **altered)
    assert not source.calls


@pytest.mark.parametrize('fault', ['residual_journal', 'captured_binding', 'claimed_user_store', 'changed_store_key_file'])
def test_no_fresh_pair_dispatch_after_user_preparation_boundary_drift(tmp_path: Path, fault: str) -> None:
    selected, radius, user, _, source, _, _ = setup(tmp_path)
    reference = grant(selected)
    if fault == 'residual_journal': (selected._directory / 'old-authority.json').write_text('{}')
    elif fault == 'captured_binding': selected._radius_execution = None
    elif fault == 'changed_store_key_file': selected._user_stores[0]._key_path.write_bytes(b'x' * 32)
    else:
        selected._user_stores[0].claim(plan_ref='synthetic-foreign-plan', requester_digest='1' * 64,
            idempotency_digest='2' * 64, context_digest='3' * 64, authorization_digest='4' * 64)
    with pytest.raises(RuntimeError): selected.execute(reference, **IDENTITY)
    assert not source.calls and radius.posts == user.posts == 0
    selected.close(); assert selected._closed()


def test_user_state_drift_stops_recovery_before_pair_delete(tmp_path: Path) -> None:
    selected, radius, user, _, _, _, mutations = setup(tmp_path)
    original = user.handle
    def drift_after_ack(method: str, path: str, body: Any) -> Any:
        response = original(method, path, body)
        if method == 'POST': user.row['accprofile'] = 'super_admin'
        return response
    user.handle = drift_after_ack
    result = selected.execute(grant(selected), **IDENTITY)
    assert result['outcome'] == 'reconciliation_required' and result['all_candidate_gates_closed']
    assert user.row is not None and radius.row['q_ref'] == 1 and user.deletes == radius.deletes == 0
    assert not any(m[1] == 'DELETE' for m in mutations)
    assert selected._user_stores[1].claim_count == selected._pair._recovery._store.claim_count == 0


def test_closed_failed_user_creator_does_not_disable_independent_pair_recovery(tmp_path: Path) -> None:
    selected, radius, user, _, _, _, _ = setup(tmp_path)
    done = []
    def on_connect() -> None:
        if not done and (selected._directory / 'create.claim.json').exists():
            done.append(True); selected._user_create.close()
    user.on_connect = on_connect
    result = selected.execute(grant(selected), **IDENTITY)
    assert done and result['outcome'] == 'reconciliation_required' and result['all_candidate_gates_closed']
    assert not result['user_create_verified'] and user.posts == user.deletes == 0
    assert result['pair_remove_verified'] and result['pair_absence_verified'] and radius.row is None


@pytest.mark.parametrize('user_present', [True, False])
def test_unknown_user_requires_its_own_absence_even_when_pair_reports_zero_references(tmp_path: Path, user_present: bool) -> None:
    selected, radius, user, _, _, _, _ = setup(tmp_path)
    user.lost_post_ack = True
    original = user.handle
    def untracked_reference(method: str, path: str, body: Any) -> Any:
        try:
            return original(method, path, body)
        finally:
            if method == 'POST':
                radius.row['q_ref'] = 0
                if not user_present: user.row = None
    user.handle = untracked_reference
    result = selected.execute(grant(selected), **IDENTITY)
    assert result['outcome'] == 'reconciliation_required' and result['all_candidate_gates_closed']
    assert not result['user_create_verified'] and not result['user_remove_verified']
    assert user.posts == 1 and user.deletes == 0
    assert result['user_absence_verified'] is not user_present
    assert radius.deletes == int(not user_present)
    assert selected._pair._recovery._store.claim_count == int(not user_present)
    assert not (selected._directory / 'create-ack.json').exists()


@pytest.mark.parametrize('mode', ['owned_delete','no_ack_absent'])
@pytest.mark.parametrize('fault', ['user_reappears','empty_collection','guard_removed','scope_drift'])
def test_fresh_parent_rechecks_user_dependency_at_final_pair_connect(tmp_path: Path, mode: str, fault: str) -> None:
    selected,radius,user,_,source,_,_=setup(tmp_path)
    saved: list[dict[str, Any]]=[]
    original=user.handle
    def user_call(method: str, path: str, body: Any) -> Any:
        try:
            result=original(method,path,body)
            if method=='POST':saved.append(dict(user.row))
            return result
        finally:
            if method=='POST'and mode=='no_ack_absent':
                if user.row is not None:saved.append(dict(user.row))
                user.row=None;radius.row['q_ref']=0
    user.handle=user_call
    user.lost_post_ack=mode=='no_ack_absent'
    changed: list[bool]=[]
    def on_connect() -> None:
        if (selected._pair._create._directory/'delete.claim.json').exists() and not changed:
            changed.append(True)
            if fault=='user_reappears':user.row=saved[0];radius.row['q_ref']=0
            elif fault=='empty_collection':user.empty_collection=True
            elif fault=='guard_removed':selected._pair_remove._user_absence=None
            else:selected._pair_remove._namespace['scope_ref']='foreign-scope'
    radius.on_connect=on_connect
    result=selected.execute(grant(selected),**IDENTITY)
    assert changed and radius.deletes==0 and result['outcome']=='reconciliation_required'
    assert result['all_candidate_gates_closed'] and not result['pair_absence_verified']
    assert selected._pair._recovery._store.claim_count==1 and len(source.calls)==4
    if fault in {'user_reappears','empty_collection'}:assert not result['user_absence_verified']
    assert user.deletes==int(mode=='owned_delete')


@pytest.mark.parametrize('boundary', ['user_create','user_remove','guard'])
def test_partial_user_preparation_without_guard_retains_original_pair(tmp_path: Path, monkeypatch: Any, boundary: str) -> None:
    from fortipam_mcp.radius_remote_user_live_workflow import RadiusRemoteUserLiveWorkflow
    from fortipam_mcp import radius_remote_user_lifecycle_workflow as module
    selected,radius,user,_,source,_,_=setup(tmp_path)
    if boundary=='guard':
        def fail(*a: Any, **k: Any) -> Any: raise ValueError('Synthetic guard preparation failure.')
        monkeypatch.setattr(module,'RadiusRemoteUserAbsenceGuard',fail)
    else:
        constructor=RadiusRemoteUserLiveWorkflow.__init__
        def initialize(self: Any, *a: Any, **k: Any) -> None:
            if k.get('operation','create')==boundary.removeprefix('user_'):
                raise ValueError('Synthetic User preparation failure.')
            constructor(self,*a,**k)
        monkeypatch.setattr(RadiusRemoteUserLiveWorkflow,'__init__',initialize)
    result=selected.execute(grant(selected),**IDENTITY)
    assert result['outcome']=='reconciliation_required' and result['all_candidate_gates_closed']
    assert radius.row is not None and radius.deletes==user.posts==user.deletes==0
    assert selected._pair._recovery._store.claim_count==0 and len(source.calls)==4
