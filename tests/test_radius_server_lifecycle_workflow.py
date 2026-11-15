"""Fixed parent intent, original child M4 use, failure cleanup and no replay."""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp.radius_fixture_material_loader import RadiusFixtureMaterialLoader
from fortipam_mcp.radius_server_lifecycle_workflow import RadiusServerLifecycleWorkflow
from fortipam_mcp.radius_server_owned_connect_contract import CONNECT_PATH
from test_radius_server_material_runtime import Peer, Loader, workflow, IDENTITY, AUTHORITY_KEY
from test_radius_server_owned_connect_workflow import connect
from test_radius_server_recovery_workflow import recovery
from test_radius_server_http_transport import Response
from test_radius_server_projection import envelope


def setup(root: Path, monkeypatch: pytest.MonkeyPatch, *, fault: str | None = None,
          enabled: bool = True, identity: dict[str,str] | None = None,
          retain: bool = False) -> tuple[Any, ...]:
    peer, now = Peer(), [100]
    fake = Loader(peer.binding)
    source = object.__new__(RadiusFixtureMaterialLoader)
    source._binding = peer.binding
    source._source_digest = 'a'*64
    source._host = 'fixture.example'
    source._key = root/'source.key'
    source._known_hosts = root/'source.hosts'
    source._enabled = True
    holder: list[Any] = []
    def validate(self: Any, binding: Any, request: Any) -> Any:
        return fake.validate_prebound(binding, request)
    def load(self: Any, binding: Any, request: Any) -> bytearray:
        holder[0]._guard_material_source(binding, request)
        return fake.load_radius_material_once(binding, request)
    monkeypatch.setattr(RadiusFixtureMaterialLoader, 'validate_prebound', validate)
    monkeypatch.setattr(RadiusFixtureMaterialLoader, 'load_radius_material_once', load)
    selected=IDENTITY if identity is None else identity
    overrides={"allowed_requester_digest":selected["requester_digest"],"allowed_transport_digest":selected["transport_digest"]}
    create, _ = workflow(root, peer, now, loader=source,**overrides)
    holder.append(create)
    native, restore = connect(root, peer, now,**overrides), recovery(root, peer, now,**overrides)
    old = peer.handle
    peer.native_posts = 0
    def handle(method: str, path: str, body: Any) -> Any:
        if method == 'POST' and path == CONNECT_PATH:
            peer.native_posts += 1
            if fault == 'native_lost':raise TimeoutError('SYNTHETIC_PRIVATE')
            values = {'status':'ok','access_status':'Access-Reject','access_message':'SYNTHETIC_PRIVATE'}
            if fault == 'unqualified':values['status'] = 'reachable'
            return Response(envelope(http_method='POST',action='test-connect',mkey=peer.binding.name,results=values))
        return old(method,path,body)
    peer.handle = handle
    if fault == 'create_lost':peer.lost_post_ack = True
    if fault == 'recovery_lost':peer.lost_delete_ack = True
    parent = RadiusServerLifecycleWorkflow(create,native,restore,source,
        authority_key=AUTHORITY_KEY,execution_enabled=enabled,retain_on_success=retain)
    return parent,peer,fake,now,create,native,restore,source


def grant(parent: RadiusServerLifecycleWorkflow) -> str:
    p = parent.preview(**IDENTITY)
    return str(parent.authorize(str(p['preview_ref']),**IDENTITY)['authorization_ref'])


def restart(parent: RadiusServerLifecycleWorkflow, root: Path, peer: Any, now: list[int],
            *, identity: dict[str,str] | None = None) -> RadiusServerLifecycleWorkflow:
    source=parent._source
    fresh_source=object.__new__(RadiusFixtureMaterialLoader)
    for name in ('_binding','_source_digest','_host','_key','_known_hosts'):
        setattr(fresh_source,name,getattr(source,name))
    fresh_source._enabled=True
    selected=IDENTITY if identity is None else identity
    overrides={'allowed_requester_digest':selected['requester_digest'],
        'allowed_transport_digest':selected['transport_digest']}
    fresh_create,_=workflow(root,peer,now,loader=fresh_source,**overrides)
    return RadiusServerLifecycleWorkflow(fresh_create,connect(root,peer,now,**overrides),
        recovery(root,peer,now,**overrides),fresh_source,
        authority_key=AUTHORITY_KEY,execution_enabled=True,retain_on_success=True)


@pytest.mark.parametrize('fault',[None,'native_lost','unqualified','create_lost'])
def test_persistent_primary_retains_only_fully_verified_success(
        tmp_path: Path,monkeypatch: pytest.MonkeyPatch,fault: str | None) -> None:
    parent,peer,fake,now,create,native,restore,source=setup(tmp_path,monkeypatch,fault=fault,retain=True)
    preview=parent.preview(**IDENTITY)
    assert preview['contract']=='fortipam-v4-radius-primary-configure-candidate-v1'
    assert preview['Proposed Changes']['operation']=='configure_radius_primary'
    assert preview['Expected State']['owned_entry_retained'] is True
    reference=parent.authorize(str(preview['preview_ref']),**IDENTITY)['authorization_ref']
    result=parent.execute(str(reference),**IDENTITY)
    assert result['owned_entry_retained'] is (fault is None)
    assert result['all_candidate_gates_closed'] and not result['user_authentication_verified']
    assert fake.loads==peer.posts==1
    if fault is None:
        assert result['outcome']=='succeeded' and not result['original_ack_removal_verified']
        assert peer.row is not None and peer.deletes==restore._store.claim_count==0
        with pytest.raises(ValueError):parent.preview_removal(**IDENTITY)
    elif fault!='create_lost':
        assert peer.deletes==restore._store.claim_count==1
        assert result['outcome']=='reconciliation_required'
    with pytest.raises(RuntimeError):parent.execute(str(reference),**IDENTITY)


def test_persistent_removal_after_restart_uses_original_ack_without_material(
        tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    parent,peer,fake,now,create,native,restore,source=setup(tmp_path,monkeypatch,retain=True)
    assert parent.execute(grant(parent),**IDENTITY)['owned_entry_retained']
    resumed=restart(parent,tmp_path,peer,now)
    with pytest.raises(RuntimeError):resumed.preview(**IDENTITY)
    removal=resumed.preview_removal(**IDENTITY)
    auth=resumed.authorize_removal(str(removal['preview_ref']),**IDENTITY)
    result=resumed.execute_removal(str(auth['authorization_ref']),**IDENTITY)
    assert result['outcome']=='succeeded' and result['verification']=='verified'
    assert peer.row is None and peer.deletes==resumed._recovery._store.claim_count==1
    assert fake.loads==peer.posts==peer.native_posts==1
    assert resumed._closed()
    with pytest.raises(ValueError):resumed.preview_removal(**IDENTITY)


def test_completion_mode_drift_cannot_reinterpret_authorized_qualification(
        tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    parent,peer,fake,*_=setup(tmp_path,monkeypatch)
    reference=grant(parent)
    parent._retain_on_success=True
    with pytest.raises(RuntimeError):parent.execute(reference,**IDENTITY)
    assert fake.loads==peer.posts==peer.deletes==0


@pytest.mark.parametrize('fault',[None,'native_lost','unqualified','create_lost','recovery_lost'])
def test_parent_runs_original_children_and_always_attempts_owned_recovery(
        tmp_path: Path,monkeypatch: pytest.MonkeyPatch,fault: str | None) -> None:
    parent,peer,fake,now,create,native,restore,source = setup(tmp_path,monkeypatch,fault=fault)
    reference = grant(parent)
    result = parent.execute(reference,**IDENTITY)
    assert result['outcome'] == ('succeeded' if fault is None else 'reconciliation_required')
    assert result['all_candidate_gates_closed'] and not result['user_authentication_verified']
    assert 'SYNTHETIC_PRIVATE' not in json.dumps(result)
    assert fake.loads == peer.posts == create._execution_store.claim_count == create._material_store.claim_count == 1
    if fault == 'create_lost':
        assert peer.native_posts == peer.deletes == native._store.claim_count == restore._store.claim_count == 0
    else:
        assert peer.native_posts == peer.deletes == native._store.claim_count == restore._store.claim_count == 1
        assert peer.row is None
    before = peer.posts,peer.native_posts,peer.deletes,fake.loads
    with pytest.raises(RuntimeError):parent.execute(reference,**IDENTITY)
    with pytest.raises(RuntimeError):parent.preview(**IDENTITY)
    assert before == (peer.posts,peer.native_posts,peer.deletes,fake.loads)


@pytest.mark.parametrize('fault',['operator','transport','expiry','parent_ref','child_ref','source_drift','source_route','api_route','closed'])
def test_parent_cannot_start_with_foreign_stale_child_or_changed_authority(
        tmp_path: Path,monkeypatch: pytest.MonkeyPatch,fault: str) -> None:
    parent,peer,fake,now,create,native,restore,source = setup(tmp_path,monkeypatch)
    reference = grant(parent);identity = dict(IDENTITY)
    if fault == 'operator':identity['requester_digest'] = '3'*64
    elif fault == 'transport':identity['transport_digest'] = '3'*64
    elif fault == 'expiry':now[0] = 160
    elif fault == 'parent_ref':reference = 'radius-lifecycle-auth-'+'0'*64
    elif fault == 'child_ref':reference = parent._authorization[1]
    elif fault == 'source_drift':source._source_digest = 'b'*64
    elif fault == 'source_route':source._host = 'other.example'
    elif fault == 'api_route':
        changed = replace(create._config,base_url='https://other.example')
        create._config = create._reader._config = native._transport._config = restore._transport._config = changed
    elif fault == 'closed':parent.close()
    with pytest.raises(RuntimeError):parent.execute(reference,**identity)
    assert fake.loads == peer.posts == peer.native_posts == peer.deletes == 0


def test_parent_close_revokes_before_final_create_dispatch(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    parent,peer,fake,now,*_ = setup(tmp_path,monkeypatch)
    fake.on_load = parent.close
    result = parent.execute(grant(parent),**IDENTITY)
    assert result['all_candidate_gates_closed'] and result['outcome'] != 'succeeded'
    assert peer.posts == peer.native_posts == peer.deletes == 0 and fake.loads == 1


def test_parent_restart_cannot_reopen_original_child_claims(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    parent,peer,fake,now,create,native,restore,source = setup(tmp_path,monkeypatch)
    assert parent.execute(grant(parent),**IDENTITY)['outcome'] == 'succeeded'
    replacement = RadiusServerLifecycleWorkflow(create,native,restore,source,
        authority_key=AUTHORITY_KEY,execution_enabled=True)
    before = peer.posts,peer.native_posts,peer.deletes,fake.loads
    with pytest.raises(RuntimeError):replacement.preview(**IDENTITY)
    assert before == (peer.posts,peer.native_posts,peer.deletes,fake.loads)


def test_parent_gate_is_independent(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    parent,peer,fake,*_ = setup(tmp_path,monkeypatch,enabled=False)
    with pytest.raises(RuntimeError):parent.preview(**IDENTITY)
    assert peer.posts == fake.loads == 0


def test_parent_authorization_cannot_substitute_child_reference(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    parent,peer,fake,*_=setup(tmp_path,monkeypatch)
    reference=grant(parent)
    parent._authorization=(reference,'radius-auth-'+'f'*64)
    with pytest.raises(RuntimeError):parent.execute(reference,**IDENTITY)
    assert fake.loads==peer.posts==peer.native_posts==peer.deletes==0


def test_recovery_gets_fresh_authority_after_create_expiry(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    parent,peer,fake,now,*_=setup(tmp_path,monkeypatch)
    old=peer.handle
    def expire(method: str,path: str,body: Any) -> Any:
        result=old(method,path,body)
        if method=='POST' and path!=CONNECT_PATH:now[0]=161
        return result
    peer.handle=expire
    result=parent.execute(grant(parent),**IDENTITY)
    assert result['outcome']!='succeeded' and result['original_ack_removal_verified']
    assert result['all_candidate_gates_closed'] and peer.row is None
    assert peer.posts==peer.deletes==fake.loads==1 and peer.native_posts==0


@pytest.mark.parametrize('role',['native','recovery'])
def test_child_consumption_after_parent_preview_blocks_first_write(tmp_path: Path,monkeypatch: pytest.MonkeyPatch,role: str) -> None:
    parent,peer,fake,now,create,native,restore,_=setup(tmp_path,monkeypatch)
    reference=grant(parent)
    store=native._store if role=='native'else restore._store
    store.claim(plan_ref='synthetic-orphan-reservation',requester_digest='1'*64,
        idempotency_digest='2'*64,authorization_digest='3'*64,context_digest='4'*64)
    with pytest.raises(RuntimeError):parent.execute(reference,**IDENTITY)
    assert fake.loads==peer.posts==peer.native_posts==peer.deletes==0 and store.claim_count==1
