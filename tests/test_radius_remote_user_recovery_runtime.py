"""Recompose only original User recovery, without source or pair dispatch."""
from __future__ import annotations

import json
from pathlib import Path
import time
from types import SimpleNamespace
from typing import Any
import pytest
from v4_planning import canonical_digest
from fortipam_mcp import radius_remote_user_lifecycle_runtime as forward
from fortipam_mcp import radius_remote_user_recovery_runtime as runtime
from fortipam_mcp import radius_server_pair_lifecycle_runtime as pair_runtime
from fortipam_mcp.radius_remote_user_live_workflow import RadiusRemoteUserLiveWorkflow
from fortipam_mcp.radius_remote_user_contract import RadiusRemoteUserBinding
from fortipam_mcp.radius_server_pair_contract import RadiusServerPairBinding
from fortipam_mcp.radius_server_pair_owned_connect_contract import CONNECT_PATH
from test_radius_remote_user_lifecycle_runtime import setup
from test_radius_server_pair_http_transport import Peer as RadiusPeer, Response
from test_radius_remote_user_http_transport import Peer as UserPeer
from test_radius_server_projection import envelope
from test_radius_pair_fixture_material_worker import fixture, write
from test_radius_pair_fixture_material_loader import Factory, peer_script


def prepared(root: Path, monkeypatch: Any, *, identity: dict[str, str] | None = None,
        stop: bool = True, lost_delete: bool = False, mode: str = 'created') -> tuple[Any, ...]:
    monkeypatch.setattr(time, 'time', lambda: 100.0)
    env, manifest, path, paths, pair_manifest, pair_paths = setup(root)
    if identity:
        pair_manifest['identity'].update(allowed_requester_digest=identity['requester_digest'],
            allowed_transport_digest=identity['transport_digest'])
    _, inspections, policy = fixture(root / 'worker')
    policy['scope_digest'] = canonical_digest(pair_manifest['identity']['create_scope_ref'])
    policy['audience_digest'] = canonical_digest(pair_manifest['identity']['audience_ref'])
    write(root / 'worker/pair-material-policy.json', policy)
    from fortipam_mcp.radius_pair_fixture_material_worker import _digest
    pair_manifest['source']['source_policy_digest'] = _digest(policy)
    Path(manifest['pair_manifest_file']).write_text(json.dumps(pair_manifest))
    source = Factory(peer_script(root / 'worker', inspections))
    radius = RadiusPeer(); handle = radius.handle
    def response(method: str, url: str, body: Any) -> Any:
        if method == 'POST' and url == CONNECT_PATH:
            return Response(envelope(http_method='POST', action='test-connect', mkey=radius.binding.name,
                results={'status':'ok', 'access_status':'Access-Reject', 'access_message':'SYNTHETIC'}))
        return handle(method, url, body)
    radius.handle = response
    binding = RadiusRemoteUserBinding(radius=RadiusServerPairBinding(**pair_manifest['binding']), **manifest['binding'])
    user = UserPeer(SimpleNamespace(_target=SimpleNamespace(_serial=pair_manifest['identity']['expected_serial']), _binding=binding), radius)
    user.lost_delete_ack = lost_delete
    if mode=='referenced_ack':
        user_handle=user.handle
        def create_referenced_user(method: str, url: str, body: Any) -> Any:
            result=user_handle(method,url,body)
            if method=='POST':user.row['q_ref']=1
            return result
        user.handle=create_referenced_user
    if mode=='terminal_no_http_claim':
        user_handle=user.handle
        failed: list[bool]=[]
        def fail_before_http_claim(method: str, url: str, body: Any) -> Any:
            if (method=='GET' and '?action=default' in url and not failed
                    and (paths['user_state_directory']/'user-create.authority.json').exists()):
                failed.append(True)
                raise TimeoutError('Synthetic dispatch preflight failure before HTTP claim.')
            return user_handle(method,url,body)
        user.handle=fail_before_http_claim
    if mode.startswith('no_ack'):
        user.lost_post_ack=True
        user_handle=user.handle
        def lose_ack(method: str, url: str, body: Any) -> Any:
            try: return user_handle(method,url,body)
            finally:
                if method=='POST':
                    radius.row['q_ref']=0
                    if mode=='no_ack_absent': user.row=None
        user.handle=lose_ack
    create, native, recovery = pair_runtime.RadiusServerPairLiveWorkflow, pair_runtime.RadiusServerPairOwnedConnectWorkflow, pair_runtime.RadiusServerPairRecoveryWorkflow
    parent = forward.RadiusRemoteUserLifecycleWorkflow
    monkeypatch.setattr(pair_runtime, 'RadiusServerPairLiveWorkflow', lambda *a, **k: create(*a, **k, connection_factory=radius.connection, source_process_factory=source))
    monkeypatch.setattr(pair_runtime, 'RadiusServerPairOwnedConnectWorkflow', lambda *a, **k: native(*a, **k, connection_factory=radius.connection))
    monkeypatch.setattr(pair_runtime, 'RadiusServerPairRecoveryWorkflow', lambda *a, **k: recovery(*a, **k, connection_factory=radius.connection))
    monkeypatch.setattr(forward, 'RadiusRemoteUserLifecycleWorkflow', lambda *a, **k: parent(*a, **k, user_connection_factory=user.connection))
    env[forward.PREFIX + 'EXECUTION_ENABLED'] = 'true'
    selected = forward.build_radius_remote_user_lifecycle_candidate(env)
    assert selected is not None
    execute = RadiusRemoteUserLiveWorkflow.execute
    def stop_after_create(workflow: Any, *a: Any, **k: Any) -> Any:
        result = execute(workflow, *a, **k)
        if stop and workflow is selected._workflow._user_create: selected.close()
        return result
    with monkeypatch.context() as scoped:
        scoped.setattr(RadiusRemoteUserLiveWorkflow, 'execute', stop_after_create)
        if mode=='pre_kernel_marker':
            retain=RadiusRemoteUserLiveWorkflow._retain_original_authority
            def stop_after_marker(workflow: Any) -> None:
                retain(workflow)
                raise RuntimeError('Synthetic stop after marker fsync before M4 reservation.')
            scoped.setattr(RadiusRemoteUserLiveWorkflow,'_retain_original_authority',stop_after_marker)
        if mode=='unattempted':
            build=parent._build_users
            def stop_before_user(workflow: Any) -> None:
                build(workflow)
                if workflow is selected._workflow: selected.close()
            scoped.setattr(parent,'_build_users',stop_before_user)
        namespace = pair_manifest['identity']
        identity = dict(requester_digest=namespace['allowed_requester_digest'], transport_digest=namespace['allowed_transport_digest'])
        p = selected._workflow.preview(**identity)
        a = selected._workflow.authorize(p['preview_ref'], **identity)
        result = selected._workflow.execute(a['authorization_ref'], **identity)
    assert result['user_create_verified'] is (mode=='created')
    assert radius.posts==1 and user.posts==int(mode not in {'unattempted','terminal_no_http_claim','pre_kernel_marker'})
    if stop:
        assert radius.row is not None and not user.deletes and not radius.deletes
        assert (user.row is not None) is (mode not in {'unattempted','no_ack_absent','terminal_no_http_claim','pre_kernel_marker'})
    env = {k:v for k,v in env.items() if not k.startswith(forward.PREFIX)}
    env.update({runtime.PREFIX+'ENABLED':'true', runtime.PREFIX+'STARTUP_MANIFEST_FILE':str(path)})
    workflow_class = runtime.RadiusRemoteUserLiveWorkflow
    monkeypatch.setattr(runtime, 'RadiusRemoteUserLiveWorkflow', lambda *a, **k: workflow_class(*a, **k, connection_factory=user.connection))
    pair_recovery_class = runtime.RadiusServerPairRecoveryWorkflow
    monkeypatch.setattr(runtime, 'RadiusServerPairRecoveryWorkflow', lambda *a, **k: pair_recovery_class(*a, **k, connection_factory=radius.connection))
    preparation_class = runtime.RadiusRemoteUserPreparationReader
    monkeypatch.setattr(runtime, 'RadiusRemoteUserPreparationReader', lambda *a, **k: preparation_class(*a, **k, connection_factory=user.connection))
    return env, manifest, path, paths, pair_manifest, pair_paths, radius, user, source, identity, selected


def test_disabled_has_no_io_and_bad_flags_fail(monkeypatch: Any) -> None:
    monkeypatch.setattr(runtime, '_profile', lambda *a: pytest.fail('Disabled profile read files.'))
    assert runtime.build_radius_remote_user_recovery_candidate({}) is None
    for flags in ({'ENABLED':'TRUE'}, {'ENABLED':True}, {'EXECUTION_ENABLED':'true'}, {'ENABLED':'true','EXECUTION_ENABLED':'yes'}):
        with pytest.raises(ValueError): runtime.build_radius_remote_user_recovery_candidate({runtime.PREFIX+k:v for k,v in flags.items()})


def test_original_stores_recompose_without_create_native_material_or_namespace_write(tmp_path: Path, monkeypatch: Any) -> None:
    env, _, _, paths, _, pair_paths, radius, user, source, identity, original = prepared(tmp_path, monkeypatch)
    before = {p:p.read_bytes() for directory in (paths['user_state_directory'], pair_paths['state_directory']) for p in directory.iterdir()}
    counts = (len(radius.connections), len(user.connections), len(source.calls))
    for name in ('RadiusServerPairLiveWorkflow', 'RadiusServerPairOwnedConnectWorkflow'):
        monkeypatch.setattr(pair_runtime, name, lambda *a, **k: pytest.fail('Recovery constructed a forward workflow.'))
    recovery = runtime.build_radius_remote_user_recovery_candidate(env)
    assert recovery is not None and not recovery._enabled and recovery._workflow._target._recovery_only
    assert counts == (len(radius.connections), len(user.connections), len(source.calls))
    assert all(p.read_bytes() == value for p,value in before.items())
    p = recovery._workflow.preview(**identity)
    with pytest.raises(Exception): recovery._workflow.authorize(p['preview_ref'], **identity)
    recovery.close()
    env[runtime.PREFIX+'EXECUTION_ENABLED'] = 'true'
    recovery = runtime.build_radius_remote_user_recovery_candidate(env)
    w = recovery._workflow
    p = w.preview(**identity); a = w.authorize(p['preview_ref'], **identity)
    assert w.execute(a['authorization_ref'], **identity)['outcome'] == 'succeeded'
    assert user.row is None and radius.row is not None and user.deletes == 1 and radius.deletes == 0
    assert len(source.calls) == counts[2] and len(radius.connections) == counts[0]
    assert w.reconcile(**identity)['user_absence_verified']
    assert original._workflow._user_stores[0].claim_count == w._store.claim_count == 1
    recovery.close()
    repeated = runtime.build_radius_remote_user_recovery_candidate(env)
    with pytest.raises(Exception): repeated._workflow.preview(**identity)
    assert repeated._workflow.reconcile(**identity)['prior_m4_outcome_unchanged']
    repeated.close()


@pytest.mark.parametrize('fault', ['missing_user_db','missing_pair_db','missing_pin','missing_handoff','missing_remove_namespace',
    'missing_ack','foreign_authority','user_key_drift','pair_key_drift','manifest_drift','forward_enabled','pair_enabled','unknown_flag'])
def test_recovery_never_repairs_missing_or_foreign_original_inputs(tmp_path: Path, monkeypatch: Any, fault: str) -> None:
    env, manifest, path, paths, _, pair_paths, radius, user, source, _, _ = prepared(tmp_path, monkeypatch)
    if fault == 'missing_user_db': paths['user_remove_database_file'].unlink()
    elif fault == 'missing_pair_db': pair_paths['native_secondary_database_file'].unlink()
    elif fault == 'missing_pin': (pair_paths['state_directory']/'runtime.namespace.json').unlink()
    elif fault == 'missing_handoff': (paths['user_state_directory']/'radius-target.handoff.json').unlink()
    elif fault == 'missing_remove_namespace': (paths['user_state_directory']/'user-remove.runtime.json').unlink()
    elif fault == 'missing_ack': (paths['user_state_directory']/'create-ack.json').unlink()
    elif fault == 'foreign_authority': (paths['user_state_directory']/'user-create.authority.json').write_text('{}')
    elif fault == 'user_key_drift': paths['user_create_execution_key_file'].write_bytes(b'x'*32)
    elif fault == 'pair_key_drift': pair_paths['parent_authority_key_file'].write_bytes(b'x'*32)
    elif fault == 'manifest_drift':
        manifest['identity']['user_remove_scope_ref'] = 'foreign-removal'; path.write_text(json.dumps(manifest))
    elif fault == 'forward_enabled': env[forward.PREFIX+'ENABLED'] = 'true'
    elif fault == 'pair_enabled': env[pair_runtime.PREFIX+'ENABLED'] = 'true'
    else: env[runtime.PREFIX+'RECREATE'] = 'true'
    existing = {p for p in tmp_path.rglob('*') if p.is_file()}
    counts = len(radius.connections), len(user.connections), len(source.calls)
    with pytest.raises(ValueError, match='recovery startup is unavailable'):
        runtime.build_radius_remote_user_recovery_candidate(env)
    assert existing == {p for p in tmp_path.rglob('*') if p.is_file()}
    assert counts == (len(radius.connections), len(user.connections), len(source.calls))
    assert not user.deletes and not radius.deletes


def test_unknown_delete_reconciliation_does_not_upgrade_or_retry(tmp_path: Path, monkeypatch: Any) -> None:
    env, _, _, _, _, _, radius, user, source, identity, original = prepared(tmp_path, monkeypatch, stop=False, lost_delete=True)
    w = original._workflow._user_remove
    before = tuple(w._store.audit_events)
    assert before[0].verification.value == 'unknown'
    recovery = runtime.build_radius_remote_user_recovery_candidate(env)
    assert recovery._workflow.reconcile(**identity)['user_absence_verified']
    with pytest.raises(Exception): recovery._workflow.preview(**identity)
    assert tuple(w._store.audit_events) == before and w._store.claim_count == 1
    assert radius.deletes == user.deletes == 1 and len(source.calls) == 4
    recovery.close()


@pytest.mark.parametrize('role', ['user_remove','user_create','radius_create'])
def test_key_drift_after_startup_denies_before_device_io(tmp_path: Path, monkeypatch: Any, role: str) -> None:
    env, _, _, paths, _, pair_paths, radius, user, source, identity, _ = prepared(tmp_path,monkeypatch)
    recovery = runtime.build_radius_remote_user_recovery_candidate(env)
    path = pair_paths['create_execution_key_file'] if role=='radius_create' else paths[role+'_execution_key_file']
    path.write_bytes(b'x'*32)
    counts = len(radius.connections),len(user.connections),len(source.calls)
    with pytest.raises(Exception): recovery._workflow.preview(**identity)
    with pytest.raises(Exception): recovery._workflow.reconcile(**identity)
    assert counts == (len(radius.connections),len(user.connections),len(source.calls))
    recovery.close()


@pytest.mark.parametrize('target', ['pin','remove_namespace'])
def test_disappearing_namespace_is_not_recreated_during_composition(tmp_path: Path, monkeypatch: Any, target: str) -> None:
    env, _, _, paths, _, pair_paths, radius, user, source, _, _ = prepared(tmp_path,monkeypatch)
    if target=='pin':
        path = pair_paths['state_directory']/'runtime.namespace.json'
        original = pair_runtime._pin
        def pin(*a: Any, **k: Any) -> Any:
            path.unlink()
            return original(*a,**k)
        monkeypatch.setattr(pair_runtime,'_pin',pin)
    else:
        path = paths['user_state_directory']/'user-remove.runtime.json'
        original_workflow = runtime.RadiusRemoteUserLiveWorkflow
        def compose(*a: Any, **k: Any) -> Any:
            path.unlink()
            return original_workflow(*a,**k)
        monkeypatch.setattr(runtime,'RadiusRemoteUserLiveWorkflow',compose)
    counts = len(radius.connections),len(user.connections),len(source.calls)
    with pytest.raises(ValueError): runtime.build_radius_remote_user_recovery_candidate(env)
    assert not path.exists() and counts==(len(radius.connections),len(user.connections),len(source.calls))


@pytest.mark.parametrize('mode', ['created','unattempted','no_ack_absent','no_ack_present','terminal_no_http_claim','pre_kernel_marker'])
def test_separate_process_uses_existing_runtime_without_source_or_authority_renewal(tmp_path: Path, monkeypatch: Any, mode: str) -> None:
    import subprocess
    import sys
    env, _, _, paths, _, pair_paths, radius, user, source, identity, original = prepared(tmp_path,monkeypatch,mode=mode)
    env[runtime.PREFIX+'EXECUTION_ENABLED']='true'
    packet = tmp_path/'restart.json'
    packet.write_text(json.dumps({'environment':env,'identity':identity,'mode':mode,
        'backend':{'schema':user.schema,'defaults':user.defaults,'row':user.row},
        'radius_backend':{'defaults':radius.defaults,'row':radius.row}}))
    packet.chmod(0o600)
    key_bytes = {p:p.read_bytes() for p in (*paths.values(),*pair_paths.values()) if p.name.endswith('key_file.fixture')}
    code = r'''
import json,sys,time
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,sys.argv[2])
from fortipam_mcp import radius_remote_user_recovery_runtime as runtime
from fortipam_mcp import radius_server_pair_lifecycle_runtime as pair_runtime
from fortipam_mcp.radius_remote_user_contract import RadiusRemoteUserBinding
from fortipam_mcp.radius_server_pair_contract import RadiusServerPairBinding
from test_radius_remote_user_http_transport import Peer
from test_radius_server_pair_http_transport import Peer as RadiusPeer
time.time=lambda:1000.0
packet=json.loads(Path(sys.argv[1]).read_bytes())
manifest=json.loads(Path(packet['environment'][runtime.PREFIX+'STARTUP_MANIFEST_FILE']).read_bytes())
pair=json.loads(Path(manifest['pair_manifest_file']).read_bytes())
b=RadiusRemoteUserBinding(radius=RadiusServerPairBinding(**pair['binding']),**manifest['binding'])
radius=RadiusPeer()
for k,v in packet['radius_backend'].items():setattr(radius,k,v)
user=Peer(SimpleNamespace(_target=SimpleNamespace(_serial=pair['identity']['expected_serial']),_binding=b),radius)
for k,v in packet['backend'].items():setattr(user,k,v)
workflow=runtime.RadiusRemoteUserLiveWorkflow
runtime.RadiusRemoteUserLiveWorkflow=lambda *a,**k:workflow(*a,**k,connection_factory=user.connection)
preparation=runtime.RadiusRemoteUserPreparationReader
runtime.RadiusRemoteUserPreparationReader=lambda *a,**k:preparation(*a,**k,connection_factory=user.connection)
pair_workflow=runtime.RadiusServerPairRecoveryWorkflow
runtime.RadiusServerPairRecoveryWorkflow=lambda *a,**k:pair_workflow(*a,**k,connection_factory=radius.connection)
def forbidden(*a,**k):raise AssertionError('Forward/source construction is forbidden.')
for name in ('RadiusServerPairLiveWorkflow','RadiusServerPairOwnedConnectWorkflow'):
    setattr(pair_runtime,name,forbidden)
selected=runtime.build_radius_remote_user_recovery_candidate(packet['environment'])
w=selected._workflow
mode=packet['mode'];before=tuple(w._original_store.audit_events)
if mode=='created':
    p=w.preview(**packet['identity']);a=w.authorize(p['preview_ref'],**packet['identity'])
    assert w.execute(a['authorization_ref'],**packet['identity'])['outcome']=='succeeded'
    assert w.reconcile(**packet['identity'])['user_absence_verified']
else:
    result=w.inspect_cleanup_state(**packet['identity'])
    assert result['user_absence_verified'] is (mode!='no_ack_present')
    assert result['user_ownership_or_delete_authority_granted'] is False
    try:w.preview(**packet['identity']);raise AssertionError('No User ACK may grant User recovery.')
    except Exception as error:
        if isinstance(error,AssertionError):raise
if mode=='no_ack_present':
    try:selected._pair.preview(**packet['identity']);raise AssertionError('A live User cannot grant pair recovery.')
    except Exception as error:
        if isinstance(error,AssertionError):raise
else:
    p=selected._pair.preview(**packet['identity']);a=selected._pair.authorize(p['preview_ref'],**packet['identity'])
    assert selected._pair.execute(a['authorization_ref'],**packet['identity'])['outcome']=='succeeded'
    assert selected._pair.reconcile(**packet['identity'])['pair_absence_verified']
assert user.posts==radius.posts==0 and user.deletes==int(mode=='created')
assert radius.deletes==int(mode!='no_ack_present')
assert tuple(w._original_store.audit_events)==before
selected.close()
print('original-runtime-user-recovery-verified')
'''
    result = subprocess.run([sys.executable,'-c',code,str(packet),str(Path(__file__).parent)],capture_output=True,text=True,timeout=30)
    assert result.returncode==0, result.stderr
    assert result.stdout.strip()=='original-runtime-user-recovery-verified'
    assert all(p.read_bytes()==value for p,value in key_bytes.items())
    w = original._workflow
    assert w._user_stores[0].claim_count==int(mode not in {'unattempted','pre_kernel_marker'})
    assert w._user_stores[1].claim_count==len(w._user_stores[1].audit_events)==int(mode=='created')
    assert w._pair._recovery._store.claim_count==int(mode!='no_ack_present')
    assert radius.deletes==0 and len(source.calls)==4
