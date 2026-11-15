"""Original pair records survive real process boundaries without forward authority."""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from fortipam_mcp.radius_remote_user_pair_handoff import load_radius_target_handoff
from fortipam_mcp.radius_remote_user_contract import RadiusRemoteUserError
from test_radius_remote_user_lifecycle_workflow import setup, IDENTITY, grant
from test_radius_remote_user_live_workflow import CREATE_KEY, REMOVE_KEY
from test_radius_server_pair_m4_runtime import store


def completed(root: Path) -> tuple[Any, ...]:
    selected, radius, user, now, source, args, mutations = setup(root)
    result = selected.execute(grant(selected), **IDENTITY)
    assert result['outcome'] == 'succeeded'
    config = selected._pair._create._config
    values = dict(user_state_directory=selected._directory, radius_state_directory=selected._pair._create._directory,
        expected_serial=selected._pair._create._serial, original_radius_store=selected._pair._create._execution_store,
        authority_key=CREATE_KEY, connection_factory=lambda *a, **k: pytest.fail('Recovery handoff made a RADIUS request.'))
    return selected, config, values, radius, user, source


def test_completed_pair_and_user_handoff_is_read_only_and_cannot_be_armed(tmp_path: Path) -> None:
    selected, config, values, radius, _, source = completed(tmp_path)
    before = {p.name: p.read_bytes() for p in selected._directory.iterdir()}
    packet = before['radius-target.handoff.json']
    for material in (config.bearer_token.encode(), CREATE_KEY, REMOVE_KEY,
            b'SYNTHETIC_STORED_PASSWORD', b'A' * 32, b'B' * 32):
        assert material not in packet
    radius_calls, material_calls = len(radius.connections), len(source.calls)
    guard = load_radius_target_handoff(config, selected._binding, **values)
    assert guard._recovery_only and guard._handoff_digest
    with pytest.raises(RadiusRemoteUserError): guard.inspect()
    guard._recovery_only = False
    with pytest.raises(RadiusRemoteUserError): guard.inspect()
    assert before == {p.name: p.read_bytes() for p in selected._directory.iterdir()}
    assert len(radius.connections) == radius_calls and len(source.calls) == material_calls
    assert selected._binding.username not in repr(guard)


@pytest.mark.parametrize('fault', ['signature', 'execution', 'extra', 'key', 'binding', 'serial', 'api',
    'store', 'original_ack', 'created', 'copied_journal', 'mode', 'symlink', 'hardlink', 'key_file', 'missing_record', 'missing_lock'])
def test_foreign_tampered_or_incomplete_handoff_never_loads(tmp_path: Path, fault: str) -> None:
    selected, config, values, _, _, source = completed(tmp_path)
    path = selected._directory / 'radius-target.handoff.json'
    binding = selected._binding
    if fault in {'signature', 'execution', 'extra'}:
        packet = json.loads(path.read_text())
        if fault == 'signature': packet['signature'] = 'f' * 64
        elif fault == 'execution': packet['payload']['execution']['plan']['requester_digest'] = 'f' * 64
        else: packet['unexpected'] = 'synthetic'
        path.write_text(json.dumps(packet))
    elif fault == 'key': values['authority_key'] = b'x' * 32
    elif fault == 'binding': binding = replace(binding, private_nonce='f' * 64)
    elif fault == 'serial': values['expected_serial'] = 'FOREIGN'
    elif fault == 'api': config = replace(config, base_url='https://foreign.example')
    elif fault == 'store': values['original_radius_store'] = store(tmp_path, 'foreign', True)
    elif fault == 'original_ack': (values['radius_state_directory'] / 'create-ack.json').unlink()
    elif fault == 'created': (values['radius_state_directory'] / 'created.json').unlink()
    elif fault == 'copied_journal':
        copy = tmp_path / 'copied-user'; copy.mkdir(mode=0o700)
        for name in ('operation.lock', 'radius-target.handoff.json'):
            (copy / name).write_bytes((selected._directory / name).read_bytes()); (copy / name).chmod(0o600)
        values['user_state_directory'] = copy
    elif fault == 'mode': path.chmod(0o644)
    elif fault == 'symlink':
        original = tmp_path / 'original-handoff'; path.rename(original); path.symlink_to(original)
    elif fault == 'hardlink': os.link(path, tmp_path / 'handoff-link')
    elif fault == 'missing_record': path.unlink()
    elif fault == 'missing_lock': (selected._directory / 'operation.lock').unlink()
    else: values['original_radius_store']._key_path.write_bytes(b'x' * 32)
    calls = len(source.calls)
    with pytest.raises(RadiusRemoteUserError): load_radius_target_handoff(config, binding, **values)
    assert len(source.calls) == calls


def test_handoff_drift_is_rejected_before_user_post(tmp_path: Path) -> None:
    selected, radius, user, _, _, _, _ = setup(tmp_path)
    done = []
    def on_connect() -> None:
        path = selected._directory / 'radius-target.handoff.json'
        if path.exists() and not done:
            done.append(True)
            packet = json.loads(path.read_text()); packet['signature'] = 'f' * 64
            path.write_text(json.dumps(packet))
    user.on_connect = on_connect
    result = selected.execute(grant(selected), **IDENTITY)
    assert done and result['outcome'] == 'reconciliation_required' and user.posts == 0
    assert user.deletes == radius.deletes == 0 and result['all_candidate_gates_closed']


def test_separate_python_process_recovers_retained_user_with_original_pins(tmp_path: Path, monkeypatch: Any) -> None:
    from fortipam_mcp.radius_remote_user_live_workflow import RadiusRemoteUserLiveWorkflow
    selected, radius, user, _, source, args, _ = setup(tmp_path)
    signing = []
    for name, key in (('create-authority.key', CREATE_KEY), ('remove-authority.key', REMOVE_KEY)):
        path = tmp_path / name; path.write_bytes(key); path.chmod(0o600); signing.append(str(path))
    execute = RadiusRemoteUserLiveWorkflow.execute
    def stop_after_user_create(workflow: Any, *a: Any, **k: Any) -> Any:
        result = execute(workflow, *a, **k)
        if workflow is selected._user_create: selected.close()
        return result
    monkeypatch.setattr(RadiusRemoteUserLiveWorkflow, 'execute', stop_after_user_create)
    result = selected.execute(grant(selected), **IDENTITY)
    assert result['user_create_verified'] and user.row is not None and radius.row is not None
    ns = selected._user_create._namespace
    original = selected._pair._create._execution_store
    creator, remover = args['user_create_store'], args['user_remove_store']
    manifest = {'binding': {'username': selected._binding.username, 'private_nonce': selected._binding.private_nonce,
            'radius': {k: getattr(selected._binding.radius, k) for k in ('name','server','secondary_server','private_nonce')}},
        'user_directory': str(selected._directory), 'radius_directory': str(selected._pair._create._directory),
        'serial': selected._pair._create._serial, 'radius_store': [str(original._path), str(original._key_path)],
        'creator_store': [str(creator._path), str(creator._key_path)],
        'remover_store': [str(remover._path), str(remover._key_path)], 'signing_paths': signing,
        'namespace': ns, 'remove_scope': args['user_remove_scope_ref'],
        'synthetic_backend': {'schema':user.schema, 'defaults':user.defaults, 'row':user.row}}
    path = tmp_path / 'restart.private.json'; path.write_text(json.dumps(manifest)); path.chmod(0o600)
    key_bytes = {p: Path(p).read_bytes() for p in (*manifest['radius_store'][1:], *manifest['creator_store'][1:], *manifest['remover_store'][1:], *signing)}
    code = r'''
import json,sys
from pathlib import Path
from types import SimpleNamespace
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.radius_remote_user_contract import RadiusRemoteUserBinding,RadiusRemoteUserError
from fortipam_mcp.radius_server_pair_contract import RadiusServerPairBinding
from fortipam_mcp.radius_remote_user_pair_handoff import load_radius_target_handoff
from fortipam_mcp.radius_remote_user_live_workflow import RadiusRemoteUserLiveWorkflow
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_radius_remote_user_http_transport import Peer
m=json.loads(Path(sys.argv[1]).read_bytes())
def ledger(pair,readonly):return PersistentM4ExecutionStateStore(Path(pair[0]),Path(pair[1]),read_only=readonly)
radius=RadiusServerPairBinding(**m['binding']['radius'])
binding=RadiusRemoteUserBinding(m['binding']['username'],radius,m['binding']['private_nonce'])
config=SecretMetadataHttpTransportConfig('https://pam.example','synthetic-token',1,None)
def no_radius(*a,**k):raise AssertionError('RADIUS network access is forbidden during recovery.')
target=load_radius_target_handoff(config,binding,user_state_directory=Path(m['user_directory']),
    radius_state_directory=Path(m['radius_directory']),expected_serial=m['serial'],
    original_radius_store=ledger(m['radius_store'],True),authority_key=Path(m['signing_paths'][0]).read_bytes(),
    connection_factory=no_radius)
try:target.inspect();raise AssertionError('Forward target use must fail.')
except RadiusRemoteUserError:pass
peer=Peer(target,SimpleNamespace(row={'q_ref':1}))
for key,value in m['synthetic_backend'].items():setattr(peer,key,value)
ns=m['namespace']
w=RadiusRemoteUserLiveWorkflow(binding,config,target=target,state_directory=Path(m['user_directory']),
    operation='remove',execution_store=ledger(m['remover_store'],False),
    original_create_store=ledger(m['creator_store'],True),authority_key=Path(m['signing_paths'][1]).read_bytes(),
    original_create_authority_key=Path(m['signing_paths'][0]).read_bytes(),environment_ref=ns['environment_ref'],
    scope_ref=m['remove_scope'],audience_ref=ns['audience_ref'],allowed_requester_digest=ns['requester_digest'],
    allowed_transport_digest=ns['transport_digest'],execution_enabled=True,clock=lambda:170,connection_factory=peer.connection)
identity={'requester_digest':ns['requester_digest'],'transport_digest':ns['transport_digest']}
p=w.preview(**identity);a=w.authorize(p['preview_ref'],**identity);r=w.execute(a['authorization_ref'],**identity)
assert r['outcome']=='succeeded'and r['verification']=='verified'and peer.row is None
assert peer.deletes==1 and peer.posts==0
w.close()
print(json.dumps({'recovery_verified':True,'user_deleted_once':True,'user_created':False,'radius_network_calls':0}))
'''
    env = dict(os.environ); env['PYTHONPATH'] = str(Path('tests').resolve()) + os.pathsep + env.get('PYTHONPATH', '')
    child = subprocess.run([sys.executable, '-c', code, str(path)], env=env, capture_output=True, text=True, timeout=30)
    assert child.returncode == 0, child.stderr
    assert json.loads(child.stdout) == {'recovery_verified':True,'user_deleted_once':True,'user_created':False,'radius_network_calls':0}
    assert creator.claim_count == original.claim_count == 1 and len(creator.audit_events) == len(original.audit_events) == 1
    assert remover.claim_count == len(remover.audit_events) == 1
    assert all(Path(p).read_bytes() == value for p,value in key_bytes.items())
    assert len(source.calls) == 4


def test_valid_metadata_signature_cannot_manufacture_an_original_m4_claim(tmp_path: Path) -> None:
    from fortipam_mcp.radius_remote_user_pair_handoff import _signature
    from v4_planning import canonical_digest
    selected, config, values, _, _, _ = completed(tmp_path)
    path = selected._directory / 'radius-target.handoff.json'
    packet = json.loads(path.read_text()); execution = packet['payload']['execution']
    plan, auth, lease = execution['plan'], execution['authorization'], execution['lease_request']
    plan['expected_current_digest'] = 'f' * 64
    plan['plan_digest'] = canonical_digest({k:v for k,v in plan.items() if k != 'plan_digest'})
    auth['plan_digest'] = plan['plan_digest']
    auth['authorization_digest'] = canonical_digest({k:v for k,v in auth.items() if k != 'authorization_digest'})
    lease['plan_digest'], lease['authorization_digest'] = plan['plan_digest'], auth['authorization_digest']
    packet['signature'] = _signature(packet['payload'], CREATE_KEY)
    path.write_text(json.dumps(packet))
    with pytest.raises(RadiusRemoteUserError): load_radius_target_handoff(config, selected._binding, **values)
    original = values['original_radius_store']
    assert original.claim_count == len(original.audit_events) == 1


def test_unfinished_original_m4_is_not_recovery_provenance(tmp_path: Path, monkeypatch: Any) -> None:
    from v4_planning import M4Claim, M4ClaimState
    selected, config, values, _, _, _ = completed(tmp_path)
    original = values['original_radius_store']
    monkeypatch.setattr(original, 'inspect_claim', lambda **kwargs: M4Claim(M4ClaimState.IN_PROGRESS))
    with pytest.raises(RadiusRemoteUserError): load_radius_target_handoff(config, selected._binding, **values)
    assert original.claim_count == len(original.audit_events) == 1


def test_missing_original_radius_key_epoch_stops_before_user_post(tmp_path: Path) -> None:
    selected, radius, user, _, _, _, _ = setup(tmp_path)
    reference = grant(selected)
    original = radius.handle
    changed = []
    def after_owned_pair(method: str, path: str, body: Any) -> Any:
        response = original(method, path, body)
        if len(radius.native_posts) == 2 and not changed:
            changed.append(True)
            selected._pair._create._execution_store._key_path.write_bytes(b'x' * 32)
        return response
    radius.handle = after_owned_pair
    result = selected.execute(reference, **IDENTITY)
    assert changed and result['outcome'] == 'reconciliation_required'
    assert user.posts == 0 and not (selected._directory / 'radius-target.handoff.json').exists()
    assert result['all_candidate_gates_closed']


def test_recovery_guard_denies_forward_even_for_a_live_zero_reference_pair(tmp_path: Path, monkeypatch: Any) -> None:
    from fortipam_mcp.radius_remote_user_live_workflow import RadiusRemoteUserLiveWorkflow, RadiusRemoteUserWorkflowError
    selected, radius, user, _, _, args, _ = setup(tmp_path)
    build = selected._build_users
    def stop_after_handoff() -> None:
        build(); selected.close()
    monkeypatch.setattr(selected, '_build_users', stop_after_handoff)
    result = selected.execute(grant(selected), **IDENTITY)
    assert result['outcome'] == 'reconciliation_required' and radius.row['q_ref'] == 0 and user.posts == 0
    config = selected._pair._create._config
    target = load_radius_target_handoff(config, selected._binding, user_state_directory=selected._directory,
        radius_state_directory=selected._pair._create._directory, expected_serial=selected._pair._create._serial,
        original_radius_store=selected._pair._create._execution_store, authority_key=CREATE_KEY,
        connection_factory=lambda *a, **k: pytest.fail('Recovery-only forward probe made a RADIUS request.'))
    ns = selected._user_create._namespace
    resumed = RadiusRemoteUserLiveWorkflow(selected._binding, config, target=target,
        state_directory=selected._directory, execution_store=args['user_create_store'], authority_key=CREATE_KEY,
        environment_ref=ns['environment_ref'], scope_ref=ns['scope_ref'], audience_ref=ns['audience_ref'],
        allowed_requester_digest=ns['requester_digest'], allowed_transport_digest=ns['transport_digest'],
        execution_enabled=True, clock=lambda:170, connection_factory=user.connection)
    with pytest.raises(RadiusRemoteUserWorkflowError): resumed.preview(**IDENTITY)
    assert resumed._store.claim_count == 0 and user.posts == 0
    resumed.close()
