"""Bound independent authentication with synthetic Account material and HTTP."""
from copy import deepcopy
import json

import pytest

from fortipam_mcp.ems_tag_account_authentication import EmsAccountAuthenticationProbe
from fortipam_mcp.ems_tag_account_enrollment import EmsAccountCentralEnrollment
from fortipam_mcp.ems_tag_account_custody import EmsAccountCustody
from fortipam_mcp.ems_tag_account_material_retirement import retire_recovered_account_material_once
from fortipam_mcp.ems_tag_http_transport import NativeEmsTagHttpTransport, _SIGNIN
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.ems_tag_sources import METADATA_PATH
from test_ems_tag_account_lifecycle import make, execute, reopen, recovery, close, close_recovery
from test_ems_tag_http_transport import make as base_http, reply
from test_ems_tag_role_fixture import CALLER


def setup(root, monkeypatch):
    create = root / 'create';create.mkdir(mode=0o700)
    env = make(create, monkeypatch);assert str(execute(env).outcome) == 'succeeded';original = reopen(env)
    owner = recovery(root / 'owner', monkeypatch, env, original)
    h = env['h']
    enrollment = EmsAccountCentralEnrollment(owner['source'], h.draft, h.parent, requester_digest=CALLER['requester_digest'],
        env_file=h.env, directory=h.directory, witness_key_file=h.key, clock=lambda: owner['now'][0])
    return env, original, owner, enrollment


def channel(root, monkeypatch, env, owner, *, fault=None):
    root.mkdir(mode=0o700)
    base, wire, connections, _, _, _ = base_http(root, monkeypatch)
    def credentials():raise AssertionError('Immutable credential callback must never be used')
    transport = NativeEmsTagHttpTransport(env['h'].transport._config, owner_credentials=credentials)
    metadata = deepcopy(owner['data']['metadata']);role = deepcopy(owner['data']['details'][env['h'].draft.role_uid])
    metadata['User'] = dict(id=19, name=env['h'].draft._metadata_body['name'], is_global=False, role=role)
    if fault == 'foreign_actor':metadata['User']['name'] = 'synthetic-foreign-user'
    if fault == 'wrong_role':metadata['User']['role']['uid'] = 'synthetic-foreign-role'
    if fault == 'super':metadata['User']['role']['is_super'] = True
    if fault == 'permission':metadata['User']['role']['manage_server_settings'] = True
    if fault == 'global':metadata['User']['is_global'] = True
    if fault == 'missing_permission':metadata['consts']['Permissions'].pop('SUPER')
    if fault == 'schema_drift':metadata['consts']['Permissions']['SUPER'] = 'synthetic_other_super'
    def get(path):
        assert path == METADATA_PATH
        if fault == 'owner_drift':owner['data']['user']['other_config']['enabled'] = True
        return dict(data=metadata, result=dict(retval=1, message=None))
    wire.get = get;old_connect = base._connect
    def connect():
        connection = old_connect();old_response = connection.getresponse
        def response():
            if fault == 'auth_denied' and connection.path == _SIGNIN:return reply(dict(result=dict(retval=0, message=None)), status=403)
            return old_response()
        connection.getresponse = response;return connection
    monkeypatch.setattr(transport, '_connect', connect)
    return transport, connections


def finish(env, original, owner, enrollment):
    enrollment.close();close_recovery(owner);original.close();close(env)


def test_exact_protected_authentication_binds_original_role_and_preserves_full_owner_scope(tmp_path, monkeypatch):
    env, original, owner, enrollment = setup(tmp_path, monkeypatch)
    transport, connections = channel(tmp_path / 'auth', monkeypatch, env, owner)
    probe = EmsAccountAuthenticationProbe(enrollment, original, transport, execution_enabled=True)
    proof = probe.run_once()
    assert proof.authenticated and proof.exact_role_mask and proof.own_session_closed
    assert proof.original_digest == original.inspect_verified_original().custody_digest and env['h'].loads == 2
    assert all(c.closed and not c.body for c in connections)
    assert transport._closure.own_logout_verified and transport._closure.next_session_check_401
    count = len(connections)
    with pytest.raises(ValueError):probe.run_once()
    assert len(connections) == count and env['h'].loads == 2
    second, second_connections = channel(tmp_path / 'auth-again', monkeypatch, env, owner)
    with pytest.raises(ValueError):EmsAccountAuthenticationProbe(enrollment, original, second, execution_enabled=True).run_once()
    assert not second_connections and env['h'].loads == 2
    packet = json.loads((original._store._path.parent / probe._reservation).read_bytes())
    assert 'password' not in json.dumps(packet).lower()
    finish(env, original, owner, enrollment)


@pytest.mark.parametrize('fault', ['foreign_actor', 'wrong_role', 'super', 'permission', 'global', 'owner_drift', 'auth_denied',
    'missing_permission', 'schema_drift'])
def test_authentication_mismatch_never_qualifies_and_closes_its_own_session(tmp_path, monkeypatch, fault):
    env, original, owner, enrollment = setup(tmp_path, monkeypatch)
    transport, connections = channel(tmp_path / 'auth', monkeypatch, env, owner, fault=fault)
    probe = EmsAccountAuthenticationProbe(enrollment, original, transport, execution_enabled=True)
    with pytest.raises(ValueError):probe.run_once()
    assert env['h'].loads == 2 and transport._closed and not list(transport._jar)
    assert all(c.closed and not c.body for c in connections)
    assert (original._store._path.parent / probe._reservation).is_file()
    assert not owner['writes'];finish(env, original, owner, enrollment)


def test_default_closed_authentication_does_not_load_material_or_make_test_user_requests(tmp_path, monkeypatch):
    env, original, owner, enrollment = setup(tmp_path, monkeypatch)
    transport, connections = channel(tmp_path / 'auth', monkeypatch, env, owner)
    probe = EmsAccountAuthenticationProbe(enrollment, original, transport)
    with pytest.raises(ValueError):probe.run_once()
    assert not connections and env['h'].loads == 1 and not (original._store._path.parent / probe._reservation).exists()
    finish(env, original, owner, enrollment)


def test_owner_scope_drift_before_authentication_never_loads_or_sends_credentials(tmp_path, monkeypatch):
    env, original, owner, enrollment = setup(tmp_path, monkeypatch)
    transport, connections = channel(tmp_path / 'auth', monkeypatch, env, owner)
    probe = EmsAccountAuthenticationProbe(enrollment, original, transport, execution_enabled=True)
    owner['data']['born']['trusted_hosts'] += ',192.0.2.99/32'
    with pytest.raises(ValueError):probe.run_once()
    assert not connections and env['h'].loads == 1 and not (original._store._path.parent / probe._reservation).exists()
    finish(env, original, owner, enrollment)


def test_authentication_recovery_and_retirement_join_within_the_fixed_owner_read_budget(tmp_path, monkeypatch):
    env, original, owner, enrollment = setup(tmp_path, monkeypatch)
    transport, _ = channel(tmp_path / 'auth', monkeypatch, env, owner)
    assert EmsAccountAuthenticationProbe(enrollment, original, transport, execution_enabled=True).run_once().authenticated
    result = owner['kernel'].execute(owner['issued'].plan, owner['issued'].authorization)
    assert str(result.outcome) == 'succeeded' and str(result.verification) == 'verified'
    store = owner['store']
    reader = PersistentM4ExecutionStateStore(store._path, store._key_path, monotonic_checkpoint=store._monotonic_checkpoint,
        checkpoint_store_ref=store._checkpoint_store_ref, read_only=True)
    restored = EmsAccountCustody.open_recovery(owner['custody']._directory, owner['custody']._key_file, reader, original)
    h = env['h']
    cleanup = EmsAccountCentralEnrollment(owner['source'], h.draft, h.parent, requester_digest=CALLER['requester_digest'],
        env_file=h.env, directory=h.directory, witness_key_file=h.key, execution_enabled=True, clock=lambda: owner['now'][0])
    retire_recovered_account_material_once(cleanup, restored, execution_enabled=True)
    assert h.env.read_bytes() == h.original and h.loads == 2
    assert owner['writes'] == ['/api/v1/admins/19/delete'] and owner['transport']._counts[METADATA_PATH] == 12
    cleanup.close();restored.close();finish(env, original, owner, enrollment)
