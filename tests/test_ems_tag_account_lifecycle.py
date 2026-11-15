"""Original Account M4 creation with synthetic HTTP and central material only."""
from copy import deepcopy
import hashlib
import http.client
import json

import pytest
from v4_planning import M4ExecutionKernel

from fortipam_mcp.ems_tag_account_adapter import NativeEmsAccountM4Adapter
from fortipam_mcp.ems_tag_account_custody import EmsAccountCustody
from fortipam_mcp.ems_tag_account_recovery import EmsAccountRecoveryAuthority
from fortipam_mcp.ems_tag_account_authority import LAB_SCOPE
from fortipam_mcp.ems_tag_admin_contract import ACCOUNT_CREATE_PATH
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_ems_tag_account_authority import authority, preview, issue
from test_ems_tag_account_material import Harness
from test_ems_tag_http_transport import reply, framed
from test_ems_tag_identity_sources import make as identity_source
from test_ems_tag_role_fixture import CALLER
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF


def make(root, monkeypatch, *, fault=None, enabled=True):
    h = Harness(root, monkeypatch);h.stage(monkeypatch)
    a = authority(h);issued = issue(a, h, preview(a, h))
    h.plan, h.auth = issued.plan, issued.authorization
    directory = root / 'custody';directory.mkdir(mode=0o700)
    key = root / 'account-custody.key';key.write_bytes(b'w' * 32);key.chmod(0o600)
    custody = EmsAccountCustody(directory, key, h.store, a, clock=lambda: h.now[0]);custody.retain_before_dispatch()
    adapter = NativeEmsAccountM4Adapter(a, custody, h.material, execution_enabled=enabled)
    connect_original = h.transport._connect
    writes, bodies = [], []
    def connect():
        connection = connect_original()
        old_request, old_response, old_close = connection.request, connection.getresponse, connection.close
        def request(method, path, *, body, headers):
            old_request(method, path, body=body, headers=headers)
            if path == ACCOUNT_CREATE_PATH:
                assert method == 'POST';writes.append(path);bodies.append(body)
                value = json.loads(body)
                assert len(value.pop('password')) == 44 and value == h.draft._metadata_body
        def response():
            if connection.path == '/api/v1/admins/19/get':return reply(dict(data=h.data['born'], result=dict(retval=1, message=None)))
            if connection.path != ACCOUNT_CREATE_PATH:return old_response()
            created = dict(h.draft._metadata_body, id=19, user_type='EMS', trusted_hosts=h.draft.trusted_host,
                idps=[], inactive=False, default_site_role_uid=None)
            created.pop('idp_guids')
            if fault == 'omitted_idps':created.pop('idps')
            if fault == 'broader_trust':created['trusted_hosts'] += ',192.0.2.99/32'
            if fault == 'trust_disabled':created['trusted_hosts_enabled'] = False
            if fault == 'global':created['is_global'] = True
            if fault == 'all_domains':created['allow_all_domains'] = True
            if fault == 'domain_assignment':created['idps'] = [{'guid': 'synthetic-extra-domain'}]
            if fault == 'site_assignment':created['sites'] = [{'role_uid': h.draft.role_uid}]
            if fault == 'wrong_type':created['user_type'] = 'BuiltIn'
            if fault == 'inactive':created['inactive'] = True
            h.data['born'] = created
            h.data['admins'].append({k: created[k] for k in ('id', 'name', 'vdom', 'user_type')})
            if fault == 'old_admin_drift':h.data['user']['other_config']['enabled'] = True
            if fault == 'old_role_drift':h.data['details']['synthetic-role']['manage_server_settings'] = True
            if fault == 'lost_response':raise http.client.RemoteDisconnected()
            payload = dict(result=dict(retval=1, message=None))
            if fault == 'selector':payload['data'] = {'id': 19}
            if fault == 'wrong_selector':payload['data'] = {'id': 20}
            if fault == 'partial_frame':
                raw = json.dumps(payload).encode();return framed(f'Content-Length: {len(raw)+1}\r\n'.encode(), raw)
            if fault == 'duplicate_json':return reply(body=b'{"result":{"retval":1,"retval":0,"message":null}}')
            if fault == 'expiry_after_send':h.now[0] = 1060
            return reply(payload)
        def close():
            old_close()
            if fault == 'close_failure' and getattr(connection, 'path', None) == ACCOUNT_CREATE_PATH:raise OSError('Synthetic close failure')
        connection.request, connection.getresponse, connection.close = request, response, close
        return connection
    monkeypatch.setattr(h.transport, '_connect', connect)
    kernel = M4ExecutionKernel(adapter, a, h.store, clock=lambda: h.now[0])
    return dict(h=h, authority=a, custody=custody, adapter=adapter, kernel=kernel, writes=writes, bodies=bodies)


def execute(env):
    return env['kernel'].execute(env['h'].plan, env['h'].auth)


def reopen(env):
    store = env['h'].store
    reader = PersistentM4ExecutionStateStore(store._path, store._key_path, monotonic_checkpoint=store._monotonic_checkpoint,
        checkpoint_store_ref=store._checkpoint_store_ref, read_only=True)
    return EmsAccountCustody.open_original(env['custody']._directory, env['custody']._key_file, reader)


def close(env):
    env['adapter'].close();env['authority'].close();env['custody'].close();env['h'].close()


@pytest.mark.parametrize('fault',['ack_signature','reservation_link','effect_link','closing_witness_key','closing_store_key'])
def test_original_account_read_chain_rejects_record_links_and_closing_drift(tmp_path,monkeypatch,fault):
    env=make(tmp_path,monkeypatch);assert str(execute(env).verification)=='verified'
    original=reopen(env);counts=dict(env['h'].transport._counts);restore=None
    if fault.startswith('closing_'):
        path=original._key_file if fault=='closing_witness_key' else original._store._key_path
        restore=(path,path.read_bytes());check_time=original._time
        def change_key(value):
            result=check_time(value);path.write_bytes(b'changed-account-read-key-value!!!');return result
        monkeypatch.setattr(original,'_time',change_key)
    else:
        name={'ack_signature':'ack.json','reservation_link':'send.json','effect_link':'effect.json'}[fault]
        path=original._directory/name;restore=(path,path.read_bytes());packet=json.loads(path.read_bytes())
        if fault=='ack_signature':packet['signature']='0'*64
        else:
            field='reservation_digest' if fault=='reservation_link' else 'attempt_digest'
            packet['value'][field]='0'*64;packet['signature']=original._mac(name,packet['value'])
        path.write_text(json.dumps(packet))
    try:
        with pytest.raises(ValueError):original.inspect_verified_original()
        assert env['h'].transport._counts==counts and len(env['writes'])==1
    finally:
        if restore is not None:restore[0].write_bytes(restore[1])
        original.close();close(env)


def recovery(root, monkeypatch, env, original, *, fault=None, same_session=False, caller=None):
    root.mkdir(mode=0o700)
    source, transport, _, _, data, now = identity_source(root, monkeypatch,
        shared_config=env['h'].transport._config, source_key=b'y' * 32,
        session_value='separate-synthetic-session' if same_session else 'independent-account-recovery')
    data.update(deepcopy(env['h'].data));old_connect = transport._connect;writes = []
    def connect():
        connection = old_connect();old_response = connection.getresponse
        def response():
            if connection.path == '/api/v1/admins/19/get':return reply(dict(data=data['born'], result=dict(retval=1, message=None)))
            if connection.method != 'DELETE':return old_response()
            assert connection.path == '/api/v1/admins/19/delete' and connection.body is None;writes.append(connection.path)
            data['admins'] = [row for row in data['admins'] if row['id'] != 19]
            data.pop('born')
            if fault == 'old_admin_drift':data['user']['other_config']['enabled'] = True
            if fault == 'lost_response':raise http.client.RemoteDisconnected()
            payload = dict(result=dict(retval=1, message=None))
            if fault == 'wrong_selector':payload['data'] = {'id': 20}
            return reply(payload)
        connection.getresponse = response;return connection
    monkeypatch.setattr(transport, '_connect', connect)
    observed = source.observe();caller = caller or dict(requester_digest=CALLER['requester_digest'], transport_digest='6' * 64)
    try:
        a = EmsAccountRecoveryAuthority(source, original, authority_key=b'z' * 32, execution_enabled=True,
            clock=lambda: now[0], **LAB_SCOPE, **caller)
        issued = a.issue(a.preview(observed, **caller), observed, **caller)
    except Exception:
        source.close();assert transport.close().next_session_check_401;raise
    for name, content in [('store.key', b'j' * 32), ('custody.key', b'k' * 32)]:
        (root / name).write_bytes(content);(root / name).chmod(0o600)
    store = PersistentM4ExecutionStateStore(root / 'recovery.sqlite', root / 'store.key',
        monotonic_checkpoint=_ExternalM4Checkpoint(), checkpoint_store_ref=CHECKPOINT_STORE_REF)
    directory = root / 'custody';directory.mkdir(mode=0o700)
    custody = EmsAccountCustody(directory, root / 'custody.key', store, a, clock=lambda: now[0]);custody.retain_before_dispatch()
    adapter = NativeEmsAccountM4Adapter(a, custody, execution_enabled=True)
    kernel = M4ExecutionKernel(adapter, a, store, clock=lambda: now[0])
    return dict(source=source, transport=transport, data=data, now=now, authority=a, issued=issued, store=store,
        custody=custody, adapter=adapter, kernel=kernel, writes=writes)


def close_recovery(env):
    for key in ('adapter', 'authority', 'custody', 'source'):env[key].close()
    assert env['transport'].close().next_session_check_401


def test_separate_session_recovery_uses_only_readonly_verified_original_and_restores_full_baseline(tmp_path, monkeypatch):
    root = tmp_path / 'create';root.mkdir(mode=0o700)
    env = make(root, monkeypatch);assert str(execute(env).outcome) == 'succeeded'
    original = reopen(env);owned = original.inspect_verified_original()
    protected = {p: p.read_bytes() for p in original._directory.iterdir()}
    recover = recovery(tmp_path / 'recover', monkeypatch, env, original)
    result = recover['kernel'].execute(recover['issued'].plan, recover['issued'].authorization)
    assert str(result.outcome) == 'succeeded' and str(result.verification) == 'verified'
    assert recover['custody'].inspect_restoration() == owned
    assert recover['adapter']._post.full_scope.digest == owned.baseline_digest
    assert recover['writes'] == ['/api/v1/admins/19/delete'] and env['h'].loads == 1
    assert recover['kernel'].execute(recover['issued'].plan, recover['issued'].authorization).idempotent_replay
    store = recover['store']
    reader = PersistentM4ExecutionStateStore(store._path, store._key_path, monotonic_checkpoint=store._monotonic_checkpoint,
        checkpoint_store_ref=store._checkpoint_store_ref, read_only=True)
    recovered = EmsAccountCustody.open_recovery(recover['custody']._directory, recover['custody']._key_file, reader, original)
    assert recovered.inspect_restoration() == owned
    with pytest.raises(ValueError):recovered.inspect_verified_original()
    assert all(p.read_bytes() == raw for p, raw in protected.items())
    recovered.close();close_recovery(recover);original.close();close(env)


@pytest.mark.parametrize('fault', ['old_admin_drift', 'lost_response', 'wrong_selector'])
def test_unknown_recovery_cannot_be_late_sealed_or_replayed(tmp_path, monkeypatch, fault):
    root = tmp_path / 'create';root.mkdir(mode=0o700)
    env = make(root, monkeypatch);assert str(execute(env).outcome) == 'succeeded'
    original = reopen(env);recover = recovery(tmp_path / 'recover', monkeypatch, env, original, fault=fault)
    result = recover['kernel'].execute(recover['issued'].plan, recover['issued'].authorization)
    assert str(result.outcome) == 'reconciliation_required' and str(result.verification) == 'unknown'
    with pytest.raises(ValueError):recover['custody'].inspect_restoration()
    before = {p: p.read_bytes() for p in recover['custody']._directory.iterdir()}
    with pytest.raises(ValueError):recover['custody'].capture_effect(recover['source']._current.full_scope, recover['source']._current.full_scope)
    assert all(p.read_bytes() == raw for p, raw in before.items())
    assert recover['kernel'].execute(recover['issued'].plan, recover['issued'].authorization).idempotent_replay
    assert recover['writes'] == ['/api/v1/admins/19/delete']
    close_recovery(recover);original.close();close(env)


@pytest.mark.parametrize('fault', ['same_session', 'same_channel', 'foreign_human', 'writable_original'])
def test_recovery_refuses_nonindependent_or_unqualified_original(tmp_path, monkeypatch, fault):
    from v4_planning import M4AuthorizationDenied
    root = tmp_path / 'create';root.mkdir(mode=0o700)
    env = make(root, monkeypatch);assert str(execute(env).outcome) == 'succeeded';original = reopen(env)
    caller = dict(requester_digest='0' * 64 if fault == 'foreign_human' else CALLER['requester_digest'],
        transport_digest='f' * 64 if fault == 'same_channel' else '6' * 64)
    with pytest.raises(M4AuthorizationDenied):recovery(tmp_path / 'recover', monkeypatch, env,
        env['custody'] if fault == 'writable_original' else original, same_session=fault == 'same_session', caller=caller)
    original.close();close(env)


@pytest.mark.parametrize('ack_shape', [None, 'selector', 'omitted_idps'])
def test_original_account_birth_requires_whole_graph_ack_active_claim_and_protected_material(tmp_path, monkeypatch, ack_shape):
    env = make(tmp_path, monkeypatch, fault=ack_shape);h = env['h']
    baseline = h.source._current.full_scope.digest
    result = execute(env)
    assert str(result.outcome) == 'succeeded' and str(result.verification) == 'verified'
    original = env['custody'].inspect_verified_original()
    assert original.baseline_digest == baseline and original.created_scope_digest == h.source._current.full_scope.digest
    assert original.account_numeric_id == 19 and original.parent_digest == h.enrollment._owned.custody_digest
    assert original.material_reference == h.enrollment.reference and h.loads == 1
    assert env['writes'] == [ACCOUNT_CREATE_PATH] and all(not body for body in env['bodies'])
    assert not h.material._lease._password and not h.material._lease._username
    reader = reopen(env);assert reader.inspect_verified_original() == original
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in env['custody']._directory.iterdir()}
    count = len(env['writes']);assert execute(env).idempotent_replay and len(env['writes']) == count
    with pytest.raises(ValueError):reader.capture_effect(h.source._current.full_scope, h.source._current.full_scope)
    assert all(hashlib.sha256(p.read_bytes()).hexdigest() == sha for p, sha in before.items())
    assert all('password' not in p.read_text().lower() for p in env['custody']._directory.iterdir())
    reader.close();close(env)


@pytest.mark.parametrize('fault', ['broader_trust', 'trust_disabled', 'global', 'all_domains', 'domain_assignment', 'site_assignment',
    'wrong_type', 'inactive', 'old_admin_drift', 'old_role_drift', 'wrong_selector', 'lost_response',
    'partial_frame', 'duplicate_json', 'expiry_after_send', 'close_failure'])
def test_uncertain_account_is_consumed_without_original_reopen_late_birth_or_redispatch(tmp_path, monkeypatch, fault):
    env = make(tmp_path, monkeypatch, fault=fault);h = env['h']
    result = execute(env)
    assert str(result.outcome) == 'reconciliation_required' and str(result.verification) == 'unknown'
    assert len(env['writes']) == 1 and h.loads == 1 and all(not body for body in env['bodies'])
    with pytest.raises(ValueError):env['custody'].inspect_verified_original()
    with pytest.raises(ValueError):reopen(env)
    before = {p: p.read_bytes() for p in env['custody']._directory.iterdir()}
    with pytest.raises(ValueError):env['custody'].capture_effect(h.source._current.full_scope, h.source._current.full_scope)
    assert all(p.read_bytes() == raw for p, raw in before.items())
    if fault != 'expiry_after_send':assert execute(env).idempotent_replay
    assert len(env['writes']) == 1;close(env)


def test_closed_gate_and_prewrite_drift_do_not_resolve_material_or_send(tmp_path, monkeypatch):
    env = make(tmp_path, monkeypatch, enabled=False);h = env['h']
    result = execute(env)
    assert str(result.outcome) == 'denied' and h.loads == 0 and not env['writes']
    assert not (h.directory / 'material.used.json').exists();close(env)


def test_prewrite_scope_drift_refuses_before_resolving_material(tmp_path, monkeypatch):
    env = make(tmp_path, monkeypatch);h = env['h']
    h.data['user']['other_config']['enabled'] = True
    result = execute(env)
    assert str(result.outcome) == 'denied' and h.loads == 0 and not env['writes']
    assert not (h.directory / 'material.used.json').exists();close(env)
