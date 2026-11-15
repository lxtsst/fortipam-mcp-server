"""Original Account/material with real local M4 and synthetic EMS replies."""
import hashlib
import json
from copy import deepcopy

import pytest
from v4_planning import M4ExecutionKernel, M4AuthorizationDenied

from fortipam_mcp.ems_tag_account_tag_source import EmsOriginalAccountTagSession
from fortipam_mcp.ems_tag_account_enrollment import EmsAccountCentralEnrollment
from fortipam_mcp.ems_tag_account_tag_preclaim import EmsTagPreclaimRecoveryPreparation
from fortipam_mcp.ems_tag_authority import EmsTagCreateAuthority
from fortipam_mcp.ems_tag_contract import EmsTagFullScope, qualify_tag_catalog, qualify_tag_detail
from fortipam_mcp.ems_tag_create_m4_adapter import NativeEmsTagCreateM4Adapter
from fortipam_mcp.ems_tag_custody import EmsTagOriginalActorBinding, EmsTagOriginalCustody, EmsTagCustodyError
from fortipam_mcp.ems_tag_recovery_contract import EmsTagOwnedRecoveryScope
from fortipam_mcp.ems_tag_sources import EmsTagSources, EmsTagSourceError, CATALOG_PATH
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_ems_tag_account_authentication import channel as account_channel
from test_ems_tag_account_lifecycle import recovery as account_owner, close_recovery
from test_ems_tag_account_tag_read import make as read_fixture, close as close_fixture
from test_ems_tag_contract import catalog, detail, envelope, full_scope
from test_ems_tag_http_transport import reply
from test_ems_tag_recovery_runtime import assemble
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF


def make(root, monkeypatch, *, enabled=True, fault=None):
    h = read_fixture(root, monkeypatch)
    state = dict(scope=full_scope())
    for transport in (h['reference'], h['transport']):
        underlying = transport._connect
        def connect(underlying=underlying, transport=transport):
            c = underlying();receive = c.getresponse
            def response():
                if c.path == CATALOG_PATH:
                    scope = EmsTagFullScope(qualify_tag_catalog(catalog()), ()) if fault == 'subset' and transport is h['transport'] else state['scope']
                    return reply(envelope(dict(tags=[json.loads(row) for row in scope.catalog._rows], total=scope.catalog.count)))
                if c.path.startswith('/api/v1/tags/zero_trust/') and c.path.endswith('/get'):
                    identifier = int(c.path.split('/')[-2])
                    return reply(envelope(json.loads(next(d._raw for d in state['scope'].details if d._id == identifier))))
                if transport is h['transport'] and fault == 'permission' and c.path == '/api/v1/init_consts':
                    result = receive();value = json.loads(result.read());result.close()
                    value['data']['User']['role']['manage_server_settings'] = True
                    return reply(value)
                return receive()
            c.getresponse = response;return c
        monkeypatch.setattr(transport, '_connect', connect)
    h['state'] = state
    h['session'] = EmsOriginalAccountTagSession(h['enrollment'], h['original'], h['transport'], h['tags'],
        source_key=b'Q'*32, phase='create', execution_enabled=enabled)
    return h


def added(draft):
    base = full_scope()
    rows = [json.loads(row) for row in base.catalog._rows]
    rows.append(dict(id=101, name=draft._name, status=False, rule_set_id=1010))
    return EmsTagFullScope(qualify_tag_catalog(catalog(*rows)),
        (*base.details, qualify_tag_detail(envelope(detail(draft)))))


def creation(root, h):
    root.mkdir(mode=0o700);(root/'custody').mkdir(mode=0o700)
    source = h['source'];caller = dict(requester_digest=h['enrollment']._requester, transport_digest='8'*64)
    authority = EmsTagCreateAuthority(source, authority_key=b'A'*32, execution_enabled=True,
        environment_ref='ems-home-lab', scope_ref='ems-account-tag-create', audience_ref='private-account-test',
        clock=lambda:h['owner']['now'][0], **caller)
    observed = source._current;issued = authority.issue(authority.preview(observed, **caller), observed, **caller)
    for name, value in [('execution.key', b'B'*32), ('custody.key', b'C'*32)]:
        (root/name).write_bytes(value);(root/name).chmod(0o600)
    store = PersistentM4ExecutionStateStore(root/'execution.sqlite', root/'execution.key',
        monotonic_checkpoint=_ExternalM4Checkpoint(), checkpoint_store_ref=CHECKPOINT_STORE_REF)
    custody = EmsTagOriginalCustody(root/'custody', root/'custody.key', source._draft,
        observed.full_scope.digest, issued.plan, issued.authorization, store,
        source_context_digest=source.source_context_digest, clock=lambda:h['owner']['now'][0], actor_binding=EmsTagOriginalActorBinding(
            h['transport'].session_binding_digest(source._key), caller['transport_digest'], hashlib.sha256(authority._key).hexdigest()))
    adapter = NativeEmsTagCreateM4Adapter(transport=h['transport'], sources=source, authority=authority,
        issued=issued, store=store, custody=custody, execution_enabled=True)
    return authority, issued, custody, adapter, M4ExecutionKernel(adapter, authority, store, clock=lambda:h['owner']['now'][0])


def install_writer(monkeypatch, transport, state, writes, draft, *, denied=False):
    underlying = transport._connect
    def connect():
        c = underlying();receive = c.getresponse
        def response():
            if c.path.endswith('/create'):
                assert c.method == 'POST' and json.loads(c.body) == draft._body
                writes.append('create')
                if denied:return reply(dict(result=dict(retval=0, message=None)), status=403)
                state['scope'] = added(draft)
                return reply(dict(result=dict(retval=1, message=None)))
            if c.path.endswith('/delete'):
                assert c.method == 'POST' and json.loads(c.body) == dict(ids=[101])
                writes.append('delete');state['scope'] = full_scope()
                return reply(dict(result=dict(retval=1, message=None)))
            if c.path == CATALOG_PATH:
                scope = state['scope']
                return reply(envelope(dict(tags=[json.loads(row) for row in scope.catalog._rows], total=scope.catalog.count)))
            if c.path.startswith('/api/v1/tags/zero_trust/') and c.path.endswith('/get'):
                identifier = int(c.path.split('/')[-2])
                return reply(envelope(json.loads(next(d._raw for d in state['scope'].details if d._id == identifier))))
            return receive()
        c.getresponse = response;return c
    monkeypatch.setattr(transport, '_connect', connect)


@pytest.mark.parametrize('interrupted', [False, True])
def test_account_create_and_independent_original_recovery_keep_exact_sources_and_m4_guards(tmp_path, monkeypatch, interrupted):
    h = make(tmp_path, monkeypatch);source = h['session'].open_once();h['source'] = source
    assert type(source) is EmsTagSources and h['env']['h'].loads == 2
    authority, issued, custody, adapter, kernel = creation(tmp_path/'tag-create', h)
    writes = [];install_writer(monkeypatch, h['transport'], h['state'], writes, source._draft)
    result = kernel.execute(issued.plan, issued.authorization)
    assert str(result.outcome) == 'succeeded' and str(result.verification) == 'verified' and writes == ['create']
    assert kernel.execute(issued.plan, issued.authorization).idempotent_replay and writes == ['create']
    stable_source = source.source_context_digest
    assert h['session'].close().next_session_check_401
    adapter.close();authority.close();custody.close()
    store = custody._store
    reader = PersistentM4ExecutionStateStore(store._path, store._key_path, read_only=True,
        monotonic_checkpoint=store._monotonic_checkpoint, checkpoint_store_ref=store._checkpoint_store_ref)
    original = EmsTagOriginalCustody(custody._directory, custody._key_file, source._draft, custody._baseline,
        issued.plan, issued.authorization, reader, source_context_digest=custody._source, actor_binding=custody._actor_binding)
    h['tags'].close();h['enrollment'].close();close_recovery(h['owner'])
    owner = account_owner(tmp_path/'recover-owner', monkeypatch, h['env'], h['original'])
    owner['data']['metadata']['consts'] = deepcopy(h['owner']['data']['metadata']['consts'])
    previous = h['env']['h']
    enrollment = EmsAccountCentralEnrollment(owner['source'], previous.draft, previous.parent,
        requester_digest=h['enrollment']._requester, env_file=previous.env, directory=previous.directory,
        witness_key_file=previous.key, clock=lambda:owner['now'][0])
    reference = owner['transport'].make_readonly_tag_reference(source._draft, source_key=b'W'*32, reference_enabled=True)
    reference._clock = lambda:owner['now'][0]
    second, connections = account_channel(tmp_path/'recover-account', monkeypatch, h['env'], owner)
    underlying = second._connect
    def connect():
        c = underlying();receive = c.getresponse
        def response():
            if c.path == '/api/v1/auth/signin':
                return reply(envelope(None), extra=b'Set-Cookie: sessionid=independent-tag-recovery; Path=/; Secure; HttpOnly\r\n')
            return receive()
        c.getresponse = response;return c
    monkeypatch.setattr(second, '_connect', connect)
    install_writer(monkeypatch, second, h['state'], writes, source._draft)
    install_writer(monkeypatch, owner['transport'], h['state'], writes, source._draft)
    session = EmsOriginalAccountTagSession(enrollment, h['original'], second, reference, source_key=source._key,
        phase='recover', tag_original=original, execution_enabled=True)
    recovered_source = session.open_once()
    assert recovered_source.source_context_digest == stable_source and h['env']['h'].loads == 3
    preserved_purpose = None
    if interrupted:
        # The authentication purpose is spent, but no M4 recovery was prepared,
        # claimed or sent. Its signed record survives the new preparation.
        purpose = h['original']._store._path.parent/session._reservation
        preserved_purpose = purpose.read_bytes()
        abandoned_root = tmp_path/'abandoned';abandoned_root.mkdir(mode=0o700)
        (abandoned_root/'custody').mkdir(mode=0o700)
        (abandoned_root/'execution.key').write_bytes(b'I'*32);(abandoned_root/'execution.key').chmod(0o600)
        checkpoint = _ExternalM4Checkpoint()
        abandoned = PersistentM4ExecutionStateStore(abandoned_root/'execution.sqlite', abandoned_root/'execution.key',
            monotonic_checkpoint=checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF)
        readonly = PersistentM4ExecutionStateStore(abandoned._path, abandoned._key_path, read_only=True,
            monotonic_checkpoint=checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF)
        second.close();recovered_source.close();reference.close();enrollment.close();close_recovery(owner)
        owner = account_owner(tmp_path/'resumed-owner', monkeypatch, h['env'], h['original'])
        owner['now'][0] = 2901;owner['source'].observe()
        owner['data']['metadata']['consts'] = deepcopy(h['owner']['data']['metadata']['consts'])
        enrollment = EmsAccountCentralEnrollment(owner['source'], previous.draft, previous.parent,
            requester_digest=h['enrollment']._requester, env_file=previous.env, directory=previous.directory,
            witness_key_file=previous.key, clock=lambda:owner['now'][0])
        with pytest.raises(ValueError):enrollment.reference
        reference = owner['transport'].make_readonly_tag_reference(source._draft, source_key=b'X'*32, reference_enabled=True)
        reference._clock = lambda:owner['now'][0]
        second, connections = account_channel(tmp_path/'resumed-account', monkeypatch, h['env'], owner)
        underlying_resume = second._connect
        def resume_connect():
            c = underlying_resume();receive = c.getresponse
            def response():
                if c.path == '/api/v1/auth/signin':
                    return reply(envelope(None), extra=b'Set-Cookie: sessionid=resumed-tag-recovery; Path=/; Secure; HttpOnly\r\n')
                return receive()
            c.getresponse = response;return c
        monkeypatch.setattr(second, '_connect', resume_connect)
        install_writer(monkeypatch, second, h['state'], writes, source._draft)
        install_writer(monkeypatch, owner['transport'], h['state'], writes, source._draft)
        # Expired enrollment alone, a writable ledger or any spent M4 claim
        # cannot obtain the new protected authentication preparation.
        with pytest.raises(ValueError):
            EmsOriginalAccountTagSession(enrollment, h['original'], second, reference, source_key=source._key,
                phase='recover', tag_original=original, execution_enabled=True)
        with pytest.raises(ValueError):
            EmsTagPreclaimRecoveryPreparation(enrollment, h['original'], original, abandoned, source_key=source._key)
        claim_count = PersistentM4ExecutionStateStore.claim_count
        with monkeypatch.context() as patch:
            patch.setattr(PersistentM4ExecutionStateStore, 'claim_count', property(
                lambda store:1 if store is readonly else claim_count.fget(store)))
            with pytest.raises(ValueError):
                EmsTagPreclaimRecoveryPreparation(enrollment, h['original'], original, readonly, source_key=source._key)
        send = original._store._path.parent/(original._store._path.name+'.ems-recover.'+original._plan.plan_digest+'.json')
        exists = type(send).exists
        with monkeypatch.context() as patch:
            patch.setattr(type(send), 'exists', lambda p:True if p == send else exists(p))
            with pytest.raises(ValueError):
                EmsTagPreclaimRecoveryPreparation(enrollment, h['original'], original, readonly, source_key=source._key)
        preparation = EmsTagPreclaimRecoveryPreparation(enrollment, h['original'], original, readonly, source_key=source._key)
        saved_env = previous.env.read_bytes()
        try:
            previous.env.write_bytes(saved_env+b'#synthetic-registration-drift\n')
            with pytest.raises(ValueError):
                EmsOriginalAccountTagSession(enrollment, h['original'], second, reference, source_key=source._key,
                    phase='recover', tag_original=original, execution_enabled=True, recovery_preparation=preparation)
            assert not connections and h['env']['h'].loads == 3
        finally:
            previous.env.write_bytes(saved_env)
        session = EmsOriginalAccountTagSession(enrollment, h['original'], second, reference, source_key=source._key,
            phase='recover', tag_original=original, execution_enabled=True, recovery_preparation=preparation)
        recovered_source = session.open_once()
        assert recovered_source.source_context_digest == stable_source and h['env']['h'].loads == 4
        assert purpose.read_bytes() == preserved_purpose and readonly.claim_count == 0
        assert (purpose.parent/preparation.reservation_name).is_file()
        with pytest.raises(ValueError):preparation.require_unused()
    with pytest.raises(M4AuthorizationDenied):
        EmsTagCreateAuthority(recovered_source, authority_key=b'D'*32,
            environment_ref='ems-home-lab', scope_ref='ems-account-tag-create', audience_ref='private-account-test',
            requester_digest=h['enrollment']._requester, transport_digest='9'*64)
    scope = EmsTagOwnedRecoveryScope(transport=second, sources=recovered_source, original=original,
        requester_digest=h['enrollment']._requester, caller_transport_digest='9'*64)
    items = assemble(tmp_path/'tag-recover', scope, key=b'E'*32, store_key=b'F'*32, witness_key=b'G'*32,
        clock=lambda:owner['now'][0])
    a, recovery_issued, recovery_store, recovery_custody, recovery_adapter, recovery_kernel = items
    a._clock = lambda:owner['now'][0];recovery_kernel._clock = lambda:owner['now'][0]
    result = recovery_kernel.execute(recovery_issued.plan, recovery_issued.authorization)
    assert str(result.outcome) == 'succeeded' and str(result.verification) == 'verified' and writes == ['create', 'delete']
    assert recovery_custody.inspect_restored().restored_api_scope_digest == custody._baseline
    assert recovery_kernel.execute(recovery_issued.plan, recovery_issued.authorization).idempotent_replay
    assert session.close().next_session_check_401
    for item in (recovery_adapter, a, scope, original):item.close()
    reference.close();enrollment.close();close_recovery(owner)
    assert all(c.closed and not c.body for c in connections)
    close_fixture(h)


@pytest.mark.parametrize('material_drift', [False, True])
def test_observation_checks_live_account_boundaries_once_and_rejects_material_drift(tmp_path, monkeypatch, material_drift):
    h = make(tmp_path, monkeypatch)
    source = h['session'].open_once()
    original_check = h['session']._guard._check
    checks = []
    def check():
        checks.append(True)
        original_check()
    monkeypatch.setattr(h['session']._guard, '_check', check)
    loads = h['env']['h'].loads
    env = h['enrollment']._env
    before = env.read_bytes()
    if material_drift:
        connect = h['transport']._connect
        def changed_connection():
            connection = connect()
            receive = connection.getresponse
            def response():
                if connection.path == CATALOG_PATH and env.read_bytes() == before:
                    env.write_bytes(before + b'# changed during the read window\n')
                return receive()
            connection.getresponse = response
            return connection
        monkeypatch.setattr(h['transport'], '_connect', changed_connection)
    try:
        if material_drift:
            with pytest.raises(EmsTagSourceError):
                source.observe()
            assert source._closed and env.read_bytes() != before
        else:
            source.observe()
            assert len(checks) == 4
        assert h['env']['h'].loads == loads and not h['owner']['writes']
    finally:
        env.write_bytes(before)
        h['transport'].close()
        close_fixture(h)


@pytest.mark.parametrize('fault', ['permission', 'subset'])
def test_mismatched_actor_permissions_or_filtered_scope_never_admits_source(tmp_path, monkeypatch, fault):
    h = make(tmp_path, monkeypatch, fault=fault)
    if fault == 'subset':h['state']['scope'] = full_scope(prior_change=True)
    with pytest.raises(ValueError):h['session'].open_once()
    assert h['transport']._closed and not list(h['transport']._jar)
    assert not h['owner']['writes'];close_fixture(h)


def test_closed_gate_never_opens_or_loads_material(tmp_path, monkeypatch):
    h = make(tmp_path, monkeypatch, enabled=False)
    with pytest.raises(ValueError):h['session'].open_once()
    assert h['env']['h'].loads == 1 and not h['connections'];close_fixture(h)


def test_original_account_purpose_cannot_be_reissued_in_another_session(tmp_path, monkeypatch):
    h = make(tmp_path, monkeypatch);source = h['session'].open_once()
    assert h['session'].close().next_session_check_401
    second, connections = account_channel(tmp_path/'second', monkeypatch, h['env'], h['owner'])
    session = EmsOriginalAccountTagSession(h['enrollment'], h['original'], second, h['tags'], source_key=source._key,
        phase='create', execution_enabled=True)
    with pytest.raises(ValueError):session.open_once()
    assert not connections and h['env']['h'].loads == 2
    close_fixture(h)


@pytest.mark.parametrize('fault', ['cookie', 'reference', 'material', 'role'])
def test_changed_live_binding_blocks_authorization_without_write(tmp_path, monkeypatch, fault):
    h = make(tmp_path, monkeypatch);source = h['session'].open_once()
    if fault == 'cookie':next(c for c in h['transport']._jar if c.name == 'sessionid').value = 'rotated'
    elif fault == 'reference':h['tags']._get = lambda _:None
    elif fault == 'material':h['enrollment']._loader._password_variable_name = b'UNBOUND_SYNTHETIC'
    else:
        h['owner']['data']['born']['trusted_hosts'] += ',192.0.2.99/32'
        h['owner']['source'].observe()
    with pytest.raises(ValueError):source.require_phase('create',h['enrollment']._requester)
    with pytest.raises(EmsTagSourceError):source.source_context_digest
    assert not h['owner']['writes']
    h['transport'].close();close_fixture(h)


def test_source_phase_check_keeps_exact_source_purpose_and_requester(tmp_path,monkeypatch):
    h=make(tmp_path,monkeypatch);source=h['session'].open_once();requester=h['enrollment']._requester
    loads=h['env']['h'].loads
    try:
        source.require_phase('create',requester)
        h['session'].require_phase('create',requester)
        for phase,actor,bound in [('recover',requester,source),('create','0'*64,source),('create',requester,h['tags'])]:
            with pytest.raises(ValueError):h['session'].require_phase(phase,actor,source=bound)
        assert h['env']['h'].loads==loads and not h['owner']['writes']
    finally:
        h['transport'].close();close_fixture(h)


def test_backend_write_denial_remains_unknown_nonreplayable_and_has_no_late_birth(tmp_path, monkeypatch):
    h = make(tmp_path, monkeypatch);h['source'] = h['session'].open_once()
    authority, issued, custody, adapter, kernel = creation(tmp_path/'denied-tag', h)
    writes = [];install_writer(monkeypatch, h['transport'], h['state'], writes, h['source']._draft, denied=True)
    result = kernel.execute(issued.plan, issued.authorization)
    assert str(result.verification) == 'unknown' and writes == ['create']
    assert kernel.execute(issued.plan, issued.authorization).idempotent_replay and writes == ['create']
    with pytest.raises(EmsTagCustodyError):custody.inspect_created_scope()
    assert h['session'].close().next_session_check_401
    adapter.close();authority.close();custody.close();close_fixture(h)
