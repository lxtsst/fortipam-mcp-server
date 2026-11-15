"""Signed own User M4 lifecycle; actual local kernel/store, synthetic HTTP."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp.radius_remote_user_live_workflow import RadiusRemoteUserLiveWorkflow, RadiusRemoteUserWorkflowError
from test_radius_remote_user_http_transport import setup as http_setup
from test_radius_server_pair_live_workflow import IDENTITY, grant
from test_radius_server_pair_m4_runtime import store
from v4_planning import canonical_digest

CREATE_KEY = b'synthetic-remote-user-create-key-0001'
REMOVE_KEY = b'synthetic-remote-user-remove-key-0001'


def setup(root: Path, *, enabled: bool = True) -> tuple[Any, ...]:
    _, peer, target, directory, source = http_setup(root)
    now = [100]
    original = store(root, 'user-create', True)
    common = dict(target=target, state_directory=directory, environment_ref='synthetic-radius-user-lab',
        audience_ref='synthetic-radius-user-audience', allowed_requester_digest=IDENTITY['requester_digest'],
        allowed_transport_digest=IDENTITY['transport_digest'], clock=lambda: now[0], connection_factory=peer.connection)
    values = dict(execution_store=original, authority_key=CREATE_KEY, scope_ref='synthetic-radius-user-create',
        execution_enabled=enabled, **common)
    selected = RadiusRemoteUserLiveWorkflow(target._binding, target._target._config, **values)
    def remove(**kwargs: Any) -> RadiusRemoteUserLiveWorkflow:
        remove_values = dict(operation='remove', original_create_store=original, original_create_authority_key=CREATE_KEY,
            execution_store=store(root, 'user-remove', True), authority_key=REMOVE_KEY,
            scope_ref='synthetic-radius-user-remove', execution_enabled=True, **common)
        return RadiusRemoteUserLiveWorkflow(target._binding, target._target._config, **(remove_values | kwargs))
    return selected, remove, peer, now, source, values


def test_create_shutdown_and_independent_signed_original_context_recovery(tmp_path: Path) -> None:
    create, remove, peer, now, source, _ = setup(tmp_path)
    before = len(source.calls)
    preview = create.preview(**IDENTITY)
    assert preview['summary_digest'] == canonical_digest({k:v for k,v in preview.items() if k != 'summary_digest'})
    auth = create.authorize(preview['preview_ref'], **IDENTITY)
    assert create._issued.plan.summary_digest == preview['summary_digest']
    result = create.execute(auth['authorization_ref'], **IDENTITY)
    assert result['outcome'] == 'succeeded' and result['verification'] == 'verified'
    assert peer.posts == 1 and peer.deletes == 0 and peer.radius.row['q_ref'] == 1
    assert create._store.claim_count == len(create._store.audit_events) == 1
    connections = len(peer.connections)
    assert create.execute(auth['authorization_ref'], **IDENTITY)['idempotent_replay']
    assert len(peer.connections) == connections
    create.close(); now[0] = 170
    recovery = remove()
    preview = recovery.preview(**IDENTITY)
    assert preview['summary_digest'] == canonical_digest({k:v for k,v in preview.items() if k != 'summary_digest'})
    result = recovery.execute(recovery.authorize(preview['preview_ref'], **IDENTITY)['authorization_ref'], **IDENTITY)
    assert result['outcome'] == 'succeeded' and result['verification'] == 'verified'
    assert recovery._store.claim_count == len(recovery._store.audit_events) == 1
    assert peer.row is None and peer.posts == peer.deletes == 1 and peer.radius.row['q_ref'] == 0
    assert len(source.calls) == before
    connections = len(peer.connections)
    assert recovery.execute(recovery._issued.authorization.authorization_ref, **IDENTITY)['idempotent_replay']
    assert len(peer.connections) == connections
    with pytest.raises(RadiusRemoteUserWorkflowError): remove().preview(**IDENTITY)
    output = json.dumps([preview, result, repr(recovery)])
    for private in (peer.username, peer.serial, str(tmp_path), peer.guard._binding.radius.name):
        assert private not in output


@pytest.mark.parametrize('operation', ['create', 'remove'])
@pytest.mark.parametrize('fault', ['identity', 'expiry', 'clock', 'gate', 'scope', 'plan', 'key', 'store', 'callback', 'clock_callback'])
def test_authority_identity_freshness_and_composition_drift_prevents_dispatch(tmp_path: Path, operation: str, fault: str) -> None:
    create, remove, peer, now, source, _ = setup(tmp_path)
    selected = create
    if operation == 'remove':
        assert create.execute(grant(create), **IDENTITY)['outcome'] == 'succeeded'
        selected = remove()
    reference = grant(selected)
    before = (peer.posts, peer.deletes, len(source.calls))
    identity = dict(IDENTITY)
    if fault == 'identity': identity['transport_digest'] = 'f' * 64
    elif fault == 'expiry': now[0] = 160
    elif fault == 'clock': now[0] = 99
    elif fault == 'gate': selected.close()
    elif fault == 'scope': selected._namespace['scope_ref'] = 'foreign-scope'
    elif fault == 'plan': object.__setattr__(selected._issued.plan, 'summary_digest', 'f' * 64)
    elif fault == 'key': selected._key = b'x' * 32
    elif fault == 'store': selected._store = selected._target._store
    elif fault == 'clock_callback': selected._clock = lambda: 100
    elif operation == 'create': selected._transport._authorize_create = lambda *a: True
    else: selected._transport._authorize_recovery = lambda *a: True
    with pytest.raises(RadiusRemoteUserWorkflowError): selected.execute(reference, **identity)
    assert before == (peer.posts, peer.deletes, len(source.calls))


@pytest.mark.parametrize('fault', ['lost_ack', 'foreign_ack', 'failed_readback', 'state_drift'])
def test_unknown_create_recovery_requires_original_ack_and_terminal_context(tmp_path: Path, fault: str) -> None:
    create, remove, peer, _, source, _ = setup(tmp_path)
    reference = grant(create)
    if fault == 'state_drift': peer.defaults['comments'] = 'changed'
    else: setattr(peer, {'lost_ack':'lost_post_ack', 'foreign_ack':'foreign_ack', 'failed_readback':'failed_readback'}[fault], True)
    result = create.execute(reference, **IDENTITY)
    assert result['outcome'] != 'succeeded'
    before = (peer.posts, len(source.calls))
    recovery = remove()
    if fault == 'failed_readback':
        assert recovery.execute(grant(recovery), **IDENTITY)['outcome'] == 'succeeded'
        assert peer.deletes == 1
    else:
        with pytest.raises(RadiusRemoteUserWorkflowError): grant(recovery)
        assert peer.deletes == 0
    assert before == (peer.posts, len(source.calls))


@pytest.mark.parametrize('operation', ['create', 'remove'])
@pytest.mark.parametrize('fault', ['expiry', 'close', 'drift'])
def test_connection_boundary_rechecks_active_authority_and_never_replays(tmp_path: Path, operation: str, fault: str) -> None:
    create, remove, peer, now, _, _ = setup(tmp_path)
    selected = create
    if operation == 'remove':
        assert create.execute(grant(create), **IDENTITY)['outcome'] == 'succeeded'
        selected = remove()
    reference = grant(selected)
    marker = 'create.claim.json' if operation == 'create' else 'delete.claim.json'
    done = []
    def on_connect() -> None:
        if (selected._reader._directory / marker).exists() and not done:
            done.append(True)
            if fault == 'expiry': now[0] = 160
            elif fault == 'close': selected.close()
            elif operation == 'create': peer.defaults['comments'] = 'changed'
            else: peer.row['comments'] = 'changed'
    peer.on_connect = on_connect
    result = selected.execute(reference, **IDENTITY)
    assert done and result['outcome'] == 'reconciliation_required'
    assert peer.posts == int(operation == 'remove') and peer.deletes == 0
    assert selected._store.claim_count == 1 and len(selected._store.audit_events) == 1
    with pytest.raises(RadiusRemoteUserWorkflowError):
        (remove() if operation == 'remove' else selected).preview(**IDENTITY)


def test_default_off_preview_cannot_authorize_and_signed_grant_cannot_be_superseded(tmp_path: Path) -> None:
    create, _, peer, _, _, _ = setup(tmp_path, enabled=False)
    p = create.preview(**IDENTITY)
    with pytest.raises(RadiusRemoteUserWorkflowError): create.authorize(p['preview_ref'], **IDENTITY)
    create._enabled = True
    with pytest.raises(RadiusRemoteUserWorkflowError): create.authorize(p['preview_ref'], **IDENTITY)
    assert peer.posts == 0 and create._store.claim_count == 0


def test_callback_and_durable_in_progress_claim_are_not_active_dispatch_ownership(tmp_path: Path) -> None:
    from fortipam_mcp.radius_remote_user_live_workflow import _execution_context
    from fortipam_mcp.radius_remote_user_contract import RadiusRemoteUserError
    create, _, peer, _, _, _ = setup(tmp_path)
    grant(create)
    plan, auth = create._issued.plan, create._issued.authorization
    create._started = True
    create._store.claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
        idempotency_digest=plan.idempotency_digest, context_digest=_execution_context(plan, auth),
        authorization_digest=auth.authorization_digest)
    with pytest.raises(RadiusRemoteUserError): create._transport.create_and_verify()
    assert peer.posts == 0 and not (create._reader._directory / 'create.claim.json').exists()
    assert not (create._reader._directory / 'user-create.authority.json').exists()


@pytest.mark.parametrize('fault', ['packet', 'signature', 'namespace', 'store', 'original_key', 'same_key', 'missing_ack', 'same_scope'])
def test_original_context_cannot_be_forged_or_adopted_for_recovery(tmp_path: Path, fault: str) -> None:
    create, remove, peer, _, _, _ = setup(tmp_path)
    assert create.execute(grant(create), **IDENTITY)['outcome'] == 'succeeded'
    root = create._reader._directory
    overrides: dict[str, Any] = {}
    if fault in {'packet', 'signature', 'namespace'}:
        path = root / 'user-create.authority.json'
        packet = json.loads(path.read_text())
        if fault == 'packet': packet['plan']['requester_digest'] = 'f' * 64
        elif fault == 'signature': packet['preview']['signature'] = 'f' * 64
        else:
            packet['namespace']['environment_ref'] = 'foreign-environment'
            runtime = root / 'user-create.runtime.json'; runtime.write_text(json.dumps(packet['namespace']))
            overrides['environment_ref'] = 'foreign-environment'
            packet['common_namespace_digest'] = canonical_digest({k:packet['namespace'][k] for k in (
                'environment_ref','audience_ref','requester_digest','transport_digest')})
        path.write_text(json.dumps(packet))
    elif fault == 'store': overrides['original_create_store'] = store(tmp_path, 'foreign-create', True)
    elif fault == 'original_key': overrides['original_create_authority_key'] = b'x' * 32
    elif fault == 'same_key': overrides['authority_key'] = CREATE_KEY
    elif fault == 'same_scope': overrides['scope_ref'] = 'synthetic-radius-user-create'
    else: (root / 'create-ack.json').unlink()
    with pytest.raises(RadiusRemoteUserWorkflowError): grant(remove(**overrides))
    assert peer.deletes == 0


def test_lost_delete_ack_allows_read_only_absence_and_no_new_grant(tmp_path: Path) -> None:
    create, remove, peer, _, _, _ = setup(tmp_path)
    assert create.execute(grant(create), **IDENTITY)['outcome'] == 'succeeded'
    recovery = remove(); reference = grant(recovery); peer.lost_delete_ack = True
    result = recovery.execute(reference, **IDENTITY)
    assert result['outcome'] == 'reconciliation_required' and peer.deletes == 1 and peer.row is None
    assert recovery._reader.inspect_deleted()
    assert recovery.execute(reference, **IDENTITY)['idempotent_replay'] and peer.deletes == 1
    with pytest.raises(RadiusRemoteUserWorkflowError): remove().preview(**IDENTITY)


def test_authorized_preview_cannot_be_replaced_and_foreign_runtime_cannot_adopt_journal(tmp_path: Path) -> None:
    create, _, peer, _, _, values = setup(tmp_path)
    grant(create)
    with pytest.raises(RadiusRemoteUserWorkflowError): create.preview(**IDENTITY)
    altered = values | {'authority_key': b'x' * 32}
    with pytest.raises(RadiusRemoteUserWorkflowError):
        RadiusRemoteUserLiveWorkflow(create._binding, create._reader._config, **altered)
    assert peer.posts == 0


@pytest.mark.parametrize('boundary', ['before_claim', 'after_claim', 'runtime'])
def test_signed_record_drift_is_rejected_before_post(tmp_path: Path, boundary: str) -> None:
    create, _, peer, _, _, _ = setup(tmp_path)
    reference = grant(create)
    root = create._reader._directory
    done = []
    def on_connect() -> None:
        if not (root / 'user-create.authority.json').exists() or done:
            return
        if boundary == 'after_claim' and not (root / 'create.claim.json').exists():
            return
        done.append(True)
        path = root / ('user-create.runtime.json' if boundary == 'runtime' else 'user-create.authority.json')
        packet = json.loads(path.read_text())
        if boundary == 'runtime': packet['environment_ref'] = 'changed-environment'
        else: packet['preview']['signature'] = 'f' * 64
        path.write_text(json.dumps(packet))
    peer.on_connect = on_connect
    if boundary == 'runtime':
        with pytest.raises(RadiusRemoteUserWorkflowError): create.execute(reference, **IDENTITY)
        assert create._store.claim_count == 1
    else:
        result = create.execute(reference, **IDENTITY)
        assert result['outcome'] == 'reconciliation_required'
    assert done and peer.posts == 0


def test_unreadable_authority_record_stops_before_any_user_http_claim(tmp_path: Path, monkeypatch: Any) -> None:
    create, _, peer, _, _, _ = setup(tmp_path)
    reference = grant(create)
    write_once = create._reader._write_once
    def oversized(name: str, value: Any) -> None:
        if name == 'user-create.authority.json': value = value | {'unexpected': 'x' * 9000}
        write_once(name, value)
    monkeypatch.setattr(create._reader, '_write_once', oversized)
    with pytest.raises(RadiusRemoteUserWorkflowError): create.execute(reference, **IDENTITY)
    assert create._closed and peer.posts == 0 and create._store.claim_count == 0
    assert not (create._reader._directory / 'create.claim.json').exists()


def test_original_ack_and_full_row_do_not_allow_recovery_while_create_m4_is_active(tmp_path: Path, monkeypatch: Any) -> None:
    from fortipam_mcp.radius_remote_user_live_workflow import _Adapter
    create, remove, peer, _, _, _ = setup(tmp_path)
    recovery = remove()
    original = _Adapter.read_postcondition
    observed = []
    def during_postcondition(adapter: Any, plan: Any) -> str:
        if adapter._workflow is create:
            assert (create._reader._directory / 'create-ack.json').exists()
            assert (create._reader._directory / 'created.json').exists()
            assert peer.row is not None
            with pytest.raises(RadiusRemoteUserWorkflowError): recovery.preview(**IDENTITY)
            observed.append(True)
        return original(adapter, plan)
    monkeypatch.setattr(_Adapter, 'read_postcondition', during_postcondition)
    assert create.execute(grant(create), **IDENTITY)['outcome'] == 'succeeded'
    assert observed and peer.deletes == 0
    assert recovery.execute(grant(recovery), **IDENTITY)['outcome'] == 'succeeded'
    assert peer.deletes == 1


def test_original_packet_is_durable_before_first_kernel_reservation(tmp_path: Path, monkeypatch: Any) -> None:
    import os, stat
    from fortipam_mcp.radius_remote_user_live_workflow import M4ExecutionKernel
    create, _, peer, _, _, _ = setup(tmp_path)
    reference = grant(create)
    sync = os.fsync
    events = []
    def syncing(fd: int) -> None:
        sync(fd)
        events.append('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file')
    execute = M4ExecutionKernel.execute
    def executing(kernel: Any, *args: Any, **kwargs: Any) -> Any:
        assert events[:2] == ['file', 'directory']
        assert create._store.claim_count == len(create._store.audit_events) == 0
        assert create._reader._read_state('user-create.authority.json') == create._original_packet()
        return execute(kernel, *args, **kwargs)
    monkeypatch.setattr(os, 'fsync', syncing)
    monkeypatch.setattr(M4ExecutionKernel, 'execute', executing)
    assert create.execute(reference, **IDENTITY)['outcome'] == 'succeeded'
    assert peer.posts == create._store.claim_count == 1


@pytest.mark.parametrize('fault', ['write', 'file_fsync', 'directory_fsync', 'readback', 'expiry', 'cancel'])
def test_retention_failure_closes_without_reserving_user_m4(tmp_path: Path, monkeypatch: Any, fault: str) -> None:
    import asyncio, os, stat
    from fortipam_mcp.radius_remote_user_live_workflow import M4ExecutionKernel
    from fortipam_mcp.radius_remote_user_http_transport import FortiPamRadiusRemoteUserHttpTransport as Transport
    create, _, peer, now, source, _ = setup(tmp_path)
    reference = grant(create)
    before = len(source.calls)
    write, read, sync = Transport._write_once, Transport._read_state, os.fsync
    def writing(reader: Any, name: str, value: Any) -> None:
        if name == 'user-create.authority.json':
            if fault == 'write': raise OSError('Synthetic write failure.')
            if fault == 'cancel': raise asyncio.CancelledError
        write(reader, name, value)
        if name == 'user-create.authority.json' and fault == 'expiry': now[0] = 160
    def reading(reader: Any, name: str) -> Any:
        if name == 'user-create.authority.json' and fault == 'readback': raise OSError('Synthetic readback failure.')
        return read(reader, name)
    def syncing(fd: int) -> None:
        kind = 'directory_fsync' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file_fsync'
        if fault == kind: raise OSError('Synthetic fsync failure.')
        sync(fd)
    monkeypatch.setattr(Transport, '_write_once', writing)
    monkeypatch.setattr(Transport, '_read_state', reading)
    monkeypatch.setattr(os, 'fsync', syncing)
    monkeypatch.setattr(M4ExecutionKernel, 'execute', lambda *a, **k: pytest.fail('No kernel reservation is allowed.'))
    with pytest.raises(asyncio.CancelledError if fault == 'cancel' else RadiusRemoteUserWorkflowError):
        create.execute(reference, **IDENTITY)
    assert create._closed and create._store.claim_count == len(create._store.audit_events) == 0
    assert peer.posts == peer.deletes == 0 and len(source.calls) == before
    assert not (create._reader._directory / 'create.claim.json').exists()
    with pytest.raises(RadiusRemoteUserWorkflowError): create.execute(reference, **IDENTITY)
