"""Synthetic private workflow tests: identity, provenance and durable dispatch."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import sqlite3

import pytest

from fortipam_mcp.secret_request_approval_revoke_live_workflow import (
    SecretRequestApprovalRevokeLiveWorkflow as Workflow,
    SecretRequestApprovalRevokeLiveWorkflowError as Error,
)
from fortipam_mcp.secret_request_approval_revoke_resolver import OwnerOnlySecretRequestApprovalRevokeResolver as Resolver
from fortipam_mcp.secret_request_approval_revoke_http_transport import (
    FortiPamSecretRequestApprovalRevokeHttpTransport as Transport,
    SecretRequestApprovalRevokeInspection as Inspection,
    SecretRequestApprovalRevokeReadback as Readback,
)
from fortipam_mcp.secret_request_approval_revoke_detail_contract import (
    SecretRequestApprovalRevokeDetailWitness as Detail,
    SecretRequestApprovalRevokeRelationWitness as Relation,
)
from test_secret_request_approval_revoke_resolver import _setup

ACTOR = dict(requester_digest='a' * 64, transport_digest='b' * 64)


def setup(tmp_path, monkeypatch, *, enabled=True):
    args, _ = _setup(tmp_path)
    resolver = Resolver(**args)
    transport = object.__new__(Transport)
    transport._binding = resolver.resolve().binding
    transport._key = b't' * 32
    transport._claim = tmp_path / 'transport.claim'
    key = tmp_path / 'auth.key'
    key.write_bytes(b'w' * 32)
    key.chmod(0o600)
    state = {'inspection': Inspection(Detail('c' * 64, 'd' * 64, 'e' * 64),
             Relation('c' * 64, 'f' * 64, '0' * 64)), 'calls': 0, 'now': 100}
    monkeypatch.setattr(Transport, 'inspect', lambda self: state['inspection'])
    def dispatch(self, inspection, *, authorization_expires_at=None):
        assert authorization_expires_at == 220
        state['calls'] += 1
        if state.get('raise'):
            raise RuntimeError('private-upstream-value')
        return Readback(True, True, True, True, False)
    monkeypatch.setattr(Transport, 'withdraw_and_readback', dispatch)
    kwargs = dict(database=tmp_path/'workflow.db', hmac_key_file=key, transport=transport,
        resolver=resolver, allowed_requester_digest=ACTOR['requester_digest'],
        allowed_transport_digest=ACTOR['transport_digest'], execution_enabled=enabled,
        clock=lambda: state['now'])
    return Workflow(**kwargs), kwargs, state


def authorize(workflow):
    preview = workflow.preview(**ACTOR)
    return workflow.authorize(preview['preview_ref'], **ACTOR)['authorization_ref']


def test_success_restart_replay_and_categorical_output(tmp_path, monkeypatch):
    w, kwargs, state = setup(tmp_path, monkeypatch)
    ref = authorize(w)
    result = w.execute(ref, **ACTOR)
    assert result['outcome'] == 'succeeded'
    assert Workflow(**kwargs).execute(ref, **ACTOR)['idempotent_replay']
    assert state['calls'] == 1
    with pytest.raises(Error):
        Workflow(**kwargs).preview(**ACTOR)
    output = json.dumps(result)
    assert 'synthetic' not in output and 'private-upstream-value' not in output


@pytest.mark.parametrize('fault', ['requester', 'transport', 'expiry', 'creation', 'inspection', 'gate'])
def test_invalid_authority_or_drift_never_dispatches(tmp_path, monkeypatch, fault):
    w, kwargs, state = setup(tmp_path, monkeypatch, enabled=fault != 'gate')
    ref = authorize(w)
    actor = dict(ACTOR)
    if fault in {'requester', 'transport'}:
        actor[fault + '_digest'] = '9' * 64
    elif fault == 'expiry': state['now'] = 220
    elif fault == 'creation': kwargs['resolver']._claim_path.write_text('{}')
    elif fault == 'inspection':
        state['inspection'] = replace(state['inspection'], detail=Detail('c'*64, '1'*64, 'e'*64))
    try:
        assert w.execute(ref, **actor)['outcome'] == 'not_executed'
    except Error:
        pass
    assert state['calls'] == 0


def test_unknown_result_is_durable_non_retry(tmp_path, monkeypatch):
    w, kwargs, state = setup(tmp_path, monkeypatch)
    ref = authorize(w)
    state['raise'] = True
    assert w.execute(ref, **ACTOR)['outcome'] == 'reconciliation_required'
    assert Workflow(**kwargs).execute(ref, **ACTOR)['outcome'] == 'reconciliation_required'
    assert state['calls'] == 1


def test_distinct_previews_concurrent_reservation_dispatches_once(tmp_path, monkeypatch):
    w, kwargs, state = setup(tmp_path, monkeypatch)
    refs = [authorize(w), authorize(w)]
    def run(ref):
        try:
            return Workflow(**kwargs).execute(ref, **ACTOR)
        except Error:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(run, refs))
    assert state['calls'] == 1


def test_reserved_crash_and_tamper_cannot_reopen(tmp_path, monkeypatch):
    w, kwargs, state = setup(tmp_path, monkeypatch)
    ref = authorize(w)
    record = w._select('authorization_ref', ref)
    assert w._reserve(record, replace(record, state='executing'))
    assert Workflow(**kwargs).execute(ref, **ACTOR)['outcome'] == 'reconciliation_required'
    assert state['calls'] == 0
    with sqlite3.connect(kwargs['database']) as db:
        db.execute("UPDATE secret_request_approval_revoke_workflow SET state='authorized'")
    with pytest.raises(Error):
        Workflow(**kwargs).execute(ref, **ACTOR)


@pytest.mark.parametrize('fault', ['namespace', 'same_key', 'binding', 'hardlink'])
def test_constructor_rejects_rebinding_and_shared_authority(tmp_path, monkeypatch, fault):
    _, kwargs, _ = setup(tmp_path, monkeypatch)
    if fault == 'namespace': kwargs['allowed_transport_digest'] = '9' * 64
    elif fault == 'same_key': kwargs['hmac_key_file'].write_bytes(kwargs['transport']._key)
    elif fault == 'binding': kwargs['transport']._binding = replace(kwargs['transport']._binding, request_id=999)
    else:
        import os
        os.link(kwargs['database'], tmp_path/'alias.db')
    with pytest.raises(Error): Workflow(**kwargs)


def test_processes_share_durable_reservation(tmp_path, monkeypatch):
    import multiprocessing
    w, kwargs, state = setup(tmp_path, monkeypatch)
    refs = [authorize(w), authorize(w)]
    context = multiprocessing.get_context('fork')
    outcomes = context.Queue()
    def run(ref):
        try:
            outcomes.put(Workflow(**kwargs).execute(ref, **ACTOR)['outcome'])
        except Error:
            outcomes.put('refused')
    workers = [context.Process(target=run, args=(ref,)) for ref in refs]
    for worker in workers: worker.start()
    for worker in workers:
        worker.join(10)
        assert worker.exitcode == 0
    results = [outcomes.get(timeout=2), outcomes.get(timeout=2)]
    assert results.count('succeeded') == 1


def test_authorize_rereads_creation_and_exact_inspection(tmp_path, monkeypatch):
    w, kwargs, state = setup(tmp_path, monkeypatch)
    preview = w.preview(**ACTOR)
    state['inspection'] = replace(state['inspection'], relation=Relation('c'*64, '2'*64, '0'*64))
    with pytest.raises(Error): w.authorize(preview['preview_ref'], **ACTOR)
    assert state['calls'] == 0


@pytest.mark.parametrize('stage', ['authorize', 'execute'])
def test_expiry_during_inspection_fails_before_dispatch(tmp_path, monkeypatch, stage):
    w, kwargs, state = setup(tmp_path, monkeypatch)
    ref = (w.preview(**ACTOR)['preview_ref'] if stage == 'authorize' else authorize(w))
    def slow_inspect(self):
        state['now'] = 220
        return state['inspection']
    monkeypatch.setattr(Transport, 'inspect', slow_inspect)
    if stage == 'authorize':
        with pytest.raises(Error): w.authorize(ref, **ACTOR)
    else:
        assert w.execute(ref, **ACTOR)['outcome'] == 'not_executed'
    assert state['calls'] == 0
