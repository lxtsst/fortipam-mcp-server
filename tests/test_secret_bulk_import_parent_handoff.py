"""Authenticated private projection to original parent storage, synthetic only."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
import socket
import sqlite3

import pytest
from starlette.testclient import TestClient

from fortipam_mcp import secret_bulk_import_parent_handoff as boundary
from fortipam_mcp import secret_bulk_import_submission as submission
from fortipam_mcp import secret_bulk_import_parent_graph as compiler
from fortipam_mcp.secret_bulk_import_dependencies import ImportTarget
from fortipam_mcp.secret_bulk_import_row_namespace import PinnedOriginalImportRows, OriginalImportOperation
from v4_planning.persistence import PersistentProtectedPlanningStore, PersistentPlanningStoreError
from v4_planning.import_parent import FileImportParentRecord
from v4_planning.store import OriginalImportBindingRecord, OriginalImportRowAckRecord
import test_secret_bulk_import_submission as intake_fixture
import test_v4_m3 as plans
from test_secret_bulk_import_parent_binding import parent
from test_v4_persistence import CHECKPOINT_STORE_REF, _ExternalCheckpoint, _new_store
from test_secret_bulk_import_dependencies import catalog, item
from test_secret_bulk_import_file import csv_bytes
from test_secret_bulk_import_row_namespace import child_plan
from test_m4_execution_store import (
    _Adapter, _ExternalM4Checkpoint, _Verifier, _authorization, _store,
    CHECKPOINT_STORE_REF as M4_CHECKPOINT_STORE_REF,
)
from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, canonical_digest


def configured(tmp_path, monkeypatch, kind='csv', *, values=None, snapshot=None, file_parent=False, text_source=None):
    if values is not None:
        prepare = intake_fixture.prepared
        def prepared(path, selected_kind):
            binding, options, clocks = prepare(path, selected_kind)
            raw = csv_bytes(values)
            binding.path.write_bytes(raw)
            return replace(binding, file_sha256=hashlib.sha256(raw).hexdigest()), options, clocks
        monkeypatch.setattr(intake_fixture, 'prepared', prepared)
    if snapshot is not None:
        monkeypatch.setattr(intake_fixture, 'catalog', lambda: snapshot)
    source = intake_fixture.source
    requester = plans._requester().digest
    monkeypatch.setattr(intake_fixture, 'source', lambda *a, **kw: source(*a, **kw, requester=requester))
    fixture = intake_fixture.configured(tmp_path, monkeypatch, kind)
    now = fixture['clocks'][0]
    monkeypatch.setattr(plans, 'NOW', now - 50)
    checkpoint = _ExternalCheckpoint()
    store, database, ledger_key = _new_store(tmp_path, now_epoch=now,
        monotonic_checkpoint=checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF)
    plan = None if file_parent else parent(store)
    key = tmp_path / 'original-parent.key'
    key.write_bytes(b'n' * 32)
    key.chmod(0o600)
    projection = fixture['options']['authority']
    checker = projection._human_owner_verifier
    owner_checker = boundary.ReferenceOwnerFileEligibility(fixture['owner_binding'],
        authority=checker._authority, authority_ref=checker._authority_ref, reference=checker._reference,
        requester_digest=requester, scope_key_path=checker._key.path, scope_key_sha256=checker._key.digest,
        clock=lambda: fixture['clocks'][0])
    owner_authority = boundary.PinnedOwnerFileIntakeAuthority(fixture['owner_binding'],
        policy_path=projection._policy, key_path=projection._key,
        policy_sha256=projection._policy_digest, key_sha256=projection._key_digest,
        human_owner_verifier=owner_checker, clock=lambda: fixture['clocks'][0])
    left, right = socket.socketpair()
    receiver = boundary._OriginalParentReceiver(left, fixture['owner_binding'], fixture['options']['catalog'],
        store=store, authority=owner_authority,
        plan_ref=plan.plan_ref if plan else 'file-import-parent-01', plan_digest=plan.plan_digest if plan else None,
        requester_digest=requester, parent_idempotency_digest='8' * 64,
        key_path=key.resolve(), key_sha256=hashlib.sha256(b'n' * 32).hexdigest(), clock=lambda: fixture['clocks'][0],
        standing_lab_authorization=file_parent, text_source=text_source)
    endpoint = receiver._endpoint
    sender = boundary._OriginalParentHandoff(right, endpoint._binding, endpoint._catalog,
                                              endpoint._context, endpoint._deadline)
    fixture.update(receiver=receiver, sender=sender, store=store, database=database, ledger_key=ledger_key,
                   checkpoint=checkpoint, plan=plan)
    return fixture


def binding_count(fixture):
    with sqlite3.connect(fixture['database']) as connection:
        return connection.execute("SELECT count(*) FROM planning_records WHERE record_type='original_import_binding'").fetchone()[0]


@pytest.mark.parametrize('scenario', ['success', 'association', 'interrupted'])
def test_native_text_source_qualifies_original_handoff_before_parent_commit(tmp_path, monkeypatch, capfd, scenario):
    from fortipam_mcp.secret_bulk_import_source_catalog import _TextOnlyImportSource
    from test_secret_bulk_import_text_source import _source_fixtures, _text_row

    fixtures, _, _ = _source_fixtures(tmp_path, monkeypatch, None)
    text_source = _TextOnlyImportSource(*fixtures)
    values = [_text_row('First'), _text_row('Second', **({'Association-Secret': 'First'} if scenario == 'association' else {}))]
    file_digest = hashlib.sha256(csv_bytes(values)).hexdigest()
    snapshot = text_source.prepare_catalog(expected_file_digest=file_digest, scope_digest='1' * 64)
    assert text_source._current is None and not text_source._used
    fixture = configured(tmp_path, monkeypatch, values=values, snapshot=snapshot,
        file_parent=True, text_source=text_source)
    receiver, sender = fixture['receiver'], fixture['sender']
    committed = []
    put_parent = fixture['store'].put_file_import_parent

    def put_qualified_parent(parent):
        qualified = receiver._qualified
        assert qualified is text_source._current and qualified.catalog is snapshot
        assert qualified.file_digest == file_digest
        text_source.check_current(qualified, file_digest=file_digest, scope_digest='1' * 64)
        if scenario == 'interrupted':
            raise KeyboardInterrupt
        committed.append(qualified)
        put_parent(parent)

    monkeypatch.setattr(fixture['store'], 'put_file_import_parent', put_qualified_parent)
    app = submission.create_owner_file_submission_app(fixture['owner_binding'],
        **fixture['options'], parent_handoff=sender)
    with fixture['reference_transport'], ThreadPoolExecutor(max_workers=1) as pool, TestClient(app) as client:
        future = pool.submit(receiver.receive_once)
        response = intake_fixture.send(client, intake_fixture.frame(fixture))
        if scenario != 'success':
            assert response.status_code == 409 and response.json() == {'status': 'unavailable'}
            with pytest.raises(KeyboardInterrupt if scenario == 'interrupted' else boundary.BulkImportIntakeError):
                future.result(timeout=5)
            assert not committed and receiver._qualified is None and text_source._current is None
            assert text_source._closed
            assert binding_count(fixture) == 0
            with pytest.raises(PersistentPlanningStoreError):
                fixture['store'].get_import_parent(receiver._plan_ref)
        else:
            original, projected, compiled = future.result(timeout=5)
            assert response.status_code == 200 and response.json() == {'status': 'projected', 'rows': 2, 'targets': 0}
            assert len(committed) == 1 and committed[0] is receiver._qualified
            assert receiver._qualified.projected is projected and receiver._qualified.catalog is snapshot
            original._verify_dependencies_binding(fixture['owner_binding'], projected, snapshot,
                authenticated_requester_digest=original._operation.requester_digest)
            assert len(compiled.steps) == 2 and all(step.kind == 'secret' for step in compiled.steps)
            assert binding_count(fixture) == 1
        assert intake_fixture.send(client, intake_fixture.frame(fixture)).status_code == 409
    assert sender._peer.fileno() == receiver._endpoint._peer.fileno() == -1
    assert capfd.readouterr() == ('', '')


@pytest.mark.parametrize('scenario', ['maximum', 'shared-and-existing'])
def test_authenticated_batch_compiles_complete_dag_and_preserves_original_identity(tmp_path, monkeypatch, capfd, scenario):
    snapshot = catalog()
    if scenario == 'maximum':
        values = [item(Name=f'Batch item {i}', URL=f'https://item-{i}.example.invalid') for i in range(256)]
        expected_targets = 256
    else:
        values = [item(Name='Child', **{'Association-Secret': 'Parent'}), item(Name='Parent'),
                  item(Name='Reuse', URL='https://reuse.example.invalid'),
                  item(Name='Update', URL='https://update.example.invalid', **{'Association-Secret': '(ID:42)'})]
        snapshot = replace(snapshot, targets=(
            ImportTarget('Retained target', 'Web Account', '', '', 'https://reuse.example.invalid', 'a' * 64),
            ImportTarget('Changed target', 'Old Web Account', '', '', 'https://update.example.invalid', 'b' * 64)))
        expected_targets = 3
    fixture = configured(tmp_path, monkeypatch, values=values, snapshot=snapshot, file_parent=True)
    receiver, sender, plan = fixture['receiver'], fixture['sender'], fixture['plan']
    app = submission.create_owner_file_submission_app(fixture['owner_binding'],
        **fixture['options'], parent_handoff=sender)
    with fixture['reference_transport'], ThreadPoolExecutor(max_workers=1) as pool, TestClient(app) as client:
        future = pool.submit(receiver.receive_once)
        response = intake_fixture.send(client, intake_fixture.frame(fixture))
        original, projected, compiled = future.result(timeout=10)
        plan = fixture['store'].get_import_parent(receiver._plan_ref)
        assert type(plan) is FileImportParentRecord
        with pytest.raises(PersistentPlanningStoreError):
            fixture['store'].get_plan(plan.plan_ref)
        assert response.status_code == 200
        assert response.json() == {'status': 'projected', 'rows': len(values), 'targets': expected_targets}
        assert intake_fixture.send(client, intake_fixture.frame(fixture)).status_code == 409
    assert len(compiled.steps) == len(values) + expected_targets
    assert len(plan.lines) == len(compiled.steps) and plan.row_count == len(values)
    assert plan.input_commitment == original._operation.input_commitment
    seen = set()
    for step in compiled.steps:
        assert set(step.depends_on) <= seen and step.line_ref not in seen
        seen.add(step.line_ref)
        if step.kind == 'secret':
            row = original.row(step.index)
            assert (step.idempotency_digest, step.parameters_digest) == (row.idempotency_digest, row.parameters_digest)
    if scenario == 'shared-and-existing':
        targets, secrets = compiled.steps[:3], {s.index: s for s in compiled.steps[3:]}
        assert [s.action_id for s in targets] == ['target-lifecycle-create', None, 'target-lifecycle-update']
        assert targets[1].idempotency_digest is None
        assert secrets[0].depends_on == (targets[0].line_ref, secrets[1].line_ref)
        assert secrets[1].depends_on == (targets[0].line_ref,)
    fixture['owner_binding'].path.unlink()
    reopened = PersistentProtectedPlanningStore(fixture['database'], fixture['ledger_key'],
        clock=lambda: fixture['clocks'][0], monotonic_checkpoint=fixture['checkpoint'],
        checkpoint_store_ref=CHECKPOINT_STORE_REF)
    tail = fixture['checkpoint'].tail
    options = dict(expected_parent_digest=plan.plan_digest, authenticated_requester_digest=plan.requester_digest)
    rebuilt = compiler._compile_original_import_graph(original, fixture['owner_binding'], projected, snapshot,
        reopened, **options, clock=lambda: fixture['clocks'][0])
    assert rebuilt.graph_digest == compiled.graph_digest and rebuilt.steps == compiled.steps
    # The same compiled row must join the original durable execution namespace;
    # rebuilding a graph cannot dispatch an already completed/uncertain row.
    checkpoint = _ExternalM4Checkpoint()
    execution = _store(tmp_path / 'm4', monotonic_checkpoint=checkpoint,
                       checkpoint_store_ref=M4_CHECKPOINT_STORE_REF)
    class Adapter(_Adapter):
        def dispatch(self, selected):
            super().dispatch(selected)
            if scenario == 'shared-and-existing':
                raise M4AdapterAmbiguous('Synthetic uncertain child')
    selected = next(step for step in compiled.steps if step.kind == 'secret')
    child = child_plan(original.row(selected.index))
    assert child.idempotency_digest == selected.idempotency_digest
    adapter, authorization = Adapter(), _authorization(child)
    result = M4ExecutionKernel(adapter, _Verifier(), execution, clock=lambda: 1000).execute(child, authorization)
    restored_execution = _store(tmp_path / 'm4', monotonic_checkpoint=checkpoint,
                               checkpoint_store_ref=M4_CHECKPOINT_STORE_REF)
    replay_adapter = Adapter()
    replay = M4ExecutionKernel(replay_adapter, _Verifier(), restored_execution, clock=lambda: 1000).execute(child, authorization)
    assert replay.idempotent_replay and replay.outcome == result.outcome
    assert adapter.calls.count('dispatch') == 1 and replay_adapter.calls == []
    assert restored_execution.claim_count == 1
    # A backwards final clock sample must refuse even if it remains after start.
    now = fixture['clocks'][0]
    samples = iter([now, now + 2, now + 3, now + 2])
    with pytest.raises(boundary.BulkImportIntakeError):
        compiler._compile_original_import_graph(original, fixture['owner_binding'], projected, snapshot,
            reopened, **options, clock=lambda: next(samples))
    assert fixture['checkpoint'].tail == tail and binding_count(fixture) == 1
    retained_binding = reopened.get_original_import_binding(plan.plan_ref, expected_plan_digest=plan.plan_digest,
        requester_digest=plan.requester_digest, namespace_key_digest=receiver._key_digest)
    binding_digest = canonical_digest(retained_binding.as_dict())
    ack = OriginalImportRowAckRecord(plan_ref=plan.plan_ref, parent_binding_digest=binding_digest,
        requester_digest=plan.requester_digest, row_index=selected.index,
        idempotency_digest=child.idempotency_digest, parameters_digest=child.parameters_digest,
        child_plan_digest=child.plan_digest, child_revision=child.revision,
        authorization_digest=authorization.authorization_digest,
        context_digest=canonical_digest(dict(plan_digest=child.plan_digest, revision=child.revision,
                                            authorization_digest=authorization.authorization_digest)),
        serial_digest='c' * 64, defaults_digest='d' * 64, ack_source_digest='e' * 64,
        acknowledgement_digest='f' * 64, native_secret_id=71)
    reopened._put_original_import_row_ack(ack)
    # Source aliases cannot create a successor, even after original invalidation.
    payload = plan.canonical_content()
    payload['plan_ref'] = 'replacement-file-parent-02'
    replacement = FileImportParentRecord.from_payload({**payload, 'plan_digest': canonical_digest(payload)})
    with pytest.raises(PersistentPlanningStoreError, match='already has a parent'):
        reopened.put_file_import_parent(replacement)
    reopened.invalidate_plan(plan.plan_ref, evaluated_at=now, reason_codes=('current_state_drift',))
    with pytest.raises(PersistentPlanningStoreError):
        reopened.get_import_parent(plan.plan_ref)
    assert reopened._get_original_import_row_ack(plan.plan_ref, idempotency_digest=child.idempotency_digest,
        requester_digest=plan.requester_digest, parent_binding_digest=binding_digest,
        parameters_digest=child.parameters_digest) == ack
    with pytest.raises(PersistentPlanningStoreError, match='already has a parent'):
        reopened.put_file_import_parent(replacement)
    with sqlite3.connect(fixture['database']) as connection:
        records = dict(connection.execute('SELECT record_type,count(*) FROM planning_records GROUP BY record_type'))
        assert records == {'file_import_parent': 1, 'original_import_binding': 1,
                           'original_import_row_ack': 1, 'plan_invalidation': 1}
    assert sender._peer.fileno() == receiver._endpoint._peer.fileno() == -1
    assert 'Batch item' not in repr(compiled) and 'Parent' not in repr(compiled)
    assert capfd.readouterr() == ('', '')


@pytest.mark.parametrize('kind', ['csv', 'xlsm', 'encrypted'])
def test_authenticated_projection_retains_original_graph_before_counts_response(tmp_path, monkeypatch, capfd, kind):
    fixture = configured(tmp_path, monkeypatch, kind)
    receiver, sender, plan = fixture['receiver'], fixture['sender'], fixture['plan']
    before = plan.canonical_content()
    app = submission.create_owner_file_submission_app(fixture['owner_binding'],
        **fixture['options'], parent_handoff=sender)
    owned = []
    wipe = boundary._wipe
    monkeypatch.setattr(boundary, '_wipe', lambda raw: (owned.append(raw), wipe(raw))[-1])
    with fixture['reference_transport'], ThreadPoolExecutor(max_workers=1) as pool, TestClient(app) as client:
        future = pool.submit(receiver.receive_once)
        response = intake_fixture.send(client, intake_fixture.frame(fixture,
            b'synthetic-password' if kind == 'encrypted' else b''))
        rows, graph, compiled = future.result(timeout=3)
        assert len(compiled.steps) == 2
        assert compiled.steps[1].idempotency_digest == rows.row(0).idempotency_digest
        assert response.status_code == 200
        assert response.json() == {'status': 'projected', 'rows': 1, 'targets': 1}
        assert binding_count(fixture) == 1
        assert intake_fixture.send(client, intake_fixture.frame(fixture)).status_code == 409
    # Owner compilation does not open the source or require an intake session.
    fixture['owner_binding'].path.unlink()
    rows._verify_dependencies_binding(fixture['owner_binding'], graph, fixture['options']['catalog'],
                                     authenticated_requester_digest=plan.requester_digest)
    reopened = PersistentProtectedPlanningStore(fixture['database'], fixture['ledger_key'],
        clock=lambda: fixture['clocks'][0], monotonic_checkpoint=fixture['checkpoint'],
        checkpoint_store_ref=CHECKPOINT_STORE_REF)
    record = reopened.get_original_import_binding(plan.plan_ref, expected_plan_digest=plan.plan_digest,
        requester_digest=plan.requester_digest, namespace_key_digest=receiver._key_digest)
    operation = OriginalImportOperation(**{field: getattr(record, field)
        for field in OriginalImportOperation.__dataclass_fields__})
    restored = PinnedOriginalImportRows(operation, key_path=receiver._key_path, key_sha256=receiver._key_digest)
    assert restored.row(0) == rows.row(0)
    assert reopened.get_plan(plan.plan_ref).canonical_content() == before
    with pytest.raises(boundary.BulkImportIntakeError):
        receiver.receive_once()
    assert owned and all(not any(raw) for raw in owned)
    assert sender._peer.fileno() == receiver._endpoint._peer.fileno() == -1
    assert capfd.readouterr() == ('', '')


@pytest.mark.parametrize('fault', ['revoked', 'invalidated', 'key-drift', 'wrong-context', 'extra-material-field', 'late-parent-read', 'denied-folder'])
def test_handoff_rejects_drift_or_untrusted_graph_without_partial_parent(tmp_path, monkeypatch, fault):
    fixture = configured(tmp_path, monkeypatch)
    receiver, sender = fixture['receiver'], fixture['sender']
    original_forward = boundary._OriginalParentHandoff._forward
    original_send = boundary._send

    def forward(self, graph):
        if fault == 'revoked':
            fixture['root_authority'].revoke(fixture['handle'], now_epoch=fixture['clocks'][0])
        elif fault == 'invalidated':
            fixture['store'].invalidate_plan(fixture['plan'].plan_ref, evaluated_at=fixture['clocks'][0],
                                             reason_codes=('current_state_drift',))
        elif fault == 'key-drift':
            receiver._key_path.write_bytes(b'x' * 32)
        elif fault == 'late-parent-read':
            get_plan = fixture['store'].get_import_parent
            def delayed(ref):
                result = get_plan(ref)
                fixture['clocks'][0] = fixture['owner_binding'].expires_at
                return result
            monkeypatch.setattr(fixture['store'], 'get_import_parent', delayed)
        return original_forward(self, graph)

    def send(peer, deadline, payload):
        if peer is sender._peer and fault in ('wrong-context', 'extra-material-field', 'denied-folder'):
            value = json.loads(payload)
            if fault == 'wrong-context':
                value['context'] = '0' * 64
            elif fault == 'denied-folder':
                value['rows'][0]['folder_id'] = 999
            else:
                value['rows'][0]['password'] = 'synthetic-forbidden-field'
            payload = json.dumps(value).encode()
        return original_send(peer, deadline, payload)

    monkeypatch.setattr(boundary._OriginalParentHandoff, '_forward', forward)
    monkeypatch.setattr(boundary, '_send', send)
    app = submission.create_owner_file_submission_app(fixture['owner_binding'],
        **fixture['options'], parent_handoff=sender)
    with fixture['reference_transport'], ThreadPoolExecutor(max_workers=1) as pool, TestClient(app) as client:
        future = pool.submit(receiver.receive_once)
        response = intake_fixture.send(client, intake_fixture.frame(fixture))
        with pytest.raises(boundary.BulkImportIntakeError):
            future.result(timeout=3)
        assert response.status_code == 409 and response.json() == {'status': 'unavailable'}
        assert intake_fixture.send(client, intake_fixture.frame(fixture)).status_code == 409
    assert binding_count(fixture) == 0
    assert sender._peer.fileno() == receiver._endpoint._peer.fileno() == -1


def test_lost_receipt_keeps_original_record_and_consumes_both_endpoints(tmp_path, monkeypatch):
    fixture = configured(tmp_path, monkeypatch)
    receiver, sender = fixture['receiver'], fixture['sender']
    send = boundary._send
    def lose_receipt(peer, deadline, payload):
        if peer is receiver._endpoint._peer:
            raise OSError('Synthetic lost receipt')
        return send(peer, deadline, payload)
    monkeypatch.setattr(boundary, '_send', lose_receipt)
    app = submission.create_owner_file_submission_app(fixture['owner_binding'],
        **fixture['options'], parent_handoff=sender)
    with fixture['reference_transport'], ThreadPoolExecutor(max_workers=1) as pool, TestClient(app) as client:
        future = pool.submit(receiver.receive_once)
        assert intake_fixture.send(client, intake_fixture.frame(fixture)).status_code == 409
        with pytest.raises(boundary.BulkImportIntakeError):
            future.result(timeout=3)
        assert binding_count(fixture) == 1
        tail = fixture['checkpoint'].tail
        assert intake_fixture.send(client, intake_fixture.frame(fixture)).status_code == 409
        with pytest.raises(boundary.BulkImportIntakeError):
            receiver.receive_once()
        assert fixture['checkpoint'].tail == tail


def test_file_parent_interruption_retains_source_claim_and_checkpoint(tmp_path, monkeypatch):
    fixture = configured(tmp_path, monkeypatch, file_parent=True)
    receiver, sender, store = fixture['receiver'], fixture['sender'], fixture['store']
    original_database = fixture['database'].read_bytes()
    def interrupted(record):
        raise OSError('Synthetic interruption after parent retention')
    monkeypatch.setattr(store, 'put_original_import_binding', interrupted)
    app = submission.create_owner_file_submission_app(fixture['owner_binding'],
        **fixture['options'], parent_handoff=sender)
    with fixture['reference_transport'], ThreadPoolExecutor(max_workers=1) as pool, TestClient(app) as client:
        future = pool.submit(receiver.receive_once)
        assert intake_fixture.send(client, intake_fixture.frame(fixture)).status_code == 409
        with pytest.raises(boundary.BulkImportIntakeError):
            future.result(timeout=3)
        assert intake_fixture.send(client, intake_fixture.frame(fixture)).status_code == 409
    retained = store.get_import_parent(receiver._plan_ref)
    assert type(retained) is FileImportParentRecord and binding_count(fixture) == 0
    with pytest.raises(PersistentPlanningStoreError):
        store.get_original_import_binding(retained.plan_ref, expected_plan_digest=retained.plan_digest,
            requester_digest=retained.requester_digest, namespace_key_digest=receiver._key_digest)
    payload = retained.canonical_content()
    payload['plan_ref'] = 'replacement-file-parent-02'
    replacement = FileImportParentRecord.from_payload({**payload, 'plan_digest': canonical_digest(payload)})
    with pytest.raises(PersistentPlanningStoreError, match='already has a parent'):
        store.put_file_import_parent(replacement)
    reopened = PersistentProtectedPlanningStore(fixture['database'], fixture['ledger_key'],
        clock=lambda: fixture['clocks'][0], monotonic_checkpoint=fixture['checkpoint'],
        checkpoint_store_ref=CHECKPOINT_STORE_REF)
    assert reopened.get_import_parent(retained.plan_ref) == retained
    other = parent(reopened, 'other')
    changed_key = OriginalImportBindingRecord(plan_ref=other.plan_ref, plan_digest=other.plan_digest,
        requester_digest=other.requester_digest, parent_idempotency_digest=retained.parent_idempotency_digest,
        input_commitment=retained.input_commitment, source_commitment='a' * 64,
        dependency_commitment=retained.dependency_commitment, namespace_key_digest='b' * 64,
        row_count=retained.row_count)
    with pytest.raises(PersistentPlanningStoreError, match='key cannot be replaced'):
        reopened.put_original_import_binding(changed_key)
    with pytest.raises(boundary.BulkImportIntakeError):
        receiver.receive_once()
    fixture['database'].write_bytes(original_database)
    with pytest.raises(PersistentPlanningStoreError):
        reopened.get_import_parent(retained.plan_ref)
    assert sender._peer.fileno() == receiver._endpoint._peer.fileno() == -1


def test_parent_handoff_requires_exact_prebound_catalog_and_source(tmp_path, monkeypatch):
    fixture = configured(tmp_path, monkeypatch)
    try:
        fixture['sender']._binding = replace(fixture['owner_binding'], subject='other-operator')
        with pytest.raises(boundary.BulkImportIntakeError):
            submission.create_owner_file_submission_app(fixture['owner_binding'],
                **fixture['options'], parent_handoff=fixture['sender'])
    finally:
        fixture['sender'].close()
        fixture['receiver'].close()


def test_session_submission_retains_unlock_only_until_shutdown_after_parent_handoff(tmp_path, monkeypatch):
    from test_secret_bulk_import_session_authority import capture_sessions, session_authority
    fixture = configured(tmp_path, monkeypatch, 'encrypted')
    sessions = capture_sessions(monkeypatch)
    with fixture['reference_transport'], ThreadPoolExecutor(max_workers=1) as pool:
        permission, _ = session_authority(tmp_path, fixture)
        app = submission.create_owner_file_session_submission_app(fixture['owner_binding'],
            **fixture['options'], session_authority=permission, parent_handoff=fixture['sender'])
        with TestClient(app) as client:
            future = pool.submit(fixture['receiver'].receive_once)
            response = intake_fixture.send(client, intake_fixture.frame(fixture, b'synthetic-password'))
            future.result(timeout=3)
            assert response.status_code == 200 and binding_count(fixture) == 1
            assert len(sessions) == 1 and any(sessions[0]._password)
        assert not any(sessions[0]._password) and not sessions[0]._watchdog.is_alive()


def test_rejected_intake_token_never_sends_graph_and_shutdown_closes_pending_owner(tmp_path, monkeypatch):
    fixture = configured(tmp_path, monkeypatch)
    fixture['intake_token'] = 'synthetic-invalid-token'
    app = submission.create_owner_file_submission_app(fixture['owner_binding'],
        **fixture['options'], parent_handoff=fixture['sender'])
    monkeypatch.setattr(boundary._OriginalParentHandoff, '_forward',
                        lambda *a: pytest.fail('Unauthenticated graph handoff'))
    with fixture['reference_transport'], ThreadPoolExecutor(max_workers=1) as pool:
        with TestClient(app) as client:
            future = pool.submit(fixture['receiver'].receive_once)
            assert intake_fixture.send(client, intake_fixture.frame(fixture)).status_code == 409
        with pytest.raises(boundary.BulkImportIntakeError):
            future.result(timeout=3)
    assert binding_count(fixture) == 0
