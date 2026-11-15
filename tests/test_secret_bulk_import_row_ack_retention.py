"""Original synthetic HTTP ACK durability; no device or adoption authority."""

from dataclasses import replace
import sqlite3

import pytest

from test_secret_bulk_import_row_http_transport import configured, assert_cleanup, MATERIAL
from test_secret_bulk_import_row_provider import execute, assert_reopened_no_dispatch
from test_v4_m3 import NOW
from v4_planning import M4Verification, canonical_digest
from v4_planning.persistence import PersistentProtectedPlanningStore, PersistentPlanningStoreError
from v4_planning.store import ProtectedStoreError


def reopened(loader, *, now=NOW + 50):
    parent = loader._parent
    return PersistentProtectedPlanningStore(parent._path, parent._key_path, clock=lambda: now,
        monotonic_checkpoint=parent._monotonic_checkpoint,
        checkpoint_store_ref=parent._checkpoint_store_ref)


def read(store, loader, **changes):
    row = loader._row
    binding = loader._parent._read_state().import_bindings[row.plan_ref]
    options = dict(idempotency_digest=row.idempotency_digest, requester_digest=row.requester_digest,
        parent_binding_digest=canonical_digest(binding.as_dict()), parameters_digest=row.parameters_digest)
    options.update(changes)
    return store._get_original_import_row_ack(row.plan_ref, **options)


def test_original_ack_is_persisted_before_readback_and_survives_reopen_without_material(tmp_path, monkeypatch, capfd):
    loader, session, state, reference, bridge, transport, runtime, exchange, _ = configured(tmp_path, monkeypatch)
    original_read = transport._read
    def observed(response, deadline):
        if len(exchange.requests) == 3:
            assert read(reopened(loader), loader).native_secret_id == 71
            assert not transport._post_matches
        return original_read(response, deadline)
    monkeypatch.setattr(transport, '_read', observed)
    try:
        with reference:
            assert execute(loader, state, runtime).verification is M4Verification.VERIFIED
            assert_reopened_no_dispatch(loader, state, runtime, M4Verification.VERIFIED)
        record = read(reopened(loader, now=NOW + 300), loader)
        assert record == transport._ack_record and record.row_index == loader._row.index
        assert record.child_plan_digest == loader._plan.plan_digest
        assert record.authorization_digest == loader._authorization.authorization_digest
        assert record.acknowledgement_digest == transport._ack.acknowledgement_digest
        assert record.serial_digest == transport._capture.serial_digest
        with sqlite3.connect(loader._parent._path) as connection:
            payload = connection.execute("SELECT payload_json FROM planning_records "
                "WHERE record_type='original_import_row_ack'").fetchone()[0]
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert tables == {'planning_records', 'integrity_anchor'}
        for forbidden in (MATERIAL, 'password', 'credential', str(loader._session._transaction._binding.path),
                          loader._session._transaction._binding.file_sha256, 'Synthetic wire-default device'):
            assert forbidden not in payload
        assert [method for method, _ in exchange.requests] == ['GET', 'POST', 'GET']
        assert_cleanup(bridge, exchange)
        assert capfd.readouterr() == ('', '')
    finally:
        session.close()


@pytest.mark.parametrize('fault', ['postcondition', 'post-authority', 'ack-close', 'connection-close'])
def test_valid_ack_survives_later_failure_without_adopting_or_replaying_unknown(tmp_path, monkeypatch, fault):
    loader, session, state, reference, bridge, transport, runtime, exchange, _ = configured(tmp_path, monkeypatch, fault=fault)
    try:
        with reference:
            assert execute(loader, state, runtime).verification is M4Verification.UNKNOWN
            assert_reopened_no_dispatch(loader, state, runtime, M4Verification.UNKNOWN)
        assert read(reopened(loader), loader) == transport._ack_record
        assert transport._ack_record.native_secret_id == 71 and not transport._post_matches
        assert sum(method == 'POST' for method, _ in exchange.requests) == 1
        assert_cleanup(bridge, exchange)
    finally:
        session.close()


@pytest.mark.parametrize('fault', ['lost-ack', 'wrong-ack-device', 'wrong-ack-status', 'boolean-id'])
def test_missing_or_invalid_ack_creates_no_retention_record(tmp_path, monkeypatch, fault):
    loader, session, state, reference, bridge, transport, runtime, exchange, _ = configured(tmp_path, monkeypatch, fault=fault)
    try:
        with reference:
            assert execute(loader, state, runtime).verification is M4Verification.UNKNOWN
            assert_reopened_no_dispatch(loader, state, runtime, M4Verification.UNKNOWN)
        with pytest.raises(PersistentPlanningStoreError):
            read(reopened(loader), loader)
        assert transport._ack_record is None and not transport._ack_retention_attempted
        assert sum(method == 'POST' for method, _ in exchange.requests) == 1
        assert_cleanup(bridge, exchange)
    finally:
        session.close()


@pytest.mark.parametrize('failure', ['write', 'checkpoint', 'interrupt'])
def test_retention_failure_never_continues_readback_or_reissues_post(tmp_path, monkeypatch, failure):
    loader, session, state, reference, bridge, transport, runtime, exchange, _ = configured(tmp_path, monkeypatch)
    if failure == 'checkpoint':
        loader._parent._monotonic_checkpoint.fail_next_advance = True
    else:
        def fail(_record):
            if failure == 'interrupt': raise KeyboardInterrupt
            raise OSError('Synthetic original ACK persistence failure')
        monkeypatch.setattr(loader._parent, '_put_original_import_row_ack', fail)
    try:
        with reference:
            if failure == 'interrupt':
                with pytest.raises(KeyboardInterrupt): execute(loader, state, runtime)
            else:
                assert execute(loader, state, runtime).verification is M4Verification.UNKNOWN
            assert_reopened_no_dispatch(loader, state, runtime, M4Verification.UNKNOWN)
        assert transport._ack_retention_attempted and transport._ack_record is None
        assert transport._failure_stage == 'ack_retention'
        assert [method for method, _ in exchange.requests] == ['GET', 'POST']
        with pytest.raises(PersistentPlanningStoreError): read(reopened(loader), loader)
        assert_cleanup(bridge, exchange)
    finally:
        session.close()


def test_ack_is_immutable_not_reparented_and_retained_after_parent_invalidation(tmp_path, monkeypatch):
    loader, session, state, reference, _, transport, runtime, _, _ = configured(tmp_path, monkeypatch)
    try:
        with reference: assert execute(loader, state, runtime).verification is M4Verification.VERIFIED
        record, store = transport._ack_record, loader._parent
        tail = store._monotonic_checkpoint.tail
        store._put_original_import_row_ack(record)
        assert store._monotonic_checkpoint.tail == tail
        for changed in (replace(record, native_secret_id=72),
                        replace(record, idempotency_digest='f' * 64),
                        replace(record, row_index=1, idempotency_digest='f' * 64),
                        replace(record, parent_binding_digest='f' * 64),
                        replace(record, context_digest='f' * 64),
                        replace(record, row_index=2, idempotency_digest='f' * 64)):
            with pytest.raises(PersistentPlanningStoreError): store._put_original_import_row_ack(changed)
        with pytest.raises(PersistentPlanningStoreError):
            read(store, loader, parameters_digest='f' * 64)
        with pytest.raises(ProtectedStoreError): replace(record, native_secret_id=True)
        with pytest.raises(PersistentPlanningStoreError):
            reopened(loader, now=NOW + 300)._put_original_import_row_ack(record)
        # Matching constructed ACK and ledger IN_PROGRESS are never a new dispatch.
        transport._ack = replace(transport._ack)
        with pytest.raises(ValueError): transport._retain_original_ack()
        store.invalidate_plan(record.plan_ref, evaluated_at=NOW + 60, reason_codes=('current_state_drift',))
        assert read(reopened(loader), loader) == record
        with pytest.raises(PersistentPlanningStoreError): store._put_original_import_row_ack(record)
    finally:
        session.close()


def test_payload_tampering_cannot_supply_ack_evidence(tmp_path, monkeypatch):
    loader, session, state, reference, _, transport, runtime, _, _ = configured(tmp_path, monkeypatch)
    try:
        with reference: assert execute(loader, state, runtime).verification is M4Verification.VERIFIED
        with sqlite3.connect(loader._parent._path) as connection:
            connection.execute("UPDATE planning_records SET payload_json=replace(payload_json, "
                "'\"native_secret_id\":71', '\"native_secret_id\":72') WHERE record_type='original_import_row_ack'")
        with pytest.raises(PersistentPlanningStoreError): read(reopened(loader), loader)
        with pytest.raises(ValueError): transport._retain_original_ack()
    finally:
        session.close()


def test_parent_ledger_rollback_cannot_discard_original_ack_or_enable_redispatch(tmp_path, monkeypatch):
    loader, session, state, reference, _, transport, runtime, exchange, _ = configured(tmp_path, monkeypatch)
    snapshot = loader._parent._path.read_bytes()
    try:
        with reference:
            assert execute(loader, state, runtime).verification is M4Verification.VERIFIED
            loader._parent._path.write_bytes(snapshot)
            with pytest.raises(PersistentPlanningStoreError): read(reopened(loader), loader)
            assert_reopened_no_dispatch(loader, state, runtime, M4Verification.VERIFIED)
        with pytest.raises(ValueError): transport._retain_original_ack()
        assert sum(method == 'POST' for method, _ in exchange.requests) == 1
    finally:
        session.close()
