"""Private C2 provenance and original-row restoration; no device or provider I/O."""

from dataclasses import asdict, replace
import hashlib
import sqlite3

import pytest

from fortipam_mcp import secret_bulk_import_row_namespace as boundary
from test_secret_bulk_import_row_namespace import original
from test_v4_m3 import NOW, _confirmation, _plan, _requester, _summary
from test_v4_persistence import CHECKPOINT_STORE_REF, _ExternalCheckpoint, _new_store
from v4_planning import canonical_digest
from v4_planning.persistence import PersistentPlanningStoreError, PersistentProtectedPlanningStore
from v4_planning.store import OriginalImportBindingRecord


def parent(store, suffix="01", *, requester=None):
    requester = _requester() if requester is None else requester
    summary = _summary(requester)
    content = summary.canonical_content()
    content["summary_ref"] = "import-summary-" + suffix
    summary = replace(summary, summary_ref="import-summary-" + suffix,
                      summary_digest=canonical_digest(content))
    confirmation = _confirmation(summary)
    content = confirmation.canonical_content()
    content["confirmation_ref"] = "import-confirmation-" + suffix
    confirmation = replace(confirmation, confirmation_ref="import-confirmation-" + suffix,
                           record_digest=canonical_digest(content))
    plan = _plan(requester, summary, confirmation, plan_ref="import-parent-" + suffix)
    store.put_summary(summary)
    store.put_confirmation(confirmation)
    store.put_plan(plan)
    return plan


def prepared(tmp_path):
    checkpoint = _ExternalCheckpoint()
    store, database, ledger_key = _new_store(tmp_path,
        monotonic_checkpoint=checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF)
    plan = parent(store)
    rows, session, _, _, _, pins = original(tmp_path)
    operation = replace(rows._operation, plan_ref=plan.plan_ref, requester_digest=plan.requester_digest)
    rows = boundary.PinnedOriginalImportRows(operation, **pins)
    return store, database, ledger_key, checkpoint, plan, rows, session, pins


def retain(store, plan, rows, session):
    boundary.retain_original_import_rows(rows, session, store,
        expected_plan_digest=plan.plan_digest, authenticated_requester_digest=plan.requester_digest)


def resolve(store, plan, session, pins, **changes):
    options = dict(original_plan_ref=plan.plan_ref, expected_plan_digest=plan.plan_digest,
        authenticated_requester_digest=plan.requester_digest, **pins)
    options.update(changes)
    return boundary.resolve_original_import_rows(session, store, **options)


def test_parent_binding_restores_original_row_after_reopen_without_public_plan_changes(tmp_path):
    store, database, ledger_key, checkpoint, plan, rows, session, pins = prepared(tmp_path)
    try:
        before = plan.canonical_content()
        retain(store, plan, rows, session)
        tail = checkpoint.tail
        retain(store, plan, rows, session)
        assert checkpoint.tail == tail
        reopened = PersistentProtectedPlanningStore(database, ledger_key, clock=lambda: NOW + 300,
            monotonic_checkpoint=checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF)
        restored = resolve(reopened, plan, session, pins)
        assert restored.row(0) == rows.row(0)
        assert reopened.get_plan(plan.plan_ref).canonical_content() == before
        # Expired metadata can be resolved but cannot compile a new binding.
        with pytest.raises(boundary.BulkImportIntakeError):
            retain(reopened, plan, rows, session)
        with sqlite3.connect(database) as connection:
            payload = connection.execute("SELECT payload_json FROM planning_records "
                "WHERE record_type='original_import_binding'").fetchone()[0]
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert tables == {"planning_records", "integrity_anchor"}
        for private in (str(session._transaction._binding.path),
                        session._transaction._binding.file_sha256, "PasswordPassphrase", "password"):
            assert private not in payload
    finally:
        session.close()


@pytest.mark.parametrize("field", ["original_plan_ref", "expected_plan_digest",
                                  "authenticated_requester_digest", "key_sha256"])
def test_replacement_resumption_context_is_rejected(tmp_path, field):
    store, _, _, _, plan, rows, session, pins = prepared(tmp_path)
    try:
        retain(store, plan, rows, session)
        changed = "replacement-parent-01" if field == "original_plan_ref" else "a" * 64
        with pytest.raises(boundary.BulkImportIntakeError):
            resolve(store, plan, session, pins, **{field: changed})
    finally:
        session.close()


def test_alias_batch_parent_and_key_cannot_reset_original_binding_even_after_invalidation(tmp_path):
    store, _, _, checkpoint, plan, rows, session, pins = prepared(tmp_path)
    try:
        retain(store, plan, rows, session)
        record = OriginalImportBindingRecord(plan_digest=plan.plan_digest,
            namespace_key_digest=pins["key_sha256"], **asdict(rows._operation))
        store.invalidate_plan(plan.plan_ref, evaluated_at=NOW + 60, reason_codes=("current_state_drift",))
        with pytest.raises(boundary.BulkImportIntakeError):
            resolve(store, plan, session, pins)
        other = parent(store, "02")
        tail = checkpoint.tail
        alias = replace(record, plan_ref=other.plan_ref, plan_digest=other.plan_digest,
                        input_commitment="a" * 64, parent_idempotency_digest="b" * 64)
        with pytest.raises(PersistentPlanningStoreError, match="already has a parent"):
            store.put_original_import_binding(alias)
        with pytest.raises(PersistentPlanningStoreError, match="key cannot be replaced"):
            store.put_original_import_binding(replace(alias, source_commitment="c" * 64,
                                                     namespace_key_digest="d" * 64))
        assert checkpoint.tail == tail
    finally:
        session.close()


def test_tamper_and_checkpoint_rollback_cannot_restore_original_rows(tmp_path):
    store, database, ledger_key, checkpoint, plan, rows, session, pins = prepared(tmp_path)
    try:
        before_tail = checkpoint.tail
        old_database = database.read_bytes()
        retain(store, plan, rows, session)
        original_database = database.read_bytes()
        database.write_bytes(old_database)
        with pytest.raises(PersistentPlanningStoreError):
            PersistentProtectedPlanningStore(database, ledger_key, monotonic_checkpoint=checkpoint,
                                             checkpoint_store_ref=CHECKPOINT_STORE_REF)
        assert checkpoint.tail != before_tail
        database.write_bytes(original_database)
        with sqlite3.connect(database) as connection:
            connection.execute("UPDATE planning_records SET payload_json='{}' "
                               "WHERE record_type='original_import_binding'")
        with pytest.raises(boundary.BulkImportIntakeError):
            resolve(store, plan, session, pins)
    finally:
        session.close()


def test_missing_parent_checkpoint_and_shared_key_cannot_retain_source(tmp_path):
    store, _, _, _, plan, rows, session, pins = prepared(tmp_path)
    try:
        record = OriginalImportBindingRecord(plan_digest=plan.plan_digest,
            namespace_key_digest=pins["key_sha256"], **asdict(rows._operation))
        with pytest.raises(PersistentPlanningStoreError):
            store.put_original_import_binding(replace(record, plan_ref="missing-parent-01"))
        with pytest.raises(PersistentPlanningStoreError, match="does not match"):
            store.put_original_import_binding(replace(record, requester_digest="a" * 64))
        no_checkpoint, _, _ = _new_store(tmp_path / "no-checkpoint")
        with pytest.raises(PersistentPlanningStoreError, match="checkpoint"):
            no_checkpoint.put_original_import_binding(record)
        shared, _, _ = _new_store(tmp_path / "shared", key=b"i" * 32,
            monotonic_checkpoint=_ExternalCheckpoint(), checkpoint_store_ref=CHECKPOINT_STORE_REF)
        parent(shared)
        with pytest.raises(boundary.BulkImportIntakeError):
            retain(shared, plan, rows, session)
        assert hashlib.sha256(b"i" * 32).hexdigest() == pins["key_sha256"]
    finally:
        session.close()


def test_constructed_source_alias_cannot_enter_authenticated_parent_record(tmp_path):
    store, _, _, checkpoint, plan, rows, session, pins = prepared(tmp_path)
    try:
        forged = boundary.PinnedOriginalImportRows(
            replace(rows._operation, source_commitment="a" * 64), **pins)
        tail = checkpoint.tail
        with pytest.raises(boundary.BulkImportIntakeError):
            retain(store, plan, forged, session)
        assert checkpoint.tail == tail
        retain(store, plan, rows, session)
    finally:
        session.close()
