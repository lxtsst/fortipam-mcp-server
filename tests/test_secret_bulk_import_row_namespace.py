"""Original-row binding plus the existing durable M4 kernel; synthetic only."""

import asyncio
import copy
from dataclasses import asdict, replace
import hashlib
import pickle

import pytest

from v4_planning import (
    M4AdapterAmbiguous, M4AdapterFailure, M4ExecutionError, M4ExecutionKernel, M4ExecutionPlan,
    canonical_digest,
)
from v4_planning.secret_create_adapter import SECRET_CREATE_ACTION_ID, SECRET_CREATE_ACTION_VERSION
from fortipam_mcp import secret_bulk_import_row_namespace as boundary
from fortipam_mcp.secret_bulk_import_session import admit_prebound_owner_file_session
from test_secret_bulk_import_session import SessionAuthority
from test_secret_bulk_import_intake import Authority, Verifier, prepared
from test_secret_bulk_import_dependencies import catalog, item
from test_secret_bulk_import_file import csv_bytes
from test_m4_execution_store import _Adapter, _ExternalM4Checkpoint, _Verifier, _authorization, _plan, _store, CHECKPOINT_STORE_REF


def original(tmp_path, *, rows=1):
    binding, options, clocks = prepared(tmp_path)
    if rows == 2:
        raw = csv_bytes([item(Name="Original first row"), item(Name="Original second row")])
        binding.path.write_bytes(raw)
        binding = replace(binding, file_sha256=hashlib.sha256(raw).hexdigest())
        options.update(authority=Authority(binding), planning_verifier=Verifier(binding, True), intake_verifier=Verifier(binding, False))
    options["session_authority"] = SessionAuthority(binding)
    session = asyncio.run(admit_prebound_owner_file_session(binding, **options))
    snapshot = catalog()
    projected = session.project_dependencies_once(snapshot)
    key = tmp_path / "original-row.key"
    key.write_bytes(b"i" * 32)
    key.chmod(0o600)
    pins = dict(key_path=key.resolve(), key_sha256=hashlib.sha256(b"i" * 32).hexdigest())
    namespaces = boundary.bind_original_import_rows(session, projected, snapshot,
        original_plan_ref="original-bulk-plan-01", authenticated_requester_digest="7" * 64,
        parent_idempotency_digest="8" * 64, **pins)
    return namespaces, session, binding, options, clocks, pins


def child_plan(row):
    fields = _plan().canonical_content()
    fields.update(plan_ref=row.plan_ref, requester_digest=row.requester_digest,
        idempotency_digest=row.idempotency_digest, parameters_digest=row.parameters_digest,
        action_id=SECRET_CREATE_ACTION_ID, action_version=SECRET_CREATE_ACTION_VERSION,
        adapter_ref="fixed-secret-create-adapter-01")
    return M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))


def test_original_rows_survive_fresh_clients_workload_time_catalog_and_reconstruction(tmp_path):
    namespaces, session, binding, options, _, pins = original(tmp_path)
    first = namespaces.row(0)
    session.close()
    fresh_binding = replace(binding, planning_client="fresh-planning-client", intake_client="fresh-intake-client",
        workload_digest="9" * 64, issued_at=1001, expires_at=1120)
    options.update(authority=Authority(fresh_binding), session_authority=SessionAuthority(fresh_binding),
        planning_verifier=Verifier(fresh_binding, True), intake_verifier=Verifier(fresh_binding, False),
        clock=lambda: 1005, monotonic=lambda: 105)
    fresh = asyncio.run(admit_prebound_owner_file_session(fresh_binding, **options))
    try:
        restored = boundary.PinnedOriginalImportRows(boundary.OriginalImportOperation(**asdict(namespaces._operation)), **pins)
        restored.verify_source_session(fresh, authenticated_requester_digest="7" * 64)
        assert restored.row(0) == first
        # Even initial compilation cannot let catalog timestamps reset identity.
        snapshot = catalog()
        projected = fresh.project_dependencies_once(snapshot)
        rebound = boundary.bind_original_import_rows(fresh, projected, snapshot,
            original_plan_ref="original-bulk-plan-01", authenticated_requester_digest="7" * 64,
            parent_idempotency_digest="8" * 64, **pins)
        assert rebound.row(0) == first
        for value in (restored, restored._operation, first):
            assert "original-bulk-plan" not in repr(value)
            for serialize in (copy.copy, copy.deepcopy, pickle.dumps):
                with pytest.raises(RuntimeError):
                    serialize(value)
    finally:
        fresh.close()


@pytest.mark.parametrize("field", ["batch_digest", "subject", "deployment_digest", "scope_digest"])
def test_independently_admitted_different_input_cannot_resume_original_rows(tmp_path, field):
    namespaces, session, binding, options, _, _ = original(tmp_path)
    session.close()
    changed = replace(binding, **{field: "different-human" if field == "subject" else "9" * 64})
    options.update(authority=Authority(changed), session_authority=SessionAuthority(changed),
        planning_verifier=Verifier(changed, True), intake_verifier=Verifier(changed, False))
    fresh = asyncio.run(admit_prebound_owner_file_session(changed, **options))
    try:
        with pytest.raises(boundary.BulkImportIntakeError):
            namespaces.verify_source_session(fresh, authenticated_requester_digest="7" * 64)
    finally:
        fresh.close()


def test_invalid_row_key_drift_or_replacement_plan_denies_before_kernel(tmp_path):
    namespaces, session, _, _, _, pins = original(tmp_path)
    try:
        row = namespaces.row(0)
        row.verify_m4_plan(child_plan(row))
        for index in (-1, True, 1):
            with pytest.raises(boundary.BulkImportIntakeError):
                namespaces.row(index)
        fields = child_plan(row).canonical_content()
        fields["plan_ref"] = "replacement-plan-01"
        changed = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
        with pytest.raises(boundary.BulkImportIntakeError):
            row.verify_m4_plan(changed)
        pins["key_path"].write_bytes(b"j" * 32)
        with pytest.raises(boundary.BulkImportIntakeError):
            namespaces.row(0)
    finally:
        session.close()


@pytest.mark.parametrize("outcome", ["verified", "unknown", "parser-failure"])
def test_durable_original_claim_prevents_reacquisition_with_fresh_authorization(tmp_path, outcome):
    namespaces, session, _, _, _, pins = original(tmp_path, rows=2)
    session.close()
    row = namespaces.row(0)
    plan = child_plan(row)
    row.verify_m4_plan(plan)
    checkpoint = _ExternalM4Checkpoint()
    store = _store(tmp_path, monotonic_checkpoint=checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF)
    class Loader(_Adapter):
        def dispatch(self, plan):
            self.calls.append("acquire_original_row")
            assert store.claim_count == 1  # Reserve precedes loading, including parser failure.
            if outcome == "unknown":
                raise M4AdapterAmbiguous("Synthetic uncertain dispatch")
            if outcome == "parser-failure":
                raise M4AdapterFailure("Synthetic parser failure")
    adapter = Loader()
    authorization = _authorization(plan)
    result = M4ExecutionKernel(adapter, _Verifier(), store, clock=lambda: 1000).execute(plan, authorization)
    assert adapter.calls.count("acquire_original_row") == 1
    restored = boundary.PinnedOriginalImportRows(boundary.OriginalImportOperation(**asdict(namespaces._operation)), **pins)
    assert restored.row(0) == row
    reopened = _store(tmp_path, monotonic_checkpoint=checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF)
    another = Loader()
    replay = M4ExecutionKernel(another, _Verifier(), reopened, clock=lambda: 1000).execute(plan, authorization)
    assert replay.idempotent_replay and replay.outcome == result.outcome and another.calls == []
    values = authorization.canonical_content()
    values.update(authorization_ref="fresh-execution-authorization-02", issued_at=1000)
    fresh_authorization = type(authorization)(**values, authorization_digest=canonical_digest(values))
    with pytest.raises(M4ExecutionError):
        M4ExecutionKernel(another, _Verifier(), reopened, clock=lambda: 1000).execute(plan, fresh_authorization)
    assert another.calls == [] and reopened.claim_count == 1
    # A distinct unstarted original row still has its own exact namespace.
    unstarted = child_plan(restored.row(1))
    assert unstarted.idempotency_digest != plan.idempotency_digest
    assert reopened.claim(plan_ref=unstarted.plan_ref, requester_digest=unstarted.requester_digest,
        idempotency_digest=unstarted.idempotency_digest, context_digest="a" * 64,
        authorization_digest="b" * 64).state.value == "new"
