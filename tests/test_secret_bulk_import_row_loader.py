"""Synthetic original-parent/M4/actual decoder join, without a device writer."""

import asyncio
import copy
from dataclasses import replace
import hashlib
import pickle
import subprocess
import sys

import pytest

from fortipam_mcp import secret_bulk_import_row_loader as boundary
from fortipam_mcp import secret_bulk_import_row_namespace as namespace
from fortipam_mcp import secret_bulk_import_file as file_boundary
from fortipam_mcp.secret_bulk_import_file import PinnedBulkImportFile
from fortipam_mcp.secret_bulk_import_session import admit_prebound_owner_file_session
from test_secret_bulk_import_dependencies import catalog, item
from test_secret_bulk_import_file import csv_bytes, encrypted_bytes, workbook_bytes
from test_secret_bulk_import_intake import Authority, Verifier, prepared
from test_secret_bulk_import_parent_binding import parent
from test_secret_bulk_import_row_namespace import child_plan
from test_secret_bulk_import_session import SessionAuthority
from test_v4_persistence import _ExternalCheckpoint, _new_store, CHECKPOINT_STORE_REF as PARENT_STORE
from test_m4_execution_store import (
    _Adapter, _ExternalM4Checkpoint, _Verifier, _authorization, _store, CHECKPOINT_STORE_REF,
)
from v4_planning import M4AdapterAmbiguous, M4ExecutionError, M4ExecutionKernel, M4Verification, canonical_digest


class ReadOnlyAcquisitionAuthority:
    def __init__(self, plan, authorization, source):
        self.expected = plan, authorization, source
        self.denied = False
        self.calls = 0

    def verify_row_acquisition(self, plan, authorization, source, *, now_epoch):
        self.calls += 1
        if self.denied or (plan, authorization, source) != self.expected or now_epoch != 1000:
            raise ValueError("Synthetic read-only acquisition check denied")

    def acquisition_expires_at(self):
        plan, auth, source = self.expected
        return min(plan.expires_at, auth.expires_at, source.expires_at)

    verify_row_completion = verify_row_acquisition


def setup(tmp_path, kind="csv", *, values=None, snapshot=None, capture=None, file_parent=False):
    parent_store, _, _ = _new_store(tmp_path, monotonic_checkpoint=_ExternalCheckpoint(),
                                  checkpoint_store_ref=PARENT_STORE, **({'now_epoch': 1000} if file_parent else {}))
    parent_plan = None if file_parent else parent(parent_store)
    binding, options, clocks = prepared(tmp_path, kind)
    values = values if values is not None else [item(Name="Original first row", **{"Description": "first description"}),
              item(Name="Original second row", Username=" second synthetic user ",
                   **{"Password/Passphrase": " second synthetic password,\r\n秘密 ",
                      "Association-Secret": "Original first row", "Description": "second\r\n描述"})]
    raw = csv_bytes(values) if kind == "csv" else workbook_bytes(values)
    if kind == "encrypted":
        raw = encrypted_bytes(raw)
    binding.path.write_bytes(raw)
    binding = replace(binding, file_sha256=hashlib.sha256(raw).hexdigest())
    options.update(authority=Authority(binding), session_authority=SessionAuthority(binding),
                   planning_verifier=Verifier(binding, True), intake_verifier=Verifier(binding, False))
    session = asyncio.run(admit_prebound_owner_file_session(binding,
        workbook_password=bytearray(b"synthetic-password") if kind == "encrypted" else None, **options))
    snapshot = snapshot or catalog()
    projected = session.project_dependencies_once(snapshot)
    if capture is not None:
        capture.update(catalog=snapshot, projected=projected)
    key = tmp_path / "original-row.key"
    key.write_bytes(b"i" * 32)
    key.chmod(0o600)
    pins = dict(key_path=key.resolve(), key_sha256=hashlib.sha256(b"i" * 32).hexdigest())
    rows = namespace.bind_original_import_rows(session, projected, snapshot,
        original_plan_ref=parent_plan.plan_ref if parent_plan else 'file-import-parent-01',
        authenticated_requester_digest=parent_plan.requester_digest if parent_plan else '7' * 64,
        parent_idempotency_digest="8" * 64, **pins)
    if file_parent:
        from fortipam_mcp.secret_bulk_import_parent_graph import _build_file_import_parent
        parent_plan = _build_file_import_parent(rows, binding, projected, snapshot,
            source_policy_digest='a' * 64, owner_decision_digest='b' * 64, created_at=1000, expires_at=1060,
            standing_lab_authorization=True)
        parent_store.put_file_import_parent(parent_plan)
    namespace.retain_original_import_rows(rows, session, parent_store,
        expected_plan_digest=parent_plan.plan_digest, authenticated_requester_digest=parent_plan.requester_digest)
    checkpoint = _ExternalM4Checkpoint()
    execution = _store(tmp_path, monotonic_checkpoint=checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF)

    class InitialProjection:
        def read_current(self, plan): return plan.expected_current_digest
        def read_postcondition(self, plan): return plan.expected_state_digest

    def make_issuer(index, **changes):
        from fortipam_mcp.secret_bulk_import_row_authority import _OriginalRowM4Authority
        args = dict(index=index, expected_parent_digest=parent_plan.plan_digest,
            authority_key=b'j' * 32, authenticated_requester_digest=parent_plan.requester_digest,
            transport_digest='9' * 64, execution_enabled=True, clock=lambda: 1000)
        reader = changes.pop('projection_reader', InitialProjection())
        args.update(changes)
        return _OriginalRowM4Authority(rows, binding, projected, snapshot, parent_store, execution, reader, **args)

    def loader(index, *, authority=True, plan=None, authorization=None, state=None):
        issuer = None
        if file_parent:
            issuer = make_issuer(index)
            issued = issuer.issue()
            plan, authorization = plan or issued.plan, authorization or issued.authorization
        else:
            plan = plan or child_plan(rows.row(index))
            authorization = authorization or _authorization(plan)
        check = ReadOnlyAcquisitionAuthority(plan, authorization, binding) if authority else None
        result = boundary._PreboundOriginalImportRowLoader(session, parent_store, state or execution,
            plan, authorization, expected_parent_digest=parent_plan.plan_digest, index=index,
            acquisition_authority=check, **pins)
        if issuer is not None:
            result._issuer = issuer
        return result

    if capture is not None:
        capture['make_loader'] = loader
        capture['make_issuer'] = make_issuer
    return loader, session, execution, checkpoint, values, binding, options, rows


class ProbeAdapter(_Adapter):
    """Only synthetic buffer assertions, never a Secret writer."""

    def __init__(self, loader, values=None, *, fail_after_copy=False):
        super().__init__()
        self.loader, self.values = loader, values
        self.owned = None
        self.fail_after_copy = fail_after_copy

    def read_current(self, plan):
        if hasattr(self.loader, '_issuer'):
            return self.loader._issuer._reader.read_current(plan)
        return super().read_current(plan)

    def read_postcondition(self, plan):
        if hasattr(self.loader, '_issuer'):
            return self.loader._issuer._reader.read_postcondition(plan)
        return super().read_postcondition(plan)

    def dispatch(self, plan):
        self.calls.append("dispatch")
        assert plan == self.loader._plan
        try:
            with self.loader._load_once() as owned:
                self.owned = owned
                if self.values is not None:
                    assert [bytes(value) for value in owned._buffers] == [value.encode() for value in self.values]
                if self.fail_after_copy:
                    raise ValueError("Synthetic downstream failure")
        except Exception:
            raise M4AdapterAmbiguous("Synthetic fixed failure category") from None


def run(loader, state, adapter=None):
    adapter = adapter or ProbeAdapter(loader)
    return M4ExecutionKernel(adapter, getattr(loader, '_issuer', _Verifier()), state).execute(
        loader._plan, loader._authorization, now_epoch=1000), adapter


@pytest.mark.parametrize("kind", ["csv", "xlsm", "encrypted"])
def test_actual_fresh_decode_copies_only_selected_native_row_and_wipes_entire_frame(tmp_path, monkeypatch, kind):
    make, session, state, _, values, binding, _, _ = setup(tmp_path, kind)
    frames, copies = [], []
    decode = PinnedBulkImportFile.decode

    def observe(self, **options):
        assert state.claim_count in (1, 2)
        copies.append(options["workbook_password"])
        frame = decode(self, **options)
        frames.append(frame._ProtectedBulkImportRows__raw)
        return frame

    monkeypatch.setattr(PinnedBulkImportFile, "decode", observe)
    original_source = binding.path.read_bytes()
    try:
        for index in range(2):
            loader = make(index)
            result, adapter = run(loader, state, ProbeAdapter(loader, values[index]))
            assert result.verification is M4Verification.VERIFIED
            assert loader._authority.calls == 3
            assert all(not any(value) for value in adapter.owned._buffers)
            assert not adapter.owned._watchdog.is_alive()
            for serialize in (copy.copy, copy.deepcopy, pickle.dumps):
                with pytest.raises(RuntimeError):
                    serialize(adapter.owned)
            with pytest.raises(boundary.BulkImportIntakeError):
                loader._load_once()
        assert len(frames) == 2 and all(raw and not any(raw) for raw in frames)
        assert all(not any(password) for password in copies)
        assert binding.path.read_bytes() == original_source
        if kind == "encrypted":
            assert any(session._password)
    finally:
        session.close()
    assert not any(session._password)


@pytest.mark.parametrize("missing", ["claim", "authority", "revoked-source", "revoked-child", "invalid-parent"])
def test_unproved_or_revoked_authority_never_reads_source(tmp_path, monkeypatch, missing):
    make, session, state, _, _, _, options, _ = setup(tmp_path)
    loader = make(0, authority=missing != "authority")
    monkeypatch.setattr(PinnedBulkImportFile, "decode", lambda *_a, **_k: pytest.fail("Denied source read"))
    try:
        if missing == "revoked-source":
            options["authority"].denied = True
        if missing == "revoked-child":
            loader._authority.denied = True
        if missing == "invalid-parent":
            loader._parent.invalidate_plan(loader._plan.plan_ref, evaluated_at=loader._parent._clock(),
                                          reason_codes=("current_state_drift",))
        if missing == "claim":
            with pytest.raises(boundary.BulkImportIntakeError):
                loader._load_once()
            assert state.claim_count == 0
        else:
            result, _ = run(loader, state)
            assert result.verification is M4Verification.UNKNOWN
    finally:
        session.close()


@pytest.mark.parametrize("failure", ["none", "downstream", "source-drift"])
def test_original_claim_reopen_and_fresh_authorization_cannot_decode_again(tmp_path, monkeypatch, failure):
    make, session, state, checkpoint, _, binding, _, _ = setup(tmp_path, "encrypted")
    loader = make(0)
    try:
        if failure == "source-drift":
            binding.path.write_bytes(binding.path.read_bytes() + b"drift")
        result, _ = run(loader, state, ProbeAdapter(loader, fail_after_copy=failure == "downstream"))
        assert result.verification is (M4Verification.VERIFIED if failure == "none" else M4Verification.UNKNOWN)
        reopened = _store(tmp_path, monotonic_checkpoint=checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF)
        monkeypatch.setattr(PinnedBulkImportFile, "decode", lambda *_a, **_k: pytest.fail("Reacquisition after reopen"))
        # A reconstruction need not read a closed source session: existing M4
        # replay is decided before the adapter or new intake loader is touched.
        adapter = ProbeAdapter(loader)
        kernel = M4ExecutionKernel(adapter, _Verifier(), reopened)
        replay = kernel.execute(loader._plan, loader._authorization, now_epoch=1000)
        assert replay.idempotent_replay and not adapter.calls
        content = loader._authorization.canonical_content()
        content["authorization_ref"] = "fresh-authorization-01"
        fresh = replace(loader._authorization, authorization_ref="fresh-authorization-01",
                        authorization_digest=canonical_digest(content))
        with pytest.raises(M4ExecutionError):
            kernel.execute(loader._plan, fresh, now_epoch=1000)
        assert reopened.claim_count == 1 and not adapter.calls
    finally:
        session.close()


def test_idle_row_disposal_uses_original_child_deadline_with_frozen_clocks(tmp_path):
    make, session, state, _, _, _, _, _ = setup(tmp_path)
    first = make(0)
    content = first._authorization.canonical_content()
    content["expires_at"] = 1001
    auth = replace(first._authorization, expires_at=1001, authorization_digest=canonical_digest(content))
    session._transaction._clock = lambda: 1000.5
    loader = make(0, authorization=auth)
    escaped = []

    class HoldProbe(ProbeAdapter):
        def dispatch(self, plan):
            escaped.append(loader._load_once())

    try:
        result, _ = run(loader, state, HoldProbe(loader))
        assert result.verification is M4Verification.VERIFIED
        owned = escaped[0]
        owned._watchdog.join(1)
        assert not owned._watchdog.is_alive() and all(not any(value) for value in owned._buffers)
        assert not session._transaction._closed.is_set()
    finally:
        for owned in escaped:
            owned.close()
        session.close()


def test_actual_stalled_child_is_killed_and_original_claim_prevents_reacquisition(tmp_path, monkeypatch):
    make, session, state, checkpoint, _, _, _, _ = setup(tmp_path)
    first = make(0)
    content = first._authorization.canonical_content()
    content["expires_at"] = 1001
    auth = replace(first._authorization, expires_at=1001, authorization_digest=canonical_digest(content))
    session._transaction._clock = lambda: 1000.8
    loader = make(0, authorization=auth)
    children = []
    spawn = subprocess.Popen

    def stalled(*_args, **options):
        child = spawn([sys.executable, "-I", "-c", "import time; time.sleep(30)"], **options)
        children.append(child)
        return child

    monkeypatch.setattr(file_boundary.subprocess, "Popen", stalled)
    try:
        result, _ = run(loader, state)
        assert result.verification is M4Verification.UNKNOWN
        assert len(children) == 1 and children[0].poll() is not None
        assert session._transaction._closed.is_set()
        reopened = _store(tmp_path, monotonic_checkpoint=checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF)
        adapter = ProbeAdapter(loader)
        replay, _ = run(loader, reopened, adapter)
        assert replay.idempotent_replay and not adapter.calls and len(children) == 1
    finally:
        session.close()


def test_child_rows_clear_automatically_on_source_cancel_without_material_getter(tmp_path):
    make, session, state, _, _, _, _, _ = setup(tmp_path, "encrypted")
    loader = make(0)
    escaped = []

    class HoldProbe(ProbeAdapter):
        def dispatch(self, plan):
            escaped.append(loader._load_once())

    try:
        run(loader, state, HoldProbe(loader))
        owned = escaped[0]
        assert any(any(value) for value in owned._buffers)
        assert not hasattr(owned, "material") and not hasattr(owned, "get_row")
        session.close()
        owned._watchdog.join(1)
        assert not owned._watchdog.is_alive() and all(not any(value) for value in owned._buffers)
        with pytest.raises(boundary.BulkImportIntakeError):
            owned.__enter__()
    finally:
        for owned in escaped:
            owned.close()
        session.close()


def test_unfinished_original_claim_reopens_without_adapter_or_source_read(tmp_path, monkeypatch):
    make, session, state, checkpoint, _, _, _, _ = setup(tmp_path)
    loader = make(0)
    context = canonical_digest({"authorization_digest": loader._authorization.authorization_digest,
        "plan_digest": loader._plan.plan_digest, "revision": loader._plan.revision})
    state.claim(plan_ref=loader._plan.plan_ref, requester_digest=loader._plan.requester_digest,
        idempotency_digest=loader._plan.idempotency_digest, context_digest=context,
        authorization_digest=loader._authorization.authorization_digest)
    monkeypatch.setattr(PinnedBulkImportFile, "decode", lambda *_a, **_k: pytest.fail("Unfinished claim reread"))
    try:
        reopened = _store(tmp_path, monotonic_checkpoint=checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF)
        adapter = ProbeAdapter(loader)
        result, _ = run(loader, reopened, adapter)
        assert result.idempotent_replay and result.verification is M4Verification.UNKNOWN
        assert not adapter.calls and reopened.claim_count == 1
    finally:
        session.close()


def test_cloned_loader_in_same_new_dispatch_cannot_read_original_row_twice(tmp_path, monkeypatch):
    make, session, state, _, _, _, _, _ = setup(tmp_path)
    loader, clone = make(0), make(0)
    reads = []
    decode = PinnedBulkImportFile.decode

    def observe(self, **options):
        reads.append(True)
        return decode(self, **options)

    monkeypatch.setattr(PinnedBulkImportFile, "decode", observe)

    class Probe(ProbeAdapter):
        def dispatch(self, plan):
            with loader._load_once():
                pass
            with pytest.raises(boundary.BulkImportIntakeError):
                clone._load_once()

    try:
        result, _ = run(loader, state, Probe(loader))
        assert result.verification is M4Verification.VERIFIED and len(reads) == 1
        # Even a live, originally matching ledger claim does not permit a
        # private loader call outside the kernel's original dispatch context.
        with pytest.raises(boundary.BulkImportIntakeError):
            clone._load_once()
    finally:
        session.close()


def test_authorization_observation_latency_cannot_extend_material_grant(tmp_path):
    make, session, state, _, _, _, _, _ = setup(tmp_path)
    loader = make(0)
    wall = [1000.0]
    session._transaction._clock = lambda: wall[0]

    class SlowAuthority(ReadOnlyAcquisitionAuthority):
        def verify_row_acquisition(self, *args, **kwargs):
            super().verify_row_acquisition(*args, **kwargs)
            wall[0] = 1000.75

        def acquisition_expires_at(self):
            return 1001

    loader._authority = SlowAuthority(loader._plan, loader._authorization, session._transaction._binding)
    held = []

    class HoldProbe(ProbeAdapter):
        def dispatch(self, plan):
            held.append(loader._load_once())

    try:
        result, _ = run(loader, state, HoldProbe(loader))
        assert result.verification is M4Verification.VERIFIED
        import time
        assert held[0]._lifetime.deadline - time.monotonic() <= 0.25
        held[0]._watchdog.join(0.5)
        assert not held[0]._watchdog.is_alive() and all(not any(value) for value in held[0]._buffers)
    finally:
        for row in held:
            row.close()
        session.close()
