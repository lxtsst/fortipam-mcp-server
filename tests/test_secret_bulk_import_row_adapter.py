"""Fixed original-row handoff with synthetic transport; no native device write."""

import copy
from dataclasses import replace
import pickle
import time

import pytest

from fortipam_mcp import secret_bulk_import_row_adapter as boundary
from fortipam_mcp import secret_bulk_import_row_loader as loader_boundary
from fortipam_mcp.secret_bulk_import_file import PinnedBulkImportFile
from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_m4_execution_store import _Adapter, _Verifier
from test_secret_bulk_import_row_authority import configured
from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, M4Verification
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome


class SyntheticTransport:
    def __init__(self, values, during=None, outcome=SecretCreateAdapterOutcome.VERIFIED_CREATED):
        self.values, self.during, self.outcome = values, during, outcome
        self.calls, self.views, self.buffers = 0, [], []

    def _create_and_verify_with_original_row(self, context, columns, *, deadline):
        self.calls += 1
        assert len(columns) == 16 and all(view.readonly for view in columns)
        assert [bytes(view) for view in columns] == [part.encode() for part in self.values]
        assert time.monotonic() < deadline <= time.monotonic() + 60
        self.views.extend(columns)
        self.buffers.extend(view.obj for view in columns)
        with pytest.raises(TypeError):
            columns[6][0] = 0
        if self.during:
            self.during(context, deadline)
        return self.outcome


def execute(loader, state, bridge):
    class Dispatch(_Adapter):
        def dispatch(self, plan):
            self.calls.append("dispatch")
            try:
                outcome = bridge.dispatch_once()
            except Exception:
                raise M4AdapterAmbiguous("Synthetic original-row use unavailable") from None
            if outcome is not SecretCreateAdapterOutcome.VERIFIED_CREATED:
                raise M4AdapterAmbiguous("Synthetic original-row result uncertain")
    adapter = Dispatch()
    return M4ExecutionKernel(adapter, _Verifier(), state).execute(
        loader._plan, loader._authorization, now_epoch=1000)


def context(loader, *, expires_at=1060):
    return boundary._OriginalRowUseContext(loader._row, loader._authority._pins, 1000, expires_at)


def assert_cleared(transport):
    assert all(not any(part) for part in transport.buffers)
    for view in transport.views:
        with pytest.raises(ValueError):
            view.tobytes()


@pytest.mark.parametrize("index", [0, 1])
def test_all_native_columns_readonly_once_and_existing_m4_reopen_never_reuses_material(tmp_path, monkeypatch, index, capfd):
    loader, session, state, values, _, _, _, _, reference = configured(tmp_path, monkeypatch, index=index)
    transport = SyntheticTransport(values[index])
    bridge = boundary._OriginalRowSecretCreateAdapter(loader, context(loader), transport)
    frames, copies, owned = [], [], []
    decode = PinnedBulkImportFile.decode
    initializer = loader_boundary._OwnedOriginalImportRow.__init__
    def observe(self, **options):
        copies.append(options["workbook_password"])
        frame = decode(self, **options)
        frames.append(frame._ProtectedBulkImportRows__raw)
        return frame
    def capture(self, *args):
        initializer(self, *args)
        owned.append(self)
    monkeypatch.setattr(PinnedBulkImportFile, "decode", observe)
    monkeypatch.setattr(loader_boundary._OwnedOriginalImportRow, "__init__", capture)
    original = session._transaction._binding.path.read_bytes()
    try:
        with reference:
            assert execute(loader, state, bridge).verification is M4Verification.VERIFIED
            reopened = PersistentM4ExecutionStateStore(state._path, state._key_path,
                monotonic_checkpoint=state._monotonic_checkpoint,
                checkpoint_store_ref=state._checkpoint_store_ref)
            assert execute(loader, reopened, bridge).verification is M4Verification.VERIFIED
            with pytest.raises(BulkImportIntakeError):
                bridge.dispatch_once()
        assert transport.calls == 1 and len(frames) == len(owned) == 1
        assert owned[0]._consumed and not owned[0]._watchdog.is_alive()
        assert all(not any(part) for part in frames + copies)
        assert_cleared(transport)
        assert session._transaction._binding.path.read_bytes() == original
        for obj in (bridge, bridge._context):
            assert "Original" not in repr(obj) and "synthetic" not in repr(obj)
            for serialize in (copy.copy, copy.deepcopy, pickle.dumps):
                with pytest.raises(RuntimeError):
                    serialize(obj)
        assert capfd.readouterr() == ("", "")
    finally:
        session.close()


@pytest.mark.parametrize("fault", ["policy", "audience", "scope", "row", "row-type", "future", "overlong"])
def test_wrong_original_use_context_rejected_without_decode_or_transport(tmp_path, monkeypatch, fault):
    loader, session, _, values, _, _, _, _, _ = configured(tmp_path, monkeypatch)
    transport = SyntheticTransport(values[0])
    selected = context(loader)
    monkeypatch.setattr(PinnedBulkImportFile, "decode", lambda *_a, **_k: pytest.fail("Unbound material read"))
    try:
        with pytest.raises((BulkImportIntakeError, ValueError)):
            if fault in {"policy", "audience", "scope"}:
                field = {"policy": "policy_decision_digest", "audience": "audience_digest", "scope": "scope_digest"}[fault]
                selected = replace(selected, permission=replace(selected.permission, **{field: "8" * 64}))
            elif fault == "row":
                selected = replace(selected, row=replace(selected.row, index=1))
            elif fault == "row-type":
                selected = replace(selected, row=replace(selected.row, index=False))
            elif fault == "future":
                selected = replace(selected, requested_at=1001, expires_at=1002)
            else:
                selected = replace(selected, expires_at=1061)
            boundary._OriginalRowSecretCreateAdapter(loader, selected, transport)
        assert not loader._used and transport.calls == 0
    finally:
        session.close()


@pytest.mark.parametrize("fault", ["exception", "ambiguous", "invalid-outcome", "revoked-during", "cancelled", "expired"])
def test_uncertain_native_use_never_returns_verified_and_clears_borrowed_material(tmp_path, monkeypatch, fault):
    loader, session, state, values, root, handle, _, _, reference = configured(tmp_path, monkeypatch)
    def during(_context, deadline):
        if fault == "exception":
            raise ValueError("Synthetic fixed downstream failure")
        if fault == "revoked-during":
            root.revoke(handle, now_epoch=1000)
        if fault == "cancelled":
            session.close()
        if fault == "expired":
            time.sleep(max(0, deadline - time.monotonic()) + 0.03)
    outcome = (SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED if fault == "ambiguous"
        else "verified_created" if fault == "invalid-outcome" else SecretCreateAdapterOutcome.VERIFIED_CREATED)
    transport = SyntheticTransport(values[0], during, outcome)
    bridge = boundary._OriginalRowSecretCreateAdapter(loader,
        context(loader, expires_at=1001 if fault == "expired" else 1060), transport)
    try:
        with reference:
            result = execute(loader, state, bridge)
            assert result.verification is M4Verification.UNKNOWN
            reopened = PersistentM4ExecutionStateStore(state._path, state._key_path,
                monotonic_checkpoint=state._monotonic_checkpoint,
                checkpoint_store_ref=state._checkpoint_store_ref)
            assert execute(loader, reopened, bridge).verification is M4Verification.UNKNOWN
        assert transport.calls == 1 and loader._used
        assert_cleared(transport)
    finally:
        session.close()


def test_reentrant_adapter_refuses_second_use_while_material_is_borrowed(tmp_path, monkeypatch):
    loader, session, state, values, _, _, _, _, reference = configured(tmp_path, monkeypatch)
    def during(_context, _deadline):
        with pytest.raises(BulkImportIntakeError):
            bridge.dispatch_once()
    transport = SyntheticTransport(values[0], during)
    bridge = boundary._OriginalRowSecretCreateAdapter(loader, context(loader), transport)
    try:
        with reference:
            assert execute(loader, state, bridge).verification is M4Verification.VERIFIED
        assert transport.calls == 1
        assert_cleared(transport)
    finally:
        session.close()


def test_short_context_budget_applies_to_decoder_before_any_native_use(tmp_path, monkeypatch):
    loader, session, state, values, _, _, _, _, reference = configured(tmp_path, monkeypatch)
    transport = SyntheticTransport(values[0])
    bridge = boundary._OriginalRowSecretCreateAdapter(loader, context(loader, expires_at=1001), transport)
    def stall(self, **options):
        assert options["_lifetime"].deadline <= bridge._deadline
        time.sleep(max(0, options["_lifetime"].deadline - time.monotonic()) + 0.03)
        options["_lifetime"].check()
    monkeypatch.setattr(PinnedBulkImportFile, "decode", stall)
    try:
        with reference:
            assert execute(loader, state, bridge).verification is M4Verification.UNKNOWN
        assert loader._used and transport.calls == 0
        assert session._transaction._closed.is_set() and not any(session._password)
    finally:
        session.close()


def test_interrupt_clears_views_and_unfinished_durable_claim_cannot_reacquire(tmp_path, monkeypatch):
    loader, session, state, values, _, _, _, _, reference = configured(tmp_path, monkeypatch)
    def interrupted(_context, _deadline):
        raise KeyboardInterrupt
    transport = SyntheticTransport(values[0], interrupted)
    bridge = boundary._OriginalRowSecretCreateAdapter(loader, context(loader), transport)
    try:
        with reference:
            with pytest.raises(KeyboardInterrupt):
                execute(loader, state, bridge)
            assert_cleared(transport)
            reopened = PersistentM4ExecutionStateStore(state._path, state._key_path,
                monotonic_checkpoint=state._monotonic_checkpoint,
                checkpoint_store_ref=state._checkpoint_store_ref)
            assert execute(loader, reopened, bridge).verification is M4Verification.UNKNOWN
        assert transport.calls == 1 and loader._used
    finally:
        session.close()
