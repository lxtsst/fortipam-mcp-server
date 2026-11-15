"""Colocated candidate lease/store mechanism; synthetic product, no device call."""

import copy
from dataclasses import replace
import pickle
import time

import pytest

from fortipam_mcp import secret_bulk_import_row_provider as boundary
from fortipam_mcp.secret_bulk_import_file import PinnedBulkImportFile
from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
from fortipam_mcp.secret_bulk_import_row_adapter import _OriginalRowSecretCreateAdapter
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_m4_execution_store import _Adapter, _Verifier
from test_secret_bulk_import_row_adapter import SyntheticTransport, assert_cleared, context
from test_secret_bulk_import_row_authority import configured
from test_v4_material_persistence import _store
from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, M4Verification
from v4_planning.material_checkpoint_authority import PersistentMaterialUseCheckpointAuthority
from v4_planning.material_provider import (
    C3MaterialBinding, MaterialAccessDenied, MaterialBindingStatus, MaterialLease,
    MaterialLeaseRequest, MaterialProviderClass, MaterialRevocationReason,
)
from v4_planning.material_persistence import MaterialUseMonotonicCheckpointError
from v4_planning.material_runtime import MaterialRuntimeOutcome, MaterialUseClaimState
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome
from v4_planning.secret_create_runtime import PackagedDenyAllSecretCreateMaterialRuntime


def material_store(tmp_path):
    root = tmp_path / "material-checkpoint"
    root.mkdir(mode=0o700)
    key = root / "checkpoint.key"
    key.write_bytes(b"d" * 32)
    key.chmod(0o600)
    cp = PersistentMaterialUseCheckpointAuthority(root / "checkpoint.db", key,
        authority_ref="original-row-material-checkpoint-01")
    return _store(tmp_path, monotonic_checkpoint=cp, checkpoint_store_ref="original-row-material-store-01")


def execute(loader, state, runtime):
    class Dispatch(_Adapter):
        def dispatch(self, plan):
            self.calls.append("dispatch")
            try:
                result = runtime.execute_once(now_epoch=1000)
            except Exception:
                raise M4AdapterAmbiguous("Synthetic owner-file material unavailable") from None
            if result is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED:
                raise M4AdapterAmbiguous("Synthetic owner-file material unresolved")
    return M4ExecutionKernel(Dispatch(), _Verifier(), state).execute(
        loader._plan, loader._authorization, now_epoch=1000)


def original_claim(store, runtime):
    return store.claim(request_digest=boundary._original_row_request_digest(runtime._provider._context),
        authorization_digest=runtime._provider._context.permission.authorization.authorization_digest)


def assert_reopened_no_dispatch(loader, state, runtime, verification):
    reopened = PersistentM4ExecutionStateStore(state._path, state._key_path,
        monotonic_checkpoint=state._monotonic_checkpoint, checkpoint_store_ref=state._checkpoint_store_ref)
    assert execute(loader, reopened, runtime).verification is verification


@pytest.mark.parametrize("index", [0, 1])
def test_real_checkpoint_claim_precedes_decode_and_fixed_postcondition_allows_created_state(tmp_path, monkeypatch, index, capfd):
    loader, session, state, values, _, _, reader, _, reference = configured(tmp_path, monkeypatch, index=index)
    material = material_store(tmp_path)
    def created(_context, _deadline):
        assert original_claim(material, runtime).state is MaterialUseClaimState.IN_PROGRESS
        # Creation changes pre-state; completion must verify the fixed post-state.
        reader.drift = True
    transport = SyntheticTransport(values[index], created)
    bridge = _OriginalRowSecretCreateAdapter(loader, context(loader), transport)
    runtime = boundary._OriginalRowMaterialRuntime(bridge, material)
    frames = []
    decode = PinnedBulkImportFile.decode
    def observed(self, **options):
        assert material.claim_count == 1 and original_claim(material, runtime).state is MaterialUseClaimState.IN_PROGRESS
        frame = decode(self, **options)
        frames.append(frame._ProtectedBulkImportRows__raw)
        return frame
    monkeypatch.setattr(PinnedBulkImportFile, "decode", observed)
    try:
        with reference:
            assert execute(loader, state, runtime).verification is M4Verification.VERIFIED
            assert_reopened_no_dispatch(loader, state, runtime, M4Verification.VERIFIED)
        claimed = original_claim(material, runtime)
        assert claimed.state is MaterialUseClaimState.REPLAY and claimed.outcome is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
        assert len(frames) == transport.calls == material.claim_count == 1
        assert all(not any(frame) for frame in frames)
        assert_cleared(transport)
        p = runtime._provider
        assert isinstance(p._lease, MaterialLease) and p._terminal and p._verified
        assert not p._owned._watchdog.is_alive()
        for obj in (p, p._binding, p._lease, runtime):
            for serialize in (copy.copy, copy.deepcopy, pickle.dumps):
                with pytest.raises(RuntimeError):
                    serialize(obj)
        for finish in (lambda: p.release_lease(p._lease),
                       lambda: p.revoke_lease(p._lease, reason=MaterialRevocationReason.CANCELLED)):
            with pytest.raises(MaterialAccessDenied):
                finish()
        assert capfd.readouterr() == ("", "")
    finally:
        session.close()


@pytest.mark.parametrize("fault", ["parser", "native-exception", "native-unknown", "cancelled", "expired",
                                  "revoked", "wrong-postcondition", "finalize-failed", "interrupt"])
def test_failed_or_uncertain_use_revokes_clears_and_keeps_original_claim_closed(tmp_path, monkeypatch, fault):
    loader, session, state, values, root, handle, reader, _, reference = configured(tmp_path, monkeypatch)
    material = material_store(tmp_path)
    def during(_context, deadline):
        if fault == "native-exception":
            raise ValueError("Synthetic native use failed")
        if fault == "cancelled":
            session.close()
        if fault == "expired":
            time.sleep(max(0, deadline - time.monotonic()) + 0.03)
        if fault == "revoked":
            root.revoke(handle, now_epoch=1000)
        if fault == "wrong-postcondition":
            reader.post_drift = True
        if fault == "interrupt":
            raise KeyboardInterrupt
    transport = SyntheticTransport(values[0], during,
        SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED if fault == "native-unknown" else SecretCreateAdapterOutcome.VERIFIED_CREATED)
    bridge = _OriginalRowSecretCreateAdapter(loader,
        context(loader, expires_at=1001 if fault == "expired" else 1060), transport)
    runtime = boundary._OriginalRowMaterialRuntime(bridge, material)
    def fail_finalize(**_values):
        raise ValueError("Synthetic finalization unknown")
    if fault == "finalize-failed":
        monkeypatch.setattr(material, "finalize", fail_finalize)
    if fault == "parser":
        def parser_failed(self, **options):
            assert original_claim(material, runtime).state is MaterialUseClaimState.IN_PROGRESS
            raise ValueError("Synthetic parser failure after reservation")
        monkeypatch.setattr(PinnedBulkImportFile, "decode", parser_failed)
    try:
        with reference:
            if fault == "interrupt":
                with pytest.raises(KeyboardInterrupt):
                    execute(loader, state, runtime)
            else:
                assert execute(loader, state, runtime).verification is M4Verification.UNKNOWN
            assert_reopened_no_dispatch(loader, state, runtime, M4Verification.UNKNOWN)
        assert transport.calls == (0 if fault == "parser" else 1)
        assert_cleared(transport)
        assert runtime._provider._terminal
        claim = original_claim(material, runtime)
        if fault in {"finalize-failed", "interrupt"}:
            assert claim.state is MaterialUseClaimState.IN_PROGRESS
        else:
            assert claim.state is MaterialUseClaimState.REPLAY and claim.outcome is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
        material_reopened = _store(tmp_path, monotonic_checkpoint=material._monotonic_checkpoint,
                                  checkpoint_store_ref=material._checkpoint_store_ref)
        assert original_claim(material_reopened, runtime) == claim
    finally:
        session.close()


@pytest.mark.parametrize("fault", ["claim-refused", "checkpoint-unknown", "checkpoint-refused"])
def test_material_claim_refusal_or_checkpoint_uncertainty_never_decodes(tmp_path, monkeypatch, fault):
    loader, session, state, values, _, _, _, _, reference = configured(tmp_path, monkeypatch)
    material = material_store(tmp_path)
    transport = SyntheticTransport(values[0])
    runtime = boundary._OriginalRowMaterialRuntime(_OriginalRowSecretCreateAdapter(loader, context(loader), transport), material)
    monkeypatch.setattr(PinnedBulkImportFile, "decode", lambda *_a, **_k: pytest.fail("Unproved material claim read"))
    if fault == "claim-refused":
        def refused(**_values):
            raise ValueError("Synthetic claim refused")
        monkeypatch.setattr(material, "claim", refused)
    else:
        original = material._monotonic_checkpoint.advance
        def lost(*args, **kwargs):
            if fault == "checkpoint-unknown":
                original(*args, **kwargs)
            raise MaterialUseMonotonicCheckpointError("Synthetic checkpoint completion unknown")
        monkeypatch.setattr(material._monotonic_checkpoint, "advance", lost)
    try:
        with reference:
            assert execute(loader, state, runtime).verification is M4Verification.UNKNOWN
            assert_reopened_no_dispatch(loader, state, runtime, M4Verification.UNKNOWN)
        assert transport.calls == 0 and not loader._used
        if fault == "checkpoint-unknown":
            reopened = _store(tmp_path, monotonic_checkpoint=material._monotonic_checkpoint,
                              checkpoint_store_ref=material._checkpoint_store_ref)
            assert original_claim(reopened, runtime).state is MaterialUseClaimState.IN_PROGRESS
        elif fault == "checkpoint-refused":
            with pytest.raises(RuntimeError):
                _store(tmp_path, monotonic_checkpoint=material._monotonic_checkpoint,
                       checkpoint_store_ref=material._checkpoint_store_ref)
    finally:
        session.close()


def test_candidate_does_not_relax_normal_request_classes_and_rejects_missing_checkpoint(tmp_path, monkeypatch):
    loader, session, _, values, _, _, _, _, _ = configured(tmp_path, monkeypatch)
    bridge = _OriginalRowSecretCreateAdapter(loader, context(loader), SyntheticTransport(values[0]))
    try:
        with pytest.raises(MaterialAccessDenied):
            boundary._OriginalRowMaterialRuntime(bridge, _store(tmp_path))
        p = boundary._OriginalRowMaterialProvider(bridge)
        assert p.validate_binding(C3MaterialBinding(), p._context) is MaterialBindingStatus.INCOMPATIBLE
        altered = replace(p._context, permission=replace(p._context.permission, audience_digest="8" * 64))
        assert p.validate_binding(p._binding, altered) is MaterialBindingStatus.INCOMPATIBLE
        assert not isinstance(p._context, MaterialLeaseRequest)
        from test_v4_material_runtime import _request
        # The separate RADIUS-only fixture type cannot admit bulk-import rows.
        with pytest.raises(ValueError):
            replace(_request(), provider_class=MaterialProviderClass.OWNED_LAB_FIXTURE_REFERENCE)
        with pytest.raises(RuntimeError):
            PackagedDenyAllSecretCreateMaterialRuntime().execute_once(p._binding, _request(), now_epoch=1000)
        assert not loader._used
    finally:
        session.close()


@pytest.mark.parametrize("saved", [None, MaterialRuntimeOutcome.VERIFIED_AND_RELEASED,
                                   MaterialRuntimeOutcome.RECONCILIATION_REQUIRED])
def test_original_material_record_stops_acquisition_even_in_a_new_dispatch_scope(tmp_path, monkeypatch, saved):
    loader, session, state, values, _, _, _, _, reference = configured(tmp_path, monkeypatch)
    material = material_store(tmp_path)
    transport = SyntheticTransport(values[0])
    runtime = boundary._OriginalRowMaterialRuntime(_OriginalRowSecretCreateAdapter(loader, context(loader), transport), material)
    request_digest = boundary._original_row_request_digest(runtime._provider._context)
    authorization_digest = loader._authorization.authorization_digest
    material.claim(request_digest=request_digest, authorization_digest=authorization_digest)
    if saved is not None:
        material.finalize(request_digest=request_digest, authorization_digest=authorization_digest, outcome=saved)
    monkeypatch.setattr(PinnedBulkImportFile, "decode", lambda *_a, **_k: pytest.fail("Replayed material read"))
    try:
        with reference:
            result = execute(loader, state, runtime)
        expected = M4Verification.VERIFIED if saved is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED else M4Verification.UNKNOWN
        assert result.verification is expected
        assert transport.calls == 0 and not loader._used and runtime._provider._lease is None
    finally:
        session.close()


def test_equal_bytes_and_another_opaque_handle_cannot_substitute_for_issued_row(tmp_path, monkeypatch):
    loader, session, state, values, _, _, _, _, reference = configured(tmp_path, monkeypatch)
    material = material_store(tmp_path)
    def during(_context, _deadline):
        p = runtime._provider
        fake_handle = boundary._OriginalRowMaterialLease()
        with pytest.raises(MaterialAccessDenied):
            p.release_lease(fake_handle)
        with pytest.raises(MaterialAccessDenied):
            p._consume_for_original_row(fake_handle)
        from fortipam_mcp.secret_bulk_import_row_loader import _OwnedOriginalImportRow
        impostor = _OwnedOriginalImportRow(p._owned._row,
            tuple(bytearray(part) for part in p._owned._buffers), p._owned._lifetime)
        try:
            with pytest.raises(BulkImportIntakeError):
                p._bridge._dispatch_owned_once(impostor)
        finally:
            impostor.close()
    transport = SyntheticTransport(values[0], during)
    runtime = boundary._OriginalRowMaterialRuntime(_OriginalRowSecretCreateAdapter(loader, context(loader), transport), material)
    try:
        with reference:
            assert execute(loader, state, runtime).verification is M4Verification.VERIFIED
        assert transport.calls == 1
        assert_cleared(transport)
    finally:
        session.close()
