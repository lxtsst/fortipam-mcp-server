"""Fixed signed remote material state, synthetic product and private source."""

import json

import pytest

from fortipam_mcp import secret_bulk_import_row_channel as boundary
from fortipam_mcp.secret_bulk_import_file import PinnedBulkImportFile
from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
from fortipam_mcp.secret_bulk_import_row_adapter import _OriginalRowSecretCreateAdapter, _OriginalRowUseContext
from fortipam_mcp.secret_bulk_import_row_provider import _OriginalRowMaterialRuntime, _original_row_request_digest
from test_m4_execution_store import _Adapter, _Verifier
from test_secret_bulk_import_row_adapter import SyntheticTransport, assert_cleared
from test_secret_bulk_import_row_channel import channel, remote
from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, M4Verification
from v4_planning.material_runtime import MaterialRuntimeOutcome, MaterialUseClaimState
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome


def original_claim(owner, context):
    return owner._material_store.claim(request_digest=_original_row_request_digest(context),
        authorization_digest=context.permission.authorization.authorization_digest)


@pytest.mark.parametrize("fault", [None, "native-unknown", "revoked", "parent-invalidated", "wrong-post",
    "lost-material-claim", "lost-row-claim", "lost-release", "lost-revoke", "ledger-drift", "wrong-signature", "wrong-claim-signature"])
def test_signed_owner_side_material_state_keeps_keys_outside_intake_and_unknowns_nonrepeatable(tmp_path, monkeypatch, fault):
    local, session, state, values, root, handle, owner, client, reference, transport, uds, _, observed = channel(
        tmp_path, monkeypatch, material=True)
    decoded, sent = [], []
    native_decode = PinnedBulkImportFile.decode
    original_post = boundary.UnixOriginalRowChannelClient._post
    target = {"lost-material-claim": "material-claim", "lost-row-claim": "claim",
              "lost-release": "material-release", "lost-revoke": "material-revoke"}.get(fault)
    def posted(self, purpose, raw):
        payload = json.loads(raw)["payload"]
        assert set(payload) == {"contract", "context", "nonce", "issued_at", "claim_digest"}
        sent.append(purpose)
        result = original_post(self, purpose, raw)
        if purpose == target:
            raise ValueError("Synthetic acknowledged response lost")
        if (fault == "wrong-signature" and purpose == "material-ready"
                or fault == "wrong-claim-signature" and purpose == "material-claim"):
            envelope = json.loads(result)
            envelope["seal"] = "0" * 128
            return bytearray(json.dumps(envelope).encode())
        return result
    monkeypatch.setattr(boundary.UnixOriginalRowChannelClient, "_post", posted)
    def decode(self, **options):
        assert owner._material_store.claim_count == 1
        assert original_claim(owner, context).state is MaterialUseClaimState.IN_PROGRESS
        decoded.append(True)
        return native_decode(self, **options)
    monkeypatch.setattr(PinnedBulkImportFile, "decode", decode)
    def during(_context, _deadline):
        if fault == "revoked":
            root.revoke(handle, now_epoch=1000)
        elif fault == "parent-invalidated":
            local._parent.invalidate_plan(local._plan.plan_ref, evaluated_at=1000, reason_codes=("synthetic-owner-change",))
        elif fault == "wrong-post":
            owner._permission._reader.post_drift = True
        elif fault is None:
            owner._permission._reader.drift = True
    native = SyntheticTransport(values[0], during,
        SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED if fault in {"native-unknown", "lost-revoke"}
        else SecretCreateAdapterOutcome.VERIFIED_CREATED)
    try:
        with reference, transport:
            loader = remote(local, session, client)
            context = _OriginalRowUseContext(loader._row, client._binding.permission, 1000, 1060)
            remote_state = boundary._OriginalRowMaterialStateClient(client, context, session)
            runtime = _OriginalRowMaterialRuntime(_OriginalRowSecretCreateAdapter(loader, context, native), remote_state)
            for obj in (client, remote_state, runtime):
                for name in ("_key", "_key_path", "_path", "_parent", "_execution", "_signer"):
                    assert not hasattr(obj, name)
            if fault == "ledger-drift":
                owner._material_store._key_path.chmod(0o644)
            class Dispatch(_Adapter):
                def dispatch(self, plan):
                    self.calls.append("dispatch")
                    owner.arm_original_dispatch()
                    try:
                        result = runtime.execute_once(now_epoch=1000)
                    except Exception:
                        raise M4AdapterAmbiguous("Synthetic remote material unavailable") from None
                    if result is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED:
                        raise M4AdapterAmbiguous("Synthetic remote material uncertain")
            first = Dispatch()
            result = M4ExecutionKernel(first, _Verifier(), state).execute(local._plan, local._authorization, now_epoch=1000)
            expected = M4Verification.VERIFIED if fault is None else M4Verification.UNKNOWN
            assert result.verification is expected
            second = Dispatch()
            assert M4ExecutionKernel(second, _Verifier(), state).execute(
                local._plan, local._authorization, now_epoch=1000).verification is expected
            assert "dispatch" not in second.calls
            assert len(decoded) == native.calls == (0 if fault in {"lost-material-claim", "lost-row-claim", "ledger-drift", "wrong-signature", "wrong-claim-signature"} else 1)
            assert_cleared(native)
            if fault == "ledger-drift":
                owner._material_store._key_path.chmod(0o600)
            elif fault == "wrong-signature":
                assert owner._material_nonce is None and owner._material_store.claim_count == 0
            else:
                claim = original_claim(owner, context)
                if fault in {"lost-material-claim", "wrong-claim-signature"}:
                    assert claim.state is MaterialUseClaimState.IN_PROGRESS and client._material_digest is None
                else:
                    saved = MaterialRuntimeOutcome.VERIFIED_AND_RELEASED if fault in {None, "lost-release"} else MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
                    assert claim.state is MaterialUseClaimState.REPLAY and claim.outcome is saved
                assert sent.count("material-claim") == 1
                assert sent.count("material-release") + sent.count("material-revoke") <= 1
            if fault in {"lost-material-claim", "lost-row-claim", "lost-release", "lost-revoke", "wrong-claim-signature"}:
                assert session._transaction._closed.is_set() and not any(session._password)
            with pytest.raises(BulkImportIntakeError):
                remote_state.claim(request_digest=_original_row_request_digest(context),
                    authorization_digest=context.permission.authorization.authorization_digest)
        wire = json.dumps(observed)
        assert str(session._transaction._binding.path) not in wire
        assert session._transaction._binding.file_sha256 not in wire
        assert "Password/Passphrase" not in wire and "Original first row" not in wire
    finally:
        session.close()
        uds.close()


def test_material_ack_proof_rejects_another_client_and_row_cannot_skip_material_claim(tmp_path, monkeypatch):
    local, session, state, _, _, _, owner, client, reference, transport, uds, settings, _ = channel(tmp_path, monkeypatch, material=True)
    monkeypatch.setattr(PinnedBulkImportFile, "decode", lambda *_a, **_k: pytest.fail("Unauthorized material decode"))
    try:
        with reference, transport:
            loader = remote(local, session, client)
            context = _OriginalRowUseContext(loader._row, client._binding.permission, 1000, 1060)
            remote_state = boundary._OriginalRowMaterialStateClient(client, context, session)
            class Dispatch(_Adapter):
                def dispatch(self, plan):
                    owner.arm_original_dispatch()
                    # Raw row claim alone must never bypass material reservation.
                    with pytest.raises(BulkImportIntakeError):
                        client._call("claim")
                    claim = remote_state.claim(request_digest=_original_row_request_digest(context),
                        authorization_digest=context.permission.authorization.authorization_digest)
                    assert claim.state is MaterialUseClaimState.NEW
                    clone = boundary.UnixOriginalRowChannelClient(client._binding, **settings)
                    for purpose in ("material-claim", "claim", "verify", "material-revoke"):
                        with pytest.raises(BulkImportIntakeError):
                            clone._call(purpose)
                    remote_state.finalize(request_digest=_original_row_request_digest(context),
                        authorization_digest=context.permission.authorization.authorization_digest,
                        outcome=MaterialRuntimeOutcome.RECONCILIATION_REQUIRED)
            M4ExecutionKernel(Dispatch(), _Verifier(), state).execute(local._plan, local._authorization, now_epoch=1000)
        assert not loader._used and owner._load_nonce is None
        assert original_claim(owner, context).outcome is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
    finally:
        session.close()
        uds.close()


def test_client_cannot_select_another_request_or_finalize_unclaimed_use(tmp_path, monkeypatch):
    local, session, _, _, _, _, _, client, reference, transport, uds, _, _ = channel(tmp_path, monkeypatch, material=True)
    try:
        with reference, transport:
            loader = remote(local, session, client)
            context = _OriginalRowUseContext(loader._row, client._binding.permission, 1000, 1060)
            remote_state = boundary._OriginalRowMaterialStateClient(client, context, session)
            with pytest.raises(BulkImportIntakeError):
                remote_state.claim(request_digest="a" * 64, authorization_digest=context.permission.authorization.authorization_digest)
            with pytest.raises(BulkImportIntakeError):
                remote_state.finalize(request_digest=_original_row_request_digest(context),
                    authorization_digest=context.permission.authorization.authorization_digest,
                    outcome=MaterialRuntimeOutcome.VERIFIED_AND_RELEASED)
            assert not remote_state._claim_attempted and not loader._used
    finally:
        session.close()
        uds.close()
