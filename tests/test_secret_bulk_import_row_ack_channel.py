"""Signed original-response retention and exact terminal joins, synthetic HTTP."""

import hashlib
import hmac
import json

import pytest

from fortipam_mcp import secret_bulk_import_row_channel as channel_module
from fortipam_mcp import secret_bulk_import_row_http_transport as http_module
from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
from fortipam_mcp.secret_bulk_import_row_adapter import _OriginalRowSecretCreateAdapter, _OriginalRowUseContext
from fortipam_mcp.secret_bulk_import_row_conversion import _Build29OriginalRowConversion
from fortipam_mcp.secret_bulk_import_row_provider import _OriginalRowMaterialRuntime
from fortipam_mcp.secret_bulk_import_row_wire import _Build29OriginalRowWireEncoder
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.web_secret_create_ack import WebSecretCreateAckCapture
from test_m4_execution_store import _Adapter, _Verifier
from test_secret_bulk_import_row_channel import channel, remote
from test_secret_bulk_import_row_http_transport import Exchange, assert_cleanup
from test_secret_bulk_import_row_wire import SERIAL, project
from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, M4Verification, canonical_digest
from v4_planning.material_persistence import PersistentMaterialUseStateStore, PersistentMaterialUseStateStoreError
from v4_planning.material_runtime import MaterialRuntimeOutcome, MaterialUseClaimState
from v4_planning.persistence import PersistentProtectedPlanningStore, PersistentPlanningStoreError


def prepare(tmp_path, monkeypatch, *, fault=None, file_parent=False, graph=None):
    defaults = project()
    capture = WebSecretCreateAckCapture(SERIAL, 'success')
    graph = {} if graph is None else graph
    values = snapshot = None
    if file_parent:
        from dataclasses import replace
        from fortipam_mcp.secret_bulk_import_dependencies import ImportTemplate, ImportTemplateField
        from test_secret_bulk_import_dependencies import catalog, item
        snapshot = replace(catalog(), templates=(ImportTemplate('Text', (ImportTemplateField('Text', 'text', True),)),))
        values = [item(Name=name, **{'Secret Template': 'Text', 'URL': '', 'Username': '',
            'Password/Passphrase': '', 'Text': 'synthetic private text', 'Service Type': '', 'Port': '',
            'Association-Secret': '' if index == 0 else 'First'}) for index, name in enumerate(('First', 'Second'))]
    parts = channel(tmp_path, monkeypatch, material=True, capture=graph,
        ack_capture=capture, ack_defaults_digest=defaults.digest(),
        file_parent=file_parent, values=values, snapshot=snapshot)
    local, session, state, _, _, _, owner, client, reference, api, _, _, _ = parts
    with reference, api:
        loader = remote(local, session, client)
        context = _OriginalRowUseContext(loader._row, client._binding.permission, 1000, 1060)
        class Pending:
            def _create_and_verify_with_original_row(self, *_a, **_k):
                pytest.fail('Unbound native transport')
        bridge = _OriginalRowSecretCreateAdapter(loader, context, Pending())
        converter = _Build29OriginalRowConversion(bridge, graph['catalog'], graph['projected'],
            target_name=None if file_parent else 'Synthetic resolved target', associated_secret_id=None)
        encoder = _Build29OriginalRowWireEncoder(converter, defaults,
            expected_defaults_digest=defaults.digest(), expected_serial_digest=SERIAL)
        class Tls:
            def set_alpn_protocols(self, protocols): self.protocols = protocols
        monkeypatch.setattr(http_module, '_ssl_context', lambda _: Tls())
        exchange = Exchange(bridge, fault=fault)
        # Exchange observes the synthetic product state on Owner's prebound reader.
        original_factory = exchange.factory
        def factory(*args, **kwargs):
            connection = original_factory(*args, **kwargs)
            request = connection.request
            def observed(method, path, body, headers):
                loader._authority._reader = owner._permission._reader
                request(method, path, body, headers)
            connection.request = observed
            return connection
        native = http_module._Build29OriginalRowHttpTransport(
            SecretMetadataHttpTransportConfig('https://synthetic.example.test', 'synthetic-token', 10, None),
            encoder, capture, connection_factory=factory)
        bridge._transport = native
        runtime = _OriginalRowMaterialRuntime(bridge,
            channel_module._OriginalRowMaterialStateClient(client, context, session))
    return parts, loader, bridge, native, runtime, exchange


def run(local, state, owner, runtime, *, arm=True):
    class Dispatch(_Adapter):
        def read_current(self, plan):
            return local._issuer._reader.read_current(plan) if hasattr(local, '_issuer') else super().read_current(plan)
        def read_postcondition(self, plan):
            return local._issuer._reader.read_postcondition(plan) if hasattr(local, '_issuer') else super().read_postcondition(plan)
        def dispatch(self, plan):
            self.calls.append('dispatch')
            if arm: owner.arm_original_dispatch()
            try:
                outcome = runtime.execute_once(now_epoch=1000)
            except Exception:
                raise M4AdapterAmbiguous('Synthetic original remote use unavailable') from None
            if outcome is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED:
                raise M4AdapterAmbiguous('Synthetic original remote use unresolved')
            # Material is already released; M4 is still IN_PROGRESS here.
            with pytest.raises(BulkImportIntakeError): owner._inspect_verified_ack()
    adapter = Dispatch()
    result = M4ExecutionKernel(adapter, getattr(local, '_issuer', _Verifier()), state).execute(
        local._plan, local._authorization, now_epoch=1000)
    return result, adapter


@pytest.mark.parametrize('fault', [None, 'lost-retention', 'wrong-signature', 'wrong-receipt', 'postcondition',
    'post-authority', 'ack-close', 'lost-release', 'checkpoint', 'lost-ack', 'wrong-ack-device', 'unarmed',
    'wrong-record-defaults', 'boolean-record-id', 'wrong-record-source', 'extra-record-key'])
def test_original_ack_remote_custody_and_both_terminals_determine_verified_evidence(tmp_path, monkeypatch, fault, capfd):
    parts, loader, bridge, native, runtime, exchange = prepare(tmp_path, monkeypatch, fault=fault)
    local, session, state, _, _, _, owner, client, reference, api, uds, settings, observed = parts
    sent = []
    original_post = channel_module.UnixOriginalRowChannelClient._post
    def post(self, purpose, raw):
        payload = json.loads(raw)['payload']
        assert set(payload) == ({'contract', 'context', 'nonce', 'issued_at', 'claim_digest', 'ack'}
            if purpose == 'retain-ack' else {'contract', 'context', 'nonce', 'issued_at', 'claim_digest'})
        sent.append(purpose)
        if purpose == 'retain-ack' and fault in {'wrong-record-defaults', 'boolean-record-id', 'wrong-record-source', 'extra-record-key'}:
            envelope = json.loads(raw)
            field, value = {'wrong-record-defaults': ('defaults_digest', 'f' * 64),
                'boolean-record-id': ('native_secret_id', True),
                'wrong-record-source': ('ack_source_digest', 'f' * 64),
                'extra-record-key': ('unselected', 'synthetic') }[fault]
            envelope['payload']['ack'][field] = value
            envelope['seal'] = hmac.new(b'q' * 32, channel_module._REQUEST_DOMAIN + purpose.encode() + b'\0'
                + channel_module._canonical(envelope['payload']), hashlib.sha256).hexdigest()
            raw = bytearray(json.dumps(envelope).encode())
        result = original_post(self, purpose, raw)
        if (fault == 'lost-retention' and purpose == 'retain-ack'
                or fault == 'lost-release' and purpose == 'material-release'):
            raise ValueError('Synthetic signed response lost')
        if fault in {'wrong-signature', 'wrong-receipt'} and purpose == 'retain-ack':
            envelope = json.loads(result)
            if fault == 'wrong-signature': envelope['seal'] = '0' * 128
            else:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                envelope['payload']['record']['retained_digest'] = 'f' * 64
                envelope['seal'] = Ed25519PrivateKey.from_private_bytes(b'z' * 32).sign(
                    channel_module._RESPONSE_DOMAIN + channel_module._canonical(envelope['payload'])).hex()
            return bytearray(json.dumps(envelope).encode())
        return result
    monkeypatch.setattr(channel_module.UnixOriginalRowChannelClient, '_post', post)
    if fault == 'checkpoint': owner._parent._monotonic_checkpoint.fail_next_advance = True
    try:
        with reference, api:
            result, _ = run(local, state, owner, runtime, arm=fault != 'unarmed')
            expected = M4Verification.VERIFIED if fault is None else M4Verification.UNKNOWN
            assert result.verification is expected
            again, adapter = run(local, state, owner, runtime)
            assert again.verification is expected and 'dispatch' not in adapter.calls
            if fault is None:
                record = owner._inspect_verified_ack()
                assert record.native_secret_id == 71
                assert native._ack_retained_digest == canonical_digest(record.as_dict())
            else:
                with pytest.raises((BulkImportIntakeError, PersistentPlanningStoreError)):
                    owner._inspect_verified_ack()
            saved = fault not in {'lost-ack', 'wrong-ack-device', 'unarmed', 'checkpoint',
                'wrong-record-defaults', 'boolean-record-id', 'wrong-record-source', 'extra-record-key'}
            if saved:
                parent = owner._record()
                reopened = PersistentProtectedPlanningStore(owner._parent._path, owner._parent._key_path,
                    monotonic_checkpoint=owner._parent._monotonic_checkpoint,
                    checkpoint_store_ref=owner._parent._checkpoint_store_ref)
                assert reopened._get_original_import_row_ack(local._plan.plan_ref,
                    idempotency_digest=local._plan.idempotency_digest, requester_digest=local._plan.requester_digest,
                    parent_binding_digest=canonical_digest(parent.as_dict()),
                    parameters_digest=local._plan.parameters_digest).native_secret_id == 71
                root_reopened = channel_module.OriginalRowChannelOwner(owner._binding, reopened,
                    state, owner._permission, material_store=owner._material_store,
                    ack_pins=owner._ack_pins, clock=owner._clock)
                if fault is None:
                    assert root_reopened._inspect_verified_ack().native_secret_id == 71
                else:
                    with pytest.raises(BulkImportIntakeError): root_reopened._inspect_verified_ack()
            assert native._ack_record is None
            assert sum(method == 'POST' for method, _ in exchange.requests) == (0 if fault == 'unarmed' else 1)
            assert sent.count('retain-ack') == (0 if fault in {'lost-ack', 'wrong-ack-device', 'unarmed'} else 1)
            if bridge._owned is not None:
                assert_cleanup(bridge, exchange)
            else:
                assert not exchange.requests and not native._post_attempted
            for obj in (loader, client, runtime._state):
                assert not any(hasattr(obj, name) for name in ('_parent', '_execution', '_signer', '_key', '_path'))
            with pytest.raises(BulkImportIntakeError): client._retain_ack_from_transport(native)
            with pytest.raises(BulkImportIntakeError): client._call('retain-ack', ack={})
            if fault in {'lost-retention', 'wrong-signature', 'wrong-receipt', 'lost-release'}:
                assert session._transaction._closed.is_set()
            if fault == 'lost-release':
                claimed = owner._material_store._inspect_claim(request_digest=runtime._state._request,
                    authorization_digest=local._authorization.authorization_digest)
                assert claimed.outcome is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
        wire = json.dumps(observed)
        for forbidden in (str(session._transaction._binding.path), session._transaction._binding.file_sha256,
                          'Original first row', 'Synthetic forbidden native HTTP reply', 'Password/Passphrase'):
            assert forbidden not in wire
        assert capfd.readouterr() == ('', '')
    finally:
        session.close()
        uds.close()


def test_file_parent_association_requires_original_ack_and_both_verified_terminals(tmp_path, monkeypatch):
    from fortipam_mcp.secret_bulk_import_row_authority import PinnedOriginalRowAcquisitionAuthority, REFERENCE_KIND
    from test_secret_bulk_import_row_authority import DependencyReader
    graph = {}
    parts, loader, bridge, native, runtime, exchange = prepare(tmp_path, monkeypatch, file_parent=True, graph=graph)
    local, session, state, _, root, _, owner, _, reference, api, uds, _, _ = parts
    try:
        second = graph['make_loader'](1)
        checker = owner._permission._checker
        permission = PinnedOriginalRowAcquisitionAuthority(owner._binding.source, second._plan, second._authorization,
            policy_decision_digest=second._issuer._issued.policy_decision_digest, scope_digest=owner._binding.source.scope_digest,
            audience_digest=second._issuer._issued.audience_digest, authority=checker._authority, authority_ref=checker._authority_ref,
            reference='owner-file-second-row-reference', scope_key_path=checker._key.path,
            scope_key_sha256=checker._key.digest, projection_reader=DependencyReader(second._plan), clock=lambda: 1000)
        grant = root.issue(permission._checker._reference, reference_kind=REFERENCE_KIND,
            requester_digest=second._plan.requester_digest, environment_ref=permission._checker._environment,
            scope_ref=permission._checker._scope, expires_at=1060, now_epoch=1000)
        binding = channel_module.OriginalRowChannelBinding(owner._binding.source, second._plan,
            second._authorization, second._parent_digest, second._rows._key.digest, permission._pins)
        dependent = channel_module.OriginalRowChannelOwner(binding, local._parent, state, permission,
            dependency_owners=(owner,), clock=lambda: 1000)
        without_proof = channel_module.OriginalRowChannelOwner(binding, local._parent, state, permission, clock=lambda: 1000)
        with reference, api:
            with pytest.raises(BulkImportIntakeError):
                dependent.prepare_original_dispatch()
            assert state.claim_count == 0
            owner.prepare_original_dispatch()
            result, _ = run(local, state, owner, runtime)
            assert result.verification is M4Verification.VERIFIED
            assert owner._inspect_verified_ack().native_secret_id == 71
            # Success status alone is insufficient; the exact ACK and released
            # material proof are read through the original dependency Owner.
            with pytest.raises(BulkImportIntakeError):
                without_proof.prepare_original_dispatch()
            before = state._monotonic_checkpoint.tail
            dependent.prepare_original_dispatch()
            assert state.claim_count == 1 and state._monotonic_checkpoint.tail == before
            root.revoke(grant, now_epoch=1000)
            with pytest.raises(BulkImportIntakeError):
                dependent.prepare_original_dispatch()
            assert state.claim_count == 1
            assert sum(method == 'POST' for method, _ in exchange.requests) == 1
            assert_cleanup(bridge, exchange)
    finally:
        session.close()
        uds.close()


def test_material_inspection_has_no_claim_side_effect_and_checks_original_authorization(tmp_path):
    from test_secret_bulk_import_row_provider import material_store
    store = material_store(tmp_path)
    before = store._path.read_bytes()
    with pytest.raises(PersistentMaterialUseStateStoreError):
        store._inspect_claim(request_digest='1' * 64, authorization_digest='2' * 64)
    assert store._path.read_bytes() == before and store.claim_count == 0
    assert store.claim(request_digest='1' * 64, authorization_digest='2' * 64).state is MaterialUseClaimState.NEW
    with pytest.raises(PersistentMaterialUseStateStoreError):
        store._inspect_claim(request_digest='1' * 64, authorization_digest='3' * 64)
    assert store._inspect_claim(request_digest='1' * 64, authorization_digest='2' * 64).state is MaterialUseClaimState.IN_PROGRESS
    store.finalize(request_digest='1' * 64, authorization_digest='2' * 64,
        outcome=MaterialRuntimeOutcome.VERIFIED_AND_RELEASED)
    reopened = PersistentMaterialUseStateStore(store._path, store._key_path,
        monotonic_checkpoint=store._monotonic_checkpoint, checkpoint_store_ref=store._checkpoint_store_ref)
    assert reopened._inspect_claim(request_digest='1' * 64,
        authorization_digest='2' * 64).outcome is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
    assert reopened.claim_count == 1
