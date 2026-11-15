"""Original DAG ordering with real M4/C3/ACK stores and synthetic product peers."""

from contextlib import ExitStack
from dataclasses import replace
import hashlib

import pytest
from starlette.testclient import TestClient

from fortipam_mcp import secret_bulk_import_batch as batch
from fortipam_mcp import secret_bulk_import_row_channel as channel_module
from fortipam_mcp import secret_bulk_import_row_http_transport as http_module
from fortipam_mcp.secret_bulk_import_dependencies import ImportTemplate, ImportTemplateField
from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
from fortipam_mcp.secret_bulk_import_row_action_worker import _compile_original_channel_action_pins
from fortipam_mcp.secret_bulk_import_row_adapter import _OriginalRowSecretCreateAdapter, _OriginalRowUseContext
from fortipam_mcp.secret_bulk_import_row_authority import PinnedOriginalRowAcquisitionAuthority, REFERENCE_KIND
from fortipam_mcp.secret_bulk_import_row_conversion import _Build29OriginalRowConversion
from fortipam_mcp.secret_bulk_import_row_provider import _OriginalRowMaterialRuntime
from fortipam_mcp.secret_bulk_import_row_wire import _Build29OriginalRowWireEncoder
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.web_secret_create_ack import WebSecretCreateAckCapture
from test_secret_bulk_import_dependencies import catalog, item
from test_secret_bulk_import_row_authority import DependencyReader
from test_secret_bulk_import_row_channel import channel
from test_secret_bulk_import_row_http_transport import Exchange, assert_cleanup
from test_secret_bulk_import_row_wire import project
from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel
from v4_planning.material_runtime import MaterialRuntimeOutcome
from v4_planning.persistence import PersistentPlanningStoreError


@pytest.mark.parametrize('fault', [None, 'lost-ack', 'm4-unknown', 'drift', 'expired', 'disabled', 'cancelled',
                                  'missing-row', 'wrong-order'])
def test_complete_original_batch_orders_dependencies_and_stops_without_replay(tmp_path, monkeypatch, fault):
    snapshot = replace(catalog(), templates=(ImportTemplate('Synthetic Credential', (
        ImportTemplateField('Username', 'username', True), ImportTemplateField('Password', 'password', True))),))
    values = [item(Name=name, URL='', **{'Secret Template': 'Synthetic Credential',
        'Association-Secret': 'Parent' if name == 'Child' else ''}) for name in ('Child', 'Parent', 'Last')]
    defaults = project()
    capture = WebSecretCreateAckCapture(defaults.serial_digest, 'success')
    graph = {}
    parts = channel(tmp_path, monkeypatch, material=True, file_parent=True, values=values,
        snapshot=snapshot, capture=graph, ack_capture=capture, ack_defaults_digest=defaults.digest())
    first, session, state, _, root, _, initial_owner, _, reference, initial_api, uds, settings, _ = parts
    checker = first._authority._checker
    clients, owners, units, exchanges, bridges, readers, order = {}, {}, [], {}, {}, {}, []
    epoch = [1000]
    def post(self, purpose, raw):
        response = clients[self._binding.context_digest()].post(channel_module._PREFIX + purpose,
            content=bytes(raw), headers={'Content-Type': 'application/json'})
        if response.status_code != 200:
            raise ValueError('Synthetic row channel refusal')
        return bytearray(response.content)
    monkeypatch.setattr(channel_module.UnixOriginalRowChannelClient, '_post', post)
    class Tls:
        def set_alpn_protocols(self, protocols): self.protocols = protocols
    monkeypatch.setattr(http_module, '_ssl_context', lambda _: Tls())

    def make_row(index, stack):
        local = first if index == 0 else graph['make_loader'](index)
        pins = local._issuer._issued
        reader = DependencyReader(local._plan)
        permission = PinnedOriginalRowAcquisitionAuthority(session._transaction._binding,
            local._plan, local._authorization, policy_decision_digest=pins.policy_decision_digest,
            scope_digest=pins.scope_digest, audience_digest=pins.audience_digest,
            authority=checker._authority, authority_ref=checker._authority_ref,
            reference=f'batch-row-permission-{index}', scope_key_path=checker._key.path,
            scope_key_sha256=checker._key.digest, projection_reader=reader, clock=lambda: 1000)
        selected = permission._checker
        root.issue(selected._reference, reference_kind=REFERENCE_KIND,
            requester_digest=local._plan.requester_digest, environment_ref=selected._environment,
            scope_ref=selected._scope, expires_at=1060, now_epoch=1000)
        ack = channel_module._OriginalRowAckPins(local._row, defaults.digest(), capture)
        binding = channel_module.OriginalRowChannelBinding(session._transaction._binding,
            local._plan, local._authorization, local._parent_digest, local._rows._key.digest, pins,
            material_requested_at=1000, material_expires_at=1060, ack_pins_digest=ack.digest())
        owner = channel_module.OriginalRowChannelOwner(binding, local._parent, state, permission,
            material_store=initial_owner._material_store, ack_pins=ack,
            dependency_owners=(owners[1],) if index == 0 else (), clock=lambda: 1000)
        app = channel_module.create_original_row_channel_app(owner,
            request_key_path=settings['request_key_path'], request_key_sha256=settings['request_key_sha256'],
            signing_key_path=settings['request_key_path'].with_name('signer.key'),
            signing_key_sha256=hashlib.sha256(b'z' * 32).hexdigest(), clock=lambda: 1000, monotonic=lambda: 100.0)
        clients[binding.context_digest()] = stack.enter_context(TestClient(app))
        client = channel_module.UnixOriginalRowChannelClient(binding, **settings)
        client._reader = reader
        loader = channel_module._RemoteOriginalImportRowLoader(session, client, index=index,
            key_path=local._rows._key.path, key_sha256=local._rows._key.digest)
        context = _OriginalRowUseContext(loader._row, pins, 1000, 1060)
        class Pending:
            def _create_and_verify_with_original_row(self, *_a, **_k):
                pytest.fail('Synthetic product transport was not composed')
        bridge = _OriginalRowSecretCreateAdapter(loader, context, Pending())
        associated = 72 if index == 0 else None
        converter = _Build29OriginalRowConversion(bridge, snapshot, graph['projected'],
            target_name=None, associated_secret_id=associated)
        encoder = _Build29OriginalRowWireEncoder(converter, defaults,
            expected_defaults_digest=defaults.digest(), expected_serial_digest=defaults.serial_digest)
        exchange = Exchange(bridge, native_id=71 + index,
            fault='lost-ack' if fault == 'lost-ack' and index == 1 else None)
        bridge._transport = http_module._Build29OriginalRowHttpTransport(
            SecretMetadataHttpTransportConfig('https://synthetic.example.test', 'synthetic-token', 10, None),
            encoder, capture, connection_factory=exchange.factory)
        runtime = _OriginalRowMaterialRuntime(bridge, channel_module._OriginalRowMaterialStateClient(client, context, session))
        class Adapter:
            def read_current(self, plan): return reader.read_current(plan)
            def read_postcondition(self, plan):
                if fault == 'm4-unknown' and index == 2:
                    raise M4AdapterAmbiguous('Synthetic final projection unavailable')
                return reader.read_postcondition(plan)
            def dispatch(self, plan):
                _compile_original_channel_action_pins(owner, snapshot, graph['projected'], defaults,
                    namespace_key_path=local._rows._key.path, index=index,
                    target_name=None, associated_secret_id=associated)
                owner.arm_original_dispatch()
                order.append(index)
                if fault == 'cancelled':
                    raise KeyboardInterrupt
                if runtime.execute_once(now_epoch=1000) is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED:
                    raise M4AdapterAmbiguous('Synthetic row result unknown')
        owners[index], exchanges[index], bridges[index], readers[index] = owner, exchange, bridge, reader
        return batch._OriginalImportRowExecution(owner,
            M4ExecutionKernel(Adapter(), local._issuer, state, clock=lambda: 1000))

    try:
        with reference, initial_api, ExitStack() as stack:
            units = tuple(make_row(index, stack) for index in (1, 2, 0))
            options = dict(expected_parent_digest=first._parent_digest, targets=(), rows=units,
                execution_enabled=fault != 'disabled', clock=lambda: epoch[0])
            def make(**changes):
                return batch._OriginalImportBatch(first._rows, session._transaction._binding,
                    graph['projected'], snapshot, first._parent, state, **{**options, **changes})
            if fault in ('missing-row', 'wrong-order'):
                with pytest.raises(BulkImportIntakeError):
                    make(rows=units[:2] if fault == 'missing-row' else tuple(reversed(units)))
                assert not order and state.claim_count == 0
                return
            driver = make()
            if fault == 'drift': readers[1].drift = True
            elif fault == 'expired': epoch[0] = 1060
            if fault == 'disabled':
                with pytest.raises(BulkImportIntakeError): driver.execute_once()
                assert not order and state.claim_count == 0
                return
            if fault == 'cancelled':
                with pytest.raises(KeyboardInterrupt): driver.execute_once()
                with pytest.raises(PersistentPlanningStoreError):
                    first._parent.get_import_parent(first._plan.plan_ref)
                with pytest.raises(BulkImportIntakeError): driver.execute_once()
                with pytest.raises(BulkImportIntakeError): make()
                assert order == [1] and state.claim_count == 1
                assert all(not exchange.requests for exchange in exchanges.values())
                return
            result = driver.execute_once()
            expected = [] if fault in ('drift', 'expired') else [1] if fault == 'lost-ack' else [1, 2] if fault else [1, 2, 0]
            assert order == expected and state.claim_count == len(expected)
            assert result.total_lines == 3 and result.completed is (fault is None)
            assert result.verified_lines == (3 if fault is None else 1 if fault == 'm4-unknown' else 0)
            if fault is None:
                assert exchanges[0].post_json['associated-secret'] == owners[1]._inspect_verified_ack().native_secret_id
                assert len({owner._inspect_verified_ack().native_secret_id for owner in owners.values()}) == 3
            else:
                with pytest.raises(PersistentPlanningStoreError):
                    first._parent.get_import_parent(first._plan.plan_ref)
            before = tuple(tuple(exchange.requests) for exchange in exchanges.values())
            with pytest.raises(BulkImportIntakeError): driver.execute_once()
            with pytest.raises(BulkImportIntakeError): make()
            assert before == tuple(tuple(exchange.requests) for exchange in exchanges.values())
            for index in expected:
                assert_cleanup(bridges[index], exchanges[index])
    finally:
        session.close()
        uds.close()
