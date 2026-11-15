"""Original wire and ACK-bound C2 comparisons; synthetic product only."""

from dataclasses import replace
import json
import threading
import time

import pytest

from fortipam_mcp import secret_bulk_import_row_wire as wire
from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
from fortipam_mcp.secret_bulk_import_row_provider import _OriginalRowMaterialRuntime
from test_secret_bulk_import_row_conversion import fixture
from test_secret_bulk_import_row_provider import execute, material_store
from test_secret_bulk_import_row_wire import SERIAL, project
from v4_planning import M4Verification
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome

MATERIAL = 'Synthetic forbidden readback material'


def detail(body):
    row = {key: value for key, value in body.items() if key in wire._READBACK_FIELDS}
    row.update(id=71, q_origin_key=71, field=[{'value': MATERIAL}], description=MATERIAL,
        **{'totp-setting': {'status': 'enable', 'shared-key': MATERIAL},
           'unselected-extension': {MATERIAL: [MATERIAL]}})
    return dict(version='v7.0.0', build=29, path='secret', name='database', http_method='GET',
        status='OK', http_status=200, vdom='root', serial='Synthetic wire-default device', results=row)


@pytest.mark.parametrize('targetless', [False, True])
@pytest.mark.parametrize('native_twins', [False, True])
@pytest.mark.parametrize('native_omissions', [False, True])
def test_fixed_readback_matches_original_wire_skips_material_and_cannot_survive_handoff(tmp_path, monkeypatch, targetless, native_twins, native_omissions):
    loader, session, state, reference, bridge, converter, _, _ = fixture(tmp_path, monkeypatch, targetless=targetless)
    defaults = project()
    encoder = wire._Build29OriginalRowWireEncoder(converter, defaults,
        expected_defaults_digest=defaults.digest(), expected_serial_digest=SERIAL)
    original_loads = json.loads
    def guarded(raw, *args, **kwargs):
        assert MATERIAL not in (raw.decode() if type(raw) in {bytes, bytearray} else str(raw))
        return original_loads(raw, *args, **kwargs)
    monkeypatch.setattr(wire.m.json, 'loads', guarded)
    class Transport:
        calls = 0
        body = response = None
        def _create_and_verify_with_original_row(self, context, columns, *, deadline):
            self.calls += 1
            with encoder._serialize_once(context, columns, deadline=deadline) as view:
                self.body = view.obj
                payload = detail(original_loads(bytes(view)))
                if native_omissions:
                    for key, fallback in wire._DETAIL_SCALAR_DEFAULTS.items():
                        if payload['results'][key] == fallback:
                            del payload['results'][key]
                self.response = bytearray(json.dumps(payload).encode())
                if native_twins:
                    self.response[:] = self.response.replace(b'"block-clipboard": "disable"',
                        b'"block-clipboard":"disable","block-clipboard":"disable"')
                assert encoder._inspect_detail_once(context, self.response, expected_secret_id=71, deadline=deadline)
                assert not any(self.response)
                retry = bytearray(json.dumps(payload).encode())
                with pytest.raises(BulkImportIntakeError):
                    encoder._inspect_detail_once(context, retry, expected_secret_id=71, deadline=deadline)
                assert not any(retry)
            return SecretCreateAdapterOutcome.VERIFIED_CREATED
    transport = Transport(); bridge._transport = transport
    runtime = _OriginalRowMaterialRuntime(bridge, material_store(tmp_path))
    try:
        with reference:
            assert execute(loader, state, runtime).verification is M4Verification.VERIFIED
            assert execute(loader, state, runtime).verification is M4Verification.VERIFIED
        assert transport.calls == 1 and not any(transport.body)
        assert encoder._active_metadata is encoder._active_deadline is encoder._active_thread is None
        stale = bytearray(b'{}')
        with pytest.raises(BulkImportIntakeError):
            encoder._inspect_detail_once(bridge._context, stale, expected_secret_id=71, deadline=time.monotonic()+1)
        assert not any(stale)
        assert len(wire._READBACK_FIELDS) == 99
        assert {'field', 'description', 'totp-setting'}.isdisjoint(wire._READBACK_FIELDS)
    finally:
        session.close()


@pytest.mark.parametrize('fault', [None, 'c2-drift', 'ack-id', 'actor-after', 'ca',
    'expired', 'rollback', 'namespace-key', 'wrong-plan', 'closed', 'read-close', 'm4-unknown'])
def test_original_ack_native_postread_joins_pending_material_and_final_m4(
        tmp_path, monkeypatch, capfd, fault):
    # Local imports preserve detail() as the existing native Exchange fixture API.
    from dataclasses import asdict
    import hashlib
    import ssl
    from fortipam_mcp import dlp_api_actor_guard as actor_module
    from fortipam_mcp import secret_bulk_import_row_channel as channel_module
    from fortipam_mcp import secret_bulk_import_row_http_transport as http_module
    from fortipam_mcp import secret_bulk_import_row_readback as boundary
    from fortipam_mcp.secret_bulk_import_dependencies import ImportTemplate, ImportTemplateField
    from fortipam_mcp.secret_bulk_import_row_adapter import _OriginalRowSecretCreateAdapter, _OriginalRowUseContext
    from fortipam_mcp.secret_bulk_import_row_conversion import _Build29OriginalRowConversion
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from fortipam_mcp.web_secret_create_ack import WebSecretCreateAckCapture
    from test_dlp_api_actor_guard import Harness, _ACTOR, _envelope, _role
    from test_secret_bulk_import_dependencies import catalog, item
    from test_secret_bulk_import_row_channel import channel, remote
    from test_secret_bulk_import_row_http_transport import Exchange, Response, assert_cleanup
    from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, canonical_digest
    from v4_planning.execution_kernel import M4ClaimState, M4Outcome
    from v4_planning.material_runtime import MaterialRuntimeOutcome, MaterialUseClaimState

    role = _role()
    role['secretgrp-permission']['secret-table'] = 'read-write'
    actor = Harness(role)
    serial = hashlib.sha256(actor.binding.expected_serial.encode()).hexdigest()
    defaults = replace(project(), serial_digest=serial)
    capture = WebSecretCreateAckCapture(serial, 'success')
    snapshot = replace(catalog(), templates=(ImportTemplate('Text', (ImportTemplateField('Text', 'text', True),)),))
    values = [item(Name='Readback', **{'Secret Template': 'Text', 'URL': '', 'Username': '',
        'Password/Passphrase': '', 'Text': 'Synthetic private row text', 'Service Type': '',
        'Port': '', 'Association-Secret': ''})]
    graph = {}
    parts = channel(tmp_path, monkeypatch, material=True, capture=graph, file_parent=True,
        values=values, snapshot=snapshot, ack_capture=capture, ack_defaults_digest=defaults.digest())
    local, session, state, _, _, _, owner, client, reference, api, uds, _, _ = parts
    trust = ssl.create_default_context()
    ca = tmp_path / 'postread-public-ca.pem'
    ca.write_bytes(b'Synthetic public CA snapshot')
    config = SecretMetadataHttpTransportConfig(actor.config.base_url, actor.config.bearer_token, 5, str(ca))
    monkeypatch.setattr(actor_module, '_ssl_context', lambda _: trust)
    monkeypatch.setattr(http_module, '_ssl_context', lambda _: trust)
    original_loads = json.loads
    clock, built, postreads, read_connections, read_responses, phases = [time.monotonic()], [], [], [], [], []
    original_current = owner._permission._reader

    class Projection:
        def read_current(self, plan):
            return original_current.read_current(plan)

        def read_postcondition(self, plan):
            if fault == 'namespace-key':
                path = local._rows._key.path
                original = path.read_bytes()
                try:
                    path.write_bytes(b'Changed synthetic namespace key')
                    return built[0].read_postcondition(plan)
                finally:
                    path.write_bytes(original)
            return built[0].read_postcondition(plan)

    owner._permission._reader = Projection()

    def read_factory(host, port, **options):
        assert (host, port) == ('pam.example.test', 9443)
        assert options['context'] is trust and 0 < options['timeout'] <= 5

        class Connection:
            closed = False
            response = inner = None

            def request(self, method, path, body=None, headers=None):
                assert method == 'GET' and body is None
                assert headers['Authorization'] == 'Bearer synthetic-token'
                postreads.append(path)
                if path.startswith('/api/v2/cmdb/secret/database/'):
                    assert path == '/api/v2/cmdb/secret/database/71?vdom=root'
                    ack, original, material = owner._inspect_ack_claims()
                    assert ack.native_secret_id == 71 and original.state is M4ClaimState.IN_PROGRESS
                    phases.append(material.state)
                    payload = detail(exchange.post_json)
                    payload['serial'] = actor.binding.expected_serial
                    if fault == 'c2-drift':
                        payload['results']['folder'] += 1
                    elif fault == 'ack-id':
                        payload['results'].update(id=72, q_origin_key=72)
                    self.response = Response(payload)
                    if fault == 'read-close':
                        self.response.failure = 'close'
                    read_responses.append(self.response)
                else:
                    if fault == 'actor-after' and len(actor.calls) == 3:
                        actor.bodies[_ACTOR] = _envelope('state', {'admin': {'name': 'different',
                            'login_name': 'different', 'guest_admin': False, 'sponsored_group_name': ''}}, monitor=True)
                    self.inner = actor.connect(host, port, **{**options, 'timeout': 5})
                    self.inner.request(method, path, headers=headers)
                    self.response = self.inner.getresponse()

            def getresponse(self):
                return self.response

            def close(self):
                self.closed = True
                if self.inner is not None:
                    self.inner.close()

        result = Connection()
        read_connections.append(result)
        return result

    try:
        with reference, api:
            loader = remote(local, session, client)
            context = _OriginalRowUseContext(loader._row, client._binding.permission, 1000, 1060)
            class Pending:
                def _create_and_verify_with_original_row(self, *_a, **_k):
                    pytest.fail('Synthetic native transport was not composed')
            bridge = _OriginalRowSecretCreateAdapter(loader, context, Pending())
            converter = _Build29OriginalRowConversion(bridge, snapshot, graph['projected'],
                target_name=None, associated_secret_id=None)
            encoder = wire._Build29OriginalRowWireEncoder(converter, defaults,
                expected_defaults_digest=defaults.digest(), expected_serial_digest=serial)
            exchange = Exchange(bridge)
            class ExchangeTls:
                protocols = ['http/1.1']
            def writer_factory(host, port, **options):
                assert (host, port) == ('pam.example.test', 9443) and options['context'] is trust
                result = exchange.factory('synthetic.example.test', 443,
                    timeout=options['timeout'], context=ExchangeTls())
                send = result.request
                def request(method, path, body, headers):
                    loader._authority._reader = original_current
                    send(method, path, body, headers)
                    payload = original_loads(result.response.payload)
                    payload['serial'] = actor.binding.expected_serial
                    result.response.payload[:] = json.dumps(payload).encode()
                    result.response.headers['Content-Length'] = str(len(result.response.payload))
                result.request = request
                return result
            native = http_module._Build29OriginalRowHttpTransport(config, encoder, capture,
                connection_factory=writer_factory)
            bridge._transport = native
            runtime = _OriginalRowMaterialRuntime(bridge,
                channel_module._OriginalRowMaterialStateClient(client, context, session))
            def selected_only(raw, *args, **options):
                assert MATERIAL not in str(raw)
                return original_loads(raw, *args, **options)
            monkeypatch.setattr(wire.m.json, 'loads', selected_only)

            class Adapter:
                calls = 0
                def read_current(self, plan):
                    return local._issuer._reader.read_current(plan)
                def read_postcondition(self, plan):
                    return built[0].read_postcondition(plan)
                def dispatch(self, plan):
                    self.calls += 1
                    reader = boundary._OriginalRowNativeReadback(owner, snapshot, graph['projected'],
                        defaults, config, actor.binding, namespace_key_path=local._rows._key.path,
                        index=0, target_name=None, associated_secret_id=None,
                        connection_factory=read_factory, clock=lambda: clock[0])
                    built.append(reader)
                    assert not postreads and not exchange.requests
                    owner.arm_original_dispatch()
                    if fault == 'ca':
                        ca.write_bytes(b'Changed synthetic public CA')
                    elif fault == 'expired':
                        clock[0] += 61
                    elif fault == 'rollback':
                        clock[0] -= 1
                    elif fault == 'wrong-plan':
                        fields = asdict(plan)
                        fields.pop('plan_digest')
                        fields['expected_state_digest'] = 'a' * 64
                        with pytest.raises(BulkImportIntakeError):
                            reader.read_postcondition(replace(plan, expected_state_digest='a' * 64,
                                plan_digest=canonical_digest(fields)))
                    elif fault == 'closed':
                        reader.close()
                    try:
                        outcome = runtime.execute_once(now_epoch=1000)
                    except Exception:
                        raise M4AdapterAmbiguous('Synthetic original row unavailable') from None
                    if outcome is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED:
                        raise M4AdapterAmbiguous('Synthetic original row unresolved')
                    if fault == 'm4-unknown':
                        raise M4AdapterAmbiguous('Synthetic M4 final result unknown')

            adapter = Adapter()
            kernel = M4ExecutionKernel(adapter, local._issuer, state, clock=lambda: 1000)
            owner.prepare_original_dispatch()
            result = kernel.execute(local._plan, local._authorization, now_epoch=1000)
            assert result.verification is (M4Verification.VERIFIED if fault is None else M4Verification.UNKNOWN)
            assert built and adapter.calls == 1
            if fault is None:
                assert result.outcome is M4Outcome.SUCCEEDED
                assert MaterialUseClaimState.IN_PROGRESS in phases and MaterialUseClaimState.REPLAY in phases
                assert len(postreads) % 7 == 0
                assert owner._inspect_verified_ack().native_secret_id == 71
            elif fault == 'm4-unknown':
                with pytest.raises(BulkImportIntakeError):
                    owner._inspect_verified_ack()
            before = tuple(postreads), tuple(exchange.requests)
            with pytest.raises(BulkImportIntakeError):
                built[0].read_postcondition(local._plan)
            replay = kernel.execute(local._plan, local._authorization, now_epoch=1000)
            assert replay.idempotent_replay and replay.verification is result.verification
            assert before == (tuple(postreads), tuple(exchange.requests)) and adapter.calls == 1
            assert sum(method == 'POST' for method, _ in exchange.requests) == 1
            if bridge._owned is not None:
                assert_cleanup(bridge, exchange)
            actor.disposed()
            assert all(connection.closed for connection in read_connections)
            assert all(response.closed for response in read_responses)
            assert all(not any(buffer) for response in read_responses for buffer in response.buffers)
            built[0].close()
            assert capfd.readouterr() == ('', '')
    finally:
        session.close()
        uds.close()


@pytest.mark.parametrize('fault', ['device', 'version', 'build', 'method', 'status', 'error', 'action',
    'id', 'origin', 'name', 'folder', 'template', 'target', 'association', 'service', 'port',
    'approval', 'inheritance', 'ztna', 'acl', 'missing', 'duplicate', 'partial', 'invalid-json',
    'wrong-context', 'thread', 'expired', 'cancelled', 'invalid-id', 'clipboard-conflict',
    'clipboard-third', 'clipboard-escaped', 'duplicate-control', 'missing-explicit-port',
    'missing-itself-launch'])
def test_readback_rejects_drift_without_replay_or_material_decode(tmp_path, monkeypatch, fault, capfd):
    loader, session, state, reference, bridge, converter, _, _ = fixture(tmp_path, monkeypatch)
    defaults = project()
    encoder = wire._Build29OriginalRowWireEncoder(converter, defaults,
        expected_defaults_digest=defaults.digest(), expected_serial_digest=SERIAL)
    class Transport:
        calls = 0
        body = response = None
        def _create_and_verify_with_original_row(self, context, columns, *, deadline):
            self.calls += 1
            with encoder._serialize_once(context, columns, deadline=deadline) as view:
                self.body = view.obj
                payload = detail(json.loads(bytes(view)))
                row = payload['results']
                changes = {'device': ('serial','Other device'), 'version': ('version','v7.0.1'),
                    'build': ('build',True), 'method': ('http_method','POST'), 'status': ('status','success'),
                    'error': ('error',False), 'action': ('action','default')}
                row_changes = {'id': ('id',True), 'origin': ('q_origin_key',72), 'name': ('name','Different'),
                    'folder': ('folder',111), 'template': ('template','Different'), 'target': ('target','Different'),
                    'association': ('associated-secret',91), 'service': ('ssh-service-status','down'),
                    'port': ('ssh-service-port',2222), 'approval': ('need-approval','enable'),
                    'inheritance': ('inherit-permission','disable'), 'ztna': ('inherit-folder-ztna','disable'),
                    'acl': ('user-permission',[{'name':'Different owner'}])}
                if fault in changes:
                    key,value = changes[fault]; payload[key] = value
                elif fault in row_changes:
                    key,value = row_changes[fault]; row[key] = value
                elif fault == 'missing': del row['recording']
                elif fault == 'missing-explicit-port': del row['ssh-service-port']
                elif fault == 'missing-itself-launch': del row['launch-with']
                elif fault == 'partial': payload['results'] = []
                elif fault == 'wrong-context': context = replace(context, requested_at=context.requested_at+1)
                elif fault == 'expired': deadline = time.monotonic()-1
                elif fault == 'cancelled': session.close()
                self.response = bytearray(json.dumps(payload).encode())
                if fault == 'duplicate':
                    self.response[:] = self.response.replace(b'"id": 71', b'"id":71,"\\u0069d":71')
                elif fault == 'invalid-json':
                    self.response[:] = self.response.replace(MATERIAL.encode(), b'\xff', 1)
                elif fault in ('clipboard-conflict', 'clipboard-third', 'clipboard-escaped', 'duplicate-control'):
                    replacements = {
                        'clipboard-conflict': b'"block-clipboard":"disable","block-clipboard":"enable"',
                        'clipboard-third': b'"block-clipboard":"disable","block-clipboard":"disable","block-clipboard":"disable"',
                        'clipboard-escaped': b'"block-clipboard":"disable","\\u0062lock-clipboard":"disable"',
                        'duplicate-control': b'"block-clipboard":"disable","recording":"disable"',
                    }
                    self.response[:] = self.response.replace(b'"block-clipboard": "disable"', replacements[fault])
                original_loads = json.loads
                def guarded(raw, *args, **kwargs):
                    assert MATERIAL not in (raw.decode() if type(raw) in {bytes, bytearray} else str(raw))
                    return original_loads(raw, *args, **kwargs)
                monkeypatch.setattr(wire.m.json,'loads',guarded)
                def inspect():
                    return encoder._inspect_detail_once(context, self.response,
                        expected_secret_id=True if fault == 'invalid-id' else 71, deadline=deadline)
                if fault == 'thread':
                    outcomes = []
                    def run():
                        try: inspect()
                        except BulkImportIntakeError: outcomes.append('denied')
                    worker = threading.Thread(target=run); worker.start(); worker.join(timeout=2)
                    assert not worker.is_alive() and outcomes == ['denied']
                    raise BulkImportIntakeError('Synthetic foreign-thread readback refused')
                inspect()
            return SecretCreateAdapterOutcome.VERIFIED_CREATED
    transport = Transport(); bridge._transport = transport
    runtime = _OriginalRowMaterialRuntime(bridge, material_store(tmp_path))
    try:
        with reference:
            assert execute(loader, state, runtime).verification is M4Verification.UNKNOWN
            assert execute(loader, state, runtime).verification is M4Verification.UNKNOWN
        assert transport.calls == 1 and not any(transport.body) and not any(transport.response)
        assert all(not any(buffer) for buffer in bridge._owned._buffers)
        assert encoder._active_metadata is None
        assert capfd.readouterr() == ('','')
    finally:
        session.close()
