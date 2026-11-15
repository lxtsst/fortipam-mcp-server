"""Original two-row Owner composition; native readers and stores, synthetic product."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest
from starlette.testclient import TestClient

from fortipam_mcp import secret_bulk_import_row_dispatch as dispatch
from fortipam_mcp.secret_bulk_import_file import PinnedBulkImportFile
from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
from fortipam_mcp.secret_bulk_import_intake_execution import _read_original_text_row
from fortipam_mcp.secret_bulk_import_row_action_worker import _compile_original_channel_action_pins, _receive, _send
from fortipam_mcp.secret_bulk_import_row_authority import _original_material_request_digest
from fortipam_mcp.secret_bulk_import_row_channel import UnixOriginalRowChannelClient, _original_ack_record
from fortipam_mcp.secret_bulk_import_row_wire import _READBACK_ARRAYS, _project_build29_secret_wire_defaults
from fortipam_mcp.secret_bulk_import_submission import create_owner_file_submission_app
from fortipam_mcp.secret_bulk_import_text_batch_owner import _OriginalTextBatchOwner
from fortipam_mcp.web_secret_create_ack import WebSecretCreateAcknowledgement, WebSecretCreateAckCapture, _ack_digest
from test_dlp_api_actor_guard import ACTOR, SERIAL
from test_m4_execution_store import _ExternalM4Checkpoint, _store, CHECKPOINT_STORE_REF
from test_secret_bulk_import_file import csv_bytes, row
from test_secret_bulk_import_parent_handoff import configured
from test_secret_bulk_import_reference_eligibility import REFERENCE
from test_secret_bulk_import_row_current import NativeSources
from test_secret_bulk_import_row_http_transport import Response
from test_secret_bulk_import_row_provider import material_store
from test_secret_bulk_import_row_readback import detail
from test_secret_bulk_import_row_wire import defaults_response
from test_secret_bulk_import_submission import frame, send
from v4_planning.execution_kernel import _ACTIVE_DISPATCH, _reserve_m4_product_startup
from v4_planning.material_runtime import MaterialRuntimeOutcome
from v4_planning.persistence import PersistentPlanningStoreError


def write(path, value):
    path.write_bytes(value)
    path.chmod(0o600)
    return hashlib.sha256(value).hexdigest()


@pytest.mark.parametrize('scenario', ['success', 'second-unknown', 'file-grant'])
def test_original_text_owner_keeps_preview_grants_and_terminal_evidence_separate(tmp_path, monkeypatch, capfd, scenario):
    native = NativeSources(tmp_path, monkeypatch, template_name='Synthetic Note', field_name='Contents')
    original_connection = native.connection
    pins_by_id, details, connections = {}, [], []

    def connection(host, port, **options):
        class Connection:
            closed = False
            inner = response = None

            def request(self, method, path, body=None, headers=None):
                assert method == 'GET' and body is None
                if path.startswith('/api/v2/cmdb/secret/database/'):
                    native_id = int(path.split('/')[-1].split('?')[0])
                    metadata = dict(pins_by_id[native_id].metadata)
                    metadata.update({name: [] for name in _READBACK_ARRAYS})
                    payload = detail(metadata); payload['serial'] = SERIAL
                    payload['results'].update(id=native_id, q_origin_key=native_id)
                    self.response = Response(payload)
                    details.append(native_id)
                else:
                    self.inner = original_connection(host, port, **options)
                    self.inner.request(method, path, headers=headers)

            def getresponse(self):
                return self.response if self.response is not None else self.inner.getresponse()

            def close(self):
                self.closed = True
                if self.inner is not None:
                    self.inner.close()

        result = Connection(); connections.append(result)
        return result

    native.connection = connection
    profile = native.profile()
    values = [row(**{'Secret Template': native.template_name, 'Name': name, 'Folder': 'Text folder', 'Username': '',
        'Password/Passphrase': '', 'URL': '', 'Port': '', 'Text': 'SYNTHETIC_TEXT'}) for name in ('First', 'Second')]
    snapshot = profile.prepare_catalog(expected_file_digest=hashlib.sha256(csv_bytes(values)).hexdigest(),
        scope_digest='1' * 64)
    fixture = configured(tmp_path, monkeypatch, values=values, snapshot=snapshot, file_parent=True, text_source=profile)
    receiver, sender = fixture['receiver'], fixture['sender']
    app = create_owner_file_submission_app(fixture['owner_binding'], **fixture['options'], parent_handoff=sender)
    execution = _store(tmp_path, monotonic_checkpoint=_ExternalM4Checkpoint(), checkpoint_store_ref=CHECKPOINT_STORE_REF)
    material = material_store(tmp_path)
    payload = defaults_response(); payload['serial'] = SERIAL
    defaults = _project_build29_secret_wire_defaults(bytearray(json.dumps(payload).encode()),
        serial_digest=hashlib.sha256(SERIAL.encode()).hexdigest())
    capture = WebSecretCreateAckCapture(defaults.serial_digest, 'success')
    env, source = tmp_path / 'product.env', tmp_path / 'product.json'
    write(env, ('SYNTHETIC_TOKEN=' + native.config.bearer_token + '\nSYNTHETIC_USERNAME=' + ACTOR + '\n').encode())
    product_digest = write(source, json.dumps(dict(contract='fortipam-original-row-product-source-v1',
        base_url=native.config.base_url, connect_ip='127.0.0.1', env_file=str(env),
        api_token_variable='SYNTHETIC_TOKEN', username_variable='SYNTHETIC_USERNAME', expected_username=ACTOR,
        ca_file=native.config.ca_file, actor=asdict(native.actor.binding))).encode())
    control, intake = socket.socketpair()
    events = []

    with tempfile.TemporaryDirectory(prefix='fp-text-batch-', dir='/private/tmp') as directory:
        root = Path(directory)
        request, signing, public = root / 'request.key', root / 'signing.key', root / 'public.key'
        request_digest, signing_digest = write(request, b'q' * 32), write(signing, b'z' * 32)
        public_digest = write(public, Ed25519PrivateKey.from_private_bytes(b'z' * 32).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        channel_path = root / 'row.sock'
        with fixture['reference_transport'], ThreadPoolExecutor(max_workers=1) as pool, TestClient(app) as client:
            future = pool.submit(receiver.receive_once)
            assert send(client, frame(fixture)).status_code == 200
            original, projected, graph = future.result(timeout=5)
            checker = receiver._authority._human_owner_verifier
            references = {0: 'original-text-row-reference-0',
                1: REFERENCE if scenario == 'file-grant' else 'original-text-row-reference-1'}
            owner = _OriginalTextBatchOwner(original, receiver, projected, graph, execution, material, defaults, capture,
                control_peer=control.dup(), authenticated_requester_digest=receiver._requester,
                authority_key=b'j' * 32, transport_digest='9' * 64,
                reference_authority=checker._authority, authority_ref=checker._authority_ref,
                reference_by_index=references, scope_key_path=checker._key.path, scope_key_sha256=checker._key.digest,
                socket_path=channel_path, request_key_path=request, request_key_sha256=request_digest,
                signing_key_path=signing, signing_key_sha256=signing_digest,
                product_source_path=source, product_source_digest=product_digest, execution_enabled=True,
                clock=lambda: fixture['clocks'][0], monotonic=lambda: native.now)
            bootstrap = owner._reference_bootstrap()
            assert all(issuer._issued is None for issuer in owner._issuers) and execution.claim_count == 0
            assert not channel_path.exists() and not owner._channels
            for index, request_grant in enumerate(bootstrap):
                if scenario == 'file-grant' and index == 1:
                    continue
                # Explicit fixture-only external bootstrap; the production Owner never issues grants.
                grant = dict(request_grant)
                reference = grant.pop('references')[0]
                fixture['root_authority'].issue(reference.pop('reference'), **reference, **grant,
                    now_epoch=fixture['clocks'][0])

            def launch(row_owner, catalog, metadata, wire_defaults, **options):
                current = row_owner._permission._reader
                assert current._post is not None and row_owner._scope is None
                index = current._row.index
                pins = _compile_original_channel_action_pins(row_owner, catalog, metadata, wire_defaults,
                    **{key: value for key, value in options.items() if key not in {'source_path', 'source_digest'}})
                _reserve_m4_product_startup(row_owner._binding.plan, row_owner._binding.authorization, execution)
                pins_by_id[71 + index] = pins
                events.append(('launch', index))

                class SyntheticProduct:
                    client = SimpleNamespace(_pins=pins)

                    def _transfer_client_once(self, peer):
                        assert row_owner._scope is _ACTIVE_DISPATCH.get() and row_owner._scope.active
                        raw = _receive(intake, pins.deadline, 16384)
                        try:
                            assert _read_original_text_row(raw, row_owner._binding.source, index,
                                row_owner._binding.namespace_key_digest) == row_owner._binding
                            assert b'SYNTHETIC_TEXT' not in raw
                        finally:
                            raw[:] = b'\0' * len(raw)
                            peer.close()
                        channel = UnixOriginalRowChannelClient(row_owner._binding, socket_path=channel_path,
                            request_key_path=request, request_key_sha256=request_digest,
                            public_key_path=public, public_key_sha256=public_digest, clock=lambda: fixture['clocks'][0])
                        assert channel._call('resolve')['record']['plan_ref'] == receiver._plan_ref
                        binding, ack = row_owner._binding, row_owner._ack_pins
                        request_digest_ = _original_material_request_digest(binding.permission,
                            binding.material_requested_at, binding.material_expires_at)
                        material.claim(request_digest=request_digest_,
                            authorization_digest=binding.authorization.authorization_digest)
                        native_ack = WebSecretCreateAcknowledgement(71 + index, capture.serial_digest,
                            _ack_digest(71 + index, capture))
                        row_owner._parent._put_original_import_row_ack(
                            _original_ack_record(binding, ack, row_owner._record(), native_ack))
                        material.finalize(request_digest=request_digest_,
                            authorization_digest=binding.authorization.authorization_digest,
                            outcome=MaterialRuntimeOutcome.VERIFIED_AND_RELEASED)
                        native.names.append(dict(pins.metadata)['name'])
                        prefix = b'?' if scenario == 'second-unknown' and index == 1 else b'V'
                        _send(intake, pins.deadline, prefix + binding.context_digest().encode('ascii'))
                        events.append(('transfer', index))

                    def close(self):
                        assert row_owner._scope is _ACTIVE_DISPATCH.get() and row_owner._scope.active
                        events.append(('close', index))

                return SyntheticProduct()

            monkeypatch.setattr(dispatch, '_launch_original_channel_action_process', launch)
            monkeypatch.setattr(PinnedBulkImportFile, 'decode', lambda *_a, **_k: pytest.fail('Owner decoded protected input'))
            principal = dict(requester_digest=receiver._requester, transport_digest='9' * 64)
            try:
                if scenario == 'file-grant':
                    with pytest.raises(BulkImportIntakeError):
                        owner.preview(**principal)
                    assert not events and execution.claim_count == 0
                else:
                    preview = owner.preview(**principal)
                    assert preview['rows'] == 2 and preview['targets'] == 0
                    assert preview['proposed'] == dict(secret_creates=2, template_profile='single_text_field')
                    assert native.template_name not in json.dumps(preview) and native.field_name not in json.dumps(preview)
                    assert all(issuer._issued is None for issuer in owner._issuers)
                    assert owner._record.plan_digest not in json.dumps(preview)
                    with pytest.raises(BulkImportIntakeError):
                        owner.authorize(preview['preview_ref'], **{**principal, 'transport_digest': '8' * 64})
                    authorization = owner.authorize(preview['preview_ref'], **principal)
                    assert all(issuer._issued == pins for _, issuer, pins, _ in owner._rows)
                    assert execution.claim_count == 0 and not events and not channel_path.exists()
                    result = owner.execute_once(authorization['authorization_ref'], **principal)
                    assert result == dict(status='succeeded' if scenario == 'success' else 'reconciliation_required',
                        verified_lines=2 if scenario == 'success' else 1, total_lines=2, completed=scenario == 'success'), (
                            events, details, execution.claim_count,
                            [(current._failed, current._post is not None) for current in owner._currents])
                    assert details == ([71, 72] if scenario == 'success' else [71])
                    assert events == [(event, index) for index in range(2) for event in ('launch', 'transfer', 'close')]
                    with pytest.raises(BulkImportIntakeError):
                        owner.execute_once(authorization['authorization_ref'], **principal)
                if scenario == 'success':
                    assert fixture['store'].get_import_parent(receiver._plan_ref) == owner._record
                else:
                    with pytest.raises(PersistentPlanningStoreError):
                        fixture['store'].get_import_parent(receiver._plan_ref)
                assert owner._closed and profile._closed and owner._control.fileno() == -1
                assert all(current._closed for current in owner._currents)
                assert all(issuer._issued is None for issuer in owner._issuers)
                assert all(channel._thread is None or not channel._thread.is_alive() for channel in owner._channels)
                assert not channel_path.exists() and control.fileno() >= 0 and intake.fileno() >= 0
                assert all(connection.closed for connection in connections)
                native.disposed()
            finally:
                owner.close()
                control.close()
                intake.close()
    assert capfd.readouterr() == ('', '')
