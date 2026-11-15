"""Owner dispatch ordering and original terminal joins; synthetic intake only."""

from dataclasses import asdict, replace
import hashlib
import json
import socket
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from fortipam_mcp import secret_bulk_import_row_dispatch as boundary
from fortipam_mcp.reference_authority_sidecar import (
    UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings, create_reference_authority_sidecar_app,
)
from fortipam_mcp.secret_bulk_import_file import PinnedBulkImportFile
from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
from fortipam_mcp.secret_bulk_import_intake_execution import _read_original_text_row
from fortipam_mcp.secret_bulk_import_parent_graph import _build_file_import_parent
from fortipam_mcp.secret_bulk_import_row_action_worker import _compile_original_channel_action_pins, _receive, _send
from fortipam_mcp.secret_bulk_import_row_authority import (
    PinnedOriginalRowAcquisitionAuthority, _OriginalRowM4Authority, _original_material_request_digest, REFERENCE_KIND,
)
from fortipam_mcp.secret_bulk_import_row_channel import (
    OriginalRowChannelBinding, OriginalRowChannelOwner, _OriginalRowAckPins, _original_ack_record,
)
from fortipam_mcp.secret_bulk_import_row_current import _OriginalRowNativeCurrent
from fortipam_mcp.secret_bulk_import_row_namespace import _bind_original_import_metadata
from fortipam_mcp.secret_bulk_import_row_wire import _READBACK_ARRAYS, _project_build29_secret_wire_defaults
from fortipam_mcp.web_secret_create_ack import WebSecretCreateAcknowledgement, WebSecretCreateAckCapture, _ack_digest
from test_dlp_api_actor_guard import ACTOR, SERIAL
from test_m4_execution_store import _ExternalM4Checkpoint, _store, CHECKPOINT_STORE_REF
from test_secret_bulk_import_file import csv_bytes, decode, row
from test_secret_bulk_import_intake import prepared
from test_secret_bulk_import_reference_eligibility import AUTHORITY, REFERENCE, source as reference_source
from test_secret_bulk_import_row_current import NativeSources
from test_secret_bulk_import_row_http_transport import Response
from test_secret_bulk_import_row_provider import material_store
from test_secret_bulk_import_row_readback import detail
from test_secret_bulk_import_row_wire import defaults_response
from test_v4_persistence import _ExternalCheckpoint, _new_store, CHECKPOINT_STORE_REF as PARENT_STORE
from v4_planning import M4ExecutionKernel, M4Outcome, M4Verification
from v4_planning.execution_kernel import _ACTIVE_DISPATCH, _reserve_m4_product_startup
from v4_planning.material_runtime import MaterialRuntimeOutcome
from v4_planning.store import OriginalImportBindingRecord


def original_owner(tmp_path, monkeypatch, native):
    profile = native.profile()
    source, _, _ = prepared(tmp_path)
    raw = csv_bytes([row(**{'Secret Template': 'Text', 'Name': 'Original text', 'Folder': 'Text folder',
        'Username': '', 'Password/Passphrase': '', 'URL': '', 'Port': '', 'Text': 'SYNTHETIC_TEXT'})])
    source.path.write_bytes(raw)
    source = replace(source, file_sha256=hashlib.sha256(raw).hexdigest())
    qualified = profile.resolve_once(decode(tmp_path, raw), expected_file_digest=source.file_sha256,
        scope_digest=source.scope_digest)
    parent_store, _, _ = _new_store(tmp_path, monotonic_checkpoint=_ExternalCheckpoint(),
        checkpoint_store_ref=PARENT_STORE, now_epoch=1000)
    key = tmp_path / 'namespace.key'
    key.write_bytes(b'i' * 32); key.chmod(0o600)
    original = _bind_original_import_metadata(source, qualified.projected, qualified.catalog,
        original_plan_ref='file-import-owner-dispatch', authenticated_requester_digest='7' * 64,
        parent_idempotency_digest='8' * 64, key_path=key, key_sha256=hashlib.sha256(b'i' * 32).hexdigest())
    parent = _build_file_import_parent(original, source, qualified.projected, qualified.catalog,
        source_policy_digest='a' * 64, owner_decision_digest='b' * 64, created_at=1000, expires_at=1060,
        standing_lab_authorization=True)
    parent_store.put_file_import_parent(parent)
    parent_store.put_original_import_binding(OriginalImportBindingRecord(plan_digest=parent.plan_digest,
        namespace_key_digest=original._key.digest, **asdict(original._operation)))
    execution = _store(tmp_path, monotonic_checkpoint=_ExternalM4Checkpoint(), checkpoint_store_ref=CHECKPOINT_STORE_REF)
    payload = defaults_response(); payload['serial'] = SERIAL
    defaults = _project_build29_secret_wire_defaults(bytearray(json.dumps(payload).encode()),
        serial_digest=hashlib.sha256(SERIAL.encode()).hexdigest())
    current = _OriginalRowNativeCurrent(original, source, qualified.projected, qualified.catalog,
        parent_store, execution, profile, qualified, defaults, index=0, expected_parent_digest=parent.plan_digest,
        authenticated_requester_digest=parent.requester_digest, clock=lambda: native.now, wall_clock=lambda: 1000)
    issuer = _OriginalRowM4Authority(original, source, qualified.projected, qualified.catalog,
        parent_store, execution, current, index=0, expected_parent_digest=parent.plan_digest,
        authority_key=b'j' * 32, authenticated_requester_digest=parent.requester_digest,
        transport_digest='9' * 64, execution_enabled=True, clock=lambda: 1000)
    pins = issuer.issue()
    root, settings, grant, _ = reference_source(tmp_path, source, [1000, 100], requester=parent.requester_digest)
    reference = TestClient(create_reference_authority_sidecar_app(root))
    reference.app.state.authority = root
    authority = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(tmp_path / 'reference.sock', AUTHORITY))
    monkeypatch.setattr(UnixReferenceAuthorityClient, '_post',
        lambda self, path, payload: reference.post(path, json=payload))
    permission = PinnedOriginalRowAcquisitionAuthority(source, pins.plan, pins.authorization,
        policy_decision_digest=pins.policy_decision_digest, scope_digest=pins.scope_digest,
        audience_digest=pins.audience_digest, authority=authority, authority_ref=AUTHORITY, reference=REFERENCE,
        scope_key_path=settings['scope_key_path'], scope_key_sha256=settings['scope_key_sha256'],
        projection_reader=current, clock=lambda: 1000)
    grant.update(reference_kind=REFERENCE_KIND, scope_ref=permission._checker._scope)
    reference.app.state.grant_handle = root.issue(REFERENCE, **grant)
    ack = _OriginalRowAckPins(original.row(0), defaults.digest(), WebSecretCreateAckCapture(defaults.serial_digest, 'success'))
    binding = OriginalRowChannelBinding(source, pins.plan, pins.authorization, parent.plan_digest,
        original._key.digest, pins, material_requested_at=1000, material_expires_at=1060, ack_pins_digest=ack.digest())
    owner = OriginalRowChannelOwner(binding, parent_store, execution, permission,
        material_store=material_store(tmp_path), ack_pins=ack, clock=lambda: 1000)
    return owner, current, issuer, reference


@pytest.mark.parametrize('fault', [None, 'unknown', 'no-c3-terminal'])
def test_owner_dispatch_requires_original_completion_and_closes_inside_scope(tmp_path, monkeypatch, capfd, fault):
    native = NativeSources(tmp_path, monkeypatch)
    original_connection = native.connection
    held, details, connections, responses = {}, [], [], []

    def connection(host, port, **options):
        class Connection:
            closed = False
            inner = response = None

            def request(self, method, path, body=None, headers=None):
                assert method == 'GET' and body is None
                if path.startswith('/api/v2/cmdb/secret/database/'):
                    assert path == '/api/v2/cmdb/secret/database/71?vdom=root'
                    body = dict(held['pins'].metadata)
                    body.update({name: [] for name in _READBACK_ARRAYS})
                    payload = detail(body); payload['serial'] = SERIAL
                    self.response = Response(payload)
                    details.append(path); responses.append(self.response)
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
    owner, current, issuer, reference = original_owner(tmp_path, monkeypatch, native)
    source = tmp_path / 'product-source.json'
    env = tmp_path / 'product.env'
    env.write_text('SYNTHETIC_TOKEN=' + native.config.bearer_token + '\nSYNTHETIC_USERNAME=' + ACTOR + '\n')
    env.chmod(0o600)
    source.write_text(json.dumps({'contract': 'fortipam-original-row-product-source-v1',
        'base_url': native.config.base_url + '/', 'connect_ip': '127.0.0.1', 'env_file': str(env),
        'api_token_variable': 'SYNTHETIC_TOKEN', 'username_variable': 'SYNTHETIC_USERNAME',
        'expected_username': ACTOR, 'ca_file': native.config.ca_file, 'actor': asdict(native.actor.binding)}))
    source.chmod(0o600)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    control, intake = socket.socketpair()
    events = []

    def launch(owner_arg, catalog, projected, defaults, **options):
        assert owner_arg is owner and current._post is not None and owner._scope is None
        pins = _compile_original_channel_action_pins(owner, catalog, projected, defaults,
            **{key: value for key, value in options.items() if key not in {'source_path', 'source_digest'}})
        _reserve_m4_product_startup(owner._binding.plan, owner._binding.authorization, owner._execution)
        held['pins'] = pins
        events.append('launch')

        class Product:
            client = SimpleNamespace(_pins=pins)

            def _transfer_client_once(self, peer):
                assert owner._scope is _ACTIVE_DISPATCH.get() and owner._scope.material_reserved
                raw = _receive(intake, pins.deadline, 16384)
                try:
                    assert b'SYNTHETIC_TEXT' not in raw
                    assert _read_original_text_row(raw, owner._binding.source, 0,
                        owner._binding.namespace_key_digest) == owner._binding
                finally:
                    raw[:] = b'\0' * len(raw)
                    peer.close()
                events.append('transfer')
                binding, ack = owner._binding, owner._ack_pins
                request = _original_material_request_digest(binding.permission, 1000, 1060)
                store = owner._material_store
                store.claim(request_digest=request, authorization_digest=binding.authorization.authorization_digest)
                native_ack = WebSecretCreateAcknowledgement(71, ack.capture.serial_digest, _ack_digest(71, ack.capture))
                owner._parent._put_original_import_row_ack(_original_ack_record(binding, ack, owner._record(), native_ack))
                if fault != 'no-c3-terminal':
                    store.finalize(request_digest=request, authorization_digest=binding.authorization.authorization_digest,
                        outcome=MaterialRuntimeOutcome.VERIFIED_AND_RELEASED)
                _send(intake, pins.deadline, (b'?' if fault == 'unknown' else b'V') + binding.context_digest().encode('ascii'))

            def close(self):
                assert _ACTIVE_DISPATCH.get() is owner._scope and owner._scope.active
                events.append('close')

        return Product()

    monkeypatch.setattr(boundary, '_launch_original_channel_action_process', launch)
    monkeypatch.setattr(PinnedBulkImportFile, 'decode', lambda *_a, **_k: pytest.fail('Owner decoded row material'))
    if fault is None:
        original_env, rejected = env.read_bytes(), control.dup()
        try:
            env.write_text('SYNTHETIC_TOKEN=other-synthetic-token\nSYNTHETIC_USERNAME=' + ACTOR + '\n')
            with pytest.raises(BulkImportIntakeError):
                boundary._OriginalRowOwnerAdapter(owner, current, intake_peer=rejected,
                    source_path=source, source_digest=digest)
            assert not events and owner._execution.claim_count == 0
        finally:
            env.write_bytes(original_env)
            rejected.close()
    adapter = boundary._OriginalRowOwnerAdapter(owner, current, intake_peer=control.dup(),
        source_path=source, source_digest=digest)
    kernel = M4ExecutionKernel(adapter, issuer, owner._execution, clock=lambda: 1000)
    try:
        with reference:
            owner.prepare_original_dispatch()
            result = kernel.execute(owner._binding.plan, owner._binding.authorization, now_epoch=1000)
            assert result.verification is (M4Verification.VERIFIED if fault is None else M4Verification.UNKNOWN), (
                events, len(details), current._failed, current._post is not None)
            assert result.outcome is (M4Outcome.SUCCEEDED if fault is None else M4Outcome.RECONCILIATION_REQUIRED)
            replay = kernel.execute(owner._binding.plan, owner._binding.authorization, now_epoch=1000)
            assert replay.idempotent_replay and replay.verification is result.verification
            if fault is None:
                assert owner._inspect_verified_ack().native_secret_id == 71 and len(details) == 1
            else:
                assert not details
                with pytest.raises(BulkImportIntakeError):
                    owner._inspect_verified_ack()
        assert events == ['launch', 'transfer', 'close'] and adapter._peer.fileno() == -1
        assert control.fileno() >= 0 and intake.fileno() >= 0 and _ACTIVE_DISPATCH.get() is None
        assert all(connection.closed for connection in connections) and all(response.closed for response in responses)
        native.disposed()
        assert capfd.readouterr() == ('', '')
    finally:
        adapter.close()
        control.close(); intake.close()


@pytest.mark.parametrize('fault', [None, 'drift', 'revoked', 'expired', 'wrong-scope', 'wrong-proof'])
def test_native_current_is_reused_only_inside_original_scope_and_forced_before_create(
        tmp_path, monkeypatch, fault):
    from v4_planning import canonical_digest
    from v4_planning.execution_kernel import _M4DispatchScope, M4ClaimState
    native = NativeSources(tmp_path, monkeypatch)
    owner, current, _, reference = original_owner(tmp_path, monkeypatch, native)
    b = owner._binding
    scope = token = None
    try:
        with reference:
            before = len(native.peers)
            owner.prepare_original_dispatch()
            assert len(native.peers) == before and owner._execution.claim_count == 0
            context = canonical_digest({'authorization_digest': b.authorization.authorization_digest,
                'plan_digest': b.plan.plan_digest, 'revision': b.plan.revision})
            claimed = owner._execution.claim(plan_ref=b.plan.plan_ref, requester_digest=b.plan.requester_digest,
                idempotency_digest=b.plan.idempotency_digest, context_digest=context,
                authorization_digest=b.authorization.authorization_digest)
            assert claimed.state is M4ClaimState.NEW
            assert current._read_for_kernel(b.plan, b.authorization) == b.plan.expected_current_digest
            assert len(native.peers) == before + 1
            scope = _M4DispatchScope(b.plan, b.authorization, owner._execution)
            if fault == 'wrong-scope':
                scope.store = None
            token = _ACTIVE_DISPATCH.set(scope)
            if fault == 'wrong-scope':
                with pytest.raises((ValueError, BulkImportIntakeError)):
                    current._bind_current_scope(b.plan, b.authorization)
                assert len(native.peers) == before + 1
                return
            current._bind_current_scope(b.plan, b.authorization)
            owner.arm_original_dispatch()
            for _ in range(4):
                owner._permission.verify_row_acquisition(b.plan, b.authorization, b.source, now_epoch=1000)
            owner._observe('material-ready', '1' * 32, None, 1000)
            owner._observe('material-claim', '2' * 32, None, 1000)
            owner._observe('claim', '3' * 32, canonical_digest(owner._material_nonce), 1000)
            for _ in range(4):
                owner._observe('verify', '4' * 32, canonical_digest(owner._load_nonce), 1000)
            assert len(native.peers) == before + 1
            deadline = current._deadline
            if fault == 'drift':
                native.fault = 'folder'
            elif fault == 'revoked':
                reference.app.state.authority.revoke(reference.app.state.grant_handle, now_epoch=1000)
            elif fault == 'expired':
                native.now = deadline
            proof = 'f' * 64 if fault == 'wrong-proof' else canonical_digest(owner._load_nonce)
            if fault is None:
                owner._observe('verify-before-create', '5' * 32, proof, 1000)
                assert len(native.peers) == before + 2
                assert current._current_sealed and current._deadline == deadline
                with pytest.raises((ValueError, BulkImportIntakeError)):
                    owner._observe('verify-before-create', '6' * 32, proof, 1000)
            else:
                with pytest.raises((ValueError, BulkImportIntakeError)):
                    owner._observe('verify-before-create', '5' * 32, proof, 1000)
                assert not owner._ack_attempted
                if fault != 'wrong-proof':
                    assert current._current_sealed
            scope.close()
            with pytest.raises(BulkImportIntakeError):
                current.read_current(b.plan)
            assert owner._execution.claim_count == 1
    finally:
        if scope is not None:
            scope.close()
        if token is not None:
            _ACTIVE_DISPATCH.reset(token)
        current.close()
        reference.close()
        native.disposed()
