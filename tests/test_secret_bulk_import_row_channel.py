"""Signed private metadata/NEW ownership channel; synthetic, no device writer."""

import hashlib
import json
import socket
from dataclasses import replace
from pathlib import Path
import shutil
import tempfile
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest
from starlette.testclient import TestClient

from fortipam_mcp import secret_bulk_import_row_channel as boundary
from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
from fortipam_mcp.secret_bulk_import_file import PinnedBulkImportFile
from test_secret_bulk_import_row_authority import configured
from test_secret_bulk_import_row_loader import ProbeAdapter, run
from v4_planning import M4Verification


def write(path, value):
    path.write_bytes(value)
    path.chmod(0o600)
    return hashlib.sha256(value).hexdigest()


def channel(tmp_path, monkeypatch, *, material=False, capture=None, ack_capture=None, ack_defaults_digest=None,
            file_parent=False, values=None, snapshot=None, target_factory=None):
    local, session, state, values, root, handle, reader, clocks, reference = configured(
        tmp_path, monkeypatch, capture=capture, file_parent=file_parent, values=values, snapshot=snapshot)
    ack_pins = boundary._OriginalRowAckPins(local._row, ack_defaults_digest, ack_capture) if ack_capture is not None else None
    binding = boundary.OriginalRowChannelBinding(session._transaction._binding, local._plan,
        local._authorization, local._parent_digest, local._rows._key.digest, local._authority._pins,
        material_requested_at=1000 if material else None, material_expires_at=1060 if material else None,
        ack_pins_digest=ack_pins.digest() if ack_pins is not None else None)
    store = None
    if material:
        from test_secret_bulk_import_row_provider import material_store
        store = material_store(tmp_path)
    owner = boundary.OriginalRowChannelOwner(binding, local._parent, state, local._authority,
        material_store=store, ack_pins=ack_pins, clock=lambda: int(clocks[0]),
        target_owners=() if target_factory is None else (target_factory(local, session, state),))
    # macOS sockaddr_un is too short for pytest's descriptive directory names.
    directory = Path(tempfile.mkdtemp(prefix="fp-row-", dir=Path("/tmp").resolve()))
    request, signer, public = directory / "request.key", directory / "signer.key", directory / "public.key"
    request_sha = write(request, b"q" * 32)
    signer_sha = write(signer, b"z" * 32)
    public_sha = write(public, Ed25519PrivateKey.from_private_bytes(b"z" * 32).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    class DisposableSocket:
        def __init__(self):
            self.socket = socket.socket(socket.AF_UNIX)

        def close(self):
            self.socket.close()
            shutil.rmtree(directory)

    uds = DisposableSocket()
    path = directory / "row.sock"
    try:
        uds.socket.bind(str(path))
    except BaseException:
        session.close()
        uds.close()
        raise
    path.chmod(0o600)
    app = boundary.create_original_row_channel_app(owner,
        request_key_path=request, request_key_sha256=request_sha,
        signing_key_path=signer, signing_key_sha256=signer_sha,
        clock=lambda: int(clocks[0]), monotonic=lambda: 100.0)
    transport = TestClient(app)
    settings = dict(socket_path=path, request_key_path=request, request_key_sha256=request_sha,
        public_key_path=public, public_key_sha256=public_sha, clock=lambda: int(clocks[0]), monotonic=lambda: 100.0)
    observed = []

    def post(self, purpose, raw):
        response = transport.post(boundary._PREFIX + purpose, content=bytes(raw),
                                  headers={"Content-Type": "application/json"})
        if response.status_code != 200:
            raise ValueError("Synthetic private refusal")
        observed.append(json.loads(response.content))
        return bytearray(response.content)

    monkeypatch.setattr(boundary.UnixOriginalRowChannelClient, "_post", post)
    client = boundary.UnixOriginalRowChannelClient(binding, **settings)
    return local, session, state, values, root, handle, owner, client, reference, transport, uds, settings, observed


def remote(local, session, client):
    result = boundary._RemoteOriginalImportRowLoader(session, client, index=0,
        key_path=local._rows._key.path, key_sha256=local._rows._key.digest)
    if hasattr(local, '_issuer'):
        result._issuer = local._issuer
    return result


@pytest.mark.parametrize('sibling_state', ['unstarted', 'verified', 'unknown', 'in-progress',
                                         'target-unproved', 'late-unknown'])
def test_file_parent_preflight_stops_without_consuming_unready_rows(tmp_path, monkeypatch, sibling_state):
    from fortipam_mcp.secret_bulk_import_dependencies import ImportTemplate, ImportTemplateField
    from test_secret_bulk_import_dependencies import catalog, item
    from v4_planning import M4AuditEvent, M4ExecutionResult, M4Outcome, M4Compensation
    from test_m4_execution_store import _store
    snapshot = catalog()
    if sibling_state == 'target-unproved':
        values = [item(Name='First'), item(Name='Second')]
    else:
        snapshot = replace(snapshot, templates=(ImportTemplate('Text', (ImportTemplateField('Text', 'text', True),)),))
        values = [item(Name=name, **{'Secret Template': 'Text', 'URL': '', 'Username': '',
                   'Password/Passphrase': '', 'Text': 'synthetic private text', 'Service Type': '', 'Port': ''})
                  for name in ('First', 'Second')]
    parts = channel(tmp_path, monkeypatch, file_parent=True, values=values, snapshot=snapshot)
    local, session, state, _, _, _, owner, client, reference, transport, uds, _, _ = parts
    try:
        parent = local._parent.get_import_parent(local._plan.plan_ref)
        sibling = next(line for line in parent.lines if line.kind == 'secret' and line.index == 1)
        ids = tuple(line.idempotency_digest for line in parent.lines if line.idempotency_digest is not None)
        def consume_sibling(status):
            state.claim(plan_ref=parent.plan_ref, requester_digest=parent.requester_digest,
                idempotency_digest=sibling.idempotency_digest, context_digest='a' * 64, authorization_digest='b' * 64)
            if status != 'in-progress':
                terminal = M4ExecutionResult(
                    M4Outcome.SUCCEEDED if status == 'verified' else M4Outcome.RECONCILIATION_REQUIRED,
                    M4Verification.VERIFIED if status == 'verified' else M4Verification.UNKNOWN,
                    M4Compensation.NOT_REQUESTED, False)
                state.finalize(plan_ref=parent.plan_ref, requester_digest=parent.requester_digest,
                    idempotency_digest=sibling.idempotency_digest, context_digest='a' * 64, result=terminal,
                    event=M4AuditEvent(0, 'verified', terminal.outcome, terminal.verification, terminal.compensation, 'c' * 64))
        if sibling_state in ('verified', 'unknown', 'in-progress'):
            consume_sibling(sibling_state)
        before, tail = state.claim_count, state._monotonic_checkpoint.tail
        with reference, transport:
            loader = remote(local, session, client)
            if sibling_state in ('unknown', 'in-progress', 'target-unproved'):
                with pytest.raises(BulkImportIntakeError):
                    owner.prepare_original_dispatch()
                assert state.claim_count == before
                assert state._monotonic_checkpoint.tail == tail
                assert not owner._parent_prepared and owner._scope is None
            else:
                owner.prepare_original_dispatch()
                assert state.claim_count == before
                assert state._monotonic_checkpoint.tail == tail
                if sibling_state == 'late-unknown':
                    consume_sibling('unknown')
                class Dispatch(ProbeAdapter):
                    def dispatch(self, plan):
                        try:
                            owner.arm_original_dispatch()
                        except BulkImportIntakeError:
                            from v4_planning import M4AdapterAmbiguous
                            raise M4AdapterAmbiguous('Original parent stopped before acquisition') from None
                        super().dispatch(plan)
                result, adapter = run(loader, state, Dispatch(loader, values[0]))
                if sibling_state == 'late-unknown':
                    assert result.verification is M4Verification.UNKNOWN
                    assert adapter.owned is None
                    assert state.claim_count == before + 2
                else:
                    assert result.verification is M4Verification.VERIFIED
                    assert all(not any(value) for value in adapter.owned._buffers)
                with pytest.raises(BulkImportIntakeError):
                    owner.prepare_original_dispatch()
        reopened = _store(tmp_path, monotonic_checkpoint=state._monotonic_checkpoint,
                          checkpoint_store_ref=state._checkpoint_store_ref)
        assert reopened._inspect_original_claims(plan_ref=parent.plan_ref, requester_digest=parent.requester_digest,
            idempotency_digests=ids) == state._inspect_original_claims(plan_ref=parent.plan_ref,
                requester_digest=parent.requester_digest, idempotency_digests=ids)
    finally:
        session.close()
        uds.close()


from test_target_create_lifecycle import fixture as target_fixture


@pytest.mark.parametrize('fault', [None, 'target-drift', 'late-drift', 'invalidated', 'source-drift', 'expired'])
def test_original_target_reuse_reads_complete_state_without_target_claim(tmp_path, monkeypatch, fault):
    import httpx
    from fortipam_mcp.secret_bulk_import_parent_graph import _OriginalImportTargetReuse
    from fortipam_mcp.secret_bulk_import_dependencies import ImportTarget, ImportTemplate, ImportTemplateField
    from test_secret_bulk_import_dependencies import catalog, item
    from test_target_api_dependency_reader import Harness, Body
    import test_target_preservation_contract as target_state

    current = target_state.row()
    baseline = target_state.capture(current)
    coordinates = baseline.coordinates
    snapshot = replace(catalog(), templates=(ImportTemplate(coordinates.template, tuple(
        ImportTemplateField(name, kind, True) for name, kind in
        [('Address', 'target-address'), ('Domain', 'domain'), ('Username', 'username'), ('Password', 'password')])),),
        targets=(ImportTarget(baseline.name, coordinates.template, coordinates.address,
            coordinates.domain, coordinates.url, baseline.state_digest),))
    values = [item(**{'Secret Template': coordinates.template, 'Target-Address': coordinates.address,
        'Domain': coordinates.domain, 'URL': '', 'Service Type': 'SSH', 'Port': '22'})]
    target_reads = []
    class TargetHarness(Harness):
        def handle(self, request):
            if request.url.path == '/api/v2/cmdb/secret/target/' + baseline.name:
                assert request.method == 'GET'
                assert request.url.query == b'with_meta=true&vdom=root'
                target_reads.append(request)
                return httpx.Response(200, headers={'content-type': 'application/json'},
                    stream=Body(bytes(target_state.response(current))))
            return super().handle(request)
    harness = TargetHarness()
    reader = harness.reader()
    graph, epoch = {}, [1000]
    def target_factory(local, session, state):
        return _OriginalImportTargetReuse(local._rows, session._transaction._binding,
            graph['projected'], snapshot, local._parent, reader, baseline, index=0,
            expected_parent_digest=local._parent_digest, expected_source_context_digest=reader._source,
            clock=lambda: epoch[0])
    parts = channel(tmp_path, monkeypatch, file_parent=True, values=values, snapshot=snapshot,
        capture=graph, target_factory=target_factory)
    local, session, state, _, _, _, owner, client, reference, api, uds, _, _ = parts
    reuse = owner._target_owners[0]
    try:
        assert reuse.line.effect == 'reuse' and reuse.line.idempotency_digest is None
        if fault == 'target-drift':
            current['description'] = 'Changed preserved field'
        elif fault == 'invalidated':
            local._parent.invalidate_plan(reuse.parent.plan_ref, evaluated_at=1000,
                reason_codes=('current_state_drift',))
        elif fault == 'source-drift':
            reader._source = 'f' * 64
        elif fault == 'expired':
            epoch[0] = reuse.parent.expires_at
        with reference, api:
            if fault not in (None, 'late-drift'):
                with pytest.raises(BulkImportIntakeError):
                    owner.prepare_original_dispatch()
                assert state.claim_count == 0 and owner._scope is None
            else:
                owner.prepare_original_dispatch()
                assert state.claim_count == 0 and len(target_reads) == 1
                if fault == 'late-drift':
                    current['hostkey'] = [{'hostkey-data': 'Changed protected field'}]
                loader = remote(local, session, client)
                class Dispatch(ProbeAdapter):
                    def dispatch(self, plan):
                        from v4_planning import M4AdapterAmbiguous
                        try:
                            owner.arm_original_dispatch()
                        except BulkImportIntakeError:
                            raise M4AdapterAmbiguous('Original reuse prerequisite changed') from None
                        super().dispatch(plan)
                result, adapter = run(loader, state, Dispatch(loader, values[0]))
                if fault == 'late-drift':
                    assert result.verification is M4Verification.UNKNOWN and adapter.owned is None
                else:
                    assert result.verification is M4Verification.VERIFIED
                assert len(target_reads) >= 2
                assert state.claim_count == 1
        assert all(request.method == 'GET' for request in target_reads)
        assert all(client.is_closed for client in harness.clients)
    finally:
        session.close()
        reader.close()
        uds.close()


@pytest.mark.parametrize('case', ['forward', 'restore', 'lost-ack', 'm4-unknown',
                                  'invalidated', 'changed-target', 'restore-lost-ack'])
def test_original_existing_target_update_and_independent_restore(tmp_path, monkeypatch, case):
    import ssl
    from fortipam_mcp.secret_bulk_import_parent_graph import _OriginalImportTargetUpdateBinding
    from fortipam_mcp.secret_bulk_import_dependencies import ImportTarget, ImportTemplate, ImportTemplateField
    from fortipam_mcp import target_coordinate_lifecycle as lifecycle
    from test_target_preservation_contract import capture as capture_target
    from test_secret_bulk_import_dependencies import catalog, item
    from fortipam_mcp.target_preservation_contract import TargetCoordinateChange
    from fortipam_mcp.target_preservation_http_transport import TargetCoordinateHttpTransport
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
    from test_target_preservation_http_transport import Peer
    from test_target_api_dependency_reader import Harness
    from v4_planning import M4AdapterAmbiguous

    original_context = ssl.create_default_context
    monkeypatch.setattr(ssl, 'create_default_context', lambda **kwargs: original_context())
    ca = tmp_path / 'target-ca.pem'
    ca.write_text('SYNTHETIC_CA')
    directory = tmp_path / 'target-coordinate'
    directory.mkdir(mode=0o700)
    peer = Peer()
    peer.row['domain'] = ''
    baseline = capture_target(peer.row)
    change = TargetCoordinateChange(baseline, replace(baseline.coordinates, domain='example.test'))
    peer.now = 1000
    transport = TargetCoordinateHttpTransport(
        SecretMetadataHttpTransportConfig('https://pam.example', 'synthetic-token', 5, str(ca)),
        change, state_directory=directory, execution_enabled=True,
        clock=lambda: peer.now, connection_factory=peer.factory)
    reader = Harness().reader(base_url='https://pam.example', ca_file=str(ca))
    baseline, coordinates = change.baseline, change.desired
    snapshot = replace(catalog(), templates=(ImportTemplate(coordinates.template, tuple(
        ImportTemplateField(name, kind, True) for name, kind in
        [('Address', 'target-address'), ('Domain', 'domain'), ('Username', 'username'), ('Password', 'password')])),),
        targets=(ImportTarget(baseline.name, baseline.coordinates.template, baseline.coordinates.address,
            baseline.coordinates.domain, baseline.coordinates.url, baseline.state_digest),))
    values = [item(**{'Secret Template': coordinates.template, 'Target-Address': coordinates.address,
        'Domain': coordinates.domain, 'URL': '', 'Service Type': 'SSH', 'Port': '22'})]
    graph, options = {}, {}
    def target_factory(local, session, state):
        binding = _OriginalImportTargetUpdateBinding(local._rows, session._transaction._binding,
            graph['projected'], snapshot, local._parent, state, transport, index=0,
            expected_parent_digest=local._parent_digest, expected_source_context_digest=reader._source,
            expected_serial_digest=baseline.serial_digest, now_epoch=1000)
        parent = binding.parent
        options.update(creator=None, transport=transport, reader=reader, store=state,
            authority_key=b'a' * 32, execution_enabled=True, original_import=binding,
            requester_digest=parent.requester_digest, transport_digest='2' * 64,
            environment_ref='owner-file-deployment-' + parent.environment_digest,
            scope_ref='owner-file-scope-' + parent.scope_digest,
            audience_ref='owner-file-audience-' + parent.audience_digest)
        return lifecycle.TargetCoordinateLifecycle(phase='update', **options)
    parts = channel(tmp_path, monkeypatch, file_parent=True, values=values, snapshot=snapshot,
        capture=graph, target_factory=target_factory)
    local, session, state, _, _, _, owner, client, reference, api, uds, _, _ = parts
    target = owner._target_owners[0]
    binding = target._import
    try:
        with reference, api:
            with pytest.raises(BulkImportIntakeError):
                owner.prepare_original_dispatch()
            assert state.claim_count == 0
            issued = target.issue(target.preview())
            assert issued.plan.plan_ref == binding.parent.plan_ref
            assert issued.plan.idempotency_digest == binding.line.idempotency_digest
            assert issued.plan.parameters_digest == binding.line.parameters_digest
            assert issued.plan.confirmation_digest == binding.parent.intent_policy_digest
            if case == 'invalidated':
                local._parent.invalidate_plan(binding.parent.plan_ref, evaluated_at=1000,
                    reason_codes=('current_state_drift',))
                with pytest.raises(lifecycle.TargetCoordinateLifecycleError):
                    target.execute(issued)
                assert state.claim_count == 0 and 'PUT' not in peer.calls
                return
            peer.lose_ack = case == 'lost-ack'
            if case == 'm4-unknown':
                def unknown(self, plan):
                    raise M4AdapterAmbiguous('Synthetic terminal read failure')
                monkeypatch.setattr(lifecycle._KernelAdapter, 'read_postcondition', unknown)
            result = target.execute(issued)
            assert state.claim_count == 1 and peer.calls.count('PUT') == 1
            if case in ('lost-ack', 'm4-unknown'):
                assert result.verification is M4Verification.UNKNOWN
                if case == 'm4-unknown':
                    assert (directory / 'update.verified.json').is_file()
                with pytest.raises(BulkImportIntakeError):
                    owner.prepare_original_dispatch()
                with pytest.raises(lifecycle.TargetCoordinateLifecycleError):
                    lifecycle.TargetCoordinateLifecycle(phase='restore', **options)
                return
            assert result.verification is M4Verification.VERIFIED
            with pytest.raises(lifecycle.TargetCoordinateLifecycleError):
                target.execute(issued)
            if case == 'changed-target':
                peer.row['description'] = 'Changed preserved field'
                with pytest.raises(BulkImportIntakeError):
                    owner.prepare_original_dispatch()
                restore = lifecycle.TargetCoordinateLifecycle(phase='restore', **options)
                with pytest.raises(lifecycle.TargetCoordinateLifecycleError):
                    restore.preview()
                return
            owner.prepare_original_dispatch()
            assert state.claim_count == 1
            restore = lifecycle.TargetCoordinateLifecycle(phase='restore', **options)
            restore_issued = restore.issue(restore.preview())
            assert restore_issued.plan.plan_ref != binding.parent.plan_ref
            assert restore_issued.plan.idempotency_digest != binding.line.idempotency_digest
            if case == 'forward':
                loader = remote(local, session, client)
                class Dispatch(ProbeAdapter):
                    def dispatch(self, plan):
                        owner.arm_original_dispatch()
                        super().dispatch(plan)
                result, _ = run(loader, state, Dispatch(loader, values[0]))
                assert result.verification is M4Verification.VERIFIED and state.claim_count == 2
                # Even an already-issued restore cannot undo a Target used by a child row.
                with pytest.raises(lifecycle.TargetCoordinateLifecycleError):
                    restore.execute(restore_issued)
                assert peer.calls.count('PUT') == 1
            else:
                peer.lose_ack = case == 'restore-lost-ack'
                result = restore.execute(restore_issued)
                assert result.verification is (M4Verification.UNKNOWN if peer.lose_ack else M4Verification.VERIFIED)
                assert capture_target(peer.row) == baseline
                assert peer.calls.count('PUT') == 2 and state.claim_count == 2
                with pytest.raises(lifecycle.TargetCoordinateLifecycleError):
                    restore.execute(restore_issued)
                # A restore attempt is terminal even if external drift puts coordinates back.
                peer.row['domain'] = coordinates.domain
                with pytest.raises(BulkImportIntakeError):
                    owner.prepare_original_dispatch()
    finally:
        session.close()
        reader.close()
        uds.close()


@pytest.mark.parametrize(('fault', 'batched'), [(None, False), ('lost-ack', False),
    ('invalidated', False), ('changed-target', False), pytest.param(None, True, id='batch-target-and-secret'),
    ('ack-readback', False), ('ack-readback-c3-unknown', False), ('ack-readback-m4-unknown', False),
    ('ack-readback-expired', False), ('ack-readback-monotonic', False)])
def test_original_target_create_and_row_use_share_parent_identity(tmp_path, monkeypatch, target_fixture, fault, batched):
    from fortipam_mcp.secret_bulk_import_batch import _OriginalImportBatch, _OriginalImportRowExecution
    from fortipam_mcp.secret_bulk_import_parent_graph import _OriginalImportTargetCreateBinding
    from fortipam_mcp.secret_bulk_import_dependencies import ImportTemplate, ImportTemplateField
    from fortipam_mcp.secret_bulk_import_row_action_worker import _compile_original_channel_action_pins
    from fortipam_mcp.web_secret_create_ack import WebSecretCreateAckCapture
    from test_secret_bulk_import_dependencies import catalog, item
    from test_secret_bulk_import_row_wire import project
    from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, M4Verification
    from v4_planning.execution_kernel import M4ClaimState, M4Outcome
    from v4_planning.material_runtime import MaterialUseClaimState
    from fortipam_mcp.target_create_lifecycle import TargetCreateLifecycleError
    make, peer, _, creator, _, _, _, _, _ = target_fixture
    peer.now = 1000
    coordinates = creator._proposal.coordinates
    snapshot = replace(catalog(), templates=(ImportTemplate(coordinates.template, tuple(
        ImportTemplateField(name, kind, True) for name, kind in
        [('Address', 'target-address'), ('Domain', 'domain'), ('Username', 'username'), ('Password', 'password')])),))
    values = [item(**{'Secret Template': coordinates.template, 'Target-Address': coordinates.address,
                      'Domain': coordinates.domain, 'URL': '', 'Service Type': 'SSH', 'Port': '22'})]
    defaults = replace(project(), serial_digest=creator._proposal.serial_digest)
    capture = WebSecretCreateAckCapture(defaults.serial_digest, 'success')
    graph = {}
    def target_factory(local, session, state):
        binding = _OriginalImportTargetCreateBinding(local._rows, session._transaction._binding,
            graph['projected'], snapshot, local._parent, state, creator, index=0,
            expected_parent_digest=local._parent_digest,
            expected_source_context_digest=creator._source_context_digest,
            expected_serial_digest=creator._proposal.serial_digest, now_epoch=1000)
        parent = binding.parent
        return make(store=state, original_import=binding, requester_digest=parent.requester_digest,
            environment_ref='owner-file-deployment-' + parent.environment_digest,
            scope_ref='owner-file-scope-' + parent.scope_digest,
            audience_ref='owner-file-audience-' + parent.audience_digest)
    parts = channel(tmp_path, monkeypatch, file_parent=True, values=values, snapshot=snapshot,
        capture=graph, material=True, ack_capture=capture, ack_defaults_digest=defaults.digest(),
        target_factory=target_factory)
    local, session, state, _, _, _, owner, client, reference, api, uds, _, _ = parts
    target = owner._target_owners[0]
    binding = target._authority._original_import
    parent = binding.parent
    readback = fault is not None and fault.startswith('ack-readback')
    c3_failure = fault in {'ack-readback-c3-unknown', 'ack-readback-expired', 'ack-readback-monotonic'}
    readback_stages = []
    try:
        with reference, api:
            if not batched:
                with pytest.raises(BulkImportIntakeError):
                    owner.prepare_original_dispatch()
                assert state.claim_count == 0
                issued = target.issue(target.preview())
                assert issued.plan.plan_ref == parent.plan_ref
                assert issued.plan.idempotency_digest == binding.line.idempotency_digest
                assert issued.plan.parameters_digest == binding.line.parameters_digest
                assert issued.plan.confirmation_digest == parent.intent_policy_digest
                if fault == 'invalidated':
                    local._parent.invalidate_plan(parent.plan_ref, evaluated_at=1000, reason_codes=('current_state_drift',))
                    with pytest.raises(TargetCreateLifecycleError):
                        target.execute(issued)
                    assert state.claim_count == 0 and 'POST' not in peer.calls
                    return
                peer.lost_ack = fault == 'lost-ack'
                result = target.execute(issued)
                assert peer.calls.count('POST') == 1 and state.claim_count == 1
            if fault == 'lost-ack':
                assert result.verification is M4Verification.UNKNOWN
                with pytest.raises(BulkImportIntakeError):
                    owner.prepare_original_dispatch()
                assert state.claim_count == 1
            elif fault == 'changed-target':
                assert result.verification is M4Verification.VERIFIED
                peer.created['description'] = 'Changed after verified creation'
                with pytest.raises(BulkImportIntakeError):
                    owner.prepare_original_dispatch()
                assert state.claim_count == 1 and peer.calls.count('POST') == 1
            else:
                if not batched:
                    assert result.verification is M4Verification.VERIFIED
                    owner.prepare_original_dispatch()
                loader = remote(local, session, client)
                from fortipam_mcp.secret_bulk_import_row_adapter import _OriginalRowSecretCreateAdapter, _OriginalRowUseContext
                from fortipam_mcp.secret_bulk_import_row_conversion import _Build29OriginalRowConversion
                from fortipam_mcp.secret_bulk_import_row_wire import _Build29OriginalRowWireEncoder
                from fortipam_mcp.secret_bulk_import_row_provider import _OriginalRowMaterialRuntime
                from fortipam_mcp import secret_bulk_import_row_http_transport as http_module
                from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
                from test_secret_bulk_import_row_http_transport import Exchange, assert_cleanup
                from v4_planning.material_runtime import MaterialRuntimeOutcome
                context = _OriginalRowUseContext(loader._row, client._binding.permission, 1000, 1060)
                class Pending:
                    def _create_and_verify_with_original_row(self, *_a, **_k):
                        pytest.fail('Native transport not bound')
                bridge = _OriginalRowSecretCreateAdapter(loader, context, Pending())
                converter = _Build29OriginalRowConversion(bridge, snapshot, graph['projected'],
                    target_name=creator._proposal.name, associated_secret_id=None)
                encoder = _Build29OriginalRowWireEncoder(converter, defaults,
                    expected_defaults_digest=defaults.digest(), expected_serial_digest=defaults.serial_digest)
                class Tls:
                    def set_alpn_protocols(self, protocols): self.protocols = protocols
                monkeypatch.setattr(http_module, '_ssl_context', lambda _: Tls())
                exchange = Exchange(bridge)
                loader._authority._reader = owner._permission._reader
                def connection_factory(*args, **kwargs):
                    connection = exchange.factory(*args, **kwargs)
                    getresponse = connection.getresponse
                    def response():
                        reply = getresponse()
                        payload = json.loads(reply.payload)
                        payload['serial'] = 'SYNTHETIC'
                        reply.payload[:] = json.dumps(payload).encode()
                        reply.headers['Content-Length'] = str(len(reply.payload))
                        return reply
                    connection.getresponse = response
                    return connection
                bridge._transport = http_module._Build29OriginalRowHttpTransport(
                    SecretMetadataHttpTransportConfig('https://synthetic.example.test', 'synthetic-token', 10, None),
                    encoder, capture, connection_factory=connection_factory)
                runtime = _OriginalRowMaterialRuntime(bridge, boundary._OriginalRowMaterialStateClient(client, context, session))
                if readback:
                    with pytest.raises(BulkImportIntakeError):
                        owner._inspect_ack_for_readback()
                    original_postread = owner._permission._reader.read_postcondition
                    def completion_postread(plan):
                        with monkeypatch.context() as denied:
                            denied.setattr(owner._permission._reader, 'read_postcondition',
                                lambda *_: pytest.fail('ACK inspection recursed into projection readback'))
                            ack = owner._inspect_ack_for_readback()
                        assert ack.native_secret_id == 71
                        with pytest.raises(BulkImportIntakeError):
                            owner._inspect_verified_ack()
                        readback_stages.append('c3-in-progress')
                        with monkeypatch.context() as uncertain:
                            uncertain.setattr(owner, '_material_finished', True)
                            with pytest.raises(BulkImportIntakeError):
                                owner._inspect_ack_for_readback()
                        if fault == 'ack-readback-expired':
                            owner._readback_lifetime.clock = lambda: owner._binding.material_expires_at
                        elif fault == 'ack-readback-monotonic':
                            owner._readback_lifetime.monotonic = lambda: owner._readback_lifetime.deadline
                        if fault in {'ack-readback-expired', 'ack-readback-monotonic'}:
                            with pytest.raises(BulkImportIntakeError):
                                owner._inspect_ack_for_readback()
                        if c3_failure:
                            raise BulkImportIntakeError('Synthetic completion unavailable')
                        return original_postread(plan)
                    monkeypatch.setattr(owner._permission._reader, 'read_postcondition', completion_postread)
                class Dispatch(ProbeAdapter):
                    def read_postcondition(self, plan):
                        if readback:
                            ack = owner._inspect_ack_for_readback()
                            record, original, material = owner._inspect_ack_claims()
                            assert record == ack and original.state is M4ClaimState.IN_PROGRESS
                            assert material.state is MaterialUseClaimState.REPLAY
                            assert material.outcome is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
                            with pytest.raises(BulkImportIntakeError):
                                owner._inspect_verified_ack()
                            readback_stages.append('m4-in-progress')
                            with monkeypatch.context() as altered:
                                altered.setattr(owner._parent, '_get_original_import_row_ack',
                                    lambda *_a, **_k: replace(ack, defaults_digest='f' * 64))
                                with pytest.raises(BulkImportIntakeError):
                                    owner._inspect_ack_for_readback()
                            with monkeypatch.context() as altered:
                                altered.setattr(owner, '_binding',
                                    replace(owner._binding, namespace_key_digest='f' * 64))
                                with pytest.raises(BulkImportIntakeError):
                                    owner._inspect_ack_for_readback()
                            if fault == 'ack-readback-m4-unknown':
                                raise M4AdapterAmbiguous('Synthetic final observation unavailable')
                        return super().read_postcondition(plan)

                    def dispatch(self, plan):
                        target_claim, = state._inspect_original_claims(plan_ref=parent.plan_ref,
                            requester_digest=parent.requester_digest,
                            idempotency_digests=(binding.line.idempotency_digest,))
                        assert target_claim.state is M4ClaimState.REPLAY
                        assert target_claim.result.outcome is M4Outcome.SUCCEEDED
                        assert target_claim.result.verification is M4Verification.VERIFIED
                        assert peer.calls.count('POST') == 1 and not exchange.requests
                        options = dict(namespace_key_path=local._rows._key.path, index=0,
                                       associated_secret_id=None)
                        with pytest.raises(BulkImportIntakeError):
                            _compile_original_channel_action_pins(owner, snapshot, graph['projected'], defaults,
                                target_name='Substituted target', **options)
                        pins = _compile_original_channel_action_pins(owner, snapshot, graph['projected'], defaults,
                            target_name=creator._proposal.name, **options)
                        assert dict(pins.metadata)['target'] == creator._proposal.name
                        owner.arm_original_dispatch()
                        outcome = runtime.execute_once(now_epoch=1000)
                        if c3_failure:
                            assert outcome is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
                            with pytest.raises(BulkImportIntakeError):
                                owner._inspect_ack_for_readback()
                            raise M4AdapterAmbiguous('Synthetic original material completion unknown')
                        assert outcome is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
                adapter = Dispatch(loader, values[0])
                if batched:
                    driver = _OriginalImportBatch(local._rows, session._transaction._binding,
                        graph['projected'], snapshot, local._parent, state,
                        expected_parent_digest=local._parent_digest, targets=(target,),
                        rows=(_OriginalImportRowExecution(owner,
                            M4ExecutionKernel(adapter, local._issuer, state, clock=lambda: 1000)),),
                        execution_enabled=True, clock=lambda: 1000)
                    assert state.claim_count == 0 and 'POST' not in peer.calls and not exchange.requests
                    batch_result = driver.execute_once()
                    assert batch_result.completed and batch_result.verified_lines == batch_result.total_lines == 2
                else:
                    row_result, adapter = run(loader, state, adapter)
                    unknown = c3_failure or fault == 'ack-readback-m4-unknown'
                    assert row_result.verification is (M4Verification.UNKNOWN if unknown else M4Verification.VERIFIED)
                assert state.claim_count == 2
                if readback:
                    assert 'c3-in-progress' in readback_stages
                    assert ('m4-in-progress' in readback_stages) is not c3_failure
                    with pytest.raises(BulkImportIntakeError):
                        owner._inspect_ack_for_readback()
                    if unknown:
                        with pytest.raises(BulkImportIntakeError):
                            owner._inspect_verified_ack()
                        assert sum(method == 'POST' for method, _ in exchange.requests) == 1
                        assert_cleanup(bridge, exchange)
                        return
                claims = state._inspect_original_claims(plan_ref=parent.plan_ref,
                    requester_digest=parent.requester_digest,
                    idempotency_digests=tuple(line.idempotency_digest for line in parent.lines))
                assert len(claims) == 2
                assert all(claim.state is M4ClaimState.REPLAY
                    and claim.result.outcome is M4Outcome.SUCCEEDED
                    and claim.result.verification is M4Verification.VERIFIED for claim in claims)
                assert owner._inspect_verified_ack().native_secret_id == 71
                assert sum(method == 'POST' for method, _ in exchange.requests) == 1
                assert_cleanup(bridge, exchange)
                # A fresh Target preview cannot replace the consumed parent line.
                with pytest.raises(TargetCreateLifecycleError):
                    target.preview()
                assert peer.calls.count('POST') == 1
    finally:
        session.close()
        uds.close()


def test_intake_uses_signed_original_records_and_active_owner_without_ledger_or_signer_inputs(tmp_path, monkeypatch, capfd):
    local, session, state, values, _, _, owner, client, reference, transport, uds, _, observed = channel(tmp_path, monkeypatch)
    try:
        with reference, transport:
            loader = remote(local, session, client)
            assert loader._row == local._row
            for obj in (client, loader):
                assert not hasattr(obj, "_parent") and not hasattr(obj, "_execution")
            assert not hasattr(client, "_signer")

            class Dispatch(ProbeAdapter):
                def dispatch(self, plan):
                    owner.arm_original_dispatch()
                    super().dispatch(plan)

            result, adapter = run(loader, state, Dispatch(loader, values[0]))
            assert result.verification is M4Verification.VERIFIED
            assert all(not any(value) for value in adapter.owned._buffers)
            with pytest.raises(BulkImportIntakeError):
                client.verify_row_acquisition(local._plan, local._authorization, client._binding.source, now_epoch=1000)
        assert owner._scope.active is False and owner._scope.store is None
        wire = json.dumps(observed)
        for private in (str(session._transaction._binding.path), session._transaction._binding.file_sha256,
                        "Original first row", "Password/Passphrase", "secret password"):
            assert private not in wire
        assert capfd.readouterr() == ("", "")
    finally:
        session.close()
        uds.close()


@pytest.mark.parametrize("fault", ["unarmed", "revoked", "forged-signature", "wrong-nonce", "request-key-drift"])
def test_unproved_remote_dispatch_and_changed_channel_never_decode_source(tmp_path, monkeypatch, fault):
    local, session, state, _, root, handle, owner, client, reference, transport, uds, settings, _ = channel(tmp_path, monkeypatch)
    try:
        with reference, transport:
            loader = remote(local, session, client)
            if fault == "revoked":
                root.revoke(handle, now_epoch=1000)
            elif fault == "request-key-drift":
                settings["request_key_path"].chmod(0o644)
            elif fault in {"forged-signature", "wrong-nonce"}:
                original = boundary.UnixOriginalRowChannelClient._post
                def changed(self, purpose, raw):
                    result = json.loads(original(self, purpose, raw))
                    if fault == "forged-signature":
                        result["seal"] = "0" * 128
                    else:
                        result["payload"]["nonce"] = "0" * 32
                    return bytearray(json.dumps(result).encode())
                monkeypatch.setattr(boundary.UnixOriginalRowChannelClient, "_post", changed)
            monkeypatch.setattr(PinnedBulkImportFile, "decode", lambda *_a, **_k: pytest.fail("Unqualified remote read"))

            class Dispatch(ProbeAdapter):
                def dispatch(self, plan):
                    if fault != "unarmed":
                        owner.arm_original_dispatch()
                    super().dispatch(plan)

            result, _ = run(loader, state, Dispatch(loader))
            assert result.verification is M4Verification.UNKNOWN
    finally:
        session.close()
        uds.close()


def test_second_intake_instance_cannot_reacquire_same_original_owner_dispatch(tmp_path, monkeypatch):
    local, session, state, _, _, _, owner, client, reference, transport, uds, settings, _ = channel(tmp_path, monkeypatch)
    reads = []
    decode = PinnedBulkImportFile.decode

    def observe(self, **options):
        reads.append(True)
        return decode(self, **options)

    monkeypatch.setattr(PinnedBulkImportFile, "decode", observe)
    try:
        with reference, transport:
            first = remote(local, session, client)
            second_client = boundary.UnixOriginalRowChannelClient(client._binding, **settings)
            second = remote(local, session, second_client)

            class Dispatch(ProbeAdapter):
                def dispatch(self, plan):
                    owner.arm_original_dispatch()
                    with first._load_once():
                        pass
                    with pytest.raises(BulkImportIntakeError):
                        second._load_once()

            result, _ = run(first, state, Dispatch(first))
            assert result.verification is M4Verification.VERIFIED and len(reads) == 1
    finally:
        session.close()
        uds.close()


def test_lost_claim_response_consumes_boundary_and_clears_source_without_retry(tmp_path, monkeypatch):
    local, session, state, _, _, _, owner, client, reference, transport, uds, _, _ = channel(tmp_path, monkeypatch)
    post = boundary.UnixOriginalRowChannelClient._post

    def lost(self, purpose, raw):
        response = post(self, purpose, raw)
        if purpose == "claim":
            raise ValueError("Synthetic response lost after consumption")
        return response

    try:
        with reference, transport:
            loader = remote(local, session, client)
            monkeypatch.setattr(boundary.UnixOriginalRowChannelClient, "_post", lost)
            monkeypatch.setattr(PinnedBulkImportFile, "decode", lambda *_a, **_k: pytest.fail("Ambiguous claim read source"))

            class Dispatch(ProbeAdapter):
                def dispatch(self, plan):
                    owner.arm_original_dispatch()
                    super().dispatch(plan)

            result, _ = run(loader, state, Dispatch(loader))
            assert result.verification is M4Verification.UNKNOWN
            assert owner._load_nonce is not None and client._claim_digest is None
            assert loader._used and session._transaction._closed.is_set() and not any(session._password)
            with pytest.raises(BulkImportIntakeError):
                loader._load_once()
    finally:
        session.close()
        uds.close()


def test_actual_uds_http_exchange_keeps_dispatch_owner_in_server_role(tmp_path, monkeypatch):
    native_post = boundary.UnixOriginalRowChannelClient._post
    local, session, state, values, _, _, owner, client, reference, transport, uds, _, _ = channel(tmp_path, monkeypatch)
    import uvicorn
    server = uvicorn.Server(uvicorn.Config(transport.app, access_log=False, log_level="critical", lifespan="off"))
    thread = threading.Thread(target=lambda: server.run(sockets=[uds.socket]), daemon=True)
    thread.start()
    until = time.monotonic() + 3
    while not server.started and thread.is_alive() and time.monotonic() < until:
        time.sleep(0.01)
    monkeypatch.setattr(boundary.UnixOriginalRowChannelClient, "_post", native_post)
    try:
        assert server.started
        with reference:
            loader = remote(local, session, client)
            class Dispatch(ProbeAdapter):
                def dispatch(self, plan):
                    owner.arm_original_dispatch()
                    super().dispatch(plan)
            result, adapter = run(loader, state, Dispatch(loader, values[0]))
            assert result.verification is M4Verification.VERIFIED
            assert all(not any(value) for value in adapter.owned._buffers)
    finally:
        session.close()
        server.should_exit = True
        thread.join(3)
        assert not thread.is_alive()
        uds.close()


@pytest.mark.parametrize("field", ["policy_decision_digest", "audience_digest", "scope_digest"])
def test_material_permission_context_is_bound_to_owner_and_signed_channel(tmp_path, monkeypatch, field):
    local, session, state, _, _, _, owner, _, reference, transport, uds, settings, _ = channel(tmp_path, monkeypatch)
    monkeypatch.setattr(PinnedBulkImportFile, "decode", lambda *_a, **_k: pytest.fail("Changed permission read"))
    try:
        with reference, transport:
            if field == "scope_digest":
                with pytest.raises(BulkImportIntakeError):
                    replace(owner._binding, permission=replace(owner._binding.permission, **{field: "8" * 64}))
            else:
                changed = replace(owner._binding, permission=replace(owner._binding.permission, **{field: "8" * 64}))
                with pytest.raises(BulkImportIntakeError):
                    boundary.OriginalRowChannelOwner(changed, local._parent, state, local._authority, clock=lambda: 1000)
                altered_client = boundary.UnixOriginalRowChannelClient(changed, **settings)
                with pytest.raises(BulkImportIntakeError):
                    remote(local, session, altered_client)
            assert owner._scope is None and owner._load_nonce is None and state.claim_count == 0
    finally:
        session.close()
        uds.close()
