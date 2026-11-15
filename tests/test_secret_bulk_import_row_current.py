"""Fresh Text current decisions over fixed native parsers and original ledgers."""

from dataclasses import asdict, replace
import hashlib
import json
import logging
import ssl
import time
from urllib.parse import quote

import httpx
import pytest

from fortipam_mcp import dlp_api_actor_guard as actor_module
from fortipam_mcp import secret_bulk_import_namespace_reader as namespace_module
from fortipam_mcp import secret_bulk_import_reference_reader as reference_module
from fortipam_mcp import secret_bulk_import_row_current as current
from fortipam_mcp import secret_bulk_import_row_namespace as original_module
from fortipam_mcp import secret_bulk_import_source_catalog as source_module
from fortipam_mcp.secret_bulk_import_parent_graph import _build_file_import_parent
from fortipam_mcp.secret_bulk_import_row_authority import _OriginalRowM4Authority
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.target_ssh_transport import TargetSshTransportConfig
from test_dlp_api_actor_guard import ACTOR, Harness, SERIAL, _ACTOR, _envelope, _role
from test_m4_execution_store import _ExternalM4Checkpoint, _event, _result, _store, CHECKPOINT_STORE_REF
from test_secret_bulk_import_file import csv_bytes, decode, row
from test_secret_bulk_import_intake import prepared
from test_secret_bulk_import_metadata import MATERIAL, response
from test_secret_bulk_import_row_wire import defaults_response
from test_target_qualified_reference_reader import Peer, ROOT, frame
from test_v4_persistence import _ExternalCheckpoint, _new_store, CHECKPOINT_STORE_REF as PARENT_STORE
from v4_planning.execution_kernel import M4Compensation, M4ExecutionResult, M4Outcome, M4Verification
from v4_planning.store import OriginalImportBindingRecord


class NativeSources:
    """Actual source-reader algorithms; only HTTP and SSH transports are fake."""

    def __init__(self, tmp_path, monkeypatch, *, template_name='Text', field_name='Text'):
        self.fault = None
        self.template_name, self.field_name = template_name, field_name
        self.now = time.monotonic()
        self.names = ['Existing A', 'Existing B', 'Hidden']
        self.requests, self.clients, self.streams, self.peers = [], [], [], []
        role = _role()
        role.update(name='super_admin', secretgrp='read-write')
        self.actor = Harness(role)
        self.actor.binding = replace(self.actor.binding, expected_profile='super_admin')
        self.actor.bodies = {
            _ACTOR: _envelope('state', {'admin': {'name': ACTOR, 'login_name': ACTOR,
                'guest_admin': False, 'sponsored_group_name': ''}}, monitor=True),
            '/api/v2/cmdb/system/api-user/' + ACTOR + '?format=name%7Caccprofile':
                _envelope('api-user', [{'name': ACTOR, 'accprofile': 'super_admin'}]),
            '/api/v2/cmdb/system/accprofile/super_admin?format=' + quote('|'.join(actor_module._ROLE_FIELDS), safe=''):
                _envelope('accprofile', [role]),
        }
        ca, known_hosts = tmp_path / 'ca.pem', tmp_path / 'known_hosts'
        ca.write_bytes(b'Synthetic public CA')
        known_hosts.write_bytes(b'Synthetic SSH pin')
        known_hosts.chmod(0o600)
        self.config = SecretMetadataHttpTransportConfig(self.actor.config.base_url,
            self.actor.config.bearer_token, 30, str(ca))
        self.ssh = TargetSshTransportConfig('synthetic.invalid', 22, ACTOR, 'synthetic-password', known_hosts, 30)
        self.trust = ssl.create_default_context()
        monkeypatch.setattr(actor_module, '_ssl_context', lambda _: self.trust)
        monkeypatch.setattr(reference_module, '_ssl_context', lambda _: self.trust)
        owner = self
        context = ROOT[:-2] + b' (database) #'

        class NamespacePeer(Peer):
            async def read(self, process, command, prompt, deadline):
                if command == namespace_module.r._VERSION:
                    return await super().read(process, command, prompt, deadline)
                self.commands.append(command)
                if command == namespace_module.r._SERIAL:
                    return frame(command, [b'Serial-Number: ' + SERIAL.encode()])
                assert prompt == context
                lines = ([b'        set name "' + name.encode() + b'"' for name in owner.names]
                    if command == namespace_module._NAMES else [b'        set folder 7'] * len(owner.names))
                return frame(command, lines, prompt=context)

        def transport(config):
            assert config.username == ACTOR and config.known_hosts_file == known_hosts
            peer = NamespacePeer()
            self.peers.append(peer)
            return peer

        async def dynamic(process, command, prompt, deadline):
            process.commands.append(command)
            return context if command == 'config secret database' else ROOT

        monkeypatch.setattr(namespace_module, 'FortiPamTargetReferenceSshTransport', transport)
        monkeypatch.setattr(namespace_module, '_complete_pre_login',
            lambda stdout, stdin, *args, **kwargs: stdout.login(stdout, stdin, *args, **kwargs))
        monkeypatch.setattr(namespace_module, '_send_and_read',
            lambda process, *args: process.read(process, *args))
        monkeypatch.setattr(namespace_module, '_send_and_read_dynamic_prompt', dynamic)

    def connection(self, host, port, **options):
        assert options['context'] is self.trust and 0 < options['timeout'] <= 30
        options['timeout'] = 5
        return self.actor.connect(host, port, **options)

    def client(self, **options):
        assert options['verify'] is self.trust and options['trust_env'] is False
        assert options['follow_redirects'] is False
        client = httpx.Client(transport=httpx.MockTransport(self.handle), **options)
        self.clients.append(client)
        return client

    def handle(self, request):
        self.requests.append(request)
        assert request.headers['authorization'] == 'Bearer ' + self.config.bearer_token
        assert 'cookie' not in request.headers
        path = request.url.path
        if request.method == 'GET' and request.url.params.get('action') == 'default':
            assert path == '/api/v2/cmdb/secret/database' and not request.content
            payload = defaults_response()
            payload['serial'] = SERIAL
            if self.fault == 'default':
                payload['results']['inherit-folder-ztna'] = 'disable'
        elif path.startswith('/api/v2/cmdb/system/admin/'):
            assert request.method == 'GET' and not request.content
            raw = _envelope('admin', [{'name': ACTOR, 'accprofile': 'super_admin',
                'status': 'enable', 'remote-auth': 'disable', 'wildcard': 'disable'}])
            return self.respond(raw)
        else:
            assert request.method == 'POST' and request.headers['x-http-method-override'] == 'GET'
            table = path.rsplit('/', 1)[1]
            payload = response(table)
            payload['serial'] = SERIAL
            if table == 'template':
                payload['results'] = [{'name': self.template_name, 'permissions': {'user': 'create-secret'},
                    'field': [{'name': 'Changed' if self.fault == 'template' else self.field_name,
                        'type': 'text', 'mandatory': 'enable'}], 'unknown-material': MATERIAL}]
            elif table == 'folder':
                payload['results'] = [] if request.content == reference_module._PERSONAL_BODY else [
                    {'id': 7, 'name': 'Text folder', 'parent-folder': 0, 'folder-type': 'public',
                        'permissions': {'user': 'view' if self.fault == 'folder' else 'add-secret'}}]
                payload.update(size=len(payload['results']), filtered_count=len(payload['results']))
            else:
                assert table == 'database'
                payload['results'] = [{'id': i, 'name': name, 'permissions': {'user': 'owner'},
                    'unselected': {'credential': MATERIAL}} for i, name in enumerate(self.names, 1) if name != 'Hidden']
                payload.update(size=len(self.names), filtered_count=len(payload['results']), revision='fresh')
        return self.respond(json.dumps(payload).encode())

    def respond(self, raw):
        owner = self

        class Stream(httpx.SyncByteStream):
            closed = False

            def __iter__(self):
                yield raw

            def close(self):
                self.closed = True

        stream = Stream()
        owner.streams.append(stream)
        return httpx.Response(200, headers={'content-type': 'application/json', 'set-cookie': 'blocked=value'}, stream=stream)

    def profile(self):
        folder_reader = source_module.ImportTemplateFolderSourceReader(self.config, self.actor.binding,
            connection_factory=self.connection, client_factory=self.client, clock=lambda: self.now)
        namespace_reader = current.ImportSecretNamespaceSourceReader(self.config, self.ssh, self.actor.binding,
            connection_factory=self.connection, client_factory=self.client, clock=lambda: self.now)
        return source_module._TextOnlyImportSource(folder_reader, folder_reader.read_once(),
            namespace_reader, namespace_reader.read_once())

    def disposed(self):
        self.actor.disposed()
        assert all(client.is_closed and not client.cookies for client in self.clients)
        assert all(stream.closed for stream in self.streams)
        assert all((peer.closed, peer.waited, peer.disconnected) == (1, 1, 1) for peer in self.peers)


@pytest.mark.parametrize('fault', [None, 'folder', 'template', 'default', 'collision', 'parent', 'claim'])
def test_original_text_decisions_use_fresh_native_evidence_and_allow_prior_name_growth(
        tmp_path, monkeypatch, caplog, fault):
    native = NativeSources(tmp_path, monkeypatch, template_name='Synthetic Note', field_name='Contents')
    profile = native.profile()
    source, _, _ = prepared(tmp_path)
    values = [row(**{'Secret Template': native.template_name, 'Name': name, 'Folder': 'Text folder',
        'Username': '', 'Password/Passphrase': '', 'URL': '', 'Port': '', 'Text': 'SYNTHETIC_PROTECTED_TEXT'})
        for name in ('Original first', 'Original second')]
    raw = csv_bytes(values)
    source.path.write_bytes(raw)
    source = replace(source, file_sha256=hashlib.sha256(raw).hexdigest())
    qualified = profile.resolve_once(decode(tmp_path, raw), expected_file_digest=source.file_sha256,
        scope_digest=source.scope_digest)
    parent_store, _, _ = _new_store(tmp_path, monotonic_checkpoint=_ExternalCheckpoint(),
        checkpoint_store_ref=PARENT_STORE, now_epoch=1000)
    key = tmp_path / 'namespace.key'
    key.write_bytes(b'i' * 32)
    key.chmod(0o600)
    original = original_module._bind_original_import_metadata(source, qualified.projected, qualified.catalog,
        original_plan_ref='file-import-parent-current', authenticated_requester_digest='7' * 64,
        parent_idempotency_digest='8' * 64, key_path=key, key_sha256=hashlib.sha256(b'i' * 32).hexdigest())
    parent = _build_file_import_parent(original, source, qualified.projected, qualified.catalog,
        source_policy_digest='a' * 64, owner_decision_digest='b' * 64, created_at=1000, expires_at=1060,
        standing_lab_authorization=True)
    parent_store.put_file_import_parent(parent)
    parent_store.put_original_import_binding(OriginalImportBindingRecord(plan_digest=parent.plan_digest,
        namespace_key_digest=original._key.digest, **asdict(original._operation)))
    execution = _store(tmp_path, monotonic_checkpoint=_ExternalM4Checkpoint(), checkpoint_store_ref=CHECKPOINT_STORE_REF)
    payload = defaults_response()
    payload['serial'] = SERIAL
    defaults = current._project_build29_secret_wire_defaults(bytearray(json.dumps(payload).encode()),
        serial_digest=hashlib.sha256(SERIAL.encode()).hexdigest())
    no_io = (len(native.requests), len(native.actor.calls), len(native.peers))
    reader = current._OriginalRowNativeCurrent(original, source, qualified.projected, qualified.catalog,
        parent_store, execution, profile, qualified, defaults, index=1, expected_parent_digest=parent.plan_digest,
        authenticated_requester_digest=parent.requester_digest, clock=lambda: native.now, wall_clock=lambda: 1000)
    assert no_io == (len(native.requests), len(native.actor.calls), len(native.peers))
    issuer = _OriginalRowM4Authority(original, source, qualified.projected, qualified.catalog,
        parent_store, execution, reader, index=1, expected_parent_digest=parent.plan_digest,
        authority_key=b'j' * 32, authenticated_requester_digest=parent.requester_digest,
        transport_digest='9' * 64, execution_enabled=True, clock=lambda: 1000)
    cleared = []
    wipe = current._wipe

    def clear(raw):
        cleared.append(raw)
        wipe(raw)

    monkeypatch.setattr(current, '_wipe', clear)
    loads = json.loads

    def selected_only(raw, *args, **kwargs):
        assert MATERIAL not in str(raw) and 'SYNTHETIC_PROTECTED_TEXT' not in str(raw)
        assert 'Synthetic forbidden default material' not in str(raw)
        return loads(raw, *args, **kwargs)

    monkeypatch.setattr(json, 'loads', selected_only)
    caplog.set_level(logging.DEBUG)
    pins = issuer.issue()
    assert execution.claim_count == 0 and len(native.peers) == 2
    deadline = reader._deadline
    native.now += 0.01
    if fault == 'parent':
        parent_store.invalidate_plan(parent.plan_ref, evaluated_at=1000, reason_codes=('current_state_drift',))
    elif fault == 'claim':
        result = M4ExecutionResult(M4Outcome.RECONCILIATION_REQUIRED, M4Verification.UNKNOWN,
            M4Compensation.NOT_REQUESTED, False)
        execution.claim(plan_ref=parent.plan_ref, requester_digest=parent.requester_digest,
            idempotency_digest=reader._row.idempotency_digest, context_digest='a' * 64, authorization_digest='b' * 64)
        execution.finalize(plan_ref=parent.plan_ref, requester_digest=parent.requester_digest,
            idempotency_digest=reader._row.idempotency_digest, context_digest='a' * 64, result=result,
            event=_event(outcome=result.outcome, verification=result.verification))
    elif fault == 'collision':
        native.names.append('ORIGINAL SECOND')
    else:
        native.fault = fault
    if fault is None:
        prior = original.row(0)
        execution.claim(plan_ref=parent.plan_ref, requester_digest=parent.requester_digest,
            idempotency_digest=prior.idempotency_digest, context_digest='a' * 64, authorization_digest='b' * 64)
        execution.finalize(plan_ref=parent.plan_ref, requester_digest=parent.requester_digest,
            idempotency_digest=prior.idempotency_digest, context_digest='a' * 64, result=_result(), event=_event())
        native.names.append('Original first')
        assert reader.read_current(pins.plan) == pins.plan.expected_current_digest
        assert reader._deadline == deadline and len(native.peers) == 3
        execution.claim(plan_ref=parent.plan_ref, requester_digest=parent.requester_digest,
            idempotency_digest=reader._row.idempotency_digest, context_digest='c' * 64, authorization_digest='d' * 64)
        assert reader.read_current(pins.plan) == pins.plan.expected_current_digest
        assert len(native.peers) == 4
        with pytest.raises(current.BulkImportIntakeError):
            reader.read_postcondition(pins.plan)
    else:
        with pytest.raises(current.BulkImportIntakeError):
            reader.read_current(pins.plan)
    before = (len(native.requests), len(native.actor.calls), len(native.peers))
    with pytest.raises(current.BulkImportIntakeError):
        reader.read_current(pins.plan)
    assert before == (len(native.requests), len(native.actor.calls), len(native.peers))
    assert all(request.method == 'GET' or request.headers.get('x-http-method-override') == 'GET'
        for request in native.requests)
    assert all(not any(raw) for raw in cleared)
    assert MATERIAL not in caplog.text and 'synthetic-token' not in caplog.text and 'SYNTHETIC_PROTECTED_TEXT' not in caplog.text
    native.disposed()
    reader.close()
