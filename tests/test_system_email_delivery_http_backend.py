"""Local fixed-POST composition, including loopback SMTP; no appliance or external mail."""
import asyncio
from contextlib import ExitStack
from dataclasses import replace
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import smtplib
import socket
import ssl
from threading import Thread
import time
import tempfile
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from fortipam_mcp.http_server import create_http_app
from fortipam_mcp.local_oauth import LocalOAuthProvider
from fortipam_mcp.system_email_capture_evidence import SystemEmailCaptureEvidenceReader
from fortipam_mcp.system_email_smtp_capture import LoopbackSystemEmailSmtpCapture, LoopbackSystemEmailSmtpReservation
from fortipam_mcp.system_email_authority import SystemEmailProtectedLabAuthority, PURPOSES
from fortipam_mcp.system_email_persistence import SystemEmailExecutionStoreSettings, open_system_email_execution_stores
from fortipam_mcp.reference_authority_sidecar import UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings, create_reference_authority_sidecar_app
from fortipam_mcp.planning_checkpoint_sidecar import UnixPlanningCheckpointClientSettings, create_checkpoint_sidecar_app
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.system_email_configuration_http_backend import SystemEmailConfigurationHttpBackend
from fortipam_mcp.system_email_configuration_transition import prepare_system_email_transition
from fortipam_mcp.system_email_delivery_contract import (
    SystemEmailCaptureObservation, SystemEmailDeliveryBinding, TEST_MESSAGE_PATH,
)
from fortipam_mcp.system_email_delivery_http_backend import (
    SystemEmailDeliveryHttpBackend, SystemEmailDeliveryHttpError, SystemEmailDeliverySourceObservation,
)
from fortipam_mcp.system_email_local_mcp_action import SystemEmailLocalMcpAction, register_system_email_local_candidate_tools
from fortipam_mcp.system_email_local_workflow import SystemEmailLocalWorkflow
from fortipam_mcp.system_email_m4_adapter import system_email_execution_digests
from fortipam_mcp.system_email_native_source import SystemEmailNativeSource, _PATH, _SCHEMA
from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
from test_ldap_server_mcp_action import _call, _login
from test_secret_bulk_import_action_process import tls_material
from test_system_email_configuration_http_backend import acknowledgement, make_http
from test_system_email_local_mcp_action import assemble
from test_system_email_local_workflow import Authority, IDENTITY, run
from test_system_email_m4_adapter import BINDING, Clock, store_at
from test_system_email_native_source import Peer
from test_system_email_smtp_capture import Sender
from test_system_email_authority import authority_store, unix_app, owner_file, ENVIRONMENT, SCOPE, AUDIENCE, REFERENCE_AUTHORITY
from v4_planning import canonical_digest, PersistentPlanningCheckpointAuthority


def delivery_ack():
    # Local monitor candidate only. No native ACK producer has been qualified.
    return dict(http_method='POST', http_status=200, status='success', serial='SYNTHETIC01',
        version='v7.0.0', build=29, path='system', name='debug', action='email')


class Evidence:
    """Separate synthetic receiver/sender sources, never a real queue probe."""
    def __init__(self, clock):
        self.clock = clock; self.calls = 0; self.messages = 0; self.pending = 0
        self.fault = 'none'; self.capture_complete = self.sender_complete = True
    def observe(self, binding):
        self.calls += 1
        if self.fault == 'error': raise RuntimeError('SYNTHETIC_PRIVATE_RECEIVER')
        now = self.clock()
        value = SystemEmailDeliverySourceObservation('c'*64, 'd'*64, binding.parameters_digest,
            SystemEmailCaptureObservation(binding.capture_scope_digest, binding.recipient_digest,
                'e'*64, self.messages, self.capture_complete), self.pending, self.sender_complete, now, now+10)
        if self.fault in ('capture_source_digest', 'sender_source_digest', 'binding_digest'):
            value = replace(value, **{self.fault: 'f'*64})
        if self.fault in ('capture_scope_digest', 'recipient_digest', 'window_digest'):
            value = replace(value, capture=replace(value.capture, **{self.fault: 'f'*64}))
        if self.fault == 'stale': value = replace(value, observed_at=now-20, expires_at=now-10)
        if self.fault == 'future': value = replace(value, observed_at=now+1, expires_at=now+11)
        return value


def workflow_with_delivery(tmp_path, configuration, change, store, evidence, *,
                           identity=IDENTITY, clock=None, factory=http.client.HTTPSConnection,
                           http_clock=time.monotonic, enabled=True, source_bound=True, evidence_factory=None,
                           delivery_store_override=None, policy_factory=None):
    clock = clock or Clock()
    context = canonical_digest({'binding': BINDING, 'requester': identity['requester_digest'],
        'transport': identity['transport_digest']})
    binding = SystemEmailDeliveryBinding('a'*48, 'b'*64, change.original.source_serial_digest,
        system_email_execution_digests(change, context)[1])
    capture_source = 'c'*64
    if evidence_factory is not None:
        evidence, capture_source = evidence_factory(binding)
    delivery = SystemEmailDeliveryHttpBackend(configuration, binding, evidence,
        capture_source_digest=capture_source, sender_source_digest='d'*64, window_digest='e'*64,
        execution_enabled=(lambda: True) if enabled else None,
        source_guard=(lambda: True) if source_bound else None,
        connection_factory=factory, http_clock=http_clock, clock=clock)
    if delivery_store_override is None:
        root = tmp_path/'delivery'; root.mkdir(mode=0o700)
        send_store = store_at(root, key_material=b'synthetic-mail-delivery-state-key-02',
            store_ref='system-email-local-delivery-ledger')
    else: send_store = delivery_store_override
    authority = policy_factory(binding, delivery, send_store) if policy_factory is not None else Authority()
    workflow = SystemEmailLocalWorkflow(change, configuration, store, binding_digest=BINDING,
        allowed_requester_digest=identity['requester_digest'], allowed_transport_digest=identity['transport_digest'],
        authority=authority, update_enabled=True, restore_enabled=True, clock=clock,
        delivery_binding=binding, delivery_backend=delivery, delivery_store=send_store, delivery_enabled=True)
    return workflow, delivery, send_store


def make(tmp_path, *, enabled=True, source_bound=True):
    peer, configuration, _, store, change = make_http(tmp_path)
    clock = Clock(); evidence = Evidence(clock); peer.posts = []
    def post_factory(*args, **kwargs):
        connection = peer.write_factory(*args, **kwargs)
        def request(method, path, *, body, headers):
            assert method == 'POST' and path == TEST_MESSAGE_PATH
            assert headers['Authorization'] == 'Bearer synthetic-token'
            peer.body_buffers.append(body); peer.posts.append(json.loads(body))
            evidence.messages += 1
        connection.request = request
        return connection
    workflow, delivery, send_store = workflow_with_delivery(tmp_path, configuration, change, store, evidence,
        clock=clock, factory=post_factory, http_clock=peer.http_clock, enabled=enabled, source_bound=source_bound)
    return peer, configuration, workflow, delivery, store, send_store, evidence


def send(workflow, peer):
    peer.ack = delivery_ack()
    return run(workflow, 'test-delivery')


def test_fixed_test_post_has_independent_capture_and_cleanup(tmp_path):
    peer, configuration, workflow, delivery, store, send_store, evidence = make(tmp_path)
    assert run(workflow, 'update')[0]['outcome'] == 'succeeded'
    assert send(workflow, peer)[0]['outcome'] == 'succeeded'
    assert peer.posts == [{'email': workflow._delivery_binding._recipient()}]
    assert delivery._ack.request_digest == workflow._delivery_binding.request_digest
    assert set(configuration._acks) == {'update'} and evidence.messages == 1
    peer.ack = acknowledgement()
    assert run(workflow, 'restore')[0]['outcome'] == 'succeeded'
    assert workflow.outcome(**IDENTITY)['workflow_outcome'] == 'verified_locally'
    assert store.claim_count == 2 and send_store.claim_count == 1
    assert all(resource.closed for resource in peer.http_resources)
    assert all(not any(raw) for raw in peer.body_buffers + peer.http_buffers)


@pytest.mark.parametrize('fault', [
    'capture_source_digest', 'sender_source_digest', 'binding_digest', 'capture_scope_digest',
    'recipient_digest', 'window_digest', 'stale', 'future', 'error',
])
def test_unbound_stale_or_foreign_evidence_prevents_preview_and_post(tmp_path, fault):
    peer, _, workflow, _, _, send_store, evidence = make(tmp_path)
    run(workflow, 'update'); evidence.fault = fault
    with pytest.raises(ValueError) as error: workflow.preview('test-delivery', **IDENTITY)
    assert 'SYNTHETIC_PRIVATE_RECEIVER' not in str(error.value)
    assert peer.posts == [] and send_store.claim_count == 0


@pytest.mark.parametrize('field,value', [('pending', 1), ('sender_complete', False), ('capture_complete', False)])
def test_capture_or_sender_incompleteness_does_not_become_send_authority(tmp_path, field, value):
    peer, _, workflow, _, _, send_store, evidence = make(tmp_path)
    run(workflow, 'update'); setattr(evidence, field, value)
    with pytest.raises(ValueError): workflow.preview('test-delivery', **IDENTITY)
    assert peer.posts == [] and send_store.claim_count == 0


def test_receiver_and_sender_observations_require_distinct_source_namespaces(tmp_path):
    peer, configuration, workflow, _, _, _, evidence = make(tmp_path)
    with pytest.raises(SystemEmailDeliveryHttpError):
        SystemEmailDeliveryHttpBackend(configuration, workflow._delivery_binding, evidence,
            capture_source_digest='c'*64, sender_source_digest='c'*64, window_digest='e'*64)
    assert evidence.calls == 0 and peer.posts == []


@pytest.mark.parametrize('enabled,source_bound', [(False, True), (True, False)])
def test_delivery_http_requires_its_own_gate_and_source_binding(tmp_path, enabled, source_bound):
    peer, _, workflow, delivery, _, send_store, _ = make(tmp_path, enabled=enabled, source_bound=source_bound)
    run(workflow, 'update')
    result, _ = send(workflow, peer)
    assert result['outcome'] != 'succeeded' and delivery._ack is None
    assert peer.posts == [] and send_store.claim_count == 1


@pytest.mark.parametrize('field,value', [('action', 'other'), ('http_method', 'PUT'), ('name', 'email-server'),
    ('results', {'password': 'SYNTHETIC_C3_SENTINEL'})])
def test_monitor_ack_contract_is_not_configuration_ack_or_mail_delivery(tmp_path, field, value, monkeypatch):
    peer, _, workflow, delivery, _, _, _ = make(tmp_path)
    run(workflow, 'update'); peer.ack = {**delivery_ack(), field: value}
    decode = json.loads
    def selected_decoder(raw, *args, **kwargs):
        assert 'SYNTHETIC_C3_SENTINEL' not in str(raw)
        return decode(raw, *args, **kwargs)
    monkeypatch.setattr(json, 'loads', selected_decoder)
    result, authorization = run(workflow, 'test-delivery')
    assert result['outcome'] != 'succeeded' and delivery._ack is None
    assert workflow.execute('test-delivery', authorization['authorization_ref'], **IDENTITY)['idempotent_replay']
    assert len(peer.posts) == 1


@pytest.mark.parametrize('fault', ['empty', 'incomplete-and-pending'])
def test_complete_http_ack_cannot_replace_capture_or_quiescence(tmp_path, fault):
    peer, _, workflow, delivery, store, _, evidence = make(tmp_path)
    run(workflow, 'update')
    original_factory = delivery._http._factory
    def factory(*args, **kwargs):
        connection = original_factory(*args, **kwargs); original_request = connection.request
        def request(*args, **kwargs):
            original_request(*args, **kwargs)
            if fault == 'empty': evidence.messages = 0
            else: evidence.capture_complete = False; evidence.pending = 1
        connection.request = request
        return connection
    delivery._http._factory = factory
    result, authorization = send(workflow, peer)
    assert result['outcome'] != 'succeeded' and delivery._ack is not None
    if fault == 'incomplete-and-pending':
        with pytest.raises(ValueError): workflow.preview('restore', **IDENTITY)
    assert store.claim_count == 1
    evidence.pending = 0; peer.ack = acknowledgement()
    assert run(workflow, 'restore')[0]['outcome'] == 'succeeded'
    assert workflow.outcome(**IDENTITY)['phase_verified_locally']['test-delivery'] is False
    assert workflow.execute('test-delivery', authorization['authorization_ref'], **IDENTITY)['idempotent_replay']
    assert len(peer.posts) == 1


def test_foreign_binding_and_missing_original_configuration_ack_deny_before_post(tmp_path):
    peer, configuration, workflow, delivery, _, send_store, _ = make(tmp_path)
    run(workflow, 'update')
    with pytest.raises(SystemEmailDeliveryHttpError):
        delivery.send_test(replace(workflow._delivery_binding), before_send=lambda: 5, timeout_seconds=5)
    configuration._acks.clear()
    assert send(workflow, peer)[0]['outcome'] != 'succeeded'
    assert len(peer.posts) == 0 and send_store.claim_count == 1


@pytest.mark.parametrize('fault', ['none', 'lost-ack'])
@pytest.mark.parametrize('protected_policy', [False, True])
def test_real_loopback_https_oauth_mcp_configure_send_restore(monkeypatch, tmp_path, fault, protected_policy):
    ca, key = tls_material(tmp_path); peer = Peer(); posts = []
    clock = lambda: int(time.time())
    sender = Sender(clock)  # The fake product sends synchronously and has no queue.
    stack = ExitStack()
    receiver = None
    reservation = LoopbackSystemEmailSmtpReservation()
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *_): pass
        def send(self, value):
            raw = json.dumps(value).encode()
            self.send_response(200); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw))); self.send_header('Connection', 'close')
            self.end_headers(); self.wfile.write(raw)
        def do_GET(self):
            assert self.headers['Authorization'] == 'Bearer synthetic-token'
            assert self.path in (_PATH, _SCHEMA)
            self.send(peer.schema if self.path == _SCHEMA else peer.body)
        def do_PUT(self):
            assert self.path == _PATH and self.headers['Authorization'] == 'Bearer synthetic-token'
            peer.body['results'].update(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
            self.send(acknowledgement())
        def do_POST(self):
            assert self.path == TEST_MESSAGE_PATH and self.headers['Authorization'] == 'Bearer synthetic-token'
            posts.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
            assert receiver is not None and posts[-1] == {'email': receiver._binding._recipient()}
            relay = peer.body['results']
            assert relay['server'] == '127.0.0.1' and relay['security'] == 'none' and relay['authenticate'] == 'disable'
            sender.pending += 1
            try:
                with smtplib.SMTP(relay['server'], relay['port'], timeout=3, local_hostname='sender.invalid') as smtp:
                    smtp.sendmail('sender@example.invalid', posts[-1]['email'],
                        b'Subject: Synthetic local test\r\n\r\nSYNTHETIC_PRIVATE_BODY\r\n')
            finally:
                sender.pending -= 1
            if fault == 'lost-ack': self.close_connection = True
            else: self.send(delivery_ack())
    product = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(ca, key)
    product.socket = tls.wrap_socket(product.socket, server_side=True)
    thread = Thread(target=product.serve_forever, daemon=True); thread.start()
    connections = []
    def connection_factory(host, port, **kwargs):
        connection = http.client.HTTPSConnection(host, port, **kwargs)
        connection._create_connection = lambda address, timeout, source_address: socket.create_connection(
            ('127.0.0.1', product.server_port), timeout, source_address)
        connections.append(connection); return connection
    try:
        reference = reference_client = cas = sockets = None
        if protected_policy:
            sockets = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='emfs-', dir='/private/tmp')))
            reference_root = tmp_path/'grants'; reference_root.mkdir(mode=0o700)
            reference = authority_store(reference_root, clock)
            cas_root = tmp_path/'cas'; cas_root.mkdir(mode=0o700)
            cas = PersistentPlanningCheckpointAuthority(cas_root/'state.db', owner_file(cas_root/'key', b'z'*32),
                authority_ref='email-full-stack-execution-cas')
            stack.enter_context(unix_app(create_reference_authority_sidecar_app(reference), sockets/'reference.sock'))
            stack.enter_context(unix_app(create_checkpoint_sidecar_app(cas), sockets/'execution.sock'))
            reference_client = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(sockets/'reference.sock', REFERENCE_AUTHORITY))
        config = SecretMetadataHttpTransportConfig(f'https://pam.example.test:{product.server_port}',
            'synthetic-token', 5, str(ca))
        source = SystemEmailNativeSource(config, expected_serial='SYNTHETIC01', connection_factory=connection_factory)
        original = source.read_empty_auth_payload()
        values = {k: v for k, v in peer.body['results'].items() if k not in ('username', 'password')}
        change = prepare_system_email_transition(original, {**values, 'server': '127.0.0.1',
            'port': reservation.port, 'security': 'none'})
        configuration = SystemEmailConfigurationHttpBackend(source, change, execution_enabled=lambda: True,
            source_guard=lambda: True, connection_factory=connection_factory)
        settings, app, server = assemble(monkeypatch, tmp_path)
        with TestClient(app, base_url='https://mcp.example.com') as client:
            headers = _login(client, 'fortipam:read fortipam:plan fortipam:operate')
            token = asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(headers['authorization'].split(' ', 1)[1]))
            principal = planning_principal_from_access_token(token, settings.v4_planning_authorization)
            identity = dict(requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest)
            send_store_override = None
            if protected_policy:
                state_settings = []
                for name, material in (('configuration', b'c'*32), ('delivery', b'd'*32)):
                    root = tmp_path/('protected-'+name); root.mkdir(mode=0o700)
                    state_settings.append(SystemEmailExecutionStoreSettings(root/'state.db', owner_file(root/'key', material),
                        UnixPlanningCheckpointClientSettings(sockets/'execution.sock', cas.authority_ref), 'email-full-stack-'+name))
                store, send_store_override = open_system_email_execution_stores(*state_settings)
            else: store = store_at(tmp_path)
            def evidence_factory(binding):
                nonlocal receiver
                receiver = LoopbackSystemEmailSmtpCapture(binding, window_digest='e'*64, _reservation=reservation).start()
                evidence = SystemEmailCaptureEvidenceReader(receiver, sender_source_digest='d'*64, sender=sender, clock=clock)
                return evidence, receiver.source_digest
            def policy_factory(binding, delivery, send_store):
                policy = SystemEmailProtectedLabAuthority(change, configuration, store, binding, delivery, send_store,
                    reference_authority=reference_client, authority_key_file=owner_file(tmp_path/'policy.key', b'p'*32),
                    binding_digest=BINDING, requester_digest=identity['requester_digest'], transport_digest=identity['transport_digest'],
                    environment_ref=ENVIRONMENT, scope_ref=SCOPE, audience_ref=AUDIENCE, window_digest='e'*64,
                    execution_enabled=True, source_guard=lambda phase: True, clock=clock)
                reference.issue_many(tuple((policy.reference_for(phase, purpose), 'system_email_'+purpose)
                    for phase in ('update', 'test-delivery', 'restore') for purpose in PURPOSES),
                    requester_digest=identity['requester_digest'], environment_ref=ENVIRONMENT, scope_ref=SCOPE,
                    expires_at=clock()+120, now_epoch=clock())
                return policy
            workflow, _, send_store = workflow_with_delivery(tmp_path, configuration, change, store, None,
                clock=clock, identity=identity, factory=connection_factory, evidence_factory=evidence_factory,
                delivery_store_override=send_store_override, policy_factory=policy_factory if protected_policy else None)
            action = SystemEmailLocalMcpAction(workflow)
            if protected_policy:
                client = stack.enter_context(TestClient(create_http_app(settings,
                    v4_system_email_local_candidate_action=action), base_url='https://mcp.example.com'))
            else: register_system_email_local_candidate_tools(server, action)
            for phase in ('update', 'test_delivery', 'restore'):
                preview = _call(client, headers, f'preview_v4_system_email_local_{phase}_700', {})
                assert not preview['isError']
                if protected_policy: assert preview['structuredContent']['authorization_policy_mode'] == 'lab_auto'
                authorization = _call(client, headers, f'authorize_v4_system_email_local_{phase}_700',
                    {'preview_ref': preview['structuredContent']['preview_ref']})
                assert not authorization['isError']
                result = _call(client, headers, f'execute_v4_system_email_local_{phase}_700',
                    {'authorization_ref': authorization['structuredContent']['authorization_ref']})
                if phase == 'test_delivery': delivery_reference = authorization['structuredContent']['authorization_ref']
                assert not result['isError']
                succeeded = phase != 'test_delivery' or fault == 'none'
                assert (result['structuredContent']['outcome'] == 'succeeded') is succeeded
            outcome = _call(client, headers, 'get_v4_system_email_local_outcome_700', {})['structuredContent']
            assert outcome['workflow_outcome'] == ('verified_locally' if fault == 'none' else 'reconciliation_required')
            assert outcome['native_delivery_qualified'] is False
            assert len(posts) == 1 and set(posts[0]) == {'email'}
            assert receiver.observe(workflow._delivery_binding).matched_messages == 1
            assert store.claim_count == 2 and send_store.claim_count == 1
            assert all(connection.sock is None for connection in connections)
            if protected_policy:
                replay = _call(client, headers, 'execute_v4_system_email_local_test_delivery_700',
                    {'authorization_ref': delivery_reference})
                assert not replay['isError'] and replay['structuredContent']['idempotent_replay']
                assert len(posts) == 1 and send_store.claim_count == 1
    finally:
        product.shutdown(); product.server_close(); thread.join(timeout=2)
        if receiver is not None: receiver.close()
        reservation.close()
        stack.close()
