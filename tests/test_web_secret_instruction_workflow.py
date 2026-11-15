"""Real original C3/M4 custody and retained-field PUTs, entirely synthetic I/O."""
import hashlib
import json
import ssl
from types import SimpleNamespace

import pytest

from fortipam_mcp import web_secret_instruction_workflow as w
from fortipam_mcp.instruction_profile_contract import InstructionPlainText, InstructionProfileCreatePlan
from fortipam_mcp.instruction_profile_live_workflow import InstructionProfileLiveWorkflow
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_instruction_profile_http_transport import Peer, Connection, Response as ProfileResponse
from test_instruction_feature_http_reader import Client, Response
from test_secret_instruction_build29_contract import SCHEMA
from test_web_secret_fixture_creation import SERIAL_DIGEST
from test_web_secret_fixture_lifecycle import fixture as lifecycle_fixture
from test_web_secret_fixture_recovery_runtime import NativeConnection


class ProfileConnection(Connection):
    def request(self, method, url, body, headers):
        assert headers['Authorization'] == 'Bearer unit-test-token'
        assert headers['Accept-Encoding'] == 'identity'
        self.response = self.peer.handle(method, url, body)


class ProfilePeer(Peer):
    def __init__(self):
        super().__init__()
        self.serial_digest = SERIAL_DIGEST
        self.binding = InstructionProfileCreatePlan('mcp-v4-ip-synthetic', 'a' * 64,
            InstructionPlainText(self.brief, self.text), self.defaults,
            schema_digest=self.schema_digest, serial_digest=self.serial_digest)

    def connection(self, host, port, **kwargs):
        assert host == 'fortipam.example.test' and port == 443
        assert kwargs['context'].check_hostname and kwargs['context'].verify_mode == ssl.CERT_REQUIRED
        connection = ProfileConnection(self)
        self.connections.append(connection)
        return connection

    def handle(self, method, url, body):
        response = super().handle(method, url, body)
        value = json.loads(response.content.getvalue())
        value['serial'] = 'unit-appliance'
        return ProfileResponse(value, response.status)


class PutConnection(NativeConnection):
    def __init__(self, peer, events):
        super().__init__('PUT', events)
        self.peer, self.bodies, self.submitted = peer, [], []
        value = json.loads(self.response.raw)
        value['mkey'] = 37
        self.response.raw = bytearray(json.dumps(value, separators=(',', ':')).encode())

    def request(self, method, path, *, body, headers):
        assert method == 'PUT' and path == '/api/v2/cmdb/secret/database/37'
        assert headers['Authorization'] == 'Bearer unit-test-token'
        assert headers['Accept-Encoding'] == 'identity'
        assert isinstance(body.obj, bytearray)
        value = json.loads(bytes(body))
        assert set(value) == {'id', 'name', 'folder', 'template', 'instruction-profile', 'field'}
        assert value['id'] == 37 and value['template'] == 'Web Account'
        assert [slot['name'] for slot in value['field']] == ['Password', 'URL', 'Username']
        assert all(set(slot) == {'id', 'name', 'value'} for slot in value['field'])
        assert value['instruction-profile'] in {'', self.peer.binding._name}
        self.bodies.append(body.obj)
        self.submitted.append(value)
        self.events.append('PUT')
        self.calls.append((method, path))
        self.peer.created['q_ref'] = int(bool(value['instruction-profile']))


def fixture(tmp_path, monkeypatch, *, enabled=True):
    original = lifecycle_fixture(tmp_path, monkeypatch)
    construct, bind, factory, directory, store, _, _, clients, _, events = original
    lifecycle = construct()
    runner, principal = bind(lifecycle)
    assert runner.execute_bound()['outcome'] == 'succeeded'
    peer = ProfilePeer()
    profile_state = tmp_path / 'profile-state'
    profile_state.mkdir(mode=0o700)
    m4_state = tmp_path / 'profile-m4'
    m4_state.mkdir(mode=0o700)
    key = m4_state / 'key'
    key.write_bytes(hashlib.sha256(b'synthetic-profile-store').digest())
    key.chmod(0o600)
    identity = dict(requester_digest=principal.requester.digest,
        transport_digest=principal.transport_namespace_digest)
    profile = InstructionProfileLiveWorkflow(peer.binding, factory._transport_config,
        serial_digest=peer.serial_digest, schema_digest=peer.schema_digest, state_directory=profile_state,
        phase='create', execution_store=PersistentM4ExecutionStateStore(m4_state / 'ledger.sqlite', key),
        authority_key=hashlib.sha256(b'synthetic-profile-authority').digest(),
        environment_ref=factory._promoter._environment_ref, scope_ref=factory._promoter._scope_ref,
        audience_ref='synthetic-profile-audience', allowed_requester_digest=identity['requester_digest'],
        allowed_transport_digest=identity['transport_digest'], execution_enabled=True,
        clock=factory._clock, connection_factory=peer.connection)
    preview = profile.preview(**identity)
    issued = profile.authorize(preview['preview_ref'], **identity)
    assert profile.execute(issued['authorization_ref'], **identity)['outcome'] == 'succeeded'
    # Queue full detail/material/detail reads for each distinct durable phase.
    def client(reference):
        responses = [Response(bytearray(item.content)) for item in clients[0].responses]
        for index in (0, 3, 6):
            value = json.loads(responses[index].content)
            value['results'][0]['instruction-profile'] = reference
            responses[index].content = bytearray(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode())
        return Client(responses)
    clients.extend(client(reference) for reference in (peer.binding._name, peer.binding._name,
        peer.binding._name, '', '', ''))
    puts = [PutConnection(peer, events), PutConnection(peer, events)]
    pending = iter(puts)
    def connection(host, port, **kwargs):
        assert host == 'fortipam.example.test' and port == 443
        assert kwargs['context'].verify_mode == ssl.CERT_REQUIRED and kwargs['context'].check_hostname
        assert 0 < kwargs['timeout'] <= 5
        return next(pending)
    monkeypatch.setattr(w, '_ssl_context', lambda _: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    arguments = dict(schema=SCHEMA, authority_key=hashlib.sha256(b'synthetic-instruction-authority').digest(),
        environment_ref=factory._promoter._environment_ref, scope_ref=factory._promoter._scope_ref,
        audience_ref='synthetic-instruction-association', success_status='success', connection_factory=connection)
    workflow = w.WebSecretInstructionWorkflow(lifecycle, profile, execution_enabled=enabled, **arguments)
    return SimpleNamespace(workflow=workflow, lifecycle=lifecycle, runner=runner, principal=principal,
        original=original, directory=directory, store=store, clients=clients, puts=puts, peer=peer,
        profile=profile, identity=identity, arguments=arguments, events=events)


def drift(client, material='password'):
    indices = (1, 5) if material == 'password' else (2, 4)
    for index in indices:
        value = json.loads(client.responses[index].content)
        value['results'] = 'changed-password' if material == 'password' else 'changed-totp'
        client.responses[index].content = bytearray(json.dumps(value, separators=(',', ':')).encode())


def test_complete_owned_roundtrip_and_original_cleanup(tmp_path, monkeypatch):
    c = fixture(tmp_path, monkeypatch)
    original = c.runner._capture._record.read_acknowledged_creation()
    seals = [(c.directory / name).read_bytes() for name in ('creation.record', 'creation.ack')]
    assert c.workflow.attach_once(c.principal) == w._SUCCESS
    attach_seals = [(c.directory / name).read_bytes() for name in ('instruction.attach.attempt', 'instruction.attach.ack')]
    assert c.runner._state == 'applied' and c.peer.created['q_ref'] == 1
    with pytest.raises(w.WebSecretInstructionWorkflowError): c.workflow.attach_once(c.principal)
    assert c.workflow.restore_once(c.principal) == w._SUCCESS
    assert c.runner._state == 'baseline' and c.peer.created['q_ref'] == 0
    with pytest.raises(w.WebSecretInstructionWorkflowError): c.workflow.restore_once(c.principal)
    assert c.lifecycle.recover_once(c.principal)['outcome'] == 'succeeded'
    assert c.store.claim_count == 4 and c.profile._execution_store.claim_count == 1
    assert [put.submitted[0]['instruction-profile'] for put in c.puts] == [c.peer.binding._name, '']
    assert c.puts[0].submitted[0]['field'] == c.puts[1].submitted[0]['field']
    assert all(len(put.calls) == 1 and put.closed and put.response.closed for put in c.puts)
    assert all(not any(body) for put in c.puts for body in put.bodies + put.response.buffers)
    assert all(len(client.calls) == 7 and client.is_closed for client in c.clients)
    assert c.runner._capture._record.read_acknowledged_creation() == original
    assert [(c.directory / name).read_bytes() for name in ('creation.record', 'creation.ack')] == seals
    assert [(c.directory / name).read_bytes() for name in ('instruction.attach.attempt', 'instruction.attach.ack')] == attach_seals
    assert c.peer.writes == ['POST']
    c.workflow.close(); c.lifecycle.close()


@pytest.mark.parametrize('fault', ['disabled', 'actor', 'restore-first', 'reader-shape', 'status', 'factory'])
def test_initial_denial_has_no_reads_claims_or_put(tmp_path, monkeypatch, fault):
    c = fixture(tmp_path, monkeypatch, enabled=fault != 'disabled')
    principal, action = c.principal, c.workflow.attach_once
    if fault == 'actor': principal = V4PlanningPrincipal(c.principal.requester, 'b' * 64)
    if fault == 'restore-first': action = c.workflow.restore_once
    if fault == 'reader-shape': c.workflow._readers.pop('restore')
    if fault == 'status': c.workflow._status = 'OK'
    if fault == 'factory': c.workflow._factory = lambda *args, **kwargs: c.puts[0]
    count = len(c.peer.calls)
    with pytest.raises(w.WebSecretInstructionWorkflowError): action(principal)
    assert c.store.claim_count == 1 and len(c.peer.calls) == count
    assert not any(client.calls for client in c.clients[1:]) and not any(put.calls for put in c.puts)
    assert not (c.directory / 'instruction.attach.attempt').exists()


@pytest.mark.parametrize('stage,material', [('current', 'password'), ('current', 'totp'),
    ('dispatch', 'password'), ('dispatch', 'totp')])
def test_independent_material_drift_prevents_put(tmp_path, monkeypatch, stage, material):
    c = fixture(tmp_path, monkeypatch)
    drift(c.clients[1 if stage == 'current' else 2], material)
    if stage == 'current':
        with pytest.raises(w.WebSecretInstructionWorkflowError): c.workflow.attach_once(c.principal)
    else:
        assert c.workflow.attach_once(c.principal)['outcome'] == 'denied'
    assert c.store.claim_count == (1 if stage == 'current' else 2)
    assert not any(put.calls for put in c.puts)
    assert not (c.directory / 'instruction.attach.ack').exists()
    with pytest.raises(w.WebSecretInstructionWorkflowError): c.workflow.attach_once(c.principal)
    with pytest.raises(w.WebSecretInstructionWorkflowError): c.workflow.restore_once(c.principal)


@pytest.mark.parametrize('stage', ['current', 'dispatch'])
def test_profile_drift_prevents_put(tmp_path, monkeypatch, stage):
    c = fixture(tmp_path, monkeypatch)
    def change(): c.peer.created['brief'] = 'Changed synthetic instructions'
    if stage == 'current': change()
    else: c.puts[0].on_connect = change
    if stage == 'current':
        with pytest.raises(w.WebSecretInstructionWorkflowError): c.workflow.attach_once(c.principal)
    else:
        assert c.workflow.attach_once(c.principal)['outcome'] == 'denied'
    assert not any(put.calls for put in c.puts)
    assert not (c.directory / 'instruction.attach.ack').exists()


def test_predispatch_denial_and_close_failure_keeps_error_private(tmp_path, monkeypatch):
    c = fixture(tmp_path, monkeypatch)
    drift(c.clients[2])
    c.puts[0].fail_close = True
    with pytest.raises(w.WebSecretInstructionWorkflowError) as caught:
        c.workflow.attach_once(c.principal)
    assert str(caught.value) == w._ERROR
    assert 'must-not-surface-private-value' not in str(caught.value)
    assert c.puts[0].closed and not c.puts[0].calls
    assert c.store.claim_count == 2 and not (c.directory / 'instruction.attach.ack').exists()
    assert c.workflow._phase.body == bytearray(len(c.workflow._phase.body))
    with pytest.raises(w.WebSecretInstructionWorkflowError): c.workflow.attach_once(c.principal)


@pytest.mark.parametrize('fault', ['foreign-id', 'status', 'response-close', 'connection-close', 'post-material'])
def test_unknown_effect_has_no_restore_or_retry_authority(tmp_path, monkeypatch, fault):
    c = fixture(tmp_path, monkeypatch)
    if fault == 'foreign-id': c.puts[0].response.raw = c.puts[0].response.raw.replace(b'"mkey":37', b'"mkey":38')
    if fault == 'status': c.puts[0].response.raw = c.puts[0].response.raw.replace(b'"status":"success"', b'"status":"OK"')
    if fault == 'response-close': c.puts[0].response.fail_close = True
    if fault == 'connection-close': c.puts[0].fail_close = True
    if fault == 'post-material': drift(c.clients[3])
    try:
        result = c.workflow.attach_once(c.principal)
    except w.WebSecretInstructionWorkflowError:
        # Resource close failures remain a categorical refusal after dispatch.
        assert fault in {'response-close', 'connection-close'}
    else: assert result['outcome'] == 'reconciliation_required'
    assert len(c.puts[0].calls) == 1 and not c.puts[1].calls and c.store.claim_count == 2
    assert (c.directory / 'instruction.attach.ack').exists() is (fault == 'post-material')
    assert all(not any(body) for body in c.puts[0].bodies + c.puts[0].response.buffers)
    with pytest.raises(w.WebSecretInstructionWorkflowError): c.workflow.attach_once(c.principal)
    with pytest.raises(w.WebSecretInstructionWorkflowError): c.workflow.restore_once(c.principal)


@pytest.mark.parametrize('fault', ['ack-tamper', 'signed-attach-tamper', 'restore-material', 'restore-dispatch-material'])
def test_restore_needs_original_attach_custody_and_complete_material(tmp_path, monkeypatch, fault):
    c = fixture(tmp_path, monkeypatch)
    assert c.workflow.attach_once(c.principal) == w._SUCCESS
    if fault == 'ack-tamper': (c.directory / 'instruction.attach.ack').write_bytes(b'0' * 64)
    elif fault == 'signed-attach-tamper':
        # A different successful original claim cannot replace the attach grant.
        c.workflow._attach.plan = c.runner._capture._record._execution_binding.plan
    else: drift(c.clients[4 if fault == 'restore-material' else 5])
    if fault == 'restore-dispatch-material':
        assert c.workflow.restore_once(c.principal)['outcome'] == 'denied'
    else:
        with pytest.raises(w.WebSecretInstructionWorkflowError): c.workflow.restore_once(c.principal)
    assert not c.puts[1].calls and c.peer.created['q_ref'] == 1
    assert c.store.claim_count == (3 if fault == 'restore-dispatch-material' else 2)
    assert not (c.directory / 'instruction.restore.ack').exists()


def test_restart_cannot_adopt_consumed_association(tmp_path, monkeypatch):
    c = fixture(tmp_path, monkeypatch)
    assert c.workflow.attach_once(c.principal) == w._SUCCESS
    c.workflow.close()
    with pytest.raises(w.WebSecretInstructionWorkflowError):
        w.WebSecretInstructionWorkflow(c.lifecycle, c.profile, execution_enabled=True, **c.arguments)
    assert c.store.claim_count == 2 and not c.puts[1].calls


@pytest.mark.parametrize('missing_length', [0, 8])
def test_native_http_response_must_complete_declared_content_length(tmp_path, monkeypatch, missing_length):
    import http.client
    import io
    c = fixture(tmp_path, monkeypatch)
    connection = c.puts[0]
    body = bytes(connection.response.raw)
    class Socket:
        def makefile(self, mode):
            return io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ' +
                str(len(body)+missing_length).encode() + b'\r\nConnection: close\r\n\r\n' + body)
    response = http.client.HTTPResponse(Socket()); response.begin()
    connection.response = response
    result = c.workflow.attach_once(c.principal)
    assert len(connection.calls) == 1 and connection.closed and response.isclosed()
    if missing_length:
        assert result['outcome'] == 'reconciliation_required' and result['verification'] == 'unknown'
        assert not (c.directory / 'instruction.attach.ack').exists()
        diagnostic = json.loads((c.directory / 'instruction.attach.failure.json').read_bytes())
        assert diagnostic == {'phase':'attach','stage':'read_body','error_class':'ValueError',
            'http_status':200,'execution_authority':False,'raw_values_returned':False}
        with pytest.raises(w.WebSecretInstructionWorkflowError): c.workflow.restore_once(c.principal)
    else:
        assert result == w._SUCCESS and (c.directory / 'instruction.attach.ack').is_file()


def test_dispatch_failure_diagnostic_never_exposes_exception_text(tmp_path, monkeypatch):
    c = fixture(tmp_path, monkeypatch)
    def unavailable(): raise OSError('synthetic-private-password-never-log')
    c.puts[0].getresponse = unavailable
    assert c.workflow.attach_once(c.principal)['outcome'] == 'reconciliation_required'
    raw = (c.directory/'instruction.attach.failure.json').read_bytes()
    value = json.loads(raw)
    assert value['stage']=='receive_headers' and value['http_status'] is None
    assert value['error_class']=='OSError' and value['execution_authority'] is False
    assert b'synthetic-private-password' not in raw and len(c.puts[0].calls)==1
    with pytest.raises(w.WebSecretInstructionWorkflowError):c.workflow.attach_once(c.principal)


@pytest.mark.parametrize('failure', [KeyboardInterrupt, SystemExit])
def test_interruption_before_body_transfer_erases_retained_values(failure):
    body = bytearray(b'synthetic-private-retained-value')
    witness = SimpleNamespace(preservation_digest='same')
    count = 0
    def local():
        nonlocal count
        count += 1
        if count == 2: raise failure()
    owner = SimpleNamespace(_local=local, _baseline=witness)
    reader = SimpleNamespace(read_instruction_update_once=lambda *args, **kwargs: (witness, body))
    with pytest.raises(failure):
        w.WebSecretInstructionWorkflow._read_body(owner, reader, '')
    assert not body
