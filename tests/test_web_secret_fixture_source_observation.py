"""Original source capture and separate disposal; all device I/O is synthetic."""
from dataclasses import replace
import json
import ssl
import http.client

import pytest

from fortipam_mcp import web_secret_create_ack as ack
from fortipam_mcp import web_secret_fixture_api_preservation_reader as reader
from fortipam_mcp import web_secret_fixture_recovery_guard as guard_module
from fortipam_mcp import web_secret_fixture_recovery_runtime as recovery
from fortipam_mcp.web_secret_fixture_lifecycle import WebSecretFixtureLifecycleError
from fortipam_mcp.web_secret_fixture_recovery_authority import WebSecretFixtureRecoveryAuthority
from test_instruction_feature_http_reader import Client, Response
from test_secret_instruction_build29_api_preservation import _source, _raw, PASSWORD
from test_web_secret_create_ack import AckResponse, _envelope
from test_web_secret_fixture_creation import SERIAL_DIGEST
from test_web_secret_fixture_creation_capture import _fixture as creation_fixture
from test_web_secret_fixture_lifecycle import fixture as lifecycle_fixture
from test_web_secret_fixture_recovery_runtime import NativeConnection


def source_fixture(tmp_path, monkeypatch, status="OK", *, normal=False):
    bind, factory, directory, store, create, metadata, _, _ = creation_fixture(tmp_path, monkeypatch)
    factory._web_fixture_capture = replace(factory._web_fixture_capture,
        ack_capture=ack.WebSecretCreateAckCapture(SERIAL_DIGEST, status if normal else None, observe_source=not normal))
    create.response = AckResponse(_raw(_envelope(status=status)))
    capture = bind()
    assert capture.execute_bound()["outcome"] == "succeeded"
    record = capture._record
    original = record.read_acknowledged_creation()
    assert original.acknowledgement.observed_status == (None if normal else status)
    row = _source("")
    row["serial"] = "unit-appliance"
    row["results"][0].update(json.loads(original.creation.baseline_json))
    base = dict(http_method="POST", http_status=200, status="OK", **{"secret-id": 37})
    password = _raw({**base, "field-id": 1, "msg": "Synthetic Password source", "results": PASSWORD})
    totp = _raw({**base, "msg": "Synthetic TOTP source", "results": ""})
    def client():
        return Client([Response(_raw(row)), Response(password), Response(totp), Response(_raw(row)),
            Response(totp), Response(password), Response(_raw(row))])
    clients = [client() for _ in range(4)]
    pending = iter(clients)
    def http_factory(**kwargs):
        return next(pending)
    monkeypatch.setattr(reader, "_ssl_context", lambda _: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    monkeypatch.setattr(recovery, "_ssl_context", lambda _: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    observer = reader.WebSecretFixtureApiPreservationReader(record, instruction_profile_name="",
        credential_envelope={**base, "field-id":1, "msg":"Synthetic Password source"} if normal else None,
        totp_envelope={**base, "msg":"Synthetic TOTP source"} if normal else None,
        phase="baseline" if normal else "source", client_factory=http_factory)
    return observer, record, http_factory, clients, directory, store, create, factory


def test_separate_readonly_reconciliation_cannot_replace_the_original_source_or_grant_recovery(tmp_path, monkeypatch):
    observer, record, http_factory, clients, directory, store, create, factory = source_fixture(tmp_path, monkeypatch)
    observer.read_once()
    original_source = (directory / 'api-preservation.source.attempt').read_bytes()
    original_store = (store._path.read_bytes(), store.claim_count, store.audit_events)
    reconciliation = reader.WebSecretFixtureApiPreservationReader(record, instruction_profile_name='',
        credential_envelope=None, totp_envelope=None, phase='reconciliation', client_factory=http_factory)
    reconciliation.read_once()
    password, totp = reconciliation.observed_envelopes()
    assert password['field-id'] == 1 and 'field-id' not in totp
    assert (directory / 'api-preservation.reconciliation.attempt').is_file()
    with pytest.raises(guard_module.WebSecretFixtureRecoveryGuardError):
        guard_module.WebSecretFixtureRecoveryGuard(record, credential_envelope=password, totp_envelope=totp,
            source_observer=reconciliation, client_factory=http_factory, clock=factory._clock)
    restarted = reader.WebSecretFixtureApiPreservationReader(record, instruction_profile_name='',
        credential_envelope=None, totp_envelope=None, phase='reconciliation', client_factory=http_factory)
    with pytest.raises(reader.WebSecretFixtureApiPreservationReadError): restarted.read_once()
    assert (directory / 'api-preservation.source.attempt').read_bytes() == original_source
    assert (store._path.read_bytes(), store.claim_count, store.audit_events) == original_store
    assert len(clients[0].calls) == len(clients[1].calls) == 7 and not clients[2].calls
    assert create.posts == 1


@pytest.mark.parametrize("status", ["OK", "success"])
@pytest.mark.parametrize("readback_fault", [None, "once", "exhausted", "malformed"])
def test_original_source_responses_then_separate_full_preservation_disposal(tmp_path, monkeypatch, status, readback_fault):
    observer, record, http_factory, clients, directory, store, create, factory = source_fixture(
        tmp_path, monkeypatch, status)
    with pytest.raises(reader.WebSecretFixtureApiPreservationReadError):
        observer.observed_envelopes()
    observer.read_once()
    password, totp = observer.observed_envelopes()
    assert password["msg"] != totp["msg"] and "results" not in password
    assert password["field-id"] == 1 and "field-id" not in totp
    original_seals = [(directory / name).read_bytes() for name in ("creation.record", "creation.ack")]
    guard = guard_module.WebSecretFixtureRecoveryGuard(record, credential_envelope=password,
        totp_envelope=totp, source_observer=observer, client_factory=http_factory, clock=factory._clock)
    authority = WebSecretFixtureRecoveryAuthority(guard, authority_key=b"synthetic-source-recovery-key-0001",
        environment_ref=factory._promoter._environment_ref, scope_ref=factory._promoter._scope_ref,
        audience_ref="synthetic-source-client", requester_digest=record._execution_binding.plan.requester_digest,
        transport_digest="a" * 64, execution_enabled=True)
    events = []
    get_count = 2 if readback_fault == "once" else 3 if readback_fault == "exhausted" else 1
    connections = [NativeConnection("DELETE", events)] + [NativeConnection("GET", events) for _ in range(get_count)]
    failures = connections[1:2] if readback_fault == "once" else connections[1:] if readback_fault == "exhausted" else []
    for connection in failures:
        def disconnected(connection=connection):
            connection.response.close()
            raise http.client.RemoteDisconnected("Synthetic absence connection failure")
        connection.getresponse = disconnected
    if readback_fault == "malformed":
        connections[1].response.raw = connections[1].response.raw.replace(b'"Not Found"', b'"invalid"')
    connections[0].response.raw = connections[0].response.raw.replace(b'"success"', json.dumps(status).encode())
    native = iter(connections)
    runtime = recovery.WebSecretFixtureRecoveryRuntime(guard, authorization_verifier=authority,
        observe_delete_source=True, execution_enabled=True, connection_factory=lambda *a, **k: next(native))
    with pytest.raises(recovery.WebSecretFixtureRecoveryError):
        runtime.observed_delete_status()
    issued = authority.issue(runtime, requester_digest=record._execution_binding.plan.requester_digest,
        transport_digest="a" * 64)
    assert issued.plan.action_id == recovery.SOURCE_ACTION and issued.plan.adapter_ref == recovery.SOURCE_ADAPTER
    assert issued.plan.action_version == "2.0.0"
    result = runtime.execute(issued.plan, issued.authorization).as_dict()
    if readback_fault in {"exhausted", "malformed"}:
        assert result["outcome"] == "reconciliation_required" and result["verification"] == "unknown"
        assert sum(call[0] == "DELETE" for connection in connections for call in connection.calls) == 1
        assert sum(call[0] == "GET" for connection in connections for call in connection.calls) == get_count
        with pytest.raises(recovery.WebSecretFixtureRecoveryError):
            runtime.observed_delete_status()
        with pytest.raises(recovery.WebSecretFixtureRecoveryError):
            runtime.execute(issued.plan, issued.authorization)
        assert (directory / "recovery.delete.ack").exists()
        runtime.close()
        return
    assert result["outcome"] == "succeeded"
    assert runtime.observed_delete_status() == status
    assert store.claim_count == 2 and create.posts == 1
    assert all(len(c.calls) == 7 and c.is_closed and not c.cookies for c in clients)
    assert all(len(c.calls) == 1 and c.closed for c in connections)
    assert original_seals == [(directory / name).read_bytes() for name in ("creation.record", "creation.ack")]
    with pytest.raises(reader.WebSecretFixtureApiPreservationReadError):
        observer.read_once()


def test_partial_source_cannot_publish_pins_or_admit_recovery(tmp_path, monkeypatch):
    observer, record, factory, clients, *_ = source_fixture(tmp_path, monkeypatch)
    clients[0].responses[2].status_code = 403
    with pytest.raises(reader.WebSecretFixtureApiPreservationReadError):
        observer.read_once()
    with pytest.raises(reader.WebSecretFixtureApiPreservationReadError):
        observer.observed_envelopes()
    with pytest.raises(guard_module.WebSecretFixtureRecoveryGuardError):
        guard_module.WebSecretFixtureRecoveryGuard(record, credential_envelope=observer._credential_envelope,
            totp_envelope=observer._credential_envelope, source_observer=observer, client_factory=factory)
    assert len(clients[0].calls) == 3 and clients[0].is_closed
    assert not any(c.calls for c in clients[1:])


def test_changed_password_after_source_cannot_become_a_new_recovery_baseline(tmp_path, monkeypatch):
    observer, record, factory, clients, *_ = source_fixture(tmp_path, monkeypatch)
    observer.read_once()
    password, totp = observer.observed_envelopes()
    for index in (1, 5):
        clients[1].responses[index].content = clients[1].responses[index].content.replace(
            b"synthetic-password", b"changed-password")
    guard = guard_module.WebSecretFixtureRecoveryGuard(record, credential_envelope=password,
        totp_envelope=totp, source_observer=observer, client_factory=factory)
    with pytest.raises(guard_module.WebSecretFixtureRecoveryGuardError):
        guard.capture_baseline_once()
    assert guard._state == "failed" and not any(c.calls for c in clients[2:])


def test_source_capture_never_activates_normal_instruction_lifecycle(tmp_path, monkeypatch):
    construct, _, factory, *_ = lifecycle_fixture(tmp_path, monkeypatch)
    factory._web_fixture_capture = replace(factory._web_fixture_capture,
        ack_capture=ack.WebSecretCreateAckCapture(SERIAL_DIGEST, None, observe_source=True))
    with pytest.raises(WebSecretFixtureLifecycleError):
        construct()
    with pytest.raises(ack.WebSecretCreateAckError):
        ack.WebSecretCreateAckCapture(SERIAL_DIGEST, None)
    with pytest.raises(ack.WebSecretCreateAckError):
        ack.WebSecretCreateAckCapture(SERIAL_DIGEST, "OK", observe_source=True)
