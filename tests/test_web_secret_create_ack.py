"""Original native ACK metadata and signed custody with synthetic HTTP only."""
from dataclasses import replace
from decimal import Decimal
import hashlib
import http.client
import io
import json
import os
import stat

import pytest

from fortipam_mcp import web_secret_create_ack as a
from fortipam_mcp import secret_bulk_import_metadata as metadata
from fortipam_mcp import secret_create_191_http_transport as transport_module
from fortipam_mcp import web_secret_fixture_creation_record as records
from test_secret_create_191_http_transport import _MetadataTransport, _config
from test_web_secret_create_dispatch_observation import _Connection, _web_binding, _create
from test_web_secret_fixture_creation_record import _fixture as record_fixture
import test_web_secret_fixture_creation as creation_source
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome


def _envelope(serial="unit-appliance", identifier=37, status="success"):
    return {"version": "v7.0.0", "build": 29, "http_method": "POST", "http_status": 200,
        "status": status, "path": "secret", "name": "database", "vdom": "root", "serial": serial,
        "mkey": identifier, "error": 0,
        "results": {"field": [{"value": "UNIT_PROTECTED_PASSWORD"}], "seed": "UNIT_PROTECTED_TOTP"}}


def _raw(value):
    return bytearray(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode())


def _capture(serial="unit-appliance", status="success"):
    return a.WebSecretCreateAckCapture(hashlib.sha256(serial.encode()).hexdigest(), status)


class AckResponse:
    status = 200
    def __init__(self, payload=None, failure=None):
        self.payload = _raw(_envelope()) if payload is None else payload
        self.failure = failure
        self.offset = 0
        self.closed = False
        self.reads = []
        self.buffers = []
        self.headers = {"Content-Type": "application/json"}
    def getheader(self, name):
        return self.headers.get(name)
    def readinto1(self, view):
        self.reads.append(len(view))
        self.buffers.append(view.obj)
        if self.failure == "read": raise OSError("Synthetic response failure")
        count = min(len(view), len(self.payload) - self.offset)
        view[:count] = memoryview(self.payload)[self.offset:self.offset + count]
        self.offset += count
        return count
    def read(self, *_args):
        pytest.fail("No unbounded/material-returning read is allowed")
    def close(self):
        self.closed = True
        if self.failure == "response_close": raise OSError("Synthetic close failure")


def _transport(monkeypatch, connection, metadata=None, *, capture=None):
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    return transport_module.FortiPam191SecretCreateHttpTransport(_config(),
        connection_factory=lambda *_args, **kwargs: connection,
        metadata_transport=metadata or _MetadataTransport(), web_ack_capture=capture or _capture())


def _record_fixture(tmp_path, monkeypatch, identifier=37):
    class Connection(_Connection):
        def __init__(self):
            super().__init__()
            self.response = AckResponse(_raw(_envelope(identifier=identifier)))
    monkeypatch.setattr(creation_source, "_Connection", Connection)
    monkeypatch.setattr(creation_source, "_transport", _transport)
    return record_fixture(tmp_path, monkeypatch)


@pytest.mark.parametrize("status", ["OK", "success"])
def test_pinned_native_ack_decodes_only_metadata_and_wipes(tmp_path, monkeypatch, status):
    raw = _raw(_envelope(status=status))
    scalar = metadata._scalar
    decoded = []
    def observe(*args):
        value = scalar(*args)
        decoded.append(value)
        return value
    monkeypatch.setattr(metadata, "_scalar", observe)
    capture = _capture(status=status)
    result = a.consume_web_secret_create_ack(raw, capture=capture)
    assert result.native_secret_id == 37 and result.serial_digest == capture.serial_digest
    assert not raw and all(value not in decoded for value in ("UNIT_PROTECTED_PASSWORD", "UNIT_PROTECTED_TOTP"))
    assert str(result) == repr(result) == "<WebSecretCreateAcknowledgement redacted>"
    assert result.acknowledgement_digest not in repr(result)
    assert str(capture) == repr(capture) == "<WebSecretCreateAckCapture redacted>"


@pytest.mark.parametrize("field,value", [
    ("version", "v7.0.1"), ("build", 30), ("http_method", "GET"), ("http_status", 201),
    ("status", "OK"), ("path", "system"), ("name", "api-user"), ("vdom", "other"),
    ("serial", "FOREIGN"), ("mkey", 0), ("mkey", "37"), ("mkey", True), ("error", 1),
])
def test_foreign_or_unsuccessful_envelope_cannot_be_original_ack(field, value):
    envelope = _envelope()
    envelope[field] = value
    raw = _raw(envelope)
    with pytest.raises(a.WebSecretCreateAckError): a.consume_web_secret_create_ack(raw, capture=_capture())
    assert not raw


@pytest.mark.parametrize("raw", [
    b'{"mkey":37}', b'{"mkey":37,"mkey":38}', b'null', b'{"mkey":37} trailing',
    b'{"field":"\xff"}', b'x' * 16_385,
])
def test_ack_shape_ambiguity_and_limits_wipe(raw):
    owned = bytearray(raw)
    with pytest.raises(a.WebSecretCreateAckError): a.consume_web_secret_create_ack(owned, capture=_capture())
    assert not owned


@pytest.mark.parametrize("kind", ["encoding", "transfer-encoding", "content-type", "oversize", "read", "clock"])
def test_private_response_read_bounds_and_failure_erasure(kind):
    response = AckResponse()
    if kind == "encoding": response.headers["Content-Encoding"] = "gzip"
    elif kind == "transfer-encoding": response.headers["Transfer-Encoding"] = "chunked"
    elif kind == "content-type": response.headers["Content-Type"] = "text/html"
    elif kind == "oversize": response.payload = bytearray(b"x" * 16_385)
    elif kind == "read": response.failure = "read"
    values = iter([10, 41]) if kind == "clock" else None
    clock = (lambda: next(values)) if values is not None else (lambda: 10)
    with pytest.raises(a.WebSecretCreateAckError):
        a.read_web_secret_create_ack(response, capture=_capture(), timeout_seconds=30, clock=clock)
    assert all(not any(buffer) for buffer in response.buffers)
    assert all(size <= 4096 for size in response.reads)
    if kind in {"clock", "transfer-encoding"}: assert not response.reads


def test_real_chunked_http_response_refuses_before_unbounded_framing_read(monkeypatch):
    class Socket:
        def makefile(self, *_args):
            return io.BytesIO(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n0\r\n" + b"X-Trailer: unit\r\n" * 80 + b"\r\n")
    response = http.client.HTTPResponse(Socket())
    response.begin()
    assert response.chunked
    monkeypatch.setattr(response, "readinto1", lambda *_args: pytest.fail("Chunk framing must never be read"))
    try:
        with pytest.raises(a.WebSecretCreateAckError):
            a.read_web_secret_create_ack(response, capture=_capture(), timeout_seconds=30)
    finally:
        response.close()


def test_opt_in_original_transport_ack_is_published_after_all_cleanup(monkeypatch):
    connection = _Connection()
    connection.response = AckResponse()
    transport = _transport(monkeypatch, connection)
    assert _create(transport) is SecretCreateAdapterOutcome.VERIFIED_CREATED
    from test_secret_create_central_lab_provider import _request
    observation = transport.read_web_create_dispatch_observation(_web_binding(), _request())
    assert observation.native_ack.native_secret_id == 37
    assert connection.posts == 1 and connection.closed and connection.response.closed
    assert not any(connection.body) and all(not any(buffer) for buffer in connection.response.buffers)


@pytest.mark.parametrize("kind", ["status", "foreign", "read", "response_close", "connection_close"])
def test_failed_or_uncertain_original_response_has_no_ack_anchor(monkeypatch, kind):
    connection = _Connection("connection_close" if kind == "connection_close" else None)
    connection.response = AckResponse(failure=kind)
    if kind == "status": connection.response.status = 403
    elif kind == "foreign": connection.response.payload = _raw(_envelope(serial="FOREIGN"))
    transport = _transport(monkeypatch, connection)
    outcome = _create(transport)
    expected = (SecretCreateAdapterOutcome.VERIFIED_CREATED if kind == "connection_close"
                else SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED)
    assert outcome is expected and transport._web_create_observation is None
    assert connection.posts == 1 and connection.closed and connection.response.closed
    assert not any(connection.body) and all(not any(buffer) for buffer in connection.response.buffers)


def test_capture_cannot_be_used_for_legacy_web_or_userinfo(monkeypatch):
    connection = _Connection()
    connection.response = AckResponse()
    transport = _transport(monkeypatch, connection)
    legacy = replace(_web_binding(), contract_ref="fortipam-191-web-secret-create-private-v1",
                     target_product_version="1.9.1", target_product_build=None)
    assert _create(transport, binding=legacy) is SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
    assert not connection.posts and not connection.response.reads
    with pytest.raises(ValueError):
        transport_module.FortiPam191SecretCreateHttpTransport(
            replace(_config(), base_url="https://actor@synthetic.example.test"), web_ack_capture=_capture())


class _TimeoutFloat(float):
    pass


@pytest.mark.parametrize("timeout", [True, Decimal("10"), _TimeoutFloat(10)])
def test_capture_refuses_incompatible_timeout_before_connection_or_post(timeout):
    config = replace(_config(), timeout_seconds=timeout)
    connections = []
    connection = _Connection()
    def connect(*args, **kwargs):
        connections.append(True)
        return connection
    with pytest.raises(ValueError):
        transport_module.FortiPam191SecretCreateHttpTransport(config,
            connection_factory=connect, web_ack_capture=_capture())
    assert not connections and not connection.posts


def test_original_ack_seal_reloads_with_original_record_and_m4_without_replay(tmp_path, monkeypatch):
    record, inputs, config, client, connection = _record_fixture(tmp_path, monkeypatch)
    original_m4 = inputs["execution_store"]._path.read_bytes()
    creation = record.record_creation()
    acknowledged = record.read_acknowledged_creation()
    assert acknowledged.creation == creation and acknowledged.acknowledgement.native_secret_id == creation.native_secret_id
    assert repr(acknowledged) == str(acknowledged) == "<WebSecretFixtureAcknowledgedCreation redacted>"
    ack_file = inputs["directory"] / "creation.ack"
    assert stat.S_IMODE(ack_file.stat().st_mode) == 0o600
    assert b"UNIT_PROTECTED" not in ack_file.read_bytes() and b"unit-test-token" not in ack_file.read_bytes()
    original_ack = ack_file.read_bytes()
    fresh_connection = _Connection()
    fresh_transport = _transport(monkeypatch, fresh_connection)
    restarted = records.WebSecretFixtureCreationRecord(config, **{**inputs, "transport": fresh_transport})
    assert restarted.read_acknowledged_creation() == acknowledged
    assert not fresh_connection.posts and connection.posts == len(client.calls) == 1
    assert ack_file.read_bytes() == original_ack and inputs["execution_store"]._path.read_bytes() == original_m4


def test_native_ack_id_must_match_independent_metadata_before_sealing(tmp_path, monkeypatch):
    record, inputs, _, client, connection = _record_fixture(tmp_path, monkeypatch, identifier=38)
    with pytest.raises(records.WebSecretFixtureCreationRecordError): record.record_creation()
    assert (inputs["directory"] / "creation.pending").exists()
    assert not (inputs["directory"] / "creation.record").exists()
    assert not (inputs["directory"] / "creation.ack").exists()
    assert connection.posts == len(client.calls) == 1


def test_legacy_metadata_record_never_manufactures_missing_original_ack(tmp_path, monkeypatch):
    record, inputs, _, _, _ = record_fixture(tmp_path, monkeypatch)
    creation = record.record_creation()
    assert record.read_creation() == creation
    with pytest.raises(records.WebSecretFixtureCreationRecordError): record.read_acknowledged_creation()
    assert not (inputs["directory"] / "creation.ack").exists()


@pytest.mark.parametrize("kind", ["missing", "damaged", "mode", "hardlink", "pending", "missing-m4"])
def test_ack_custody_defects_never_adopt_or_replay(tmp_path, monkeypatch, kind):
    record, inputs, _, client, connection = _record_fixture(tmp_path, monkeypatch)
    record.record_creation()
    path = inputs["directory"] / "creation.ack"
    if kind == "missing": path.unlink()
    elif kind == "damaged": path.write_bytes(b"damaged")
    elif kind == "mode": path.chmod(0o644)
    elif kind == "hardlink": os.link(path, tmp_path / "other")
    elif kind == "pending": (inputs["directory"] / "creation.pending").touch(mode=0o600)
    else: inputs["execution_store"]._path.unlink()
    with pytest.raises(records.WebSecretFixtureCreationRecordError): record.read_acknowledged_creation()
    assert connection.posts == len(client.calls) == 1


def test_ack_modified_payload_is_denied_before_json_decode(tmp_path, monkeypatch):
    record, inputs, _, _, _ = _record_fixture(tmp_path, monkeypatch)
    creation = record.record_creation()
    (inputs["directory"] / "creation.ack").write_bytes(b"damaged" * 40)
    monkeypatch.setattr(records.json, "loads", lambda *_args: pytest.fail("Seal must verify before decode"))
    with pytest.raises(records.WebSecretFixtureCreationRecordError): record._read_ack(creation, None)


@pytest.mark.parametrize("kind", ["bearer", "status"])
def test_changed_startup_source_cannot_adopt_original_ack(tmp_path, monkeypatch, kind):
    record, inputs, config, _, _ = _record_fixture(tmp_path, monkeypatch)
    creation = record.record_creation()
    capture = _capture(status="OK") if kind == "status" else _capture()
    if kind == "bearer": config = replace(config, bearer_token="different-unit-token")
    other = transport_module.FortiPam191SecretCreateHttpTransport(config, web_ack_capture=capture)
    restarted = records.WebSecretFixtureCreationRecord(config, **{**inputs, "transport": other})
    assert restarted.read_creation() == creation
    with pytest.raises(records.WebSecretFixtureCreationRecordError): restarted.read_acknowledged_creation()


def test_ack_write_failure_retains_pending_and_cannot_repeat_get(tmp_path, monkeypatch):
    record, inputs, _, client, connection = _record_fixture(tmp_path, monkeypatch)
    original_open = records.os.open
    def open_file(path, flags, *args, **kwargs):
        if path == "creation.ack" and flags & os.O_CREAT: raise OSError("Synthetic ACK write failure")
        return original_open(path, flags, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(records.os, "open", open_file)
        with pytest.raises(records.WebSecretFixtureCreationRecordError): record.record_creation()
    assert (inputs["directory"] / "creation.pending").exists()
    with pytest.raises(records.WebSecretFixtureCreationRecordError): record.record_creation()
    with pytest.raises(records.WebSecretFixtureCreationRecordError): record.read_acknowledged_creation()
    assert connection.posts == len(client.calls) == 1


def test_explicit_factory_keeps_original_c3_m4_and_captures_ack_once(tmp_path, monkeypatch):
    from test_web_secret_fixture_creation_capture import _fixture as factory_fixture
    bind, factory, directory, store, connection, client, bodies, _ = factory_fixture(tmp_path, monkeypatch)
    factory._web_fixture_capture = replace(factory._web_fixture_capture, ack_capture=_capture())
    connection.response = AckResponse()
    original_request = connection.request
    def request(method, path, body, headers):
        assert (directory / "creation.attempt").exists()
        assert headers["Accept-Encoding"] == "identity"
        return original_request(method, path, body, headers)
    connection.request = request
    runner = bind()
    result = runner.execute_bound()
    assert result["outcome"] == "succeeded" and result["verification"] == "verified"
    evidence = runner.read_acknowledged_creation()
    assert evidence.creation.native_secret_id == evidence.acknowledgement.native_secret_id == 37
    assert (directory / "creation.ack").exists() and not (directory / "creation.pending").exists()
    assert connection.posts == len(client.calls) == 1 and all(not any(body) for body in bodies)
    assert runner.execute_bound()["idempotent_replay"] is True
    assert connection.posts == len(client.calls) == 1


def test_ack_source_serial_mismatch_is_refused_before_factory_dispatch(tmp_path, monkeypatch):
    from test_web_secret_fixture_creation_capture import _fixture as factory_fixture
    from fortipam_mcp.secret_onboarding_action_sequence import OnboardingActionCoordinatorError
    bind, factory, _, _, connection, client, _, _ = factory_fixture(tmp_path, monkeypatch)
    factory._web_fixture_capture = replace(factory._web_fixture_capture, ack_capture=_capture(serial="FOREIGN"))
    with pytest.raises(OnboardingActionCoordinatorError): bind()
    assert not connection.posts and not client.calls


def test_existing_ack_refuses_factory_before_original_post(tmp_path, monkeypatch):
    from test_web_secret_fixture_creation_capture import _fixture as factory_fixture
    from fortipam_mcp.web_secret_fixture_creation_capture import WebSecretFixtureCaptureError
    bind, factory, directory, _, connection, client, _, _ = factory_fixture(tmp_path, monkeypatch)
    factory._web_fixture_capture = replace(factory._web_fixture_capture, ack_capture=_capture())
    (directory / "creation.ack").write_bytes(b"orphaned-unit-ack")
    runner = bind()
    with pytest.raises(WebSecretFixtureCaptureError): runner.execute_bound()
    assert not connection.posts and not client.calls
    assert not (directory / "creation.attempt").exists()
