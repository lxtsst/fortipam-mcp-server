"""Fixed private source with real local signed creation/M4 and synthetic HTTP."""
from contextlib import contextmanager
import hashlib
import json
import os
import ssl
import stat

import pytest

from fortipam_mcp import web_secret_fixture_api_preservation_reader as r
from test_instruction_feature_http_reader import Client, Response
from test_secret_instruction_build29_api_preservation import _source, _raw, PROFILE, PASSWORD
from test_web_secret_fixture_creation import SERIAL
from test_web_secret_fixture_creation_record import _fixture as record_fixture


def _fixture(tmp_path, monkeypatch, reference="", password_id=1, serial=None):
    if serial is not None:
        import test_web_secret_fixture_creation as creation_source
        monkeypatch.setattr(creation_source, "SERIAL", serial)
        monkeypatch.setattr(creation_source, "SERIAL_DIGEST", hashlib.sha256(serial.encode()).hexdigest())
    record, inputs, config, _, connection = record_fixture(tmp_path, monkeypatch)
    evidence = record.record_creation()
    baseline = json.loads(evidence.baseline_json)
    row = _source(reference)
    row["serial"] = SERIAL if serial is None else serial
    row["results"][0].update({**baseline, "instruction-profile": reference})
    row["results"][0]["field"][0].update(id=password_id, q_origin_key=password_id)
    password_pin = {"http_method": "POST", "http_status": 200, "status": "OK",
                    "secret-id": evidence.native_secret_id, "msg": "Synthetic Password source"}
    totp_pin = {**password_pin, "msg": "Synthetic TOTP source"}
    password = _raw({**password_pin, "results": PASSWORD})
    totp = _raw({**totp_pin, "results": ""})
    client = Client([Response(_raw(row)), Response(password), Response(totp), Response(_raw(row)),
                     Response(totp), Response(password), Response(_raw(row))])
    seen = []
    monkeypatch.setattr(r, "_ssl_context", lambda _: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    def factory(**kwargs):
        seen.append(kwargs)
        return client
    controller = r.WebSecretFixtureApiPreservationReader(record, instruction_profile_name=reference,
        credential_envelope=password_pin, totp_envelope=totp_pin,
        phase="applied" if reference else "baseline", client_factory=factory)
    return controller, record, inputs, config, connection, client, seen


def test_exact_seven_requests_use_original_record_and_derived_password_slot(tmp_path, monkeypatch):
    reader, record, inputs, config, connection, client, seen = _fixture(tmp_path, monkeypatch, password_id=7)
    original_file = (inputs["directory"] / "creation.record").read_bytes()
    original_m4 = inputs["execution_store"]._path.read_bytes()
    original_consume = r.consume_secret_instruction_build29_api_preservation
    buffers = []
    def consume(raw, **kwargs):
        assert client.is_closed and not client.cookies and all(response.is_closed for response in client.responses)
        buffers.append(raw)
        return original_consume(raw, **kwargs)
    monkeypatch.setattr(r, "consume_secret_instruction_build29_api_preservation", consume)
    result = reader.read_once()
    assert len(result.preservation_digest) == 64 and result.preservation_digest not in repr(result)
    assert buffers and all(not buffer for buffer in buffers)
    assert repr(reader) == str(reader) == "<WebSecretFixtureApiPreservationReader redacted>"
    assert [method for method, _, _ in client.calls] == ["GET", "POST", "POST", "GET", "POST", "POST", "GET"]
    expected_get = config.base_url + "/api/v2/cmdb/secret/database/37"
    assert [url for method, url, _ in client.calls if method == "GET"] == [expected_get] * 3
    bodies = [kwargs["json"] for method, url, kwargs in client.calls if method == "POST"]
    assert bodies == [{"secret-id": 37, "field-id": 7}, {"secret-id": 37, "totp-share-key": 1},
                      {"secret-id": 37, "totp-share-key": 1}, {"secret-id": 37, "field-id": 7}]
    assert all(url == config.base_url + r._CLEAR for method, url, _ in client.calls if method == "POST")
    for method, _, kwargs in client.calls:
        headers = kwargs["headers"]
        assert headers["Authorization"] == "Bearer " + config.bearer_token
        assert headers["Accept-Encoding"] == "identity"
        assert "Cookie" not in headers and "X-CSRFTOKEN" not in headers
        assert 0 < kwargs["timeout"] <= 10
        if method == "GET": assert "json" not in kwargs
    assert not seen[0]["follow_redirects"] and not seen[0]["trust_env"]
    assert seen[0]["verify"].check_hostname and seen[0]["verify"].verify_mode == ssl.CERT_REQUIRED
    assert seen[0]["verify"].minimum_version >= ssl.TLSVersion.TLSv1_2
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.read_once()
    assert len(client.calls) == 7 and connection.posts == 1
    assert (inputs["directory"] / "creation.record").read_bytes() == original_file
    assert inputs["execution_store"]._path.read_bytes() == original_m4
    assert record.read_creation().native_secret_id == 37


def test_applied_reference_and_volatile_direct_totp_renders(tmp_path, monkeypatch):
    reader, _, _, _, _, client, _ = _fixture(tmp_path, monkeypatch, reference=PROFILE)
    client.responses[3].content = client.responses[3].content.replace(b'"shared-key":null', b'"shared-key":"ENC VOLATILE"')
    client.responses[6].content = client.responses[6].content.replace(b'"shared-key":null', b'"shared-key":""')
    assert len(reader.read_once().preservation_digest) == 64


@pytest.mark.parametrize("index", range(7))
def test_http_failure_stops_at_that_request_without_retry(tmp_path, monkeypatch, index):
    reader, _, _, _, _, client, _ = _fixture(tmp_path, monkeypatch)
    client.responses[index].status_code = 403
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError) as caught:
        reader.read_once()
    assert str(caught.value) == r._ERROR
    assert len(client.calls) == index + 1 and client.is_closed and not client.cookies
    assert all(response.is_closed for response in client.responses[:index + 1])
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.read_once()
    assert len(client.calls) == index + 1


@pytest.mark.parametrize("index", [0, 3, 6])
@pytest.mark.parametrize("old,new", [
    (b'"folder":17', b'"folder":18'), (b'"recording":"enable"', b'"recording":"disable"'),
    (b'"uuid":"11111111', b'"uuid":"21111111'), (b'"future-config":', b'"foreign-config":'),
    (b'"instruction-profile":""', b'"instruction-profile":"mcp-v4-ip-other"'),
])
def test_identity_config_or_full_frame_drift_stops(tmp_path, monkeypatch, index, old, new):
    reader, _, _, _, _, client, _ = _fixture(tmp_path, monkeypatch)
    client.responses[index].content = client.responses[index].content.replace(old, new)
    if index == 0 and old == b'"future-config":':
        # An unchanged future field name is allowed; drift is compared across frames.
        expected = 4
    else: expected = index + 1
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.read_once()
    assert len(client.calls) == expected
    assert client.is_closed and not client.cookies


@pytest.mark.parametrize("index", [1, 2, 4, 5])
def test_wrong_material_envelope_never_becomes_a_witness(tmp_path, monkeypatch, index):
    reader, _, _, _, _, client, _ = _fixture(tmp_path, monkeypatch)
    client.responses[index].content = client.responses[index].content.replace(b'"secret-id":37', b'"secret-id":38')
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.read_once()
    assert len(client.calls) == index + 1 and client.is_closed


def test_changed_password_between_brackets_refuses(tmp_path, monkeypatch):
    reader, _, _, _, _, client, _ = _fixture(tmp_path, monkeypatch)
    client.responses[5].content = client.responses[5].content.replace(b"synthetic-password", b"changed-password")
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.read_once()
    assert len(client.calls) == 6 and client.is_closed


def test_changed_totp_stops_before_password_after(tmp_path, monkeypatch):
    reader, _, _, _, _, client, _ = _fixture(tmp_path, monkeypatch)
    client.responses[4].content = client.responses[4].content.replace(b'"results":""', b'"results":"changed-key"')
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.read_once()
    assert len(client.calls) == 5 and client.is_closed and not client.cookies


@pytest.mark.parametrize("defect", ["not-closed", "close-error", "record-drift"])
def test_client_close_boundary_cannot_publish_and_wipes(tmp_path, monkeypatch, defect):
    reader, _, inputs, _, _, client, _ = _fixture(tmp_path, monkeypatch)
    class ClosingClient(Client):
        def __exit__(self, *args):
            if defect == "not-closed": return
            super().__exit__(*args)
            if defect == "close-error": raise ValueError("Synthetic close error")
            (inputs["directory"] / "creation.pending").touch(mode=0o600)
    client.__class__ = ClosingClient
    consumed = []
    erased = []
    original_wipe = r._zeroize_mutable
    def consume(*args, **kwargs):
        consumed.append(True)
        raise AssertionError("Must refuse before final consumer")
    def wipe(buffer):
        original_wipe(buffer)
        erased.append(buffer)
    monkeypatch.setattr(r, "consume_secret_instruction_build29_api_preservation", consume)
    monkeypatch.setattr(r, "_zeroize_mutable", wipe)
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.read_once()
    assert len(client.calls) == 7 and not consumed and not client.cookies
    assert all(response.is_closed for response in client.responses)
    assert erased and all(not any(buffer) for buffer in erased)


def test_deadline_during_middle_get_stops_before_next_material_read(tmp_path, monkeypatch):
    reader, _, _, _, _, client, _ = _fixture(tmp_path, monkeypatch)
    expired = False
    original_iter = client.responses[3].iter_raw
    def iter_raw():
        nonlocal expired
        for chunk in original_iter():
            expired = True
            yield chunk
    client.responses[3].iter_raw = iter_raw
    reader._clock = lambda: 41 if expired else 10
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.read_once()
    assert len(client.calls) == 4 and client.is_closed and not client.cookies
    assert all(response.is_closed for response in client.responses[:4])


@pytest.mark.parametrize("defect", ["type", "pending", "damaged-record", "missing-m4", "userinfo", "envelope"])
def test_unqualified_local_context_refuses_before_client(tmp_path, monkeypatch, defect):
    reader, record, inputs, _, _, client, seen = _fixture(tmp_path, monkeypatch)
    if defect == "pending": (inputs["directory"] / "creation.pending").touch(mode=0o600)
    elif defect == "damaged-record": (inputs["directory"] / "creation.record").write_bytes(b"damaged")
    elif defect == "missing-m4": inputs["execution_store"]._path.unlink()
    elif defect == "userinfo":
        from dataclasses import replace
        record._config = replace(record._config, base_url="https://actor@synthetic.example.test")
    target = record if defect != "type" else object()
    pin = reader._credential_envelope if defect != "envelope" else {**reader._credential_envelope, "status": "success"}
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError):
        r.WebSecretFixtureApiPreservationReader(target, instruction_profile_name="", credential_envelope=pin,
            totp_envelope=reader._totp_envelope, client_factory=reader._factory)
    assert not seen and not client.calls


@pytest.mark.parametrize("source", ["password", "totp"])
def test_present_material_serial_must_match_original_record_before_client(tmp_path, monkeypatch, source):
    reader, record, _, _, _, client, seen = _fixture(tmp_path, monkeypatch)
    password_pin = {**reader._credential_envelope}
    totp_pin = {**reader._totp_envelope}
    pin = password_pin if source == "password" else totp_pin
    pin["serial"] = "FOREIGNSERIAL"
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError):
        r.WebSecretFixtureApiPreservationReader(record, instruction_profile_name="",
            credential_envelope=password_pin, totp_envelope=totp_pin, client_factory=reader._factory)
    assert not seen and not client.calls


def test_matching_present_serial_is_bound_without_inventing_absent_members(tmp_path, monkeypatch):
    serial = "UNITAPPLIANCE"
    reader, record, _, _, _, client, _ = _fixture(tmp_path, monkeypatch, serial=serial)
    password_pin = {**reader._credential_envelope, "serial": serial}
    totp_pin = {**reader._totp_envelope, "serial": serial}
    bound = r.WebSecretFixtureApiPreservationReader(record, instruction_profile_name="",
        credential_envelope=password_pin, totp_envelope=totp_pin, client_factory=reader._factory)
    for index in (1, 2, 4, 5):
        client.responses[index].content = client.responses[index].content[:-1] + b',"serial":' + _raw(serial) + b'}'
    assert len(bound.read_once().preservation_digest) == 64
    assert "serial" not in reader._credential_envelope and "serial" not in reader._totp_envelope


def test_original_record_drift_mid_read_stops_before_next_request(tmp_path, monkeypatch):
    reader, _, inputs, _, _, client, _ = _fixture(tmp_path, monkeypatch)
    original_stream = client.stream
    @contextmanager
    def stream(*args, **kwargs):
        with original_stream(*args, **kwargs) as response:
            yield response
        if len(client.calls) == 2:
            (inputs["directory"] / "creation.pending").touch(mode=0o600)
    client.stream = stream
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.read_once()
    assert len(client.calls) == 2 and client.is_closed and not client.cookies


@pytest.mark.parametrize("clock_values", [[10, 9], [10, float("nan")], [10, 41]])
def test_bad_clock_stops_before_client(tmp_path, monkeypatch, clock_values):
    reader, _, _, _, _, client, seen = _fixture(tmp_path, monkeypatch)
    iterator = iter(clock_values)
    reader._clock = lambda: next(iterator)
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.read_once()
    assert not client.calls and not seen


@pytest.mark.parametrize("index,kind", [(0, "encoding"), (1, "oversize"), (2, "content-type"), (0, "redirect")])
def test_response_boundaries_and_failed_buffers_close(tmp_path, monkeypatch, index, kind):
    reader, _, _, _, _, client, _ = _fixture(tmp_path, monkeypatch)
    if kind == "encoding": client.responses[index].headers["content-encoding"] = "gzip"
    elif kind == "oversize": client.responses[index].content = bytearray(b"x" * 16_385)
    elif kind == "content-type": client.responses[index].headers["content-type"] = "text/html"
    else: client.responses[index].status_code = 302
    erased = []
    original = r._zeroize_mutable
    def wipe(buffer):
        original(buffer)
        erased.append(buffer)
    monkeypatch.setattr(r, "_zeroize_mutable", wipe)
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.read_once()
    assert len(client.calls) == index + 1 and client.is_closed and not client.cookies
    assert erased and all(not any(buffer) for buffer in erased)


def _fresh(reader, *, phase=None, reference=None, factory=None):
    return r.WebSecretFixtureApiPreservationReader(reader._record,
        instruction_profile_name=reader._reference if reference is None else reference,
        credential_envelope=reader._credential_envelope, totp_envelope=reader._totp_envelope,
        phase=reader._phase if phase is None else phase,
        client_factory=reader._factory if factory is None else factory)


@pytest.mark.parametrize("failure", [False, True])
def test_durable_phase_attempt_blocks_fresh_instance_after_success_or_failure(tmp_path, monkeypatch, failure):
    reader, record, inputs, _, _, client, seen = _fixture(tmp_path, monkeypatch)
    marker = inputs["directory"] / r._ATTEMPTS["baseline"]
    original_record = (inputs["directory"] / "creation.record").read_bytes()
    original_m4 = inputs["execution_store"]._path.read_bytes()
    if failure:
        client.responses[0].status_code = 403
        with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.read_once()
    else:
        reader.read_once()
    assert stat.S_IMODE(marker.stat().st_mode) == 0o600 and len(marker.read_bytes()) == 65
    assert marker.read_bytes() == reader._attempt_payload
    assert b"synthetic-password" not in marker.read_bytes()
    previous_calls = len(client.calls)
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): _fresh(reader).read_once()
    assert len(client.calls) == previous_calls and len(seen) == 1
    assert record.read_creation() == reader._original
    assert (inputs["directory"] / "creation.record").read_bytes() == original_record
    assert inputs["execution_store"]._path.read_bytes() == original_m4


@pytest.mark.parametrize("boundary", ["file", "directory"])
def test_attempt_fsync_failure_retains_consumption_before_http(tmp_path, monkeypatch, boundary):
    reader, _, inputs, _, _, client, seen = _fixture(tmp_path, monkeypatch)
    marker = inputs["directory"] / r._ATTEMPTS["baseline"]
    original_fsync = r.os.fsync
    def fsync(descriptor):
        directory = stat.S_ISDIR(os.fstat(descriptor).st_mode)
        if directory == (boundary == "directory"):
            raise OSError("Synthetic fsync failure")
        return original_fsync(descriptor)
    with monkeypatch.context() as patch:
        patch.setattr(r.os, "fsync", fsync)
        with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.read_once()
    assert marker.exists() and not client.calls and not seen
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): _fresh(reader).read_once()
    assert not client.calls and not seen


@pytest.mark.parametrize("kind", ["partial", "symlink", "directory", "fifo", "hardlink"])
def test_existing_attempt_never_imports_recovery_or_blocks_open(tmp_path, monkeypatch, kind):
    reader, _, inputs, _, _, client, seen = _fixture(tmp_path, monkeypatch)
    marker = inputs["directory"] / r._ATTEMPTS["baseline"]
    if kind == "directory": marker.mkdir()
    elif kind == "fifo": os.mkfifo(marker, 0o600)
    elif kind in {"symlink", "hardlink"}:
        other = tmp_path / "unrelated"
        other.write_bytes(reader._attempt_payload)
        other.chmod(0o600)
        if kind == "symlink": marker.symlink_to(other)
        else: os.link(other, marker)
    else: marker.write_bytes(b"partial")
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.read_once()
    assert not client.calls and not seen


@pytest.mark.parametrize("kind", ["unlink", "content", "mode", "symlink", "fifo"])
def test_attempt_tampering_stops_before_next_http_without_blocking(tmp_path, monkeypatch, kind):
    reader, _, inputs, _, _, client, _ = _fixture(tmp_path, monkeypatch)
    marker = inputs["directory"] / r._ATTEMPTS["baseline"]
    original_stream = client.stream
    @contextmanager
    def stream(*args, **kwargs):
        with original_stream(*args, **kwargs) as response:
            yield response
        if kind == "unlink": marker.unlink()
        elif kind == "content": marker.write_bytes(b"x" * 65)
        elif kind == "mode": marker.chmod(0o644)
        else:
            marker.unlink()
            if kind == "fifo": os.mkfifo(marker, 0o600)
            else: marker.symlink_to(inputs["directory"] / "creation.record")
    client.stream = stream
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.read_once()
    assert len(client.calls) == 1 and client.is_closed and not client.cookies


@pytest.mark.parametrize("phase,reference", [
    ("other", ""), ("applied", ""), ("baseline", PROFILE), ("restored", PROFILE), ("recovery", PROFILE),
])
def test_phase_reference_mismatch_has_no_reservation_or_client(tmp_path, monkeypatch, phase, reference):
    reader, _, inputs, _, _, client, seen = _fixture(tmp_path, monkeypatch)
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): _fresh(reader, phase=phase, reference=reference)
    assert not tuple(inputs["directory"].glob("api-preservation.*")) and not client.calls and not seen


def test_distinct_fixed_phase_has_own_consumption_not_replay_or_authority(tmp_path, monkeypatch):
    reader, _, inputs, _, _, client, _ = _fixture(tmp_path, monkeypatch)
    reader.read_once()
    second_client = Client([Response(response.content) for response in client.responses])
    restored = _fresh(reader, phase="restored", factory=lambda **_: second_client)
    restored.read_once()
    assert len(client.calls) == len(second_client.calls) == 7
    assert (inputs["directory"] / r._ATTEMPTS["baseline"]).exists()
    assert (inputs["directory"] / r._ATTEMPTS["restored"]).exists()
    assert reader._attempt_payload != restored._attempt_payload
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): _fresh(restored).read_once()
    assert len(second_client.calls) == 7


def test_concurrent_instances_reserve_same_phase_only_once(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    reader, _, inputs, _, _, client, seen = _fixture(tmp_path, monkeypatch)
    other = _fresh(reader)
    def run(controller):
        try: return controller.read_once()
        except r.WebSecretFixtureApiPreservationReadError: return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, [reader, other]))
    assert sum(result is not None for result in results) == 1
    assert len(seen) == 1 and len(client.calls) == 7
    assert (inputs["directory"] / r._ATTEMPTS["baseline"]).exists()


@pytest.mark.parametrize("kind", ["rename", "replace", "rewrite"])
def test_attempt_path_or_open_file_change_during_read_is_rejected(tmp_path, monkeypatch, kind):
    reader, _, inputs, _, _, client, seen = _fixture(tmp_path, monkeypatch)
    marker = inputs["directory"] / r._ATTEMPTS["baseline"]
    original_read = r.os.read
    def read(descriptor, count):
        raw = original_read(descriptor, count)
        if count == 66:
            if kind == "rewrite": marker.write_bytes(b"x" * 65)
            else:
                marker.rename(inputs["directory"] / "moved-attempt")
                if kind == "replace":
                    marker.write_bytes(reader._attempt_payload)
                    marker.chmod(0o600)
        return raw
    monkeypatch.setattr(r.os, "read", read)
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.read_once()
    assert not client.calls and not seen


def test_attempt_close_error_still_closes_directory_descriptor(tmp_path, monkeypatch):
    reader, _, _, _, _, client, seen = _fixture(tmp_path, monkeypatch)
    original_open, original_close = r.os.open, r.os.close
    marker_fds = []
    closes_after_failure = []
    failed = False
    def open_file(path, flags, *args, **kwargs):
        descriptor = original_open(path, flags, *args, **kwargs)
        if path == r._ATTEMPTS["baseline"] and not flags & os.O_CREAT:
            marker_fds.append(descriptor)
        return descriptor
    def close(descriptor):
        nonlocal failed
        original_close(descriptor)
        if failed: closes_after_failure.append(descriptor)
        if descriptor in marker_fds and not failed:
            failed = True
            raise OSError("Synthetic close-after-close failure")
    monkeypatch.setattr(r.os, "open", open_file)
    monkeypatch.setattr(r.os, "close", close)
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.read_once()
    assert failed and len(closes_after_failure) >= 2 and not client.calls and not seen
    for descriptor in closes_after_failure:
        with pytest.raises(OSError): os.fstat(descriptor)
