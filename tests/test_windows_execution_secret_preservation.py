"""Seven fixed synthetic observations, joined to real original M4/C3 custody."""
import json
import ssl

import httpx
import pytest

from fortipam_mcp import windows_execution_secret_preservation as p
from test_windows_execution_secret_ack import fixture
from test_windows_execution_secret_material import execute
from test_windows_execution_secret_contract import SERIAL, postcondition
from v4_planning import M4Outcome


class Source:
    def __init__(self, fault=None):
        self.fault = fault
        self.requests = []
        self.responses = []
        self.clients = []
        self.gets = self.passwords = 0
        self.hook = lambda: None

    def handle(self, request):
        self.requests.append(request)
        self.hook()
        assert request.headers["authorization"] == "Bearer synthetic-api-token"
        if request.method == "GET":
            assert str(request.url) == "https://lab.example.test/api/v2/cmdb/secret/database/43?with_meta=true&vdom=root"
            value = postcondition()
            row = value["results"]
            row.update({"instruction-profile":"", "dependency":[], "subscriber":[],
                "field":[{"id":1,"name":"Password","value":"MASKED"},
                         {"id":2,"name":"Username","value":"UNIT-WINDOWS\\labuser"}],
                "totp-setting":{"status":"disable", "shared-key":None if self.gets % 2 == 0 else "rendered-mask"},
                "future-annotation":{"opaque":"unchanged"}})
            self.gets += 1
            if self.fault == "username": row["field"][1]["value"] = "OTHER\\labuser"
            if self.fault == "field-name": row["field"][1]["name"] = "Login"
            if self.fault == "duplicate-id": row["field"][1]["id"] = 1
            if self.fault == "field-zero": row["field"][0]["id"] = 0
            if self.fault == "extra-field": row["field"].append({"id":3,"name":"Domain","value":"other"})
            if self.fault == "dependency": row["dependency"] = [{"id":1,"target":"other"}]
            if self.fault == "instruction": row["instruction-profile"] = "existing-profile"
            if self.fault == "reference": row["q_ref"] = 1
            if self.fault == "uuid": row["uuid"] = "00000000-0000-4000-8000-000000000002"
            if self.fault == "row-drift" and self.gets % 3 == 2: row["future-annotation"]["opaque"] = "changed"
            if self.fault == "stable-row-drift": row["future-annotation"]["opaque"] = "changed"
        else:
            assert request.method == "POST" and request.url.path == "/api/v2/internal/secret-clear-text"
            body = json.loads(request.content)
            assert body["secret-id"] == 43
            value = dict(version="v7.0.0", build=29, serial=SERIAL, http_method="POST", http_status=200,
                status="OK", **{"secret-id":43}, msg="Success")
            if self.fault == "sensitive-message": value["msg"] = "synthetic-credential"
            if "field-id" in body:
                assert set(body) == {"secret-id","field-id"} and body["field-id"] == 1
                self.passwords += 1
                value.update({"field-id":1, "results":"synthetic-credential"})
                if self.fault == "password": value["results"] = "changed-credential"
                if self.fault == "password-drift" and self.passwords % 2 == 0: value["results"] = "changed-credential"
                if self.fault == "foreign-envelope": value["secret-id"] = 44
            else:
                assert body == {"secret-id":43,"totp-share-key":1}
                value["results"] = ""
                if self.fault == "totp-nonempty": value["results"] = "ABCD2345"
                if self.fault == "totp-null": value["results"] = None
            if self.fault == "status": value["status"] = "success"
        status = 403 if self.fault == "http" else 200
        response = httpx.Response(status, headers={"content-type":"application/json"},
            stream=httpx.ByteStream(json.dumps(value, separators=(",", ":")).encode()))
        self.responses.append(response)
        return response

    def factory(self, **kwargs):
        assert kwargs["follow_redirects"] is False and kwargs["trust_env"] is False
        assert kwargs["verify"].check_hostname and kwargs["verify"].verify_mode == ssl.CERT_REQUIRED
        client = httpx.Client(transport=httpx.MockTransport(self.handle), **kwargs)
        self.clients.append(client)
        return client


def setup(tmp_path, monkeypatch):
    cmp = fixture(tmp_path)
    assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    monkeypatch.setattr(p, "_ssl_context", lambda config: ssl.create_default_context())
    return cmp


def reader(cmp, source, phase="baseline", clock=lambda:0):
    return p.WindowsExecutionSecretPreservationReader(cmp["custody"], phase=phase,
        client_factory=source.factory, http_clock=clock)


def test_full_rows_and_original_request_materials_match_with_explicit_empty_totp(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    source = Source()
    scalar = p.parser._scalar
    def check(buffer, span):
        assert not any(marker in buffer[slice(*span)] for marker in
            (b"synthetic-credential", b"UNIT-WINDOWS", b"MASKED", b"rendered-mask", b"unchanged"))
        return scalar(buffer, span)
    monkeypatch.setattr(p.parser, "_scalar", check)
    before = cmp["custody"].inspect_original_creation()
    baseline = reader(cmp, source).read_once()
    recovered = reader(cmp, source, "recovery").read_once()
    assert baseline.preservation_digest == recovered.preservation_digest
    assert baseline.custody_digest == before.custody_digest
    assert len(source.requests) == 14 and source.passwords == 4
    assert all(response.is_closed for response in source.responses)
    assert all(client.is_closed and not len(client.cookies) for client in source.clients)
    assert cmp["custody"].inspect_original_creation() == before
    data = b"".join(path.read_bytes() for path in cmp["directory"].iterdir())
    for material in (b"synthetic-credential", b"UNIT-WINDOWS", b"MASKED", b"rendered-mask", b"unchanged"):
        assert material not in data


@pytest.mark.parametrize("fault", ["username", "field-name", "duplicate-id", "field-zero", "extra-field",
    "dependency", "instruction", "reference", "uuid", "row-drift", "password", "password-drift",
    "foreign-envelope", "totp-nonempty", "totp-null", "status", "http"])
def test_incomplete_drifted_or_foreign_material_never_produces_a_preservation_record(tmp_path, monkeypatch, fault):
    cmp = setup(tmp_path, monkeypatch)
    source = Source(fault)
    observation = reader(cmp, source)
    with pytest.raises(p.WindowsExecutionSecretPreservationError): observation.read_once()
    assert not (cmp["directory"]/"preservation.baseline.result.json").exists()
    assert (cmp["directory"]/"preservation.baseline.attempt.json").exists()
    count = len(source.requests)
    assert 0 < count <= 7
    with pytest.raises(p.WindowsExecutionSecretPreservationError): observation.read_once()
    with pytest.raises(p.WindowsExecutionSecretPreservationError): reader(cmp, source).read_once()
    assert len(source.requests) == count and cmp["loader"].loads == 1
    assert all(response.is_closed for response in source.responses)
    assert all(client.is_closed and not len(client.cookies) for client in source.clients)


def test_current_row_drift_refuses_recovery_before_password_or_totp_requests(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    source = Source();reader(cmp, source).read_once()
    changed = Source("stable-row-drift")
    with pytest.raises(p.WindowsExecutionSecretPreservationError): reader(cmp, changed, "recovery").read_once()
    assert len(changed.requests) == 1 and changed.passwords == 0


def test_native_envelope_text_is_never_persisted_in_source_pin_records(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    source = Source("sensitive-message")
    reader(cmp, source).read_once()
    data = b"".join(path.read_bytes() for path in cmp["directory"].iterdir())
    assert b"synthetic-credential" not in data and b"Success" not in data


def test_missing_baseline_cannot_be_replaced_by_another_phase_or_unsigned_witness(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    source = Source()
    with pytest.raises(p.WindowsExecutionSecretPreservationError): reader(cmp, source, "recovery").read_once()
    assert not source.requests
    with pytest.raises(p.WindowsExecutionSecretPreservationError): reader(cmp, source, "other-phase")


def test_failed_or_replaced_live_attempt_is_not_replayed(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    source = Source()
    def replace_attempt():
        if len(source.requests) == 1:
            path = cmp["directory"]/"preservation.baseline.attempt.json"
            replacement = path.with_suffix(".replacement")
            replacement.write_bytes(path.read_bytes());replacement.chmod(0o600);replacement.replace(path)
    source.hook = replace_attempt
    with pytest.raises(p.WindowsExecutionSecretPreservationError): reader(cmp, source).read_once()
    assert len(source.requests) == 1


def test_missing_or_damaged_baseline_attempt_refuses_before_network(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    source = Source();reader(cmp, source).read_once()
    (cmp["directory"]/"preservation.baseline.attempt.json").unlink()
    count = len(source.requests)
    with pytest.raises(p.WindowsExecutionSecretPreservationError): reader(cmp, source, "recovery").read_once()
    assert len(source.requests) == count


def test_clock_failure_consumes_only_observation_attempt_and_erases_buffers(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    source = Source()
    buffers = []
    erase = p._zeroize_mutable
    def zeroize(buffer):
        erase(buffer);buffers.append(buffer)
    monkeypatch.setattr(p, "_zeroize_mutable", zeroize)
    with pytest.raises(p.WindowsExecutionSecretPreservationError): reader(cmp, source, clock=lambda:float("nan")).read_once()
    assert not source.requests and all(not any(buffer) for buffer in buffers)
    assert (cmp["directory"]/"preservation.baseline.attempt.json").exists()


def test_parent_deadline_cannot_be_extended_by_a_new_observation_phase(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    source = Source()
    observation = reader(cmp, source, clock=lambda:10)
    with pytest.raises(p.WindowsExecutionSecretPreservationError):observation.read_once(max_deadline=9)
    assert not source.requests
