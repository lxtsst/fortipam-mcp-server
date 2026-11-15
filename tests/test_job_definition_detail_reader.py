"""Exact disabled Job readback through a real synthetic Owner session."""
from dataclasses import asdict
import json
import logging
from typing import Any

import httpx
import pytest

import fortipam_mcp.job_definition_detail_reader as module
from fortipam_mcp.job_definition_create_contract import compile_disabled_job_create_body
from fortipam_mcp.job_definition_detail_reader import JobDefinitionDetailReader, JobDefinitionDetailReaderError
from fortipam_mcp.job_definition_projection import JobDefinitionExpectation
from fortipam_mcp.owner_session_metadata import OwnerSessionMetadataTransport
from fortipam_mcp.secret_metadata_http_transport import (
    FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig, SYSTEM_STATUS_PATH,
)
from test_job_definition_http_transport import SOURCE, TARGET, _source

SERIAL = "FPAVUNIT000001"
ACTOR = "unit-admin"


def _body() -> dict[str, object]:
    return compile_disabled_job_create_body(
        {"status": "success", "version": "v7.0.0", "build": 29, "results": _source()},
        source_name=SOURCE, target_name=TARGET, target_requester="adminapi", expected_secret_id=999,
    )


def _payload() -> dict[str, Any]:
    return {**module._ENVELOPE, "serial": SERIAL, "mkey": TARGET,
            "results": {**{k: v for k, v in _body().items() if k != "$originalName"},
                        "q_origin_key": TARGET, "approval-status": "approved",
                        "max-timeout": 0, "q_ref": 0, "q_static": False,
                        "unselected": {"password": "synthetic-never-decode"}}}


def _collection_payload() -> dict[str, Any]:
    row = {k: v for k, v in _payload()["results"].items()
           if k not in module._SUMMARY_TRANSFORMED | {"q_ref", "q_static", "max-timeout"}}
    row.update({"execution-time-start": 0, "execution-time-end": 0, "result-txt": "",
                "scheduled-time": "Synthetic formatted time", "job-sch-interval": "1"})
    return {**module._ENVELOPE, "http_method": "POST", "status": "OK", "serial": SERIAL, "results": [row]}


def _reader(payload: dict[str, Any] | bytes | None = None, *, failure: str = "", pristine: bool = False,
            collection_payload: dict[str, Any] | None = None) -> tuple[JobDefinitionDetailReader, OwnerSessionMetadataTransport, list[tuple[str, str]]]:
    config = SecretMetadataHttpTransportConfig("https://pam.example.test", "synthetic-api-token", 5, None)
    witness = FortiPamSecretMetadataHttpTransport(config, bound_secret_name="witness")
    active = False
    calls: list[tuple[str, str]] = []
    now = [1000.0]
    details = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal active, details
        path = request.url.path
        calls.append((request.method, path))
        assert request.url.host == "pam.example.test" and "authorization" not in request.headers
        if path == "/remote/login":
            return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH">')
        if path == "/XX/YY/ZZ/AUTH":
            active = True
            headers = [("location", "/"), ("set-cookie", "testsession=synthetic; Secure; Path=/")]
            if failure != "csrf":
                headers.append(("set-cookie", 'ccsrftoken="synthetic-csrf"; Secure; Path=/'))
            return httpx.Response(303, headers=headers)
        if path == "/logout":
            active = failure == "logout"
            return httpx.Response(200)
        if path == "/":
            return httpx.Response(200)
        if not active:
            return httpx.Response(401, json={})
        if path == SYSTEM_STATUS_PATH:
            return httpx.Response(200, json={"version": "v7.0.0", "build": 29, "serial": SERIAL})
        if path == "/api/v2/monitor/web-ui/state":
            return httpx.Response(200, json={"http_method": "GET", "http_status": 200, "status": "success",
                "version": "v7.0.0", "build": 29, "path": "web-ui", "name": "state",
                "results": {"admin": {"name": ACTOR, "login_name": "other" if failure == "actor" else ACTOR,
                    "sponsored_group_name": "", "guest_admin": False}}})
        if path == "/api/v2/cmdb/secret/job":
            assert request.method == "POST" and request.headers["X-HTTP-Method-Override"] == "GET"
            assert request.headers["X-CSRFTOKEN"] == "synthetic-csrf"
            assert request.url.query == b"with_meta=true&vdom=root" and request.content == b'{"json_filter":[]}'
            return httpx.Response(200, json=_collection_payload() if collection_payload is None else collection_payload)
        assert path == "/api/v2/cmdb/secret/job/" + TARGET
        assert request.url.query == (b"with_meta=true&vdom=root" if pristine else b"vdom=root")
        assert request.method == "GET"
        if failure == "expiry":
            now[0] += 301
        content = _payload() if payload is None else payload
        details += 1
        if pristine and isinstance(content, dict):
            content["results"].update({"execution-time-start": "synthetic-native-zero-time",
                                      "execution-time-end": "synthetic-native-zero-time", "result-txt": ""})
            if details == 2 and failure == "join-drift":
                content["results"]["execution-time-start"] = "synthetic-changed-time"
            if details == 2 and failure == "join-enable":
                content["results"]["status"] = "enable"
            if failure == "detail-result":
                content["results"]["result-txt"] = "synthetic-private-result"
        raw = content if isinstance(content, bytes) else json.dumps(content).encode()
        return httpx.Response(403 if failure == "status" else 200, content=raw,
                              headers={"content-type": "text/html" if failure == "mime" else "application/json"})

    owner = OwnerSessionMetadataTransport(config, owner_name=ACTOR, credentials=lambda: (ACTOR, "synthetic-password"),
        folder_path="JobRead", secret_name="job-read", target_name="job-read", witness=witness,
        client_factory=lambda **kwargs: httpx.Client(**kwargs, transport=httpx.MockTransport(respond)), clock=lambda: now[0])
    reader = JobDefinitionDetailReader(owner, expected_serial=SERIAL,
        expected=JobDefinitionExpectation(TARGET, "adminapi", 999, "echo BP008_JOB_OK"), expected_create_body=_body(),
        expected_max_timeout=0 if pristine else None)
    return reader, owner, calls


@pytest.mark.parametrize(("failure", "stage"), [
    ("status", "read_response_forbidden"), ("mime", "read_response_content_type"),
    ("expiry", "read_session"), ("detail-result", "detail_result"),
    ("join-drift", "detail_drift"),
])
def test_pristine_failure_retains_only_fixed_category(failure: str, stage: str) -> None:
    reader, _, _ = _reader(pristine=True, failure=failure)
    with pytest.raises(JobDefinitionDetailReaderError) as caught:
        reader.read_pristine()
    assert caught.value.stage == stage
    assert str(caught.value) == module._UNAVAILABLE
    assert TARGET not in repr(caught.value) and "synthetic-private-result" not in repr(caught.value)


def test_pristine_join_brackets_native_summary_without_decoding_material(monkeypatch: pytest.MonkeyPatch) -> None:
    reader, owner, calls = _reader(pristine=True)
    original = module.json.loads

    def restricted_loads(raw: Any, *args: Any, **kwargs: Any) -> Any:
        assert b"synthetic-never-decode" not in (raw.encode() if isinstance(raw, str) else bytes(raw))
        return original(raw, *args, **kwargs)

    monkeypatch.setattr(module.json, "loads", restricted_loads)
    result = reader.read_pristine()
    assert result.verified and result.not_started and result.definition.definition_verified
    assert result.unreferenced and result.nonstatic and result.timeout_matches_expectation
    job_calls = [(method, path) for method, path in calls if "/secret/job" in path]
    assert job_calls == [("GET", "/api/v2/cmdb/secret/job/" + TARGET),
                         ("POST", "/api/v2/cmdb/secret/job"),
                         ("GET", "/api/v2/cmdb/secret/job/" + TARGET)]
    assert owner.logout_verified and owner._client is None


@pytest.mark.parametrize("key,value", [
    ("execution-time-start", 1), ("execution-time-end", 1), ("execution-time-start", "0"),
    ("execution-time-start", False), ("result-txt", "synthetic-private-result"),
    ("status", "enable"), ("secret", 1000), ("script", "synthetic-other-script"),
])
def test_pristine_join_rejects_started_state_or_summary_drift(key: str, value: object) -> None:
    collection = _collection_payload()
    collection["results"][0][key] = value
    reader, owner, calls = _reader(pristine=True, collection_payload=collection)
    with pytest.raises(JobDefinitionDetailReaderError):
        reader.read_pristine()
    assert owner.logout_verified
    assert calls.count(("GET", "/api/v2/cmdb/secret/job/" + TARGET)) == 1


@pytest.mark.parametrize("failure", ["join-drift", "join-enable", "csrf", "logout", "detail-result"])
def test_pristine_join_requires_stable_details_csrf_and_logout(failure: str) -> None:
    reader, owner, _ = _reader(pristine=True, failure=failure)
    with pytest.raises(JobDefinitionDetailReaderError):
        reader.read_pristine()
    assert owner._client is None and owner.logout_verified is (failure != "logout")


@pytest.mark.parametrize("pristine", [False, True])
def test_private_session_and_job_urls_are_suppressed_in_http_logs(caplog: pytest.LogCaptureFixture, pristine: bool) -> None:
    reader, owner, _ = _reader(pristine=pristine)
    caplog.set_level(logging.DEBUG, logger="httpx")
    if pristine:
        assert reader.read_pristine().verified
    else:
        assert reader.readback().definition_verified
    assert not any(record.name == "httpx" for record in caplog.records)
    assert owner.logout_verified


@pytest.mark.parametrize("key,value", [("q_ref", 1), ("q_ref", False), ("q_ref", "0"),
                                       ("q_static", True), ("q_static", 0), ("max-timeout", 1)])
def test_pristine_join_needs_explicit_zero_references_nonstatic_and_timeout(key: str, value: object) -> None:
    payload = _payload()
    payload["results"][key] = value
    reader, owner, _ = _reader(payload, pristine=True)
    with pytest.raises(JobDefinitionDetailReaderError):
        reader.read_pristine()
    assert owner.logout_verified


@pytest.mark.parametrize("key", ["q_ref", "q_static", "max-timeout"])
def test_pristine_join_never_infers_missing_metadata_defaults(key: str) -> None:
    payload = _payload()
    del payload["results"][key]
    reader, owner, _ = _reader(payload, pristine=True)
    with pytest.raises(JobDefinitionDetailReaderError):
        reader.read_pristine()
    assert owner.logout_verified


def test_pristine_join_requires_separate_timeout_expectation_before_login() -> None:
    reader, _, calls = _reader()
    with pytest.raises(JobDefinitionDetailReaderError):
        reader.read_pristine()
    assert not calls


@pytest.mark.parametrize("shape", ["missing", "duplicate", "wrong-envelope", "missing-execution"])
def test_pristine_join_needs_one_exact_row_and_complete_native_evidence(shape: str) -> None:
    collection = _collection_payload()
    if shape == "missing":
        collection["results"] = []
    elif shape == "duplicate":
        collection["results"] *= 2
    elif shape == "wrong-envelope":
        collection["http_method"] = "GET"
    else:
        del collection["results"][0]["execution-time-end"]
    reader, owner, _ = _reader(pristine=True, collection_payload=collection)
    with pytest.raises(JobDefinitionDetailReaderError):
        reader.read_pristine()
    assert owner.logout_verified


def test_exact_read_is_categorical_fixed_get_and_closes_real_session(monkeypatch: pytest.MonkeyPatch) -> None:
    reader, owner, calls = _reader()
    original = module.json.loads

    def restricted_loads(raw: Any, *args: Any, **kwargs: Any) -> Any:
        assert b"synthetic-never-decode" not in (raw.encode() if isinstance(raw, str) else bytes(raw))
        return original(raw, *args, **kwargs)

    monkeypatch.setattr(module.json, "loads", restricted_loads)
    result = reader.readback()
    assert result.definition_verified and set(asdict(result).values()) == {True}
    assert TARGET not in repr(result) and "BP008" not in repr(result)
    assert owner.logout_verified and owner._client is None
    assert [c for c in calls if c[0] != "GET"] == [("POST", "/XX/YY/ZZ/AUTH")]
    assert calls[-2:] == [("GET", "/logout"), ("GET", SYSTEM_STATUS_PATH)]
    assert calls.count(("GET", "/api/v2/cmdb/secret/job/" + TARGET)) == 1


@pytest.mark.parametrize("native_array,accepted", [(b"[ \r\n\t ]", True), (b"[{}]", False), (b'"[]"', False)])
def test_native_empty_procedure_array_whitespace_preserves_exact_empty_semantics(native_array: bytes, accepted: bool) -> None:
    raw = json.dumps(_payload()).encode()
    for field in (b"ssh-procedure", b"web-api-procedure"):
        raw = raw.replace(b'"' + field + b'": []', b'"' + field + b'": ' + native_array)
    reader, owner, _ = _reader(raw)
    if accepted:
        assert reader.readback().definition_verified
    else:
        with pytest.raises(JobDefinitionDetailReaderError):
            reader.readback()
    assert owner.logout_verified


@pytest.mark.parametrize("change", ["selector", "script", "enabled", "partial", "extra", "write_bridge"])
def test_invalid_private_binding_fails_before_login(change: str) -> None:
    _, owner, calls = _reader()
    body = _body()
    name = TARGET
    if change == "selector":
        name = "../other"
    elif change == "script":
        body["script"] = "synthetic-other-script"
    elif change == "enabled":
        body["status"] = "enable"
    elif change == "partial":
        del body["job-sch-interval"]
    elif change == "extra":
        body["unqualified"] = True
    else:
        owner._allow_secret_create = True
    with pytest.raises(JobDefinitionDetailReaderError):
        JobDefinitionDetailReader(owner, expected_serial=SERIAL,
            expected=JobDefinitionExpectation(name, "adminapi", 999, "echo BP008_JOB_OK"), expected_create_body=body)
    assert not calls and owner._client is None


@pytest.mark.parametrize("field", list(k for k in _body() if k != "$originalName"))
def test_any_missing_creation_field_is_denied_and_session_closed(field: str) -> None:
    payload = _payload()
    del payload["results"][field]
    reader, owner, _ = _reader(payload)
    with pytest.raises(JobDefinitionDetailReaderError):
        reader.readback()
    assert owner.logout_verified and owner._client is None


@pytest.mark.parametrize("field,value", [
    ("job-sch-start-date", 123), ("scheduled-time", 123), ("job-sch-month-day", []),
    ("job-sch-week-day", []), ("job-sch-interval", "1"), ("job-sch-frequency", "Day"),
    ("script", "synthetic-other-script"), ("status", "enable"), ("approval-status", "pending"),
    ("secret", True), ("user", "other"), ("q_origin_key", "other"),
])
def test_formatted_summaries_or_configuration_drift_are_denied(field: str, value: object) -> None:
    payload = _payload()
    payload["results"][field] = value
    reader, owner, _ = _reader(payload)
    with pytest.raises(JobDefinitionDetailReaderError):
        reader.readback()
    assert owner.logout_verified


@pytest.mark.parametrize("field,value", [("serial", "OTHER"), ("build", True), ("vdom", "other"), ("mkey", "other"), ("http_method", "POST")])
def test_wrong_device_or_envelope_denied(field: str, value: object) -> None:
    payload = _payload()
    payload[field] = value
    reader, owner, _ = _reader(payload)
    with pytest.raises(JobDefinitionDetailReaderError):
        reader.readback()
    assert owner.logout_verified


@pytest.mark.parametrize("error", [True, -3, "0", "synthetic-private-error"])
def test_error_envelope_cannot_supply_success(error: object) -> None:
    payload = _payload()
    payload["error"] = error
    reader, owner, _ = _reader(payload)
    with pytest.raises(JobDefinitionDetailReaderError):
        reader.readback()
    assert owner.logout_verified


@pytest.mark.parametrize("error", [0, None])
def test_zero_or_null_error_and_single_row_array_are_accepted(error: object) -> None:
    payload = _payload()
    payload["error"] = error
    payload["results"] = [payload["results"]]
    reader, owner, _ = _reader(payload)
    assert reader.readback().definition_verified
    assert owner.logout_verified


@pytest.mark.parametrize("failure", ["actor", "status", "mime", "expiry", "logout"])
def test_identity_transport_expiry_and_logout_fail_closed(failure: str) -> None:
    reader, owner, calls = _reader(failure=failure)
    with pytest.raises(JobDefinitionDetailReaderError, match="^The fixed disabled Job detail read is unavailable\\.$"):
        reader.readback()
    assert owner._client is None
    assert owner.logout_verified is (failure != "logout")
    if failure == "actor":
        assert not any("/secret/job/" in path for _, path in calls)


@pytest.mark.parametrize("malformation", ["duplicate", "extra", "oversize", "two_rows"])
def test_malformed_or_unbounded_detail_denied_and_raw_zeroed(malformation: str) -> None:
    payload = _payload()
    raw = json.dumps(payload).encode()
    if malformation == "duplicate":
        raw = raw.replace(b'"build": 29', b'"build": 29, "build": 29')
    elif malformation == "extra":
        raw += b' {}'
    elif malformation == "oversize":
        raw += b' ' * module._LIMIT
    else:
        payload["results"] = [payload["results"], payload["results"]]
        raw = json.dumps(payload).encode()
    reader, owner, _ = _reader(raw)
    with pytest.raises(JobDefinitionDetailReaderError):
        reader.readback()
    assert owner.logout_verified
    private_raw = bytearray(raw)
    with pytest.raises(Exception):
        reader._project(private_raw)
    assert not any(private_raw)
