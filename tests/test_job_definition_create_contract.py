"""Behavior checks for the fixed 7.0 disabled Job request shape."""

from dataclasses import replace
import copy
import hashlib
import json

import pytest
from v4_planning.material_provider import MaterialAccessDenied

from fortipam_mcp.job_definition_create_contract import (
    JobDefinitionCreateContractError,
    DisabledJobCreateAckPins,
    consume_disabled_job_create_ack,
    compile_disabled_job_create_body,
)


def _source() -> dict[str, object]:
    return {
        "status": "success", "version": "v7.0.0", "build": 29,
        "results": {
            "name": "mcp-v4-bp008-job-20260930-r3",
            "user": "admin", "secret": 999, "associated-secret": 0,
            "status": "disable", "type": "ssh-script",
            "schedule": "one-shot", "script-type": "custom-script",
            "script-name": "", "script": "echo BP008_JOB_OK",
            "approval-status": "approved", "ssh-procedure": [],
            "web-api-procedure": [], "new-line-mode": "crlf",
            "scheduled-time": "2026-10-01 07:05:00",
            "job-sch-start-date": "2026-10-01 07:05:00",
            "job-sch-frequency": "day", "job-sch-interval": 1,
            "job-sch-month-day": "", "job-sch-month-type": "specific",
            "job-sch-week-day": "", "web-proxy-port": 8080,
            "web-proxy-server": "",
        },
    }


def _compile(payload: object) -> dict[str, object]:
    return compile_disabled_job_create_body(
        payload,
        source_name="mcp-v4-bp008-job-20260930-r3",
        target_name="mcp-v4-bp008-job-20260930-r4",
        target_requester="adminapi",
        expected_secret_id=999,
    )


def test_compiles_only_the_observed_disabled_gui_post_shape() -> None:
    body = _compile(_source())
    assert set(body) == {
        "$originalName", "associated-secret", "job-sch-frequency",
        "job-sch-interval", "job-sch-month-day", "job-sch-month-type",
        "job-sch-start-date", "job-sch-week-day", "name", "new-line-mode",
        "schedule", "scheduled-time", "script", "script-name", "script-type",
        "secret", "ssh-procedure", "status", "type", "user",
        "web-api-procedure", "web-proxy-port", "web-proxy-server",
    }
    assert body["status"] == "disable"
    assert body["$originalName"] == ""
    assert body["name"] == "mcp-v4-bp008-job-20260930-r4"
    assert body["user"] == "adminapi"
    assert "approval-status" not in body
    assert "execution-time-start" not in body


@pytest.mark.parametrize("field,value", [
    ("status", "enable"),
    ("script", "id"),
    ("secret", 1000),
    ("ssh-procedure", [{"type": "command"}]),
])
def test_changed_effect_or_binding_is_rejected(field: str, value: object) -> None:
    payload = _source()
    record = payload["results"]
    assert isinstance(record, dict)
    record[field] = value
    with pytest.raises(JobDefinitionCreateContractError, match="unavailable"):
        _compile(payload)


def test_ambiguous_source_is_rejected() -> None:
    payload = _source()
    payload["results"] = [payload["results"], payload["results"]]
    with pytest.raises(JobDefinitionCreateContractError, match="unavailable"):
        _compile(payload)


def test_unbound_requester_is_rejected() -> None:
    with pytest.raises(JobDefinitionCreateContractError, match="unavailable"):
        compile_disabled_job_create_body(
            _source(),
            source_name="mcp-v4-bp008-job-20260930-r3",
            target_name="mcp-v4-bp008-job-20260930-r4",
            target_requester="admin api",
            expected_secret_id=999,
        )


def _ack_pins():
    return DisabledJobCreateAckPins("mcp-v4-bp008-job-20261021-r99",
        hashlib.sha256(b"synthetic-appliance").hexdigest(),
        "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64)


def _ack():
    return dict(version="v7.0.0", build=29, http_method="POST", http_status=200,
        status="success", path="secret", name="job", vdom="root",
        serial="synthetic-appliance", mkey=_ack_pins().job_name, error=0)


def _ack_bytes(value):
    return bytearray(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode())


def _consume_ack(raw, pins=None, **options):
    return consume_disabled_job_create_ack(raw, pins=pins or _ack_pins(),
        http_status=options.get("http_status", 200),
        content_type=options.get("content_type", "application/json"),
        witness_key=options.get("witness_key", b"synthetic-job-ack-witness-key-32bytes"))


def test_ack_witness_binds_original_context_without_decoding_private_content(monkeypatch):
    from fortipam_mcp import secret_bulk_import_metadata as metadata
    value = _ack()
    value["unknown"] = {"script": "SYNTHETIC_PRIVATE_SCRIPT", "password": ["SYNTHETIC_SECRET"]}
    original = metadata._scalar
    original_loads = json.loads

    def scalar(buffer, span):
        token = bytes(buffer[slice(*span)])
        assert b"SYNTHETIC_PRIVATE" not in token and b"SYNTHETIC_SECRET" not in token
        return original(buffer, span)

    monkeypatch.setattr(metadata, "_scalar", scalar)
    def scalar_loads(token, *args, **kwargs):
        assert bytes(token).lstrip()[:1] not in (b"{", b"[")
        return original_loads(token, *args, **kwargs)

    monkeypatch.setattr(json, "loads", scalar_loads)
    raw = _ack_bytes(value)
    witness = _consume_ack(raw)
    assert not any(raw) and witness.context_digest == _ack_pins().context_digest
    assert "20261021" not in repr(witness) and "20261021" not in repr(_ack_pins())
    for field in ("requester_digest", "body_digest", "plan_digest", "authorization_digest", "private_nonce"):
        other = replace(_ack_pins(), **{field: "f" * 64})
        changed = _consume_ack(_ack_bytes(value), other)
        assert changed.context_digest != witness.context_digest
        assert changed.acknowledgement_digest != witness.acknowledgement_digest
    assert _consume_ack(_ack_bytes(value), witness_key=b"other-synthetic-job-ack-key-32bytes").acknowledgement_digest != witness.acknowledgement_digest
    for private in (witness, _ack_pins()):
        with pytest.raises(TypeError): json.dumps(private)
        with pytest.raises(MaterialAccessDenied): copy.copy(private)


@pytest.mark.parametrize("field,value", [
    ("http_method", "GET"), ("http_method", "DELETE"), ("http_status", True),
    ("status", "OK"), ("status", "error"), ("build", True), ("build", 30),
    ("version", "v1.9.1"), ("path", "system"), ("name", "database"), ("vdom", "other"),
    ("mkey", 99), ("mkey", "mcp-v4-bp008-job-20261021-r98"),
    ("serial", "another-appliance"), ("error", False), ("error", None), ("error", -3),
    ("results", {}), ("action", ""), ("schema_errors", []),
])
def test_wrong_or_uncertain_job_ack_is_not_evidence_and_is_erased(field, value):
    raw = _ack_bytes({**_ack(), field: value})
    with pytest.raises(JobDefinitionCreateContractError, match="^The fixed disabled Job definition is unavailable.$"):
        _consume_ack(raw)
    assert not any(raw)


@pytest.mark.parametrize("fault", ["missing", "duplicate", "escaped-duplicate", "two-documents", "oversize",
    "bad-json", "wrong-http", "boolean-http", "bad-media", "short-key", "alias-key", "missing-pins"])
def test_ambiguous_job_ack_consumption_erases_even_before_envelope_validation(fault):
    value, options = _ack(), {}
    if fault == "missing": del value["mkey"]
    raw = _ack_bytes(value)
    if fault == "duplicate": raw[-1:] = b',"mkey":"duplicate"}'
    if fault == "escaped-duplicate": raw[-1:] = b',"m\\u006bey":"duplicate"}'
    if fault == "two-documents": raw.extend(b"{}")
    if fault == "oversize": raw.extend(b" " * 16_385)
    if fault == "bad-json": raw[-1:] = b",}"
    if fault == "wrong-http": options["http_status"] = 403
    if fault == "boolean-http": options["http_status"] = True
    if fault == "bad-media": options["content_type"] = "text/html"
    if fault == "short-key": options["witness_key"] = b"short"
    if fault == "alias-key": options["witness_key"] = raw
    with pytest.raises(JobDefinitionCreateContractError):
        if fault == "missing-pins":
            consume_disabled_job_create_ack(raw, pins=None, http_status=200,
                content_type="application/json", witness_key=b"synthetic-job-ack-witness-key-32bytes")
        else:
            _consume_ack(raw, **options)
    assert not any(raw)


def test_ack_context_refuses_invalid_selector_digest_and_forged_pin_fields():
    for change in ({"job_name": "foreign/selector"}, {"job_name": True},
                   {"plan_digest": "short"}, {"private_nonce": "z" * 64}):
        with pytest.raises(JobDefinitionCreateContractError): replace(_ack_pins(), **change)
    forged = _ack_pins()
    object.__setattr__(forged, "authorization_digest", "bad")
    raw = _ack_bytes(_ack())
    with pytest.raises(JobDefinitionCreateContractError): _consume_ack(raw, forged)
    assert not any(raw)
