"""Synthetic response-boundary cases; no device material or access."""

import hashlib
import hmac
import json
from typing import Any

import pytest

import fortipam_mcp.secret_approval_build29_totp_boundary as module
from fortipam_mcp.secret_approval_build29_totp_boundary import (
    SecretApprovalBuild29TotpBoundaryError,
    consume_secret_approval_build29_totp_response as consume,
)


_KEY = b"synthetic-unit-witness-key-only-01"
_PIN: dict[str, str | int] = {
    "version": "v7.0.0", "build": 29, "serial": "FPAVUNIT0001",
    "http_method": "POST", "http_status": 200, "status": "OK", "error": 0,
}


def _raw(result: object = "") -> bytearray:
    return bytearray(json.dumps({**_PIN, "results": result}).encode())


def _consume(raw: bytearray, **changes: Any) -> module.SecretApprovalBuild29TotpWitness:
    arguments: dict[str, Any] = {
        "http_status": 200, "content_type": "application/json; charset=utf-8",
        "expected_envelope": _PIN, "witness_key": _KEY,
    }
    arguments.update(changes)
    return consume(raw, **arguments)


@pytest.mark.parametrize("material", ["", "MFRGGZDFMZTWQ2LK", "mfrggzdf", "MY======"])
def test_exact_scalar_hmac_and_buffer_consumption(material: str) -> None:
    raw = _raw(material)
    witness = _consume(raw)
    assert witness.material_digest == hmac.new(_KEY, material.encode(), hashlib.sha256).hexdigest()
    assert witness.explicit_empty is (material == "")
    assert witness.material_digest not in repr(witness)
    assert not raw


def test_no_response_json_decoding_or_material_copy(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _raw("MFRGGZDF")
    original_new = hmac.new
    seen = []

    def checked_new(key: bytes, msg: object, digestmod: Any) -> Any:
        assert type(msg) is memoryview
        assert msg.obj is raw
        seen.append(True)
        return original_new(key, msg, digestmod)

    def forbidden_loads(*args: object, **kwargs: object) -> object:
        raise AssertionError("Response decoding is forbidden.")

    monkeypatch.setattr(module.hmac, "new", checked_new)
    monkeypatch.setattr(module.json, "loads", forbidden_loads)
    assert not _consume(raw).explicit_empty
    assert seen == [True]
    assert not raw


@pytest.mark.parametrize("result", [None, 0, True, [], {}, "123456", "AB+CD", "AB_CD", "AB-CD",
                                   "AB CD", "AB\nCD", "é", "=", "AB=CD", "A" * 129])
def test_reject_unsupported_or_nonstring_material(result: object) -> None:
    raw = _raw(result)
    with pytest.raises(SecretApprovalBuild29TotpBoundaryError) as caught:
        _consume(raw)
    assert str(caught.value) == module._UNAVAILABLE
    assert caught.value.__cause__ is None
    assert not raw


@pytest.mark.parametrize("name,replacement", [
    ("version", "v7.0.1"), ("build", True), ("build", 30), ("build", "29"),
    ("serial", "FPAVOTHER0001"), ("http_method", "GET"), ("http_status", True),
    ("http_status", 201), ("status", "success"), ("status", "error"), ("error", 1),
])
def test_reject_envelope_identity_status_and_exact_types(name: str, replacement: object) -> None:
    payload: dict[str, object] = {**_PIN, "results": ""}
    payload[name] = replacement
    raw = bytearray(json.dumps(payload).encode())
    with pytest.raises(SecretApprovalBuild29TotpBoundaryError):
        _consume(raw)
    assert not raw


@pytest.mark.parametrize("raw", [
    b'{}', b'[]', b'null', b'{"status":"OK"}',
    b'{"status":"OK","results":"","results":""}',
    b'{"status":"OK","status":"OK","results":""}',
    b'{"status":"OK","results":"","schema_errors":[]}',
    b'{"status":"OK","results":"","unknown":null}',
    b'{"status":"OK","results":"","error":0}',
    b'{"status":"OK","resu\\u006cts":""}',
    b'{"status":"OK","results":"\\u0041"}',
    b'{"status":"OK","results":""}{}',
    b'{"status":"OK","results":"",}',
    b'{"status":"OK","results":""',
    b'{"status":"OK" "results":""}',
])
def test_reject_missing_duplicate_error_escaped_or_ambiguous_response(raw: bytes) -> None:
    buffer = bytearray(raw)
    with pytest.raises(SecretApprovalBuild29TotpBoundaryError):
        _consume(buffer, expected_envelope={"status": "OK"})
    assert not buffer


def test_only_explicitly_pinned_observed_envelope_is_accepted() -> None:
    raw = bytearray(b' \n { "results" : "", "status" : "success" } \t')
    assert _consume(raw, expected_envelope={"status": "success"}).explicit_empty
    assert not raw


def test_minimal_post_envelope_requires_its_exact_pinned_members() -> None:
    pin = {"status": "OK", "http_method": "POST", "http_status": 200}
    raw = bytearray(b'{"http_method":"POST","http_status":200,"results":"","status":"OK"}')
    assert _consume(raw, expected_envelope=pin).explicit_empty
    assert not raw
    raw = bytearray(b'{"http_method":"POST","http_status":200,"results":"","status":"OK","build":29}')
    with pytest.raises(SecretApprovalBuild29TotpBoundaryError):
        _consume(raw, expected_envelope=pin)
    assert not raw


def test_six_member_subject_message_envelope_is_exact_and_private() -> None:
    pin = {"status": "OK", "http_method": "POST", "http_status": 200,
           "secret-id": 24, "msg": "Synthetic unit status."}
    raw = bytearray(json.dumps({**pin, "results": "MFRGGZDF"}).encode())
    witness = _consume(raw, expected_envelope=pin)
    assert witness.material_digest == hmac.new(_KEY, b"MFRGGZDF", hashlib.sha256).hexdigest()
    assert not witness.explicit_empty
    assert witness.material_digest not in repr(witness)
    assert "Synthetic unit status." not in repr(witness)
    assert not raw


@pytest.mark.parametrize("name,replacement", [
    ("secret-id", True), ("secret-id", 0), ("secret-id", 25),
    ("msg", "Other synthetic status."), ("msg", "Synthetic\nstatus."),
    ("msg", "x" * 257),
])
def test_subject_and_message_response_must_match_pin(name: str, replacement: object) -> None:
    pin = {"status": "OK", "http_method": "POST", "http_status": 200,
           "secret-id": 24, "msg": "Synthetic unit status."}
    payload: dict[str, object] = {**pin, "results": ""}
    payload[name] = replacement
    raw = bytearray(json.dumps(payload).encode())
    with pytest.raises(SecretApprovalBuild29TotpBoundaryError):
        _consume(raw, expected_envelope=pin)
    assert not raw


@pytest.mark.parametrize("missing", ["secret-id", "msg"])
def test_subject_message_members_cannot_be_missing(missing: str) -> None:
    pin = {"status": "OK", "http_method": "POST", "http_status": 200,
           "secret-id": 24, "msg": "Synthetic unit status."}
    payload: dict[str, object] = {**pin, "results": ""}
    del payload[missing]
    raw = bytearray(json.dumps(payload).encode())
    with pytest.raises(SecretApprovalBuild29TotpBoundaryError):
        _consume(raw, expected_envelope=pin)
    assert not raw


@pytest.mark.parametrize("name,value", [
    ("secret-id", True), ("secret-id", 0), ("secret-id", -1),
    ("secret-id", 2_147_483_648), ("msg", ""), ("msg", "Synthetic\nstatus."),
    ("msg", "x" * 257), ("msg", "é"), ("msg", "\x7f"),
])
def test_invalid_subject_and_message_pins_are_rejected(name: str, value: object) -> None:
    pin: dict[str, object] = {"status": "OK", "http_method": "POST", "http_status": 200,
                              "secret-id": 24, "msg": "Synthetic unit status."}
    pin[name] = value
    raw = bytearray(json.dumps({**pin, "results": ""}).encode())
    with pytest.raises(SecretApprovalBuild29TotpBoundaryError):
        _consume(raw, expected_envelope=pin)
    assert not raw


@pytest.mark.parametrize("changes", [
    {"http_status": True}, {"http_status": 403}, {"content_type": "text/json"},
    {"witness_key": b""}, {"witness_key": b"x" * 31}, {"witness_key": "x" * 32},
    {"expected_envelope": {}}, {"expected_envelope": {"status": ["OK", "success"]}},
    {"expected_envelope": {"status": "OK", "build": True}},
    {"expected_envelope": {"status": "OK", "error": 1}},
    {"expected_envelope": {"status": "OK", "schema_errors": 0}},
    {"expected_envelope": {"status": "OK", "serial": "private\nserial"}},
])
def test_reject_untrusted_contract_or_weak_key_and_consume_input(changes: dict[str, object]) -> None:
    raw = _raw()
    with pytest.raises(SecretApprovalBuild29TotpBoundaryError):
        _consume(raw, **changes)
    assert not raw


def test_raw_size_limit_and_external_view_are_zeroized(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _raw("MFRGGZDF")
    monkeypatch.setattr(module, "MAX_RESPONSE_BYTES", len(raw) - 1)
    with memoryview(raw) as view:
        with pytest.raises(SecretApprovalBuild29TotpBoundaryError):
            _consume(raw)
        assert all(value == 0 for value in view)
    assert all(value == 0 for value in raw)


def test_hmac_failure_does_not_retain_response(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _raw("MFRGGZDF")

    def fail(*args: object, **kwargs: object) -> object:
        raise RuntimeError("Synthetic private detail.")

    monkeypatch.setattr(module.hmac, "new", fail)
    with pytest.raises(SecretApprovalBuild29TotpBoundaryError) as caught:
        _consume(raw)
    assert str(caught.value) == module._UNAVAILABLE
    assert not raw
