"""Exact native PUT metadata, context separation and byte-only erasure."""
from dataclasses import replace
import hashlib
import json

import pytest

from fortipam_mcp import secret_instruction_build29_put_ack as a
from fortipam_mcp import secret_bulk_import_metadata as metadata

KEY = b"synthetic-instruction-ack-witness-key"


def pins():
    return a.SecretInstructionBuild29PutAckPins(37, hashlib.sha256(b"unit-appliance").hexdigest(),
        "c" * 64, "mcp-v4-ip-unit", "attach", "a" * 64, "b" * 64, "success")


def envelope():
    return dict(version="v7.0.0", build=29, http_method="PUT", http_status=200, status="success",
        path="secret", name="database", vdom="root", serial="unit-appliance", mkey=37, error=0)


def raw(value):
    return bytearray(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode())


def consume(buffer, capture=None, **kwargs):
    return a.consume_secret_instruction_build29_put_ack(buffer, pins=capture or pins(),
        http_status=kwargs.get("http_status", 200), content_type=kwargs.get("content_type", "application/json"),
        witness_key=kwargs.get("witness_key", KEY))


def test_exact_put_witness_is_private_and_context_bound_without_authority(monkeypatch):
    value = envelope()
    value["unselected"] = {"Password": "synthetic-private-秘密", "totp": ["undecoded"]}
    original_scalar = metadata._scalar
    decoded = []
    def scalar(buffer, span):
        token = bytes(buffer[slice(*span)])
        assert b"synthetic-private" not in token and b"undecoded" not in token
        decoded.append(token)
        return original_scalar(buffer, span)
    monkeypatch.setattr(metadata, "_scalar", scalar)
    data = raw(value)
    witness = consume(data)
    assert not any(data) and witness.context_digest == pins().context_digest
    assert decoded and "unit-appliance" not in repr(witness) and "mcp-v4" not in repr(pins())
    with pytest.raises(TypeError): json.dumps(witness)
    for capture in (replace(pins(), phase="restore"), replace(pins(), plan_digest="d" * 64),
            replace(pins(), authorization_digest="e" * 64), replace(pins(), creation_digest="f" * 64),
            replace(pins(), instruction_profile_name="mcp-v4-ip-other"),
            replace(pins(), retained_body_digest="1" * 64), replace(pins(), retained_body_digest="2" * 64)):
        assert consume(raw(value), capture).acknowledgement_digest != witness.acknowledgement_digest
    assert consume(raw(value), witness_key=b"other-synthetic-instruction-ack-key").acknowledgement_digest != witness.acknowledgement_digest


@pytest.mark.parametrize("field,value", [("http_method", "POST"), ("http_method", "DELETE"),
    ("http_status", True), ("status", "OK"), ("serial", "foreign-appliance"), ("mkey", "37"),
    ("mkey", 38), ("build", 30), ("error", None), ("error", 2), ("path", "system"),
    ("action", ""), ("schema_errors", []), ("results", "synthetic-private")])
def test_foreign_or_uncertain_native_ack_is_erased_and_cannot_be_restoration_evidence(field, value):
    data = raw({**envelope(), field: value})
    with pytest.raises(a.SecretInstructionBuild29PutAckError) as error:
        consume(data)
    assert not any(data) and str(error.value) == "The private Secret Instruction PUT acknowledgement is unavailable."


@pytest.mark.parametrize("fault", ["duplicate", "escaped-duplicate", "missing", "two-documents", "oversize",
    "http-denied", "bad-media", "short-key", "key-alias"])
def test_ambiguous_or_incomplete_inputs_fail_closed_and_erase(fault):
    data, options = raw(envelope()), {}
    if fault == "duplicate": data[-1:] = b',"mkey":37}'
    if fault == "escaped-duplicate": data[-1:] = b',"m\\u006bey":37}'
    if fault == "missing":
        value = envelope(); del value["serial"]; data = raw(value)
    if fault == "two-documents": data.extend(b"{}")
    if fault == "oversize": data.extend(b" " * 16_385)
    if fault == "http-denied": options["http_status"] = 403
    if fault == "bad-media": options["content_type"] = "text/html"
    if fault == "short-key": options["witness_key"] = b"short"
    if fault == "key-alias": options["witness_key"] = data
    with pytest.raises(a.SecretInstructionBuild29PutAckError): consume(data, **options)
    assert not any(data)


def test_status_pin_and_invalid_context_cannot_be_silently_widened():
    data = raw({**envelope(), "status": "OK"})
    assert consume(data, replace(pins(), success_status="OK")).context_digest != pins().context_digest
    assert not any(data)
    for changes in ({"phase": "source"}, {"native_secret_id": True}, {"success_status": None},
            {"plan_digest": "bad"}, {"instruction_profile_name": "foreign/profile"}):
        with pytest.raises(a.SecretInstructionBuild29PutAckError): replace(pins(), **changes)
