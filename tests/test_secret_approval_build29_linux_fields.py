"""Synthetic offline boundaries; no device or stored-password qualification."""
import json

import pytest

from fortipam_mcp import secret_approval_build29_linux_fields as candidate
from fortipam_mcp.secret_approval_build29_linux_metadata import (
    _NATIVE_ENVELOPE, qualify_secret_approval_build29_linux_metadata,
)
from fortipam_mcp.target_contract import DEFAULT_TEMPLATE

IDENTITY = {"id": 17, "name": "synthetic-linux", "folder": 9,
            "template": DEFAULT_TEMPLATE, "target": "synthetic-target"}
ADDRESS = "192.0.2.10"
ACCOUNT = bytearray(b'synthetic-"account\\')
PASSWORD_TOKEN = b'"opaque-\\"token\\\\with\\u0041"'


def source():
    row = {**IDENTITY, "need-approval": "disable", "need-approval-job": "disable",
           "bypass-approval": "disable", "approval-profile": "", "inherit-permission": "enable",
           "totp-setting": {"status": "disable", "shared-key": "opaque-totp"},
           "keyinfo": "opaque-key", "field": [
               {"id": 3, "name": "Password", "type": "password", "value": "REPLACE"},
               {"id": 1, "name": "Host", "type": "target-address", "value": ADDRESS},
               {"id": 2, "name": "Username", "type": "username", "value": ACCOUNT.decode()},
           ]}
    raw = bytearray(json.dumps({**_NATIVE_ENVELOPE, "serial": "SYNTHETIC1", "results": [row]},
                               separators=(",", ":")).encode()).replace(b'"REPLACE"', PASSWORD_TOKEN)
    digest = qualify_secret_approval_build29_linux_metadata(
        bytearray(raw), identity=IDENTITY, expected_serial="SYNTHETIC1",
    ).metadata_digest
    return raw, digest


def project(raw, digest, **overrides):
    arguments = dict(identity=IDENTITY, expected_serial="SYNTHETIC1",
                     expected_metadata_digest=digest, username=memoryview(ACCOUNT),
                     target_ipv4_address=ADDRESS)
    arguments.update(overrides)
    return candidate.project_secret_approval_build29_linux_fields(raw, **arguments)


def track_erasure(monkeypatch):
    erased = []
    original = candidate._zeroize_mutable

    def zeroize(value):
        original(value)
        erased.append(value)

    monkeypatch.setattr(candidate, "_zeroize_mutable", zeroize)
    return erased


@pytest.mark.parametrize("annotations", [False, True])
def test_observed_type_grammar_and_opaque_projection_without_material_decode(monkeypatch, annotations):
    raw, digest = source()
    if annotations:
        raw = raw.replace(b'"id":3', b'"desc":"observed annotation","q_origin_key":3,"id":3')
    erased = track_erasure(monkeypatch)
    original = json.loads
    encoded_account = json.dumps(ACCOUNT.decode()).encode()

    def guarded(value, **kwargs):
        encoded = value.encode() if isinstance(value, str) else value
        assert not any(marker in encoded for marker in (
            PASSWORD_TOKEN, encoded_account, ADDRESS.encode(), b"opaque-totp", b"opaque-key",
        ))
        return original(value, **kwargs)

    monkeypatch.setattr(candidate.json, "loads", guarded)
    result = project(raw, digest)
    assert type(result) is bytearray
    assert b'"value":' + PASSWORD_TOKEN in result
    assert result.index(b'"Host"') < result.index(b'"Username"') < result.index(b'"Password"')
    assert all(key not in result for key in (b'"type"', b'"desc"', b'"q_origin_key"', b'"keyinfo"'))
    assert not raw and erased and all(not buffer for buffer in erased)
    assert ACCOUNT == b'synthetic-"account\\'
    candidate._zeroize_mutable(result)


@pytest.mark.parametrize("before,after", [
    (b'"id":17', b'"id":18'),
    (b'"name":"synthetic-linux"', b'"name":"changed"'),
    (b'"folder":9', b'"folder":10'),
    (b'"target":"synthetic-target"', b'"target":"other"'),
    (b'"serial":"SYNTHETIC1"', b'"serial":"OTHER"'),
    (b'"build":29', b'"build":30'),
    (b'"http_method":"GET"', b'"http_method":"PUT"'),
    (b'"inherit-permission":"enable"', b'"inherit-permission":"disable"'),
    (b'"id":17', b'"id":17,"id":17'),
    (b'"id":3', b'"id":3,"id":3'),
    (b'"id":3', b'"id":1'),
    (b'"id":3', b'"id":true'),
    (b'"id":3', b'"id":0'),
    (b'"name":"Host"', b'"name":"Username"'),
    (b'"type":"target-address"', b'"type":"host"'),
    (b'"type":"username"', b'"type":"password"'),
    (b'"type":"password"', b'"type":"username"'),
    (b'"type":"password",', b''),
    (b'"name":"Host"', b'"name":"Host","unknown":1'),
    (b'"name":"Host"', b'"name":"Host","desc":"","desc":""'),
    (b'"name":"Host"', b'"name":"Host","q_origin_key":1,"q_origin_key":1'),
    (b'"value":"192.0.2.10"', b'"value":"192.0.2.11"'),
    (b'"value":"192.0.2.10"', b'"value":"192.0.2.\\u00310"'),
    (b'"value":"192.0.2.10"', b'"value":"192.0.2.10","value":"192.0.2.10"'),
    (b'synthetic-\\"account', b'drift-\\"account'),
    (PASSWORD_TOKEN, b'null'),
    (PASSWORD_TOKEN, b'""'),
    (PASSWORD_TOKEN, b'"bad-\\x-token"'),
    (PASSWORD_TOKEN, b'"bad-\xff-token"'),
])
def test_binding_slot_and_material_drift_rejected_with_erasure(monkeypatch, before, after):
    raw, digest = source()
    assert before in raw
    raw = raw.replace(before, after, 1)
    erased = track_erasure(monkeypatch)
    with pytest.raises(candidate.SecretApprovalBuild29LinuxFieldsError) as failure:
        project(raw, digest)
    assert str(failure.value) == "The private build-29 Linux fields are unavailable."
    assert not raw and erased and all(not buffer for buffer in erased)


@pytest.mark.parametrize("override", [
    {"identity": {**IDENTITY, "template": "Web Account"}},
    {"identity": {**IDENTITY, "id": True}},
    {"expected_serial": "OTHER"}, {"expected_metadata_digest": "0" * 64},
    {"expected_metadata_digest": "invalid"},
    {"username": memoryview(bytearray(b"other"))},
    {"target_ipv4_address": "192.0.2.11"}, {"target_ipv4_address": "::1"},
])
def test_caller_binding_refusal_consumes_source(override):
    raw, digest = source()
    with pytest.raises(candidate.SecretApprovalBuild29LinuxFieldsError):
        project(raw, digest, **override)
    assert not raw


def test_enabled_totp_refused_even_with_matching_digest():
    raw, _ = source()
    raw = raw.replace(b'"status":"disable"', b'"status":"enable"')
    digest = qualify_secret_approval_build29_linux_metadata(
        bytearray(raw), identity=IDENTITY, expected_serial="SYNTHETIC1",
    ).metadata_digest
    with pytest.raises(candidate.SecretApprovalBuild29LinuxFieldsError):
        project(raw, digest)
    assert not raw


@pytest.mark.parametrize("extra", [False, True])
def test_exact_three_slot_set_required(extra):
    raw, digest = source()
    if extra:
        raw = raw.replace(b'"field":[', b'"field":[{"id":4,"name":"Other","type":"text","value":"x"},')
    else:
        start = raw.index(b'{"id":3')
        end = raw.index(b'},{"id":1', start) + 2
        del raw[start:end]
    with pytest.raises(candidate.SecretApprovalBuild29LinuxFieldsError):
        project(raw, digest)
    assert not raw


def test_partial_output_is_erased_on_late_failure(monkeypatch):
    raw, digest = source()
    erased = track_erasure(monkeypatch)
    original = candidate._slots

    def incomplete(field):
        slots = original(field)
        del slots["Password"]
        return slots

    monkeypatch.setattr(candidate, "_slots", incomplete)
    with pytest.raises(candidate.SecretApprovalBuild29LinuxFieldsError):
        project(raw, digest)
    assert len(erased) == 6 and all(not buffer for buffer in erased)
