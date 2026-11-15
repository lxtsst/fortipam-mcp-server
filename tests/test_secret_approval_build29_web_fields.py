import hashlib
import json

import pytest

from fortipam_mcp import secret_approval_build29_web_fields as candidate


IDENTITY = {"id": 17, "name": "synthetic-web", "folder": 9,
            "template": "Web Account", "target": ""}
URL = "https://example.test/"
ACCOUNT = b'synthetic-"account\\'
PASSWORD = b'opaque-\\"token\\\\with\\u0041'


def source() -> tuple[bytearray, str]:
    row = {**IDENTITY, "recording": "enable", "totp-setting": {"status": "disable", "shared-key": None},
           "permissions": {"approval_status": "none", "user": 4}}
    expected = {**row, "permissions": {"user": 4}}
    digest = hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    envelope = {"version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
                "path": "secret", "name": "database", "status": "OK", "results": [row]}
    raw = bytearray(json.dumps(envelope).encode())
    fields = (b'[{"id":3,"name":"URL","desc":"","type":"url","q_origin_key":3,"value":' + json.dumps(URL).encode()
              + b'},{"id":2,"name":"Username","desc":"","type":"username","q_origin_key":2,"value":'
              + json.dumps(ACCOUNT.decode()).encode()
              + b'},{"id":1,"name":"Password","desc":"","type":"password","q_origin_key":1,"value":"'
              + PASSWORD + b'"}]')
    at = raw.index(b'"recording"')
    raw[at:at] = b'"field":' + fields + b','
    raw = raw.replace(b'"shared-key": null', b'"shared-key": "opaque-totp"')
    return raw, digest


def project(raw: bytearray, digest: str) -> bytearray:
    return candidate.project_secret_approval_build29_web_fields(
        raw, identity=IDENTITY, expected_metadata_digest=digest,
        username=memoryview(ACCOUNT), web_url=URL,
    )


def test_private_projection_preserves_raw_slots_without_decoding_material_and_erases_source(monkeypatch: pytest.MonkeyPatch) -> None:
    raw, digest = source()
    original_loads = json.loads
    original_zeroize = candidate._zeroize_mutable
    erased: list[bytearray] = []

    def guarded_loads(value: object, **kwargs: object) -> object:
        assert isinstance(value, (str, bytes, bytearray))
        encoded = value.encode() if isinstance(value, str) else value
        assert not any(marker in encoded for marker in (
            json.dumps(ACCOUNT.decode()).encode(), PASSWORD, b"opaque-totp",
        ))
        return original_loads(value, **kwargs)

    def zeroize(value: bytearray) -> None:
        original_zeroize(value)
        erased.append(value)

    monkeypatch.setattr(candidate.json, "loads", guarded_loads)
    monkeypatch.setattr(candidate, "_zeroize_mutable", zeroize)
    result = project(raw, digest)
    assert isinstance(result, bytearray) and not raw
    assert b'"value":"' + PASSWORD + b'"' in result
    assert all(key not in result for key in (b'"keyinfo"', b'"desc"', b'"type"', b'"q_origin_key"'))
    assert result.index(b'"Password"') < result.index(b'"URL"') < result.index(b'"Username"')
    assert all(not value for value in erased)
    candidate._zeroize_mutable(result)
    assert not result


@pytest.mark.parametrize("before,after", [
    (b'"id":17', b'"id":18'),
    (b'"folder":9', b'"folder":10'),
    (b'"template":"Web Account"', b'"template":"Unknown"'),
    (b'"target":""', b'"target":"synthetic-target"'),
    (b'"build":29', b'"build":30'),
    (b'"http_method":"GET"', b'"http_method":"PUT"'),
    (b'"status":"OK"', b'"status":"error"'),
    (b'"recording":"enable"', b'"recording":"disable"'),
    (b'"approval_status":"none"', b'"approval_status":"unknown"'),
    (b'"approval_status":"none"', b'"approval_status":null'),
    (b'"user":4', b'"user":3'),
    (b'"id":3', b'"id":0'),
    (b'"id":3', b'"id":true'),
    (b'"id":3', b'"id":2'),
    (b'"id":3', b'"id":3,"id":3'),
    (b'"name":"URL"', b'"name":"Username"'),
    (b'"name":"URL"', b'"name":"Unknown"'),
    (b'"name":"URL"', b'"name":"URL","extra":1'),
    (b'"desc":"",', b''),
    (b'"desc":""', b'"desc":null'),
    (b'"desc":""', b'"desc":"nonempty"'),
    (b'"desc":""', b'"desc":"","desc":""'),
    (b'"type":"url"', b'"type":"password"'),
    (b'"type":"url"', b'"type":null'),
    (b'"q_origin_key":3', b'"q_origin_key":4'),
    (b'"q_origin_key":3', b'"q_origin_key":"3"'),
    (b'"q_origin_key":3', b'"q_origin_key":true'),
    (b'"name":"URL"', b'"name":"URL","keyinfo":""'),
    (b'https://example.test/', b'https://drift.test/'),
    (b'synthetic-', b'different-'),
    (b'"value":"https://example.test/"', b'"value":null'),
    (b'"value":"https://example.test/"', b'"value":""'),
    (b'"value":"https://example.test/"', b'"value":"https://example.test/","value":"https://example.test/"'),
    (b'"value":"https://example.test/"', b'"value":"https:\\/\\/example.test/"'),
    (b'opaque-\\"token', b'opaque-\\xtoken'),
])
def test_unqualified_slot_identity_and_drift_refuse_without_material_in_error(
    before: bytes, after: bytes, monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw, digest = source()
    # Compact only public whitespace; never decode the protected response.
    raw = raw.replace(b': ', b':').replace(b', ', b',')
    assert before in raw
    raw = raw.replace(before, after, 1)
    original_zeroize = candidate._zeroize_mutable
    erased: list[bytearray] = []

    def zeroize(value: bytearray) -> None:
        original_zeroize(value)
        erased.append(value)

    monkeypatch.setattr(candidate, "_zeroize_mutable", zeroize)
    with pytest.raises(candidate.SecretApprovalBuild29WebFieldsError) as failure:
        project(raw, digest)
    assert str(failure.value) == "The private build-29 Web Account fields are unavailable."
    assert "opaque" not in repr(failure.value) and "synthetic" not in repr(failure.value)
    assert not raw and erased and all(not value for value in erased)


def test_missing_slot_or_unqualified_binding_is_consumed_without_dispatch() -> None:
    raw, digest = source()
    begin = raw.index(b'{"id":3,"name":"URL"')
    end = raw.index(b'},{"id":2', begin) + 2
    del raw[begin:end]
    with pytest.raises(candidate.SecretApprovalBuild29WebFieldsError):
        project(raw, digest)
    assert not raw
    raw, digest = source()
    with pytest.raises(candidate.SecretApprovalBuild29WebFieldsError):
        candidate.project_secret_approval_build29_web_fields(
            raw, identity={**IDENTITY, "id": True}, expected_metadata_digest=digest,
            username=memoryview(ACCOUNT), web_url=URL,
        )
    assert not raw


def test_one_identical_nonselected_native_member_uses_existing_normalizer() -> None:
    raw, digest = source()
    member = b'"recording": "enable"'
    raw = raw.replace(member, member + b", " + member)
    result = project(raw, digest)
    assert b'"value":"' + PASSWORD + b'"' in result and not raw
    candidate._zeroize_mutable(result)


def test_web_projection_uses_same_exact_annotation_normalization() -> None:
    raw, digest = source()
    raw = raw.replace(b'"approval_status": "none"', b'"approval_status": "required"')
    raw = raw.replace(b'"recording"', b'"num-approval-tiers":1,"recording"', 1)
    result = project(raw, digest)
    assert b'"value":"' + PASSWORD + b'"' in result and not raw
    candidate._zeroize_mutable(result)


@pytest.mark.parametrize("kind", [
    "conflict", "decoded_equal", "two", "identity", "template", "target", "field",
    "keyinfo", "approval", "origin", "envelope", "nested", "totp", "totp_nested",
])
def test_duplicate_exception_refuses_conflicting_selected_or_protected_members(kind: str) -> None:
    raw, digest = source()
    member = b'"recording": "enable"'
    replacement = member
    if kind == "conflict":
        replacement = member + b', "recording": "disable"'
    elif kind == "decoded_equal":
        replacement = member + b', "recording": "en\\u0061ble"'
    elif kind == "two":
        replacement = member + b", " + member + b", " + member
    elif kind in ("identity", "template", "target", "envelope"):
        member = {"identity": b'"id": 17', "template": b'"template": "Web Account"',
                  "target": b'"target": ""', "envelope": b'"build": 29'}[kind]
        replacement = member + b", " + member
    elif kind in ("keyinfo", "approval", "origin"):
        key = {"keyinfo": "keyinfo", "approval": "need-approval", "origin": "q_origin_key"}[kind]
        replacement = member + b', "' + key.encode() + b'":null, "' + key.encode() + b'":null'
    elif kind == "field":
        replacement = member + b', "field":null'
    elif kind == "nested":
        replacement = member + b', "extra":{"x":1,"x":1}'
    elif kind == "totp":
        member = b'"totp-setting": {"status": "disable", "shared-key": "opaque-totp"}'
        replacement = member + b", " + member.replace(b"opaque-totp", b"different")
    else:
        member = b'"shared-key": "opaque-totp"'
        replacement = member + b", " + member.replace(b"opaque-totp", b"different")
    assert member in raw
    raw = raw.replace(member, replacement, 1)
    with pytest.raises(candidate.SecretApprovalBuild29WebFieldsError) as failure:
        project(raw, digest)
    assert not raw and "opaque" not in repr(failure.value)
