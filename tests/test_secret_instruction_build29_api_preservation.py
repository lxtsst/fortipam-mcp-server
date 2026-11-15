"""Private API consumers with synthetic full rows and clear-source responses."""
from copy import deepcopy
import hashlib
import hmac
import json
from typing import Any

import pytest

from fortipam_mcp import secret_instruction_build29_api_preservation as c
from fortipam_mcp.secret_approval_build29_totp_boundary import SecretApprovalBuild29TotpWitness

KEY = b"synthetic-instruction-api-key-0001"
IDENTITY: dict[str, object] = {"id": 24, "name": "mcp-v4-api-unit01", "folder": 3,
                              "template": "Web Account", "target": "",
                              "uuid": "12345678-1234-1234-1234-123456789abc"}
PROFILE = "mcp-v4-ip-unit01"
SERIAL = "SYNTHETICSERIAL01"
ENVELOPE: dict[str, str | int] = {"secret-id": 24, "http_method": "POST", "http_status": 200,
                                 "status": "OK", "msg": "Synthetic qualified clear source"}
PASSWORD = 'synthetic-password-中文-"-\\'


def _clear(material: object = PASSWORD, **changes: object) -> bytearray:
    return bytearray(json.dumps({**ENVELOPE, "results": material, **changes}, ensure_ascii=False,
                               separators=(",", ":")).encode())


def _credential(material: object = PASSWORD, **changes: Any) -> c.SecretInstructionBuild29CredentialWitness:
    args: dict[str, Any] = {"expected_secret_id": 24, "expected_field_id": 1, "http_status": 200,
                            "content_type": "application/json", "expected_envelope": ENVELOPE,
                            "witness_key": KEY}
    args.update(changes)
    return c.consume_secret_instruction_build29_credential_response(_clear(material), **args)


def _totp(material: bytes = b"") -> SecretApprovalBuild29TotpWitness:
    return SecretApprovalBuild29TotpWitness(hmac.new(KEY, material, hashlib.sha256).hexdigest(), not material)


def _source(profile: str = "", totp: object = None) -> dict[str, Any]:
    fields = [{"id": ident, "q_origin_key": ident, "name": name, "type": name.lower(), "desc": "", "value": value}
              for ident, name, value in ((1, "Password", "ENC MASKED"), (2, "Username", "synthetic-user"),
                                         (3, "URL", "https://example.test/"))]
    return {"version": "v7.0.0", "build": 29, "serial": SERIAL, "http_method": "GET", "http_status": 200,
            "status": "OK", "path": "secret", "name": "database", "vdom": "root",
            "results": [{**IDENTITY, "instruction-profile": profile, "field": fields,
                         "inherit-permission": "enable", "recording": "enable", "http-service-status": "up",
                         "need-approval": "disable", "need-approval-job": "disable", "bypass-approval": "enable",
                         "approval-profile": "", "permissions": {"approval_status": "none", "user": 4},
                         "keyinfo": {"opaque": "synthetic-private-metadata"},
                         "totp-setting": {"status": "disable", "shared-key": totp, "totp-duration": 30},
                         "future-config": {"nested": ["synthetic-unknown-中文"]}}]}


def _raw(source: object) -> bytearray:
    return bytearray(json.dumps(source, ensure_ascii=False, separators=(",", ":")).encode())


def _consume(raw: bytearray, **changes: Any) -> c.SecretInstructionBuild29ApiPreservationWitness:
    args: dict[str, Any] = {"identity": IDENTITY, "serial_digest": hashlib.sha256(SERIAL.encode()).hexdigest(),
                            "instruction_profile_name": "", "credential_before": _credential(),
                            "credential_after": _credential(), "totp_before": _totp(), "totp_after": _totp(),
                            "witness_key": KEY}
    args.update(changes)
    return c.consume_secret_instruction_build29_api_preservation(raw, **args)


def test_full_api_attach_restore_and_totp_rendering_are_stable() -> None:
    raw_before, raw_after, raw_restored = _raw(_source()), _raw(_source(PROFILE, "ENC VOLATILE")), _raw(_source(totp=""))
    before = _consume(raw_before)
    after = _consume(raw_after, instruction_profile_name=PROFILE)
    final = _consume(raw_restored)
    assert before.preservation_digest == after.preservation_digest == final.preservation_digest
    assert before.preservation_digest not in repr(before)
    assert not raw_before and not raw_after and not raw_restored


@pytest.mark.parametrize("member,value", [
    ("need-approval", "enable"), ("need-approval-job", "enable"), ("bypass-approval", "disable"),
    ("approval-profile", "mcp-v4-approval-unit01"), ("inherit-permission", "disable"),
    ("recording", "disable"), ("http-service-status", "down"),
    ("permissions", {"approval_status": "required", "user": 4}),
    ("keyinfo", {"opaque": "changed-private-metadata"}),
    ("future-config", {"nested": ["changed-unknown-中文"]}),
    ("instruction-profile-extra", "must-stay-in-digest"),
])
def test_every_other_configuration_or_annotation_is_retained(member: str, value: object) -> None:
    before = _consume(_raw(_source()))
    changed = _source(PROFILE)
    changed["results"][0][member] = value
    assert _consume(_raw(changed), instruction_profile_name=PROFILE).preservation_digest != before.preservation_digest


@pytest.mark.parametrize("index", [0, 1, 2])
def test_no_credential_slot_render_is_excluded(index: int) -> None:
    before = _consume(_raw(_source()))
    changed = _source()
    changed["results"][0]["field"][index]["value"] = "changed-slot-render"
    assert _consume(_raw(changed)).preservation_digest != before.preservation_digest


def test_masked_password_equality_does_not_hide_clear_password_change() -> None:
    before = _consume(_raw(_source()))
    changed = _credential("changed-clear-password")
    after = _consume(_raw(_source()), credential_before=changed, credential_after=changed)
    assert after.preservation_digest != before.preservation_digest
    raw = _raw(_source())
    with pytest.raises(c.SecretInstructionBuild29ApiPreservationError):
        _consume(raw, credential_after=changed)
    assert not raw


@pytest.mark.parametrize("material", ["", "ASCII", "中文-é", 'escaped-"-\\-\n', "A" * 8000])
def test_clear_response_supports_full_json_strings_without_decoding(material: str, monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _clear(material)
    original = json.loads

    def guarded(value: object, **kwargs: Any) -> Any:
        raise AssertionError("The clear Password response must not be deserialized.")

    monkeypatch.setattr(c.metadata.json, "loads", guarded)
    result = c.consume_secret_instruction_build29_credential_response(raw, expected_secret_id=24, expected_field_id=1,
        http_status=200, content_type="application/json", expected_envelope=ENVELOPE, witness_key=KEY)
    assert len(result.material_digest) == 64 and result.material_digest not in repr(result)
    assert not raw
    assert original is not guarded


def test_encoded_clear_token_comparison_is_conservative() -> None:
    first = _clear("A")
    second = first.replace(b'"results":"A"', b'"results":"\\u0041"')
    def consume(raw: bytearray) -> c.SecretInstructionBuild29CredentialWitness:
        return c.consume_secret_instruction_build29_credential_response(raw, expected_secret_id=24, expected_field_id=1,
            http_status=200, content_type="application/json", expected_envelope=ENVELOPE, witness_key=KEY)
    assert consume(first).material_digest != consume(second).material_digest
    assert not first and not second


@pytest.mark.parametrize("field_id", [1, 2, True, "1", None, 0])
def test_native_password_field_selector_is_exact_and_password_only(field_id: object) -> None:
    envelope = {**ENVELOPE, "field-id": field_id}
    raw = _clear(**{"field-id": field_id})
    arguments = dict(expected_secret_id=24, expected_field_id=1, http_status=200,
                     content_type="application/json", expected_envelope=envelope, witness_key=KEY)
    if type(field_id) is int and field_id == 1:
        assert c.consume_secret_instruction_build29_credential_response(raw, **arguments).field_id == 1
    else:
        with pytest.raises(c.SecretInstructionBuild29ApiPreservationError):
            c.consume_secret_instruction_build29_credential_response(raw, **arguments)
    assert not raw
    with pytest.raises(ValueError):
        c._pinned_tokens(envelope)


@pytest.mark.parametrize("material", [None, False, 0, [], {}, "A" * 8193])
def test_missing_or_nonstring_or_oversize_clear_values_refuse(material: object) -> None:
    raw = _clear(material)
    with pytest.raises(c.SecretInstructionBuild29ApiPreservationError) as caught:
        c.consume_secret_instruction_build29_credential_response(raw, expected_secret_id=24, expected_field_id=1,
            http_status=200, content_type="application/json", expected_envelope=ENVELOPE, witness_key=KEY)
    assert str(caught.value) == c._ERROR and not raw


@pytest.mark.parametrize("fault", [
    "wrong-secret", "wrong-field", "wrong-key", "wrong-kind", "changed-totp", "nonempty-totp", "missing-credential",
    "bad-build", "bad-serial", "bool-id", "foreign-uuid", "zero-uuid", "foreign-reference", "missing-field",
    "missing-totp", "enabled-totp", "missing-shared-key", "object-shared-key", "duplicate-selected", "duplicate-totp",
    "duplicate-slot", "extra-row", "action", "schema-errors", "trailing-json", "partial-count", "pagination",
])
def test_binding_bracket_shape_or_pagination_failure_wipes(fault: str) -> None:
    source, changes = _source(), {}
    row = source["results"][0]
    if fault == "wrong-secret": changes["credential_after"] = c.SecretInstructionBuild29CredentialWitness(25, 1, _credential().key_digest, _credential().material_digest)
    elif fault == "wrong-field": changes["credential_after"] = _credential(expected_field_id=2)
    elif fault == "wrong-key": changes["credential_after"] = _credential(witness_key=b"another-synthetic-key-only-000001")
    elif fault == "wrong-kind": changes["credential_after"] = _totp()
    elif fault == "changed-totp": changes["totp_after"] = _totp(b"MFRGGZDF")
    elif fault == "nonempty-totp": changes.update(totp_before=_totp(b"MFRGGZDF"), totp_after=_totp(b"MFRGGZDF"))
    elif fault == "missing-credential": changes["credential_before"] = None
    elif fault == "bad-build": source["build"] = True
    elif fault == "bad-serial": source["serial"] = "OTHER"
    elif fault == "bool-id": row["id"] = True
    elif fault == "foreign-uuid": row["uuid"] = "12345678-1234-1234-1234-123456789abd"
    elif fault == "zero-uuid": changes["identity"] = {**IDENTITY, "uuid": "00000000-0000-0000-0000-000000000000"}
    elif fault == "foreign-reference": row["instruction-profile"] = "another-profile"
    elif fault == "missing-field": del row["field"]
    elif fault == "missing-totp": del row["totp-setting"]
    elif fault == "enabled-totp": row["totp-setting"]["status"] = "enable"
    elif fault == "missing-shared-key": del row["totp-setting"]["shared-key"]
    elif fault == "object-shared-key": row["totp-setting"]["shared-key"] = {}
    elif fault == "duplicate-slot": row["field"][1]["id"] = row["field"][1]["q_origin_key"] = 1
    elif fault == "extra-row": source["results"].append(deepcopy(row))
    elif fault == "action": source["action"] = "default"
    elif fault == "schema-errors": source["schema_errors"] = []
    elif fault == "partial-count": source["size"] = 0
    elif fault == "pagination": source["limit_reached"] = True
    raw = _raw(source)
    if fault == "duplicate-selected": raw = raw.replace(b'"instruction-profile":""', b'"instruction-profile":"","instruction-profile":""')
    elif fault == "duplicate-totp": raw = raw.replace(b'"shared-key":null', b'"shared-key":null,"shared-key":null')
    elif fault == "trailing-json": raw += b"{}"
    with pytest.raises(c.SecretInstructionBuild29ApiPreservationError) as caught:
        _consume(raw, **changes)
    assert str(caught.value) == c._ERROR and not raw


def test_material_tokens_never_enter_json_loads(monkeypatch: pytest.MonkeyPatch) -> None:
    original = json.loads
    markers = (b"ENC MASKED", b"synthetic-user", b"example.test", b"synthetic-private-metadata", b"synthetic-unknown")
    def guarded(value: Any, **kwargs: Any) -> Any:
        encoded = value.encode() if type(value) is str else value
        assert not any(marker in encoded for marker in markers)
        return original(value, **kwargs)
    monkeypatch.setattr(c.metadata.json, "loads", guarded)
    assert len(_consume(_raw(_source())).preservation_digest) == 64


@pytest.mark.parametrize("fault", [
    "status", "method", "subject", "missing-result", "duplicate-result", "unknown-member", "bad-json",
    "http-status", "content-type", "field-id", "key", "unpinned-msg",
])
def test_clear_source_envelope_or_binding_refuses_without_values(fault: str) -> None:
    raw, changes = _clear(), {}
    if fault == "status": raw = _clear(status="success")
    elif fault == "method": raw = _clear(http_method="GET")
    elif fault == "subject": raw = _clear(**{"secret-id": 25})
    elif fault == "missing-result": raw = _raw(ENVELOPE)
    elif fault == "duplicate-result": raw = raw.replace(b'"results":', b'"results":null,"results":')
    elif fault == "unknown-member": raw = _clear(schema_errors=[])
    elif fault == "bad-json": raw = raw[:-1]
    elif fault == "http-status": changes["http_status"] = True
    elif fault == "content-type": changes["content_type"] = "text/html"
    elif fault == "field-id": changes["expected_field_id"] = True
    elif fault == "key": changes["witness_key"] = b"x" * 31
    elif fault == "unpinned-msg": changes["expected_envelope"] = {key: value for key, value in ENVELOPE.items() if key != "msg"}
    arguments: dict[str, Any] = {"expected_secret_id": 24, "expected_field_id": 1, "http_status": 200,
                                "content_type": "application/json", "expected_envelope": ENVELOPE,
                                "witness_key": KEY}
    arguments.update(changes)
    with pytest.raises(c.SecretInstructionBuild29ApiPreservationError) as caught:
        c.consume_secret_instruction_build29_credential_response(raw, **arguments)
    assert str(caught.value) == c._ERROR and not raw


def test_failure_with_external_view_overwrites_buffer() -> None:
    raw = _raw(_source())
    with memoryview(raw) as view:
        with pytest.raises(c.SecretInstructionBuild29ApiPreservationError):
            _consume(raw, credential_before=None)
        assert all(value == 0 for value in view)


def test_success_hashes_original_views_and_erases_private_field_copy(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _raw(_source())
    original_update, original_zeroize = hmac.HMAC.update, c._zeroize_mutable
    native_views, erased_fields = [], []
    def update(digest: hmac.HMAC, value: Any) -> None:
        if type(value) is memoryview and value.obj is raw:
            native_views.append(True)
        original_update(digest, value)
    def wipe(value: bytearray) -> None:
        if value is not raw and b"ENC MASKED" in value:
            erased_fields.append(value)
        original_zeroize(value)
    monkeypatch.setattr(c.hmac.HMAC, "update", update)
    monkeypatch.setattr(c, "_zeroize_mutable", wipe)
    _consume(raw)
    assert native_views and erased_fields and not raw and all(not value for value in erased_fields)
