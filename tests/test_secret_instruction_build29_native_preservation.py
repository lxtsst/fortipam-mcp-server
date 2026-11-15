"""Synthetic complete frames; no device identity or real material sources."""

import hashlib
import hmac
from typing import Any, cast

import pytest

from fortipam_mcp import secret_instruction_build29_native_preservation as module
from fortipam_mcp.secret_approval_build29_totp_boundary import (
    SecretApprovalBuild29TotpWitness,
    consume_secret_approval_build29_totp_response,
)


_KEY = b"synthetic-instruction-witness-key-01"
_NAME = "mcp-v4-instruction-unit01"
_PROFILE = "mcp-v4-ip-unit01"


def _totp(material: bytes = b"") -> SecretApprovalBuild29TotpWitness:
    return SecretApprovalBuild29TotpWitness(
        hmac.new(_KEY, material, hashlib.sha256).hexdigest(), not material,
    )


def _frame(profile: str = "", enc: bytes = b"UNITTOTPENC01") -> bytearray:
    lines = [b"config secret database", b"    edit 24",
             b'        set name "' + _NAME.encode() + b'"',
             b"        set folder 3", b'        set template "Web Account"',
             b"        set uuid 12345678-1234-1234-1234-123456789abc",
             b"        set need-approval disable", b"        set need-approval-job disable",
             b"        set bypass-approval enable"]
    if profile:
        lines.append(b'        set instruction-profile "' + profile.encode() + b'"')
    lines += [b"        config field", b"            edit 1",
              b'                set name "Password"', b"                set value ENC UNITPASSWORDENC01",
              b"            next", b"        end", b"        config totp-setting",
              b"            set status disable", b"            set shared-key ENC " + enc,
              b"            set totp-duration 30", b"        end",
              b"        unset future-reference", b"    next", b"end"]
    return bytearray(b"\n".join(lines))


def _consume(raw: bytearray, **changes: Any) -> module.SecretInstructionBuild29NativePreservationWitness:
    arguments: dict[str, Any] = {
        "expected_secret_id": 24, "expected_secret_name": _NAME,
        "instruction_profile_name": "", "totp_before": _totp(),
        "totp_after": _totp(), "witness_key": _KEY,
    }
    arguments.update(changes)
    return module.consume_secret_instruction_build29_native_preservation(raw, **arguments)


def test_attach_and_exact_restore_preserve_complete_native_content() -> None:
    baseline, applied, restored = _frame(), _frame(_PROFILE, b"UNITTOTPENC02"), _frame(enc=b"UNITTOTPENC03")
    before = _consume(baseline)
    after = _consume(applied, instruction_profile_name=_PROFILE)
    final = _consume(restored)
    assert before.preservation_digest == after.preservation_digest == final.preservation_digest
    assert before.preservation_digest not in repr(before)
    assert not baseline and not applied and not restored


@pytest.mark.parametrize("old,new", [
    (b"UNITPASSWORDENC01", b"UNITPASSWORDENC02"),
    (b"set folder 3", b"set folder 4"),
    (b"123456789abc", b"123456789abd"),
    (b"set need-approval disable", b"set need-approval enable"),
    (b"set need-approval-job disable", b"set need-approval-job enable"),
    (b"set bypass-approval enable", b"set bypass-approval disable"),
    (b"set status disable", b"set status enable"),
    (b"set totp-duration 30", b"set totp-duration 60"),
    (b"unset future-reference", b"unset other-reference"),
    (b"unset future-reference", b'set approval-profile "mcp-v4-approval-unit01"'),
])
def test_all_non_instruction_fields_including_password_and_approval_are_preserved(old: bytes, new: bytes) -> None:
    baseline = _consume(_frame())
    changed = _frame(_PROFILE).replace(old, new)
    assert _consume(changed, instruction_profile_name=_PROFILE).preservation_digest != baseline.preservation_digest
    assert not changed


def test_unknown_nested_and_unicode_content_stays_in_digest() -> None:
    raw = _frame()
    added = raw.replace(b"    next\nend", b"        config future-setting\n"
                        b"            edit 9\n                set label \"\xe4\xb8\xad\xe6\x96\x87\"\n"
                        b"            next\n        end\n    next\nend")
    assert _consume(added).preservation_digest != _consume(raw).preservation_digest
    assert not raw and not added


def test_bracket_uses_real_offline_totp_consumer_and_detects_semantic_change() -> None:
    envelope: dict[str, str | int] = {"http_method": "POST", "http_status": 200,
                                     "status": "OK", "secret-id": 24,
                                     "msg": "Successfully fetched clear_text"}
    raw = bytearray(b'{"http_method":"POST","http_status":200,"status":"OK",'
                    b'"secret-id":24,"msg":"Successfully fetched clear_text","results":""}')
    empty = consume_secret_approval_build29_totp_response(
        raw, http_status=200, content_type="application/json", expected_envelope=envelope, witness_key=_KEY,
    )
    assert not raw
    baseline = _consume(_frame(), totp_before=empty, totp_after=empty)
    nonempty = _totp(b"MFRGGZDF")
    assert _consume(_frame(), totp_before=nonempty, totp_after=nonempty).preservation_digest != baseline.preservation_digest
    raw = _frame(_PROFILE)
    with pytest.raises(module.SecretInstructionBuild29NativePreservationError):
        _consume(raw, instruction_profile_name=_PROFILE, totp_before=empty, totp_after=nonempty)
    assert not raw


@pytest.mark.parametrize("old,new,profile", [
    (b"    edit 24", b"    edit 25", ""),
    (b'        set name "' + _NAME.encode() + b'"', b'        set name "other"', ""),
    (b"        config field", b'        set instruction-profile ""\n        config field', ""),
    (b"        config field", b"        unset instruction-profile\n        config field", ""),
    (b"        config field", b'        set instruction-profile "foreign"\n        config field', ""),
    (b"        config field", b"        config field", _PROFILE),
    (b"                set value ENC UNITPASSWORDENC01", b'                set instruction-profile "' + _PROFILE.encode() + b'"', ""),
    (b"            set shared-key ENC UNITTOTPENC01", b"            set shared-key ENC UNITTOTPENC01\n            set shared-key ENC UNITTOTPENC01", ""),
    (b"        config totp-setting", b"        config other-setting", ""),
    (b"    next\nend", b"    next\n    edit 25\n    next\nend", ""),
    (b"end", b"end\ntrailing private scalar", ""),
    (b"\n", b"\r\n", ""),
])
def test_scope_binding_ambiguous_or_unqualified_render_refuses(old: bytes, new: bytes, profile: str) -> None:
    raw = _frame().replace(old, new, 1)
    with pytest.raises(module.SecretInstructionBuild29NativePreservationError) as caught:
        _consume(raw, instruction_profile_name=profile)
    assert str(caught.value) == module._UNAVAILABLE and caught.value.__cause__ is None
    assert not raw


def test_foreign_duplicate_or_nested_applied_reference_refuses() -> None:
    line = b'        set instruction-profile "' + _PROFILE.encode() + b'"'
    for replacement in (line + b"\n" + line, line.replace(_PROFILE.encode(), b"mcp-v4-ip-other"),
                        b"        config nested\n    " + line + b"\n        end"):
        raw = _frame(_PROFILE).replace(line, replacement)
        with pytest.raises(module.SecretInstructionBuild29NativePreservationError):
            _consume(raw, instruction_profile_name=_PROFILE)
        assert not raw


@pytest.mark.parametrize("changes", [
    {"expected_secret_id": True}, {"expected_secret_id": 0}, {"expected_secret_id": 2_147_483_648},
    {"expected_secret_name": ""}, {"expected_secret_name": "invalid\nname"},
    {"instruction_profile_name": None}, {"instruction_profile_name": "external-profile"},
    {"witness_key": b"x" * 31}, {"witness_key": None}, {"totp_before": None},
    {"totp_after": SecretApprovalBuild29TotpWitness("x" * 64, True)},
    {"totp_after": SecretApprovalBuild29TotpWitness(_totp().material_digest, cast(Any, 1))},
    {"witness_key": b"another-synthetic-private-key-0001"},
])
def test_invalid_input_or_bracket_consumes_without_values(changes: dict[str, object]) -> None:
    raw = _frame()
    with pytest.raises(module.SecretInstructionBuild29NativePreservationError) as caught:
        _consume(raw, **changes)
    assert str(caught.value) == module._UNAVAILABLE
    assert not raw


def test_bound_size_failure_erases_external_view(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _frame()
    monkeypatch.setattr(module, "_MAX_OUTPUT_BYTES", len(raw) - 1)
    with memoryview(raw) as view:
        with pytest.raises(module.SecretInstructionBuild29NativePreservationError):
            _consume(raw)
        assert all(value == 0 for value in view)


def test_hashing_uses_original_mutable_views(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _frame()
    original = hmac.HMAC.update
    views = []

    def update(instance: hmac.HMAC, value: Any) -> None:
        if type(value) is memoryview:
            assert value.obj is raw
            views.append(True)
        original(instance, value)

    monkeypatch.setattr(module.hmac.HMAC, "update", update)
    assert len(_consume(raw).preservation_digest) == 64
    assert views and not raw
