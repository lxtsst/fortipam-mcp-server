"""Synthetic complete native frames and private material-witness composition."""

import hashlib
import hmac
from typing import Any, cast

import pytest

import fortipam_mcp.secret_approval_build29_native_preservation as module
from fortipam_mcp.secret_approval_build29_native_preservation import (
    SecretApprovalBuild29NativePreservationError,
    consume_secret_approval_build29_native_preservation as consume,
)
from fortipam_mcp.secret_approval_build29_totp_boundary import SecretApprovalBuild29TotpWitness


_KEY = b"synthetic-unit-witness-key-only-01"
_NAME = "mcp-v4-approval-unit01"
_BASE = ("disable", "disable", "enable", "")
_APPLIED = ("enable", "enable", "enable", "mcp-v4-approval-profile-unit01")


def _totp(material: bytes = b"") -> SecretApprovalBuild29TotpWitness:
    return SecretApprovalBuild29TotpWitness(
        hmac.new(_KEY, material, hashlib.sha256).hexdigest(), not material,
    )


def _frame(approval: tuple[str, str, str, str] = _BASE, *, enc: bytes = b"UNITNATIVEENC01") -> bytearray:
    lines = [b"config secret database", b"    edit 24", b'        set name "' + _NAME.encode() + b'"',
             b'        set description "Synthetic private metadata."']
    for name, value in zip(module._FIELDS[:3], approval[:3]):
        lines.append(b"        set " + name + b" " + value.encode())
    if approval[3]:
        lines.append(b'        set approval-profile "' + approval[3].encode() + b'"')
    lines += [b"        config field", b"            edit 1",
              b'                set value ENC UNITOTHERENC01', b"            next", b"        end",
              b"        config totp-setting", b"            set status disable",
              b"            set shared-key ENC " + enc, b"            set totp-duration 30",
              b"        end", b"        unset future-reference", b"    next", b"end"]
    return bytearray(b"\n".join(lines))


def _consume(raw: bytearray, **changes: Any) -> module.SecretApprovalBuild29NativePreservationWitness:
    arguments: dict[str, Any] = {
        "expected_secret_id": 24, "expected_secret_name": _NAME, "approval_values": _BASE,
        "totp_before": _totp(), "totp_after": _totp(), "witness_key": _KEY,
    }
    arguments.update(changes)
    return consume(raw, **arguments)


def test_only_totp_ciphertext_and_correlated_approval_changes_are_stable() -> None:
    baseline = _frame()
    applied = _frame(_APPLIED, enc=b"DIFFERENTUNITENC02")
    before = _consume(baseline)
    after = _consume(applied, approval_values=_APPLIED)
    assert before.preservation_digest == after.preservation_digest
    assert before.preservation_digest not in repr(before)
    assert not baseline and not applied


@pytest.mark.parametrize("old,new", [
    (b"UNITOTHERENC01", b"CHANGEDOTHERENC02"),
    (b"Synthetic private metadata.", b"Changed private metadata."),
    (b"set status disable", b"set status enable"),
    (b"set totp-duration 30", b"set totp-duration 60"),
    (b"unset future-reference", b"unset other-reference"),
])
def test_every_other_native_value_remains_in_the_digest(old: bytes, new: bytes) -> None:
    baseline = _consume(_frame())
    changed = _frame().replace(old, new)
    assert _consume(changed).preservation_digest != baseline.preservation_digest
    assert not changed


def test_unknown_nested_configuration_is_preserved_bytewise() -> None:
    baseline = _frame()
    addition = (b"        config future-setting\n            edit 9\n"
                b'                set future-value "Synthetic Unicode: \xc3\xa9"\n'
                b"            next\n        end\n")
    changed = baseline.replace(b"    next\nend", addition + b"    next\nend")
    assert _consume(changed).preservation_digest != _consume(baseline).preservation_digest
    assert not changed and not baseline


def test_nonempty_semantic_witness_is_retained_and_bracketed() -> None:
    empty = _consume(_frame())
    material = _totp(b"MFRGGZDF")
    nonempty = _consume(_frame(), totp_before=material, totp_after=material)
    assert nonempty.preservation_digest != empty.preservation_digest
    other = _totp(b"MFRGGZDFMZTWQ2LK")
    assert _consume(_frame(), totp_before=other, totp_after=other).preservation_digest != nonempty.preservation_digest


def test_hash_updates_use_views_of_consumed_native_buffer(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _frame()
    original_update = hmac.HMAC.update
    original_new = hmac.new
    viewed: list[bool] = []

    def update(instance: hmac.HMAC, value: Any) -> None:
        if type(value) is memoryview:
            assert value.obj is raw
            viewed.append(True)
        original_update(instance, value)

    monkeypatch.setattr(module.hmac.HMAC, "update", update)
    assert len(_consume(raw).preservation_digest) == 64
    assert viewed
    assert not raw
    assert original_new is hmac.new


@pytest.mark.parametrize("old,new", [
    (b"config secret database", b"config secret policy"),
    (b"    edit 24", b"    edit 25"),
    (b'set name "mcp-v4-approval-unit01"', b'set name "mcp-v4-other-unit01"'),
    (b"set need-approval disable", b"set need-approval enable"),
    (b"        set need-approval-job disable\n", b""),
    (b"set bypass-approval enable", b"set bypass-approval disable"),
    (b"    next\nend", b"end"),
    (b"    next\nend", b"    next\n    next\nend"),
    (b"    next\nend", b"    next\n    edit 24\n    next\nend"),
    (b"    next\nend", b"    next"),
    (b"config totp-setting", b"config other-setting"),
    (b"            set shared-key ENC UNITNATIVEENC01", b"        set shared-key ENC UNITNATIVEENC01"),
    (b"set shared-key ENC UNITNATIVEENC01", b"set shared-key UNITNATIVEENC01"),
    (b"set shared-key ENC UNITNATIVEENC01", b"set shared-key ENC UNIT NATIVE"),
    (b"set shared-key ENC UNITNATIVEENC01", b'set shared-key ENC "UNITNATIVEENC01"'),
    (b"            set shared-key ENC UNITNATIVEENC01\n", b""),
    (b"set shared-key ENC UNITNATIVEENC01", b"unset shared-key"),
    (b"        config totp-setting", b"        config totp-setting\n        end\n        config totp-setting"),
    (b"            set shared-key ENC UNITNATIVEENC01", b"            set shared-key ENC UNITNATIVEENC01\n            set shared-key ENC UNITNATIVEENC01"),
    (b"        set need-approval disable", b"        set need-approval disable\n        set need-approval disable"),
    (b'        set name "mcp-v4-approval-unit01"', b'        set name "mcp-v4-approval-unit01"\n        set name "mcp-v4-approval-unit01"'),
    (b"        config field", b"        unset approval-profile\n        config field"),
    (b"        config field", b'        set approval-profile ""\n        config field'),
    (b"                set value ENC UNITOTHERENC01", b"                set need-approval disable"),
    (b"                set value ENC UNITOTHERENC01", b"                set shared-key ENC UNITOTHERENC01"),
    (b"        config field", b"        config secret database\n        end\n        config field"),
    (b"\n", b"\r\n"),
    (b"config secret database", b"show full-configuration secret database 24\nconfig secret database"),
    (b"end", b"end\n# "),
])
def test_fail_wrong_scope_binding_approval_or_ambiguous_frame(old: bytes, new: bytes) -> None:
    raw = _frame().replace(old, new, 1)
    with pytest.raises(SecretApprovalBuild29NativePreservationError) as caught:
        _consume(raw)
    assert str(caught.value) == module._UNAVAILABLE
    assert caught.value.__cause__ is None
    assert not raw


@pytest.mark.parametrize("changes", [
    {"expected_secret_id": True}, {"expected_secret_id": 0},
    {"expected_secret_name": ""}, {"expected_secret_name": "invalid\nname"},
    {"approval_values": list(_BASE)}, {"approval_values": ("disable",) * 3},
    {"approval_values": ("invalid", "disable", "disable", "")},
    {"witness_key": b""}, {"witness_key": b"x" * 31}, {"witness_key": None},
    {"totp_before": None}, {"totp_after": _totp(b"MFRGGZDF")},
    {"totp_before": SecretApprovalBuild29TotpWitness("x" * 64, True)},
    {"totp_after": SecretApprovalBuild29TotpWitness(_totp().material_digest, False)},
    {"totp_before": SecretApprovalBuild29TotpWitness(_totp().material_digest, cast(Any, 1))},
    {"witness_key": b"different-private-key-for-unit-01"},
])
def test_contract_bracket_or_key_failure_consumes_input(changes: dict[str, object]) -> None:
    raw = _frame()
    with pytest.raises(SecretApprovalBuild29NativePreservationError):
        _consume(raw, **changes)
    assert not raw


def test_size_limit_and_external_view_are_overwritten(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _frame()
    monkeypatch.setattr(module, "_MAX_OUTPUT_BYTES", len(raw) - 1)
    with memoryview(raw) as view:
        with pytest.raises(SecretApprovalBuild29NativePreservationError):
            _consume(raw)
        assert all(value == 0 for value in view)
    assert all(value == 0 for value in raw)


def test_full_footer_is_preserved_and_internal_empty_line_rejected() -> None:
    baseline = _consume(_frame())
    raw = _frame() + b"\n"
    assert _consume(raw).preservation_digest != baseline.preservation_digest
    assert not raw
    raw = _frame().replace(b"    edit 24\n", b"    edit 24\n\n")
    with pytest.raises(SecretApprovalBuild29NativePreservationError):
        _consume(raw)
    assert not raw
    raw = _frame() + b"\n\n"
    with pytest.raises(SecretApprovalBuild29NativePreservationError):
        _consume(raw)
    assert not raw
