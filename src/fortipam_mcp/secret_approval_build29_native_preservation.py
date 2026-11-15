"""Pure private composition of full native configuration and TOTP evidence.

Source/session/version/serial qualification and same-subject/key TOTP bracketing
remain trusted adapter responsibilities. This helper grants no runtime authority.
"""

from dataclasses import dataclass
import hashlib
import hmac
import re

from .folder_namespace_ssh_reader import _MAX_OUTPUT_BYTES
from .secret_approval_build29_totp_boundary import SecretApprovalBuild29TotpWitness
from .secret_metadata_http_transport import _zeroize_mutable


_UNAVAILABLE = "The fixed build-29 full native preservation witness is unavailable."
_FIELDS = (b"need-approval", b"need-approval-job", b"bypass-approval", b"approval-profile")
_DOMAIN = b"fortipam-700-build29-full-native-totp-preservation-v1\x00"
_ENC = re.compile(rb"[A-Za-z0-9+/=_-]{1,8192}")
_CONFIG = re.compile(rb"[a-z][a-z0-9-]*(?: [a-z][a-z0-9-]*)*")
_MEMBER = re.compile(rb"[a-z][a-z0-9-]*")


class SecretApprovalBuild29NativePreservationError(RuntimeError):
    """Non-disclosing refusal of a protected native composition."""

    def __init__(self) -> None:
        super().__init__(_UNAVAILABLE)


@dataclass(frozen=True, slots=True, repr=False)
class SecretApprovalBuild29NativePreservationWitness:
    """Opaque protected digest for the existing native-preservation seam."""

    preservation_digest: str


def consume_secret_approval_build29_native_preservation(
    raw: bytearray, *, expected_secret_id: int, expected_secret_name: str,
    approval_values: tuple[str, str, str, str],
    totp_before: SecretApprovalBuild29TotpWitness,
    totp_after: SecretApprovalBuild29TotpWitness,
    witness_key: bytes | bytearray,
) -> SecretApprovalBuild29NativePreservationWitness:
    """Consume one complete CLI frame, preserving every non-approval byte.

    Input is a protected LF join of the existing CLI reader's qualified frame
    lines, with only command/prompt removed.
    Exactly correlated approval lines are excluded from the non-approval
    digest. Only the one direct ``totp-setting`` shared-key ENC value is replaced
    with its private semantic HMAC and empty flag; its line/setting remain.
    All other native content, including unknown settings and other encrypted
    values, is hashed bytewise without decoding or copying input material.

    Both TOTP witnesses must be produced by the same separately qualified bound
    source and private key before/after this frame. Their opaque type cannot
    itself establish that provenance. The caller owns key lifetime. Raw input
    is overwritten on every exit; only a private keyed digest is returned.
    """
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= _MAX_OUTPUT_BYTES
                or type(expected_secret_id) is not int
                or not 0 < expected_secret_id <= 2_147_483_647
                or not _safe_name(expected_secret_name, 64)
                or type(approval_values) is not tuple or len(approval_values) != 4
                or any(type(value) is not str for value in approval_values)
                or any(value not in ("enable", "disable") for value in approval_values[:3])
                or (approval_values[3] and not _safe_name(approval_values[3], 79))
                or type(witness_key) not in (bytes, bytearray)
                or witness_key is raw or len(witness_key) < 32):
            raise ValueError
        _qualify_bracket(totp_before, totp_after, witness_key)
        expected_edit = b"edit " + str(expected_secret_id).encode("ascii")
        expected_name = b'set name "' + expected_secret_name.encode("ascii") + b'"'
        expected_fields = [b"set " + field + b" " + value.encode("ascii")
                           for field, value in zip(_FIELDS[:3], approval_values[:3])]
        if approval_values[3]:
            expected_fields.append(b'set approval-profile "' + approval_values[3].encode("ascii") + b'"')
        semantic = (b"semantic-hmac-sha256:" + totp_before.material_digest.encode("ascii")
                    + (b":empty=1" if totp_before.explicit_empty else b":empty=0"))
        digest = hmac.new(witness_key, digestmod=hashlib.sha256)
        digest.update(_DOMAIN)
        _compose(raw, expected_edit, expected_name, expected_fields, semantic, digest)
        return SecretApprovalBuild29NativePreservationWitness(digest.hexdigest())
    except Exception:
        raise SecretApprovalBuild29NativePreservationError() from None
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)


def _safe_name(value: object, maximum: int) -> bool:
    return (type(value) is str and 1 <= len(value) <= maximum
            and all(32 <= ord(character) <= 126 and character not in {'"', "\\"}
                    for character in value))


def _qualify_bracket(
    before: SecretApprovalBuild29TotpWitness, after: SecretApprovalBuild29TotpWitness,
    key: bytes | bytearray,
) -> None:
    for witness in (before, after):
        if (type(witness) is not SecretApprovalBuild29TotpWitness
                or type(witness.material_digest) is not str
                or re.fullmatch(r"[0-9a-f]{64}", witness.material_digest) is None
                or type(witness.explicit_empty) is not bool):
            raise ValueError
    if (not hmac.compare_digest(before.material_digest, after.material_digest)
            or before.explicit_empty is not after.explicit_empty
            or before.explicit_empty and not hmac.compare_digest(
                before.material_digest, hmac.new(key, b"", hashlib.sha256).hexdigest())):
        raise ValueError


def _line_spans(raw: bytearray) -> list[tuple[int, int, int]]:
    spans = []
    start = 0
    for index, value in enumerate(raw):
        if value == 10:
            spans.append((start, index, index + 1))
            start = index + 1
        elif value < 32 or value == 127:
            raise ValueError
    if start < len(raw):
        spans.append((start, len(raw), len(raw)))
    return spans


def _equal(raw: bytearray, start: int, end: int, expected: bytes) -> bool:
    with memoryview(raw)[start:end] as value:
        return value == expected


def _match(raw: bytearray, start: int, end: int, pattern: re.Pattern[bytes]) -> bool:
    with memoryview(raw)[start:end] as value:
        return pattern.fullmatch(value) is not None


def _feed(digest: hmac.HMAC, raw: bytearray, start: int, end: int) -> None:
    with memoryview(raw)[start:end] as value:
        digest.update(value)


def _compose(
    raw: bytearray, expected_edit: bytes, expected_name: bytes,
    expected_fields: list[bytes], semantic: bytes, digest: hmac.HMAC,
    *, excluded_fields: tuple[bytes, ...] = _FIELDS,
) -> None:
    spans = _line_spans(raw)
    if not spans:
        raise ValueError
    stack: list[str] = []
    root_edit_count = name_count = totp_count = shared_key_count = 0
    selected: set[int] = set()
    totp_depth: int | None = None
    closed = False
    for number, (start, end, following) in enumerate(spans):
        if start == end:
            raise ValueError
        if closed:
            raise ValueError
        cursor = start
        while cursor < end and raw[cursor] == 32:
            cursor += 1
        indent = cursor - start
        excluded = False
        replaced: int | None = None
        if number == 0:
            if indent or not _equal(raw, cursor, end, b"config secret database"):
                raise ValueError
            stack.append("config")
        elif _equal(raw, cursor, end, b"next") or _equal(raw, cursor, end, b"end"):
            if not stack or indent != (len(stack) - 1) * 4:
                raise ValueError
            closing = "edit" if _equal(raw, cursor, end, b"next") else "config"
            if stack[-1] != closing:
                raise ValueError
            if totp_depth == len(stack):
                totp_depth = None
            stack.pop()
            closed = not stack
        else:
            if indent != len(stack) * 4:
                raise ValueError
            if raw.startswith(b"edit ", cursor, end):
                if not stack or stack[-1] != "config" or cursor + 5 >= end:
                    raise ValueError
                if len(stack) == 1:
                    root_edit_count += 1
                    if root_edit_count != 1 or not _equal(raw, cursor, end, expected_edit):
                        raise ValueError
                elif totp_depth is not None:
                    raise ValueError
                stack.append("edit")
            elif raw.startswith(b"config ", cursor, end):
                if len(stack) < 2 or not _match(raw, cursor + 7, end, _CONFIG):
                    raise ValueError
                if _equal(raw, cursor + 7, end, b"secret database"):
                    raise ValueError
                if _equal(raw, cursor + 7, end, b"totp-setting"):
                    totp_count += 1
                    if len(stack) != 2 or stack[-1] != "edit" or totp_count != 1:
                        raise ValueError
                    totp_depth = len(stack) + 1
                elif totp_depth is not None:
                    raise ValueError
                stack.append("config")
            elif raw.startswith(b"set ", cursor, end) or raw.startswith(b"unset ", cursor, end):
                if len(stack) < 2:
                    raise ValueError
                is_set = raw.startswith(b"set ", cursor, end)
                member_start = cursor + (4 if is_set else 6)
                separator = raw.find(b" ", member_start, end)
                member_end = end if separator == -1 else separator
                if not _match(raw, member_start, member_end, _MEMBER):
                    raise ValueError
                if is_set and (separator == -1 or separator + 1 >= end):
                    raise ValueError
                if not is_set and separator != -1:
                    raise ValueError
                root_member = stack == ["config", "edit"]
                if _equal(raw, member_start, member_end, b"name") and root_member:
                    name_count += 1
                    if name_count != 1 or not _equal(raw, cursor, end, expected_name):
                        raise ValueError
                for field_number, field in enumerate(excluded_fields):
                    if _equal(raw, member_start, member_end, field):
                        if (not root_member or field_number >= len(expected_fields)
                                or field_number in selected
                                or not _equal(raw, cursor, end, expected_fields[field_number])):
                            raise ValueError
                        selected.add(field_number)
                        excluded = True
                if _equal(raw, member_start, member_end, b"shared-key"):
                    shared_key_count += 1
                    if (not is_set or len(stack) != 3 or totp_depth != len(stack)
                            or shared_key_count != 1 or separator == -1
                            or not raw.startswith(b"ENC ", separator + 1, end)
                            or not _match(raw, separator + 5, end, _ENC)):
                        raise ValueError
                    replaced = separator + 1
            else:
                raise ValueError
        if not excluded:
            if replaced is None:
                _feed(digest, raw, start, following)
            else:
                _feed(digest, raw, start, replaced)
                digest.update(semantic)
                _feed(digest, raw, end, following)
    if (not closed or root_edit_count != 1 or name_count != 1 or totp_count != 1
            or shared_key_count != 1 or selected != set(range(len(expected_fields)))):
        raise ValueError
