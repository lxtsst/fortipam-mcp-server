"""Private, offline boundary for one source-qualified internal TOTP response.

The trusted adapter must pin the exact observed envelope and bind the POST to
its sealed Secret/session. This parser does not qualify that source, infer
missing identity fields, or register a Tool. A digest remains private material
evidence, never an MCP result, audit field, or proof of source qualification.
"""

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import re

from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES, _json_string_end, _json_value_end,
    _skip_json_space, _zeroize_mutable,
)


_UNAVAILABLE = "The fixed build-29 TOTP material witness is unavailable."
_ENVELOPE_NAMES = frozenset({
    "version", "build", "serial", "http_method", "http_status", "status", "error",
    "secret-id", "msg",
})
_FIXED_VALUES: dict[str, str | int] = {
    "version": "v7.0.0", "build": 29, "http_method": "POST", "http_status": 200,
    "error": 0,
}
_BASE32 = re.compile(rb"[A-Za-z2-7]*={0,6}")


class SecretApprovalBuild29TotpBoundaryError(RuntimeError):
    """Non-disclosing rejection; never retain parser exception details."""

    def __init__(self) -> None:
        super().__init__(_UNAVAILABLE)


@dataclass(frozen=True, slots=True, repr=False)
class SecretApprovalBuild29TotpWitness:
    """Opaque private evidence only; no scalar or source identifiers."""

    material_digest: str
    explicit_empty: bool


def consume_secret_approval_build29_totp_response(
    raw: bytearray, *, http_status: int, content_type: str,
    expected_envelope: Mapping[str, str | int], witness_key: bytes | bytearray,
) -> SecretApprovalBuild29TotpWitness:
    """Consume/zero raw input, returning HMAC of the exact unescaped scalar.

    ``expected_envelope`` is protected trusted configuration from a separately
    qualified source observation, including its one exact success status. The
    complete root member set must equal that pin plus ``results``. Optional
    source identity members are never inferred; if present they must be pinned
    and match the fixed build-29 POST values. Callers must bound network reads
    before collecting ``raw``; this pure parser also rejects oversized input.

    Only an explicit empty or at most 128-byte ASCII Base32-compatible string
    is supported. Escapes and other representations fail closed. The caller
    owns the witness key and its lifetime; use the same private key across
    reads to compare material. The input is overwritten in all exit paths.
    """
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= MAX_RESPONSE_BYTES
                or type(http_status) is not int or http_status != 200
                or type(content_type) is not str
                or content_type.split(";", 1)[0].strip().lower() != "application/json"
                or type(witness_key) not in (bytes, bytearray)
                or witness_key is raw or len(witness_key) < 32):
            raise ValueError
        pins = _pinned_tokens(expected_envelope)
        start = _skip_json_space(raw, 0)
        end = _json_value_end(raw, start)
        if _skip_json_space(raw, end) != len(raw):
            raise ValueError
        spans = _member_spans(raw, start, end, pins)
        if set(spans) != set(pins):
            raise ValueError
        for name, (_, token) in pins.items():
            if name == "results":
                continue
            left, right = spans[name]
            with memoryview(raw)[left:right] as value:
                if value != token:
                    raise ValueError
        left, right = spans["results"]
        if raw[left] != 34 or raw[right - 1] != 34 or not 2 <= right - left <= 130:
            raise ValueError
        with memoryview(raw)[left + 1:right - 1] as material:
            if _BASE32.fullmatch(material) is None or (material and material[0] == 61):
                raise ValueError
            digest = hmac.new(witness_key, material, hashlib.sha256).hexdigest()
            return SecretApprovalBuild29TotpWitness(digest, len(material) == 0)
    except Exception:
        raise SecretApprovalBuild29TotpBoundaryError() from None
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)


def _pinned_tokens(
    envelope: Mapping[str, str | int],
) -> dict[str, tuple[bytes, bytes]]:
    if not isinstance(envelope, Mapping):
        raise ValueError
    values = dict(envelope)
    if (not values or not set(values) <= _ENVELOPE_NAMES
            or type(values.get("status")) is not str
            or values["status"] not in ("OK", "success")):
        raise ValueError
    for name, value in values.items():
        if name == "secret-id":
            if type(value) is not int or not 0 < value <= 2_147_483_647:
                raise ValueError
        elif name == "msg":
            if (type(value) is not str or not 1 <= len(value) <= 256
                    or any(not 32 <= ord(character) <= 126 for character in value)):
                raise ValueError
        elif name == "serial":
            if (type(value) is not str or not 1 <= len(value) <= 64
                    or not value.isascii() or not value.isalnum()):
                raise ValueError
        elif name in _FIXED_VALUES:
            expected = _FIXED_VALUES[name]
            if type(value) is not type(expected) or value != expected:
                raise ValueError
    tokens = {name: (json.dumps(name).encode("ascii"),
                     json.dumps(value).encode("ascii")) for name, value in values.items()}
    tokens["results"] = (b'"results"', b"")
    return tokens


def _member_spans(
    raw: bytearray, start: int, end: int, pins: dict[str, tuple[bytes, bytes]],
) -> dict[str, tuple[int, int]]:
    """Recognize only pinned canonical member names, without decoding input."""
    if raw[start] != 123 or raw[end - 1] != 125:
        raise ValueError
    cursor = _skip_json_space(raw, start + 1)
    spans: dict[str, tuple[int, int]] = {}
    while cursor < end - 1:
        key_end = _json_string_end(raw, cursor)
        if key_end - cursor > 32:
            raise ValueError
        with memoryview(raw)[cursor:key_end + 1] as token:
            matches = [name for name, (key, _) in pins.items() if token == key]
        if len(matches) != 1 or matches[0] in spans:
            raise ValueError
        separator = _skip_json_space(raw, key_end + 1)
        if separator >= end - 1 or raw[separator] != 58:
            raise ValueError
        left = _skip_json_space(raw, separator + 1)
        right = _json_value_end(raw, left)
        if right >= end:
            raise ValueError
        spans[matches[0]] = (left, right)
        cursor = _skip_json_space(raw, right)
        if cursor == end - 1:
            return spans
        if cursor >= end - 1 or raw[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(raw, cursor + 1)
        if cursor >= end - 1:
            raise ValueError
    return spans
