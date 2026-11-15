"""Unwired private Web Account field projection; no write qualification.

Consume one fresh build-29 GET buffer. Only metadata and slot names/IDs are
decoded; material JSON string spans remain private bytes. The returned mutable
array belongs to the private caller, which must erase it after final dispatch.
Password token forwarding and stored-password preservation remain unqualified.
"""

from collections.abc import Mapping
import hmac
import json
import re
from typing import Any

from .secret_approval_build29_http_transport import (
    _normalize_one_native_metadata_duplicate, _preserved_metadata_digest, _raw_members,
    _redact_material_members,
)
from .mutable_json_buffer import _MutableJSONBuffer
from .secret_create_191_http_transport import _quoted_material, _valid_material_view, _valid_utf8
from .secret_description_update_http_transport import _field_span
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES, _json_string_end, _json_value_end,
    _redact_json_field_values, _skip_json_space, _zeroize_mutable,
)

_UNAVAILABLE = "The private build-29 Web Account fields are unavailable."
_SLOTS = ("Password", "URL", "Username")
_STRING = re.compile(rb'"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"\Z')


class SecretApprovalBuild29WebFieldsError(ValueError):
    """Categorical rejection without source or material values."""


def project_secret_approval_build29_web_fields(
    raw: bytearray, *, identity: Mapping[str, object],
    expected_metadata_digest: str, username: memoryview, web_url: str,
) -> bytearray:
    """Return three projected slots, consuming/erasing the source buffer.

    Digest semantics use the approval transport's sole preservation kernel
    after material redaction, including its fixed computed annotations. URL and
    Username must match the existing material serializer's exact JSON encoding;
    alternate equivalent encodings are deliberately refused. This narrow
    candidate requires the exact fresh GET six-member slot shape and projects
    only id/name/value, omitting read-only desc/type/origin metadata.
    """
    field, output, account, url = bytearray(), bytearray(), bytearray(), bytearray()
    builder = _MutableJSONBuffer()
    succeeded = False
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= MAX_RESPONSE_BYTES
                or set(identity) != {"id", "name", "folder", "template", "target"}
                or any(not _positive_integer(identity[key]) for key in ("id", "folder"))
                or any(type(identity[key]) is not str or not identity[key] for key in ("name", "template"))
                or identity["template"] != "Web Account" or identity["target"] != ""
                or type(expected_metadata_digest) is not str
                or re.fullmatch(r"[0-9a-f]{64}", expected_metadata_digest) is None
                or not _valid_material_view(username)
                or type(web_url) is not str or not web_url):
            raise ValueError
        start, end = _field_span(raw)
        field = bytearray(end - start)
        with memoryview(raw) as view, memoryview(field) as destination:
            destination[:] = view[start:end]
        _redact_json_field_values(raw)
        _redact_material_members(raw)
        _reject_bound_member_duplicates(raw, set(identity) | {"totp-setting", "shared-key"})
        _normalize_one_native_metadata_duplicate(raw)
        envelope = json.loads(raw, object_pairs_hook=_unique_object)
        if (type(envelope) is not dict
                or any(type(envelope.get(key)) is not type(value) or envelope[key] != value
                       for key, value in {"version": "v7.0.0", "build": 29, "http_status": 200,
                                          "http_method": "GET", "path": "secret", "name": "database"}.items())
                or envelope.get("status") not in {"OK", "success"}
                or type(envelope.get("results")) is not list or len(envelope["results"]) != 1):
            raise ValueError
        row = envelope["results"][0]
        if (type(row) is not dict or row.get("field") is not None
                or any(type(row.get(key)) is not type(value) or row[key] != value
                       for key, value in identity.items())
                or not hmac.compare_digest(expected_metadata_digest, _preserved_metadata_digest(row))):
            raise ValueError
        account = _quoted_material(username)
        encoded_url = bytearray(web_url.encode("utf-8"))
        try:
            with memoryview(encoded_url) as view:
                url = _quoted_material(view)
        finally:
            _zeroize_mutable(encoded_url)
        slots = _slots(field)
        for name, expected in (("Username", account), ("URL", url)):
            begin, finish = slots[name]["value"]
            if not hmac.compare_digest(memoryview(field)[begin:finish], expected):
                raise ValueError
        builder.extend(b"[")
        for index, name in enumerate(_SLOTS):
            if index:
                builder.extend(b",")
            builder.extend(b"{")
            for position, key in enumerate(("id", "name", "value")):
                if position:
                    builder.extend(b",")
                builder.extend(b'"' + key.encode("ascii") + b'":')
                begin, finish = slots[name][key]
                builder.extend(memoryview(field)[begin:finish])
            builder.extend(b"}")
        builder.extend(b"]")
        output = builder.finish()
        succeeded = True
        return output
    except Exception:
        raise SecretApprovalBuild29WebFieldsError(_UNAVAILABLE) from None
    finally:
        builder.close()
        for buffer in (field, account, url):
            _zeroize_mutable(buffer)
        if isinstance(raw, bytearray):
            _zeroize_mutable(raw)
        if not succeeded:
            _zeroize_mutable(output)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError
        result[name] = value
    return result


def _positive_integer(value: object) -> bool:
    return type(value) is int and value > 0


def _reject_bound_member_duplicates(raw: bytearray, bound: set[str]) -> None:
    """Keep extra binding and TOTP material containers strict after erasure."""
    start = _skip_json_space(raw, 0)
    end = _json_value_end(raw, start)
    result = [(a, b) for key, _, a, b, _ in _raw_members(raw, start, end) if key == "results"]
    if len(result) != 1:
        raise ValueError
    left, _ = result[0]
    if raw[left] != 91:
        raise ValueError
    row_start = _skip_json_space(raw, left + 1)
    row_end = _json_value_end(raw, row_start)
    seen: set[str] = set()
    for key, _, _, _, _ in _raw_members(raw, row_start, row_end):
        if key in bound and key in seen:
            raise ValueError
        seen.add(key)


def _slots(field: bytearray) -> dict[str, dict[str, tuple[int, int]]]:
    cursor = _skip_json_space(field, 1)
    slots: dict[str, dict[str, tuple[int, int]]] = {}
    identifiers: set[int] = set()
    while field[cursor] != 93:
        if field[cursor] != 123:
            raise ValueError
        cursor = _skip_json_space(field, cursor + 1)
        members: dict[str, tuple[int, int]] = {}
        while field[cursor] != 125:
            end = _json_string_end(field, cursor)
            key = json.loads(field[cursor:end + 1])
            if key not in {"desc", "id", "name", "q_origin_key", "type", "value"} or key in members:
                raise ValueError
            cursor = _skip_json_space(field, end + 1)
            if field[cursor] != 58:
                raise ValueError
            cursor = _skip_json_space(field, cursor + 1)
            end = _json_value_end(field, cursor)
            members[key] = (cursor, end)
            cursor = _skip_json_space(field, end)
            if field[cursor] == 125:
                break
            if field[cursor] != 44:
                raise ValueError
            cursor = _skip_json_space(field, cursor + 1)
            if field[cursor] == 125:
                raise ValueError
        if set(members) != {"desc", "id", "name", "q_origin_key", "type", "value"}:
            raise ValueError
        first, last = members["id"]
        if re.fullmatch(rb"[1-9][0-9]*", field[first:last]) is None:
            raise ValueError
        identifier = int(field[first:last])
        first, last = members["q_origin_key"]
        if field[first:last] != str(identifier).encode("ascii"):
            raise ValueError
        first, last = members["name"]
        name = json.loads(field[first:last])
        if name not in _SLOTS or name in slots or identifier in identifiers:
            raise ValueError
        first, last = members["desc"]
        if field[first:last] != b'""':
            raise ValueError
        first, last = members["type"]
        if field[first:last] != b'"' + name.lower().encode("ascii") + b'"':
            raise ValueError
        for key in ("value", "desc", "type"):
            first, last = members[key]
            view = memoryview(field)[first:last]
            try:
                if _STRING.fullmatch(view) is None or not _valid_utf8(view):
                    raise ValueError
                if key == "value" and last - first <= 2:
                    raise ValueError
            finally:
                view.release()
        slots[name] = members
        identifiers.add(identifier)
        cursor = _skip_json_space(field, cursor + 1)
        if field[cursor] == 93:
            break
        if field[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(field, cursor + 1)
        if field[cursor] == 93:
            raise ValueError
    if set(slots) != set(_SLOTS) or _skip_json_space(field, cursor + 1) != len(field):
        raise ValueError
    return slots
