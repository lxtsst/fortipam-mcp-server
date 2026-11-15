"""Inactive private build-29 metadata projection; no source or write authority.

Native Secret collection reads use POST with a GET override and may ignore
``format``. Validate JSON without deserializing unselected values, then decode
only compiled metadata fields. This module owns and clears the response buffer.
Collection counts describe a visible view, never a global namespace or ACL.
Bound detail reads prove matching metadata, not backend association eligibility.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from typing import Literal, TypeAlias

from v4_planning.material_provider import _OpaqueC3Object

from .secret_create_191_http_transport import _valid_utf8
from .secret_metadata_http_transport import (
    _json_string_end, _json_value_end, _skip_json_space, _zeroize_mutable,
)

_ERROR = "Protected bulk-import metadata unavailable."
_MAX_BYTES = 2 * 1024 * 1024
_MAX_ROWS = 4096
_NUMBER = re.compile(rb"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_Table: TypeAlias = Literal["template", "target", "folder", "database"]
_KINDS = frozenset({"target-address", "domain", "url", "service-address", "username",
                    "password", "public-key", "private-key", "passphrase", "text", "cert"})
_PERMISSIONS = {
    "template": frozenset({"none", "create-secret", "owner"}),
    "target": frozenset({"none", "create-secret", "owner"}),
    "folder": frozenset({"none", "view", "add-secret", "edit", "owner"}),
    "database": frozenset({"none", "list", "view", "edit", "owner"}),
}

_ENVELOPE_FIELDS = frozenset({"version", "build", "path", "name", "http_method", "status",
    "http_status", "vdom", "serial", "results", "error", "limit_reached", "size",
    "filtered_count", "next_idx", "revision"})
_ROW_FIELDS = {
    "template": frozenset({"name", "field", "permissions", "q_origin_key"}),
    "target": frozenset({"name", "template", "address", "domain", "url", "permissions", "q_origin_key"}),
    "folder": frozenset({"id", "name", "parent-folder", "folder-type", "permissions", "q_origin_key"}),
    "database": frozenset({"id", "name", "permissions", "q_origin_key"}),
}


class BulkImportMetadataError(ValueError):
    """Fixed failure without a response value or partial projection."""


@dataclass(frozen=True, slots=True, repr=False)
class ImportMetadataField(_OpaqueC3Object):
    name: str
    kind: str
    mandatory: bool


@dataclass(frozen=True, slots=True, repr=False)
class ImportMetadataTemplate(_OpaqueC3Object):
    name: str
    fields: tuple[ImportMetadataField, ...]
    permission: str | None


@dataclass(frozen=True, slots=True, repr=False)
class ImportMetadataTarget(_OpaqueC3Object):
    name: str
    template: str
    address: str
    domain: str
    url: str
    permission: str | None


@dataclass(frozen=True, slots=True, repr=False)
class ImportMetadataFolder(_OpaqueC3Object):
    identifier: int
    name: str
    parent_identifier: int
    kind: str
    permission: str | None


@dataclass(frozen=True, slots=True, repr=False)
class ImportMetadataSecret(_OpaqueC3Object):
    identifier: int
    name: str
    permission: str | None


_Row: TypeAlias = ImportMetadataTemplate | ImportMetadataTarget | ImportMetadataFolder | ImportMetadataSecret


@dataclass(frozen=True, slots=True, repr=False)
class NativeImportMetadataCollection(_OpaqueC3Object):
    table: _Table
    rows: tuple[_Row, ...]
    size: int | None
    filtered_count: int | None
    # Missing counts remain missing. Even matching counts prove only this view.
    revision: str | None
    serial_digest: str


class _InvalidJsonUtf8(ValueError):
    """Malformed wire encoding; no token or response content is retained."""


def _validate_string(token: memoryview) -> None:
    # Reuse the existing private writer's byte-only UTF-8 validation.
    if len(token) < 2 or token[0] != 34 or token[-1] != 34:
        raise ValueError
    if not _valid_utf8(token):
        raise _InvalidJsonUtf8
    index = 1
    while index < len(token) - 1:
        value = token[index]
        if value < 32 or value == 34:
            raise ValueError
        if value == 92:
            index += 1
            if index >= len(token) - 1:
                raise ValueError
            if token[index] == 117:
                if index + 4 >= len(token) - 1 or any(
                        token[i] not in b"0123456789abcdefABCDEF" for i in range(index + 1, index + 5)):
                    raise ValueError
                index += 4
            elif token[index] not in b'"\\/bfnrt':
                raise ValueError
        index += 1


def _selected_key(content: bytearray, start: int, end: int, selected: frozenset[str]) -> str | None:
    """Normalize ASCII JSON key bytes only; return an existing compiled name."""
    normalized = bytearray()
    try:
        cursor = start + 1
        while cursor < end - 1:
            value = content[cursor]
            if value == 92:
                cursor += 1
                if content[cursor] != 117:
                    return None  # Compiled names contain no escaped punctuation/control.
                value = 0
                for index in range(cursor + 1, cursor + 5):
                    digit = content[index]
                    value = value * 16 + (digit - 48 if digit <= 57 else digit - 87 if digit >= 97 else digit - 55)
                cursor += 4
            if not (65 <= value <= 90 or 97 <= value <= 122 or 48 <= value <= 57 or value in (36, 45, 95)):
                return None
            normalized.append(value)
            if len(normalized) > 64:
                return None
            cursor += 1
        for key in selected:
            if normalized == key.encode("ascii"):
                return key
        return None
    finally:
        _zeroize_mutable(normalized)


def _object_spans(content: bytearray, start: int, end: int,
                  selected: frozenset[str]) -> dict[str, tuple[int, int]]:
    if content[start] != 123 or content[end - 1] != 125:
        raise ValueError
    cursor = _skip_json_space(content, start + 1)
    spans: dict[str, tuple[int, int]] = {}
    while cursor < end - 1:
        key_end = _json_string_end(content, cursor) + 1
        key = _selected_key(content, cursor, key_end, selected)
        separator = _skip_json_space(content, key_end)
        if content[separator] != 58:
            raise ValueError
        left = _skip_json_space(content, separator + 1)
        right = _json_value_end(content, left)
        if key is not None:
            if key in spans:
                raise ValueError
            spans[key] = left, right
        cursor = _skip_json_space(content, right)
        if cursor == end - 1:
            break
        cursor = _skip_json_space(content, cursor + 1)
    return spans


def _validate_json(content: bytearray, start: int, end: int, *, depth: int,
                   budget: list[int]) -> None:
    """Validate unselected keys/values as bytes, without decoded value strings."""
    budget[0] -= 1
    if budget[0] < 0 or depth > 16 or not 0 <= start < end <= len(content):
        raise ValueError
    first = content[start]
    if first not in (91, 123):
        with memoryview(content)[start:end] as token:
            if first == 34:
                if len(token) > 65536:
                    raise ValueError
                if not hmac.compare_digest(token, b'""'):
                    _validate_string(token)
            elif not any(hmac.compare_digest(token, literal) for literal in (b"true", b"false", b"null")):
                if _NUMBER.fullmatch(token) is None:
                    raise ValueError
        return
    closing = 93 if first == 91 else 125
    if content[end - 1] != closing:
        raise ValueError
    cursor, count = _skip_json_space(content, start + 1), 0
    while cursor < end - 1:
        count += 1
        if count > (_MAX_ROWS if first == 91 else 512):
            raise ValueError
        if first == 123:
            key_end = _json_string_end(content, cursor) + 1
            _validate_json(content, cursor, key_end, depth=depth + 1, budget=budget)
            cursor = _skip_json_space(content, key_end)
            if cursor >= end - 1 or content[cursor] != 58:
                raise ValueError
            cursor = _skip_json_space(content, cursor + 1)
        value_end = _json_value_end(content, cursor)
        if value_end >= end:
            raise ValueError
        _validate_json(content, cursor, value_end, depth=depth + 1, budget=budget)
        cursor = _skip_json_space(content, value_end)
        if cursor == end - 1:
            break
        if cursor >= end - 1 or content[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(content, cursor + 1)
        if cursor >= end - 1:
            raise ValueError


def _array(content: bytearray, span: tuple[int, int], maximum: int) -> list[tuple[int, int]]:
    start, end = span
    if content[start] != 91 or content[end - 1] != 93:
        raise ValueError
    cursor = _skip_json_space(content, start + 1)
    items: list[tuple[int, int]] = []
    while cursor < end - 1:
        if len(items) >= maximum:
            raise ValueError
        right = _json_value_end(content, cursor)
        items.append((cursor, right))
        cursor = _skip_json_space(content, right)
        if cursor == end - 1:
            break
        cursor = _skip_json_space(content, cursor + 1)
    return items


def _scalar(content: bytearray, span: tuple[int, int]) -> object:
    start, end = span
    if content[start] in (91, 123):
        raise ValueError
    return json.loads(content[start:end])  # Only compiled metadata scalar spans.


def _text(value: object, *, empty: bool = False, maximum: int = 255) -> str:
    if (type(value) is not str or not empty and not value or value != value.strip()
            or len(value.encode("utf-8")) > maximum
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError
    return value


def _integer(value: object, *, zero: bool = False) -> int:
    if type(value) is not int or not (0 if zero else 1) <= value <= 2147483647:
        raise ValueError
    return value


def _permission(content: bytearray, spans: dict[str, tuple[int, int]], table: _Table) -> str | None:
    if "permissions" not in spans:
        return None
    fields = _object_spans(content, *spans["permissions"], frozenset({"user"}))
    if "user" not in fields:
        return None
    value = _scalar(content, fields["user"])
    if type(value) is not str or value not in _PERMISSIONS[table]:
        raise ValueError
    return value


def _row(content: bytearray, span: tuple[int, int], table: _Table) -> _Row:
    fields = _object_spans(content, *span, _ROW_FIELDS[table])
    name = _text(_scalar(content, fields["name"]))
    permission = _permission(content, fields, table)
    if table == "template":
        definitions = []
        for field_span in _array(content, fields["field"], 64):
            field = _object_spans(content, *field_span, frozenset({"name", "type", "mandatory"}))
            label = _text(_scalar(content, field["name"]))
            kind = _scalar(content, field["type"])
            mandatory = _scalar(content, field["mandatory"])
            if type(kind) is not str or kind not in _KINDS or mandatory not in ("enable", "disable"):
                raise ValueError
            definitions.append(ImportMetadataField(label, kind, mandatory == "enable"))
        if len({field.name.casefold() for field in definitions}) != len(definitions):
            raise ValueError
        result: _Row = ImportMetadataTemplate(name, tuple(definitions), permission)
        primary: str | int = name
    elif table == "target":
        result = ImportMetadataTarget(name, _text(_scalar(content, fields["template"])),
            _text(_scalar(content, fields["address"]), empty=True, maximum=65536),
            _text(_scalar(content, fields["domain"]), empty=True, maximum=65536),
            _text(_scalar(content, fields["url"]), empty=True, maximum=65536), permission)
        primary = name
    else:
        identifier = _integer(_scalar(content, fields["id"]))
        primary = identifier
        if table == "database":
            result = ImportMetadataSecret(identifier, name, permission)
        else:
            parent = _integer(_scalar(content, fields["parent-folder"]), zero=True)
            kind = _scalar(content, fields["folder-type"])
            if kind not in ("public", "personal") or parent == identifier or "/" in name:
                raise ValueError
            result = ImportMetadataFolder(identifier, name, parent, str(kind), permission)
    if "q_origin_key" in fields and _scalar(content, fields["q_origin_key"]) != primary:
        raise ValueError
    return result


def project_native_import_secret_detail(
    content: bytearray, *, expected_serial_digest: str, expected: ImportMetadataSecret,
) -> ImportMetadataSecret:
    """Bind a build-29 GET detail to a private collection reference.

    This proves only matching readable metadata, never association eligibility.
    Unselected material is not decoded; the input is cleared on every outcome.
    """
    try:
        if (type(content) is not bytearray or not 0 < len(content) <= _MAX_BYTES
                or type(expected_serial_digest) is not str
                or _DIGEST.fullmatch(expected_serial_digest) is None
                or type(expected) is not ImportMetadataSecret):
            raise ValueError
        _integer(expected.identifier)
        _text(expected.name)
        if expected.permission is not None and (
                type(expected.permission) is not str or expected.permission not in _PERMISSIONS["database"]):
            raise ValueError
        start = _skip_json_space(content, 0)
        end = _json_value_end(content, start)
        if _skip_json_space(content, end) != len(content):
            raise ValueError
        _validate_json(content, start, end, depth=0, budget=[50000])
        envelope = _object_spans(content, start, end, _ENVELOPE_FIELDS | {"action"})
        for key, value in {"version": "v7.0.0", "build": 29, "path": "secret", "name": "database",
                           "http_method": "GET", "status": "OK", "http_status": 200,
                           "vdom": "root"}.items():
            observed = _scalar(content, envelope[key])
            if type(observed) is not type(value) or observed != value:
                raise ValueError
        if "action" in envelope and _scalar(content, envelope["action"]) != "":
            raise ValueError
        if "error" in envelope:
            error = _scalar(content, envelope["error"])
            if error is not None and (type(error) is not int or error != 0):
                raise ValueError
        serial = _text(_scalar(content, envelope["serial"]), maximum=128)
        if not hmac.compare_digest(hashlib.sha256(serial.encode()).hexdigest(), expected_serial_digest):
            raise ValueError
        span = envelope["results"]
        if content[span[0]] == 91:
            rows = _array(content, span, 1)
            if len(rows) != 1:
                raise ValueError
            span = rows[0]
        selected = _object_spans(content, *span, _ROW_FIELDS["database"])
        if "q_origin_key" in selected:
            _integer(_scalar(content, selected["q_origin_key"]))
        result = _row(content, span, "database")
        if not isinstance(result, ImportMetadataSecret) or result != expected:
            raise ValueError
        return result
    except Exception:
        raise BulkImportMetadataError(_ERROR) from None
    finally:
        if isinstance(content, bytearray):
            _zeroize_mutable(content)


def project_native_import_metadata(content: bytearray, *, table: _Table,
                                   expected_serial_digest: str) -> NativeImportMetadataCollection:
    """Project a fixed native read response, never a catalog/authorization receipt."""
    try:
        if (type(content) is not bytearray or not 0 < len(content) <= _MAX_BYTES
                or table not in _PERMISSIONS or type(expected_serial_digest) is not str
                or _DIGEST.fullmatch(expected_serial_digest) is None):
            raise ValueError
        start = _skip_json_space(content, 0)
        end = _json_value_end(content, start)
        if _skip_json_space(content, end) != len(content):
            raise ValueError
        _validate_json(content, start, end, depth=0, budget=[50000])
        envelope = _object_spans(content, start, end, _ENVELOPE_FIELDS)
        for key, expected in {"version": "v7.0.0", "build": 29, "path": "secret", "name": table,
                              "http_method": "POST", "status": "OK", "http_status": 200,
                              "vdom": "root"}.items():
            value = _scalar(content, envelope[key])
            if type(value) is not type(expected) or value != expected:
                raise ValueError
        serial = _text(_scalar(content, envelope["serial"]), maximum=128)
        if not hmac.compare_digest(hashlib.sha256(serial.encode()).hexdigest(), expected_serial_digest):
            raise ValueError
        if "error" in envelope:
            error = _scalar(content, envelope["error"])
            if error is not None and (type(error) is not int or error != 0):
                raise ValueError
        if "limit_reached" in envelope and _scalar(content, envelope["limit_reached"]) is not False:
            raise ValueError
        rows = tuple(_row(content, span, table) for span in _array(content, envelope["results"], _MAX_ROWS))
        primary = [row.identifier if isinstance(row, (ImportMetadataFolder, ImportMetadataSecret))
                   else row.name.casefold() for row in rows]
        if len(set(primary)) != len(primary):
            raise ValueError
        size = _integer(_scalar(content, envelope["size"]), zero=True) if "size" in envelope else None
        filtered = _integer(_scalar(content, envelope["filtered_count"]), zero=True) if "filtered_count" in envelope else None
        if (size is not None and size < len(rows) or filtered is not None and filtered != len(rows)):
            raise ValueError
        if "next_idx" in envelope:
            cursor = _integer(_scalar(content, envelope["next_idx"]), zero=True)
            if cursor not in (0, len(rows)):
                raise ValueError
        revision = _text(_scalar(content, envelope["revision"]), empty=True) if "revision" in envelope else None
        return NativeImportMetadataCollection(table, rows, size, filtered, revision, expected_serial_digest)
    except Exception:
        raise BulkImportMetadataError(_ERROR) from None
    finally:
        if isinstance(content, bytearray):
            _zeroize_mutable(content)
