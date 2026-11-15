"""Private, consuming projections for the qualified build-29 LDAP create profile.

No function performs I/O. The caller owns the fixed HTTP route and status.
Protected snapshots are for in-process drift checks, never planning/MCP output.
Password and the unclassified obtain-user-info value are never decoded.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import re
from types import MappingProxyType
from typing import TypeAlias

from v4_planning.material_provider import C3MaterialBinding

from .ldap_server_contract import LdapServerCandidateError, LdapServerCreateBinding
from .secret_create_191_http_transport import _valid_utf8
from .secret_metadata_http_transport import (
    _json_string_end, _json_value_end, _skip_json_space, _zeroize_mutable,
)

_UNAVAILABLE = "The private LDAP server projection is unavailable."
_MAX_BYTES = 8 * 1_048_576
_MAX_ITEMS = 10_000
_NUMBER = re.compile(rb"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z")
Scalar: TypeAlias = str | int
Span: TypeAlias = tuple[int, int]

# The sole permitted source is the qualified build-29 field/type projection.
LDAP_SCHEMA_TYPES: Mapping[str, str] = MappingProxyType({
    "account-key-filter": "string", "account-key-processing": "option",
    "antiphish": "option", "ca-cert": "string", "cnid": "string", "dn": "string",
    "gateway": "string", "group-filter": "string", "group-member-check": "option",
    "group-object-filter": "string", "group-search-base": "string", "interface": "string",
    "interface-select-method": "option", "member-attr": "string", "name": "string",
    "password": "password", "password-attr": "string", "password-expiry-warning": "option",
    "password-renewal": "option", "port": "integer", "search-type": "option",
    "secondary-server": "string", "secure": "option", "server": "string",
    "server-identity-check": "option", "source-ip": "string", "source-port": "integer",
    "ssl-min-proto-version": "option", "tertiary-server": "string", "two-factor": "option",
    "two-factor-authentication": "option", "two-factor-notification": "option",
    "type": "option", "user-info-exchange-server": "string", "username": "string",
})
_OPAQUE = frozenset({"password", "obtain-user-info"})
_METADATA = frozenset({
    "q_ref", "q_static", "q_global_entry", "q_origin_key", "q_mkey_type", "q_name",
    "q_no_edit", "q_no_rename", "q_path", "q_type",
})
_ENVELOPE = frozenset({
    "action", "build", "http_method", "http_status", "name", "path", "results",
    "revision", "old_revision", "serial", "status", "vdom", "version", "mkey", "size", "matched_count",
    "next_idx", "limit_reached", "revision_changed",
})


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode()).hexdigest()


class _ProtectedProjection(C3MaterialBinding):
    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> None:
        raise LdapServerCandidateError(_UNAVAILABLE)

    def __delattr__(self, name: str) -> None:
        raise LdapServerCandidateError(_UNAVAILABLE)


class LdapServerSchema(_ProtectedProjection):
    """Protected exact schema qualification; attributes remain private context."""

    __slots__ = ("types", "serial_digest", "state_digest")
    types: Mapping[str, str]
    serial_digest: str
    state_digest: str

    def __init__(self, types: Mapping[str, str], serial_digest: str) -> None:
        object.__setattr__(self, "types", MappingProxyType(dict(types)))
        object.__setattr__(self, "serial_digest", serial_digest)
        object.__setattr__(self, "state_digest", _digest({"types": dict(types), "serial": serial_digest}))


class LdapServerDefaults(_ProtectedProjection):
    """Protected default snapshot, including non-decoded opaque token digests."""

    __slots__ = ("values", "opaque_token_digests", "metadata", "serial_digest",
                 "schema_digest", "state_digest")
    values: Mapping[str, Scalar]
    opaque_token_digests: Mapping[str, str]
    metadata: Mapping[str, object]
    serial_digest: str
    schema_digest: str
    state_digest: str

    def __init__(self, values: Mapping[str, Scalar], opaque: Mapping[str, str],
                 metadata: Mapping[str, object], schema: LdapServerSchema) -> None:
        object.__setattr__(self, "values", MappingProxyType(dict(values)))
        object.__setattr__(self, "opaque_token_digests", MappingProxyType(dict(opaque)))
        object.__setattr__(self, "metadata", MappingProxyType(dict(metadata)))
        object.__setattr__(self, "serial_digest", schema.serial_digest)
        object.__setattr__(self, "schema_digest", schema.state_digest)
        object.__setattr__(self, "state_digest", _digest({"values": dict(values), "opaque": dict(opaque),
            "metadata": dict(metadata), "schema": self.schema_digest, "serial": self.serial_digest}))


class LdapServerDetail(LdapServerDefaults):
    """Protected exact created state; no ownership or deletion authority."""

    __slots__ = ("reference_count", "parameters_digest")
    reference_count: int
    parameters_digest: str

    def __init__(self, values: Mapping[str, Scalar], opaque: Mapping[str, str],
                 metadata: Mapping[str, object], schema: LdapServerSchema,
                 binding: LdapServerCreateBinding) -> None:
        super().__init__(values, opaque, metadata, schema)
        object.__setattr__(self, "reference_count", 0)
        object.__setattr__(self, "parameters_digest", binding.parameters_digest)
        object.__setattr__(self, "state_digest", _digest({"state": self.state_digest, "intent": self.parameters_digest}))


def _validate_string(token: memoryview) -> None:
    """Validate JSON encoding without making a decoded password string."""
    if len(token) < 3 or token[0] != 34 or token[-1] != 34 or not _valid_utf8(token):
        raise ValueError
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
                    token[i] not in b"0123456789abcdefABCDEF" for i in range(index + 1, index + 5)
                ):
                    raise ValueError
                index += 4
            elif token[index] not in b'"\\/bfnrt':
                raise ValueError
        index += 1


def _string(content: bytearray, span: Span) -> None:
    with memoryview(content)[slice(*span)] as token:
        if not (len(token) == 2 and token[0] == token[1] == 34):
            _validate_string(token)


def _members(content: bytearray, span: Span) -> dict[str, Span]:
    left, right = span
    if content[left] != 123 or content[right - 1] != 125:
        raise ValueError
    fields: dict[str, Span] = {}
    cursor = _skip_json_space(content, left + 1)
    while cursor < right - 1:
        key_end = _json_string_end(content, cursor) + 1
        if key_end - cursor > 258:
            raise ValueError
        _string(content, (cursor, key_end))
        key = json.loads(content[cursor:key_end])
        if type(key) is not str or key in fields or len(fields) >= _MAX_ITEMS:
            raise ValueError
        cursor = _skip_json_space(content, key_end)
        if content[cursor] != 58:
            raise ValueError
        left = _skip_json_space(content, cursor + 1)
        right_value = _json_value_end(content, left)
        if right_value >= right:
            raise ValueError
        fields[key] = left, right_value
        cursor = _skip_json_space(content, right_value)
        if cursor == right - 1:
            break
        if content[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(content, cursor + 1)
        if cursor >= right - 1:
            raise ValueError
    return fields


def _array(content: bytearray, span: Span) -> list[Span]:
    left, right = span
    if content[left] != 91 or content[right - 1] != 93:
        raise ValueError
    result: list[Span] = []
    cursor = _skip_json_space(content, left + 1)
    while cursor < right - 1:
        end = _json_value_end(content, cursor)
        if end >= right or len(result) >= _MAX_ITEMS:
            raise ValueError
        result.append((cursor, end))
        cursor = _skip_json_space(content, end)
        if cursor == right - 1:
            break
        if content[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(content, cursor + 1)
        if cursor >= right - 1:
            raise ValueError
    return result


def _validate(content: bytearray, span: Span, depth: int = 0) -> None:
    if depth > 20:
        raise ValueError
    first = content[span[0]]
    if first == 123:
        for child in _members(content, span).values():
            _validate(content, child, depth + 1)
    elif first == 91:
        for child in _array(content, span):
            _validate(content, child, depth + 1)
    elif first == 34:
        _string(content, span)
    else:
        with memoryview(content)[slice(*span)] as token:
            if token.tobytes() not in (b"true", b"false", b"null") and _NUMBER.fullmatch(token) is None:
                raise ValueError


def _decode(content: bytearray, fields: Mapping[str, Span], key: str) -> object:
    if key in _OPAQUE:
        raise ValueError
    return json.loads(content[slice(*fields[key])])


def _expect(content: bytearray, fields: Mapping[str, Span], key: str, expected: object) -> None:
    observed = _decode(content, fields, key)
    if type(observed) is not type(expected) or observed != expected:
        raise ValueError


def _top(content: bytearray, *, expected_serial: str, method: str = "GET",
         status: str = "success", http_status: int = 200, monitor: bool = False) -> dict[str, Span]:
    if (type(content) is not bytearray or not 0 < len(content) <= _MAX_BYTES
        or type(expected_serial) is not str or not 1 <= len(expected_serial) <= 128):
        raise ValueError
    start = _skip_json_space(content, 0)
    end = _json_value_end(content, start)
    if _skip_json_space(content, end) != len(content):
        raise ValueError
    fields = _members(content, (start, end))
    if not set(fields) <= _ENVELOPE:
        raise ValueError
    # Validate syntax and duplicate members without decoding any JSON values.
    _validate(content, (start, end))
    for key, expected in {"version": "v7.0.0", "build": 29, "serial": expected_serial,
                          "status": status}.items():
        _expect(content, fields, key, expected)
    if not monitor:
        for key, expected in {"http_method": method, "path": "user", "name": "ldap"}.items():
            _expect(content, fields, key, expected)
    elif "http_method" in fields:
        _expect(content, fields, "http_method", "GET")
    if "http_status" in fields:
        _expect(content, fields, "http_status", http_status)
    if "vdom" in fields:
        _expect(content, fields, "vdom", "root")
    return fields


def _schema(schema: LdapServerSchema, expected_serial: str) -> None:
    if (type(schema) is not LdapServerSchema or dict(schema.types) != LDAP_SCHEMA_TYPES
        or schema.serial_digest != hashlib.sha256(expected_serial.encode()).hexdigest()
        or schema.state_digest != _digest({"types": dict(schema.types), "serial": schema.serial_digest})):
        raise ValueError


def _record(content: bytearray, top: Mapping[str, Span]) -> dict[str, Span]:
    span = top["results"]
    if content[span[0]] == 91:
        rows = _array(content, span)
        if len(rows) != 1:
            raise ValueError
        span = rows[0]
    row = _members(content, span)
    if (not set(LDAP_SCHEMA_TYPES) <= set(row)
        or set(row) - set(LDAP_SCHEMA_TYPES) - _METADATA != {"obtain-user-info"}):
        raise ValueError
    return row


def _snapshot(content: bytearray, row: Mapping[str, Span]) -> tuple[
        dict[str, Scalar], dict[str, str], dict[str, object]]:
    values: dict[str, Scalar] = {}
    opaque: dict[str, str] = {}
    metadata: dict[str, object] = {}
    for key, span in row.items():
        if key in _OPAQUE:
            _string(content, span)
            with memoryview(content)[slice(*span)] as token:
                opaque[key] = hashlib.sha256(token).hexdigest()
        elif key in LDAP_SCHEMA_TYPES:
            value = _decode(content, row, key)
            expected = int if LDAP_SCHEMA_TYPES[key] == "integer" else str
            if type(value) is not expected or not isinstance(value, (str, int)):
                raise ValueError
            values[key] = value
        else:
            value = _decode(content, row, key)
            metadata_type = (bool if key in {"q_static", "q_global_entry", "q_no_edit", "q_no_rename"}
                             else int if key in {"q_ref", "q_type"} else str)
            if type(value) is not metadata_type:
                raise ValueError
            metadata[key] = value
    return values, opaque, metadata


def _destroy(content: bytearray) -> None:
    if isinstance(content, bytearray):
        _zeroize_mutable(content)


def project_ldap_schema(content: bytearray, *, expected_serial: str) -> LdapServerSchema:
    """Consume the fixed schema GET; accept exactly the observed 35 field types."""
    try:
        top = _top(content, expected_serial=expected_serial)
        _expect(content, top, "action", "schema")
        result = _members(content, top["results"])
        children = _members(content, result["children"])
        if set(children) != set(LDAP_SCHEMA_TYPES):
            raise ValueError
        for name, expected in LDAP_SCHEMA_TYPES.items():
            descriptor = _members(content, children[name])
            _expect(content, descriptor, "type", expected)
        return LdapServerSchema(LDAP_SCHEMA_TYPES, hashlib.sha256(expected_serial.encode()).hexdigest())
    except Exception:
        raise LdapServerCandidateError(_UNAVAILABLE) from None
    finally:
        _destroy(content)


def project_ldap_defaults(content: bytearray, schema: LdapServerSchema, *,
                          expected_serial: str) -> LdapServerDefaults:
    """Keep all 34 classified values and only raw-token hashes for two opaque fields."""
    try:
        _schema(schema, expected_serial)
        top = _top(content, expected_serial=expected_serial)
        _expect(content, top, "action", "default")
        values, opaque, metadata = _snapshot(content, _record(content, top))
        if values["name"] != "":
            raise ValueError
        return LdapServerDefaults(values, opaque, metadata, schema)
    except Exception:
        raise LdapServerCandidateError(_UNAVAILABLE) from None
    finally:
        _destroy(content)


def project_ldap_detail(content: bytearray, schema: LdapServerSchema, defaults: LdapServerDefaults,
                        binding: LdapServerCreateBinding, *, expected_serial: str) -> LdapServerDetail:
    """Qualify this profile's sole normalization; require explicit integer q_ref zero."""
    try:
        _schema(schema, expected_serial)
        if (type(defaults) is not LdapServerDefaults or defaults.schema_digest != schema.state_digest
            or defaults.serial_digest != schema.serial_digest):
            raise ValueError
        top = _top(content, expected_serial=expected_serial)
        if "mkey" in top:
            _expect(content, top, "mkey", binding.name)
        values, opaque, metadata = _snapshot(content, _record(content, top))
        desired = binding.desired_nonmaterial()
        if (len(desired) != 17 or desired["group-object-filter"] != ""
            or type(metadata.get("q_ref")) is not int or metadata["q_ref"] != 0
            or "q_origin_key" in metadata and metadata["q_origin_key"] != binding.name
            or set(values) != set(defaults.values)):
            raise ValueError
        for key, current in values.items():
            expected = (defaults.values[key] if key not in desired or key == "group-object-filter"
                        else desired[key])
            if type(current) is not type(expected) or current != expected:
                raise ValueError
        if opaque["obtain-user-info"] != defaults.opaque_token_digests["obtain-user-info"]:
            raise ValueError
        return LdapServerDetail(values, opaque, metadata, schema, binding)
    except Exception:
        raise LdapServerCandidateError(_UNAVAILABLE) from None
    finally:
        _destroy(content)


def project_ldap_info(content: bytearray, binding: LdapServerCreateBinding, *,
                      expected_serial: str) -> bool:
    """Positive native info-only evidence; HTTP caller pins the monitor request route."""
    try:
        top = _top(content, expected_serial=expected_serial, monitor=True)
        result = _members(content, top["results"])
        # Native info-only evidence requires these positive nodes and no error;
        # build 29 also returns other result members. They are syntax-validated
        # by _top but are neither interpreted nor returned by this projection.
        if "error" in result or not {"schema", "general", "rootdse"} <= set(result):
            raise ValueError
        schema = _members(content, result["schema"])
        general = _members(content, result["general"])
        _members(content, result["rootdse"])
        classes = _array(content, schema["objectClasses"])
        if not classes or any(content[span[0]] != 34 for span in classes):
            raise ValueError
        if not _members(content, schema["attributeTypes"]):
            raise ValueError
        _expect(content, general, "configured_dn", binding.dn)
        if "server_type" not in general:
            raise ValueError
        return True
    except Exception:
        raise LdapServerCandidateError(_UNAVAILABLE) from None
    finally:
        _destroy(content)


def project_ldap_ack(content: bytearray, binding: LdapServerCreateBinding, *,
                     expected_serial: str, method: str = "POST") -> bool:
    """Qualify only a fixed POST/DELETE acknowledgement, never infer a readback."""
    try:
        if method not in {"POST", "DELETE"}:
            raise ValueError
        top = _top(content, expected_serial=expected_serial, method=method)
        if "mkey" in top:
            _expect(content, top, "mkey", binding.name)
        if "results" in top:
            span = top["results"]
            if content[span[0]] == 123:
                if _members(content, span):
                    raise ValueError
            elif content[span[0]] != 91 or _array(content, span):
                raise ValueError
        return True
    except Exception:
        raise LdapServerCandidateError(_UNAVAILABLE) from None
    finally:
        _destroy(content)


def project_ldap_absence(content: bytearray, binding: LdapServerCreateBinding, *,
                         expected_serial: str, http_status: int, collection: bool = False) -> bool:
    """Two separate fixed reads must both pass; neither alone authorizes creation/deletion."""
    try:
        expected_status = 200 if collection else 404
        if type(http_status) is not int or http_status != expected_status or type(collection) is not bool:
            raise ValueError
        top = _top(content, expected_serial=expected_serial, http_status=expected_status,
                   status="success" if collection else "error")
        if "mkey" in top:
            _expect(content, top, "mkey", binding.name)
        if not collection:
            if "results" in top:
                raise ValueError
        else:
            for span in _array(content, top["results"]):
                row = _members(content, span)
                if not {"name"} <= set(row) or not set(row) <= {"name"} | _METADATA:
                    raise ValueError
                name = _decode(content, row, "name")
                if type(name) is not str or name == binding.name:
                    raise ValueError
        return True
    except Exception:
        raise LdapServerCandidateError(_UNAVAILABLE) from None
    finally:
        _destroy(content)
