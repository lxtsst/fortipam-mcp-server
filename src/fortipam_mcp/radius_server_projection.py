"""Private build-29 RADIUS state qualification, with no I/O or execution path.

Four password tokens and two empty unclassified arrays are hashed without decoding.
The complete snapshot stays inside the protected process. This module does not
qualify test-connect success, material application, ownership, or deletion.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from types import MappingProxyType
from typing import TypeAlias

from v4_planning.material_provider import C3MaterialBinding

from .ldap_server_projection import (
    _array, _digest, _members, _string, _validate,
)
from .secret_metadata_http_transport import (
    _json_value_end, _skip_json_space, _zeroize_mutable,
)

_UNAVAILABLE = "The private RADIUS state projection is unavailable."
_MAX_BYTES = 2 * 1_048_576
Scalar: TypeAlias = str | int
Span: TypeAlias = tuple[int, int]

# Exact minimized type map from the same build-29 schema/default qualification.
# None deliberately means unclassified, not a guessed table schema.
RADIUS_SCHEMA_TYPES: Mapping[str, str | None] = MappingProxyType({
    "accounting-server": None, "acct-all-servers": "option",
    "acct-interim-interval": "integer", "all-usergroup": "option",
    "auth-type": "option", "class": None, "group-override-attr-type": "option",
    "h3c-compatibility": "option", "interface": "string",
    "interface-select-method": "option", "name": "string", "nas-ip": "ipv4-address",
    "password-encoding": "option", "password-renewal": "option", "radius-coa": "option",
    "radius-port": "integer", "require-message-authenticator": "option", "rsso": "option",
    "rsso-context-timeout": "integer", "rsso-endpoint-attribute": "option",
    "rsso-endpoint-block-attribute": "option", "rsso-ep-one-ip-only": "option",
    "rsso-flush-ip-session": "option", "rsso-log-flags": "option", "rsso-log-period": "integer",
    "rsso-radius-response": "option", "rsso-radius-server-port": "integer",
    "rsso-secret": "password", "rsso-validate-request-secret": "option",
    "secondary-secret": "password", "secondary-server": "string", "secret": "password",
    "server": "string", "source-ip": "string", "sso-attribute": "option",
    "sso-attribute-key": "string", "sso-attribute-value-override": "option",
    "switch-controller-acct-fast-framedip-detect": "integer",
    "switch-controller-service-type": "option", "tertiary-secret": "password",
    "tertiary-server": "string", "timeout": "integer", "use-management-vdom": "option",
    "username-case-sensitive": "option",
})
_OPAQUE_ARRAYS = frozenset({"accounting-server", "class"})
_PASSWORDS = frozenset({"secret", "secondary-secret", "tertiary-secret", "rsso-secret"})
_METADATA_TYPES: Mapping[str, type] = MappingProxyType({
    "q_ref": int, "q_static": bool, "q_global_entry": bool, "q_origin_key": str,
    "q_mkey_type": str, "q_name": str, "q_no_edit": bool, "q_no_rename": bool,
    "q_path": str, "q_type": int,
})
_ENVELOPE = frozenset({
    "action", "build", "http_method", "http_status", "name", "path", "results",
    "revision", "old_revision", "serial", "status", "vdom", "version", "mkey", "size",
    "matched_count", "next_idx", "limit_reached", "revision_changed",
})


class RadiusServerProjectionError(RuntimeError):
    """Value-free refusal; native data never appears in the error."""


class _ProtectedProjection(C3MaterialBinding):
    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> None:
        raise RadiusServerProjectionError(_UNAVAILABLE)

    def __delattr__(self, name: str) -> None:
        raise RadiusServerProjectionError(_UNAVAILABLE)


class RadiusServerSchema(_ProtectedProjection):
    """Exact field-shape/device binding, not permission or product maturity."""

    __slots__ = ("serial_digest", "state_digest")
    serial_digest: str
    state_digest: str

    def __init__(self, serial_digest: str) -> None:
        object.__setattr__(self, "serial_digest", serial_digest)
        object.__setattr__(self, "state_digest", _digest({
            "types": dict(RADIUS_SCHEMA_TYPES), "serial": serial_digest,
        }))


class RadiusServerState(_ProtectedProjection):
    """Complete private values and opaque hashes; never a public read result."""

    __slots__ = ("values", "opaque_token_digests", "metadata", "schema_digest", "state_digest")
    values: Mapping[str, Scalar]
    opaque_token_digests: Mapping[str, str]
    metadata: Mapping[str, object]
    schema_digest: str
    state_digest: str

    def __init__(self, values: Mapping[str, Scalar], opaque: Mapping[str, str],
                 metadata: Mapping[str, object], schema: RadiusServerSchema) -> None:
        object.__setattr__(self, "values", MappingProxyType(dict(values)))
        object.__setattr__(self, "opaque_token_digests", MappingProxyType(dict(opaque)))
        object.__setattr__(self, "metadata", MappingProxyType(dict(metadata)))
        object.__setattr__(self, "schema_digest", schema.state_digest)
        object.__setattr__(self, "state_digest", _digest({
            "values": dict(values), "opaque": dict(opaque), "metadata": dict(metadata),
            "schema": schema.state_digest,
        }))


def _decode(content: bytearray, fields: Mapping[str, Span], key: str) -> object:
    if key in _PASSWORDS | _OPAQUE_ARRAYS:
        raise ValueError
    return json.loads(content[slice(*fields[key])])


def _expect(content: bytearray, fields: Mapping[str, Span], key: str, expected: object) -> None:
    value = _decode(content, fields, key)
    if type(value) is not type(expected) or value != expected:
        raise ValueError


def _top(content: bytearray, expected_serial: str) -> dict[str, Span]:
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
    # Validate envelope scalars only. Result fields have their own fixed shape
    # checks below; recursively decoding unclassified array member names would
    # cross the opaque boundary even when the enclosing buffer is later wiped.
    for name, location in fields.items():
        if name != "results":
            if content[location[0]] in (91, 123):
                raise ValueError
            _validate(content, location)
    for name, expected in {
        "version": "v7.0.0", "build": 29, "serial": expected_serial, "status": "success",
        "http_method": "GET", "path": "user", "name": "radius",
    }.items():
        _expect(content, fields, name, expected)
    for name, expected in {"http_status": 200, "vdom": "root"}.items():
        if name in fields:
            _expect(content, fields, name, expected)
    return fields


def _check_schema(schema: RadiusServerSchema, expected_serial: str) -> None:
    if type(expected_serial) is not str or not 1 <= len(expected_serial) <= 128:
        raise ValueError
    serial_digest = hashlib.sha256(expected_serial.encode()).hexdigest()
    if (type(schema) is not RadiusServerSchema or schema.serial_digest != serial_digest
        or schema.state_digest != _digest({"types": dict(RADIUS_SCHEMA_TYPES), "serial": serial_digest})):
        raise ValueError


def _snapshot(content: bytearray, span: Span, schema: RadiusServerSchema) -> RadiusServerState:
    if content[span[0]] == 91:
        rows = _array(content, span)
        if len(rows) != 1:
            raise ValueError
        span = rows[0]
    fields = _members(content, span)
    if (not set(RADIUS_SCHEMA_TYPES) <= set(fields)
        or not set(fields) <= set(RADIUS_SCHEMA_TYPES) | set(_METADATA_TYPES)):
        raise ValueError
    values: dict[str, Scalar] = {}
    opaque: dict[str, str] = {}
    metadata: dict[str, object] = {}
    for name, location in fields.items():
        if name in _PASSWORDS | _OPAQUE_ARRAYS:
            if name in _PASSWORDS:
                _string(content, location)
            else:
                # No schema exists for populated arrays. The primary-only
                # profile qualifies empty arrays and refuses other shapes
                # before traversing or decoding any opaque member names.
                if _array(content, location):
                    raise ValueError
            with memoryview(content)[slice(*location)] as token:
                opaque[name] = hashlib.sha256(token).hexdigest()
        elif name in RADIUS_SCHEMA_TYPES:
            if content[location[0]] in (91, 123):
                raise ValueError
            _validate(content, location)
            value = _decode(content, fields, name)
            expected_type = int if RADIUS_SCHEMA_TYPES[name] == "integer" else str
            if type(value) is not expected_type or not isinstance(value, (str, int)):
                raise ValueError
            values[name] = value
        else:
            if content[location[0]] in (91, 123):
                raise ValueError
            _validate(content, location)
            value = _decode(content, fields, name)
            if type(value) is not _METADATA_TYPES[name]:
                raise ValueError
            metadata[name] = value
    return RadiusServerState(values, opaque, metadata, schema)


def _destroy(content: bytearray) -> None:
    if isinstance(content, bytearray):
        _zeroize_mutable(content)


def project_radius_schema(content: bytearray, *, expected_serial: str) -> RadiusServerSchema:
    """Consume exactly the 44-field schema; do not infer two missing types."""
    try:
        top = _top(content, expected_serial)
        _expect(content, top, "action", "schema")
        result = _members(content, top["results"])
        _validate(content, top["results"])
        children = _members(content, result["children"])
        if set(children) != set(RADIUS_SCHEMA_TYPES):
            raise ValueError
        for name, kind in RADIUS_SCHEMA_TYPES.items():
            descriptor = _members(content, children[name])
            if kind is None:
                if "type" in descriptor:
                    raise ValueError
            else:
                _expect(content, descriptor, "type", kind)
        return RadiusServerSchema(hashlib.sha256(expected_serial.encode()).hexdigest())
    except Exception:
        raise RadiusServerProjectionError(_UNAVAILABLE) from None
    finally:
        _destroy(content)


def project_radius_defaults(content: bytearray, schema: RadiusServerSchema, *,
                            expected_serial: str) -> RadiusServerState:
    """Consume all defaults, retaining 38 scalars and six opaque token hashes."""
    try:
        _check_schema(schema, expected_serial)
        top = _top(content, expected_serial)
        _expect(content, top, "action", "default")
        state = _snapshot(content, top["results"], schema)
        if (state.values["name"] != "" or state.values["server"] != ""
            or state.values["secondary-server"] != "" or state.values["tertiary-server"] != ""
            or state.values["auth-type"] != "auto" or state.values["radius-port"] != 0
            or state.values["require-message-authenticator"] != "enable"):
            raise ValueError
        return state
    except Exception:
        raise RadiusServerProjectionError(_UNAVAILABLE) from None
    finally:
        _destroy(content)


def project_radius_detail(content: bytearray, schema: RadiusServerSchema, *,
                          expected_serial: str) -> RadiusServerState:
    """Consume one complete detail; it grants no create/adoption/recovery authority."""
    try:
        _check_schema(schema, expected_serial)
        top = _top(content, expected_serial)
        if "action" in top:
            raise ValueError
        state = _snapshot(content, top["results"], schema)
        if not state.values["name"]:
            raise ValueError
        if "mkey" in top:
            _expect(content, top, "mkey", state.values["name"])
        if "q_origin_key" in state.metadata and state.metadata["q_origin_key"] != state.values["name"]:
            raise ValueError
        return state
    except Exception:
        raise RadiusServerProjectionError(_UNAVAILABLE) from None
    finally:
        _destroy(content)
