"""Inactive fixed Instruction feature state and transition contract.

All configuration fields are bound privately, including fields unknown to the
frontend. Only the compiled guest-instruction value becomes a PUT body. This
module supplies no execution, shared-setting ownership or restoration authority.
"""
from __future__ import annotations

import hashlib
import json
from typing import Literal, NoReturn

from v4_planning.material_provider import _OpaqueC3Object
from . import secret_bulk_import_metadata as m
from . import target_lifecycle_dependencies as d
from .secret_metadata_http_transport import (
    _json_string_end, _json_value_end, _skip_json_space, _zeroize_mutable,
)

CONTRACT = "fortipam-700-build29-instruction-feature-private-v2"
_SCHEMA_DEFAULT_PATHS = frozenset(
    ("results", "children", "reverse-service-setting", "children", name, "default")
    for name in ("auto-gateway-id-whitelist", "client-ca")
)
_FLAG = "guest-instruction"
_METADATA = frozenset({"q_global_entry", "q_mkey_type", "q_name", "q_no_edit",
    "q_no_rename", "q_origin_key", "q_path", "q_ref", "q_static", "q_type"})
_ERROR = "The private Instruction feature contract is unavailable."


class InstructionFeatureContractError(ValueError):
    """A categorical refusal with no raw configuration or partial state."""


def _fail() -> NoReturn:
    raise InstructionFeatureContractError(_ERROR) from None


def _require_digest(value: str) -> None:
    if type(value) is not str or m._DIGEST.fullmatch(value) is None:
        _fail()


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
        separators=(",", ":"), allow_nan=False).encode()).hexdigest()


class _Private(_OpaqueC3Object):
    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> None:
        _fail()

    def __delattr__(self, name: str) -> None:
        _fail()


def _fields(raw: bytearray, span: tuple[int, int]) -> dict[str, tuple[int, int]]:
    """Decode object keys only; never deserialize configuration values."""
    start, end = span
    if raw[start] != 123 or raw[end - 1] != 125:
        raise ValueError
    cursor = _skip_json_space(raw, start + 1)
    fields: dict[str, tuple[int, int]] = {}
    while cursor < end - 1:
        key_end = _json_string_end(raw, cursor) + 1
        key = json.loads(raw[cursor:key_end])
        if type(key) is not str or len(key) > 512 or key in fields or len(fields) >= 512:
            raise ValueError
        separator = _skip_json_space(raw, key_end)
        if raw[separator] != 58:
            raise ValueError
        left = _skip_json_space(raw, separator + 1)
        right = _json_value_end(raw, left)
        fields[key] = (left, right)
        cursor = _skip_json_space(raw, right)
        if cursor == end - 1:
            break
        if raw[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(raw, cursor + 1)
    return fields


def _fingerprint(raw: bytearray, span: tuple[int, int], depth: int = 0) -> str:
    """Ignore structural whitespace/order; preserve every scalar's wire bytes."""
    if depth > 16:
        raise ValueError
    start, end = span
    if raw[start] == 123:
        fields = _fields(raw, span)
        return _digest(["object", [(key, _fingerprint(raw, fields[key], depth + 1))
                                  for key in sorted(fields)]])
    if raw[start] == 91:
        return _digest(["array", [_fingerprint(raw, item, depth + 1)
                                 for item in m._array(raw, span, 4096)]])
    return _digest(["scalar", hashlib.sha256(memoryview(raw)[start:end]).hexdigest()])


class InstructionFeatureState(_Private):
    """Opaque complete setting, schema and device binding, without raw values."""
    __slots__ = ("_serial", "_schema", "_preserved", "_state", "enabled", "field_count")
    _serial: str
    _schema: str
    _preserved: str
    _state: str
    enabled: bool
    field_count: int

    def __init__(self) -> None:
        _fail()


def _schema_fingerprint(raw: bytearray, span: tuple[int, int],
                        path: tuple[str, ...] = ("results",)) -> str:
    """Build29 v2 ignores only two validated string defaults, never current values.

    Their real default changes no longer signal schema drift. Presence, string
    type, surrounding metadata and every other value remain bound. The complete
    envelope must pass strict JSON/UTF-8 validation before this helper is used.
    """
    if path in _SCHEMA_DEFAULT_PATHS:
        if raw[span[0]] != 34:
            raise ValueError
        return _digest([CONTRACT, "schema-default", path, "string"])
    if any(target[:len(path)] == path for target in _SCHEMA_DEFAULT_PATHS):
        fields = _fields(raw, span)
        required = {target[len(path)] for target in _SCHEMA_DEFAULT_PATHS
                    if target[:len(path)] == path}
        if not required <= fields.keys():
            raise ValueError
        if "default" in required and m._scalar(raw, fields["type"]) != "string":
            raise ValueError
        return _digest(["object", [(key, _schema_fingerprint(raw, fields[key], path + (key,)))
                                  for key in sorted(fields)]])
    return _fingerprint(raw, span, len(path) - 1)


def _schema_binding(schema: bytearray, serial_digest: str) -> tuple[frozenset[str], str]:
    """Qualify the entire schema before a reader may request configuration."""
    _require_digest(serial_digest)
    schema_span = d._one(schema, d._envelope(schema, path="secret", name="setting",
        serial_digest=serial_digest, action="schema"))
    children_span = _fields(schema, schema_span)["children"]
    children = _fields(schema, children_span)
    if _FLAG not in children or len(children) < 2 or set(children) & _METADATA:
        raise ValueError
    properties = _fields(schema, children[_FLAG])
    if m._scalar(schema, properties["type"]) != "option":
        raise ValueError
    choices = [m._scalar(schema, _fields(schema, span)["name"])
               for span in m._array(schema, properties["options"], 8)]
    if len(choices) != 2 or set(choices) != {"enable", "disable"}:
        raise ValueError
    return frozenset(children), _schema_fingerprint(schema, schema_span)


def read_instruction_feature_state(schema: bytearray, current: bytearray, *,
                                   serial_digest: str) -> InstructionFeatureState:
    """Consume exact full schema/current envelopes and wipe both inputs."""
    try:
        children, schema_digest = _schema_binding(schema, serial_digest)
        state_span = d._one(current, d._envelope(current, path="secret", name="setting",
                                               serial_digest=serial_digest))
        fields = _fields(current, state_span)
        if (set(fields) - _METADATA != children
                or "q_no_edit" in fields and m._scalar(current, fields["q_no_edit"]) is not False):
            raise ValueError
        value = m._scalar(current, fields[_FLAG])
        if type(value) is not str or value not in {"enable", "disable"}:
            raise ValueError
        preserved = _digest([(key, _fingerprint(current, fields[key]))
                             for key in sorted(fields) if key != _FLAG])
        state = object.__new__(InstructionFeatureState)
        values = {"_serial": serial_digest, "_schema": schema_digest,
            "_preserved": preserved, "_state": _digest([CONTRACT, serial_digest,
                schema_digest, preserved, value]), "enabled": value == "enable",
            "field_count": len(children)}
        for key, item in values.items():
            object.__setattr__(state, key, item)
        return state
    except Exception:
        _fail()
    finally:
        for raw in (schema, current):
            if type(raw) is bytearray:
                _zeroize_mutable(raw)


class InstructionFeatureTransition(_Private):
    """A fixed transition; restore still requires the original enable ACK."""
    __slots__ = ("_current", "_expected", "_phase", "digest")
    _current: str
    _expected: str
    _phase: Literal["enable", "restore"]
    digest: str

    def __init__(self, baseline: InstructionFeatureState, current: InstructionFeatureState, *,
                 phase: Literal["enable", "restore"], operation_nonce: str) -> None:
        _require_digest(operation_nonce)
        if (type(baseline) is not InstructionFeatureState or type(current) is not InstructionFeatureState
                or type(phase) is not str or phase not in {"enable", "restore"}
                or baseline.enabled or current.enabled != (phase == "restore")
                or (baseline._serial, baseline._schema, baseline._preserved)
                    != (current._serial, current._schema, current._preserved)):
            _fail()
        target = "enable" if phase == "enable" else "disable"
        expected = _digest([CONTRACT, baseline._serial, baseline._schema, baseline._preserved, target])
        for key, value in {"_current": current._state, "_expected": expected, "_phase": phase,
                "digest": _digest([CONTRACT, phase, operation_nonce, baseline._state,
                                   current._state, expected])}.items():
            object.__setattr__(self, key, value)


def build_instruction_feature_body(plan: InstructionFeatureTransition,
                                   current: InstructionFeatureState) -> bytearray:
    """Compile only the fixed flag after complete current-state drift rejection."""
    if (type(plan) is not InstructionFeatureTransition or type(current) is not InstructionFeatureState
            or plan._current != current._state):
        _fail()
    return bytearray(b'{"guest-instruction":"enable"}' if plan._phase == "enable"
                     else b'{"guest-instruction":"disable"}')


def verify_instruction_feature_readback(plan: InstructionFeatureTransition,
                                       current: InstructionFeatureState) -> None:
    if (type(plan) is not InstructionFeatureTransition or type(current) is not InstructionFeatureState
            or plan._expected != current._state):
        _fail()
