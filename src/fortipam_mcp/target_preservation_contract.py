"""Private build-29 Target coordinate changes with complete native-state checks.

No I/O, runtime registration or authorization. All 36 configured fields and
observed compiled metadata are fingerprinted; only identity and four coordinates
are decoded. Nested content stays opaque. Token fingerprints ignore insignificant
whitespace, but retain string encoding, object member order and array order.
The caller must independently qualify the route, actor, ownership, freshness,
schema, backend PUT semantics and M4 authority, and clear returned request bodies.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re

from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as m
from .secret_metadata_http_transport import (
    _json_string_end, _json_value_end, _skip_json_space, _zeroize_mutable,
)

_ERROR = "Protected Target preservation unavailable."
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
TARGET_STATE_FIELDS = frozenset({
    'access',
    'address',
    'ca',
    'class',
    'creation-time',
    'description',
    'domain',
    'dynamic-gateway',
    'gateway',
    'gateway-cn',
    'group-permission',
    'hostkey',
    'id',
    'kdc-address',
    'ldaps-min-ssl-version',
    'ldaps-port',
    'name',
    'rdp-load-balancing-info',
    'rdp-min-ssl-version',
    'service-addrs',
    'sql-log',
    'sql-server-log-status',
    'ssh-hostkey-change-action',
    'ssh-hostkey-import-method',
    'ssh-hostkey-new-algorithm-action',
    'ssh-hostkey-verification',
    'ssms-min-ssl-version',
    'template',
    'url',
    'user-base',
    'user-naming-attribute',
    'user-permission',
    'uuid',
    'web-proxy',
    'web-proxy-status',
    'winrm-https',
})

_COORDINATES = ("template", "address", "domain", "url")
_METADATA = frozenset({
    "q_ref", "q_static", "q_global_entry", "q_origin_key", "q_mkey_type", "q_name",
    "q_no_edit", "q_no_rename", "q_path", "q_type", "permissions",
    "is_service_addr", "appfilter_result", "priv_acct", "gateway_info",
})
_ENVELOPE = frozenset({"version", "build", "path", "name", "http_method", "status",
    "http_status", "vdom", "serial", "results", "error", "mkey", "limit_reached",
    "size", "matched_count", "next_idx"})


class TargetPreservationError(ValueError):
    """Fixed non-disclosing failure; never a partial state or request."""


@dataclass(frozen=True, slots=True, repr=False)
class TargetCoordinates(_OpaqueC3Object):
    template: str
    address: str
    domain: str
    url: str

    def __post_init__(self) -> None:
        try:
            for key in _COORDINATES:
                m._text(getattr(self, key), empty=key != "template", maximum=79 if key == "template" else 255)
        except Exception:
            raise TargetPreservationError(_ERROR) from None


@dataclass(frozen=True, slots=True, repr=False)
class TargetState(_OpaqueC3Object):
    name: str
    serial_digest: str
    coordinates: TargetCoordinates
    field_digests: tuple[tuple[str, str], ...]
    metadata_digests: tuple[tuple[str, str], ...]
    state_digest: str
    preserved_digest: str


@dataclass(frozen=True, slots=True, repr=False)
class TargetCoordinateChange(_OpaqueC3Object):
    baseline: TargetState
    desired: TargetCoordinates


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _token_digest(content: bytearray, span: tuple[int, int]) -> str:
    digest = hashlib.sha256()
    cursor, end = span
    with memoryview(content) as view:
        while cursor < end:
            if content[cursor] in b" \t\r\n":
                cursor += 1
            else:
                right = _json_string_end(content, cursor) + 1 if content[cursor] == 34 else cursor + 1
                digest.update(view[cursor:right])
                cursor = right
    return digest.hexdigest()


def _member_count(content: bytearray, span: tuple[int, int]) -> int:
    start, end = span
    if content[start] != 123 or content[end - 1] != 125:
        raise ValueError
    cursor, count = _skip_json_space(content, start + 1), 0
    while cursor < end - 1:
        key_end = _json_string_end(content, cursor) + 1
        left = _skip_json_space(content, _skip_json_space(content, key_end) + 1)
        cursor = _skip_json_space(content, _json_value_end(content, left))
        count += 1
        if cursor != end - 1:
            cursor = _skip_json_space(content, cursor + 1)
    return count


def _state_digests(name: str, serial: str, fields: tuple[tuple[str, str], ...],
                   metadata: tuple[tuple[str, str], ...]) -> tuple[str, str]:
    return (_digest((name, serial, fields, metadata)),
            _digest((name, serial, tuple(item for item in fields if item[0] not in _COORDINATES), metadata)))


def _api_source_context(base_url: str, token_digest: str, ca_digest: str | None,
                        serial_digest: str) -> str:
    """Bind constructor-captured source inputs; never reread a mutable CA path."""
    return _digest(('target-api-dependency-source-v1', base_url,
                    token_digest, ca_digest, serial_digest))


def _checked_state(state: TargetState) -> None:
    if (type(state) is not TargetState or type(state.coordinates) is not TargetCoordinates
            or type(state.field_digests) is not tuple or type(state.metadata_digests) is not tuple
            or type(state.serial_digest) is not str or _DIGEST.fullmatch(state.serial_digest) is None):
        raise ValueError
    m._text(state.name)
    state.coordinates.__post_init__()
    for entries in (state.field_digests, state.metadata_digests):
        if any(type(item) is not tuple or len(item) != 2 or type(item[0]) is not str
               or type(item[1]) is not str or _DIGEST.fullmatch(item[1]) is None for item in entries):
            raise ValueError
        if entries != tuple(sorted(entries)) or len({item[0] for item in entries}) != len(entries):
            raise ValueError
    if (set(dict(state.field_digests)) != TARGET_STATE_FIELDS
            or not set(dict(state.metadata_digests)) <= _METADATA
            or dict(state.field_digests)["name"] != _digest(state.name)
            or any(dict(state.field_digests)[key] != _digest(getattr(state.coordinates, key)) for key in _COORDINATES)
            or _state_digests(state.name, state.serial_digest, state.field_digests, state.metadata_digests)
            != (state.state_digest, state.preserved_digest)):
        raise ValueError


def capture_target_state(content: bytearray, *, expected_name: str,
                         expected_serial_digest: str) -> TargetState:
    """Consume a complete fixed detail response; fingerprints confer no authority."""
    try:
        if (type(content) is not bytearray or not 0 < len(content) <= 2 * 1024 * 1024
                or type(expected_serial_digest) is not str or _DIGEST.fullmatch(expected_serial_digest) is None):
            raise ValueError
        m._text(expected_name)
        start = _skip_json_space(content, 0)
        end = _json_value_end(content, start)
        if _skip_json_space(content, end) != len(content):
            raise ValueError
        m._validate_json(content, start, end, depth=0, budget=[50000])
        envelope = m._object_spans(content, start, end, _ENVELOPE)
        for key, expected in {"version": "v7.0.0", "build": 29, "path": "secret", "name": "target",
                              "http_method": "GET", "status": "success", "http_status": 200,
                              "vdom": "root"}.items():
            value = m._scalar(content, envelope[key])
            if type(value) is not type(expected) or value != expected:
                raise ValueError
        serial = m._text(m._scalar(content, envelope["serial"]), maximum=128)
        if not hmac.compare_digest(hashlib.sha256(serial.encode()).hexdigest(), expected_serial_digest):
            raise ValueError
        if "error" in envelope:
            error = m._scalar(content, envelope["error"])
            if error is not None and (type(error) is not int or error != 0):
                raise ValueError
        if "mkey" in envelope and m._scalar(content, envelope["mkey"]) != expected_name:
            raise ValueError
        if "limit_reached" in envelope and m._scalar(content, envelope["limit_reached"]) is not False:
            raise ValueError
        for key in ("size", "matched_count", "next_idx"):
            if key in envelope:
                value = m._scalar(content, envelope[key])
                if type(value) is not int or value not in ((0, 1) if key == "next_idx" else (1,)):
                    raise ValueError
        row = envelope["results"]
        if content[row[0]] == 91:
            rows = m._array(content, row, 1)
            if len(rows) != 1:
                raise ValueError
            row = rows[0]
        spans = m._object_spans(content, *row, TARGET_STATE_FIELDS | _METADATA)
        if (not TARGET_STATE_FIELDS <= set(spans) or _member_count(content, row) != len(spans)
                or m._scalar(content, spans["name"]) != expected_name):
            raise ValueError
        if "q_origin_key" in spans and m._scalar(content, spans["q_origin_key"]) != expected_name:
            raise ValueError
        coordinates = TargetCoordinates(*(m._text(m._scalar(content, spans[key]),
            empty=key != "template", maximum=79 if key == "template" else 255) for key in _COORDINATES))
        decoded = {"name": expected_name, **{key: getattr(coordinates, key) for key in _COORDINATES}}
        fields = tuple((key, _digest(decoded[key]) if key in decoded else _token_digest(content, spans[key]))
                       for key in sorted(TARGET_STATE_FIELDS))
        metadata = tuple((key, _token_digest(content, spans[key])) for key in sorted(_METADATA & set(spans)))
        state_digest, preserved_digest = _state_digests(expected_name, expected_serial_digest, fields, metadata)
        return TargetState(expected_name, expected_serial_digest, coordinates, fields, metadata,
                           state_digest, preserved_digest)
    except Exception:
        raise TargetPreservationError(_ERROR) from None
    finally:
        if isinstance(content, bytearray):
            _zeroize_mutable(content)


def _body(change: TargetCoordinateChange, *, restore: bool) -> bytearray:
    values = change.baseline.coordinates if restore else change.desired
    return bytearray(json.dumps({key: getattr(values, key) for key in _COORDINATES
        if getattr(change.baseline.coordinates, key) != getattr(change.desired, key)},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())


def _checked_change(change: TargetCoordinateChange) -> None:
    if type(change) is not TargetCoordinateChange or type(change.desired) is not TargetCoordinates:
        raise ValueError
    _checked_state(change.baseline)
    change.desired.__post_init__()
    if change.desired == change.baseline.coordinates:
        raise ValueError


def compile_target_coordinate_update(content: bytearray, *, baseline: TargetState,
                                     desired: TargetCoordinates) -> tuple[bytearray, TargetCoordinateChange]:
    """Consume a fresh detail and compile only changed coordinates after drift checks."""
    try:
        change = TargetCoordinateChange(baseline, desired)
        _checked_change(change)
        current = capture_target_state(content, expected_name=baseline.name,
                                       expected_serial_digest=baseline.serial_digest)
        if current.state_digest != baseline.state_digest or current.coordinates != baseline.coordinates:
            raise ValueError
        return _body(change, restore=False), change
    except Exception:
        raise TargetPreservationError(_ERROR) from None
    finally:
        if isinstance(content, bytearray):
            _zeroize_mutable(content)


def verify_target_coordinate_update(content: bytearray, *, change: TargetCoordinateChange) -> TargetState:
    """Verify all coordinates and all preserved fields after an independently authorized update."""
    try:
        _checked_change(change)
        current = capture_target_state(content, expected_name=change.baseline.name,
                                       expected_serial_digest=change.baseline.serial_digest)
        if current.coordinates != change.desired or current.preserved_digest != change.baseline.preserved_digest:
            raise ValueError
        return current
    except Exception:
        raise TargetPreservationError(_ERROR) from None
    finally:
        if isinstance(content, bytearray):
            _zeroize_mutable(content)


def compile_target_coordinate_restore(content: bytearray, *, change: TargetCoordinateChange,
                                      updated: TargetState) -> bytearray:
    """Restore only changed coordinates; any drift since verified readback denies restore."""
    try:
        _checked_state(updated)
        current = verify_target_coordinate_update(content, change=change)
        if current.state_digest != updated.state_digest or current.coordinates != updated.coordinates:
            raise ValueError
        return _body(change, restore=True)
    except Exception:
        raise TargetPreservationError(_ERROR) from None
    finally:
        if isinstance(content, bytearray):
            _zeroize_mutable(content)


def verify_target_coordinate_restore(content: bytearray, *, change: TargetCoordinateChange) -> TargetState:
    """Verify exact restoration of the complete original native-state fingerprint."""
    try:
        _checked_change(change)
        current = capture_target_state(content, expected_name=change.baseline.name,
                                       expected_serial_digest=change.baseline.serial_digest)
        if current.state_digest != change.baseline.state_digest or current.coordinates != change.baseline.coordinates:
            raise ValueError
        return current
    except Exception:
        raise TargetPreservationError(_ERROR) from None
    finally:
        if isinstance(content, bytearray):
            _zeroize_mutable(content)
