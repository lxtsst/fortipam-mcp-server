"""Consuming fixed JWT preflight evidence, without dispatch or ownership.

This qualification profile requires an empty actor-visible JWT-key collection,
unambiguous non-JWT API-user selectors and one exact projected name returning
the qualified native 404. It does not establish visibility beyond that actor.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as parser
from .jwt_manual_key_contract import DEFAULT_FIELDS, _NAME, _default_digest, _digest, _require_digest
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .target_lifecycle_dependencies import _envelope, _one, _spans
from .local_user_reset_projection import _object_spans as _all_spans

_CONTRACT = "fortipam-build29-manual-jwt-preflight-private-v1"
_ERROR = "The private manual JWT-key preflight is unavailable."


class JwtManualKeyPreflightError(RuntimeError):
    """Non-disclosing refusal; no inferred global absence or retry authority."""


@dataclass(frozen=True, slots=True, repr=False)
class JwtManualKeyPreflight(_OpaqueC3Object):
    name_digest: str
    serial_digest: str
    schema_digest: str
    defaults_digest: str
    api_users_digest: str
    state_digest: str


def _top(raw: bytearray) -> dict[str, tuple[int, int]]:
    _spans(raw)
    left = _skip_json_space(raw, 0)
    return _all_spans(raw, left, _json_value_end(raw, left))


def _collection(raw: bytearray, table: str, serial_digest: str) -> tuple[list[dict[str, str]], str]:
    path = "secret" if table == "jwt-key" else "system"
    span = _envelope(raw, path=path, name=table, serial_digest=serial_digest)
    top = _top(raw)
    if (parser._scalar(raw, top["status"]) != "success"
            or {"schema_errors", "filtered_count", "start", "limit", "total"} & top.keys()):
        raise ValueError
    rows = parser._array(raw, span, 128)
    if len(rows) >= 128:
        raise ValueError
    for key in ("size", "matched_count"):
        value = parser._scalar(raw, top[key])
        if type(value) is not int or value != len(rows):
            raise ValueError
    limit_present = "limit_reached" in top
    if limit_present and parser._scalar(raw, top["limit_reached"]) is not False:
        raise ValueError
    # Native complete views also carry next_idx (empty: 0, six users: 5).
    # Treat it as opaque metadata; completeness uses the qualified exact counts.
    # Native limit_reached is absent: preserve presence, never coerce it to false.
    index = parser._scalar(raw, top["next_idx"])
    if type(index) is not int or not 0 <= index < 2 ** 31:
        raise ValueError
    fields = frozenset({"name", "type"} | ({"jwt-key"} if table == "api-user" else set()))
    projected = []
    for row in rows:
        selected = parser._object_spans(raw, *row, fields | {"q_origin_key"})
        value = {key: parser._text(parser._scalar(raw, selected[key]), maximum=255, empty=key == "jwt-key")
                 for key in fields}
        if "q_origin_key" in selected and parser._scalar(raw, selected["q_origin_key"]) != value["name"]:
            raise ValueError
        projected.append(value)
    if len({row["name"] for row in projected}) != len(projected):
        raise ValueError
    metadata_digest = _digest({"size": len(rows), "matched_count": len(rows), "next_idx": index,
        "limit_reached_present": limit_present})
    return sorted(projected, key=lambda row: row["name"]), metadata_digest


def _absence(raw: bytearray, name: str, serial_digest: str) -> None:
    fields = _top(raw)
    expected = dict(version="v7.0.0", build=29, http_method="GET", http_status=404, status="error",
                    path="secret", name="jwt-key", vdom="root", mkey=name)
    for key, value in expected.items():
        actual = parser._scalar(raw, fields[key])
        if type(actual) is not type(value) or actual != value:
            raise ValueError
    serial = parser._text(parser._scalar(raw, fields["serial"]), maximum=128)
    if hashlib.sha256(serial.encode()).hexdigest() != serial_digest:
        raise ValueError
    if ("schema_errors" in fields or "error" in fields and parser._scalar(raw, fields["error"]) is not None
            or "action" in fields and parser._scalar(raw, fields["action"]) != ""):
        raise ValueError
    if "results" in fields:
        span = fields["results"]
        if raw[span[0]] == 91:
            if parser._array(raw, span, 1):
                raise ValueError
        elif parser._scalar(raw, span) is not None:
            raise ValueError
    for key in ("size", "matched_count"):
        if key in fields:
            value = parser._scalar(raw, fields[key])
            if type(value) is not int or value != 0:
                raise ValueError


def consume_jwt_manual_key_preflight(
    schema: bytearray, defaults: bytearray, keys: bytearray, users: bytearray, absence: bytearray, *,
    name: str, serial_digest: str, expected_schema_digest: str, expected_defaults_digest: str,
) -> JwtManualKeyPreflight:
    """Consume five original responses; return only pinned projection digests.

    Transport freshness/origin/token, HTTP status and native actor qualification
    belong to the trusted fixed reader. This pure consumer grants no authority.
    """
    buffers = (schema, defaults, keys, users, absence)
    try:
        if type(name) is not str or len(name) > 35 or _NAME.fullmatch(name) is None:
            raise ValueError
        for value in (serial_digest, expected_schema_digest, expected_defaults_digest):
            _require_digest(value)
        if any("schema_errors" in _top(raw) for raw in (schema, defaults)):
            raise ValueError
        span = _envelope(schema, path="secret", name="jwt-key", serial_digest=serial_digest, action="schema")
        outer = parser._object_spans(schema, *_one(schema, span), frozenset({"children"}))
        children = _all_spans(schema, *outer["children"])
        if set(children) != DEFAULT_FIELDS:
            raise ValueError
        schema_digest = _digest({key: json.loads(schema[slice(*value)]) for key, value in children.items()})
        span = _envelope(defaults, path="secret", name="jwt-key", serial_digest=serial_digest, action="default")
        fields = _all_spans(defaults, *_one(defaults, span))
        if set(fields) != DEFAULT_FIELDS:
            raise ValueError
        defaults_digest = _default_digest({key: json.loads(defaults[slice(*value)]) for key, value in fields.items()})
        if schema_digest != expected_schema_digest or defaults_digest != expected_defaults_digest:
            raise ValueError
        key_rows, keys_meta = _collection(keys, "jwt-key", serial_digest)
        user_rows, users_meta = _collection(users, "api-user", serial_digest)
        if key_rows or not user_rows or any(row["type"] == "jwt" or row["jwt-key"] != "" for row in user_rows):
            raise ValueError
        _absence(absence, name, serial_digest)
        users_digest = _digest(user_rows)
        state_digest = _digest({"contract": _CONTRACT, "name": name, "serial": serial_digest,
            "schema": schema_digest, "defaults": defaults_digest, "keys": _digest(key_rows),
            "key_collection_meta": keys_meta, "api_users": users_digest, "api_user_collection_meta": users_meta,
            "qualified_exact_projected_absence": True})
        return JwtManualKeyPreflight(hashlib.sha256(name.encode()).hexdigest(), serial_digest,
            schema_digest, defaults_digest, users_digest, state_digest)
    except Exception:
        raise JwtManualKeyPreflightError(_ERROR) from None
    finally:
        for raw in buffers:
            if type(raw) is bytearray:
                _zeroize_mutable(raw)


__all__ = ["JwtManualKeyPreflightError", "JwtManualKeyPreflight", "consume_jwt_manual_key_preflight"]
