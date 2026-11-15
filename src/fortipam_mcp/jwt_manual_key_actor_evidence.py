"""Consuming native JWT editor entitlement evidence, without write authority.

This private candidate supports only the qualified VDOM-disabled global-actor
case. A trusted reader must bind the four original GETs to one fresh TLS/token
source. Native UI permission is not proof of backend POST permission, least
privilege, M4 authorization, object ownership or recovery eligibility.
"""
from __future__ import annotations

import hashlib

from . import secret_bulk_import_metadata as parser
from .jwt_manual_key_contract import _Private, _digest, _fail, _require_digest
from .local_user_reset_fixture_preflight import _actor_context
from .secret_metadata_http_transport import _zeroize_mutable, _skip_json_space, _json_value_end
from .target_lifecycle_dependencies import _envelope, _one, _spans

ACTOR_CONTRACT = "fortipam-700-build29-manual-jwt-editor-entitlement-private-v1"
_SOURCE = "0c2bf35bb5cde1a5154012d6bf2f529d8d59e782a35aebe0bd29976ca9da434f"
_ROLE = frozenset({"name", "sysgrp", "sysgrp-permission"})
_LEVELS = frozenset({"none", "read", "read-write"})


class JwtManualKeyActorEvidence(_Private):
    """Opaque projection digests; constructing this is not runtime authority."""

    __slots__ = ("actor_digest", "role_digest", "serial_digest", "digest")
    actor_digest: str
    role_digest: str
    serial_digest: str
    digest: str

    def __init__(self, actor_digest: str, role_digest: str, serial_digest: str) -> None:
        for value in (actor_digest, role_digest, serial_digest):
            _require_digest(value)
        for key, value in {"actor_digest": actor_digest, "role_digest": role_digest,
                           "serial_digest": serial_digest}.items():
            object.__setattr__(self, key, value)
        object.__setattr__(self, "digest", _digest({"contract": ACTOR_CONTRACT, "source": _SOURCE,
            "actor": actor_digest, "role": role_digest, "serial": serial_digest}))


def _name(value: str) -> None:
    if type(value) is not str or not 0 < len(value) <= 255 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        _fail()


def _role(content: bytearray, span: tuple[int, int], expected_name: str) -> dict[str, object]:
    fields = parser._object_spans(content, *span, _ROLE)
    name = parser._scalar(content, fields["name"])
    group = parser._scalar(content, fields["sysgrp"])
    granular = parser._object_spans(content, *fields["sysgrp-permission"], frozenset({"cfg"}))
    cfg = parser._scalar(content, granular["cfg"])
    if (type(name) is not str or name != expected_name or type(group) is not str
            or group not in _LEVELS | {"custom"} or type(cfg) is not str or cfg not in _LEVELS):
        _fail()
    return {"name": name, "sysgrp": group, "cfg": cfg}


def _row(content: bytearray, table: str, serial_digest: str, expected_name: str,
         fields: frozenset[str]) -> dict[str, tuple[int, int]]:
    span = _checked_envelope(content, table, serial_digest)
    top = _spans(content)
    if "mkey" in top and parser._scalar(content, top["mkey"]) != expected_name:
        _fail()
    # An exact-key GET may return a row object or one-item array.
    row = parser._object_spans(content, *_one(content, span), fields | {"q_origin_key"})
    if not fields <= row.keys():
        _fail()
    for key in {"name", "q_origin_key"} & row.keys():
        value = parser._scalar(content, row[key])
        if type(value) is not str or value != expected_name:
            _fail()
    return row


def _checked_envelope(content: bytearray, table: str, serial_digest: str, *, monitor: bool = False) -> tuple[int, int]:
    span = _envelope(content, path="web-ui" if monitor else "system", name=table,
                     serial_digest=serial_digest, monitor=monitor)
    top = _spans(content)
    left = _skip_json_space(content, 0)
    top = parser._object_spans(content, left, _json_value_end(content, left),
                               frozenset(top) | {"matched_count", "schema_errors", "next_idx"})
    serial = parser._text(parser._scalar(content, top["serial"]), maximum=128)
    if hashlib.sha256(serial.encode()).hexdigest() != serial_digest or {"schema_errors", "next_idx"} & top.keys():
        _fail()
    for key in ("size", "matched_count"):
        if key in top:
            value = parser._scalar(content, top[key])
            if type(value) is not int or value != 1:
                _fail()
    if "limit_reached" in top and parser._scalar(content, top["limit_reached"]) is not False:
        _fail()
    return span


def consume_jwt_manual_key_actor_inputs(
    actor: bytearray, user: bytearray, role: bytearray, maintenance: bytearray, *,
    expected_actor: str, expected_profile: str, serial_digest: str,
) -> JwtManualKeyActorEvidence:
    """Require native SYSTEM_CFG write access and erase all four input buffers.

    Read-only routes, maintenance, non-global actors and enabled/unknown VDOM
    modes refuse. The native super_admin flag is deliberately not a requirement
    of this route; it remains a separate API-issuance qualification.
    """
    buffers = (actor, user, role, maintenance)
    try:
        _name(expected_actor); _name(expected_profile); _require_digest(serial_digest)
        if any(type(value) is not bytearray for value in buffers):
            _fail()
        span = _checked_envelope(actor, "state", serial_digest, monitor=True)
        context_digest = _actor_context(actor, expected_name=expected_actor)
        state = parser._object_spans(actor, *span, frozenset({"admin", "vdom_mode", "maintenance_mode"}))
        admin = parser._object_spans(actor, *state["admin"], frozenset({"global_admin", "profile"}))
        if parser._scalar(actor, admin["global_admin"]) is not True:
            _fail()
        if parser._scalar(actor, state["vdom_mode"]) != "":
            _fail()
        state_maintenance = parser._object_spans(actor, *state["maintenance_mode"], frozenset({"mode"}))
        if parser._scalar(actor, state_maintenance["mode"]) != "disable":
            _fail()
        active_role = _role(actor, admin["profile"], expected_profile)
        u = _row(user, "api-user", serial_digest, expected_actor, frozenset({"name", "accprofile"}))
        if parser._scalar(user, u["accprofile"]) != expected_profile:
            _fail()
        _row(role, "accprofile", serial_digest, expected_profile, _ROLE)
        persisted_span = _checked_envelope(role, "accprofile", serial_digest)
        persisted_role = _role(role, _one(role, persisted_span), expected_profile)
        if active_role != persisted_role:
            _fail()
        effective = active_role["cfg"] if active_role["sysgrp"] == "custom" else active_role["sysgrp"]
        if effective != "read-write":
            _fail()
        mspan = _checked_envelope(maintenance, "maintenance", serial_digest)
        m = parser._object_spans(maintenance, *_one(maintenance, mspan), frozenset({"mode"}))
        if parser._scalar(maintenance, m["mode"]) != "disable":
            _fail()
        actor_digest = _digest({"context": context_digest, "api_user": expected_actor,
            "profile": expected_profile, "global_admin": True, "vdom_mode": "", "maintenance": "disable"})
        return JwtManualKeyActorEvidence(actor_digest, _digest(persisted_role), serial_digest)
    except Exception:
        _fail()
    finally:
        for raw in buffers:
            if type(raw) is bytearray:
                _zeroize_mutable(raw)


__all__ = ["ACTOR_CONTRACT", "JwtManualKeyActorEvidence", "consume_jwt_manual_key_actor_inputs"]
