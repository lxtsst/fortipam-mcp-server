"""Private local Owner context evidence for a future JWT source package.

The existing API-user editor witness remains unchanged. A trusted producer must
bind these three fixed GETs and their device Dates to one authenticated local
Owner session. This consuming contract authenticates no session, issues no grant
and qualifies neither JWT POST permission nor an alternative execution path.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from . import secret_bulk_import_metadata as parser
from .jwt_manual_key_actor_evidence import _checked_envelope, _name, _row
from .jwt_manual_key_contract import _Private, _digest, _fail, _require_digest
from .local_user_reset_fixture_preflight import _actor_context
from .secret_metadata_http_transport import MAX_RESPONSE_BYTES, _zeroize_mutable

CONTRACT = "fortipam-700-build29-jwt-local-owner-context-private-v1"
_ADMIN_FIELDS = frozenset({"name", "accprofile", "status", "remote-auth", "wildcard"})


class JwtManualKeyOwnerActorEvidence(_Private):
    """Immutable opaque source evidence, never an execution authorization."""

    __slots__ = ("actor_digest", "mapping_digest", "serial_digest", "observation_digest", "digest")
    actor_digest: str
    mapping_digest: str
    serial_digest: str
    observation_digest: str
    digest: str

    def __init__(self, actor_digest: str, mapping_digest: str, serial_digest: str, observation_digest: str) -> None:
        for value in (actor_digest, mapping_digest, serial_digest, observation_digest):
            _require_digest(value)
        for key, value in {"actor_digest": actor_digest, "mapping_digest": mapping_digest,
                           "serial_digest": serial_digest, "observation_digest": observation_digest}.items():
            object.__setattr__(self, key, value)
        object.__setattr__(self, "digest", _digest({"contract": CONTRACT,
            "actor": actor_digest, "mapping": mapping_digest, "serial": serial_digest,
            "observation": observation_digest}))

    def summary(self) -> dict[str, object]:
        return {"contract": CONTRACT, "bracketed_local_super_admin_context_matched": True,
                "source_provenance_authenticated": False,
                "jwt_backend_write_permission_qualified": False, "execution_authorized": False}


def _state(raw: bytearray, owner: str, serial: str) -> str:
    span = _checked_envelope(raw, "state", serial, monitor=True)
    context = _actor_context(raw, expected_name=owner)
    state = parser._object_spans(raw, *span, frozenset({"admin", "vdom_mode", "maintenance_mode"}))
    admin = parser._object_spans(raw, *state["admin"],
        frozenset({"global_admin", "super_admin", "profile"}))
    if any(parser._scalar(raw, admin[key]) is not True for key in ("global_admin", "super_admin")):
        _fail()
    if parser._scalar(raw, state["vdom_mode"]) != "":
        _fail()
    maintenance = parser._object_spans(raw, *state["maintenance_mode"], frozenset({"mode"}))
    if parser._scalar(raw, maintenance["mode"]) != "disable":
        _fail()
    profile = parser._object_spans(raw, *admin["profile"], frozenset({"name", "sysgrp", "secretgrp"}))
    expected = {"name": "super_admin", "sysgrp": "read-write", "secretgrp": "read-write"}
    for key, value in expected.items():
        observed = parser._scalar(raw, profile[key])
        if type(observed) is not str or observed != value:
            _fail()
    return _digest({"context": context, "global_admin": True, "native_super_admin": True,
                    "profile": expected, "vdom_mode": "", "maintenance": "disable"})


def consume_jwt_manual_key_owner_actor_inputs(
    before: bytearray, local_user: bytearray, after: bytearray, *, expected_owner: str,
    serial_digest: str, first_device_date: datetime, last_device_date: datetime,
) -> JwtManualKeyOwnerActorEvidence:
    """Require fresh, ordered, stable Owner sources and consume every buffer.

    Only selected nonmaterial scalars are decoded. Tokens, cookies, key fields
    and unrelated profile values never enter a witness or summary. Producer
    provenance and same-session Date authenticity remain separate obligations.
    """
    buffers = (before, local_user, after)
    try:
        _name(expected_owner)
        _require_digest(serial_digest)
        if any(type(raw) is not bytearray or not 0 < len(raw) <= MAX_RESPONSE_BYTES for raw in buffers):
            _fail()
        now = datetime.now(timezone.utc)
        dates = (first_device_date, last_device_date)
        if any(not isinstance(value, datetime) or value.utcoffset() is None for value in dates):
            _fail()
        if (last_device_date < first_device_date
                or last_device_date - first_device_date > timedelta(seconds=60)
                or any(abs(now - value) > timedelta(minutes=5) for value in dates)):
            _fail()
        first = _state(before, expected_owner, serial_digest)
        last = _state(after, expected_owner, serial_digest)
        if first != last:
            _fail()
        fields = _row(local_user, "admin", serial_digest, expected_owner, _ADMIN_FIELDS)
        expected = {"name": expected_owner, "accprofile": "super_admin",
            "status": "enable", "remote-auth": "disable", "wildcard": "disable"}
        for key, value in expected.items():
            observed = parser._scalar(local_user, fields[key])
            if type(observed) is not str or observed != value:
                _fail()
        dates_digest = _digest({"first_device_date": first_device_date.astimezone(timezone.utc).isoformat(),
                               "last_device_date": last_device_date.astimezone(timezone.utc).isoformat()})
        return JwtManualKeyOwnerActorEvidence(first, _digest(expected), serial_digest, dates_digest)
    except Exception:
        _fail()
    finally:
        for raw in buffers:
            if type(raw) is bytearray:
                _zeroize_mutable(raw)


__all__ = ["CONTRACT", "JwtManualKeyOwnerActorEvidence", "consume_jwt_manual_key_owner_actor_inputs"]
