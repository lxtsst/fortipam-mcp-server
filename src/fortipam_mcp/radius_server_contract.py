"""Private build-29 primary-only create and original-ACK recovery prerequisites.

These consuming projections perform no I/O, grant no execution authority, and do
not qualify connectivity. The caller must retain its own durable dispatch claim
and successful ACK before adopting or recovering the created object.
"""
from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
import hashlib
import ipaddress
import re

from v4_planning.material_provider import C3MaterialBinding

from .ldap_server_projection import _array, _digest, _members, _validate
from .radius_server_projection import (
    RADIUS_SCHEMA_TYPES, RadiusServerSchema, RadiusServerState, _check_schema,
    _decode, _destroy, _expect, _METADATA_TYPES,
)
from .secret_metadata_http_transport import _json_value_end, _skip_json_space

ACTION_ID = "radius-server-create"
ACTION_VERSION = "1.0.0"
CONTRACT = "fortipam-700-build29-radius-primary-create-private-v1"
_UNAVAILABLE = "The private RADIUS server candidate is unavailable."
_NAME = re.compile(r"mcp-v4-radius-[a-z0-9][a-z0-9-]{0,20}\Z")
_ENVELOPE = frozenset({
    "build", "http_method", "http_status", "name", "path", "results", "revision",
    "old_revision", "serial", "status", "vdom", "version", "mkey", "size",
    "matched_count", "next_idx", "limit_reached", "revision_changed",
})
_METADATA = frozenset({
    "q_ref", "q_static", "q_global_entry", "q_origin_key", "q_mkey_type", "q_name",
    "q_no_edit", "q_no_rename", "q_path", "q_type",
})
Span = tuple[int, int]


class RadiusServerCandidateError(RuntimeError):
    """Value-free refusal for this unregistered private candidate."""


class RadiusServerCreateOutcome(StrEnum):
    VERIFIED_CREATED = "verified_created"
    RECONCILIATION_REQUIRED = "reconciliation_required"


class RadiusServerCreateObservation(StrEnum):
    ABSENT_OBSERVED = "absent_observed"
    PRESENT_OBSERVED = "present_observed"
    NOT_ASSESSED = "not_assessed"


class RadiusServerCreateBinding(C3MaterialBinding):
    """Owner-bound disposable selectors; never accepted from an MCP argument."""

    __slots__ = ("name", "server", "private_nonce")
    name: str
    server: str
    private_nonce: str

    def __init__(self, name: str, server: str, private_nonce: str) -> None:
        try:
            if (type(name) is not str or _NAME.fullmatch(name) is None
                or type(server) is not str or type(private_nonce) is not str
                or re.fullmatch(r"[0-9a-f]{64}", private_nonce) is None):
                raise ValueError
            address = ipaddress.IPv4Address(server)
            if (str(address) != server or not address.is_private or address.is_loopback
                or address.is_unspecified or address.is_link_local or address.is_multicast):
                raise ValueError
            for key, value in (("name", name), ("server", server), ("private_nonce", private_nonce)):
                object.__setattr__(self, key, value)
        except Exception:
            raise RadiusServerCandidateError(_UNAVAILABLE) from None

    def __setattr__(self, name: str, value: object) -> None:
        raise RadiusServerCandidateError(_UNAVAILABLE)

    def __delattr__(self, name: str) -> None:
        raise RadiusServerCandidateError(_UNAVAILABLE)

    def desired_nonmaterial(self) -> dict[str, str]:
        return {"name": self.name, "auth-type": "auto", "server": self.server,
                "secondary-server": ""}

    @property
    def parameters_digest(self) -> str:
        return _digest({"contract": CONTRACT, "intent": self.desired_nonmaterial(),
                        "private_nonce": self.private_nonce})


def qualify_radius_created_state(state: RadiusServerState, defaults: RadiusServerState,
                                 schema: RadiusServerSchema, binding: RadiusServerCreateBinding,
                                 *, expected_serial: str) -> None:
    """Require all 44 fields, unchanged omitted defaults and explicit zero references.

    A changed opaque primary token is evidence of storage only. It does not prove
    that the submitted material was applied or that the server is reachable.
    """
    try:
        _check_schema(schema, expected_serial)
        if (type(binding) is not RadiusServerCreateBinding
            or any(type(value) is not RadiusServerState for value in (state, defaults))
            or any(value.schema_digest != schema.state_digest for value in (state, defaults))
            or set(state.values) != set(defaults.values)
            or set(state.values) | set(state.opaque_token_digests) != set(RADIUS_SCHEMA_TYPES)
            or set(state.opaque_token_digests) != set(defaults.opaque_token_digests)
            or type(state.metadata.get("q_ref")) is not int or state.metadata["q_ref"] != 0
            or "q_origin_key" in state.metadata and state.metadata["q_origin_key"] != binding.name):
            raise ValueError
        desired = binding.desired_nonmaterial()
        for key, current in state.values.items():
            expected = desired.get(key, defaults.values[key])
            if type(current) is not type(expected) or current != expected:
                raise ValueError
        for key, digest in state.opaque_token_digests.items():
            if (re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or (digest == defaults.opaque_token_digests[key]) == (key == "secret")):
                raise ValueError
    except Exception:
        raise RadiusServerCandidateError(_UNAVAILABLE) from None


def _top(content: bytearray, binding: RadiusServerCreateBinding, *, expected_serial: str,
         method: str, status: str, http_status: int) -> Mapping[str, Span]:
    if (type(content) is not bytearray or not 0 < len(content) <= 2 * 1048576
        or type(binding) is not RadiusServerCreateBinding or type(expected_serial) is not str
        or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", expected_serial) is None):
        raise ValueError
    start = _skip_json_space(content, 0)
    end = _json_value_end(content, start)
    if _skip_json_space(content, end) != len(content):
        raise ValueError
    fields = _members(content, (start, end))
    if not set(fields) <= _ENVELOPE:
        raise ValueError
    for key, location in fields.items():
        if key != "results":
            if content[location[0]] in (91, 123):
                raise ValueError
            _validate(content, location)
    for key, expected in {"version": "v7.0.0", "build": 29, "serial": expected_serial,
                          "status": status, "http_method": method,
                          "path": "user", "name": "radius"}.items():
        _expect(content, fields, key, expected)
    for key, expected in {"http_status": http_status, "vdom": "root", "mkey": binding.name}.items():
        if key in fields:
            _expect(content, fields, key, expected)
    return fields


def project_radius_ack(content: bytearray, binding: RadiusServerCreateBinding, *,
                       expected_serial: str, http_status: int, method: str) -> str:
    """Consume one exact successful POST/DELETE ACK; return its private digest."""
    try:
        if method not in {"POST", "DELETE"} or type(http_status) is not int or http_status != 200:
            raise ValueError
        top = _top(content, binding, expected_serial=expected_serial, method=method,
                   status="success", http_status=200)
        # A mutation ACK must identify this selector, not merely report success.
        _expect(content, top, "mkey", binding.name)
        if "results" in top:
            span = top["results"]
            if content[span[0]] == 123:
                if _members(content, span):
                    raise ValueError
            elif content[span[0]] != 91 or _array(content, span):
                raise ValueError
        return hashlib.sha256(content).hexdigest()
    except Exception:
        raise RadiusServerCandidateError(_UNAVAILABLE) from None
    finally:
        _destroy(content)


def project_radius_absence(content: bytearray, binding: RadiusServerCreateBinding, *,
                           expected_serial: str, http_status: int, collection: bool) -> None:
    """Both exact-detail and name-only collection reads are required by the caller."""
    try:
        expected = 200 if collection else 404
        if type(collection) is not bool or type(http_status) is not int or http_status != expected:
            raise ValueError
        top = _top(content, binding, expected_serial=expected_serial, method="GET",
                   status="success" if collection else "error", http_status=expected)
        if not collection:
            if "results" in top:
                raise ValueError
        else:
            rows = _array(content, top["results"])
            for key, expected_value in {"limit_reached": False, "next_idx": 0,
                                        "matched_count": len(rows), "size": len(rows)}.items():
                if key in top:
                    _expect(content, top, key, expected_value)
            for span in rows:
                row = _members(content, span)
                if "name" not in row or not set(row) <= {"name"} | _METADATA:
                    raise ValueError
                for key, location in row.items():
                    if content[location[0]] in (91, 123):
                        raise ValueError
                    _validate(content, location)
                    expected_type = str if key == "name" else _METADATA_TYPES[key]
                    if type(_decode(content, row, key)) is not expected_type:
                        raise ValueError
                name = _decode(content, row, "name")
                if type(name) is not str or not name or name == binding.name:
                    raise ValueError
    except Exception:
        raise RadiusServerCandidateError(_UNAVAILABLE) from None
    finally:
        _destroy(content)
