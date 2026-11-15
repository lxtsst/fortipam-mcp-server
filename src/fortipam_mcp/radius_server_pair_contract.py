"""Private, I/O-free paired RADIUS prerequisites; no dispatch authority.

The build29 native model serializes two populated servers in seven fields.
This separate lab profile leaves the accepted primary-only contract unchanged.
Opaque-token changes prove storage only, never correct material or failover.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import re
from typing import Literal

from v4_planning.material_provider import C3MaterialBinding

from .ldap_server_projection import _digest
from .radius_server_contract import (
    _NAME, RadiusServerCreateBinding, project_radius_ack, project_radius_absence,
)
from .radius_server_projection import RADIUS_SCHEMA_TYPES, RadiusServerSchema, RadiusServerState, _check_schema
from .mutable_json_buffer import _MutableJSONBuffer
from .secret_create_191_http_transport import _append_material
from .secret_metadata_http_transport import _zeroize_mutable

CONTRACT = "fortipam-700-build29-radius-pair-create-private-v1"
ACTION_ID = "radius-server-pair-create"
ACTION_VERSION = "1.0.0"
_ERROR = "The private paired RADIUS prerequisite is unavailable."


class RadiusServerPairError(RuntimeError):
    """Categorical refusal without selectors, material or product output."""


class RadiusServerPairBinding(C3MaterialBinding):
    """Immutable two-address lab intent, accepted only inside a private boundary."""

    __slots__ = ("name", "server", "secondary_server", "private_nonce")
    name: str
    server: str
    secondary_server: str
    private_nonce: str

    def __init__(self, name: str, server: str, secondary_server: str, private_nonce: str) -> None:
        try:
            if (type(name) is not str or _NAME.fullmatch(name) is None
                    or type(private_nonce) is not str or re.fullmatch(r"[0-9a-f]{64}", private_nonce) is None
                    or server == secondary_server):
                raise ValueError
            for endpoint in (server, secondary_server):
                if type(endpoint) is not str:
                    raise ValueError
                address = ipaddress.IPv4Address(endpoint)
                if (str(address) != endpoint or not address.is_private or address.is_loopback
                        or address.is_unspecified or address.is_link_local or address.is_multicast):
                    raise ValueError
            for key, value in (("name", name), ("server", server),
                    ("secondary_server", secondary_server), ("private_nonce", private_nonce)):
                object.__setattr__(self, key, value)
        except Exception:
            raise RadiusServerPairError(_ERROR) from None

    def __setattr__(self, name: str, value: object) -> None:
        raise RadiusServerPairError(_ERROR)

    def __delattr__(self, name: str) -> None:
        raise RadiusServerPairError(_ERROR)

    def desired_nonmaterial(self) -> dict[str, str]:
        return {"name": self.name, "auth-type": "auto", "server": self.server,
            "secondary-server": self.secondary_server}

    @property
    def parameters_digest(self) -> str:
        return _digest({"contract": CONTRACT, "intent": self.desired_nonmaterial(),
            "private_nonce": self.private_nonce})


def _material(value: memoryview) -> bool:
    return (type(value) is memoryview and value.readonly and value.ndim == 1
        and value.format == "B" and value.c_contiguous and value.nbytes == 32
        and type(value.obj) is bytearray
        and all(65 <= c <= 90 or 97 <= c <= 122 or 48 <= c <= 57 or c in (45, 95) for c in value))


def pair_create_body(binding: RadiusServerPairBinding, primary: memoryview, secondary: memoryview) -> bytearray:
    """Serialize distinct mutable-backed lab leases without decoding either value.

    The caller owns the leases and must clear them and the returned buffer. This
    consuming wire helper does not acquire, reserve, validate or dispatch a lease.
    """
    with _MutableJSONBuffer() as body:
        try:
            if (type(binding) is not RadiusServerPairBinding or not _material(primary)
                    or not _material(secondary) or primary.obj is secondary.obj
                    or hmac.compare_digest(primary, secondary)):
                raise ValueError
            body.extend(json.dumps(binding.desired_nonmaterial() | {"$originalName": ""},
                sort_keys=True, separators=(",", ":"), allow_nan=False).encode()[:-1])
            body.extend(b',"secret":')
            _append_material(body, primary)
            body.extend(b',"secondary-secret":')
            _append_material(body, secondary)
            body.extend(b"}")
            return body.finish()
        except Exception:
            raise RadiusServerPairError(_ERROR) from None


def pair_owned_connect_body(binding: RadiusServerPairBinding,
                            ordinal: Literal["primary", "secondary"]) -> bytearray:
    """One saved-selector test wire; no material and no automatic failover claim."""
    if type(binding) is not RadiusServerPairBinding or type(ordinal) is not str or ordinal not in {"primary", "secondary"}:
        raise RadiusServerPairError(_ERROR)
    return bytearray(json.dumps({"mkey": binding.name,
        "server": binding.server if ordinal == "primary" else binding.secondary_server,
        "auth_type": "auto", "ordinal": ordinal}, sort_keys=True, separators=(",", ":")).encode())


def _selector(binding: RadiusServerPairBinding) -> RadiusServerCreateBinding:
    # These two pure CMDB-envelope projections inspect only the selector, not
    # desired configuration. This temporary object is never execution authority
    # or journal ownership; both remain bound to the distinct pair contract.
    if type(binding) is not RadiusServerPairBinding:
        raise RadiusServerPairError(_ERROR)
    return RadiusServerCreateBinding(binding.name, binding.server, binding.private_nonce)


def project_radius_pair_ack(content: bytearray, binding: RadiusServerPairBinding, *,
        expected_serial: str, http_status: int, method: str) -> str:
    try:
        return project_radius_ack(content, _selector(binding), expected_serial=expected_serial,
            http_status=http_status, method=method)
    except Exception:
        raise RadiusServerPairError(_ERROR) from None
    finally:
        _zeroize_mutable(content)


def project_radius_pair_absence(content: bytearray, binding: RadiusServerPairBinding, *,
        expected_serial: str, http_status: int, collection: bool) -> None:
    try:
        project_radius_absence(content, _selector(binding), expected_serial=expected_serial,
            http_status=http_status, collection=collection)
    except Exception:
        raise RadiusServerPairError(_ERROR) from None
    finally:
        _zeroize_mutable(content)


def qualify_radius_pair_created_state(state: RadiusServerState, defaults: RadiusServerState,
        schema: RadiusServerSchema, binding: RadiusServerPairBinding, *, expected_serial: str) -> None:
    """Require the full schema, two stored tokens, unchanged other defaults and q_ref=0."""
    try:
        _check_schema(schema, expected_serial)
        if (type(binding) is not RadiusServerPairBinding
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
                    or (digest == defaults.opaque_token_digests[key]) == (key in {"secret", "secondary-secret"})):
                raise ValueError
    except Exception:
        raise RadiusServerPairError(_ERROR) from None
