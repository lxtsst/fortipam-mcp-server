"""Private owned-selector connect wire and observation prerequisites, with no I/O.

The native editor omits the masked secret when testing a saved entry. This
module neither resolves material nor proves ownership or authorizes a request.
Its observation output stays diagnostic. The separate exact response predicate
grants no ownership, dispatch or connectivity authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Literal

from v4_planning.material_provider import _OpaqueC3Object

from .radius_server_contract import RadiusServerCreateBinding
from .secret_approval_build29_totp_boundary import _member_spans
from .secret_bulk_import_metadata import _validate_json
from .secret_metadata_http_transport import _json_string_end, _json_value_end, _skip_json_space, _zeroize_mutable

CONTRACT = "fortipam-700-build29-radius-owned-connect-observation-private-v1"
CONNECT_PATH = "/api/v2/monitor/user/radius/test-connect"
_MAX_BYTES = 65536
_ERROR = "The private owned RADIUS connect observation is unavailable."
_HTTP_STATUSES = frozenset({200, 400, 401, 403, 404, 500})
_NEGATIVE = frozenset({"unreachable", "invalid_secret", "no_msg_authenticator_attr"})
# Observation tokens only. None is an accepted positive product response.
_OBSERVABLE = _NEGATIVE | {"success", "ok", "reachable", "connected", "valid_secret", "valid", "passed"}
_TOP = frozenset({"version", "build", "serial", "http_method", "http_status", "status", "results",
    "vdom", "path", "name", "mkey", "action", "revision", "old_revision", "revision_changed", "error", "message"})
_RESULT = frozenset({"status", "access_status", "access_message", "message", "error", "server", "delay", "success"})
REJECT_ONLY_RESPONSE_CONTRACT = "fortipam-700-build29-radius-primary-reject-only-response-private-v1"


class RadiusOwnedConnectError(RuntimeError):
    """Categorical refusal without server-controlled text or private context."""


def owned_connect_body(binding: RadiusServerCreateBinding) -> bytearray:
    """Fixed four-field body; caller must prove original ACK and full state first."""
    if type(binding) is not RadiusServerCreateBinding:
        raise RadiusOwnedConnectError(_ERROR)
    return bytearray(json.dumps({"mkey": binding.name, "server": binding.server,
        "auth_type": "auto", "ordinal": "primary"}, sort_keys=True, separators=(",", ":")).encode())


@dataclass(frozen=True, slots=True, repr=False)
class RadiusOwnedConnectObservation(_OpaqueC3Object):
    http_status: int
    status_token: str | None
    result_status_only: bool
    negative_status: bool

    def __post_init__(self) -> None:
        if (type(self.http_status) is not int or self.http_status not in _HTTP_STATUSES
                or self.status_token is not None and (type(self.status_token) is not str
                    or self.status_token not in _OBSERVABLE)
                or type(self.result_status_only) is not bool or type(self.negative_status) is not bool
                or self.negative_status != (self.status_token in _NEGATIVE)):
            raise RadiusOwnedConnectError(_ERROR)

    def as_dict(self) -> dict[str, object]:
        return {"contract": CONTRACT, "http_status": self.http_status, "status_token": self.status_token,
            "result_status_only": self.result_status_only, "negative_status": self.negative_status,
            "observation_only": True, "connectivity_qualified": False}


def _spans(raw: bytearray, span: tuple[int, int], names: frozenset[str]) -> dict[str, tuple[int, int]]:
    return _member_spans(raw, *span, {key: (json.dumps(key).encode(), b"") for key in names})


def _equals(raw: bytearray, fields: dict[str, tuple[int, int]], key: str, value: object) -> bool:
    if key not in fields:
        return False
    with memoryview(raw)[slice(*fields[key])] as token:
        return token == json.dumps(value, separators=(",", ":")).encode()


def _route_matches(raw: bytearray, fields: dict[str, tuple[int, int]]) -> bool:
    # Match the existing build29 monitor reader's joined route semantics,
    # without decoding arbitrary route text or assuming the CMDB field split.
    parts = CONNECT_PATH.removeprefix("/api/v2/monitor/").split("/")
    for path_end in range(1, len(parts)):
        for name_end in range(path_end + 1, len(parts) + 1):
            action = "/".join(parts[name_end:])
            if (_equals(raw, fields, "path", "/".join(parts[:path_end]))
                    and _equals(raw, fields, "name", "/".join(parts[path_end:name_end]))
                    and (not action and "action" not in fields or _equals(raw, fields, "action", action))):
                return True
    return False


def _diagnostic_members(raw: bytearray, span: tuple[int, int], names: frozenset[str]
                        ) -> tuple[dict[str, tuple[int, int]], int]:
    """Count unknown keys without decoding, retaining only fixed canonical names."""
    left, right = span
    if raw[left] != 123 or raw[right - 1] != 125:
        raise ValueError
    pins = {name: json.dumps(name).encode() for name in names}
    cursor = _skip_json_space(raw, left + 1)
    fields: dict[str, tuple[int, int]] = {}
    unknown = count = 0
    while cursor < right - 1:
        count += 1
        if count > 64:
            raise ValueError
        end = _json_string_end(raw, cursor) + 1
        with memoryview(raw)[cursor:end] as token:
            key = next((name for name, value in pins.items() if token == value), None)
        separator = _skip_json_space(raw, end)
        if raw[separator] != 58:
            raise ValueError
        start = _skip_json_space(raw, separator + 1)
        finish = _json_value_end(raw, start)
        if key is None:
            unknown += 1
        elif key in fields:
            raise ValueError
        else:
            fields[key] = start, finish
        cursor = _skip_json_space(raw, finish)
        if cursor == right - 1:
            break
        if raw[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(raw, cursor + 1)
    return fields, unknown


def diagnose_owned_connect_shape(raw: bytearray, binding: RadiusServerCreateBinding, *,
        expected_serial: str, http_status: int) -> dict[str, object]:
    """Non-consuming minimized evidence; caller retains exclusive wiping duty.

    No unknown names, text, locators or raw tokens enter the returned record.
    A diagnostic never grants authority or qualifies a response as successful.
    """
    result: dict[str, object] = {"contract": CONTRACT + ":shape-v1", "json_valid": False,
        "diagnosis_complete": False, "device_build_match": False, "method_post": False,
        "route_matches": False, "envelope_status_matches_http": False,
        "http_status_matches": False, "vdom_matches": False, "selector_matches": False,
        "envelope_unknown_members": None, "result_unknown_members": None,
        "result_kind": "not_assessed", "result_known_fields": [], "status_token": None,
        "connectivity_qualified": False}
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= _MAX_BYTES
                or type(binding) is not RadiusServerCreateBinding or type(expected_serial) is not str
                or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", expected_serial) is None
                or type(http_status) is not int or http_status not in _HTTP_STATUSES):
            raise ValueError
        start = _skip_json_space(raw, 0)
        end = _json_value_end(raw, start)
        if _skip_json_space(raw, end) != len(raw):
            raise ValueError
        _validate_json(raw, start, end, depth=0, budget=[20000])
        result["json_valid"] = True
        fields, unknown = _diagnostic_members(raw, (start, end), _TOP)
        result.update(envelope_unknown_members=unknown,
            device_build_match=all(_equals(raw, fields, key, value) for key, value in
                {"version": "v7.0.0", "build": 29, "serial": expected_serial}.items()),
            method_post=_equals(raw, fields, "http_method", "POST"),
            route_matches=_route_matches(raw, fields),
            http_status_matches="http_status" not in fields or _equals(raw, fields, "http_status", http_status),
            vdom_matches="vdom" not in fields or _equals(raw, fields, "vdom", "root"),
            selector_matches="mkey" not in fields or _equals(raw, fields, "mkey", binding.name),
            envelope_status_matches_http=_equals(raw, fields, "status", "success" if http_status == 200 else "error"))
        if "results" not in fields:
            result["result_kind"] = "absent"
        elif raw[fields["results"][0]] == 123:
            result["result_kind"] = "object"
            members, unknown = _diagnostic_members(raw, fields["results"], _RESULT)
            result.update(result_unknown_members=unknown, result_known_fields=sorted(members),
                status_token=next((value for value in sorted(_OBSERVABLE)
                                  if _equals(raw, members, "status", value)), None))
        else:
            result["result_kind"] = "array" if raw[fields["results"][0]] == 91 else "scalar"
        result["diagnosis_complete"] = True
    except Exception:
        pass
    return result


def _parse_owned_connect_observation(raw: bytearray, binding: RadiusServerCreateBinding, *,
        expected_serial: str, http_status: int) -> RadiusOwnedConnectObservation:
    """Validate without consuming. The public entry point owns buffer wiping."""
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= _MAX_BYTES
                or type(binding) is not RadiusServerCreateBinding or type(expected_serial) is not str
                or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", expected_serial) is None
                or type(http_status) is not int or http_status not in _HTTP_STATUSES):
            raise ValueError
        start = _skip_json_space(raw, 0)
        end = _json_value_end(raw, start)
        if _skip_json_space(raw, end) != len(raw):
            raise ValueError
        _validate_json(raw, start, end, depth=0, budget=[20000])
        fields = _spans(raw, (start, end), _TOP)
        expected_status: Literal["success", "error"] = "success" if http_status == 200 else "error"
        for key, expected in {"version": "v7.0.0", "build": 29, "serial": expected_serial,
                              "status": expected_status}.items():
            if not _equals(raw, fields, key, expected):
                raise ValueError
        if not _route_matches(raw, fields):
            raise ValueError
        for key, expected in {"http_method": "POST", "http_status": http_status, "vdom": "root",
                "mkey": binding.name}.items():
            if key in fields and not _equals(raw, fields, key, expected):
                raise ValueError
        if http_status == 200 and "error" in fields:
            raise ValueError
        token = None
        status_only = False
        if "results" in fields:
            result = _spans(raw, fields["results"], _RESULT)
            if any(key in result and raw[result[key][0]] != 34
                   for key in ("access_status", "access_message")):
                raise ValueError
            if http_status == 200 and set(result) & {"error", "success"}:
                raise ValueError
            token = next((value for value in sorted(_OBSERVABLE) if _equals(raw, result, "status", value)), None)
            status_only = set(result) == {"status"}
        elif http_status == 200:
            raise ValueError
        return RadiusOwnedConnectObservation(http_status, token, status_only, token in _NEGATIVE)
    except Exception:
        raise RadiusOwnedConnectError(_ERROR) from None



def project_owned_connect_observation(raw: bytearray, binding: RadiusServerCreateBinding, *,
        expected_serial: str, http_status: int) -> RadiusOwnedConnectObservation:
    """Consume one bounded source observation. Always leave success unqualified."""
    try:
        return _parse_owned_connect_observation(raw, binding, expected_serial=expected_serial,
                                               http_status=http_status)
    finally:
        if isinstance(raw, bytearray):
            _zeroize_mutable(raw)


def matches_reject_only_connect_response(raw: bytearray, binding: RadiusServerCreateBinding, *,
        expected_serial: str, http_status: int) -> bool:
    """Match only the evidenced three-string reject-only response grammar.

    This predicate does not consume input or prove ownership, material application,
    an original active M4 dispatch, unchanged state or user authentication. Trusted
    composition must establish those applicable controls before using the result.
    Arbitrary access-message text is never decoded. The caller must wipe input.
    """
    try:
        observed = _parse_owned_connect_observation(raw, binding, expected_serial=expected_serial,
                                                  http_status=http_status)
        if http_status != 200 or observed.status_token != "ok":
            return False
        start = _skip_json_space(raw, 0)
        fields = _spans(raw, (start, _json_value_end(raw, start)), _TOP)
        result = _spans(raw, fields["results"], _RESULT)
        return (set(result) == {"status", "access_status", "access_message"}
                and _equals(raw, fields, "http_method", "POST")
                and _equals(raw, result, "access_status", "Access-Reject"))
    except Exception:
        return False
