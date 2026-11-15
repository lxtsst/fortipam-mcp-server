"""Pure disabled Standard Remote User draft for one privately bound RADIUS pair.

No lookup, material acquisition, authorization, transport or Tool registration.
A prepared wire does not prove an owned server, user creation or authentication.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from typing import Any

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from .local_user_reset_fixture_create import _FIELDS, _validate_scope
from .local_user_reset_metadata_reader import _validate_value
from .local_user_reset_projection import (
    _material, _object_spans, _sanitize_object, _sanitize_value, _schema_fields, _string_or_empty,
)
from .radius_server_pair_contract import RadiusServerPairBinding
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable

CONTRACT = "fortipam-700-build29-radius-remote-user-create-private-v1"
_ERROR = "The private RADIUS Remote User draft is unavailable."
_USERNAME = re.compile(r"mcp-v4-radius-user-[a-f0-9]{8}\Z")
_HEX = re.compile(r"[a-f0-9]{64}\Z")


class RadiusRemoteUserError(RuntimeError):
    """Categorical refusal without identities, defaults or protected tokens."""


@dataclass(frozen=True, slots=True, repr=False)
class RadiusRemoteUserBinding(_OpaqueC3Object):
    username: str
    radius: RadiusServerPairBinding
    private_nonce: str

    def __post_init__(self) -> None:
        if (type(self.username) is not str or _USERNAME.fullmatch(self.username) is None
                or type(self.radius) is not RadiusServerPairBinding
                or type(self.private_nonce) is not str or _HEX.fullmatch(self.private_nonce) is None):
            raise RadiusRemoteUserError(_ERROR)

    @property
    def parameters_digest(self) -> str:
        return canonical_digest({"contract": CONTRACT, "username": self.username,
            "radius_parameters_digest": self.radius.parameters_digest, "private_nonce": self.private_nonce,
            "status": "disable", "profile": "pam_standard_user", "wildcard": "disable", "remote_group": False})


@dataclass(frozen=True, slots=True, repr=False)
class RadiusRemoteUserCreateDraft(_OpaqueC3Object):
    binding: RadiusRemoteUserBinding
    source_defaults_digest: str
    request_digest: str
    _wire: bytes
    _response_vdom: str
    _schema_digest: str
    _response_serial: str


def prepare_radius_remote_user_create(content: bytearray, schema: Mapping[str, Any],
        binding: RadiusRemoteUserBinding, *, expected_serial: str) -> RadiusRemoteUserCreateDraft:
    """Project only new-user defaults; never decode password/history/shared-key.

    The native New User UI explicitly clears the local password, including for
    Remote User. The empty wire field is fixed syntax, not a credential source.
    """
    sanitized = bytearray()
    try:
        if (type(content) is not bytearray or not 0 < len(content) <= 1048576
                or type(binding) is not RadiusRemoteUserBinding or type(expected_serial) is not str
                or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", expected_serial) is None):
            raise ValueError
        fields = _schema_fields(schema)
        if schema.get("serial") != expected_serial:
            raise ValueError
        start = _skip_json_space(content, 0)
        end = _json_value_end(content, start)
        if _skip_json_space(content, end) != len(content):
            raise ValueError
        _validate_value(content, start, end, depth=0)
        envelope = _object_spans(content, start, end)
        expected = {"action": "default", "build": 29, "http_method": "GET", "http_status": 200,
            "name": "admin", "path": "system", "status": "success", "version": "v7.0.0", "serial": expected_serial}
        for key, value in expected.items():
            observed = json.loads(content[slice(*envelope[key])])
            if type(observed) is not type(value) or observed != value:
                raise ValueError
        scope = json.loads(content[slice(*envelope["vdom"])])
        _validate_scope(scope)
        spans = _object_spans(content, *envelope["results"])
        if not (_FIELDS - {"vdom"}) <= spans.keys() or not {"password", "webauthn"} <= spans.keys():
            raise ValueError
        for key in ("password", *(f"history{i}" for i in range(20))):
            if key in spans:
                with memoryview(content)[slice(*spans[key])] as token:
                    _string_or_empty(token)
        defaults: dict[str, Any] = {}
        for field in sorted(_FIELDS - {"accprofile", "guest-lang", "vdom"}):
            if _material(field, fields.get(field), root=True):
                raise ValueError
            _sanitize_value(content, *spans[field], fields.get(field), sanitized, depth=1)
            defaults[field] = json.loads(sanitized)
            _zeroize_mutable(sanitized)
        if (defaults["name"] != "" or type(defaults["id"]) is not int or defaults["id"] != 0
                or defaults["status"] not in {"enable", "disable"}):
            raise ValueError
        if (any(defaults[f] != "disable" for f in ("remote-auth", "wildcard", "guest-auth", "cert-auth", "two-factor"))
                or defaults["auto-created-user"] != "no"
                or any(defaults[f] != "" for f in ("remote-group", "remote-server", "sponsor-group", "schedule", "fortitoken", "email-to"))):
            raise ValueError
        if "force-saml-login" not in spans or content[slice(*spans["force-saml-login"])] != b'"disable"':
            raise ValueError
        webauthn = _object_spans(content, *spans["webauthn"])
        if content[slice(*webauthn["status"])] != b'"disable"':
            raise ValueError
        schema_digest = hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        source_payload = json.dumps({"contract": CONTRACT, "binding": binding.parameters_digest, "schema_digest": schema_digest,
            "defaults": defaults, "serial": expected_serial, "response_vdom": scope},
            sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        source = hashlib.sha256(b"radius-remote-user-source-v1\x00" + binding.private_nonce.encode() + b"\x00" + source_payload).hexdigest()
        defaults.update(name=binding.username, accprofile="pam_standard_user", status="disable",
            wildcard="disable", password="", **{"remote-auth": "enable", "remote-server": binding.radius.name,
                "remote-group": "", "guest-lang": "en", "vdom": [], "webauthn": {"status": "disable"}})
        wire = json.dumps(defaults, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        request = hashlib.sha256(b"radius-remote-user-request-v1\x00" + binding.private_nonce.encode() + b"\x00" + wire).hexdigest()
        return RadiusRemoteUserCreateDraft(binding, source, request, wire, scope, schema_digest, expected_serial)
    except Exception:
        raise RadiusRemoteUserError(_ERROR) from None
    finally:
        _zeroize_mutable(sanitized)
        if isinstance(content, bytearray):
            _zeroize_mutable(content)


@dataclass(frozen=True, slots=True, repr=False)
class RadiusRemoteUserObservedState(_OpaqueC3Object):
    assigned_id: int
    nonmaterial_state_digest: str
    reported_reference_count: int


def qualify_radius_remote_user_detail(content: bytearray, schema: Mapping[str, Any],
        draft: RadiusRemoteUserCreateDraft, *, expected_serial: str) -> RadiusRemoteUserObservedState:
    """Require zero references for creation/readback or original-ACK removal."""
    state = project_radius_remote_user_detail(content, schema, draft, expected_serial=expected_serial)
    if state.reported_reference_count != 0:
        raise RadiusRemoteUserError(_ERROR)
    return state


def project_radius_remote_user_detail(content: bytearray, schema: Mapping[str, Any],
        draft: RadiusRemoteUserCreateDraft, *, expected_serial: str) -> RadiusRemoteUserObservedState:
    """Observe the disabled row's full stable non-material state and references.

    A successful projection is not original-ACK ownership or deletion authority.
    Nonzero references are observable but cannot satisfy the strict qualifier.
    Login history is excluded from configuration drift using the existing User
    projection rule; schema password/history material is never decoded.
    """
    sanitized = bytearray()
    try:
        if (type(content) is not bytearray or not 0 < len(content) <= 1048576 or type(draft) is not RadiusRemoteUserCreateDraft
                or type(expected_serial) is not str or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", expected_serial) is None):
            raise ValueError
        fields = _schema_fields(schema)
        if schema.get("serial") != expected_serial or expected_serial != draft._response_serial:
            raise ValueError
        schema_digest = hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        if schema_digest != draft._schema_digest:
            raise ValueError
        request = hashlib.sha256(b"radius-remote-user-request-v1\x00" + draft.binding.private_nonce.encode() + b"\x00" + draft._wire).hexdigest()
        if request != draft.request_digest:
            raise ValueError
        expected = json.loads(draft._wire)
        if (set(expected) != _FIELDS | {"webauthn", "password"} or expected["password"] != ""
                or expected["name"] != draft.binding.username or expected["status"] != "disable"
                or expected["accprofile"] != "pam_standard_user" or expected["remote-auth"] != "enable"
                or expected["remote-server"] != draft.binding.radius.name or expected["remote-group"] != ""):
            raise ValueError
        start = _skip_json_space(content, 0)
        end = _json_value_end(content, start)
        if _skip_json_space(content, end) != len(content):
            raise ValueError
        _validate_value(content, start, end, depth=0)
        envelope = _object_spans(content, start, end)
        for key, value in {"http_method": "GET", "http_status": 200, "status": "success", "path": "system", "name": "admin",
                "version": "v7.0.0", "build": 29, "serial": expected_serial, "vdom": draft._response_vdom, "mkey": draft.binding.username}.items():
            actual = json.loads(content[slice(*envelope[key])])
            if type(actual) is not type(value) or actual != value:
                raise ValueError
        left, right = envelope["results"]
        if content[left] == 91:
            left = _skip_json_space(content, left + 1)
            item_end = _json_value_end(content, left)
            if _skip_json_space(content, item_end) != right - 1:
                raise ValueError
            right = item_end
        raw_row = _object_spans(content, left, right)
        for flag in ("q_static", "q_global_entry", "q_no_edit", "q_no_rename"):
            if flag in raw_row:
                with memoryview(content)[slice(*raw_row[flag])] as token:
                    if not hmac.compare_digest(token, b"true") and not hmac.compare_digest(token, b"false"):
                        raise ValueError
        _sanitize_object(content, left, right, fields, sanitized, depth=0)
        row = json.loads(sanitized)
        if (type(row.get("id")) is not int or row["id"] <= 0 or type(row.get("q_ref")) is not int
                or not 0 <= row["q_ref"] <= 2**31 - 1
                or row.get("q_origin_key", draft.binding.username) != draft.binding.username):
            raise ValueError
        if row.get("force-saml-login") != "disable":
            raise ValueError
        for key, value in expected.items():
            if key in {"id", "password"}:
                continue
            if key == "vdom":
                if row.get(key) not in ([], [{"name": draft._response_vdom, "q_origin_key": draft._response_vdom}]):
                    raise ValueError
            elif key == "webauthn":
                if not isinstance(row.get(key), dict) or row[key].get("status") != "disable":
                    raise ValueError
            elif row.get(key) != value or type(row[key]) is not type(value):
                raise ValueError
        stable = {key: value for key, value in row.items() if key != "login-time"}
        digest = hashlib.sha256(b"radius-remote-user-state-v1\x00" + draft.binding.private_nonce.encode() + b"\x00"
            + json.dumps(stable, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        return RadiusRemoteUserObservedState(row["id"], digest, row["q_ref"])
    except Exception:
        raise RadiusRemoteUserError(_ERROR) from None
    finally:
        _zeroize_mutable(sanitized)
        if isinstance(content, bytearray):
            _zeroize_mutable(content)


def _response_envelope(content: bytearray, binding: RadiusRemoteUserBinding, *,
        expected_serial: str, expected_vdom: str, method: str, http_status: int) -> dict[str, tuple[int, int]]:
    from .radius_server_contract import _ENVELOPE
    if (type(content) is not bytearray or not 0 < len(content) <= 1048576
            or type(binding) is not RadiusRemoteUserBinding
            or type(expected_serial) is not str or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", expected_serial) is None):
        raise ValueError
    _validate_scope(expected_vdom)
    start = _skip_json_space(content, 0)
    end = _json_value_end(content, start)
    if _skip_json_space(content, end) != len(content):
        raise ValueError
    _validate_value(content, start, end, depth=0)
    top = _object_spans(content, start, end)
    if not top.keys() <= _ENVELOPE | {"action"}:
        raise ValueError
    if "action" in top and content[slice(*top["action"])] != b'""':
        raise ValueError
    expected = {"build": 29, "version": "v7.0.0", "serial": expected_serial,
        "path": "system", "name": "admin", "http_method": method,
        "http_status": http_status, "vdom": expected_vdom,
        "status": "error" if http_status == 404 else "success"}
    for key, value in expected.items():
        actual = json.loads(content[slice(*top[key])])
        if type(actual) is not type(value) or actual != value:
            raise ValueError
    if "mkey" in top:
        if json.loads(content[slice(*top["mkey"])]) != binding.username:
            raise ValueError
    return top


def qualify_radius_remote_user_ack(content: bytearray, binding: RadiusRemoteUserBinding, *,
        expected_serial: str, expected_vdom: str, method: str, http_status: int) -> str:
    """Consume an exact POST/DELETE ACK; readback cannot manufacture it."""
    from .ldap_server_projection import _array
    try:
        if method not in {"POST", "DELETE"} or type(http_status) is not int or http_status != 200:
            raise ValueError
        top = _response_envelope(content, binding, expected_serial=expected_serial,
            expected_vdom=expected_vdom, method=method, http_status=http_status)
        if "mkey" not in top:
            raise ValueError
        for key in ("revision", "old_revision"):
            if key in top:
                with memoryview(content)[slice(*top[key])] as token:
                    _string_or_empty(token)
        if "revision_changed" in top and content[slice(*top["revision_changed"])] != b"true":
            raise ValueError
        if "results" in top:
            left, right = top["results"]
            if content[left] == 123:
                if _object_spans(content, left, right):
                    raise ValueError
            elif content[left] != 91 or _array(content, (left, right)):
                raise ValueError
        return hashlib.sha256(content).hexdigest()
    except Exception:
        raise RadiusRemoteUserError(_ERROR) from None
    finally:
        if isinstance(content, bytearray):
            _zeroize_mutable(content)


def qualify_radius_remote_user_absence(content: bytearray, binding: RadiusRemoteUserBinding, *,
        expected_serial: str, expected_vdom: str, http_status: int, collection: bool) -> None:
    """Fixed detail404 plus complete name-only collection must both pass."""
    from .ldap_server_projection import _array
    from .radius_server_contract import _METADATA
    from .radius_server_projection import _METADATA_TYPES
    try:
        expected = 200 if collection else 404
        if type(collection) is not bool or type(http_status) is not int or http_status != expected:
            raise ValueError
        top = _response_envelope(content, binding, expected_serial=expected_serial,
            expected_vdom=expected_vdom, method="GET", http_status=expected)
        if not collection:
            if "results" in top:
                raise ValueError
        else:
            rows = _array(content, top["results"])
            # The fixed unpaged build29 User read reports the last row index,
            # as qualified by the existing User name reader and live source.
            for key, value in {"limit_reached": False, "next_idx": max(0, len(rows) - 1),
                    "matched_count": len(rows), "size": len(rows)}.items():
                if key in top:
                    actual = json.loads(content[slice(*top[key])])
                    if type(actual) is not type(value) or actual != value:
                        raise ValueError
            for span in rows:
                row = _object_spans(content, *span)
                if "name" not in row or not row.keys() <= {"name"} | _METADATA:
                    raise ValueError
                for key, location in row.items():
                    if content[location[0]] in (91, 123):
                        raise ValueError
                    value = json.loads(content[slice(*location)])
                    if type(value) is not (str if key == "name" else _METADATA_TYPES[key]):
                        raise ValueError
                name = json.loads(content[slice(*row["name"])])
                if not name or name == binding.username:
                    raise ValueError
    except Exception:
        raise RadiusRemoteUserError(_ERROR) from None
    finally:
        if isinstance(content, bytearray):
            _zeroize_mutable(content)
