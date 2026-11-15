"""Private build-29 User projection, not a reset/absence/reference authority.

All non-material schema fields must be present. Password and history values
are removed before a whole-record decoder is used. This module has no network
or runtime registration; an inspector must bind the fixed reads and separately
verify fixture provenance and the product's reported usage observation.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from typing import Any

from v4_planning.material_provider import C3MaterialBinding

from .local_user_reset_http_transport import LocalUserResetHttpTransportError, _NAME, _members
from .local_user_reset_owner_session import _validate_string
from .secret_metadata_http_transport import (
    _json_string_end, _json_value_end, _skip_json_space, _zeroize_mutable,
)

_UNAVAILABLE = "The private Local User reset projection is unavailable."
_KEY = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_MAX_BYTES = 1_048_576
_MAX_DEPTH = 16
_SCALAR_TYPES = frozenset({
    "string", "var-string", "integer", "option", "user", "ipv4-classnet", "ipv6-prefix", "datetime",
})
_METADATA = frozenset({
    "q_ref", "q_static", "q_global_entry", "q_origin_key", "q_mkey_type", "q_name",
    "q_no_edit", "q_no_rename", "q_path", "q_type",
})
_HISTORY = frozenset(f"history{index}" for index in range(20))
# These fields are returned by build 29 but absent from its User schema.
# The official User detail example also identifies them. Only the observed
# empty GUI tables qualify; nonempty tables need their own field classification.
_EXTRA_FIELDS: Mapping[str, Mapping[str, str]] = {
    "force-saml-login": {"type": "option"},
    "gui-custom-conf": {"type": "string"},
    "gui-default-dashboard-template": {"type": "string"},
    "gui-ignore-invalid-signature-version": {"type": "string"},
    "gui-ignore-release-overview-version": {"type": "string"},
    "gui-dashboard": {"type": "empty-array"},
    "gui-global-menu-favorites": {"type": "empty-array"},
    "gui-vdom-menu-favorites": {"type": "empty-array"},
    "gui-vdom-menu-favorites-secret": {"type": "empty-array"},
}
_WEBAUTHN_EXTRA_FIELDS: Mapping[str, Mapping[str, str]] = {
    "user-handle": {"type": "empty-string"},
    "credential-id": {"type": "empty-string"},
    "public-key": {"type": "empty-string"},
    "transports": {"type": "empty-string"},
    "algorithm": {"type": "integer"},
}
_REQUIRED = frozenset({
    "name", "id", "status", "accprofile", "remote-auth", "wildcard",
    "guest-auth", "sponsor-group", "schedule", "password", "vdom", "webauthn",
})


@dataclass(frozen=True, slots=True, repr=False)
class LocalUserResetUserProjection(C3MaterialBinding):
    """Protected observation; no assertion of complete incoming references."""

    username: str
    status: str
    is_local: bool
    access_profile: str
    sponsor_group: str
    schedule: str
    guest_auth: str
    nonmaterial_state_digest: str
    reported_reference_count: int
    product_version: str = "7.0.0"
    product_build: int = 29


def project_local_user_reset_detail(
    content: bytearray, schema: object, *, expected_username: str,
) -> LocalUserResetUserProjection:
    """Consume one exact full GET response; destroy input on success/failure.

The schema argument is the protected fixed User schema response, never a
caller-supplied MCP schema. Successful projection alone does not prove fixture
ownership, usage visibility, permission to reset, or safe deletion.
    """
    sanitized = bytearray()
    try:
        if (type(content) is not bytearray or not 0 < len(content) <= _MAX_BYTES
            or not isinstance(expected_username, str) or len(expected_username) > 64
            or _NAME.fullmatch(expected_username) is None):
            raise ValueError
        fields = _schema_fields(schema)
        start = _skip_json_space(content, 0)
        end = _json_value_end(content, start)
        if _skip_json_space(content, end) != len(content):
            raise ValueError
        envelope = _members(content, start, end, {
            b'"build"', b'"http_method"', b'"http_status"', b'"name"', b'"path"',
            b'"results"', b'"revision"', b'"serial"', b'"status"', b'"vdom"', b'"version"',
            b'"mkey"',
        })
        for key, value in {
            b'"build"': b'29', b'"http_method"': b'"GET"', b'"http_status"': b'200',
            b'"name"': b'"admin"', b'"path"': b'"system"', b'"status"': b'"success"',
            b'"version"': b'"v7.0.0"',
        }.items():
            left, right = envelope[key]
            with memoryview(content)[left:right] as token:
                if token != value:
                    raise ValueError
        for key in (b'"revision"', b'"serial"', b'"vdom"'):
            if key in envelope:
                left, right = envelope[key]
                with memoryview(content)[left:right] as token:
                    _string_or_empty(token)
        if b'"mkey"' in envelope:
            left, right = envelope[b'"mkey"']
            with memoryview(content)[left:right] as token:
                if token != json.dumps(expected_username).encode("ascii"):
                    raise ValueError
        left, right = envelope[b'"results"']
        if content[left] == 91:
            left = _skip_json_space(content, left + 1)
            item_end = _json_value_end(content, left)
            if _skip_json_space(content, item_end) != right - 1:
                raise ValueError
            right = item_end
        _sanitize_object(content, left, right, fields, sanitized, depth=0)
        record = json.loads(sanitized)
        if (record.get("name") != expected_username or type(record.get("id")) is not int
            or record["id"] <= 0 or type(record.get("q_ref")) is not int or record["q_ref"] < 0
            or record.get("q_origin_key", expected_username) != expected_username):
            raise ValueError
        for name in ("status", "remote-auth", "wildcard", "guest-auth", "force-saml-login"):
            if record.get(name) not in {"enable", "disable"}:
                raise ValueError
        for name in ("accprofile", "sponsor-group", "schedule"):
            if not isinstance(record.get(name), str):
                raise ValueError
        if not record["accprofile"]:
            raise ValueError
        for name in ("q_static", "q_global_entry", "q_no_edit", "q_no_rename"):
            if name in record and type(record[name]) is not bool:
                raise ValueError
        for name in ("q_origin_key", "q_mkey_type", "q_name", "q_path"):
            if name in record and not isinstance(record[name], str):
                raise ValueError
        if "q_type" in record and (type(record["q_type"]) is not int or record["q_type"] < 0):
            raise ValueError
        # Login adds an audit row to this schema-backed table. Validate it,
        # but keep session history out of the configuration drift binding.
        stable_record = {key: value for key, value in record.items() if key != "login-time"}
        digest = hashlib.sha256(json.dumps(
            stable_record, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")).hexdigest()
        return LocalUserResetUserProjection(
            username=record["name"], status=record["status"],
            is_local=record["remote-auth"] == "disable" and record["wildcard"] == "disable",
            access_profile=record["accprofile"], sponsor_group=record["sponsor-group"],
            schedule=record["schedule"], guest_auth=record["guest-auth"],
            nonmaterial_state_digest=digest, reported_reference_count=record["q_ref"],
        )
    except Exception:
        raise LocalUserResetHttpTransportError(_UNAVAILABLE) from None
    finally:
        try:
            _zeroize_mutable(sanitized)
        finally:
            if isinstance(content, bytearray):
                _zeroize_mutable(content)


def _schema_fields(schema: object) -> Mapping[str, Any]:
    if not isinstance(schema, Mapping):
        raise ValueError
    for key, value in {"build": 29, "http_method": "GET", "http_status": 200,
        "name": "admin", "path": "system", "status": "success", "version": "v7.0.0",
        "action": "schema"}.items():
        if type(schema.get(key)) is not type(value) or schema[key] != value:
            raise ValueError
    results = schema.get("results")
    if not isinstance(results, Mapping):
        raise ValueError
    fields = results.get("children")
    if (not isinstance(fields, Mapping) or not _REQUIRED <= fields.keys()
        or not isinstance(fields["password"], Mapping)
        or fields["password"].get("type") != "password-2"):
        raise ValueError
    return fields


def _object_spans(content: bytearray, start: int, end: int) -> dict[str, tuple[int, int]]:
    if end <= start or content[start] != 123 or content[end - 1] != 125:
        raise ValueError
    cursor = _skip_json_space(content, start + 1)
    fields: dict[str, tuple[int, int]] = {}
    while cursor < end - 1:
        key_end = _json_string_end(content, cursor)
        # Decode only a bounded schema field name, never a value.
        if key_end - cursor > 66:
            raise ValueError
        key = json.loads(content[cursor:key_end + 1])
        if (not isinstance(key, str) or _KEY.fullmatch(key) is None or key in fields
            or len(fields) >= 512):
            raise ValueError
        separator = _skip_json_space(content, key_end + 1)
        if content[separator] != 58:
            raise ValueError
        left = _skip_json_space(content, separator + 1)
        right = _json_value_end(content, left)
        if right >= end:
            raise ValueError
        fields[key] = left, right
        cursor = _skip_json_space(content, right)
        if cursor == end - 1:
            break
        if content[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(content, cursor + 1)
        if cursor >= end - 1:
            raise ValueError
    return fields


def _material(name: str, descriptor: object, *, root: bool) -> bool:
    return (root and (name in {"password", "shared-key"} or name in _HISTORY)
            or isinstance(descriptor, Mapping) and descriptor.get("type") == "password-2")


def _string_or_empty(token: memoryview) -> None:
    if not hmac.compare_digest(token, b'""'):
        _validate_string(token)


def _sanitize_object(content: bytearray, start: int, end: int,
                     schema: Mapping[str, Any], output: bytearray, *, depth: int) -> None:
    if depth > _MAX_DEPTH:
        raise ValueError
    root = depth == 0
    spans = _object_spans(content, start, end)
    required = {key for key, value in schema.items() if not _material(key, value, root=root)}
    if root:
        required.update(_EXTRA_FIELDS)
        required.add("q_ref")
    if not required <= spans.keys():
        raise ValueError
    reference = (not root and set(schema) == {"name"}
                 and isinstance(schema["name"], Mapping)
                 and schema["name"].get("type") in {"string", "var-string"})
    if reference and "q_origin_key" in spans:
        for key in ("name", "q_origin_key"):
            with memoryview(content)[slice(*spans[key])] as token:
                _string_or_empty(token)
        if json.loads(content[slice(*spans["name"])]) != json.loads(content[slice(*spans["q_origin_key"])]):
            raise ValueError
    login_history = depth == 1 and set(schema) == {
        "last-failed-login", "last-login", "last-login-ip", "usr-name", "q_origin_key"}
    if login_history:
        if "q_origin_key" not in spans or "usr-name" not in spans:
            raise ValueError
        with (memoryview(content)[slice(*spans["q_origin_key"])] as origin,
              memoryview(content)[slice(*spans["usr-name"])] as user):
            _string_or_empty(origin)
            _string_or_empty(user)
            if not hmac.compare_digest(origin, user):
                raise ValueError
    output.append(123)
    first = True
    for name, (left, right) in spans.items():
        descriptor = schema.get(name)
        if _material(name, descriptor, root=root):
            with memoryview(content)[left:right] as token:
                _string_or_empty(token)
            continue
        if root and name in _EXTRA_FIELDS:
            descriptor = _EXTRA_FIELDS[name]
        if root and name == "webauthn":
            if not isinstance(descriptor, Mapping) or not isinstance(descriptor.get("children"), Mapping):
                raise ValueError
            # Only the actual new fixture's empty credential state qualifies.
            # Never decode nonempty, schema-omitted WebAuthn material or infer
            # its meaning from these field names. Preserve every accepted field.
            descriptor = {**descriptor, "children": {**descriptor["children"], **_WEBAUTHN_EXTRA_FIELDS}}
        if root and name == "login-time":
            if (not isinstance(descriptor, Mapping)
                or not isinstance(descriptor.get("children"), Mapping)
                or set(descriptor["children"]) != {
                    "last-failed-login", "last-login", "last-login-ip", "usr-name"}):
                raise ValueError
            descriptor = {**descriptor, "children": {**descriptor["children"],
                "q_origin_key": {"type": "var-string"}}}
        metadata = (root and name in _METADATA) or (reference and name == "q_origin_key")
        if descriptor is None and not metadata:
            raise ValueError
        if not first:
            output.append(44)
        first = False
        output.extend(json.dumps(name).encode("ascii"))
        output.append(58)
        if metadata:
            if content[left] in {91, 123}:
                raise ValueError
            output.extend(memoryview(content)[left:right])
        else:
            _sanitize_value(content, left, right, descriptor, output, depth=depth + 1)
    output.append(125)


def _sanitize_value(content: bytearray, start: int, end: int, descriptor: object,
                    output: bytearray, *, depth: int) -> None:
    if not isinstance(descriptor, Mapping) or depth > _MAX_DEPTH:
        raise ValueError
    children = descriptor.get("children")
    if isinstance(children, Mapping):
        if content[start] == 123:
            _sanitize_object(content, start, end, children, output, depth=depth)
        elif content[start] == 91:
            output.append(91)
            cursor = _skip_json_space(content, start + 1)
            count = 0
            while cursor < end - 1:
                if count >= 512:
                    raise ValueError
                item_end = _json_value_end(content, cursor)
                if count:
                    output.append(44)
                _sanitize_object(content, cursor, item_end, children, output, depth=depth)
                count += 1
                cursor = _skip_json_space(content, item_end)
                if cursor == end - 1:
                    break
                if content[cursor] != 44:
                    raise ValueError
                cursor = _skip_json_space(content, cursor + 1)
                if cursor >= end - 1:
                    raise ValueError
            output.append(93)
        else:
            raise ValueError
    elif descriptor.get("type") == "empty-string":
        with memoryview(content)[start:end] as token:
            if not hmac.compare_digest(token, b'""'):
                raise ValueError
        output.extend(b'""')
    elif descriptor.get("type") == "empty-array":
        if (content[start] != 91 or content[end - 1] != 93
            or _skip_json_space(content, start + 1) != end - 1):
            raise ValueError
        output.extend(b"[]")
    elif descriptor.get("type") in _SCALAR_TYPES:
        # Product scalar types cannot smuggle an unclassified nested record.
        with memoryview(content)[start:end] as token:
            if descriptor["type"] == "integer":
                if re.fullmatch(rb"-?(?:0|[1-9][0-9]*)", token) is None:
                    raise ValueError
            else:
                _string_or_empty(token)
            output.extend(token)
    else:
        raise ValueError
