"""Private build-29 opaque field retention for one fixed DLP association.

No network, credential provider, generic patch or plaintext-password claim is
provided. Returned JSON value/keyinfo tokens stay mutable and opaque until the
private adapter submits the native routing/retained-field body.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
import hmac
import json
import re
import secrets

from v4_planning.material_provider import C3MaterialBinding

from .local_user_reset_metadata_reader import _validate_value
from .local_user_reset_name_reader import _ENVELOPE
from .local_user_reset_projection import _object_spans
from .secret_description_update_http_transport import _field_span
from .secret_dlp_association_contract import compile_fixed_secret_dlp_body, project_secret_dlp_metadata
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES, _json_string_end, _json_value_end, _redact_json_field_values, _skip_json_space, _zeroize_mutable,
)

_UNAVAILABLE = "The fixed Secret DLP opaque carrier is unavailable."
_TEMPLATE = "Unix Account (SSH Password)"
_TEMPLATE_FIELDS = frozenset({
    "access", "description", "enforce-sso-launch", "field", "group-permission", "launcher", "name",
    "password-changer", "q_origin_key", "server-info", "ssh-term", "totp-setting", "user-permission", "web-filler",
})
_DESCRIPTOR_FIELDS = frozenset({"mandatory", "name", "need-edit", "q_origin_key", "type"})
_FIELD_TYPES = {"Host": "target-address", "Username": "username", "Password": "password"}


class SecretDlpOpaqueCarrierError(RuntimeError):
    """Stable refusal without response, token, keyinfo, key or selector values."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretDlpOpaqueBinding(C3MaterialBinding):
    """Private constructor-bound Secret, unchanged Target and appliance identity."""

    expected_secret_id: int
    expected_folder_id: int
    expected_secret_name: str
    expected_target: str
    expected_serial: str
    expected_template: str = _TEMPLATE

    def __post_init__(self) -> None:
        if (
            any(type(value) is not int or not 0 < value <= 2_147_483_647
                for value in (self.expected_secret_id, self.expected_folder_id))
            or not _safe_name(self.expected_secret_name, 255)
            or re.fullmatch(r"mcp-v4-bp005-dlp-audit-[A-Za-z0-9][A-Za-z0-9._-]*", self.expected_secret_name) is None
            or not _safe_name(self.expected_target, 79)
            or type(self.expected_serial) is not str
            or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.expected_serial) is None
            or self.expected_template != _TEMPLATE
        ):
            raise SecretDlpOpaqueCarrierError(_UNAVAILABLE)


class SecretDlpOpaqueWitness(C3MaterialBinding):
    """One process-local ephemeral key shared by fresh before/after captures."""

    __slots__ = ("_binding", "_key", "_carriers", "_closed")

    def __init__(self, binding: SecretDlpOpaqueBinding) -> None:
        if type(binding) is not SecretDlpOpaqueBinding:
            raise SecretDlpOpaqueCarrierError(_UNAVAILABLE)
        self._binding = binding
        self._key = bytearray(secrets.token_bytes(32))
        self._carriers: list[SecretDlpOpaqueCarrier] = []
        self._closed = False

    def __enter__(self) -> SecretDlpOpaqueWitness:
        self._require_open()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _require_open(self) -> None:
        if self._closed:
            raise SecretDlpOpaqueCarrierError(_UNAVAILABLE)

    def capture(self, secret_response: bytearray, template_response: bytearray) -> SecretDlpOpaqueCarrier:
        """Consume both bounded mutable GET bodies, including on any refusal.

        Complete recursive JSON/duplicate checks run before decoding metadata.
        Credential values and keyinfo are never passed to json.loads.
        """
        native_fields = bytearray()
        transferred = False
        try:
            self._require_open()
            if (type(secret_response) is not bytearray or type(template_response) is not bytearray
                or secret_response is template_response):
                raise ValueError
            template_row = _row_span(template_response, self._binding, table="template")
            template_types = _template_types(template_response, template_row, self._binding)
            row_span = _row_span(secret_response, self._binding, table="database")
            row = _object_spans(secret_response, *row_span)
            identity = self._identity()
            for key, value in {**identity, "target": self._binding.expected_target}.items():
                if secret_response[slice(*row[key])] != _encode(value):
                    raise ValueError
            if "q_origin_key" in row:
                origin = json.loads(secret_response[slice(*row["q_origin_key"])])
                if type(origin) not in {int, str} or origin not in {
                    self._binding.expected_secret_id, str(self._binding.expected_secret_id),
                }:
                    raise ValueError
            start, end = _field_span(secret_response)
            opaque_digest = self._witness(secret_response, start, end)
            shape = _compile_fields(secret_response, (start, end), template_types, native_fields)
            if not _redact_json_field_values(secret_response):
                raise ValueError
            redacted = json.loads(secret_response)
            redacted_row = redacted["results"]
            if isinstance(redacted_row, list):
                redacted_row = redacted_row[0]
            preserved = {key: value for key, value in redacted_row.items()
                         if key not in {"field", "dlp-status", "dlp-sensor"}}
            canonical = bytearray(_encode(preserved))
            try:
                metadata_witness = self._witness(canonical, 0, len(canonical))
            finally:
                _zeroize_mutable(canonical)
            projection = project_secret_dlp_metadata(redacted, credential_shape=shape,
                                                     opaque_field_digest=opaque_digest)
            carrier = SecretDlpOpaqueCarrier(self, projection, shape, opaque_digest,
                                             metadata_witness, native_fields)
            self._carriers.append(carrier)
            transferred = True
            return carrier
        except Exception:
            raise SecretDlpOpaqueCarrierError(_UNAVAILABLE) from None
        finally:
            if not transferred:
                _zeroize_mutable(native_fields)
            for content in (secret_response, template_response):
                if type(content) is bytearray:
                    _zeroize_mutable(content)

    def _identity(self) -> dict[str, object]:
        b = self._binding
        return {"id": b.expected_secret_id, "folder": b.expected_folder_id,
                "name": b.expected_secret_name, "template": b.expected_template}

    def _witness(self, content: bytearray, start: int, end: int) -> str:
        self._require_open()
        with memoryview(content)[start:end] as token:
            return hmac.digest(self._key, token, "sha256").hex()

    def close(self) -> None:
        """Wipe every retained token and body as well as the shared witness key."""
        for carrier in self._carriers:
            carrier.close()
        self._carriers.clear()
        _zeroize_mutable(self._key)
        self._closed = True


class SecretDlpOpaqueCarrier(C3MaterialBinding):
    """Private captured state; only the fixed association compiler emits a body."""

    __slots__ = ("_owner", "_projection", "_shape", "_opaque", "_metadata", "_fields", "_bodies", "_closed")

    def __init__(self, owner: SecretDlpOpaqueWitness, projection: dict[str, object],
                 shape: list[dict[str, object]], opaque: str, metadata: str, fields: bytearray) -> None:
        self._owner, self._projection, self._shape = owner, projection, shape
        self._opaque, self._metadata, self._fields = opaque, metadata, fields
        self._bodies: list[bytearray] = []
        self._closed = False

    def _require_open(self) -> None:
        self._owner._require_open()
        if self._closed:
            raise SecretDlpOpaqueCarrierError(_UNAVAILABLE)

    @property
    def projection(self) -> dict[str, object]:
        """Private redacted contract input; return an independent metadata copy."""
        self._require_open()
        return deepcopy(self._projection)

    @property
    def credential_shape(self) -> list[dict[str, object]]:
        self._require_open()
        return deepcopy(self._shape)

    @property
    def opaque_field_digest(self) -> str:
        self._require_open()
        return self._opaque

    @property
    def redacted_metadata_witness_digest(self) -> str:
        self._require_open()
        return self._metadata

    def encode_association(
        self, sensor: object, *, expected_sensor_name: str, expected_sensor_digest: str,
        expected_preservation_digest: str, expected_opaque_field_digest: str, restore: bool = False,
    ) -> bytearray:
        """Compile the fixed DLP delta and unchanged identity/Target/opaque fields.

        The mutable body is private adapter input, never an MCP result. Both the
        caller and close() must wipe it after the bounded exchange.
        """
        body = bytearray()
        try:
            self._require_open()
            delta = compile_fixed_secret_dlp_body(
                self._projection, sensor, identity=self._owner._identity(),
                expected_sensor_name=expected_sensor_name, expected_sensor_digest=expected_sensor_digest,
                expected_preservation_digest=expected_preservation_digest,
                expected_credential_shape=self._shape, expected_opaque_field_digest=expected_opaque_field_digest,
                restore=restore,
            )
            routing = {**delta, "target": self._owner._binding.expected_target}
            body.extend(_encode(routing)[:-1])
            body.extend(b',"field":')
            body.extend(self._fields)
            body.extend(b"}")
            self._bodies.append(body)
            return body
        except Exception:
            _zeroize_mutable(body)
            raise SecretDlpOpaqueCarrierError(_UNAVAILABLE) from None

    def close(self) -> None:
        _zeroize_mutable(self._fields)
        for body in self._bodies:
            _zeroize_mutable(body)
        self._bodies.clear()
        self._projection.clear()
        self._shape.clear()
        self._closed = True


def _safe_name(value: object, limit: int) -> bool:
    try:
        return (type(value) is str and 0 < len(value.encode("utf-8")) <= limit
                and all(ord(character) >= 32 and ord(character) != 127 for character in value))
    except UnicodeError:
        return False


def _encode(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


def _row_span(content: bytearray, binding: SecretDlpOpaqueBinding, *, table: str) -> tuple[int, int]:
    if not 0 < len(content) <= MAX_RESPONSE_BYTES:
        raise ValueError
    left = _skip_json_space(content, 0); right = _json_value_end(content, left)
    if _skip_json_space(content, right) != len(content):
        raise ValueError
    root = _object_spans(content, left, right)
    if not root.keys() <= _ENVELOPE | {"mkey"}:
        raise ValueError
    envelope_span = left, right
    for key, value in {"version": "v7.0.0", "build": 29, "http_status": 200, "http_method": "GET",
                       "path": "secret", "name": table, "serial": binding.expected_serial}.items():
        if content[slice(*root[key])] != _encode(value):
            raise ValueError
    if not any(hmac.compare_digest(content[slice(*root["status"])], value) for value in (b'"OK"', b'"success"')):
        raise ValueError
    for key, expected in (("action", b'""'), ("vdom", b'"root"'), ("size", b"1"),
                          ("matched_count", b"1"), ("limit_reached", b"false")):
        if key in root and content[slice(*root[key])] != expected:
            raise ValueError
    if "next_idx" in root:
        raise ValueError
    if "mkey" in root:
        expected_mkey = binding.expected_template if table == "template" else binding.expected_secret_id
        actual_mkey = json.loads(content[slice(*root["mkey"])])
        if type(actual_mkey) not in {str, int} or actual_mkey not in {expected_mkey, str(expected_mkey)}:
            raise ValueError
    left, right = root["results"]
    if content[left] == 91:
        left = _skip_json_space(content, left + 1); end = _json_value_end(content, left)
        if _skip_json_space(content, end) != right - 1:
            raise ValueError
        right = end
    if table == "database":
        _normalize_build29_clipboard_duplicate(content, (left, right))
    _validate_value(content, *envelope_span, depth=0)
    _object_spans(content, left, right)
    return left, right


def _normalize_build29_clipboard_duplicate(content: bytearray, span: tuple[int, int]) -> None:
    """Keep the one native identical duplicate; all other duplicates stay denied.

    Called only after qualifying the exact build-29 Secret GET envelope. Replace
    the second row-level member and its preceding comma with spaces so offsets
    and the complete opaque field-table bytes stay unchanged. Nested objects
    are skipped here and subsequently undergo the unchanged strict validator.
    """
    left, right = span
    if content[left] != 123 or content[right - 1] != 125:
        raise ValueError
    cursor = _skip_json_space(content, left + 1)
    preceding_comma: int | None = None
    first: tuple[int, int] | None = None
    count = 0
    while cursor < right - 1:
        key_end = _json_string_end(content, cursor)
        if key_end - cursor > 66:
            raise ValueError
        key = json.loads(content[cursor:key_end + 1])
        colon = _skip_json_space(content, key_end + 1)
        if content[colon] != 58:
            raise ValueError
        value_start = _skip_json_space(content, colon + 1)
        value_end = _json_value_end(content, value_start)
        if value_end >= right:
            raise ValueError
        if key == "block-clipboard":
            count += 1
            if count > 2:
                raise ValueError
            if first is None:
                first = value_start, value_end
            else:
                if preceding_comma is None:
                    raise ValueError
                with memoryview(content)[slice(*first)] as original, memoryview(content)[value_start:value_end] as duplicate:
                    if (not any(hmac.compare_digest(original, token) for token in (b'"enable"', b'"disable"'))
                        or not hmac.compare_digest(original, duplicate)):
                        raise ValueError
                content[preceding_comma:value_end] = b" " * (value_end - preceding_comma)
        cursor = _skip_json_space(content, value_end)
        if cursor == right - 1:
            break
        if content[cursor] != 44:
            raise ValueError
        preceding_comma = cursor
        cursor = _skip_json_space(content, cursor + 1)
        if cursor >= right - 1:
            raise ValueError


def _array_items(content: bytearray, span: tuple[int, int]) -> list[tuple[int, int]]:
    left, right = span
    if content[left] != 91 or content[right - 1] != 93:
        raise ValueError
    cursor = _skip_json_space(content, left + 1)
    items: list[tuple[int, int]] = []
    while cursor < right - 1:
        if len(items) >= 3:
            raise ValueError
        end = _json_value_end(content, cursor)
        if end >= right:
            raise ValueError
        items.append((cursor, end))
        cursor = _skip_json_space(content, end)
        if cursor == right - 1:
            break
        if content[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(content, cursor + 1)
        if cursor >= right - 1:
            raise ValueError
    return items


def _template_types(content: bytearray, span: tuple[int, int], binding: SecretDlpOpaqueBinding) -> dict[str, str]:
    row = _object_spans(content, *span)
    if set(row) != _TEMPLATE_FIELDS:
        raise ValueError
    for key in ("name", "q_origin_key"):
        if content[slice(*row[key])] != _encode(binding.expected_template):
            raise ValueError
    result: dict[str, str] = {}
    for item_span in _array_items(content, row["field"]):
        item = _object_spans(content, *item_span)
        if set(item) != _DESCRIPTOR_FIELDS:
            raise ValueError
        name = json.loads(content[slice(*item["name"])])
        if type(name) is not str or name not in _FIELD_TYPES or name in result:
            raise ValueError
        for key, expected in (("type", _FIELD_TYPES[name]), ("q_origin_key", name), ("mandatory", "enable")):
            if content[slice(*item[key])] != _encode(expected):
                raise ValueError
        if not any(hmac.compare_digest(content[slice(*item["need-edit"])], value)
                   for value in (b'"enable"', b'"disable"')):
            raise ValueError
        result[name] = _FIELD_TYPES[name]
    if set(result) != set(_FIELD_TYPES):
        raise ValueError
    return result


def _compile_fields(content: bytearray, span: tuple[int, int], types: Mapping[str, str],
                    output: bytearray) -> list[dict[str, object]]:
    entries: dict[str, dict[str, tuple[int, int]]] = {}
    shape: list[dict[str, object]] = []
    ids: set[int] = set()
    for item_span in _array_items(content, span):
        item = _object_spans(content, *item_span)
        required = {"id", "name", "value"}
        native_metadata = {"desc", "type", "q_origin_key"}
        if (not required <= item.keys()
            or not item.keys() <= required | native_metadata | {"keyinfo"}
            or (native_metadata & item.keys() and not native_metadata <= item.keys())):
            raise ValueError
        name = json.loads(content[slice(*item["name"])])
        identifier = json.loads(content[slice(*item["id"])])
        if (type(name) is not str or name not in types or name in entries
            or type(identifier) is not int or not 0 < identifier <= 2_147_483_647 or identifier in ids):
            raise ValueError
        if native_metadata <= item.keys():
            origin = json.loads(content[slice(*item["q_origin_key"])])
            if (type(origin) is not int or origin != identifier
                or content[slice(*item["type"])] != _encode(types[name])
                or content[item["desc"][0]] != 34):
                raise ValueError
        for key in {"value", "keyinfo"} & item.keys():
            if content[item[key][0]] != 34:
                raise ValueError
        if name != "Host" and content[slice(*item["value"])] == b'""':
            raise ValueError
        entries[name] = item; ids.add(identifier)
        shape.append({"id": identifier, "name": name, "type": types[name]})
    if set(entries) not in ({"Password", "Username"}, {"Host", "Password", "Username"}):
        raise ValueError
    output.extend(b"[")
    for index, name in enumerate(("Password", "Username")):
        if index:
            output.extend(b",")
        item = entries[name]
        output.extend(b"{")
        for position, key in enumerate(key for key in ("id", "name", "value", "keyinfo") if key in item):
            if position:
                output.extend(b",")
            output.extend(_encode(key)); output.extend(b":")
            with memoryview(content)[slice(*item[key])] as token:
                output.extend(token)
        output.extend(b"}")
    output.extend(b"]")
    return sorted(shape, key=lambda item: str(item["name"]))
