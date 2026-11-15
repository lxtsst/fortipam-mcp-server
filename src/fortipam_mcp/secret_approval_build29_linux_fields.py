"""Unwired private Linux field projection; no native write qualification.

Password JSON tokens remain opaque. Forwarding does not establish stored-password
preservation. The private caller owns and must erase the returned mutable array.
"""
from collections.abc import Mapping
import hmac
from ipaddress import IPv4Address
import json
import re

from .secret_approval_build29_http_transport import _raw_members
from .secret_approval_build29_linux_metadata import qualify_secret_approval_build29_linux_metadata
from .mutable_json_buffer import _MutableJSONBuffer
from .secret_create_191_http_transport import _quoted_material, _valid_material_view, _valid_utf8
from .secret_description_update_http_transport import _field_span
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES, _json_value_end, _skip_json_space, _zeroize_mutable,
)

_TYPES = {"Host": "target-address", "Username": "username", "Password": "password"}
_STRING = re.compile(rb'"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"\Z')


class SecretApprovalBuild29LinuxFieldsError(ValueError):
    """Categorical rejection without source or material values."""


def project_secret_approval_build29_linux_fields(
    raw: bytearray, *, identity: Mapping[str, object], expected_serial: str,
    expected_metadata_digest: str, username: memoryview, target_ipv4_address: str,
) -> bytearray:
    """Consume a fixed native GET and return only bound id/name/value spans.

    Capture the mutable field before the metadata observer consumes the original
    buffer. No second full response copy is needed. Host and Username require the
    existing material serializer's exact JSON encoding, including its escapes.
    """
    field, output = bytearray(), bytearray()
    account, host, address = bytearray(), bytearray(), bytearray()
    builder = _MutableJSONBuffer()
    succeeded = False
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= MAX_RESPONSE_BYTES
                or type(expected_metadata_digest) is not str
                or re.fullmatch(r"[0-9a-f]{64}", expected_metadata_digest) is None
                or not _valid_material_view(username)
                or type(target_ipv4_address) is not str
                or str(IPv4Address(target_ipv4_address)) != target_ipv4_address):
            raise ValueError
        start, end = _field_span(raw)
        field = bytearray(end - start)
        with memoryview(raw) as view, memoryview(field) as destination:
            destination[:] = view[start:end]
        observation = qualify_secret_approval_build29_linux_metadata(
            raw, identity=identity, expected_serial=expected_serial,
        )
        if (not observation.totp_disabled
                or not hmac.compare_digest(expected_metadata_digest, observation.metadata_digest)
                or len(observation.slots) != 3
                or {slot.name: slot.type for slot in observation.slots} != _TYPES):
            raise ValueError
        slots = _slots(field)
        account = _quoted_material(username)
        address.extend(target_ipv4_address.encode("ascii"))
        with memoryview(address) as view:
            host = _quoted_material(view)
        for name, expected in (("Host", host), ("Username", account)):
            first, last = slots[name]["value"]
            with memoryview(field)[first:last] as view:
                if not hmac.compare_digest(view, expected):
                    raise ValueError
        builder.extend(b"[")
        for index, name in enumerate(_TYPES):
            if index:
                builder.extend(b",")
            builder.extend(b"{")
            for position, key in enumerate(("id", "name", "value")):
                if position:
                    builder.extend(b",")
                builder.extend(b'"' + key.encode("ascii") + b'":')
                first, last = slots[name][key]
                with memoryview(field)[first:last] as view:
                    builder.extend(view)
            builder.extend(b"}")
        builder.extend(b"]")
        output = builder.finish()
        succeeded = True
        return output
    except Exception:
        raise SecretApprovalBuild29LinuxFieldsError(
            "The private build-29 Linux fields are unavailable.",
        ) from None
    finally:
        builder.close()
        for buffer in (field, account, host, address):
            _zeroize_mutable(buffer)
        if isinstance(raw, bytearray):
            _zeroize_mutable(raw)
        if not succeeded:
            _zeroize_mutable(output)


def _slots(field: bytearray) -> dict[str, dict[str, tuple[int, int]]]:
    """Locate spans after the observer validates slot structure and identity."""
    cursor = _skip_json_space(field, 1)
    slots: dict[str, dict[str, tuple[int, int]]] = {}
    while cursor < len(field) - 1:
        end = _json_value_end(field, cursor)
        members = {key: (first, last) for key, _, first, last, _
                   in _raw_members(field, cursor, end)}
        first, last = members["name"]
        name = json.loads(field[first:last])
        first, last = members["value"]
        with memoryview(field)[first:last] as view:
            if len(view) <= 2 or _STRING.fullmatch(view) is None or not _valid_utf8(view):
                raise ValueError
        slots[name] = members
        cursor = _skip_json_space(field, end)
        if cursor < len(field) - 1:
            cursor = _skip_json_space(field, cursor + 1)
    return slots
