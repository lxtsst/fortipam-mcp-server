"""Unwired Linux read-only observations; no material or write qualification.

Synthetic parser tests do not establish appliance behavior. Slot names/types
are observations, not an accepted update schema or preservation witness.
"""
from collections.abc import Mapping
from dataclasses import dataclass
import json
from typing import Any

from .secret_approval_build29_http_transport import (
    _FIELD_ORDER, _NATIVE_ENVELOPE, _normalize_one_native_metadata_duplicate,
    _preserved_metadata_digest, _raw_members, _redact_material_members,
)
from .secret_description_update_http_transport import _field_span
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES, _json_value_end, _skip_json_space, _zeroize_mutable,
)
from .target_contract import DEFAULT_TEMPLATE


class SecretApprovalBuild29LinuxMetadataError(ValueError):
    """Non-disclosing rejection of an unavailable observation."""


@dataclass(frozen=True, slots=True, repr=False)
class LinuxFieldSlotObservation:
    id: int
    name: str
    type: str


@dataclass(frozen=True, slots=True, repr=False)
class SecretApprovalBuild29LinuxMetadataObservation:
    approval_values: tuple[str, str, str, str]
    metadata_digest: str
    totp_disabled: bool
    slots: tuple[LinuxFieldSlotObservation, ...]


def _text(value: object, limit: int = 255) -> bool:
    return (type(value) is str and 0 < len(value.encode("utf-8")) <= limit
            and all(ord(char) >= 32 and ord(char) != 127 for char in value))


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError
        result[name] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError


def _observe_slots(raw: bytearray) -> tuple[LinuxFieldSlotObservation, ...]:
    start, end = _field_span(raw)
    if raw[start] != 91 or raw[end - 1] != 93:
        raise ValueError
    cursor = _skip_json_space(raw, start + 1)
    slots: list[LinuxFieldSlotObservation] = []
    ids: set[int] = set()
    names: set[str] = set()
    while cursor < end - 1:
        finish = _json_value_end(raw, cursor)
        members: dict[str, tuple[int, int]] = {}
        for key, _, left, right, _ in _raw_members(raw, cursor, finish):
            if key in members or key not in {"id", "name", "type", "value", "desc", "q_origin_key"}:
                raise ValueError
            members[key] = (left, right)
        if not {"id", "name", "type", "value"}.issubset(members):
            raise ValueError
        observed = {key: json.loads(raw[left:right]) for key, (left, right) in members.items()
                    if key in {"id", "name", "type"}}
        identifier, name, kind = observed["id"], observed["name"], observed["type"]
        if (type(identifier) is not int or not 0 < identifier <= 2_147_483_647
                or not _text(name) or not _text(kind) or identifier in ids or name in names):
            raise ValueError
        slots.append(LinuxFieldSlotObservation(identifier, name, kind))
        ids.add(identifier)
        names.add(name)
        if len(slots) > 32:
            raise ValueError
        cursor = _skip_json_space(raw, finish)
        if cursor == end - 1:
            break
        if raw[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(raw, cursor + 1)
        if cursor >= end - 1:
            raise ValueError
    if not slots or cursor != end - 1:
        raise ValueError
    return tuple(slots)


def qualify_secret_approval_build29_linux_metadata(
    raw: bytearray, *, identity: Mapping[str, object], expected_serial: str,
) -> SecretApprovalBuild29LinuxMetadataObservation:
    """Consume a fixed native GET buffer and return only read-only observations."""
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= MAX_RESPONSE_BYTES
                or set(identity) != {"id", "name", "folder", "template", "target"}
                or any(type(identity[key]) is not int or not 0 < identity[key] <= 2_147_483_647  # type: ignore[operator]
                       for key in ("id", "folder"))
                or not all(_text(identity[key]) for key in ("name", "template", "target"))
                or identity["template"] != DEFAULT_TEMPLATE or not _text(expected_serial, 128)):
            raise ValueError
        slots = _observe_slots(raw)
        _redact_material_members(raw)
        _normalize_one_native_metadata_duplicate(raw)
        payload = json.loads(raw, object_pairs_hook=_unique, parse_constant=_reject_constant)
        if (type(payload) is not dict or set(payload) != set(_NATIVE_ENVELOPE) | {"serial", "results"}
                or any(type(payload.get(key)) is not type(value) or payload[key] != value
                       for key, value in _NATIVE_ENVELOPE.items())
                or payload["serial"] != expected_serial
                or type(payload["results"]) is not list or len(payload["results"]) != 1):
            raise ValueError
        row = payload["results"][0]
        if (type(row) is not dict or row.get("field") is not None
                or any(type(row.get(key)) is not type(value) or row[key] != value
                       for key, value in identity.items())):
            raise ValueError
        approval = tuple(row[key] for key in _FIELD_ORDER)
        if (any(type(value) is not str or value not in {"enable", "disable"} for value in approval[:3])
                or type(approval[3]) is not str
                or approval[3] != "" and not _text(approval[3], 79)):
            raise ValueError
        totp = row.get("totp-setting")
        if type(totp) is not dict or totp.get("status") not in {"enable", "disable"}:
            raise ValueError
        return SecretApprovalBuild29LinuxMetadataObservation(
            (approval[0], approval[1], approval[2], approval[3]),
            _preserved_metadata_digest(row), totp["status"] == "disable", slots,
        )
    except Exception:
        raise SecretApprovalBuild29LinuxMetadataError("Linux approval metadata observation is unavailable.") from None
    finally:
        if isinstance(raw, bytearray):
            _zeroize_mutable(raw)
