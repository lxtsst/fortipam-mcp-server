"""Private build-29 single-Web-Secret subscription contract; no dispatch.

Only the authenticated, privately bound owner can select the fixed entry-change
event. Enabling requires an unset email or an exact private recipient binding.
This compiler establishes neither backend
POST acceptance, notification delivery nor permission-loss behavior.
"""

from collections.abc import Mapping
from dataclasses import dataclass
import json
import re
from typing import Literal

from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES, _json_value_end, _skip_json_space,
)
from .secret_request_http_transport import _object_members

SUBSCRIPTION_PATH = "/api/v2/internal/subscribe"
Operation = Literal["subscribe", "restore"]
_UNAVAILABLE = "The fixed Secret event subscription is unavailable."
_ENVELOPE = {
    "version": "v7.0.0", "build": 29, "http_status": 200,
    "http_method": "GET", "path": "secret", "name": "database",
}
_FIELDS = frozenset({"id", "name", "folder", "template", "target", "subscriber"})
_EVENTS = frozenset({
    "pwd-chg", "pwd-vrf", "sec-cred-exp", "pwd-view", "cfg-chg", "sec-launch",
    "sec-checkin", "sec-checkout", "sec-cert", "sec-file-dl",
})


class SecretEventSubscriptionContractError(ValueError):
    """Never include selectors, emails or upstream response content."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretEventSubscriptionBinding:
    secret_id: int
    folder_id: int
    secret_name: str
    target_name: str
    owner_name: str


def project_subscription_detail(raw: bytearray) -> dict[str, object]:
    """Decode only selected metadata, skipping credential bytes entirely.

    The caller owns and zeroizes the raw buffer. A caller-supplied ``format``
    query is never relied upon to filter Secret material on build 29.
    """
    try:
        if type(raw) is not bytearray or not 0 < len(raw) <= MAX_RESPONSE_BYTES:
            raise ValueError
        start = _skip_json_space(raw, 0)
        end = _json_value_end(raw, start)
        if _skip_json_space(raw, end) != len(raw):
            raise ValueError
        spans = _object_members(raw, start, end, set(_ENVELOPE) | {"status", "results"})
        if set(spans) != set(_ENVELOPE) | {"status", "results"}:
            raise ValueError
        result = {key: json.loads(raw[a:b]) for key, (a, b) in spans.items() if key != "results"}
        _envelope(result)
        a, b = spans["results"]
        if raw[a] == 91:
            a = _skip_json_space(raw, a + 1)
            record_end = _json_value_end(raw, a)
            if _skip_json_space(raw, record_end) != b - 1:
                raise ValueError
            b = record_end
        fields = _object_members(raw, a, b, _FIELDS)
        if set(fields) != _FIELDS:
            raise ValueError
        result["results"] = {
            key: _subscribers(raw, a, b) if key == "subscriber" else json.loads(raw[a:b])
            for key, (a, b) in fields.items()
        }
        return result
    except Exception:
        raise SecretEventSubscriptionContractError(_UNAVAILABLE) from None


def _subscribers(raw: bytearray, start: int, end: int) -> list[dict[str, str]]:
    if raw[start] != 91 or raw[end - 1] != 93:
        raise ValueError
    cursor = _skip_json_space(raw, start + 1)
    rows: list[dict[str, str]] = []
    while cursor < end - 1:
        record_end = _json_value_end(raw, cursor)
        fields = _object_spans(raw, cursor, record_end)
        if set(fields) != {"name", "event"} or len(rows) >= 64:
            raise ValueError
        row: dict[str, str] = {}
        for key, (a, b) in fields.items():
            if raw[a] != 34 or b - a > 1600:
                raise ValueError
            value = json.loads(raw[a:b])
            if type(value) is not str:
                raise ValueError
            row[key] = value
        rows.append(row)
        cursor = _skip_json_space(raw, record_end)
        if cursor == end - 1:
            break
        if raw[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(raw, cursor + 1)
        if cursor >= end - 1:
            raise ValueError
    return rows


def _envelope(payload: Mapping[str, object]) -> None:
    if any(type(payload.get(k)) is not type(v) or payload.get(k) != v
           for k, v in _ENVELOPE.items()) or payload.get("status") not in {"OK", "success"}:
        raise ValueError


def project_subscription_portal(raw: bytearray) -> dict[str, object]:
    """Retain only source-named current-user identity/email, without credentials."""
    try:
        if type(raw) is not bytearray or not 0 < len(raw) <= MAX_RESPONSE_BYTES:
            raise ValueError
        start = _skip_json_space(raw, 0)
        end = _json_value_end(raw, start)
        if _skip_json_space(raw, end) != len(raw):
            raise ValueError
        root = _object_members(raw, start, end, {"results"})
        if set(root) != {"results"}:
            raise ValueError
        a, b = root["results"]
        fields = _object_members(raw, a, b, {"name", "email"})
        if set(fields) != {"name", "email"}:
            raise ValueError
        if any(raw[a] != 34 or b - a > 1600 for a, b in fields.values()):
            raise ValueError
        return {key: json.loads(raw[a:b]) for key, (a, b) in fields.items()}
    except Exception:
        raise SecretEventSubscriptionContractError(_UNAVAILABLE) from None


def _current(payload: object, binding: SecretEventSubscriptionBinding) -> tuple[Mapping[str, object], list[str]]:
    if type(binding) is not SecretEventSubscriptionBinding:
        raise ValueError
    if any(type(v) is not int or not 0 < v <= 2_147_483_647
           for v in (binding.secret_id, binding.folder_id)):
        raise ValueError
    if any(type(v) is not str or not v or len(v.encode()) > 255
           or any(ord(c) < 32 or ord(c) == 127 for c in v)
           for v in (binding.secret_name, binding.target_name, binding.owner_name)):
        raise ValueError
    if not isinstance(payload, Mapping):
        raise ValueError
    _envelope(payload)
    row = payload.get("results")
    if not isinstance(row, Mapping) or set(row) != _FIELDS:
        raise ValueError
    expected = {"id": binding.secret_id, "folder": binding.folder_id,
                "name": binding.secret_name, "template": "Web Account", "target": binding.target_name}
    if any(type(row.get(k)) is not type(v) or row.get(k) != v for k, v in expected.items()):
        raise ValueError
    subscribers = row.get("subscriber")
    if not isinstance(subscribers, list) or len(subscribers) > 64:
        raise ValueError
    names: set[str] = set()
    own: list[str] = []
    for subscriber in subscribers:
        if not isinstance(subscriber, Mapping) or set(subscriber) != {"name", "event"}:
            raise ValueError
        name, event = subscriber["name"], subscriber["event"]
        if (type(name) is not str or not name or name in names or len(name.encode()) > 255
                or any(ord(c) < 32 or ord(c) == 127 for c in name)
                or type(event) is not str or len(event) > 160):
            raise ValueError
        names.add(name)
        events = event.split(" ") if event else []
        if len(events) != len(set(events)) or not set(events) <= _EVENTS:
            raise ValueError
        if name == binding.owner_name:
            own = events
    return row, own


def compile_fixed_subscription(
    payload: object, portal: object, binding: SecretEventSubscriptionBinding, *, operation: Operation,
    expected_email: str = "",
) -> dict[str, object]:
    """Compile only disabled -> cfg-chg or that exact cfg-chg -> disabled.

    The fixed transport must verify the portal's authenticated identity and
    enabling email guard again immediately before its durable reservation.
    An email change cannot block removal of this exact temporary subscription.
    """
    try:
        validate_subscription_email_binding(expected_email)
        _, events = _current(payload, binding)
        if not isinstance(portal, Mapping) or set(portal) != {"name", "email"}:
            raise ValueError
        name, email = portal["name"], portal["email"]
        if (type(name) is not str or name != binding.owner_name
                or type(email) is not str or len(email) > 255
                or operation not in {"subscribe", "restore"}
                or operation == "subscribe" and email != expected_email
                or events != ([] if operation == "subscribe" else ["cfg-chg"])):
            raise ValueError
        return {"secret-id": binding.secret_id, "event": "cfg-chg" if operation == "subscribe" else ""}
    except Exception:
        raise SecretEventSubscriptionContractError(_UNAVAILABLE) from None


def validate_subscription_email_binding(value: str) -> None:
    """Accept an unset address or one bounded ASCII mailbox, never a list."""
    if type(value) is not str or len(value) > 254 or (value and re.fullmatch(
        r"[A-Za-z0-9_+-]+(?:\.[A-Za-z0-9_+-]+)*@"
        r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*(?:\.[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)+",
        value,
    ) is None):
        raise SecretEventSubscriptionContractError(_UNAVAILABLE)


def subscription_readback_matches(
    before: object, after: object, binding: SecretEventSubscriptionBinding, *, subscribed: bool,
) -> bool:
    """Check selected state and preserve every other projected subscriber.

    Restoration allows the backend to remove an empty current-owner row. It
    does not claim preservation of metadata outside this projection.
    """
    try:
        if type(subscribed) is not bool:
            return False
        old, old_events = _current(before, binding)
        new, new_events = _current(after, binding)
        if old_events != ([] if subscribed else ["cfg-chg"]) or new_events != (["cfg-chg"] if subscribed else []):
            return False
        def others(row: Mapping[str, object]) -> dict[str, str]:
            rows = row["subscriber"]
            assert isinstance(rows, list)
            return {r["name"]: r["event"] for r in rows if r["name"] != binding.owner_name}
        return others(old) == others(new)
    except Exception:
        return False
