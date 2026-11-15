"""Private build-29 withdrawal post-state witness, without write authority.

The fixed source transition is approved -> pending, cleared Launcher times and
empty tier1. The observed native marker either resets to0 or remains integer1;
neither marker is approval or access evidence. The bounded opaque response
revision may change; both actual revisions remain bound by the metadata digests.
All other envelope and row metadata must be preserved. This proves a metadata transition only, never a DELETE ACK,
backend launch denial, original creation continuity, or execution authority.
Both same-session device Dates must be fresh and inside the original window.
Historical evidence must use a separately scoped reconciliation contract; do
not replace the process clock or relabel retained device Dates as current.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Any

from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES, _json_value_end, _redact_json_field_values,
    _skip_json_space, _zeroize_mutable,
)
from .secret_approval_build29_http_transport import (
    _raw_members, _redact_material_members, _validate_ack_json,
)
from .secret_request_approval_revoke_contract import (
    secret_request_approval_revoke_launcher_window_available,
)
from .secret_request_approval_revoke_detail_contract import (
    SecretRequestApprovalRevokeDetailBinding, _digest, _reject_constant,
    _reject_raw_duplicates, _unique_members,
    qualify_secret_request_approval_revoke_get_detail,
)

_UNAVAILABLE = "The fixed Launcher Request withdrawal post-state is unavailable."
_CONTRACT = "secret-request-approval-revoke-build29-post-state-v3"
_CLEARED_TIME = "0000-00-00 00:00:00"
_EXPECTED_POST: dict[str, object] = {
    "start-time": _CLEARED_TIME, "expiration-time": _CLEARED_TIME,
    "final-status": "pending", "tier1-status": "pending", "tier1": [],
}
_TRANSITION_FIELDS = frozenset(_EXPECTED_POST) | {"tier-last-sent"}


class SecretRequestApprovalRevokePostContractError(ValueError):
    """Stable refusal without private identifiers or upstream exception text."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestApprovalRevokePostWitness:
    """Private immutable evidence digests; not an authorization or permit."""

    private_binding_digest: str
    private_pre_metadata_digest: str
    private_post_metadata_digest: str
    private_transition_digest: str


def qualify_secret_request_approval_revoke_post_state(
    pre_native_json: bytes | bytearray,
    post_native_json: bytes | bytearray,
    *, binding: SecretRequestApprovalRevokeDetailBinding,
    authenticated_reviewer: str,
    pre_server_time: datetime | None,
    post_server_time: datetime | None,
) -> SecretRequestApprovalRevokePostWitness:
    """Qualify fresh fixed GETs around one withdrawal, returning no raw values.

    Trusted caller establishes actual session, reviewer and device Date provenance.
    Raw scalar token equality additionally preserves redacted fields without ever
    decoding their values. Alternate scalar encodings conservatively fail closed.
    """
    try:
        before_witness = qualify_secret_request_approval_revoke_get_detail(
            pre_native_json, binding=binding, authenticated_reviewer=authenticated_reviewer,
            server_time=pre_server_time,
        )
        if (not isinstance(pre_server_time, datetime)
                or not isinstance(post_server_time, datetime)
                or pre_server_time.utcoffset() is None
                or post_server_time.utcoffset() is None
                or post_server_time < pre_server_time):
            raise ValueError
        before, before_preserved = _read_metadata(pre_native_json)
        after, after_preserved = _read_metadata(post_native_json)
        pre_row, post_row = before["results"][0], after["results"][0]
        if (set(before) != set(after)
                or type(after.get("revision")) is not str or not after["revision"]
                or len(after["revision"].encode("utf-8")) > 128
                or set(pre_row) != set(post_row)
                or type(pre_row.get("tier-last-sent")) is not int
                or pre_row["tier-last-sent"] != 1
                or any(type(pre_row.get(key)) is not str or pre_row[key] != "pending"
                       for key in ("tier2-status", "tier3-status"))
                or type(post_row.get("tier-last-sent")) is not int
                or post_row["tier-last-sent"] not in {0, 1}
                or any(type(post_row.get(key)) is not type(value) or post_row[key] != value
                       for key, value in _EXPECTED_POST.items())
                or before_preserved != after_preserved):
            raise ValueError
        if not secret_request_approval_revoke_launcher_window_available(
            {key: pre_row[key] for key in ("start-time", "expiration-time", "timezone")},
            server_time=post_server_time,
        ):
            raise ValueError
        post_digest = _digest(after)
        return SecretRequestApprovalRevokePostWitness(
            private_binding_digest=before_witness.private_binding_digest,
            private_pre_metadata_digest=before_witness.private_native_metadata_digest,
            private_post_metadata_digest=post_digest,
            private_transition_digest=_digest({
                "contract": _CONTRACT, "binding": before_witness.private_binding_digest,
                "pre": before_witness.private_native_metadata_digest, "post": post_digest,
                "preserved": before_preserved,
                "pre_date": pre_server_time.astimezone(timezone.utc).isoformat(),
                "post_date": post_server_time.astimezone(timezone.utc).isoformat(),
            }),
        )
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError, RuntimeError, IndexError, OSError):
        raise SecretRequestApprovalRevokePostContractError(_UNAVAILABLE) from None


def _read_metadata(native: bytes | bytearray) -> tuple[dict[str, Any], str]:
    if type(native) not in (bytes, bytearray) or not 0 < len(native) <= MAX_RESPONSE_BYTES:
        raise ValueError
    raw = bytearray(native)
    try:
        start = _skip_json_space(raw, 0)
        end = _json_value_end(raw, start)
        if raw[start] != 123 or _skip_json_space(raw, end) != len(raw):
            raise ValueError
        _validate_ack_json(raw, start, end)
        _reject_raw_duplicates(raw, start, end)
        preserved = {}
        for key, _, left, right, _ in _raw_members(raw, start, end):
            if key != "results":
                # Original native pre/post sources have different revisions.
                # Identity and every other envelope token still require equality;
                # revision shape and both actual metadata digests are checked above.
                if key != "revision":
                    preserved[key] = _token_digest(raw, left, right)
                continue
            if raw[left] != 91:
                raise ValueError
            row_start = _skip_json_space(raw, left + 1)
            row_end = _json_value_end(raw, row_start)
            if raw[row_start] != 123 or _skip_json_space(raw, row_end) != right - 1:
                raise ValueError
            preserved[key] = _digest({
                member: _token_digest(raw, first, last)
                for member, _, first, last, _ in _raw_members(raw, row_start, row_end)
                if member not in _TRANSITION_FIELDS
            })
        _redact_json_field_values(raw)
        _redact_material_members(raw)
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_members,
                             parse_constant=_reject_constant)
        return payload, _digest(preserved)
    finally:
        _zeroize_mutable(raw)


def _token_digest(raw: bytearray, start: int, end: int) -> str:
    """Hash bounded validated syntax; decode object keys only, never values."""
    if raw[start] == 123:
        return _digest({
            key: _token_digest(raw, left, right)
            for key, _, left, right, _ in _raw_members(raw, start, end)
        })
    if raw[start] == 91:
        items = []
        cursor = _skip_json_space(raw, start + 1)
        while cursor < end - 1:
            right = _json_value_end(raw, cursor)
            items.append(_token_digest(raw, cursor, right))
            cursor = _skip_json_space(raw, right)
            if cursor < end - 1:
                cursor = _skip_json_space(raw, cursor + 1)
        return _digest(items)
    return hashlib.sha256(memoryview(raw)[start:end]).hexdigest()
