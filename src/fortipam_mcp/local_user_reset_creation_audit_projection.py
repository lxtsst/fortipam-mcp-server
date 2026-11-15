"""Private, material-safe projection of one completed User creation event query.

This is a parser for a fixed reader, not a log-search tool or a provenance
receipt. The reader must bind the query to protected fixture and API identity
sources, verify the disk-log source, and clean up its own search session.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from v4_planning.material_provider import C3MaterialBinding

from .local_user_reset_metadata_reader import _validate_value
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import (
    _json_string_end, _json_value_end, _skip_json_space, _zeroize_mutable,
)

_NAME = re.compile(r"mcp-v4-user-reset-([0-9]{10})-[a-f0-9]{6}\Z")
_ACTOR = re.compile(r"[A-Za-z0-9_.@-]{1,128}\Z")
_MAX_BYTES = 1_048_576
_MAX_ROWS = 25
_MAX_WINDOW_MS = 48 * 60 * 60 * 1000
_UNAVAILABLE = "The private Local User creation audit projection is unavailable."


class LocalUserResetCreationAuditError(RuntimeError):
    """Fixed failure with no log or fixture values."""


@dataclass(frozen=True, slots=True, repr=False)
class LocalUserResetCreationAuditObservation(C3MaterialBinding):
    """One exact Add and no other returned action in a completed query."""

    creation_event_digest: str
    creation_timestamp_ms: int
    lifecycle_observed_through_ms: int


def _value(content: bytearray, span: tuple[int, int]) -> object:
    return json.loads(content[slice(*span)])


def _normalize_log_metadata_key(content: bytearray) -> None:
    """The log-only '#' key is outside the strict CMDB key grammar.

    Change only that complete object key to an ignored sentinel. A preexisting
    '_' key then collides and is rejected by the structural validator.
    """
    cursor = 0
    while cursor < len(content):
        if content[cursor] != 34:
            cursor += 1
            continue
        end = _json_string_end(content, cursor)
        separator = _skip_json_space(content, end + 1)
        if (content[cursor:end + 1] == b'"#"' and separator < len(content)
            and content[separator] == 58):
            content[cursor + 1] = 95
        cursor = end + 1


def project_local_user_reset_creation_audit(
    content: bytearray, *, username: str, api_actor: str,
    start_ms: int, end_ms: int,
) -> LocalUserResetCreationAuditObservation:
    """Consume a completed exact-object System Events response and clear it.

    The caller supplies the protected username and authenticated API actor,
    not an MCP argument. Only fixed event metadata is decoded. Configuration
    attributes, messages, and raw log fields never enter a decoded object.
    """
    try:
        match = _NAME.fullmatch(username) if isinstance(username, str) else None
        if (type(content) is not bytearray or not 0 < len(content) <= _MAX_BYTES
            or match is None or not isinstance(api_actor, str)
            or _ACTOR.fullmatch(api_actor) is None
            or type(start_ms) is not int or type(end_ms) is not int
            or start_ms < 0 or not start_ms < end_ms
            or end_ms - start_ms > _MAX_WINDOW_MS
            or not start_ms <= (int(match.group(1)) - 60) * 1000
            or end_ms < int(match.group(1)) * 1000):
            raise ValueError
        left = _skip_json_space(content, 0)
        right = _json_value_end(content, left)
        if _skip_json_space(content, right) != len(content):
            raise ValueError
        _normalize_log_metadata_key(content)
        _validate_value(content, left, right, depth=0)
        root = _object_spans(content, left, right)
        for key in ("completed", "session_id", "total_lines", "results"):
            if key not in root:
                raise ValueError
        completed = _value(content, root["completed"])
        if type(completed) not in {int, float} or completed != 100:
            raise ValueError
        session = _value(content, root["session_id"])
        if isinstance(session, str) and re.fullmatch(r"[1-9][0-9]{0,15}", session):
            session = int(session)
        if type(session) is not int or not 0 < session <= 9_007_199_254_740_991:
            raise ValueError
        if "rows" in root:
            rows = _value(content, root["rows"])
            if type(rows) is not int or not 1 <= rows <= _MAX_ROWS:
                raise ValueError
        results_start, results_end = root["results"]
        if content[results_start] != 91 or content[results_end - 1] != 93:
            raise ValueError
        row_start = _skip_json_space(content, results_start + 1)
        row_end = _json_value_end(content, row_start)
        if _skip_json_space(content, row_end) != results_end - 1:
            raise ValueError
        row = _object_spans(content, row_start, row_end)
        required = {"cfgobj", "cfgpath", "action", "user", "subtype", "_metadata"}
        if not required <= row.keys():
            raise ValueError
        for key, expected in (
            ("cfgobj", username), ("cfgpath", "system.admin"),
            ("subtype", "system"),
            ("action", "Add"), ("user", api_actor),
        ):
            if _value(content, row[key]) != expected:
                raise ValueError
        metadata = _object_spans(content, *row["_metadata"])
        if "timestamp" not in metadata:
            raise ValueError
        timestamp = _value(content, metadata["timestamp"])
        created_ms = int(match.group(1)) * 1000
        if (type(timestamp) is not int or not start_ms <= timestamp <= end_ms
            or not created_ms - 60_000 <= timestamp <= created_ms + 600_000):
            raise ValueError
        total = _value(content, root["total_lines"])
        if type(total) is not int or total != 1:
            raise ValueError
        if "logid" in row:
            logid = _value(content, row["logid"])
            if ((type(logid) is not int or logid < 0)
                and (not isinstance(logid, str) or len(logid) > 64)):
                raise ValueError
        else:
            logid = None
        payload = ["bp002-create-event-build29/v1", username, api_actor,
                   timestamp, logid]
        digest = hashlib.sha256(json.dumps(
            payload, separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii")).hexdigest()
        return LocalUserResetCreationAuditObservation(digest, timestamp, end_ms)
    except Exception:
        raise LocalUserResetCreationAuditError(_UNAVAILABLE) from None
    finally:
        if isinstance(content, bytearray):
            _zeroize_mutable(content)
