"""Private bounded projection of one completed build-29 secret-file query.

The caller owns the fixed query, authenticated actor and search-session cleanup.
This projection establishes neither DLP enforcement nor a file/session join.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Literal

from .local_user_reset_creation_audit_projection import _normalize_log_metadata_key
from .local_user_reset_metadata_reader import _validate_value
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable

_MAX_BYTES = 1_048_576
_MAX_ROWS = 25
_MAX_WINDOW_MS = 24 * 60 * 60 * 1000
_UINT32_MAX = 4_294_967_295
_ACTOR = re.compile(r"[A-Za-z0-9_.@-]{1,128}\Z")
_APPTYPES = frozenset({
    "rdp", "ssh", "vnc", "sqlserver", "ot-client", "web", "web-rdp", "web-ssh",
    "web-telnet", "web-vnc", "web-sftp", "web-smb", "other", "ssh-pwd", "ssh-key",
    "samba", "ad-ldap", "open-ldap",
})
_ACTIONS = frozenset({
    "accepted", "denied", "failed", "secret-checkin", "secret-revoke", "approval-expired",
    "sch-exceeded", "max-duration", "kick-out", "video-stopped", "token-timeout",
    "secret-connect", "video-start", "video-finish", "initial-state", "success",
    "connection-error", "login-auth-error", "changer-error", "job-error", "script-error",
    "parameter-error", "temporary-error", "pwd-chg-not-enabled", "internel-error",
    "loop-error", "dn-not-found", "dn-found", "pass", "resp", "wait", "updating",
    "succeeded", "upload", "download", "delete", "update",
})
_OPERATIONS = frozenset({
    "start", "fetching", "setup", "uploading", "video-finished", "connection-start",
    "connection-close", "start-watch-video", "stop-watch-video", "download-video",
    "password-change", "password-verification", "password-recovery", "job-execution",
    "checkout", "checkin", "renew", "clear-text-view", "request", "approve", "deny",
    "approval-revoke", "script", "dependency-check", "dependency-update",
    "dependency-update-check", "certificate-expiring", "certificate-expired",
    "appfilter-enforce", "appfilter-deforce", "appfilter-check", "appfilter-purgeall",
    "subscribe", "invite", "revoke", "upload-file", "download-file", "delete-file",
    "delete-orphan-file", "delete-aged-file", "file-not-found", "secret-cred-expiring",
    "secret-cred-expired",
})
_UNAVAILABLE = "The private Secret file audit projection is unavailable."


class SecretFileAuditProjectionError(RuntimeError):
    """Fixed failure without query, actor, event or material values."""


@dataclass(frozen=True, slots=True)
class SecretFileAuditObservation:
    """Only counts and categorical evidence from an exact completed query."""

    query_completed: bool
    query_handle_qualified: bool
    returned_event_count: int
    web_sftp_event_count: int
    upload_event_count: int
    download_event_count: int
    delete_event_count: int
    event_session_binding_present_count: int
    file_session_correlation: Literal["unproven"] = "unproven"


def _scalar(content: bytearray, span: tuple[int, int]) -> object:
    left, right = span
    # Never decode a container, including a container injected into metadata.
    if right - left > 1024 or content[left] in (123, 91):
        raise ValueError
    return json.loads(content[left:right])


def _enum(content: bytearray, span: tuple[int, int], allowed: frozenset[str]) -> str:
    value = _scalar(content, span)
    if type(value) is not str or value not in allowed:
        raise ValueError
    return value


def _row_spans(content: bytearray, span: tuple[int, int]) -> tuple[tuple[int, int], ...]:
    left, right = span
    if content[left] != 91 or content[right - 1] != 93:
        raise ValueError
    cursor = _skip_json_space(content, left + 1)
    rows: list[tuple[int, int]] = []
    while cursor < right - 1:
        if len(rows) >= _MAX_ROWS or content[cursor] != 123:
            raise ValueError
        end = _json_value_end(content, cursor)
        if end >= right:
            raise ValueError
        rows.append((cursor, end))
        cursor = _skip_json_space(content, end)
        if cursor == right - 1:
            break
        if content[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(content, cursor + 1)
        if cursor >= right - 1:
            raise ValueError
    return tuple(rows)


def project_secret_file_audit(
    content: bytearray, *, expected_secret_id: int, expected_actor: str,
    start_ms: int, end_ms: int,
) -> SecretFileAuditObservation:
    """Consume and erase one exact completed page without decoding raw logs."""
    try:
        if (type(content) is not bytearray or not 0 < len(content) <= _MAX_BYTES
            or type(expected_secret_id) is not int or not 0 < expected_secret_id <= _UINT32_MAX
            or type(expected_actor) is not str or _ACTOR.fullmatch(expected_actor) is None
            or type(start_ms) is not int or type(end_ms) is not int
            or not 0 <= start_ms < end_ms <= 9_223_372_036_854_775_807
            or end_ms - start_ms > _MAX_WINDOW_MS):
            raise ValueError
        left = _skip_json_space(content, 0)
        right = _json_value_end(content, left)
        if _skip_json_space(content, right) != len(content):
            raise ValueError
        _normalize_log_metadata_key(content)
        _validate_value(content, left, right, depth=0)
        root = _object_spans(content, left, right)
        if not {"completed", "session_id", "total_lines", "results"} <= root.keys():
            raise ValueError
        completed = _scalar(content, root["completed"])
        if type(completed) not in {int, float} or completed != 100:
            raise ValueError
        query_handle = _scalar(content, root["session_id"])
        if type(query_handle) is str and re.fullmatch(r"[1-9][0-9]{0,15}", query_handle):
            query_handle = int(query_handle)
        if type(query_handle) is not int or not 0 < query_handle <= 9_007_199_254_740_991:
            raise ValueError
        if "rows" in root:
            page_size = _scalar(content, root["rows"])
            if type(page_size) is not int or not 1 <= page_size <= _MAX_ROWS:
                raise ValueError
        rows = _row_spans(content, root["results"])
        total = _scalar(content, root["total_lines"])
        if type(total) is not int or total != len(rows) or not 0 <= total <= _MAX_ROWS:
            raise ValueError
        web_sftp = upload = download = delete = session_present = 0
        for span in rows:
            row = _object_spans(content, *span)
            if not {"secretid", "user", "subtype", "apptype", "action", "operation",
                    "sessionid", "_metadata"} <= row.keys():
                raise ValueError
            secret_id = _scalar(content, row["secretid"])
            if type(secret_id) is not int or secret_id != expected_secret_id:
                raise ValueError
            if (_scalar(content, row["user"]) != expected_actor
                or _scalar(content, row["subtype"]) != "secret-file"):
                raise ValueError
            metadata = _object_spans(content, *row["_metadata"])
            if "timestamp" not in metadata:
                raise ValueError
            timestamp = _scalar(content, metadata["timestamp"])
            if type(timestamp) is not int or not start_ms <= timestamp <= end_ms:
                raise ValueError
            apptype = _enum(content, row["apptype"], _APPTYPES)
            action = _enum(content, row["action"], _ACTIONS)
            _enum(content, row["operation"], _OPERATIONS)
            session_id = _scalar(content, row["sessionid"])
            if type(session_id) is not int or not 0 <= session_id <= _UINT32_MAX:
                raise ValueError
            uuid: object = ""
            if "uuid" in row:
                uuid = _scalar(content, row["uuid"])
                if type(uuid) is not str or re.fullmatch(r"[!-~]{0,128}", uuid) is None:
                    raise ValueError
            web_sftp += int(apptype == "web-sftp")
            upload += int(action == "upload")
            download += int(action == "download")
            delete += int(action == "delete")
            session_present += int(session_id > 0 and bool(uuid))
        return SecretFileAuditObservation(True, True, len(rows), web_sftp, upload,
                                          download, delete, session_present)
    except Exception:
        raise SecretFileAuditProjectionError(_UNAVAILABLE) from None
    finally:
        if isinstance(content, bytearray):
            _zeroize_mutable(content)
