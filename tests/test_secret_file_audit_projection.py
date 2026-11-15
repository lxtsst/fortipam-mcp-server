"""Synthetic bounded checks; no device logs or material fixtures."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, asdict
import json
from typing import Any

import pytest

from fortipam_mcp.secret_file_audit_projection import (
    SecretFileAuditObservation, SecretFileAuditProjectionError, project_secret_file_audit,
)

SECRET_ID = 42
ACTOR = "synthetic-owner"
START = 1_790_000_000_000
END = START + 60_000


def _row(**changes: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "#": 1, "secretid": SECRET_ID, "user": ACTOR, "subtype": "secret-file",
        "apptype": "web-sftp", "action": "upload", "operation": "upload-file",
        "sessionid": 123, "uuid": "synthetic-uuid", "_metadata": {"timestamp": START},
        "msg": "opaque_message_marker", "log": "opaque_log_marker",
        "raw": {"content": "opaque_content_marker"}, "filename": "opaque_filename_marker",
        "content": "opaque_content_marker", "C3": "opaque_material_marker",
    }
    result.update(changes)
    return result


def _response(events: list[dict[str, Any]] | None = None, **changes: Any) -> bytearray:
    events = [_row()] if events is None else events
    root: dict[str, Any] = {"completed": 100, "session_id": 7, "rows": 25,
                           "total_lines": len(events), "results": events}
    root.update(changes)
    return bytearray(json.dumps(root, separators=(",", ":")).encode())


def _project(content: bytearray, **changes: Any) -> SecretFileAuditObservation:
    args: dict[str, Any] = {"expected_secret_id": SECRET_ID, "expected_actor": ACTOR,
                            "start_ms": START, "end_ms": END}
    args.update(changes)
    return project_secret_file_audit(content, **args)


def test_complete_page_is_immutable_counts_only_and_always_unproven() -> None:
    content = _response([_row(), _row(action="download", operation="download-file", uuid=""),
                         _row(action="delete", operation="delete-file", apptype="ssh", sessionid=0)])
    observation = _project(content)
    assert not content
    assert asdict(observation) == {
        "query_completed": True, "query_handle_qualified": True, "returned_event_count": 3,
        "web_sftp_event_count": 2, "upload_event_count": 1, "download_event_count": 1,
        "delete_event_count": 1, "event_session_binding_present_count": 1,
        "file_session_correlation": "unproven",
    }
    assert ACTOR not in repr(observation) and "synthetic-uuid" not in repr(observation)
    with pytest.raises(FrozenInstanceError):
        setattr(observation, "returned_event_count", 0)


def test_empty_complete_query_is_zero_events_without_functionality_inference() -> None:
    content = _response([], session_id="8")
    observation = _project(content)
    assert not content and observation.query_completed and observation.query_handle_qualified
    assert observation.returned_event_count == observation.web_sftp_event_count == 0
    assert observation.file_session_correlation == "unproven"


def test_missing_optional_uuid_is_unproven_and_25_rows_are_accepted() -> None:
    row = _row()
    del row["uuid"]
    content = _response([row] * 25)
    observation = _project(content)
    assert not content and observation.returned_event_count == 25
    assert observation.event_session_binding_present_count == 0


@pytest.mark.parametrize("changes", [
    {"completed": 99}, {"completed": True}, {"session_id": 0}, {"session_id": True},
    {"session_id": "07"}, {"session_id": "unqualified"}, {"session_id": 9_007_199_254_740_992},
    {"rows": 0}, {"rows": 26}, {"rows": True}, {"total_lines": 0},
    {"total_lines": True}, {"total_lines": 26}, {"results": {}}, {"results": [None]},
])
def test_incomplete_query_or_wrong_root_types_fail_and_wipe(changes: dict[str, Any]) -> None:
    content = _response(**changes)
    with pytest.raises(SecretFileAuditProjectionError, match="unavailable"):
        _project(content)
    assert not content


@pytest.mark.parametrize("changes", [
    {"secretid": SECRET_ID + 1}, {"secretid": str(SECRET_ID)}, {"secretid": True},
    {"user": "other-actor"}, {"subtype": "secret"}, {"_metadata": {}},
    {"_metadata": {"timestamp": START - 1}}, {"_metadata": {"timestamp": END + 1}},
    {"_metadata": {"timestamp": True}}, {"apptype": "unsafe arbitrary text"},
    {"action": "unknown"}, {"operation": "unknown"}, {"apptype": {"content": "opaque_marker"}},
    {"sessionid": -1}, {"sessionid": 4_294_967_296}, {"sessionid": "123"},
    {"sessionid": True}, {"uuid": 7}, {"uuid": "bad\nvalue"}, {"uuid": "x" * 129},
])
def test_event_drift_wrong_types_or_unknown_enums_fail_and_wipe(changes: dict[str, Any]) -> None:
    content = _response([_row(**changes)])
    with pytest.raises(SecretFileAuditProjectionError):
        _project(content)
    assert not content


@pytest.mark.parametrize("changes", [
    {"expected_secret_id": True}, {"expected_secret_id": 0}, {"expected_secret_id": 4_294_967_296},
    {"expected_actor": "bad\nactor"}, {"start_ms": True}, {"start_ms": -1},
    {"end_ms": START}, {"end_ms": START + 86_400_001},
])
def test_invalid_private_bindings_wipe(changes: dict[str, Any]) -> None:
    content = _response()
    with pytest.raises(SecretFileAuditProjectionError):
        _project(content, **changes)
    assert not content


@pytest.mark.parametrize("fault", ["extra_row", "oversize", "missing_key", "duplicate_root",
                                     "duplicate_row", "duplicate_timestamp", "normalized_collision",
                                     "trailing", "trailing_comma"])
def test_limits_duplicate_keys_and_malformed_pages_fail_and_wipe(fault: str) -> None:
    content = _response()
    if fault == "extra_row": content = _response([_row()] * 26)
    elif fault == "oversize": content.extend(b" " * 1_048_576)
    elif fault == "missing_key": content = bytearray(content.replace(b'"secretid":42,', b"", 1))
    elif fault == "duplicate_root": content = bytearray(content.replace(b'"completed":100', b'"completed":100,"completed":100', 1))
    elif fault == "duplicate_row": content = bytearray(content.replace(b'"secretid":42', b'"secretid":42,"secretid":42', 1))
    elif fault == "duplicate_timestamp": content = bytearray(content.replace(b'"timestamp":', b'"timestamp":1,"timestamp":', 1))
    elif fault == "normalized_collision": content = _response([_row(_="collision")])
    elif fault == "trailing": content.extend(b"{}")
    elif fault == "trailing_comma": content = bytearray(content.replace(b'}]}', b'},]}', 1))
    with pytest.raises(SecretFileAuditProjectionError):
        _project(content)
    assert not content


def test_only_fixed_scalar_values_are_decoded_and_decoder_failure_wipes(monkeypatch: pytest.MonkeyPatch) -> None:
    original = json.loads
    decoded: list[bytes] = []

    def recording(value: Any, *args: Any, **kwargs: Any) -> Any:
        token = bytes(value) if isinstance(value, (bytes, bytearray, memoryview)) else str(value).encode()
        decoded.append(token)
        return original(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", recording)
    content = _response()
    _project(content)
    assert not content
    assert not any(b"opaque_" in value or value.startswith((b"{", b"[")) for value in decoded)

    def fail(value: Any, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("synthetic private decoder error")

    monkeypatch.setattr(json, "loads", fail)
    content = _response()
    with pytest.raises(SecretFileAuditProjectionError, match="unavailable"):
        _project(content)
    assert not content
