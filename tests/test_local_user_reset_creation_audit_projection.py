"""Synthetic checks for the private BP002 creation-event projection."""

from __future__ import annotations

import json

import pytest

from fortipam_mcp.local_user_reset_creation_audit_projection import (
    LocalUserResetCreationAuditError, project_local_user_reset_creation_audit,
)

CREATED = 1_790_000_000
NAME = f"mcp-v4-user-reset-{CREATED}-abcdef"
ACTOR = "synthetic-api-actor"
START = (CREATED - 60) * 1000
END = (CREATED + 600) * 1000


def _response(*, row_changes: dict | None = None, root_changes: dict | None = None,
              extra_rows: list[dict] | None = None) -> bytearray:
    row = {
        "#": 1,
        "cfgobj": NAME,
        "cfgpath": "system.admin",
        "subtype": "system",
        "action": "Add",
        "user": ACTOR,
        "ui": "unknown-channel",
        "eventtime": "synthetic-time",
        "logid": "synthetic-log-id",
        "_metadata": {"timestamp": CREATED * 1000},
        "cfgattr": "private_password_material_should_not_be_decoded",
        "msg": "private_message_should_not_be_decoded",
    }
    row.update(row_changes or {})
    rows = [row, *(extra_rows or [])]
    root = {"completed": 100, "session_id": 7, "rows": 25,
            "total_lines": len(rows), "results": rows}
    root.update(root_changes or {})
    return bytearray(json.dumps(root, separators=(",", ":")).encode("utf-8"))


def _project(content: bytearray):
    return project_local_user_reset_creation_audit(
        content, username=NAME, api_actor=ACTOR, start_ms=START, end_ms=END,
    )


def test_one_creation_event_is_stable_and_erases_raw_log() -> None:
    first = _response()
    observation = _project(first)
    assert len(observation.creation_event_digest) == 64
    assert observation.creation_timestamp_ms == CREATED * 1000
    assert observation.lifecycle_observed_through_ms == END
    assert not first

    second = _response(root_changes={"session_id": "8"})
    assert _project(second).creation_event_digest == observation.creation_event_digest
    assert not second


@pytest.mark.parametrize("row_changes", [
    {"cfgobj": "another-user"}, {"cfgpath": "system.api-user"},
    {"action": "Edit"}, {"user": "another-actor"},
    {"_metadata": {"timestamp": START - 1}},
    {"_metadata": {"timestamp": (CREATED + 601) * 1000}},
    {"_metadata": {}}, {"cfgobj": None},
])
def test_rejects_wrong_event_or_window(row_changes: dict) -> None:
    content = _response(row_changes=row_changes)
    with pytest.raises(LocalUserResetCreationAuditError):
        _project(content)
    assert not content


@pytest.mark.parametrize("root_changes", [
    {"completed": 80}, {"completed": True}, {"session_id": "bad"},
    {"total_lines": 2}, {"rows": 26}, {"results": []},
])
def test_rejects_incomplete_or_truncated_query(root_changes: dict) -> None:
    content = _response(root_changes=root_changes)
    with pytest.raises(LocalUserResetCreationAuditError):
        _project(content)
    assert not content


def test_rejects_later_action_and_duplicate_log_metadata_key() -> None:
    content = _response(extra_rows=[{"cfgobj": NAME, "cfgpath": "system.admin",
                                     "action": "Delete", "user": ACTOR}])
    with pytest.raises(LocalUserResetCreationAuditError):
        _project(content)
    assert not content

    content = _response()
    text = content.decode().replace('"total_lines":1,', "")
    missing_total = bytearray(text.encode())
    with pytest.raises(LocalUserResetCreationAuditError):
        _project(missing_total)
    assert not missing_total

    content = _response(row_changes={"_": "already-used"})
    with pytest.raises(LocalUserResetCreationAuditError):
        _project(content)
    assert not content


def test_log_material_values_are_never_decoded(monkeypatch: pytest.MonkeyPatch) -> None:
    original = json.loads
    decoded: list[bytes] = []

    def recording_loads(value, *args, **kwargs):
        decoded.append(bytes(value) if isinstance(value, (bytes, bytearray, memoryview))
                       else str(value).encode())
        return original(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", recording_loads)
    content = _response()
    _project(content)
    assert not content
    assert not any(b"private_password_material" in value or b"private_message" in value
                   for value in decoded)
