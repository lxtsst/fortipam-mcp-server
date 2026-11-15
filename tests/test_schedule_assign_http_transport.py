from __future__ import annotations

import json
from pathlib import Path

import pytest

import fortipam_mcp.schedule_assign_http_transport as transport_module
from fortipam_mcp.schedule_assign_http_transport import (
    FIXED_DETACH_ROLE,
    FortiPamScheduleAssignHttpTransport,
    ScheduleAssignHttpTransportConfig,
    ScheduleAssignHttpTransportConfigurationError,
    ScheduleAssignHttpTransportError,
    load_schedule_assign_http_transport_config,
    _mapping_digest,
    _mapping_digest_without_key,
)
from fortipam_mcp.schedule_ssh_transport import ScheduleReadback


USER = "mcp-v4-user-b57"
SCHEDULE = "mcp-v4-schedule-b66"


class _Response:
    def __init__(self, status_code: int, payload: object) -> None:
        self.status_code = status_code
        self.content = json.dumps(payload).encode("utf-8")
        self.headers = {"content-type": "application/json"}


class _Client:
    def __init__(self, responses: list[_Response], calls: list[dict[str, object]]) -> None:
        self._responses = responses
        self._calls = calls

    def __enter__(self) -> "_Client":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def request(self, method: str, url: str, **kwargs: object) -> _Response:
        self._calls.append({"method": method, "url": url, **kwargs})
        return self._responses.pop(0)


def _config() -> ScheduleAssignHttpTransportConfig:
    return ScheduleAssignHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _user(schedule: str = "") -> dict[str, object]:
    return {
        "id": 57,
        "name": USER,
        "display-name": "Laboratory User",
        "status": "disable",
        "wildcard": "disable",
        "remote-auth": "disable",
        "remote-server": "",
        "remote-group": "",
        "force-saml-login": "disable",
        "accprofile": "mcp-v4-role-b76a",
        "comments": "retained",
        "trusthost1": "0.0.0.0 0.0.0.0",
        "schedule": schedule,
        "two-factor": "disable",
        "password": "ENC protected-placeholder",
        "history0": "protected-history",
        "q_ref": 1,
    }


def _schedule() -> dict[str, object]:
    return {
        "name": SCHEDULE,
        "start": "01:00",
        "end": "01:30",
        "day": "monday",
        "color": 0,
    }


class _ScheduleSsh:
    def __init__(self) -> None:
        self.calls = 0

    def readback_existing(self, schedule_name: str) -> ScheduleReadback:
        assert schedule_name == SCHEDULE
        self.calls += 1
        return ScheduleReadback(True, True, True, True, True)


def _fixed_digests(
    monkeypatch: pytest.MonkeyPatch,
    user: dict[str, object],
    schedule: dict[str, object],
) -> None:
    monkeypatch.setattr(transport_module, "FIXED_USER_RECORD_DIGEST", _mapping_digest(user))
    monkeypatch.setattr(
        transport_module,
        "FIXED_USER_NON_SCHEDULE_DIGEST",
        _mapping_digest_without_key(user, "schedule"),
    )
    monkeypatch.setattr(
        transport_module,
        "FIXED_SCHEDULE_RECORD_DIGEST",
        _mapping_digest(schedule),
    )


def test_loader_requires_dedicated_owner_only_token_file(tmp_path: Path) -> None:
    token = tmp_path / "token"
    token.write_text("unit-test-token\n", encoding="utf-8")
    token.chmod(0o600)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_SCHEDULE_ASSIGN_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_SCHEDULE_ASSIGN_BASE_URL": "https://fpa.example.test",
        "FPA_HOME_LAB_FPA1_V4_SCHEDULE_ASSIGN_API_TOKEN_FILE": str(token),
        "FPA_HOME_LAB_FPA1_V4_SCHEDULE_ASSIGN_TIMEOUT_SECONDS": "12",
    }

    loaded = load_schedule_assign_http_transport_config(environment)

    assert loaded.base_url == "https://fpa.example.test"
    assert loaded.timeout_seconds == 12
    token.chmod(0o640)
    with pytest.raises(ScheduleAssignHttpTransportConfigurationError, match="owner-only"):
        load_schedule_assign_http_transport_config(environment)


def test_inspection_returns_only_categorical_pair_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, {"results": [_user()]}),
        _Response(200, {"results": [_schedule()]}),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamScheduleAssignHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    inspection = transport.inspect_assignment(USER, SCHEDULE)

    assert inspection.user_exists is True
    assert inspection.schedule_exists is True
    assert inspection.user_disabled is True
    assert inspection.user_local is True
    assert inspection.schedule_unassigned is True
    assert all(
        len(value) == 64
        for value in (
            inspection.user_non_schedule_state_digest,
            inspection.schedule_state_digest,
            inspection.state_digest,
        )
    )
    assert "protected" not in repr(inspection)
    assert [call["method"] for call in calls] == ["GET", "GET"]


def test_assignment_uses_product_projection_and_proves_preservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    baseline_user = _user()
    baseline_schedule = _schedule()
    responses = [
        _Response(200, {"results": [baseline_user]}),
        _Response(200, {"results": [baseline_schedule]}),
        _Response(200, {"results": [baseline_user]}),
        _Response(200, {"results": [baseline_schedule]}),
        _Response(200, {"http_status": 200}),
        _Response(200, {"results": [baseline_user | {"schedule": SCHEDULE}]}),
        _Response(200, {"results": [baseline_schedule]}),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamScheduleAssignHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )
    inspection = transport.inspect_assignment(USER, SCHEDULE)

    readback = transport.assign_and_readback(
        USER,
        SCHEDULE,
        user_non_schedule_state_digest=inspection.user_non_schedule_state_digest,
        schedule_state_digest=inspection.schedule_state_digest,
    )

    assert readback.verified is True
    put = calls[4]
    assert put["method"] == "PUT"
    assert put["url"] == f"https://fpa.example.test/api/v2/cmdb/system/admin/{USER}"
    body = put["json"]
    assert isinstance(body, dict)
    assert body["$originalName"] == USER
    assert body["name"] == USER
    assert body["id"] == 57
    assert body["schedule"] == SCHEDULE
    assert body["status"] == "disable"
    assert body["accprofile"] == "mcp-v4-role-b76a"
    assert body["comments"] == "retained"
    assert "password" not in body
    assert "history0" not in body
    assert "q_ref" not in body
    assert [call["method"] for call in calls] == [
        "GET",
        "GET",
        "GET",
        "GET",
        "PUT",
        "GET",
        "GET",
    ]


def test_assignment_rejects_drift_before_put(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, {"results": [_user()]}),
        _Response(200, {"results": [_schedule()]}),
        _Response(200, {"results": [_user() | {"comments": "drift"}]}),
        _Response(200, {"results": [_schedule()]}),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamScheduleAssignHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )
    inspection = transport.inspect_assignment(USER, SCHEDULE)

    with pytest.raises(ScheduleAssignHttpTransportError):
        transport.assign_and_readback(
            USER,
            SCHEDULE,
            user_non_schedule_state_digest=inspection.user_non_schedule_state_digest,
            schedule_state_digest=inspection.schedule_state_digest,
        )

    assert all(call["method"] == "GET" for call in calls)


def test_assignment_rejects_unbounded_names_before_any_request() -> None:
    transport = FortiPamScheduleAssignHttpTransport(_config())

    with pytest.raises(ScheduleAssignHttpTransportError):
        transport.inspect_assignment("admin", SCHEDULE)
    with pytest.raises(ScheduleAssignHttpTransportError):
        transport.inspect_assignment(USER, "always")


def test_fixed_detach_inspection_requires_exact_projection_and_sole_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = _user(SCHEDULE)
    schedule = _schedule()
    _fixed_digests(monkeypatch, user, schedule)
    calls: list[dict[str, object]] = []
    ssh = _ScheduleSsh()
    responses = [
        _Response(200, {"results": [user]}),
        _Response(200, {"results": [schedule]}),
        _Response(200, {"results": [user, _user() | {"name": "mcp-v4-user-other"}]}),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamScheduleAssignHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, calls),
        schedule_ssh_transport=ssh,
    )

    inspection = transport.inspect_fixed_detach()

    assert inspection.eligible is True
    assert inspection.schedule_reference_count == 1
    assert inspection.role_matches is True
    assert ssh.calls == 1
    assert [call["method"] for call in calls] == ["GET", "GET", "GET"]
    assert "protected" not in repr(inspection)


def test_fixed_detach_clears_only_schedule_and_proves_preservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = _user(SCHEDULE)
    schedule = _schedule()
    updated = user | {"schedule": ""}
    _fixed_digests(monkeypatch, user, schedule)
    calls: list[dict[str, object]] = []
    ssh = _ScheduleSsh()
    responses = [
        _Response(200, {"results": [user]}),
        _Response(200, {"results": [schedule]}),
        _Response(200, {"results": [user]}),
        _Response(200, {"results": [user]}),
        _Response(200, {"results": [schedule]}),
        _Response(200, {"results": [user]}),
        _Response(200, {"results": [user]}),
        _Response(200, {"results": [schedule]}),
        _Response(200, {"http_status": 200}),
        _Response(200, {"results": [updated]}),
        _Response(200, {"results": [schedule]}),
        _Response(200, {"results": [updated]}),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamScheduleAssignHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, calls),
        schedule_ssh_transport=ssh,
    )
    inspection = transport.inspect_fixed_detach()

    readback = transport.detach_fixed_and_readback(
        expected_user_record_digest=inspection.user_record_digest,
        expected_user_non_schedule_state_digest=(
            inspection.user_non_schedule_state_digest
        ),
        expected_schedule_state_digest=inspection.schedule_state_digest,
    )

    assert readback.verified is True
    put = calls[8]
    assert put["method"] == "PUT"
    body = put["json"]
    assert isinstance(body, dict)
    assert body["schedule"] == ""
    assert body["accprofile"] == FIXED_DETACH_ROLE
    assert body["status"] == "disable"
    assert "password" not in body
    assert "history0" not in body
    assert ssh.calls == 3


def test_fixed_detach_rejects_complete_record_drift_before_put(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = _user(SCHEDULE)
    schedule = _schedule()
    _fixed_digests(monkeypatch, user, schedule)
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, {"results": [user | {"comments": "drift"}]}),
        _Response(200, {"results": [schedule]}),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamScheduleAssignHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, calls),
        schedule_ssh_transport=_ScheduleSsh(),
    )

    with pytest.raises(ScheduleAssignHttpTransportError):
        transport.inspect_fixed_detach()
    assert all(call["method"] == "GET" for call in calls)
