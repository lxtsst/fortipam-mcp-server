from __future__ import annotations

import hashlib
import json

import pytest

import fortipam_mcp.schedule_delete_http_transport as transport_module
from fortipam_mcp.schedule_assign_http_transport import ScheduleAssignHttpTransportConfig
from fortipam_mcp.schedule_delete_http_transport import (
    SCHEDULE_DELETE_NAME,
    FortiPamScheduleDeleteHttpTransport,
    ScheduleDeleteHttpTransportError,
)
from fortipam_mcp.schedule_ssh_transport import ScheduleInspection, ScheduleReadback


class _Response:
    def __init__(self, status_code: int, payload: object) -> None:
        self.status_code = status_code
        self.content = json.dumps(payload).encode()
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


class _ScheduleSsh:
    def __init__(self) -> None:
        self.exists = True
        self.references = 0
        self.projection_matches = True

    def inspect(self, name: str) -> ScheduleInspection:
        assert name == SCHEDULE_DELETE_NAME
        return ScheduleInspection(self.exists)

    def readback_existing(self, name: str) -> ScheduleReadback:
        assert name == SCHEDULE_DELETE_NAME
        value = self.projection_matches
        return ScheduleReadback(value, value, value, value, value)

    def reference_count(self, name: str) -> int:
        assert name == SCHEDULE_DELETE_NAME
        return self.references


def _schedule() -> dict[str, object]:
    return {
        "name": SCHEDULE_DELETE_NAME,
        "q_origin_key": SCHEDULE_DELETE_NAME,
        "start": "01:00",
        "end": "01:30",
        "day": "monday",
        "color": 0,
    }


def _user(*, schedule: str = "") -> dict[str, object]:
    return {
        "id": 57,
        "name": "mcp-v4-user-b57",
        "status": "disable",
        "remote-auth": "disable",
        "wildcard": "disable",
        "accprofile": "mcp-v4-role-b76a",
        "schedule": schedule,
        "comments": "fixed",
    }


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _user_non_schedule_digest(record: dict[str, object]) -> str:
    return _digest({key: value for key, value in record.items() if key != "schedule"})


def _transport(
    responses: list[_Response],
    schedule_ssh: _ScheduleSsh,
    calls: list[dict[str, object]] | None = None,
) -> FortiPamScheduleDeleteHttpTransport:
    return FortiPamScheduleDeleteHttpTransport(
        ScheduleAssignHttpTransportConfig(
            "https://fpa.example.test", "token", 15, None
        ),
        schedule_ssh,
        client_factory=lambda **_: _Client(
            responses,
            calls if calls is not None else [],
        ),
        accepted_digest=_digest(_schedule()),
    )


def _prepare(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    monkeypatch.setattr(
        transport_module,
        "FIXED_USER_NON_SCHEDULE_DIGEST",
        _user_non_schedule_digest(_user()),
    )


def test_inspect_requires_complete_schedule_unassigned_user_and_zero_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(monkeypatch)
    result = _transport(
        [
            _Response(200, {"results": [_schedule()]}),
            _Response(200, {"results": [_user()]}),
            _Response(200, {"results": [_user()]}),
        ],
        _ScheduleSsh(),
    ).inspect_delete_target()

    assert result.exists is True
    assert result.eligible_fixed_schedule is True
    assert result.user_reference_count == 0
    assert result.cmdb_reference_count == 0
    assert result.target_digest == _digest(_schedule())
    assert result.fixed_user_unassigned is True


@pytest.mark.parametrize("drift", ["api", "ssh", "user", "user_ref", "cmdb_ref"])
def test_inspect_fails_closed_on_drift(
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    _prepare(monkeypatch)
    schedule = _schedule()
    user = _user()
    users = [_user()]
    schedule_ssh = _ScheduleSsh()
    if drift == "api":
        schedule["end"] = "02:00"
    elif drift == "ssh":
        schedule_ssh.projection_matches = False
    elif drift == "user":
        user["accprofile"] = "changed"
    elif drift == "user_ref":
        users.append({"name": "other", "schedule": SCHEDULE_DELETE_NAME})
    else:
        schedule_ssh.references = 1
    transport = _transport(
        [
            _Response(200, {"results": [schedule]}),
            _Response(200, {"results": users}),
            _Response(200, {"results": [user]}),
        ],
        schedule_ssh,
    )
    if drift in {"user", "user_ref", "cmdb_ref"}:
        assert transport.inspect_delete_target().eligible_fixed_schedule is False
    else:
        with pytest.raises(ScheduleDeleteHttpTransportError):
            transport.inspect_delete_target()


def test_delete_is_bodyless_and_verifies_schedule_absence_and_user_preservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(monkeypatch)
    calls: list[dict[str, object]] = []
    schedule_ssh = _ScheduleSsh()
    responses = [
        _Response(200, {"results": [_schedule()]}),
        _Response(200, {"results": [_user()]}),
        _Response(200, {"results": [_user()]}),
        _Response(200, {"http_status": 200}),
        _Response(404, {"http_status": 404}),
        _Response(200, {"results": [_user()]}),
    ]
    transport = _transport(responses, schedule_ssh, calls)
    original_inspect = schedule_ssh.inspect

    def inspect_after_delete(name: str) -> ScheduleInspection:
        if any(call["method"] == "DELETE" for call in calls):
            return ScheduleInspection(False)
        return original_inspect(name)

    schedule_ssh.inspect = inspect_after_delete  # type: ignore[method-assign]
    result = transport.delete_and_readback(_digest(_schedule()))

    assert result.verified is True
    assert [call["method"] for call in calls] == [
        "GET",
        "GET",
        "GET",
        "DELETE",
        "GET",
        "GET",
    ]
    delete_call = calls[3]
    assert set(delete_call) == {"method", "url", "headers"}
    assert delete_call["url"].endswith(
        "/firewall.schedule/recurring/mcp-v4-schedule-b66"
    )


def test_absent_target_is_ineligible_and_never_deletes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(monkeypatch)
    calls: list[dict[str, object]] = []
    transport = _transport(
        [_Response(404, {"http_status": 404}), _Response(404, {"http_status": 404})],
        _ScheduleSsh(),
        calls,
    )
    assert transport.inspect_delete_target().exists is False
    with pytest.raises(ScheduleDeleteHttpTransportError):
        transport.delete_and_readback("a" * 64)
    assert [call["method"] for call in calls] == ["GET", "GET"]
