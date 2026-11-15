from __future__ import annotations

import hashlib
import json

import pytest

import fortipam_mcp.automation_action_delete_http_transport as transport_module
from fortipam_mcp.address_http_transport import AddressHttpTransportConfig
from fortipam_mcp.automation_action_delete_http_transport import (
    ACTION_DELETE_NAME,
    AutomationActionDeleteHttpTransportError,
    FortiPamAutomationActionDeleteHttpTransport,
)
from fortipam_mcp.automation_action_ssh_transport import (
    AutomationActionInspection,
    AutomationActionReadback,
)


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


class _ActionSsh:
    def __init__(self) -> None:
        self.exists = True
        self.references = 0
        self.projection_matches = True

    def inspect(self, name: str) -> AutomationActionInspection:
        assert name == ACTION_DELETE_NAME
        return AutomationActionInspection(self.exists)

    def readback_existing(self, name: str) -> AutomationActionReadback:
        assert name == ACTION_DELETE_NAME
        value = self.projection_matches
        return AutomationActionReadback(value, value, value, value, value, value)

    def reference_count(self, name: str) -> int:
        assert name == ACTION_DELETE_NAME
        return self.references


def _action() -> dict[str, object]:
    return {
        "name": ACTION_DELETE_NAME,
        "q_origin_key": ACTION_DELETE_NAME,
        "action-type": "email",
        "email-subject": "FortiPAM V4 unbound action",
        "email-to": "mcp-v4-no-send@example.invalid",
        "message": "MCP V4 unbound action no stitch",
        "description": "MCP V4 unbound automation action",
    }


def _digest(record: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _transport(
    responses: list[_Response],
    action_ssh: _ActionSsh,
    calls: list[dict[str, object]] | None = None,
) -> FortiPamAutomationActionDeleteHttpTransport:
    return FortiPamAutomationActionDeleteHttpTransport(
        AddressHttpTransportConfig("https://fpa.example.test", "token", 15, None),
        action_ssh,
        client_factory=lambda **_: _Client(responses, calls if calls is not None else []),
        accepted_digest=_digest(_action()),
    )


def test_inspect_requires_complete_action_absent_dependencies_and_zero_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    result = _transport(
        [
            _Response(200, {"results": [_action()]}),
            _Response(404, {"http_status": 404}),
            _Response(404, {"http_status": 404}),
        ],
        _ActionSsh(),
    ).inspect_delete_target()

    assert result.exists is True
    assert result.eligible_fixed_action is True
    assert result.action_reference_count == 0
    assert result.target_digest == _digest(_action())
    assert result.accepted_trigger_absent is True
    assert result.accepted_stitch_absent is True


@pytest.mark.parametrize("drift", ["api", "ssh", "reference", "trigger", "stitch"])
def test_inspect_fails_closed_on_drift(
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    action = _action()
    action_ssh = _ActionSsh()
    if drift == "api":
        action["message"] = "changed"
    elif drift == "ssh":
        action_ssh.projection_matches = False
    elif drift == "reference":
        action_ssh.references = 1
    responses = [
        _Response(200, {"results": [action]}),
        _Response(200 if drift == "trigger" else 404, {"http_status": 404}),
        _Response(200 if drift == "stitch" else 404, {"http_status": 404}),
    ]
    transport = _transport(responses, action_ssh)
    if drift in {"reference", "trigger", "stitch"}:
        assert transport.inspect_delete_target().eligible_fixed_action is False
    else:
        with pytest.raises(AutomationActionDeleteHttpTransportError):
            transport.inspect_delete_target()


def test_delete_is_bodyless_and_verifies_action_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    calls: list[dict[str, object]] = []
    action_ssh = _ActionSsh()
    responses = [
        _Response(200, {"results": [_action()]}),
        _Response(404, {"http_status": 404}),
        _Response(404, {"http_status": 404}),
        _Response(200, {"http_status": 200}),
        _Response(404, {"http_status": 404}),
    ]
    transport = _transport(responses, action_ssh, calls)
    original_inspect = action_ssh.inspect

    def inspect_after_delete(name: str) -> AutomationActionInspection:
        if any(call["method"] == "DELETE" for call in calls):
            return AutomationActionInspection(False)
        return original_inspect(name)

    action_ssh.inspect = inspect_after_delete  # type: ignore[method-assign]
    result = transport.delete_and_readback(_digest(_action()))

    assert result.verified is True
    assert [call["method"] for call in calls] == ["GET", "GET", "GET", "DELETE", "GET"]
    delete_call = calls[3]
    assert set(delete_call) == {"method", "url", "headers"}
    assert delete_call["url"].endswith("/automation-action/mcp-v4-automation-action-b44")


def test_absent_target_is_ineligible_and_never_deletes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    calls: list[dict[str, object]] = []
    transport = _transport(
        [_Response(404, {"http_status": 404}), _Response(404, {"http_status": 404})],
        _ActionSsh(),
        calls,
    )
    assert transport.inspect_delete_target().exists is False
    with pytest.raises(AutomationActionDeleteHttpTransportError):
        transport.delete_and_readback("a" * 64)
    assert [call["method"] for call in calls] == ["GET", "GET"]
