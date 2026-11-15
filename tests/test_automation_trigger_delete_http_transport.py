from __future__ import annotations

import hashlib
import json

import pytest

import fortipam_mcp.automation_trigger_delete_http_transport as transport_module
from fortipam_mcp.address_http_transport import AddressHttpTransportConfig
from fortipam_mcp.automation_action_ssh_transport import AutomationActionInspection
from fortipam_mcp.automation_trigger_delete_http_transport import (
    ACTION_PRESERVE_NAME,
    AutomationTriggerDeleteHttpTransportError,
    FortiPamAutomationTriggerDeleteHttpTransport,
    TRIGGER_DELETE_NAME,
)
from fortipam_mcp.automation_trigger_ssh_transport import (
    AutomationTriggerInspection,
    AutomationTriggerReadback,
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


class _TriggerSsh:
    def __init__(self) -> None:
        self.exists = True
        self.references = 0
        self.top_level_matches = True

    def inspect(self, name: str) -> AutomationTriggerInspection:
        assert name == TRIGGER_DELETE_NAME
        return AutomationTriggerInspection(self.exists)

    def readback_existing(self, name: str) -> AutomationTriggerReadback:
        assert name == TRIGGER_DELETE_NAME
        return AutomationTriggerReadback(
            self.top_level_matches,
            self.top_level_matches,
            self.top_level_matches,
            self.top_level_matches,
            self.top_level_matches,
            False,
        )

    def reference_count(self, name: str) -> int:
        assert name == TRIGGER_DELETE_NAME
        return self.references


class _ActionSsh:
    def __init__(self) -> None:
        self.exists = True

    def inspect(self, name: str) -> AutomationActionInspection:
        assert name == ACTION_PRESERVE_NAME
        return AutomationActionInspection(self.exists)


def _trigger() -> dict[str, object]:
    return {
        "name": TRIGGER_DELETE_NAME,
        "q_origin_key": TRIGGER_DELETE_NAME,
        "event-type": "event-log",
        "category": 1,
        "logic": "and",
        "logid": [{"id": 44547, "q_origin_key": 44547}],
        "fields": [
            {
                "id": 1,
                "q_origin_key": 1,
                "match": "regex",
                "name": "msg",
                "value": "mcp-v4-no-action",
            }
        ],
    }


def _action() -> dict[str, object]:
    return {
        "name": ACTION_PRESERVE_NAME,
        "q_origin_key": ACTION_PRESERVE_NAME,
        "action-type": "email",
        "email-subject": "FortiPAM V4 unbound action",
        "message": "MCP V4 unbound action no stitch",
        "description": "MCP V4 unbound automation action",
    }


def _digest(record: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _transport(
    responses: list[_Response],
    trigger_ssh: _TriggerSsh,
    action_ssh: _ActionSsh,
    calls: list[dict[str, object]] | None = None,
) -> FortiPamAutomationTriggerDeleteHttpTransport:
    return FortiPamAutomationTriggerDeleteHttpTransport(
        AddressHttpTransportConfig("https://fpa.example.test", "token", 15, None),
        trigger_ssh,
        action_ssh,
        client_factory=lambda **_: _Client(responses, calls if calls is not None else []),
        accepted_digest=_digest(_trigger()),
        action_digest=_digest(_action()),
    )


def test_inspect_requires_complete_trigger_action_and_zero_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    result = _transport(
        [_Response(200, {"results": [_trigger()]}), _Response(200, {"results": [_action()]})],
        _TriggerSsh(),
        _ActionSsh(),
    ).inspect_delete_target()

    assert result.exists is True
    assert result.eligible_fixed_trigger is True
    assert result.trigger_reference_count == 0
    assert result.target_digest == _digest(_trigger())
    assert result.action_digest == _digest(_action())


@pytest.mark.parametrize("drift", ["api", "ssh", "action", "reference"])
def test_inspect_fails_closed_on_drift(
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    trigger = _trigger()
    trigger_ssh = _TriggerSsh()
    action_ssh = _ActionSsh()
    if drift == "api":
        trigger["logic"] = "or"
    elif drift == "ssh":
        trigger_ssh.top_level_matches = False
    elif drift == "action":
        action_ssh.exists = False
    else:
        trigger_ssh.references = 1
    transport = _transport(
        [_Response(200, {"results": [trigger]}), _Response(200, {"results": [_action()]})],
        trigger_ssh,
        action_ssh,
    )
    if drift == "reference":
        assert transport.inspect_delete_target().eligible_fixed_trigger is False
    else:
        with pytest.raises(AutomationTriggerDeleteHttpTransportError):
            transport.inspect_delete_target()


def test_delete_is_bodyless_and_verifies_trigger_absence_and_action_preservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    calls: list[dict[str, object]] = []
    trigger_ssh = _TriggerSsh()
    action_ssh = _ActionSsh()
    responses = [
        _Response(200, {"results": [_trigger()]}),
        _Response(200, {"results": [_action()]}),
        _Response(200, {"http_status": 200}),
        _Response(404, {"http_status": 404}),
        _Response(200, {"results": [_action()]}),
    ]
    transport = _transport(responses, trigger_ssh, action_ssh, calls)
    original_inspect = trigger_ssh.inspect

    def inspect_after_delete(name: str) -> AutomationTriggerInspection:
        if any(call["method"] == "DELETE" for call in calls):
            return AutomationTriggerInspection(False)
        return original_inspect(name)

    trigger_ssh.inspect = inspect_after_delete  # type: ignore[method-assign]
    result = transport.delete_and_readback(_digest(_trigger()))

    assert result.verified is True
    assert [call["method"] for call in calls] == ["GET", "GET", "DELETE", "GET", "GET"]
    delete_call = calls[2]
    assert set(delete_call) == {"method", "url", "headers"}
    assert delete_call["url"].endswith("/automation-trigger/mcp-v4-automation-trigger-b40")


def test_absent_target_is_ineligible_and_never_deletes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    calls: list[dict[str, object]] = []
    transport = _transport([_Response(404, {"http_status": 404})], _TriggerSsh(), _ActionSsh(), calls)
    inspection = transport.inspect_delete_target()
    assert inspection.exists is False
    with pytest.raises(AutomationTriggerDeleteHttpTransportError):
        transport.delete_and_readback("a" * 64)
    assert [call["method"] for call in calls] == ["GET", "GET"]
