from __future__ import annotations

import hashlib
import json

import pytest

import fortipam_mcp.automation_stitch_delete_http_transport as transport_module
from fortipam_mcp.address_http_transport import AddressHttpTransportConfig
from fortipam_mcp.automation_stitch_delete_http_transport import (
    ACTION_PRESERVE_NAME,
    AutomationStitchDeleteHttpTransportError,
    FortiPamAutomationStitchDeleteHttpTransport,
    STITCH_DELETE_NAME,
    TRIGGER_PRESERVE_NAME,
)
from fortipam_mcp.automation_stitch_ssh_transport import (
    AutomationStitchInspection,
    AutomationStitchReadback,
)


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


class _Ssh:
    def __init__(self) -> None:
        self.stitch_exists = True
        self.trigger_exists = True
        self.action_exists = True
        self.updated = True
        self.references = 0
        self.calls: list[tuple[str, ...]] = []

    def inspect(
        self,
        stitch_name: str,
        trigger_name: str,
        action_name: str,
    ) -> AutomationStitchInspection:
        self.calls.append(("inspect", stitch_name, trigger_name, action_name))
        return AutomationStitchInspection(
            self.stitch_exists,
            self.trigger_exists,
            self.action_exists,
        )

    def readback_existing(
        self,
        stitch_name: str,
        trigger_name: str,
        action_name: str,
    ) -> AutomationStitchReadback:
        self.calls.append(("readback", stitch_name, trigger_name, action_name))
        return AutomationStitchReadback(*([self.updated] * 7))

    def reference_count(self, name: str) -> int:
        self.calls.append(("references", name))
        return self.references


def _config() -> AddressHttpTransportConfig:
    return AddressHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _stitch() -> dict[str, object]:
    return {
        "actions": [
            {
                "action": ACTION_PRESERVE_NAME,
                "delay": 0,
                "id": 1,
                "q_origin_key": 1,
                "required": "enable",
            }
        ],
        "description": "MCP V4 disabled single-action lab stitch",
        "destination": "",
        "name": STITCH_DELETE_NAME,
        "q_origin_key": STITCH_DELETE_NAME,
        "status": "disable",
        "trigger": TRIGGER_PRESERVE_NAME,
    }


def _trigger() -> dict[str, object]:
    return {
        "name": TRIGGER_PRESERVE_NAME,
        "q_origin_key": TRIGGER_PRESERVE_NAME,
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
        json.dumps(
            record,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _transport(
    responses: list[_Response],
    ssh: _Ssh,
    calls: list[dict[str, object]] | None = None,
) -> FortiPamAutomationStitchDeleteHttpTransport:
    request_calls = calls if calls is not None else []
    return FortiPamAutomationStitchDeleteHttpTransport(
        _config(),
        ssh,  # type: ignore[arg-type]
        client_factory=lambda **_: _Client(responses, request_calls),
        accepted_digest=_digest(_stitch()),
        trigger_digest=_digest(_trigger()),
        action_digest=_digest(_action()),
    )


def test_inspect_requires_complete_fixed_projection_dependencies_and_zero_refs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    ssh = _Ssh()

    result = _transport(
        [
            _Response(200, {"results": [_stitch()]}),
            _Response(200, {"results": [_trigger()]}),
            _Response(200, {"results": [_action()]}),
        ],
        ssh,
    ).inspect_delete_target()

    assert result.exists is True
    assert result.eligible_fixed_stitch is True
    assert result.stitch_reference_count == 0
    assert result.target_digest == _digest(_stitch())
    assert result.trigger_digest == _digest(_trigger())
    assert result.action_digest == _digest(_action())
    assert ssh.calls == [
        ("readback", STITCH_DELETE_NAME, TRIGGER_PRESERVE_NAME, ACTION_PRESERVE_NAME),
        ("references", STITCH_DELETE_NAME),
    ]


def test_inspect_fails_closed_on_target_dependency_or_ssh_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    drifted = _stitch()
    drifted["status"] = "enable"
    with pytest.raises(AutomationStitchDeleteHttpTransportError):
        _transport(
            [
                _Response(200, {"results": [drifted]}),
                _Response(200, {"results": [_trigger()]}),
                _Response(200, {"results": [_action()]}),
            ],
            _Ssh(),
        ).inspect_delete_target()

    trigger = _trigger()
    trigger["logic"] = "or"
    with pytest.raises(AutomationStitchDeleteHttpTransportError):
        _transport(
            [
                _Response(200, {"results": [_stitch()]}),
                _Response(200, {"results": [trigger]}),
                _Response(200, {"results": [_action()]}),
            ],
            _Ssh(),
        ).inspect_delete_target()

    ssh = _Ssh()
    ssh.updated = False
    with pytest.raises(AutomationStitchDeleteHttpTransportError):
        _transport(
            [
                _Response(200, {"results": [_stitch()]}),
                _Response(200, {"results": [_trigger()]}),
                _Response(200, {"results": [_action()]}),
            ],
            ssh,
        ).inspect_delete_target()


def test_nonzero_reference_is_ineligible(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    ssh = _Ssh()
    ssh.references = 1

    result = _transport(
        [
            _Response(200, {"results": [_stitch()]}),
            _Response(200, {"results": [_trigger()]}),
            _Response(200, {"results": [_action()]}),
        ],
        ssh,
    ).inspect_delete_target()

    assert result.eligible_fixed_stitch is False
    assert result.stitch_reference_count == 1


def test_delete_is_one_exact_bodyless_request_with_dependency_preservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    ssh = _Ssh()
    calls: list[dict[str, object]] = []
    transport = _transport(
        [
            _Response(200, {"results": [_stitch()]}),
            _Response(200, {"results": [_trigger()]}),
            _Response(200, {"results": [_action()]}),
            _Response(200, {"http_status": 200}),
            _Response(404, {"http_status": 404}),
            _Response(200, {"results": [_trigger()]}),
            _Response(200, {"results": [_action()]}),
        ],
        ssh,
        calls,
    )
    ssh.stitch_exists = False

    result = transport.delete_and_readback(_digest(_stitch()))

    assert result.verified is True
    assert [call["method"] for call in calls] == [
        "GET",
        "GET",
        "GET",
        "DELETE",
        "GET",
        "GET",
        "GET",
    ]
    assert calls[3]["url"] == (
        "https://fpa.example.test/api/v2/cmdb/system/automation-stitch/"
        "mcp-v4-automation-stitch-b68"
    )
    assert "json" not in calls[3]
    assert "content" not in calls[3]


def test_absent_is_categorical(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())

    result = _transport(
        [_Response(404, {"http_status": 404})],
        _Ssh(),
    ).inspect_delete_target()

    assert result.exists is False
    assert result.eligible_fixed_stitch is False
