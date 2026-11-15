from __future__ import annotations

import json

import pytest

from fortipam_mcp.approval_profile_http_transport import (
    ApprovalProfileHttpTransportError,
    COLLECTION_PATH,
    FortiPamApprovalProfileHttpTransport,
)
from fortipam_mcp.secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig,
)


PROFILE = "mcp-v4-approval-profile-bp008-e2e"


class _Response:
    def __init__(self, status: int, payload: object, *, content_type: str = "application/json") -> None:
        self.status = status
        self._content = json.dumps(payload).encode("utf-8")
        self._content_type = content_type
        self.closed = False

    def getheader(self, name: str, default: str = "") -> str:
        return self._content_type if name.lower() == "content-type" else default

    def read(self, amount: int | None = None) -> bytes:
        return self._content if amount is None else self._content[:amount]

    def close(self) -> None:
        self.closed = True


class _Connection:
    def __init__(self, response: _Response, calls: list[dict[str, object]]) -> None:
        self._response = response
        self._calls = calls
        self.closed = False

    def request(self, method: str, url: str, body=None, headers=None) -> None:
        self._calls.append(
            {"method": method, "url": url, "body": body, "headers": headers}
        )

    def getresponse(self) -> _Response:
        return self._response

    def close(self) -> None:
        self.closed = True


def _config() -> SecretMetadataHttpTransportConfig:
    return SecretMetadataHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _record() -> dict[str, object]:
    return {
        "approver-perm-req": "none",
        "auto-approval-schedule": "",
        "description": "MCP V4 unbound approval profile",
        "email-approval-link-expiry": 120,
        "email-template": "",
        "field": [],
        "first-group": "",
        "first-num": 1,
        "first-user": ["admin"],
        "max-allowed-duration": 0,
        "name": PROFILE,
        "q_origin_key": PROFILE,
        "remote-group-email": "disable",
        "second-group": "",
        "second-num": 0,
        "second-user": [],
        "self-approval": "disable",
        "third-group": "",
        "third-num": 0,
        "third-user": [],
        "type": "single",
    }


def _transport(response: _Response, calls: list[dict[str, object]]) -> FortiPamApprovalProfileHttpTransport:
    return FortiPamApprovalProfileHttpTransport(
        _config(),
        connection_factory=lambda *_, **__: _Connection(response, calls),
    )


def test_readback_uses_one_fixed_get_and_returns_only_categorical_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "fortipam_mcp.approval_profile_http_transport._ssl_context",
        lambda _: object(),
    )
    calls: list[dict[str, object]] = []

    result = _transport(_Response(200, {"results": [_record()]}), calls).readback(PROFILE)

    assert result.verified is True
    assert calls == [
        {
            "method": "GET",
            "url": f"{COLLECTION_PATH}/{PROFILE}",
            "body": None,
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
                "Connection": "close",
                "User-Agent": "fortipam-mcp-v4-approval-profile-read/1",
            },
        }
    ]
    assert "admin" not in repr(result)


def test_readback_accepts_fortipam_expanded_single_tier_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "fortipam_mcp.approval_profile_http_transport._ssl_context",
        lambda _: object(),
    )
    calls: list[dict[str, object]] = []
    record = {
        **_record(),
        "first-user": [{"name": "admin", "q_origin_key": "admin"}],
        "first-group": [],
        "second-num": 1,
        "second-group": [],
        "third-num": 1,
        "third-group": [],
    }

    result = _transport(_Response(200, {"results": [record]}), calls).readback(PROFILE)

    assert result.verified is True


@pytest.mark.parametrize(
    ("status", "payload", "content_type", "raises", "verified"),
    [
        (404, {"http_status": 404}, "application/json", False, False),
        (200, {"results": [{**_record(), "self-approval": "enable"}]}, "application/json", False, False),
        (403, {"http_status": 403}, "application/json", True, False),
        (200, {"results": [_record()]}, "text/html", True, False),
    ],
)
def test_readback_fails_closed_for_absence_drift_or_invalid_response(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    payload: object,
    content_type: str,
    raises: bool,
    verified: bool,
) -> None:
    monkeypatch.setattr(
        "fortipam_mcp.approval_profile_http_transport._ssl_context",
        lambda _: object(),
    )
    operation = lambda: _transport(
        _Response(status, payload, content_type=content_type), []
    ).readback(PROFILE)
    if raises:
        with pytest.raises(ApprovalProfileHttpTransportError):
            operation()
    else:
        assert operation().verified is verified
