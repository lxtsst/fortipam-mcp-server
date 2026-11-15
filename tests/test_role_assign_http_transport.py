from __future__ import annotations

import json
from pathlib import Path

import pytest

import fortipam_mcp.role_assign_http_transport as transport_module
from fortipam_mcp.role_assign_http_transport import (
    FortiPamRoleAssignHttpTransport,
    RoleAssignHttpTransportConfig,
    RoleAssignHttpTransportConfigurationError,
    RoleAssignHttpTransportError,
    load_role_assign_http_transport_config,
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


USER = "mcp-v4-user-01"
ROLE = "mcp-v4-role-01"


def _config() -> RoleAssignHttpTransportConfig:
    return RoleAssignHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def test_loader_requires_dedicated_owner_only_token_file(tmp_path: Path) -> None:
    token = tmp_path / "token"
    token.write_text("unit-test-token\n", encoding="utf-8")
    token.chmod(0o600)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_ROLE_ASSIGN_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_ROLE_ASSIGN_BASE_URL": "https://fpa.example.test",
        "FPA_HOME_LAB_FPA1_V4_ROLE_ASSIGN_API_TOKEN_FILE": str(token),
        "FPA_HOME_LAB_FPA1_V4_ROLE_ASSIGN_TIMEOUT_SECONDS": "12",
    }

    loaded = load_role_assign_http_transport_config(environment)

    assert loaded.base_url == "https://fpa.example.test"
    assert loaded.timeout_seconds == 12
    token.chmod(0o640)
    with pytest.raises(RoleAssignHttpTransportConfigurationError, match="owner-only"):
        load_role_assign_http_transport_config(environment)


def test_inspect_uses_only_fixed_user_and_role_detail_gets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, {"results": [{"status": "disable", "accprofile": "Guest"}]}),
        _Response(200, {"results": [{"name": ROLE}]}),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamRoleAssignHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    inspection = transport.inspect_assignment(USER, ROLE)

    assert inspection.user_exists is True
    assert inspection.role_exists is True
    assert inspection.user_disabled is True
    assert inspection.assignment_matches is False
    assert len(inspection.state_digest) == 64
    assert "Guest" not in repr(inspection)
    assert calls == [
        {
            "method": "GET",
            "url": f"https://fpa.example.test/api/v2/cmdb/system/admin/{USER}",
            "headers": {"Accept": "application/json", "Authorization": "Bearer unit-test-token"},
            "json": None,
        },
        {
            "method": "GET",
            "url": f"https://fpa.example.test/api/v2/cmdb/system/accprofile/{ROLE}",
            "headers": {"Accept": "application/json", "Authorization": "Bearer unit-test-token"},
            "json": None,
        },
    ]


def test_assign_uses_one_minimal_put_then_fixed_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, {"http_status": 200}),
        _Response(200, {"results": [{"status": "disable", "accprofile": ROLE}]}),
        _Response(200, {"results": [{"name": ROLE}]}),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamRoleAssignHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    readback = transport.assign_and_readback(USER, ROLE)

    assert readback.verified is True
    assert calls == [
        {
            "method": "PUT",
            "url": f"https://fpa.example.test/api/v2/cmdb/system/admin/{USER}",
            "headers": {"Accept": "application/json", "Authorization": "Bearer unit-test-token"},
            "json": {"accprofile": ROLE},
        },
        {
            "method": "GET",
            "url": f"https://fpa.example.test/api/v2/cmdb/system/admin/{USER}",
            "headers": {"Accept": "application/json", "Authorization": "Bearer unit-test-token"},
            "json": None,
        },
        {
            "method": "GET",
            "url": f"https://fpa.example.test/api/v2/cmdb/system/accprofile/{ROLE}",
            "headers": {"Accept": "application/json", "Authorization": "Bearer unit-test-token"},
            "json": None,
        },
    ]


def test_rejects_unprefixed_user_or_role_before_any_request() -> None:
    transport = FortiPamRoleAssignHttpTransport(_config())

    with pytest.raises(RoleAssignHttpTransportError):
        transport.inspect_assignment("admin", ROLE)
    with pytest.raises(RoleAssignHttpTransportError):
        transport.assign_and_readback(USER, "super_admin")
