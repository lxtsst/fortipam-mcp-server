from __future__ import annotations

import json
from pathlib import Path

import pytest

import fortipam_mcp.local_user_http_transport as transport_module
from fortipam_mcp.local_user_http_transport import (
    ENV_PREFIX,
    FortiPamLocalUserHttpTransport,
    LocalUserHttpTransportConfig,
    LocalUserHttpTransportConfigurationError,
    LocalUserHttpTransportError,
    load_local_user_http_transport_config,
)


def _config() -> LocalUserHttpTransportConfig:
    return LocalUserHttpTransportConfig(
        base_url="https://fpa.example",
        bearer_token="bounded-token",
        timeout_seconds=15,
        ca_file=None,
    )


def test_load_requires_an_independent_owner_only_token_file(tmp_path: Path) -> None:
    token_file = tmp_path / "local-user-token"
    token_file.write_text("bounded-token\n")
    token_file.chmod(0o600)

    config = load_local_user_http_transport_config(
        {
            f"{ENV_PREFIX}ENABLED": "true",
            f"{ENV_PREFIX}BASE_URL": "https://fpa.example",
            f"{ENV_PREFIX}API_TOKEN_FILE": str(token_file),
        }
    )

    assert config.base_url == "https://fpa.example"
    assert config.bearer_token == "bounded-token"
    token_file.chmod(0o644)
    with pytest.raises(LocalUserHttpTransportConfigurationError):
        load_local_user_http_transport_config(
            {
                f"{ENV_PREFIX}ENABLED": "true",
                f"{ENV_PREFIX}BASE_URL": "https://fpa.example",
                f"{ENV_PREFIX}API_TOKEN_FILE": str(token_file),
            }
        )


def test_inspect_uses_one_fixed_encoded_get_without_metadata_disclosure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient([_response({"results": {"status": "enable"}})])
    monkeypatch.setattr(transport_module, "_ssl_context", lambda config: object())
    transport = FortiPamLocalUserHttpTransport(_config(), client_factory=lambda **kwargs: client)

    result = transport.inspect("mcp-user-01")

    assert result.exists is True
    assert result.status == "enable"
    assert client.requests == [
        (
            "GET",
            "https://fpa.example/api/v2/cmdb/system/admin/mcp-user-01",
            None,
        )
    ]


def test_disable_uses_one_fixed_put_and_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(
        [
            _response({"status": "success"}),
            _response({"results": {"status": "disable"}}),
        ]
    )
    monkeypatch.setattr(transport_module, "_ssl_context", lambda config: object())
    transport = FortiPamLocalUserHttpTransport(_config(), client_factory=lambda **kwargs: client)

    result = transport.disable_and_readback("mcp-user-01")

    assert result.verified is True
    assert client.requests == [
        (
            "PUT",
            "https://fpa.example/api/v2/cmdb/system/admin/mcp-user-01",
            {"status": "disable"},
        ),
        (
            "GET",
            "https://fpa.example/api/v2/cmdb/system/admin/mcp-user-01",
            None,
        ),
    ]


def test_transport_rejects_unknown_status_and_non_success_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda config: object())
    unknown = FortiPamLocalUserHttpTransport(
        _config(),
        client_factory=lambda **kwargs: _FakeClient([_response({"results": {}})]),
    )
    rejected = FortiPamLocalUserHttpTransport(
        _config(),
        client_factory=lambda **kwargs: _FakeClient([_response({}, status=403)]),
    )

    with pytest.raises(LocalUserHttpTransportError):
        unknown.inspect("mcp-user-01")
    with pytest.raises(LocalUserHttpTransportError):
        rejected.inspect("mcp-user-01")


class _FakeClient:
    def __init__(self, responses: list[_FakeResponse]) -> None:
        self._responses = responses
        self.requests: list[tuple[str, str, dict[str, str] | None]] = []

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: object,
        json: dict[str, str] | None,
    ) -> "_FakeResponse":
        del headers
        self.requests.append((method, url, json))
        return self._responses.pop(0)


class _FakeResponse:
    def __init__(self, payload: object, *, status: int = 200) -> None:
        self.status_code = status
        self.headers = {"content-type": "application/json"}
        self.content = json.dumps(payload).encode("utf-8")


def _response(payload: object, *, status: int = 200) -> _FakeResponse:
    return _FakeResponse(payload, status=status)
