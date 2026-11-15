from __future__ import annotations

import json
from pathlib import Path

import pytest

import fortipam_mcp.secret_gateway_reconciliation_http_transport as transport_module
from fortipam_mcp.secret_gateway_reconciliation_http_transport import (
    COLLECTION_PATH,
    FortiPamSecretGatewayReconciliationHttpTransport,
    SecretGatewayReconciliationHttpTransportConfig,
    SecretGatewayReconciliationHttpTransportConfigurationError,
    SecretGatewayReconciliationHttpTransportError,
    load_secret_gateway_reconciliation_http_transport_config,
)


NAME = "mcp-v4-secret-gateway-b46"


class _Response:
    def __init__(
        self,
        status_code: int,
        content: bytes,
        content_type: str = "application/json",
    ) -> None:
        self.status_code = status_code
        self.content = content
        self.headers = {"content-type": content_type}


class _Client:
    def __init__(self, response: _Response, calls: list[dict[str, object]]) -> None:
        self._response = response
        self._calls = calls

    def __enter__(self) -> _Client:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def request(self, method: str, url: str, **kwargs: object) -> _Response:
        self._calls.append({"method": method, "url": url, **kwargs})
        return self._response


def _config() -> SecretGatewayReconciliationHttpTransportConfig:
    return SecretGatewayReconciliationHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _payload(**overrides: object) -> bytes:
    record: dict[str, object] = {
        "name": NAME,
        "status": "disable",
        "type": "forward",
        "address": "192.0.2.1",
        "port": 443,
        "url-map": "tcp",
        "ssl-max-version": "tls-1.3",
        "description": "MCP V4 disabled forward gateway",
        "q_origin_key": "ignored-read-only-metadata",
    }
    record.update(overrides)
    return json.dumps({"results": record}).encode("utf-8")


def test_loader_requires_exact_enable_and_owner_only_token(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("unit-test-token\n", encoding="utf-8")
    token_file.chmod(0o600)
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("unit-test-ca\n", encoding="utf-8")
    environment = {
        "FPA_HOME_LAB_FPA1_V4_SECRET_GATEWAY_RECONCILE_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_SECRET_GATEWAY_RECONCILE_API_BASE_URL": "https://fpa.example.test",
        "FPA_HOME_LAB_FPA1_V4_SECRET_GATEWAY_RECONCILE_API_API_TOKEN_FILE": str(token_file),
        "FPA_HOME_LAB_FPA1_V4_SECRET_GATEWAY_RECONCILE_API_CA_FILE": str(ca_file),
    }

    loaded = load_secret_gateway_reconciliation_http_transport_config(environment)

    assert loaded.base_url == "https://fpa.example.test"
    token_file.chmod(0o644)
    with pytest.raises(SecretGatewayReconciliationHttpTransportConfigurationError):
        load_secret_gateway_reconciliation_http_transport_config(environment)


@pytest.mark.parametrize("enabled", (None, "TRUE", "false"))
def test_loader_fails_closed_when_not_exactly_enabled(
    tmp_path: Path,
    enabled: str | None,
) -> None:
    del tmp_path
    environment = {}
    if enabled is not None:
        environment[
            "FPA_HOME_LAB_FPA1_V4_SECRET_GATEWAY_RECONCILE_API_ENABLED"
        ] = enabled

    with pytest.raises(SecretGatewayReconciliationHttpTransportConfigurationError):
        load_secret_gateway_reconciliation_http_transport_config(environment)


@pytest.mark.parametrize(
    "base_url",
    (
        "http://fpa.example.test",
        "https://user:password@fpa.example.test",
        "https://fpa.example.test/api",
        "https://fpa.example.test?query=true",
        "https://fpa.example.test:70000",
    ),
)
def test_config_rejects_non_bare_https_origins(base_url: str) -> None:
    with pytest.raises(SecretGatewayReconciliationHttpTransportConfigurationError):
        SecretGatewayReconciliationHttpTransportConfig(
            base_url=base_url,
            bearer_token="unit-test-token",
            timeout_seconds=15,
            ca_file=None,
        )


def test_detail_get_returns_only_exact_categorical_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretGatewayReconciliationHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(_Response(200, _payload()), calls),
    )

    readback = transport.read_disabled_forward_baseline(NAME)

    assert readback.verified is True
    assert calls == [
        {
            "method": "GET",
            "url": f"https://fpa.example.test{COLLECTION_PATH}/{NAME}",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
        }
    ]


@pytest.mark.parametrize(
    "overrides",
    (
        {"name": "mcp-v4-secret-gateway-other"},
        {"status": "enable"},
        {"type": "reverse"},
        {"address": "198.51.100.1"},
        {"port": 8443},
        {"url-map": "http"},
        {"ssl-max-version": "tls-1.2"},
        {"description": "other"},
    ),
)
def test_readback_fails_closed_on_each_non_exact_contract_field(
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, object],
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretGatewayReconciliationHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(_Response(200, _payload(**overrides)), []),
    )

    assert transport.read_disabled_forward_baseline(NAME).verified is False


@pytest.mark.parametrize(
    "content",
    (
        json.dumps({"result": json.loads(_payload())["results"]}).encode("utf-8"),
        json.dumps({"results": [json.loads(_payload())["results"]]}).encode("utf-8"),
    ),
)
def test_readback_accepts_only_documented_single_record_wrappers(
    monkeypatch: pytest.MonkeyPatch,
    content: bytes,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretGatewayReconciliationHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(_Response(200, content), []),
    )

    assert transport.read_disabled_forward_baseline(NAME).verified is True


@pytest.mark.parametrize(
    "response",
    (
        _Response(403, b"{}"),
        _Response(404, b"{}"),
        _Response(200, b"not-json"),
        _Response(200, b"{}", "text/plain"),
        _Response(200, b"x" * (transport_module.MAX_RESPONSE_BYTES + 1)),
        _Response(200, b'{"results": []}'),
        _Response(200, b'{"results": [{"name": "one"}, {"name": "two"}]}'),
    ),
)
def test_transport_rejects_denial_missing_malformed_oversized_and_ambiguous_responses(
    monkeypatch: pytest.MonkeyPatch,
    response: _Response,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretGatewayReconciliationHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(response, []),
    )

    with pytest.raises(SecretGatewayReconciliationHttpTransportError):
        transport.read_disabled_forward_baseline(NAME)


@pytest.mark.parametrize(
    "name",
    (
        "default",
        'mcp-v4-secret-gateway-x"/../',
        "mcp-v4-secret-gateway-name with spaces",
    ),
)
def test_transport_rejects_out_of_scope_names_before_request(name: str) -> None:
    transport = FortiPamSecretGatewayReconciliationHttpTransport(
        _config(),
        client_factory=lambda **_: pytest.fail("request must not be constructed"),
    )

    with pytest.raises(SecretGatewayReconciliationHttpTransportError):
        transport.read_disabled_forward_baseline(name)


def test_transport_maps_client_failure_to_stable_non_disclosing_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())

    def fail(**_: object) -> object:
        raise RuntimeError("sensitive transport detail")

    transport = FortiPamSecretGatewayReconciliationHttpTransport(
        _config(), client_factory=fail
    )

    with pytest.raises(
        SecretGatewayReconciliationHttpTransportError,
        match="transport is unavailable",
    ) as exc_info:
        transport.read_disabled_forward_baseline(NAME)
    assert "sensitive transport detail" not in str(exc_info.value)
