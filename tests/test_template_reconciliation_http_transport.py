from __future__ import annotations

import json
from pathlib import Path

import pytest

import fortipam_mcp.template_reconciliation_http_transport as transport_module
from fortipam_mcp.template_reconciliation_http_transport import (
    COLLECTION_PATH,
    FortiPamTemplateReconciliationHttpTransport,
    TemplateReconciliationHttpTransportConfig,
    TemplateReconciliationHttpTransportConfigurationError,
    TemplateReconciliationHttpTransportError,
    load_template_reconciliation_http_transport_config,
)


NAME = "mcp-v4-template-b53"


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


def _config() -> TemplateReconciliationHttpTransportConfig:
    return TemplateReconciliationHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _payload(*, port: int = 5900) -> bytes:
    return json.dumps(
        {
            "results": {
                "name": NAME,
                "access": "everyone",
                "field": [
                    {
                        "name": "Username",
                        "type": "username",
                        "mandatory": "enable",
                        "q_origin_key": "ignored-read-only-metadata",
                    },
                    {
                        "name": "Password",
                        "type": "password",
                        "mandatory": "enable",
                    },
                ],
                "launcher": [
                    {
                        "launcher-name": "Web VNC",
                        "port": port,
                        "q_origin_key": "ignored-read-only-metadata",
                    }
                ],
            }
        }
    ).encode("utf-8")


def test_loader_requires_owner_only_token_file(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("unit-test-token\n", encoding="utf-8")
    token_file.chmod(0o600)
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("unit-test-ca\n", encoding="utf-8")
    environment = {
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_RECONCILE_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_RECONCILE_API_BASE_URL": "https://fpa.example.test",
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_RECONCILE_API_API_TOKEN_FILE": str(token_file),
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_RECONCILE_API_CA_FILE": str(ca_file),
    }

    loaded = load_template_reconciliation_http_transport_config(environment)

    assert loaded.base_url == "https://fpa.example.test"
    token_file.chmod(0o644)
    with pytest.raises(TemplateReconciliationHttpTransportConfigurationError):
        load_template_reconciliation_http_transport_config(environment)


def test_detail_get_returns_only_exact_categorical_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamTemplateReconciliationHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(_Response(200, _payload()), calls),
    )

    readback = transport.read_default_web_vnc_baseline(NAME)

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
    ("payload", "expected"),
    (
        (_payload(port=5901), False),
        (
            json.dumps(
                {
                    "results": {
                        "name": NAME,
                        "access": "everyone",
                        "field": [
                            {"name": "Username", "type": "username", "mandatory": "enable"},
                            {"name": "Password", "type": "password", "mandatory": "enable"},
                            {"name": "Extra", "type": "text", "mandatory": "disable"},
                        ],
                        "launcher": [{"launcher-name": "Web VNC", "port": 5900}],
                    }
                }
            ).encode("utf-8"),
            False,
        ),
    ),
)
def test_readback_fails_closed_on_non_exact_baseline(
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    expected: bool,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamTemplateReconciliationHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(_Response(200, payload), []),
    )

    assert transport.read_default_web_vnc_baseline(NAME).verified is expected


@pytest.mark.parametrize("collection", ("field", "launcher"))
def test_readback_rejects_malformed_extra_members_instead_of_filtering_them(
    monkeypatch: pytest.MonkeyPatch,
    collection: str,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    payload = json.loads(_payload())
    payload["results"][collection].append(None)
    transport = FortiPamTemplateReconciliationHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            _Response(200, json.dumps(payload).encode("utf-8")), []
        ),
    )

    assert transport.read_default_web_vnc_baseline(NAME).verified is False


@pytest.mark.parametrize(
    "response",
    (
        _Response(403, b"{}"),
        _Response(200, b"not-json"),
        _Response(200, b"{}", "text/plain"),
        _Response(200, b"x" * (transport_module.MAX_RESPONSE_BYTES + 1)),
    ),
)
def test_transport_rejects_non_json_denial_malformed_and_oversized_responses(
    monkeypatch: pytest.MonkeyPatch,
    response: _Response,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamTemplateReconciliationHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(response, []),
    )

    with pytest.raises(TemplateReconciliationHttpTransportError):
        transport.read_default_web_vnc_baseline(NAME)


def test_transport_rejects_out_of_scope_name_before_request() -> None:
    transport = FortiPamTemplateReconciliationHttpTransport(
        _config(),
        client_factory=lambda **_: pytest.fail("request must not be constructed"),
    )

    with pytest.raises(TemplateReconciliationHttpTransportError):
        transport.read_default_web_vnc_baseline("default")
    with pytest.raises(TemplateReconciliationHttpTransportError):
        transport.read_default_web_vnc_baseline('mcp-v4-template-x"/../')
