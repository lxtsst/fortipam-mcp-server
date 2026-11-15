from __future__ import annotations

from pathlib import Path

import pytest

import fortipam_mcp.template_archive_http_transport as transport_module
from fortipam_mcp.template_archive_http_transport import (
    COLLECTION_PATH,
    FortiPamTemplateArchiveHttpTransport,
    TemplateArchiveHttpTransportConfig,
    TemplateArchiveHttpTransportConfigurationError,
    TemplateArchiveHttpTransportError,
    load_template_archive_http_transport_config,
)


NAME = "mcp-v4-template-archive-01"


class _Response:
    def __init__(self, status_code: int, content: bytes = b"{}") -> None:
        self.status_code = status_code
        self.content = content


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


def _config() -> TemplateArchiveHttpTransportConfig:
    return TemplateArchiveHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def test_loader_requires_dedicated_exact_opt_in(tmp_path: Path) -> None:
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("unit-test-ca\n", encoding="utf-8")
    environment = {
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_ARCHIVE_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_ARCHIVE_API_BASE_URL": "https://fpa.example.test",
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_ARCHIVE_API_API_TOKEN": "unit-test-token",
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_ARCHIVE_API_CA_FILE": str(ca_file),
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_ARCHIVE_API_TIMEOUT_SECONDS": "12",
    }

    loaded = load_template_archive_http_transport_config(environment)

    assert loaded.base_url == "https://fpa.example.test"
    assert loaded.timeout_seconds == 12
    environment["FPA_HOME_LAB_FPA1_V4_TEMPLATE_ARCHIVE_API_ENABLED"] = "false"
    with pytest.raises(TemplateArchiveHttpTransportConfigurationError, match="ENABLED"):
        load_template_archive_http_transport_config(environment)


@pytest.mark.parametrize(
    "base_url",
    (
        "http://fpa.example.test",
        "https://user:pass@fpa.example.test",
        "https://fpa.example.test/api",
        "https://fpa.example.test?query=yes",
    ),
)
def test_config_rejects_non_origin_https_target(base_url: str) -> None:
    with pytest.raises(TemplateArchiveHttpTransportConfigurationError):
        TemplateArchiveHttpTransportConfig(
            base_url=base_url,
            bearer_token="unit-test-token",
            timeout_seconds=15,
            ca_file=None,
        )


def test_delete_uses_only_the_fixed_catalogued_route_and_discards_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamTemplateArchiveHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(_Response(200, b"not-returned"), calls),
    )

    result = transport.delete_template(NAME)

    assert result.deletion_accepted is True
    assert calls == [
        {
            "method": "DELETE",
            "url": f"https://fpa.example.test{COLLECTION_PATH}/{NAME}",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
        }
    ]


@pytest.mark.parametrize("status", (201, 202, 204, 400, 403, 404, 500))
def test_delete_rejects_non_catalogued_success_and_out_of_scope_name(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamTemplateArchiveHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(_Response(status), []),
    )

    with pytest.raises(TemplateArchiveHttpTransportError):
        transport.delete_template(NAME)
    with pytest.raises(TemplateArchiveHttpTransportError):
        transport.delete_template("mcp-v4-template-01")


def test_delete_rejects_oversized_response_before_any_result_is_projected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamTemplateArchiveHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            _Response(200, b"x" * (transport_module.MAX_RESPONSE_BYTES + 1)),
            [],
        ),
    )

    with pytest.raises(TemplateArchiveHttpTransportError):
        transport.delete_template(NAME)
