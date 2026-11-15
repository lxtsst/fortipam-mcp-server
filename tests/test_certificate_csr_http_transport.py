from __future__ import annotations

import json
from pathlib import Path

import pytest

import fortipam_mcp.certificate_csr_http_transport as transport_module
from fortipam_mcp.certificate_csr_http_transport import (
    CertificateCsrHttpTransportConfig,
    CertificateCsrHttpTransportConfigurationError,
    CertificateCsrHttpTransportError,
    FortiPamCertificateCsrHttpTransport,
    load_certificate_csr_http_transport_config,
)


class _Response:
    def __init__(
        self,
        status_code: int,
        payload: object,
        content_type: str = "application/json",
    ) -> None:
        self.status_code = status_code
        self.content = json.dumps(payload).encode("utf-8")
        self.headers = {"content-type": content_type}


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


def _config() -> CertificateCsrHttpTransportConfig:
    return CertificateCsrHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def test_loader_requires_exact_api_opt_in_and_configuration(tmp_path: Path) -> None:
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("unit-test-ca\n", encoding="utf-8")
    environment = {
        "FPA_HOME_LAB_FPA1_V4_CERTIFICATE_CSR_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_CERTIFICATE_CSR_API_BASE_URL": (
            "https://fpa.example.test"
        ),
        "FPA_HOME_LAB_FPA1_V4_CERTIFICATE_CSR_API_API_TOKEN": "unit-test-token",
        "FPA_HOME_LAB_FPA1_V4_CERTIFICATE_CSR_API_CA_FILE": str(ca_file),
        "FPA_HOME_LAB_FPA1_V4_CERTIFICATE_CSR_API_TIMEOUT_SECONDS": "12",
    }

    loaded = load_certificate_csr_http_transport_config(environment)

    assert loaded.base_url == "https://fpa.example.test"
    assert loaded.timeout_seconds == 12
    environment["FPA_HOME_LAB_FPA1_V4_CERTIFICATE_CSR_API_ENABLED"] = "false"
    with pytest.raises(CertificateCsrHttpTransportConfigurationError, match="ENABLED"):
        load_certificate_csr_http_transport_config(environment)


def test_inspect_requires_detail_absence_and_vendor_name_availability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _Response(404, {"status": "error"}),
        _Response(200, {"results": {"is_valid": True, "value": "hidden"}}),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamCertificateCsrHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    result = transport.inspect("mcp-v4-cert-unit")

    assert result.exists is False
    assert result.name_available is True
    assert calls[0]["method"] == "GET"
    assert calls[0]["url"] == (
        "https://fpa.example.test/api/v2/cmdb/vpn.certificate/local/"
        "mcp-v4-cert-unit"
    )
    assert calls[1]["method"] == "GET"
    assert "mkey=mcp-v4-cert-unit" in str(calls[1]["url"])
    assert "scope=global" in str(calls[1]["url"])


def test_generate_posts_only_preview_derived_body_and_redacts_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, {"http_status": 200, "results": "not-returned"}),
        _Response(
            200,
            {
                "results": [
                    {
                        "name": "mcp-v4-cert-unit",
                        "csr": "",
                        "private-key": "",
                        "certificate": "",
                    }
                ]
            },
        ),
        _Response(
            200,
            {
                "results": [
                    {
                        "name": "mcp-v4-cert-unit",
                        "type": "local-csr",
                        "status": "pending",
                        "key_type": "RSA",
                        "key_size": 0,
                        "range": "global",
                        "has_valid_cert_key": True,
                        "protected-extra": "sensitive-generated-material",
                    }
                ]
            },
        ),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamCertificateCsrHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    result = transport.generate_and_readback("mcp-v4-cert-unit", "127.0.0.1")

    assert result.verified is True
    assert "sensitive" not in str(result)
    assert calls[0]["method"] == "POST"
    assert calls[0]["url"] == (
        "https://fpa.example.test/api/v2/monitor/vpn-certificate/"
        "csr/generate?vdom=root"
    )
    assert calls[0]["json"] == {
        "keytype": "rsa",
        "keysize": 2048,
        "orgunits": [],
        "scope": "global",
        "certname": "mcp-v4-cert-unit",
        "subject": "127.0.0.1",
    }
    assert calls[1]["method"] == "GET"
    assert calls[1]["json"] is None
    assert calls[2]["method"] == "GET"
    assert calls[2]["url"] == (
        "https://fpa.example.test/api/v2/monitor/system/available-certificates"
    )
    assert calls[2]["json"] is None


def test_readback_classifies_existing_csr_without_material_or_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, {"results": [{"name": "mcp-v4-cert-unit"}]}),
        _Response(
            200,
            {
                "results": [
                    {
                        "name": "mcp-v4-cert-unit",
                        "type": "local-csr",
                        "status": "pending",
                        "key_type": "RSA",
                        "range": "global",
                        "has_valid_cert_key": True,
                        "protected-extra": "sensitive-generated-material",
                    }
                ]
            },
        ),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamCertificateCsrHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    result = transport.readback("mcp-v4-cert-unit")

    assert result.verified is True
    assert "sensitive" not in str(result)
    assert [call["method"] for call in calls] == ["GET", "GET"]
    assert all(call["json"] is None for call in calls)


def test_transport_fails_closed_on_invalid_contract_or_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamCertificateCsrHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [_Response(404, {}), _Response(200, {"results": {"is_valid": True}})],
            [],
        ),
    )
    with pytest.raises(CertificateCsrHttpTransportError):
        transport.inspect("unsafe-name")

    rejected = FortiPamCertificateCsrHttpTransport(
        _config(),
        client_factory=lambda **_: _Client([_Response(400, {"status": "error"})], []),
    )
    with pytest.raises(CertificateCsrHttpTransportError):
        rejected.generate_and_readback("mcp-v4-cert-unit", "127.0.0.1")
