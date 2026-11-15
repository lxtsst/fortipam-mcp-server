from __future__ import annotations

import json
from pathlib import Path

import pytest

import fortipam_mcp.address_http_transport as transport_module
from fortipam_mcp.address_http_transport import (
    AddressHttpTransportConfig,
    AddressHttpTransportConfigurationError,
    AddressHttpTransportError,
    FortiPamAddressHttpTransport,
    load_address_http_transport_config,
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


def _config() -> AddressHttpTransportConfig:
    return AddressHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def test_loader_requires_exact_opt_in_and_dedicated_configuration(tmp_path: Path) -> None:
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("unit-test-ca\n", encoding="utf-8")
    environment = {
        "FPA_HOME_LAB_FPA1_V4_ADDRESS_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_ADDRESS_API_BASE_URL": "https://fpa.example.test",
        "FPA_HOME_LAB_FPA1_V4_ADDRESS_API_API_TOKEN": "unit-test-token",
        "FPA_HOME_LAB_FPA1_V4_ADDRESS_API_CA_FILE": str(ca_file),
        "FPA_HOME_LAB_FPA1_V4_ADDRESS_API_TIMEOUT_SECONDS": "12",
    }

    loaded = load_address_http_transport_config(environment)

    assert loaded.base_url == "https://fpa.example.test"
    assert loaded.timeout_seconds == 12
    environment["FPA_HOME_LAB_FPA1_V4_ADDRESS_API_ENABLED"] = "false"
    with pytest.raises(AddressHttpTransportConfigurationError, match="ENABLED"):
        load_address_http_transport_config(environment)


def test_inspect_maps_only_json_404_to_address_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamAddressHttpTransport(
        _config(), client_factory=lambda **_: _Client([_Response(404, {})], calls)
    )

    result = transport.inspect("mcp-address-01")

    assert result.exists is False
    assert result.is_ipv4_ipmask is False
    assert calls == [
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/cmdb/firewall/address/mcp-address-01",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": None,
        }
    ]


def test_create_posts_only_compiled_ipmask_body_then_reads_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    name = "mcp-address-01"
    cidr = "198.51.100.10/32"
    subnet = "198.51.100.10 255.255.255.255"
    responses = [
        _Response(200, {"http_status": 200}),
        _Response(
            200,
            {"results": [{"name": name, "type": "ipmask", "subnet": subnet}]},
        ),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamAddressHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    result = transport.create_and_readback(name, cidr)

    assert result.verified is True
    assert calls == [
        {
            "method": "POST",
            "url": "https://fpa.example.test/api/v2/cmdb/firewall/address",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": {"name": name, "type": "ipmask", "subnet": subnet},
        },
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/cmdb/firewall/address/mcp-address-01",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": None,
        },
    ]


def test_create_rejects_non_200_unverified_or_noncanonical_cidr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    rejected = FortiPamAddressHttpTransport(
        _config(), client_factory=lambda **_: _Client([_Response(400, {})], [])
    )
    with pytest.raises(AddressHttpTransportError):
        rejected.create_and_readback("mcp-address-01", "198.51.100.10/32")

    partial = FortiPamAddressHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [
                _Response(200, {"http_status": 200}),
                _Response(200, {"results": [{"name": "mcp-address-01"}]}),
            ],
            [],
        ),
    )
    assert partial.create_and_readback("mcp-address-01", "198.51.100.10/32").verified is False
    with pytest.raises(AddressHttpTransportError):
        rejected.create_and_readback("mcp-address-01", "198.51.100.10/24")


def test_inspect_projects_only_existing_ipv4_ipmask_eligibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamAddressHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [
                _Response(
                    200,
                    {
                        "results": [
                            {
                                "name": "mcp-address-01",
                                "type": "ipmask",
                                "subnet": "198.51.100.0 255.255.255.0",
                            }
                        ]
                    },
                )
            ],
            calls,
        ),
    )

    result = transport.inspect("mcp-address-01")

    assert result.exists is True
    assert result.is_ipv4_ipmask is True
    assert calls[0]["method"] == "GET"
