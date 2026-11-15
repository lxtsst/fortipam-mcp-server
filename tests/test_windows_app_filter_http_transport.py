from __future__ import annotations

import json
from pathlib import Path

import pytest

import fortipam_mcp.windows_app_filter_http_transport as transport_module
from fortipam_mcp.windows_app_filter_http_transport import (
    WINDOWS_APP_FILTER_DELETE_NAME,
    WINDOWS_APP_FILTER_REFRESH_PERIOD,
    WindowsAppFilterHttpTransportConfig,
    WindowsAppFilterHttpTransportConfigurationError,
    WindowsAppFilterHttpTransportError,
    FortiPamWindowsAppFilterHttpTransport,
    load_windows_app_filter_http_transport_config,
)


NAME = "mcp-v4-winapp-filter-01"


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


def _config() -> WindowsAppFilterHttpTransportConfig:
    return WindowsAppFilterHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _delete_payload() -> dict[str, object]:
    return {
        "results": [
            {
                "name": WINDOWS_APP_FILTER_DELETE_NAME,
                "q_origin_key": WINDOWS_APP_FILTER_DELETE_NAME,
                "refresh-period": WINDOWS_APP_FILTER_REFRESH_PERIOD,
                "rules": [],
            }
        ]
    }


def _secrets(*, referenced: bool = False) -> dict[str, object]:
    return {
        "results": [
            {
                "id": 1,
                "windows-app-filter-profile": (
                    WINDOWS_APP_FILTER_DELETE_NAME if referenced else "other-profile"
                ),
            }
        ]
    }


def test_loader_requires_exact_opt_in_and_dedicated_configuration(tmp_path: Path) -> None:
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("unit-test-ca\n", encoding="utf-8")
    environment = {
        "FPA_HOME_LAB_FPA1_V4_WINDOWS_APP_FILTER_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_WINDOWS_APP_FILTER_API_BASE_URL": "https://fpa.example.test",
        "FPA_HOME_LAB_FPA1_V4_WINDOWS_APP_FILTER_API_API_TOKEN": "unit-test-token",
        "FPA_HOME_LAB_FPA1_V4_WINDOWS_APP_FILTER_API_CA_FILE": str(ca_file),
        "FPA_HOME_LAB_FPA1_V4_WINDOWS_APP_FILTER_API_TIMEOUT_SECONDS": "12",
    }

    loaded = load_windows_app_filter_http_transport_config(environment)

    assert loaded.base_url == "https://fpa.example.test"
    assert loaded.timeout_seconds == 12
    environment["FPA_HOME_LAB_FPA1_V4_WINDOWS_APP_FILTER_API_ENABLED"] = "false"
    with pytest.raises(WindowsAppFilterHttpTransportConfigurationError, match="ENABLED"):
        load_windows_app_filter_http_transport_config(environment)


def test_inspect_maps_only_json_404_to_profile_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamWindowsAppFilterHttpTransport(
        _config(), client_factory=lambda **_: _Client([_Response(404, {})], calls)
    )

    result = transport.inspect(NAME)

    assert result.exists is False
    assert calls == [
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/cmdb/secret/winappfilter-profile/mcp-v4-winapp-filter-01",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": None,
        }
    ]


def test_create_posts_only_fixed_name_then_reads_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, {"http_status": 200}),
        _Response(200, {"results": [{"name": NAME}]}),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamWindowsAppFilterHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    result = transport.create_and_readback(NAME)

    assert result.verified is True
    assert calls == [
        {
            "method": "POST",
            "url": "https://fpa.example.test/api/v2/cmdb/secret/winappfilter-profile",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": {"name": NAME},
        },
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/cmdb/secret/winappfilter-profile/mcp-v4-winapp-filter-01",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": None,
        },
    ]


def test_create_rejects_non_200_or_unverified_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    rejected = FortiPamWindowsAppFilterHttpTransport(
        _config(), client_factory=lambda **_: _Client([_Response(400, {})], [])
    )
    with pytest.raises(WindowsAppFilterHttpTransportError):
        rejected.create_and_readback(NAME)

    partial = FortiPamWindowsAppFilterHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [
                _Response(200, {"http_status": 200}),
                _Response(200, {"results": [{"name": "different"}]}),
            ],
            [],
        ),
    )
    assert partial.create_and_readback(NAME).verified is False
    with pytest.raises(WindowsAppFilterHttpTransportError):
        rejected.inspect("outside-lab-scope")


def test_inspect_requires_one_supported_detail_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamWindowsAppFilterHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [_Response(200, {"results": [{"name": NAME}]})],
            [],
        ),
    )

    assert transport.inspect(NAME).exists is True


def test_delete_inspection_requires_exact_empty_shape_and_zero_secret_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    responses = [_Response(200, _delete_payload()), _Response(200, _secrets())]
    transport = FortiPamWindowsAppFilterHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, []),
    )

    inspection = transport.inspect_delete_target()

    assert inspection.exists is True
    assert inspection.eligible_fixed_profile is True
    assert inspection.secret_reference_count == 0
    assert len(inspection.target_digest) == 64

    referenced_responses = [
        _Response(200, _delete_payload()),
        _Response(200, _secrets(referenced=True)),
    ]
    referenced = FortiPamWindowsAppFilterHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(referenced_responses, []),
    ).inspect_delete_target()
    assert referenced.eligible_fixed_profile is False
    assert referenced.secret_reference_count == 1

    drifted = _delete_payload()
    record = drifted["results"][0]
    assert isinstance(record, dict)
    record["refresh-period"] = 60
    rejected = FortiPamWindowsAppFilterHttpTransport(
        _config(),
        client_factory=lambda **_: _Client([_Response(200, drifted)], []),
    )
    with pytest.raises(WindowsAppFilterHttpTransportError):
        rejected.inspect_delete_target()


def test_delete_rechecks_detail_and_secrets_then_deletes_and_proves_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    digest_responses = [
        _Response(200, _delete_payload()),
        _Response(200, _secrets()),
    ]
    digest_transport = FortiPamWindowsAppFilterHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(digest_responses, []),
    )
    digest = digest_transport.inspect_delete_target().target_digest
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, _delete_payload()),
        _Response(200, _secrets()),
        _Response(200, {"http_status": 200}),
        _Response(404, {}),
    ]
    transport = FortiPamWindowsAppFilterHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, calls),
    )

    result = transport.delete_and_readback(digest)

    assert result.verified is True
    assert [call["method"] for call in calls] == ["GET", "GET", "DELETE", "GET"]
    assert str(calls[0]["url"]).endswith(
        "/api/v2/cmdb/secret/winappfilter-profile/mcp-v4-winapp-filter-b26"
    )
    assert str(calls[1]["url"]).endswith(
        "/api/v2/cmdb/secret/database?start=0&count=100"
    )
    assert str(calls[2]["url"]).endswith(
        "/api/v2/cmdb/secret/winappfilter-profile/mcp-v4-winapp-filter-b26"
    )
    assert all(call["json"] is None for call in calls)


def test_delete_rejects_invalid_digest_absence_or_new_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    absent = FortiPamWindowsAppFilterHttpTransport(
        _config(), client_factory=lambda **_: _Client([_Response(404, {})], [])
    )
    with pytest.raises(WindowsAppFilterHttpTransportError):
        absent.delete_and_readback("invalid")
    with pytest.raises(WindowsAppFilterHttpTransportError):
        absent.delete_and_readback("a" * 64)

    referenced_responses = [
        _Response(200, _delete_payload()),
        _Response(200, _secrets(referenced=True)),
    ]
    referenced = FortiPamWindowsAppFilterHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(referenced_responses, []),
    )
    with pytest.raises(WindowsAppFilterHttpTransportError):
        referenced.delete_and_readback("a" * 64)
