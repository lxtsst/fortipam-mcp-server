from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

import fortipam_mcp.target_http_transport as transport_module
from fortipam_mcp.target_contract import (
    DEFAULT_TEMPLATE,
    TARGET_CLASS,
    WEB_PROXY_STATUS,
    TargetWebProxyEnableInspection,
)
from fortipam_mcp.target_http_transport import (
    FortiPamTargetHttpTransport,
    TargetHttpTransportConfig,
    TargetHttpTransportConfigurationError,
    TargetHttpTransportError,
    load_target_http_transport_config,
)


class _Response:
    def __init__(self, status_code: int, payload: object, content_type: str = "application/json") -> None:
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


def _config() -> TargetHttpTransportConfig:
    return TargetHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
        owner_username="unit-test-owner",
    )


def _default_response() -> _Response:
    return _Response(
        200,
        {
            "results": {
                "domain": "",
                "url": "",
                "service-addrs": [],
                "dynamic-gateway": "disable",
                "gateway": "",
                "gateway-cn": "",
                "user-naming-attribute": "sAMAccountName",
                "user-base": "",
                "description": "",
                "rdp-min-ssl-version": "default",
                "rdp-load-balancing-info": "",
                "kdc-address": "",
                "ldaps-min-ssl-version": "default",
                "ssms-min-ssl-version": "default",
                "ldaps-port": 636,
                "access": "everyone",
                "user-permission": [],
                "group-permission": [],
                "web-proxy-status": "disable",
                "web-proxy": {"cred-replacement": "disable", "domain-list": []},
                "winrm-https": "disable",
                "sql-server-log-status": "disable",
                "sql-log": {"log-all": "disable", "max-log-entry-sz": 16, "monitor-db": []},
            }
        },
    )


def _version_response(version: str = "v1.9.1", build: int = 1758) -> _Response:
    return _Response(200, {"version": version, "build": build})


def _create_191(
    transport: FortiPamTargetHttpTransport,
    target_name: str = "mcp-target-01",
    address: str = "192.0.2.10",
):
    return transport.create_and_readback(
        target_name,
        address,
        expected_product_version="1.9.1",
        expected_product_build=1758,
    )


def _default_response_70() -> _Response:
    legacy = json.loads(_default_response().content)["results"]
    detail = {
        **legacy,
        "address": "",
        "ca": "",
        "class": "Other",
        "creation-time": "",
        "hostkey": [],
        "id": 0,
        "name": "",
        "ssh-hostkey-change-action": "disable",
        "ssh-hostkey-import-method": "manual",
        "ssh-hostkey-new-algorithm-action": "disable",
        "ssh-hostkey-verification": "disable",
        "template": "Unix Account (SSH Password)",
        "uuid": "00000000-0000-0000-0000-000000000000",
        "web-proxy": {
            "auth-scheme": "basic",
            "auth-url": "",
            "cred-replacement": "disable",
            "domain-list": [],
            "domain-list-access-type": "include",
            "password-key": "",
            "vendor": "generic",
        },
        "sql-log": {
            "log-all": "disable",
            "log-rpc-parameters": "disable",
            "max-log-entry-sz": 16,
            "monitor-db": [],
        },
    }
    return _Response(200, {"results": detail})


def _owner_response() -> _Response:
    return _Response(200, {"results": [{"name": "unit-test-owner"}]})


def _group_response() -> _Response:
    return _Response(200, {"results": [{"name": "everyone"}]})


def test_loader_requires_exact_api_opt_in_and_configuration(tmp_path: Path) -> None:
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("unit-test-ca\n", encoding="utf-8")
    environment = {
        "FPA_HOME_LAB_FPA1_V4_TARGET_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_TARGET_API_BASE_URL": "https://fpa.example.test",
        "FPA_HOME_LAB_FPA1_V4_TARGET_API_API_TOKEN": "unit-test-token",
        "FPA_HOME_LAB_FPA1_V4_TARGET_API_CA_FILE": str(ca_file),
        "FPA_HOME_LAB_FPA1_V4_TARGET_API_TIMEOUT_SECONDS": "12",
        "FPA_HOME_LAB_FPA1_V4_TARGET_API_OWNER_USERNAME": "unit-test-owner",
    }

    loaded = load_target_http_transport_config(environment)

    assert loaded.base_url == "https://fpa.example.test"
    assert loaded.timeout_seconds == 12
    assert loaded.owner_username == "unit-test-owner"
    environment["FPA_HOME_LAB_FPA1_V4_TARGET_API_ENABLED"] = "false"
    with pytest.raises(TargetHttpTransportConfigurationError, match="ENABLED"):
        load_target_http_transport_config(environment)


def test_inspect_maps_only_a_json_404_to_target_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _version_response(),
        _Response(404, {"status": "error"}),
        _owner_response(),
        _group_response(),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamTargetHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    result = transport.inspect("mcp-target-01")

    assert result.exists is False
    assert (result.product_version, result.product_build) == ("1.9.1", 1758)
    assert calls == [
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/monitor/system/status",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": None,
        },
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/cmdb/secret/target/mcp-target-01",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": None,
        },
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/cmdb/system/admin/unit-test-owner",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": None,
        },
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/cmdb/user/group/everyone",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": None,
        }
    ]


def test_inspect_existing_target_does_not_require_create_prerequisites(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    config = TargetHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    responses = [_version_response(), _Response(200, {"results": {"name": "mcp-target-01"}})]
    transport = FortiPamTargetHttpTransport(
        config,
        client_factory=lambda **_: _Client(responses, calls),
    )

    result = transport.inspect("mcp-target-01")

    assert result.exists is True
    assert [call["url"] for call in calls] == [
        "https://fpa.example.test/api/v2/monitor/system/status",
        "https://fpa.example.test/api/v2/cmdb/secret/target/mcp-target-01"
    ]


def test_create_posts_only_the_compiled_api_body_and_verifies_detail_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    target_name = "mcp-target-01"
    address = "192.0.2.10"
    responses = [
        _version_response(),
        _default_response(),
        _owner_response(),
        _group_response(),
        _Response(200, {"mkey": target_name}),
        _Response(
            200,
            {
                "results": [
                    {
                        "name": target_name,
                        "class": TARGET_CLASS,
                        "template": DEFAULT_TEMPLATE,
                        "address": address,
                        "user-permission": [
                            {
                                "id": 1,
                                "user-name": [{"name": "unit-test-owner"}],
                                "permission": "owner",
                            }
                        ],
                        "group-permission": [
                            {
                                "id": 1,
                                "group-name": [{"name": "everyone"}],
                                "permission": "create-secret",
                            }
                        ],
                        "web-proxy-status": WEB_PROXY_STATUS,
                    }
                ]
            },
        ),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamTargetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, calls),
    )

    result = _create_191(transport, target_name, address)

    assert result.verified is True
    assert calls[0]["url"].endswith("/api/v2/monitor/system/status")
    assert calls[1]["url"].endswith("/api/v2/cmdb/secret/target?action=default")
    assert calls[2]["url"].endswith("/api/v2/cmdb/system/admin/unit-test-owner")
    assert calls[3]["url"].endswith("/api/v2/cmdb/user/group/everyone")
    assert calls[4]["method"] == "POST"
    assert calls[4]["url"] == "https://fpa.example.test/api/v2/cmdb/secret/target"
    assert calls[4]["json"] == {
        "name": target_name,
        "class": TARGET_CLASS,
        "template": DEFAULT_TEMPLATE,
        "address": address,
        "domain": "",
        "url": "",
        "service-addrs": [],
        "dynamic-gateway": "disable",
        "gateway": "",
        "gateway-cn": "",
        "user-naming-attribute": "sAMAccountName",
        "user-base": "",
        "description": "",
        "rdp-min-ssl-version": "default",
        "rdp-load-balancing-info": "",
        "kdc-address": "",
        "ldaps-min-ssl-version": "default",
        "ssms-min-ssl-version": "default",
        "ldaps-port": 636,
        "access": "customized",
        "user-permission": [
            {
                "id": 1,
                "user-name": [{"name": "unit-test-owner"}],
                "permission": "owner",
            }
        ],
        "group-permission": [
            {
                "id": 1,
                "group-name": [{"name": "everyone"}],
                "permission": "create-secret",
            }
        ],
        "web-proxy-status": WEB_PROXY_STATUS,
        "winrm-https": "disable",
        "sql-server-log-status": "disable",
        "sql-log": {},
        "$originalName": target_name,
    }
    assert "web-proxy" not in calls[4]["json"]
    assert calls[5]["method"] == "GET"
    assert calls[5]["json"] is None


@pytest.mark.parametrize("web_proxy_enabled", [False, True])
def test_build_29_create_uses_only_frontend_unparse_fields_and_rechecks_profile(
    monkeypatch: pytest.MonkeyPatch,
    web_proxy_enabled: bool,
) -> None:
    calls: list[dict[str, object]] = []
    target_name = "mcp-target-70-01"
    address = "192.0.2.41"
    responses = [
        _version_response("v7.0.0", 29),
        _default_response_70(),
        _owner_response(),
        _group_response(),
        _Response(200, {"results": {"web-proxy": web_proxy_enabled}}),
        _Response(200, {"http_status": 200, "status": "success"}),
        _Response(
            200,
            {"results": [{
                "name": target_name,
                "class": TARGET_CLASS,
                "template": DEFAULT_TEMPLATE,
                "address": address,
                "web-proxy-status": WEB_PROXY_STATUS,
                "user-permission": [{"id": 1, "user-name": [{"name": "unit-test-owner"}], "permission": "owner"}],
                "group-permission": [{"id": 1, "group-name": [{"name": "everyone"}], "permission": "create-secret"}],
            }]},
        ),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamTargetHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    readback = transport.create_and_readback(
        target_name,
        address,
        expected_product_version="7.0.0",
        expected_product_build=29,
    )

    assert readback.verified is True
    assert calls[4]["url"].endswith("/api/v2/monitor/web-proxy-status")
    body = calls[5]["json"]
    assert isinstance(body, dict)
    assert body["name"] == target_name
    assert body["address"] == address
    assert body["ca"] == ""
    assert body["hostkey"] == []
    assert body["sql-log"] == {
        "log-all": "disable", "max-log-entry-sz": 16, "monitor-db": []
    }
    assert "uuid" not in body
    assert "id" not in body
    assert "creation-time" not in body
    if web_proxy_enabled:
        assert body["web-proxy"] == {"cred-replacement": "disable", "domain-list": []}
    else:
        assert body["web-proxy"] == json.loads(_default_response_70().content)["results"]["web-proxy"]


def test_create_rejects_http_200_product_error_envelope_before_readback() -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _version_response(),
        _default_response(),
        _owner_response(),
        _group_response(),
        _Response(200, {"status": "error", "error": -7, "message": "private"}),
    ]
    transport = FortiPamTargetHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    with pytest.raises(TargetHttpTransportError) as caught:
        _create_191(transport)

    assert caught.value.failure_stage == "target_create_acknowledgement"
    assert caught.value.product_error_code == -7
    assert caught.value.product_status == "error"
    assert [call["method"] for call in calls] == ["GET", "GET", "GET", "GET", "POST"]


def test_build_29_create_rejects_version_drift_before_default_or_write() -> None:
    calls: list[dict[str, object]] = []
    responses = [_version_response("v7.0.0", 30)]
    transport = FortiPamTargetHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    with pytest.raises(TargetHttpTransportError):
        transport.create_and_readback(
            "mcp-target-70-01",
            "192.0.2.41",
            expected_product_version="7.0.0",
            expected_product_build=29,
        )

    assert len(calls) == 1
    assert calls[0]["url"].endswith("/api/v2/monitor/system/status")


def test_build_29_web_proxy_branch_matches_frontend_falsy_parse_for_status_shaped_result() -> None:
    responses = [_Response(200, {"version": "v7.0.0", "build": 29})]
    transport = FortiPamTargetHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, [])
    )

    assert transport._read_global_web_proxy_enabled(
        expected_product_identity=("7.0.0", 29)
    ) is False


def test_create_rejects_non_200_or_unverifiable_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    drift_calls: list[dict[str, object]] = []
    default_drift = FortiPamTargetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [_version_response(), _Response(200, {"results": {"access": "customized"}})],
            drift_calls,
        ),
    )
    with pytest.raises(TargetHttpTransportError):
        _create_191(default_drift)
    assert [call["method"] for call in drift_calls] == ["GET", "GET"]

    rejected_responses = [
        _version_response(),
        _default_response(),
        _owner_response(),
        _group_response(),
        _Response(400, {"status": "error"}),
    ]
    rejected = FortiPamTargetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(rejected_responses, []),
    )
    with pytest.raises(TargetHttpTransportError) as rejected_error:
        _create_191(rejected)
    assert rejected_error.value.failure_stage == "target_create_post"
    assert rejected_error.value.http_status == 400
    assert rejected_error.value.product_status == "error"
    assert rejected_error.value.product_error_class == "unclassified"

    partial_responses = [
        _version_response(),
        _default_response(),
        _owner_response(),
        _group_response(),
        _Response(200, {"mkey": 1}),
        _Response(200, {"results": [{"name": "mcp-target-01"}]}),
    ]
    partial = FortiPamTargetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(partial_responses, []),
    )
    assert _create_191(partial).verified is False


def test_create_reports_only_categorical_invalid_acknowledgement() -> None:
    responses = [
        _version_response(),
        _default_response(),
        _owner_response(),
        _group_response(),
        _Response(200, {"http_status": 500, "message": "must remain private"}),
    ]
    transport = FortiPamTargetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, []),
    )

    with pytest.raises(TargetHttpTransportError) as caught:
        _create_191(transport)

    assert str(caught.value) == "FortiPAM V4 Target API transport is unavailable."
    assert caught.value.failure_stage == "target_create_acknowledgement"
    assert caught.value.http_status == 200
    assert "private" not in str(caught.value)


def test_create_classifies_product_error_without_returning_message() -> None:
    responses = [
        _version_response(),
        _default_response(),
        _owner_response(),
        _group_response(),
        _Response(
            500,
            {
                "status": "error",
                "error": -15,
                "message": "Duplicate address contains a private object name",
            },
        ),
    ]
    transport = FortiPamTargetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, []),
    )

    with pytest.raises(TargetHttpTransportError) as caught:
        _create_191(transport)

    assert caught.value.product_error_code == -15
    assert caught.value.product_status == "error"
    assert caught.value.product_error_class == "duplicate_target_address"
    assert "private object" not in str(caught.value)


def test_create_rejects_an_unresolvable_owner_before_post(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [_version_response(), _default_response(), _Response(404, {"status": "error"})]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamTargetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, calls),
    )

    with pytest.raises(TargetHttpTransportError):
        _create_191(transport)

    assert [call["method"] for call in calls] == ["GET", "GET", "GET"]
    assert calls[2]["url"].endswith("/api/v2/cmdb/system/admin/unit-test-owner")


def test_create_rejects_an_unresolvable_create_secret_group_before_post(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _version_response(),
        _default_response(),
        _owner_response(),
        _Response(404, {"status": "error"}),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamTargetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, calls),
    )

    with pytest.raises(TargetHttpTransportError):
        _create_191(transport)

    assert [call["method"] for call in calls] == ["GET", "GET", "GET", "GET"]
    assert calls[3]["url"].endswith("/api/v2/cmdb/user/group/everyone")


def test_create_requires_a_fixed_owner_identity() -> None:
    config = TargetHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )
    transport = FortiPamTargetHttpTransport(config)

    with pytest.raises(TargetHttpTransportConfigurationError, match="Owner"):
        _create_191(transport)


def test_inspect_description_update_returns_only_state_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamTargetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [
                _Response(
                    200,
                    {
                        "results": [
                            {"name": "mcp-target-01", "description": "old value"}
                        ]
                    },
                )
            ],
            calls,
        ),
    )

    result = transport.inspect_description_update("mcp-target-01", "new value")

    assert result.exists is True
    assert result.description_matches is False
    assert len(result.state_digest) == 64
    assert "old value" not in str(result)
    assert calls[0]["method"] == "GET"


def test_update_description_uses_minimal_put_and_detail_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, {"http_status": 200}),
        _Response(
            200,
            {
                "results": [
                    {"name": "mcp-target-01", "description": "new value"}
                ]
            },
        ),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamTargetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, calls),
    )

    result = transport.update_description_and_readback("mcp-target-01", "new value")

    assert result.verified is True
    assert calls == [
        {
            "method": "PUT",
            "url": "https://fpa.example.test/api/v2/cmdb/secret/target/mcp-target-01",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": {"description": "new value"},
        },
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/cmdb/secret/target/mcp-target-01",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": None,
        },
    ]


def test_inspect_web_proxy_enable_returns_only_categorical_disabled_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamTargetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [
                _Response(
                    200,
                    {
                        "results": [
                            {
                                "name": "mcp-target-web-01",
                                "web-proxy-status": "disable",
                            }
                        ]
                    },
                )
            ],
            calls,
        ),
    )

    result = transport.inspect_web_proxy_enable("mcp-target-web-01")

    assert isinstance(result, TargetWebProxyEnableInspection)
    assert result.exists is True
    assert result.web_proxy_disabled is True
    assert len(result.state_digest) == 64
    assert "mcp-target-web-01" not in str(result)
    assert "web-proxy-status" not in str(result)
    assert "'disable'" not in str(result)
    assert calls[0]["method"] == "GET"


def test_enable_web_proxy_uses_only_fixed_minimal_put_and_detail_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, {"http_status": 200}),
        _Response(
            200,
            {
                "results": [
                    {
                        "name": "mcp-target-web-01",
                        "web-proxy-status": "enable",
                    }
                ]
            },
        ),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamTargetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, calls),
    )

    result = transport.enable_web_proxy_and_readback("mcp-target-web-01")

    assert result.verified is True
    assert calls == [
        {
            "method": "PUT",
            "url": "https://fpa.example.test/api/v2/cmdb/secret/target/mcp-target-web-01",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": {"web-proxy-status": "enable"},
        },
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/cmdb/secret/target/mcp-target-web-01",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": None,
        },
    ]


def test_web_proxy_inspection_rejects_an_unknown_detail_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamTargetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [
                _Response(
                    200,
                    {
                        "results": [
                            {
                                "name": "mcp-target-web-01",
                                "web-proxy-status": "unknown",
                            }
                        ]
                    },
                )
            ],
            [],
        ),
    )

    with pytest.raises(TargetHttpTransportError):
        transport.inspect_web_proxy_enable("mcp-target-web-01")


def test_classification_tag_assignment_inspects_exact_target_and_tag_without_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    target_name = "mcp-v4-target-update-01"
    tag_name = "mcp-v4-classification-tag-01"
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    responses = [
        _Response(
            200,
            {
                "results": [
                    {
                        "name": target_name,
                        "class": "Other",
                        "description": "retained",
                        "template": "Unix Account (SSH Password)",
                    }
                ]
            },
        ),
        _Response(
            200,
            {
                "results": [
                    {
                        "name": tag_name,
                        "description": "retained tag",
                        "q_origin_key": tag_name,
                    }
                ]
            },
        ),
    ]
    transport = FortiPamTargetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, calls),
    )

    result = transport.inspect_classification_tag_assignment(target_name, tag_name)

    assert result.target_exists is True
    assert result.classification_tag_exists is True
    assert result.current_class_is_other is True
    assert result.current_class_matches_tag is False
    assert all(
        len(value) == 64
        for value in (
            result.target_non_class_state_digest,
            result.classification_tag_state_digest,
            result.state_digest,
        )
    )
    assert target_name not in str(result)
    assert tag_name not in str(result)
    assert [call["method"] for call in calls] == ["GET", "GET"]


def test_classification_tag_assignment_puts_only_class_and_proves_preservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    target_name = "mcp-v4-target-update-01"
    tag_name = "mcp-v4-classification-tag-01"
    baseline_target = {
        "name": target_name,
        "class": "Other",
        "description": "retained",
        "template": "Unix Account (SSH Password)",
        "web-proxy-status": "enable",
    }
    baseline_tag = {
        "name": tag_name,
        "description": "retained tag",
        "q_origin_key": tag_name,
    }
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    responses = [
        _Response(200, {"results": [baseline_target]}),
        _Response(200, {"results": [baseline_tag]}),
        _Response(200, {"http_status": 200}),
        _Response(200, {"results": [baseline_target | {"class": tag_name}]}),
        _Response(200, {"results": [baseline_tag]}),
    ]
    transport = FortiPamTargetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, calls),
    )
    inspection = transport.inspect_classification_tag_assignment(target_name, tag_name)

    result = transport.assign_classification_tag_and_readback(
        target_name,
        tag_name,
        target_non_class_state_digest=inspection.target_non_class_state_digest,
        classification_tag_state_digest=inspection.classification_tag_state_digest,
    )

    assert result.verified is True
    assert calls[2]["method"] == "PUT"
    assert calls[2]["url"].endswith("/api/v2/cmdb/secret/target/" + target_name)
    assert calls[2]["json"] == {"class": tag_name}
    assert [call["method"] for call in calls[3:]] == ["GET", "GET"]


def test_classification_tag_assignment_rejects_non_class_state_drift_in_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_name = "mcp-v4-target-update-01"
    tag_name = "mcp-v4-classification-tag-01"
    baseline_target = {
        "name": target_name,
        "class": "Other",
        "description": "retained",
    }
    baseline_tag = {"name": tag_name, "description": "retained tag"}
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    responses = [
        _Response(200, {"results": [baseline_target]}),
        _Response(200, {"results": [baseline_tag]}),
        _Response(200, {"http_status": 200}),
        _Response(
            200,
            {
                "results": [
                    baseline_target
                    | {"class": tag_name, "description": "unexpected drift"}
                ]
            },
        ),
        _Response(200, {"results": [baseline_tag]}),
    ]
    transport = FortiPamTargetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, []),
    )
    inspection = transport.inspect_classification_tag_assignment(target_name, tag_name)

    result = transport.assign_classification_tag_and_readback(
        target_name,
        tag_name,
        target_non_class_state_digest=inspection.target_non_class_state_digest,
        classification_tag_state_digest=inspection.classification_tag_state_digest,
    )

    assert result.target_class_matches is True
    assert result.target_non_class_state_preserved is False
    assert result.verified is False


def test_classification_tag_assignment_rollback_puts_only_other_and_preserves_tag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    target_name = "mcp-v4-target-update-01"
    tag_name = "mcp-v4-classification-tag-01"
    assigned_target = {
        "name": target_name,
        "class": tag_name,
        "description": "retained",
        "template": "Unix Account (SSH Password)",
    }
    restored_target = assigned_target | {"class": TARGET_CLASS}
    baseline_tag = {
        "name": tag_name,
        "description": "retained tag",
        "q_origin_key": tag_name,
    }
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    responses = [
        _Response(200, {"results": [assigned_target]}),
        _Response(200, {"results": [baseline_tag]}),
        _Response(200, {"http_status": 200}),
        _Response(200, {"results": [restored_target]}),
        _Response(200, {"results": [baseline_tag]}),
    ]
    transport = FortiPamTargetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, calls),
    )
    inspection = transport.inspect_classification_tag_assignment(target_name, tag_name)

    result = transport.restore_default_classification_and_readback(
        target_name,
        tag_name,
        target_non_class_state_digest=inspection.target_non_class_state_digest,
        classification_tag_state_digest=inspection.classification_tag_state_digest,
    )

    assert inspection.current_class_matches_tag is True
    assert inspection.current_class_is_other is False
    assert result.verified is True
    assert calls[2]["method"] == "PUT"
    assert calls[2]["url"].endswith("/api/v2/cmdb/secret/target/" + target_name)
    assert calls[2]["json"] == {"class": TARGET_CLASS}
    assert [call["method"] for call in calls[3:]] == ["GET", "GET"]


def _domain_envelope(results: object, *, method: str = "GET", status: int = 200) -> _Response:
    return _Response(status, {"results": results, "status": "Not Found" if status == 404 else "success",
        "http_method": method, "http_status": status, "version": "v7.0.0", "build": 29,
        "path": "secret", "name": "target", "vdom": "root"})


def _domain_responses() -> list[_Response]:
    detail = {"name": "mcp-v4-target-domain-20261002-r1", "class": "Other",
        "template": "Windows Domain Account", "address": "192.0.2.73", "domain": "ad.example.test",
        "ldaps-port": 636, "user-naming-attribute": "sAMAccountName", "user-base": "",
        "web-proxy-status": "disable", "access": "customized",
        "sql-server-log-status": "disable", "ssh-hostkey-verification": "disable",
        "winrm-https": "disable", "hostkey": [],
        "user-permission": [{"id": 1, "user-name": [{"name": "unit-test-owner"}], "permission": "owner"}],
        "group-permission": [{"id": 1, "group-name": [{"name": "everyone"}], "permission": "create-secret"}]}
    collection = _domain_envelope([])
    payload = json.loads(collection.content); payload["matched_count"] = 0; payload["status"] = "OK"
    collection.content = json.dumps(payload).encode()
    missing = _domain_envelope([], status=404)
    missing_body = json.loads(missing.content); missing_body["error"] = "Not Found"
    missing.content = json.dumps(missing_body).encode()
    return [_version_response("v7.0.0", 29), missing, collection,
        _Response(200, {"version": "v7.0.0", "build": 29, "results": [{"name": "Windows Domain Account",
            "field": [{"name": n, "type": t} for n, t in (
                ("Domain-Controller", "target-address"), ("Domain", "domain"),
                ("Username", "username"), ("Password", "password"))]}]}),
        _default_response_70(), _owner_response(), _group_response(),
        _Response(200, {"results": {"web-proxy": False}}),
        _domain_envelope([], method="POST"), _domain_envelope([detail])]


@pytest.mark.parametrize("acknowledged,http_status,product_error", [(True, 200, 0), (False, 200, -3), (False, 500, -7)])
def test_domain_target_fixed_body_and_durable_restart_refusal(
    tmp_path: Path, acknowledged: bool, http_status: int, product_error: int,
) -> None:
    from fortipam_mcp.target_contract import DomainTargetCreateInput
    tmp_path.chmod(0o700); claim = tmp_path / "claim.json"
    calls: list[dict[str, object]] = []; responses = _domain_responses()
    if not acknowledged:
        responses[8] = _Response(http_status, {"status": "error", "error": product_error,
            "message": "Duplicate target address" if http_status == 500 else "Unclassified failure"})
    transport = FortiPamTargetHttpTransport(_config(), client_factory=lambda **_: _Client(responses, calls))
    request = DomainTargetCreateInput("mcp-v4-target-domain-20261002-r1", "192.0.2.73", "ad.example.test")
    if acknowledged:
        assert transport.create_domain_target_and_readback(request, claim_path=claim).verified
    else:
        with pytest.raises(TargetHttpTransportError) as failure:
            transport.create_domain_target_and_readback(request, claim_path=claim)
        assert failure.value.failure_stage == (
            "domain_target_create_acknowledgement" if http_status == 200 else "domain_target_create_post"
        )
        assert failure.value.http_status == http_status
        assert failure.value.product_error_code == product_error
        assert failure.value.product_status == "error"
        assert failure.value.product_error_class == (
            "unclassified" if http_status == 200 else "duplicate_target_address"
        )
    assert claim.exists() and claim.stat().st_mode & 0o777 == 0o600
    post = [c for c in calls if c["method"] == "POST"]; assert len(post) == 1
    body = post[0]["json"]; assert isinstance(body, dict)
    assert body["template"] == "Windows Domain Account" and body["domain"] == "ad.example.test"
    assert body["ldaps-port"] == 636 and body["web-proxy-status"] == "disable"
    assert "web-proxy" not in body and body["sql-log"] == {}
    assert "field" not in body and "password" not in body and "id" not in body
    count = len(calls)
    fresh = FortiPamTargetHttpTransport(_config(), client_factory=lambda **_: _Client([], calls))
    with pytest.raises(TargetHttpTransportError):
        fresh.create_domain_target_and_readback(request, claim_path=claim)
    assert len(calls) == count


@pytest.mark.parametrize("defect", ["build", "template", "field_type", "occupied_address", "populated_missing", "unsafe_parent", "hostkey_scan", "sql_logging"])
def test_domain_target_missing_prerequisite_never_reserves_or_posts(tmp_path: Path, defect: str) -> None:
    from fortipam_mcp.target_contract import DomainTargetCreateInput
    tmp_path.chmod(0o700); claim = tmp_path / "claim.json"
    responses = _domain_responses(); calls: list[dict[str, object]] = []
    if defect == "build": responses[0] = _version_response("v7.0.0", 30)
    if defect == "template":
        body = json.loads(responses[3].content); body["results"][0]["field"][0]["name"] = "Host"
        responses[3] = _Response(200, body)
    if defect == "field_type":
        body = json.loads(responses[3].content); body["results"][0]["field"][1]["type"] = "text"
        responses[3] = _Response(200, body)
    if defect == "occupied_address":
        body = json.loads(responses[2].content); body["results"] = [{"address": "192.0.2.73"}]; body["matched_count"] = 1
        responses[2] = _Response(200, body)
    if defect == "populated_missing": responses[1] = _domain_envelope([{"name": "private"}], status=404)
    if defect == "unsafe_parent": tmp_path.chmod(0o755)
    if defect in {"hostkey_scan", "sql_logging"}:
        body = json.loads(responses[4].content)
        key = "ssh-hostkey-verification" if defect == "hostkey_scan" else "sql-server-log-status"
        body["results"][key] = "enable"
        responses[4] = _Response(200, body)
    transport = FortiPamTargetHttpTransport(_config(), client_factory=lambda **_: _Client(responses, calls))
    request = DomainTargetCreateInput("mcp-v4-target-domain-20261002-r1", "192.0.2.73", "ad.example.test")
    with pytest.raises(TargetHttpTransportError):
        transport.create_domain_target_and_readback(request, claim_path=claim)
    assert not claim.exists() and not any(c["method"] == "POST" for c in calls)


@pytest.mark.parametrize("defect", ["content_type", "size", "json"])
def test_domain_target_unknown_http_response_preserves_status_and_claim(tmp_path: Path, defect: str) -> None:
    from fortipam_mcp.target_contract import DomainTargetCreateInput

    tmp_path.chmod(0o700)
    claim = tmp_path / "claim.json"
    responses = _domain_responses()
    response = _Response(502, {"untrusted": "private response"})
    if defect == "content_type":
        response.headers["content-type"] = "text/html"
    elif defect == "size":
        response.content = b"x" * (transport_module._MAX_RESPONSE_BYTES + 1)
    else:
        response.content = b"private invalid JSON"
    responses[8] = response
    calls: list[dict[str, object]] = []
    transport = FortiPamTargetHttpTransport(_config(), client_factory=lambda **_: _Client(responses, calls))
    request = DomainTargetCreateInput("mcp-v4-target-domain-20261002-r1", "192.0.2.73", "ad.example.test")
    with pytest.raises(TargetHttpTransportError) as failure:
        transport.create_domain_target_and_readback(request, claim_path=claim)
    assert failure.value.http_status == 502
    assert failure.value.failure_stage == "http_response_" + defect
    assert "private" not in str(failure.value)
    assert failure.value.product_error_code is None
    assert claim.exists() and len([c for c in calls if c["method"] == "POST"]) == 1
    count = len(calls)
    with pytest.raises(TargetHttpTransportError):
        transport.create_domain_target_and_readback(request, claim_path=claim)
    assert len(calls) == count


@pytest.mark.parametrize("key,value", [
    ("sql-server-log-status", "enable"),
    ("ssh-hostkey-verification", "enable"),
    ("winrm-https", "enable"),
    ("hostkey", [{"hostkey-data": "unexpected"}]),
])
def test_domain_target_readback_rejects_unexpected_service_settings(tmp_path: Path, key: str, value: object) -> None:
    from fortipam_mcp.target_contract import DomainTargetCreateInput

    tmp_path.chmod(0o700)
    responses = _domain_responses()
    payload = json.loads(responses[9].content)
    payload["results"][0][key] = value
    responses[9] = _Response(200, payload)
    calls: list[dict[str, object]] = []
    transport = FortiPamTargetHttpTransport(_config(), client_factory=lambda **_: _Client(responses, calls))
    result = transport.create_domain_target_and_readback(
        DomainTargetCreateInput("mcp-v4-target-domain-20261002-r1", "192.0.2.73", "ad.example.test"),
        claim_path=tmp_path / "claim.json",
    )
    assert not result.verified
    assert len([call for call in calls if call["method"] == "POST"]) == 1


def _web_request():
    from fortipam_mcp.target_contract import WebTargetCreateInput
    return WebTargetCreateInput("mcp-v4-target-web-20261003-r1", "https://app.example.test/login")


def _web_responses() -> list[_Response]:
    defaults = json.loads(_default_response_70().content)
    defaults.update(version="v7.0.0", build=29)
    from fortipam_mcp.target_http_transport import _target_create_body_70
    body = _target_create_body_70(defaults["results"], name=_web_request().target_name,
        address="", owner_username="unit-test-owner", web_proxy_enabled=False)
    body.update(template="Web Account", url=_web_request().web_url)
    body.pop("web-proxy"); body["sql-log"] = {}; body.pop("$originalName")
    return [_version_response("v7.0.0", 29), _domain_envelope([], status=404),
        _Response(200, {"version": "v7.0.0", "build": 29, "results": [{"name": "Web Account",
            "field": [{"name": n, "type": t} for n, t in
                      (("URL", "url"), ("Username", "username"), ("Password", "password"))]}]}),
        _Response(200, defaults), _owner_response(), _group_response(),
        _domain_envelope([], method="POST"), _domain_envelope([body])]


@pytest.mark.parametrize("url", ["ftp://app.example.test", "https://user:password@app.example.test",
    "https://app.example.test/#", "https://app.example.test/\n", "https://app.example.test:70000",
    "https://app.example.test:0", "https://app.example.test/" + "x" * 255])
def test_web_target_binding_rejects_unsupported_url_without_disclosure(url: str) -> None:
    from fortipam_mcp.target_contract import WebTargetCreateInput
    with pytest.raises(ValueError) as error:
        WebTargetCreateInput(_web_request().target_name, url)
    assert url not in str(error.value)
    assert _web_request().target_name not in repr(_web_request())
    assert _web_request().web_url not in repr(_web_request())


@pytest.mark.parametrize("failure", [None, "duplicate", "ambiguous_ack", "lost_ack", "fsync"])
def test_web_target_create_once_and_durable_replay_denial(tmp_path: Path, monkeypatch, failure: str | None) -> None:
    tmp_path.chmod(0o700)
    claim = tmp_path / "web.claim.json"
    calls: list[dict[str, object]] = []; responses = _web_responses()
    if failure == "duplicate":
        responses[6] = _domain_envelope([], method="POST", status=500)
    if failure == "ambiguous_ack":
        responses[6] = _Response(200, {"status": "success"})
    class Client(_Client):
        def request(self, method, url, **kwargs):
            if method == "POST":
                assert claim.exists()
                if failure == "lost_ack":
                    self._calls.append({"method": method, "url": url})
                    raise TimeoutError
            return super().request(method, url, **kwargs)
    factory = lambda **_: Client(responses, calls)
    transport = FortiPamTargetHttpTransport(_config(), client_factory=factory)
    if failure == "fsync":
        monkeypatch.setattr(transport_module.os, "fsync", lambda _: (_ for _ in ()).throw(OSError("sync failed")))
    if failure:
        with pytest.raises((TargetHttpTransportError, OSError)):
            transport.create_web_target_and_readback(_web_request(), claim_path=claim, expected_state_digest=_web_expected_digest(), expires_at=int(time.time()) + 60)
    else:
        assert transport.create_web_target_and_readback(_web_request(), claim_path=claim, expected_state_digest=_web_expected_digest(), expires_at=int(time.time()) + 60).verified
        body = next(c["json"] for c in calls if c["method"] == "POST")
        assert body["template"] == "Web Account" and body["url"] == _web_request().web_url
        assert body["address"] == "" and body["web-proxy-status"] == "disable"
        assert "web-proxy" not in body and body["sql-log"] == {}
    assert claim.exists() and claim.stat().st_mode & 0o777 == 0o600
    assert json.loads(claim.read_text())["contract"] == "fortipam_700_web_target_create_v1"
    assert _web_request().web_url not in claim.read_text()
    assert sum(c["method"] == "POST" for c in calls) == (0 if failure == "fsync" else 1)
    previous = len(calls)
    with pytest.raises(TargetHttpTransportError):
        FortiPamTargetHttpTransport(_config(), client_factory=factory).create_web_target_and_readback(
            _web_request(), claim_path=claim, expected_state_digest=_web_expected_digest(), expires_at=int(time.time()) + 60)
    assert len(calls) == previous


@pytest.mark.parametrize("defect", ["version", "visible_existing", "template", "defaults", "owner", "group"])
def test_web_target_prerequisite_failure_does_not_consume_or_write(tmp_path: Path, defect: str) -> None:
    tmp_path.chmod(0o700); claim = tmp_path / "web.claim.json"
    calls: list[dict[str, object]] = []; responses = _web_responses()
    index = {"version": 0, "visible_existing": 1, "template": 2, "defaults": 3, "owner": 4, "group": 5}[defect]
    responses[index] = _Response(403, {})
    transport = FortiPamTargetHttpTransport(_config(), client_factory=lambda **_: _Client(responses, calls))
    with pytest.raises(TargetHttpTransportError):
        transport.create_web_target_and_readback(_web_request(), claim_path=claim, expected_state_digest=_web_expected_digest(), expires_at=int(time.time()) + 60)
    assert not claim.exists() and all(c["method"] == "GET" for c in calls)


@pytest.mark.parametrize("key,value", [("url", "https://other.example.test"), ("template", "Windows Machine"),
    ("address", "192.0.2.10"), ("web-proxy-status", "enable"), ("group-permission", []),
    ("ssh-hostkey-verification", "enable"), ("gateway", "unexpected-gateway")])
def test_web_target_readback_drift_is_unaccepted_and_nonretryable(tmp_path: Path, key: str, value: object) -> None:
    tmp_path.chmod(0o700); claim = tmp_path / "web.claim.json"
    calls: list[dict[str, object]] = []; responses = _web_responses()
    payload = json.loads(responses[-1].content); payload["results"][0][key] = value
    responses[-1] = _Response(200, payload)
    transport = FortiPamTargetHttpTransport(_config(), client_factory=lambda **_: _Client(responses, calls))
    assert not transport.create_web_target_and_readback(_web_request(), claim_path=claim, expected_state_digest=_web_expected_digest(), expires_at=int(time.time()) + 60).verified
    assert claim.exists() and sum(c["method"] == "POST" for c in calls) == 1


@pytest.mark.parametrize("defect", ["template_fields", "template_build", "default_address", "default_ssh", "default_build"])
def test_web_target_success_response_with_wrong_dependency_rejects_before_write(tmp_path: Path, defect: str) -> None:
    tmp_path.chmod(0o700); claim = tmp_path / "web.claim.json"
    calls: list[dict[str, object]] = []; responses = _web_responses()
    index = 2 if defect.startswith("template") else 3
    payload = json.loads(responses[index].content)
    if defect == "template_fields":
        payload["results"][0]["field"][0]["type"] = "target-address"
    elif defect.endswith("build"):
        payload["build"] = 30
    else:
        payload["results"]["address" if defect == "default_address" else "ssh-hostkey-verification"] = (
            "192.0.2.80" if defect == "default_address" else "enable")
    responses[index] = _Response(200, payload)
    transport = FortiPamTargetHttpTransport(_config(), client_factory=lambda **_: _Client(responses, calls))
    with pytest.raises(TargetHttpTransportError):
        transport.create_web_target_and_readback(_web_request(), claim_path=claim, expected_state_digest=_web_expected_digest(), expires_at=int(time.time()) + 60)
    assert not claim.exists() and all(c["method"] == "GET" for c in calls)


def _web_expected_digest() -> str:
    body = json.loads(_web_responses()[-1].content)["results"][0]
    body["$originalName"] = _web_request().target_name
    return transport_module._mapping_digest(body)


@pytest.mark.parametrize("reason", ["body_drift", "expired", "expires_during_read"])
def test_web_target_rechecks_preview_before_reserving_dispatch(tmp_path, monkeypatch, reason) -> None:
    tmp_path.chmod(0o700); claim = tmp_path / "web.claim.json"
    calls: list[dict[str, object]] = []; responses = _web_responses()
    transport = FortiPamTargetHttpTransport(_config(), client_factory=lambda **_: _Client(responses, calls))
    expected = transport.inspect_web_target_create(_web_request(), claim_path=claim)
    assert expected == _web_expected_digest() and not claim.exists()
    responses[:] = _web_responses()
    if reason == "body_drift":
        payload = json.loads(responses[3].content); payload["results"]["ca"] = "different-ca"
        responses[3] = _Response(200, payload)
    clock = iter([2000, 2000] if reason == "expired" else [1000, 2000] if reason == "expires_during_read" else [1000, 1000])
    monkeypatch.setattr(transport_module.time, "time", lambda: next(clock))
    with pytest.raises(TargetHttpTransportError):
        transport.create_web_target_and_readback(_web_request(), claim_path=claim,
            expected_state_digest=expected, expires_at=1600)
    assert not claim.exists() and all(c["method"] == "GET" for c in calls)


def test_web_target_expiry_during_claim_persistence_keeps_claim_without_post(tmp_path, monkeypatch) -> None:
    tmp_path.chmod(0o700); claim = tmp_path / "web.claim.json"
    calls: list[dict[str, object]] = []; responses = _web_responses()
    now = [1000]
    monkeypatch.setattr(transport_module.time, "time", lambda: now[0])
    original = transport_module._reserve_target_create_claim
    def reserve(path, body, *, profile):
        original(path, body, profile=profile)
        now[0] = 1600
    monkeypatch.setattr(transport_module, "_reserve_target_create_claim", reserve)
    transport = FortiPamTargetHttpTransport(_config(), client_factory=lambda **_: _Client(responses, calls))
    with pytest.raises(TargetHttpTransportError):
        transport.create_web_target_and_readback(_web_request(), claim_path=claim,
            expected_state_digest=_web_expected_digest(), expires_at=1600)
    assert claim.exists() and all(c["method"] == "GET" for c in calls)


@pytest.mark.parametrize("defect", [None, "wrong_row", "wrong_principal", "extra_permission", "unknown_field", "boolean_origin"])
def test_web_target_native_origin_metadata_preserves_exact_acl_check(tmp_path, defect) -> None:
    tmp_path.chmod(0o700); claim = tmp_path / "web.claim.json"
    calls: list[dict[str, object]] = []; responses = _web_responses()
    payload = json.loads(responses[-1].content); detail = payload["results"][0]
    for collection, key in (("user-permission", "user-name"), ("group-permission", "group-name")):
        row = detail[collection][0]; row["q_origin_key"] = str(row["id"])
        row[key][0]["q_origin_key"] = row[key][0]["name"]
    row = detail["user-permission"][0]
    if defect == "wrong_row": row["q_origin_key"] = "999"
    if defect == "wrong_principal": row["user-name"][0]["q_origin_key"] = "other-user"
    if defect == "extra_permission": detail["user-permission"].append(dict(row))
    if defect == "unknown_field": row["unqualified"] = True
    if defect == "boolean_origin": row["q_origin_key"] = True
    responses[-1] = _Response(200, payload)
    transport = FortiPamTargetHttpTransport(_config(), client_factory=lambda **_: _Client(responses, calls))
    result = transport.create_web_target_and_readback(_web_request(), claim_path=claim,
        expected_state_digest=_web_expected_digest(), expires_at=int(time.time()) + 60)
    assert result.verified is (defect is None)
    assert claim.exists() and sum(c["method"] == "POST" for c in calls) == 1


@pytest.mark.parametrize("defect", [None, "binding", "defaults", "claim_contract", "claim_public", "claim_symlink", "acl"])
def test_web_target_independent_reconciliation_is_readonly_and_preserves_claim(tmp_path, defect) -> None:
    from dataclasses import replace
    tmp_path.chmod(0o700); claim = tmp_path / "web.claim.json"
    value = {"contract": "fortipam_700_web_target_create_v1", "state": "post_attempt_reserved",
             "request_digest": _web_expected_digest(), "reserved_at": 123}
    if defect == "claim_contract": value["contract"] = "fortipam_700_domain_target_create_v1"
    claim.write_text(json.dumps(value)); claim.chmod(0o644 if defect == "claim_public" else 0o600)
    if defect == "claim_symlink":
        link = tmp_path / "linked.json"; link.symlink_to(claim); claim = link
    before = claim.read_bytes()
    rows = _web_responses(); responses = [rows[0], rows[3], rows[-1]]
    defaults = json.loads(responses[1].content)
    if defect == "defaults": defaults["results"]["ca"] = "changed-ca"
    responses[1] = _Response(200, defaults)
    payload = json.loads(responses[-1].content); row = payload["results"][0]["user-permission"][0]
    row["q_origin_key"] = "99" if defect == "acl" else "1"
    responses[-1] = _Response(200, payload)
    calls: list[dict[str, object]] = []
    transport = FortiPamTargetHttpTransport(_config(), client_factory=lambda **_: _Client(responses, calls))
    request = replace(_web_request(), web_url="https://other.example.test") if defect == "binding" else _web_request()
    if defect not in (None, "acl"):
        with pytest.raises(TargetHttpTransportError):
            transport.reconcile_web_target_create(request, claim_path=claim)
    else:
        assert transport.reconcile_web_target_create(request, claim_path=claim).verified is (defect is None)
    assert claim.read_bytes() == before and all(c["method"] == "GET" for c in calls)
    if defect and defect.startswith("claim_"): assert not calls


def _web_namespace_observation(*, absent=True, candidate=None):
    from fortipam_mcp.target_namespace_ssh_reader import TargetNamespaceObservation, _candidate_digest
    return TargetNamespaceObservation(
        "name_absent" if absent else "name_present", 2 if absent else 3, 2,
        "a" * 64, absent, _candidate_digest(candidate or _web_request().target_name),
    )


@pytest.mark.parametrize("reason", ["present", "wrong_candidate", "untyped", "failure"])
def test_web_target_namespace_rejects_before_claim_or_post(tmp_path, reason) -> None:
    tmp_path.chmod(0o700)
    claim = tmp_path / "namespace.claim.json"
    calls = []
    responses = _web_responses()
    def observe(name):
        assert name == _web_request().target_name
        if reason == "failure":
            raise RuntimeError("private native output")
        if reason == "untyped":
            return {"global_name_absent": True}
        return _web_namespace_observation(absent=reason != "present",
            candidate="mcp-v4-target-web-20261007-r9" if reason == "wrong_candidate" else None)
    transport = FortiPamTargetHttpTransport(_config(),
        client_factory=lambda **_: _Client(responses, calls), web_target_namespace_observer=observe)
    with pytest.raises(TargetHttpTransportError) as error:
        transport.create_web_target_and_readback(_web_request(), claim_path=claim,
            expected_state_digest=_web_expected_digest(), expires_at=int(time.time()) + 60)
    assert not claim.exists() and all(call["method"] == "GET" for call in calls)
    assert "private native output" not in str(error.value)


@pytest.mark.parametrize("after_present", [True, False])
def test_web_target_namespace_requires_presence_after_one_post(tmp_path, after_present) -> None:
    tmp_path.chmod(0o700)
    claim = tmp_path / "namespace.claim.json"
    calls = []
    observed = []
    responses = _web_responses()
    def observe(name):
        observed.append(name)
        return _web_namespace_observation(absent=len(observed) == 1 or not after_present)
    transport = FortiPamTargetHttpTransport(_config(),
        client_factory=lambda **_: _Client(responses, calls), web_target_namespace_observer=observe)
    if after_present:
        assert transport.create_web_target_and_readback(_web_request(), claim_path=claim,
            expected_state_digest=_web_expected_digest(), expires_at=int(time.time()) + 60).verified
    else:
        with pytest.raises(TargetHttpTransportError):
            transport.create_web_target_and_readback(_web_request(), claim_path=claim,
                expected_state_digest=_web_expected_digest(), expires_at=int(time.time()) + 60)
    assert len(observed) == 2 and claim.exists()
    assert sum(call["method"] == "POST" for call in calls) == 1
    previous = len(calls)
    with pytest.raises(TargetHttpTransportError):
        transport.create_web_target_and_readback(_web_request(), claim_path=claim,
            expected_state_digest=_web_expected_digest(), expires_at=int(time.time()) + 60)
    assert len(calls) == previous and len(observed) == 2


def test_web_target_namespace_drift_after_preview_prevents_dispatch(tmp_path) -> None:
    tmp_path.chmod(0o700)
    claim = tmp_path / "namespace.claim.json"
    calls = []
    observed = []
    responses = _web_responses()[:6] + _web_responses()
    def observe(name):
        observed.append(name)
        return _web_namespace_observation(absent=len(observed) == 1)
    transport = FortiPamTargetHttpTransport(_config(),
        client_factory=lambda **_: _Client(responses, calls), web_target_namespace_observer=observe)
    expected = transport.inspect_web_target_create(_web_request(), claim_path=claim)
    with pytest.raises(TargetHttpTransportError):
        transport.create_web_target_and_readback(_web_request(), claim_path=claim,
            expected_state_digest=expected, expires_at=int(time.time()) + 60)
    assert len(observed) == 2 and not claim.exists()
    assert all(call["method"] == "GET" for call in calls)


def test_web_target_namespace_slow_read_rechecks_expiry_before_claim(tmp_path, monkeypatch) -> None:
    tmp_path.chmod(0o700)
    claim = tmp_path / "namespace.claim.json"
    calls = []
    responses = _web_responses()
    clock = [100]
    monkeypatch.setattr(transport_module.time, "time", lambda: clock[0])
    def observe(name):
        clock[0] = 200
        return _web_namespace_observation()
    transport = FortiPamTargetHttpTransport(_config(),
        client_factory=lambda **_: _Client(responses, calls), web_target_namespace_observer=observe)
    with pytest.raises(TargetHttpTransportError):
        transport.create_web_target_and_readback(_web_request(), claim_path=claim,
            expected_state_digest=_web_expected_digest(), expires_at=150)
    assert not claim.exists() and all(call["method"] == "GET" for call in calls)


def test_web_target_historical_reconciliation_does_not_use_candidate_namespace(tmp_path) -> None:
    tmp_path.chmod(0o700)
    claim = tmp_path / "web.claim.json"
    claim.write_text(json.dumps({"contract": "fortipam_700_web_target_create_v1",
        "state": "post_attempt_reserved", "request_digest": _web_expected_digest(), "reserved_at": 123}))
    claim.chmod(0o600)
    before = claim.read_bytes()
    calls = []
    rows = _web_responses()
    responses = [rows[0], rows[3], rows[-1]]
    def observe(name):
        pytest.fail("Historical reconciliation must not acquire new candidate authority.")
    transport = FortiPamTargetHttpTransport(_config(),
        client_factory=lambda **_: _Client(responses, calls),
        web_target_namespace_observer=observe)
    assert transport.reconcile_web_target_create(_web_request(), claim_path=claim).verified
    assert claim.read_bytes() == before and all(call["method"] == "GET" for call in calls)
