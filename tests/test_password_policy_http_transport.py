from __future__ import annotations

import json
from pathlib import Path

import pytest

import fortipam_mcp.password_policy_http_transport as transport_module
from fortipam_mcp.password_policy_http_transport import (
    MAXIMUM_LENGTH,
    MINIMUM_LENGTH,
    PASSWORD_REQUIREMENTS,
    PASSWORD_POLICY_DELETE_NAME,
    FortiPamPasswordPolicyHttpTransport,
    PasswordPolicyHttpTransportConfig,
    PasswordPolicyHttpTransportConfigurationError,
    PasswordPolicyHttpTransportError,
    load_password_policy_http_transport_config,
)


NAME = "mcp-v4-password-policy-01"


class _Response:
    def __init__(self, status_code: int, payload: object) -> None:
        self.status_code = status_code
        self.content = json.dumps(payload).encode("utf-8")
        self.headers = {"content-type": "application/json"}


class _Client:
    def __init__(self, responses: list[_Response], calls: list[dict[str, object]]) -> None:
        self._responses = responses
        self._calls = calls

    def __enter__(self) -> _Client:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def request(self, method: str, url: str, **kwargs: object) -> _Response:
        self._calls.append({"method": method, "url": url, **kwargs})
        return self._responses.pop(0)


def _config() -> PasswordPolicyHttpTransportConfig:
    return PasswordPolicyHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _readback_payload() -> dict[str, object]:
    return {
        "results": [
            {
                "name": NAME,
                "minimum-length": MINIMUM_LENGTH,
                "maximum-length": MAXIMUM_LENGTH,
                "password-requirement": [
                    {
                        "id": requirement_id,
                        "char-set": character_set,
                        "minimum-num": minimum_num,
                    }
                    for requirement_id, character_set, minimum_num in PASSWORD_REQUIREMENTS
                ],
            }
        ]
    }


def _delete_payload() -> dict[str, object]:
    payload = _readback_payload()
    record = payload["results"][0]
    assert isinstance(record, dict)
    record["name"] = PASSWORD_POLICY_DELETE_NAME
    record["q_origin_key"] = "opaque-origin-key"
    return payload


def test_loader_requires_exact_opt_in_and_dedicated_configuration(tmp_path: Path) -> None:
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("unit-test-ca\n", encoding="utf-8")
    environment = {
        "FPA_HOME_LAB_FPA1_V4_PASSWORD_POLICY_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_PASSWORD_POLICY_API_BASE_URL": "https://fpa.example.test",
        "FPA_HOME_LAB_FPA1_V4_PASSWORD_POLICY_API_API_TOKEN": "unit-test-token",
        "FPA_HOME_LAB_FPA1_V4_PASSWORD_POLICY_API_CA_FILE": str(ca_file),
        "FPA_HOME_LAB_FPA1_V4_PASSWORD_POLICY_API_TIMEOUT_SECONDS": "12",
    }

    loaded = load_password_policy_http_transport_config(environment)

    assert loaded.base_url == "https://fpa.example.test"
    assert loaded.timeout_seconds == 12
    environment["FPA_HOME_LAB_FPA1_V4_PASSWORD_POLICY_API_ENABLED"] = "false"
    with pytest.raises(PasswordPolicyHttpTransportConfigurationError, match="ENABLED"):
        load_password_policy_http_transport_config(environment)


def test_inspect_maps_only_json_404_to_password_policy_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamPasswordPolicyHttpTransport(
        _config(), client_factory=lambda **_: _Client([_Response(404, {})], calls)
    )

    result = transport.inspect(NAME)

    assert result.exists is False
    assert calls == [
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/cmdb/secret/password-policy/mcp-v4-password-policy-01",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": None,
        }
    ]


def test_create_posts_only_fixed_body_then_reads_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [_Response(200, {"http_status": 200}), _Response(200, _readback_payload())]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamPasswordPolicyHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    result = transport.create_and_readback(NAME)

    assert result.verified is True
    assert calls == [
        {
            "method": "POST",
            "url": "https://fpa.example.test/api/v2/cmdb/secret/password-policy",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": {
                "name": NAME,
                "minimum-length": MINIMUM_LENGTH,
                "maximum-length": MAXIMUM_LENGTH,
                "password-requirement": [
                    {
                        "id": requirement_id,
                        "char-set": character_set,
                        "minimum-num": minimum_num,
                    }
                    for requirement_id, character_set, minimum_num in PASSWORD_REQUIREMENTS
                ],
            },
        },
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/cmdb/secret/password-policy/mcp-v4-password-policy-01",
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
    rejected = FortiPamPasswordPolicyHttpTransport(
        _config(), client_factory=lambda **_: _Client([_Response(400, {})], [])
    )
    with pytest.raises(PasswordPolicyHttpTransportError):
        rejected.create_and_readback(NAME)

    partial = FortiPamPasswordPolicyHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [_Response(200, {"http_status": 200}), _Response(200, {"results": [{"name": NAME}]})],
            [],
        ),
    )
    assert partial.create_and_readback(NAME).verified is False
    with pytest.raises(PasswordPolicyHttpTransportError):
        rejected.inspect("outside-lab-scope")


def test_inspect_requires_one_supported_detail_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamPasswordPolicyHttpTransport(
        _config(),
        client_factory=lambda **_: _Client([_Response(200, _readback_payload())], []),
    )

    assert transport.inspect(NAME).exists is True


def test_delete_inspection_accepts_only_the_exact_fixed_policy_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamPasswordPolicyHttpTransport(
        _config(),
        client_factory=lambda **_: _Client([_Response(200, _delete_payload())], []),
    )

    inspection = transport.inspect_delete_target()

    assert inspection.exists is True
    assert inspection.eligible_fixed_policy is True
    assert len(inspection.target_digest) == 64

    drifted = _delete_payload()
    drifted_record = drifted["results"][0]
    assert isinstance(drifted_record, dict)
    drifted_record["maximum-length"] = 17
    rejected = FortiPamPasswordPolicyHttpTransport(
        _config(),
        client_factory=lambda **_: _Client([_Response(200, drifted)], []),
    )
    with pytest.raises(PasswordPolicyHttpTransportError):
        rejected.inspect_delete_target()


def test_delete_uses_only_fixed_detail_delete_and_absence_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    digest_transport = FortiPamPasswordPolicyHttpTransport(
        _config(),
        client_factory=lambda **_: _Client([_Response(200, _delete_payload())], []),
    )
    digest = digest_transport.inspect_delete_target().target_digest
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, _delete_payload()),
        _Response(200, {"http_status": 200}),
        _Response(404, {}),
    ]
    transport = FortiPamPasswordPolicyHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, calls),
    )

    result = transport.delete_and_readback(digest)

    assert result.verified is True
    assert [call["method"] for call in calls] == ["GET", "DELETE", "GET"]
    assert all(
        str(call["url"]).endswith(
            "/api/v2/cmdb/secret/password-policy/mcp-v4-password-policy-b28"
        )
        for call in calls
    )
    assert all(call["json"] is None for call in calls)


def test_delete_rejects_invalid_digest_and_missing_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamPasswordPolicyHttpTransport(
        _config(),
        client_factory=lambda **_: _Client([_Response(404, {})], []),
    )
    with pytest.raises(PasswordPolicyHttpTransportError):
        transport.delete_and_readback("invalid")
    with pytest.raises(PasswordPolicyHttpTransportError):
        transport.delete_and_readback("a" * 64)
