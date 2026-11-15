from __future__ import annotations

import json
from pathlib import Path

import pytest

import fortipam_mcp.character_set_http_transport as transport_module
from fortipam_mcp.character_set_http_transport import (
    CHARACTER_SET_DELETE_NAME,
    CHARACTER_SET_VALUE,
    CharacterSetHttpTransportConfig,
    CharacterSetHttpTransportConfigurationError,
    CharacterSetHttpTransportError,
    FortiPamCharacterSetHttpTransport,
    load_character_set_http_transport_config,
)


NAME = "mcp-v4-char-set-01"


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


def _config() -> CharacterSetHttpTransportConfig:
    return CharacterSetHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _delete_payload() -> dict[str, object]:
    return {
        "results": [
            {
                "name": CHARACTER_SET_DELETE_NAME,
                "char-set": CHARACTER_SET_VALUE,
                "q_origin_key": "opaque-origin-key",
            }
        ]
    }


def _password_policies(*, referenced: bool = False) -> dict[str, object]:
    return {
        "results": [
            {
                "name": "categorical-policy",
                "password-requirement": [
                    {
                        "id": 1,
                        "char-set": (
                            CHARACTER_SET_DELETE_NAME if referenced else "lower"
                        ),
                        "minimum-num": 1,
                    }
                ],
            }
        ]
    }


def test_loader_requires_exact_opt_in_and_dedicated_configuration(tmp_path: Path) -> None:
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("unit-test-ca\n", encoding="utf-8")
    environment = {
        "FPA_HOME_LAB_FPA1_V4_CHARACTER_SET_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_CHARACTER_SET_API_BASE_URL": "https://fpa.example.test",
        "FPA_HOME_LAB_FPA1_V4_CHARACTER_SET_API_API_TOKEN": "unit-test-token",
        "FPA_HOME_LAB_FPA1_V4_CHARACTER_SET_API_CA_FILE": str(ca_file),
        "FPA_HOME_LAB_FPA1_V4_CHARACTER_SET_API_TIMEOUT_SECONDS": "12",
    }

    loaded = load_character_set_http_transport_config(environment)

    assert loaded.base_url == "https://fpa.example.test"
    assert loaded.timeout_seconds == 12
    environment["FPA_HOME_LAB_FPA1_V4_CHARACTER_SET_API_ENABLED"] = "false"
    with pytest.raises(CharacterSetHttpTransportConfigurationError, match="ENABLED"):
        load_character_set_http_transport_config(environment)


def test_inspect_maps_only_json_404_to_character_set_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamCharacterSetHttpTransport(
        _config(), client_factory=lambda **_: _Client([_Response(404, {})], calls)
    )

    result = transport.inspect(NAME)

    assert result.exists is False
    assert calls == [
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/cmdb/secret/password-char-set/mcp-v4-char-set-01",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": None,
        }
    ]


def test_create_posts_only_documented_fixed_body_then_reads_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, {"http_status": 200}),
        _Response(
            200,
            {"results": [{"name": NAME, "char-set": CHARACTER_SET_VALUE}]},
        ),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamCharacterSetHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    result = transport.create_and_readback(NAME)

    assert result.verified is True
    assert calls == [
        {
            "method": "POST",
            "url": "https://fpa.example.test/api/v2/cmdb/secret/password-char-set",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": {"name": NAME, "char-set": CHARACTER_SET_VALUE},
        },
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/cmdb/secret/password-char-set/mcp-v4-char-set-01",
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
    rejected = FortiPamCharacterSetHttpTransport(
        _config(), client_factory=lambda **_: _Client([_Response(400, {})], [])
    )
    with pytest.raises(CharacterSetHttpTransportError):
        rejected.create_and_readback(NAME)

    partial = FortiPamCharacterSetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [
                _Response(200, {"http_status": 200}),
                _Response(200, {"results": [{"name": NAME}]}),
            ],
            [],
        ),
    )
    assert partial.create_and_readback(NAME).verified is False
    with pytest.raises(CharacterSetHttpTransportError):
        rejected.inspect("outside-lab-scope")


def test_inspect_requires_one_supported_detail_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamCharacterSetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [_Response(200, {"results": [{"name": NAME, "char-set": CHARACTER_SET_VALUE}]})],
            [],
        ),
    )

    assert transport.inspect(NAME).exists is True


def test_delete_inspection_requires_exact_shape_and_zero_policy_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamCharacterSetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [_Response(200, _delete_payload()), _Response(200, _password_policies())],
            [],
        ),
    )

    inspection = transport.inspect_delete_target()

    assert inspection.exists is True
    assert inspection.eligible_fixed_character_set is True
    assert inspection.password_policy_reference_count == 0
    assert len(inspection.target_digest) == 64

    referenced_responses = [
        _Response(200, _delete_payload()),
        _Response(200, _password_policies(referenced=True)),
    ]
    referenced = FortiPamCharacterSetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(referenced_responses, []),
    ).inspect_delete_target()
    assert referenced.eligible_fixed_character_set is False
    assert referenced.password_policy_reference_count == 1

    drifted = _delete_payload()
    record = drifted["results"][0]
    assert isinstance(record, dict)
    record["char-set"] = "drifted"
    rejected = FortiPamCharacterSetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client([_Response(200, drifted)], []),
    )
    with pytest.raises(CharacterSetHttpTransportError):
        rejected.inspect_delete_target()


def test_delete_uses_fixed_detail_dependency_read_delete_and_absence_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    digest_transport = FortiPamCharacterSetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [_Response(200, _delete_payload()), _Response(200, _password_policies())],
            [],
        ),
    )
    digest = digest_transport.inspect_delete_target().target_digest
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, _delete_payload()),
        _Response(200, _password_policies()),
        _Response(200, {"http_status": 200}),
        _Response(404, {}),
    ]
    transport = FortiPamCharacterSetHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    result = transport.delete_and_readback(digest)

    assert result.verified is True
    assert [call["method"] for call in calls] == ["GET", "GET", "DELETE", "GET"]
    assert str(calls[0]["url"]).endswith(
        "/api/v2/cmdb/secret/password-char-set/mcp-v4-char-set-b25"
    )
    assert str(calls[1]["url"]).endswith(
        "/api/v2/cmdb/secret/password-policy"
    )
    assert str(calls[2]["url"]).endswith(
        "/api/v2/cmdb/secret/password-char-set/mcp-v4-char-set-b25"
    )
    assert str(calls[3]["url"]).endswith(
        "/api/v2/cmdb/secret/password-char-set/mcp-v4-char-set-b25"
    )
    assert all(call["json"] is None for call in calls)


def test_delete_rejects_invalid_digest_missing_target_or_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamCharacterSetHttpTransport(
        _config(), client_factory=lambda **_: _Client([_Response(404, {})], [])
    )
    with pytest.raises(CharacterSetHttpTransportError):
        transport.delete_and_readback("invalid")
    with pytest.raises(CharacterSetHttpTransportError):
        transport.delete_and_readback("a" * 64)

    referenced_responses = [
        _Response(200, _delete_payload()),
        _Response(200, _password_policies(referenced=True)),
    ]
    referenced = FortiPamCharacterSetHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(referenced_responses, []),
    )
    with pytest.raises(CharacterSetHttpTransportError):
        referenced.delete_and_readback("a" * 64)
