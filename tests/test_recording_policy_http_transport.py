from __future__ import annotations

import json
from pathlib import Path

import pytest

import fortipam_mcp.recording_policy_http_transport as transport_module
from fortipam_mcp.recording_policy_http_transport import (
    FortiPamRecordingPolicyHttpTransport,
    RecordingPolicyHttpTransportConfig,
    RecordingPolicyHttpTransportConfigurationError,
    RecordingPolicyHttpTransportError,
    load_recording_policy_http_transport_config,
)


NAME = "mcp-v4-secret-policy-recording-01"


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


def _config() -> RecordingPolicyHttpTransportConfig:
    return RecordingPolicyHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _detail(recording: str) -> dict[str, object]:
    return {"results": [{"name": NAME, "recording": recording}]}


def test_loader_requires_exact_opt_in_and_dedicated_configuration(tmp_path: Path) -> None:
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("unit-test-ca\n", encoding="utf-8")
    environment = {
        "FPA_HOME_LAB_FPA1_V4_RECORDING_POLICY_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_RECORDING_POLICY_API_BASE_URL": "https://fpa.example.test",
        "FPA_HOME_LAB_FPA1_V4_RECORDING_POLICY_API_API_TOKEN": "unit-test-token",
        "FPA_HOME_LAB_FPA1_V4_RECORDING_POLICY_API_CA_FILE": str(ca_file),
        "FPA_HOME_LAB_FPA1_V4_RECORDING_POLICY_API_TIMEOUT_SECONDS": "12",
    }

    loaded = load_recording_policy_http_transport_config(environment)

    assert loaded.base_url == "https://fpa.example.test"
    assert loaded.timeout_seconds == 12
    environment["FPA_HOME_LAB_FPA1_V4_RECORDING_POLICY_API_ENABLED"] = "false"
    with pytest.raises(RecordingPolicyHttpTransportConfigurationError, match="ENABLED"):
        load_recording_policy_http_transport_config(environment)


def test_inspect_projects_only_categorical_recording_posture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamRecordingPolicyHttpTransport(
        _config(), client_factory=lambda **_: _Client([_Response(200, _detail("not-set"))], calls)
    )

    result = transport.inspect(NAME)

    assert result.policy_exists is True
    assert result.recording_enabled is False
    assert result.ready_to_enable is True
    assert len(result.state_digest) == 64
    assert calls == [
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/cmdb/secret/policy/mcp-v4-secret-policy-recording-01",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": None,
        }
    ]


def test_enable_rechecks_baseline_writes_only_recording_then_reads_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, _detail("disable")),
        _Response(200, {"http_status": 200}),
        _Response(200, _detail("enable")),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamRecordingPolicyHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    result = transport.enable_and_readback(NAME)

    assert result.verified is True
    assert calls[1] == {
        "method": "PUT",
        "url": "https://fpa.example.test/api/v2/cmdb/secret/policy/mcp-v4-secret-policy-recording-01",
        "headers": {
            "Accept": "application/json",
            "Authorization": "Bearer unit-test-token",
        },
        "json": {"recording": "enable"},
    }
    assert [call["method"] for call in calls] == ["GET", "PUT", "GET"]


def test_transport_fails_closed_for_existing_enabled_unknown_or_invalid_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    enabled = FortiPamRecordingPolicyHttpTransport(
        _config(), client_factory=lambda **_: _Client([_Response(200, _detail("enable"))], [])
    )
    assert enabled.inspect(NAME).recording_enabled is True
    rejected = FortiPamRecordingPolicyHttpTransport(
        _config(), client_factory=lambda **_: _Client([_Response(200, _detail("unknown"))], [])
    )
    with pytest.raises(RecordingPolicyHttpTransportError):
        rejected.inspect(NAME)
    with pytest.raises(RecordingPolicyHttpTransportError):
        rejected.inspect("outside-lab-scope")


def test_transport_returns_unverified_readback_for_missing_detail_after_put(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamRecordingPolicyHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [
                _Response(200, _detail("not-set")),
                _Response(200, {"http_status": 200}),
                _Response(404, {}),
            ],
            [],
        ),
    )

    assert transport.enable_and_readback(NAME).verified is False
