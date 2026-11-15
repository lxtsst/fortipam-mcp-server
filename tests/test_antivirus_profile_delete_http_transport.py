from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import fortipam_mcp.antivirus_profile_delete_http_transport as transport_module
from fortipam_mcp.antivirus_profile_delete_http_transport import (
    ANTIVIRUS_PROFILE_DELETE_NAME,
    AntivirusProfileDeleteHttpTransportConfig,
    AntivirusProfileDeleteHttpTransportConfigurationError,
    AntivirusProfileDeleteHttpTransportError,
    FortiPamAntivirusProfileDeleteHttpTransport,
    load_antivirus_profile_delete_http_transport_config,
)
from fortipam_mcp.antivirus_profile_ssh_transport import (
    AntivirusProfileInspection,
    AntivirusProfileReadback,
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


class _SshTransport:
    def __init__(self) -> None:
        self.readback_verified = True
        self.exists = True
        self.readback_calls: list[str] = []
        self.inspect_calls: list[str] = []

    def readback(self, name: str) -> AntivirusProfileReadback:
        self.readback_calls.append(name)
        return AntivirusProfileReadback(
            self.readback_verified,
            self.readback_verified,
            self.readback_verified,
            self.readback_verified,
            self.readback_verified,
        )

    def inspect(self, name: str) -> AntivirusProfileInspection:
        self.inspect_calls.append(name)
        return AntivirusProfileInspection(self.exists)


def _config() -> AntivirusProfileDeleteHttpTransportConfig:
    return AntivirusProfileDeleteHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _record() -> dict[str, object]:
    return {
        "name": ANTIVIRUS_PROFILE_DELETE_NAME,
        "q_origin_key": ANTIVIRUS_PROFILE_DELETE_NAME,
        "http": {"av-scan": "block"},
        "ssh": {"av-scan": "block"},
        "scan-archive": "disable",
    }


def _digest(record: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            record,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _detail(record: dict[str, object] | None = None) -> dict[str, object]:
    return {"results": [record or _record()]}


def _secrets(*, referenced: bool = False, count: int = 1) -> dict[str, object]:
    return {
        "results": [
            {
                "id": index,
                "antivirus-profile": (
                    ANTIVIRUS_PROFILE_DELETE_NAME if referenced and index == 0 else "other"
                ),
            }
            for index in range(count)
        ]
    }


def _transport(
    responses: list[_Response],
    ssh: _SshTransport,
    calls: list[dict[str, object]] | None = None,
) -> FortiPamAntivirusProfileDeleteHttpTransport:
    request_calls = calls if calls is not None else []
    record = _record()
    return FortiPamAntivirusProfileDeleteHttpTransport(
        _config(),
        ssh,  # type: ignore[arg-type]
        client_factory=lambda **_: _Client(responses, request_calls),
        accepted_digest=_digest(record),
    )


def test_loader_requires_exact_opt_in_and_dedicated_configuration(tmp_path: Path) -> None:
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("unit-test-ca\n", encoding="utf-8")
    environment = {
        "FPA_HOME_LAB_FPA1_V4_ANTIVIRUS_PROFILE_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_ANTIVIRUS_PROFILE_API_BASE_URL": (
            "https://fpa.example.test"
        ),
        "FPA_HOME_LAB_FPA1_V4_ANTIVIRUS_PROFILE_API_API_TOKEN": "unit-test-token",
        "FPA_HOME_LAB_FPA1_V4_ANTIVIRUS_PROFILE_API_CA_FILE": str(ca_file),
        "FPA_HOME_LAB_FPA1_V4_ANTIVIRUS_PROFILE_API_TIMEOUT_SECONDS": "12",
    }

    loaded = load_antivirus_profile_delete_http_transport_config(environment)

    assert loaded.base_url == "https://fpa.example.test"
    assert loaded.timeout_seconds == 12
    environment["FPA_HOME_LAB_FPA1_V4_ANTIVIRUS_PROFILE_API_ENABLED"] = "false"
    with pytest.raises(
        AntivirusProfileDeleteHttpTransportConfigurationError,
        match="ENABLED",
    ):
        load_antivirus_profile_delete_http_transport_config(environment)


def test_inspect_requires_full_digest_api_projection_ssh_projection_and_zero_refs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    ssh = _SshTransport()
    transport = _transport(
        [_Response(200, _detail()), _Response(200, _secrets())],
        ssh,
    )

    inspection = transport.inspect_delete_target()

    assert inspection.exists is True
    assert inspection.eligible_fixed_profile is True
    assert inspection.secret_reference_count == 0
    assert inspection.target_digest == _digest(_record())
    assert ssh.readback_calls == [ANTIVIRUS_PROFILE_DELETE_NAME]

    referenced = _transport(
        [_Response(200, _detail()), _Response(200, _secrets(referenced=True))],
        _SshTransport(),
    ).inspect_delete_target()
    assert referenced.eligible_fixed_profile is False
    assert referenced.secret_reference_count == 1


def test_inspect_fails_closed_on_digest_api_or_ssh_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    drifted = _record()
    drifted["scan-archive"] = "enable"
    with pytest.raises(AntivirusProfileDeleteHttpTransportError):
        _transport([_Response(200, _detail(drifted))], _SshTransport()).inspect_delete_target()

    wrong_projection = _record()
    http = wrong_projection["http"]
    assert isinstance(http, dict)
    http["av-scan"] = "monitor"
    wrong_digest_transport = FortiPamAntivirusProfileDeleteHttpTransport(
        _config(),
        _SshTransport(),  # type: ignore[arg-type]
        client_factory=lambda **_: _Client(
            [_Response(200, _detail(wrong_projection))], []
        ),
        accepted_digest=_digest(wrong_projection),
    )
    with pytest.raises(AntivirusProfileDeleteHttpTransportError):
        wrong_digest_transport.inspect_delete_target()

    ssh = _SshTransport()
    ssh.readback_verified = False
    with pytest.raises(AntivirusProfileDeleteHttpTransportError):
        _transport([_Response(200, _detail())], ssh).inspect_delete_target()


def test_secret_scan_is_complete_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    calls: list[dict[str, object]] = []
    transport = _transport(
        [
            _Response(200, _detail()),
            _Response(200, _secrets(count=100)),
            _Response(200, _secrets(count=1)),
        ],
        _SshTransport(),
        calls,
    )

    assert transport.inspect_delete_target().eligible_fixed_profile is True
    assert str(calls[-2]["url"]).endswith("?start=0&count=100")
    assert str(calls[-1]["url"]).endswith("?start=100&count=100")


def test_delete_rechecks_then_proves_dual_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    calls: list[dict[str, object]] = []
    ssh = _SshTransport()
    ssh.exists = False
    transport = _transport(
        [
            _Response(200, _detail()),
            _Response(200, _secrets()),
            _Response(200, {"http_status": 200}),
            _Response(404, {}),
        ],
        ssh,
        calls,
    )

    result = transport.delete_and_readback(_digest(_record()))

    assert result.verified is True
    assert [call["method"] for call in calls] == ["GET", "GET", "DELETE", "GET"]
    assert all(call["json"] is None for call in calls)
    assert ssh.inspect_calls == [ANTIVIRUS_PROFILE_DELETE_NAME]


def test_delete_rejects_absence_reference_and_ambiguous_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    absent = _transport([_Response(404, {})], _SshTransport())
    with pytest.raises(AntivirusProfileDeleteHttpTransportError):
        absent.delete_and_readback("invalid")
    with pytest.raises(AntivirusProfileDeleteHttpTransportError):
        absent.delete_and_readback(_digest(_record()))

    referenced = _transport(
        [_Response(200, _detail()), _Response(200, _secrets(referenced=True))],
        _SshTransport(),
    )
    with pytest.raises(AntivirusProfileDeleteHttpTransportError):
        referenced.delete_and_readback(_digest(_record()))

    ambiguous = _transport(
        [
            _Response(200, _detail()),
            _Response(200, _secrets()),
            _Response(503, {}),
        ],
        _SshTransport(),
    )
    with pytest.raises(AntivirusProfileDeleteHttpTransportError):
        ambiguous.delete_and_readback(_digest(_record()))
