from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import ANY

import pytest

import fortipam_mcp.maintenance_mode_status_http_transport as transport_module
from fortipam_mcp.maintenance_mode_ssh_transport import (
    MaintenanceModeInspection,
    MaintenanceModeReadback,
)
from fortipam_mcp.maintenance_mode_status_http_transport import (
    FortiPamMaintenanceModeStatusHttpTransport,
    FortiPamMaintenanceModeSuccessorTransport,
    MAINTENANCE_PATH,
    MaintenanceModeStatusHttpTransportConfig,
    MaintenanceModeStatusHttpTransportConfigurationError,
    MaintenanceModeStatusHttpTransportError,
    load_maintenance_mode_status_http_transport_config,
)


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


def _config() -> MaintenanceModeStatusHttpTransportConfig:
    return MaintenanceModeStatusHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _payload(mode: str = "disable") -> bytes:
    return json.dumps(
        {"results": {"mode": mode, "unrelated": "not-returned"}}
    ).encode("utf-8")


def test_loader_requires_exact_enable_and_owner_only_token(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("unit-test-token\n", encoding="utf-8")
    token_file.chmod(0o600)
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("unit-test-ca\n", encoding="utf-8")
    environment = {
        "FPA_HOME_LAB_FPA1_V4_MAINTENANCE_MODE_STATUS_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_MAINTENANCE_MODE_STATUS_API_BASE_URL": "https://fpa.example.test",
        "FPA_HOME_LAB_FPA1_V4_MAINTENANCE_MODE_STATUS_API_API_TOKEN_FILE": str(token_file),
        "FPA_HOME_LAB_FPA1_V4_MAINTENANCE_MODE_STATUS_API_CA_FILE": str(ca_file),
    }

    loaded = load_maintenance_mode_status_http_transport_config(environment)

    assert loaded.base_url == "https://fpa.example.test"
    token_file.chmod(0o644)
    with pytest.raises(MaintenanceModeStatusHttpTransportConfigurationError):
        load_maintenance_mode_status_http_transport_config(environment)


@pytest.mark.parametrize("enabled", (None, "TRUE", "false"))
def test_loader_fails_closed_when_not_exactly_enabled(enabled: str | None) -> None:
    environment = {}
    if enabled is not None:
        environment[
            "FPA_HOME_LAB_FPA1_V4_MAINTENANCE_MODE_STATUS_API_ENABLED"
        ] = enabled

    with pytest.raises(MaintenanceModeStatusHttpTransportConfigurationError):
        load_maintenance_mode_status_http_transport_config(environment)


@pytest.mark.parametrize(
    "base_url",
    (
        "http://fpa.example.test",
        "https://user:password@fpa.example.test",
        "https://fpa.example.test/api",
        "https://fpa.example.test?query=true",
        "https://fpa.example.test:70000",
    ),
)
def test_config_rejects_non_bare_https_origins(base_url: str) -> None:
    with pytest.raises(MaintenanceModeStatusHttpTransportConfigurationError):
        MaintenanceModeStatusHttpTransportConfig(
            base_url=base_url,
            bearer_token="unit-test-token",
            timeout_seconds=15,
            ca_file=None,
        )


@pytest.mark.parametrize("mode", ("enable", "disable"))
def test_exact_get_returns_only_explicit_mode(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    calls: list[dict[str, object]] = []
    factory_kwargs: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())

    def factory(**kwargs: object) -> _Client:
        factory_kwargs.append(kwargs)
        return _Client(_Response(200, _payload(mode)), calls)

    transport = FortiPamMaintenanceModeStatusHttpTransport(
        _config(), client_factory=factory
    )

    assert transport.inspect() == MaintenanceModeInspection(mode)
    assert factory_kwargs == [
        {
            "verify": ANY,
            "timeout": 15.0,
            "follow_redirects": False,
            "trust_env": False,
        }
    ]
    assert calls == [
        {
            "method": "GET",
            "url": f"https://fpa.example.test{MAINTENANCE_PATH}",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
        }
    ]


@pytest.mark.parametrize(
    "response",
    (
        _Response(401, b"{}"),
        _Response(403, b"{}"),
        _Response(404, b"{}"),
        _Response(200, b"not-json"),
        _Response(200, b"{}", "text/plain"),
        _Response(200, b"x" * (transport_module.MAX_RESPONSE_BYTES + 1)),
        _Response(200, b'{"results": {"mode": "unknown"}}'),
        _Response(200, b'{"results": []}'),
        _Response(200, b'{"results": [{"mode": "disable"}, {"mode": "enable"}]}'),
    ),
)
def test_transport_rejects_denied_malformed_oversized_or_ambiguous_state(
    monkeypatch: pytest.MonkeyPatch,
    response: _Response,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamMaintenanceModeStatusHttpTransport(
        _config(), client_factory=lambda **_: _Client(response, [])
    )

    with pytest.raises(MaintenanceModeStatusHttpTransportError):
        transport.inspect()


def test_transport_maps_client_failure_to_stable_non_disclosing_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())

    def fail(**_: object) -> object:
        raise RuntimeError("sensitive transport detail")

    transport = FortiPamMaintenanceModeStatusHttpTransport(
        _config(), client_factory=fail
    )

    with pytest.raises(
        MaintenanceModeStatusHttpTransportError,
        match="transport is unavailable",
    ) as exc_info:
        transport.inspect()
    assert "sensitive transport detail" not in str(exc_info.value)


class _StatusTransport:
    def __init__(self, statuses: list[str]) -> None:
        self.statuses = statuses
        self.calls = 0

    def inspect(self) -> MaintenanceModeInspection:
        status = self.statuses[self.calls]
        self.calls += 1
        return MaintenanceModeInspection(status)


class _SshTransport:
    def __init__(self) -> None:
        self.calls = 0
        self.disable_calls = 0

    def _enable_after_external_preflight(self) -> None:
        self.calls += 1

    def _disable_after_external_preflight(self) -> MaintenanceModeReadback:
        self.disable_calls += 1
        return MaintenanceModeReadback("disable")


class _FailingSshTransport:
    def __init__(self) -> None:
        self.calls = 0

    def _enable_after_external_preflight(self) -> None:
        self.calls += 1
        raise RuntimeError("fixed SSH write failed")

    def _disable_after_external_preflight(self) -> MaintenanceModeReadback:
        self.calls += 1
        raise RuntimeError("fixed SSH write failed")


def test_successor_requires_disabled_api_preflight_then_exact_api_readback() -> None:
    status = _StatusTransport(["disable", "enable"])
    ssh = _SshTransport()
    successor = FortiPamMaintenanceModeSuccessorTransport(  # type: ignore[arg-type]
        status, ssh
    )

    assert successor.enable_and_readback() == MaintenanceModeReadback("enable")
    assert status.calls == 2
    assert ssh.calls == 1


def test_successor_disable_requires_enabled_preflight_and_dual_readback() -> None:
    status = _StatusTransport(["enable", "disable"])
    ssh = _SshTransport()
    successor = FortiPamMaintenanceModeSuccessorTransport(  # type: ignore[arg-type]
        status, ssh
    )

    assert successor.disable_and_readback() == MaintenanceModeReadback("disable")
    assert status.calls == 2
    assert ssh.disable_calls == 1


@pytest.mark.parametrize(
    ("statuses", "rollback_readback", "expected_ssh_calls"),
    (
        (["disable"], "disable", 0),
        (["enable", "enable"], "disable", 1),
        (["enable"], "enable", 1),
    ),
)
def test_successor_disable_fails_closed_on_bad_preflight_or_readback(
    statuses: list[str],
    rollback_readback: str,
    expected_ssh_calls: int,
) -> None:
    status = _StatusTransport(statuses)
    ssh = _SshTransport()
    original = ssh._disable_after_external_preflight

    def readback() -> MaintenanceModeReadback:
        value = original()
        return MaintenanceModeReadback(rollback_readback) if value else value

    ssh._disable_after_external_preflight = readback  # type: ignore[method-assign]
    successor = FortiPamMaintenanceModeSuccessorTransport(  # type: ignore[arg-type]
        status, ssh
    )

    with pytest.raises(MaintenanceModeStatusHttpTransportError):
        successor.disable_and_readback()
    assert ssh.disable_calls == expected_ssh_calls


@pytest.mark.parametrize(
    ("statuses", "expected_ssh_calls"),
    (
        (["enable"], 0),
        (["disable", "disable"], 1),
    ),
)
def test_successor_fails_closed_without_writing_on_bad_preflight_or_readback(
    statuses: list[str],
    expected_ssh_calls: int,
) -> None:
    status = _StatusTransport(statuses)
    ssh = _SshTransport()
    successor = FortiPamMaintenanceModeSuccessorTransport(  # type: ignore[arg-type]
        status, ssh
    )

    with pytest.raises(MaintenanceModeStatusHttpTransportError):
        successor.enable_and_readback()
    assert ssh.calls == expected_ssh_calls


def test_successor_does_not_claim_api_readback_after_failed_ssh_write() -> None:
    status = _StatusTransport(["disable"])
    ssh = _FailingSshTransport()
    successor = FortiPamMaintenanceModeSuccessorTransport(  # type: ignore[arg-type]
        status, ssh
    )

    with pytest.raises(RuntimeError, match="fixed SSH write failed"):
        successor.enable_and_readback()
    assert status.calls == 1
    assert ssh.calls == 1
