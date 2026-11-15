from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import ANY

import pytest

import fortipam_mcp.snmp_agent_status_http_transport as transport_module
from fortipam_mcp.snmp_agent_ssh_transport import SnmpAgentInspection, SnmpAgentReadback
from fortipam_mcp.snmp_agent_status_http_transport import (
    FortiPamSnmpAgentStatusHttpTransport,
    FortiPamSnmpAgentSuccessorTransport,
    SYSINFO_PATH,
    SnmpAgentStatusHttpTransportConfig,
    SnmpAgentStatusHttpTransportConfigurationError,
    SnmpAgentStatusHttpTransportError,
    load_snmp_agent_status_http_transport_config,
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


def _config() -> SnmpAgentStatusHttpTransportConfig:
    return SnmpAgentStatusHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _payload(status: str = "disable") -> bytes:
    return json.dumps(
        {
            "results": {
                "status": status,
                "description": "not-returned",
                "contact-info": "not-returned",
            }
        }
    ).encode("utf-8")


def test_loader_requires_exact_enable_and_owner_only_token(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("unit-test-token\n", encoding="utf-8")
    token_file.chmod(0o600)
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("unit-test-ca\n", encoding="utf-8")
    environment = {
        "FPA_HOME_LAB_FPA1_V4_SNMP_AGENT_STATUS_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_SNMP_AGENT_STATUS_API_BASE_URL": "https://fpa.example.test",
        "FPA_HOME_LAB_FPA1_V4_SNMP_AGENT_STATUS_API_API_TOKEN_FILE": str(token_file),
        "FPA_HOME_LAB_FPA1_V4_SNMP_AGENT_STATUS_API_CA_FILE": str(ca_file),
    }

    loaded = load_snmp_agent_status_http_transport_config(environment)

    assert loaded.base_url == "https://fpa.example.test"
    token_file.chmod(0o644)
    with pytest.raises(SnmpAgentStatusHttpTransportConfigurationError):
        load_snmp_agent_status_http_transport_config(environment)


@pytest.mark.parametrize("enabled", (None, "TRUE", "false"))
def test_loader_fails_closed_when_not_exactly_enabled(enabled: str | None) -> None:
    environment = {}
    if enabled is not None:
        environment["FPA_HOME_LAB_FPA1_V4_SNMP_AGENT_STATUS_API_ENABLED"] = enabled

    with pytest.raises(SnmpAgentStatusHttpTransportConfigurationError):
        load_snmp_agent_status_http_transport_config(environment)


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
    with pytest.raises(SnmpAgentStatusHttpTransportConfigurationError):
        SnmpAgentStatusHttpTransportConfig(
            base_url=base_url,
            bearer_token="unit-test-token",
            timeout_seconds=15,
            ca_file=None,
        )


@pytest.mark.parametrize("status", ("enable", "disable"))
def test_exact_get_returns_only_explicit_status(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    calls: list[dict[str, object]] = []
    factory_kwargs: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())

    def factory(**kwargs: object) -> _Client:
        factory_kwargs.append(kwargs)
        return _Client(_Response(200, _payload(status)), calls)

    transport = FortiPamSnmpAgentStatusHttpTransport(
        _config(), client_factory=factory
    )

    assert transport.inspect() == SnmpAgentInspection(status)
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
            "url": f"https://fpa.example.test{SYSINFO_PATH}",
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
        _Response(200, b'{"results": {"status": "unknown"}}'),
        _Response(200, b'{"results": []}'),
        _Response(200, b'{"results": [{"status": "disable"}, {"status": "enable"}]}'),
    ),
)
def test_transport_rejects_denied_malformed_oversized_or_ambiguous_state(
    monkeypatch: pytest.MonkeyPatch,
    response: _Response,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSnmpAgentStatusHttpTransport(
        _config(), client_factory=lambda **_: _Client(response, [])
    )

    with pytest.raises(SnmpAgentStatusHttpTransportError):
        transport.inspect()


def test_transport_maps_client_failure_to_stable_non_disclosing_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())

    def fail(**_: object) -> object:
        raise RuntimeError("sensitive transport detail")

    transport = FortiPamSnmpAgentStatusHttpTransport(_config(), client_factory=fail)

    with pytest.raises(
        SnmpAgentStatusHttpTransportError,
        match="transport is unavailable",
    ) as exc_info:
        transport.inspect()
    assert "sensitive transport detail" not in str(exc_info.value)


class _StatusTransport:
    def __init__(self, statuses: list[str]) -> None:
        self.statuses = statuses
        self.calls = 0

    def inspect(self) -> SnmpAgentInspection:
        status = self.statuses[self.calls]
        self.calls += 1
        return SnmpAgentInspection(status)


class _SshTransport:
    def __init__(self, status: str = "enable") -> None:
        self.status = status
        self.calls = 0

    def _enable_after_external_preflight(self) -> SnmpAgentReadback:
        self.calls += 1
        return SnmpAgentReadback(self.status)

    def _disable_after_external_preflight(self) -> SnmpAgentReadback:
        self.calls += 1
        return SnmpAgentReadback(self.status)


def test_successor_requires_disabled_api_preflight_then_dual_enable_readback() -> None:
    status = _StatusTransport(["disable", "enable"])
    ssh = _SshTransport()
    successor = FortiPamSnmpAgentSuccessorTransport(status, ssh)  # type: ignore[arg-type]

    assert successor.enable_and_readback() == SnmpAgentReadback("enable")
    assert status.calls == 2
    assert ssh.calls == 1


def test_successor_requires_enabled_api_preflight_then_dual_disable_readback() -> None:
    status = _StatusTransport(["enable", "disable"])
    ssh = _SshTransport("disable")
    successor = FortiPamSnmpAgentSuccessorTransport(status, ssh)  # type: ignore[arg-type]

    assert successor.disable_and_readback() == SnmpAgentReadback("disable")
    assert status.calls == 2
    assert ssh.calls == 1


@pytest.mark.parametrize(
    ("statuses", "ssh_status", "expected_ssh_calls"),
    (
        (["enable"], "enable", 0),
        (["disable"], "disable", 1),
        (["disable", "disable"], "enable", 1),
    ),
)
def test_successor_fails_closed_without_writing_on_bad_preflight_or_readback(
    statuses: list[str],
    ssh_status: str,
    expected_ssh_calls: int,
) -> None:
    status = _StatusTransport(statuses)
    ssh = _SshTransport(ssh_status)
    successor = FortiPamSnmpAgentSuccessorTransport(status, ssh)  # type: ignore[arg-type]

    with pytest.raises(SnmpAgentStatusHttpTransportError):
        successor.enable_and_readback()
    assert ssh.calls == expected_ssh_calls


@pytest.mark.parametrize(
    ("statuses", "ssh_status", "expected_ssh_calls"),
    (
        (["disable"], "disable", 0),
        (["enable"], "enable", 1),
        (["enable", "enable"], "disable", 1),
    ),
)
def test_successor_disable_fails_closed_on_bad_preflight_or_readback(
    statuses: list[str],
    ssh_status: str,
    expected_ssh_calls: int,
) -> None:
    status = _StatusTransport(statuses)
    ssh = _SshTransport(ssh_status)
    successor = FortiPamSnmpAgentSuccessorTransport(status, ssh)  # type: ignore[arg-type]

    with pytest.raises(SnmpAgentStatusHttpTransportError):
        successor.disable_and_readback()
    assert ssh.calls == expected_ssh_calls
