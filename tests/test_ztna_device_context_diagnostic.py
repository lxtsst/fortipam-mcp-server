from __future__ import annotations

from ipaddress import IPv4Address
from pathlib import Path

import pytest

from fortipam_mcp.ztna_device_context_diagnostic import (
    FortiPamZtnaDeviceContextDiagnostic,
    FortiPamZtnaDeviceContextSshTransport,
    V4_ZTNA_DEVICE_CONTEXT_DIAGNOSTIC_FEATURE_ENV,
    ZtnaDeviceContextDiagnosticConfig,
    ZtnaDeviceContextDiagnosticConfigurationError,
    ZtnaDeviceContextDiagnosticTransportError,
    load_v4_ztna_device_context_diagnostic_feature,
    load_ztna_device_context_diagnostic_config,
)


class _FakeTransport:
    def __init__(self, *outputs: bytes) -> None:
        self._outputs = outputs
        self.calls = 0

    def collect(self) -> tuple[bytes, bytes, bytes]:
        self.calls += 1
        return self._outputs  # type: ignore[return-value]


class _UnavailableTransport:
    def collect(self) -> tuple[bytes, bytes, bytes]:
        raise ZtnaDeviceContextDiagnosticTransportError("not returned")


def _diagnostic(*outputs: bytes) -> FortiPamZtnaDeviceContextDiagnostic:
    return FortiPamZtnaDeviceContextDiagnostic(
        _FakeTransport(*outputs),
        access_proxy_name="private_access_proxy",
        endpoint_ipv4=IPv4Address("192.0.2.10"),
    )


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> ZtnaDeviceContextDiagnosticConfig:
    known_hosts, password = _files(tmp_path)
    return ZtnaDeviceContextDiagnosticConfig(
        host="fpa.example",
        port=22,
        username="fortipam-ztna-reader",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        access_proxy_name="private_access_proxy",
        endpoint_ipv4=IPv4Address("192.0.2.10"),
        timeout_seconds=15,
    )


def test_diagnostic_identifies_client_certificate_gate_without_leaking_values() -> None:
    result = _diagnostic(
        b'config firewall access-proxy\n'
        b'    edit "private_access_proxy"\n'
        b'        set client-cert disable\n'
        b'        set empty-cert-action block\n'
        b'    next\n'
        b'end\n',
        b"dynamic list\n192.0.2.10 private-tag\n",
        b"device context is not available\nprivate-session-token\n",
    ).collect()

    assert result["execution_status"] == "succeeded"
    assert result["client_certificate_mode"] == "disabled"
    assert result["empty_certificate_action"] == "block"
    assert result["access_proxy_evidence"] == "complete"
    assert result["dynamic_endpoint_state"] == "observed"
    assert result["wad_device_context_state"] == "absent"
    assert result["first_failed_gate"] == "access_proxy_client_certificate_disabled"
    rendered = repr(result)
    for forbidden in (
        "192.0.2.10",
        "private_access_proxy",
        "private-tag",
        "private-session-token",
    ):
        assert forbidden not in rendered


def test_diagnostic_reports_wad_context_only_after_prior_gates_are_observed() -> None:
    result = _diagnostic(
        b"firewall access-proxy:\n"
        b"== [private_access_proxy]\n"
        b"client-cert: enable\n"
        b"empty-cert-action: accept\n",
        b"dynamic record 192.0.2.10 resolved\n",
        b"device id: redacted-device-id\n",
    ).collect()

    assert result["client_certificate_mode"] == "enabled"
    assert result["dynamic_endpoint_state"] == "observed"
    assert result["wad_device_context_state"] == "present"
    assert result["first_failed_gate"] == "no_failure_observed"
    assert result["secret_launch_authorization_assessed"] is False
    assert result["wad_debug_enabled"] is False
    assert "redacted-device-id" not in repr(result)


def test_diagnostic_selects_only_the_bound_access_proxy() -> None:
    result = _diagnostic(
        b'config firewall access-proxy\n'
        b'    edit "unrelated_access_proxy"\n'
        b'        set client-cert disable\n'
        b'        set empty-cert-action block\n'
        b'    next\n'
        b'    edit "private_access_proxy"\n'
        b'        set client-cert enable\n'
        b'        set empty-cert-action accept\n'
        b'    next\n'
        b'end\n',
        b"dynamic record 192.0.2.10 resolved\n",
        b"device context available\n",
    ).collect()

    assert result["execution_status"] == "succeeded"
    assert result["client_certificate_mode"] == "enabled"
    assert result["empty_certificate_action"] == "accept"
    assert result["first_failed_gate"] == "no_failure_observed"
    assert "unrelated_access_proxy" not in repr(result)


def test_diagnostic_rejects_missing_or_duplicate_bound_access_proxy() -> None:
    missing = _diagnostic(
        b'config firewall access-proxy\n'
        b'    edit "unrelated_access_proxy"\n'
        b'        set client-cert enable\n'
        b'    next\n'
        b'end\n',
        b"dynamic record 192.0.2.10 resolved\n",
        b"device context available\n",
    ).collect()
    duplicate = _diagnostic(
        b'config firewall access-proxy\n'
        b'    edit "private_access_proxy"\n'
        b'        set client-cert enable\n'
        b'    next\n'
        b'    edit "private_access_proxy"\n'
        b'        set client-cert disable\n'
        b'    next\n'
        b'end\n',
        b"dynamic record 192.0.2.10 resolved\n",
        b"device context available\n",
    ).collect()

    for result in (missing, duplicate):
        assert result["execution_status"] == "failed"
        assert result["diagnostic_state"] == "parser_rejected"
        assert result["first_failed_gate"] == "diagnostic_unavailable"
        assert "private_access_proxy" not in repr(result)


def test_diagnostic_fails_closed_when_dynamic_or_wad_output_is_ambiguous() -> None:
    result = _diagnostic(
        b'config firewall access-proxy\n'
        b'    edit "private_access_proxy"\n'
        b'        set client-cert enable\n'
        b'    next\n'
        b'end\n',
        b"dynamic list query completed\n",
        b"query completed\n",
    ).collect()

    assert result["dynamic_endpoint_state"] == "unknown"
    assert result["wad_device_context_state"] == "unknown"
    assert result["first_failed_gate"] == "dynamic_endpoint_state_unknown"


def test_diagnostic_rejects_cli_failure_output_without_returning_it() -> None:
    result = _diagnostic(
        b'config firewall access-proxy\n'
        b'    edit "private_access_proxy"\n'
        b'        set client-cert enable\n'
        b'    next\n'
        b'end\n',
        b"permission denied private-endpoint\n",
        b"device id: private-device\n",
    ).collect()

    assert result["execution_status"] == "failed"
    assert result["diagnostic_state"] == "parser_rejected"
    assert "private-endpoint" not in repr(result)


def test_transport_failure_is_categorical() -> None:
    result = FortiPamZtnaDeviceContextDiagnostic(
        _UnavailableTransport(),
        access_proxy_name="private_access_proxy",
        endpoint_ipv4=IPv4Address("192.0.2.10"),
    ).collect()

    assert result["execution_status"] == "failed"
    assert result["diagnostic_state"] == "transport_unavailable"
    assert result["first_failed_gate"] == "diagnostic_unavailable"


def test_loader_requires_private_owner_only_settings(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_ZTNA_DIAGNOSTIC_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_ZTNA_DIAGNOSTIC_SSH_USERNAME": "fortipam-ztna-reader",
        "FPA_HOME_LAB_FPA1_V4_ZTNA_DIAGNOSTIC_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_ZTNA_DIAGNOSTIC_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
        "FPA_HOME_LAB_FPA1_V4_ZTNA_DIAGNOSTIC_ACCESS_PROXY_NAME": "private_access_proxy",
        "FPA_HOME_LAB_FPA1_V4_ZTNA_DIAGNOSTIC_ENDPOINT_IPV4": "192.0.2.10",
    }

    loaded = load_ztna_device_context_diagnostic_config(environment)

    assert loaded.access_proxy_name == "private_access_proxy"
    assert loaded.endpoint_ipv4 == IPv4Address("192.0.2.10")
    environment["FPA_HOME_LAB_FPA1_V4_ZTNA_DIAGNOSTIC_ENDPOINT_IPV4"] = "8.8.8.8"
    with pytest.raises(ZtnaDeviceContextDiagnosticConfigurationError, match="private"):
        load_ztna_device_context_diagnostic_config(environment)
    environment["FPA_HOME_LAB_FPA1_V4_ZTNA_DIAGNOSTIC_ENDPOINT_IPV4"] = "192.0.2.10"
    password.chmod(0o640)
    with pytest.raises(ZtnaDeviceContextDiagnosticConfigurationError, match="owner-only"):
        load_ztna_device_context_diagnostic_config(environment)


def test_feature_flag_is_exactly_opt_in() -> None:
    assert load_v4_ztna_device_context_diagnostic_feature({}) is False
    assert load_v4_ztna_device_context_diagnostic_feature(
        {V4_ZTNA_DEVICE_CONTEXT_DIAGNOSTIC_FEATURE_ENV: "false"}
    ) is False
    assert load_v4_ztna_device_context_diagnostic_feature(
        {V4_ZTNA_DEVICE_CONTEXT_DIAGNOSTIC_FEATURE_ENV: "true"}
    ) is True
    with pytest.raises(ZtnaDeviceContextDiagnosticConfigurationError, match="exactly"):
        load_v4_ztna_device_context_diagnostic_feature(
            {V4_ZTNA_DEVICE_CONTEXT_DIAGNOSTIC_FEATURE_ENV: "TRUE"}
        )


def test_ssh_transport_compiles_only_the_three_fixed_read_commands(
    tmp_path: Path,
) -> None:
    transport = FortiPamZtnaDeviceContextSshTransport(_config(tmp_path))

    assert transport._commands() == (
        "show full-configuration firewall access-proxy | grep -A 80 "
        '"^ *edit.*private_access_proxy"',
        "diagnose firewall dynamic list",
        "diagnose wad dev query-by ipv4 192.0.2.10",
    )
