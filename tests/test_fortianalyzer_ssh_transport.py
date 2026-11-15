from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.fortianalyzer_ssh_transport as transport_module
from fortipam_mcp.fortianalyzer_ssh_transport import (
    FortiAnalyzerSshTransportConfig,
    FortiAnalyzerSshTransportConfigurationError,
    FortiAnalyzerSshTransportError,
    FortiPamFortiAnalyzerSshTransport,
    _inspection,
    load_fortianalyzer_ssh_transport_config,
)


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> FortiAnalyzerSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return FortiAnalyzerSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-fortianalyzer-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def _status(status: str) -> bytes:
    return f"    set status {status}\r\n".encode("ascii")


def _server(value: str) -> bytes:
    return f'    set server "{value}"\r\n'.encode("ascii")


def _settings(
    status: str,
    server: str,
) -> tuple[tuple[bytes, bytes], tuple[bytes, bytes]]:
    return (_status(status), _status(status)), (_server(server), _server(server))


def test_loader_requires_dedicated_ssh_configuration(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_FORTIANALYZER_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_FORTIANALYZER_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_FORTIANALYZER_SSH_USERNAME": "fortipam-fortianalyzer-writer",
        "FPA_HOME_LAB_FPA1_V4_FORTIANALYZER_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_FORTIANALYZER_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_fortianalyzer_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    invalid = dict(environment)
    invalid["FPA_HOME_LAB_FPA1_V4_FORTIANALYZER_SSH_HOST"] = (
        "fpa.example\nset status enable"
    )
    with pytest.raises(FortiAnalyzerSshTransportConfigurationError):
        load_fortianalyzer_ssh_transport_config(invalid)


def test_inspection_requires_unambiguous_status_and_unchanged_server() -> None:
    inspection = _inspection(_settings("disable", "faz.private.example"))

    assert inspection.status == "disable"
    assert inspection.server_configured is True
    assert inspection.exact_disabled_baseline is True
    assert "faz.private.example" not in str(inspection)
    with pytest.raises(FortiAnalyzerSshTransportError):
        _inspection(((_status("disable"), _status("enable")), _settings("disable", "faz.example")[1]))
    with pytest.raises(FortiAnalyzerSshTransportError):
        _inspection(((_status("disable"), _status("disable")), (_server("faz-a.example"), _server("faz-b.example"))))
    unconfigured = _inspection(((_status("disable"), _status("disable")), (b"", b' set server ""\n')))
    assert unconfigured.server_configured is False
    assert unconfigured.exact_disabled_baseline is False


def test_enable_uses_only_the_fixed_delivery_status_transition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamFortiAnalyzerSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (fortianalyzer) #"

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command == "set status enable"
        return b""

    async def dynamic(
        process: object,
        command: str,
        known_root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, known_root_prompt, deadline
        commands.append(command)
        if command == "config log fortianalyzer setting":
            return table_prompt
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(transport._enable_delivery(object(), root_prompt, 100.0))

    assert commands == ["config log fortianalyzer setting", "set status enable", "end"]


def test_reader_uses_both_requested_show_forms_for_each_fixed_projection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamFortiAnalyzerSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        if "status" in command:
            return b"status"
        assert "server" in command
        return b"server"

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config log fortianalyzer setting":
            return b"fpa (fortianalyzer) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(transport._read_settings(object(), b"fpa #", 100.0))

    assert output == ((b"status", b"status"), (b"server", b"server"))
    assert commands == [
        "config log fortianalyzer setting",
        "show | grep status",
        "show full-configuration | grep status",
        "show | grep server",
        "show full-configuration | grep server",
        "end",
    ]
