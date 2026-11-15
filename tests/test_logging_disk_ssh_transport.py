from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.logging_disk_ssh_transport as transport_module
from fortipam_mcp.logging_disk_ssh_transport import (
    FortiPamLoggingDiskSshTransport,
    LoggingDiskSshTransportConfig,
    LoggingDiskSshTransportConfigurationError,
    LoggingDiskSshTransportError,
    _status,
    load_logging_disk_ssh_transport_config,
)


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> LoggingDiskSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return LoggingDiskSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-logging-disk-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def _output(table: str, status: str) -> bytes:
    return f"config log {table} setting\r\n    set status {status}\r\nend\r\n".encode("ascii")


def test_loader_requires_dedicated_ssh_configuration(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_LOGGING_DISK_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_LOGGING_DISK_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_LOGGING_DISK_SSH_USERNAME": "fortipam-logging-disk-writer",
        "FPA_HOME_LAB_FPA1_V4_LOGGING_DISK_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_LOGGING_DISK_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_logging_disk_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    invalid = dict(environment)
    invalid["FPA_HOME_LAB_FPA1_V4_LOGGING_DISK_SSH_HOST"] = "fpa.example\nset status disable"
    with pytest.raises(LoggingDiskSshTransportConfigurationError):
        load_logging_disk_ssh_transport_config(invalid)


def test_status_requires_one_unambiguous_effective_value() -> None:
    assert _status((b"", _output("memory", "enable"))) == "enable"
    assert _status((_output("disk", "disable"), _output("disk", "disable"))) == "disable"
    with pytest.raises(LoggingDiskSshTransportError):
        _status((_output("disk", "disable"), _output("disk", "enable")))
    with pytest.raises(LoggingDiskSshTransportError):
        _status((b"", b"permission denied"))


def test_disable_uses_only_the_fixed_disk_logging_transition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamLoggingDiskSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (disk) #"

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, deadline
        commands.append(command)
        assert command == "set status disable"
        return b""

    async def dynamic(
        process: object,
        command: str,
        known_root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, known_root_prompt, deadline
        commands.append(command)
        if command == "config log disk setting":
            return table_prompt
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(transport._disable_disk(object(), root_prompt, 100.0))

    assert commands == ["config log disk setting", "set status disable", "end"]


def test_reader_uses_both_requested_show_forms_for_memory_and_disk(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamLoggingDiskSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, deadline
        commands.append(command)
        assert command in {
            "show | grep status",
            "show full-configuration | grep status",
        }
        return _output("memory", "enable") if b"memory" in prompt else _output("disk", "enable")

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config log memory setting":
            return b"fpa (memory) #"
        if command == "config log disk setting":
            return b"fpa (disk) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    inspection = asyncio.run(transport._read_settings(object(), b"fpa #", 100.0))

    assert inspection.memory_status == "enable"
    assert inspection.disk_status == "enable"
    assert commands == [
        "config log memory setting",
        "show | grep status",
        "show full-configuration | grep status",
        "end",
        "config log disk setting",
        "show | grep status",
        "show full-configuration | grep status",
        "end",
    ]
