from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.maintenance_mode_ssh_transport as transport_module
from fortipam_mcp.maintenance_mode_ssh_transport import (
    FortiPamMaintenanceModeSshTransport,
    MaintenanceModeSshTransportConfig,
    MaintenanceModeSshTransportConfigurationError,
    MaintenanceModeSshTransportError,
    _status,
    load_maintenance_mode_ssh_transport_config,
)


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> MaintenanceModeSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return MaintenanceModeSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-maintenance-mode-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def _output(status: str) -> bytes:
    return f"config system maintenance\r\n    set mode {status}\r\nend\r\n".encode("ascii")


def test_loader_requires_dedicated_ssh_configuration(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_MAINTENANCE_MODE_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_MAINTENANCE_MODE_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_MAINTENANCE_MODE_SSH_USERNAME": "fortipam-maintenance-mode-writer",
        "FPA_HOME_LAB_FPA1_V4_MAINTENANCE_MODE_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_MAINTENANCE_MODE_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_maintenance_mode_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    invalid = dict(environment)
    invalid["FPA_HOME_LAB_FPA1_V4_MAINTENANCE_MODE_SSH_HOST"] = "fpa.example\nset mode enable"
    with pytest.raises(MaintenanceModeSshTransportConfigurationError):
        load_maintenance_mode_ssh_transport_config(invalid)


def test_status_requires_one_unambiguous_effective_value() -> None:
    assert _status((b"", _output("disable"))) == "disable"
    assert _status((_output("enable"), _output("enable"))) == "enable"
    marked_full = _output("enable").replace(
        b"set mode enable",
        b"set mode enable <---",
    )
    assert _status((_output("enable"), marked_full)) == "enable"
    with pytest.raises(MaintenanceModeSshTransportError):
        _status((_output("disable"), _output("enable")))
    with pytest.raises(MaintenanceModeSshTransportError):
        _status((_output("enable"), b"    set mode enable unexpected\r\n"))
    with pytest.raises(MaintenanceModeSshTransportError):
        _status((b"", b"permission denied"))


def test_enable_uses_only_the_fixed_maintenance_transition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamMaintenanceModeSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (maintenance) #"

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command == "set mode enable"
        return b""

    async def dynamic(
        process: object,
        command: str,
        known_root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, known_root_prompt, deadline
        commands.append(command)
        if command == "config system maintenance":
            return table_prompt
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(transport._enable_maintenance_mode(object(), root_prompt, 100.0))

    assert commands == ["config system maintenance", "set mode enable", "end"]


def test_disable_recovery_uses_only_the_fixed_maintenance_transition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamMaintenanceModeSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (maintenance) #"

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command == "set mode disable"
        return b""

    async def dynamic(
        process: object,
        command: str,
        known_root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, known_root_prompt, deadline
        commands.append(command)
        if command == "config system maintenance":
            return table_prompt
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(transport._disable_maintenance_mode(object(), root_prompt, 100.0))

    assert commands == ["config system maintenance", "set mode disable", "end"]


def test_reader_uses_both_requested_show_forms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamMaintenanceModeSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command in {"show | grep mode", "show | grep mode -f"}
        return b"status"

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config system maintenance":
            return b"fpa (maintenance) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(transport._read_status(object(), b"fpa #", 100.0))

    assert output == (b"status", b"status")
    assert commands == [
        "config system maintenance",
        "show | grep mode",
        "show | grep mode -f",
        "end",
    ]
