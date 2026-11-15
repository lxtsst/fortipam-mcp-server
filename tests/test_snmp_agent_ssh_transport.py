from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.snmp_agent_ssh_transport as transport_module
from fortipam_mcp.snmp_agent_ssh_transport import (
    FortiPamSnmpAgentSshTransport,
    SnmpAgentInspection,
    SnmpAgentReadback,
    SnmpAgentSshTransportConfig,
    SnmpAgentSshTransportConfigurationError,
    SnmpAgentSshTransportError,
    _status,
    load_snmp_agent_ssh_transport_config,
)


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> SnmpAgentSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return SnmpAgentSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-snmp-agent-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def _output(status: str) -> bytes:
    return f"config system snmp sysinfo\r\n    set status {status}\r\nend\r\n".encode("ascii")


def test_loader_requires_dedicated_ssh_configuration(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_SNMP_AGENT_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_SNMP_AGENT_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_SNMP_AGENT_SSH_USERNAME": "fortipam-snmp-agent-writer",
        "FPA_HOME_LAB_FPA1_V4_SNMP_AGENT_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_SNMP_AGENT_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_snmp_agent_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    invalid = dict(environment)
    invalid["FPA_HOME_LAB_FPA1_V4_SNMP_AGENT_SSH_HOST"] = "fpa.example\nset status enable"
    with pytest.raises(SnmpAgentSshTransportConfigurationError):
        load_snmp_agent_ssh_transport_config(invalid)


def test_status_requires_one_unambiguous_effective_value() -> None:
    assert _status((b"", _output("disable"))) == "disable"
    assert _status((_output("enable"), _output("enable"))) == "enable"
    marked_full = _output("enable").replace(
        b"set status enable",
        b"set status enable <---",
    )
    assert _status((_output("enable"), marked_full)) == "enable"
    with pytest.raises(SnmpAgentSshTransportError):
        _status((_output("disable"), _output("enable")))
    with pytest.raises(SnmpAgentSshTransportError):
        _status((_output("enable"), b"    set status enable unexpected\r\n"))
    with pytest.raises(SnmpAgentSshTransportError):
        _status((b"", b"permission denied"))
    assert SnmpAgentInspection("enable").exact_enabled_baseline is True
    assert SnmpAgentInspection("disable").exact_enabled_baseline is False
    assert SnmpAgentReadback("disable").verified_disabled is True


def test_enable_uses_only_the_fixed_system_agent_transition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamSnmpAgentSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (snmp) #"

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
        if command == "config system snmp sysinfo":
            return table_prompt
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(transport._enable_agent(object(), root_prompt, 100.0))

    assert commands == ["config system snmp sysinfo", "set status enable", "end"]


def test_disable_uses_only_the_fixed_system_agent_transition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamSnmpAgentSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (snmp) #"

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
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
        if command == "config system snmp sysinfo":
            return table_prompt
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(transport._disable_agent(object(), root_prompt, 100.0))

    assert commands == ["config system snmp sysinfo", "set status disable", "end"]


def test_reader_uses_both_requested_show_forms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamSnmpAgentSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command in {
            "show | grep status",
            "show full-configuration | grep status",
        }
        return b"status"

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config system snmp sysinfo":
            return b"fpa (snmp) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(transport._read_status(object(), b"fpa #", 100.0))

    assert output == (b"status", b"status")
    assert commands == [
        "config system snmp sysinfo",
        "show | grep status",
        "show full-configuration | grep status",
        "end",
    ]
