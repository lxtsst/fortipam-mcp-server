from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.launcher_ssh_transport as transport_module
from fortipam_mcp.launcher_ssh_transport import (
    FortiPamLauncherSshTransport,
    LauncherSshTransportConfig,
    LauncherSshTransportConfigurationError,
    LauncherSshTransportError,
    _readback,
    load_launcher_ssh_transport_config,
)


LAUNCHER_NAME = "mcp-v4-launcher-01"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> LauncherSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return LauncherSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-launcher-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_LAUNCHER_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_LAUNCHER_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_LAUNCHER_SSH_USERNAME": "fortipam-launcher-writer",
        "FPA_HOME_LAB_FPA1_V4_LAUNCHER_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_LAUNCHER_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_launcher_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-launcher-writer"
    password.chmod(0o640)
    with pytest.raises(LauncherSshTransportConfigurationError, match="owner-only"):
        load_launcher_ssh_transport_config(environment)


def test_input_rejects_out_of_scope_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamLauncherSshTransport(_config(tmp_path))

    with pytest.raises(LauncherSshTransportError):
        transport.inspect("Example Windows RDP")
    with pytest.raises(LauncherSshTransportError):
        transport.create_and_readback('mcp-v4-launcher-unsafe"\nset type ssh')


def test_readback_requires_all_fixed_native_rdp_controls() -> None:
    output = (
        b'edit "mcp-v4-launcher-01"\r\n'
        + b"set type rdp\r\n"
        + b'set exe "mstsc.exe"\r\n'
        + b'set parameter "/V:$HOST:$PORT /noConsentPrompt"\r\n'
        + b'set cmd "cmdkey /generic:$HOST /user:$USER /pass:$PASSWORD"\r\n'
        + b'set cmd "cmdkey /del:$HOST"\r\n'
        + b"set launch-timeout 15\r\n"
    )

    assert _readback(output, LAUNCHER_NAME).verified is True
    assert (
        _readback(
            output.replace(b"set type rdp", b"set type ssh"),
            LAUNCHER_NAME,
        ).verified
        is False
    )


def test_create_uses_only_the_fixed_guide_launcher_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamLauncherSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (launcher) #"
    launcher_prompt = b"fpa (mcp-v4-launcher-01) #"
    os_app_prompt = b"fpa (os_app) #"
    application_prompt = b"fpa (1) #"
    init_commands_prompt = b"fpa (init-commands) #"
    init_command_prompt = b"fpa (1) #"
    clean_commands_prompt = b"fpa (clean-commands) #"
    clean_command_prompt = b"fpa (1) #"

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        return b""

    async def dynamic(
        process: object,
        command: str,
        known_root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, known_root_prompt, deadline
        commands.append(command)
        if command == "config secret launcher":
            return table_prompt
        if command == 'edit "mcp-v4-launcher-01"':
            return launcher_prompt
        if command == "config os_app":
            return os_app_prompt
        if command == "config init-commands":
            return init_commands_prompt
        if command == "config clean-commands":
            return clean_commands_prompt
        if command == "edit 1":
            count = commands.count("edit 1")
            return (
                application_prompt
                if count == 1
                else init_command_prompt
                if count == 2
                else clean_command_prompt
            )
        if command == "next":
            count = commands.count("next")
            return (
                init_commands_prompt
                if count == 1
                else clean_commands_prompt
                if count == 2
                else os_app_prompt
                if count == 3
                else table_prompt
            )
        if command == "end":
            count = commands.count("end")
            return (
                application_prompt
                if count in {1, 2}
                else launcher_prompt
                if count == 3
                else root_prompt
            )
        raise AssertionError(command)

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._create_launcher(
            object(),
            root_prompt,
            LAUNCHER_NAME,
            100.0,
        )
    )

    assert commands == [
        "config secret launcher",
        'edit "mcp-v4-launcher-01"',
        "set type rdp",
        "set launch-timeout 15",
        "config os_app",
        "edit 1",
        'set exe "mstsc.exe"',
        'set parameter "/V:$HOST:$PORT /noConsentPrompt"',
        "config init-commands",
        "edit 1",
        'set cmd "cmdkey /generic:$HOST /user:$USER /pass:$PASSWORD"',
        "next",
        "end",
        "config clean-commands",
        "edit 1",
        'set cmd "cmdkey /del:$HOST"',
        "next",
        "end",
        "next",
        "end",
        "next",
        "end",
    ]


def test_launcher_reader_reads_existing_launcher_in_bounded_nested_contexts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamLauncherSshTransport(_config(tmp_path))
    commands: list[str] = []

    table_prompt = b"fpa (launcher) #"
    launcher_prompt = b"fpa (mcp-v4-launcher-01) #"
    os_app_prompt = b"fpa (os_app) #"

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "show | grep mcp-v4-launcher-01":
            assert prompt == table_prompt
            return b'edit "mcp-v4-launcher-01"\n'
        if command in {
            "show full-configuration | grep rdp",
            "show full-configuration | grep launch-timeout",
        }:
            assert prompt == launcher_prompt
            return b"launcher"
        assert command == "show full-configuration"
        assert prompt == os_app_prompt
        return b"os-app"

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config secret launcher":
            return table_prompt
        if command == 'edit "mcp-v4-launcher-01"':
            return launcher_prompt
        if command == "config os_app":
            return os_app_prompt
        if command == "end":
            return launcher_prompt if commands.count("end") == 1 else root_prompt
        assert command == "next"
        return table_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._show_launcher(object(), b"fpa #", LAUNCHER_NAME, 100.0)
    )

    assert output == b'edit "mcp-v4-launcher-01"\nlauncherlauncheros-app'
    assert commands == [
        "config secret launcher",
        "show | grep mcp-v4-launcher-01",
        'edit "mcp-v4-launcher-01"',
        "show full-configuration | grep rdp",
        "show full-configuration | grep launch-timeout",
        "config os_app",
        "show full-configuration",
        "end",
        "next",
        "end",
    ]


def test_launcher_reader_does_not_enter_edit_for_an_absent_launcher(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamLauncherSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command == "show | grep mcp-v4-launcher-01"
        return b""

    async def dynamic(
        process: object,
        command: str,
        known_root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config secret launcher":
            return b"fpa (launcher) #"
        assert command == "end"
        return known_root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._show_launcher(object(), root_prompt, LAUNCHER_NAME, 100.0)
    )

    assert output == b""
    assert commands == [
        "config secret launcher",
        "show | grep mcp-v4-launcher-01",
        "end",
    ]
