from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.launcher_ssh_transport as transport_module
from fortipam_mcp.launcher_ssh_transport import (
    FortiPamLauncherSshTransport,
    LAUNCHER_DEFAULT_TIMEOUT_SECONDS,
    LAUNCHER_UPDATED_TIMEOUT_SECONDS,
    LauncherSshTransportConfig,
    LauncherSshTransportConfigurationError,
    LauncherSshTransportError,
    _update_baseline_readback,
    _update_readback,
    load_launcher_update_ssh_transport_config,
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
        username="fortipam-launcher-updater",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def _output(timeout_seconds: int) -> bytes:
    return (
        b'edit "mcp-v4-launcher-01"\r\n'
        + b"set type rdp\r\n"
        + b'set exe "mstsc.exe"\r\n'
        + b'set parameter "/V:$HOST:$PORT /noConsentPrompt"\r\n'
        + b'set cmd "cmdkey /generic:$HOST /user:$USER /pass:$PASSWORD"\r\n'
        + b'set cmd "cmdkey /del:$HOST"\r\n'
        + f"set launch-timeout {timeout_seconds}\r\n".encode("ascii")
    )


def test_update_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_LAUNCHER_UPDATE_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_LAUNCHER_UPDATE_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_LAUNCHER_UPDATE_SSH_USERNAME": "fortipam-launcher-updater",
        "FPA_HOME_LAB_FPA1_V4_LAUNCHER_UPDATE_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_LAUNCHER_UPDATE_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_launcher_update_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-launcher-updater"
    password.chmod(0o640)
    with pytest.raises(LauncherSshTransportConfigurationError, match="owner-only"):
        load_launcher_update_ssh_transport_config(environment)


def test_update_input_rejects_out_of_scope_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamLauncherSshTransport(_config(tmp_path))

    with pytest.raises(LauncherSshTransportError):
        transport.update_baseline_readback("Example Windows RDP")
    with pytest.raises(LauncherSshTransportError):
        transport.update_timeout_and_readback('mcp-v4-launcher-unsafe"\nset type ssh')


def test_update_readback_requires_exact_create_baseline_and_exact_updated_timeout() -> None:
    baseline = _update_baseline_readback(
        _output(LAUNCHER_DEFAULT_TIMEOUT_SECONDS),
        LAUNCHER_NAME,
    )
    updated = _update_readback(
        _output(LAUNCHER_UPDATED_TIMEOUT_SECONDS),
        LAUNCHER_NAME,
    )

    assert baseline.verified is True
    assert updated.verified is True
    assert (
        _update_baseline_readback(
            _output(LAUNCHER_UPDATED_TIMEOUT_SECONDS),
            LAUNCHER_NAME,
        ).verified
        is False
    )
    assert (
        _update_readback(
            _output(LAUNCHER_DEFAULT_TIMEOUT_SECONDS),
            LAUNCHER_NAME,
        ).verified
        is False
    )


def test_update_writes_only_the_fixed_guide_timeout_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamLauncherSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (launcher) #"
    launcher_prompt = b"fpa (mcp-v4-launcher-01) #"

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command == f"set launch-timeout {LAUNCHER_UPDATED_TIMEOUT_SECONDS}"
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
        if command == "next":
            return table_prompt
        if command == "end":
            return root_prompt
        raise AssertionError(command)

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._update_timeout(
            object(),
            root_prompt,
            LAUNCHER_NAME,
            100.0,
        )
    )

    assert commands == [
        "config secret launcher",
        'edit "mcp-v4-launcher-01"',
        f"set launch-timeout {LAUNCHER_UPDATED_TIMEOUT_SECONDS}",
        "next",
        "end",
    ]
