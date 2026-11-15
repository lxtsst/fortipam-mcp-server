from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.ssh_filter_ssh_transport as transport_module
from fortipam_mcp.ssh_filter_ssh_transport import (
    FortiPamSshFilterSshTransport,
    SshFilterSshTransportConfig,
    SshFilterSshTransportConfigurationError,
    SshFilterSshTransportError,
    _readback,
    load_ssh_filter_ssh_transport_config,
)


PROFILE_NAME = "mcp-v4-ssh-filter-01"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> SshFilterSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return SshFilterSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-ssh-filter-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_SSH_FILTER_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_SSH_FILTER_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_SSH_FILTER_SSH_USERNAME": "fortipam-ssh-filter-writer",
        "FPA_HOME_LAB_FPA1_V4_SSH_FILTER_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_SSH_FILTER_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_ssh_filter_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-ssh-filter-writer"
    password.chmod(0o640)
    with pytest.raises(SshFilterSshTransportConfigurationError, match="owner-only"):
        load_ssh_filter_ssh_transport_config(environment)


def test_input_rejects_out_of_scope_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamSshFilterSshTransport(_config(tmp_path))

    with pytest.raises(SshFilterSshTransportError):
        transport.inspect("default")
    with pytest.raises(SshFilterSshTransportError):
        transport.create_and_readback('mcp-v4-ssh-filter-unsafe"\nset x y')


def test_readback_requires_all_fixed_deny_profile_controls() -> None:
    output = (
        b'edit "mcp-v4-ssh-filter-01"\r\n'
        + b"set restricted-mode disable\r\n"
        + b'set pattern "rm"\r\n'
        + b"set log enable\r\n"
        + b"set alert enable\r\n"
    )

    assert _readback(output, PROFILE_NAME).verified is True
    assert (
        _readback(
            output.replace(b"set alert enable", b"set alert disable"),
            PROFILE_NAME,
        ).verified
        is False
    )


def test_create_uses_only_the_fixed_guide_ssh_filter_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamSshFilterSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (profile) #"
    profile_prompt = b"fpa (mcp-v4-ssh-filter-01) #"
    shell_prompt = b"fpa (shell-commands) #"
    pattern_prompt = b"fpa (1) #"

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
        if command == "config ssh-filter profile":
            return table_prompt
        if command == 'edit "mcp-v4-ssh-filter-01"':
            return profile_prompt
        if command == "config shell-commands":
            return shell_prompt
        if command == "edit 1":
            return pattern_prompt
        if command == "next":
            return shell_prompt if commands.count("next") == 1 else table_prompt
        if command == "end":
            return profile_prompt if commands.count("end") == 1 else root_prompt
        raise AssertionError(command)

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._create_profile(
            object(),
            root_prompt,
            PROFILE_NAME,
            100.0,
        )
    )

    assert commands == [
        "config ssh-filter profile",
        'edit "mcp-v4-ssh-filter-01"',
        "set restricted-mode disable",
        "config shell-commands",
        "edit 1",
        'set pattern "rm"',
        "set log enable",
        "set alert enable",
        "next",
        "end",
        "next",
        "end",
    ]


def test_profile_reader_uses_compiled_locator_and_bounded_full_show_forms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamSshFilterSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        return {
            "show | grep mcp-v4-ssh-filter-01": b"locator",
            'show full-configuration | grep -A 80 "^ *edit.*mcp-v4-ssh-filter-01"': b"full",
        }[command]

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config ssh-filter profile":
            return b"fpa (profile) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._show_profile(object(), b"fpa #", PROFILE_NAME, 100.0)
    )

    assert output == b"locatorfull"
    assert commands == [
        "config ssh-filter profile",
        "show | grep mcp-v4-ssh-filter-01",
        'show full-configuration | grep -A 80 "^ *edit.*mcp-v4-ssh-filter-01"',
        "end",
    ]
