from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.antivirus_profile_ssh_transport as transport_module
from fortipam_mcp.antivirus_profile_ssh_transport import (
    AntivirusProfileSshTransportConfig,
    AntivirusProfileSshTransportConfigurationError,
    AntivirusProfileSshTransportError,
    FortiPamAntivirusProfileSshTransport,
    _readback,
    load_antivirus_profile_ssh_transport_config,
)


PROFILE_NAME = "mcp-v4-av-profile-01"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> AntivirusProfileSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return AntivirusProfileSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-av-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_ANTIVIRUS_PROFILE_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_ANTIVIRUS_PROFILE_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_ANTIVIRUS_PROFILE_SSH_USERNAME": "fortipam-av-writer",
        "FPA_HOME_LAB_FPA1_V4_ANTIVIRUS_PROFILE_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_ANTIVIRUS_PROFILE_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_antivirus_profile_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-av-writer"
    password.chmod(0o640)
    with pytest.raises(
        AntivirusProfileSshTransportConfigurationError,
        match="owner-only",
    ):
        load_antivirus_profile_ssh_transport_config(environment)


def test_input_rejects_out_of_scope_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamAntivirusProfileSshTransport(_config(tmp_path))

    with pytest.raises(AntivirusProfileSshTransportError):
        transport.inspect("profile")
    with pytest.raises(AntivirusProfileSshTransportError):
        transport.create_and_readback('mcp-v4-av-profile-unsafe"\nset x y')


def test_readback_requires_both_fixed_http_and_ssh_block_contexts() -> None:
    output = (
        b'edit "mcp-v4-av-profile-01"\r\n'
        + b"config http\r\n"
        + b"set av-scan block\r\n"
        + b"end\r\n"
        + b"config ssh\r\n"
        + b"set av-scan block\r\n"
        + b"end\r\n"
    )

    assert _readback(output, PROFILE_NAME).verified is True
    assert (
        _readback(
            output.replace(b"config ssh", b"config scp"),
            PROFILE_NAME,
        ).verified
        is False
    )


def test_create_uses_only_the_fixed_guide_http_ssh_block_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamAntivirusProfileSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (profile) #"
    profile_prompt = b"fpa (mcp-v4-av-profile-01) #"
    http_prompt = b"fpa (http) #"
    ssh_prompt = b"fpa (ssh) #"
    end_count = 0

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
        nonlocal end_count
        del process, known_root_prompt, deadline
        commands.append(command)
        if command == "config antivirus profile":
            return table_prompt
        if command == 'edit "mcp-v4-av-profile-01"':
            return profile_prompt
        if command == "config http":
            return http_prompt
        if command == "config ssh":
            return ssh_prompt
        if command == "next":
            return table_prompt
        assert command == "end"
        end_count += 1
        return profile_prompt if end_count <= 2 else root_prompt

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
        "config antivirus profile",
        'edit "mcp-v4-av-profile-01"',
        "config http",
        "set av-scan block",
        "end",
        "config ssh",
        "set av-scan block",
        "end",
        "next",
        "end",
    ]


def test_profile_reader_accepts_only_compiled_locator_and_bounded_full_show_forms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamAntivirusProfileSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        return {
            "show | grep mcp-v4-av-profile-01": b"locator",
            'show full-configuration | grep -A 80 "^ *edit.*mcp-v4-av-profile-01"': b"full",
        }[command]

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config antivirus profile":
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
        "config antivirus profile",
        "show | grep mcp-v4-av-profile-01",
        'show full-configuration | grep -A 80 "^ *edit.*mcp-v4-av-profile-01"',
        "end",
    ]
