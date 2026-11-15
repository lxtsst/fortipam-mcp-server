from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.client_integrity_ssh_transport as transport_module
from fortipam_mcp.client_integrity_ssh_transport import (
    ClientIntegritySshTransportConfig,
    ClientIntegritySshTransportConfigurationError,
    ClientIntegritySshTransportError,
    FortiPamClientIntegritySshTransport,
    _readback,
    load_client_integrity_ssh_transport_config,
)


CLIENT_SOFTWARE_NAME = "mcp-v4-client-integrity-01"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> ClientIntegritySshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return ClientIntegritySshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-client-integrity-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def _full_output(name: str = CLIENT_SOFTWARE_NAME) -> bytes:
    return (
        f'edit "{name}"\r\n'.encode("ascii")
        + b"    config pkg\r\n"
        + b'        edit "x64"\r\n'
        + b"            set integrity-check cert\r\n"
        + b"            set download-option external\r\n"
        + b'            set external-url "https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe"\r\n'
        + b'            set ca "Fortinet_SSL"\r\n'
        + b'            set client-name "putty"\r\n'
        + b"        next\r\n"
        + b"    end\r\n"
        + b"next\r\n"
    )


def test_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_CLIENT_INTEGRITY_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_CLIENT_INTEGRITY_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_CLIENT_INTEGRITY_SSH_USERNAME": "fortipam-client-integrity-writer",
        "FPA_HOME_LAB_FPA1_V4_CLIENT_INTEGRITY_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_CLIENT_INTEGRITY_SSH_KNOWN_HOSTS_FILE": str(
            known_hosts
        ),
    }

    loaded = load_client_integrity_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-client-integrity-writer"
    password.chmod(0o640)
    with pytest.raises(
        ClientIntegritySshTransportConfigurationError,
        match="owner-only",
    ):
        load_client_integrity_ssh_transport_config(environment)


def test_input_rejects_out_of_scope_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamClientIntegritySshTransport(_config(tmp_path))

    with pytest.raises(ClientIntegritySshTransportError):
        transport.inspect("putty")
    with pytest.raises(ClientIntegritySshTransportError):
        transport.create_and_readback('mcp-v4-client-integrity-01"\nset ca "evil')


def test_readback_requires_one_exact_selected_x64_package() -> None:
    output = _full_output()

    assert _readback(output, CLIENT_SOFTWARE_NAME).verified is True
    unrelated = _full_output("unrelated-client-software").replace(
        b"set integrity-check cert",
        b"set integrity-check none",
    )
    assert _readback(unrelated + output, CLIENT_SOFTWARE_NAME).verified is True
    assert (
        _readback(
            output.replace(b"set integrity-check cert", b"set integrity-check none"),
            CLIENT_SOFTWARE_NAME,
        ).verified
        is False
    )
    assert _readback(output + output, CLIENT_SOFTWARE_NAME).verified is False


def test_create_uses_only_the_fixed_guide_client_integrity_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamClientIntegritySshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (client-software) #"
    entry_prompt = b"fpa (mcp-v4-client-integrity-01) #"
    package_table_prompt = b"fpa (pkg) #"
    package_prompt = b"fpa (x64) #"
    expected_dynamic = [
        ("config secret client-software", table_prompt),
        ('edit "mcp-v4-client-integrity-01"', entry_prompt),
        ("config pkg", package_table_prompt),
        ('edit "x64"', package_prompt),
        ("next", package_table_prompt),
        ("end", entry_prompt),
        ("next", table_prompt),
        ("end", root_prompt),
    ]

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
        expected_command, response = expected_dynamic.pop(0)
        assert command == expected_command
        return response

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._create_client_software(
            object(),
            root_prompt,
            CLIENT_SOFTWARE_NAME,
            100.0,
        )
    )

    assert expected_dynamic == []
    assert commands == [
        "config secret client-software",
        'edit "mcp-v4-client-integrity-01"',
        "config pkg",
        'edit "x64"',
        "set integrity-check cert",
        "set download-option external",
        'set external-url "https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe"',
        'set ca "Fortinet_SSL"',
        'set client-name "putty"',
        "next",
        "end",
        "next",
        "end",
    ]


def test_reader_uses_both_requested_show_forms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamClientIntegritySshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command in {
            "show | grep mcp-v4-client-integrity-01",
            "show | grep mcp-v4-client-integrity-01 -f",
        }
        return b"client-software"

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config secret client-software":
            return b"fpa (client-software) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    compact, full = asyncio.run(
        transport._show_client_software(
            object(),
            b"fpa #",
            CLIENT_SOFTWARE_NAME,
            100.0,
        )
    )

    assert (compact, full) == (b"client-software", b"client-software")
    assert commands == [
        "config secret client-software",
        "show | grep mcp-v4-client-integrity-01",
        "show | grep mcp-v4-client-integrity-01 -f",
        "end",
    ]
