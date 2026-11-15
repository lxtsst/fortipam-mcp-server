from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.role_create_ssh_transport as transport_module
from fortipam_mcp.role_create_ssh_transport import (
    FortiPamRoleCreateSshTransport,
    RoleCreateSshTransportConfig,
    RoleCreateSshTransportConfigurationError,
    RoleCreateSshTransportError,
    _CORE_COMMANDS,
    _SECRET_PERMISSION_COMMANDS,
    _readback,
    _update_inspection,
    load_role_create_ssh_transport_config,
)


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> RoleCreateSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return RoleCreateSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-role-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_ROLE_CREATE_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_ROLE_CREATE_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_ROLE_CREATE_SSH_USERNAME": "fortipam-role-writer",
        "FPA_HOME_LAB_FPA1_V4_ROLE_CREATE_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_ROLE_CREATE_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_role_create_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-role-writer"
    password.chmod(0o640)
    with pytest.raises(RoleCreateSshTransportConfigurationError, match="owner-only"):
        load_role_create_ssh_transport_config(environment)


def test_input_rejects_unprefixed_or_cli_injection_before_connection(tmp_path: Path) -> None:
    transport = FortiPamRoleCreateSshTransport(_config(tmp_path))

    with pytest.raises(RoleCreateSshTransportError):
        transport.inspect("standard-user")
    with pytest.raises(RoleCreateSshTransportError):
        transport.create_and_readback('mcp-v4-role-unsafe"\nset secfabgrp read-write')


def test_readback_requires_every_fixed_guide_example_permission() -> None:
    output = b'edit "mcp-v4-role-01"\r\n' + b"\r\n".join(
        command.encode("ascii")
        for command in _CORE_COMMANDS + _SECRET_PERMISSION_COMMANDS
    )

    readback = _readback(output, "mcp-v4-role-01")

    assert readback.verified is True
    assert _readback(
        output.replace(b"set request read-write", b"set request read"),
        "mcp-v4-role-01",
    ).verified is False
    assert _readback(
        output + b"\r\nset system-diagnostics enable",
        "mcp-v4-role-01",
    ).verified is False


def test_diagnostics_update_rejects_missing_native_permission_dependencies() -> None:
    role = "mcp-v4-role-01"
    baseline = f'edit "{role}"\n'.encode() + b"\n".join(
        command.encode("ascii")
        for command in _CORE_COMMANDS + _SECRET_PERMISSION_COMMANDS
    )
    admin = b"\nset sysgrp custom\nconfig sysgrp-permission\nset admin read-write\nend\n"

    assert _update_inspection(baseline, b"", role).verified is False
    assert _update_inspection(baseline + admin, b"", role).verified is False
    assert _update_inspection(
        baseline + b"\nset cli enable\n" + admin, b"", role
    ).verified is True
    assert _update_inspection(
        baseline + b"\nset cli enable\n" + admin.replace(b"admin read-write", b"admin read"),
        b"", role,
    ).verified is False
    assert _update_inspection(
        baseline + b"\nset cli enable\n" + admin.replace(b"sysgrp-permission", b"secretgrp-permission"),
        b"", role,
    ).verified is False


def test_create_role_uses_only_the_fixed_guide_example_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamRoleCreateSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (accprofile) #"
    entry_prompt = b"fpa (accprofile) #"
    permission_prompt = b"fpa (secretgrp-permission) #"
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
        if command == 'edit "mcp-v4-role-01"':
            return entry_prompt
        if command == "config secretgrp-permission":
            return permission_prompt
        if command == "end":
            end_count += 1
            return entry_prompt if end_count == 1 else root_prompt
        assert command == "next"
        return table_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._create_role(
            object(),
            root_prompt,
            "mcp-v4-role-01",
            100.0,
        )
    )

    assert commands == [
        "config system accprofile",
        'edit "mcp-v4-role-01"',
        *_CORE_COMMANDS,
        "config secretgrp-permission",
        *_SECRET_PERMISSION_COMMANDS,
        "end",
        "next",
        "end",
    ]


def test_accprofile_context_collects_both_bounded_show_forms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamRoleCreateSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        return {
            "show | grep mcp-v4-role-01": b"compact",
            "show | grep mcp-v4-role-01 -f": b"full",
        }.get(command, b"")

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._run_accprofile_context(
            object(),
            b"fpa #",
            ("show | grep mcp-v4-role-01", "show | grep mcp-v4-role-01 -f"),
            100.0,
        )
    )

    assert output == b"compactfull"
    assert commands == [
        "config system accprofile",
        "show | grep mcp-v4-role-01",
        "show | grep mcp-v4-role-01 -f",
        "end",
    ]


def test_role_entry_readback_enters_only_the_requested_role(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamRoleCreateSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (accprofile) #"
    entry_prompt = b"fpa (accprofile) #"

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command == "show"
        return b'edit "mcp-v4-role-01"\r\nset secretgrp custom'

    async def dynamic(
        process: object,
        command: str,
        known_root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, known_root_prompt, deadline
        commands.append(command)
        return {
            "config system accprofile": table_prompt,
            'edit "mcp-v4-role-01"': entry_prompt,
            "next": table_prompt,
            "end": root_prompt,
        }[command]

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._read_role_entry(object(), root_prompt, "mcp-v4-role-01", 100.0)
    )

    assert output == b'edit "mcp-v4-role-01"\r\nset secretgrp custom'
    assert commands == [
        "config system accprofile",
        'edit "mcp-v4-role-01"',
        "show",
        "next",
        "end",
    ]
