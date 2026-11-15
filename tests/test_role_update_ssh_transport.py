from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.role_create_ssh_transport as transport_module
from fortipam_mcp.role_create_ssh_transport import (
    FortiPamRoleCreateSshTransport,
    RoleCreateSshTransportConfig,
    RoleCreateSshTransportConfigurationError,
    _CORE_COMMANDS,
    _SECRET_PERMISSION_COMMANDS,
    _UPDATED_SYSTEM_DIAGNOSTICS_COMMAND,
    _update_inspection,
    _update_readback,
    load_role_update_ssh_transport_config,
)


ROLE_NAME = "mcp-v4-role-01"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _environment(tmp_path: Path) -> dict[str, str]:
    known_hosts, password = _files(tmp_path)
    return {
        "FPA_HOME_LAB_FPA1_V4_ROLE_UPDATE_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_ROLE_UPDATE_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_ROLE_UPDATE_SSH_USERNAME": "fortipam-role-updater",
        "FPA_HOME_LAB_FPA1_V4_ROLE_UPDATE_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_ROLE_UPDATE_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }


def _config(tmp_path: Path) -> RoleCreateSshTransportConfig:
    return load_role_update_ssh_transport_config(_environment(tmp_path))


def _role_output(*, diagnostics: str) -> bytes:
    commands = (
        *_CORE_COMMANDS, "set cli enable", "set sysgrp custom",
        "config sysgrp-permission", "set admin read-write", "end",
        diagnostics, *_SECRET_PERMISSION_COMMANDS,
    )
    return b'edit "mcp-v4-role-01"\r\n' + b"\r\n".join(
        command.encode("ascii") for command in commands
    )


def test_update_loader_uses_its_own_dedicated_transport_scope(tmp_path: Path) -> None:
    environment = _environment(tmp_path)

    loaded = load_role_update_ssh_transport_config(environment)

    assert loaded.username == "fortipam-role-updater"
    environment["FPA_HOME_LAB_FPA1_V4_ROLE_UPDATE_ENABLED"] = "false"
    with pytest.raises(
        RoleCreateSshTransportConfigurationError,
        match="must be exactly true",
    ):
        load_role_update_ssh_transport_config(environment)


def test_update_inspection_requires_exact_unassigned_create_baseline() -> None:
    baseline = _role_output(diagnostics="")

    inspection = _update_inspection(baseline, b"", ROLE_NAME)

    assert inspection.verified is True
    assert _update_inspection(baseline.replace(b"set cli enable", b"set cli disable"),
                              b"", ROLE_NAME).verified is False
    assert (
        _update_inspection(
            baseline,
            b'edit "mcp-v4-user-01"\r\nset accprofile "mcp-v4-role-01"\r\n',
            ROLE_NAME,
        ).verified
        is False
    )
    assert (
        _update_inspection(
            baseline.replace(b"set request read-write", b"set request read"),
            b"",
            ROLE_NAME,
        ).verified
        is False
    )


def test_update_readback_requires_only_the_fixed_enabled_diagnostic_state() -> None:
    updated = _role_output(diagnostics=_UPDATED_SYSTEM_DIAGNOSTICS_COMMAND)

    assert _update_readback(updated, b"", ROLE_NAME).verified is True
    assert (
        _update_readback(_role_output(diagnostics=""), b"", ROLE_NAME).verified
        is False
    )
    assert (
        _update_readback(
            updated,
            b'edit "mcp-v4-user-01"\r\nset accprofile "mcp-v4-role-01"\r\n',
            ROLE_NAME,
        ).verified
        is False
    )


def test_update_uses_only_the_fixed_system_diagnostics_cli_shape(
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
        return b""

    async def dynamic(
        process: object,
        command: str,
        known_root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, known_root_prompt, deadline
        commands.append(command)
        if command == f'edit "{ROLE_NAME}"':
            return entry_prompt
        if command == "next":
            return table_prompt
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._enable_system_diagnostics(
            object(),
            root_prompt,
            ROLE_NAME,
            100.0,
        )
    )

    assert commands == [
        "config system accprofile",
        f'edit "{ROLE_NAME}"',
        "set system-diagnostics enable",
        "next",
        "end",
    ]


def test_admin_context_collects_compact_and_full_bounded_show_forms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamRoleCreateSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        return {
            f"show | grep {ROLE_NAME}": b"compact",
            f"show | grep {ROLE_NAME} -f": b"full",
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
        transport._run_admin_context(
            object(),
            b"fpa #",
            (f"show | grep {ROLE_NAME}", f"show | grep {ROLE_NAME} -f"),
            100.0,
        )
    )

    assert output == b"compactfull"
    assert commands == [
        "config system admin",
        f"show | grep {ROLE_NAME}",
        f"show | grep {ROLE_NAME} -f",
        "end",
    ]
