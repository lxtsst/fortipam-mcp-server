from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.local_user_create_ssh_transport as transport_module
from fortipam_mcp.local_user_create_ssh_transport import (
    DEFAULT_ACCESS_PROFILE,
    FortiPamLocalUserCreateSshTransport,
    LocalUserCreateSshTransportConfig,
    LocalUserCreateSshTransportConfigurationError,
    LocalUserCreateSshTransportError,
    _readback,
    load_local_user_create_ssh_transport_config,
)


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> LocalUserCreateSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return LocalUserCreateSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-local-user-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_LOCAL_USER_CREATE_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_LOCAL_USER_CREATE_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_LOCAL_USER_CREATE_SSH_USERNAME": "fortipam-local-user-writer",
        "FPA_HOME_LAB_FPA1_V4_LOCAL_USER_CREATE_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_LOCAL_USER_CREATE_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_local_user_create_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-local-user-writer"
    password.chmod(0o640)
    with pytest.raises(LocalUserCreateSshTransportConfigurationError, match="owner-only"):
        load_local_user_create_ssh_transport_config(environment)


def test_input_rejects_cli_injection_before_connection(tmp_path: Path) -> None:
    transport = FortiPamLocalUserCreateSshTransport(_config(tmp_path))

    with pytest.raises(LocalUserCreateSshTransportError):
        transport.inspect('unsafe"\nset status enable')
    with pytest.raises(LocalUserCreateSshTransportError):
        transport.create_and_readback("unsafe name")


def test_readback_requires_exact_fixed_profile_and_disabled_status() -> None:
    output = (
        b'edit "mcp-user-create-01"\r\n'
        + f'    set accprofile "{DEFAULT_ACCESS_PROFILE}"\r\n'.encode("ascii")
        + b"    set status disable\r\n"
    )

    readback = _readback(output, "mcp-user-create-01")

    assert readback.verified is True
    assert _readback(
        output.replace(b"set status disable", b"set status enable"),
        "mcp-user-create-01",
    ).verified is False
    assert _readback(
        output.replace(b"Guest", b"Administrator"),
        "mcp-user-create-01",
    ).verified is False


def test_admin_context_collects_multiple_async_command_outputs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamLocalUserCreateSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        return {
            "show | grep mcp-user-create-01": b"compact",
            "show | grep mcp-user-create-01 -f": b"full",
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
            ("show | grep mcp-user-create-01", "show | grep mcp-user-create-01 -f"),
            100.0,
        )
    )

    assert output == b"compactfull"
    assert commands == [
        "config system admin",
        "show | grep mcp-user-create-01",
        "show | grep mcp-user-create-01 -f",
        "end",
    ]
