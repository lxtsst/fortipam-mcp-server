from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.approval_profile_ssh_transport as transport_module
from fortipam_mcp.approval_profile_ssh_transport import (
    ApprovalProfileSshTransportConfigurationError,
    FortiPamApprovalProfileSshTransport,
    _update_readback,
    load_approval_profile_update_ssh_transport_config,
)


PROFILE_NAME = "mcp-v4-approval-profile-01"


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
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_PROFILE_UPDATE_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_PROFILE_UPDATE_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_PROFILE_UPDATE_SSH_USERNAME": (
            "fortipam-approval-profile-update-writer"
        ),
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_PROFILE_UPDATE_SSH_PASSWORD_FILE": str(
            password
        ),
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_PROFILE_UPDATE_SSH_KNOWN_HOSTS_FILE": str(
            known_hosts
        ),
    }


def test_update_loader_uses_its_own_dedicated_transport_scope(tmp_path: Path) -> None:
    environment = _environment(tmp_path)

    loaded = load_approval_profile_update_ssh_transport_config(environment)

    assert loaded.username == "fortipam-approval-profile-update-writer"
    environment["FPA_HOME_LAB_FPA1_V4_APPROVAL_PROFILE_UPDATE_ENABLED"] = "false"
    with pytest.raises(
        ApprovalProfileSshTransportConfigurationError,
        match="must be exactly true",
    ):
        load_approval_profile_update_ssh_transport_config(environment)


def test_update_readback_requires_preserved_baseline_and_fixed_new_description() -> None:
    output = (
        b'edit "mcp-v4-approval-profile-01"\r\n'
        + b"set type single\r\n"
        + b"set first-num 1\r\n"
        + b'set first-user "admin"\r\n'
        + b'set description "MCP V4 updated unbound approval profile"\r\n'
        + b"set remote-group-email disable\r\n"
        + b"set approver-perm-req none\r\n"
        + b"set email-template ''\r\n"
        + b"set email-approval-link-expiry 120\r\n"
    )

    assert _update_readback(output, PROFILE_NAME).verified is True
    assert (
        _update_readback(
            output.replace(b"set first-num 1", b"set first-num 2"),
            PROFILE_NAME,
        ).verified
        is False
    )


def test_update_uses_only_the_fixed_description_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamApprovalProfileSshTransport(
        load_approval_profile_update_ssh_transport_config(_environment(tmp_path))
    )
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (approval-profile) #"
    profile_prompt = b"fpa (mcp-v4-approval-profile-01) #"

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
        if command == "config secret approval-profile":
            return table_prompt
        if command == 'edit "mcp-v4-approval-profile-01"':
            return profile_prompt
        if command == "next":
            return table_prompt
        if command == "end":
            return root_prompt
        raise AssertionError(command)

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._update_profile_description(
            object(),
            root_prompt,
            PROFILE_NAME,
            100.0,
        )
    )

    assert commands == [
        "config secret approval-profile",
        'edit "mcp-v4-approval-profile-01"',
        'set description "MCP V4 updated unbound approval profile"',
        "next",
        "end",
    ]
