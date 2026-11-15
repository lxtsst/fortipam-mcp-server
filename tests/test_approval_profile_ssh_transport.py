from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.approval_profile_ssh_transport as transport_module
from fortipam_mcp.approval_profile_ssh_transport import (
    APPROVAL_PROFILE_UPDATED_DESCRIPTION,
    ApprovalProfileSshTransportConfig,
    ApprovalProfileSshTransportConfigurationError,
    ApprovalProfileSshTransportError,
    FortiPamApprovalProfileSshTransport,
    _readback,
    _strict_reference_count,
    _update_readback,
    load_approval_profile_ssh_transport_config,
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


def _config(tmp_path: Path) -> ApprovalProfileSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return ApprovalProfileSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-approval-profile-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_PROFILE_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_PROFILE_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_PROFILE_SSH_USERNAME": (
            "fortipam-approval-profile-writer"
        ),
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_PROFILE_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_PROFILE_SSH_KNOWN_HOSTS_FILE": str(
            known_hosts
        ),
    }

    loaded = load_approval_profile_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-approval-profile-writer"
    password.chmod(0o640)
    with pytest.raises(
        ApprovalProfileSshTransportConfigurationError,
        match="owner-only",
    ):
        load_approval_profile_ssh_transport_config(environment)


def test_input_rejects_out_of_scope_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamApprovalProfileSshTransport(_config(tmp_path))

    with pytest.raises(ApprovalProfileSshTransportError):
        transport.inspect("default")
    with pytest.raises(ApprovalProfileSshTransportError):
        transport.create_and_readback('mcp-v4-approval-profile-unsafe"\nset x y')


def test_readback_requires_all_fixed_unbound_approval_profile_controls() -> None:
    output = (
        b'edit "mcp-v4-approval-profile-01"\r\n'
        + b"set type single\r\n"
        + b"set first-num 1\r\n"
        + b'set first-user "admin"\r\n'
        + b'set description "MCP V4 unbound approval profile"\r\n'
        + b"set remote-group-email disable\r\n"
        + b"set approver-perm-req none\r\n"
        + b"set email-template ''\r\n"
        + b"set email-approval-link-expiry 120\r\n"
    )

    assert _readback(output, PROFILE_NAME).verified is True
    assert (
        _readback(
            output.replace(b"set first-num 1", b"set first-num 2"),
            PROFILE_NAME,
        ).verified
        is False
    )


def test_updated_readback_and_reference_parser_are_exact() -> None:
    output = (
        b'edit "mcp-v4-approval-profile-01"\n'
        b"set type single\n"
        b"set first-num 1\n"
        b'set first-user "admin"\n'
        + f'set description "{APPROVAL_PROFILE_UPDATED_DESCRIPTION}"\n'.encode("ascii")
        + b"set remote-group-email disable\n"
        + b"set approver-perm-req none\n"
        + b"set email-template ''\n"
        + b"set email-approval-link-expiry 120\n"
    )
    assert _update_readback(output, PROFILE_NAME).verified is True

    command = (
        "diagnose sys cmdb refcnt show secret.approval-profile.name " + PROFILE_NAME
    )
    assert _strict_reference_count(
        command.encode("ascii") + b"\r\nfpa #",
        command,
        b"fpa #",
    ) == 0
    assert _strict_reference_count(
        command.encode("ascii") + b"\nentry used by x\nfpa #",
        command,
        b"fpa #",
    ) == 1
    with pytest.raises(ApprovalProfileSshTransportError):
        _strict_reference_count(
            command.encode("ascii") + b"\nwrapped output\nfpa #",
            command,
            b"fpa #",
        )

def test_create_uses_only_the_fixed_guide_approval_profile_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamApprovalProfileSshTransport(_config(tmp_path))
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
        transport._create_profile(
            object(),
            root_prompt,
            PROFILE_NAME,
            100.0,
        )
    )

    assert commands == [
        "config secret approval-profile",
        'edit "mcp-v4-approval-profile-01"',
        "set type single",
        "set first-num 1",
        'set first-user "admin"',
        'set description "MCP V4 unbound approval profile"',
        "set remote-group-email disable",
        "set approver-perm-req none",
        "set email-template ''",
        "set email-approval-link-expiry 120",
        "next",
        "end",
    ]


def test_profile_reader_uses_both_requested_show_forms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamApprovalProfileSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command in {
            "show | grep mcp-v4-approval-profile-01",
            'show full-configuration | grep -A 80 "^ *edit.*mcp-v4-approval-profile-01"',
        }
        return b"profile"

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config secret approval-profile":
            return b"fpa (approval-profile) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._show_profile(object(), b"fpa #", PROFILE_NAME, 100.0)
    )

    assert output == b"profileprofile"
    assert commands == [
        "config secret approval-profile",
        "show | grep mcp-v4-approval-profile-01",
        'show full-configuration | grep -A 80 "^ *edit.*mcp-v4-approval-profile-01"',
        "end",
    ]
