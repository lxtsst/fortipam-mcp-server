from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.secret_approval_ssh_transport as transport_module
from fortipam_mcp.approval_profile_ssh_transport import (
    ApprovalProfileSshTransportConfig,
)
from fortipam_mcp.secret_approval_ssh_transport import (
    FortiPamSecretApprovalSshTransport,
    SecretApprovalSshTransportError,
)


PROFILE_NAME = "mcp-v4-approval-profile-01"


def _config(tmp_path: Path) -> ApprovalProfileSshTransportConfig:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(
        "fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n"
    )
    known_hosts.chmod(0o600)
    return ApprovalProfileSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-secret-approval-writer",
        password="test-password",
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_fixed_secret_approval_update_compiles_only_four_approval_fields(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamSecretApprovalSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (database) #"
    secret_prompt = b"fpa (42) #"

    async def send(
        process: object,
        command: str,
        prompt: bytes,
        deadline: float,
    ) -> bytes:
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
        return {
            "config secret database": table_prompt,
            "edit 42": secret_prompt,
            "next": table_prompt,
            "end": root_prompt,
        }[command]

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._apply_commands(
            object(),
            root_prompt,
            100.0,
            42,
            PROFILE_NAME,
        )
    )

    assert commands == [
        "config secret database",
        "edit 42",
        "set need-approval enable",
        "set need-approval-job disable",
        "set bypass-approval disable",
        'set approval-profile "mcp-v4-approval-profile-01"',
        "next",
        "end",
    ]


def test_secret_approval_transport_rejects_unbounded_selector_before_io(
    tmp_path: Path,
) -> None:
    transport = FortiPamSecretApprovalSshTransport(_config(tmp_path))

    with pytest.raises(SecretApprovalSshTransportError):
        transport.enable_interactive_approval(0, PROFILE_NAME)
    with pytest.raises(SecretApprovalSshTransportError):
        transport.enable_interactive_approval(
            42,
            'mcp-v4-approval-profile-bad"\nset field value',
        )
