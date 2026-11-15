from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.approval_email_template_ssh_transport as transport_module
from fortipam_mcp.approval_email_template_ssh_transport import (
    ApprovalEmailTemplateSshTransportConfigurationError,
    ApprovalEmailTemplateSshTransportError,
    FortiPamApprovalEmailTemplateSshTransport,
    _strict_reference_count,
    _update_readback,
    load_approval_email_template_update_ssh_transport_config,
)


TEMPLATE_NAME = "mcp-v4-approval-email-template-01"


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
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_SSH_USERNAME": (
            "fortipam-approval-template-update-writer"
        ),
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_SSH_PASSWORD_FILE": str(
            password
        ),
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_SSH_KNOWN_HOSTS_FILE": str(
            known_hosts
        ),
    }


def test_update_loader_uses_its_own_dedicated_transport_scope(tmp_path: Path) -> None:
    environment = _environment(tmp_path)

    loaded = load_approval_email_template_update_ssh_transport_config(environment)

    assert loaded.username == "fortipam-approval-template-update-writer"
    environment["FPA_HOME_LAB_FPA1_V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ENABLED"] = "false"
    with pytest.raises(
        ApprovalEmailTemplateSshTransportConfigurationError,
        match="must be exactly true",
    ):
        load_approval_email_template_update_ssh_transport_config(environment)


def test_update_readback_requires_both_fixed_updated_template_controls() -> None:
    output = (
        b'edit "mcp-v4-approval-email-template-01"\r\n'
        + b'set subject "FortiPAM V4 updated approval template"\r\n'
        + b'set content "MCP V4 updated approval template"\r\n'
    )

    assert _update_readback(output, TEMPLATE_NAME).verified is True
    assert (
        _update_readback(
            output.replace(
                b'set content "MCP V4 updated approval template"',
                b'set content "wrong"',
            ),
            TEMPLATE_NAME,
        ).verified
        is False
    )


def test_update_uses_only_the_fixed_subject_and_content_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamApprovalEmailTemplateSshTransport(
        load_approval_email_template_update_ssh_transport_config(_environment(tmp_path))
    )
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (approval-email-template) #"
    template_prompt = b"fpa (mcp-v4-approval-email-template-01) #"

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
        if command == "config secret approval-email-template":
            return table_prompt
        if command == 'edit "mcp-v4-approval-email-template-01"':
            return template_prompt
        if command == "next":
            return table_prompt
        if command == "end":
            return root_prompt
        raise AssertionError(command)

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._update_template(
            object(),
            root_prompt,
            TEMPLATE_NAME,
            100.0,
        )
    )

    assert commands == [
        "config secret approval-email-template",
        'edit "mcp-v4-approval-email-template-01"',
        'set subject "FortiPAM V4 updated approval template"',
        'set content "MCP V4 updated approval template"',
        "next",
        "end",
    ]


def test_reference_count_requires_exact_unwrapped_echo_prompt_envelope() -> None:
    command = (
        "diagnose sys cmdb refcnt show secret.approval-email-template.name "
        "mcp-v4-approval-email-template-b37"
    )
    root_prompt = b"fpa #"

    assert _strict_reference_count(
        command.encode("ascii") + b"\r\n" + root_prompt,
        command,
        root_prompt,
    ) == 0
    assert _strict_reference_count(
        command.encode("ascii")
        + b"\r\nentry used by secret.approval-profile:name\r\n"
        + root_prompt,
        command,
        root_prompt,
    ) == 1

    with pytest.raises(ApprovalEmailTemplateSshTransportError):
        _strict_reference_count(
            command[:80].encode("ascii")
            + b"\r\n"
            + command[80:].encode("ascii")
            + b"\r\n"
            + root_prompt,
            command,
            root_prompt,
        )
    with pytest.raises(ApprovalEmailTemplateSshTransportError):
        _strict_reference_count(
            command.encode("ascii") + b"\r\nunknown output\r\n" + root_prompt,
            command,
            root_prompt,
        )
