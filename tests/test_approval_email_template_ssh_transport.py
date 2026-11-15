from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.approval_email_template_ssh_transport as transport_module
from fortipam_mcp.approval_email_template_ssh_transport import (
    ApprovalEmailTemplateSshTransportConfig,
    ApprovalEmailTemplateSshTransportConfigurationError,
    ApprovalEmailTemplateSshTransportError,
    FortiPamApprovalEmailTemplateSshTransport,
    _readback,
    load_approval_email_template_ssh_transport_config,
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


def _config(tmp_path: Path) -> ApprovalEmailTemplateSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return ApprovalEmailTemplateSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-approval-template-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_EMAIL_TEMPLATE_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_EMAIL_TEMPLATE_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_EMAIL_TEMPLATE_SSH_USERNAME": (
            "fortipam-approval-template-writer"
        ),
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_EMAIL_TEMPLATE_SSH_PASSWORD_FILE": str(
            password
        ),
        "FPA_HOME_LAB_FPA1_V4_APPROVAL_EMAIL_TEMPLATE_SSH_KNOWN_HOSTS_FILE": str(
            known_hosts
        ),
    }

    loaded = load_approval_email_template_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-approval-template-writer"
    password.chmod(0o640)
    with pytest.raises(
        ApprovalEmailTemplateSshTransportConfigurationError,
        match="owner-only",
    ):
        load_approval_email_template_ssh_transport_config(environment)


def test_input_rejects_out_of_scope_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamApprovalEmailTemplateSshTransport(_config(tmp_path))

    with pytest.raises(ApprovalEmailTemplateSshTransportError):
        transport.inspect("default")
    with pytest.raises(ApprovalEmailTemplateSshTransportError):
        transport.create_and_readback('mcp-v4-approval-email-template-unsafe"\nset x y')


def test_readback_requires_both_fixed_unassociated_template_controls() -> None:
    output = (
        b'edit "mcp-v4-approval-email-template-01"\r\n'
        + b'set subject "FortiPAM V4 unbound approval template"\r\n'
        + b'set content "MCP V4 unbound approval template"\r\n'
    )

    assert _readback(output, TEMPLATE_NAME).verified is True
    assert (
        _readback(
            output.replace(
                b'set content "MCP V4 unbound approval template"',
                b'set content "wrong"',
            ),
            TEMPLATE_NAME,
        ).verified
        is False
    )


def test_create_uses_only_the_fixed_guide_template_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamApprovalEmailTemplateSshTransport(_config(tmp_path))
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
        transport._create_template(
            object(),
            root_prompt,
            TEMPLATE_NAME,
            100.0,
        )
    )

    assert commands == [
        "config secret approval-email-template",
        'edit "mcp-v4-approval-email-template-01"',
        'set subject "FortiPAM V4 unbound approval template"',
        'set content "MCP V4 unbound approval template"',
        "next",
        "end",
    ]


def test_template_reader_uses_both_requested_show_forms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamApprovalEmailTemplateSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command in {
            "show | grep mcp-v4-approval-email-template-01",
            'show full-configuration | grep -A 80 "^ *edit.*mcp-v4-approval-email-template-01"',
        }
        return b"template"

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config secret approval-email-template":
            return b"fpa (approval-email-template) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._show_template(object(), b"fpa #", TEMPLATE_NAME, 100.0)
    )

    assert output == b"templatetemplate"
    assert commands == [
        "config secret approval-email-template",
        "show | grep mcp-v4-approval-email-template-01",
        'show full-configuration | grep -A 80 "^ *edit.*mcp-v4-approval-email-template-01"',
        "end",
    ]
