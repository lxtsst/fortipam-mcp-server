from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.automation_stitch_ssh_transport as transport_module
from fortipam_mcp.automation_stitch_ssh_transport import (
    AutomationStitchSshTransportConfig,
    AutomationStitchSshTransportConfigurationError,
    AutomationStitchSshTransportError,
    FortiPamAutomationStitchSshTransport,
    _readback,
    _strict_reference_count,
    load_automation_stitch_ssh_transport_config,
)


STITCH_NAME = "mcp-v4-automation-stitch-01"
TRIGGER_NAME = "mcp-v4-automation-trigger-01"
ACTION_NAME = "mcp-v4-automation-action-01"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> AutomationStitchSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return AutomationStitchSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-automation-stitch-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_AUTOMATION_STITCH_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_AUTOMATION_STITCH_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_AUTOMATION_STITCH_SSH_USERNAME": (
            "fortipam-automation-stitch-writer"
        ),
        "FPA_HOME_LAB_FPA1_V4_AUTOMATION_STITCH_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_AUTOMATION_STITCH_SSH_KNOWN_HOSTS_FILE": str(
            known_hosts
        ),
    }

    loaded = load_automation_stitch_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-automation-stitch-writer"
    password.chmod(0o640)
    with pytest.raises(
        AutomationStitchSshTransportConfigurationError,
        match="owner-only",
    ):
        load_automation_stitch_ssh_transport_config(environment)


def test_input_rejects_out_of_scope_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamAutomationStitchSshTransport(_config(tmp_path))

    with pytest.raises(AutomationStitchSshTransportError):
        transport.inspect("default", TRIGGER_NAME, ACTION_NAME)
    with pytest.raises(AutomationStitchSshTransportError):
        transport.create_and_readback(
            'mcp-v4-automation-stitch-unsafe"\nset x y',
            TRIGGER_NAME,
            ACTION_NAME,
        )


def test_readback_requires_all_fixed_disabled_stitch_controls() -> None:
    output = (
        b'edit "mcp-v4-automation-stitch-01"\r\n'
        + b"set status disable\r\n"
        + b'set description "MCP V4 disabled single-action lab stitch"\r\n'
        + b'set trigger "mcp-v4-automation-trigger-01"\r\n'
        + b"config actions\r\n"
        + b"edit 1\r\n"
        + b'set action "mcp-v4-automation-action-01"\r\n'
        + b"set delay 0\r\n"
        + b"set required enable\r\n"
    )

    assert _readback(output, STITCH_NAME, TRIGGER_NAME, ACTION_NAME).verified is True
    assert (
        _readback(
            output.replace(b"set status disable", b"set status enable"),
            STITCH_NAME,
            TRIGGER_NAME,
            ACTION_NAME,
        ).verified
        is False
    )


def test_strict_reference_count_requires_exact_wide_terminal_envelope() -> None:
    command = (
        "diagnose sys cmdb refcnt show system.automation-stitch.name "
        + STITCH_NAME
    )
    root_prompt = b"fpa #"

    assert _strict_reference_count(
        command.encode("ascii") + b"\r\nfpa #",
        command,
        root_prompt,
    ) == 0
    assert _strict_reference_count(
        command.encode("ascii")
        + b"\r\nentry used by system.example.name x\r\nfpa #",
        command,
        root_prompt,
    ) == 1
    with pytest.raises(AutomationStitchSshTransportError):
        _strict_reference_count(
            command.encode("ascii") + b"\r\nunknown output\r\nfpa #",
            command,
            root_prompt,
        )
    with pytest.raises(AutomationStitchSshTransportError):
        _strict_reference_count(
            b"wrapped command\r\nfpa #",
            command,
            root_prompt,
        )

def test_create_uses_only_the_fixed_disabled_single_action_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamAutomationStitchSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (automation-stitch) #"
    stitch_prompt = b"fpa (mcp-v4-automation-stitch-01) #"
    actions_prompt = b"fpa (actions) #"
    action_prompt = b"fpa (1) #"

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
        if command == "config system automation-stitch":
            return table_prompt
        if command == 'edit "mcp-v4-automation-stitch-01"':
            return stitch_prompt
        if command == "config actions":
            return actions_prompt
        if command == "edit 1":
            return action_prompt
        if command == "next":
            return actions_prompt if commands.count("next") == 1 else table_prompt
        if command == "end":
            return stitch_prompt if commands.count("end") == 1 else root_prompt
        raise AssertionError(command)

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._create_stitch(
            object(),
            root_prompt,
            STITCH_NAME,
            TRIGGER_NAME,
            ACTION_NAME,
            100.0,
        )
    )

    assert commands == [
        "config system automation-stitch",
        'edit "mcp-v4-automation-stitch-01"',
        "set status disable",
        'set description "MCP V4 disabled single-action lab stitch"',
        'set trigger "mcp-v4-automation-trigger-01"',
        "config actions",
        "edit 1",
        'set action "mcp-v4-automation-action-01"',
        "set delay 0",
        "set required enable",
        "next",
        "end",
        "next",
        "end",
    ]


def test_reader_uses_both_requested_show_forms_for_all_three_contexts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamAutomationStitchSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command.startswith("show | grep mcp-v4-automation-")
        return b"entry"

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command in {
            "config system automation-stitch",
            "config system automation-trigger",
            "config system automation-action",
        }:
            return b"fpa (table) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    async def exercise() -> None:
        assert await transport._show_context(
            object(),
            b"fpa #",
            "config system automation-stitch",
            STITCH_NAME,
            100.0,
        ) == b"entryentry"
        assert await transport._show_context(
            object(),
            b"fpa #",
            "config system automation-trigger",
            TRIGGER_NAME,
            100.0,
        ) == b"entryentry"
        assert await transport._show_context(
            object(),
            b"fpa #",
            "config system automation-action",
            ACTION_NAME,
            100.0,
        ) == b"entryentry"

    asyncio.run(exercise())

    assert commands == [
        "config system automation-stitch",
        f"show | grep {STITCH_NAME}",
        f"show | grep {STITCH_NAME} -f",
        "end",
        "config system automation-trigger",
        f"show | grep {TRIGGER_NAME}",
        f"show | grep {TRIGGER_NAME} -f",
        "end",
        "config system automation-action",
        f"show | grep {ACTION_NAME}",
        f"show | grep {ACTION_NAME} -f",
        "end",
    ]


def test_readback_aborts_exact_stitch_entry_without_committing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamAutomationStitchSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (automation-stitch) #"
    stitch_prompt = b"fpa (mcp-v4-automation-stitch-01) #"

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, deadline
        commands.append(command)
        assert command == "show full-configuration"
        assert prompt == stitch_prompt
        return b"entry-with-nested-action"

    async def dynamic(
        process: object,
        command: str,
        known_root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, known_root_prompt, deadline
        commands.append(command)
        if command == "config system automation-stitch":
            return table_prompt
        if command == f'edit "{STITCH_NAME}"':
            return stitch_prompt
        if command == "abort":
            return root_prompt
        raise AssertionError(command)

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._show_created_stitch(
            object(),
            root_prompt,
            STITCH_NAME,
            100.0,
        )
    )

    assert output == b"entry-with-nested-action"
    assert commands == [
        "config system automation-stitch",
        f'edit "{STITCH_NAME}"',
        "show full-configuration",
        "abort",
    ]


def test_readback_aborts_after_show_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamAutomationStitchSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        raise OSError("synthetic read failure")

    async def dynamic(
        process: object,
        command: str,
        known_root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, known_root_prompt, deadline
        commands.append(command)
        if command == "config system automation-stitch":
            return b"fpa (automation-stitch) #"
        if command == f'edit "{STITCH_NAME}"':
            return b"fpa (mcp-v4-automation-stitch-01) #"
        assert command == "abort"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    with pytest.raises(AutomationStitchSshTransportError):
        asyncio.run(
            transport._show_created_stitch(object(), root_prompt, STITCH_NAME, 100.0)
        )
    assert commands == [
        "config system automation-stitch",
        f'edit "{STITCH_NAME}"',
        "show full-configuration",
        "abort",
    ]
