from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.automation_action_ssh_transport as transport_module
from fortipam_mcp.automation_action_ssh_transport import (
    AutomationActionSshTransportConfig,
    AutomationActionSshTransportConfigurationError,
    AutomationActionSshTransportError,
    FortiPamAutomationActionSshTransport,
    _readback,
    _strict_reference_count,
    load_automation_action_ssh_transport_config,
)


ACTION_NAME = "mcp-v4-automation-action-01"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> AutomationActionSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return AutomationActionSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-automation-action-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_AUTOMATION_ACTION_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_AUTOMATION_ACTION_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_AUTOMATION_ACTION_SSH_USERNAME": (
            "fortipam-automation-action-writer"
        ),
        "FPA_HOME_LAB_FPA1_V4_AUTOMATION_ACTION_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_AUTOMATION_ACTION_SSH_KNOWN_HOSTS_FILE": str(
            known_hosts
        ),
    }

    loaded = load_automation_action_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-automation-action-writer"
    password.chmod(0o640)
    with pytest.raises(
        AutomationActionSshTransportConfigurationError,
        match="owner-only",
    ):
        load_automation_action_ssh_transport_config(environment)


def test_input_rejects_out_of_scope_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamAutomationActionSshTransport(_config(tmp_path))

    with pytest.raises(AutomationActionSshTransportError):
        transport.inspect("default")
    with pytest.raises(AutomationActionSshTransportError):
        transport.create_and_readback('mcp-v4-automation-action-unsafe"\nset x y')


def test_readback_requires_all_fixed_unbound_email_action_controls() -> None:
    output = (
        b'edit "mcp-v4-automation-action-01"\r\n'
        + b"set action-type email\r\n"
        + b'set email-subject "FortiPAM V4 unbound action"\r\n'
        + b'set email-to "mcp-v4-no-send@example.invalid"\r\n'
        + b'set message "MCP V4 unbound action no stitch"\r\n'
        + b'set description "MCP V4 unbound automation action"\r\n'
    )

    assert _readback(output, ACTION_NAME).verified is True
    assert (
        _readback(
            output.replace(b"set action-type email", b"set action-type cli-script"),
            ACTION_NAME,
        ).verified
        is False
    )


def test_create_uses_only_the_fixed_guide_automation_action_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamAutomationActionSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (automation-action) #"
    action_prompt = b"fpa (mcp-v4-automation-action-01) #"

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
        if command == "config system automation-action":
            return table_prompt
        if command == 'edit "mcp-v4-automation-action-01"':
            return action_prompt
        if command == "next":
            return table_prompt
        if command == "end":
            return root_prompt
        raise AssertionError(command)

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._create_action(
            object(),
            root_prompt,
            ACTION_NAME,
            100.0,
        )
    )

    assert commands == [
        "config system automation-action",
        'edit "mcp-v4-automation-action-01"',
        "set action-type email",
        'set email-subject "FortiPAM V4 unbound action"',
        'set email-to "mcp-v4-no-send@example.invalid"',
        'set message "MCP V4 unbound action no stitch"',
        'set description "MCP V4 unbound automation action"',
        "next",
        "end",
    ]


def test_action_reader_uses_both_requested_show_forms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamAutomationActionSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command in {
            "show | grep mcp-v4-automation-action-01",
            "show | grep mcp-v4-automation-action-01 -f",
        }
        return b"action"

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config system automation-action":
            return b"fpa (automation-action) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._show_action(object(), b"fpa #", ACTION_NAME, 100.0)
    )

    assert output == b"actionaction"
    assert commands == [
        "config system automation-action",
        "show | grep mcp-v4-automation-action-01",
        "show | grep mcp-v4-automation-action-01 -f",
        "end",
    ]


def test_reference_count_requires_exact_echo_prompt_and_known_rows() -> None:
    command = (
        "diagnose sys cmdb refcnt show system.automation-action.name "
        "mcp-v4-automation-action-01"
    )
    root_prompt = b"fpa #"
    assert _strict_reference_count(
        command.encode() + b"\r\n" + root_prompt,
        command,
        root_prompt,
    ) == 0
    assert _strict_reference_count(
        command.encode()
        + b"\r\nentry used by system.automation-stitch:name\r\n"
        + root_prompt,
        command,
        root_prompt,
    ) == 1
    with pytest.raises(AutomationActionSshTransportError):
        _strict_reference_count(
            command.encode() + b"\r\nunrecognized row\r\n" + root_prompt,
            command,
            root_prompt,
        )


def test_reference_count_uses_wide_terminal_and_exact_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamAutomationActionSshTransport(_config(tmp_path))
    command = (
        "diagnose sys cmdb refcnt show system.automation-action.name "
        "mcp-v4-automation-action-01"
    )
    observed: list[str] = []

    class _Connection:
        async def __aenter__(self) -> "_Connection":
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

    async def open_cli(connection: object) -> tuple[object, bytes, float]:
        del connection
        return object(), b"fpa #", 100.0

    async def send(
        process: object,
        actual_command: str,
        prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        observed.append(actual_command)
        return actual_command.encode() + b"\r\n" + prompt

    async def close(process: object) -> None:
        del process

    monkeypatch.setattr(transport, "_connection", lambda: _Connection())
    monkeypatch.setattr(transport, "_open_cli", open_cli)
    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_close_cli", close)

    assert transport.reference_count(ACTION_NAME) == 0
    assert observed == [command]
