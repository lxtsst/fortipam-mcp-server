from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.automation_trigger_ssh_transport as transport_module
from fortipam_mcp.automation_trigger_ssh_transport import (
    AutomationTriggerSshTransportConfig,
    AutomationTriggerSshTransportConfigurationError,
    AutomationTriggerSshTransportError,
    FortiPamAutomationTriggerSshTransport,
    _readback,
    _strict_reference_count,
    load_automation_trigger_ssh_transport_config,
)


TRIGGER_NAME = "mcp-v4-automation-trigger-01"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> AutomationTriggerSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return AutomationTriggerSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-automation-trigger-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_AUTOMATION_TRIGGER_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_AUTOMATION_TRIGGER_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_AUTOMATION_TRIGGER_SSH_USERNAME": (
            "fortipam-automation-trigger-writer"
        ),
        "FPA_HOME_LAB_FPA1_V4_AUTOMATION_TRIGGER_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_AUTOMATION_TRIGGER_SSH_KNOWN_HOSTS_FILE": str(
            known_hosts
        ),
    }

    loaded = load_automation_trigger_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-automation-trigger-writer"
    password.chmod(0o640)
    with pytest.raises(
        AutomationTriggerSshTransportConfigurationError,
        match="owner-only",
    ):
        load_automation_trigger_ssh_transport_config(environment)


def test_input_rejects_out_of_scope_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamAutomationTriggerSshTransport(_config(tmp_path))

    with pytest.raises(AutomationTriggerSshTransportError):
        transport.inspect("default")
    with pytest.raises(AutomationTriggerSshTransportError):
        transport.create_and_readback('mcp-v4-automation-trigger-unsafe"\nset x y')


def test_readback_requires_all_fixed_no_action_trigger_controls() -> None:
    output = (
        b'edit "mcp-v4-automation-trigger-01"\r\n'
        + b"set event-type event-log\r\n"
        + b"set logid 44547\r\n"
        + b"set category 1\r\n"
        + b"set logic and\r\n"
        + b"set match regex\r\n"
        + b'set name "msg"\r\n'
        + b'set value "mcp-v4-no-action"\r\n'
    )

    assert _readback(output, TRIGGER_NAME).verified is True
    assert (
        _readback(
            output.replace(b"set logic and", b"set logic or"),
            TRIGGER_NAME,
        ).verified
        is False
    )


def test_create_uses_only_the_fixed_guide_automation_trigger_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamAutomationTriggerSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (automation-trigger) #"
    trigger_prompt = b"fpa (mcp-v4-automation-trigger-01) #"
    fields_prompt = b"fpa (fields) #"
    field_prompt = b"fpa (1) #"

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
        if command == "config system automation-trigger":
            return table_prompt
        if command == 'edit "mcp-v4-automation-trigger-01"':
            return trigger_prompt
        if command == "config fields":
            return fields_prompt
        if command == "edit 1":
            return field_prompt
        if command == "next":
            return fields_prompt if commands.count("next") == 1 else table_prompt
        if command == "end":
            return trigger_prompt if commands.count("end") == 1 else root_prompt
        raise AssertionError(command)

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._create_trigger(
            object(),
            root_prompt,
            TRIGGER_NAME,
            100.0,
        )
    )

    assert commands == [
        "config system automation-trigger",
        'edit "mcp-v4-automation-trigger-01"',
        "set event-type event-log",
        "set category 1",
        "set logid 44547",
        "set logic and",
        "config fields",
        "edit 1",
        "set match regex",
        'set name "msg"',
        'set value "mcp-v4-no-action"',
        "next",
        "end",
        "next",
        "end",
    ]


def test_trigger_reader_uses_exact_entry_show_and_aborts_without_saving(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamAutomationTriggerSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        if command == "show | grep mcp-v4-automation-trigger-01":
            return b'edit "mcp-v4-automation-trigger-01"\r\n'
        assert command == "show"
        return b"config fields\r\nset name \"msg\"\r\n"

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config system automation-trigger":
            return b"fpa (automation-trigger) #"
        if command == 'edit "mcp-v4-automation-trigger-01"':
            return b"fpa (mcp-v4-automation-trigger-01) #"
        assert command == "abort"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._show_trigger(object(), b"fpa #", TRIGGER_NAME, 100.0)
    )

    assert output == (
        b'edit "mcp-v4-automation-trigger-01"\r\n'
        b"config fields\r\nset name \"msg\"\r\n"
    )
    assert commands == [
        "config system automation-trigger",
        "show | grep mcp-v4-automation-trigger-01",
        'edit "mcp-v4-automation-trigger-01"',
        "show",
        "abort",
    ]


def test_trigger_reader_does_not_edit_an_absent_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamAutomationTriggerSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command == "show | grep mcp-v4-automation-trigger-01"
        return b""

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config system automation-trigger":
            return b"fpa (automation-trigger) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._show_trigger(object(), b"fpa #", TRIGGER_NAME, 100.0)
    )

    assert output == b""
    assert commands == [
        "config system automation-trigger",
        "show | grep mcp-v4-automation-trigger-01",
        "end",
    ]


def test_strict_reference_count_requires_exact_envelope_and_known_rows() -> None:
    command = (
        "diagnose sys cmdb refcnt show system.automation-trigger.name "
        "mcp-v4-automation-trigger-01"
    )
    prompt = b"fpa #"
    assert _strict_reference_count(
        command.encode() + b"\r\n" + prompt,
        command,
        prompt,
    ) == 0
    assert _strict_reference_count(
        command.encode() + b"\r\nentry used by system.automation-stitch:name x\r\n" + prompt,
        command,
        prompt,
    ) == 1
    with pytest.raises(AutomationTriggerSshTransportError):
        _strict_reference_count(
            command.encode() + b"\r\nunrecognized\r\n" + prompt,
            command,
            prompt,
        )
