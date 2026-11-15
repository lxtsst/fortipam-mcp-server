from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.schedule_ssh_transport as transport_module
from fortipam_mcp.schedule_ssh_transport import (
    FortiPamScheduleSshTransport,
    ScheduleSshTransportConfig,
    ScheduleSshTransportConfigurationError,
    ScheduleSshTransportError,
    _readback,
    _strict_reference_count,
    load_schedule_ssh_transport_config,
)


SCHEDULE_NAME = "mcp-v4-schedule-01"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> ScheduleSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return ScheduleSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-schedule-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_SCHEDULE_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_SCHEDULE_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_SCHEDULE_SSH_USERNAME": "fortipam-schedule-writer",
        "FPA_HOME_LAB_FPA1_V4_SCHEDULE_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_SCHEDULE_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_schedule_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-schedule-writer"
    password.chmod(0o640)
    with pytest.raises(
        ScheduleSshTransportConfigurationError,
        match="owner-only",
    ):
        load_schedule_ssh_transport_config(environment)


def test_input_rejects_out_of_scope_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamScheduleSshTransport(_config(tmp_path))

    with pytest.raises(ScheduleSshTransportError):
        transport.inspect("always")
    with pytest.raises(ScheduleSshTransportError):
        transport.create_and_readback('mcp-v4-schedule-unsafe"\nset x y')


def test_readback_requires_all_fixed_recurring_schedule_controls() -> None:
    output = (
        b'edit "mcp-v4-schedule-01"\r\n'
        + b"set start 01:00\r\n"
        + b"set end 01:30\r\n"
        + b"set day monday\r\n"
        + b"set color 0\r\n"
    )

    assert _readback(output, SCHEDULE_NAME).verified is True
    assert (
        _readback(
            output.replace(b"set day monday", b"set day tuesday"),
            SCHEDULE_NAME,
        ).verified
        is False
    )
    assert _readback(
        output.replace(b"set color 0\r\n", b""),
        SCHEDULE_NAME,
    ).verified is True
    assert _readback(
        output.replace(b"set color 0", b"set color 1"),
        SCHEDULE_NAME,
    ).verified is False


def test_create_uses_only_the_fixed_recurring_schedule_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamScheduleSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (recurring) #"
    schedule_prompt = b"fpa (mcp-v4-schedule-01) #"

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
        if command == "config firewall schedule recurring":
            return table_prompt
        if command == 'edit "mcp-v4-schedule-01"':
            return schedule_prompt
        if command == "next":
            return table_prompt
        if command == "end":
            return root_prompt
        raise AssertionError(command)

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._create_schedule(
            object(),
            root_prompt,
            SCHEDULE_NAME,
            100.0,
        )
    )

    assert commands == [
        "config firewall schedule recurring",
        'edit "mcp-v4-schedule-01"',
        "set start 01:00",
        "set end 01:30",
        "set day monday",
        "set color 0",
        "next",
        "end",
    ]


def test_reader_uses_both_requested_show_forms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamScheduleSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command in {
            "show | grep mcp-v4-schedule-01",
            "show | grep mcp-v4-schedule-01 -f",
        }
        return b"schedule"

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config firewall schedule recurring":
            return b"fpa (recurring) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._show_schedule(object(), b"fpa #", SCHEDULE_NAME, 100.0)
    )

    assert output == b"scheduleschedule"
    assert commands == [
        "config firewall schedule recurring",
        "show | grep mcp-v4-schedule-01",
        "show | grep mcp-v4-schedule-01 -f",
        "end",
    ]


def test_reference_count_parser_requires_exact_echo_prompt_and_known_rows() -> None:
    command = (
        "diagnose sys cmdb refcnt show firewall.schedule.recurring.name "
        "mcp-v4-schedule-01"
    )
    root_prompt = b"fpa #"

    assert _strict_reference_count(
        command.encode() + b"\r\n" + root_prompt,
        command,
        root_prompt,
    ) == 0
    assert _strict_reference_count(
        command.encode()
        + b"\r\nentry used by table system.admin:name user\r\n"
        + root_prompt,
        command,
        root_prompt,
    ) == 1
    with pytest.raises(ScheduleSshTransportError):
        _strict_reference_count(
            command.encode() + b"\r\nunrecognized output\r\n" + root_prompt,
            command,
            root_prompt,
        )
    with pytest.raises(ScheduleSshTransportError):
        _strict_reference_count(
            b"different command\r\n" + root_prompt,
            command,
            root_prompt,
        )
