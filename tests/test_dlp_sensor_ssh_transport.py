from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.dlp_sensor_ssh_transport as transport_module
from fortipam_mcp.dlp_sensor_ssh_transport import (
    DlpSensorSshTransportConfig,
    DlpSensorSshTransportConfigurationError,
    DlpSensorSshTransportError,
    FortiPamDlpSensorSshTransport,
    _contains_rendered_line,
    _file_pattern_reference_count,
    _readback,
    _regexp_readback,
    load_dlp_sensor_ssh_transport_config,
)


SENSOR_NAME = "mcp-v4-dlp-sensor-01"
PATTERN_ID = 1001
PATTERN_NAME = "mcp-v4-dlp-pattern-01"
REGEXP_SENSOR_NAME = "mcp-v4-dlp-regexp-sensor-01"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> DlpSensorSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return DlpSensorSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-dlp-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_DLP_SENSOR_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_DLP_SENSOR_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_DLP_SENSOR_SSH_USERNAME": "fortipam-dlp-writer",
        "FPA_HOME_LAB_FPA1_V4_DLP_SENSOR_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_DLP_SENSOR_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_dlp_sensor_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-dlp-writer"
    password.chmod(0o640)
    with pytest.raises(DlpSensorSshTransportConfigurationError, match="owner-only"):
        load_dlp_sensor_ssh_transport_config(environment)


def test_input_rejects_out_of_scope_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamDlpSensorSshTransport(_config(tmp_path))

    with pytest.raises(DlpSensorSshTransportError):
        transport.inspect("sensor", PATTERN_ID, PATTERN_NAME)
    with pytest.raises(DlpSensorSshTransportError):
        transport.inspect(SENSOR_NAME, 999, PATTERN_NAME)
    with pytest.raises(DlpSensorSshTransportError):
        transport.create_and_readback('mcp-v4-dlp-sensor-unsafe"\nset x y', PATTERN_ID)
    with pytest.raises(DlpSensorSshTransportError):
        transport.inspect_regexp_sensor(SENSOR_NAME)
    with pytest.raises(DlpSensorSshTransportError):
        transport.create_regexp_and_readback(
            'mcp-v4-dlp-regexp-sensor-unsafe"\nset x y'
        )


def test_readback_requires_the_fixed_http_get_pdf_block_filter_only() -> None:
    output = (
        b'edit "mcp-v4-dlp-sensor-01"\r\n'
        + b"config filter\r\n"
        + b"edit 1\r\n"
        + b'set name "mcp-v4-dlp-filter-pdf-block"\r\n'
        + b"set proto http-get\r\n"
        + b"set filter-by file-type\r\n"
        + b"set file-type 1001\r\n"
        + b"set action block\r\n"
    )

    assert _readback(output, SENSOR_NAME, PATTERN_ID).verified is True
    assert (
        _readback(
            output.replace(b"set action block", b"set action log-only"),
            SENSOR_NAME,
            PATTERN_ID,
        ).verified
        is False
    )


def test_inspection_markers_reject_cli_command_echo_false_positives() -> None:
    command_echo = (
        b'show full-configuration | grep -A 80 "^ *edit 1001$"\r\n'
        b'show | grep mcp-v4-dlp-pattern-01\r\n'
    )

    assert _contains_rendered_line(command_echo, b"edit 1001") is False
    assert (
        _contains_rendered_line(command_echo, b'set name "mcp-v4-dlp-pattern-01"')
        is False
    )
    assert _contains_rendered_line(b"  edit 1001\r\n", b"edit 1001") is True


def test_regexp_sensor_marker_rejects_the_bounded_show_command_echo() -> None:
    command_echo = (
        b'show full-configuration | grep -A 80 "^ *edit.*mcp-v4-dlp-regexp-sensor-01"\r\n'
    )

    assert (
        _contains_rendered_line(
            command_echo, b'edit "mcp-v4-dlp-regexp-sensor-01"'
        )
        is False
    )
    assert (
        _contains_rendered_line(
            b'edit "mcp-v4-dlp-regexp-sensor-01"\r\n',
            b'edit "mcp-v4-dlp-regexp-sensor-01"',
        )
        is True
    )

def test_file_pattern_reference_count_ignores_command_echo() -> None:
    output = (
        b'show full-configuration | grep "^ *set file-type 1001$"\r\n'
        b"set file-type 1001\r\n"
        b"    set file-type 1001\r\n"
        b"set file-type 1002\r\n"
    )

    assert _file_pattern_reference_count(output, PATTERN_ID) == 2


def test_regexp_readback_requires_the_fixed_http_get_sentinel_filter_only() -> None:
    output = (
        b'edit "mcp-v4-dlp-regexp-sensor-01"\r\n'
        + b"config filter\r\n"
        + b"edit 1\r\n"
        + b'set name "mcp-v4-dlp-filter-regexp-block"\r\n'
        + b"set type file\r\n"
        + b"set proto http-get\r\n"
        + b"set filter-by regexp\r\n"
        + b'set regexp "MCP_V4_DLP_REGEX_SENTINEL"\r\n'
        + b"set action block\r\n"
    )

    assert _regexp_readback(output, REGEXP_SENSOR_NAME).verified is True
    assert (
        _regexp_readback(
            output.replace(
                b'MCP_V4_DLP_REGEX_SENTINEL', b"MCP_V4_DLP_OTHER_SENTINEL"
            ),
            REGEXP_SENSOR_NAME,
        ).verified
        is False
    )


def test_create_uses_only_the_fixed_guide_sensor_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamDlpSensorSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (sensor) #"
    sensor_prompt = b"fpa (mcp-v4-dlp-sensor-01) #"
    filter_prompt = b"fpa (filter) #"
    entry_prompt = b"fpa (1) #"
    next_count = 0
    end_count = 0

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
        nonlocal end_count, next_count
        del process, known_root_prompt, deadline
        commands.append(command)
        if command == "config dlp sensor":
            return table_prompt
        if command == 'edit "mcp-v4-dlp-sensor-01"':
            return sensor_prompt
        if command == "config filter":
            return filter_prompt
        if command == "edit 1":
            return entry_prompt
        if command == "next":
            next_count += 1
            return filter_prompt if next_count == 1 else table_prompt
        assert command == "end"
        end_count += 1
        return sensor_prompt if end_count == 1 else root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._create_sensor(
            object(),
            root_prompt,
            SENSOR_NAME,
            PATTERN_ID,
            100.0,
        )
    )

    assert commands == [
        "config dlp sensor",
        'edit "mcp-v4-dlp-sensor-01"',
        "config filter",
        "edit 1",
        'set name "mcp-v4-dlp-filter-pdf-block"',
        "set proto http-get",
        "set filter-by file-type",
        "set file-type 1001",
        "set action block",
        "next",
        "end",
        "next",
        "end",
    ]


def test_regexp_create_uses_only_the_fixed_guide_sensor_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamDlpSensorSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (sensor) #"
    sensor_prompt = b"fpa (mcp-v4-dlp-regexp-sensor-01) #"
    filter_prompt = b"fpa (filter) #"
    entry_prompt = b"fpa (1) #"
    next_count = 0
    end_count = 0

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
        nonlocal end_count, next_count
        del process, known_root_prompt, deadline
        commands.append(command)
        if command == "config dlp sensor":
            return table_prompt
        if command == 'edit "mcp-v4-dlp-regexp-sensor-01"':
            return sensor_prompt
        if command == "config filter":
            return filter_prompt
        if command == "edit 1":
            return entry_prompt
        if command == "next":
            next_count += 1
            return filter_prompt if next_count == 1 else table_prompt
        assert command == "end"
        end_count += 1
        return sensor_prompt if end_count == 1 else root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._create_regexp_sensor(
            object(),
            root_prompt,
            REGEXP_SENSOR_NAME,
            100.0,
        )
    )

    assert commands == [
        "config dlp sensor",
        'edit "mcp-v4-dlp-regexp-sensor-01"',
        "config filter",
        "edit 1",
        'set name "mcp-v4-dlp-filter-regexp-block"',
        "set type file",
        "set proto http-get",
        "set filter-by regexp",
        'set regexp "MCP_V4_DLP_REGEX_SENTINEL"',
        "set action block",
        "next",
        "end",
        "next",
        "end",
    ]


def test_context_reader_accepts_only_compiled_bounded_full_show_form(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamDlpSensorSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command == 'show full-configuration | grep -A 80 "^ *edit.*mcp-v4-dlp-sensor-01"'
        return b"full"

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config dlp sensor":
            return b"fpa (sensor) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._show_context(
            object(),
            b"fpa #",
            "config dlp sensor",
            'show full-configuration | grep -A 80 "^ *edit.*mcp-v4-dlp-sensor-01"',
            100.0,
        )
    )

    assert output == b"full"
    assert commands == [
        "config dlp sensor",
        'show full-configuration | grep -A 80 "^ *edit.*mcp-v4-dlp-sensor-01"',
        "end",
    ]
