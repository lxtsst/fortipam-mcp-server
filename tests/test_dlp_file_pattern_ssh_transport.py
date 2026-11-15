from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.dlp_file_pattern_ssh_transport as transport_module
from fortipam_mcp.dlp_file_pattern_ssh_transport import (
    DlpFilePatternSshTransportConfig,
    DlpFilePatternSshTransportConfigurationError,
    DlpFilePatternSshTransportError,
    FortiPamDlpFilePatternSshTransport,
    _readback,
    load_dlp_file_pattern_ssh_transport_config,
)


PATTERN_ID = 1001
PATTERN_NAME = "mcp-v4-dlp-pattern-01"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> DlpFilePatternSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return DlpFilePatternSshTransportConfig(
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
        "FPA_HOME_LAB_FPA1_V4_DLP_FILE_PATTERN_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_DLP_FILE_PATTERN_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_DLP_FILE_PATTERN_SSH_USERNAME": "fortipam-dlp-writer",
        "FPA_HOME_LAB_FPA1_V4_DLP_FILE_PATTERN_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_DLP_FILE_PATTERN_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_dlp_file_pattern_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-dlp-writer"
    password.chmod(0o640)
    with pytest.raises(DlpFilePatternSshTransportConfigurationError, match="owner-only"):
        load_dlp_file_pattern_ssh_transport_config(environment)


def test_input_rejects_out_of_scope_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamDlpFilePatternSshTransport(_config(tmp_path))

    with pytest.raises(DlpFilePatternSshTransportError):
        transport.inspect(999, PATTERN_NAME)
    with pytest.raises(DlpFilePatternSshTransportError):
        transport.create_and_readback(PATTERN_ID, 'mcp-v4-dlp-pattern-unsafe"\nset x y')


def test_readback_requires_the_fixed_pdf_entry_only() -> None:
    output = (
        b"edit 1001\r\n"
        + b'set name "mcp-v4-dlp-pattern-01"\r\n'
        + b"config entries\r\n"
        + b'edit "pdf"\r\n'
        + b"set filter-type type\r\n"
        + b"set file-type pdf\r\n"
    )

    assert _readback(output, PATTERN_ID, PATTERN_NAME).verified is True
    assert (
        _readback(
            output.replace(b"set file-type pdf", b"set file-type zip"),
            PATTERN_ID,
            PATTERN_NAME,
        ).verified
        is False
    )


def test_readback_does_not_treat_the_full_context_command_echo_as_an_entry() -> None:
    echoed_command = b'show full-configuration | grep -A 80 "^ *edit 1001$"\r\n'

    readback = _readback(echoed_command, PATTERN_ID, PATTERN_NAME)

    assert readback.pattern_id_exists is False
    assert readback.pattern_name_matches is False


def test_readback_accepts_fixed_pdf_fields_from_the_entries_context() -> None:
    root_output = b'edit 1001\r\nset name "mcp-v4-dlp-pattern-01"\r\n'
    entries_output = b"set filter-type type\r\nset file-type pdf\r\n"

    assert _readback(root_output, PATTERN_ID, PATTERN_NAME, entries_output).verified is True


def test_create_reads_back_on_a_new_ssh_session(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamDlpFilePatternSshTransport(_config(tmp_path))
    connections = [_Connection(), _Connection()]
    opened: list[_Connection] = []
    created: list[tuple[int, str]] = []
    root_output = (
        b"edit 1001\r\n"
        + b'set name "mcp-v4-dlp-pattern-01"\r\n'
    )
    entries_output = (
        b"set filter-type type\r\n"
        + b"set file-type pdf\r\n"
    )

    monkeypatch.setattr(transport, "_connection", lambda: connections.pop(0))

    async def open_cli(connection: _Connection) -> tuple[object, bytes, float]:
        opened.append(connection)
        return object(), b"fpa #", 100.0

    async def create_pattern(
        process: object,
        root_prompt: bytes,
        pattern_id: int,
        pattern_name: str,
        deadline: float,
    ) -> None:
        del process, root_prompt, deadline
        created.append((pattern_id, pattern_name))

    async def read_context(
        process: object,
        root_prompt: bytes,
        commands: tuple[str, ...],
        deadline: float,
    ) -> bytes:
        del process, root_prompt, deadline
        assert commands == (
            "show | grep 1001",
            "show | grep mcp-v4-dlp-pattern-01",
            'show full-configuration | grep -A 80 "^ *edit 1001$"',
        )
        return root_output

    async def read_entries(pattern_id: int) -> bytes:
        assert pattern_id == PATTERN_ID
        return entries_output

    async def close_cli(process: object) -> None:
        del process

    monkeypatch.setattr(transport, "_open_cli", open_cli)
    monkeypatch.setattr(transport, "_create_pattern", create_pattern)
    monkeypatch.setattr(transport, "_run_file_pattern_context", read_context)
    monkeypatch.setattr(transport, "_readback_entries_from_new_session", read_entries)
    monkeypatch.setattr(transport_module, "_close_cli", close_cli)

    result = asyncio.run(transport._create_and_readback(PATTERN_ID, PATTERN_NAME))

    assert result.verified is True
    assert created == [(PATTERN_ID, PATTERN_NAME)]
    assert len(opened) == 2


def test_create_uses_only_the_fixed_guide_pdf_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamDlpFilePatternSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (filepattern) #"
    entry_prompt = b"fpa (1001) #"
    entries_prompt = b"fpa (entries) #"
    pdf_prompt = b"fpa (pdf) #"
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
        if command == "config dlp filepattern":
            return table_prompt
        if command == "edit 1001":
            return entry_prompt
        if command == "config entries":
            return entries_prompt
        if command == 'edit "pdf"':
            return pdf_prompt
        if command == "next":
            next_count += 1
            return entries_prompt if next_count == 1 else table_prompt
        assert command == "end"
        end_count += 1
        return entry_prompt if end_count == 1 else root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._create_pattern(
            object(),
            root_prompt,
            PATTERN_ID,
            PATTERN_NAME,
            100.0,
        )
    )

    assert commands == [
        "config dlp filepattern",
        "edit 1001",
        'set name "mcp-v4-dlp-pattern-01"',
        "config entries",
        'edit "pdf"',
        "set filter-type type",
        "set file-type pdf",
        "next",
        "end",
        "next",
        "end",
    ]


class _Connection:
    async def __aenter__(self) -> "_Connection":
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        del exc_type, exc, traceback


def test_file_pattern_context_collects_only_fixed_locator_and_bounded_full_forms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamDlpFilePatternSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        return {
            "show | grep 1001": b"id-locator",
            "show | grep mcp-v4-dlp-pattern-01": b"name-locator",
            'show full-configuration | grep -A 80 "^ *edit 1001$"': b"full",
        }.get(
            command,
            b"",
        )

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config dlp filepattern":
            return b"fpa (filepattern) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._run_file_pattern_context(
            object(),
            b"fpa #",
            (
                "show | grep 1001",
                "show | grep mcp-v4-dlp-pattern-01",
                'show full-configuration | grep -A 80 "^ *edit 1001$"',
            ),
            100.0,
        )
    )

    assert output == b"id-locatorname-locatorfull"
    assert commands == [
        "config dlp filepattern",
        "show | grep 1001",
        "show | grep mcp-v4-dlp-pattern-01",
        'show full-configuration | grep -A 80 "^ *edit 1001$"',
        "end",
    ]
