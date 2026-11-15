from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.launcher_ssh_transport as transport_module
from fortipam_mcp.launcher_ssh_transport import (
    FortiPamLauncherSshTransport,
    LauncherSshTransportConfig,
    LauncherSshTransportConfigurationError,
    LauncherSshTransportError,
    _matcher_baseline_readback,
    _matcher_readback,
    load_launcher_matcher_ssh_transport_config,
)


LAUNCHER_NAME = "mcp-v4-launcher-01"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> LauncherSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return LauncherSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-launcher-matcher",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def _output(*, configured: bool) -> bytes:
    lines = [
        b'edit "mcp-v4-launcher-01"',
        b"set type rdp",
        b'set exe "mstsc.exe"',
        b'set parameter "/V:$HOST:$PORT /noConsentPrompt"',
        b'set cmd "cmdkey /generic:$HOST /user:$USER /pass:$PASSWORD"',
        b'set cmd "cmdkey /del:$HOST"',
        b"set launch-timeout 15",
    ]
    if configured:
        lines.extend(
            (
                b"set multiprocess enable",
                b"set fullscreen-record enable",
                b"set proc-matcher-type process-cmdline",
                b'set proc-matcher-pattern "^mstsc\\\\.exe.*"',
            )
        )
    else:
        lines.append(b"set proc-matcher-type default")
    return b"\r\n".join(lines) + b"\r\n"


def test_matcher_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_LAUNCHER_MATCHER_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_LAUNCHER_MATCHER_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_LAUNCHER_MATCHER_SSH_USERNAME": "fortipam-launcher-matcher",
        "FPA_HOME_LAB_FPA1_V4_LAUNCHER_MATCHER_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_LAUNCHER_MATCHER_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_launcher_matcher_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-launcher-matcher"
    password.chmod(0o640)
    with pytest.raises(LauncherSshTransportConfigurationError, match="owner-only"):
        load_launcher_matcher_ssh_transport_config(environment)


def test_matcher_input_rejects_out_of_scope_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamLauncherSshTransport(_config(tmp_path))

    with pytest.raises(LauncherSshTransportError):
        transport.matcher_baseline_readback("Example Windows RDP")
    with pytest.raises(LauncherSshTransportError):
        transport.configure_command_line_matcher_and_readback(
            'mcp-v4-launcher-unsafe"\nset type ssh'
        )


def test_matcher_readbacks_require_the_exact_local_baseline_and_fixed_matcher() -> None:
    baseline = _matcher_baseline_readback(_output(configured=False), LAUNCHER_NAME)
    configured = _matcher_readback(_output(configured=True), LAUNCHER_NAME)

    assert baseline.verified is True
    assert configured.verified is True
    assert _matcher_baseline_readback(_output(configured=True), LAUNCHER_NAME).verified is False
    assert _matcher_readback(_output(configured=False), LAUNCHER_NAME).verified is False


def test_matcher_writes_only_the_fixed_guide_prerequisites_and_pattern(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamLauncherSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (launcher) #"
    launcher_prompt = b"fpa (mcp-v4-launcher-01) #"
    os_app_prompt = b"fpa (os_app) #"
    application_prompt = b"fpa (1) #"
    end_prompts = [launcher_prompt, root_prompt]

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command in {
            "set multiprocess enable",
            "set fullscreen-record enable",
            "set proc-matcher-type process-cmdline",
            'set proc-matcher-pattern "^mstsc\\.exe.*"',
        }
        return b""

    async def dynamic(
        process: object,
        command: str,
        known_root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, known_root_prompt, deadline
        commands.append(command)
        if command == "config secret launcher":
            return table_prompt
        if command == 'edit "mcp-v4-launcher-01"':
            return launcher_prompt
        if command == "config os_app":
            return os_app_prompt
        if command == "edit 1":
            return application_prompt
        if command == "next":
            if len(commands) == 9:
                return os_app_prompt
            return table_prompt
        if command == "end":
            return end_prompts.pop(0)
        raise AssertionError(command)

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._configure_command_line_matcher(
            object(),
            root_prompt,
            LAUNCHER_NAME,
            100.0,
        )
    )

    assert commands == [
        "config secret launcher",
        'edit "mcp-v4-launcher-01"',
        "config os_app",
        "edit 1",
        "set multiprocess enable",
        "set fullscreen-record enable",
        "set proc-matcher-type process-cmdline",
        'set proc-matcher-pattern "^mstsc\\.exe.*"',
        "next",
        "end",
        "next",
        "end",
    ]


def test_matcher_readback_rejects_the_concept_label_as_a_cli_enum() -> None:
    invalid = _output(configured=True).replace(
        b"set proc-matcher-type process-cmdline",
        b"set proc-matcher-type command-line",
    )

    assert _matcher_readback(invalid, LAUNCHER_NAME).verified is False


def test_matcher_readback_rejects_the_guide_example_field_typo() -> None:
    invalid = _output(configured=True).replace(
        b"set multiprocess enable",
        b"set multipleprocess enable",
    )

    assert _matcher_readback(invalid, LAUNCHER_NAME).verified is False


def test_matcher_readback_rejects_the_unsafely_unescaped_pattern() -> None:
    invalid = _output(configured=True).replace(
        b'set proc-matcher-pattern "^mstsc\\\\.exe.*"',
        b'set proc-matcher-pattern "^mstsc.exe.*"',
    )

    assert _matcher_readback(invalid, LAUNCHER_NAME).verified is False
