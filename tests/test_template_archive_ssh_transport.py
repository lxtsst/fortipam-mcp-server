from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.template_ssh_transport as transport_module
from fortipam_mcp.template_ssh_transport import (
    FortiPamTemplateSshTransport,
    TemplateSshTransportConfig,
    TemplateSshTransportConfigurationError,
    _archive_absence_readback,
    _archive_preflight_readback,
    load_template_archive_ssh_transport_config,
)


NAME = "mcp-v4-template-archive-01"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> TemplateSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return TemplateSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-template-archive-reader",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def _baseline_output() -> bytes:
    return (
        f'edit "{NAME}"\r\n'.encode("ascii")
        + b"set access everyone\r\n"
        + b'edit "Username"\r\n'
        + b"set type username\r\n"
        + b"set mandatory enable\r\n"
        + b'edit "Password"\r\n'
        + b"set type password\r\n"
        + b"set mandatory enable\r\n"
        + b'set launcher-name "Web VNC"\r\n'
        + b"set port 5900\r\n"
    )


def test_archive_loader_requires_a_separate_owner_only_ssh_scope(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_ARCHIVE_SSH_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_ARCHIVE_SSH_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_ARCHIVE_SSH_SSH_USERNAME": (
            "fortipam-template-archive-reader"
        ),
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_ARCHIVE_SSH_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_TEMPLATE_ARCHIVE_SSH_SSH_KNOWN_HOSTS_FILE": str(
            known_hosts
        ),
    }

    loaded = load_template_archive_ssh_transport_config(environment)

    assert loaded.username == "fortipam-template-archive-reader"
    environment["FPA_HOME_LAB_FPA1_V4_TEMPLATE_ARCHIVE_SSH_ENABLED"] = "false"
    with pytest.raises(TemplateSshTransportConfigurationError, match="ENABLED"):
        load_template_archive_ssh_transport_config(environment)


def test_archive_readbacks_require_exact_baseline_and_no_direct_references() -> None:
    preflight = _archive_preflight_readback(_baseline_output(), b"", b"", NAME)
    absence = _archive_absence_readback(b"", b"", b"", NAME)

    assert preflight.verified is True
    assert absence.verified is True
    assert (
        _archive_preflight_readback(
            _baseline_output(),
            f'set template "{NAME}"\n'.encode("ascii"),
            b"",
            NAME,
        ).verified
        is False
    )
    assert (
        _archive_absence_readback(
            b"",
            b"",
            f'set template "{NAME}"\n'.encode("ascii"),
            NAME,
        ).verified
        is False
    )


def test_archive_reference_reader_uses_only_fixed_secret_contexts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamTemplateSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    database_prompt = b"fpa (database) #"
    target_prompt = b"fpa (target) #"

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command in {
            f"show | grep {NAME}",
            f"show | grep {NAME} -f",
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
        if command == "config secret database":
            return database_prompt
        if command == "config secret target":
            return target_prompt
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    database_output = asyncio.run(
        transport._show_template_references(
            object(), root_prompt, "database", NAME, 100.0
        )
    )
    target_output = asyncio.run(
        transport._show_template_references(
            object(), root_prompt, "target", NAME, 100.0
        )
    )

    assert database_output == b""
    assert target_output == b""
    assert commands == [
        "config secret database",
        f"show | grep {NAME}",
        f"show | grep {NAME} -f",
        "end",
        "config secret target",
        f"show | grep {NAME}",
        f"show | grep {NAME} -f",
        "end",
    ]
