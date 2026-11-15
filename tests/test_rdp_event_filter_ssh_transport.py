from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.rdp_event_filter_ssh_transport as transport_module
from fortipam_mcp.rdp_event_filter_ssh_transport import (
    FortiPamRdpEventFilterSshTransport,
    RdpEventFilterSshTransportConfig,
    RdpEventFilterSshTransportConfigurationError,
    RdpEventFilterSshTransportError,
    _readback,
    load_rdp_event_filter_ssh_transport_config,
)


PROFILE_NAME = "mcp-v4-rdp-event-filter-01"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> RdpEventFilterSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return RdpEventFilterSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-event-filter-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_RDP_EVENT_FILTER_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_RDP_EVENT_FILTER_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_RDP_EVENT_FILTER_SSH_USERNAME": "fortipam-event-filter-writer",
        "FPA_HOME_LAB_FPA1_V4_RDP_EVENT_FILTER_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_RDP_EVENT_FILTER_SSH_KNOWN_HOSTS_FILE": str(
            known_hosts
        ),
    }

    loaded = load_rdp_event_filter_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-event-filter-writer"
    password.chmod(0o640)
    with pytest.raises(
        RdpEventFilterSshTransportConfigurationError,
        match="owner-only",
    ):
        load_rdp_event_filter_ssh_transport_config(environment)


def test_input_rejects_out_of_scope_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamRdpEventFilterSshTransport(_config(tmp_path))

    with pytest.raises(RdpEventFilterSshTransportError):
        transport.inspect("event-filter")
    with pytest.raises(RdpEventFilterSshTransportError):
        transport.create_and_readback('mcp-v4-rdp-event-filter-unsafe"\nset x y')


def test_readback_requires_all_three_fixed_event_categories() -> None:
    output = (
        b'edit "mcp-v4-rdp-event-filter-01"\r\n'
        + b"set process-log enable\r\n"
        + b"set filesystem-log enable\r\n"
        + b"set user-management enable\r\n"
    )

    assert _readback(output, PROFILE_NAME).verified is True
    assert _readback(
        output.replace(
            b"set user-management enable", b"set   user-management   monitor"
        ),
        PROFILE_NAME,
    ).verified is True
    assert _readback(
        output.replace(b"set user-management enable", b"set user-management-log enable"),
        PROFILE_NAME,
    ).verified is True
    assert (
        _readback(
            output.replace(b"set filesystem-log enable", b"set filesystem-log disable"),
            PROFILE_NAME,
        ).verified
        is False
    )


def test_create_uses_only_the_fixed_guide_event_filter_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamRdpEventFilterSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (event-filter-profile) #"
    profile_prompt = b"fpa (mcp-v4-rdp-event-filter-01) #"

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
        if command == "config secret event-filter-profile":
            return table_prompt
        if command == 'edit "mcp-v4-rdp-event-filter-01"':
            return profile_prompt
        if command == "next":
            return table_prompt
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._create_profile(
            object(),
            root_prompt,
            PROFILE_NAME,
            100.0,
        )
    )

    assert commands == [
        "config secret event-filter-profile",
        'edit "mcp-v4-rdp-event-filter-01"',
        "set process-log enable",
        "set filesystem-log enable",
        "set user-management enable",
        "next",
        "end",
    ]


def test_profile_reader_accepts_only_compiled_locator_and_bounded_full_show_forms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamRdpEventFilterSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        return {
            "show | grep mcp-v4-rdp-event-filter-01": b"locator",
            'show full-configuration | grep -A 256 "^ *edit.*mcp-v4-rdp-event-filter-01"': b"full",
        }[command]

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config secret event-filter-profile":
            return b"fpa (event-filter-profile) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._show_profile(object(), b"fpa #", PROFILE_NAME, 100.0)
    )

    assert output == b"locatorfull"
    assert commands == [
        "config secret event-filter-profile",
        "show | grep mcp-v4-rdp-event-filter-01",
        'show full-configuration | grep -A 256 "^ *edit.*mcp-v4-rdp-event-filter-01"',
        "end",
    ]
