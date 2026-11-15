from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.address_group_ssh_transport as transport_module
from fortipam_mcp.address_group_ssh_transport import (
    AddressGroupSshTransportConfig,
    AddressGroupSshTransportConfigurationError,
    AddressGroupSshTransportError,
    FortiPamAddressGroupSshTransport,
    _readback,
    _reference_count,
    load_address_group_ssh_transport_config,
)


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> AddressGroupSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return AddressGroupSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-address-group-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_explicit_owner_only_ssh_configuration(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_ADDRESS_GROUP_CLI_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_ADDRESS_GROUP_CLI_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_ADDRESS_GROUP_CLI_SSH_USERNAME": "fortipam-address-group-writer",
        "FPA_HOME_LAB_FPA1_V4_ADDRESS_GROUP_CLI_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_ADDRESS_GROUP_CLI_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_address_group_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    password.chmod(0o640)
    with pytest.raises(AddressGroupSshTransportConfigurationError, match="owner-only"):
        load_address_group_ssh_transport_config(environment)


def test_input_rejects_cli_injection_before_connection(tmp_path: Path) -> None:
    transport = FortiPamAddressGroupSshTransport(_config(tmp_path))

    with pytest.raises(AddressGroupSshTransportError):
        transport.inspect('unsafe"\nset member "other')
    with pytest.raises(AddressGroupSshTransportError):
        transport.create_and_readback("safe-group", "unsafe member")
    with pytest.raises(AddressGroupSshTransportError):
        transport.reference_readback("safe-group", "unsafe member")
    with pytest.raises(AddressGroupSshTransportError):
        transport.inspect_address('unsafe"\nend')
    with pytest.raises(AddressGroupSshTransportError):
        transport.address_reference_count("unsafe member")


def test_readback_requires_exactly_one_compiled_member() -> None:
    output = b'edit "mcp-address-group-01"\r\n    set member "mcp-address-01"\r\n'

    assert _readback(output, "mcp-address-group-01", "mcp-address-01").verified is True
    assert _readback(
        output.replace(
            b'set member "mcp-address-01"',
            b'set member "mcp-address-01" "other-address"',
        ),
        "mcp-address-group-01",
        "mcp-address-01",
    ).verified is False


def test_reference_parser_requires_exact_echo_prompt_and_reference_rows() -> None:
    command = (
        "diagnose sys cmdb refcnt show firewall.addrgrp.name "
        "mcp-v4-address-group-b65"
    )
    prompt = b"fpa #"

    assert _reference_count(command.encode() + b"\r\n" + prompt, command, prompt) == 0
    assert _reference_count(
        command.encode()
        + b"\r\nentry used by table firewall.policy:name redacted\r\n"
        + prompt,
        command,
        prompt,
    ) == 1
    for output in (
        b"wrapped echo\r\n" + prompt,
        command.encode() + b"\r\nunexpected output\r\n" + prompt,
        command.encode() + b"\r\nother #",
    ):
        with pytest.raises(AddressGroupSshTransportError):
            _reference_count(output, command, prompt)


def test_addrgrp_context_uses_fixed_show_grep_forms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamAddressGroupSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        return b"output"

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    result = asyncio.run(
        transport._run_addrgrp_context(
            object(),
            b"fpa #",
            ("show | grep mcp-address-group-01", "show | grep mcp-address-group-01 -f"),
            100.0,
        )
    )

    assert result == b"outputoutput"
    assert commands == [
        "config firewall addrgrp",
        "show | grep mcp-address-group-01",
        "show | grep mcp-address-group-01 -f",
        "end",
    ]


def test_address_context_uses_fixed_show_grep_forms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamAddressGroupSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        return b"output"

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    result = asyncio.run(
        transport._run_address_context(
            object(),
            b"fpa #",
            ("show | grep mcp-address-01", "show | grep mcp-address-01 -f"),
            100.0,
        )
    )

    assert result == b"outputoutput"
    assert commands == [
        "config firewall address",
        "show | grep mcp-address-01",
        "show | grep mcp-address-01 -f",
        "end",
    ]


def test_create_uses_only_the_compiled_addrgrp_sequence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamAddressGroupSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        return b""

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command.startswith("edit "):
            return b"fpa (mcp-address-group-01) #"
        if command == "next":
            return b"fpa (addrgrp) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._create_group(
            object(),
            b"fpa #",
            "mcp-address-group-01",
            "mcp-address-01",
            100.0,
        )
    )

    assert commands == [
        "config firewall addrgrp",
        'edit "mcp-address-group-01"',
        'set member "mcp-address-01"',
        "next",
        "end",
    ]
