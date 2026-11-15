from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.secret_gateway_ssh_transport as transport_module
from fortipam_mcp.secret_gateway_ssh_transport import (
    FortiPamSecretGatewaySshTransport,
    SecretGatewaySshTransportConfig,
    SecretGatewaySshTransportConfigurationError,
    SecretGatewaySshTransportError,
    _readback,
    load_secret_gateway_ssh_transport_config,
)


GATEWAY_NAME = "mcp-v4-secret-gateway-01"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> SecretGatewaySshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return SecretGatewaySshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-secret-gateway-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_SECRET_GATEWAY_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_SECRET_GATEWAY_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_SECRET_GATEWAY_SSH_USERNAME": "fortipam-secret-gateway-writer",
        "FPA_HOME_LAB_FPA1_V4_SECRET_GATEWAY_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_SECRET_GATEWAY_SSH_KNOWN_HOSTS_FILE": str(
            known_hosts
        ),
    }

    loaded = load_secret_gateway_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-secret-gateway-writer"
    password.chmod(0o640)
    with pytest.raises(
        SecretGatewaySshTransportConfigurationError,
        match="owner-only",
    ):
        load_secret_gateway_ssh_transport_config(environment)


def test_input_rejects_out_of_scope_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamSecretGatewaySshTransport(_config(tmp_path))

    with pytest.raises(SecretGatewaySshTransportError):
        transport.inspect("default")
    with pytest.raises(SecretGatewaySshTransportError):
        transport.create_and_readback('mcp-v4-secret-gateway-01"\nset status enable')


def test_readback_requires_all_fixed_disabled_forward_controls() -> None:
    output = (
        b'edit "mcp-v4-secret-gateway-01"\r\n'
        + b"set status disable\r\n"
        + b"set type forward\r\n"
        + b'set address "192.0.2.1"\r\n'
        + b"set port 443\r\n"
        + b'set url-map "tcp"\r\n'
        + b"set ssl-max-version tls-1.3\r\n"
        + b'set description "MCP V4 disabled forward gateway"\r\n'
    )

    assert _readback(output, GATEWAY_NAME).verified is True
    assert (
        _readback(
            output.replace(b"set status disable", b"set status enable"),
            GATEWAY_NAME,
        ).verified
        is False
    )


def test_create_uses_only_the_fixed_guide_secret_gateway_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamSecretGatewaySshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (gateway) #"
    gateway_prompt = b"fpa (mcp-v4-secret-gateway-01) #"

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
        if command == "config secret gateway":
            return table_prompt
        if command == 'edit "mcp-v4-secret-gateway-01"':
            return gateway_prompt
        if command == "next":
            return table_prompt
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._create_gateway(
            object(),
            root_prompt,
            GATEWAY_NAME,
            100.0,
        )
    )

    assert commands == [
        "config secret gateway",
        'edit "mcp-v4-secret-gateway-01"',
        "set status disable",
        "set type forward",
        'set address "192.0.2.1"',
        "set port 443",
        'set url-map "tcp"',
        "set ssl-max-version tls-1.3",
        'set description "MCP V4 disabled forward gateway"',
        "next",
        "end",
    ]


def test_gateway_reader_uses_both_requested_show_forms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamSecretGatewaySshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command in {
            "show | grep mcp-v4-secret-gateway-01",
            "show | grep mcp-v4-secret-gateway-01 -f",
        }
        return b"gateway"

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config secret gateway":
            return b"fpa (gateway) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._show_gateway(object(), b"fpa #", GATEWAY_NAME, 100.0)
    )

    assert output == b"gatewaygateway"
    assert commands == [
        "config secret gateway",
        "show | grep mcp-v4-secret-gateway-01",
        "show | grep mcp-v4-secret-gateway-01 -f",
        "end",
    ]
