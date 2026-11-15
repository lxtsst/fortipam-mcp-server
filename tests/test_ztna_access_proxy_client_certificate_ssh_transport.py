from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.ztna_access_proxy_client_certificate_ssh_transport as transport_module
from fortipam_mcp.ztna_access_proxy_client_certificate_ssh_transport import (
    FortiPamZtnaAccessProxySshTransport,
    ZTNA_MANAGED_ONLY,
    ZTNA_MIXED_ACCESS,
    ZtnaAccessProxyReadback,
    ZtnaAccessProxySshTransportConfig,
    ZtnaAccessProxySshTransportConfigurationError,
    ZtnaAccessProxySshTransportError,
    _inspection,
    load_ztna_access_proxy_ssh_transport_config,
)


ACCESS_PROXY_NAME = "fortipam_access_proxy"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> ZtnaAccessProxySshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return ZtnaAccessProxySshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-ztna-proxy-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        access_proxy_name=ACCESS_PROXY_NAME,
        timeout_seconds=15,
    )


def _output(
    *,
    client_cert: str = "disable",
    empty_cert: str = "block",
    name: str = ACCESS_PROXY_NAME,
) -> bytes:
    return (
        b"config firewall access-proxy\r\n"
        + f'    edit "{name}"\r\n'.encode("ascii")
        + f"        set client-cert {client_cert}\r\n".encode("ascii")
        + f"        set empty-cert-action {empty_cert}\r\n".encode("ascii")
        + b"    next\r\nend\r\n"
    )


def test_loader_requires_dedicated_private_access_proxy_settings(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_ZTNA_ACCESS_PROXY_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_ZTNA_ACCESS_PROXY_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_ZTNA_ACCESS_PROXY_SSH_USERNAME": "fortipam-ztna-proxy-writer",
        "FPA_HOME_LAB_FPA1_V4_ZTNA_ACCESS_PROXY_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_ZTNA_ACCESS_PROXY_SSH_KNOWN_HOSTS_FILE": str(
            known_hosts
        ),
        "FPA_HOME_LAB_FPA1_V4_ZTNA_ACCESS_PROXY_ACCESS_PROXY_NAME": ACCESS_PROXY_NAME,
    }

    loaded = load_ztna_access_proxy_ssh_transport_config(environment)

    assert loaded.access_proxy_name == ACCESS_PROXY_NAME
    password.chmod(0o640)
    with pytest.raises(
        ZtnaAccessProxySshTransportConfigurationError,
        match="owner-only",
    ):
        load_ztna_access_proxy_ssh_transport_config(environment)


def test_effective_projection_requires_one_exact_access_proxy_and_both_fields() -> None:
    state = _inspection(_output(), ACCESS_PROXY_NAME)

    assert state.client_certificate_mode == "disable"
    assert state.empty_certificate_action == "block"
    assert state.exact_disabled_block_baseline is True
    assert _inspection(_output(client_cert="enable", empty_cert="accept"), ACCESS_PROXY_NAME).exact_disabled_block_baseline is False
    with pytest.raises(ZtnaAccessProxySshTransportError):
        _inspection(_output() + _output(), ACCESS_PROXY_NAME)
    with pytest.raises(ZtnaAccessProxySshTransportError):
        _inspection(_output(empty_cert="unknown"), ACCESS_PROXY_NAME)


def test_input_rejects_out_of_scope_mode_before_connection(tmp_path: Path) -> None:
    transport = FortiPamZtnaAccessProxySshTransport(_config(tmp_path))

    with pytest.raises(ZtnaAccessProxySshTransportError):
        transport.configure_and_readback("enable-global-ztna")


@pytest.mark.parametrize(
    ("mode", "expected_action"),
    ((ZTNA_MANAGED_ONLY, "block"), (ZTNA_MIXED_ACCESS, "accept")),
)
def test_configuration_uses_only_fixed_client_certificate_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mode: str,
    expected_action: str,
) -> None:
    transport = FortiPamZtnaAccessProxySshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (access-proxy) #"
    entry_prompt = b"fpa (fortipam_access_proxy) #"
    expected_dynamic = [
        ("config firewall access-proxy", table_prompt),
        ('edit "fortipam_access_proxy"', entry_prompt),
        ("next", table_prompt),
        ("end", root_prompt),
    ]

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
        expected_command, response = expected_dynamic.pop(0)
        assert command == expected_command
        return response

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(transport._configure_access_proxy(object(), root_prompt, mode, 100.0))

    assert expected_dynamic == []
    assert commands == [
        "config firewall access-proxy",
        'edit "fortipam_access_proxy"',
        "set client-cert enable",
        f"set empty-cert-action {expected_action}",
        "next",
        "end",
    ]


def test_rollback_uses_only_fixed_disabled_block_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamZtnaAccessProxySshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (access-proxy) #"
    entry_prompt = b"fpa (fortipam_access_proxy) #"
    expected_dynamic = [
        ("config firewall access-proxy", table_prompt),
        ('edit "fortipam_access_proxy"', entry_prompt),
        ("next", table_prompt),
        ("end", root_prompt),
    ]

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
        expected_command, response = expected_dynamic.pop(0)
        assert command == expected_command
        return response

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(transport._restore_access_proxy(object(), root_prompt, 100.0))

    assert expected_dynamic == []
    assert commands == [
        "config firewall access-proxy",
        'edit "fortipam_access_proxy"',
        "set client-cert disable",
        "set empty-cert-action block",
        "next",
        "end",
    ]


def test_readback_categorizes_exact_rollback_state() -> None:
    assert ZtnaAccessProxyReadback("disable", "block").verified_disabled_block is True
    assert ZtnaAccessProxyReadback("enable", "block").verified_disabled_block is False


def test_current_state_read_uses_bounded_full_access_proxy_projection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamZtnaAccessProxySshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command == (
            "show full-configuration firewall access-proxy | grep -A 80 "
            '"^ *edit.*fortipam_access_proxy"'
        )
        return _output()

    monkeypatch.setattr(transport_module, "_send_and_read", send)

    output = asyncio.run(transport._get_access_proxy(object(), b"fpa #", 100.0))

    assert output == _output()
    assert commands == [
        "show full-configuration firewall access-proxy | grep -A 80 "
        '"^ *edit.*fortipam_access_proxy"'
    ]
