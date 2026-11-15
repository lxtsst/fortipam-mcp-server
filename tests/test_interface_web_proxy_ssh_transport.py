from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.interface_web_proxy_ssh_transport as transport_module
from fortipam_mcp.interface_web_proxy_ssh_transport import (
    FortiPamInterfaceWebProxySshTransport,
    InterfaceWebProxyReadback,
    InterfaceWebProxySshTransportConfig,
    InterfaceWebProxySshTransportConfigurationError,
    InterfaceWebProxySshTransportError,
    _filtered_inspection,
    _inspection,
    load_interface_web_proxy_ssh_transport_config,
)


INTERFACE_NAME = "port1"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> InterfaceWebProxySshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return InterfaceWebProxySshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-interface-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        interface_name=INTERFACE_NAME,
        timeout_seconds=15,
    )


def _output(
    *entries: tuple[str, str | None],
) -> bytes:
    lines = [b"config system interface\r\n"]
    for name, status in entries:
        lines.append(f'    edit "{name}"\r\n'.encode("ascii"))
        if status is not None:
            lines.append(f"        set explicit-web-proxy {status}\r\n".encode("ascii"))
        lines.append(b"    next\r\n")
    lines.append(b"end\r\n")
    return b"".join(lines)


def test_loader_requires_dedicated_private_interface_settings(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_INTERFACE_WEB_PROXY_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_INTERFACE_WEB_PROXY_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_INTERFACE_WEB_PROXY_SSH_USERNAME": "fortipam-interface-writer",
        "FPA_HOME_LAB_FPA1_V4_INTERFACE_WEB_PROXY_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_INTERFACE_WEB_PROXY_SSH_KNOWN_HOSTS_FILE": str(
            known_hosts
        ),
        "FPA_HOME_LAB_FPA1_V4_INTERFACE_WEB_PROXY_INTERFACE_NAME": INTERFACE_NAME,
    }

    loaded = load_interface_web_proxy_ssh_transport_config(environment)

    assert loaded.interface_name == INTERFACE_NAME
    password.chmod(0o640)
    with pytest.raises(
        InterfaceWebProxySshTransportConfigurationError,
        match="owner-only",
    ):
        load_interface_web_proxy_ssh_transport_config(environment)


def test_effective_projection_requires_one_existing_interface_and_one_safe_baseline() -> None:
    state = _inspection(_output((INTERFACE_NAME, None), ("port2", None)), INTERFACE_NAME)

    assert state.selected_interface_status == "disable"
    assert state.enabled_interface_count == 0
    assert state.exact_disabled_baseline is True
    enabled = _inspection(_output((INTERFACE_NAME, "enable")), INTERFACE_NAME)
    assert enabled.exact_disabled_baseline is False
    assert enabled.exact_enabled_baseline is True
    assert _inspection(
        _output((INTERFACE_NAME, None), ("port2", "enable")), INTERFACE_NAME
    ).exact_disabled_baseline is False
    with pytest.raises(InterfaceWebProxySshTransportError):
        _inspection(_output(("port2", None)), INTERFACE_NAME)
    with pytest.raises(InterfaceWebProxySshTransportError):
        _inspection(_output((INTERFACE_NAME, "enable"), (INTERFACE_NAME, "disable")), INTERFACE_NAME)


def test_filtered_projection_combines_exact_selector_and_bounded_status_count() -> None:
    state = _filtered_inspection(
        _output((INTERFACE_NAME, "enable")),
        b"set explicit-web-proxy enable\nset explicit-web-proxy disable\n",
        INTERFACE_NAME,
    )

    assert state.selected_interface_status == "enable"
    assert state.enabled_interface_count == 1
    assert state.exact_disabled_baseline is False
    assert state.exact_enabled_baseline is True
    with pytest.raises(InterfaceWebProxySshTransportError):
        _filtered_inspection(_output((INTERFACE_NAME, None)), b"", INTERFACE_NAME)


def test_filtered_projection_accepts_exact_fortipam_grep_match_suffix() -> None:
    selected = _output((INTERFACE_NAME, "enable")).replace(
        b'    edit "port1"\r\n',
        b'    edit "port1" <---\r\n',
    )

    state = _filtered_inspection(
        selected,
        b"set explicit-web-proxy enable\n",
        INTERFACE_NAME,
    )

    assert state.selected_interface_status == "enable"
    assert state.enabled_interface_count == 1


def test_enable_command_has_one_fixed_interface_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamInterfaceWebProxySshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (interface) #"
    entry_prompt = b"fpa (port1) #"
    expected_dynamic = [
        ("config system interface", table_prompt),
        ('edit "port1"', entry_prompt),
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

    asyncio.run(transport._enable_interface_web_proxy(object(), root_prompt, 100.0))

    assert expected_dynamic == []
    assert commands == [
        "config system interface",
        'edit "port1"',
        "set explicit-web-proxy enable",
        "next",
        "end",
    ]


def test_disable_command_has_one_fixed_interface_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamInterfaceWebProxySshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (interface) #"
    entry_prompt = b"fpa (port1) #"
    expected_dynamic = [
        ("config system interface", table_prompt),
        ('edit "port1"', entry_prompt),
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

    asyncio.run(transport._disable_interface_web_proxy(object(), root_prompt, 100.0))

    assert expected_dynamic == []
    assert commands == [
        "config system interface",
        'edit "port1"',
        "set explicit-web-proxy disable",
        "next",
        "end",
    ]


def test_readback_classifies_fixed_enable_and_disable_postconditions() -> None:
    assert InterfaceWebProxyReadback("enable", 1).verified is True
    assert InterfaceWebProxyReadback("enable", 1).verified_disabled is False
    assert InterfaceWebProxyReadback("disable", 0).verified_disabled is True
    assert InterfaceWebProxyReadback("disable", 1).verified_disabled is False


def test_current_state_read_uses_only_fixed_interface_show_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamInterfaceWebProxySshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (interface) #"
    expected_dynamic = [
        ("config system interface", table_prompt),
        ("end", root_prompt),
    ]
    selected_output = _output((INTERFACE_NAME, "enable"))
    status_output = b"set explicit-web-proxy enable\r\n"

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        if command == "show | grep port1 -f":
            return selected_output
        assert command == "show full-configuration | grep explicit-web-proxy"
        return status_output

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

    assert asyncio.run(
        transport._show_interface_state(object(), root_prompt, 100.0)
    ) == (selected_output, status_output)
    assert expected_dynamic == []
    assert commands == [
        "config system interface",
        "show | grep port1 -f",
        "show full-configuration | grep explicit-web-proxy",
        "end",
    ]


@pytest.mark.parametrize("direction", ["enable", "disable"])
@pytest.mark.parametrize("failure", ["lost_ack", "fsync"])
def test_uncertain_dispatch_remains_consumed_after_transport_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, direction: str, failure: str,
) -> None:
    from dataclasses import replace
    import json

    directory = tmp_path / "claims"
    directory.mkdir(mode=0o700)
    config = replace(_config(tmp_path), claim_directory=directory)
    connected = []
    writes = []

    class Connection:
        async def __aenter__(self):
            connected.append(True)
            return self

        async def __aexit__(self, *args):
            return None

    async def open_cli(self, connection):
        return object(), b"fpa #", 100.0

    async def show(self, process, prompt, deadline):
        state = "disable" if direction == "enable" else "enable"
        return _output((INTERFACE_NAME, state)), f"set explicit-web-proxy {state}\n".encode()

    async def write(self, process, prompt, deadline):
        claim = directory / f"interface-web-proxy-{direction}.claim.json"
        assert json.loads(claim.read_text())["state"] == "reserved_nonretry"
        assert claim.stat().st_mode & 0o777 == 0o600
        writes.append(direction)
        raise TimeoutError("acknowledgement lost")

    async def close(process):
        return None

    cls = FortiPamInterfaceWebProxySshTransport
    monkeypatch.setattr(cls, "_connection", lambda self: Connection())
    monkeypatch.setattr(cls, "_open_cli", open_cli)
    monkeypatch.setattr(cls, "_show_interface_state", show)
    monkeypatch.setattr(cls, f"_{direction}_interface_web_proxy", write)
    monkeypatch.setattr(transport_module, "_close_cli", close)
    if failure == "fsync":
        def failed_sync(fd):
            raise OSError("durability unavailable")
        monkeypatch.setattr(transport_module.os, "fsync", failed_sync)
    with pytest.raises(InterfaceWebProxySshTransportError):
        getattr(cls(config), f"{direction}_and_readback")()
    with pytest.raises(InterfaceWebProxySshTransportError):
        getattr(cls(config), f"{direction}_and_readback")()
    assert writes == ([direction] if failure == "lost_ack" else [])
    assert len(connected) == 1
    # Recovery has an independent claim and is not suppressed by the forward claim.
    inverse = "disable" if direction == "enable" else "enable"
    assert cls(config)._require_unconsumed(inverse).parent == directory


@pytest.mark.parametrize("state", ["missing", "public", "symlink", "consumed"])
def test_unsafe_claim_state_rejects_before_ssh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str,
) -> None:
    from dataclasses import replace

    config = _config(tmp_path)
    if state != "missing":
        directory = tmp_path / "claims"
        directory.mkdir(mode=0o700)
        if state == "public":
            directory.chmod(0o755)
        if state == "consumed":
            (directory / "interface-web-proxy-enable.claim.json").write_text("incomplete")
        if state == "symlink":
            link = tmp_path / "linked"
            link.symlink_to(directory, target_is_directory=True)
            directory = link
        config = replace(config, claim_directory=directory)

    def unexpected_connection(self):
        pytest.fail("Unsafe claim state must not reach SSH")

    monkeypatch.setattr(FortiPamInterfaceWebProxySshTransport, "_connection", unexpected_connection)
    with pytest.raises(InterfaceWebProxySshTransportError):
        FortiPamInterfaceWebProxySshTransport(config).enable_and_readback()
