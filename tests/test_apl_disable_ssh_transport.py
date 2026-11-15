from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.apl_ssh_transport as transport_module
from fortipam_mcp.apl_ssh_transport import (
    AplSshTransportConfig,
    AplSshTransportConfigurationError,
    AplSshTransportError,
    FortiPamAplSshTransport,
    _disable_inspection,
    _readback,
    load_apl_disable_ssh_transport_config,
)


RULE = "mcp-v4-apl-01"
USER_GROUP = "mcp-v4-user-group-01"
ROLE = "mcp-v4-role-01"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> AplSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return AplSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-apl-disable-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def _rule_output(*, status: str = "enable", group: str = USER_GROUP, role: str = ROLE) -> bytes:
    return (
        f'edit "{RULE}"\r\n'.encode("ascii")
        + f"set status {status}\r\n".encode("ascii")
        + f'set remote-group "{group}"\r\n'.encode("ascii")
        + f'set accprofile "{role}"\r\n'.encode("ascii")
        + b"next\r\n"
    )


def _object_output(name: str) -> bytes:
    return f'edit "{name}"\r\nnext\r\n'.encode("ascii")


def test_loader_requires_separate_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_APL_DISABLE_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_APL_DISABLE_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_APL_DISABLE_SSH_USERNAME": "fortipam-apl-disable-writer",
        "FPA_HOME_LAB_FPA1_V4_APL_DISABLE_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_APL_DISABLE_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_apl_disable_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    password.chmod(0o640)
    with pytest.raises(AplSshTransportConfigurationError, match="owner-only"):
        load_apl_disable_ssh_transport_config(environment)


def test_disable_input_rejects_nonv4_or_injected_names_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamAplSshTransport(_config(tmp_path))

    with pytest.raises(AplSshTransportError):
        transport.inspect_disable("rule", USER_GROUP, ROLE)
    with pytest.raises(AplSshTransportError):
        transport.inspect_disable(RULE, USER_GROUP, "pam_standard_user")
    with pytest.raises(AplSshTransportError):
        transport.inspect_disable(RULE, 'unsafe"\nset status disable', ROLE)


def test_disable_inspection_requires_exact_enabled_rule_and_dependencies() -> None:
    baseline = _disable_inspection(
        _rule_output(),
        _object_output(USER_GROUP),
        _object_output(ROLE),
        RULE,
        USER_GROUP,
        ROLE,
    )
    assert baseline.disable_baseline_verified is True
    assert (
        _disable_inspection(
            _rule_output(status="disable"),
            _object_output(USER_GROUP),
            _object_output(ROLE),
            RULE,
            USER_GROUP,
            ROLE,
        ).disable_baseline_verified
        is False
    )
    assert (
        _disable_inspection(
            _rule_output(group="mcp-v4-user-group-other"),
            _object_output(USER_GROUP),
            _object_output(ROLE),
            RULE,
            USER_GROUP,
            ROLE,
        ).disable_baseline_verified
        is False
    )
    assert _readback(_rule_output(status="disable"), RULE, USER_GROUP, ROLE).verified is True


def test_disable_uses_only_fixed_status_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamAplSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (auto-provision-rule) #"
    rule_prompt = b"fpa (mcp-v4-apl-01) #"

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
        if command == "config user auto-provision-rule":
            return table_prompt
        if command == 'edit "mcp-v4-apl-01"':
            return rule_prompt
        if command == "next":
            return table_prompt
        if command == "end":
            return root_prompt
        raise AssertionError(command)

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(transport._disable_rule(object(), root_prompt, RULE, 100.0))

    assert commands == [
        "config user auto-provision-rule",
        'edit "mcp-v4-apl-01"',
        "set status disable",
        "next",
        "end",
    ]
