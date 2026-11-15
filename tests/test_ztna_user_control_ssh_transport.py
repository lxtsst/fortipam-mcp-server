from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.ztna_user_control_ssh_transport as transport_module
from fortipam_mcp.ztna_user_control_ssh_transport import (
    FortiPamZtnaUserControlSshTransport,
    ZtnaUserControlSshTransportConfig,
    ZtnaUserControlSshTransportConfigurationError,
    ZtnaUserControlSshTransportError,
    _inspection,
    load_ztna_user_control_ssh_transport_config,
)


ACCESS_PROXY_NAME = "fortipam_access_proxy"
POLICY_ID = "1"
EMS_TAG_NAME = "managed_tag"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> ZtnaUserControlSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return ZtnaUserControlSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-ztna-user-control-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        access_proxy_name=ACCESS_PROXY_NAME,
        policy_id=POLICY_ID,
        ems_tag_name=EMS_TAG_NAME,
        timeout_seconds=15,
    )


def _access_proxy_output(
    *,
    client_cert: str = "enable",
    empty_cert: str = "block",
) -> bytes:
    return (
        b"config firewall access-proxy\r\n"
        + f'    edit "{ACCESS_PROXY_NAME}"\r\n'.encode("ascii")
        + f"        set client-cert {client_cert}\r\n".encode("ascii")
        + f"        set empty-cert-action {empty_cert}\r\n".encode("ascii")
        + b"    next\r\nend\r\n"
    )


def _policy_output(*, ztna_status: str = "disable", ems_tag: str = EMS_TAG_NAME) -> bytes:
    return (
        b"config firewall policy\r\n"
        + f"    edit {POLICY_ID}\r\n".encode("ascii")
        + b"        set type access-proxy\r\n"
        + f'        set access-proxy "{ACCESS_PROXY_NAME}"\r\n'.encode("ascii")
        + f'        set ztna-ems-tag "{ems_tag}"\r\n'.encode("ascii")
        + f"        set ztna-status {ztna_status}\r\n".encode("ascii")
        + b"    next\r\nend\r\n"
    )


def test_loader_requires_dedicated_policy_and_tag_references(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_ZTNA_USER_CONTROL_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_ZTNA_USER_CONTROL_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_ZTNA_USER_CONTROL_SSH_USERNAME": "fortipam-ztna-user-control-writer",
        "FPA_HOME_LAB_FPA1_V4_ZTNA_USER_CONTROL_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_ZTNA_USER_CONTROL_SSH_KNOWN_HOSTS_FILE": str(
            known_hosts
        ),
        "FPA_HOME_LAB_FPA1_V4_ZTNA_USER_CONTROL_ACCESS_PROXY_NAME": ACCESS_PROXY_NAME,
        "FPA_HOME_LAB_FPA1_V4_ZTNA_USER_CONTROL_POLICY_ID": POLICY_ID,
        "FPA_HOME_LAB_FPA1_V4_ZTNA_USER_CONTROL_EMS_TAG_NAME": EMS_TAG_NAME,
    }

    loaded = load_ztna_user_control_ssh_transport_config(environment)

    assert loaded.policy_id == POLICY_ID
    assert loaded.ems_tag_name == EMS_TAG_NAME
    invalid = dict(environment)
    invalid["FPA_HOME_LAB_FPA1_V4_ZTNA_USER_CONTROL_POLICY_ID"] = "1\nset ztna-status enable"
    with pytest.raises(ZtnaUserControlSshTransportConfigurationError):
        load_ztna_user_control_ssh_transport_config(invalid)


def test_inspection_requires_exact_disabled_access_level_baseline(tmp_path: Path) -> None:
    config = _config(tmp_path)
    access_proxy_output = (_access_proxy_output(), _access_proxy_output())
    policy_output = (_policy_output(), _policy_output())

    state = _inspection(access_proxy_output, policy_output, config)

    assert state.exact_disabled_access_level_baseline is True
    assert state.exact_enabled_access_level_baseline is False
    enabled = _inspection(
        access_proxy_output,
        (_policy_output(ztna_status="enable"), _policy_output(ztna_status="enable")),
        config,
    )
    assert enabled.exact_disabled_access_level_baseline is False
    assert enabled.exact_enabled_access_level_baseline is True
    assert (
        _inspection(
            (_access_proxy_output(empty_cert="accept"), _access_proxy_output(empty_cert="accept")),
            policy_output,
            config,
        ).exact_disabled_access_level_baseline
        is False
    )
    assert (
        _inspection(
            access_proxy_output,
            (_policy_output(ems_tag="different_tag"), _policy_output(ems_tag="different_tag")),
            config,
        ).exact_disabled_access_level_baseline
        is False
    )
    with pytest.raises(ZtnaUserControlSshTransportError):
        _inspection(
            access_proxy_output,
            (_policy_output(ztna_status="unknown"), _policy_output(ztna_status="unknown")),
            config,
        )


def test_inspection_accepts_short_grep_locators_and_parses_only_full_outputs(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    state = _inspection(
        (f'    edit "{ACCESS_PROXY_NAME}"\r\n'.encode("ascii"), _access_proxy_output()),
        (f"    edit {POLICY_ID}\r\n".encode("ascii"), _policy_output()),
        config,
    )

    assert state.exact_disabled_access_level_baseline is True
    with pytest.raises(ZtnaUserControlSshTransportError):
        _inspection(
            (b'    edit "fortipam_access_proxy_renamed"\r\n', _access_proxy_output()),
            (f"    edit {POLICY_ID}\r\n".encode("ascii"), _policy_output()),
            config,
        )


def test_enable_uses_only_the_fixed_policy_status_transition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamZtnaUserControlSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (policy) #"
    policy_prompt = b"fpa (1) #"

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command == "set ztna-status enable"
        return b""

    async def dynamic(
        process: object,
        command: str,
        known_root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, known_root_prompt, deadline
        commands.append(command)
        if command == "config firewall policy":
            return table_prompt
        if command == "edit 1":
            return policy_prompt
        if command == "next":
            return table_prompt
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(transport._enable_policy(object(), root_prompt, 100.0))

    assert commands == [
        "config firewall policy",
        "edit 1",
        "set ztna-status enable",
        "next",
        "end",
    ]


def test_disable_uses_only_the_fixed_policy_status_transition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamZtnaUserControlSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (policy) #"
    policy_prompt = b"fpa (1) #"

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command == "set ztna-status disable"
        return b""

    async def dynamic(
        process: object,
        command: str,
        known_root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, known_root_prompt, deadline
        commands.append(command)
        if command == "config firewall policy":
            return table_prompt
        if command == "edit 1":
            return policy_prompt
        if command == "next":
            return table_prompt
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(transport._disable_policy(object(), root_prompt, 100.0))

    assert commands == [
        "config firewall policy",
        "edit 1",
        "set ztna-status disable",
        "next",
        "end",
    ]


def test_reader_uses_bounded_full_projection_for_each_private_object(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamZtnaUserControlSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command in {
            "show full-configuration firewall access-proxy | grep -A 80 "
            '"^ *edit.*fortipam_access_proxy"',
            "show full-configuration firewall policy | grep -A 80 "
            '"^ *edit 1"',
        }
        return b"object"

    monkeypatch.setattr(transport_module, "_send_and_read", send)

    access_proxy, policy = asyncio.run(
        transport._read_current(object(), b"fpa #", 100.0)
    )

    assert access_proxy == (b"object", b"object")
    assert policy == (b"object", b"object")
    assert commands == [
        "show full-configuration firewall access-proxy | grep -A 80 "
        '"^ *edit.*fortipam_access_proxy"',
        "show full-configuration firewall policy | grep -A 80 "
        '"^ *edit 1"',
    ]
