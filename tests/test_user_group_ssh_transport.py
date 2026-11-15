from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import fortipam_mcp.user_group_ssh_transport as transport_module
from fortipam_mcp.user_group_ssh_transport import (
    FortiPamUserGroupSshTransport,
    UserGroupSshTransportConfig,
    UserGroupSshTransportConfigurationError,
    UserGroupSshTransportError,
    _readback,
    load_user_group_ssh_transport_config,
)


USER_GROUP = "mcp-v4-user-group-01"
LDAP_SERVER = "lab-ldap"
LDAP_GROUP_DN = "cn=PAM_Group,cn=users,dc=fortipam,dc=ca"


def _files(tmp_path: Path) -> tuple[Path, Path]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fpa.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("test-password\n")
    password.chmod(0o600)
    return known_hosts, password


def _config(tmp_path: Path) -> UserGroupSshTransportConfig:
    known_hosts, password = _files(tmp_path)
    return UserGroupSshTransportConfig(
        host="fpa.example",
        port=22,
        username="fortipam-user-group-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def test_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_USER_GROUP_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_USER_GROUP_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_USER_GROUP_SSH_USERNAME": "fortipam-user-group-writer",
        "FPA_HOME_LAB_FPA1_V4_USER_GROUP_SSH_PASSWORD_FILE": str(password),
        "FPA_HOME_LAB_FPA1_V4_USER_GROUP_SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    }

    loaded = load_user_group_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-user-group-writer"
    password.chmod(0o640)
    with pytest.raises(
        UserGroupSshTransportConfigurationError,
        match="owner-only",
    ):
        load_user_group_ssh_transport_config(environment)


def test_input_rejects_out_of_scope_or_cli_injection_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamUserGroupSshTransport(_config(tmp_path))

    with pytest.raises(UserGroupSshTransportError):
        transport.inspect("everyone")
    with pytest.raises(UserGroupSshTransportError):
        transport.create_and_readback(
            USER_GROUP,
            'unsafe"\nset x y',
            LDAP_GROUP_DN,
        )
    with pytest.raises(UserGroupSshTransportError):
        transport.create_and_readback(
            USER_GROUP,
            LDAP_SERVER,
            'cn=unsafe"\nset x y',
        )


def test_readback_requires_all_fixed_remote_ldap_match_controls() -> None:
    output = (
        b'edit "mcp-v4-user-group-01"\r\n'
        + b'set member "lab-ldap"\r\n'
        + b"config match\r\n"
        + b"edit 1\r\n"
        + b'set server-name "lab-ldap"\r\n'
        + b'set group-name "cn=PAM_Group,cn=users,dc=fortipam,dc=ca"\r\n'
    )

    assert _readback(output, USER_GROUP, LDAP_SERVER, LDAP_GROUP_DN).verified is True
    assert (
        _readback(
            output.replace(b'set server-name "lab-ldap"', b'set server-name "other"'),
            USER_GROUP,
            LDAP_SERVER,
            LDAP_GROUP_DN,
        ).verified
        is False
    )


def test_create_uses_only_the_fixed_guide_remote_user_group_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamUserGroupSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (group) #"
    group_prompt = b"fpa (mcp-v4-user-group-01) #"
    match_table_prompt = b"fpa (match) #"
    match_prompt = b"fpa (1) #"

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
        if command == "config user group":
            return table_prompt
        if command == 'edit "mcp-v4-user-group-01"':
            return group_prompt
        if command == "config match":
            return match_table_prompt
        if command == "edit 1":
            return match_prompt
        if command == "next":
            return match_table_prompt if commands.count("next") == 1 else table_prompt
        if command == "end":
            return group_prompt if commands.count("end") == 1 else root_prompt
        raise AssertionError(command)

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._create_user_group(
            object(),
            root_prompt,
            USER_GROUP,
            LDAP_SERVER,
            LDAP_GROUP_DN,
            100.0,
        )
    )

    assert commands == [
        "config user group",
        'edit "mcp-v4-user-group-01"',
        'set member "lab-ldap"',
        "config match",
        "edit 1",
        'set server-name "lab-ldap"',
        'set group-name "cn=PAM_Group,cn=users,dc=fortipam,dc=ca"',
        "next",
        "end",
        "next",
        "end",
    ]


def test_reader_uses_both_requested_show_forms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamUserGroupSshTransport(_config(tmp_path))
    commands: list[str] = []

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, prompt, deadline
        commands.append(command)
        assert command in {
            "show | grep mcp-v4-user-group-01",
            "show | grep mcp-v4-user-group-01 -f",
        }
        return b"group"

    async def dynamic(
        process: object,
        command: str,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, deadline
        commands.append(command)
        if command == "config user group":
            return b"fpa (group) #"
        assert command == "end"
        return root_prompt

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._show_user_group(object(), b"fpa #", USER_GROUP, 100.0)
    )

    assert output == b"groupgroup"
    assert commands == [
        "config user group",
        "show | grep mcp-v4-user-group-01",
        "show | grep mcp-v4-user-group-01 -f",
        "end",
    ]


def test_absence_inspection_uses_collection_reader_without_entering_object(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamUserGroupSshTransport(_config(tmp_path))
    calls: list[str] = []

    class Connection:
        async def __aenter__(self) -> object:
            return object()

        async def __aexit__(self, *args: object) -> None:
            del args

    async def open_cli(connection: object) -> tuple[object, bytes, float]:
        del connection
        return object(), b"fpa #", 100.0

    async def collection(*args: object) -> bytes:
        del args
        calls.append("collection")
        return b""

    async def exact(*args: object) -> bytes:
        del args
        raise AssertionError("absence inspection must not enter an object")

    async def close(process: object) -> None:
        del process
        calls.append("close")

    monkeypatch.setattr(transport, "_connection", lambda: Connection())
    monkeypatch.setattr(transport, "_open_cli", open_cli)
    monkeypatch.setattr(transport, "_show_user_group", collection)
    monkeypatch.setattr(transport, "_show_existing_user_group", exact)
    monkeypatch.setattr(transport_module, "_close_cli", close)

    result = asyncio.run(transport._inspect(USER_GROUP))

    assert result.user_group_exists is False
    assert calls == ["collection", "close"]


def test_existing_object_reader_enters_only_the_exact_group_and_uses_show(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamUserGroupSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    group_prompt = b"fpa (mcp-v4-user-group-01) #"
    readback = (
        b'edit "mcp-v4-user-group-01"\r\n'
        b'    set member "lab-ldap"\r\n'
        b"    config match\r\n"
        b"        edit 1\r\n"
        b'            set server-name "lab-ldap"\r\n'
        b'            set group-name "cn=PAM_Group,cn=users,dc=fortipam,dc=ca"\r\n'
        b"        next\r\n"
        b"    end\r\n"
        b"next\r\n"
    )

    async def send(process: object, command: str, prompt: bytes, deadline: float) -> bytes:
        del process, deadline
        commands.append(command)
        assert command == "show"
        assert prompt == group_prompt
        return readback

    async def dynamic(
        process: object,
        command: str,
        known_root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        del process, known_root_prompt, deadline
        commands.append(command)
        if command == "config user group":
            return b"fpa (group) #"
        if command == 'edit "mcp-v4-user-group-01"':
            return group_prompt
        if command == "end":
            return root_prompt
        raise AssertionError(command)

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    output = asyncio.run(
        transport._show_existing_user_group(
            object(),
            root_prompt,
            USER_GROUP,
            100.0,
        )
    )

    assert _readback(output, USER_GROUP, LDAP_SERVER, LDAP_GROUP_DN).verified is True
    assert commands == [
        "config user group",
        'edit "mcp-v4-user-group-01"',
        "show",
        "end",
    ]


def test_create_readback_uses_exact_object_reader_without_collection_grep(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamUserGroupSshTransport(_config(tmp_path))
    calls: list[str] = []
    readback = (
        b'edit "mcp-v4-user-group-01"\n'
        b'set member "lab-ldap"\n'
        b"config match\n"
        b"edit 1\n"
        b'set server-name "lab-ldap"\n'
        b'set group-name "cn=PAM_Group,cn=users,dc=fortipam,dc=ca"\n'
    )

    class Connection:
        async def __aenter__(self) -> object:
            return object()

        async def __aexit__(self, *args: object) -> None:
            del args

    async def open_cli(connection: object) -> tuple[object, bytes, float]:
        del connection
        return object(), b"fpa #", 100.0

    async def create(*args: object) -> None:
        del args
        calls.append("create")

    async def exact(*args: object) -> bytes:
        del args
        calls.append("exact")
        return readback

    async def collection(*args: object) -> bytes:
        del args
        raise AssertionError("post-create readback must not use collection grep")

    async def close(process: object) -> None:
        del process
        calls.append("close")

    monkeypatch.setattr(transport, "_connection", lambda: Connection())
    monkeypatch.setattr(transport, "_open_cli", open_cli)
    monkeypatch.setattr(transport, "_create_user_group", create)
    monkeypatch.setattr(transport, "_show_existing_user_group", exact)
    monkeypatch.setattr(transport, "_show_user_group", collection)
    monkeypatch.setattr(transport_module, "_close_cli", close)

    result = asyncio.run(
        transport._create_and_readback(
            USER_GROUP,
            LDAP_SERVER,
            LDAP_GROUP_DN,
        )
    )

    assert result.verified is True
    assert calls == ["create", "exact", "close"]
