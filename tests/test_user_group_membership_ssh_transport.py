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
    _membership_inspection,
    _membership_readback,
    load_user_group_membership_ssh_transport_config,
)


USER_GROUP = "mcp-v4-user-group-01"
LDAP_SERVER = "lab-ldap"
PRIMARY_DN = "cn=PAM_Primary,cn=users,dc=fortipam,dc=ca"
ADDITIONAL_DN = "cn=PAM_Secondary,cn=users,dc=fortipam,dc=ca"


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
        username="fortipam-user-group-membership-writer",
        password=password.read_text().strip(),
        known_hosts_file=known_hosts,
        timeout_seconds=15,
    )


def _baseline_output(*, second_match: str | None = None) -> bytes:
    output = (
        b'edit "mcp-v4-user-group-01"\r\n'
        + b'set member "lab-ldap"\r\n'
        + b"config match\r\n"
        + b"edit 1\r\n"
        + b'set server-name "lab-ldap"\r\n'
        + b'set group-name "cn=PAM_Primary,cn=users,dc=fortipam,dc=ca"\r\n'
        + b"next\r\n"
    )
    if second_match is not None:
        output += (
            b"edit 2\r\n"
            + b'set server-name "lab-ldap"\r\n'
            + f'set group-name "{second_match}"\r\n'.encode("ascii")
            + b"next\r\n"
        )
    return output


def test_loader_requires_dedicated_owner_only_password_file(tmp_path: Path) -> None:
    known_hosts, password = _files(tmp_path)
    environment = {
        "FPA_HOME_LAB_FPA1_V4_USER_GROUP_MEMBERSHIP_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_USER_GROUP_MEMBERSHIP_SSH_HOST": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_USER_GROUP_MEMBERSHIP_SSH_USERNAME": (
            "fortipam-user-group-membership-writer"
        ),
        "FPA_HOME_LAB_FPA1_V4_USER_GROUP_MEMBERSHIP_SSH_PASSWORD_FILE": str(
            password
        ),
        "FPA_HOME_LAB_FPA1_V4_USER_GROUP_MEMBERSHIP_SSH_KNOWN_HOSTS_FILE": str(
            known_hosts
        ),
    }

    loaded = load_user_group_membership_ssh_transport_config(environment)

    assert loaded.host == "fpa.example"
    assert loaded.username == "fortipam-user-group-membership-writer"
    password.chmod(0o640)
    with pytest.raises(
        UserGroupSshTransportConfigurationError,
        match="owner-only",
    ):
        load_user_group_membership_ssh_transport_config(environment)


def test_input_rejects_nonv4_group_injection_and_duplicate_match_before_connection(
    tmp_path: Path,
) -> None:
    transport = FortiPamUserGroupSshTransport(_config(tmp_path))

    with pytest.raises(UserGroupSshTransportError):
        transport.inspect_membership("everyone", LDAP_SERVER, PRIMARY_DN, ADDITIONAL_DN)
    with pytest.raises(UserGroupSshTransportError):
        transport.inspect_membership(
            USER_GROUP,
            'unsafe"\nset x y',
            PRIMARY_DN,
            ADDITIONAL_DN,
        )
    with pytest.raises(UserGroupSshTransportError):
        transport.inspect_membership(
            USER_GROUP,
            LDAP_SERVER,
            PRIMARY_DN,
            PRIMARY_DN,
        )


def test_inspection_rejects_any_existing_second_match_and_readback_requires_exact_values() -> None:
    baseline = _baseline_output()
    assert (
        _membership_inspection(
            baseline,
            USER_GROUP,
            LDAP_SERVER,
            PRIMARY_DN,
            ADDITIONAL_DN,
        ).baseline_verified
        is True
    )
    assert (
        _membership_inspection(
            _baseline_output(second_match="cn=Unrelated,dc=fortipam,dc=ca"),
            USER_GROUP,
            LDAP_SERVER,
            PRIMARY_DN,
            ADDITIONAL_DN,
        ).baseline_verified
        is False
    )
    assert (
        _membership_readback(
            _baseline_output(second_match=ADDITIONAL_DN),
            USER_GROUP,
            LDAP_SERVER,
            PRIMARY_DN,
            ADDITIONAL_DN,
        ).verified
        is True
    )
    assert (
        _membership_readback(
            _baseline_output(second_match="cn=Wrong,dc=fortipam,dc=ca"),
            USER_GROUP,
            LDAP_SERVER,
            PRIMARY_DN,
            ADDITIONAL_DN,
        ).verified
        is False
    )


def test_change_uses_only_fixed_second_remote_group_match_cli_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FortiPamUserGroupSshTransport(_config(tmp_path))
    commands: list[str] = []
    root_prompt = b"fpa #"
    table_prompt = b"fpa (group) #"
    group_prompt = b"fpa (mcp-v4-user-group-01) #"
    match_table_prompt = b"fpa (match) #"
    match_prompt = b"fpa (2) #"

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
        if command == "edit 2":
            return match_prompt
        if command == "next":
            return match_table_prompt if commands.count("next") == 1 else table_prompt
        if command == "end":
            return group_prompt if commands.count("end") == 1 else root_prompt
        raise AssertionError(command)

    monkeypatch.setattr(transport_module, "_send_and_read", send)
    monkeypatch.setattr(transport_module, "_send_and_read_dynamic_prompt", dynamic)

    asyncio.run(
        transport._add_remote_ldap_match(
            object(),
            root_prompt,
            USER_GROUP,
            LDAP_SERVER,
            ADDITIONAL_DN,
            100.0,
        )
    )

    assert commands == [
        "config user group",
        'edit "mcp-v4-user-group-01"',
        "config match",
        "edit 2",
        'set server-name "lab-ldap"',
        'set group-name "cn=PAM_Secondary,cn=users,dc=fortipam,dc=ca"',
        "next",
        "end",
        "next",
        "end",
    ]


def test_membership_inspection_does_not_edit_an_absent_group(
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
        raise AssertionError("an absent group must not be entered with edit")

    async def close(process: object) -> None:
        del process
        calls.append("close")

    monkeypatch.setattr(transport, "_connection", lambda: Connection())
    monkeypatch.setattr(transport, "_open_cli", open_cli)
    monkeypatch.setattr(transport, "_show_user_group", collection)
    monkeypatch.setattr(transport, "_show_existing_user_group", exact)
    monkeypatch.setattr(transport_module, "_close_cli", close)

    result = asyncio.run(
        transport._inspect_membership(
            USER_GROUP,
            LDAP_SERVER,
            PRIMARY_DN,
            ADDITIONAL_DN,
        )
    )

    assert result.user_group_exists is False
    assert calls == ["collection", "close"]


def test_membership_change_readback_uses_exact_object_reader(
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

    async def change(*args: object) -> None:
        del args
        calls.append("change")

    async def exact(*args: object) -> bytes:
        del args
        calls.append("exact")
        return _baseline_output(second_match=ADDITIONAL_DN)

    async def collection(*args: object) -> bytes:
        del args
        raise AssertionError("post-change readback must not use collection grep")

    async def close(process: object) -> None:
        del process
        calls.append("close")

    monkeypatch.setattr(transport, "_connection", lambda: Connection())
    monkeypatch.setattr(transport, "_open_cli", open_cli)
    monkeypatch.setattr(transport, "_add_remote_ldap_match", change)
    monkeypatch.setattr(transport, "_show_existing_user_group", exact)
    monkeypatch.setattr(transport, "_show_user_group", collection)
    monkeypatch.setattr(transport_module, "_close_cli", close)

    result = asyncio.run(
        transport._add_remote_ldap_match_and_readback(
            USER_GROUP,
            LDAP_SERVER,
            PRIMARY_DN,
            ADDITIONAL_DN,
        )
    )

    assert result.verified is True
    assert calls == ["change", "exact", "close"]
