"""Pinned SSH fallback for one bounded FortiPAM remote User Group create.

The FortiPAM 1.9.1 Administration Guide documents a remote LDAP User Group
with one LDAP server member and one matching distinguished name.  This module
implements only that unattached laboratory object.  It never creates an
Auto-Provision Rule, assigns a Role, changes a Folder/Secret ACL, imports a
user, or starts a session.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine, Mapping
from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, cast

import asyncssh

from .cli_safety import CliTransportError, _complete_pre_login
from .target_ssh_transport import (
    _close_cli,
    _require_root_prompt,
    _send_and_read,
    _send_and_read_dynamic_prompt,
)


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_USER_GROUP_"
MEMBERSHIP_ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_USER_GROUP_MEMBERSHIP_"
USER_GROUP_NAME_PREFIX = "mcp-v4-user-group-"
USER_GROUP_CONFIGURATION = "remote-ldap-single-match-unbound-v1"
USER_GROUP_MEMBERSHIP_CONFIGURATION = "remote-ldap-second-match-unbound-v1"
_CONFIG_COMMAND = "config user group"
_MATCH_CONTEXT = "config match"
_NAME = re.compile(r"mcp-v4-user-group-[A-Za-z0-9][A-Za-z0-9._-]{0,43}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_LDAP_DN = re.compile(r"[A-Za-z0-9][A-Za-z0-9=,._@+:-]{0,253}\Z")
_UNAVAILABLE = "FortiPAM V4 User Group transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_MATCH_ID = "1"
_ADDITIONAL_MATCH_ID = "2"


class UserGroupSshTransportError(RuntimeError):
    """Stable non-disclosing failure for the bounded SSH transport."""


class UserGroupSshTransportConfigurationError(ValueError):
    """Raised when dedicated User Group SSH settings are unsafe."""


@dataclass(frozen=True, slots=True)
class UserGroupSshTransportConfig:
    """Dedicated pinned SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise UserGroupSshTransportConfigurationError(
                "The User Group SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise UserGroupSshTransportConfigurationError(
                "The User Group SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise UserGroupSshTransportConfigurationError(
                "The User Group SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise UserGroupSshTransportConfigurationError(
                "The User Group SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.password
        ):
            raise UserGroupSshTransportConfigurationError(
                "The User Group SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class UserGroupInspection:
    """Value-minimized preflight evidence for one User Group."""

    user_group_exists: bool


@dataclass(frozen=True, slots=True)
class UserGroupReadback:
    """Categorical readback for the fixed remote LDAP match contract."""

    user_group_exists: bool
    ldap_server_member_present: bool
    match_server_present: bool
    match_group_dn_present: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.user_group_exists,
                self.ldap_server_member_present,
                self.match_server_present,
                self.match_group_dn_present,
            )
        )


@dataclass(frozen=True, slots=True)
class UserGroupMembershipInspection:
    """Categorical baseline evidence for one second remote LDAP group match."""

    user_group_exists: bool
    ldap_server_member_present: bool
    primary_match_server_present: bool
    primary_match_group_dn_present: bool
    additional_match_present: bool

    @property
    def baseline_verified(self) -> bool:
        return all(
            (
                self.user_group_exists,
                self.ldap_server_member_present,
                self.primary_match_server_present,
                self.primary_match_group_dn_present,
                not self.additional_match_present,
            )
        )


@dataclass(frozen=True, slots=True)
class UserGroupMembershipReadback:
    """Categorical readback for a second remote LDAP group match."""

    user_group_exists: bool
    ldap_server_member_present: bool
    primary_match_server_present: bool
    primary_match_group_dn_present: bool
    additional_match_server_present: bool
    additional_match_group_dn_present: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.user_group_exists,
                self.ldap_server_member_present,
                self.primary_match_server_present,
                self.primary_match_group_dn_present,
                self.additional_match_server_present,
                self.additional_match_group_dn_present,
            )
        )


def load_user_group_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> UserGroupSshTransportConfig:
    """Load only independently scoped User Group SSH credentials."""

    env = os.environ if environment is None else environment
    return _load_user_group_ssh_transport_config(env, ENV_PREFIX)


def load_user_group_membership_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> UserGroupSshTransportConfig:
    """Load only independently scoped User Group membership SSH credentials."""

    env = os.environ if environment is None else environment
    return _load_user_group_ssh_transport_config(env, MEMBERSHIP_ENV_PREFIX)


def _load_user_group_ssh_transport_config(
    environment: Mapping[str, str],
    prefix: str,
) -> UserGroupSshTransportConfig:
    if _value_for_prefix(environment, prefix, "ENABLED") != "true":
        raise UserGroupSshTransportConfigurationError(
            f"{prefix}ENABLED must be exactly true."
        )
    host = _value_for_prefix(environment, prefix, "SSH_HOST")
    username = _value_for_prefix(environment, prefix, "SSH_USERNAME")
    password_file = _value_for_prefix(environment, prefix, "SSH_PASSWORD_FILE")
    known_hosts_file = _value_for_prefix(environment, prefix, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value_for_prefix(environment, prefix, "SSH_PORT") or "22"
    timeout_raw = _value_for_prefix(environment, prefix, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise UserGroupSshTransportConfigurationError(
            "Dedicated User Group SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise UserGroupSshTransportConfigurationError(
            "The User Group SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return UserGroupSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamUserGroupSshTransport:
    """Run only compiled User Group inspection and creation commands."""

    def __init__(self, config: UserGroupSshTransportConfig) -> None:
        self._config = config

    def inspect(self, user_group_name: str) -> UserGroupInspection:
        safe_name = _user_group_name(user_group_name)
        return cast(UserGroupInspection, _run_sync(self._inspect(safe_name)))

    def create_and_readback(
        self,
        user_group_name: str,
        ldap_server_name: str,
        ldap_group_dn: str,
    ) -> UserGroupReadback:
        safe_name = _user_group_name(user_group_name)
        safe_server = _ldap_server_name(ldap_server_name)
        safe_dn = _ldap_group_dn(ldap_group_dn)
        return cast(
            UserGroupReadback,
            _run_sync(
                self._create_and_readback(
                    safe_name,
                    safe_server,
                    safe_dn,
                )
            ),
        )

    def inspect_membership(
        self,
        user_group_name: str,
        ldap_server_name: str,
        primary_ldap_group_dn: str,
        additional_ldap_group_dn: str,
    ) -> UserGroupMembershipInspection:
        """Inspect one exact V4 create baseline before adding match ID 2."""

        safe_name = _user_group_name(user_group_name)
        safe_server = _ldap_server_name(ldap_server_name)
        safe_primary = _ldap_group_dn(primary_ldap_group_dn)
        safe_additional = _ldap_group_dn(additional_ldap_group_dn)
        _distinct_group_dns(safe_primary, safe_additional)
        return cast(
            UserGroupMembershipInspection,
            _run_sync(
                self._inspect_membership(
                    safe_name,
                    safe_server,
                    safe_primary,
                    safe_additional,
                )
            ),
        )

    def add_remote_ldap_match_and_readback(
        self,
        user_group_name: str,
        ldap_server_name: str,
        primary_ldap_group_dn: str,
        additional_ldap_group_dn: str,
    ) -> UserGroupMembershipReadback:
        """Add exactly match ID 2 to the known one-match V4 User Group."""

        safe_name = _user_group_name(user_group_name)
        safe_server = _ldap_server_name(ldap_server_name)
        safe_primary = _ldap_group_dn(primary_ldap_group_dn)
        safe_additional = _ldap_group_dn(additional_ldap_group_dn)
        _distinct_group_dns(safe_primary, safe_additional)
        return cast(
            UserGroupMembershipReadback,
            _run_sync(
                self._add_remote_ldap_match_and_readback(
                    safe_name,
                    safe_server,
                    safe_primary,
                    safe_additional,
                )
            ),
        )

    async def _inspect(self, user_group_name: str) -> UserGroupInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_user_group(
                    process,
                    root_prompt,
                    user_group_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return UserGroupInspection(
            user_group_exists=_user_group_marker(user_group_name)
            in output.replace(b"\r", b"")
        )

    async def _create_and_readback(
        self,
        user_group_name: str,
        ldap_server_name: str,
        ldap_group_dn: str,
    ) -> UserGroupReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_user_group(
                    process,
                    root_prompt,
                    user_group_name,
                    ldap_server_name,
                    ldap_group_dn,
                    deadline,
                )
                output = await self._show_existing_user_group(
                    process,
                    root_prompt,
                    user_group_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(
            output,
            user_group_name,
            ldap_server_name,
            ldap_group_dn,
        )

    async def _inspect_membership(
        self,
        user_group_name: str,
        ldap_server_name: str,
        primary_ldap_group_dn: str,
        additional_ldap_group_dn: str,
    ) -> UserGroupMembershipInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_user_group(
                    process,
                    root_prompt,
                    user_group_name,
                    deadline,
                )
                if _user_group_marker(user_group_name) in output.replace(b"\r", b""):
                    output = await self._show_existing_user_group(
                        process,
                        root_prompt,
                        user_group_name,
                        deadline,
                    )
            finally:
                await _close_cli(process)
        return _membership_inspection(
            output,
            user_group_name,
            ldap_server_name,
            primary_ldap_group_dn,
            additional_ldap_group_dn,
        )

    async def _add_remote_ldap_match_and_readback(
        self,
        user_group_name: str,
        ldap_server_name: str,
        primary_ldap_group_dn: str,
        additional_ldap_group_dn: str,
    ) -> UserGroupMembershipReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._add_remote_ldap_match(
                    process,
                    root_prompt,
                    user_group_name,
                    ldap_server_name,
                    additional_ldap_group_dn,
                    deadline,
                )
                output = await self._show_existing_user_group(
                    process,
                    root_prompt,
                    user_group_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _membership_readback(
            output,
            user_group_name,
            ldap_server_name,
            primary_ldap_group_dn,
            additional_ldap_group_dn,
        )

    async def _create_user_group(
        self,
        process: Any,
        root_prompt: bytes,
        user_group_name: str,
        ldap_server_name: str,
        ldap_group_dn: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            group_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{user_group_name}"',
                root_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                f'set member "{ldap_server_name}"',
                group_prompt,
                deadline,
            )
            match_table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _MATCH_CONTEXT,
                root_prompt,
                deadline,
            )
            match_prompt = await _send_and_read_dynamic_prompt(
                process,
                f"edit {_MATCH_ID}",
                root_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                f'set server-name "{ldap_server_name}"',
                match_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                f'set group-name "{ldap_group_dn}"',
                match_prompt,
                deadline,
            )
            returned_match_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_match_table != match_table_prompt:
                raise UserGroupSshTransportError(_UNAVAILABLE)
            returned_group = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            if returned_group != group_prompt:
                raise UserGroupSshTransportError(_UNAVAILABLE)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise UserGroupSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise UserGroupSshTransportError(_UNAVAILABLE) from exc

    async def _add_remote_ldap_match(
        self,
        process: Any,
        root_prompt: bytes,
        user_group_name: str,
        ldap_server_name: str,
        additional_ldap_group_dn: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            group_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{user_group_name}"',
                root_prompt,
                deadline,
            )
            match_table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _MATCH_CONTEXT,
                root_prompt,
                deadline,
            )
            match_prompt = await _send_and_read_dynamic_prompt(
                process,
                f"edit {_ADDITIONAL_MATCH_ID}",
                root_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                f'set server-name "{ldap_server_name}"',
                match_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                f'set group-name "{additional_ldap_group_dn}"',
                match_prompt,
                deadline,
            )
            returned_match_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_match_table != match_table_prompt:
                raise UserGroupSshTransportError(_UNAVAILABLE)
            returned_group = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            if returned_group != group_prompt:
                raise UserGroupSshTransportError(_UNAVAILABLE)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise UserGroupSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise UserGroupSshTransportError(_UNAVAILABLE) from exc

    async def _show_user_group(
        self,
        process: Any,
        root_prompt: bytes,
        user_group_name: str,
        deadline: float,
    ) -> bytes:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            compact = await _send_and_read(
                process,
                f"show | grep {user_group_name}",
                table_prompt,
                deadline,
            )
            full = await _send_and_read(
                process,
                f"show | grep {user_group_name} -f",
                table_prompt,
                deadline,
            )
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
            return compact + full
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise UserGroupSshTransportError(_UNAVAILABLE) from exc

    async def _show_existing_user_group(
        self,
        process: Any,
        root_prompt: bytes,
        user_group_name: str,
        deadline: float,
    ) -> bytes:
        """Read one proven existing User Group from its exact object context."""

        try:
            await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            group_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{user_group_name}"',
                root_prompt,
                deadline,
            )
            output = await _send_and_read(
                process,
                "show",
                group_prompt,
                deadline,
            )
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
            return output
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise UserGroupSshTransportError(_UNAVAILABLE) from exc

    def _connection(self) -> Any:
        return asyncssh.connect(
            self._config.host,
            port=self._config.port,
            username=self._config.username,
            password=self._config.password,
            known_hosts=str(self._config.known_hosts_file),
            client_keys=None,
            agent_path=None,
            preferred_auth="password",
            public_key_auth=False,
            password_auth=True,
            kbdint_auth=False,
            host_based_auth=False,
            gss_auth=False,
            gss_kex=False,
            config=[],
            connect_timeout=self._config.timeout_seconds,
            keepalive_interval=5,
            keepalive_count_max=1,
        )

    async def _open_cli(self, connection: Any) -> tuple[Any, bytes, float]:
        try:
            process = await connection.create_process(
                term_type="vt100",
                term_size=(80, 24),
                encoding=None,
            )
            deadline = time.monotonic() + self._config.timeout_seconds
            root_prompt = await _complete_pre_login(
                process.stdout,
                process.stdin,
                deadline,
                _MAX_OUTPUT_BYTES,
                accept_pre_login_banner=False,
            )
            return process, root_prompt, deadline
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise UserGroupSshTransportError(_UNAVAILABLE) from exc


def _readback(
    output: bytes,
    user_group_name: str,
    ldap_server_name: str,
    ldap_group_dn: str,
) -> UserGroupReadback:
    normalized = output.replace(b"\r", b"")
    return UserGroupReadback(
        user_group_exists=_user_group_marker(user_group_name) in normalized,
        ldap_server_member_present=(
            f'set member "{ldap_server_name}"'.encode("ascii") in normalized
        ),
        match_server_present=(
            f'set server-name "{ldap_server_name}"'.encode("ascii") in normalized
        ),
        match_group_dn_present=(
            f'set group-name "{ldap_group_dn}"'.encode("ascii") in normalized
        ),
    )


def _membership_inspection(
    output: bytes,
    user_group_name: str,
    ldap_server_name: str,
    primary_ldap_group_dn: str,
    additional_ldap_group_dn: str,
) -> UserGroupMembershipInspection:
    base = _readback(
        output,
        user_group_name,
        ldap_server_name,
        primary_ldap_group_dn,
    )
    return UserGroupMembershipInspection(
        user_group_exists=base.user_group_exists,
        ldap_server_member_present=base.ldap_server_member_present,
        primary_match_server_present=_match_value_present(
            output,
            _MATCH_ID,
            f'set server-name "{ldap_server_name}"',
        ),
        primary_match_group_dn_present=_match_value_present(
            output,
            _MATCH_ID,
            f'set group-name "{primary_ldap_group_dn}"',
        ),
        additional_match_present=_match_entry_exists(output, _ADDITIONAL_MATCH_ID),
    )


def _membership_readback(
    output: bytes,
    user_group_name: str,
    ldap_server_name: str,
    primary_ldap_group_dn: str,
    additional_ldap_group_dn: str,
) -> UserGroupMembershipReadback:
    inspection = _membership_inspection(
        output,
        user_group_name,
        ldap_server_name,
        primary_ldap_group_dn,
        additional_ldap_group_dn,
    )
    return UserGroupMembershipReadback(
        user_group_exists=inspection.user_group_exists,
        ldap_server_member_present=inspection.ldap_server_member_present,
        primary_match_server_present=inspection.primary_match_server_present,
        primary_match_group_dn_present=inspection.primary_match_group_dn_present,
        additional_match_server_present=_match_value_present(
            output,
            _ADDITIONAL_MATCH_ID,
            f'set server-name "{ldap_server_name}"',
        ),
        additional_match_group_dn_present=_match_value_present(
            output,
            _ADDITIONAL_MATCH_ID,
            f'set group-name "{additional_ldap_group_dn}"',
        ),
    )


def _match_value_present(output: bytes, match_id: str, value: str) -> bool:
    normalized = output.replace(b"\r", b"")
    marker = f"edit {match_id}\n".encode("ascii")
    start = 0
    expected = value.encode("ascii")
    while True:
        found = normalized.find(marker, start)
        if found < 0:
            return False
        next_marker = normalized.find(b"\nnext", found + len(marker))
        block = normalized[found:] if next_marker < 0 else normalized[found:next_marker]
        if expected in block:
            return True
        start = found + len(marker)


def _match_entry_exists(output: bytes, match_id: str) -> bool:
    normalized = output.replace(b"\r", b"")
    return f"edit {match_id}\n".encode("ascii") in normalized


def _distinct_group_dns(primary: str, additional: str) -> None:
    if primary == additional:
        raise UserGroupSshTransportError(_UNAVAILABLE)


def _user_group_marker(user_group_name: str) -> bytes:
    return f'edit "{user_group_name}"'.encode("ascii")


def _user_group_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise UserGroupSshTransportError(_UNAVAILABLE)
    return value


def _ldap_server_name(value: str) -> str:
    if not isinstance(value, str) or _SAFE_NAME.fullmatch(value) is None:
        raise UserGroupSshTransportError(_UNAVAILABLE)
    return value


def _ldap_group_dn(value: str) -> str:
    if not isinstance(value, str) or _LDAP_DN.fullmatch(value) is None:
        raise UserGroupSshTransportError(_UNAVAILABLE)
    return value


def _safe_name(value: str) -> bool:
    return isinstance(value, str) and _SAFE_NAME.fullmatch(value) is not None


def _safe_host(value: str) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 255
        and not any(character.isspace() or character in "@/\\" for character in value)
    )


def _private_regular_file(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise UserGroupSshTransportConfigurationError(
            f"The User Group SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise UserGroupSshTransportConfigurationError(
            f"The User Group SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise UserGroupSshTransportConfigurationError(
            f"The User Group SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise UserGroupSshTransportConfigurationError(
            "The User Group SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UserGroupSshTransportConfigurationError(
            "The User Group SSH password file is invalid."
        ) from exc


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    return _value_for_prefix(environment, ENV_PREFIX, suffix)


def _value_for_prefix(
    environment: Mapping[str, str],
    prefix: str,
    suffix: str,
) -> str | None:
    value = environment.get(f"{prefix}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _run_sync(coroutine: Coroutine[Any, Any, Any]) -> Any:
    try:
        return asyncio.run(coroutine)
    except UserGroupSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise UserGroupSshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "ENV_PREFIX",
    "FortiPamUserGroupSshTransport",
    "MEMBERSHIP_ENV_PREFIX",
    "USER_GROUP_CONFIGURATION",
    "USER_GROUP_MEMBERSHIP_CONFIGURATION",
    "USER_GROUP_NAME_PREFIX",
    "UserGroupInspection",
    "UserGroupMembershipInspection",
    "UserGroupMembershipReadback",
    "UserGroupReadback",
    "UserGroupSshTransportConfig",
    "UserGroupSshTransportConfigurationError",
    "UserGroupSshTransportError",
    "load_user_group_membership_ssh_transport_config",
    "load_user_group_ssh_transport_config",
]
