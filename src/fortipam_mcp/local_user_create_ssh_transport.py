"""Pinned SSH transport for one bounded FortiPAM Local User create contract.

The first V4 implementation creates one disabled Local User with the installed
``Guest`` access profile.  An initial password is generated only in process
memory, written to the appliance over the pinned SSH session, and never
returned through MCP, logs, or readback projections.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine, Mapping
from dataclasses import dataclass
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any, cast

import asyncssh

from .cli_safety import (
    CliTransportError,
    _complete_pre_login,
    _raise_for_remote_rejection,
    _read_until_prompt,
)
from .target_ssh_transport import (
    _close_cli,
    _require_context_prompt,
    _require_root_prompt,
    _send_and_read,
    _send_and_read_dynamic_prompt,
)


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_LOCAL_USER_CREATE_"
DEFAULT_ACCESS_PROFILE = "Guest"
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_DENIED_MESSAGE = "FortiPAM V4 Local User create transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024


class LocalUserCreateSshTransportError(RuntimeError):
    """Stable, non-disclosing failure for the bounded SSH transport."""


class LocalUserCreateSshTransportConfigurationError(ValueError):
    """Raised when the dedicated Local User create SSH configuration is unsafe."""


@dataclass(frozen=True, slots=True)
class LocalUserCreateSshTransportConfig:
    """Dedicated pinned-SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise LocalUserCreateSshTransportConfigurationError(
                "The Local User create SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise LocalUserCreateSshTransportConfigurationError(
                "The Local User create SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise LocalUserCreateSshTransportConfigurationError(
                "The Local User create SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise LocalUserCreateSshTransportConfigurationError(
                "The Local User create SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise LocalUserCreateSshTransportConfigurationError(
                "The Local User create SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class LocalUserCreateInspection:
    """Value-minimized preflight; optional digest binds stronger private reads."""

    exists: bool
    state_digest: str | None = None


@dataclass(frozen=True, slots=True)
class LocalUserCreateReadback:
    """Categorical readback; optional evidence digest stays out of MCP output."""

    user_exists: bool
    access_profile_matches: bool
    status_disabled: bool
    evidence_digest: str | None = None
    status_enabled: bool = False

    @property
    def verified(self) -> bool:
        exact_status = (
            self.status_disabled is True and self.status_enabled is False
        ) or (
            self.status_disabled is False and self.status_enabled is True
        )
        return all(value is True for value in (self.user_exists, self.access_profile_matches)) and exact_status


def load_local_user_create_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> LocalUserCreateSshTransportConfig:
    """Load only independently scoped Local User create SSH credentials."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise LocalUserCreateSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise LocalUserCreateSshTransportConfigurationError(
            "Dedicated Local User create SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise LocalUserCreateSshTransportConfigurationError(
            "The Local User create SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return LocalUserCreateSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamLocalUserCreateSshTransport:
    """Run only compiled inspection and fixed disabled-user creation commands."""

    def __init__(self, config: LocalUserCreateSshTransportConfig) -> None:
        self._config = config

    def inspect(self, username: str) -> LocalUserCreateInspection:
        name = _user_name(username)
        return cast(LocalUserCreateInspection, _run_sync(self._inspect(name)))

    def create_and_readback(self, username: str) -> LocalUserCreateReadback:
        name = _user_name(username)
        return cast(LocalUserCreateReadback, _run_sync(self._create_and_readback(name)))

    async def _inspect(self, username: str) -> LocalUserCreateInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                compact = await self._run_admin_context(
                    process,
                    root_prompt,
                    (f"show | grep {username}",),
                    deadline,
                )
                full = await self._run_admin_context(
                    process,
                    root_prompt,
                    (f"show | grep {username} -f",),
                    deadline,
                )
            finally:
                await _close_cli(process)
        marker = f'edit "{username}"'.encode("ascii")
        return LocalUserCreateInspection(exists=marker in compact + full)

    async def _create_and_readback(self, username: str) -> LocalUserCreateReadback:
        password = _generated_initial_password()
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_user(process, root_prompt, username, password, deadline)
                output = await self._run_admin_context(
                    process,
                    root_prompt,
                    (f"show | grep {username} -f",),
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, username)

    async def _create_user(
        self,
        process: Any,
        root_prompt: bytes,
        username: str,
        password: str,
        deadline: float,
    ) -> None:
        table_prompt = _admin_context_prompt(root_prompt)
        try:
            await _send_and_read(process, "config system admin", table_prompt, deadline)
            entry_prompt = await _send_and_read_dynamic_prompt(
                process, f'edit "{username}"', root_prompt, deadline
            )
            await _send_and_read(
                process,
                f'set accprofile "{DEFAULT_ACCESS_PROFILE}"',
                entry_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                f'set password "{password}"',
                entry_prompt,
                deadline,
            )
            await _send_and_read(process, "set status disable", entry_prompt, deadline)
            returned_context = await _send_and_read_dynamic_prompt(
                process, "next", root_prompt, deadline
            )
            _require_context_prompt(root_prompt, returned_context, "admin")
            returned_root = await _send_and_read_dynamic_prompt(
                process, "end", root_prompt, deadline
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise LocalUserCreateSshTransportError(_DENIED_MESSAGE) from exc

    async def _run_admin_context(
        self,
        process: Any,
        root_prompt: bytes,
        commands: tuple[str, ...],
        deadline: float,
    ) -> bytes:
        table_prompt = _admin_context_prompt(root_prompt)
        try:
            await _send_and_read(process, "config system admin", table_prompt, deadline)
            outputs: list[bytes] = []
            for command in commands:
                outputs.append(
                    await _send_and_read(process, command, table_prompt, deadline)
                )
            output = b"".join(outputs)
            returned_root = await _send_and_read_dynamic_prompt(
                process, "end", root_prompt, deadline
            )
            _require_root_prompt(root_prompt, returned_root)
            return output
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise LocalUserCreateSshTransportError(_DENIED_MESSAGE) from exc

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
                term_type="vt100", term_size=(80, 24), encoding=None
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
            raise LocalUserCreateSshTransportError(_DENIED_MESSAGE) from exc


def _readback(output: bytes, username: str) -> LocalUserCreateReadback:
    normalized = output.replace(b"\r", b"")
    marker = f'edit "{username}"'.encode("ascii")
    access_profile_markers = (
        f'set accprofile "{DEFAULT_ACCESS_PROFILE}"'.encode("ascii"),
        f"set accprofile {DEFAULT_ACCESS_PROFILE}".encode("ascii"),
    )
    return LocalUserCreateReadback(
        user_exists=marker in normalized,
        access_profile_matches=any(marker in normalized for marker in access_profile_markers),
        status_disabled=b"set status disable" in normalized,
    )


def _admin_context_prompt(root_prompt: bytes) -> bytes:
    if len(root_prompt) < 3 or root_prompt[-2:-1] != b" " or root_prompt[-1:] not in {b"#", b"$"}:
        raise LocalUserCreateSshTransportError(_DENIED_MESSAGE)
    return root_prompt[:-2] + b" (admin) " + root_prompt[-1:]


def _user_name(value: str) -> str:
    if not _safe_name(value):
        raise LocalUserCreateSshTransportError(_DENIED_MESSAGE)
    return value


def _generated_initial_password() -> str:
    """Return a one-use ASCII password satisfying common product policy defaults."""

    return f"McpV4!{secrets.token_hex(5)}aZ9"


def _safe_name(value: str) -> bool:
    return isinstance(value, str) and _NAME.fullmatch(value) is not None


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
        raise LocalUserCreateSshTransportConfigurationError(
            f"The Local User create SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise LocalUserCreateSshTransportConfigurationError(
            f"The Local User create SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise LocalUserCreateSshTransportConfigurationError(
            f"The Local User create SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise LocalUserCreateSshTransportConfigurationError(
            "The Local User create SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LocalUserCreateSshTransportConfigurationError(
            "The Local User create SSH password file is invalid."
        ) from exc
    return value


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _run_sync(coroutine: Coroutine[Any, Any, Any]) -> Any:
    try:
        return asyncio.run(coroutine)
    except LocalUserCreateSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise LocalUserCreateSshTransportError(_DENIED_MESSAGE) from exc


__all__ = [
    "DEFAULT_ACCESS_PROFILE",
    "ENV_PREFIX",
    "FortiPamLocalUserCreateSshTransport",
    "LocalUserCreateInspection",
    "LocalUserCreateReadback",
    "LocalUserCreateSshTransportConfig",
    "LocalUserCreateSshTransportConfigurationError",
    "LocalUserCreateSshTransportError",
    "load_local_user_create_ssh_transport_config",
]
