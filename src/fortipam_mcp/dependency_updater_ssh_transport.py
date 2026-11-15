"""Pinned SSH fallback for one bounded FortiPAM Dependency Updater create.

The FortiPAM API catalog lists Dependency Updater routes but does not establish
the 1.9.1 REST request body. This module therefore implements only the
Administration Guide's fixed Windows-service example: a named, unattached
updater with restart disabled. It never associates the updater to a Secret or
Target and never invokes a service operation.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_DEPENDENCY_UPDATER_"
DEPENDENCY_UPDATER_NAME_PREFIX = "mcp-v4-dependency-updater-"
DEPENDENCY_UPDATER_CONFIGURATION = "win-service-restart-disabled-v1"
_CONFIG_COMMAND = "config secret dependency-updater"
_NAME = re.compile(r"mcp-v4-dependency-updater-[A-Za-z0-9][A-Za-z0-9._-]{0,37}\Z")
_SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._$-]{0,63}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_UNAVAILABLE = "FortiPAM V4 Dependency Updater transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_SETTINGS_PREFIX = (
    "set type win-service",
    "set restart disable",
)


class DependencyUpdaterSshTransportError(RuntimeError):
    """Stable non-disclosing failure for the bounded SSH transport."""


class DependencyUpdaterSshTransportConfigurationError(ValueError):
    """Raised when dedicated Dependency Updater SSH settings are unsafe."""


@dataclass(frozen=True, slots=True)
class DependencyUpdaterSshTransportConfig:
    """Dedicated pinned SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise DependencyUpdaterSshTransportConfigurationError(
                "The Dependency Updater SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise DependencyUpdaterSshTransportConfigurationError(
                "The Dependency Updater SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise DependencyUpdaterSshTransportConfigurationError(
                "The Dependency Updater SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise DependencyUpdaterSshTransportConfigurationError(
                "The Dependency Updater SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise DependencyUpdaterSshTransportConfigurationError(
                "The Dependency Updater SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class DependencyUpdaterInspection:
    """Value-minimized preflight evidence for one Dependency Updater."""

    updater_name_exists: bool


@dataclass(frozen=True, slots=True)
class DependencyUpdaterReadback:
    """Categorical readback for the fixed Windows-service updater contract."""

    updater_name_exists: bool
    win_service_type_enabled: bool
    restart_disabled: bool
    service_name_matches: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.updater_name_exists,
                self.win_service_type_enabled,
                self.restart_disabled,
                self.service_name_matches,
            )
        )


def load_dependency_updater_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> DependencyUpdaterSshTransportConfig:
    """Load only independently scoped Dependency Updater SSH credentials."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise DependencyUpdaterSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise DependencyUpdaterSshTransportConfigurationError(
            "Dedicated Dependency Updater SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise DependencyUpdaterSshTransportConfigurationError(
            "The Dependency Updater SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return DependencyUpdaterSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamDependencyUpdaterSshTransport:
    """Run only compiled Dependency Updater inspection and create commands."""

    def __init__(self, config: DependencyUpdaterSshTransportConfig) -> None:
        self._config = config

    def inspect(self, updater_name: str) -> DependencyUpdaterInspection:
        safe_name = _updater_name(updater_name)
        return cast(DependencyUpdaterInspection, _run_sync(self._inspect(safe_name)))

    def create_and_readback(
        self,
        updater_name: str,
        service_name: str,
    ) -> DependencyUpdaterReadback:
        safe_name = _updater_name(updater_name)
        safe_service_name = _service_name(service_name)
        return cast(
            DependencyUpdaterReadback,
            _run_sync(self._create_and_readback(safe_name, safe_service_name)),
        )

    async def _inspect(self, updater_name: str) -> DependencyUpdaterInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_updater(
                    process,
                    root_prompt,
                    updater_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return DependencyUpdaterInspection(
            updater_name_exists=_updater_marker(updater_name)
            in output.replace(b"\r", b"")
        )

    async def _create_and_readback(
        self,
        updater_name: str,
        service_name: str,
    ) -> DependencyUpdaterReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_updater(
                    process,
                    root_prompt,
                    updater_name,
                    service_name,
                    deadline,
                )
                output = await self._show_updater(
                    process,
                    root_prompt,
                    updater_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, updater_name, service_name)

    async def _create_updater(
        self,
        process: Any,
        root_prompt: bytes,
        updater_name: str,
        service_name: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            updater_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{updater_name}"',
                root_prompt,
                deadline,
            )
            for command in _SETTINGS_PREFIX:
                await _send_and_read(process, command, updater_prompt, deadline)
            await _send_and_read(
                process,
                f'set service-name "{service_name}"',
                updater_prompt,
                deadline,
            )
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise DependencyUpdaterSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise DependencyUpdaterSshTransportError(_UNAVAILABLE) from exc

    async def _show_updater(
        self,
        process: Any,
        root_prompt: bytes,
        updater_name: str,
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
                f"show | grep {updater_name}",
                table_prompt,
                deadline,
            )
            full = await _send_and_read(
                process,
                f"show | grep {updater_name} -f",
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
            raise DependencyUpdaterSshTransportError(_UNAVAILABLE) from exc

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
            raise DependencyUpdaterSshTransportError(_UNAVAILABLE) from exc


def _readback(
    output: bytes,
    updater_name: str,
    service_name: str,
) -> DependencyUpdaterReadback:
    normalized = output.replace(b"\r", b"")
    return DependencyUpdaterReadback(
        updater_name_exists=_updater_marker(updater_name) in normalized,
        win_service_type_enabled=b"set type win-service" in normalized,
        restart_disabled=b"set restart disable" in normalized,
        service_name_matches=_service_name_present(normalized, service_name),
    )


def _updater_marker(updater_name: str) -> bytes:
    return f'edit "{updater_name}"'.encode("ascii")


def _service_name_present(output: bytes, service_name: str) -> bool:
    escaped = re.escape(service_name.encode("ascii"))
    pattern = (
        rb"(?m)^\s*set service-name\s+(?:"
        + escaped
        + rb'|"'
        + escaped
        + rb'"|\''
        + escaped
        + rb"')\s*$"
    )
    return re.search(pattern, output) is not None


def _updater_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise DependencyUpdaterSshTransportError(_UNAVAILABLE)
    return value


def _service_name(value: str) -> str:
    if not isinstance(value, str) or _SERVICE_NAME.fullmatch(value) is None:
        raise DependencyUpdaterSshTransportError(_UNAVAILABLE)
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
        raise DependencyUpdaterSshTransportConfigurationError(
            f"The Dependency Updater SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise DependencyUpdaterSshTransportConfigurationError(
            f"The Dependency Updater SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise DependencyUpdaterSshTransportConfigurationError(
            f"The Dependency Updater SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise DependencyUpdaterSshTransportConfigurationError(
            "The Dependency Updater SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DependencyUpdaterSshTransportConfigurationError(
            "The Dependency Updater SSH password file is invalid."
        ) from exc


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _run_sync(coroutine: Coroutine[Any, Any, Any]) -> Any:
    try:
        return asyncio.run(coroutine)
    except DependencyUpdaterSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise DependencyUpdaterSshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "DEPENDENCY_UPDATER_CONFIGURATION",
    "DEPENDENCY_UPDATER_NAME_PREFIX",
    "DependencyUpdaterInspection",
    "DependencyUpdaterReadback",
    "DependencyUpdaterSshTransportConfig",
    "DependencyUpdaterSshTransportConfigurationError",
    "DependencyUpdaterSshTransportError",
    "ENV_PREFIX",
    "FortiPamDependencyUpdaterSshTransport",
    "load_dependency_updater_ssh_transport_config",
]
