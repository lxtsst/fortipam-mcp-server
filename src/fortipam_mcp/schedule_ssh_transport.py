"""Pinned SSH fallback for one bounded FortiPAM recurring Schedule create.

FortiPAM 1.9.1 documents User Management schedules and their recurring window
semantics. The catalog exposes Schedule routes but no POST request-body schema.
This module therefore creates only one unattached, laboratory-prefixed recurring
Schedule using a fixed Monday maintenance window. It never assigns the Schedule
to a User, Role, approval policy, Firewall Policy, Folder, Secret, or session.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_SCHEDULE_"
SCHEDULE_NAME_PREFIX = "mcp-v4-schedule-"
SCHEDULE_CONFIGURATION = "recurring-monday-0100-0130-unattached-v1"
_CONFIG_COMMAND = "config firewall schedule recurring"
_NAME = re.compile(r"mcp-v4-schedule-[A-Za-z0-9][A-Za-z0-9._-]{0,14}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_UNAVAILABLE = "FortiPAM V4 Schedule transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_SCHEDULE_SETTINGS = (
    "set start 01:00",
    "set end 01:30",
    "set day monday",
    "set color 0",
)


class ScheduleSshTransportError(RuntimeError):
    """Stable non-disclosing failure for the bounded Schedule transport."""


class ScheduleSshTransportConfigurationError(ValueError):
    """Raised when dedicated Schedule SSH settings are unsafe."""


@dataclass(frozen=True, slots=True)
class ScheduleSshTransportConfig:
    """Dedicated pinned SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise ScheduleSshTransportConfigurationError(
                "The Schedule SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise ScheduleSshTransportConfigurationError(
                "The Schedule SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise ScheduleSshTransportConfigurationError(
                "The Schedule SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise ScheduleSshTransportConfigurationError(
                "The Schedule SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.password
        ):
            raise ScheduleSshTransportConfigurationError(
                "The Schedule SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class ScheduleInspection:
    """Value-minimized preflight evidence for one recurring Schedule."""

    schedule_name_exists: bool


@dataclass(frozen=True, slots=True)
class ScheduleReadback:
    """Categorical readback for the fixed recurring Schedule contract."""

    schedule_name_exists: bool
    fixed_start_present: bool
    fixed_end_present: bool
    monday_present: bool
    color_zero_present: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.schedule_name_exists,
                self.fixed_start_present,
                self.fixed_end_present,
                self.monday_present,
                self.color_zero_present,
            )
        )


def load_schedule_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> ScheduleSshTransportConfig:
    """Load only independently scoped Schedule SSH credentials."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise ScheduleSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise ScheduleSshTransportConfigurationError(
            "Dedicated Schedule SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise ScheduleSshTransportConfigurationError(
            "The Schedule SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return ScheduleSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamScheduleSshTransport:
    """Run only compiled recurring Schedule inspection and creation commands."""

    def __init__(self, config: ScheduleSshTransportConfig) -> None:
        self._config = config

    def inspect(self, schedule_name: str) -> ScheduleInspection:
        safe_name = _schedule_name(schedule_name)
        return cast(ScheduleInspection, _run_sync(self._inspect(safe_name)))

    def create_and_readback(self, schedule_name: str) -> ScheduleReadback:
        safe_name = _schedule_name(schedule_name)
        return cast(
            ScheduleReadback,
            _run_sync(self._create_and_readback(safe_name)),
        )

    def readback_existing(self, schedule_name: str) -> ScheduleReadback:
        """Return the complete fixed projection without changing the Schedule."""

        safe_name = _schedule_name(schedule_name)
        return cast(
            ScheduleReadback,
            _run_sync(self._readback_existing(safe_name)),
        )

    def reference_count(self, schedule_name: str) -> int:
        """Return a strictly parsed fixed Schedule CMDB reference count."""

        safe_name = _schedule_name(schedule_name)
        return cast(int, _run_sync(self._reference_count(safe_name)))

    async def _inspect(self, schedule_name: str) -> ScheduleInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_schedule(
                    process,
                    root_prompt,
                    schedule_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return ScheduleInspection(
            schedule_name_exists=_schedule_marker(schedule_name)
            in output.replace(b"\r", b"")
        )

    async def _create_and_readback(self, schedule_name: str) -> ScheduleReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_schedule(
                    process,
                    root_prompt,
                    schedule_name,
                    deadline,
                )
                output = await self._show_schedule(
                    process,
                    root_prompt,
                    schedule_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, schedule_name)

    async def _readback_existing(self, schedule_name: str) -> ScheduleReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_schedule(
                    process,
                    root_prompt,
                    schedule_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, schedule_name)

    async def _reference_count(self, schedule_name: str) -> int:
        command = (
            "diagnose sys cmdb refcnt show firewall.schedule.recurring.name "
            + schedule_name
        )
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await _send_and_read(
                    process,
                    command,
                    root_prompt,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _strict_reference_count(output, command, root_prompt)

    async def _create_schedule(
        self,
        process: Any,
        root_prompt: bytes,
        schedule_name: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            schedule_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{schedule_name}"',
                root_prompt,
                deadline,
            )
            for command in _SCHEDULE_SETTINGS:
                await _send_and_read(process, command, schedule_prompt, deadline)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise ScheduleSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ScheduleSshTransportError(_UNAVAILABLE) from exc

    async def _show_schedule(
        self,
        process: Any,
        root_prompt: bytes,
        schedule_name: str,
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
                f"show | grep {schedule_name}",
                table_prompt,
                deadline,
            )
            full = await _send_and_read(
                process,
                f"show | grep {schedule_name} -f",
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
            raise ScheduleSshTransportError(_UNAVAILABLE) from exc

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
                term_size=(200, 24),
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
            raise ScheduleSshTransportError(_UNAVAILABLE) from exc


def _readback(output: bytes, schedule_name: str) -> ScheduleReadback:
    normalized = output.replace(b"\r", b"")
    schedule_marker = _schedule_marker(schedule_name)
    color_zero_present = b"set color 0" in normalized or (
        schedule_marker in normalized and b"set color" not in normalized
    )
    return ScheduleReadback(
        schedule_name_exists=schedule_marker in normalized,
        fixed_start_present=b"set start 01:00" in normalized,
        fixed_end_present=b"set end 01:30" in normalized,
        monday_present=b"set day monday" in normalized,
        # FortiPAM omits the fixed color when it holds its zero/default value
        # even in the requested full Schedule projection. A non-default color
        # remains explicit and therefore fails this fixed-zero contract.
        color_zero_present=color_zero_present,
    )


def _schedule_marker(schedule_name: str) -> bytes:
    return f'edit "{schedule_name}"'.encode("ascii")


def _strict_reference_count(output: bytes, command: str, root_prompt: bytes) -> int:
    normalized = output.replace(b"\r", b"")
    lines = normalized.split(b"\n")
    if (
        len(lines) < 2
        or lines[0].strip() != command.encode("ascii")
        or lines[-1].rstrip(b" ") != root_prompt
    ):
        raise ScheduleSshTransportError(_UNAVAILABLE)
    middle = [line for line in lines[1:-1] if line.strip()]
    if any(b"entry used by" not in line.lower() for line in middle):
        raise ScheduleSshTransportError(_UNAVAILABLE)
    return len(middle)


def _schedule_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise ScheduleSshTransportError(_UNAVAILABLE)
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
        raise ScheduleSshTransportConfigurationError(
            f"The Schedule SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ScheduleSshTransportConfigurationError(
            f"The Schedule SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ScheduleSshTransportConfigurationError(
            f"The Schedule SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ScheduleSshTransportConfigurationError(
            "The Schedule SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScheduleSshTransportConfigurationError(
            "The Schedule SSH password file is invalid."
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
    except ScheduleSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise ScheduleSshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "ENV_PREFIX",
    "FortiPamScheduleSshTransport",
    "SCHEDULE_CONFIGURATION",
    "SCHEDULE_NAME_PREFIX",
    "ScheduleInspection",
    "ScheduleReadback",
    "ScheduleSshTransportConfig",
    "ScheduleSshTransportConfigurationError",
    "ScheduleSshTransportError",
    "load_schedule_ssh_transport_config",
]
