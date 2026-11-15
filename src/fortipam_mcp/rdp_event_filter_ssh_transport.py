"""Pinned SSH transport for one bounded FortiPAM RDP event-filter profile.

The action creates only one laboratory-prefixed profile with the documented
process, filesystem, and user-management event categories enabled. It is not a
generic CLI relay and cannot alter an existing profile, a Secret, a Policy, a
Target, WinRM, or a session.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_RDP_EVENT_FILTER_"
RDP_EVENT_FILTER_NAME_PREFIX = "mcp-v4-rdp-event-filter-"
RDP_EVENT_FILTER_CONFIGURATION = "all_event_categories_enabled_v1"
_CONFIG_COMMAND = "config secret event-filter-profile"
_SETTING_COMMANDS = (
    "set process-log enable",
    "set filesystem-log enable",
    "set user-management enable",
)
_NAME = re.compile(r"mcp-v4-rdp-event-filter-[A-Za-z0-9][A-Za-z0-9._-]{0,38}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_DENIED_MESSAGE = "FortiPAM V4 RDP event-filter transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_FULL_CONTEXT_LINES = 256


class RdpEventFilterSshTransportError(RuntimeError):
    """Stable, non-disclosing failure for the bounded SSH transport."""


class RdpEventFilterSshTransportConfigurationError(ValueError):
    """Raised when dedicated RDP event-filter SSH settings are unsafe."""


@dataclass(frozen=True, slots=True)
class RdpEventFilterSshTransportConfig:
    """Dedicated pinned-SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise RdpEventFilterSshTransportConfigurationError(
                "The RDP event-filter SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise RdpEventFilterSshTransportConfigurationError(
                "The RDP event-filter SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise RdpEventFilterSshTransportConfigurationError(
                "The RDP event-filter SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise RdpEventFilterSshTransportConfigurationError(
                "The RDP event-filter SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise RdpEventFilterSshTransportConfigurationError(
                "The RDP event-filter SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class RdpEventFilterInspection:
    """Value-minimized preflight evidence for one RDP event-filter profile."""

    profile_name_exists: bool


@dataclass(frozen=True, slots=True)
class RdpEventFilterReadback:
    """Categorical readback for the one fixed event-filter profile."""

    profile_name_exists: bool
    process_log_enabled: bool
    filesystem_log_enabled: bool
    user_management_enabled: bool
    user_management_directive_present: bool = False
    user_management_explicitly_disabled: bool = False

    @property
    def verified(self) -> bool:
        return all(
            (
                self.profile_name_exists,
                self.process_log_enabled,
                self.filesystem_log_enabled,
                self.user_management_enabled,
            )
        )


def load_rdp_event_filter_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> RdpEventFilterSshTransportConfig:
    """Load only independently scoped RDP event-filter SSH credentials."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise RdpEventFilterSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise RdpEventFilterSshTransportConfigurationError(
            "Dedicated RDP event-filter SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise RdpEventFilterSshTransportConfigurationError(
            "The RDP event-filter SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return RdpEventFilterSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamRdpEventFilterSshTransport:
    """Run only compiled profile inspection and fixed profile creation."""

    def __init__(self, config: RdpEventFilterSshTransportConfig) -> None:
        self._config = config

    def inspect(self, profile_name: str) -> RdpEventFilterInspection:
        safe_name = _profile_name(profile_name)
        return cast(RdpEventFilterInspection, _run_sync(self._inspect(safe_name)))

    def create_and_readback(self, profile_name: str) -> RdpEventFilterReadback:
        safe_name = _profile_name(profile_name)
        return cast(
            RdpEventFilterReadback,
            _run_sync(self._create_and_readback(safe_name)),
        )

    def readback(self, profile_name: str) -> RdpEventFilterReadback:
        """Read one fixed Profile projection without issuing a CLI mutation."""

        safe_name = _profile_name(profile_name)
        return cast(RdpEventFilterReadback, _run_sync(self._readback_only(safe_name)))

    async def _inspect(self, profile_name: str) -> RdpEventFilterInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_profile(
                    process,
                    root_prompt,
                    profile_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return RdpEventFilterInspection(
            profile_name_exists=_profile_marker(profile_name)
            in output.replace(b"\r", b"")
        )

    async def _create_and_readback(
        self,
        profile_name: str,
    ) -> RdpEventFilterReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_profile(process, root_prompt, profile_name, deadline)
                output = await self._show_profile(
                    process,
                    root_prompt,
                    profile_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, profile_name)

    async def _readback_only(self, profile_name: str) -> RdpEventFilterReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_profile(
                    process, root_prompt, profile_name, deadline
                )
            finally:
                await _close_cli(process)
        return _readback(output, profile_name)

    async def _create_profile(
        self,
        process: Any,
        root_prompt: bytes,
        profile_name: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            profile_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{profile_name}"',
                root_prompt,
                deadline,
            )
            for command in _SETTING_COMMANDS:
                await _send_and_read(process, command, profile_prompt, deadline)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise RdpEventFilterSshTransportError(_DENIED_MESSAGE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise RdpEventFilterSshTransportError(_DENIED_MESSAGE) from exc

    async def _show_profile(
        self,
        process: Any,
        root_prompt: bytes,
        profile_name: str,
        deadline: float,
    ) -> bytes:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            outputs = (
                await _send_and_read(
                    process,
                    f"show | grep {profile_name}",
                    table_prompt,
                    deadline,
                ),
                await _send_and_read(
                    process,
                    (
                        "show full-configuration | grep -A "
                        f"{_FULL_CONTEXT_LINES} \"^ *edit.*{profile_name}\""
                    ),
                    table_prompt,
                    deadline,
                ),
            )
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
            return b"".join(outputs)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise RdpEventFilterSshTransportError(_DENIED_MESSAGE) from exc

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
            raise RdpEventFilterSshTransportError(_DENIED_MESSAGE) from exc


def _readback(output: bytes, profile_name: str) -> RdpEventFilterReadback:
    normalized = output.replace(b"\r", b"")
    return RdpEventFilterReadback(
        profile_name_exists=_profile_marker(profile_name) in normalized,
        process_log_enabled=b"set process-log enable" in normalized,
        filesystem_log_enabled=b"set filesystem-log enable" in normalized,
        user_management_enabled=(
            re.search(
                rb"\bset\s+user-management(?:-log)?\s+(?:enable|monitor)\b",
                normalized,
            )
            is not None
        ),
        user_management_directive_present=b"user-management" in normalized,
        user_management_explicitly_disabled=b"set user-management disable" in normalized,
    )


def _profile_marker(profile_name: str) -> bytes:
    return f'edit "{profile_name}"'.encode("ascii")


def _profile_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise RdpEventFilterSshTransportError(_DENIED_MESSAGE)
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
        raise RdpEventFilterSshTransportConfigurationError(
            f"The RDP event-filter SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RdpEventFilterSshTransportConfigurationError(
            f"The RDP event-filter SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise RdpEventFilterSshTransportConfigurationError(
            f"The RDP event-filter SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RdpEventFilterSshTransportConfigurationError(
            "The RDP event-filter SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RdpEventFilterSshTransportConfigurationError(
            "The RDP event-filter SSH password file is invalid."
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
    except RdpEventFilterSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise RdpEventFilterSshTransportError(_DENIED_MESSAGE) from exc


__all__ = [
    "ENV_PREFIX",
    "FortiPamRdpEventFilterSshTransport",
    "RDP_EVENT_FILTER_CONFIGURATION",
    "RDP_EVENT_FILTER_NAME_PREFIX",
    "RdpEventFilterInspection",
    "RdpEventFilterReadback",
    "RdpEventFilterSshTransportConfig",
    "RdpEventFilterSshTransportConfigurationError",
    "RdpEventFilterSshTransportError",
    "load_rdp_event_filter_ssh_transport_config",
]
