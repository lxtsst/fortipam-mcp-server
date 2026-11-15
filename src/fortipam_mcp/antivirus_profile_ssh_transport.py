"""Pinned SSH transport for one bounded FortiPAM AntiVirus Profile creation.

The action creates one laboratory-prefixed profile with the documented HTTP and
SSH ``av-scan block`` settings. It is not a generic CLI relay and cannot change
existing profiles, Secrets, licensing, FortiSandbox, or other AV controls.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_ANTIVIRUS_PROFILE_"
ANTIVIRUS_PROFILE_NAME_PREFIX = "mcp-v4-av-profile-"
ANTIVIRUS_PROFILE_CONFIGURATION = "http_ssh_block_v1"
_CONFIG_COMMAND = "config antivirus profile"
_HTTP_CONTEXT = "config http"
_SSH_CONTEXT = "config ssh"
_SCAN_COMMAND = "set av-scan block"
_NAME = re.compile(r"mcp-v4-av-profile-[A-Za-z0-9][A-Za-z0-9._-]{0,39}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_DENIED_MESSAGE = "FortiPAM V4 AntiVirus Profile transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_FULL_CONTEXT_LINES = 80


class AntivirusProfileSshTransportError(RuntimeError):
    """Stable, non-disclosing failure for the bounded SSH transport."""


class AntivirusProfileSshTransportConfigurationError(ValueError):
    """Raised when dedicated AntiVirus Profile SSH settings are unsafe."""


@dataclass(frozen=True, slots=True)
class AntivirusProfileSshTransportConfig:
    """Dedicated pinned-SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise AntivirusProfileSshTransportConfigurationError(
                "The AntiVirus Profile SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise AntivirusProfileSshTransportConfigurationError(
                "The AntiVirus Profile SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise AntivirusProfileSshTransportConfigurationError(
                "The AntiVirus Profile SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise AntivirusProfileSshTransportConfigurationError(
                "The AntiVirus Profile SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise AntivirusProfileSshTransportConfigurationError(
                "The AntiVirus Profile SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class AntivirusProfileInspection:
    """Value-minimized preflight evidence for one AntiVirus Profile."""

    profile_name_exists: bool


@dataclass(frozen=True, slots=True)
class AntivirusProfileReadback:
    """Categorical readback for the one fixed HTTP/SSH block profile."""

    profile_name_exists: bool
    http_context_matches: bool
    http_scan_block_matches: bool
    ssh_context_matches: bool
    ssh_scan_block_matches: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.profile_name_exists,
                self.http_context_matches,
                self.http_scan_block_matches,
                self.ssh_context_matches,
                self.ssh_scan_block_matches,
            )
        )


def load_antivirus_profile_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> AntivirusProfileSshTransportConfig:
    """Load only independently scoped AntiVirus Profile SSH credentials."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise AntivirusProfileSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise AntivirusProfileSshTransportConfigurationError(
            "Dedicated AntiVirus Profile SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise AntivirusProfileSshTransportConfigurationError(
            "The AntiVirus Profile SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return AntivirusProfileSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamAntivirusProfileSshTransport:
    """Run only compiled profile inspection and fixed HTTP/SSH block creation."""

    def __init__(self, config: AntivirusProfileSshTransportConfig) -> None:
        self._config = config

    def inspect(self, profile_name: str) -> AntivirusProfileInspection:
        safe_name = _profile_name(profile_name)
        return cast(AntivirusProfileInspection, _run_sync(self._inspect(safe_name)))

    def create_and_readback(self, profile_name: str) -> AntivirusProfileReadback:
        safe_name = _profile_name(profile_name)
        return cast(
            AntivirusProfileReadback,
            _run_sync(self._create_and_readback(safe_name)),
        )

    def readback(self, profile_name: str) -> AntivirusProfileReadback:
        """Read one fixed Profile projection without issuing a CLI mutation."""

        safe_name = _profile_name(profile_name)
        return cast(AntivirusProfileReadback, _run_sync(self._readback_only(safe_name)))

    async def _inspect(self, profile_name: str) -> AntivirusProfileInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_profile(process, root_prompt, profile_name, deadline)
            finally:
                await _close_cli(process)
        return AntivirusProfileInspection(
            profile_name_exists=_profile_marker(profile_name) in output.replace(b"\r", b"")
        )

    async def _create_and_readback(
        self,
        profile_name: str,
    ) -> AntivirusProfileReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_profile(process, root_prompt, profile_name, deadline)
                output = await self._show_profile(process, root_prompt, profile_name, deadline)
            finally:
                await _close_cli(process)
        return _readback(output, profile_name)

    async def _readback_only(self, profile_name: str) -> AntivirusProfileReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_profile(process, root_prompt, profile_name, deadline)
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
            http_prompt = await _send_and_read_dynamic_prompt(
                process,
                _HTTP_CONTEXT,
                root_prompt,
                deadline,
            )
            await _send_and_read(process, _SCAN_COMMAND, http_prompt, deadline)
            returned_profile = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            if returned_profile != profile_prompt:
                raise AntivirusProfileSshTransportError(_DENIED_MESSAGE)
            ssh_prompt = await _send_and_read_dynamic_prompt(
                process,
                _SSH_CONTEXT,
                root_prompt,
                deadline,
            )
            await _send_and_read(process, _SCAN_COMMAND, ssh_prompt, deadline)
            returned_profile = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            if returned_profile != profile_prompt:
                raise AntivirusProfileSshTransportError(_DENIED_MESSAGE)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise AntivirusProfileSshTransportError(_DENIED_MESSAGE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise AntivirusProfileSshTransportError(_DENIED_MESSAGE) from exc

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
            raise AntivirusProfileSshTransportError(_DENIED_MESSAGE) from exc

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
            raise AntivirusProfileSshTransportError(_DENIED_MESSAGE) from exc


def _readback(output: bytes, profile_name: str) -> AntivirusProfileReadback:
    normalized = output.replace(b"\r", b"")
    http_start = normalized.find(_HTTP_CONTEXT.encode("ascii"))
    ssh_start = normalized.find(_SSH_CONTEXT.encode("ascii"))
    http_block = _context_contains_scan_block(normalized, http_start, ssh_start)
    ssh_block = _context_contains_scan_block(normalized, ssh_start, -1)
    return AntivirusProfileReadback(
        profile_name_exists=_profile_marker(profile_name) in normalized,
        http_context_matches=http_start >= 0,
        http_scan_block_matches=http_block,
        ssh_context_matches=ssh_start >= 0,
        ssh_scan_block_matches=ssh_block,
    )


def _context_contains_scan_block(output: bytes, start: int, end: int) -> bool:
    if start < 0:
        return False
    segment = output[start:] if end < 0 else output[start:end]
    return _SCAN_COMMAND.encode("ascii") in segment


def _profile_marker(profile_name: str) -> bytes:
    return f'edit "{profile_name}"'.encode("ascii")


def _profile_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise AntivirusProfileSshTransportError(_DENIED_MESSAGE)
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
        raise AntivirusProfileSshTransportConfigurationError(
            f"The AntiVirus Profile SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise AntivirusProfileSshTransportConfigurationError(
            f"The AntiVirus Profile SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AntivirusProfileSshTransportConfigurationError(
            f"The AntiVirus Profile SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AntivirusProfileSshTransportConfigurationError(
            "The AntiVirus Profile SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AntivirusProfileSshTransportConfigurationError(
            "The AntiVirus Profile SSH password file is invalid."
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
    except AntivirusProfileSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise AntivirusProfileSshTransportError(_DENIED_MESSAGE) from exc


__all__ = [
    "ANTIVIRUS_PROFILE_CONFIGURATION",
    "ANTIVIRUS_PROFILE_NAME_PREFIX",
    "AntivirusProfileInspection",
    "AntivirusProfileReadback",
    "AntivirusProfileSshTransportConfig",
    "AntivirusProfileSshTransportConfigurationError",
    "AntivirusProfileSshTransportError",
    "ENV_PREFIX",
    "FortiPamAntivirusProfileSshTransport",
    "load_antivirus_profile_ssh_transport_config",
]
