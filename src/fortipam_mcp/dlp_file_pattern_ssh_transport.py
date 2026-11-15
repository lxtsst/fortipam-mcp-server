"""Pinned SSH transport for one bounded FortiPAM DLP file-pattern creation.

The action creates one laboratory-prefixed DLP file pattern with exactly one
``pdf`` file-type entry.  The command sequence is taken from the FortiPAM 1.9.1
Administration Guide DLP file-pattern example.  It is not a generic CLI relay
and accepts no arbitrary DLP rule, protocol, action, sensor, or file matcher.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_DLP_FILE_PATTERN_"
DLP_FILE_PATTERN_NAME_PREFIX = "mcp-v4-dlp-pattern-"
DLP_FILE_PATTERN_PROFILE = "single_pdf_file_type_v1"
_CONFIG_COMMAND = "config dlp filepattern"
_ENTRY_NAME = "pdf"
_FILE_TYPE = "pdf"
_MIN_PATTERN_ID = 1000
_MAX_PATTERN_ID = 9999
_NAME = re.compile(r"mcp-v4-dlp-pattern-[A-Za-z0-9][A-Za-z0-9._-]{0,39}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_DENIED_MESSAGE = "FortiPAM V4 DLP file-pattern transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_FULL_CONTEXT_LINES = 80


class DlpFilePatternSshTransportError(RuntimeError):
    """Stable, non-disclosing failure for the bounded SSH transport."""


class DlpFilePatternSshTransportConfigurationError(ValueError):
    """Raised when dedicated DLP file-pattern SSH settings are unsafe."""


@dataclass(frozen=True, slots=True)
class DlpFilePatternSshTransportConfig:
    """Dedicated pinned-SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise DlpFilePatternSshTransportConfigurationError(
                "The DLP file-pattern SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise DlpFilePatternSshTransportConfigurationError(
                "The DLP file-pattern SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise DlpFilePatternSshTransportConfigurationError(
                "The DLP file-pattern SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise DlpFilePatternSshTransportConfigurationError(
                "The DLP file-pattern SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise DlpFilePatternSshTransportConfigurationError(
                "The DLP file-pattern SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class DlpFilePatternInspection:
    """Value-minimized preflight evidence for one DLP file pattern."""

    pattern_id_exists: bool
    pattern_name_exists: bool


@dataclass(frozen=True, slots=True)
class DlpFilePatternReadback:
    """Categorical readback for the one fixed PDF file-pattern contract."""

    pattern_id_exists: bool
    pattern_name_matches: bool
    pdf_file_type_entry_matches: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.pattern_id_exists,
                self.pattern_name_matches,
                self.pdf_file_type_entry_matches,
            )
        )


def load_dlp_file_pattern_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> DlpFilePatternSshTransportConfig:
    """Load only independently scoped DLP file-pattern SSH credentials."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise DlpFilePatternSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise DlpFilePatternSshTransportConfigurationError(
            "Dedicated DLP file-pattern SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise DlpFilePatternSshTransportConfigurationError(
            "The DLP file-pattern SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return DlpFilePatternSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamDlpFilePatternSshTransport:
    """Run only compiled inspection and fixed PDF file-pattern creation commands."""

    def __init__(self, config: DlpFilePatternSshTransportConfig) -> None:
        self._config = config

    def inspect(self, pattern_id: int, pattern_name: str) -> DlpFilePatternInspection:
        safe_id = _pattern_id(pattern_id)
        safe_name = _pattern_name(pattern_name)
        return cast(DlpFilePatternInspection, _run_sync(self._inspect(safe_id, safe_name)))

    def create_and_readback(
        self,
        pattern_id: int,
        pattern_name: str,
    ) -> DlpFilePatternReadback:
        safe_id = _pattern_id(pattern_id)
        safe_name = _pattern_name(pattern_name)
        return cast(
            DlpFilePatternReadback,
            _run_sync(self._create_and_readback(safe_id, safe_name)),
        )

    def readback(
        self,
        pattern_id: int,
        pattern_name: str,
    ) -> DlpFilePatternReadback:
        """Read only the exact fixed PDF File Pattern projection."""

        safe_id = _pattern_id(pattern_id)
        safe_name = _pattern_name(pattern_name)
        root_output = cast(
            bytes,
            _run_sync(self._readback_from_new_session(safe_id, safe_name)),
        )
        entries_output = cast(
            bytes,
            _run_sync(self._readback_entries_from_new_session(safe_id)),
        )
        return _readback(root_output, safe_id, safe_name, entries_output)

    async def _inspect(
        self,
        pattern_id: int,
        pattern_name: str,
    ) -> DlpFilePatternInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._run_file_pattern_context(
                    process,
                    root_prompt,
                    (
                        f"show | grep {pattern_id}",
                        f"show | grep {pattern_name}",
                        (
                            "show full-configuration | grep -A "
                            f"{_FULL_CONTEXT_LINES} \"^ *edit {pattern_id}$\""
                        ),
                    ),
                    deadline,
                )
            finally:
                await _close_cli(process)
        normalized = output.replace(b"\r", b"")
        return DlpFilePatternInspection(
            pattern_id_exists=_contains_id_marker(normalized, pattern_id),
            pattern_name_exists=_name_marker(pattern_name) in normalized,
        )

    async def _create_and_readback(
        self,
        pattern_id: int,
        pattern_name: str,
    ) -> DlpFilePatternReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_pattern(
                    process,
                    root_prompt,
                    pattern_id,
                    pattern_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        root_output = await self._readback_from_new_session(pattern_id, pattern_name)
        entries_output = await self._readback_entries_from_new_session(pattern_id)
        return _readback(root_output, pattern_id, pattern_name, entries_output)

    async def _readback_from_new_session(
        self,
        pattern_id: int,
        pattern_name: str,
    ) -> bytes:
        """Read the fixed contract on a fresh SSH session after a write."""

        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._run_file_pattern_context(
                    process,
                    root_prompt,
                    (
                        f"show | grep {pattern_id}",
                        f"show | grep {pattern_name}",
                        (
                            "show full-configuration | grep -A "
                            f"{_FULL_CONTEXT_LINES} \"^ *edit {pattern_id}$\""
                        ),
                    ),
                    deadline,
                )
            finally:
                await _close_cli(process)
        return output

    async def _readback_entries_from_new_session(self, pattern_id: int) -> bytes:
        """Read only the existing File Pattern's entries context on a new session."""

        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                table_prompt = await _send_and_read_dynamic_prompt(
                    process,
                    _CONFIG_COMMAND,
                    root_prompt,
                    deadline,
                )
                entry_prompt = await _send_and_read_dynamic_prompt(
                    process,
                    f"edit {pattern_id}",
                    root_prompt,
                    deadline,
                )
                entries_prompt = await _send_and_read_dynamic_prompt(
                    process,
                    "config entries",
                    root_prompt,
                    deadline,
                )
                output = await _send_and_read(
                    process,
                    "show full-configuration",
                    entries_prompt,
                    deadline,
                )
                returned_entry = await _send_and_read_dynamic_prompt(
                    process,
                    "end",
                    root_prompt,
                    deadline,
                )
                if returned_entry != entry_prompt:
                    raise DlpFilePatternSshTransportError(_DENIED_MESSAGE)
                returned_table = await _send_and_read_dynamic_prompt(
                    process,
                    "next",
                    root_prompt,
                    deadline,
                )
                if returned_table != table_prompt:
                    raise DlpFilePatternSshTransportError(_DENIED_MESSAGE)
                returned_root = await _send_and_read_dynamic_prompt(
                    process,
                    "end",
                    root_prompt,
                    deadline,
                )
                _require_root_prompt(root_prompt, returned_root)
            except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
                raise DlpFilePatternSshTransportError(_DENIED_MESSAGE) from exc
            finally:
                await _close_cli(process)
        return output

    async def _create_pattern(
        self,
        process: Any,
        root_prompt: bytes,
        pattern_id: int,
        pattern_name: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            entry_prompt = await _send_and_read_dynamic_prompt(
                process,
                f"edit {pattern_id}",
                root_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                f'set name "{pattern_name}"',
                entry_prompt,
                deadline,
            )
            entries_prompt = await _send_and_read_dynamic_prompt(
                process,
                "config entries",
                root_prompt,
                deadline,
            )
            pdf_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{_ENTRY_NAME}"',
                root_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                "set filter-type type",
                pdf_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                f"set file-type {_FILE_TYPE}",
                pdf_prompt,
                deadline,
            )
            returned_entries = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_entries != entries_prompt:
                raise DlpFilePatternSshTransportError(_DENIED_MESSAGE)
            returned_entry = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            if returned_entry != entry_prompt:
                raise DlpFilePatternSshTransportError(_DENIED_MESSAGE)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise DlpFilePatternSshTransportError(_DENIED_MESSAGE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise DlpFilePatternSshTransportError(_DENIED_MESSAGE) from exc

    async def _run_file_pattern_context(
        self,
        process: Any,
        root_prompt: bytes,
        commands: tuple[str, ...],
        deadline: float,
    ) -> bytes:
        try:
            context_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            outputs = [
                await _send_and_read(process, command, context_prompt, deadline)
                for command in commands
            ]
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
            return b"".join(outputs)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise DlpFilePatternSshTransportError(_DENIED_MESSAGE) from exc

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
            raise DlpFilePatternSshTransportError(_DENIED_MESSAGE) from exc


def _readback(
    output: bytes,
    pattern_id: int,
    pattern_name: str,
    entries_output: bytes | None = None,
) -> DlpFilePatternReadback:
    normalized = output.replace(b"\r", b"")
    normalized_entries = (
        normalized if entries_output is None else entries_output.replace(b"\r", b"")
    )
    return DlpFilePatternReadback(
        pattern_id_exists=_contains_id_marker(normalized, pattern_id),
        pattern_name_matches=_name_marker(pattern_name) in normalized,
        pdf_file_type_entry_matches=all(
            marker in normalized_entries
            for marker in (
                b"set filter-type type",
                f"set file-type {_FILE_TYPE}".encode("ascii"),
            )
        ),
    )


def _contains_id_marker(output: bytes, pattern_id: int) -> bool:
    """Match only a rendered File Pattern entry, never a command echo."""

    marker = re.compile(
        rb"^ *edit " + str(pattern_id).encode("ascii") + rb"$",
        re.MULTILINE,
    )
    return marker.search(output) is not None


def _name_marker(pattern_name: str) -> bytes:
    return f'set name "{pattern_name}"'.encode("ascii")


def _pattern_id(value: int) -> int:
    if type(value) is not int or not _MIN_PATTERN_ID <= value <= _MAX_PATTERN_ID:
        raise DlpFilePatternSshTransportError(_DENIED_MESSAGE)
    return value


def _pattern_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise DlpFilePatternSshTransportError(_DENIED_MESSAGE)
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
        raise DlpFilePatternSshTransportConfigurationError(
            f"The DLP file-pattern SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise DlpFilePatternSshTransportConfigurationError(
            f"The DLP file-pattern SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise DlpFilePatternSshTransportConfigurationError(
            f"The DLP file-pattern SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise DlpFilePatternSshTransportConfigurationError(
            "The DLP file-pattern SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DlpFilePatternSshTransportConfigurationError(
            "The DLP file-pattern SSH password file is invalid."
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
    except DlpFilePatternSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise DlpFilePatternSshTransportError(_DENIED_MESSAGE) from exc


__all__ = [
    "DLP_FILE_PATTERN_NAME_PREFIX",
    "DLP_FILE_PATTERN_PROFILE",
    "DlpFilePatternInspection",
    "DlpFilePatternReadback",
    "DlpFilePatternSshTransportConfig",
    "DlpFilePatternSshTransportConfigurationError",
    "DlpFilePatternSshTransportError",
    "ENV_PREFIX",
    "FortiPamDlpFilePatternSshTransport",
    "load_dlp_file_pattern_ssh_transport_config",
]
