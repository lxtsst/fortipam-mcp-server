"""Pinned SSH transport for two bounded FortiPAM DLP Sensor configurations.

The action supports either one laboratory PDF ``file-type``/``block`` Sensor
that references an existing laboratory File Pattern, or one laboratory
``regexp``/``block`` Sensor with a fixed safe sentinel expression.  Both use
the documented ``http-get`` protocol.  This is not a generic CLI relay and it
does not accept arbitrary Sensor, Filter, protocol, action, expression, or
Secret configuration.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_DLP_SENSOR_"
DLP_SENSOR_NAME_PREFIX = "mcp-v4-dlp-sensor-"
DLP_SENSOR_PROFILE = "single_http_get_pdf_block_v1"
DLP_REGEXP_SENSOR_NAME_PREFIX = "mcp-v4-dlp-regexp-sensor-"
DLP_REGEXP_SENSOR_PROFILE = "single_http_get_file_regexp_block_v1"
DLP_SFTP_AUDIT_SENSOR_NAME_PREFIX = "mcp-v4-dlp-sftp-audit-"
DLP_SFTP_AUDIT_SENSOR_PROFILE = "single_web_sftp_file_regexp_log_only_v1"
_SFTP_AUDIT_SENSOR_NAME = re.compile(
    r"mcp-v4-dlp-sftp-audit-[A-Za-z0-9][A-Za-z0-9._-]{0,12}\Z"
)
_SENSOR_CONFIG_COMMAND = "config dlp sensor"
_FILE_PATTERN_CONFIG_COMMAND = "config dlp filepattern"
_FILTER_ID = 1
_FILTER_NAME = "mcp-v4-dlp-filter-pdf-block"
_REGEXP_FILTER_NAME = "mcp-v4-dlp-filter-regexp-block"
_PROTOCOL = "http-get"
_FILTER_BY = "file-type"
_REGEXP_FILTER_BY = "regexp"
_REGEXP_FILTER_TYPE = "file"
_REGEXP_SENTINEL = "MCP_V4_DLP_REGEX_SENTINEL"
_ACTION = "block"
_MIN_PATTERN_ID = 1000
_MAX_PATTERN_ID = 9999
_SENSOR_NAME = re.compile(r"mcp-v4-dlp-sensor-[A-Za-z0-9][A-Za-z0-9._-]{0,39}\Z")
_REGEXP_SENSOR_NAME = re.compile(
    r"mcp-v4-dlp-regexp-sensor-[A-Za-z0-9][A-Za-z0-9._-]{0,32}\Z"
)
_PATTERN_NAME = re.compile(r"mcp-v4-dlp-pattern-[A-Za-z0-9][A-Za-z0-9._-]{0,39}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_DENIED_MESSAGE = "FortiPAM V4 DLP Sensor transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_FULL_CONTEXT_LINES = 80


class DlpSensorSshTransportError(RuntimeError):
    """Stable, non-disclosing failure for the bounded SSH transport."""


class DlpSensorSshTransportConfigurationError(ValueError):
    """Raised when dedicated DLP Sensor SSH settings are unsafe."""


@dataclass(frozen=True, slots=True)
class DlpSensorSshTransportConfig:
    """Dedicated pinned-SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise DlpSensorSshTransportConfigurationError(
                "The DLP Sensor SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise DlpSensorSshTransportConfigurationError(
                "The DLP Sensor SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise DlpSensorSshTransportConfigurationError(
                "The DLP Sensor SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise DlpSensorSshTransportConfigurationError(
                "The DLP Sensor SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise DlpSensorSshTransportConfigurationError(
                "The DLP Sensor SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class DlpSensorInspection:
    """Value-minimized preflight evidence for one DLP Sensor and File Pattern."""

    sensor_name_exists: bool
    file_pattern_id_exists: bool
    file_pattern_name_exists: bool
    file_pattern_binding_matches: bool


@dataclass(frozen=True, slots=True)
class DlpSensorReadback:
    """Categorical readback for the one fixed DLP Sensor filter contract."""

    sensor_name_exists: bool
    filter_id_exists: bool
    filter_name_matches: bool
    protocol_matches: bool
    filter_by_matches: bool
    file_pattern_id_matches: bool
    action_matches: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.sensor_name_exists,
                self.filter_id_exists,
                self.filter_name_matches,
                self.protocol_matches,
                self.filter_by_matches,
                self.file_pattern_id_matches,
                self.action_matches,
            )
        )


@dataclass(frozen=True, slots=True)
class DlpRegexpSensorInspection:
    """Value-minimized preflight evidence for one fixed Regexp Sensor."""

    sensor_name_exists: bool


@dataclass(frozen=True, slots=True)
class DlpRegexpSensorReadback:
    """Categorical readback for the one fixed Regexp Sensor filter."""

    sensor_name_exists: bool
    filter_id_exists: bool
    filter_name_matches: bool
    filter_type_matches: bool
    protocol_matches: bool
    filter_by_matches: bool
    regexp_matches: bool
    action_matches: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.sensor_name_exists,
                self.filter_id_exists,
                self.filter_name_matches,
                self.filter_type_matches,
                self.protocol_matches,
                self.filter_by_matches,
                self.regexp_matches,
                self.action_matches,
            )
        )


def load_dlp_sensor_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> DlpSensorSshTransportConfig:
    """Load only independently scoped DLP Sensor SSH credentials."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise DlpSensorSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise DlpSensorSshTransportConfigurationError(
            "Dedicated DLP Sensor SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise DlpSensorSshTransportConfigurationError(
            "The DLP Sensor SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return DlpSensorSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamDlpSensorSshTransport:
    """Run only compiled inspection and two fixed laboratory Sensor creates."""

    def __init__(self, config: DlpSensorSshTransportConfig) -> None:
        self._config = config

    def inspect(
        self,
        sensor_name: str,
        file_pattern_id: int,
        file_pattern_name: str,
    ) -> DlpSensorInspection:
        safe_sensor_name = _sensor_name(sensor_name)
        safe_pattern_id = _pattern_id(file_pattern_id)
        safe_pattern_name = _pattern_name(file_pattern_name)
        return cast(
            DlpSensorInspection,
            _run_sync(
                self._inspect(
                    safe_sensor_name,
                    safe_pattern_id,
                    safe_pattern_name,
                )
            ),
        )

    def create_and_readback(
        self,
        sensor_name: str,
        file_pattern_id: int,
    ) -> DlpSensorReadback:
        safe_sensor_name = _sensor_name(sensor_name)
        safe_pattern_id = _pattern_id(file_pattern_id)
        return cast(
            DlpSensorReadback,
            _run_sync(self._create_and_readback(safe_sensor_name, safe_pattern_id)),
        )

    def readback(
        self,
        sensor_name: str,
        file_pattern_id: int,
    ) -> DlpSensorReadback:
        """Read only the exact fixed PDF Sensor projection."""

        safe_sensor_name = _sensor_name(sensor_name)
        safe_pattern_id = _pattern_id(file_pattern_id)
        return cast(
            DlpSensorReadback,
            _run_sync(self._readback_sensor(safe_sensor_name, safe_pattern_id)),
        )

    def file_pattern_reference_count(self, file_pattern_id: int) -> int:
        """Count exact rendered Sensor references to one fixed File Pattern ID."""

        safe_pattern_id = _pattern_id(file_pattern_id)
        return cast(
            int,
            _run_sync(self._file_pattern_reference_count(safe_pattern_id)),
        )

    def inspect_regexp_sensor(self, sensor_name: str) -> DlpRegexpSensorInspection:
        """Inspect only the existence state for the fixed Regexp profile."""

        safe_sensor_name = _regexp_sensor_name(sensor_name)
        return cast(
            DlpRegexpSensorInspection,
            _run_sync(self._inspect_regexp_sensor(safe_sensor_name)),
        )

    def inspect_sftp_audit_sensor(self, sensor_name: str) -> DlpRegexpSensorInspection:
        """Inspect presence only for the fixed Web SFTP log-only Sensor."""

        safe_sensor_name = _sftp_audit_sensor_name(sensor_name)
        return cast(
            DlpRegexpSensorInspection,
            _run_sync(self._inspect_regexp_sensor(safe_sensor_name)),
        )

    def readback_regexp_sensor(self, sensor_name: str) -> DlpRegexpSensorReadback:
        """Read only the complete fixed Regexp Sensor projection."""

        safe_sensor_name = _regexp_sensor_name(sensor_name)
        return cast(
            DlpRegexpSensorReadback,
            _run_sync(self._readback_regexp_sensor(safe_sensor_name)),
        )

    def create_regexp_and_readback(
        self,
        sensor_name: str,
    ) -> DlpRegexpSensorReadback:
        """Create one fixed sentinel Regexp Sensor and read it back."""

        safe_sensor_name = _regexp_sensor_name(sensor_name)
        return cast(
            DlpRegexpSensorReadback,
            _run_sync(self._create_regexp_and_readback(safe_sensor_name)),
        )

    async def _inspect(
        self,
        sensor_name: str,
        file_pattern_id: int,
        file_pattern_name: str,
    ) -> DlpSensorInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                sensor_output = await self._show_context(
                    process,
                    root_prompt,
                    _SENSOR_CONFIG_COMMAND,
                    (
                        "show full-configuration | grep -A "
                        f"{_FULL_CONTEXT_LINES} \"^ *edit.*{sensor_name}\""
                    ),
                    deadline,
                )
                pattern_id_output = await self._show_context(
                    process,
                    root_prompt,
                    _FILE_PATTERN_CONFIG_COMMAND,
                    (
                        "show full-configuration | grep -A "
                        f"{_FULL_CONTEXT_LINES} \"^ *edit {file_pattern_id}$\""
                    ),
                    deadline,
                )
                pattern_name_output = await self._show_context(
                    process,
                    root_prompt,
                    _FILE_PATTERN_CONFIG_COMMAND,
                    f"show | grep {file_pattern_name}",
                    deadline,
                )
            finally:
                await _close_cli(process)
        normalized_sensor = sensor_output.replace(b"\r", b"")
        normalized_pattern_id = pattern_id_output.replace(b"\r", b"")
        normalized_pattern_name = pattern_name_output.replace(b"\r", b"")
        return DlpSensorInspection(
            sensor_name_exists=_contains_rendered_line(
                normalized_sensor, _sensor_marker(sensor_name)
            ),
            file_pattern_id_exists=_contains_rendered_line(
                normalized_pattern_id, _pattern_id_marker(file_pattern_id)
            ),
            file_pattern_name_exists=_contains_rendered_line(
                normalized_pattern_name, _pattern_name_marker(file_pattern_name)
            ),
            file_pattern_binding_matches=(
                _contains_rendered_line(
                    normalized_pattern_id, _pattern_id_marker(file_pattern_id)
                )
                and _contains_rendered_line(
                    normalized_pattern_id, _pattern_name_marker(file_pattern_name)
                )
            ),
        )

    async def _create_and_readback(
        self,
        sensor_name: str,
        file_pattern_id: int,
    ) -> DlpSensorReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_sensor(
                    process,
                    root_prompt,
                    sensor_name,
                    file_pattern_id,
                    deadline,
                )
            finally:
                await _close_cli(process)
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_context(
                    process,
                    root_prompt,
                    _SENSOR_CONFIG_COMMAND,
                    (
                        "show full-configuration | grep -A "
                        f"{_FULL_CONTEXT_LINES} \"^ *edit.*{sensor_name}\""
                    ),
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, sensor_name, file_pattern_id)

    async def _readback_sensor(
        self,
        sensor_name: str,
        file_pattern_id: int,
    ) -> DlpSensorReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_context(
                    process,
                    root_prompt,
                    _SENSOR_CONFIG_COMMAND,
                    (
                        "show full-configuration | grep -A "
                        f"{_FULL_CONTEXT_LINES} \"^ *edit.*{sensor_name}\""
                    ),
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, sensor_name, file_pattern_id)

    async def _file_pattern_reference_count(self, file_pattern_id: int) -> int:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_context(
                    process,
                    root_prompt,
                    _SENSOR_CONFIG_COMMAND,
                    (
                        "show full-configuration | grep "
                        f'"^ *set file-type {file_pattern_id}$"'
                    ),
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _file_pattern_reference_count(output, file_pattern_id)

    async def _inspect_regexp_sensor(
        self,
        sensor_name: str,
    ) -> DlpRegexpSensorInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_context(
                    process,
                    root_prompt,
                    _SENSOR_CONFIG_COMMAND,
                    (
                        "show full-configuration | grep -A "
                        f"{_FULL_CONTEXT_LINES} \"^ *edit.*{sensor_name}\""
                    ),
                    deadline,
                )
            finally:
                await _close_cli(process)
        return DlpRegexpSensorInspection(
            sensor_name_exists=_contains_rendered_line(
                output, _sensor_marker(sensor_name)
            )
        )

    async def _readback_regexp_sensor(
        self,
        sensor_name: str,
    ) -> DlpRegexpSensorReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_context(
                    process,
                    root_prompt,
                    _SENSOR_CONFIG_COMMAND,
                    (
                        "show full-configuration | grep -A "
                        f"{_FULL_CONTEXT_LINES} \"^ *edit.*{sensor_name}\""
                    ),
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _regexp_readback(output, sensor_name)

    async def _create_regexp_and_readback(
        self,
        sensor_name: str,
    ) -> DlpRegexpSensorReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_regexp_sensor(
                    process,
                    root_prompt,
                    sensor_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_context(
                    process,
                    root_prompt,
                    _SENSOR_CONFIG_COMMAND,
                    (
                        "show full-configuration | grep -A "
                        f"{_FULL_CONTEXT_LINES} \"^ *edit.*{sensor_name}\""
                    ),
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _regexp_readback(output, sensor_name)

    async def _create_sensor(
        self,
        process: Any,
        root_prompt: bytes,
        sensor_name: str,
        file_pattern_id: int,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _SENSOR_CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            sensor_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{sensor_name}"',
                root_prompt,
                deadline,
            )
            filter_prompt = await _send_and_read_dynamic_prompt(
                process,
                "config filter",
                root_prompt,
                deadline,
            )
            entry_prompt = await _send_and_read_dynamic_prompt(
                process,
                f"edit {_FILTER_ID}",
                root_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                f'set name "{_FILTER_NAME}"',
                entry_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                f"set proto {_PROTOCOL}",
                entry_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                f"set filter-by {_FILTER_BY}",
                entry_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                f"set file-type {file_pattern_id}",
                entry_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                f"set action {_ACTION}",
                entry_prompt,
                deadline,
            )
            returned_filter = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_filter != filter_prompt:
                raise DlpSensorSshTransportError(_DENIED_MESSAGE)
            returned_sensor = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            if returned_sensor != sensor_prompt:
                raise DlpSensorSshTransportError(_DENIED_MESSAGE)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise DlpSensorSshTransportError(_DENIED_MESSAGE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise DlpSensorSshTransportError(_DENIED_MESSAGE) from exc

    async def _create_regexp_sensor(
        self,
        process: Any,
        root_prompt: bytes,
        sensor_name: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _SENSOR_CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            sensor_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{sensor_name}"',
                root_prompt,
                deadline,
            )
            filter_prompt = await _send_and_read_dynamic_prompt(
                process,
                "config filter",
                root_prompt,
                deadline,
            )
            entry_prompt = await _send_and_read_dynamic_prompt(
                process,
                f"edit {_FILTER_ID}",
                root_prompt,
                deadline,
            )
            for command in (
                f'set name "{_REGEXP_FILTER_NAME}"',
                f"set type {_REGEXP_FILTER_TYPE}",
                f"set proto {_PROTOCOL}",
                f"set filter-by {_REGEXP_FILTER_BY}",
                f'set regexp "{_REGEXP_SENTINEL}"',
                f"set action {_ACTION}",
            ):
                await _send_and_read(process, command, entry_prompt, deadline)
            returned_filter = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_filter != filter_prompt:
                raise DlpSensorSshTransportError(_DENIED_MESSAGE)
            returned_sensor = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            if returned_sensor != sensor_prompt:
                raise DlpSensorSshTransportError(_DENIED_MESSAGE)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise DlpSensorSshTransportError(_DENIED_MESSAGE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise DlpSensorSshTransportError(_DENIED_MESSAGE) from exc

    async def _show_context(
        self,
        process: Any,
        root_prompt: bytes,
        context_command: str,
        show_command: str,
        deadline: float,
    ) -> bytes:
        try:
            context_prompt = await _send_and_read_dynamic_prompt(
                process,
                context_command,
                root_prompt,
                deadline,
            )
            output = await _send_and_read(
                process,
                show_command,
                context_prompt,
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
            raise DlpSensorSshTransportError(_DENIED_MESSAGE) from exc

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
            raise DlpSensorSshTransportError(_DENIED_MESSAGE) from exc


def _readback(
    output: bytes,
    sensor_name: str,
    file_pattern_id: int,
) -> DlpSensorReadback:
    normalized = output.replace(b"\r", b"")
    return DlpSensorReadback(
        sensor_name_exists=_sensor_marker(sensor_name) in normalized,
        filter_id_exists=_filter_id_marker() in normalized,
        filter_name_matches=_filter_name_marker() in normalized,
        protocol_matches=f"set proto {_PROTOCOL}".encode("ascii") in normalized,
        filter_by_matches=f"set filter-by {_FILTER_BY}".encode("ascii") in normalized,
        file_pattern_id_matches=(
            f"set file-type {file_pattern_id}".encode("ascii") in normalized
        ),
        action_matches=f"set action {_ACTION}".encode("ascii") in normalized,
    )


def _regexp_readback(output: bytes, sensor_name: str) -> DlpRegexpSensorReadback:
    """Parse only the exact fixed Regexp Sensor contract from CLI readback."""

    normalized = output.replace(b"\r", b"")
    return DlpRegexpSensorReadback(
        sensor_name_exists=_sensor_marker(sensor_name) in normalized,
        filter_id_exists=_filter_id_marker() in normalized,
        filter_name_matches=(
            f'set name "{_REGEXP_FILTER_NAME}"'.encode("ascii") in normalized
        ),
        filter_type_matches=(
            f"set type {_REGEXP_FILTER_TYPE}".encode("ascii") in normalized
        ),
        protocol_matches=f"set proto {_PROTOCOL}".encode("ascii") in normalized,
        filter_by_matches=(
            f"set filter-by {_REGEXP_FILTER_BY}".encode("ascii") in normalized
        ),
        regexp_matches=(
            f'set regexp "{_REGEXP_SENTINEL}"'.encode("ascii") in normalized
        ),
        action_matches=f"set action {_ACTION}".encode("ascii") in normalized,
    )


def _sensor_marker(sensor_name: str) -> bytes:
    return f'edit "{sensor_name}"'.encode("ascii")


def _pattern_id_marker(file_pattern_id: int) -> bytes:
    return f"edit {file_pattern_id}".encode("ascii")


def _pattern_name_marker(file_pattern_name: str) -> bytes:
    return f'set name "{file_pattern_name}"'.encode("ascii")


def _file_pattern_reference_count(output: bytes, file_pattern_id: int) -> int:
    marker = re.compile(
        rb"^ *set file-type " + str(file_pattern_id).encode("ascii") + rb"$",
        re.MULTILINE,
    )
    return len(marker.findall(output.replace(b"\r", b"")))


def _filter_id_marker() -> bytes:
    return f"edit {_FILTER_ID}".encode("ascii")


def _filter_name_marker() -> bytes:
    return f'set name "{_FILTER_NAME}"'.encode("ascii")


def _contains_rendered_line(output: bytes, marker: bytes) -> bool:
    """Match one exact CLI-rendered configuration line, never command echo."""

    return re.search(
        rb"(?m)^[ \\t]*" + re.escape(marker) + rb"[ \\t]*$",
        output.replace(b"\r", b""),
    ) is not None


def _sensor_name(value: str) -> str:
    if not isinstance(value, str) or _SENSOR_NAME.fullmatch(value) is None:
        raise DlpSensorSshTransportError(_DENIED_MESSAGE)
    return value


def _regexp_sensor_name(value: str) -> str:
    if not isinstance(value, str) or _REGEXP_SENSOR_NAME.fullmatch(value) is None:
        raise DlpSensorSshTransportError(_DENIED_MESSAGE)
    return value


def _sftp_audit_sensor_name(value: str) -> str:
    if not isinstance(value, str) or _SFTP_AUDIT_SENSOR_NAME.fullmatch(value) is None:
        raise DlpSensorSshTransportError(_DENIED_MESSAGE)
    return value


def _pattern_id(value: int) -> int:
    if type(value) is not int or not _MIN_PATTERN_ID <= value <= _MAX_PATTERN_ID:
        raise DlpSensorSshTransportError(_DENIED_MESSAGE)
    return value


def _pattern_name(value: str) -> str:
    if not isinstance(value, str) or _PATTERN_NAME.fullmatch(value) is None:
        raise DlpSensorSshTransportError(_DENIED_MESSAGE)
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
        raise DlpSensorSshTransportConfigurationError(
            f"The DLP Sensor SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise DlpSensorSshTransportConfigurationError(
            f"The DLP Sensor SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise DlpSensorSshTransportConfigurationError(
            f"The DLP Sensor SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise DlpSensorSshTransportConfigurationError(
            "The DLP Sensor SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DlpSensorSshTransportConfigurationError(
            "The DLP Sensor SSH password file is invalid."
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
    except DlpSensorSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise DlpSensorSshTransportError(_DENIED_MESSAGE) from exc


__all__ = [
    "DLP_SFTP_AUDIT_SENSOR_NAME_PREFIX",
    "DLP_SFTP_AUDIT_SENSOR_PROFILE",
    "DLP_REGEXP_SENSOR_NAME_PREFIX",
    "DLP_REGEXP_SENSOR_PROFILE",
    "DLP_SENSOR_NAME_PREFIX",
    "DLP_SENSOR_PROFILE",
    "DlpRegexpSensorInspection",
    "DlpRegexpSensorReadback",
    "DlpSensorInspection",
    "DlpSensorReadback",
    "DlpSensorSshTransportConfig",
    "DlpSensorSshTransportConfigurationError",
    "DlpSensorSshTransportError",
    "ENV_PREFIX",
    "FortiPamDlpSensorSshTransport",
    "load_dlp_sensor_ssh_transport_config",
]
