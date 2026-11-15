"""Pinned SSH fallback for enabling existing FortiAnalyzer log delivery.

FortiPAM 1.9.1 documents ``config log fortianalyzer setting`` and the
``set status enable`` transition.  The catalog contains the matching REST
route but no request-body schema, so this adapter never guesses a REST write.
It enables only an already configured FortiAnalyzer setting whose server
binding is unchanged.  It never sets a server, upload interval, certificate,
authorization, filter, or logging category.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine, Mapping
from dataclasses import dataclass
import hashlib
import hmac
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_FORTIANALYZER_"
FORTIANALYZER_CONFIGURATION = "enable-existing-fortianalyzer-delivery-v1"
_FORTIANALYZER_CONFIG_COMMAND = "config log fortianalyzer setting"
_UNAVAILABLE = "FortiPAM V4 FortiAnalyzer action is unavailable."
_MAX_OUTPUT_BYTES = 32 * 1024
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_STATUS_LINE = re.compile(rb"(?im)^\s*set\s+status\s+(enable|disable)\s*$")
_SERVER_LINE = re.compile(rb"(?im)^\s*set\s+server\s+(.+?)\s*$")


class FortiAnalyzerSshTransportError(RuntimeError):
    """Stable non-disclosing failure for the bounded SSH adapter."""


class FortiAnalyzerSshTransportConfigurationError(ValueError):
    """Raised when private, fixed FortiAnalyzer settings are unsafe."""


@dataclass(frozen=True, slots=True)
class FortiAnalyzerSshTransportConfig:
    """Dedicated SSH settings for one bounded FortiAnalyzer enable action."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise FortiAnalyzerSshTransportConfigurationError(
                "The FortiAnalyzer SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise FortiAnalyzerSshTransportConfigurationError(
                "The FortiAnalyzer SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise FortiAnalyzerSshTransportConfigurationError(
                "The FortiAnalyzer SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise FortiAnalyzerSshTransportConfigurationError(
                "The FortiAnalyzer SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise FortiAnalyzerSshTransportConfigurationError(
                "The FortiAnalyzer SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class FortiAnalyzerInspection:
    """Value-minimized state with an internal configured-server binding digest."""

    status: str
    server_binding_digest: str | None

    @property
    def server_configured(self) -> bool:
        return self.server_binding_digest is not None

    @property
    def exact_disabled_baseline(self) -> bool:
        return self.status == "disable" and self.server_configured


@dataclass(frozen=True, slots=True)
class FortiAnalyzerReadback:
    """Categorical readback of one FortiAnalyzer delivery enable transition."""

    status: str
    server_binding_digest: str | None

    @property
    def server_configured(self) -> bool:
        return self.server_binding_digest is not None

    @property
    def verified(self) -> bool:
        return self.status == "enable" and self.server_configured


def load_fortianalyzer_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> FortiAnalyzerSshTransportConfig:
    """Load only independently scoped, non-generic SSH configuration."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise FortiAnalyzerSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise FortiAnalyzerSshTransportConfigurationError(
            "Dedicated FortiAnalyzer SSH settings are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise FortiAnalyzerSshTransportConfigurationError(
            "The FortiAnalyzer SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return FortiAnalyzerSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamFortiAnalyzerSshTransport:
    """Run only compiled FortiAnalyzer preflight and enable commands."""

    def __init__(self, config: FortiAnalyzerSshTransportConfig) -> None:
        self._config = config

    def inspect(self) -> FortiAnalyzerInspection:
        return cast(FortiAnalyzerInspection, _run_sync(self._inspect()))

    def enable_and_readback(
        self,
        *,
        expected_server_binding_digest: str,
    ) -> FortiAnalyzerReadback:
        if not _valid_binding_digest(expected_server_binding_digest):
            raise FortiAnalyzerSshTransportError(_UNAVAILABLE)
        return cast(
            FortiAnalyzerReadback,
            _run_sync(self._enable_and_readback(expected_server_binding_digest)),
        )

    async def _inspect(self) -> FortiAnalyzerInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                outputs = await self._read_settings(process, root_prompt, deadline)
            finally:
                await _close_cli(process)
        return _inspection(outputs)

    async def _enable_and_readback(
        self,
        expected_server_binding_digest: str,
    ) -> FortiAnalyzerReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                current = _inspection(await self._read_settings(process, root_prompt, deadline))
                if (
                    not current.exact_disabled_baseline
                    or current.server_binding_digest is None
                    or not hmac.compare_digest(
                        current.server_binding_digest,
                        expected_server_binding_digest,
                    )
                ):
                    raise FortiAnalyzerSshTransportError(_UNAVAILABLE)
                await self._enable_delivery(process, root_prompt, deadline)
                readback = _inspection(await self._read_settings(process, root_prompt, deadline))
            finally:
                await _close_cli(process)
        if (
            readback.server_binding_digest is None
            or not hmac.compare_digest(
                readback.server_binding_digest,
                expected_server_binding_digest,
            )
        ):
            raise FortiAnalyzerSshTransportError(_UNAVAILABLE)
        return FortiAnalyzerReadback(
            status=readback.status,
            server_binding_digest=readback.server_binding_digest,
        )

    async def _read_settings(
        self,
        process: Any,
        root_prompt: bytes,
        deadline: float,
    ) -> tuple[tuple[bytes, bytes], tuple[bytes, bytes]]:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _FORTIANALYZER_CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            status_compact = await _send_and_read(
                process,
                "show | grep status",
                table_prompt,
                deadline,
            )
            status_full = await _send_and_read(
                process,
                "show full-configuration | grep status",
                table_prompt,
                deadline,
            )
            server_compact = await _send_and_read(
                process,
                "show | grep server",
                table_prompt,
                deadline,
            )
            server_full = await _send_and_read(
                process,
                "show full-configuration | grep server",
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
            return (status_compact, status_full), (server_compact, server_full)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise FortiAnalyzerSshTransportError(_UNAVAILABLE) from exc

    async def _enable_delivery(
        self,
        process: Any,
        root_prompt: bytes,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _FORTIANALYZER_CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            await _send_and_read(process, "set status enable", table_prompt, deadline)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise FortiAnalyzerSshTransportError(_UNAVAILABLE) from exc

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
            raise FortiAnalyzerSshTransportError(_UNAVAILABLE) from exc


def _inspection(
    outputs: tuple[tuple[bytes, bytes], tuple[bytes, bytes]],
) -> FortiAnalyzerInspection:
    status_output, server_output = outputs
    return FortiAnalyzerInspection(
        status=_status(status_output),
        server_binding_digest=_server_binding_digest(server_output),
    )


def _status(output: tuple[bytes, bytes]) -> str:
    compact, full = (_normalized(value) for value in output)
    compact_values = _status_values(compact)
    full_values = _status_values(full)
    if len(full_values) != 1:
        raise FortiAnalyzerSshTransportError(_UNAVAILABLE)
    status = next(iter(full_values))
    if compact_values and compact_values != {status}:
        raise FortiAnalyzerSshTransportError(_UNAVAILABLE)
    return status


def _server_binding_digest(output: tuple[bytes, bytes]) -> str | None:
    compact, full = (_normalized(value) for value in output)
    compact_values = _server_values(compact)
    full_values = _server_values(full)
    if compact_values != full_values or len(full_values) > 1:
        raise FortiAnalyzerSshTransportError(_UNAVAILABLE)
    if not full_values:
        return None
    return hashlib.sha256(next(iter(full_values))).hexdigest()


def _status_values(output: bytes) -> set[str]:
    if _contains_failure_marker(output):
        raise FortiAnalyzerSshTransportError(_UNAVAILABLE)
    values: set[str] = set()
    for match in _STATUS_LINE.finditer(output):
        try:
            values.add(match.group(1).decode("ascii"))
        except UnicodeDecodeError as exc:
            raise FortiAnalyzerSshTransportError(_UNAVAILABLE) from exc
    return values


def _server_values(output: bytes) -> set[bytes]:
    if _contains_failure_marker(output):
        raise FortiAnalyzerSshTransportError(_UNAVAILABLE)
    values: set[bytes] = set()
    for match in _SERVER_LINE.finditer(output):
        value = match.group(1).strip()
        if value in {b'""', b"''"}:
            continue
        if (
            not value
            or len(value) > 255
            or any(character < 32 or character == 127 for character in value)
        ):
            raise FortiAnalyzerSshTransportError(_UNAVAILABLE)
        values.add(value)
    return values


def _normalized(output: bytes) -> bytes:
    if len(output) > _MAX_OUTPUT_BYTES:
        raise FortiAnalyzerSshTransportError(_UNAVAILABLE)
    return output.replace(b"\r", b"")


def _contains_failure_marker(output: bytes) -> bool:
    lowered = output.lower()
    return any(
        marker in lowered
        for marker in (
            b"permission denied",
            b"not permitted",
            b"not allowed",
            b"access denied",
            b"command fail",
            b"unknown action",
            b"unknown command",
            b"parse error",
        )
    )


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
        raise FortiAnalyzerSshTransportConfigurationError(
            f"The FortiAnalyzer SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise FortiAnalyzerSshTransportConfigurationError(
            f"The FortiAnalyzer SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise FortiAnalyzerSshTransportConfigurationError(
            f"The FortiAnalyzer SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise FortiAnalyzerSshTransportConfigurationError(
            "The FortiAnalyzer SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FortiAnalyzerSshTransportConfigurationError(
            "The FortiAnalyzer SSH password file is invalid."
        ) from exc


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _valid_binding_digest(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _run_sync(coroutine: Coroutine[Any, Any, Any]) -> Any:
    try:
        return asyncio.run(coroutine)
    except FortiAnalyzerSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise FortiAnalyzerSshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "ENV_PREFIX",
    "FORTIANALYZER_CONFIGURATION",
    "FortiAnalyzerInspection",
    "FortiAnalyzerReadback",
    "FortiAnalyzerSshTransportConfig",
    "FortiAnalyzerSshTransportConfigurationError",
    "FortiAnalyzerSshTransportError",
    "FortiPamFortiAnalyzerSshTransport",
    "load_fortianalyzer_ssh_transport_config",
]
