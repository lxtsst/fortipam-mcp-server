"""Pinned SSH fallback for enabling one preconfigured FortiPAM SNMP agent.

FortiPAM 1.9.1 documents ``config system snmp sysinfo`` for SNMP Agent
configuration, but no exact FortiPAM REST request body is established for this
object. This adapter therefore changes only the existing agent's ``status``
from ``disable`` to ``enable``. It never creates or changes an SNMP community,
SNMPv3 user, notification host, interface administrative-access setting, or
trap destination.
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
from .target_ssh_transport import _close_cli, _require_root_prompt, _send_and_read, _send_and_read_dynamic_prompt


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_SNMP_AGENT_"
SNMP_AGENT_CONFIGURATION = "enable-preconfigured-system-snmp-agent-v1"
SNMP_AGENT_ROLLBACK_CONFIGURATION = "disable-preconfigured-system-snmp-agent-v1"
_SNMP_CONFIG_COMMAND = "config system snmp sysinfo"
_UNAVAILABLE = "FortiPAM V4 SNMP agent action is unavailable."
_MAX_OUTPUT_BYTES = 32 * 1024
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_STATUS_LINE = re.compile(
    rb"(?im)^[ \t]*set[ \t]+status[ \t]+(enable|disable)"
    rb"(?:[ \t]+<---)?[ \t]*$"
)


class SnmpAgentSshTransportError(RuntimeError):
    """Stable non-disclosing failure for the bounded SSH adapter."""


class SnmpAgentSshTransportConfigurationError(ValueError):
    """Raised when private, fixed SNMP agent settings are unsafe."""


@dataclass(frozen=True, slots=True)
class SnmpAgentSshTransportConfig:
    """Dedicated SSH settings for the existing system SNMP agent only."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise SnmpAgentSshTransportConfigurationError("The SNMP agent SSH host is invalid.")
        if not _safe_name(self.username):
            raise SnmpAgentSshTransportConfigurationError("The SNMP agent SSH username is invalid.")
        if not 1 <= self.port <= 65535:
            raise SnmpAgentSshTransportConfigurationError("The SNMP agent SSH port is invalid.")
        if not 1 <= self.timeout_seconds <= 60:
            raise SnmpAgentSshTransportConfigurationError("The SNMP agent SSH timeout is invalid.")
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise SnmpAgentSshTransportConfigurationError("The SNMP agent SSH password is invalid.")
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class SnmpAgentInspection:
    """Value-minimized state of the existing system SNMP agent."""

    status: str

    @property
    def exact_disabled_baseline(self) -> bool:
        return self.status == "disable"

    @property
    def exact_enabled_baseline(self) -> bool:
        return self.status == "enable"


@dataclass(frozen=True, slots=True)
class SnmpAgentReadback:
    """Categorical readback of the one system SNMP agent transition."""

    status: str

    @property
    def verified(self) -> bool:
        return self.status == "enable"

    @property
    def verified_disabled(self) -> bool:
        return self.status == "disable"


def load_snmp_agent_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> SnmpAgentSshTransportConfig:
    """Load only independently scoped, non-generic SSH configuration."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise SnmpAgentSshTransportConfigurationError(f"{ENV_PREFIX}ENABLED must be exactly true.")
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise SnmpAgentSshTransportConfigurationError(
            "Dedicated SNMP agent SSH settings are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise SnmpAgentSshTransportConfigurationError(
            "The SNMP agent SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return SnmpAgentSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamSnmpAgentSshTransport:
    """Run only compiled system SNMP agent preflight and enable commands."""

    def __init__(self, config: SnmpAgentSshTransportConfig) -> None:
        self._config = config

    def inspect(self) -> SnmpAgentInspection:
        return cast(SnmpAgentInspection, _run_sync(self._inspect()))

    def enable_and_readback(self) -> SnmpAgentReadback:
        return cast(SnmpAgentReadback, _run_sync(self._enable_and_readback()))

    def _enable_after_external_preflight(self) -> SnmpAgentReadback:
        """Run only the fixed write/readback after an exact external drift check."""

        return cast(
            SnmpAgentReadback,
            _run_sync(self._enable_after_external_preflight_async()),
        )

    def _disable_after_external_preflight(self) -> SnmpAgentReadback:
        """Run only the fixed recovery write/readback after an API drift check."""

        return cast(
            SnmpAgentReadback,
            _run_sync(self._disable_after_external_preflight_async()),
        )

    async def _inspect(self) -> SnmpAgentInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._read_status(process, root_prompt, deadline)
            finally:
                await _close_cli(process)
        return SnmpAgentInspection(status=_status(output))

    async def _enable_and_readback(self) -> SnmpAgentReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._read_status(process, root_prompt, deadline)
                if _status(output) != "disable":
                    raise SnmpAgentSshTransportError(_UNAVAILABLE)
                await self._enable_agent(process, root_prompt, deadline)
                output = await self._read_status(process, root_prompt, deadline)
            finally:
                await _close_cli(process)
        return SnmpAgentReadback(status=_status(output))

    async def _enable_after_external_preflight_async(self) -> SnmpAgentReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._enable_agent(process, root_prompt, deadline)
                output = await self._read_status(process, root_prompt, deadline)
            finally:
                await _close_cli(process)
        return SnmpAgentReadback(status=_status(output))

    async def _disable_after_external_preflight_async(self) -> SnmpAgentReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._disable_agent(process, root_prompt, deadline)
                output = await self._read_status(process, root_prompt, deadline)
            finally:
                await _close_cli(process)
        return SnmpAgentReadback(status=_status(output))

    async def _read_status(
        self,
        process: Any,
        root_prompt: bytes,
        deadline: float,
    ) -> tuple[bytes, bytes]:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _SNMP_CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            compact = await _send_and_read(process, "show | grep status", table_prompt, deadline)
            full = await _send_and_read(
                process,
                "show full-configuration | grep status",
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
            return compact, full
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise SnmpAgentSshTransportError(_UNAVAILABLE) from exc

    async def _enable_agent(
        self,
        process: Any,
        root_prompt: bytes,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _SNMP_CONFIG_COMMAND,
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
            raise SnmpAgentSshTransportError(_UNAVAILABLE) from exc

    async def _disable_agent(
        self,
        process: Any,
        root_prompt: bytes,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _SNMP_CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            await _send_and_read(process, "set status disable", table_prompt, deadline)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise SnmpAgentSshTransportError(_UNAVAILABLE) from exc

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
            raise SnmpAgentSshTransportError(_UNAVAILABLE) from exc


def _status(output: tuple[bytes, bytes]) -> str:
    compact, full = (_normalized(value) for value in output)
    compact_values = _status_values(compact)
    full_values = _status_values(full)
    if len(full_values) != 1:
        raise SnmpAgentSshTransportError(_UNAVAILABLE)
    status = next(iter(full_values))
    if compact_values and compact_values != {status}:
        raise SnmpAgentSshTransportError(_UNAVAILABLE)
    return status


def _status_values(output: bytes) -> set[str]:
    if _contains_failure_marker(output):
        raise SnmpAgentSshTransportError(_UNAVAILABLE)
    values: set[str] = set()
    for match in _STATUS_LINE.finditer(output):
        try:
            values.add(match.group(1).decode("ascii"))
        except UnicodeDecodeError as exc:
            raise SnmpAgentSshTransportError(_UNAVAILABLE) from exc
    return values


def _normalized(output: bytes) -> bytes:
    if len(output) > _MAX_OUTPUT_BYTES:
        raise SnmpAgentSshTransportError(_UNAVAILABLE)
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
        raise SnmpAgentSshTransportConfigurationError(
            f"The SNMP agent SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SnmpAgentSshTransportConfigurationError(
            f"The SNMP agent SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise SnmpAgentSshTransportConfigurationError(
            f"The SNMP agent SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SnmpAgentSshTransportConfigurationError(
            "The SNMP agent SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SnmpAgentSshTransportConfigurationError(
            "The SNMP agent SSH password file is invalid."
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
    except SnmpAgentSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise SnmpAgentSshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "ENV_PREFIX",
    "FortiPamSnmpAgentSshTransport",
    "SNMP_AGENT_CONFIGURATION",
    "SNMP_AGENT_ROLLBACK_CONFIGURATION",
    "SnmpAgentInspection",
    "SnmpAgentReadback",
    "SnmpAgentSshTransportConfig",
    "SnmpAgentSshTransportConfigurationError",
    "SnmpAgentSshTransportError",
    "load_snmp_agent_ssh_transport_config",
]
