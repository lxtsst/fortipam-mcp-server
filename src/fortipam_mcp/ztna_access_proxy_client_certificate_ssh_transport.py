"""Pinned SSH adapter for one bounded FortiPAM ZTNA Access Proxy prerequisite.

FortiPAM 1.9.1 documents Access Proxy client-certificate handling as CLI-only.
This adapter changes only one protected Access Proxy's ``client-cert`` and
``empty-cert-action`` values.  It never selects an EMS tag, changes a proxy
policy, Folder, Secret, Launcher, session, or WAD debug setting.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_ZTNA_ACCESS_PROXY_"
ZTNA_ACCESS_PROXY_CONFIGURATION = "secret-level-prerequisite-only-v1"
ZTNA_MANAGED_ONLY = "managed_only"
ZTNA_MIXED_ACCESS = "mixed_access"
_ACCESS_MODES = frozenset((ZTNA_MANAGED_ONLY, ZTNA_MIXED_ACCESS))
_CONFIG_COMMAND = "config firewall access-proxy"
_UNAVAILABLE = "FortiPAM V4 ZTNA Access Proxy transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_FULL_CONTEXT_LINES = 80
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_EDIT_LINE = re.compile(
    rb"(?P<indent>[ \t]*)edit[ \t]+(?:\"(?P<quoted>[^\"\r\n]+)\"|(?P<bare>[A-Za-z0-9][A-Za-z0-9._-]{0,63}))[ \t]*"
)
_SUMMARY_LINE = re.compile(
    rb"(?:==[ \t]*)?\[[ \t]*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]{0,63})[ \t]*\][ \t]*"
)


class ZtnaAccessProxySshTransportError(RuntimeError):
    """Stable non-disclosing failure for the bounded SSH adapter."""


class ZtnaAccessProxySshTransportConfigurationError(ValueError):
    """Raised when dedicated ZTNA Access Proxy settings are unsafe."""


@dataclass(frozen=True, slots=True)
class ZtnaAccessProxySshTransportConfig:
    """Dedicated pinned SSH settings and one private Access Proxy reference."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    access_proxy_name: str
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise ZtnaAccessProxySshTransportConfigurationError(
                "The ZTNA Access Proxy SSH host is invalid."
            )
        if not _safe_name(self.username) or not _safe_name(self.access_proxy_name):
            raise ZtnaAccessProxySshTransportConfigurationError(
                "The ZTNA Access Proxy SSH identity or object reference is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise ZtnaAccessProxySshTransportConfigurationError(
                "The ZTNA Access Proxy SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise ZtnaAccessProxySshTransportConfigurationError(
                "The ZTNA Access Proxy SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise ZtnaAccessProxySshTransportConfigurationError(
                "The ZTNA Access Proxy SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class ZtnaAccessProxyInspection:
    """Value-minimized effective state of the protected Access Proxy."""

    client_certificate_mode: str
    empty_certificate_action: str

    @property
    def exact_disabled_block_baseline(self) -> bool:
        return (
            self.client_certificate_mode == "disable"
            and self.empty_certificate_action == "block"
        )


@dataclass(frozen=True, slots=True)
class ZtnaAccessProxyReadback:
    """Value-minimized verification of one fixed Access Proxy outcome."""

    client_certificate_mode: str
    empty_certificate_action: str

    def verified_for(self, endpoint_access_mode: str) -> bool:
        return (
            self.client_certificate_mode == "enable"
            and self.empty_certificate_action == _empty_certificate_action(endpoint_access_mode)
        )

    @property
    def verified_disabled_block(self) -> bool:
        """Return whether the original pre-action state was restored exactly."""

        return (
            self.client_certificate_mode == "disable"
            and self.empty_certificate_action == "block"
        )


def load_ztna_access_proxy_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> ZtnaAccessProxySshTransportConfig:
    """Load only independently scoped, protected ZTNA Access Proxy settings."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise ZtnaAccessProxySshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    access_proxy_name = _value(env, "ACCESS_PROXY_NAME")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file, access_proxy_name}:
        raise ZtnaAccessProxySshTransportConfigurationError(
            "Dedicated ZTNA Access Proxy SSH settings and one private object reference are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise ZtnaAccessProxySshTransportConfigurationError(
            "The ZTNA Access Proxy SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    assert access_proxy_name is not None
    return ZtnaAccessProxySshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        access_proxy_name=access_proxy_name,
        timeout_seconds=timeout,
    )


class FortiPamZtnaAccessProxySshTransport:
    """Run only compiled Access Proxy inspection and client-cert configuration."""

    def __init__(self, config: ZtnaAccessProxySshTransportConfig) -> None:
        self._config = config

    def inspect(self) -> ZtnaAccessProxyInspection:
        return cast(ZtnaAccessProxyInspection, _run_sync(self._inspect()))

    def configure_and_readback(self, endpoint_access_mode: str) -> ZtnaAccessProxyReadback:
        mode = _access_mode(endpoint_access_mode)
        return cast(
            ZtnaAccessProxyReadback,
            _run_sync(self._configure_and_readback(mode)),
        )

    def restore_disabled_block_and_readback(self) -> ZtnaAccessProxyReadback:
        """Restore only the accepted pre-action client-certificate state."""

        return cast(
            ZtnaAccessProxyReadback,
            _run_sync(self._restore_disabled_block_and_readback()),
        )

    async def _inspect(self) -> ZtnaAccessProxyInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._get_access_proxy(process, root_prompt, deadline)
            finally:
                await _close_cli(process)
        return _inspection(output, self._config.access_proxy_name)

    async def _configure_and_readback(
        self,
        endpoint_access_mode: str,
    ) -> ZtnaAccessProxyReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._configure_access_proxy(
                    process,
                    root_prompt,
                    endpoint_access_mode,
                    deadline,
                )
                output = await self._get_access_proxy(process, root_prompt, deadline)
            finally:
                await _close_cli(process)
        state = _inspection(output, self._config.access_proxy_name)
        return ZtnaAccessProxyReadback(
            client_certificate_mode=state.client_certificate_mode,
            empty_certificate_action=state.empty_certificate_action,
        )

    async def _restore_disabled_block_and_readback(self) -> ZtnaAccessProxyReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._restore_access_proxy(process, root_prompt, deadline)
                output = await self._get_access_proxy(process, root_prompt, deadline)
            finally:
                await _close_cli(process)
        state = _inspection(output, self._config.access_proxy_name)
        return ZtnaAccessProxyReadback(
            client_certificate_mode=state.client_certificate_mode,
            empty_certificate_action=state.empty_certificate_action,
        )

    async def _configure_access_proxy(
        self,
        process: Any,
        root_prompt: bytes,
        endpoint_access_mode: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process, _CONFIG_COMMAND, root_prompt, deadline
            )
            entry_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{self._config.access_proxy_name}"',
                root_prompt,
                deadline,
            )
            for command in (
                "set client-cert enable",
                f"set empty-cert-action {_empty_certificate_action(endpoint_access_mode)}",
            ):
                await _send_and_read(process, command, entry_prompt, deadline)
            returned_table = await _send_and_read_dynamic_prompt(
                process, "next", root_prompt, deadline
            )
            if returned_table != table_prompt:
                raise ZtnaAccessProxySshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process, "end", root_prompt, deadline
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ZtnaAccessProxySshTransportError(_UNAVAILABLE) from exc

    async def _restore_access_proxy(
        self,
        process: Any,
        root_prompt: bytes,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process, _CONFIG_COMMAND, root_prompt, deadline
            )
            entry_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{self._config.access_proxy_name}"',
                root_prompt,
                deadline,
            )
            for command in (
                "set client-cert disable",
                "set empty-cert-action block",
            ):
                await _send_and_read(process, command, entry_prompt, deadline)
            returned_table = await _send_and_read_dynamic_prompt(
                process, "next", root_prompt, deadline
            )
            if returned_table != table_prompt:
                raise ZtnaAccessProxySshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process, "end", root_prompt, deadline
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ZtnaAccessProxySshTransportError(_UNAVAILABLE) from exc

    async def _get_access_proxy(
        self,
        process: Any,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        try:
            return await _send_and_read(
                process,
                "show full-configuration firewall access-proxy | grep -A "
                f'{_FULL_CONTEXT_LINES} "^ *edit.*{self._config.access_proxy_name}"',
                root_prompt,
                deadline,
            )
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ZtnaAccessProxySshTransportError(_UNAVAILABLE) from exc

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
            raise ZtnaAccessProxySshTransportError(_UNAVAILABLE) from exc


def _inspection(output: bytes, access_proxy_name: str) -> ZtnaAccessProxyInspection:
    selected = _select_access_proxy(output, access_proxy_name)
    client = _field_value(selected, "client-cert", frozenset({"enable", "disable"}))
    empty = _field_value(
        selected,
        "empty-cert-action",
        frozenset({"accept", "block"}),
    )
    if client == "unknown" or empty == "unknown":
        raise ZtnaAccessProxySshTransportError(_UNAVAILABLE)
    return ZtnaAccessProxyInspection(client, empty)


def _select_access_proxy(output: bytes, access_proxy_name: str) -> bytes:
    normalized = _normalized(output)
    if _contains_failure_marker(normalized):
        raise ZtnaAccessProxySshTransportError(_UNAVAILABLE)
    configured = _named_config_blocks(normalized, access_proxy_name)
    if len(configured) == 1:
        return configured[0]
    if configured:
        raise ZtnaAccessProxySshTransportError(_UNAVAILABLE)
    summaries = _named_summary_blocks(normalized, access_proxy_name)
    if len(summaries) == 1:
        return summaries[0]
    raise ZtnaAccessProxySshTransportError(_UNAVAILABLE)


def _named_config_blocks(output: bytes, access_proxy_name: str) -> list[bytes]:
    expected = access_proxy_name.encode("ascii")
    lines = output.splitlines(keepends=True)
    candidates: list[tuple[int, bytes]] = []
    for index, line in enumerate(lines):
        match = _EDIT_LINE.fullmatch(line.rstrip(b"\r\n"))
        if match is None:
            continue
        candidate = match.group("quoted") or match.group("bare")
        if candidate != expected:
            continue
        indent = match.group("indent")
        for end_index in range(index + 1, len(lines)):
            if lines[end_index].rstrip(b"\r\n") == indent + b"next":
                candidates.append((len(indent), b"".join(lines[index : end_index + 1])))
                break
        else:
            raise ZtnaAccessProxySshTransportError(_UNAVAILABLE)
    if not candidates:
        return []
    shallowest = min(indent for indent, _ in candidates)
    return [block for indent, block in candidates if indent == shallowest]


def _named_summary_blocks(output: bytes, access_proxy_name: str) -> list[bytes]:
    expected = access_proxy_name.encode("ascii")
    lines = output.splitlines(keepends=True)
    starts = [
        index
        for index, line in enumerate(lines)
        if (match := _SUMMARY_LINE.fullmatch(line.rstrip(b"\r\n"))) is not None
        and match.group("name") == expected
    ]
    blocks: list[bytes] = []
    for index in starts:
        end_index = len(lines)
        for candidate in range(index + 1, len(lines)):
            if _SUMMARY_LINE.fullmatch(lines[candidate].rstrip(b"\r\n")) is not None:
                end_index = candidate
                break
        blocks.append(b"".join(lines[index:end_index]))
    return blocks


def _field_value(output: bytes, field: str, allowed: frozenset[str]) -> str:
    pattern = re.compile(
        rb"(?im)^\s*(?:set\s+)?"
        + re.escape(field.encode("ascii"))
        + rb"\s*(?::|\s)\s*([A-Za-z-]+)\b"
    )
    values = {
        match.group(1).decode("ascii").lower()
        for match in pattern.finditer(output)
        if match.group(1).decode("ascii").lower() in allowed
    }
    return values.pop() if len(values) == 1 else "unknown"


def _empty_certificate_action(endpoint_access_mode: str) -> str:
    mode = _access_mode(endpoint_access_mode)
    return "block" if mode == ZTNA_MANAGED_ONLY else "accept"


def _access_mode(value: str) -> str:
    if not isinstance(value, str) or value not in _ACCESS_MODES:
        raise ZtnaAccessProxySshTransportError(_UNAVAILABLE)
    return value


def _normalized(output: bytes) -> bytes:
    if len(output) > _MAX_OUTPUT_BYTES:
        raise ZtnaAccessProxySshTransportError(_UNAVAILABLE)
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
        raise ZtnaAccessProxySshTransportConfigurationError(
            f"The ZTNA Access Proxy SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ZtnaAccessProxySshTransportConfigurationError(
            f"The ZTNA Access Proxy SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ZtnaAccessProxySshTransportConfigurationError(
            f"The ZTNA Access Proxy SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ZtnaAccessProxySshTransportConfigurationError(
            "The ZTNA Access Proxy SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ZtnaAccessProxySshTransportConfigurationError(
            "The ZTNA Access Proxy SSH password file is invalid."
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
    except ZtnaAccessProxySshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise ZtnaAccessProxySshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "ENV_PREFIX",
    "FortiPamZtnaAccessProxySshTransport",
    "ZTNA_ACCESS_PROXY_CONFIGURATION",
    "ZTNA_MANAGED_ONLY",
    "ZTNA_MIXED_ACCESS",
    "ZtnaAccessProxyInspection",
    "ZtnaAccessProxyReadback",
    "ZtnaAccessProxySshTransportConfig",
    "ZtnaAccessProxySshTransportConfigurationError",
    "ZtnaAccessProxySshTransportError",
    "load_ztna_access_proxy_ssh_transport_config",
]
