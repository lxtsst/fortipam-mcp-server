"""Pinned SSH fallback for one FortiPAM Explicit Web Proxy prerequisite.

FortiPAM 1.9.1 documents ``explicit-web-proxy`` on one system interface as a
prerequisite for Web Proxy target use.  This adapter changes only that one
setting from its documented disabled default to enabled.  It never changes an
interface address, access service, proxy port, CA certificate, VIP, route,
DNS, Secret, Target, or traffic policy.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine, Mapping
from dataclasses import dataclass, field
import os
import json
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_INTERFACE_WEB_PROXY_"
INTERFACE_WEB_PROXY_CONFIGURATION = "enable-one-existing-interface-explicit-web-proxy-v1"
INTERFACE_WEB_PROXY_ROLLBACK_CONFIGURATION = (
    "disable-one-existing-interface-explicit-web-proxy-v1"
)
_INTERFACE_CONFIG_COMMAND = "config system interface"
_EXPLICIT_WEB_PROXY_STATUS_COMMAND = (
    "show full-configuration | grep explicit-web-proxy"
)
_UNAVAILABLE = "FortiPAM V4 interface Explicit Web Proxy action is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_EDIT_LINE = re.compile(
    rb"(?P<indent>[ \t]*)edit[ \t]+(?:\"(?P<quoted>[^\"\r\n]+)\"|(?P<bare>[A-Za-z0-9][A-Za-z0-9._-]{0,63}))[ \t]*"
)
_EXPLICIT_WEB_PROXY_LINE = re.compile(
    rb"(?im)^\s*set\s+explicit-web-proxy\s+(enable|disable)\s*$"
)
_GREP_MATCH_SUFFIX = re.compile(rb"[ \t]+<---[ \t]*(?=\n|\Z)")


class InterfaceWebProxySshTransportError(RuntimeError):
    """Stable non-disclosing failure for the bounded SSH adapter."""


class InterfaceWebProxySshTransportConfigurationError(ValueError):
    """Raised when private, fixed interface settings are unsafe."""


@dataclass(frozen=True, slots=True)
class InterfaceWebProxySshTransportConfig:
    """Dedicated SSH settings and one private existing-interface reference."""

    host: str
    port: int
    username: str
    password: str = field(repr=False)
    known_hosts_file: Path
    interface_name: str
    timeout_seconds: float
    claim_directory: Path | None = None

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise InterfaceWebProxySshTransportConfigurationError(
                "The interface Web Proxy SSH host is invalid."
            )
        if not _safe_name(self.username) or not _safe_name(self.interface_name):
            raise InterfaceWebProxySshTransportConfigurationError(
                "The interface Web Proxy SSH identity or interface reference is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise InterfaceWebProxySshTransportConfigurationError(
                "The interface Web Proxy SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise InterfaceWebProxySshTransportConfigurationError(
                "The interface Web Proxy SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise InterfaceWebProxySshTransportConfigurationError(
                "The interface Web Proxy SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class InterfaceWebProxyInspection:
    """Value-minimized state required for the one safe transition."""

    selected_interface_status: str
    enabled_interface_count: int

    @property
    def exact_disabled_baseline(self) -> bool:
        return (
            self.selected_interface_status == "disable"
            and self.enabled_interface_count == 0
        )

    @property
    def exact_enabled_baseline(self) -> bool:
        return (
            self.selected_interface_status == "enable"
            and self.enabled_interface_count == 1
        )


@dataclass(frozen=True, slots=True)
class InterfaceWebProxyReadback:
    """Categorical readback of the one Explicit Web Proxy transition."""

    selected_interface_status: str
    enabled_interface_count: int

    @property
    def verified(self) -> bool:
        return (
            self.selected_interface_status == "enable"
            and self.enabled_interface_count == 1
        )

    @property
    def verified_disabled(self) -> bool:
        return (
            self.selected_interface_status == "disable"
            and self.enabled_interface_count == 0
        )


def load_interface_web_proxy_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> InterfaceWebProxySshTransportConfig:
    """Load only independently scoped, non-generic SSH configuration."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise InterfaceWebProxySshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    interface_name = _value(env, "INTERFACE_NAME")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file, interface_name}:
        raise InterfaceWebProxySshTransportConfigurationError(
            "Dedicated interface Web Proxy SSH settings and one interface reference are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise InterfaceWebProxySshTransportConfigurationError(
            "The interface Web Proxy SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    assert interface_name is not None
    return InterfaceWebProxySshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        interface_name=interface_name,
        timeout_seconds=timeout,
        claim_directory=Path(value) if (value := _value(env, "CLAIM_DIRECTORY")) else None,
    )


class FortiPamInterfaceWebProxySshTransport:
    """Run only fixed interface inspection and Explicit Web Proxy enablement."""

    def __init__(self, config: InterfaceWebProxySshTransportConfig) -> None:
        self._config = config

    def inspect(self) -> InterfaceWebProxyInspection:
        return cast(InterfaceWebProxyInspection, _run_sync(self._inspect()))

    def enable_and_readback(self) -> InterfaceWebProxyReadback:
        self._require_unconsumed("enable")
        return cast(InterfaceWebProxyReadback, _run_sync(self._enable_and_readback()))

    def disable_and_readback(self) -> InterfaceWebProxyReadback:
        self._require_unconsumed("disable")
        return cast(InterfaceWebProxyReadback, _run_sync(self._disable_and_readback()))

    def _require_unconsumed(self, direction: str) -> Path:
        """Reject missing state and any prior attempt before connecting."""
        try:
            directory = self._config.claim_directory
            if direction not in {"enable", "disable"} or directory is None or not directory.is_absolute():
                raise ValueError
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
            path = directory / f"interface-web-proxy-{direction}.claim.json"
            if os.path.lexists(path):
                raise ValueError
            return path
        except (OSError, ValueError):
            raise InterfaceWebProxySshTransportError(_UNAVAILABLE) from None

    def _reserve_claim(self, direction: str) -> None:
        """Fsync one direction-specific claim after drift checks, before CLI writes."""
        path = self._require_unconsumed(direction)
        try:
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                info = os.fstat(parent)
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise OSError
                fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
                with os.fdopen(fd, "w") as stream:
                    json.dump({"contract": "interface-web-proxy-dispatch-v1",
                               "direction": direction, "state": "reserved_nonretry"}, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.fsync(parent)
            finally:
                os.close(parent)
        except OSError:
            raise InterfaceWebProxySshTransportError(_UNAVAILABLE) from None

    async def _inspect(self) -> InterfaceWebProxyInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                selected, statuses = await self._show_interface_state(
                    process, root_prompt, deadline
                )
            finally:
                await _close_cli(process)
        return _filtered_inspection(selected, statuses, self._config.interface_name)

    async def _enable_and_readback(self) -> InterfaceWebProxyReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                selected, statuses = await self._show_interface_state(
                    process, root_prompt, deadline
                )
                current = _filtered_inspection(
                    selected, statuses, self._config.interface_name
                )
                if not current.exact_disabled_baseline:
                    raise InterfaceWebProxySshTransportError(_UNAVAILABLE)
                self._reserve_claim("enable")
                await self._enable_interface_web_proxy(process, root_prompt, deadline)
                selected, statuses = await self._show_interface_state(
                    process, root_prompt, deadline
                )
                verified = _filtered_inspection(
                    selected, statuses, self._config.interface_name
                )
            finally:
                await _close_cli(process)
        return InterfaceWebProxyReadback(
            selected_interface_status=verified.selected_interface_status,
            enabled_interface_count=verified.enabled_interface_count,
        )

    async def _disable_and_readback(self) -> InterfaceWebProxyReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                selected, statuses = await self._show_interface_state(
                    process, root_prompt, deadline
                )
                current = _filtered_inspection(
                    selected, statuses, self._config.interface_name
                )
                if not current.exact_enabled_baseline:
                    raise InterfaceWebProxySshTransportError(_UNAVAILABLE)
                self._reserve_claim("disable")
                await self._disable_interface_web_proxy(process, root_prompt, deadline)
                selected, statuses = await self._show_interface_state(
                    process, root_prompt, deadline
                )
                verified = _filtered_inspection(
                    selected, statuses, self._config.interface_name
                )
            finally:
                await _close_cli(process)
        return InterfaceWebProxyReadback(
            selected_interface_status=verified.selected_interface_status,
            enabled_interface_count=verified.enabled_interface_count,
        )

    async def _show_interface_state(
        self,
        process: Any,
        root_prompt: bytes,
        deadline: float,
    ) -> tuple[bytes, bytes]:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _INTERFACE_CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            selected = await _send_and_read(
                process,
                f"show | grep {self._config.interface_name} -f",
                table_prompt,
                deadline,
            )
            statuses = await _send_and_read(
                process,
                _EXPLICIT_WEB_PROXY_STATUS_COMMAND,
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
            return selected, statuses
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise InterfaceWebProxySshTransportError(_UNAVAILABLE) from exc

    async def _enable_interface_web_proxy(
        self,
        process: Any,
        root_prompt: bytes,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _INTERFACE_CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            entry_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{self._config.interface_name}"',
                root_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                "set explicit-web-proxy enable",
                entry_prompt,
                deadline,
            )
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise InterfaceWebProxySshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise InterfaceWebProxySshTransportError(_UNAVAILABLE) from exc

    async def _disable_interface_web_proxy(
        self,
        process: Any,
        root_prompt: bytes,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _INTERFACE_CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            entry_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{self._config.interface_name}"',
                root_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                "set explicit-web-proxy disable",
                entry_prompt,
                deadline,
            )
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise InterfaceWebProxySshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise InterfaceWebProxySshTransportError(_UNAVAILABLE) from exc

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
            raise InterfaceWebProxySshTransportError(_UNAVAILABLE) from exc


def _inspection(output: bytes, interface_name: str) -> InterfaceWebProxyInspection:
    normalized = _normalized(output)
    if _contains_failure_marker(normalized):
        raise InterfaceWebProxySshTransportError(_UNAVAILABLE)
    selected = _select_interface(normalized, interface_name)
    selected_status = _explicit_web_proxy_status(selected)
    enabled_count = len(
        [
            block
            for block in _all_config_blocks(normalized)
            if _explicit_web_proxy_status(block) == "enable"
        ]
    )
    return InterfaceWebProxyInspection(selected_status, enabled_count)


def _filtered_inspection(
    selected_output: bytes,
    status_output: bytes,
    interface_name: str,
) -> InterfaceWebProxyInspection:
    selected_normalized = _normalized(selected_output)
    status_normalized = _normalized(status_output)
    if _contains_failure_marker(selected_normalized) or _contains_failure_marker(
        status_normalized
    ):
        raise InterfaceWebProxySshTransportError(_UNAVAILABLE)
    selected_status = _explicit_web_proxy_status(
        _select_interface(selected_normalized, interface_name)
    )
    status_values = [
        match.group(1).decode("ascii").lower()
        for match in _EXPLICIT_WEB_PROXY_LINE.finditer(status_normalized)
    ]
    if not status_values:
        raise InterfaceWebProxySshTransportError(_UNAVAILABLE)
    enabled_count = status_values.count("enable")
    if selected_status == "enable" and enabled_count < 1:
        raise InterfaceWebProxySshTransportError(_UNAVAILABLE)
    return InterfaceWebProxyInspection(selected_status, enabled_count)


def _select_interface(output: bytes, interface_name: str) -> bytes:
    expected = interface_name.encode("ascii")
    blocks = [
        block
        for name, block in _all_named_config_blocks(output)
        if name == expected
    ]
    if len(blocks) != 1:
        raise InterfaceWebProxySshTransportError(_UNAVAILABLE)
    return blocks[0]


def _all_config_blocks(output: bytes) -> list[bytes]:
    return [block for _, block in _all_named_config_blocks(output)]


def _all_named_config_blocks(output: bytes) -> list[tuple[bytes, bytes]]:
    lines = output.splitlines(keepends=True)
    candidates: list[tuple[int, bytes, bytes]] = []
    for index, line in enumerate(lines):
        match = _EDIT_LINE.fullmatch(line.rstrip(b"\r\n"))
        if match is None:
            continue
        name = match.group("quoted") or match.group("bare")
        assert name is not None
        indent = match.group("indent")
        for end_index in range(index + 1, len(lines)):
            if lines[end_index].rstrip(b"\r\n") == indent + b"next":
                candidates.append(
                    (len(indent), name, b"".join(lines[index : end_index + 1]))
                )
                break
        else:
            raise InterfaceWebProxySshTransportError(_UNAVAILABLE)
    if not candidates:
        raise InterfaceWebProxySshTransportError(_UNAVAILABLE)
    shallowest = min(indent for indent, _, _ in candidates)
    return [(name, block) for indent, name, block in candidates if indent == shallowest]


def _explicit_web_proxy_status(output: bytes) -> str:
    values = {
        match.group(1).decode("ascii").lower()
        for match in _EXPLICIT_WEB_PROXY_LINE.finditer(output)
    }
    if not values:
        # The 1.9.1 guide documents Explicit Web Proxy as disabled by default.
        return "disable"
    if len(values) != 1:
        raise InterfaceWebProxySshTransportError(_UNAVAILABLE)
    return values.pop()


def _normalized(output: bytes) -> bytes:
    if len(output) > _MAX_OUTPUT_BYTES:
        raise InterfaceWebProxySshTransportError(_UNAVAILABLE)
    normalized = output.replace(b"\r", b"")
    return _GREP_MATCH_SUFFIX.sub(b"", normalized)


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
        raise InterfaceWebProxySshTransportConfigurationError(
            f"The interface Web Proxy SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise InterfaceWebProxySshTransportConfigurationError(
            f"The interface Web Proxy SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise InterfaceWebProxySshTransportConfigurationError(
            f"The interface Web Proxy SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise InterfaceWebProxySshTransportConfigurationError(
            "The interface Web Proxy SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InterfaceWebProxySshTransportConfigurationError(
            "The interface Web Proxy SSH password file is invalid."
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
    except InterfaceWebProxySshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise InterfaceWebProxySshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "ENV_PREFIX",
    "FortiPamInterfaceWebProxySshTransport",
    "INTERFACE_WEB_PROXY_CONFIGURATION",
    "INTERFACE_WEB_PROXY_ROLLBACK_CONFIGURATION",
    "InterfaceWebProxyInspection",
    "InterfaceWebProxyReadback",
    "InterfaceWebProxySshTransportConfig",
    "InterfaceWebProxySshTransportConfigurationError",
    "InterfaceWebProxySshTransportError",
    "load_interface_web_proxy_ssh_transport_config",
]
