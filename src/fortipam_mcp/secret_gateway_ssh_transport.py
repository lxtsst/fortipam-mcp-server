"""Pinned SSH fallback for one bounded FortiPAM Secret Gateway create.

The FortiPAM API catalog lists Secret Gateway routes but does not establish a
FortiPAM 1.9.1 REST request body. This module therefore implements only the
Administration Guide's fixed, disabled Forward Gateway shape. It never binds a
Target or Secret, enables forwarding, configures a gateway chain, or changes a
certificate, CA, SNI, reverse service, or session.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_SECRET_GATEWAY_"
SECRET_GATEWAY_NAME_PREFIX = "mcp-v4-secret-gateway-"
SECRET_GATEWAY_CONFIGURATION = "disabled-forward-documentation-ipv4-v1"
_CONFIG_COMMAND = "config secret gateway"
_NAME = re.compile(r"mcp-v4-secret-gateway-[A-Za-z0-9][A-Za-z0-9._-]{0,37}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_UNAVAILABLE = "FortiPAM V4 Secret Gateway transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_DOCUMENTATION_ADDRESS = "192.0.2.1"
_DESCRIPTION = "MCP V4 disabled forward gateway"
_SETTINGS = (
    "set status disable",
    "set type forward",
    f'set address "{_DOCUMENTATION_ADDRESS}"',
    "set port 443",
    'set url-map "tcp"',
    "set ssl-max-version tls-1.3",
    f'set description "{_DESCRIPTION}"',
)


class SecretGatewaySshTransportError(RuntimeError):
    """Stable non-disclosing failure for the bounded SSH transport."""


class SecretGatewaySshTransportConfigurationError(ValueError):
    """Raised when dedicated Secret Gateway SSH settings are unsafe."""


@dataclass(frozen=True, slots=True)
class SecretGatewaySshTransportConfig:
    """Dedicated pinned SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise SecretGatewaySshTransportConfigurationError(
                "The Secret Gateway SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise SecretGatewaySshTransportConfigurationError(
                "The Secret Gateway SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise SecretGatewaySshTransportConfigurationError(
                "The Secret Gateway SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise SecretGatewaySshTransportConfigurationError(
                "The Secret Gateway SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise SecretGatewaySshTransportConfigurationError(
                "The Secret Gateway SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class SecretGatewayInspection:
    """Value-minimized preflight evidence for one Secret Gateway."""

    gateway_name_exists: bool


@dataclass(frozen=True, slots=True)
class SecretGatewayReadback:
    """Categorical readback for the fixed disabled Forward Gateway contract."""

    gateway_name_exists: bool
    status_disabled: bool
    forward_type_enabled: bool
    documentation_address_matches: bool
    port_443_enabled: bool
    tcp_url_map_enabled: bool
    tls_1_3_maximum_enabled: bool
    description_matches: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.gateway_name_exists,
                self.status_disabled,
                self.forward_type_enabled,
                self.documentation_address_matches,
                self.port_443_enabled,
                self.tcp_url_map_enabled,
                self.tls_1_3_maximum_enabled,
                self.description_matches,
            )
        )


def load_secret_gateway_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> SecretGatewaySshTransportConfig:
    """Load only independently scoped Secret Gateway SSH credentials."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise SecretGatewaySshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise SecretGatewaySshTransportConfigurationError(
            "Dedicated Secret Gateway SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise SecretGatewaySshTransportConfigurationError(
            "The Secret Gateway SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return SecretGatewaySshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamSecretGatewaySshTransport:
    """Run only compiled Secret Gateway inspection and create commands."""

    def __init__(self, config: SecretGatewaySshTransportConfig) -> None:
        self._config = config

    def inspect(self, gateway_name: str) -> SecretGatewayInspection:
        safe_name = _gateway_name(gateway_name)
        return cast(SecretGatewayInspection, _run_sync(self._inspect(safe_name)))

    def create_and_readback(self, gateway_name: str) -> SecretGatewayReadback:
        safe_name = _gateway_name(gateway_name)
        return cast(
            SecretGatewayReadback,
            _run_sync(self._create_and_readback(safe_name)),
        )

    async def _inspect(self, gateway_name: str) -> SecretGatewayInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_gateway(
                    process,
                    root_prompt,
                    gateway_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return SecretGatewayInspection(
            gateway_name_exists=_gateway_marker(gateway_name)
            in output.replace(b"\r", b"")
        )

    async def _create_and_readback(self, gateway_name: str) -> SecretGatewayReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_gateway(
                    process,
                    root_prompt,
                    gateway_name,
                    deadline,
                )
                output = await self._show_gateway(
                    process,
                    root_prompt,
                    gateway_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, gateway_name)

    async def _create_gateway(
        self,
        process: Any,
        root_prompt: bytes,
        gateway_name: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            gateway_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{gateway_name}"',
                root_prompt,
                deadline,
            )
            for command in _SETTINGS:
                await _send_and_read(process, command, gateway_prompt, deadline)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise SecretGatewaySshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise SecretGatewaySshTransportError(_UNAVAILABLE) from exc

    async def _show_gateway(
        self,
        process: Any,
        root_prompt: bytes,
        gateway_name: str,
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
                f"show | grep {gateway_name}",
                table_prompt,
                deadline,
            )
            full = await _send_and_read(
                process,
                f"show | grep {gateway_name} -f",
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
            raise SecretGatewaySshTransportError(_UNAVAILABLE) from exc

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
            raise SecretGatewaySshTransportError(_UNAVAILABLE) from exc


def _readback(output: bytes, gateway_name: str) -> SecretGatewayReadback:
    normalized = output.replace(b"\r", b"")
    return SecretGatewayReadback(
        gateway_name_exists=_gateway_marker(gateway_name) in normalized,
        status_disabled=_setting_present(normalized, "status", "disable"),
        forward_type_enabled=_setting_present(normalized, "type", "forward"),
        documentation_address_matches=_setting_present(
            normalized,
            "address",
            _DOCUMENTATION_ADDRESS,
        ),
        port_443_enabled=_setting_present(normalized, "port", "443"),
        tcp_url_map_enabled=_setting_present(normalized, "url-map", "tcp"),
        tls_1_3_maximum_enabled=_setting_present(
            normalized,
            "ssl-max-version",
            "tls-1.3",
        ),
        description_matches=_setting_present(normalized, "description", _DESCRIPTION),
    )


def _gateway_marker(gateway_name: str) -> bytes:
    return f'edit "{gateway_name}"'.encode("ascii")


def _setting_present(output: bytes, setting: str, value: str) -> bool:
    escaped_setting = re.escape(setting.encode("ascii"))
    escaped_value = re.escape(value.encode("ascii"))
    pattern = (
        rb"(?m)^\s*set\s+"
        + escaped_setting
        + rb"\s+(?:"
        + escaped_value
        + rb'|"'
        + escaped_value
        + rb'"|\''
        + escaped_value
        + rb"')\s*$"
    )
    return re.search(pattern, output) is not None


def _gateway_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise SecretGatewaySshTransportError(_UNAVAILABLE)
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
        raise SecretGatewaySshTransportConfigurationError(
            f"The Secret Gateway SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SecretGatewaySshTransportConfigurationError(
            f"The Secret Gateway SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise SecretGatewaySshTransportConfigurationError(
            f"The Secret Gateway SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SecretGatewaySshTransportConfigurationError(
            "The Secret Gateway SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SecretGatewaySshTransportConfigurationError(
            "The Secret Gateway SSH password file is invalid."
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
    except SecretGatewaySshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise SecretGatewaySshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "ENV_PREFIX",
    "SECRET_GATEWAY_CONFIGURATION",
    "SECRET_GATEWAY_NAME_PREFIX",
    "FortiPamSecretGatewaySshTransport",
    "SecretGatewayInspection",
    "SecretGatewayReadback",
    "SecretGatewaySshTransportConfig",
    "SecretGatewaySshTransportConfigurationError",
    "SecretGatewaySshTransportError",
    "load_secret_gateway_ssh_transport_config",
]
