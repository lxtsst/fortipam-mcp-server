"""Pinned SSH fallback for one bounded FortiPAM client-integrity precondition.

The FortiPAM API catalog lists Client Software routes but does not establish a
1.9.1 REST request body. This module therefore implements only the
Administration Guide's documented Client Software CLI example: one named x64
PuTTY package with certificate integrity checking and an external download
source. It never binds the entry to a Launcher or Template, creates no Secret,
and cannot make any session subject to integrity enforcement by itself.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_CLIENT_INTEGRITY_"
CLIENT_INTEGRITY_NAME_PREFIX = "mcp-v4-client-integrity-"
CLIENT_INTEGRITY_CONFIGURATION = "putty-x64-external-certificate-v1"
_CONFIG_COMMAND = "config secret client-software"
_PACKAGE_CONTEXT = "config pkg"
_PACKAGE_NAME = "x64"
_NAME = re.compile(r"mcp-v4-client-integrity-[A-Za-z0-9][A-Za-z0-9._-]{0,37}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_UNAVAILABLE = "FortiPAM V4 client-integrity transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_INTEGRITY_COMMAND = "set integrity-check cert"
_DOWNLOAD_COMMAND = "set download-option external"
_EXTERNAL_URL_COMMAND = (
    'set external-url "https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe"'
)
_CA_COMMAND = 'set ca "Fortinet_SSL"'
_CLIENT_NAME_COMMAND = 'set client-name "putty"'
_EDIT_LINE = re.compile(
    rb"(?m)^(?P<indent>\s*)edit\s+(?:\"(?P<quoted>[A-Za-z0-9._-]+)\"|(?P<bare>[A-Za-z0-9._-]+))\s*$"
)


class ClientIntegritySshTransportError(RuntimeError):
    """Stable, non-disclosing failure for the bounded SSH transport."""


class ClientIntegritySshTransportConfigurationError(ValueError):
    """Raised when dedicated client-integrity SSH settings are unsafe."""


@dataclass(frozen=True, slots=True)
class ClientIntegritySshTransportConfig:
    """Dedicated pinned SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise ClientIntegritySshTransportConfigurationError(
                "The client-integrity SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise ClientIntegritySshTransportConfigurationError(
                "The client-integrity SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise ClientIntegritySshTransportConfigurationError(
                "The client-integrity SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise ClientIntegritySshTransportConfigurationError(
                "The client-integrity SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.password
        ):
            raise ClientIntegritySshTransportConfigurationError(
                "The client-integrity SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class ClientIntegrityInspection:
    """Value-minimized preflight evidence for one client software entry."""

    client_software_name_exists: bool


@dataclass(frozen=True, slots=True)
class ClientIntegrityReadback:
    """Categorical readback for the fixed client-integrity precondition."""

    client_software_name_exists: bool
    x64_package_present: bool
    certificate_integrity_check_enabled: bool
    external_download_enabled: bool
    external_url_matches: bool
    ca_certificate_matches: bool
    putty_client_name_matches: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.client_software_name_exists,
                self.x64_package_present,
                self.certificate_integrity_check_enabled,
                self.external_download_enabled,
                self.external_url_matches,
                self.ca_certificate_matches,
                self.putty_client_name_matches,
            )
        )


def load_client_integrity_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> ClientIntegritySshTransportConfig:
    """Load only independently scoped client-integrity SSH credentials."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise ClientIntegritySshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise ClientIntegritySshTransportConfigurationError(
            "Dedicated client-integrity SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise ClientIntegritySshTransportConfigurationError(
            "The client-integrity SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return ClientIntegritySshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamClientIntegritySshTransport:
    """Run only compiled Client Software inspection and create commands."""

    def __init__(self, config: ClientIntegritySshTransportConfig) -> None:
        self._config = config

    def inspect(self, client_software_name: str) -> ClientIntegrityInspection:
        safe_name = _client_software_name(client_software_name)
        return cast(ClientIntegrityInspection, _run_sync(self._inspect(safe_name)))

    def create_and_readback(self, client_software_name: str) -> ClientIntegrityReadback:
        safe_name = _client_software_name(client_software_name)
        return cast(
            ClientIntegrityReadback,
            _run_sync(self._create_and_readback(safe_name)),
        )

    async def _inspect(self, client_software_name: str) -> ClientIntegrityInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                compact, full = await self._show_client_software(
                    process,
                    root_prompt,
                    client_software_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        marker = _client_software_marker(client_software_name)
        return ClientIntegrityInspection(marker in compact or marker in full)

    async def _create_and_readback(
        self,
        client_software_name: str,
    ) -> ClientIntegrityReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_client_software(
                    process,
                    root_prompt,
                    client_software_name,
                    deadline,
                )
                _, full = await self._show_client_software(
                    process,
                    root_prompt,
                    client_software_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(full, client_software_name)

    async def _create_client_software(
        self,
        process: Any,
        root_prompt: bytes,
        client_software_name: str,
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
                f'edit "{client_software_name}"',
                root_prompt,
                deadline,
            )
            package_table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _PACKAGE_CONTEXT,
                root_prompt,
                deadline,
            )
            package_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{_PACKAGE_NAME}"',
                root_prompt,
                deadline,
            )
            for command in (
                _INTEGRITY_COMMAND,
                _DOWNLOAD_COMMAND,
                _EXTERNAL_URL_COMMAND,
                _CA_COMMAND,
                _CLIENT_NAME_COMMAND,
            ):
                await _send_and_read(process, command, package_prompt, deadline)
            returned_package_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_package_table != package_table_prompt:
                raise ClientIntegritySshTransportError(_UNAVAILABLE)
            returned_entry = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            if returned_entry != entry_prompt:
                raise ClientIntegritySshTransportError(_UNAVAILABLE)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise ClientIntegritySshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ClientIntegritySshTransportError(_UNAVAILABLE) from exc

    async def _show_client_software(
        self,
        process: Any,
        root_prompt: bytes,
        client_software_name: str,
        deadline: float,
    ) -> tuple[bytes, bytes]:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            compact = await _send_and_read(
                process,
                f"show | grep {client_software_name}",
                table_prompt,
                deadline,
            )
            full = await _send_and_read(
                process,
                f"show | grep {client_software_name} -f",
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
            raise ClientIntegritySshTransportError(_UNAVAILABLE) from exc

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
                term_size=(80, 24),
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
            raise ClientIntegritySshTransportError(_UNAVAILABLE) from exc


def _readback(output: bytes, client_software_name: str) -> ClientIntegrityReadback:
    try:
        object_block = _named_block(output, client_software_name)
        package_block = _named_block(object_block, _PACKAGE_NAME)
    except ValueError:
        return ClientIntegrityReadback(False, False, False, False, False, False, False)
    return ClientIntegrityReadback(
        client_software_name_exists=True,
        x64_package_present=True,
        certificate_integrity_check_enabled=_setting_present(
            package_block,
            _INTEGRITY_COMMAND,
        ),
        external_download_enabled=_setting_present(
            package_block,
            _DOWNLOAD_COMMAND,
        ),
        external_url_matches=_setting_present(package_block, _EXTERNAL_URL_COMMAND),
        ca_certificate_matches=_setting_present(package_block, _CA_COMMAND),
        putty_client_name_matches=_setting_present(package_block, _CLIENT_NAME_COMMAND),
    )


def _named_block(output: bytes, name: str) -> bytes:
    """Return exactly one `edit` block at matching indentation, or fail closed."""

    normalized = output.replace(b"\r", b"")
    expected = name.encode("ascii")
    lines = normalized.splitlines(keepends=True)
    blocks: list[bytes] = []
    for index, line in enumerate(lines):
        match = _EDIT_LINE.fullmatch(line.rstrip(b"\n"))
        if match is None:
            continue
        candidate = match.group("quoted") or match.group("bare")
        if candidate != expected:
            continue
        indent = match.group("indent")
        for end_index in range(index + 1, len(lines)):
            if lines[end_index].rstrip(b"\n") == indent + b"next":
                blocks.append(b"".join(lines[index : end_index + 1]))
                break
        else:
            raise ValueError("unterminated object block")
    if len(blocks) != 1:
        raise ValueError("object block is absent or ambiguous")
    return blocks[0]


def _setting_present(output: bytes, command: str) -> bool:
    pattern = re.compile(
        rb"(?m)^\s*" + re.escape(command.encode("ascii")) + rb"\s*$"
    )
    return pattern.search(output.replace(b"\r", b"")) is not None


def _client_software_marker(client_software_name: str) -> bytes:
    return f'edit "{client_software_name}"'.encode("ascii")


def _client_software_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise ClientIntegritySshTransportError(_UNAVAILABLE)
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
        raise ClientIntegritySshTransportConfigurationError(
            f"The client-integrity SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ClientIntegritySshTransportConfigurationError(
            f"The client-integrity SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ClientIntegritySshTransportConfigurationError(
            f"The client-integrity SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ClientIntegritySshTransportConfigurationError(
            "The client-integrity SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ClientIntegritySshTransportConfigurationError(
            "The client-integrity SSH password file is invalid."
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
    except ClientIntegritySshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise ClientIntegritySshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "CLIENT_INTEGRITY_CONFIGURATION",
    "CLIENT_INTEGRITY_NAME_PREFIX",
    "ClientIntegrityInspection",
    "ClientIntegrityReadback",
    "ClientIntegritySshTransportConfig",
    "ClientIntegritySshTransportConfigurationError",
    "ClientIntegritySshTransportError",
    "ENV_PREFIX",
    "FortiPamClientIntegritySshTransport",
    "load_client_integrity_ssh_transport_config",
]
