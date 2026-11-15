"""Pinned SSH adapter for generating one FortiPAM Secret Audit report.

FortiPAM 1.9.1 documents ``execute audit secret-access``.  The generated CSV
contains access-distribution metadata, so this adapter never returns its
content, filename, identities, Targets, Folders, Secrets, or permissions.  It
accepts no caller-controlled CLI input and treats an unrecognised command
result as reconciliation-required rather than reporting success.
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
from .secret_audit_inventory_http_transport import (
    FortiPamSecretAuditInventoryHttpTransport,
)
from .target_ssh_transport import (
    _close_cli,
    _require_root_prompt,
    _send_and_read,
)


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_SECRET_AUDIT_"
SECRET_AUDIT_CONFIGURATION = "generate-secret-access-audit-report-v1"
_GENERATE_COMMAND = "execute audit secret-access"
_UNAVAILABLE = "FortiPAM V4 Secret Audit action is unavailable."
_MAX_OUTPUT_BYTES = 32 * 1024
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_REPORT_NAME = re.compile(
    rb"\bSecretAccessAuditReport-\d{4}-\d{2}-\d{2}-\d{6}\.csv\b",
    re.IGNORECASE,
)


class SecretAuditSshTransportError(RuntimeError):
    """Stable, non-disclosing failure for the fixed Secret Audit adapter."""


class SecretAuditSshTransportConfigurationError(ValueError):
    """Raised when private, fixed Secret Audit settings are unsafe."""


@dataclass(frozen=True, slots=True)
class SecretAuditSshTransportConfig:
    """Dedicated SSH settings for one fixed report-generation operation."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise SecretAuditSshTransportConfigurationError(
                "The Secret Audit SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise SecretAuditSshTransportConfigurationError(
                "The Secret Audit SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise SecretAuditSshTransportConfigurationError(
                "The Secret Audit SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise SecretAuditSshTransportConfigurationError(
                "The Secret Audit SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.password
        ):
            raise SecretAuditSshTransportConfigurationError(
                "The Secret Audit SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class SecretAuditInspection:
    """Value-minimized preflight state for the fixed report operation."""

    cli_reachable: bool
    report_inventory_read: bool = False

    @property
    def exact_current_state(self) -> bool:
        return self.cli_reachable


@dataclass(frozen=True, slots=True)
class SecretAuditReadback:
    """Categorical evidence that the generated report name was observed only locally."""

    generated_report_name_observed: bool

    @property
    def verified(self) -> bool:
        return self.generated_report_name_observed


def load_secret_audit_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> SecretAuditSshTransportConfig:
    """Load only independently scoped, non-generic SSH configuration."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise SecretAuditSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise SecretAuditSshTransportConfigurationError(
            "Dedicated Secret Audit SSH settings are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise SecretAuditSshTransportConfigurationError(
            "The Secret Audit SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return SecretAuditSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamSecretAuditSshTransport:
    """Run only fixed preflight and Secret Audit generation commands."""

    def __init__(
        self,
        config: SecretAuditSshTransportConfig,
        *,
        inventory_reader: FortiPamSecretAuditInventoryHttpTransport | None = None,
    ) -> None:
        self._config = config
        self._inventory_reader = inventory_reader

    def inspect(self) -> SecretAuditInspection:
        return cast(SecretAuditInspection, _run_sync(self._inspect()))

    def generate_and_readback(self) -> SecretAuditReadback:
        return cast(SecretAuditReadback, _run_sync(self._generate_and_readback()))

    async def _inspect(self) -> SecretAuditInspection:
        if self._inventory_reader is not None:
            await asyncio.to_thread(self._inventory_reader.snapshot)
        async with self._connection() as connection:
            process, _root_prompt, _deadline = await self._open_cli(connection)
            await _close_cli(process)
        return SecretAuditInspection(
            cli_reachable=True,
            report_inventory_read=self._inventory_reader is not None,
        )

    async def _generate_and_readback(self) -> SecretAuditReadback:
        before = (
            await asyncio.to_thread(self._inventory_reader.snapshot)
            if self._inventory_reader is not None
            else None
        )
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._generate(process, root_prompt, deadline)
            finally:
                await _close_cli(process)
        cli_name_observed = _generated_report_name_observed(output)
        cli_name_match = _REPORT_NAME.search(_normalized(output)) if cli_name_observed else None
        if before is not None and self._inventory_reader is not None:
            for attempt in range(6):
                after = await asyncio.to_thread(self._inventory_reader.snapshot)
                new_names = after.names - before.names
                if len(new_names) == 1:
                    matches_cli_name = (
                        cli_name_match is None
                        or cli_name_match.group().decode("ascii") in new_names
                    )
                    return SecretAuditReadback(
                        generated_report_name_observed=matches_cli_name
                    )
                if len(new_names) > 1:
                    return SecretAuditReadback(generated_report_name_observed=False)
                if attempt < 5:
                    await asyncio.sleep(2)
            return SecretAuditReadback(generated_report_name_observed=False)
        return SecretAuditReadback(
            generated_report_name_observed=cli_name_observed
        )

    async def _generate(
        self,
        process: Any,
        root_prompt: bytes,
        deadline: float,
    ) -> bytes:
        try:
            return await _send_and_read(
                process,
                _GENERATE_COMMAND,
                root_prompt,
                deadline,
            )
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise SecretAuditSshTransportError(_UNAVAILABLE) from exc

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
            raise SecretAuditSshTransportError(_UNAVAILABLE) from exc


def _generated_report_name_observed(output: bytes) -> bool:
    normalized = _normalized(output)
    if _contains_failure_marker(normalized):
        raise SecretAuditSshTransportError(_UNAVAILABLE)
    return _REPORT_NAME.search(normalized) is not None


def _normalized(output: bytes) -> bytes:
    if len(output) > _MAX_OUTPUT_BYTES:
        raise SecretAuditSshTransportError(_UNAVAILABLE)
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
        raise SecretAuditSshTransportConfigurationError(
            f"The Secret Audit SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SecretAuditSshTransportConfigurationError(
            f"The Secret Audit SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise SecretAuditSshTransportConfigurationError(
            f"The Secret Audit SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SecretAuditSshTransportConfigurationError(
            "The Secret Audit SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SecretAuditSshTransportConfigurationError(
            "The Secret Audit SSH password file is invalid."
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
    except SecretAuditSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise SecretAuditSshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "ENV_PREFIX",
    "FortiPamSecretAuditSshTransport",
    "SECRET_AUDIT_CONFIGURATION",
    "SecretAuditInspection",
    "SecretAuditReadback",
    "SecretAuditSshTransportConfig",
    "SecretAuditSshTransportConfigurationError",
    "SecretAuditSshTransportError",
    "load_secret_audit_ssh_transport_config",
]
