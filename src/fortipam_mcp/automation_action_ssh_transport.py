"""Pinned SSH fallback for one bounded FortiPAM Automation Action create.

The FortiPAM 1.9.1 Administration Guide documents the Automation Action email
CLI grammar, while the catalog does not establish a REST request body. This
module creates only an unbound fixed-recipient email Action. It never creates an
Automation Stitch, so it cannot directly execute an email action.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_AUTOMATION_ACTION_"
AUTOMATION_ACTION_NAME_PREFIX = "mcp-v4-automation-action-"
AUTOMATION_ACTION_CONFIGURATION = "email-fixed-recipient-no-stitch-v1"
_CONFIG_COMMAND = "config system automation-action"
_NAME = re.compile(r"mcp-v4-automation-action-[A-Za-z0-9][A-Za-z0-9._-]{0,38}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_UNAVAILABLE = "FortiPAM V4 Automation Action transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_ACTION_SETTINGS = (
    "set action-type email",
    'set email-subject "FortiPAM V4 unbound action"',
    'set email-to "mcp-v4-no-send@example.invalid"',
    'set message "MCP V4 unbound action no stitch"',
    'set description "MCP V4 unbound automation action"',
)


class AutomationActionSshTransportError(RuntimeError):
    """Stable non-disclosing failure for the bounded SSH transport."""


class AutomationActionSshTransportConfigurationError(ValueError):
    """Raised when dedicated Automation Action SSH settings are unsafe."""


@dataclass(frozen=True, slots=True)
class AutomationActionSshTransportConfig:
    """Dedicated pinned SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise AutomationActionSshTransportConfigurationError(
                "The Automation Action SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise AutomationActionSshTransportConfigurationError(
                "The Automation Action SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise AutomationActionSshTransportConfigurationError(
                "The Automation Action SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise AutomationActionSshTransportConfigurationError(
                "The Automation Action SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise AutomationActionSshTransportConfigurationError(
                "The Automation Action SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class AutomationActionInspection:
    """Value-minimized preflight evidence for one Automation Action."""

    action_name_exists: bool


@dataclass(frozen=True, slots=True)
class AutomationActionReadback:
    """Categorical readback for the fixed unbound email Action contract."""

    action_name_exists: bool
    email_type_enabled: bool
    fixed_subject_present: bool
    fixed_recipient_present: bool
    fixed_message_present: bool
    fixed_description_present: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.action_name_exists,
                self.email_type_enabled,
                self.fixed_subject_present,
                self.fixed_recipient_present,
                self.fixed_message_present,
                self.fixed_description_present,
            )
        )


def load_automation_action_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> AutomationActionSshTransportConfig:
    """Load only independently scoped Automation Action SSH credentials."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise AutomationActionSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise AutomationActionSshTransportConfigurationError(
            "Dedicated Automation Action SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise AutomationActionSshTransportConfigurationError(
            "The Automation Action SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return AutomationActionSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamAutomationActionSshTransport:
    """Run only compiled Automation Action inspection and creation commands."""

    def __init__(self, config: AutomationActionSshTransportConfig) -> None:
        self._config = config

    def inspect(self, action_name: str) -> AutomationActionInspection:
        safe_name = _action_name(action_name)
        return cast(AutomationActionInspection, _run_sync(self._inspect(safe_name)))

    def create_and_readback(self, action_name: str) -> AutomationActionReadback:
        safe_name = _action_name(action_name)
        return cast(
            AutomationActionReadback,
            _run_sync(self._create_and_readback(safe_name)),
        )

    def readback_existing(self, action_name: str) -> AutomationActionReadback:
        """Read the fixed Action projection without changing it."""

        safe_name = _action_name(action_name)
        return cast(
            AutomationActionReadback,
            _run_sync(self._readback_existing(safe_name)),
        )

    def reference_count(self, action_name: str) -> int:
        """Return a strictly parsed fixed Action CMDB reference count."""

        safe_name = _action_name(action_name)
        return cast(int, _run_sync(self._reference_count(safe_name)))

    async def _inspect(self, action_name: str) -> AutomationActionInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_action(
                    process,
                    root_prompt,
                    action_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return AutomationActionInspection(
            action_name_exists=_action_marker(action_name)
            in output.replace(b"\r", b"")
        )

    async def _create_and_readback(self, action_name: str) -> AutomationActionReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_action(
                    process,
                    root_prompt,
                    action_name,
                    deadline,
                )
                output = await self._show_action(
                    process,
                    root_prompt,
                    action_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, action_name)

    async def _readback_existing(
        self,
        action_name: str,
    ) -> AutomationActionReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_action(
                    process,
                    root_prompt,
                    action_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, action_name)

    async def _reference_count(self, action_name: str) -> int:
        command = (
            "diagnose sys cmdb refcnt show system.automation-action.name "
            + action_name
        )
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await _send_and_read(
                    process,
                    command,
                    root_prompt,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _strict_reference_count(output, command, root_prompt)

    async def _create_action(
        self,
        process: Any,
        root_prompt: bytes,
        action_name: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            action_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{action_name}"',
                root_prompt,
                deadline,
            )
            for command in _ACTION_SETTINGS:
                await _send_and_read(process, command, action_prompt, deadline)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise AutomationActionSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise AutomationActionSshTransportError(_UNAVAILABLE) from exc

    async def _show_action(
        self,
        process: Any,
        root_prompt: bytes,
        action_name: str,
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
                f"show | grep {action_name}",
                table_prompt,
                deadline,
            )
            full = await _send_and_read(
                process,
                f"show | grep {action_name} -f",
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
            raise AutomationActionSshTransportError(_UNAVAILABLE) from exc

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
                term_type="vt100", term_size=(200, 24), encoding=None
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
            raise AutomationActionSshTransportError(_UNAVAILABLE) from exc


def _readback(output: bytes, action_name: str) -> AutomationActionReadback:
    normalized = output.replace(b"\r", b"")
    return AutomationActionReadback(
        action_name_exists=_action_marker(action_name) in normalized,
        email_type_enabled=b"set action-type email" in normalized,
        fixed_subject_present=_ACTION_SETTINGS[1].encode("ascii") in normalized,
        fixed_recipient_present=_ACTION_SETTINGS[2].encode("ascii") in normalized,
        fixed_message_present=_ACTION_SETTINGS[3].encode("ascii") in normalized,
        fixed_description_present=_ACTION_SETTINGS[4].encode("ascii") in normalized,
    )


def _action_marker(action_name: str) -> bytes:
    return f'edit "{action_name}"'.encode("ascii")


def _strict_reference_count(output: bytes, command: str, root_prompt: bytes) -> int:
    normalized = output.replace(b"\r", b"")
    lines = normalized.split(b"\n")
    if (
        len(lines) < 2
        or lines[0].strip() != command.encode("ascii")
        or lines[-1].rstrip(b" ") != root_prompt
    ):
        raise AutomationActionSshTransportError(_UNAVAILABLE)
    middle = [line for line in lines[1:-1] if line.strip()]
    if any(b"entry used by" not in line.lower() for line in middle):
        raise AutomationActionSshTransportError(_UNAVAILABLE)
    return len(middle)


def _action_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise AutomationActionSshTransportError(_UNAVAILABLE)
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
        raise AutomationActionSshTransportConfigurationError(
            f"The Automation Action SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise AutomationActionSshTransportConfigurationError(
            f"The Automation Action SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AutomationActionSshTransportConfigurationError(
            f"The Automation Action SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AutomationActionSshTransportConfigurationError(
            "The Automation Action SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AutomationActionSshTransportConfigurationError(
            "The Automation Action SSH password file is invalid."
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
    except AutomationActionSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise AutomationActionSshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "AUTOMATION_ACTION_CONFIGURATION",
    "AUTOMATION_ACTION_NAME_PREFIX",
    "AutomationActionInspection",
    "AutomationActionReadback",
    "AutomationActionSshTransportConfig",
    "AutomationActionSshTransportConfigurationError",
    "AutomationActionSshTransportError",
    "ENV_PREFIX",
    "FortiPamAutomationActionSshTransport",
    "load_automation_action_ssh_transport_config",
]
