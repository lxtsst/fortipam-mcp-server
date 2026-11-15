"""Pinned SSH fallback for one disabled FortiPAM Automation Stitch create.

The FortiPAM 1.9.1 guide documents the Stitch, Trigger, and Action object
model and the disabled/enable lifecycle.  The precise nested CLI body is
cross-checked against Fortinet's documented ``config system
automation-stitch`` grammar.  It remains a local-only candidate until a
confirmed FortiPAM 1.9.1 write/readback validates that grammar.

This transport can create only one disabled, single-action laboratory Stitch
and can read that exact nested projection plus a strictly parsed CMDB reference
count for a separately gated recovery workflow. It references only
independently-created V4 Trigger and Action names. It does not test, enable,
execute, alter, or delete any automation object.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_AUTOMATION_STITCH_"
AUTOMATION_STITCH_NAME_PREFIX = "mcp-v4-automation-stitch-"
AUTOMATION_STITCH_CONFIGURATION = "disabled-single-action-lab-stitch-v1"
_CONFIG_COMMAND = "config system automation-stitch"
_TRIGGER_CONFIG_COMMAND = "config system automation-trigger"
_ACTION_CONFIG_COMMAND = "config system automation-action"
_ACTIONS_CONTEXT = "config actions"
_ACTION_ENTRY_ID = 1
_STITCH_NAME = re.compile(
    r"mcp-v4-automation-stitch-[A-Za-z0-9][A-Za-z0-9._-]{0,37}\Z"
)
_TRIGGER_NAME = re.compile(
    r"mcp-v4-automation-trigger-[A-Za-z0-9][A-Za-z0-9._-]{0,37}\Z"
)
_ACTION_NAME = re.compile(
    r"mcp-v4-automation-action-[A-Za-z0-9][A-Za-z0-9._-]{0,38}\Z"
)
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_UNAVAILABLE = "FortiPAM V4 Automation Stitch transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_STITCH_SETTINGS = (
    "set status disable",
    'set description "MCP V4 disabled single-action lab stitch"',
)
_ACTION_SETTINGS = (
    "set delay 0",
    "set required enable",
)


class AutomationStitchSshTransportError(RuntimeError):
    """Stable non-disclosing failure for the bounded SSH transport."""


class AutomationStitchSshTransportConfigurationError(ValueError):
    """Raised when dedicated Automation Stitch SSH settings are unsafe."""


@dataclass(frozen=True, slots=True)
class AutomationStitchSshTransportConfig:
    """Dedicated pinned SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise AutomationStitchSshTransportConfigurationError(
                "The Automation Stitch SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise AutomationStitchSshTransportConfigurationError(
                "The Automation Stitch SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise AutomationStitchSshTransportConfigurationError(
                "The Automation Stitch SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise AutomationStitchSshTransportConfigurationError(
                "The Automation Stitch SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise AutomationStitchSshTransportConfigurationError(
                "The Automation Stitch SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class AutomationStitchInspection:
    """Value-minimized preflight evidence for one disabled Stitch chain."""

    stitch_name_exists: bool
    trigger_name_exists: bool
    action_name_exists: bool


@dataclass(frozen=True, slots=True)
class AutomationStitchReadback:
    """Categorical readback for the fixed disabled Stitch contract."""

    stitch_name_exists: bool
    status_disabled: bool
    fixed_description_present: bool
    trigger_reference_matches: bool
    single_action_reference_matches: bool
    action_delay_zero: bool
    action_required_enabled: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.stitch_name_exists,
                self.status_disabled,
                self.fixed_description_present,
                self.trigger_reference_matches,
                self.single_action_reference_matches,
                self.action_delay_zero,
                self.action_required_enabled,
            )
        )


def load_automation_stitch_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> AutomationStitchSshTransportConfig:
    """Load only independently scoped Automation Stitch SSH credentials."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise AutomationStitchSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise AutomationStitchSshTransportConfigurationError(
            "Dedicated Automation Stitch SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise AutomationStitchSshTransportConfigurationError(
            "The Automation Stitch SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return AutomationStitchSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamAutomationStitchSshTransport:
    """Run only compiled disabled Stitch inspection and creation commands."""

    def __init__(self, config: AutomationStitchSshTransportConfig) -> None:
        self._config = config

    def inspect(
        self,
        stitch_name: str,
        trigger_name: str,
        action_name: str,
    ) -> AutomationStitchInspection:
        safe_stitch = _stitch_name(stitch_name)
        safe_trigger = _trigger_name(trigger_name)
        safe_action = _action_name(action_name)
        return cast(
            AutomationStitchInspection,
            _run_sync(self._inspect(safe_stitch, safe_trigger, safe_action)),
        )

    def create_and_readback(
        self,
        stitch_name: str,
        trigger_name: str,
        action_name: str,
    ) -> AutomationStitchReadback:
        safe_stitch = _stitch_name(stitch_name)
        safe_trigger = _trigger_name(trigger_name)
        safe_action = _action_name(action_name)
        return cast(
            AutomationStitchReadback,
            _run_sync(
                self._create_and_readback(safe_stitch, safe_trigger, safe_action)
            ),
        )

    def readback_existing(
        self,
        stitch_name: str,
        trigger_name: str,
        action_name: str,
    ) -> AutomationStitchReadback:
        """Read the exact nested disabled Stitch projection without changing it."""

        safe_stitch = _stitch_name(stitch_name)
        safe_trigger = _trigger_name(trigger_name)
        safe_action = _action_name(action_name)
        return cast(
            AutomationStitchReadback,
            _run_sync(
                self._readback_existing(safe_stitch, safe_trigger, safe_action)
            ),
        )

    def reference_count(self, stitch_name: str) -> int:
        """Return a strictly parsed fixed Stitch CMDB reference count."""

        safe_stitch = _stitch_name(stitch_name)
        return cast(int, _run_sync(self._reference_count(safe_stitch)))

    async def _inspect(
        self,
        stitch_name: str,
        trigger_name: str,
        action_name: str,
    ) -> AutomationStitchInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                stitch_output = await self._show_context(
                    process,
                    root_prompt,
                    _CONFIG_COMMAND,
                    stitch_name,
                    deadline,
                )
                trigger_output = await self._show_context(
                    process,
                    root_prompt,
                    _TRIGGER_CONFIG_COMMAND,
                    trigger_name,
                    deadline,
                )
                action_output = await self._show_context(
                    process,
                    root_prompt,
                    _ACTION_CONFIG_COMMAND,
                    action_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return AutomationStitchInspection(
            stitch_name_exists=_entry_marker(stitch_name)
            in stitch_output.replace(b"\r", b""),
            trigger_name_exists=_entry_marker(trigger_name)
            in trigger_output.replace(b"\r", b""),
            action_name_exists=_entry_marker(action_name)
            in action_output.replace(b"\r", b""),
        )

    async def _create_and_readback(
        self,
        stitch_name: str,
        trigger_name: str,
        action_name: str,
    ) -> AutomationStitchReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_stitch(
                    process,
                    root_prompt,
                    stitch_name,
                    trigger_name,
                    action_name,
                    deadline,
                )
                output = await self._show_created_stitch(
                    process,
                    root_prompt,
                    stitch_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, stitch_name, trigger_name, action_name)

    async def _readback_existing(
        self,
        stitch_name: str,
        trigger_name: str,
        action_name: str,
    ) -> AutomationStitchReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_created_stitch(
                    process,
                    root_prompt,
                    stitch_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, stitch_name, trigger_name, action_name)

    async def _reference_count(self, stitch_name: str) -> int:
        command = (
            "diagnose sys cmdb refcnt show system.automation-stitch.name "
            + stitch_name
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

    async def _create_stitch(
        self,
        process: Any,
        root_prompt: bytes,
        stitch_name: str,
        trigger_name: str,
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
            stitch_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{stitch_name}"',
                root_prompt,
                deadline,
            )
            for command in _STITCH_SETTINGS:
                await _send_and_read(process, command, stitch_prompt, deadline)
            await _send_and_read(
                process,
                f'set trigger "{trigger_name}"',
                stitch_prompt,
                deadline,
            )
            actions_prompt = await _send_and_read_dynamic_prompt(
                process,
                _ACTIONS_CONTEXT,
                root_prompt,
                deadline,
            )
            action_prompt = await _send_and_read_dynamic_prompt(
                process,
                f"edit {_ACTION_ENTRY_ID}",
                root_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                f'set action "{action_name}"',
                action_prompt,
                deadline,
            )
            for command in _ACTION_SETTINGS:
                await _send_and_read(process, command, action_prompt, deadline)
            returned_actions = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_actions != actions_prompt:
                raise AutomationStitchSshTransportError(_UNAVAILABLE)
            returned_stitch = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            if returned_stitch != stitch_prompt:
                raise AutomationStitchSshTransportError(_UNAVAILABLE)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise AutomationStitchSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise AutomationStitchSshTransportError(_UNAVAILABLE) from exc

    async def _show_context(
        self,
        process: Any,
        root_prompt: bytes,
        config_command: str,
        entry_name: str,
        deadline: float,
    ) -> bytes:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                config_command,
                root_prompt,
                deadline,
            )
            compact = await _send_and_read(
                process,
                f"show | grep {entry_name}",
                table_prompt,
                deadline,
            )
            full = await _send_and_read(
                process,
                f"show | grep {entry_name} -f",
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
            raise AutomationStitchSshTransportError(_UNAVAILABLE) from exc

    async def _show_created_stitch(
        self,
        process: Any,
        root_prompt: bytes,
        stitch_name: str,
        deadline: float,
    ) -> bytes:
        """Read one existing Stitch entry, including its nested action context."""

        try:
            await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            stitch_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{stitch_name}"',
                root_prompt,
                deadline,
            )
            try:
                output = await _send_and_read(
                    process,
                    "show full-configuration",
                    stitch_prompt,
                    deadline,
                )
            finally:
                returned_root = await _send_and_read_dynamic_prompt(
                    process,
                    "abort",
                    root_prompt,
                    deadline,
                )
                _require_root_prompt(root_prompt, returned_root)
            return output
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise AutomationStitchSshTransportError(_UNAVAILABLE) from exc

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
            raise AutomationStitchSshTransportError(_UNAVAILABLE) from exc


def _readback(
    output: bytes,
    stitch_name: str,
    trigger_name: str,
    action_name: str,
) -> AutomationStitchReadback:
    normalized = output.replace(b"\r", b"")
    return AutomationStitchReadback(
        stitch_name_exists=_entry_marker(stitch_name) in normalized,
        status_disabled=_STITCH_SETTINGS[0].encode("ascii") in normalized,
        fixed_description_present=_STITCH_SETTINGS[1].encode("ascii") in normalized,
        trigger_reference_matches=(
            f'set trigger "{trigger_name}"'.encode("ascii") in normalized
        ),
        single_action_reference_matches=(
            f'set action "{action_name}"'.encode("ascii") in normalized
        ),
        action_delay_zero=_ACTION_SETTINGS[0].encode("ascii") in normalized,
        action_required_enabled=_ACTION_SETTINGS[1].encode("ascii") in normalized,
    )


def _entry_marker(entry_name: str) -> bytes:
    return f'edit "{entry_name}"'.encode("ascii")


def _strict_reference_count(output: bytes, command: str, root_prompt: bytes) -> int:
    normalized = output.replace(b"\r", b"")
    lines = normalized.split(b"\n")
    if (
        len(lines) < 2
        or lines[0].strip() != command.encode("ascii")
        or lines[-1].rstrip(b" ") != root_prompt
    ):
        raise AutomationStitchSshTransportError(_UNAVAILABLE)
    middle = [line for line in lines[1:-1] if line.strip()]
    if any(b"entry used by" not in line.lower() for line in middle):
        raise AutomationStitchSshTransportError(_UNAVAILABLE)
    return len(middle)


def _stitch_name(value: str) -> str:
    if not isinstance(value, str) or _STITCH_NAME.fullmatch(value) is None:
        raise AutomationStitchSshTransportError(_UNAVAILABLE)
    return value


def _trigger_name(value: str) -> str:
    if not isinstance(value, str) or _TRIGGER_NAME.fullmatch(value) is None:
        raise AutomationStitchSshTransportError(_UNAVAILABLE)
    return value


def _action_name(value: str) -> str:
    if not isinstance(value, str) or _ACTION_NAME.fullmatch(value) is None:
        raise AutomationStitchSshTransportError(_UNAVAILABLE)
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
        raise AutomationStitchSshTransportConfigurationError(
            f"The Automation Stitch SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise AutomationStitchSshTransportConfigurationError(
            f"The Automation Stitch SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AutomationStitchSshTransportConfigurationError(
            f"The Automation Stitch SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AutomationStitchSshTransportConfigurationError(
            "The Automation Stitch SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AutomationStitchSshTransportConfigurationError(
            "The Automation Stitch SSH password file is invalid."
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
    except AutomationStitchSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise AutomationStitchSshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "AUTOMATION_STITCH_CONFIGURATION",
    "AUTOMATION_STITCH_NAME_PREFIX",
    "AutomationStitchInspection",
    "AutomationStitchReadback",
    "AutomationStitchSshTransportConfig",
    "AutomationStitchSshTransportConfigurationError",
    "AutomationStitchSshTransportError",
    "ENV_PREFIX",
    "FortiPamAutomationStitchSshTransport",
    "load_automation_stitch_ssh_transport_config",
]
