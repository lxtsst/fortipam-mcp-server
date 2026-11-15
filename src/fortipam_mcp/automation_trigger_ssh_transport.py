"""Pinned SSH fallback for one bounded FortiPAM Automation Trigger create.

The FortiPAM 1.9.1 Administration Guide specifies that automation triggers are
configured through CLI. This module creates only an unbound event-log trigger
with one fixed regex field; it never creates an Automation Action or Stitch and
therefore never executes an automation action.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_AUTOMATION_TRIGGER_"
AUTOMATION_TRIGGER_NAME_PREFIX = "mcp-v4-automation-trigger-"
AUTOMATION_TRIGGER_CONFIGURATION = "event-log-44547-msg-regex-no-action-v1"
_CONFIG_COMMAND = "config system automation-trigger"
_FIELDS_CONTEXT = "config fields"
_NAME = re.compile(r"mcp-v4-automation-trigger-[A-Za-z0-9][A-Za-z0-9._-]{0,37}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_UNAVAILABLE = "FortiPAM V4 Automation Trigger transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_FIELD_ID = "1"
_TRIGGER_SETTINGS = (
    "set event-type event-log",
    "set category 1",
    "set logid 44547",
    "set logic and",
)
_FIELD_SETTINGS = (
    "set match regex",
    'set name "msg"',
    'set value "mcp-v4-no-action"',
)


class AutomationTriggerSshTransportError(RuntimeError):
    """Stable non-disclosing failure for the bounded SSH transport."""


class AutomationTriggerSshTransportConfigurationError(ValueError):
    """Raised when dedicated Automation Trigger SSH settings are unsafe."""


@dataclass(frozen=True, slots=True)
class AutomationTriggerSshTransportConfig:
    """Dedicated pinned SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise AutomationTriggerSshTransportConfigurationError(
                "The Automation Trigger SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise AutomationTriggerSshTransportConfigurationError(
                "The Automation Trigger SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise AutomationTriggerSshTransportConfigurationError(
                "The Automation Trigger SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise AutomationTriggerSshTransportConfigurationError(
                "The Automation Trigger SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise AutomationTriggerSshTransportConfigurationError(
                "The Automation Trigger SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class AutomationTriggerInspection:
    """Value-minimized preflight evidence for one Automation Trigger."""

    trigger_name_exists: bool


@dataclass(frozen=True, slots=True)
class AutomationTriggerReadback:
    """Categorical readback for the fixed unbound trigger contract."""

    trigger_name_exists: bool
    event_log_type_enabled: bool
    fixed_logid_present: bool
    category_one_present: bool
    logic_and_enabled: bool
    msg_regex_field_present: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.trigger_name_exists,
                self.event_log_type_enabled,
                self.fixed_logid_present,
                self.category_one_present,
                self.logic_and_enabled,
                self.msg_regex_field_present,
            )
        )


def load_automation_trigger_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> AutomationTriggerSshTransportConfig:
    """Load only independently scoped Automation Trigger SSH credentials."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise AutomationTriggerSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise AutomationTriggerSshTransportConfigurationError(
            "Dedicated Automation Trigger SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise AutomationTriggerSshTransportConfigurationError(
            "The Automation Trigger SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return AutomationTriggerSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamAutomationTriggerSshTransport:
    """Run only compiled Automation Trigger inspection and creation commands."""

    def __init__(self, config: AutomationTriggerSshTransportConfig) -> None:
        self._config = config

    def inspect(self, trigger_name: str) -> AutomationTriggerInspection:
        safe_name = _trigger_name(trigger_name)
        return cast(AutomationTriggerInspection, _run_sync(self._inspect(safe_name)))

    def create_and_readback(self, trigger_name: str) -> AutomationTriggerReadback:
        safe_name = _trigger_name(trigger_name)
        return cast(
            AutomationTriggerReadback,
            _run_sync(self._create_and_readback(safe_name)),
        )

    def readback_existing(self, trigger_name: str) -> AutomationTriggerReadback:
        """Read the fixed Trigger projection without changing it."""

        safe_name = _trigger_name(trigger_name)
        return cast(
            AutomationTriggerReadback,
            _run_sync(self._readback_existing(safe_name)),
        )

    def reference_count(self, trigger_name: str) -> int:
        """Return a strictly parsed fixed Trigger CMDB reference count."""

        safe_name = _trigger_name(trigger_name)
        return cast(int, _run_sync(self._reference_count(safe_name)))

    async def _inspect(self, trigger_name: str) -> AutomationTriggerInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_trigger(
                    process,
                    root_prompt,
                    trigger_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return AutomationTriggerInspection(
            trigger_name_exists=_trigger_marker(trigger_name)
            in output.replace(b"\r", b"")
        )

    async def _create_and_readback(self, trigger_name: str) -> AutomationTriggerReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_trigger(
                    process,
                    root_prompt,
                    trigger_name,
                    deadline,
                )
                output = await self._show_trigger(
                    process,
                    root_prompt,
                    trigger_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, trigger_name)

    async def _readback_existing(
        self,
        trigger_name: str,
    ) -> AutomationTriggerReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_trigger(
                    process,
                    root_prompt,
                    trigger_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, trigger_name)

    async def _reference_count(self, trigger_name: str) -> int:
        command = (
            "diagnose sys cmdb refcnt show system.automation-trigger.name "
            + trigger_name
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

    async def _create_trigger(
        self,
        process: Any,
        root_prompt: bytes,
        trigger_name: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            trigger_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{trigger_name}"',
                root_prompt,
                deadline,
            )
            for command in _TRIGGER_SETTINGS:
                await _send_and_read(process, command, trigger_prompt, deadline)
            fields_prompt = await _send_and_read_dynamic_prompt(
                process,
                _FIELDS_CONTEXT,
                root_prompt,
                deadline,
            )
            field_prompt = await _send_and_read_dynamic_prompt(
                process,
                f"edit {_FIELD_ID}",
                root_prompt,
                deadline,
            )
            for command in _FIELD_SETTINGS:
                await _send_and_read(process, command, field_prompt, deadline)
            returned_fields = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_fields != fields_prompt:
                raise AutomationTriggerSshTransportError(_UNAVAILABLE)
            returned_trigger = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            if returned_trigger != trigger_prompt:
                raise AutomationTriggerSshTransportError(_UNAVAILABLE)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise AutomationTriggerSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise AutomationTriggerSshTransportError(_UNAVAILABLE) from exc

    async def _show_trigger(
        self,
        process: Any,
        root_prompt: bytes,
        trigger_name: str,
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
                f"show | grep {trigger_name}",
                table_prompt,
                deadline,
            )
            if _trigger_marker(trigger_name) in compact.replace(b"\r", b""):
                trigger_prompt = await _send_and_read_dynamic_prompt(
                    process,
                    f'edit "{trigger_name}"',
                    root_prompt,
                    deadline,
                )
                try:
                    full = await _send_and_read(
                        process,
                        "show",
                        trigger_prompt,
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
                return compact + full
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
            return compact
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise AutomationTriggerSshTransportError(_UNAVAILABLE) from exc

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
            raise AutomationTriggerSshTransportError(_UNAVAILABLE) from exc


def _readback(output: bytes, trigger_name: str) -> AutomationTriggerReadback:
    normalized = output.replace(b"\r", b"")
    return AutomationTriggerReadback(
        trigger_name_exists=_trigger_marker(trigger_name) in normalized,
        event_log_type_enabled=b"set event-type event-log" in normalized,
        fixed_logid_present=b"set logid 44547" in normalized,
        category_one_present=b"set category 1" in normalized,
        logic_and_enabled=b"set logic and" in normalized,
        msg_regex_field_present=all(setting.encode("ascii") in normalized for setting in _FIELD_SETTINGS),
    )


def _trigger_marker(trigger_name: str) -> bytes:
    return f'edit "{trigger_name}"'.encode("ascii")


def _strict_reference_count(output: bytes, command: str, root_prompt: bytes) -> int:
    normalized = output.replace(b"\r", b"")
    lines = normalized.split(b"\n")
    if (
        len(lines) < 2
        or lines[0].strip() != command.encode("ascii")
        or lines[-1].rstrip(b" ") != root_prompt
    ):
        raise AutomationTriggerSshTransportError(_UNAVAILABLE)
    middle = [line for line in lines[1:-1] if line.strip()]
    if any(b"entry used by" not in line.lower() for line in middle):
        raise AutomationTriggerSshTransportError(_UNAVAILABLE)
    return len(middle)


def _trigger_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise AutomationTriggerSshTransportError(_UNAVAILABLE)
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
        raise AutomationTriggerSshTransportConfigurationError(
            f"The Automation Trigger SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise AutomationTriggerSshTransportConfigurationError(
            f"The Automation Trigger SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AutomationTriggerSshTransportConfigurationError(
            f"The Automation Trigger SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AutomationTriggerSshTransportConfigurationError(
            "The Automation Trigger SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AutomationTriggerSshTransportConfigurationError(
            "The Automation Trigger SSH password file is invalid."
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
    except AutomationTriggerSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise AutomationTriggerSshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "AUTOMATION_TRIGGER_CONFIGURATION",
    "AUTOMATION_TRIGGER_NAME_PREFIX",
    "AutomationTriggerInspection",
    "AutomationTriggerReadback",
    "AutomationTriggerSshTransportConfig",
    "AutomationTriggerSshTransportConfigurationError",
    "AutomationTriggerSshTransportError",
    "ENV_PREFIX",
    "FortiPamAutomationTriggerSshTransport",
    "load_automation_trigger_ssh_transport_config",
]
