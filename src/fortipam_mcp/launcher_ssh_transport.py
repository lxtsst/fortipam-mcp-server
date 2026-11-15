"""Pinned SSH fallback for bounded FortiPAM native RDP Launcher actions.

The 1.9.1 API catalog does not establish a Launcher REST write contract.  This
module therefore implements only the Administration Guide's documented
``config secret launcher`` example: a Windows native RDP launcher using
``mstsc.exe`` and fixed ``cmdkey`` setup/cleanup commands. Separate update
paths accept that exact create baseline only: one changes the documented
``launch-timeout`` setting from 15 to 30 seconds, while the other applies the
Guide's CommandLine process-matcher prerequisites. It never acts as a generic
CLI relay and creates no Secret or Template association.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_LAUNCHER_"
UPDATE_ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_LAUNCHER_UPDATE_"
MATCHER_ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_LAUNCHER_MATCHER_"
LAUNCHER_NAME_PREFIX = "mcp-v4-launcher-"
LAUNCHER_CONFIGURATION = "windows-rdp-mstsc-cmdkey-timeout-15-v2"
LAUNCHER_UPDATE_CONFIGURATION = "windows-rdp-mstsc-timeout-15-to-30-v1"
LAUNCHER_MATCHER_CONFIGURATION = "windows-rdp-mstsc-command-line-matcher-v1"
LAUNCHER_DEFAULT_TIMEOUT_SECONDS = 15
LAUNCHER_UPDATED_TIMEOUT_SECONDS = 30
_CONFIG_COMMAND = "config secret launcher"
_OS_APP_CONTEXT = "config os_app"
_INIT_COMMANDS_CONTEXT = "config init-commands"
_CLEAN_COMMANDS_CONTEXT = "config clean-commands"
_LAUNCHER_NAME = re.compile(r"mcp-v4-launcher-[A-Za-z0-9][A-Za-z0-9._-]{0,46}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_UNAVAILABLE = "FortiPAM V4 Launcher create transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_TYPE_COMMAND = "set type rdp"
_EXE_COMMAND = 'set exe "mstsc.exe"'
_PARAMETER_COMMAND = 'set parameter "/V:$HOST:$PORT /noConsentPrompt"'
_INIT_COMMAND = 'set cmd "cmdkey /generic:$HOST /user:$USER /pass:$PASSWORD"'
_CLEAN_COMMAND = 'set cmd "cmdkey /del:$HOST"'
_DEFAULT_TIMEOUT_COMMAND = f"set launch-timeout {LAUNCHER_DEFAULT_TIMEOUT_SECONDS}"
_UPDATED_TIMEOUT_COMMAND = f"set launch-timeout {LAUNCHER_UPDATED_TIMEOUT_SECONDS}"
_MATCHER_TYPE_DEFAULT_COMMAND = "set proc-matcher-type default"
_MATCHER_TYPE_COMMAND = "set proc-matcher-type process-cmdline"
_MATCHER_PATTERN_COMMAND = 'set proc-matcher-pattern "^mstsc\\.exe.*"'
_MATCHER_PATTERN_READBACK = 'set proc-matcher-pattern "^mstsc\\\\.exe.*"'
_MULTIPROCESS_COMMAND = "set multiprocess enable"
_FULLSCREEN_RECORD_COMMAND = "set fullscreen-record enable"


class LauncherSshTransportError(RuntimeError):
    """Stable, non-disclosing failure for the bounded SSH transport."""


class LauncherSshTransportConfigurationError(ValueError):
    """Raised when dedicated Launcher transport settings are unsafe."""


@dataclass(frozen=True, slots=True)
class LauncherSshTransportConfig:
    """Dedicated pinned SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise LauncherSshTransportConfigurationError(
                "The Launcher SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise LauncherSshTransportConfigurationError(
                "The Launcher SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise LauncherSshTransportConfigurationError(
                "The Launcher SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise LauncherSshTransportConfigurationError(
                "The Launcher SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise LauncherSshTransportConfigurationError(
                "The Launcher SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class LauncherInspection:
    """Value-minimized preflight evidence for one Launcher."""

    launcher_name_exists: bool


@dataclass(frozen=True, slots=True)
class LauncherReadback:
    """Categorical readback for the fixed native RDP Launcher contract."""

    launcher_name_exists: bool
    type_is_rdp: bool
    mstsc_executable_present: bool
    native_rdp_parameter_present: bool
    cmdkey_initial_command_present: bool
    cmdkey_clean_command_present: bool
    launch_timeout_is_default: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.launcher_name_exists,
                self.type_is_rdp,
                self.mstsc_executable_present,
                self.native_rdp_parameter_present,
                self.cmdkey_initial_command_present,
                self.cmdkey_clean_command_present,
                self.launch_timeout_is_default,
            )
        )


@dataclass(frozen=True, slots=True)
class LauncherUpdateBaselineReadback:
    """Categorical evidence for the exact Launcher-create baseline only."""

    launcher_name_exists: bool
    type_is_rdp: bool
    mstsc_executable_present: bool
    native_rdp_parameter_present: bool
    cmdkey_initial_command_present: bool
    cmdkey_clean_command_present: bool
    launch_timeout_is_default: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.launcher_name_exists,
                self.type_is_rdp,
                self.mstsc_executable_present,
                self.native_rdp_parameter_present,
                self.cmdkey_initial_command_present,
                self.cmdkey_clean_command_present,
                self.launch_timeout_is_default,
            )
        )


@dataclass(frozen=True, slots=True)
class LauncherUpdateReadback:
    """Categorical evidence for the exact bounded Launcher timeout update."""

    launcher_name_exists: bool
    type_is_rdp: bool
    mstsc_executable_present: bool
    native_rdp_parameter_present: bool
    cmdkey_initial_command_present: bool
    cmdkey_clean_command_present: bool
    launch_timeout_is_updated: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.launcher_name_exists,
                self.type_is_rdp,
                self.mstsc_executable_present,
                self.native_rdp_parameter_present,
                self.cmdkey_initial_command_present,
                self.cmdkey_clean_command_present,
                self.launch_timeout_is_updated,
            )
        )


@dataclass(frozen=True, slots=True)
class LauncherMatcherBaselineReadback:
    """Categorical evidence for an uncustomized local Launcher baseline."""

    launcher_name_exists: bool
    type_is_rdp: bool
    mstsc_executable_present: bool
    native_rdp_parameter_present: bool
    cmdkey_initial_command_present: bool
    cmdkey_clean_command_present: bool
    launch_timeout_is_default: bool
    matcher_type_is_default: bool
    matcher_pattern_absent: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.launcher_name_exists,
                self.type_is_rdp,
                self.mstsc_executable_present,
                self.native_rdp_parameter_present,
                self.cmdkey_initial_command_present,
                self.cmdkey_clean_command_present,
                self.launch_timeout_is_default,
                self.matcher_type_is_default,
                self.matcher_pattern_absent,
            )
        )


@dataclass(frozen=True, slots=True)
class LauncherMatcherReadback:
    """Categorical evidence for the fixed CommandLine matcher configuration."""

    launcher_name_exists: bool
    type_is_rdp: bool
    mstsc_executable_present: bool
    native_rdp_parameter_present: bool
    cmdkey_initial_command_present: bool
    cmdkey_clean_command_present: bool
    launch_timeout_is_default: bool
    multiprocess_enabled: bool
    fullscreen_recording_enabled: bool
    matcher_type_is_command_line: bool
    matcher_pattern_is_fixed: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.launcher_name_exists,
                self.type_is_rdp,
                self.mstsc_executable_present,
                self.native_rdp_parameter_present,
                self.cmdkey_initial_command_present,
                self.cmdkey_clean_command_present,
                self.launch_timeout_is_default,
                self.multiprocess_enabled,
                self.fullscreen_recording_enabled,
                self.matcher_type_is_command_line,
                self.matcher_pattern_is_fixed,
            )
        )


def load_launcher_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> LauncherSshTransportConfig:
    """Load only independently scoped Launcher SSH credentials."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise LauncherSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise LauncherSshTransportConfigurationError(
            "Dedicated Launcher SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise LauncherSshTransportConfigurationError(
            "The Launcher SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return LauncherSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


def load_launcher_update_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> LauncherSshTransportConfig:
    """Load only independently scoped Launcher-update SSH settings."""

    env = os.environ if environment is None else environment
    if _value_for_prefix(env, UPDATE_ENV_PREFIX, "ENABLED") != "true":
        raise LauncherSshTransportConfigurationError(
            f"{UPDATE_ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value_for_prefix(env, UPDATE_ENV_PREFIX, "SSH_HOST")
    username = _value_for_prefix(env, UPDATE_ENV_PREFIX, "SSH_USERNAME")
    password_file = _value_for_prefix(env, UPDATE_ENV_PREFIX, "SSH_PASSWORD_FILE")
    known_hosts_file = _value_for_prefix(env, UPDATE_ENV_PREFIX, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value_for_prefix(env, UPDATE_ENV_PREFIX, "SSH_PORT") or "22"
    timeout_raw = (
        _value_for_prefix(env, UPDATE_ENV_PREFIX, "SSH_TIMEOUT_SECONDS") or "15"
    )
    if None in {host, username, password_file, known_hosts_file}:
        raise LauncherSshTransportConfigurationError(
            "Dedicated Launcher update SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise LauncherSshTransportConfigurationError(
            "The Launcher update SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return LauncherSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


def load_launcher_matcher_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> LauncherSshTransportConfig:
    """Load only independently scoped Launcher-matcher SSH settings."""

    env = os.environ if environment is None else environment
    if _value_for_prefix(env, MATCHER_ENV_PREFIX, "ENABLED") != "true":
        raise LauncherSshTransportConfigurationError(
            f"{MATCHER_ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value_for_prefix(env, MATCHER_ENV_PREFIX, "SSH_HOST")
    username = _value_for_prefix(env, MATCHER_ENV_PREFIX, "SSH_USERNAME")
    password_file = _value_for_prefix(env, MATCHER_ENV_PREFIX, "SSH_PASSWORD_FILE")
    known_hosts_file = _value_for_prefix(env, MATCHER_ENV_PREFIX, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value_for_prefix(env, MATCHER_ENV_PREFIX, "SSH_PORT") or "22"
    timeout_raw = (
        _value_for_prefix(env, MATCHER_ENV_PREFIX, "SSH_TIMEOUT_SECONDS") or "15"
    )
    if None in {host, username, password_file, known_hosts_file}:
        raise LauncherSshTransportConfigurationError(
            "Dedicated Launcher matcher SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise LauncherSshTransportConfigurationError(
            "The Launcher matcher SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return LauncherSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamLauncherSshTransport:
    """Run only compiled Launcher inspection, create, timeout, and matcher actions."""

    def __init__(self, config: LauncherSshTransportConfig) -> None:
        self._config = config

    def inspect(self, launcher_name: str) -> LauncherInspection:
        safe_name = _launcher_name(launcher_name)
        return cast(LauncherInspection, _run_sync(self._inspect(safe_name)))

    def create_and_readback(self, launcher_name: str) -> LauncherReadback:
        safe_name = _launcher_name(launcher_name)
        return cast(
            LauncherReadback,
            _run_sync(self._create_and_readback(safe_name)),
        )

    def update_baseline_readback(
        self,
        launcher_name: str,
    ) -> LauncherUpdateBaselineReadback:
        """Read only the exact create baseline eligible for the timeout update."""

        safe_name = _launcher_name(launcher_name)
        return cast(
            LauncherUpdateBaselineReadback,
            _run_sync(self._update_baseline_readback(safe_name)),
        )

    def update_timeout_and_readback(
        self,
        launcher_name: str,
    ) -> LauncherUpdateReadback:
        """Change only the fixed timeout and return categorical full readback."""

        safe_name = _launcher_name(launcher_name)
        return cast(
            LauncherUpdateReadback,
            _run_sync(self._update_timeout_and_readback(safe_name)),
        )

    def matcher_baseline_readback(
        self,
        launcher_name: str,
    ) -> LauncherMatcherBaselineReadback:
        """Read only the exact uncustomized baseline eligible for matcher setup."""

        safe_name = _launcher_name(launcher_name)
        return cast(
            LauncherMatcherBaselineReadback,
            _run_sync(self._matcher_baseline_readback(safe_name)),
        )

    def configure_command_line_matcher_and_readback(
        self,
        launcher_name: str,
    ) -> LauncherMatcherReadback:
        """Configure only the documented fixed matcher prerequisites and pattern."""

        safe_name = _launcher_name(launcher_name)
        return cast(
            LauncherMatcherReadback,
            _run_sync(self._configure_command_line_matcher_and_readback(safe_name)),
        )

    async def _inspect(self, launcher_name: str) -> LauncherInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_launcher(
                    process,
                    root_prompt,
                    launcher_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return LauncherInspection(
            launcher_name_exists=_launcher_marker(launcher_name)
            in output.replace(b"\r", b"")
        )

    async def _create_and_readback(self, launcher_name: str) -> LauncherReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_launcher(
                    process,
                    root_prompt,
                    launcher_name,
                    deadline,
                )
                output = await self._show_launcher(
                    process,
                    root_prompt,
                    launcher_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, launcher_name)

    async def _update_baseline_readback(
        self,
        launcher_name: str,
    ) -> LauncherUpdateBaselineReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_launcher(
                    process,
                    root_prompt,
                    launcher_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _update_baseline_readback(output, launcher_name)

    async def _update_timeout_and_readback(
        self,
        launcher_name: str,
    ) -> LauncherUpdateReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._update_timeout(
                    process,
                    root_prompt,
                    launcher_name,
                    deadline,
                )
                output = await self._show_launcher(
                    process,
                    root_prompt,
                    launcher_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _update_readback(output, launcher_name)

    async def _matcher_baseline_readback(
        self,
        launcher_name: str,
    ) -> LauncherMatcherBaselineReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_launcher(
                    process,
                    root_prompt,
                    launcher_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _matcher_baseline_readback(output, launcher_name)

    async def _configure_command_line_matcher_and_readback(
        self,
        launcher_name: str,
    ) -> LauncherMatcherReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._configure_command_line_matcher(
                    process,
                    root_prompt,
                    launcher_name,
                    deadline,
                )
                output = await self._show_launcher(
                    process,
                    root_prompt,
                    launcher_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _matcher_readback(output, launcher_name)

    async def _create_launcher(
        self,
        process: Any,
        root_prompt: bytes,
        launcher_name: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            launcher_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{launcher_name}"',
                root_prompt,
                deadline,
            )
            await _send_and_read(process, _TYPE_COMMAND, launcher_prompt, deadline)
            await _send_and_read(
                process,
                _DEFAULT_TIMEOUT_COMMAND,
                launcher_prompt,
                deadline,
            )
            os_app_prompt = await _send_and_read_dynamic_prompt(
                process,
                _OS_APP_CONTEXT,
                root_prompt,
                deadline,
            )
            application_prompt = await _send_and_read_dynamic_prompt(
                process,
                "edit 1",
                root_prompt,
                deadline,
            )
            await _send_and_read(process, _EXE_COMMAND, application_prompt, deadline)
            await _send_and_read(
                process,
                _PARAMETER_COMMAND,
                application_prompt,
                deadline,
            )
            init_commands_prompt = await _send_and_read_dynamic_prompt(
                process,
                _INIT_COMMANDS_CONTEXT,
                root_prompt,
                deadline,
            )
            init_command_prompt = await _send_and_read_dynamic_prompt(
                process,
                "edit 1",
                root_prompt,
                deadline,
            )
            await _send_and_read(process, _INIT_COMMAND, init_command_prompt, deadline)
            returned_init_commands = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_init_commands != init_commands_prompt:
                raise LauncherSshTransportError(_UNAVAILABLE)
            returned_application = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            if returned_application != application_prompt:
                raise LauncherSshTransportError(_UNAVAILABLE)
            clean_commands_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CLEAN_COMMANDS_CONTEXT,
                root_prompt,
                deadline,
            )
            clean_command_prompt = await _send_and_read_dynamic_prompt(
                process,
                "edit 1",
                root_prompt,
                deadline,
            )
            await _send_and_read(process, _CLEAN_COMMAND, clean_command_prompt, deadline)
            returned_clean_commands = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_clean_commands != clean_commands_prompt:
                raise LauncherSshTransportError(_UNAVAILABLE)
            returned_application = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            if returned_application != application_prompt:
                raise LauncherSshTransportError(_UNAVAILABLE)
            returned_os_app = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_os_app != os_app_prompt:
                raise LauncherSshTransportError(_UNAVAILABLE)
            returned_launcher = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            if returned_launcher != launcher_prompt:
                raise LauncherSshTransportError(_UNAVAILABLE)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise LauncherSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise LauncherSshTransportError(_UNAVAILABLE) from exc

    async def _update_timeout(
        self,
        process: Any,
        root_prompt: bytes,
        launcher_name: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            launcher_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{launcher_name}"',
                root_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                _UPDATED_TIMEOUT_COMMAND,
                launcher_prompt,
                deadline,
            )
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise LauncherSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise LauncherSshTransportError(_UNAVAILABLE) from exc

    async def _configure_command_line_matcher(
        self,
        process: Any,
        root_prompt: bytes,
        launcher_name: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            launcher_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{launcher_name}"',
                root_prompt,
                deadline,
            )
            os_app_prompt = await _send_and_read_dynamic_prompt(
                process,
                _OS_APP_CONTEXT,
                root_prompt,
                deadline,
            )
            application_prompt = await _send_and_read_dynamic_prompt(
                process,
                "edit 1",
                root_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                _MULTIPROCESS_COMMAND,
                application_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                _FULLSCREEN_RECORD_COMMAND,
                application_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                _MATCHER_TYPE_COMMAND,
                application_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                _MATCHER_PATTERN_COMMAND,
                application_prompt,
                deadline,
            )
            returned_os_app = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_os_app != os_app_prompt:
                raise LauncherSshTransportError(_UNAVAILABLE)
            returned_launcher = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            if returned_launcher != launcher_prompt:
                raise LauncherSshTransportError(_UNAVAILABLE)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise LauncherSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise LauncherSshTransportError(_UNAVAILABLE) from exc

    async def _show_launcher(
        self,
        process: Any,
        root_prompt: bytes,
        launcher_name: str,
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
                f"show | grep {launcher_name}",
                table_prompt,
                deadline,
            )
            if _launcher_marker(launcher_name) not in compact.replace(b"\r", b""):
                returned_root = await _send_and_read_dynamic_prompt(
                    process,
                    "end",
                    root_prompt,
                    deadline,
                )
                _require_root_prompt(root_prompt, returned_root)
                return compact
            launcher_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{launcher_name}"',
                root_prompt,
                deadline,
            )
            launcher = await _send_and_read(
                process,
                "show full-configuration | grep rdp",
                launcher_prompt,
                deadline,
            )
            timeout = await _send_and_read(
                process,
                "show full-configuration | grep launch-timeout",
                launcher_prompt,
                deadline,
            )
            os_app_prompt = await _send_and_read_dynamic_prompt(
                process,
                _OS_APP_CONTEXT,
                root_prompt,
                deadline,
            )
            os_app = await _send_and_read(
                process,
                "show full-configuration",
                os_app_prompt,
                deadline,
            )
            returned_launcher = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            if returned_launcher != launcher_prompt:
                raise LauncherSshTransportError(_UNAVAILABLE)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise LauncherSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
            return compact + launcher + timeout + os_app
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise LauncherSshTransportError(_UNAVAILABLE) from exc

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
            raise LauncherSshTransportError(_UNAVAILABLE) from exc


def _readback(output: bytes, launcher_name: str) -> LauncherReadback:
    normalized = output.replace(b"\r", b"")
    return LauncherReadback(
        launcher_name_exists=_launcher_marker(launcher_name) in normalized,
        type_is_rdp=_TYPE_COMMAND.encode("ascii") in normalized,
        mstsc_executable_present=_EXE_COMMAND.encode("ascii") in normalized,
        native_rdp_parameter_present=_PARAMETER_COMMAND.encode("ascii") in normalized,
        cmdkey_initial_command_present=_INIT_COMMAND.encode("ascii") in normalized,
        cmdkey_clean_command_present=_CLEAN_COMMAND.encode("ascii") in normalized,
        launch_timeout_is_default=_DEFAULT_TIMEOUT_COMMAND.encode("ascii") in normalized,
    )


def _update_baseline_readback(
    output: bytes,
    launcher_name: str,
) -> LauncherUpdateBaselineReadback:
    normalized = output.replace(b"\r", b"")
    return LauncherUpdateBaselineReadback(
        launcher_name_exists=_launcher_marker(launcher_name) in normalized,
        type_is_rdp=_TYPE_COMMAND.encode("ascii") in normalized,
        mstsc_executable_present=_EXE_COMMAND.encode("ascii") in normalized,
        native_rdp_parameter_present=_PARAMETER_COMMAND.encode("ascii") in normalized,
        cmdkey_initial_command_present=_INIT_COMMAND.encode("ascii") in normalized,
        cmdkey_clean_command_present=_CLEAN_COMMAND.encode("ascii") in normalized,
        launch_timeout_is_default=_DEFAULT_TIMEOUT_COMMAND.encode("ascii") in normalized,
    )


def _update_readback(output: bytes, launcher_name: str) -> LauncherUpdateReadback:
    normalized = output.replace(b"\r", b"")
    return LauncherUpdateReadback(
        launcher_name_exists=_launcher_marker(launcher_name) in normalized,
        type_is_rdp=_TYPE_COMMAND.encode("ascii") in normalized,
        mstsc_executable_present=_EXE_COMMAND.encode("ascii") in normalized,
        native_rdp_parameter_present=_PARAMETER_COMMAND.encode("ascii") in normalized,
        cmdkey_initial_command_present=_INIT_COMMAND.encode("ascii") in normalized,
        cmdkey_clean_command_present=_CLEAN_COMMAND.encode("ascii") in normalized,
        launch_timeout_is_updated=_UPDATED_TIMEOUT_COMMAND.encode("ascii") in normalized,
    )


def _matcher_baseline_readback(
    output: bytes,
    launcher_name: str,
) -> LauncherMatcherBaselineReadback:
    normalized = output.replace(b"\r", b"")
    return LauncherMatcherBaselineReadback(
        launcher_name_exists=_launcher_marker(launcher_name) in normalized,
        type_is_rdp=_TYPE_COMMAND.encode("ascii") in normalized,
        mstsc_executable_present=_EXE_COMMAND.encode("ascii") in normalized,
        native_rdp_parameter_present=_PARAMETER_COMMAND.encode("ascii") in normalized,
        cmdkey_initial_command_present=_INIT_COMMAND.encode("ascii") in normalized,
        cmdkey_clean_command_present=_CLEAN_COMMAND.encode("ascii") in normalized,
        launch_timeout_is_default=_DEFAULT_TIMEOUT_COMMAND.encode("ascii") in normalized,
        matcher_type_is_default=_MATCHER_TYPE_DEFAULT_COMMAND.encode("ascii")
        in normalized,
        matcher_pattern_absent=b"proc-matcher-pattern" not in normalized,
    )


def _matcher_readback(output: bytes, launcher_name: str) -> LauncherMatcherReadback:
    normalized = output.replace(b"\r", b"")
    return LauncherMatcherReadback(
        launcher_name_exists=_launcher_marker(launcher_name) in normalized,
        type_is_rdp=_TYPE_COMMAND.encode("ascii") in normalized,
        mstsc_executable_present=_EXE_COMMAND.encode("ascii") in normalized,
        native_rdp_parameter_present=_PARAMETER_COMMAND.encode("ascii") in normalized,
        cmdkey_initial_command_present=_INIT_COMMAND.encode("ascii") in normalized,
        cmdkey_clean_command_present=_CLEAN_COMMAND.encode("ascii") in normalized,
        launch_timeout_is_default=_DEFAULT_TIMEOUT_COMMAND.encode("ascii") in normalized,
        multiprocess_enabled=_MULTIPROCESS_COMMAND.encode("ascii") in normalized,
        fullscreen_recording_enabled=_FULLSCREEN_RECORD_COMMAND.encode("ascii")
        in normalized,
        matcher_type_is_command_line=_MATCHER_TYPE_COMMAND.encode("ascii")
        in normalized,
        matcher_pattern_is_fixed=_MATCHER_PATTERN_READBACK.encode("ascii")
        in normalized,
    )


def _launcher_marker(launcher_name: str) -> bytes:
    return f'edit "{launcher_name}"'.encode("ascii")


def _launcher_name(value: str) -> str:
    if not isinstance(value, str) or _LAUNCHER_NAME.fullmatch(value) is None:
        raise LauncherSshTransportError(_UNAVAILABLE)
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
        raise LauncherSshTransportConfigurationError(
            f"The Launcher SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise LauncherSshTransportConfigurationError(
            f"The Launcher SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise LauncherSshTransportConfigurationError(
            f"The Launcher SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise LauncherSshTransportConfigurationError(
            "The Launcher SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LauncherSshTransportConfigurationError(
            "The Launcher SSH password file is invalid."
        ) from exc


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _value_for_prefix(
    environment: Mapping[str, str],
    prefix: str,
    suffix: str,
) -> str | None:
    value = environment.get(f"{prefix}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _run_sync(coroutine: Coroutine[Any, Any, Any]) -> Any:
    try:
        return asyncio.run(coroutine)
    except LauncherSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise LauncherSshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "ENV_PREFIX",
    "MATCHER_ENV_PREFIX",
    "UPDATE_ENV_PREFIX",
    "FortiPamLauncherSshTransport",
    "LAUNCHER_DEFAULT_TIMEOUT_SECONDS",
    "LAUNCHER_CONFIGURATION",
    "LAUNCHER_MATCHER_CONFIGURATION",
    "LAUNCHER_NAME_PREFIX",
    "LAUNCHER_UPDATED_TIMEOUT_SECONDS",
    "LAUNCHER_UPDATE_CONFIGURATION",
    "LauncherInspection",
    "LauncherReadback",
    "LauncherMatcherBaselineReadback",
    "LauncherMatcherReadback",
    "LauncherUpdateBaselineReadback",
    "LauncherUpdateReadback",
    "LauncherSshTransportConfig",
    "LauncherSshTransportConfigurationError",
    "LauncherSshTransportError",
    "load_launcher_ssh_transport_config",
    "load_launcher_matcher_ssh_transport_config",
    "load_launcher_update_ssh_transport_config",
]
