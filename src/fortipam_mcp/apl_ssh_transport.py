"""Pinned SSH fallback for one disabled FortiPAM Auto-Provision Rule create.

The FortiPAM 1.9.1 Administration Guide documents the
``config user auto-provision-rule`` CLI with a remote group, Role, and status.
This transport creates only an unattached, disabled, laboratory-prefixed rule.
It never enables a rule, changes an existing rule, creates a user/group/Role,
changes an identity server, or starts a session.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_APL_"
DISABLE_ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_APL_DISABLE_"
APL_NAME_PREFIX = "mcp-v4-apl-"
APL_CONFIGURATION = "disabled-existing-v4-ldap-user-group-and-role-v1"
APL_DISABLE_CONFIGURATION = "enabled-existing-v4-apl-to-disabled-v1"
_APL_CONFIG_COMMAND = "config user auto-provision-rule"
_USER_GROUP_CONFIG_COMMAND = "config user group"
_ROLE_CONFIG_COMMAND = "config system accprofile"
_APL_NAME = re.compile(r"mcp-v4-apl-[A-Za-z0-9][A-Za-z0-9._-]{0,51}\Z")
_USER_GROUP_NAME = re.compile(
    r"mcp-v4-user-group-[A-Za-z0-9][A-Za-z0-9._-]{0,43}\Z"
)
_ROLE_NAME = re.compile(r"mcp-v4-role-[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_UNAVAILABLE = "FortiPAM V4 Auto-Provision Rule transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024


class AplSshTransportError(RuntimeError):
    """Stable non-disclosing failure for the bounded SSH transport."""


class AplSshTransportConfigurationError(ValueError):
    """Raised when dedicated Auto-Provision Rule SSH settings are unsafe."""


@dataclass(frozen=True, slots=True)
class AplSshTransportConfig:
    """Dedicated pinned SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise AplSshTransportConfigurationError(
                "The Auto-Provision Rule SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise AplSshTransportConfigurationError(
                "The Auto-Provision Rule SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise AplSshTransportConfigurationError(
                "The Auto-Provision Rule SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise AplSshTransportConfigurationError(
                "The Auto-Provision Rule SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.password
        ):
            raise AplSshTransportConfigurationError(
                "The Auto-Provision Rule SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class AplInspection:
    """Value-minimized preflight evidence for one disabled APL create."""

    auto_provision_rule_exists: bool
    remote_user_group_exists: bool
    role_exists: bool

    @property
    def create_baseline_verified(self) -> bool:
        return all(
            (
                not self.auto_provision_rule_exists,
                self.remote_user_group_exists,
                self.role_exists,
            )
        )


@dataclass(frozen=True, slots=True)
class AplReadback:
    """Categorical readback for the fixed disabled Auto-Provision Rule."""

    auto_provision_rule_exists: bool
    status_disabled: bool
    remote_user_group_matches: bool
    role_matches: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.auto_provision_rule_exists,
                self.status_disabled,
                self.remote_user_group_matches,
                self.role_matches,
            )
        )


@dataclass(frozen=True, slots=True)
class AplDisableInspection:
    """Categorical baseline evidence for one existing enabled V4 APL."""

    auto_provision_rule_exists: bool
    status_enabled: bool
    remote_user_group_matches: bool
    role_matches: bool
    remote_user_group_exists: bool
    role_exists: bool

    @property
    def disable_baseline_verified(self) -> bool:
        return all(
            (
                self.auto_provision_rule_exists,
                self.status_enabled,
                self.remote_user_group_matches,
                self.role_matches,
                self.remote_user_group_exists,
                self.role_exists,
            )
        )


def load_apl_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> AplSshTransportConfig:
    """Load only independently scoped Auto-Provision Rule SSH credentials."""

    env = os.environ if environment is None else environment
    return _load_apl_ssh_transport_config(env, ENV_PREFIX)


def load_apl_disable_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> AplSshTransportConfig:
    """Load only independently scoped APL-disable SSH credentials."""

    env = os.environ if environment is None else environment
    return _load_apl_ssh_transport_config(env, DISABLE_ENV_PREFIX)


def _load_apl_ssh_transport_config(
    environment: Mapping[str, str],
    prefix: str,
) -> AplSshTransportConfig:
    if _value_for_prefix(environment, prefix, "ENABLED") != "true":
        raise AplSshTransportConfigurationError(
            f"{prefix}ENABLED must be exactly true."
        )
    host = _value_for_prefix(environment, prefix, "SSH_HOST")
    username = _value_for_prefix(environment, prefix, "SSH_USERNAME")
    password_file = _value_for_prefix(environment, prefix, "SSH_PASSWORD_FILE")
    known_hosts_file = _value_for_prefix(environment, prefix, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value_for_prefix(environment, prefix, "SSH_PORT") or "22"
    timeout_raw = _value_for_prefix(environment, prefix, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise AplSshTransportConfigurationError(
            "Dedicated Auto-Provision Rule SSH host, username, password file, "
            "and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise AplSshTransportConfigurationError(
            "The Auto-Provision Rule SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return AplSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamAplSshTransport:
    """Run only compiled APL inspection and disabled-rule creation commands."""

    def __init__(self, config: AplSshTransportConfig) -> None:
        self._config = config

    def inspect(
        self,
        auto_provision_rule_name: str,
        remote_user_group_name: str,
        role_name: str,
    ) -> AplInspection:
        rule = _apl_name(auto_provision_rule_name)
        group = _user_group_name(remote_user_group_name)
        role = _role_name(role_name)
        return cast(AplInspection, _run_sync(self._inspect(rule, group, role)))

    def create_disabled_and_readback(
        self,
        auto_provision_rule_name: str,
        remote_user_group_name: str,
        role_name: str,
    ) -> AplReadback:
        rule = _apl_name(auto_provision_rule_name)
        group = _user_group_name(remote_user_group_name)
        role = _role_name(role_name)
        return cast(
            AplReadback,
            _run_sync(self._create_disabled_and_readback(rule, group, role)),
        )

    def inspect_disable(
        self,
        auto_provision_rule_name: str,
        remote_user_group_name: str,
        role_name: str,
    ) -> AplDisableInspection:
        """Inspect only the exact existing enabled V4 APL disable baseline."""

        rule = _apl_name(auto_provision_rule_name)
        group = _user_group_name(remote_user_group_name)
        role = _role_name(role_name)
        return cast(
            AplDisableInspection,
            _run_sync(self._inspect_disable(rule, group, role)),
        )

    def disable_and_readback(
        self,
        auto_provision_rule_name: str,
        remote_user_group_name: str,
        role_name: str,
    ) -> AplReadback:
        """Disable only the exact enabled V4 APL baseline and read it back."""

        rule = _apl_name(auto_provision_rule_name)
        group = _user_group_name(remote_user_group_name)
        role = _role_name(role_name)
        return cast(
            AplReadback,
            _run_sync(self._disable_and_readback(rule, group, role)),
        )

    async def _inspect(
        self,
        auto_provision_rule_name: str,
        remote_user_group_name: str,
        role_name: str,
    ) -> AplInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                rule_output = await self._show_object(
                    process,
                    root_prompt,
                    _APL_CONFIG_COMMAND,
                    auto_provision_rule_name,
                    deadline,
                )
                group_output = await self._show_object(
                    process,
                    root_prompt,
                    _USER_GROUP_CONFIG_COMMAND,
                    remote_user_group_name,
                    deadline,
                )
                role_output = await self._show_object(
                    process,
                    root_prompt,
                    _ROLE_CONFIG_COMMAND,
                    role_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _inspection(
            rule_output,
            group_output,
            role_output,
            auto_provision_rule_name,
            remote_user_group_name,
            role_name,
        )

    async def _create_disabled_and_readback(
        self,
        auto_provision_rule_name: str,
        remote_user_group_name: str,
        role_name: str,
    ) -> AplReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                rule_output = await self._show_object(
                    process,
                    root_prompt,
                    _APL_CONFIG_COMMAND,
                    auto_provision_rule_name,
                    deadline,
                )
                group_output = await self._show_object(
                    process,
                    root_prompt,
                    _USER_GROUP_CONFIG_COMMAND,
                    remote_user_group_name,
                    deadline,
                )
                role_output = await self._show_object(
                    process,
                    root_prompt,
                    _ROLE_CONFIG_COMMAND,
                    role_name,
                    deadline,
                )
                baseline = _inspection(
                    rule_output,
                    group_output,
                    role_output,
                    auto_provision_rule_name,
                    remote_user_group_name,
                    role_name,
                )
                if not baseline.create_baseline_verified:
                    raise AplSshTransportError(_UNAVAILABLE)
                await self._create_disabled_rule(
                    process,
                    root_prompt,
                    auto_provision_rule_name,
                    remote_user_group_name,
                    role_name,
                    deadline,
                )
                output = await self._show_object(
                    process,
                    root_prompt,
                    _APL_CONFIG_COMMAND,
                    auto_provision_rule_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(
            output,
            auto_provision_rule_name,
            remote_user_group_name,
            role_name,
        )

    async def _inspect_disable(
        self,
        auto_provision_rule_name: str,
        remote_user_group_name: str,
        role_name: str,
    ) -> AplDisableInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                rule_output = await self._show_object(
                    process,
                    root_prompt,
                    _APL_CONFIG_COMMAND,
                    auto_provision_rule_name,
                    deadline,
                )
                group_output = await self._show_object(
                    process,
                    root_prompt,
                    _USER_GROUP_CONFIG_COMMAND,
                    remote_user_group_name,
                    deadline,
                )
                role_output = await self._show_object(
                    process,
                    root_prompt,
                    _ROLE_CONFIG_COMMAND,
                    role_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _disable_inspection(
            rule_output,
            group_output,
            role_output,
            auto_provision_rule_name,
            remote_user_group_name,
            role_name,
        )

    async def _disable_and_readback(
        self,
        auto_provision_rule_name: str,
        remote_user_group_name: str,
        role_name: str,
    ) -> AplReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                rule_output = await self._show_object(
                    process,
                    root_prompt,
                    _APL_CONFIG_COMMAND,
                    auto_provision_rule_name,
                    deadline,
                )
                group_output = await self._show_object(
                    process,
                    root_prompt,
                    _USER_GROUP_CONFIG_COMMAND,
                    remote_user_group_name,
                    deadline,
                )
                role_output = await self._show_object(
                    process,
                    root_prompt,
                    _ROLE_CONFIG_COMMAND,
                    role_name,
                    deadline,
                )
                baseline = _disable_inspection(
                    rule_output,
                    group_output,
                    role_output,
                    auto_provision_rule_name,
                    remote_user_group_name,
                    role_name,
                )
                if not baseline.disable_baseline_verified:
                    raise AplSshTransportError(_UNAVAILABLE)
                await self._disable_rule(
                    process,
                    root_prompt,
                    auto_provision_rule_name,
                    deadline,
                )
                output = await self._show_object(
                    process,
                    root_prompt,
                    _APL_CONFIG_COMMAND,
                    auto_provision_rule_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(
            output,
            auto_provision_rule_name,
            remote_user_group_name,
            role_name,
        )

    async def _create_disabled_rule(
        self,
        process: Any,
        root_prompt: bytes,
        auto_provision_rule_name: str,
        remote_user_group_name: str,
        role_name: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _APL_CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            rule_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{auto_provision_rule_name}"',
                root_prompt,
                deadline,
            )
            await _send_and_read(process, "set status disable", rule_prompt, deadline)
            await _send_and_read(
                process,
                f'set remote-group "{remote_user_group_name}"',
                rule_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                f'set accprofile "{role_name}"',
                rule_prompt,
                deadline,
            )
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise AplSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise AplSshTransportError(_UNAVAILABLE) from exc

    async def _disable_rule(
        self,
        process: Any,
        root_prompt: bytes,
        auto_provision_rule_name: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _APL_CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            rule_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{auto_provision_rule_name}"',
                root_prompt,
                deadline,
            )
            await _send_and_read(process, "set status disable", rule_prompt, deadline)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise AplSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise AplSshTransportError(_UNAVAILABLE) from exc

    async def _show_object(
        self,
        process: Any,
        root_prompt: bytes,
        config_command: str,
        object_name: str,
        deadline: float,
    ) -> bytes:
        """Return only bounded CLI bytes for a pre-validated V4 object name."""

        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                config_command,
                root_prompt,
                deadline,
            )
            compact = await _send_and_read(
                process,
                f"show | grep {object_name}",
                table_prompt,
                deadline,
            )
            full = await _send_and_read(
                process,
                f"show | grep {object_name} -f",
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
            raise AplSshTransportError(_UNAVAILABLE) from exc

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
            raise AplSshTransportError(_UNAVAILABLE) from exc


def _inspection(
    rule_output: bytes,
    group_output: bytes,
    role_output: bytes,
    auto_provision_rule_name: str,
    remote_user_group_name: str,
    role_name: str,
) -> AplInspection:
    return AplInspection(
        auto_provision_rule_exists=(
            _marker(auto_provision_rule_name) in _normalized(rule_output)
        ),
        remote_user_group_exists=(
            _marker(remote_user_group_name) in _normalized(group_output)
        ),
        role_exists=_marker(role_name) in _normalized(role_output),
    )


def _disable_inspection(
    rule_output: bytes,
    group_output: bytes,
    role_output: bytes,
    auto_provision_rule_name: str,
    remote_user_group_name: str,
    role_name: str,
) -> AplDisableInspection:
    normalized = _normalized(rule_output)
    return AplDisableInspection(
        auto_provision_rule_exists=_marker(auto_provision_rule_name) in normalized,
        status_enabled=b"set status enable" in normalized,
        remote_user_group_matches=(
            f'set remote-group "{remote_user_group_name}"'.encode("ascii")
            in normalized
        ),
        role_matches=f'set accprofile "{role_name}"'.encode("ascii") in normalized,
        remote_user_group_exists=(
            _marker(remote_user_group_name) in _normalized(group_output)
        ),
        role_exists=_marker(role_name) in _normalized(role_output),
    )


def _readback(
    output: bytes,
    auto_provision_rule_name: str,
    remote_user_group_name: str,
    role_name: str,
) -> AplReadback:
    normalized = _normalized(output)
    return AplReadback(
        auto_provision_rule_exists=_marker(auto_provision_rule_name) in normalized,
        status_disabled=b"set status disable" in normalized,
        remote_user_group_matches=(
            f'set remote-group "{remote_user_group_name}"'.encode("ascii")
            in normalized
        ),
        role_matches=f'set accprofile "{role_name}"'.encode("ascii") in normalized,
    )


def _normalized(output: bytes) -> bytes:
    return output.replace(b"\r", b"")


def _marker(name: str) -> bytes:
    return f'edit "{name}"'.encode("ascii")


def _apl_name(value: str) -> str:
    if not isinstance(value, str) or _APL_NAME.fullmatch(value) is None:
        raise AplSshTransportError(_UNAVAILABLE)
    return value


def _user_group_name(value: str) -> str:
    if not isinstance(value, str) or _USER_GROUP_NAME.fullmatch(value) is None:
        raise AplSshTransportError(_UNAVAILABLE)
    return value


def _role_name(value: str) -> str:
    if not isinstance(value, str) or _ROLE_NAME.fullmatch(value) is None:
        raise AplSshTransportError(_UNAVAILABLE)
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
        raise AplSshTransportConfigurationError(
            f"The Auto-Provision Rule SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise AplSshTransportConfigurationError(
            f"The Auto-Provision Rule SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AplSshTransportConfigurationError(
            f"The Auto-Provision Rule SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AplSshTransportConfigurationError(
            "The Auto-Provision Rule SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AplSshTransportConfigurationError(
            "The Auto-Provision Rule SSH password file is invalid."
        ) from exc


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    return _value_for_prefix(environment, ENV_PREFIX, suffix)


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
    except AplSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise AplSshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "APL_CONFIGURATION",
    "APL_DISABLE_CONFIGURATION",
    "APL_NAME_PREFIX",
    "AplDisableInspection",
    "AplInspection",
    "AplReadback",
    "AplSshTransportConfig",
    "AplSshTransportConfigurationError",
    "AplSshTransportError",
    "DISABLE_ENV_PREFIX",
    "ENV_PREFIX",
    "FortiPamAplSshTransport",
    "load_apl_ssh_transport_config",
    "load_apl_disable_ssh_transport_config",
]
