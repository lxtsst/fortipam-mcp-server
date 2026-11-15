"""Pinned SSH transport for bounded FortiPAM Role create and update contracts.

The action creates only an unassigned, laboratory-prefixed custom Role whose
permissions reproduce the ``pam_standard_user`` CLI example in the FortiPAM
1.9.1 Administration Guide.  It accepts no caller-controlled permission,
assignment, target, Secret, or credential input.
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

from .cli_safety import (
    CliTransportError,
    _complete_pre_login,
    _raise_for_remote_rejection,
    _read_until_prompt,
)
from .target_ssh_transport import (
    _close_cli,
    _require_root_prompt,
    _send_and_read,
    _send_and_read_dynamic_prompt,
)


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_ROLE_CREATE_"
UPDATE_ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_ROLE_UPDATE_"
ROLE_NAME_PREFIX = "mcp-v4-role-"
ROLE_CONFIGURATION_PROFILE = "pam_standard_user_guide_profile_v1"
ROLE_UPDATE_CONFIGURATION_PROFILE = "pam_standard_user_diagnostics_enable_v1"
_ROLE_NAME = re.compile(r"mcp-v4-role-[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_DENIED_MESSAGE = "FortiPAM V4 Role create transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_CORE_COMMANDS = (
    "set secfabgrp read",
    "set ftviewgrp read",
    "set authgrp read",
    "set secretgrp custom",
)
_SECRET_PERMISSION_COMMANDS = (
    "set launcher read",
    "set pwd-changer read",
    "set template read-write",
    "set secret-policy read",
    "set request read-write",
    "set folder-table read-write",
    "set secret-table read-write",
    "set create-personal-folder read-write",
)
_UPDATED_SYSTEM_DIAGNOSTICS_COMMAND = "set system-diagnostics enable"


class RoleCreateSshTransportError(RuntimeError):
    """Stable, non-disclosing failure for the bounded SSH transport."""


class RoleCreateSshTransportConfigurationError(ValueError):
    """Raised when the dedicated Role create SSH configuration is unsafe."""


@dataclass(frozen=True, slots=True)
class RoleCreateSshTransportConfig:
    """Dedicated pinned-SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise RoleCreateSshTransportConfigurationError(
                "The Role create SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise RoleCreateSshTransportConfigurationError(
                "The Role create SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise RoleCreateSshTransportConfigurationError(
                "The Role create SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise RoleCreateSshTransportConfigurationError(
                "The Role create SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise RoleCreateSshTransportConfigurationError(
                "The Role create SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class RoleCreateInspection:
    """Value-minimized preflight evidence for one custom Role."""

    exists: bool


@dataclass(frozen=True, slots=True)
class RoleCreateReadback:
    """Categorical readback for the fixed guide-example Role contract."""

    role_exists: bool
    core_access_matches: bool
    secret_permissions_match: bool
    system_diagnostics_disabled: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.role_exists,
                self.core_access_matches,
                self.secret_permissions_match,
                self.system_diagnostics_disabled,
            )
        )


@dataclass(frozen=True, slots=True)
class RoleUpdateInspection:
    """Value-minimized eligibility state for one fixed Role update."""

    role_exists: bool
    core_access_matches: bool
    secret_permissions_match: bool
    system_diagnostics_disabled: bool
    role_assigned: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.role_exists,
                self.core_access_matches,
                self.secret_permissions_match,
                self.system_diagnostics_disabled,
                not self.role_assigned,
            )
        )


@dataclass(frozen=True, slots=True)
class RoleUpdateReadback:
    """Categorical postcondition for the fixed diagnostic-permission update."""

    role_exists: bool
    core_access_matches: bool
    secret_permissions_match: bool
    system_diagnostics_enabled: bool
    role_assigned: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.role_exists,
                self.core_access_matches,
                self.secret_permissions_match,
                self.system_diagnostics_enabled,
                not self.role_assigned,
            )
        )


def load_role_create_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> RoleCreateSshTransportConfig:
    """Load only independently scoped Role create SSH credentials."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise RoleCreateSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise RoleCreateSshTransportConfigurationError(
            "Dedicated Role create SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise RoleCreateSshTransportConfigurationError(
            "The Role create SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return RoleCreateSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


def load_role_update_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> RoleCreateSshTransportConfig:
    """Load only independently scoped Role-update SSH credentials."""

    env = os.environ if environment is None else environment
    if _value_for_prefix(env, UPDATE_ENV_PREFIX, "ENABLED") != "true":
        raise RoleCreateSshTransportConfigurationError(
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
        raise RoleCreateSshTransportConfigurationError(
            "Dedicated Role update SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise RoleCreateSshTransportConfigurationError(
            "The Role update SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return RoleCreateSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamRoleCreateSshTransport:
    """Run only compiled inspection and fixed unassigned-Role creation commands."""

    def __init__(self, config: RoleCreateSshTransportConfig) -> None:
        self._config = config

    def inspect(self, role_name: str) -> RoleCreateInspection:
        name = _role_name(role_name)
        return cast(RoleCreateInspection, _run_sync(self._inspect(name)))

    def create_and_readback(self, role_name: str) -> RoleCreateReadback:
        name = _role_name(role_name)
        return cast(RoleCreateReadback, _run_sync(self._create_and_readback(name)))

    def inspect_update(self, role_name: str) -> RoleUpdateInspection:
        """Read the exact guide-example baseline and assignment absence."""

        name = _role_name(role_name)
        return cast(RoleUpdateInspection, _run_sync(self._inspect_update(name)))

    def enable_diagnostics_and_readback(self, role_name: str) -> RoleUpdateReadback:
        """Enable only diagnostic CLI permission and return categorical readback."""

        name = _role_name(role_name)
        return cast(
            RoleUpdateReadback,
            _run_sync(self._enable_diagnostics_and_readback(name)),
        )

    async def _inspect(self, role_name: str) -> RoleCreateInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                compact = await self._run_accprofile_context(
                    process,
                    root_prompt,
                    (f"show | grep {role_name}",),
                    deadline,
                )
                full = await self._run_accprofile_context(
                    process,
                    root_prompt,
                    (f"show | grep {role_name} -f",),
                    deadline,
                )
            finally:
                await _close_cli(process)
        marker = f'edit "{role_name}"'.encode("ascii")
        return RoleCreateInspection(exists=marker in compact + full)

    async def _create_and_readback(self, role_name: str) -> RoleCreateReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_role(process, root_prompt, role_name, deadline)
                output = await self._read_role_entry(
                    process, root_prompt, role_name, deadline
                )
            finally:
                await _close_cli(process)
        return _readback(output, role_name)

    async def _inspect_update(self, role_name: str) -> RoleUpdateInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                role_output = await self._read_role_entry(
                    process, root_prompt, role_name, deadline
                )
                assignment_output = await self._run_admin_context(
                    process,
                    root_prompt,
                    (
                        f"show | grep {role_name}",
                        f"show | grep {role_name} -f",
                    ),
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _update_inspection(role_output, assignment_output, role_name)

    async def _enable_diagnostics_and_readback(
        self,
        role_name: str,
    ) -> RoleUpdateReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._enable_system_diagnostics(
                    process,
                    root_prompt,
                    role_name,
                    deadline,
                )
                role_output = await self._read_role_entry(
                    process, root_prompt, role_name, deadline
                )
                assignment_output = await self._run_admin_context(
                    process,
                    root_prompt,
                    (
                        f"show | grep {role_name}",
                        f"show | grep {role_name} -f",
                    ),
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _update_readback(role_output, assignment_output, role_name)

    async def _create_role(
        self,
        process: Any,
        root_prompt: bytes,
        role_name: str,
        deadline: float,
    ) -> None:
        table_prompt = _accprofile_context_prompt(root_prompt)
        try:
            await _send_and_read(process, "config system accprofile", table_prompt, deadline)
            entry_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{role_name}"',
                root_prompt,
                deadline,
            )
            for command in _CORE_COMMANDS:
                await _send_and_read(process, command, entry_prompt, deadline)
            permission_prompt = await _send_and_read_dynamic_prompt(
                process,
                "config secretgrp-permission",
                root_prompt,
                deadline,
            )
            for command in _SECRET_PERMISSION_COMMANDS:
                await _send_and_read(process, command, permission_prompt, deadline)
            returned_entry = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            if returned_entry != entry_prompt:
                raise RoleCreateSshTransportError(_DENIED_MESSAGE)
            returned_context = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_context != table_prompt:
                raise RoleCreateSshTransportError(_DENIED_MESSAGE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise RoleCreateSshTransportError(_DENIED_MESSAGE) from exc

    async def _enable_system_diagnostics(
        self,
        process: Any,
        root_prompt: bytes,
        role_name: str,
        deadline: float,
    ) -> None:
        table_prompt = _accprofile_context_prompt(root_prompt)
        try:
            await _send_and_read(process, "config system accprofile", table_prompt, deadline)
            entry_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{role_name}"',
                root_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                _UPDATED_SYSTEM_DIAGNOSTICS_COMMAND,
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
                raise RoleCreateSshTransportError(_DENIED_MESSAGE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise RoleCreateSshTransportError(_DENIED_MESSAGE) from exc

    async def _run_accprofile_context(
        self,
        process: Any,
        root_prompt: bytes,
        commands: tuple[str, ...],
        deadline: float,
    ) -> bytes:
        context_prompt = _accprofile_context_prompt(root_prompt)
        try:
            await _send_and_read(process, "config system accprofile", context_prompt, deadline)
            outputs = [
                await _send_and_read(process, command, context_prompt, deadline)
                for command in commands
            ]
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
            return b"".join(outputs)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise RoleCreateSshTransportError(_DENIED_MESSAGE) from exc

    async def _read_role_entry(
        self,
        process: Any,
        root_prompt: bytes,
        role_name: str,
        deadline: float,
    ) -> bytes:
        """Read one exact Role entry so nested permissions remain observable."""

        table_prompt = _accprofile_context_prompt(root_prompt)
        try:
            entered_table = await _send_and_read_dynamic_prompt(
                process, "config system accprofile", root_prompt, deadline
            )
            if entered_table != table_prompt:
                raise RoleCreateSshTransportError(_DENIED_MESSAGE)
            entry_prompt = await _send_and_read_dynamic_prompt(
                process, f'edit "{role_name}"', root_prompt, deadline
            )
            output = await _send_and_read(
                process, "show", entry_prompt, deadline
            )
            returned_table = await _send_and_read_dynamic_prompt(
                process, "next", root_prompt, deadline
            )
            if returned_table != table_prompt:
                raise RoleCreateSshTransportError(_DENIED_MESSAGE)
            returned_root = await _send_and_read_dynamic_prompt(
                process, "end", root_prompt, deadline
            )
            _require_root_prompt(root_prompt, returned_root)
            return output
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise RoleCreateSshTransportError(_DENIED_MESSAGE) from exc

    async def _run_admin_context(
        self,
        process: Any,
        root_prompt: bytes,
        commands: tuple[str, ...],
        deadline: float,
    ) -> bytes:
        context_prompt = _admin_context_prompt(root_prompt)
        try:
            await _send_and_read(process, "config system admin", context_prompt, deadline)
            outputs = [
                await _send_and_read(process, command, context_prompt, deadline)
                for command in commands
            ]
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
            return b"".join(outputs)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise RoleCreateSshTransportError(_DENIED_MESSAGE) from exc

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
            raise RoleCreateSshTransportError(_DENIED_MESSAGE) from exc


def _readback(output: bytes, role_name: str) -> RoleCreateReadback:
    normalized = output.replace(b"\r", b"")
    return RoleCreateReadback(
        role_exists=f'edit "{role_name}"'.encode("ascii") in normalized,
        core_access_matches=all(
            command.encode("ascii") in normalized for command in _CORE_COMMANDS
        ),
        secret_permissions_match=all(
            command.encode("ascii") in normalized
            for command in _SECRET_PERMISSION_COMMANDS
        ),
        system_diagnostics_disabled=b"set system-diagnostics enable" not in normalized,
    )


def _update_inspection(
    role_output: bytes,
    assignment_output: bytes,
    role_name: str,
) -> RoleUpdateInspection:
    normalized = role_output.replace(b"\r", b"")
    return RoleUpdateInspection(
        role_exists=_role_marker(role_name) in normalized,
        core_access_matches=all(
            command.encode("ascii") in normalized for command in _CORE_COMMANDS
        ) and _diagnostics_prerequisites_match(normalized),
        secret_permissions_match=all(
            command.encode("ascii") in normalized
            for command in _SECRET_PERMISSION_COMMANDS
        ),
        system_diagnostics_disabled=b"set system-diagnostics enable" not in normalized,
        role_assigned=_role_assignment_marker(role_name)
        in assignment_output.replace(b"\r", b""),
    )


def _update_readback(
    role_output: bytes,
    assignment_output: bytes,
    role_name: str,
) -> RoleUpdateReadback:
    normalized = role_output.replace(b"\r", b"")
    return RoleUpdateReadback(
        role_exists=_role_marker(role_name) in normalized,
        core_access_matches=all(
            command.encode("ascii") in normalized for command in _CORE_COMMANDS
        ) and _diagnostics_prerequisites_match(normalized),
        secret_permissions_match=all(
            command.encode("ascii") in normalized
            for command in _SECRET_PERMISSION_COMMANDS
        ),
        system_diagnostics_enabled=(
            _UPDATED_SYSTEM_DIAGNOSTICS_COMMAND.encode("ascii") in normalized
        ),
        role_assigned=_role_assignment_marker(role_name)
        in assignment_output.replace(b"\r", b""),
    )


def _diagnostics_prerequisites_match(output: bytes) -> bool:
    """Require the native CLI and System Admin dependencies before an update."""

    if re.search(rb"(?m)^\s*set cli enable\s*$", output) is None:
        return False
    if re.search(rb"(?m)^\s*set sysgrp read-write\s*$", output) is not None:
        return True
    if re.search(rb"(?m)^\s*set sysgrp custom\s*$", output) is None:
        return False
    permission = re.search(
        rb"(?ms)^\s*config sysgrp-permission\s*\n(.*?)^\s*end\s*$", output
    )
    return permission is not None and re.search(
        rb"(?m)^\s*set admin read-write\s*$", permission.group(1)
    ) is not None


def _accprofile_context_prompt(root_prompt: bytes) -> bytes:
    if (
        len(root_prompt) < 3
        or root_prompt[-2:-1] != b" "
        or root_prompt[-1:] not in {b"#", b"$"}
    ):
        raise RoleCreateSshTransportError(_DENIED_MESSAGE)
    return root_prompt[:-2] + b" (accprofile) " + root_prompt[-1:]


def _admin_context_prompt(root_prompt: bytes) -> bytes:
    if (
        len(root_prompt) < 3
        or root_prompt[-2:-1] != b" "
        or root_prompt[-1:] not in {b"#", b"$"}
    ):
        raise RoleCreateSshTransportError(_DENIED_MESSAGE)
    return root_prompt[:-2] + b" (admin) " + root_prompt[-1:]


def _role_marker(role_name: str) -> bytes:
    return f'edit "{role_name}"'.encode("ascii")


def _role_assignment_marker(role_name: str) -> bytes:
    return f'set accprofile "{role_name}"'.encode("ascii")


def _role_name(value: str) -> str:
    if not isinstance(value, str) or _ROLE_NAME.fullmatch(value) is None:
        raise RoleCreateSshTransportError(_DENIED_MESSAGE)
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
        raise RoleCreateSshTransportConfigurationError(
            f"The Role create SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RoleCreateSshTransportConfigurationError(
            f"The Role create SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise RoleCreateSshTransportConfigurationError(
            f"The Role create SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RoleCreateSshTransportConfigurationError(
            "The Role create SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RoleCreateSshTransportConfigurationError(
            "The Role create SSH password file is invalid."
        ) from exc
    return value


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
    except RoleCreateSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise RoleCreateSshTransportError(_DENIED_MESSAGE) from exc


__all__ = [
    "ENV_PREFIX",
    "UPDATE_ENV_PREFIX",
    "FortiPamRoleCreateSshTransport",
    "ROLE_CONFIGURATION_PROFILE",
    "ROLE_UPDATE_CONFIGURATION_PROFILE",
    "ROLE_NAME_PREFIX",
    "RoleCreateInspection",
    "RoleCreateReadback",
    "RoleCreateSshTransportConfig",
    "RoleCreateSshTransportConfigurationError",
    "RoleCreateSshTransportError",
    "RoleUpdateInspection",
    "RoleUpdateReadback",
    "load_role_create_ssh_transport_config",
    "load_role_update_ssh_transport_config",
]
