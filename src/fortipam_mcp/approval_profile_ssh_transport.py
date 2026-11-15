"""Pinned SSH fallback for one bounded FortiPAM Approval Profile create.

The FortiPAM 1.9.1 Administration Guide supplies an Approval Profile CLI
example, while the API catalog has no POST request schema. This creates only an
unbound single-tier Profile; it never associates a Secret or starts approval.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_APPROVAL_PROFILE_"
UPDATE_ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_APPROVAL_PROFILE_UPDATE_"
APPROVAL_PROFILE_NAME_PREFIX = "mcp-v4-approval-profile-"
APPROVAL_PROFILE_CONFIGURATION = "single-tier-admin-unbound-v1"
APPROVAL_PROFILE_UPDATE_CONFIGURATION = "single-tier-admin-description-update-v1"
APPROVAL_PROFILE_UPDATED_DESCRIPTION = "MCP V4 updated unbound approval profile"
_CONFIG_COMMAND = "config secret approval-profile"
_NAME = re.compile(r"mcp-v4-approval-profile-[A-Za-z0-9][A-Za-z0-9._-]{0,39}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_UNAVAILABLE = "FortiPAM V4 Approval Profile transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_FULL_CONTEXT_LINES = 80
_APPROVAL_SETTINGS = (
    "set type single",
    "set first-num 1",
    'set first-user "admin"',
    'set description "MCP V4 unbound approval profile"',
    "set remote-group-email disable",
    "set approver-perm-req none",
    "set email-template ''",
    "set email-approval-link-expiry 120",
)
_UPDATED_DESCRIPTION = f'set description "{APPROVAL_PROFILE_UPDATED_DESCRIPTION}"'


class ApprovalProfileSshTransportError(RuntimeError):
    """Stable non-disclosing failure for the bounded SSH transport."""


class ApprovalProfileSshTransportConfigurationError(ValueError):
    """Raised when dedicated Approval Profile SSH settings are unsafe."""


@dataclass(frozen=True, slots=True)
class ApprovalProfileSshTransportConfig:
    """Dedicated pinned SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise ApprovalProfileSshTransportConfigurationError(
                "The Approval Profile SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise ApprovalProfileSshTransportConfigurationError(
                "The Approval Profile SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise ApprovalProfileSshTransportConfigurationError(
                "The Approval Profile SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise ApprovalProfileSshTransportConfigurationError(
                "The Approval Profile SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise ApprovalProfileSshTransportConfigurationError(
                "The Approval Profile SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class ApprovalProfileInspection:
    """Value-minimized preflight evidence for one Approval Profile."""

    profile_name_exists: bool


@dataclass(frozen=True, slots=True)
class ApprovalProfileReadback:
    """Categorical readback for the fixed single-tier Profile contract."""

    profile_name_exists: bool
    single_tier_enabled: bool
    first_approval_count_one: bool
    fixed_approver_present: bool
    fixed_description_present: bool
    remote_group_email_disabled: bool
    approver_permission_requirement_none: bool
    email_template_unset: bool
    email_approval_link_expiry_default: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.profile_name_exists,
                self.single_tier_enabled,
                self.first_approval_count_one,
                self.fixed_approver_present,
                self.fixed_description_present,
                self.remote_group_email_disabled,
                self.approver_permission_requirement_none,
                self.email_template_unset,
                self.email_approval_link_expiry_default,
            )
        )


@dataclass(frozen=True, slots=True)
class ApprovalProfileUpdateReadback:
    """Categorical readback for one fixed Profile description update."""

    profile_name_exists: bool
    single_tier_enabled: bool
    first_approval_count_one: bool
    fixed_approver_present: bool
    updated_description_present: bool
    remote_group_email_disabled: bool
    approver_permission_requirement_none: bool
    email_template_unset: bool
    email_approval_link_expiry_default: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.profile_name_exists,
                self.single_tier_enabled,
                self.first_approval_count_one,
                self.fixed_approver_present,
                self.updated_description_present,
                self.remote_group_email_disabled,
                self.approver_permission_requirement_none,
                self.email_template_unset,
                self.email_approval_link_expiry_default,
            )
        )


def load_approval_profile_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> ApprovalProfileSshTransportConfig:
    """Load only independently scoped Approval Profile SSH credentials."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise ApprovalProfileSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise ApprovalProfileSshTransportConfigurationError(
            "Dedicated Approval Profile SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise ApprovalProfileSshTransportConfigurationError(
            "The Approval Profile SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return ApprovalProfileSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


def load_approval_profile_update_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> ApprovalProfileSshTransportConfig:
    """Load only independently scoped Approval Profile update SSH credentials."""

    env = os.environ if environment is None else environment
    if _value_for_prefix(env, UPDATE_ENV_PREFIX, "ENABLED") != "true":
        raise ApprovalProfileSshTransportConfigurationError(
            f"{UPDATE_ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value_for_prefix(env, UPDATE_ENV_PREFIX, "SSH_HOST")
    username = _value_for_prefix(env, UPDATE_ENV_PREFIX, "SSH_USERNAME")
    password_file = _value_for_prefix(env, UPDATE_ENV_PREFIX, "SSH_PASSWORD_FILE")
    known_hosts_file = _value_for_prefix(env, UPDATE_ENV_PREFIX, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value_for_prefix(env, UPDATE_ENV_PREFIX, "SSH_PORT") or "22"
    timeout_raw = _value_for_prefix(env, UPDATE_ENV_PREFIX, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise ApprovalProfileSshTransportConfigurationError(
            "Dedicated Approval Profile update SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise ApprovalProfileSshTransportConfigurationError(
            "The Approval Profile update SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return ApprovalProfileSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamApprovalProfileSshTransport:
    """Run only compiled Approval Profile inspection and creation commands."""

    def __init__(self, config: ApprovalProfileSshTransportConfig) -> None:
        self._config = config

    def inspect(self, profile_name: str) -> ApprovalProfileInspection:
        safe_name = _profile_name(profile_name)
        return cast(ApprovalProfileInspection, _run_sync(self._inspect(safe_name)))

    def create_and_readback(self, profile_name: str) -> ApprovalProfileReadback:
        safe_name = _profile_name(profile_name)
        return cast(
            ApprovalProfileReadback,
            _run_sync(self._create_and_readback(safe_name)),
        )

    def readback(self, profile_name: str) -> ApprovalProfileReadback:
        safe_name = _profile_name(profile_name)
        return cast(ApprovalProfileReadback, _run_sync(self._readback(safe_name)))

    def update_description_and_readback(
        self,
        profile_name: str,
    ) -> ApprovalProfileUpdateReadback:
        safe_name = _profile_name(profile_name)
        return cast(
            ApprovalProfileUpdateReadback,
            _run_sync(self._update_description_and_readback(safe_name)),
        )

    def readback_updated(
        self,
        profile_name: str,
    ) -> ApprovalProfileUpdateReadback:
        """Read the exact fixed updated projection without changing it."""

        safe_name = _profile_name(profile_name)
        return cast(
            ApprovalProfileUpdateReadback,
            _run_sync(self._readback_updated(safe_name)),
        )

    def reference_count(self, profile_name: str) -> int:
        """Return a strictly parsed fixed Profile CMDB reference count."""

        safe_name = _profile_name(profile_name)
        return cast(int, _run_sync(self._reference_count(safe_name)))

    async def _inspect(self, profile_name: str) -> ApprovalProfileInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_profile(
                    process,
                    root_prompt,
                    profile_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return ApprovalProfileInspection(
            profile_name_exists=_profile_marker(profile_name)
            in output.replace(b"\r", b"")
        )

    async def _create_and_readback(self, profile_name: str) -> ApprovalProfileReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_profile(
                    process,
                    root_prompt,
                    profile_name,
                    deadline,
                )
                output = await self._show_profile(
                    process,
                    root_prompt,
                    profile_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, profile_name)

    async def _readback(self, profile_name: str) -> ApprovalProfileReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_profile(
                    process,
                    root_prompt,
                    profile_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, profile_name)

    async def _update_description_and_readback(
        self,
        profile_name: str,
    ) -> ApprovalProfileUpdateReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._update_profile_description(
                    process,
                    root_prompt,
                    profile_name,
                    deadline,
                )
                output = await self._show_profile(
                    process,
                    root_prompt,
                    profile_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _update_readback(output, profile_name)

    async def _readback_updated(
        self,
        profile_name: str,
    ) -> ApprovalProfileUpdateReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_profile(
                    process,
                    root_prompt,
                    profile_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _update_readback(output, profile_name)

    async def _reference_count(self, profile_name: str) -> int:
        command = (
            "diagnose sys cmdb refcnt show secret.approval-profile.name "
            + profile_name
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

    async def _create_profile(
        self,
        process: Any,
        root_prompt: bytes,
        profile_name: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            profile_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{profile_name}"',
                root_prompt,
                deadline,
            )
            for command in _APPROVAL_SETTINGS:
                await _send_and_read(process, command, profile_prompt, deadline)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise ApprovalProfileSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ApprovalProfileSshTransportError(_UNAVAILABLE) from exc

    async def _update_profile_description(
        self,
        process: Any,
        root_prompt: bytes,
        profile_name: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            profile_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{profile_name}"',
                root_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                _UPDATED_DESCRIPTION,
                profile_prompt,
                deadline,
            )
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise ApprovalProfileSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ApprovalProfileSshTransportError(_UNAVAILABLE) from exc

    async def _show_profile(
        self,
        process: Any,
        root_prompt: bytes,
        profile_name: str,
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
                f"show | grep {profile_name}",
                table_prompt,
                deadline,
            )
            full = await _send_and_read(
                process,
                (
                    "show full-configuration | grep "
                    f'-A {_FULL_CONTEXT_LINES} "^ *edit.*{profile_name}"'
                ),
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
            raise ApprovalProfileSshTransportError(_UNAVAILABLE) from exc

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
            raise ApprovalProfileSshTransportError(_UNAVAILABLE) from exc


def _readback(output: bytes, profile_name: str) -> ApprovalProfileReadback:
    normalized = output.replace(b"\r", b"")
    return ApprovalProfileReadback(
        profile_name_exists=_profile_marker(profile_name) in normalized,
        single_tier_enabled=_APPROVAL_SETTINGS[0].encode("ascii") in normalized,
        first_approval_count_one=_APPROVAL_SETTINGS[1].encode("ascii") in normalized,
        fixed_approver_present=_APPROVAL_SETTINGS[2].encode("ascii") in normalized,
        fixed_description_present=_APPROVAL_SETTINGS[3].encode("ascii") in normalized,
        remote_group_email_disabled=_APPROVAL_SETTINGS[4].encode("ascii") in normalized,
        approver_permission_requirement_none=(
            _APPROVAL_SETTINGS[5].encode("ascii") in normalized
        ),
        email_template_unset=_APPROVAL_SETTINGS[6].encode("ascii") in normalized,
        email_approval_link_expiry_default=(
            _APPROVAL_SETTINGS[7].encode("ascii") in normalized
        ),
    )


def _update_readback(output: bytes, profile_name: str) -> ApprovalProfileUpdateReadback:
    normalized = output.replace(b"\r", b"")
    return ApprovalProfileUpdateReadback(
        profile_name_exists=_profile_marker(profile_name) in normalized,
        single_tier_enabled=_APPROVAL_SETTINGS[0].encode("ascii") in normalized,
        first_approval_count_one=_APPROVAL_SETTINGS[1].encode("ascii") in normalized,
        fixed_approver_present=_APPROVAL_SETTINGS[2].encode("ascii") in normalized,
        updated_description_present=_UPDATED_DESCRIPTION.encode("ascii") in normalized,
        remote_group_email_disabled=_APPROVAL_SETTINGS[4].encode("ascii") in normalized,
        approver_permission_requirement_none=(
            _APPROVAL_SETTINGS[5].encode("ascii") in normalized
        ),
        email_template_unset=_APPROVAL_SETTINGS[6].encode("ascii") in normalized,
        email_approval_link_expiry_default=(
            _APPROVAL_SETTINGS[7].encode("ascii") in normalized
        ),
    )


def _profile_marker(profile_name: str) -> bytes:
    return f'edit "{profile_name}"'.encode("ascii")


def _strict_reference_count(output: bytes, command: str, root_prompt: bytes) -> int:
    normalized = output.replace(b"\r", b"")
    lines = normalized.split(b"\n")
    if (
        len(lines) < 2
        or lines[0].strip() != command.encode("ascii")
        or lines[-1].rstrip(b" ") != root_prompt
    ):
        raise ApprovalProfileSshTransportError(_UNAVAILABLE)
    middle = [line for line in lines[1:-1] if line.strip()]
    if any(b"entry used by" not in line.lower() for line in middle):
        raise ApprovalProfileSshTransportError(_UNAVAILABLE)
    return len(middle)


def _profile_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise ApprovalProfileSshTransportError(_UNAVAILABLE)
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
        raise ApprovalProfileSshTransportConfigurationError(
            f"The Approval Profile SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ApprovalProfileSshTransportConfigurationError(
            f"The Approval Profile SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ApprovalProfileSshTransportConfigurationError(
            f"The Approval Profile SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ApprovalProfileSshTransportConfigurationError(
            "The Approval Profile SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApprovalProfileSshTransportConfigurationError(
            "The Approval Profile SSH password file is invalid."
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
    except ApprovalProfileSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise ApprovalProfileSshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "APPROVAL_PROFILE_CONFIGURATION",
    "APPROVAL_PROFILE_UPDATE_CONFIGURATION",
    "APPROVAL_PROFILE_NAME_PREFIX",
    "APPROVAL_PROFILE_UPDATED_DESCRIPTION",
    "ApprovalProfileInspection",
    "ApprovalProfileReadback",
    "ApprovalProfileUpdateReadback",
    "ApprovalProfileSshTransportConfig",
    "ApprovalProfileSshTransportConfigurationError",
    "ApprovalProfileSshTransportError",
    "ENV_PREFIX",
    "UPDATE_ENV_PREFIX",
    "FortiPamApprovalProfileSshTransport",
    "load_approval_profile_ssh_transport_config",
    "load_approval_profile_update_ssh_transport_config",
]
