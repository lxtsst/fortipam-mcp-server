"""Pinned SSH fallback for one bounded FortiPAM Secret Policy create.

The FortiPAM API catalog exposes Secret Policy routes, but its 1.9.1 REST
request body is not established.  This module therefore implements only the
Administration Guide's fixed ``config secret policy`` grammar.  It creates an
unattached laboratory Policy with SSH filtering disabled and RDP clipboard
blocking enabled; it is not a generic CLI relay.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_SECRET_POLICY_"
SECRET_POLICY_NAME_PREFIX = "mcp-v4-secret-policy-"
SECRET_POLICY_CONFIGURATION = "clipboard-block-and-ssh-filter-disabled-v1"
SECRET_POLICY_UPDATE_CONFIGURATION = "clipboard-block-disable-on-create-baseline-v1"
_CONFIG_COMMAND = "config secret policy"
_SETTING_COMMANDS = (
    "set ssh-filter disable",
    "set block-clipboard enable",
)
_UPDATE_SETTING_COMMAND = "set block-clipboard disable"
_NAME = re.compile(r"mcp-v4-secret-policy-[A-Za-z0-9][A-Za-z0-9._-]{0,42}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_UNAVAILABLE = "FortiPAM V4 Secret Policy transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_FULL_CONTEXT_LINES = 80


class SecretPolicySshTransportError(RuntimeError):
    """Stable non-disclosing failure for the bounded SSH transport."""


class SecretPolicySshTransportConfigurationError(ValueError):
    """Raised when dedicated Secret Policy SSH settings are unsafe."""


@dataclass(frozen=True, slots=True)
class SecretPolicySshTransportConfig:
    """Dedicated pinned-SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise SecretPolicySshTransportConfigurationError(
                "The Secret Policy SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise SecretPolicySshTransportConfigurationError(
                "The Secret Policy SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise SecretPolicySshTransportConfigurationError(
                "The Secret Policy SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise SecretPolicySshTransportConfigurationError(
                "The Secret Policy SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise SecretPolicySshTransportConfigurationError(
                "The Secret Policy SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class SecretPolicyInspection:
    """Value-minimized preflight evidence for one Secret Policy."""

    policy_name_exists: bool


@dataclass(frozen=True, slots=True)
class SecretPolicyReadback:
    """Categorical readback for the one fixed unattached Policy contract."""

    policy_name_exists: bool
    ssh_filter_disabled: bool
    rdp_clipboard_block_enabled: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.policy_name_exists,
                self.ssh_filter_disabled,
                self.rdp_clipboard_block_enabled,
            )
        )


@dataclass(frozen=True, slots=True)
class SecretPolicyUpdateBaseline:
    """Categorical prerequisite for the single permitted Policy update."""

    policy_name_exists: bool
    ssh_filter_disabled: bool
    rdp_clipboard_block_enabled: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.policy_name_exists,
                self.ssh_filter_disabled,
                self.rdp_clipboard_block_enabled,
            )
        )


@dataclass(frozen=True, slots=True)
class SecretPolicyUpdateReadback:
    """Categorical result for the one fixed Policy update."""

    policy_name_exists: bool
    ssh_filter_disabled: bool
    rdp_clipboard_block_disabled: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.policy_name_exists,
                self.ssh_filter_disabled,
                self.rdp_clipboard_block_disabled,
            )
        )


def load_secret_policy_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> SecretPolicySshTransportConfig:
    """Load only independently scoped Secret Policy SSH credentials."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise SecretPolicySshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise SecretPolicySshTransportConfigurationError(
            "Dedicated Secret Policy SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise SecretPolicySshTransportConfigurationError(
            "The Secret Policy SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return SecretPolicySshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamSecretPolicySshTransport:
    """Run only compiled Policy inspection plus fixed create/update commands."""

    def __init__(self, config: SecretPolicySshTransportConfig) -> None:
        self._config = config

    def inspect(self, policy_name: str) -> SecretPolicyInspection:
        safe_name = _policy_name(policy_name)
        return cast(SecretPolicyInspection, _run_sync(self._inspect(safe_name)))

    def create_and_readback(self, policy_name: str) -> SecretPolicyReadback:
        safe_name = _policy_name(policy_name)
        return cast(
            SecretPolicyReadback,
            _run_sync(self._create_and_readback(safe_name)),
        )

    def read_update_baseline(self, policy_name: str) -> SecretPolicyUpdateBaseline:
        """Return the exact create baseline required before the one update."""

        safe_name = _policy_name(policy_name)
        return cast(
            SecretPolicyUpdateBaseline,
            _run_sync(self._read_update_baseline(safe_name)),
        )

    def read_session_security_baseline(self, policy_name: str) -> SecretPolicyUpdateBaseline:
        """Read only the selected complete CLI block for onboarding checks.

        The legacy mutation baseline deliberately retains its original parser.
        A read-only check must not combine controls from trailing grep context.
        """
        safe_name = _policy_name(policy_name)
        return cast(SecretPolicyUpdateBaseline,
            _run_sync(self._read_update_baseline(safe_name, session_security=True)))

    def update_clipboard_and_readback(
        self,
        policy_name: str,
    ) -> SecretPolicyUpdateReadback:
        """Disable only RDP clipboard blocking on the exact local baseline."""

        safe_name = _policy_name(policy_name)
        return cast(
            SecretPolicyUpdateReadback,
            _run_sync(self._update_clipboard_and_readback(safe_name)),
        )

    async def _inspect(self, policy_name: str) -> SecretPolicyInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_policy(
                    process,
                    root_prompt,
                    policy_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return SecretPolicyInspection(
            policy_name_exists=_policy_marker(policy_name)
            in output.replace(b"\r", b"")
        )

    async def _create_and_readback(self, policy_name: str) -> SecretPolicyReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_policy(process, root_prompt, policy_name, deadline)
                output = await self._show_policy(
                    process,
                    root_prompt,
                    policy_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, policy_name)

    async def _read_update_baseline(
        self,
        policy_name: str,
        *, session_security: bool = False,
    ) -> SecretPolicyUpdateBaseline:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_policy(
                    process,
                    root_prompt,
                    policy_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        if session_security:
            output = _selected_session_security_policy(output, policy_name)
        return _update_baseline(output, policy_name)

    async def _update_clipboard_and_readback(
        self,
        policy_name: str,
    ) -> SecretPolicyUpdateReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._update_clipboard_policy(
                    process,
                    root_prompt,
                    policy_name,
                    deadline,
                )
                output = await self._show_policy(
                    process,
                    root_prompt,
                    policy_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _update_readback(output, policy_name)

    async def _create_policy(
        self,
        process: Any,
        root_prompt: bytes,
        policy_name: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            policy_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{policy_name}"',
                root_prompt,
                deadline,
            )
            for command in _SETTING_COMMANDS:
                await _send_and_read(process, command, policy_prompt, deadline)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise SecretPolicySshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise SecretPolicySshTransportError(_UNAVAILABLE) from exc

    async def _update_clipboard_policy(
        self,
        process: Any,
        root_prompt: bytes,
        policy_name: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            policy_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{policy_name}"',
                root_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                _UPDATE_SETTING_COMMAND,
                policy_prompt,
                deadline,
            )
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise SecretPolicySshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise SecretPolicySshTransportError(_UNAVAILABLE) from exc

    async def _show_policy(
        self,
        process: Any,
        root_prompt: bytes,
        policy_name: str,
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
                f"show | grep {policy_name}",
                table_prompt,
                deadline,
            )
            full = await _send_and_read(
                process,
                (
                    "show full-configuration | grep "
                    f'-A {_FULL_CONTEXT_LINES} "^ *edit.*{policy_name}"'
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
            raise SecretPolicySshTransportError(_UNAVAILABLE) from exc

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
            raise SecretPolicySshTransportError(_UNAVAILABLE) from exc


def _readback(output: bytes, policy_name: str) -> SecretPolicyReadback:
    normalized = output.replace(b"\r", b"")
    return SecretPolicyReadback(
        policy_name_exists=_policy_marker(policy_name) in normalized,
        ssh_filter_disabled=b"set ssh-filter disable" in normalized,
        rdp_clipboard_block_enabled=b"set block-clipboard enable" in normalized,
    )


def _update_baseline(output: bytes, policy_name: str) -> SecretPolicyUpdateBaseline:
    normalized = output.replace(b"\r", b"")
    return SecretPolicyUpdateBaseline(
        policy_name_exists=_policy_marker(policy_name) in normalized,
        ssh_filter_disabled=_setting_state(normalized, b"ssh-filter") == "disable",
        rdp_clipboard_block_enabled=(
            _setting_state(normalized, b"block-clipboard") == "enable"
        ),
    )


def _update_readback(output: bytes, policy_name: str) -> SecretPolicyUpdateReadback:
    normalized = output.replace(b"\r", b"")
    return SecretPolicyUpdateReadback(
        policy_name_exists=_policy_marker(policy_name) in normalized,
        ssh_filter_disabled=_setting_state(normalized, b"ssh-filter") == "disable",
        rdp_clipboard_block_disabled=(
            _setting_state(normalized, b"block-clipboard") == "disable"
        ),
    )


def _selected_session_security_policy(output: bytes, policy_name: str) -> bytes:
    """Select the fixed flat Policy table entry, requiring its matching footer."""
    name = _policy_name(policy_name).encode("ascii")
    normalized = output.replace(b"\r", b"")
    header = re.compile(rb'(?m)^( *)edit "' + re.escape(name) + rb'"[ \t]*$')
    matches = list(header.finditer(normalized))
    if not matches:
        raise SecretPolicySshTransportError(_UNAVAILABLE)
    # The compact show contributes a header; full-configuration contributes
    # the final exact header and its complete flat body.
    selected = matches[-1]
    footer = re.search(rb"(?m)^" + re.escape(selected.group(1)) + rb"next[ \t]*$", normalized[selected.end():])
    if footer is None:
        raise SecretPolicySshTransportError(_UNAVAILABLE)
    body = normalized[selected.end():selected.end() + footer.start()]
    if re.search(rb"(?m)^\s*(?:edit|config|end)\b", body):
        raise SecretPolicySshTransportError(_UNAVAILABLE)
    return normalized[selected.start():selected.end() + footer.end()]


def _setting_state(output: bytes, field: bytes) -> str:
    pattern = re.compile(
        rb"(?im)^\s*set\s+" + re.escape(field) + rb"\s+(enable|disable)\s*$"
    )
    values = {
        match.group(1).decode("ascii")
        for match in pattern.finditer(output)
    }
    return values.pop() if len(values) == 1 else "unknown"


def _policy_marker(policy_name: str) -> bytes:
    return f'edit "{policy_name}"'.encode("ascii")


def _policy_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise SecretPolicySshTransportError(_UNAVAILABLE)
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
        raise SecretPolicySshTransportConfigurationError(
            f"The Secret Policy SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SecretPolicySshTransportConfigurationError(
            f"The Secret Policy SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise SecretPolicySshTransportConfigurationError(
            f"The Secret Policy SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SecretPolicySshTransportConfigurationError(
            "The Secret Policy SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SecretPolicySshTransportConfigurationError(
            "The Secret Policy SSH password file is invalid."
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
    except SecretPolicySshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise SecretPolicySshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "ENV_PREFIX",
    "FortiPamSecretPolicySshTransport",
    "SECRET_POLICY_CONFIGURATION",
    "SECRET_POLICY_UPDATE_CONFIGURATION",
    "SECRET_POLICY_NAME_PREFIX",
    "SecretPolicyInspection",
    "SecretPolicyReadback",
    "SecretPolicyUpdateBaseline",
    "SecretPolicyUpdateReadback",
    "SecretPolicySshTransportConfig",
    "SecretPolicySshTransportConfigurationError",
    "SecretPolicySshTransportError",
    "load_secret_policy_ssh_transport_config",
]
