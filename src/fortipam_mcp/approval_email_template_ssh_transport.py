"""Pinned SSH fallback for one bounded FortiPAM Approval Email Template create.

The FortiPAM 1.9.1 Administration Guide supplies the template CLI grammar,
while the API catalog has no POST request schema.  This creates only one fixed,
unassociated template; it never enables an email server or sends an email.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_APPROVAL_EMAIL_TEMPLATE_"
UPDATE_ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_"
APPROVAL_EMAIL_TEMPLATE_NAME_PREFIX = "mcp-v4-approval-email-template-"
APPROVAL_EMAIL_TEMPLATE_CONFIGURATION = "unassociated-fixed-template-v1"
APPROVAL_EMAIL_TEMPLATE_UPDATE_CONFIGURATION = "unassociated-fixed-template-update-v1"
APPROVAL_EMAIL_TEMPLATE_UPDATED_SUBJECT = "FortiPAM V4 updated approval template"
APPROVAL_EMAIL_TEMPLATE_UPDATED_CONTENT = "MCP V4 updated approval template"
_CONFIG_COMMAND = "config secret approval-email-template"
_NAME = re.compile(
    r"mcp-v4-approval-email-template-[A-Za-z0-9][A-Za-z0-9._-]{0,32}\Z"
)
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_UNAVAILABLE = "FortiPAM V4 Approval Email Template transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_FULL_CONTEXT_LINES = 80
_TEMPLATE_SETTINGS = (
    'set subject "FortiPAM V4 unbound approval template"',
    'set content "MCP V4 unbound approval template"',
)
_UPDATED_TEMPLATE_SETTINGS = (
    f'set subject "{APPROVAL_EMAIL_TEMPLATE_UPDATED_SUBJECT}"',
    f'set content "{APPROVAL_EMAIL_TEMPLATE_UPDATED_CONTENT}"',
)


class ApprovalEmailTemplateSshTransportError(RuntimeError):
    """Stable non-disclosing failure for the bounded SSH transport."""


class ApprovalEmailTemplateSshTransportConfigurationError(ValueError):
    """Raised when dedicated template SSH settings are unsafe."""


@dataclass(frozen=True, slots=True)
class ApprovalEmailTemplateSshTransportConfig:
    """Dedicated pinned SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise ApprovalEmailTemplateSshTransportConfigurationError(
                "The Approval Email Template SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise ApprovalEmailTemplateSshTransportConfigurationError(
                "The Approval Email Template SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise ApprovalEmailTemplateSshTransportConfigurationError(
                "The Approval Email Template SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise ApprovalEmailTemplateSshTransportConfigurationError(
                "The Approval Email Template SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise ApprovalEmailTemplateSshTransportConfigurationError(
                "The Approval Email Template SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class ApprovalEmailTemplateInspection:
    """Value-minimized preflight evidence for one template."""

    template_name_exists: bool


@dataclass(frozen=True, slots=True)
class ApprovalEmailTemplateReadback:
    """Categorical readback for the fixed unassociated template contract."""

    template_name_exists: bool
    fixed_subject_present: bool
    fixed_content_present: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.template_name_exists,
                self.fixed_subject_present,
                self.fixed_content_present,
            )
        )


@dataclass(frozen=True, slots=True)
class ApprovalEmailTemplateUpdateReadback:
    """Categorical readback for one fixed unassociated template update."""

    template_name_exists: bool
    updated_subject_present: bool
    updated_content_present: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.template_name_exists,
                self.updated_subject_present,
                self.updated_content_present,
            )
        )


def load_approval_email_template_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> ApprovalEmailTemplateSshTransportConfig:
    """Load only independently scoped template SSH credentials."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise ApprovalEmailTemplateSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise ApprovalEmailTemplateSshTransportConfigurationError(
            "Dedicated Approval Email Template SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise ApprovalEmailTemplateSshTransportConfigurationError(
            "The Approval Email Template SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return ApprovalEmailTemplateSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


def load_approval_email_template_update_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> ApprovalEmailTemplateSshTransportConfig:
    """Load only independently scoped template update SSH credentials."""

    env = os.environ if environment is None else environment
    if _value_for_prefix(env, UPDATE_ENV_PREFIX, "ENABLED") != "true":
        raise ApprovalEmailTemplateSshTransportConfigurationError(
            f"{UPDATE_ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value_for_prefix(env, UPDATE_ENV_PREFIX, "SSH_HOST")
    username = _value_for_prefix(env, UPDATE_ENV_PREFIX, "SSH_USERNAME")
    password_file = _value_for_prefix(env, UPDATE_ENV_PREFIX, "SSH_PASSWORD_FILE")
    known_hosts_file = _value_for_prefix(env, UPDATE_ENV_PREFIX, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value_for_prefix(env, UPDATE_ENV_PREFIX, "SSH_PORT") or "22"
    timeout_raw = _value_for_prefix(env, UPDATE_ENV_PREFIX, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise ApprovalEmailTemplateSshTransportConfigurationError(
            "Dedicated Approval Email Template update SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise ApprovalEmailTemplateSshTransportConfigurationError(
            "The Approval Email Template update SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return ApprovalEmailTemplateSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamApprovalEmailTemplateSshTransport:
    """Run only compiled template inspection and creation commands."""

    def __init__(self, config: ApprovalEmailTemplateSshTransportConfig) -> None:
        self._config = config

    def inspect(self, template_name: str) -> ApprovalEmailTemplateInspection:
        safe_name = _template_name(template_name)
        return cast(ApprovalEmailTemplateInspection, _run_sync(self._inspect(safe_name)))

    def create_and_readback(self, template_name: str) -> ApprovalEmailTemplateReadback:
        safe_name = _template_name(template_name)
        return cast(
            ApprovalEmailTemplateReadback,
            _run_sync(self._create_and_readback(safe_name)),
        )

    def readback(self, template_name: str) -> ApprovalEmailTemplateReadback:
        safe_name = _template_name(template_name)
        return cast(ApprovalEmailTemplateReadback, _run_sync(self._readback(safe_name)))

    def update_and_readback(
        self,
        template_name: str,
    ) -> ApprovalEmailTemplateUpdateReadback:
        safe_name = _template_name(template_name)
        return cast(
            ApprovalEmailTemplateUpdateReadback,
            _run_sync(self._update_and_readback(safe_name)),
        )

    def readback_updated(
        self,
        template_name: str,
    ) -> ApprovalEmailTemplateUpdateReadback:
        """Read the exact fixed updated projection without changing it."""

        safe_name = _template_name(template_name)
        return cast(
            ApprovalEmailTemplateUpdateReadback,
            _run_sync(self._readback_updated(safe_name)),
        )

    def reference_count(self, template_name: str) -> int:
        """Return a strictly parsed fixed Template CMDB reference count."""

        safe_name = _template_name(template_name)
        return cast(int, _run_sync(self._reference_count(safe_name)))

    async def _inspect(self, template_name: str) -> ApprovalEmailTemplateInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_template(
                    process,
                    root_prompt,
                    template_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return ApprovalEmailTemplateInspection(
            template_name_exists=_template_marker(template_name)
            in output.replace(b"\r", b"")
        )

    async def _create_and_readback(
        self,
        template_name: str,
    ) -> ApprovalEmailTemplateReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_template(
                    process,
                    root_prompt,
                    template_name,
                    deadline,
                )
                output = await self._show_template(
                    process,
                    root_prompt,
                    template_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, template_name)

    async def _readback(self, template_name: str) -> ApprovalEmailTemplateReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_template(
                    process,
                    root_prompt,
                    template_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, template_name)

    async def _update_and_readback(
        self,
        template_name: str,
    ) -> ApprovalEmailTemplateUpdateReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._update_template(
                    process,
                    root_prompt,
                    template_name,
                    deadline,
                )
                output = await self._show_template(
                    process,
                    root_prompt,
                    template_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _update_readback(output, template_name)

    async def _readback_updated(
        self,
        template_name: str,
    ) -> ApprovalEmailTemplateUpdateReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                output = await self._show_template(
                    process,
                    root_prompt,
                    template_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _update_readback(output, template_name)

    async def _reference_count(self, template_name: str) -> int:
        command = (
            "diagnose sys cmdb refcnt show "
            "secret.approval-email-template.name "
            + template_name
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

    async def _create_template(
        self,
        process: Any,
        root_prompt: bytes,
        template_name: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            template_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{template_name}"',
                root_prompt,
                deadline,
            )
            for command in _TEMPLATE_SETTINGS:
                await _send_and_read(process, command, template_prompt, deadline)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise ApprovalEmailTemplateSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ApprovalEmailTemplateSshTransportError(_UNAVAILABLE) from exc

    async def _update_template(
        self,
        process: Any,
        root_prompt: bytes,
        template_name: str,
        deadline: float,
    ) -> None:
        try:
            table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _CONFIG_COMMAND,
                root_prompt,
                deadline,
            )
            template_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{template_name}"',
                root_prompt,
                deadline,
            )
            for command in _UPDATED_TEMPLATE_SETTINGS:
                await _send_and_read(process, command, template_prompt, deadline)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise ApprovalEmailTemplateSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ApprovalEmailTemplateSshTransportError(_UNAVAILABLE) from exc

    async def _show_template(
        self,
        process: Any,
        root_prompt: bytes,
        template_name: str,
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
                f"show | grep {template_name}",
                table_prompt,
                deadline,
            )
            full = await _send_and_read(
                process,
                (
                    "show full-configuration | grep "
                    f'-A {_FULL_CONTEXT_LINES} "^ *edit.*{template_name}"'
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
            raise ApprovalEmailTemplateSshTransportError(_UNAVAILABLE) from exc

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
            raise ApprovalEmailTemplateSshTransportError(_UNAVAILABLE) from exc


def _readback(output: bytes, template_name: str) -> ApprovalEmailTemplateReadback:
    normalized = output.replace(b"\r", b"")
    return ApprovalEmailTemplateReadback(
        template_name_exists=_template_marker(template_name) in normalized,
        fixed_subject_present=_TEMPLATE_SETTINGS[0].encode("ascii") in normalized,
        fixed_content_present=_TEMPLATE_SETTINGS[1].encode("ascii") in normalized,
    )


def _update_readback(
    output: bytes,
    template_name: str,
) -> ApprovalEmailTemplateUpdateReadback:
    normalized = output.replace(b"\r", b"")
    return ApprovalEmailTemplateUpdateReadback(
        template_name_exists=_template_marker(template_name) in normalized,
        updated_subject_present=_UPDATED_TEMPLATE_SETTINGS[0].encode("ascii")
        in normalized,
        updated_content_present=_UPDATED_TEMPLATE_SETTINGS[1].encode("ascii")
        in normalized,
    )


def _template_marker(template_name: str) -> bytes:
    return f'edit "{template_name}"'.encode("ascii")


def _strict_reference_count(output: bytes, command: str, root_prompt: bytes) -> int:
    normalized = output.replace(b"\r", b"")
    lines = normalized.split(b"\n")
    if (
        len(lines) < 2
        or lines[0].strip() != command.encode("ascii")
        or lines[-1].rstrip(b" ") != root_prompt
    ):
        raise ApprovalEmailTemplateSshTransportError(_UNAVAILABLE)
    middle = [line for line in lines[1:-1] if line.strip()]
    if any(b"entry used by" not in line.lower() for line in middle):
        raise ApprovalEmailTemplateSshTransportError(_UNAVAILABLE)
    return len(middle)


def _template_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise ApprovalEmailTemplateSshTransportError(_UNAVAILABLE)
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
        raise ApprovalEmailTemplateSshTransportConfigurationError(
            f"The Approval Email Template SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ApprovalEmailTemplateSshTransportConfigurationError(
            f"The Approval Email Template SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ApprovalEmailTemplateSshTransportConfigurationError(
            f"The Approval Email Template SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ApprovalEmailTemplateSshTransportConfigurationError(
            "The Approval Email Template SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApprovalEmailTemplateSshTransportConfigurationError(
            "The Approval Email Template SSH password file is invalid."
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
    except ApprovalEmailTemplateSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise ApprovalEmailTemplateSshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "APPROVAL_EMAIL_TEMPLATE_CONFIGURATION",
    "APPROVAL_EMAIL_TEMPLATE_UPDATE_CONFIGURATION",
    "APPROVAL_EMAIL_TEMPLATE_NAME_PREFIX",
    "APPROVAL_EMAIL_TEMPLATE_UPDATED_CONTENT",
    "APPROVAL_EMAIL_TEMPLATE_UPDATED_SUBJECT",
    "ApprovalEmailTemplateInspection",
    "ApprovalEmailTemplateReadback",
    "ApprovalEmailTemplateUpdateReadback",
    "ApprovalEmailTemplateSshTransportConfig",
    "ApprovalEmailTemplateSshTransportConfigurationError",
    "ApprovalEmailTemplateSshTransportError",
    "ENV_PREFIX",
    "UPDATE_ENV_PREFIX",
    "FortiPamApprovalEmailTemplateSshTransport",
    "load_approval_email_template_ssh_transport_config",
    "load_approval_email_template_update_ssh_transport_config",
]
