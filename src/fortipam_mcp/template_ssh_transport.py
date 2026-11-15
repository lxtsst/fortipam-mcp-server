"""Pinned SSH fallback for one bounded FortiPAM Web VNC Template create.

The 1.9.1 API catalog does not establish a Template REST write contract. This
module therefore implements only the Administration Guide's documented Web VNC
template example: two mandatory metadata fields and the built-in Web VNC
Launcher at its documented default port. It never carries Secret field values
or creates a Secret or Target association.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine, Mapping
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_TEMPLATE_"
TEMPLATE_ARCHIVE_SSH_ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_TEMPLATE_ARCHIVE_SSH_"
TEMPLATE_NAME_PREFIX = "mcp-v4-template-"
TEMPLATE_CONFIGURATION = "web-vnc-username-password-v1"
TEMPLATE_UPDATE_CONFIGURATION = "web-vnc-launcher-port-5900-to-5901-v1"
TEMPLATE_ARCHIVE_CONFIGURATION = "unreferenced-web-vnc-template-delete-v1"
TEMPLATE_DEFAULT_PORT = 5900
TEMPLATE_UPDATED_PORT = 5901
_CONFIG_COMMAND = "config secret template"
_FIELD_CONTEXT = "config field"
_LAUNCHER_CONTEXT = "config launcher"
_TEMPLATE_NAME = re.compile(r"mcp-v4-template-[A-Za-z0-9][A-Za-z0-9._-]{0,46}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_UNAVAILABLE = "FortiPAM V4 Template create transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_ACCESS_COMMAND = "set access everyone"
_USERNAME_FIELD = "Username"
_PASSWORD_FIELD = "Password"
_USERNAME_TYPE_COMMAND = "set type username"
_PASSWORD_TYPE_COMMAND = "set type password"
_MANDATORY_COMMAND = "set mandatory enable"
_WEB_VNC_LAUNCHER_COMMAND = 'set launcher-name "Web VNC"'
_WEB_VNC_PORT_COMMAND = f"set port {TEMPLATE_DEFAULT_PORT}"
_WEB_VNC_UPDATED_PORT_COMMAND = f"set port {TEMPLATE_UPDATED_PORT}"


class TemplateSshTransportError(RuntimeError):
    """Stable, non-disclosing failure for the bounded SSH transport."""


class TemplateSshTransportConfigurationError(ValueError):
    """Raised when dedicated Template transport settings are unsafe."""


@dataclass(frozen=True, slots=True)
class TemplateSshTransportConfig:
    """Dedicated pinned SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise TemplateSshTransportConfigurationError(
                "The Template SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise TemplateSshTransportConfigurationError(
                "The Template SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise TemplateSshTransportConfigurationError(
                "The Template SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise TemplateSshTransportConfigurationError(
                "The Template SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise TemplateSshTransportConfigurationError(
                "The Template SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class TemplateInspection:
    """Value-minimized preflight evidence for one Template."""

    template_name_exists: bool


@dataclass(frozen=True, slots=True)
class TemplateReadback:
    """Categorical readback for the fixed Web VNC Template contract."""

    template_name_exists: bool
    access_everyone: bool
    username_field_present: bool
    username_field_mandatory: bool
    password_field_present: bool
    password_field_mandatory: bool
    web_vnc_launcher_present: bool
    web_vnc_port_matches: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.template_name_exists,
                self.access_everyone,
                self.username_field_present,
                self.username_field_mandatory,
                self.password_field_present,
                self.password_field_mandatory,
                self.web_vnc_launcher_present,
                self.web_vnc_port_matches,
            )
        )


@dataclass(frozen=True, slots=True)
class TemplateUpdateBaselineReadback:
    """Categorical evidence for the exact Web VNC Template create baseline."""

    template_name_exists: bool
    access_everyone: bool
    username_field_present: bool
    username_field_mandatory: bool
    password_field_present: bool
    password_field_mandatory: bool
    web_vnc_launcher_present: bool
    web_vnc_port_is_default: bool
    configuration_digest: str = field(default="", repr=False)

    @property
    def verified(self) -> bool:
        return all(
            (
                self.template_name_exists,
                self.access_everyone,
                self.username_field_present,
                self.username_field_mandatory,
                self.password_field_present,
                self.password_field_mandatory,
                self.web_vnc_launcher_present,
                self.web_vnc_port_is_default,
                re.fullmatch(r"[0-9a-f]{64}", self.configuration_digest) is not None,
            )
        )


@dataclass(frozen=True, slots=True)
class TemplateUpdateReadback:
    """Categorical evidence for the one fixed Web VNC port update."""

    template_name_exists: bool
    access_everyone: bool
    username_field_present: bool
    username_field_mandatory: bool
    password_field_present: bool
    password_field_mandatory: bool
    web_vnc_launcher_present: bool
    web_vnc_port_is_updated: bool
    configuration_digest: str = field(default="", repr=False)

    @property
    def verified(self) -> bool:
        return all(
            (
                self.template_name_exists,
                self.access_everyone,
                self.username_field_present,
                self.username_field_mandatory,
                self.password_field_present,
                self.password_field_mandatory,
                self.web_vnc_launcher_present,
                self.web_vnc_port_is_updated,
                re.fullmatch(r"[0-9a-f]{64}", self.configuration_digest) is not None,
            )
        )


@dataclass(frozen=True, slots=True)
class TemplateArchivePreflightReadback:
    """Categorical evidence that a disposable Template has no known references."""

    template_name_exists: bool
    access_everyone: bool
    username_field_present: bool
    username_field_mandatory: bool
    password_field_present: bool
    password_field_mandatory: bool
    web_vnc_launcher_present: bool
    web_vnc_port_is_default: bool
    secret_references_absent: bool
    target_references_absent: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.template_name_exists,
                self.access_everyone,
                self.username_field_present,
                self.username_field_mandatory,
                self.password_field_present,
                self.password_field_mandatory,
                self.web_vnc_launcher_present,
                self.web_vnc_port_is_default,
                self.secret_references_absent,
                self.target_references_absent,
            )
        )


@dataclass(frozen=True, slots=True)
class TemplateArchiveAbsenceReadback:
    """Categorical post-delete evidence for the dedicated archive workflow."""

    template_name_absent: bool
    secret_references_absent: bool
    target_references_absent: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.template_name_absent,
                self.secret_references_absent,
                self.target_references_absent,
            )
        )


def load_template_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> TemplateSshTransportConfig:
    """Load only independently scoped Template SSH credentials."""

    return _load_template_ssh_transport_config(environment, prefix=ENV_PREFIX)


def load_template_archive_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> TemplateSshTransportConfig:
    """Load the independent readback scope for Template archive only."""

    return _load_template_ssh_transport_config(
        environment,
        prefix=TEMPLATE_ARCHIVE_SSH_ENV_PREFIX,
    )


def _load_template_ssh_transport_config(
    environment: Mapping[str, str] | None,
    *,
    prefix: str,
) -> TemplateSshTransportConfig:
    """Load one exact Template SSH namespace with no credential fallback."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED", prefix=prefix) != "true":
        raise TemplateSshTransportConfigurationError(
            f"{prefix}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST", prefix=prefix)
    username = _value(env, "SSH_USERNAME", prefix=prefix)
    password_file = _value(env, "SSH_PASSWORD_FILE", prefix=prefix)
    login_env_file = _value(env, "SSH_LOGIN_ENV_FILE", prefix=prefix)
    username_variable = _value(env, "SSH_USERNAME_VARIABLE", prefix=prefix)
    password_variable = _value(env, "SSH_PASSWORD_VARIABLE", prefix=prefix)
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE", prefix=prefix)
    port_raw = _value(env, "SSH_PORT", prefix=prefix) or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS", prefix=prefix) or "15"
    referenced_login = any(value is not None for value in (
        login_env_file, username_variable, password_variable,
    ))
    if referenced_login:
        if (username is not None or password_file is not None
                or None in {login_env_file, username_variable, password_variable}):
            raise TemplateSshTransportConfigurationError(
                "The Template SSH protected credential references are unavailable."
            )
    elif username is None or password_file is None:
        raise TemplateSshTransportConfigurationError(
            "Dedicated Template SSH host, username, password file, and known_hosts are required."
        )
    if host is None or known_hosts_file is None:
        raise TemplateSshTransportConfigurationError(
            "Dedicated Template SSH host and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise TemplateSshTransportConfigurationError(
            "The Template SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert known_hosts_file is not None
    if referenced_login:
        from .secret_create_central_lab_provider import (
            OwnerOnlyCentralLabSecretCreateEnvFileLoader,
        )
        material: tuple[bytearray, bytearray] | None = None
        try:
            assert login_env_file is not None
            assert username_variable is not None
            assert password_variable is not None
            loader = OwnerOnlyCentralLabSecretCreateEnvFileLoader(
                secret_env_path=Path(login_env_file),
                username_variable_name=username_variable,
                password_variable_name=password_variable,
            )
            material = loader.load_secret_create_material_once()
            username, password = (value.decode("utf-8") for value in material)
        except Exception:
            raise TemplateSshTransportConfigurationError(
                "The Template SSH protected credential references are unavailable."
            ) from None
        finally:
            if material is not None:
                for value in material:
                    value[:] = bytes(len(value))
    else:
        assert password_file is not None
        password = _read_password_file(Path(password_file))
    assert username is not None
    return TemplateSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=password,
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamTemplateSshTransport:
    """Run only compiled Template inspection and creation commands."""

    def __init__(self, config: TemplateSshTransportConfig) -> None:
        self._config = config

    def inspect(self, template_name: str) -> TemplateInspection:
        safe_name = _template_name(template_name)
        return cast(TemplateInspection, _run_sync(self._inspect(safe_name)))

    def create_and_readback(self, template_name: str) -> TemplateReadback:
        safe_name = _template_name(template_name)
        return cast(
            TemplateReadback,
            _run_sync(self._create_and_readback(safe_name)),
        )

    def update_baseline_readback(
        self,
        template_name: str,
    ) -> TemplateUpdateBaselineReadback:
        """Return the exact create baseline required before the one update."""

        safe_name = _template_name(template_name)
        return cast(
            TemplateUpdateBaselineReadback,
            _run_sync(self._update_baseline_readback(safe_name)),
        )

    def update_web_vnc_port_and_readback(
        self,
        template_name: str,
    ) -> TemplateUpdateReadback:
        """Change only the built-in Web VNC Launcher port on the known baseline."""

        safe_name = _template_name(template_name)
        return cast(
            TemplateUpdateReadback,
            _run_sync(self._update_web_vnc_port_and_readback(safe_name)),
        )

    def updated_web_vnc_readback(self, template_name: str) -> TemplateUpdateReadback:
        """Read the complete port-5901 state without issuing a configuration command."""

        safe_name = _template_name(template_name)
        return cast(TemplateUpdateReadback, _run_sync(self._updated_web_vnc_readback(safe_name)))

    def archive_preflight_readback(
        self,
        template_name: str,
    ) -> TemplateArchivePreflightReadback:
        """Prove the exact default baseline has no direct Secret/Target reference."""

        safe_name = _template_name(template_name)
        return cast(
            TemplateArchivePreflightReadback,
            _run_sync(self._archive_preflight_readback(safe_name)),
        )

    def archive_absence_readback(
        self,
        template_name: str,
    ) -> TemplateArchiveAbsenceReadback:
        """Prove the dedicated Template and direct references are absent after delete."""

        safe_name = _template_name(template_name)
        return cast(
            TemplateArchiveAbsenceReadback,
            _run_sync(self._archive_absence_readback(safe_name)),
        )

    async def _inspect(self, template_name: str) -> TemplateInspection:
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
        return TemplateInspection(
            template_name_exists=_template_marker(template_name)
            in output.replace(b"\r", b"")
        )

    async def _create_and_readback(self, template_name: str) -> TemplateReadback:
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

    async def _update_baseline_readback(
        self,
        template_name: str,
    ) -> TemplateUpdateBaselineReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection, full_template_read=True)
            try:
                output = await self._show_template_for_update(
                    process,
                    root_prompt,
                    template_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _update_baseline_readback(output, template_name)

    async def _update_web_vnc_port_and_readback(
        self,
        template_name: str,
    ) -> TemplateUpdateReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection, full_template_read=True)
            try:
                await self._update_web_vnc_port(
                    process,
                    root_prompt,
                    template_name,
                    deadline,
                )
                output = await self._show_template_for_update(
                    process,
                    root_prompt,
                    template_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _update_readback(output, template_name)

    async def _updated_web_vnc_readback(self, template_name: str) -> TemplateUpdateReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection, full_template_read=True)
            try:
                output = await self._show_template_for_update(
                    process, root_prompt, template_name, deadline,
                )
            finally:
                await _close_cli(process)
        return _update_readback(output, template_name)

    async def _archive_preflight_readback(
        self,
        template_name: str,
    ) -> TemplateArchivePreflightReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                template_output = await self._show_template(
                    process,
                    root_prompt,
                    template_name,
                    deadline,
                )
                secret_output = await self._show_template_references(
                    process,
                    root_prompt,
                    "database",
                    template_name,
                    deadline,
                )
                target_output = await self._show_template_references(
                    process,
                    root_prompt,
                    "target",
                    template_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _archive_preflight_readback(
            template_output,
            secret_output,
            target_output,
            template_name,
        )

    async def _archive_absence_readback(
        self,
        template_name: str,
    ) -> TemplateArchiveAbsenceReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                template_output = await self._show_template(
                    process,
                    root_prompt,
                    template_name,
                    deadline,
                )
                secret_output = await self._show_template_references(
                    process,
                    root_prompt,
                    "database",
                    template_name,
                    deadline,
                )
                target_output = await self._show_template_references(
                    process,
                    root_prompt,
                    "target",
                    template_name,
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _archive_absence_readback(
            template_output,
            secret_output,
            target_output,
            template_name,
        )

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
            await _send_and_read(process, _ACCESS_COMMAND, template_prompt, deadline)
            field_table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _FIELD_CONTEXT,
                root_prompt,
                deadline,
            )
            username_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{_USERNAME_FIELD}"',
                root_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                _USERNAME_TYPE_COMMAND,
                username_prompt,
                deadline,
            )
            await _send_and_read(process, _MANDATORY_COMMAND, username_prompt, deadline)
            returned_field_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_field_table != field_table_prompt:
                raise TemplateSshTransportError(_UNAVAILABLE)
            password_prompt = await _send_and_read_dynamic_prompt(
                process,
                f'edit "{_PASSWORD_FIELD}"',
                root_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                _PASSWORD_TYPE_COMMAND,
                password_prompt,
                deadline,
            )
            await _send_and_read(process, _MANDATORY_COMMAND, password_prompt, deadline)
            returned_field_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_field_table != field_table_prompt:
                raise TemplateSshTransportError(_UNAVAILABLE)
            returned_template = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            if returned_template != template_prompt:
                raise TemplateSshTransportError(_UNAVAILABLE)
            launcher_table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _LAUNCHER_CONTEXT,
                root_prompt,
                deadline,
            )
            launcher_prompt = await _send_and_read_dynamic_prompt(
                process,
                "edit 1",
                root_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                _WEB_VNC_LAUNCHER_COMMAND,
                launcher_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                _WEB_VNC_PORT_COMMAND,
                launcher_prompt,
                deadline,
            )
            returned_launcher_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_launcher_table != launcher_table_prompt:
                raise TemplateSshTransportError(_UNAVAILABLE)
            returned_template = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            if returned_template != template_prompt:
                raise TemplateSshTransportError(_UNAVAILABLE)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise TemplateSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise TemplateSshTransportError(_UNAVAILABLE) from exc

    async def _update_web_vnc_port(
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
            launcher_table_prompt = await _send_and_read_dynamic_prompt(
                process,
                _LAUNCHER_CONTEXT,
                root_prompt,
                deadline,
            )
            launcher_prompt = await _send_and_read_dynamic_prompt(
                process,
                "edit 1",
                root_prompt,
                deadline,
            )
            await _send_and_read(
                process,
                _WEB_VNC_UPDATED_PORT_COMMAND,
                launcher_prompt,
                deadline,
            )
            returned_launcher_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_launcher_table != launcher_table_prompt:
                raise TemplateSshTransportError(_UNAVAILABLE)
            returned_template = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            if returned_template != template_prompt:
                raise TemplateSshTransportError(_UNAVAILABLE)
            returned_table = await _send_and_read_dynamic_prompt(
                process,
                "next",
                root_prompt,
                deadline,
            )
            if returned_table != table_prompt:
                raise TemplateSshTransportError(_UNAVAILABLE)
            returned_root = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise TemplateSshTransportError(_UNAVAILABLE) from exc

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
                f"show | grep {template_name} -f",
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
            raise TemplateSshTransportError(_UNAVAILABLE) from exc

    async def _show_template_for_update(
        self,
        process: Any,
        root_prompt: bytes,
        template_name: str,
        deadline: float,
    ) -> bytes:
        """Read one complete entry, including defaults, without entering edit mode."""

        name = _template_name(template_name)
        try:
            return await _send_and_read(
                process,
                f'show full-configuration secret template "{name}"',
                root_prompt,
                deadline,
            )
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise TemplateSshTransportError(_UNAVAILABLE) from exc

    async def _show_template_references(
        self,
        process: Any,
        root_prompt: bytes,
        context: str,
        template_name: str,
        deadline: float,
    ) -> bytes:
        """Read only direct Template bindings from one fixed Secret context."""

        if context not in {"database", "target"}:
            raise TemplateSshTransportError(_UNAVAILABLE)
        try:
            context_prompt = await _send_and_read_dynamic_prompt(
                process,
                f"config secret {context}",
                root_prompt,
                deadline,
            )
            compact = await _send_and_read(
                process,
                f"show | grep {template_name}",
                context_prompt,
                deadline,
            )
            full = await _send_and_read(
                process,
                f"show | grep {template_name} -f",
                context_prompt,
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
            raise TemplateSshTransportError(_UNAVAILABLE) from exc

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

    async def _open_cli(
        self, connection: Any, *, full_template_read: bool = False,
    ) -> tuple[Any, bytes, float]:
        try:
            process = await connection.create_process(
                term_type="vt100", term_size=(80, 1000 if full_template_read else 24), encoding=None
            )
            deadline = time.monotonic() + self._config.timeout_seconds
            root_prompt = await _complete_pre_login(
                process.stdout,
                process.stdin,
                deadline,
                _MAX_OUTPUT_BYTES,
                accept_pre_login_banner=False,
            )
            _require_root_prompt(root_prompt, root_prompt)
            return process, root_prompt, deadline
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise TemplateSshTransportError(_UNAVAILABLE) from exc


def _readback(output: bytes, template_name: str) -> TemplateReadback:
    normalized = output.replace(b"\r", b"")
    username_section = _field_section(normalized, _USERNAME_FIELD)
    password_section = _field_section(normalized, _PASSWORD_FIELD)
    return TemplateReadback(
        template_name_exists=_template_marker(template_name) in normalized,
        access_everyone=_ACCESS_COMMAND.encode("ascii") in normalized,
        username_field_present=_USERNAME_TYPE_COMMAND.encode("ascii") in username_section,
        username_field_mandatory=_MANDATORY_COMMAND.encode("ascii") in username_section,
        password_field_present=_PASSWORD_TYPE_COMMAND.encode("ascii") in password_section,
        password_field_mandatory=_MANDATORY_COMMAND.encode("ascii") in password_section,
        web_vnc_launcher_present=_WEB_VNC_LAUNCHER_COMMAND.encode("ascii")
        in normalized,
        web_vnc_port_matches=_WEB_VNC_PORT_COMMAND.encode("ascii") in normalized,
    )


def _update_baseline_readback(
    output: bytes,
    template_name: str,
) -> TemplateUpdateBaselineReadback:
    baseline, digest = _strict_web_vnc_readback(output, template_name, TEMPLATE_DEFAULT_PORT)
    return TemplateUpdateBaselineReadback(
        template_name_exists=baseline.template_name_exists,
        access_everyone=baseline.access_everyone,
        username_field_present=baseline.username_field_present,
        username_field_mandatory=baseline.username_field_mandatory,
        password_field_present=baseline.password_field_present,
        password_field_mandatory=baseline.password_field_mandatory,
        web_vnc_launcher_present=baseline.web_vnc_launcher_present,
        web_vnc_port_is_default=baseline.web_vnc_port_matches,
        configuration_digest=digest,
    )


def _update_readback(output: bytes, template_name: str) -> TemplateUpdateReadback:
    baseline, digest = _strict_web_vnc_readback(output, template_name, TEMPLATE_UPDATED_PORT)
    return TemplateUpdateReadback(
        template_name_exists=baseline.template_name_exists,
        access_everyone=baseline.access_everyone,
        username_field_present=baseline.username_field_present,
        username_field_mandatory=baseline.username_field_mandatory,
        password_field_present=baseline.password_field_present,
        password_field_mandatory=baseline.password_field_mandatory,
        web_vnc_launcher_present=baseline.web_vnc_launcher_present,
        web_vnc_port_is_updated=baseline.web_vnc_port_matches,
        configuration_digest=digest,
    )


@dataclass
class _TemplateCliBlock:
    settings: dict[str, tuple[str, ...]] = field(default_factory=dict)
    entries: dict[str, _TemplateCliBlock] = field(default_factory=dict)
    tables: dict[str, _TemplateCliBlock] = field(default_factory=dict)

    def projection(self) -> dict[str, object]:
        return {
            "settings": self.settings,
            "entry_order": list(self.entries),
            "table_order": list(self.tables),
            "entries": {name: child.projection() for name, child in self.entries.items()},
            "tables": {name: child.projection() for name, child in self.tables.items()},
        }


def _exact_template_cli_entry(output: bytes, name: str) -> _TemplateCliBlock | None:
    """Reject incomplete, repeated or ambiguous native configuration blocks."""

    if len(output) > _MAX_OUTPUT_BYTES:
        return None
    try:
        lines = [line.strip() for line in output.decode("utf-8").replace("\r", "").splitlines()]
        if lines.count(_CONFIG_COMMAND) != 1:
            return None
        root = _TemplateCliBlock()
        stack = [("config", root)]
        for index, line in enumerate(
            lines[lines.index(_CONFIG_COMMAND) + 1:], lines.index(_CONFIG_COMMAND) + 1,
        ):
            if not line:
                continue
            tokens = shlex.split(line)
            kind, current = stack[-1]
            if len(tokens) == 2 and tokens[0] == "edit" and kind == "config":
                if tokens[1] in current.entries:
                    return None
                child = _TemplateCliBlock()
                current.entries[tokens[1]] = child
                stack.append(("edit", child))
            elif len(tokens) == 2 and tokens[0] == "config":
                if tokens[1] in current.tables:
                    return None
                child = _TemplateCliBlock()
                current.tables[tokens[1]] = child
                stack.append(("config", child))
            elif len(tokens) >= 3 and tokens[0] == "set":
                if tokens[1] in current.settings:
                    return None
                current.settings[tokens[1]] = tuple(tokens[2:])
            elif tokens == ["next"] and kind == "edit":
                stack.pop()
            elif tokens == ["end"] and kind == "config":
                stack.pop()
                if not stack:
                    if root.settings or root.tables or set(root.entries) != {name}:
                        return None
                    if any(
                        tail and re.fullmatch(r"[A-Za-z0-9._-]{1,63} [#$]", tail) is None
                        for tail in lines[index + 1:]
                    ):
                        return None
                    return root.entries[name]
            else:
                return None
    except (UnicodeDecodeError, ValueError):
        return None
    return None


def _strict_web_vnc_readback(
    output: bytes, template_name: str, port: int,
) -> tuple[TemplateReadback, str]:
    entry = _exact_template_cli_entry(output, template_name)
    if entry is None:
        return TemplateReadback(False, False, False, False, False, False, False, False), ""
    fields = entry.tables.get("field", _TemplateCliBlock())
    launchers = entry.tables.get("launcher", _TemplateCliBlock())
    exact_fields = (
        not fields.settings and not fields.tables
        and set(fields.entries) == {"Username", "Password"}
    )
    exact_launchers = (
        not launchers.settings and not launchers.tables
        and set(launchers.entries) == {"1"}
    )
    username = fields.entries.get("Username", _TemplateCliBlock())
    password = fields.entries.get("Password", _TemplateCliBlock())
    launcher = launchers.entries.get("1", _TemplateCliBlock())
    readback = TemplateReadback(
        template_name_exists=True,
        access_everyone=entry.settings.get("access") == ("everyone",),
        username_field_present=exact_fields and not username.tables and not username.entries
        and set(username.settings) == {"type", "mandatory", "need-edit"}
        and username.settings.get("need-edit") == ("disable",)
        and username.settings.get("type") == ("username",),
        username_field_mandatory=exact_fields and username.settings.get("mandatory") == ("enable",),
        password_field_present=exact_fields and not password.tables and not password.entries
        and set(password.settings) == {"type", "mandatory", "need-edit"}
        and password.settings.get("need-edit") == ("disable",)
        and password.settings.get("type") == ("password",),
        password_field_mandatory=exact_fields and password.settings.get("mandatory") == ("enable",),
        web_vnc_launcher_present=exact_launchers and not launcher.tables and not launcher.entries
        and set(launcher.settings) == {"launcher-name", "port"}
        and launcher.settings.get("launcher-name") == ("Web VNC",),
        web_vnc_port_matches=exact_launchers and launcher.settings.get("port") == (str(port),),
    )
    # Only the confirmed Launcher port may change. Hash every other observed setting.
    launcher.settings.pop("port", None)
    digest = hashlib.sha256(
        json.dumps(entry.projection(), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return readback, digest


def _archive_preflight_readback(
    template_output: bytes,
    secret_output: bytes,
    target_output: bytes,
    template_name: str,
) -> TemplateArchivePreflightReadback:
    baseline = _readback(template_output, template_name)
    marker = _template_reference_marker(template_name)
    return TemplateArchivePreflightReadback(
        template_name_exists=baseline.template_name_exists,
        access_everyone=baseline.access_everyone,
        username_field_present=baseline.username_field_present,
        username_field_mandatory=baseline.username_field_mandatory,
        password_field_present=baseline.password_field_present,
        password_field_mandatory=baseline.password_field_mandatory,
        web_vnc_launcher_present=baseline.web_vnc_launcher_present,
        web_vnc_port_is_default=baseline.web_vnc_port_matches,
        secret_references_absent=marker not in secret_output.replace(b"\r", b""),
        target_references_absent=marker not in target_output.replace(b"\r", b""),
    )


def _archive_absence_readback(
    template_output: bytes,
    secret_output: bytes,
    target_output: bytes,
    template_name: str,
) -> TemplateArchiveAbsenceReadback:
    marker = _template_reference_marker(template_name)
    return TemplateArchiveAbsenceReadback(
        template_name_absent=_template_marker(template_name)
        not in template_output.replace(b"\r", b""),
        secret_references_absent=marker not in secret_output.replace(b"\r", b""),
        target_references_absent=marker not in target_output.replace(b"\r", b""),
    )


def _field_section(output: bytes, field_name: str) -> bytes:
    marker = f'edit "{field_name}"'.encode("ascii")
    start = output.find(marker)
    if start < 0:
        return b""
    other_name = _PASSWORD_FIELD if field_name == _USERNAME_FIELD else _USERNAME_FIELD
    other_marker = f'edit "{other_name}"'.encode("ascii")
    next_marker = output.find(other_marker, start + len(marker))
    return output[start:] if next_marker < 0 else output[start:next_marker]


def _template_marker(template_name: str) -> bytes:
    return f'edit "{template_name}"'.encode("ascii")


def _template_reference_marker(template_name: str) -> bytes:
    return f'set template "{template_name}"'.encode("ascii")


def _template_name(value: str) -> str:
    if not isinstance(value, str) or _TEMPLATE_NAME.fullmatch(value) is None:
        raise TemplateSshTransportError(_UNAVAILABLE)
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
        raise TemplateSshTransportConfigurationError(
            f"The Template SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise TemplateSshTransportConfigurationError(
            f"The Template SSH {label} file is unsafe."
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise TemplateSshTransportConfigurationError(
            f"The Template SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise TemplateSshTransportConfigurationError(
            "The Template SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TemplateSshTransportConfigurationError(
            "The Template SSH password file is invalid."
        ) from exc


def _value(
    environment: Mapping[str, str],
    suffix: str,
    *,
    prefix: str = ENV_PREFIX,
) -> str | None:
    value = environment.get(f"{prefix}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _run_sync(coroutine: Coroutine[Any, Any, Any]) -> Any:
    try:
        return asyncio.run(coroutine)
    except TemplateSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise TemplateSshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "ENV_PREFIX",
    "FortiPamTemplateSshTransport",
    "TEMPLATE_ARCHIVE_CONFIGURATION",
    "TEMPLATE_ARCHIVE_SSH_ENV_PREFIX",
    "TEMPLATE_CONFIGURATION",
    "TEMPLATE_DEFAULT_PORT",
    "TEMPLATE_NAME_PREFIX",
    "TEMPLATE_UPDATED_PORT",
    "TEMPLATE_UPDATE_CONFIGURATION",
    "TemplateInspection",
    "TemplateArchiveAbsenceReadback",
    "TemplateArchivePreflightReadback",
    "TemplateReadback",
    "TemplateUpdateBaselineReadback",
    "TemplateUpdateReadback",
    "TemplateSshTransportConfig",
    "TemplateSshTransportConfigurationError",
    "TemplateSshTransportError",
    "load_template_archive_ssh_transport_config",
    "load_template_ssh_transport_config",
]
