"""Fixed SSH fallback for noncredential controls on one existing Secret.

This candidate transport changes only recording, clipboard blocking, and one
validated existing RDP event-filter association. It does not inspect or write
Secret fields, Folder, Template, Target, or any other Secret setting.

The caller must independently establish, through an authoritative current-state
projection, that the numeric Secret ID already exists and is the exact intended
object. ``edit`` alone cannot establish existing-object safety because it may
create an absent CLI entry.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine, Mapping
import os
from pathlib import Path
import re
import time
from typing import Any

import asyncssh

from .approval_profile_ssh_transport import (
    ApprovalProfileSshTransportConfig,
    _read_password_file,
    _value_for_prefix,
)
from .cli_safety import CliTransportError, _complete_pre_login
from .rdp_event_filter_ssh_transport import RDP_EVENT_FILTER_NAME_PREFIX
from .secret_metadata_http_transport import SecretSessionControlsProjectionInspection
from .secret_session_controls_http_transport import _mutable_control_changes
from .target_ssh_transport import (
    _close_cli,
    _require_root_prompt,
    _send_and_read,
    _send_and_read_dynamic_prompt,
)


_CONFIG_COMMAND = "config secret database"
_PROFILE_NAME = re.compile(
    rf"{re.escape(RDP_EVENT_FILTER_NAME_PREFIX)}[A-Za-z0-9][A-Za-z0-9._-]{{0,38}}\Z"
)
_MAX_OUTPUT_BYTES = 64 * 1024
_UNAVAILABLE = "FortiPAM V4 Secret session-controls transport is unavailable."
ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_SECRET_SESSION_CONTROLS_"
API_UNAVAILABLE_REASON = "rest-field-replacement-20260915"


class SecretSessionControlsSshTransportError(RuntimeError):
    """Stable non-disclosing failure for the fixed Secret control update."""


class SecretSessionControlsSshTransportConfigurationError(ValueError):
    """Raised when dedicated Secret controls SSH settings are unsafe."""


def load_secret_session_controls_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> ApprovalProfileSshTransportConfig:
    """Load only the dedicated API-unavailable SSH fallback configuration."""

    env = os.environ if environment is None else environment
    if _value_for_prefix(env, ENV_PREFIX, "ENABLED") != "true":
        raise SecretSessionControlsSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    if _value_for_prefix(env, ENV_PREFIX, "API_UNAVAILABLE_REASON") != API_UNAVAILABLE_REASON:
        raise SecretSessionControlsSshTransportConfigurationError(
            f"{ENV_PREFIX}API_UNAVAILABLE_REASON is not the required fallback reason."
        )
    host = _value_for_prefix(env, ENV_PREFIX, "SSH_HOST")
    username = _value_for_prefix(env, ENV_PREFIX, "SSH_USERNAME")
    password_file = _value_for_prefix(env, ENV_PREFIX, "SSH_PASSWORD_FILE")
    known_hosts_file = _value_for_prefix(env, ENV_PREFIX, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value_for_prefix(env, ENV_PREFIX, "SSH_PORT") or "22"
    timeout_raw = _value_for_prefix(env, ENV_PREFIX, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise SecretSessionControlsSshTransportConfigurationError(
            "Dedicated Secret session-controls SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
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
    except (OSError, ValueError) as exc:
        raise SecretSessionControlsSshTransportConfigurationError(
            "The dedicated Secret session-controls SSH configuration is invalid."
        ) from exc


class FortiPamSecretSessionControlsSshTransport:
    """Apply fixed controls after caller-authoritative existing-ID verification."""

    def __init__(self, config: ApprovalProfileSshTransportConfig) -> None:
        if not isinstance(config, ApprovalProfileSshTransportConfig):
            raise SecretSessionControlsSshTransportError(_UNAVAILABLE)
        self._config = config

    def enable_controls(
        self,
        secret_id: int,
        rdp_event_filter_profile_name: str,
        *,
        prewrite: SecretSessionControlsProjectionInspection,
    ) -> None:
        safe_id = _secret_id(secret_id)
        safe_profile = _profile_name(rdp_event_filter_profile_name)
        try:
            commands = _control_commands(prewrite, safe_profile)
        except Exception as exc:
            raise SecretSessionControlsSshTransportError(_UNAVAILABLE) from exc
        _run_sync(self._enable_controls(safe_id, commands))

    async def _enable_controls(
        self,
        secret_id: int,
        commands: tuple[str, ...],
    ) -> None:
        try:
            async with self._connection() as connection:
                process, root_prompt, deadline = await self._open_cli(connection)
                try:
                    await self._apply_commands(
                        process,
                        root_prompt,
                        deadline,
                        secret_id,
                        commands,
                    )
                finally:
                    await _close_cli(process)
        except SecretSessionControlsSshTransportError:
            raise
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise SecretSessionControlsSshTransportError(_UNAVAILABLE) from exc

    async def _apply_commands(
        self,
        process: Any,
        root_prompt: bytes,
        deadline: float,
        secret_id: int,
        commands: tuple[str, ...],
    ) -> None:
        table_prompt = await _send_and_read_dynamic_prompt(
            process,
            _CONFIG_COMMAND,
            root_prompt,
            deadline,
        )
        secret_prompt = await _send_and_read_dynamic_prompt(
            process,
            f"edit {secret_id}",
            root_prompt,
            deadline,
        )
        for command in commands:
            await _send_and_read(process, command, secret_prompt, deadline)
        returned_table = await _send_and_read_dynamic_prompt(
            process,
            "next",
            root_prompt,
            deadline,
        )
        if returned_table != table_prompt:
            raise SecretSessionControlsSshTransportError(_UNAVAILABLE)
        returned_root = await _send_and_read_dynamic_prompt(
            process,
            "end",
            root_prompt,
            deadline,
        )
        _require_root_prompt(root_prompt, returned_root)

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
                term_size=(200, 24),
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
            raise SecretSessionControlsSshTransportError(_UNAVAILABLE) from exc


def _secret_id(value: int) -> int:
    if type(value) is not int or value <= 0 or value > 2_147_483_647:
        raise SecretSessionControlsSshTransportError(_UNAVAILABLE)
    return value


def _profile_name(value: str) -> str:
    if not isinstance(value, str) or _PROFILE_NAME.fullmatch(value) is None:
        raise SecretSessionControlsSshTransportError(_UNAVAILABLE)
    return value


def _control_commands(
    prewrite: SecretSessionControlsProjectionInspection,
    profile: str,
) -> tuple[str, ...]:
    """Compile only the protected Policy-allowed controls that still differ."""

    changes = _mutable_control_changes(prewrite, profile)
    allowed = {
        "recording",
        "block-clipboard",
        "rdp-event-filter",
        "rdp-event-filter-profile",
    }
    if set(changes) - allowed or not changes:
        raise SecretSessionControlsSshTransportError(_UNAVAILABLE)
    commands: list[str] = []
    for field, command in (
        ("recording", "set recording enable"),
        ("block-clipboard", "set block-clipboard enable"),
        ("rdp-event-filter", "set rdp-event-filter enable"),
    ):
        if field in changes:
            if changes[field] != "enable":
                raise SecretSessionControlsSshTransportError(_UNAVAILABLE)
            commands.append(command)
    if "rdp-event-filter-profile" in changes:
        if changes["rdp-event-filter-profile"] != profile:
            raise SecretSessionControlsSshTransportError(_UNAVAILABLE)
        commands.append(f'set rdp-event-filter-profile "{profile}"')
    if not commands:
        raise SecretSessionControlsSshTransportError(_UNAVAILABLE)
    return tuple(commands)


def _run_sync(coroutine: Coroutine[Any, Any, Any]) -> Any:
    try:
        return asyncio.run(coroutine)
    except SecretSessionControlsSshTransportError:
        raise
    except RuntimeError as exc:
        # ``asyncio.run`` rejects an active event loop before awaiting the
        # supplied coroutine. Close it so the stable error path cannot leak an
        # unawaited coroutine warning.
        coroutine.close()
        raise SecretSessionControlsSshTransportError(_UNAVAILABLE) from exc
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        raise SecretSessionControlsSshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "API_UNAVAILABLE_REASON",
    "ENV_PREFIX",
    "FortiPamSecretSessionControlsSshTransport",
    "SecretSessionControlsSshTransportConfigurationError",
    "SecretSessionControlsSshTransportError",
    "load_secret_session_controls_ssh_transport_config",
]
