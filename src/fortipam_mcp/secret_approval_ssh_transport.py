"""Fixed CLI transport for one Secret interactive-approval association.

This transport changes only the four source-backed approval members on one
protected numeric Secret ID.  It does not inspect, serialize, or rewrite the
Secret field table.  Product readback remains the responsibility of the
independent metadata API projection.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
import re
import time
from typing import Any

import asyncssh

from .approval_profile_ssh_transport import ApprovalProfileSshTransportConfig
from .cli_safety import CliTransportError, _complete_pre_login
from .target_ssh_transport import (
    _close_cli,
    _require_root_prompt,
    _send_and_read,
    _send_and_read_dynamic_prompt,
)


_CONFIG_COMMAND = "config secret database"
_PROFILE_NAME = re.compile(
    r"mcp-v4-approval-profile-[A-Za-z0-9][A-Za-z0-9._-]{0,39}\Z"
)
_MAX_OUTPUT_BYTES = 64 * 1024
_UNAVAILABLE = "FortiPAM V4 Secret approval transport is unavailable."


class SecretApprovalSshTransportError(RuntimeError):
    """Stable non-disclosing failure for the fixed Secret approval write."""


class FortiPamSecretApprovalSshTransport:
    """Apply one exact interactive-approval profile without touching fields."""

    def __init__(self, config: ApprovalProfileSshTransportConfig) -> None:
        if not isinstance(config, ApprovalProfileSshTransportConfig):
            raise SecretApprovalSshTransportError(_UNAVAILABLE)
        self._config = config

    def enable_interactive_approval(
        self,
        secret_id: int,
        approval_profile_name: str,
    ) -> None:
        safe_id = _secret_id(secret_id)
        safe_profile = _profile_name(approval_profile_name)
        _run_sync(self._enable_interactive_approval(safe_id, safe_profile))

    async def _enable_interactive_approval(
        self,
        secret_id: int,
        approval_profile_name: str,
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
                        approval_profile_name,
                    )
                finally:
                    await _close_cli(process)
        except SecretApprovalSshTransportError:
            raise
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise SecretApprovalSshTransportError(_UNAVAILABLE) from exc

    async def _apply_commands(
        self,
        process: Any,
        root_prompt: bytes,
        deadline: float,
        secret_id: int,
        approval_profile_name: str,
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
        for command in (
            "set need-approval enable",
            "set need-approval-job disable",
            "set bypass-approval disable",
            f'set approval-profile "{approval_profile_name}"',
        ):
            await _send_and_read(process, command, secret_prompt, deadline)
        returned_table = await _send_and_read_dynamic_prompt(
            process,
            "next",
            root_prompt,
            deadline,
        )
        if returned_table != table_prompt:
            raise SecretApprovalSshTransportError(_UNAVAILABLE)
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
            raise SecretApprovalSshTransportError(_UNAVAILABLE) from exc


def _secret_id(value: int) -> int:
    if type(value) is not int or value <= 0 or value > 2_147_483_647:
        raise SecretApprovalSshTransportError(_UNAVAILABLE)
    return value


def _profile_name(value: str) -> str:
    if not isinstance(value, str) or _PROFILE_NAME.fullmatch(value) is None:
        raise SecretApprovalSshTransportError(_UNAVAILABLE)
    return value


def _run_sync(coroutine: Coroutine[Any, Any, Any]) -> Any:
    try:
        return asyncio.run(coroutine)
    except SecretApprovalSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise SecretApprovalSshTransportError(_UNAVAILABLE) from exc


__all__ = [
    "FortiPamSecretApprovalSshTransport",
    "SecretApprovalSshTransportError",
]
