"""Pinned-SSH transport for one FortiPAM Local User disable contract.

The action deliberately reuses the dedicated V4 SSH identity configuration
already required for the Target action.  It has no generic CLI relay, accepts
only one safe local-user name, and returns categorical state only.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from dataclasses import dataclass
import re
import time
from typing import Any, Literal, cast

import asyncssh

from .cli_safety import (
    CliTransportError,
    _complete_pre_login,
    _raise_for_remote_rejection,
    _read_until_prompt,
)
from .target_ssh_transport import (
    TargetSshTransportConfig,
    _require_context_prompt,
    _require_root_prompt,
    _send_and_read_dynamic_prompt,
)


_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_DENIED_MESSAGE = "FortiPAM V4 Local User transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_UserStatus = Literal["enable", "disable", "unknown"]


class LocalUserSshTransportError(RuntimeError):
    """Stable failure for the bounded Local User transport."""


@dataclass(frozen=True, slots=True)
class LocalUserInspection:
    """Value-minimized Local User preflight evidence."""

    exists: bool
    status: _UserStatus

    @property
    def enabled(self) -> bool:
        """Whether the live record is explicitly enabled."""

        return self.exists and self.status == "enable"


@dataclass(frozen=True, slots=True)
class LocalUserReadback:
    """Value-minimized disable/readback evidence."""

    user_exists: bool
    status_disabled: bool

    @property
    def verified(self) -> bool:
        """Whether the exact expected disabled state is present."""

        return self.user_exists and self.status_disabled


class FortiPamLocalUserSshTransport:
    """Execute only compiled Local User inspection and disable sequences."""

    def __init__(self, config: TargetSshTransportConfig) -> None:
        self._config = config

    def inspect(self, username: str) -> LocalUserInspection:
        """Return the exact user's existence and current status without a write."""

        name = _user_name(username)
        return cast(LocalUserInspection, _run_sync(self._inspect(name)))

    def disable_and_readback(self, username: str) -> LocalUserReadback:
        """Disable one Local User and verify it with fixed full readback."""

        name = _user_name(username)
        return cast(LocalUserReadback, _run_sync(self._disable_and_readback(name)))

    async def _inspect(self, username: str) -> LocalUserInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                compact = await self._run_admin_context(
                    process,
                    root_prompt,
                    (f"show | grep {username}",),
                    deadline,
                )
                full = await self._run_admin_context(
                    process,
                    root_prompt,
                    (f"show | grep {username} -f",),
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _inspection(compact + full, username)

    async def _disable_and_readback(self, username: str) -> LocalUserReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._disable_user(process, root_prompt, username, deadline)
                readback = await self._run_admin_context(
                    process,
                    root_prompt,
                    (f"show | grep {username} -f",),
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(readback, username)

    async def _disable_user(
        self,
        process: Any,
        root_prompt: bytes,
        username: str,
        deadline: float,
    ) -> None:
        """Disable one user while following the appliance's entry prompt."""

        admin_prompt = _context_prompt(root_prompt)
        try:
            await _send_and_read(process, "config system admin", admin_prompt, deadline)
            entry_prompt = await _send_and_read_dynamic_prompt(
                process, f'edit "{username}"', root_prompt, deadline
            )
            await _send_and_read(process, "set status disable", entry_prompt, deadline)
            returned_admin_prompt = await _send_and_read_dynamic_prompt(
                process, "next", root_prompt, deadline
            )
            _require_context_prompt(root_prompt, returned_admin_prompt, "admin")
            returned_root_prompt = await _send_and_read_dynamic_prompt(
                process, "end", root_prompt, deadline
            )
            _require_root_prompt(root_prompt, returned_root_prompt)
        except LocalUserSshTransportError:
            raise
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise LocalUserSshTransportError(_DENIED_MESSAGE) from exc

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
            raise LocalUserSshTransportError(_DENIED_MESSAGE) from exc

    async def _run_admin_context(
        self,
        process: Any,
        root_prompt: bytes,
        commands: tuple[str, ...],
        deadline: float,
    ) -> bytes:
        context_prompt = _context_prompt(root_prompt)
        try:
            await _send_and_read(
                process,
                "config system admin",
                context_prompt,
                deadline,
            )
            outputs = [
                await _send_and_read(process, command, context_prompt, deadline)
                for command in commands
            ]
            await _send_and_read(process, "end", root_prompt, deadline)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise LocalUserSshTransportError(_DENIED_MESSAGE) from exc
        return b"".join(outputs)


async def _send_and_read(
    process: Any,
    command: str,
    expected_prompt: bytes,
    deadline: float,
) -> bytes:
    stdin = process.stdin
    stdout = process.stdout
    stdin.write(command.encode("ascii") + b"\n")
    await stdin.drain()
    output = await _read_until_prompt(
        stdout,
        deadline,
        _MAX_OUTPUT_BYTES,
        expected_prompt=expected_prompt,
    )
    _raise_for_remote_rejection(output)
    return output


async def _close_cli(process: Any) -> None:
    try:
        process.stdin.write(b"exit\n")
        await process.stdin.drain()
    except Exception:
        return


def _run_sync(coroutine: Coroutine[Any, Any, Any]) -> Any:
    try:
        return asyncio.run(coroutine)
    except LocalUserSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise LocalUserSshTransportError(_DENIED_MESSAGE) from exc


def _inspection(output: bytes, username: str) -> LocalUserInspection:
    normalized = output.replace(b"\r", b"")
    marker = f'edit "{username}"'.encode("ascii")
    if marker not in normalized:
        return LocalUserInspection(False, "unknown")
    disabled = b"set status disable" in normalized
    enabled = b"set status enable" in normalized
    if disabled and not enabled:
        status: _UserStatus = "disable"
    elif enabled and not disabled:
        status = "enable"
    elif not disabled and not enabled:
        # FortiPAM emits only non-default settings in this filtered output.
        # A Local User without an explicit status line therefore has the
        # appliance default, which is enabled. This behavior is verified on
        # the lab appliance with a newly-created Guest fixture.
        status = "enable"
    else:
        status = "unknown"
    return LocalUserInspection(True, status)


def _readback(output: bytes, username: str) -> LocalUserReadback:
    inspection = _inspection(output, username)
    return LocalUserReadback(
        user_exists=inspection.exists,
        status_disabled=inspection.status == "disable",
    )


def _context_prompt(root_prompt: bytes) -> bytes:
    if len(root_prompt) < 3:
        raise LocalUserSshTransportError(_DENIED_MESSAGE)
    suffix = root_prompt[-1:]
    if suffix not in {b"#", b"$"} or root_prompt[-2:-1] != b" ":
        raise LocalUserSshTransportError(_DENIED_MESSAGE)
    return root_prompt[:-2] + b" (admin) " + suffix


def _user_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise LocalUserSshTransportError(_DENIED_MESSAGE)
    return value


__all__ = [
    "FortiPamLocalUserSshTransport",
    "LocalUserInspection",
    "LocalUserReadback",
    "LocalUserSshTransportError",
]
