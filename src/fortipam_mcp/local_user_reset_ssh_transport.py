"""Pinned SSH transport for one bounded FortiPAM Local User password reset.

The action is intentionally narrower than the general Local User CLI surface.
It can reset a generated password only for an existing disabled Guest account
whose name is in the V4 laboratory namespace.  The replacement password stays
in process memory only and is never returned through MCP, logs, or readback.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from dataclasses import dataclass
import re
import secrets
import time
from typing import Any, Literal, cast

import asyncssh

from .cli_safety import (
    CliTransportError,
    _complete_pre_login,
    _extract_prompt,
    _raise_for_remote_rejection,
    _read_until_prompt,
)
from .local_user_create_ssh_transport import (
    DEFAULT_ACCESS_PROFILE,
    LocalUserCreateSshTransportConfig,
)
from .secret_metadata_http_transport import _zeroize_mutable
from .target_ssh_transport import (
    _close_cli,
    _require_context_prompt,
    _require_root_prompt,
    _require_same_host_prompt,
    _send_and_read,
    _send_and_read_dynamic_prompt,
)


LAB_USER_NAME_PREFIX = "mcp-v4-user-"
_NAME = re.compile(r"mcp-v4-user-[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")
_DENIED_MESSAGE = "FortiPAM V4 Local User reset transport is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_UserStatus = Literal["enable", "disable", "unknown"]


class LocalUserResetSshTransportError(RuntimeError):
    """Stable, non-disclosing failure for the bounded SSH transport."""

    phase: str = "unknown"
    reason: str = "unavailable"
    return_code: int | None = None


async def _reset_command(
    process: Any,
    command: str | bytearray,
    root_prompt: bytes,
    deadline: float,
    phase: Literal["enter_admin", "select_target", "set_password", "commit_target", "leave_admin"],
    expected_prompt: bytes | None = None,
) -> bytes:
    """Keep fixed failure categories without exposing CLI output or material."""
    failure = LocalUserResetSshTransportError(_DENIED_MESSAGE)
    failure.phase = phase
    encoded = command.encode("ascii") if isinstance(command, str) else command
    line = bytearray(encoded)
    line.append(10)
    try:
        process.stdin.write(line)
        await process.stdin.drain()
        output = await _read_until_prompt(
            process.stdout, deadline, _MAX_OUTPUT_BYTES, expected_prompt=expected_prompt,
        )
        # Echoed input can contain material resembling an error. Never classify
        # or retain that input as a device diagnostic.
        diagnostic = output.replace(encoded, b"").lower()
        code = re.search(rb"return code (-?[0-9]{1,5})(?:\D|$)", diagnostic)
        if code is not None:
            failure.return_code = int(code.group(1))
        if phase == "select_target" and re.search(rb"new entry[^\r\n]{0,120}added", diagnostic):
            failure.reason = "target_missing"
            raise failure
        if re.search(rb"only[^\r\n]{0,80}admin user can change password", diagnostic):
            failure.reason = "actor_not_authorized"
            raise failure
        for marker, reason in (
            (b"old password checking error", "old_password_rejected"),
            (b"password policy violation", "password_policy_rejected"),
            (b"permission denied", "permission_denied"),
            (b"access denied", "permission_denied"),
        ):
            if marker in diagnostic:
                failure.reason = reason
                raise failure
        if failure.return_code not in (None, 0):
            failure.reason = "remote_rejected"
            raise failure
        try:
            _raise_for_remote_rejection(diagnostic)
        except CliTransportError:
            failure.reason = "remote_rejected"
            raise failure from None
        prompt = _extract_prompt(output)
        _require_same_host_prompt(root_prompt, prompt)
        return prompt
    except LocalUserResetSshTransportError:
        raise
    except (CliTransportError, asyncssh.Error, OSError, TimeoutError):
        failure.reason = "transport_or_prompt_failure"
        raise failure from None
    finally:
        _zeroize_mutable(line)


@dataclass(frozen=True, slots=True)
class LocalUserResetInspection:
    """Value-minimized preflight state for one reset-eligible Local User."""

    exists: bool
    access_profile_matches: bool
    status: _UserStatus

    @property
    def eligible(self) -> bool:
        """Whether the exact restricted reset baseline is present."""

        return (
            self.exists
            and self.access_profile_matches
            and self.status == "disable"
        )


@dataclass(frozen=True, slots=True)
class LocalUserResetReadback:
    """Categorical post-write verification for the reset contract."""

    user_exists: bool
    access_profile_matches: bool
    status_disabled: bool

    @property
    def verified(self) -> bool:
        """Whether the non-secret Local User baseline was preserved."""

        return all(
            (
                self.user_exists,
                self.access_profile_matches,
                self.status_disabled,
            )
        )


class FortiPamLocalUserResetSshTransport:
    """Run only compiled reset inspection and password-write sequences."""

    def __init__(self, config: LocalUserCreateSshTransportConfig) -> None:
        self._config = config

    def inspect(self, username: str) -> LocalUserResetInspection:
        """Read exactly one reset-eligible user without returning its metadata."""

        name = _user_name(username)
        return cast(LocalUserResetInspection, _run_sync(self._inspect(name)))

    def reset_and_readback(self, username: str) -> LocalUserResetReadback:
        """Write one generated password and verify the user remains restricted."""

        name = _user_name(username)
        return cast(LocalUserResetReadback, _run_sync(self._reset_and_readback(name)))

    def inspect_writer(self) -> bool:
        """Whether the bound writer matches the laboratory-qualified role.

        False means this candidate has no qualified writer, not that FortiPAM
        universally denies every other role. No role is changed by this read.
        """
        return cast(bool, _run_sync(self._inspect_writer()))

    async def _inspect_writer(self) -> bool:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                return await self._writer_qualified(process, root_prompt, deadline)
            finally:
                await _close_cli(process)

    async def _writer_qualified(self, process: Any, prompt: bytes, deadline: float) -> bool:
        name = self._config.username
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name) is None:
            return False
        output = await self._run_admin_context(
            process, prompt, (f"show full-configuration | grep {name} -f",), deadline,
        )
        return _qualified_writer(output, name)

    async def _require_writer(self, process: Any, prompt: bytes, deadline: float) -> None:
        if not await self._writer_qualified(process, prompt, deadline):
            error = LocalUserResetSshTransportError(_DENIED_MESSAGE)
            error.phase = "writer_preflight"
            error.reason = "actor_unqualified"
            raise error

    async def _inspect(self, username: str) -> LocalUserResetInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._require_writer(process, root_prompt, deadline)
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

    async def _reset_and_readback(self, username: str) -> LocalUserResetReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._require_writer(process, root_prompt, deadline)
                password = _generated_replacement_password()
                await self._reset_password(
                    process,
                    root_prompt,
                    username,
                    password,
                    deadline,
                )
                output = await self._run_admin_context(
                    process,
                    root_prompt,
                    (f"show | grep {username} -f",),
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(output, username)

    async def _reset_password(
        self,
        process: Any,
        root_prompt: bytes,
        username: str,
        password: str,
        deadline: float,
    ) -> None:
        """Run only the documented Local User password CLI mutation."""

        admin_prompt = _context_prompt(root_prompt)
        try:
            await _reset_command(process, "config system admin", root_prompt,
                                 deadline, "enter_admin", admin_prompt)
            entry_prompt = await _reset_command(
                process,
                f'edit "{username}"',
                root_prompt,
                deadline,
                "select_target",
            )
            await _reset_command(
                process,
                f'set password "{password}"',
                root_prompt,
                deadline,
                "set_password",
                entry_prompt,
            )
            returned_admin_prompt = await _reset_command(
                process,
                "next",
                root_prompt,
                deadline,
                "commit_target",
            )
            _require_context_prompt(root_prompt, returned_admin_prompt, "admin")
            returned_root_prompt = await _reset_command(
                process,
                "end",
                root_prompt,
                deadline,
                "leave_admin",
            )
            _require_root_prompt(root_prompt, returned_root_prompt)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise LocalUserResetSshTransportError(_DENIED_MESSAGE) from exc

    async def _run_admin_context(
        self,
        process: Any,
        root_prompt: bytes,
        commands: tuple[str, ...],
        deadline: float,
    ) -> bytes:
        admin_prompt = _context_prompt(root_prompt)
        try:
            await _send_and_read(process, "config system admin", admin_prompt, deadline)
            outputs = [
                await _send_and_read(process, command, admin_prompt, deadline)
                for command in commands
            ]
            returned_root_prompt = await _send_and_read_dynamic_prompt(
                process,
                "end",
                root_prompt,
                deadline,
            )
            _require_root_prompt(root_prompt, returned_root_prompt)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise LocalUserResetSshTransportError(_DENIED_MESSAGE) from exc
        return b"".join(outputs)

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
            raise LocalUserResetSshTransportError(_DENIED_MESSAGE) from exc


def _inspection(output: bytes, username: str) -> LocalUserResetInspection:
    stanza = _stanza(output, username)
    if stanza is None:
        return LocalUserResetInspection(False, False, "unknown")
    disabled = b"set status disable" in stanza
    enabled = b"set status enable" in stanza
    if disabled and not enabled:
        status: _UserStatus = "disable"
    elif enabled and not disabled:
        status = "enable"
    elif not disabled and not enabled:
        # The appliance suppresses the default enabled setting in filtered
        # output.  A missing status line is consequently not reset-eligible.
        status = "enable"
    else:
        status = "unknown"
    profile_markers = (
        f'set accprofile "{DEFAULT_ACCESS_PROFILE}"'.encode("ascii"),
        f"set accprofile {DEFAULT_ACCESS_PROFILE}".encode("ascii"),
    )
    return LocalUserResetInspection(
        exists=True,
        access_profile_matches=any(marker in stanza for marker in profile_markers),
        status=status,
    )


def _readback(output: bytes, username: str) -> LocalUserResetReadback:
    inspection = _inspection(output, username)
    return LocalUserResetReadback(
        user_exists=inspection.exists,
        access_profile_matches=inspection.access_profile_matches,
        status_disabled=inspection.status == "disable",
    )


def _qualified_writer(output: bytes, username: str) -> bool:
    """Match one exact full-config stanza without returning role or identity."""
    return _writer_profile(output, username) == b"super_admin"


def _writer_profile(output: bytes, username: str) -> bytes | None:
    """Parse the direct admin entry, ignoring grep arrows and nested names."""
    normalized = output.replace(b"\r", b"")
    tables = list(re.finditer(rb"^config system admin[ \t]*(?:<---[ \t]*)?\n", normalized, re.MULTILINE))
    if len(tables) != 1:
        return None
    tail = normalized[tables[0].end():]
    end = re.search(rb"^end[ \t]*(?:\n|$)", tail, re.MULTILINE)
    if end is None:
        return None
    table = tail[:end.start()]
    pattern = rb'^    edit "' + re.escape(username.encode("ascii")) + rb'"[ \t]*(?:<---[ \t]*)?\n'
    matches = list(re.finditer(pattern, table, re.MULTILINE))
    if len(matches) != 1:
        return None
    match = matches[0]
    tail = table[match.end():]
    end = re.search(rb"^    (next[ \t]*|edit[^\r\n]*|end[ \t]*)(?:\n|$)", tail, re.MULTILINE)
    if end is None or end.group(1).strip() != b"next":
        return None
    stanza = tail[:end.start()]
    roles = re.findall(rb'^        set accprofile (?:"([^"\r\n]+)"|([^\s"]+))[ \t]*(?:<---[ \t]*)?$',
                       stanza, re.MULTILINE)
    return (roles[0][0] or roles[0][1]) if len(roles) == 1 else None


def _stanza(output: bytes, username: str) -> bytes | None:
    normalized = output.replace(b"\r", b"")
    marker = f'edit "{username}"'.encode("ascii")
    start = normalized.find(marker)
    if start < 0:
        return None
    remainder = normalized[start + len(marker) :]
    next_edit = remainder.find(b"\nedit ")
    if next_edit >= 0:
        remainder = remainder[:next_edit]
    return marker + remainder


def _context_prompt(root_prompt: bytes) -> bytes:
    if len(root_prompt) < 3 or root_prompt[-2:-1] != b" ":
        raise LocalUserResetSshTransportError(_DENIED_MESSAGE)
    suffix = root_prompt[-1:]
    if suffix not in {b"#", b"$"}:
        raise LocalUserResetSshTransportError(_DENIED_MESSAGE)
    return root_prompt[:-2] + b" (admin) " + suffix


def _generated_replacement_password() -> str:
    """Return a one-use ASCII password satisfying common product defaults."""

    return f"McpV4!{secrets.token_hex(5)}rZ9"


def _user_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise LocalUserResetSshTransportError(_DENIED_MESSAGE)
    return value


def _run_sync(coroutine: Coroutine[Any, Any, Any]) -> Any:
    try:
        return asyncio.run(coroutine)
    except LocalUserResetSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise LocalUserResetSshTransportError(_DENIED_MESSAGE) from exc


__all__ = [
    "FortiPamLocalUserResetSshTransport",
    "LAB_USER_NAME_PREFIX",
    "LocalUserResetInspection",
    "LocalUserResetReadback",
    "LocalUserResetSshTransportError",
    "_readback",
]
