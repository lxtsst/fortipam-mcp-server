"""Pinned-SSH transport for one FortiPAM SSH Target create contract.

This module intentionally contains no generic CLI relay.  It can inspect and
create exactly one IPv4 ``Unix Account (SSH Password)`` Target, using compiled
FortiPAM CLI sequences and returning only categorical verification evidence.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
import ipaddress
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Final, cast

import asyncssh

from .cli_safety import (
    CliTransportError,
    _complete_pre_login,
    _extract_prompt,
    _raise_for_remote_rejection,
    _read_until_prompt,
)
from .target_contract import (
    DEFAULT_TEMPLATE,
    TARGET_CLASS,
    WEB_PROXY_STATUS,
    TargetInspection,
    TargetReadback,
)


ENV_PREFIX: Final = "FPA_HOME_LAB_FPA1_V4_TARGET_"
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_DENIED_MESSAGE: Final = "FortiPAM V4 Target transport is unavailable."
_MAX_OUTPUT_BYTES: Final = 64 * 1024


class TargetSshTransportError(RuntimeError):
    """Stable failure for the bounded Target transport."""


class TargetSshTransportConfigurationError(ValueError):
    """Raised when dedicated SSH Target transport configuration is unsafe."""


@dataclass(frozen=True, slots=True)
class TargetSshTransportConfig:
    """Dedicated password-file SSH configuration held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise TargetSshTransportConfigurationError("The Target SSH host is invalid.")
        if not _safe_name(self.username):
            raise TargetSshTransportConfigurationError("The Target SSH username is invalid.")
        if not 1 <= self.port <= 65535:
            raise TargetSshTransportConfigurationError("The Target SSH port is invalid.")
        if not 1 <= self.timeout_seconds <= 60:
            raise TargetSshTransportConfigurationError("The Target SSH timeout is invalid.")
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.password
        ):
            raise TargetSshTransportConfigurationError("The Target SSH password is invalid.")
        _private_regular_file(self.known_hosts_file, "known_hosts")


def load_target_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> TargetSshTransportConfig:
    """Load a dedicated, explicit Target SSH configuration.

    The ordinary FortiPAM API or SSH environment variables are never used as a
    fallback.  This prevents a Target action from silently inheriting a broad
    legacy identity.
    """

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise TargetSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise TargetSshTransportConfigurationError(
            "Dedicated Target SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise TargetSshTransportConfigurationError(
            "The Target SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return TargetSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamTargetSshTransport:
    """Execute only compiled SSH Target inspection and creation sequences."""

    def __init__(self, config: TargetSshTransportConfig) -> None:
        self._config = config

    def inspect(self, target_name: str) -> TargetInspection:
        """Return target absence/presence without a write.

        FortiPAM exposes the fixed template as a Target field, but a
        template-context CLI read requires write-level Template entitlement on
        this release. The bounded create/readback below therefore validates
        the fixed template without expanding the dedicated identity beyond
        Target write capability.
        """

        name = _target_name(target_name)
        return cast(TargetInspection, _run_sync(self._inspect(name)))

    def resolve_unique_target_name_for_address(self, address: str) -> str | None:
        """Resolve one exact existing Target name for a fixed IPv4 address.

        The result is for an owner-only composition boundary; callers must not
        expose it through an MCP result or log it.  Ambiguous or absent matches
        return ``None`` rather than selecting a Target.
        """

        ipv4 = _ipv4(address)
        return cast(str | None, _run_sync(self._resolve_unique_target_name(ipv4)))

    def create_and_readback(
        self,
        target_name: str,
        address: str,
        *,
        expected_product_version: str | None = None,
        expected_product_build: int | None = None,
    ) -> TargetReadback:
        """Create one fixed SSH Target and verify it using a bounded readback."""

        if expected_product_version is not None or expected_product_build is not None:
            raise TargetSshTransportError(_DENIED_MESSAGE)

        name = _target_name(target_name)
        ipv4 = _ipv4(address)
        return cast(TargetReadback, _run_sync(self._create_and_readback(name, ipv4)))

    async def _inspect(self, target_name: str) -> TargetInspection:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                target_compact = await self._run_context(
                    process,
                    root_prompt,
                    "target",
                    (f"show | grep {target_name}",),
                    deadline,
                )
                target_full = await self._run_context(
                    process,
                    root_prompt,
                    "target",
                    (f"show | grep {target_name} -f",),
                    deadline,
                )
            finally:
                await _close_cli(process)
        target_marker = f'edit "{target_name}"'.encode("ascii")
        return TargetInspection(exists=target_marker in target_compact + target_full)

    async def _resolve_unique_target_name(self, address: str) -> str | None:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                target_full = await self._run_context(
                    process,
                    root_prompt,
                    "target",
                    (f"show | grep {address} -f",),
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _unique_target_name_for_address(target_full, address)

    async def _create_and_readback(
        self,
        target_name: str,
        address: str,
    ) -> TargetReadback:
        creation_time = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                await self._create_target(
                    process,
                    root_prompt,
                    target_name,
                    address,
                    creation_time,
                    deadline,
                )
                readback = await self._run_context(
                    process,
                    root_prompt,
                    "target",
                    (f"show | grep {target_name} -f",),
                    deadline,
                )
            finally:
                await _close_cli(process)
        return _readback(readback, target_name, address)

    async def _create_target(
        self,
        process: Any,
        root_prompt: bytes,
        target_name: str,
        address: str,
        creation_time: str,
        deadline: float,
    ) -> None:
        """Create one Target while tracking the appliance's entry prompt.

        FortiPAM changes from the table context prompt to a per-entry prompt
        after ``edit``.  That prompt can use a different privilege marker and
        abbreviate the entry name, so it is learned from the pinned appliance
        rather than constructed from requester-controlled input.
        """

        table_prompt = _context_prompt(root_prompt, "target")
        commands = (
            f'set class "{TARGET_CLASS}"',
            f'set template "{DEFAULT_TEMPLATE}"',
            f'set address "{address}"',
            f"set creation-time {creation_time}",
            f"set web-proxy-status {WEB_PROXY_STATUS}",
        )
        try:
            await _send_and_read(process, "config secret target", table_prompt, deadline)
            entry_prompt = await _send_and_read_dynamic_prompt(
                process, f'edit "{target_name}"', root_prompt, deadline
            )
            for command in commands:
                await _send_and_read(process, command, entry_prompt, deadline)
            returned_table_prompt = await _send_and_read_dynamic_prompt(
                process, "next", root_prompt, deadline
            )
            _require_context_prompt(root_prompt, returned_table_prompt, "target")
            returned_root_prompt = await _send_and_read_dynamic_prompt(
                process, "end", root_prompt, deadline
            )
            _require_root_prompt(root_prompt, returned_root_prompt)
        except TargetSshTransportError:
            raise
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise TargetSshTransportError(_DENIED_MESSAGE) from exc

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
            raise TargetSshTransportError(_DENIED_MESSAGE) from exc

    async def _run_context(
        self,
        process: Any,
        root_prompt: bytes,
        context: str,
        commands: tuple[str, ...],
        deadline: float,
    ) -> bytes:
        context_prompt = _context_prompt(root_prompt, context)
        try:
            await _send_and_read(process, f"config secret {context}", context_prompt, deadline)
            outputs = [
                await _send_and_read(process, command, context_prompt, deadline)
                for command in commands
            ]
            await _send_and_read(process, "end", root_prompt, deadline)
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise TargetSshTransportError(_DENIED_MESSAGE) from exc
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


async def _send_and_read_dynamic_prompt(
    process: Any,
    command: str,
    root_prompt: bytes,
    deadline: float,
) -> bytes:
    """Send a compiled command and return a same-host prompt learned live."""

    stdin = process.stdin
    stdout = process.stdout
    stdin.write(command.encode("ascii") + b"\n")
    await stdin.drain()
    output = await _read_until_prompt(
        stdout,
        deadline,
        _MAX_OUTPUT_BYTES,
        expected_prompt=None,
    )
    _raise_for_remote_rejection(output)
    prompt = _extract_prompt(output)
    _require_same_host_prompt(root_prompt, prompt)
    return prompt


async def _close_cli(process: Any) -> None:
    try:
        stdin = process.stdin
        stdin.write(b"exit\n")
        await stdin.drain()
    except Exception:
        return


def _run_sync(coroutine: Coroutine[Any, Any, Any]) -> Any:
    try:
        return asyncio.run(coroutine)
    except TargetSshTransportError:
        raise
    except (asyncssh.Error, OSError, TimeoutError, RuntimeError) as exc:
        raise TargetSshTransportError(_DENIED_MESSAGE) from exc


def _readback(output: bytes, target_name: str, address: str) -> TargetReadback:
    normalized = output.replace(b"\r", b"")
    return TargetReadback(
        target_exists=f'edit "{target_name}"'.encode("ascii") in normalized,
        class_matches=f'set class "{TARGET_CLASS}"'.encode("ascii") in normalized,
        template_matches=f'set template "{DEFAULT_TEMPLATE}"'.encode("ascii")
        in normalized,
        address_matches=f'set address "{address}"'.encode("ascii") in normalized,
        web_proxy_disabled=f"set web-proxy-status {WEB_PROXY_STATUS}".encode("ascii")
        in normalized,
        owner_relation_matches=False,
        create_secret_group_relation_matches=False,
    )


def _context_prompt(root_prompt: bytes, context: str) -> bytes:
    if context not in {"target", "template"} or len(root_prompt) < 3:
        raise TargetSshTransportError(_DENIED_MESSAGE)
    suffix = root_prompt[-1:]
    if suffix not in {b"#", b"$"} or root_prompt[-2:-1] != b" ":
        raise TargetSshTransportError(_DENIED_MESSAGE)
    return root_prompt[:-2] + f" ({context}) ".encode("ascii") + suffix


def _require_same_host_prompt(root_prompt: bytes, prompt: bytes) -> None:
    """Reject an unrecognized dynamic prompt without exposing terminal data."""

    root_match = re.fullmatch(rb"([A-Za-z0-9._-]{1,63}) [#$]", root_prompt)
    prompt_match = re.fullmatch(
        rb"([A-Za-z0-9._-]{1,63})(?: \(([^()\r\n]{1,80})\))? [#$]", prompt
    )
    if root_match is None or prompt_match is None or root_match.group(1) != prompt_match.group(1):
        raise TargetSshTransportError(_DENIED_MESSAGE)


def _require_context_prompt(root_prompt: bytes, prompt: bytes, context: str) -> None:
    _require_same_host_prompt(root_prompt, prompt)
    match = re.fullmatch(
        rb"[A-Za-z0-9._-]{1,63} \(([^()\r\n]{1,80})\) [#$]", prompt
    )
    if match is None or match.group(1) != context.encode("ascii"):
        raise TargetSshTransportError(_DENIED_MESSAGE)


def _require_root_prompt(root_prompt: bytes, prompt: bytes) -> None:
    _require_same_host_prompt(root_prompt, prompt)
    if b" (" in prompt:
        raise TargetSshTransportError(_DENIED_MESSAGE)


def _target_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise TargetSshTransportError(_DENIED_MESSAGE)
    return value


def _safe_name(value: str) -> bool:
    return isinstance(value, str) and _NAME.fullmatch(value) is not None


def _safe_host(value: str) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 255
        and not any(character.isspace() or character in "@/\\" for character in value)
    )


def _ipv4(value: str) -> str:
    if not isinstance(value, str):
        raise TargetSshTransportError(_DENIED_MESSAGE)
    try:
        parsed = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise TargetSshTransportError(_DENIED_MESSAGE) from exc
    return str(parsed)


def _unique_target_name_for_address(output: bytes, address: str) -> str | None:
    """Return one exact Target block matching ``address``, otherwise none."""

    output = output.replace(b"\r", b"")
    output = re.sub(rb"(?m)[ \t]+<---[ \t]*$", b"", output)
    entry = re.compile(
        rb'(?ms)^(?P<indent>[ \t]*)edit "(?P<name>[^"\r\n]+)"\r?\n'
        rb'(?P<body>.*?)(?=^(?P=indent)(?:edit |next\b|end\b)|\Z)'
    )
    matches: set[str] = set()
    for match in entry.finditer(output):
        addresses = re.findall(
            rb'(?m)^[ \t]*set address "([0-9.]+)"[ \t]*\r?$',
            match.group("body"),
        )
        if len(addresses) == 1 and addresses[0].decode("ascii") == address:
            name = match.group("name")
            if re.fullmatch(rb"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name) is None:
                return None
            matches.add(name.decode("ascii"))
    return next(iter(matches)) if len(matches) == 1 else None


def _private_regular_file(path: Path, label: str) -> None:
    try:
        status = path.lstat()
    except OSError as exc:
        raise TargetSshTransportConfigurationError(
            f"The Target SSH {label} file is unavailable."
        ) from exc
    if not stat.S_ISREG(status.st_mode) or stat.S_ISLNK(status.st_mode):
        raise TargetSshTransportConfigurationError(
            f"The Target SSH {label} file is unsafe."
        )
    if stat.S_IMODE(status.st_mode) & 0o077:
        raise TargetSshTransportConfigurationError(
            f"The Target SSH {label} file must be owner-only."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise TargetSshTransportConfigurationError(
            "The Target SSH password file is unavailable."
        ) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TargetSshTransportConfigurationError(
            "The Target SSH password file is invalid."
        ) from exc
    return value


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


__all__ = [
    "DEFAULT_TEMPLATE",
    "ENV_PREFIX",
    "FortiPamTargetSshTransport",
    "TargetInspection",
    "TargetReadback",
    "TargetSshTransportConfig",
    "TargetSshTransportConfigurationError",
    "TargetSshTransportError",
    "load_target_ssh_transport_config",
]
