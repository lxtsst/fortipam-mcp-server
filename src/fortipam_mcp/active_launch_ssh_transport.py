"""Pinned SSH adapter for bounded FortiPAM active-launch control.

FortiPAM 1.9.1 documents ``diagnose wad token list`` for active-launch
inspection and ``diagnose wad token clear <token_id>`` for disconnecting one
launch.  Omitting the token ID clears every active launch, so this adapter
never emits that form and never accepts caller-controlled CLI text.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine, Mapping
from dataclasses import dataclass, replace
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, cast

import asyncssh

from .cli_safety import CliTransportError, _complete_pre_login, _raise_for_remote_rejection
from . import target_qualified_reference_reader as _source_reader
from .target_ssh_transport import _close_cli, _require_root_prompt, _send_and_read


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_ACTIVE_LAUNCH_"
ACTIVE_LAUNCH_LIST_COMMAND = "diagnose wad token list"
ACTIVE_LAUNCH_CLEAR_COMMAND = "diagnose wad token clear"
_UNAVAILABLE = "FortiPAM V4 active-launch control is unavailable."
_MAX_OUTPUT_BYTES = 64 * 1024
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SAFE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TOKEN_ID = re.compile(
    rb"token(?:[\t _-]*id)?[\t ]*[:=][\t ]*([A-Za-z0-9][A-Za-z0-9._:-]{0,127})",
    re.IGNORECASE,
)
_PROMPT_LINE = re.compile(rb"[A-Za-z0-9_.()\- ]{1,128}[#$>]\s*\Z")
_NATIVE_ENDPOINT = re.compile(
    rb"([0-9]{1,3}(?:\.[0-9]{1,3}){3}):([0-9]{1,5})->"
    rb"([A-Za-z0-9][A-Za-z0-9.-]{0,252}):([0-9]{1,5})"
)
_NATIVE_ID = re.compile(
    rb"id=([1-9][0-9]{0,127}), worker_id=(?:0|[1-9][0-9]{0,9}) "
    rb"launcher=[^\x00-\x1f\x7f=]{1,255}"
)
_NATIVE_ACCOUNT = re.compile(
    rb"account_name=[^\x00-\x20\x7f=]{1,128} secret=[1-9][0-9]{0,9} "
    rb"secret_name=[^\x00-\x1f\x7f=]{1,255}"
)
_NATIVE_GATEWAY = re.compile(
    rb"gateway_name=[^\x00-\x1f\x7f=]{0,255} gateway_address=[^\x00-\x20\x7f=]{0,255}"
)


class ActiveLaunchSshTransportError(RuntimeError):
    """Stable, non-disclosing failure for active-launch control."""


class ActiveLaunchSshTransportConfigurationError(ValueError):
    """Raised when dedicated active-launch SSH settings are unsafe."""


@dataclass(frozen=True, slots=True)
class ActiveLaunchSshTransportConfig:
    """Dedicated SSH settings held only in process memory."""

    host: str
    port: int
    username: str
    password: str
    known_hosts_file: Path
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not _safe_host(self.host):
            raise ActiveLaunchSshTransportConfigurationError(
                "The active-launch SSH host is invalid."
            )
        if not _safe_name(self.username):
            raise ActiveLaunchSshTransportConfigurationError(
                "The active-launch SSH username is invalid."
            )
        if not 1 <= self.port <= 65535:
            raise ActiveLaunchSshTransportConfigurationError(
                "The active-launch SSH port is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise ActiveLaunchSshTransportConfigurationError(
                "The active-launch SSH timeout is invalid."
            )
        if not self.password or len(self.password) > 512 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.password
        ):
            raise ActiveLaunchSshTransportConfigurationError(
                "The active-launch SSH password is invalid."
            )
        _private_regular_file(self.known_hosts_file, "known_hosts")


@dataclass(frozen=True, slots=True)
class ActiveLaunchListing:
    """Internal token inventory; token values must never leave the adapter."""

    recognized: bool
    token_ids: tuple[str, ...]
    record_identities: tuple[tuple[str, str], ...] = ()
    serial_digest: str | None = None


@dataclass(frozen=True, slots=True)
class ActiveLaunchClearReadback:
    """Categorical post-clear evidence without disclosing a token or session."""

    listing_recognized: bool
    selected_launch_absent: bool
    other_launches_preserved: bool = False

    @property
    def verified(self) -> bool:
        return (
            self.listing_recognized
            and self.selected_launch_absent
            and self.other_launches_preserved
        )


def load_active_launch_ssh_transport_config(
    environment: Mapping[str, str] | None = None,
) -> ActiveLaunchSshTransportConfig:
    """Load only independently scoped active-launch SSH settings."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise ActiveLaunchSshTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    host = _value(env, "SSH_HOST")
    username = _value(env, "SSH_USERNAME")
    password_file = _value(env, "SSH_PASSWORD_FILE")
    known_hosts_file = _value(env, "SSH_KNOWN_HOSTS_FILE")
    port_raw = _value(env, "SSH_PORT") or "22"
    timeout_raw = _value(env, "SSH_TIMEOUT_SECONDS") or "15"
    if None in {host, username, password_file, known_hosts_file}:
        raise ActiveLaunchSshTransportConfigurationError(
            "Dedicated active-launch SSH host, username, password file, and known_hosts are required."
        )
    try:
        port = int(port_raw)
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise ActiveLaunchSshTransportConfigurationError(
            "The active-launch SSH numeric settings are invalid."
        ) from exc
    assert host is not None
    assert username is not None
    assert password_file is not None
    assert known_hosts_file is not None
    return ActiveLaunchSshTransportConfig(
        host=host,
        port=port,
        username=username,
        password=_read_password_file(Path(password_file)),
        known_hosts_file=Path(known_hosts_file),
        timeout_seconds=timeout,
    )


class FortiPamActiveLaunchSshTransport:
    """Run only fixed WAD list and exact-token clear commands."""

    def __init__(self, config: ActiveLaunchSshTransportConfig, *, expected_serial_digest: str | None = None) -> None:
        if expected_serial_digest is not None and (
                type(expected_serial_digest) is not str or re.fullmatch(r'[0-9a-f]{64}', expected_serial_digest) is None):
            raise ActiveLaunchSshTransportError(_UNAVAILABLE)
        self._config = config
        self._expected_serial_digest = expected_serial_digest

    def list_active_launches(self) -> ActiveLaunchListing:
        return cast(ActiveLaunchListing, _run_sync(self._list_active_launches()))

    def clear_active_launch_and_readback(
        self,
        token_id: str,
        *, expected_identity_digest: str | None = None,
        guard: Callable[[], None] | None = None,
    ) -> ActiveLaunchClearReadback:
        safe_token = _token_id(token_id)
        if guard is not None and not callable(guard):
            raise ActiveLaunchSshTransportError(_UNAVAILABLE)
        if expected_identity_digest is not None and (
                self._expected_serial_digest is None or type(expected_identity_digest) is not str
                or re.fullmatch(r'[0-9a-f]{64}', expected_identity_digest) is None):
            raise ActiveLaunchSshTransportError(_UNAVAILABLE)
        return cast(
            ActiveLaunchClearReadback,
            _run_sync(self._clear_active_launch_and_readback(safe_token,
                expected_identity_digest=expected_identity_digest, guard=guard)),
        )

    async def _list_active_launches(self) -> ActiveLaunchListing:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                listing = await self._qualified_listing(process, root_prompt, deadline)
            finally:
                await _close_cli(process)
        return listing

    async def _qualified_listing(self, process: Any, root_prompt: bytes, deadline: float) -> ActiveLaunchListing:
        try:
            serial = None
            if self._expected_serial_digest is not None:
                serial = await self._source_digest(process, root_prompt, deadline)
            listing = _listing_from_output(await self._list(process, root_prompt, deadline))
            if serial is not None and await self._source_digest(process, root_prompt, deadline) != serial:
                raise ValueError
            return replace(listing, serial_digest=serial)
        except Exception:
            raise ActiveLaunchSshTransportError(_UNAVAILABLE) from None

    async def _source_digest(self, process: Any, root_prompt: bytes, deadline: float) -> str:
        raw = await _send_and_read(process, _source_reader._SERIAL, root_prompt, deadline)
        lines = _source_reader._lines(raw, _source_reader._SERIAL, root_prompt)
        match = re.fullmatch(rb'Serial-Number: ([A-Za-z0-9_-]{1,128})', lines[0]) if len(lines) == 1 else None
        if match is None or self._expected_serial_digest is None:
            raise ValueError
        digest = hashlib.sha256(match[1]).hexdigest()
        if not hmac.compare_digest(digest, self._expected_serial_digest):
            raise ValueError
        raw = await _send_and_read(process, _source_reader._VERSION, root_prompt, deadline)
        _source_reader._version(_source_reader._lines(raw, _source_reader._VERSION, root_prompt))
        return digest

    async def _clear_active_launch_and_readback(
        self,
        token_id: str,
        *, expected_identity_digest: str | None = None,
        guard: Callable[[], None] | None = None,
    ) -> ActiveLaunchClearReadback:
        async with self._connection() as connection:
            process, root_prompt, deadline = await self._open_cli(connection)
            try:
                current = await self._qualified_listing(process, root_prompt, deadline)
                if not current.recognized or token_id not in current.token_ids:
                    raise ActiveLaunchSshTransportError(_UNAVAILABLE)
                identity = dict(current.record_identities).get(token_id)
                if expected_identity_digest is not None and (
                        self._expected_serial_digest is None or identity is None
                        or not hmac.compare_digest(identity, expected_identity_digest)):
                    raise ActiveLaunchSshTransportError(_UNAVAILABLE)
                if guard is not None:
                    try:
                        guard()
                    except Exception:
                        raise ActiveLaunchSshTransportError(_UNAVAILABLE) from None
                output = await self._clear(process, root_prompt, deadline, token_id)
                if expected_identity_digest is not None:
                    try:
                        # A complete exact-command response is required before
                        # absence can count as this dispatch's readback. Body
                        # text grants nothing; native postconditions decide.
                        _source_reader._lines(output, _clear_command(token_id), root_prompt)
                        _raise_for_remote_rejection(output)
                    except Exception:
                        raise ActiveLaunchSshTransportError(_UNAVAILABLE) from None
                updated = await self._qualified_listing(process, root_prompt, deadline)
            finally:
                await _close_cli(process)
        return ActiveLaunchClearReadback(
            listing_recognized=updated.recognized,
            selected_launch_absent=updated.recognized and token_id not in updated.token_ids,
            other_launches_preserved=updated.recognized and (
                set(current.token_ids) - {token_id}
            ).issubset(updated.token_ids) and all(
                dict(updated.record_identities).get(other) == original_identity
                for other, original_identity in current.record_identities if other != token_id
            ),
        )

    async def _list(self, process: Any, root_prompt: bytes, deadline: float) -> bytes:
        try:
            return await _send_and_read(
                process,
                ACTIVE_LAUNCH_LIST_COMMAND,
                root_prompt,
                deadline,
            )
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ActiveLaunchSshTransportError(_UNAVAILABLE) from exc

    async def _clear(
        self,
        process: Any,
        root_prompt: bytes,
        deadline: float,
        token_id: str,
    ) -> bytes:
        try:
            return await _send_and_read(
                process,
                _clear_command(token_id),
                root_prompt,
                deadline,
            )
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ActiveLaunchSshTransportError(_UNAVAILABLE) from exc

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
            try:
                _require_root_prompt(root_prompt, root_prompt)
            except Exception as exc:
                raise ActiveLaunchSshTransportError(_UNAVAILABLE) from exc
            return process, root_prompt, deadline
        except (CliTransportError, asyncssh.Error, OSError, TimeoutError) as exc:
            raise ActiveLaunchSshTransportError(_UNAVAILABLE) from exc


def _listing_from_output(output: bytes) -> ActiveLaunchListing:
    normalized = _normalized(output)
    if _contains_failure_marker(normalized):
        raise ActiveLaunchSshTransportError(_UNAVAILABLE)
    if _only_command_echo_and_prompt(normalized):
        return ActiveLaunchListing(recognized=True, token_ids=())
    unknown = ActiveLaunchListing(recognized=False, token_ids=())
    lines = [line.strip() for line in normalized.splitlines() if line.strip()]
    if not lines:
        return unknown
    echoed = lines[0] == ACTIVE_LAUNCH_LIST_COMMAND.encode("ascii")
    prompted = _PROMPT_LINE.fullmatch(lines[-1]) is not None
    body = lines[int(echoed):len(lines) - int(prompted)]
    legacy = [_TOKEN_ID.fullmatch(line) for line in body]
    record_identities: tuple[tuple[str, str], ...] = ()
    if body and all(match is not None for match in legacy):
        token_ids = tuple(match.group(1).decode("ascii") for match in legacy if match is not None)
    else:
        # Build29 native IDs are meaningful only inside complete four-line
        # records and a completed command response. Never extract arbitrary id=.
        if not echoed or not prompted or not body or len(body) % 4:
            return unknown
        native_ids: list[str] = []
        identities: list[tuple[str, str]] = []
        for offset in range(0, len(body), 4):
            endpoint = _NATIVE_ENDPOINT.fullmatch(body[offset])
            identifier = _NATIVE_ID.fullmatch(body[offset + 1])
            if (endpoint is None or identifier is None
                    or _NATIVE_ACCOUNT.fullmatch(body[offset + 2]) is None
                    or _NATIVE_GATEWAY.fullmatch(body[offset + 3]) is None):
                return unknown
            if (any(int(part) > 255 for part in endpoint.group(1).split(b'.'))
                    or int(endpoint.group(2)) > 65535 or not 1 <= int(endpoint.group(4)) <= 65535
                    or any(not label or len(label) > 63 or label.startswith(b'-') or label.endswith(b'-')
                           for label in endpoint.group(3).rstrip(b'.').split(b'.'))):
                return unknown
            token = identifier.group(1).decode("ascii")
            native_ids.append(token)
            identities.append((token, hashlib.sha256(b'fortipam-build29-active-launch-record/v1\0'
                + b'\n'.join(body[offset:offset + 4])).hexdigest()))
        token_ids = tuple(native_ids)
        record_identities = tuple(identities)
    if len(set(token_ids)) != len(token_ids):
        return unknown
    return ActiveLaunchListing(recognized=True, token_ids=token_ids, record_identities=record_identities)


def _clear_command(token_id: str) -> str:
    return f"{ACTIVE_LAUNCH_CLEAR_COMMAND} {_token_id(token_id)}"


def _token_id(value: str) -> str:
    if not isinstance(value, str) or _SAFE_TOKEN.fullmatch(value) is None:
        raise ActiveLaunchSshTransportError(_UNAVAILABLE)
    return value


def _only_command_echo_and_prompt(output: bytes) -> bool:
    residual = [line.strip() for line in output.splitlines() if line.strip()]
    return (len(residual) == 2 and residual[0] == ACTIVE_LAUNCH_LIST_COMMAND.encode("ascii")
        and _PROMPT_LINE.fullmatch(residual[1]) is not None)


def _normalized(output: bytes) -> bytes:
    if len(output) > _MAX_OUTPUT_BYTES:
        raise ActiveLaunchSshTransportError(_UNAVAILABLE)
    return output.replace(b"\r", b"")


def _contains_failure_marker(output: bytes) -> bool:
    lowered = output.lower()
    return any(
        marker in lowered
        for marker in (
            b"permission denied",
            b"not permitted",
            b"not allowed",
            b"access denied",
            b"command fail",
            b"unknown action",
            b"unknown command",
            b"parse error",
        )
    )


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
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        raise ActiveLaunchSshTransportConfigurationError(
            f"The active-launch {label} file is unavailable."
        ) from exc
    if not path.is_file() or mode & 0o077:
        raise ActiveLaunchSshTransportConfigurationError(
            f"The active-launch {label} file must be a private regular file."
        )


def _read_password_file(path: Path) -> str:
    _private_regular_file(path, "password")
    try:
        password = path.read_text(encoding="utf-8").rstrip("\r\n")
    except OSError as exc:
        raise ActiveLaunchSshTransportConfigurationError(
            "The active-launch password file is unreadable."
        ) from exc
    if not password:
        raise ActiveLaunchSshTransportConfigurationError(
            "The active-launch password file is empty."
        )
    return password


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    return value if value is not None and value != "" else None


def _run_sync(coroutine: Coroutine[Any, Any, Any]) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    coroutine.close()
    raise ActiveLaunchSshTransportError(_UNAVAILABLE)
