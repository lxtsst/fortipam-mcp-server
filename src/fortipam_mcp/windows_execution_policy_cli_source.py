"""Fixed same-device Policy namespace/reference source, without write authority.

The trusted composition must supply fresh API names/counts from the same device
and bracket the SSH Owner's native global role. These caller values alone are
not provenance, permissions, original ownership or a deletion authorization.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
import re
from threading import RLock
import time

from v4_planning.material_provider import _OpaqueC3Object

from .cli_safety import _complete_pre_login
from .target_preservation_contract import _digest
from .target_qualified_reference_reader import _SERIAL, _VERSION, _LIMIT, _lines, _version
from .target_reference_ssh_transport import FortiPamTargetReferenceSshTransport
from .target_ssh_transport import TargetSshTransportConfig, _send_and_read, _send_and_read_dynamic_prompt
from .windows_execution_policy_contract import WindowsExecutionPolicyRequest

_CONTRACT = "fortipam-build29-windows-policy-cli-source-v1"
_NAMES = 'show full-configuration | grep "^    edit "'
_REFERENCE = 'diagnose sys cmdb refcnt show secret.policy.name '
_SAFE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
_ERROR = 'The private Windows Policy CLI source is unavailable.'
ZERO_PROFILE = 'create-zero-v1'
FOLDER_LINK_PROFILE = 'owned-folder-zero-or-one-v1'


class WindowsPolicyCliSourceError(ValueError):
    """No private names, credentials or raw CLI output in failures."""


def _names(values: tuple[str, ...]) -> tuple[str, ...]:
    if (type(values) is not tuple or not 1 <= len(values) <= 128
            or any(type(value) is not str or not 0 < len(value.encode()) <= 255
                or any(ord(ch) < 32 or ord(ch) == 127 or ch in '\\"' for ch in value) for value in values)
            or len({value.casefold() for value in values}) != len(values)):
        raise ValueError
    return tuple(sorted(values))


@dataclass(frozen=True, slots=True, repr=False)
class WindowsPolicyCliObservation(_OpaqueC3Object):
    source_context_digest: str
    request_digest: str
    witness_digest: str
    namespace_digest: str
    global_count: int
    candidate_absent: bool
    candidate_reference_count: int | None
    control_reference_count: int
    command_count: int
    observed_at: float
    expires_at: float


class WindowsPolicyCliSource(_OpaqueC3Object):
    """Two namespace reads and a nonzero reference control; no arbitrary command."""

    def __init__(self, config: TargetSshTransportConfig, *, request: WindowsExecutionPolicyRequest,
            control_policy_name: str, clock: Callable[[], float] = time.monotonic,
            reference_profile: str = ZERO_PROFILE) -> None:
        try:
            if (type(config) is not TargetSshTransportConfig or type(request) is not WindowsExecutionPolicyRequest
                    or type(control_policy_name) is not str or _SAFE.fullmatch(control_policy_name) is None
                    or control_policy_name == request.binding.name or not callable(clock)
                    or type(reference_profile) is not str or reference_profile not in (ZERO_PROFILE, FOLDER_LINK_PROFILE)):
                raise ValueError
            config.__post_init__()
            request.validate()
            self._config, self._request, self._control = config, request, control_policy_name
            self._reference_profile = reference_profile
            self._source = self._context()
            self._ssh = FortiPamTargetReferenceSshTransport(config)
            self._clock, self._last = clock, -1.0
            self._closed = self._failed = False
            self._current: WindowsPolicyCliObservation | None = None
            self._lock = RLock()
        except Exception:
            raise WindowsPolicyCliSourceError(_ERROR) from None

    def _context(self) -> str:
        self._config.__post_init__()
        self._request.validate()
        value = self._config
        parts = (_CONTRACT, self._request.request_digest, self._control, value.host,
            value.port, value.username, hashlib.sha256(value.password.encode()).hexdigest(),
            hashlib.sha256(Path(value.known_hosts_file).read_bytes()).hexdigest(), value.timeout_seconds)
        if self._reference_profile == ZERO_PROFILE:
            return _digest(parts)
        if self._reference_profile == FOLDER_LINK_PROFILE:
            return _digest((*parts, FOLDER_LINK_PROFILE))
        raise ValueError

    def _now(self) -> float:
        try:
            value = self._clock()
            if (self._closed or self._failed or type(value) not in (int, float) or not math.isfinite(value)
                    or value < 0 or value < self._last or self._context() != self._source):
                raise ValueError
            self._last = float(value)
            return float(value)
        except Exception:
            self._failed = True
            raise ValueError from None

    def observe(self, *, api_names: tuple[str, ...], control_reference_count: int,
            candidate_reference_count: int | None,
            before_send: Callable[[], None]) -> WindowsPolicyCliObservation:
        """Bind original API witnesses; the consuming reader must prove their source."""
        with self._lock:
            self._current = None
            try:
                names = _names(api_names)
                candidate = self._request.binding.name
                if (not callable(before_send) or self._control not in names
                        or type(control_reference_count) is not int or not 0 < control_reference_count <= 128
                        or (candidate not in names and candidate_reference_count is not None)
                        or (candidate in names and (type(candidate_reference_count) is not int
                            or candidate_reference_count not in
                                ((0, 1) if self._reference_profile == FOLDER_LINK_PROFILE else (0,))))):
                    raise ValueError
                started = self._now()
                expires = started + min(30.0, self._config.timeout_seconds)
                def guard() -> None:
                    if self._now() >= expires:
                        raise ValueError
                    before_send()
                    if self._now() >= expires:
                        raise ValueError
                actual, count, commands = asyncio.run(self._read(names, control_reference_count, candidate_reference_count, guard))
                guard()
                result = WindowsPolicyCliObservation(self._source, self._request.request_digest,
                    _digest((names, self._control, control_reference_count, candidate_reference_count)),
                    _digest(actual), len(actual), candidate not in actual, count, control_reference_count, commands,
                    started, expires)
                self._current = result
                return result
            except Exception:
                self._failed = True
                raise WindowsPolicyCliSourceError(_ERROR) from None

    def check_current(self, observation: WindowsPolicyCliObservation, *, api_names: tuple[str, ...],
            control_reference_count: int, candidate_reference_count: int | None) -> None:
        try:
            with self._lock:
                if (type(observation) is not WindowsPolicyCliObservation or observation is not self._current
                        or not observation.observed_at <= self._now() < observation.expires_at
                        or observation.source_context_digest != self._source
                        or observation.request_digest != self._request.request_digest
                        or observation.witness_digest != _digest((_names(api_names), self._control,
                            control_reference_count, candidate_reference_count))):
                    raise ValueError
        except Exception:
            raise WindowsPolicyCliSourceError(_ERROR) from None

    async def _read(self, names: tuple[str, ...], control: int, candidate_count: int | None,
            guard: Callable[[], None]) -> tuple[tuple[str, ...], int | None, int]:
        async with asyncio.timeout(self._config.timeout_seconds):
            maximum_commands = 11 if candidate_count is None else 12
            deadline = time.monotonic() + min(30.0, self._config.timeout_seconds)
            guard()
            connection = await self._ssh._connection()
            try:
                guard()
                process = await connection.create_process(term_type='vt100', term_size=(200, 24), encoding=None)
                try:
                    root = await _complete_pre_login(process.stdout, process.stdin, deadline, _LIMIT,
                        accept_pre_login_banner=False)
                    if re.fullmatch(rb'[A-Za-z0-9._-]{1,63} #', root) is None:
                        raise ValueError
                    commands = 0
                    async def send(command: str, prompt: bytes) -> tuple[bytes, ...]:
                        nonlocal commands
                        guard(); commands += 1
                        if commands > maximum_commands:
                            raise ValueError
                        raw = await _send_and_read(process, command, prompt, deadline)
                        guard()
                        return _lines(raw, command, prompt)
                    async def identity() -> None:
                        rows = await send(_SERIAL, root)
                        match = re.fullmatch(rb'Serial-Number: ([A-Za-z0-9_-]{1,128})', rows[0]) if len(rows) == 1 else None
                        if match is None or hashlib.sha256(match[1]).hexdigest() != self._request.binding.serial_digest:
                            raise ValueError
                        _version(await send(_VERSION, root))
                    async def namespace() -> tuple[str, ...]:
                        nonlocal commands
                        guard(); commands += 1
                        if commands > maximum_commands:
                            raise ValueError
                        prompt = await _send_and_read_dynamic_prompt(process, 'config secret policy', root, deadline)
                        guard()
                        if prompt != root[:-2] + b' (policy) #':
                            raise ValueError
                        selected = []
                        for line in await send(_NAMES, prompt):
                            match = re.fullmatch(rb'    edit "([^"\\\r\n]+)"', line)
                            if match is None:
                                raise ValueError
                            selected.append(match[1].decode())
                        selected_names = _names(tuple(selected))
                        guard(); commands += 1
                        if commands > maximum_commands:
                            raise ValueError
                        returned = await _send_and_read_dynamic_prompt(process, 'end', root, deadline)
                        guard()
                        if returned != root:
                            raise ValueError
                        return selected_names
                    async def references(name: str) -> int:
                        rows = await send(_REFERENCE + '"' + name + '"', root)
                        if (len(rows) > 128 or any(b'entry used by' not in line.lower()
                                or any(marker in line.lower() for marker in (b'--more--', b'truncated', b'maximum output'))
                                for line in rows)):
                            raise ValueError
                        return len(rows)
                    await identity()
                    first = await namespace()
                    if first != names or await references(self._control) != control:
                        raise ValueError
                    count = None
                    if candidate_count is not None:
                        count = await references(self._request.binding.name)
                        if count != candidate_count:
                            raise ValueError
                    if await namespace() != first:
                        raise ValueError
                    await identity()
                    if commands != maximum_commands:
                        raise ValueError
                    return first, count, commands
                finally:
                    process.close()
                    async with asyncio.timeout(1):
                        await process.wait_closed()
            finally:
                connection.abort()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._current = None
