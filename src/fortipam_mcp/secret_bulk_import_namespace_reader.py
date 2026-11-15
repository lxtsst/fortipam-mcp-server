"""Private global-name observation; trusted composition qualifies Owner/API source.

Names and multiplicity stay private. This reader does not qualify caller-created
API metadata, the SSH actor's role, association eligibility or import authority.
"""
from __future__ import annotations

import asyncio
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import math
import re
from threading import RLock
import time
import unicodedata

from v4_planning.material_provider import _OpaqueC3Object
from . import secret_bulk_import_metadata as m
from . import target_qualified_reference_reader as r
from .cli_safety import _complete_pre_login
from .target_reference_ssh_transport import FortiPamTargetReferenceSshTransport
from .target_ssh_transport import TargetSshTransportConfig, _send_and_read, _send_and_read_dynamic_prompt

_NAMES = 'show full-configuration | grep "^        set name "'
_FOLDERS = 'show full-configuration | grep "^        set folder "'
_ERROR = 'Protected Secret import namespace unavailable.'


class BulkImportNamespaceError(ValueError):
    """No private metadata or raw CLI in failures."""


def _name(value: object) -> str:
    if (type(value) is not str or not 0 < len(value.encode('utf-8')) <= 255
            or any(ch in '\\"' or unicodedata.category(ch).startswith('C') for ch in value)):
        raise ValueError
    return value


def _witnesses(view: m.NativeImportMetadataCollection, serial: str) -> tuple[str, ...]:
    if (type(view) is not m.NativeImportMetadataCollection or view.table != 'database'
            or view.serial_digest != serial or type(view.rows) is not tuple
            or not 2 <= len(view.rows) <= 4096 or type(view.size) is not int
            or not len(view.rows) <= view.size <= 4096
            or type(view.filtered_count) is not int or view.filtered_count != len(view.rows)):
        raise ValueError
    names, identifiers = [], set()
    for row in view.rows:
        if type(row) is not m.ImportMetadataSecret:
            raise ValueError
        m._integer(row.identifier)
        if row.identifier in identifiers:
            raise ValueError
        identifiers.add(row.identifier)
        names.append(_name(row.name))
    if len(set(names)) < 2:
        raise ValueError
    return tuple(names)


def _project(first: bytes, second: bytes, folders: bytes, prompt: bytes,
             view: m.NativeImportMetadataCollection, serial: str) -> tuple[str, ...]:
    witnesses = Counter(_witnesses(view, serial))
    if first != second:
        raise ValueError
    names: list[str] = []
    for line in r._lines(first, _NAMES, prompt):
        match = re.fullmatch(rb'        set name "([^"\\\r\n]+)"', line)
        if match is None or len(names) >= 4096:
            raise ValueError
        names.append(_name(match[1].decode('utf-8')))
    folder_lines = r._lines(folders, _FOLDERS, prompt)
    if len(names) != view.size or len(folder_lines) != len(names):
        raise ValueError
    for line in folder_lines:
        match = re.fullmatch(rb'        set folder (0|[1-9][0-9]{0,9})', line)
        if match is None or int(match[1]) > 2147483647:
            raise ValueError
    observed = Counter(names)
    if any(observed[name] < count for name, count in witnesses.items()):
        raise ValueError
    return tuple(sorted(names))


@dataclass(frozen=True, slots=True, repr=False)
class ImportSecretNamespaceObservation(_OpaqueC3Object):
    names: tuple[str, ...]
    api_view: m.NativeImportMetadataCollection
    observed_at: float
    expires_at: float


class SecretBulkImportNamespaceReader(_OpaqueC3Object):
    """Fixed repeated projection with count/witness checks; no caller CLI or grant."""

    def __init__(self, config: TargetSshTransportConfig, *, serial_digest: str,
                 clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(config) is not TargetSshTransportConfig or type(serial_digest) is not str
                    or m._DIGEST.fullmatch(serial_digest) is None or not callable(clock)):
                raise ValueError
            config.__post_init__()
            self._ssh = FortiPamTargetReferenceSshTransport(config)
            self._serial = serial_digest
            self._timeout = min(30.0, config.timeout_seconds)
            self._clock = clock
            self._lock = RLock()
            self._last: float | None = None
            self._closed = False
            self._failed = False
            self._current: ImportSecretNamespaceObservation | None = None
        except Exception:
            raise BulkImportNamespaceError(_ERROR) from None

    def _now(self) -> float:
        try:
            value = self._clock()
            if (type(value) not in (int, float) or not math.isfinite(value) or value < 0
                    or self._closed or self._failed or self._last is not None and value < self._last):
                raise ValueError
            self._last = float(value)
            return float(value)
        except Exception:
            self._failed = True
            raise ValueError from None

    def read_namespace(self, api_view: m.NativeImportMetadataCollection) -> ImportSecretNamespaceObservation:
        with self._lock:
            self._current = None
            try:
                _witnesses(api_view, self._serial)
                started = self._now()
                expires = started + self._timeout
                names = asyncio.run(self._read(api_view))
                if not started <= self._now() < expires:
                    raise ValueError
                result = ImportSecretNamespaceObservation(names, api_view, started, expires)
                self._current = result
                return result
            except Exception:
                raise BulkImportNamespaceError(_ERROR) from None

    def check_current(self, observation: ImportSecretNamespaceObservation,
                      *, api_view: m.NativeImportMetadataCollection) -> None:
        with self._lock:
            try:
                _witnesses(api_view, self._serial)
                if (type(observation) is not ImportSecretNamespaceObservation
                        or observation is not self._current or api_view != observation.api_view
                        or not observation.observed_at <= self._now() < observation.expires_at):
                    raise ValueError
            except Exception:
                raise BulkImportNamespaceError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._current = None

    async def _read(self, view: m.NativeImportMetadataCollection) -> tuple[str, ...]:
        async with asyncio.timeout(self._timeout):
            deadline = time.monotonic() + self._timeout
            connection = await self._ssh._connection()
            try:
                process = await connection.create_process(term_type='vt100', term_size=(200, 24), encoding=None)
                try:
                    root = await _complete_pre_login(process.stdout, process.stdin, deadline, r._LIMIT,
                                                    accept_pre_login_banner=False)
                    if re.fullmatch(rb'[A-Za-z0-9._-]{1,63} #', root) is None:
                        raise ValueError
                    async def identity() -> None:
                        raw = await _send_and_read(process, r._SERIAL, root, deadline)
                        lines = r._lines(raw, r._SERIAL, root)
                        if len(lines) != 1:
                            raise ValueError
                        match = re.fullmatch(rb'Serial-Number: ([A-Za-z0-9_-]{1,128})', lines[0])
                        if match is None or hashlib.sha256(match[1]).hexdigest() != self._serial:
                            raise ValueError
                        r._version(r._lines(await _send_and_read(process, r._VERSION, root, deadline), r._VERSION, root))
                    await identity()
                    context = await _send_and_read_dynamic_prompt(process, 'config secret database', root, deadline)
                    if context != root[:-2] + b' (database) #':
                        raise ValueError
                    first = await _send_and_read(process, _NAMES, context, deadline)
                    folders = await _send_and_read(process, _FOLDERS, context, deadline)
                    second = await _send_and_read(process, _NAMES, context, deadline)
                    names = _project(first, second, folders, context, view, self._serial)
                    if await _send_and_read_dynamic_prompt(process, 'end', root, deadline) != root:
                        raise ValueError
                    await identity()
                    return names
                finally:
                    process.close()
                    async with asyncio.timeout(1):
                        await process.wait_closed()
            finally:
                connection.abort()
