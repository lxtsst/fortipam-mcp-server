"""Private Target operation records shared by the fixed lifecycle adapters."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
from typing import Any

from .secret_metadata_http_transport import _zeroize_mutable
from v4_planning.material_provider import _OpaqueC3Object

_RECORD_LIMIT = 16384


class _TargetOperationRecords(_OpaqueC3Object):
    __slots__ = ()
    _directory: Path
    _identity: tuple[int, int]
    _namespace: str
    _clock: Callable[[], int]
    _last_clock: int | None
    _clock_failed: bool

    def _now(self) -> int:
        try:
            value = self._clock()
            if type(value) is not int or value < 0 or self._clock_failed or self._last_clock is not None and value < self._last_clock:
                raise ValueError
            object.__setattr__(self, '_last_clock', value)
            return value
        except Exception:
            object.__setattr__(self, '_clock_failed', True)
            raise ValueError from None

    @contextmanager
    def _lock(self) -> Iterator[int]:
        directory = descriptor = None
        try:
            directory = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            info = os.fstat(directory)
            if ((info.st_dev, info.st_ino) != self._identity or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
            descriptor = os.open('operation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 0o600, dir_fd=directory)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size:
                raise ValueError
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            current = os.stat('operation.lock', dir_fd=directory, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError
            yield directory
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if directory is not None:
                os.close(directory)

    def _write(self, directory: int, name: str, value: object) -> None:
        raw = bytearray(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
        try:
            if not 0 < len(raw) <= _RECORD_LIMIT:
                raise ValueError
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            os.fsync(directory)
        finally:
            _zeroize_mutable(raw)

    def _read(self, directory: int, name: str) -> dict[str, Any]:
        raw = bytearray()
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= _RECORD_LIMIT:
                raise ValueError
            with os.fdopen(descriptor, 'rb', closefd=False) as stream:
                raw = bytearray(stream.read(_RECORD_LIMIT + 1))
            if len(raw) != info.st_size:
                raise ValueError
            def members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
                result: dict[str, Any] = {}
                for key, item in pairs:
                    if key in result:
                        raise ValueError
                    result[key] = item
                return result
            value = json.loads(raw, object_pairs_hook=members)
            if type(value) is not dict or value.get('namespace') != self._namespace:
                raise ValueError
            return value
        finally:
            os.close(descriptor); _zeroize_mutable(raw)
