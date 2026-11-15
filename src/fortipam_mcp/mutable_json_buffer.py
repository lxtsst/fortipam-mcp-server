"""Private mutable assembly; erase owned allocations before replacing them.

This buffer has no material resolution, authorization or dispatch capability.
The caller owns and must erase the exact bytearray returned by finish().
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from types import TracebackType

_BYTEARRAY_TYPE = bytearray
_ZERO_BLOCK = b"\0" * 4096


def _wipe(storage: bytearray) -> None:
    try:
        with memoryview(storage) as target:
            offset = 0
            while offset < len(target):
                size = min(len(_ZERO_BLOCK), len(target) - offset)
                target[offset:offset + size] = _ZERO_BLOCK[:size]
                offset += size
    except BaseException:
        for index in range(len(storage)):
            storage[index] = 0
        raise


def _erase_transfer_storage(storage: bytearray) -> None:
    try:
        _wipe(storage)
    except BaseException:
        for index in range(len(storage)):
            storage[index] = 0
        raise


def _clear_mutable_group(values: Iterable[object], clear: Callable[[bytearray], None]) -> None:
    """Attempt every exact owned bytearray, then propagate the first failure.

    Callers keep their existing eraser/clear semantics. No input is resolved,
    copied, decoded or hashed; non-bytearray entries are not owned here.
    """
    failure: BaseException | None = None
    for value in values:
        if type(value) is not _BYTEARRAY_TYPE:
            continue
        try:
            clear(value)
        except BaseException as error:
            if failure is None:
                failure = error
    if failure is not None:
        raise failure


def _take_mutable_prefix(storage: bytearray, length: int) -> bytearray:
    """Transfer an exact prefix, erasing the original allocation before release.

    Shrinking a populated bytearray may free an uncleared allocation. Copies
    here use a destination view, avoiding bytearray slice-assignment temporaries.
    The caller owns the returned array; failed transfers erase both allocations.
    """
    result: bytearray | None = None
    try:
        try:
            if (type(storage) is not _BYTEARRAY_TYPE or type(length) is not int
                    or not 0 <= length <= len(storage)):
                raise ValueError("The private mutable prefix is unavailable.")
            result = bytearray(length)
            with memoryview(storage) as source, memoryview(result) as destination:
                destination[:] = source[:length]
        finally:
            if type(storage) is _BYTEARRAY_TYPE:
                _erase_transfer_storage(storage)
    except BaseException:
        try:
            if result is not None:
                _erase_transfer_storage(result)
        finally:
            if type(storage) is _BYTEARRAY_TYPE:
                _erase_transfer_storage(storage)
        raise
    if result is None:
        raise ValueError("The private mutable prefix is unavailable.")
    return result


class _MutableJSONBuffer:
    """Append without resizing an allocation that may already contain C3."""

    __slots__ = ("_storage", "_size", "_closed")

    def __init__(self) -> None:
        self._storage = bytearray()
        self._size = 0
        self._closed = False

    def __enter__(self) -> _MutableJSONBuffer:
        if self._closed:
            raise ValueError("The private buffer is closed.")
        return self

    def __exit__(self, exc_type: type[BaseException] | None,
                 exc: BaseException | None, traceback: TracebackType | None) -> None:
        self.close()

    def _reserve(self, additional: int) -> None:
        if self._closed:
            raise ValueError("The private buffer is closed.")
        required = self._size + additional
        if required <= len(self._storage):
            return
        replacement = bytearray(max(required, 64, 2 * len(self._storage)))
        try:
            with memoryview(self._storage) as source, memoryview(replacement) as destination:
                destination[:self._size] = source[:self._size]
            _wipe(self._storage)
            self._storage = replacement
        except BaseException:
            try:
                _wipe(replacement)
            finally:
                self.close()
            raise

    def append(self, value: int) -> None:
        if type(value) is not int or not 0 <= value <= 255:
            raise ValueError("The private buffer requires a byte.")
        self._reserve(1)
        self._storage[self._size] = value
        self._size += 1

    def extend(self, value: bytes | bytearray | memoryview) -> None:
        with memoryview(value) as source:
            if source.ndim != 1 or source.format != "B" or not source.c_contiguous:
                raise ValueError("The private buffer requires contiguous bytes.")
            count = len(source)
            self._reserve(count)
            with memoryview(self._storage) as destination:
                destination[self._size:self._size + count] = source
            self._size += count

    def finish(self) -> bytearray:
        if self._closed:
            raise ValueError("The private buffer is closed.")
        result = bytearray(self._size)
        try:
            with memoryview(self._storage) as source, memoryview(result) as destination:
                destination[:] = source[:self._size]
            self.close()
            return result
        except BaseException:
            try:
                _wipe(result)
            finally:
                self.close()
            raise

    def close(self) -> None:
        self._closed = True
        _wipe(self._storage)
        self._size = 0
