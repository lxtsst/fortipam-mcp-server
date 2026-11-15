"""Inactive, private bulk-import file decoder; no provider or MCP registration.

Paths and file digests are prebound inside a trusted material boundary, never
MCP/plan inputs. The decoder consumes the supplied mutable workbook password.
Decoded rows remain opaque and expire after 60 seconds. This helper neither
authorizes use nor qualifies device dependencies, field semantics, or writes.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
from pathlib import Path
import re
import selectors
import stat
import struct
import subprocess
import sys
import threading
import time
from typing import Callable, TypeVar

from v4_planning.material_provider import _OpaqueC3Object

from .mutable_json_buffer import _take_mutable_prefix
from . import _secret_bulk_import_worker as worker

_ERROR = "Protected bulk-import file unavailable."
_TIMEOUT_SECONDS = 30.0
_PARSER_CONTRACT = "native-bulk-import-file-v1"
_T = TypeVar("_T")
_Rows = tuple[tuple[memoryview, ...], ...]
_SourceIdentity = tuple[int, ...]


class BulkImportFileError(ValueError):
    """A fixed, non-disclosing file-boundary failure."""


class _ParserLifetime:
    """Private narrowing of the existing parser budget; never authorization."""

    def __init__(self, deadline: float, cancelled: threading.Event) -> None:
        if not math.isfinite(deadline) or not isinstance(cancelled, threading.Event):
            raise ValueError
        self.deadline, self.cancelled = deadline, cancelled

    def check(self) -> None:
        if self.cancelled.is_set() or time.monotonic() >= self.deadline:
            raise ValueError


def _wipe(raw: bytearray) -> None:
    raw[:] = b"\x00" * len(raw)


def _source_identity(parent: os.stat_result, file: os.stat_result) -> _SourceIdentity:
    return (parent.st_dev, parent.st_ino, parent.st_uid, parent.st_mode,
            file.st_dev, file.st_ino, file.st_uid, file.st_mode, file.st_nlink,
            file.st_size, file.st_mtime_ns, file.st_ctime_ns)


def _read_owned(
    path: Path, expected_identity: _SourceIdentity | None = None,
) -> tuple[bytearray, _SourceIdentity]:
    parent = descriptor = None
    raw = bytearray(worker.MAX_FILE_BYTES + 1)
    okay = False
    try:
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError
        parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        for part in path.parent.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            previous, parent = parent, child
            os.close(previous)
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=parent)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 0 < before.st_size <= worker.MAX_FILE_BYTES):
            raise ValueError
        identity = _source_identity(info, before)
        if expected_identity is not None and identity != expected_identity:
            raise ValueError
        count = 0
        while count < len(raw):
            with memoryview(raw)[count:] as view:
                received = os.readv(descriptor, [view])
            if not received:
                break
            count += received
        after = os.fstat(descriptor)
        if (count != before.st_size
                or identity != _source_identity(os.fstat(parent), after)):
            raise ValueError
        raw = _take_mutable_prefix(raw, count)
        okay = True
        return raw, identity
    finally:
        try:
            try:
                if descriptor is not None:
                    os.close(descriptor)
            finally:
                if parent is not None:
                    os.close(parent)
        except BaseException:
            okay = False
            raise
        finally:
            if not okay:
                _wipe(raw)


def _run_parser(raw: bytearray, password: bytearray, kind: int, *,
                lifetime: _ParserLifetime | None = None) -> bytearray:
    result = bytearray(worker.MAX_FRAME_BYTES + 1)
    process: subprocess.Popen[bytes] | None = None
    views: list[memoryview] = []
    okay = False
    try:
        if lifetime is not None:
            lifetime.check()
        header = struct.pack("!8sBHI", worker.INPUT_MAGIC, kind, len(password), len(raw))
        views = [memoryview(header), memoryview(password), memoryview(raw)]
        process = subprocess.Popen(
            [sys.executable, "-I", "-B", str(Path(worker.__file__).resolve())],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={}, cwd="/", close_fds=True, bufsize=0,
        )
        if process.stdin is None or process.stdout is None:
            raise ValueError
        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        deadline, part, sent, count = time.monotonic() + _TIMEOUT_SECONDS, 0, 0, 0
        if lifetime is not None:
            deadline = min(deadline, lifetime.deadline)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdin, selectors.EVENT_WRITE)
            selector.register(process.stdout, selectors.EVENT_READ)
            finished = False
            while not finished:
                if lifetime is not None:
                    lifetime.check()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError
                ready = selector.select(min(remaining, 0.05) if lifetime is not None else remaining)
                if not ready:
                    if lifetime is None:
                        raise ValueError
                    continue
                for key, _ in ready:
                    if key.fileobj is process.stdin:
                        while part < len(views) and sent == len(views[part]):
                            part, sent = part + 1, 0
                        if part == len(views):
                            selector.unregister(process.stdin)
                            process.stdin.close()
                        else:
                            with views[part][sent:sent + 65536] as view:
                                sent += os.write(process.stdin.fileno(), view)
                    else:
                        with memoryview(result)[count:] as view:
                            received = os.readv(process.stdout.fileno(), [view])
                        if not received:
                            finished = True
                            break
                        count += received
                        if count > worker.MAX_FRAME_BYTES:
                            raise ValueError
        while lifetime is not None and process.poll() is None:
            lifetime.check()
            if time.monotonic() >= deadline:
                raise ValueError
            try:
                process.wait(timeout=min(0.05, max(0.001, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                pass
        if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0 or count < 10:
            raise ValueError
        if lifetime is not None:
            lifetime.check()
        del result[count:]
        okay = True
        return result
    finally:
        for view in views:
            view.release()
        try:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
        except BaseException:
            okay = False
            raise
        finally:
            try:
                if process is not None:
                    try:
                        if process.stdin is not None:
                            process.stdin.close()
                    finally:
                        if process.stdout is not None:
                            process.stdout.close()
            except BaseException:
                okay = False
                raise
            finally:
                if not okay:
                    _wipe(result)


class ProtectedBulkImportRows(_OpaqueC3Object):
    """Owned mutable row frame; trusted private consumers only, once, within TTL."""

    __slots__ = ("__raw", "__spans", "__expires", "__used", "__lock", "__file_sha256")
    _display_name = "ProtectedBulkImportRows"

    def __init__(self, raw: bytearray, expires: float, *, file_sha256: str | None = None) -> None:
        self.__raw, self.__expires, self.__used = raw, expires, False
        self.__file_sha256 = file_sha256
        self.__spans: list[list[tuple[int, int]]] = []
        self.__lock = threading.RLock()
        try:
            if raw[:8] != worker.OUTPUT_MAGIC:
                raise ValueError
            count = struct.unpack_from("!H", raw, 8)[0]
            if not 1 <= count <= worker.MAX_ROWS:
                raise ValueError
            offset = 10
            for _ in range(count):
                row = []
                for _ in worker.HEADERS:
                    size = struct.unpack_from("!I", raw, offset)[0]
                    offset += 4
                    if size > worker.MAX_CELL_BYTES or offset + size > len(raw):
                        raise ValueError
                    row.append((offset, offset + size))
                    offset += size
                self.__spans.append(row)
            if offset != len(raw):
                raise ValueError
        except BaseException:
            self.clear()
            raise BulkImportFileError(_ERROR) from None

    def clear(self) -> None:
        with self.__lock:
            self._clear_unlocked()

    def _clear_unlocked(self) -> None:
        self.__used = True
        _wipe(self.__raw)
        self.__spans.clear()

    def __enter__(self) -> ProtectedBulkImportRows:
        return self

    def __exit__(self, *_: object) -> None:
        self.clear()

    def __del__(self) -> None:
        self.clear()

    def _consume_once(self, consumer: Callable[[_Rows], _T], *,
                      expected_sha256: str | None = None) -> _T:
        if not self.__lock.acquire(blocking=False):
            raise BulkImportFileError(_ERROR)
        if self.__used:
            self.__lock.release()
            raise BulkImportFileError(_ERROR)
        views: list[tuple[memoryview, ...]] = []
        try:
            if time.monotonic() >= self.__expires:
                raise ValueError
            if expected_sha256 is not None and (
                type(expected_sha256) is not str or self.__file_sha256 is None
                or not hmac.compare_digest(expected_sha256, self.__file_sha256)
            ):
                raise ValueError
            self.__used = True
            for row in self.__spans:
                views.append(tuple(memoryview(self.__raw)[start:end].toreadonly()
                                   for start, end in row))
            result = consumer(tuple(views))
            if not self.__spans or time.monotonic() >= self.__expires:
                raise ValueError
            return result
        except BaseException:
            raise BulkImportFileError(_ERROR) from None
        finally:
            for row_views in views:
                for view in row_views:
                    view.release()
            self._clear_unlocked()
            self.__lock.release()


def _decode_prebound_file(
    path: Path, *, expected_sha256: str, file_format: str,
    workbook_password: bytearray | None = None,
    expected_identity: _SourceIdentity | None = None,
    parser_contract: str = _PARSER_CONTRACT,
    lifetime: _ParserLifetime | None = None,
) -> ProtectedBulkImportRows:
    """Read a digest-bound owner-only file and consume/clear password on all exits.

    This is private intake infrastructure, not a preview API or material lease.
    It must not be connected to a planner or MCP without separately qualifying
    intake identity, provider purpose/audience, and independent M4 authority.
    """
    raw: bytearray | None = None
    frame: bytearray | None = None
    password = workbook_password if workbook_password is not None else bytearray()
    expires = time.monotonic() + 60
    try:
        if (type(password) is not bytearray or len(password) > worker.MAX_PASSWORD_BYTES
                or type(expected_sha256) is not str
                or re.fullmatch(r"[a-f0-9]{64}", expected_sha256) is None
                or file_format not in ("csv", "xlsm")
                or parser_contract != _PARSER_CONTRACT):
            raise ValueError
        if lifetime is not None:
            lifetime.check()
            expires = min(expires, lifetime.deadline)
        raw, _ = _read_owned(path, expected_identity)
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256):
            raise ValueError
        if lifetime is None:
            frame = _run_parser(raw, password, 1 if file_format == "csv" else 2)
        else:
            lifetime.check()
            frame = _run_parser(raw, password, 1 if file_format == "csv" else 2, lifetime=lifetime)
            lifetime.check()
        if time.monotonic() >= expires:
            raise ValueError
        rows = ProtectedBulkImportRows(frame, expires, file_sha256=expected_sha256)
        frame = None
        return rows
    except BaseException:
        raise BulkImportFileError(_ERROR) from None
    finally:
        if raw is not None:
            _wipe(raw)
        if frame is not None:
            _wipe(frame)
        if type(password) is bytearray:
            _wipe(password)


def decode_prebound_file(
    path: Path, *, expected_sha256: str, file_format: str,
    workbook_password: bytearray | None = None,
) -> ProtectedBulkImportRows:
    """Decode one digest-bound file; this does not pin identity across calls."""
    return _decode_prebound_file(
        path, expected_sha256=expected_sha256, file_format=file_format,
        workbook_password=workbook_password,
    )


class PinnedBulkImportFile(_OpaqueC3Object):
    """Private source consistency evidence, not an intake authorization or lease.

    Pinning reads and clears bounded original bytes without decoding them or
    retaining a password. Each decode opens the same prebound path and compares
    identity on that descriptor before reading. No lifetime, child claim, replay
    grant or provider registration is supplied by this object.
    """

    __slots__ = ("__path", "__digest", "__format", "__identity", "__parser_contract")
    _display_name = "PinnedBulkImportFile"

    def __init__(self, path: Path, *, expected_sha256: str, file_format: str) -> None:
        raw: bytearray | None = None
        try:
            if (type(expected_sha256) is not str
                    or re.fullmatch(r"[a-f0-9]{64}", expected_sha256) is None
                    or file_format not in ("csv", "xlsm")):
                raise ValueError
            raw, identity = _read_owned(path)
            if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256):
                raise ValueError
            self.__path, self.__digest, self.__format = path, expected_sha256, file_format
            self.__identity, self.__parser_contract = identity, _PARSER_CONTRACT
        except BaseException:
            raise BulkImportFileError(_ERROR) from None
        finally:
            if raw is not None:
                _wipe(raw)

    def decode(self, *, workbook_password: bytearray | None = None,
               _lifetime: _ParserLifetime | None = None) -> ProtectedBulkImportRows:
        """Decode afresh; the caller must separately authorize each material use."""
        return _decode_prebound_file(
            self.__path, expected_sha256=self.__digest, file_format=self.__format,
            workbook_password=workbook_password, expected_identity=self.__identity,
            parser_contract=self.__parser_contract,
            lifetime=_lifetime,
        )
