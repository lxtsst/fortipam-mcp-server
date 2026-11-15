"""Private one-use backup password and artifact custody; no MCP material surface."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
from threading import RLock
import time

from v4_planning.material_provider import (
    C3MaterialBinding, MaterialAccessDenied, MaterialBindingStatus, MaterialLease,
    MaterialLeaseCompletion, MaterialRevocationReason, _OpaqueC3Object,
)
from v4_planning.models import require_digest
from .ldap_server_runtime import _private_directory, _read
from .mutable_json_buffer import _erase_transfer_storage

CONTRACT = "fortipam-build29-encrypted-backup-custody-v1"
MAX_BACKUP_BYTES = 16 * 1024 * 1024
_ERROR = "The private backup custody is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class BackupLeaseRequest(_OpaqueC3Object):
    """Action-specific control context; never relabel a local sink as a vault."""
    plan_digest: str
    policy_digest: str
    authorization_digest: str
    scope_digest: str
    audience_digest: str
    requested_at: int
    expires_at: int

    def __post_init__(self) -> None:
        for value in (self.plan_digest, self.policy_digest, self.authorization_digest,
                      self.scope_digest, self.audience_digest):
            require_digest(value, "backup_context")
        if (type(self.requested_at) is not int or type(self.expires_at) is not int
                or not 0 <= self.requested_at < self.expires_at <= self.requested_at + 60):
            raise ValueError(_ERROR)


class BackupCustodyBinding(C3MaterialBinding):
    def __init__(self, directory: Path, *, scope_digest: str, audience_digest: str,
                 retain_until: int) -> None:
        _private_directory(directory)
        # Backup bytes and their password must never be persisted in a checkout.
        if any((parent / ".git").exists() for parent in (directory, *directory.parents)):
            raise ValueError(_ERROR)
        for value in (scope_digest, audience_digest):
            require_digest(value, "backup_binding")
        if type(retain_until) is not int or retain_until <= 0:
            raise ValueError(_ERROR)
        self._directory = directory
        info = directory.stat()
        self._inode = (info.st_dev, info.st_ino)
        self._scope, self._audience, self._retain_until = scope_digest, audience_digest, retain_until

    def _check(self) -> None:
        _private_directory(self._directory)
        info = self._directory.stat()
        if (info.st_dev, info.st_ino) != self._inode:
            raise ValueError(_ERROR)

    def _empty(self) -> None:
        self._check()
        if any(self._directory.iterdir()):
            raise ValueError(_ERROR)

    def _write(self, name: str, chunks: Iterable[bytes | bytearray | memoryview], *,
               limit: int, guard: Callable[[], None]) -> tuple[int, str]:
        self._check()
        parent = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if (os.fstat(parent).st_dev, os.fstat(parent).st_ino) != self._inode:
                raise ValueError(_ERROR)
            guard()
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            count, checksum = 0, hashlib.sha256()
            try:
                for chunk in chunks:
                    guard()
                    if not isinstance(chunk, (bytes, bytearray, memoryview)) or count + len(chunk) > limit:
                        raise ValueError(_ERROR)
                    view = memoryview(chunk)
                    try:
                        offset = 0
                        while offset < len(view):
                            written = os.write(descriptor, view[offset:])
                            if written <= 0:
                                raise ValueError(_ERROR)
                            offset += written
                        checksum.update(view)
                        count += len(view)
                    finally:
                        view.release()
                os.fsync(descriptor)
                info = os.fstat(descriptor)
                if (not count or info.st_size != count or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                    raise ValueError(_ERROR)
            finally:
                os.close(descriptor)
            os.fsync(parent)
            guard()
            return count, checksum.hexdigest()
        finally:
            os.close(parent)


class _BackupLease(MaterialLease):
    __slots__ = ()


class BackupArtifactCustody(_OpaqueC3Object):
    """Retain output for its owner; release/revoke clears RAM, never recovery data."""
    def __init__(self, binding: BackupCustodyBinding, request: BackupLeaseRequest, *,
                 guard: Callable[[], None], dispatch_guard: Callable[[], None],
                 clock: Callable[[], int] = lambda: int(time.time())) -> None:
        if type(binding) is not BackupCustodyBinding or type(request) is not BackupLeaseRequest:
            raise ValueError(_ERROR)
        self._binding, self._request, self._guard, self._clock = binding, request, guard, clock
        self._dispatch_guard = dispatch_guard
        self._lock = RLock()
        self._attempted = self._consumed = False
        self._lease: _BackupLease | None = None
        self._password: bytearray | None = None
        self._receipt: tuple[int, str] | None = None
        self._password_digest: str | None = None
        self._record_digest: str | None = None
        self._released = False

    def _valid(self) -> None:
        request, binding, now = self._request, self._binding, self._clock()
        if (request.scope_digest != binding._scope or request.audience_digest != binding._audience
                or type(now) is not int or not request.requested_at <= now < request.expires_at
                or binding._retain_until < request.expires_at + 86400):
            raise ValueError(_ERROR)
        binding._check()
        self._guard()

    def _active_valid(self) -> None:
        self._valid()
        self._dispatch_guard()

    def validate_binding(self, binding: BackupCustodyBinding, request: BackupLeaseRequest) -> MaterialBindingStatus:
        try:
            with self._lock:
                if binding is not self._binding or request is not self._request or self._attempted:
                    return MaterialBindingStatus.INCOMPATIBLE
                self._active_valid()
                binding._empty()
                return MaterialBindingStatus.AVAILABLE
        except Exception:
            return MaterialBindingStatus.UNAVAILABLE

    def acquire_lease(self, binding: BackupCustodyBinding, request: BackupLeaseRequest) -> MaterialLease:
        try:
            with self._lock:
                if self.validate_binding(binding, request) is not MaterialBindingStatus.AVAILABLE:
                    raise ValueError
                self._attempted = True
                # An exclusive durable claim precedes generation and survives process loss.
                binding._write("lease.claim", [request.authorization_digest.encode()], limit=64, guard=self._active_valid)
                self._password = bytearray(secrets.choice(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(15))
                _, self._password_digest = binding._write("backup.password", [self._password], limit=15, guard=self._active_valid)
                self._lease = _BackupLease()
                return self._lease
        except Exception:
            self._clear()
            raise MaterialAccessDenied(_ERROR) from None

    def _consume(self, lease: MaterialLease,
                 download: Callable[[memoryview], Iterable[bytes]]) -> None:
        try:
            with self._lock:
                if lease is not self._lease or self._lease is None or self._consumed or self._password is None:
                    raise ValueError
                self._consumed = True
                self._active_valid()
                view = memoryview(self._password).toreadonly()
                stream = None
                try:
                    stream = download(view)
                    receipt = self._binding._write("backup.conf", stream, limit=MAX_BACKUP_BYTES, guard=self._active_valid)
                finally:
                    close = getattr(stream, "close", None)
                    if callable(close):
                        close()
                    view.release()
                if receipt[0] < 64:
                    raise ValueError
                self._receipt = receipt
                self._verify_files()
                record = json.dumps(dict(contract=CONTRACT, bytes=receipt[0], sha256=receipt[1],
                    retain_until=self._binding._retain_until, native_encryption_requested=True,
                    restore_tested=False), sort_keys=True, separators=(",", ":")).encode()
                _, self._record_digest = self._binding._write("integrity.json", [record], limit=1024, guard=self._active_valid)
        except Exception:
            raise MaterialAccessDenied(_ERROR) from None
        finally:
            self._clear()

    def _verify_files(self) -> None:
        self._valid()
        self._verify_stored_files()

    def _verify_stored_files(self, *, before_read: Callable[[], None] | None = None) -> None:
        """Private local integrity check, with no lease renewal or authority.

        Retained-output readers must separately verify the original terminal
        claim, retention and fresh read authorization before calling this seam.
        """
        self._binding._check()
        if self._receipt is None or self._password_digest is None:
            raise ValueError(_ERROR)
        for name, size, wanted in (("backup.conf", *self._receipt), ("backup.password", 15, self._password_digest)):
            if before_read is not None: before_read()
            raw = _read(self._binding._directory / name, MAX_BACKUP_BYTES if name == "backup.conf" else 15)
            try:
                if before_read is not None: before_read()
                if len(raw) != size or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), wanted):
                    raise ValueError(_ERROR)
            finally:
                _erase_transfer_storage(raw)

    def _clear(self) -> None:
        if self._password is not None:
            self._password[:] = bytes(len(self._password))
            self._password = None

    def _verify_record(self, *, before_read: Callable[[], None] | None = None) -> None:
        if self._record_digest is None:
            raise ValueError(_ERROR)
        if before_read is not None: before_read()
        raw = _read(self._binding._directory / "integrity.json", 1024)
        try:
            if before_read is not None: before_read()
            if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), self._record_digest):
                raise ValueError(_ERROR)
        finally:
            _erase_transfer_storage(raw)

    def release_lease(self, lease: MaterialLease) -> MaterialLeaseCompletion:
        try:
            with self._lock:
                if lease is not self._lease or self._lease is None or not self._consumed:
                    raise ValueError
                self._verify_files()
                self._verify_record()
                self._released = True
                self._lease = None
                return MaterialLeaseCompletion.RELEASED
        except Exception:
            raise MaterialAccessDenied(_ERROR) from None
        finally:
            self._clear()

    def revoke_lease(self, lease: MaterialLease, *, reason: MaterialRevocationReason) -> MaterialLeaseCompletion:
        with self._lock:
            if type(reason) is not MaterialRevocationReason or lease is not self._lease or self._lease is None:
                raise MaterialAccessDenied(_ERROR)
            self._clear()
            self._lease = None
            return MaterialLeaseCompletion.REVOKED

    def verify_retained(self) -> None:
        if not self._released:
            raise MaterialAccessDenied(_ERROR)
        self._verify_files()
        self._verify_record()
