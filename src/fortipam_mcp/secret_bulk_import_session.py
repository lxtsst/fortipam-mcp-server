"""Inactive owner-workload source lifecycle, without a row provider or route.

Only trusted composition can admit a session. Its watchdog owns idle disposal;
no password accessor, renewal, journal, child authorization or import is supplied.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Protocol

from mcp.server.auth.provider import TokenVerifier
from v4_planning.material_provider import _OpaqueC3Object

from ._secret_bulk_import_worker import MAX_PASSWORD_BYTES
from .secret_bulk_import_dependencies import ImportDependencyCatalog, ResolvedImportDependencies
from .secret_bulk_import_file import _ParserLifetime, _wipe
from .secret_bulk_import_intake import (
    BulkImportIntakeError, OwnerFileIntakeAuthority, OwnerFileIntakeBinding,
    _AdmittedOwnerFile, _ERROR, admit_prebound_owner_file,
)

_POLL_SECONDS = 0.05


class OwnerFileSessionAuthority(Protocol):
    """Additional fixed source-session permission, independent of projection."""

    def verify_source_session(self, binding: OwnerFileIntakeBinding, *, now_epoch: int) -> object:
        """Exactly None permits this intent; any other result or failure denies."""
        ...

    def source_session_expires_at(self, binding: OwnerFileIntakeBinding, *, now_epoch: int) -> int:
        """Return the independently verified decision horizon, not a caller TTL."""
        ...


class _SessionAdmissionAuthority:
    def __init__(self, projection: OwnerFileIntakeAuthority, session: OwnerFileSessionAuthority) -> None:
        self._projection, self._session = projection, session
        self.expires_at: int | None = None

    def verify(self, binding: OwnerFileIntakeBinding, *, now_epoch: int) -> None:
        if (self._projection.verify(binding, now_epoch=now_epoch) is not None
                or self._session.verify_source_session(binding, now_epoch=now_epoch) is not None):
            raise ValueError
        expires = self._session.source_session_expires_at(binding, now_epoch=now_epoch)
        if type(expires) is not int or not now_epoch < expires <= binding.expires_at:
            raise ValueError
        self.expires_at = expires if self.expires_at is None else min(self.expires_at, expires)
        if now_epoch >= self.expires_at:
            raise ValueError


class _OwnerFileSourceSession(_OpaqueC3Object):
    """Owned unlock memory with an autonomous, non-renewable deadline.

    Workload shutdown/revocation must call close. The timer clears idle memory
    without any subsequent API call. Active decoder copies clear after bounded
    cancellation and child reaping; they are never overwritten while borrowed.
    Process death invalidates this object, not a proof of physical-memory erasure.
    """

    __slots__ = ("_transaction", "_password", "_memory_lock", "_projection_lock",
                 "_deadline", "_watchdog")

    def __init__(self, transaction: _AdmittedOwnerFile, password: bytearray) -> None:
        self._transaction = transaction
        self._password = bytearray()
        self._memory_lock, self._projection_lock = threading.RLock(), threading.Lock()
        self._watchdog: threading.Thread | None = None
        claimed = False
        try:
            if type(transaction) is not _AdmittedOwnerFile or type(password) is not bytearray:
                raise ValueError
            if not transaction._lock.acquire(blocking=False):
                raise ValueError
            try:
                if transaction._used or transaction._session_claimed:
                    raise ValueError
                transaction._session_claimed = True
                claimed = True
            finally:
                transaction._lock.release()
            transaction._check()
            with transaction._state_lock:
                remaining = min(transaction._expires - transaction._last_wall,
                                transaction._deadline - transaction._last_mono, 900.0)
            self._deadline = time.monotonic() + remaining
            self._password = bytearray(password)
            _wipe(password)
            self._remaining()
            self._watchdog = threading.Thread(target=self._watch, name="owner-file-disposal", daemon=True)
            self._watchdog.start()
        except BaseException:
            if claimed:
                self._dispose()
            else:
                _wipe(self._password)
            raise BulkImportIntakeError(_ERROR) from None

    def _remaining(self) -> float:
        with self._transaction._state_lock:
            admission = self._transaction._authority
            if isinstance(admission, _SessionAdmissionAuthority) and admission.expires_at is not None:
                reduction = max(0.0, self._transaction._expires - admission.expires_at)
                self._transaction._expires -= reduction
                self._transaction._deadline -= reduction
                self._deadline -= reduction
            self._transaction._check()
            remaining = min(self._deadline - time.monotonic(),
                            self._transaction._expires - self._transaction._last_wall,
                            self._transaction._deadline - self._transaction._last_mono)
            if remaining <= 0:
                raise ValueError
            return remaining

    def _dispose(self) -> None:
        self._transaction.close()
        with self._memory_lock:
            _wipe(self._password)

    def _watch(self) -> None:
        try:
            while not self._transaction._closed.wait(min(_POLL_SECONDS, self._remaining())):
                pass
        except BaseException:
            pass
        finally:
            self._dispose()

    def close(self) -> None:
        """Invalidate and clear retained unlock memory; stop the owning timer."""
        self._dispose()
        watchdog = self._watchdog
        if watchdog is not None and watchdog is not threading.current_thread() and watchdog.ident is not None:
            watchdog.join(timeout=1)

    def __enter__(self) -> _OwnerFileSourceSession:
        try:
            self._remaining()
            return self
        except BaseException:
            self.close()
            raise BulkImportIntakeError(_ERROR) from None

    def __exit__(self, *_: object) -> None:
        self.close()

    def project_dependencies_once(self, catalog: ImportDependencyCatalog) -> ResolvedImportDependencies:
        """One authorized projection with a fresh unlock copy, never a row lease."""
        if not self._projection_lock.acquire(blocking=False):
            raise BulkImportIntakeError(_ERROR)
        password = bytearray()
        try:
            with self._memory_lock:
                remaining = self._remaining()
                password = bytearray(self._password)
            lifetime = _ParserLifetime(time.monotonic() + min(remaining, 60.0),
                                       self._transaction._closed)
            result = self._transaction.project_dependencies_once(
                catalog, workbook_password=password, _lifetime=lifetime,
            )
            self._remaining()
            return result
        except BaseException:
            self.close()
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            _wipe(password)
            self._projection_lock.release()


async def admit_prebound_owner_file_session(
    binding: OwnerFileIntakeBinding, *, planning_token: str, intake_token: str,
    workbook_password: bytearray | None = None,
    planning_verifier: TokenVerifier | None = None, intake_verifier: TokenVerifier | None = None,
    authority: OwnerFileIntakeAuthority | None = None,
    session_authority: OwnerFileSessionAuthority | None = None,
    clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic,
) -> _OwnerFileSourceSession:
    """Fresh dual-token admission before pinning or retaining the private unlock.

    This candidate does not change the existing no-retention submission endpoint
    or frozen source denial. Restart must repeat authentication; no state persists.
    """
    transaction: _AdmittedOwnerFile | None = None
    password = workbook_password if workbook_password is not None else bytearray()
    try:
        if (type(binding) is not OwnerFileIntakeBinding or type(password) is not bytearray
                or len(password) > MAX_PASSWORD_BYTES
                or (binding.file_format == "csv" and password)
                or authority is None or session_authority is None
                or not callable(getattr(session_authority, "verify_source_session", None))
                or not callable(getattr(session_authority, "source_session_expires_at", None))):
            raise ValueError
        admission = _SessionAdmissionAuthority(authority, session_authority)
        transaction = await admit_prebound_owner_file(
            binding, planning_token=planning_token, intake_token=intake_token,
            planning_verifier=planning_verifier, intake_verifier=intake_verifier,
            authority=admission, clock=clock, monotonic=monotonic,
        )
        with transaction._state_lock:
            if admission.expires_at is None:
                raise ValueError
            reduction = max(0.0, transaction._expires - admission.expires_at)
            transaction._expires -= reduction
            transaction._deadline -= reduction
            transaction._check()
        return _OwnerFileSourceSession(transaction, password)
    except BaseException:
        if transaction is not None:
            transaction.close()
        raise BulkImportIntakeError(_ERROR) from None
    finally:
        if type(password) is bytearray:
            _wipe(password)
