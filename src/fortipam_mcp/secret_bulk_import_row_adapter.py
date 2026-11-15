"""Inactive fixed sixteen-column row handoff; no provider class or device route."""

from __future__ import annotations

from dataclasses import dataclass
import threading
import time
from typing import Protocol

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome

from . import _secret_bulk_import_worker as worker
from .secret_bulk_import_intake import BulkImportIntakeError, _ERROR
from .secret_bulk_import_row_authority import PinnedOriginalRowAcquisitionAuthority, _OriginalRowPermissionPins
from .secret_bulk_import_row_channel import UnixOriginalRowChannelClient, _RemoteOriginalImportRowLoader
from .secret_bulk_import_row_loader import _OwnedOriginalImportRow, _PreboundOriginalImportRowLoader
from .secret_bulk_import_row_namespace import OriginalImportRow


@dataclass(frozen=True, slots=True, repr=False)
class _OriginalRowUseContext(_OpaqueC3Object):
    """Private original C2 joins, deliberately not a registered lease request."""

    row: OriginalImportRow
    permission: _OriginalRowPermissionPins
    requested_at: int
    expires_at: int

    def __post_init__(self) -> None:
        if (type(self.row) is not OriginalImportRow or type(self.permission) is not _OriginalRowPermissionPins
                or type(self.row.index) is not int or not 0 <= self.row.index < 256):
            raise BulkImportIntakeError(_ERROR)
        self.permission.__post_init__()
        self.row.verify_m4_plan(self.permission.plan)
        if (type(self.requested_at) is not int or type(self.expires_at) is not int
                or not self.permission.authorization.issued_at <= self.requested_at < self.expires_at
                or self.expires_at > min(self.requested_at + 60, self.permission.plan.expires_at,
                                        self.permission.authorization.expires_at)):
            raise BulkImportIntakeError(_ERROR)


class OriginalRowSecretCreateTransport(Protocol):
    """Prebound versioned native adapter, not an arbitrary material callback.

    It receives all native columns in HEADERS order, performs fixed native field
    mapping/readback, and returns a closed outcome before the supplied deadline.
    A concrete product implementation still requires separate qualification.
    """

    def _create_and_verify_with_original_row(
        self, context: _OriginalRowUseContext, columns: tuple[memoryview, ...], *, deadline: float,
    ) -> SecretCreateAdapterOutcome: ...


class _OriginalRowSecretCreateAdapter(_OpaqueC3Object):
    """One exact original row, fixed transport, fresh checks and owned cleanup."""

    def __init__(self, loader: _PreboundOriginalImportRowLoader, context: _OriginalRowUseContext,
                 transport: OriginalRowSecretCreateTransport) -> None:
        try:
            if (type(loader) not in {_PreboundOriginalImportRowLoader, _RemoteOriginalImportRowLoader}
                    or type(context) is not _OriginalRowUseContext
                    or not callable(getattr(transport, "_create_and_verify_with_original_row", None))):
                raise ValueError
            context.__post_init__()
            self._loader, self._context, self._transport = loader, context, transport
            self._used, self._lock = False, threading.Lock()
            self._owned: _OwnedOriginalImportRow | None = None
            self._verify_context()
            remaining = loader._session._remaining()
            now = loader._session._transaction._last_wall
            if not context.requested_at <= now < context.expires_at:
                raise ValueError
            self._deadline = time.monotonic() + min(remaining, context.expires_at - now)
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def _verify_context(self) -> None:
        loader, context = self._loader, self._context
        authority = loader._authority
        if type(authority) is PinnedOriginalRowAcquisitionAuthority:
            pins = authority._pins
        elif type(authority) is UnixOriginalRowChannelClient:
            pins = authority._binding.permission
        else:
            raise ValueError
        if (pins != context.permission or loader._row != context.row
                or loader._plan != pins.plan or loader._authorization != pins.authorization
                or loader._session._transaction._binding.scope_digest != pins.scope_digest):
            raise ValueError

    def _verify(self, *, completed: bool = False) -> None:
        self._verify_context()
        loader = self._loader
        loader._session._remaining()
        now = loader._session._transaction._last_wall
        if not self._context.requested_at <= now < self._context.expires_at:
            raise ValueError
        loader._verify(completed=completed)
        now = loader._session._transaction._last_wall
        self._deadline = min(self._deadline, time.monotonic() + self._context.expires_at - now)
        if time.monotonic() >= self._deadline:
            raise ValueError
        loader._acquisition_deadline = (self._deadline if loader._acquisition_deadline is None
                                       else min(loader._acquisition_deadline, self._deadline))
        if loader._lifetime is not None:
            loader._lifetime.deadline = min(loader._lifetime.deadline, self._deadline)
            loader._lifetime.check()

    def _acquire_once(self) -> _OwnedOriginalImportRow:
        """Provider-only acquisition after the durable material-use claim."""
        from .secret_bulk_import_row_http_transport import _Build29OriginalRowHttpTransport
        if not self._lock.acquire(blocking=False):
            raise BulkImportIntakeError(_ERROR)
        try:
            if self._used:
                raise ValueError
            self._used = True
            self._verify()
            if type(self._transport) is _Build29OriginalRowHttpTransport:
                self._transport._prepare_actor_once(self._context, deadline=self._deadline)
            self._owned = self._loader._load_once()
            return self._owned
        except BaseException as error:
            if type(self._transport) is _Build29OriginalRowHttpTransport and self._transport._product_client is not None:
                self._transport._product_client.close()
            if isinstance(error, Exception):
                raise BulkImportIntakeError(_ERROR) from None
            raise
        finally:
            self._lock.release()

    def _dispatch_owned_once(self, owned: _OwnedOriginalImportRow) -> SecretCreateAdapterOutcome:
        """Fixed provider consumer; no public accessor or arbitrary callback."""
        from .secret_bulk_import_row_http_transport import _Build29OriginalRowHttpTransport
        if (type(owned) is not _OwnedOriginalImportRow or owned is not self._owned
                or not self._used or not self._lock.acquire(blocking=False)):
            raise BulkImportIntakeError(_ERROR)
        views: list[memoryview] = []
        try:
            with owned._lock:
                if (owned._row != self._context.row or owned._consumed or owned._closed.is_set()
                        or len(owned._buffers) != len(worker.HEADERS)):
                    raise ValueError
                self._verify()
                owned._lifetime.check()
                owned._consumed = True
                views.extend(memoryview(part).toreadonly() for part in owned._buffers)
                try:
                    outcome = self._transport._create_and_verify_with_original_row(
                        self._context, tuple(views), deadline=owned._lifetime.deadline)
                    if type(outcome) is not SecretCreateAdapterOutcome:
                        raise ValueError
                    self._verify(completed=outcome is SecretCreateAdapterOutcome.VERIFIED_CREATED)
                    owned._lifetime.check()
                    if owned._closed.is_set():
                        raise ValueError
                    return outcome
                finally:
                    for view in views:
                        view.release()
                    views.clear()
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            for view in views:
                view.release()
            owned.close()
            if type(self._transport) is _Build29OriginalRowHttpTransport and self._transport._product_client is not None:
                self._transport._product_client.close()
            self._lock.release()

    def dispatch_once(self) -> SecretCreateAdapterOutcome:
        """Existing private handoff; provider composition uses the two phases."""
        owned = self._acquire_once()
        try:
            return self._dispatch_owned_once(owned)
        finally:
            owned.close()
