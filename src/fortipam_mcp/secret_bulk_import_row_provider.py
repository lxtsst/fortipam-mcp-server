"""Inactive owner-file candidate lease, reusing the existing claimed-use engine.

No enum/Tool/runtime profile is registered. The exact private owner-file context
stays distinct from the accepted inventory/vault/managed request classes. This
candidate uses the existing checkpoint-bound material store locally or the fixed
signed owner-side state client; separated intake receives no ledger or signing
inputs. Product transport and activation require their own qualification.
"""

from __future__ import annotations

import threading

from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import (
    C3MaterialBinding, MaterialAccessDenied, MaterialBindingStatus, MaterialLease,
    MaterialLeaseCompletion, MaterialRevocationReason, _OpaqueC3Object,
)
from v4_planning.material_runtime import (
    MaterialRuntimeError, MaterialRuntimeOutcome, MaterialUseOutcome, _MaterialLeaseUse,
)
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome

from .secret_bulk_import_row_adapter import _OriginalRowSecretCreateAdapter, _OriginalRowUseContext
from .secret_bulk_import_row_authority import _original_material_request_digest
from .secret_bulk_import_row_channel import _OriginalRowMaterialStateClient
from .secret_bulk_import_row_loader import _OwnedOriginalImportRow

_UNAVAILABLE = "The private owner-file material lifecycle is unavailable."


def _original_row_request_digest(context: _OriginalRowUseContext) -> str:
    context.__post_init__()
    # Private row identity is already joined by the original keyed child plan;
    # no source locator/hash/index or material is written to the material ledger.
    return _original_material_request_digest(context.permission, context.requested_at, context.expires_at)


class _OriginalRowBinding(C3MaterialBinding):
    __slots__ = ()


class _OriginalRowMaterialLease(MaterialLease):
    __slots__ = ()


class _OriginalRowMaterialProvider(_OpaqueC3Object):
    """Four candidate operations; only the exact fixed adapter consumes views."""

    def __init__(self, bridge: _OriginalRowSecretCreateAdapter) -> None:
        if type(bridge) is not _OriginalRowSecretCreateAdapter:
            raise MaterialAccessDenied(_UNAVAILABLE)
        self._bridge, self._context = bridge, bridge._context
        self._binding = _OriginalRowBinding()
        self._owned: _OwnedOriginalImportRow | None = None
        self._lease: _OriginalRowMaterialLease | None = None
        self._attempted = self._terminal = self._verified = False
        self._lock = threading.RLock()

    def validate_binding(self, binding: C3MaterialBinding, request: _OriginalRowUseContext) -> MaterialBindingStatus:
        if binding is not self._binding or type(request) is not _OriginalRowUseContext or request != self._context:
            return MaterialBindingStatus.INCOMPATIBLE
        if self._attempted or self._terminal:
            return MaterialBindingStatus.UNAVAILABLE
        try:
            request.__post_init__()
            self._bridge._verify()
        except Exception:
            return MaterialBindingStatus.UNAVAILABLE
        return MaterialBindingStatus.AVAILABLE

    def acquire_lease(self, binding: C3MaterialBinding, request: _OriginalRowUseContext) -> MaterialLease:
        with self._lock:
            if self.validate_binding(binding, request) is not MaterialBindingStatus.AVAILABLE:
                raise MaterialAccessDenied(_UNAVAILABLE)
            self._attempted = True
            try:
                self._owned = self._bridge._acquire_once()
                self._lease = _OriginalRowMaterialLease()
                return self._lease
            except BaseException:
                self._clear_on_exit()
                raise

    def _active(self, lease: MaterialLease) -> _OwnedOriginalImportRow:
        if (type(lease) is not _OriginalRowMaterialLease or lease is not self._lease
                or self._owned is None or self._terminal):
            raise MaterialAccessDenied(_UNAVAILABLE)
        return self._owned

    def _consume_for_original_row(self, lease: MaterialLease) -> MaterialUseOutcome:
        with self._lock:
            owned = self._active(lease)
            result = self._bridge._dispatch_owned_once(owned)
            self._verified = result is SecretCreateAdapterOutcome.VERIFIED_CREATED
            return MaterialUseOutcome.VERIFIED if self._verified else MaterialUseOutcome.AMBIGUOUS

    def release_lease(self, lease: MaterialLease) -> MaterialLeaseCompletion:
        with self._lock:
            owned = self._active(lease)
            self._terminal = True
            try:
                if not self._verified or not owned._consumed:
                    raise MaterialAccessDenied(_UNAVAILABLE)
                owned._lifetime.check()
                self._bridge._verify(completed=True)
                return MaterialLeaseCompletion.RELEASED
            finally:
                owned.close()

    def revoke_lease(self, lease: MaterialLease, *, reason: MaterialRevocationReason) -> MaterialLeaseCompletion:
        with self._lock:
            if type(reason) is not MaterialRevocationReason:
                raise MaterialAccessDenied(_UNAVAILABLE)
            owned = self._active(lease)
            self._terminal = True
            owned.close()
            return MaterialLeaseCompletion.REVOKED

    def _clear_on_exit(self) -> None:
        with self._lock:
            self._terminal = True
            if self._owned is not None:
                self._owned.close()


class _OriginalRowMaterialRuntime(_OpaqueC3Object):
    """Fixed candidate use; no caller-selected binding/request/consumer or store."""

    def __init__(self, bridge: _OriginalRowSecretCreateAdapter,
                 state_store: PersistentMaterialUseStateStore | _OriginalRowMaterialStateClient) -> None:
        if (type(bridge) is not _OriginalRowSecretCreateAdapter
                or type(state_store) not in {PersistentMaterialUseStateStore, _OriginalRowMaterialStateClient}
                or not state_store.monotonic_checkpoint_protocol_bound):
            raise MaterialAccessDenied(_UNAVAILABLE)
        if type(state_store) is _OriginalRowMaterialStateClient:
            state_store._verify_bridge(bridge)
        self._provider = _OriginalRowMaterialProvider(bridge)
        self._state = state_store
        self._started, self._lock = False, threading.Lock()

    def verify_ready(self) -> None:
        self._state.verify_ready()

    def execute_once(self, *, now_epoch: int) -> MaterialRuntimeOutcome:
        if not self._lock.acquire(blocking=False):
            raise MaterialRuntimeError(_UNAVAILABLE)
        p = self._provider
        context = p._context
        try:
            if self._started:
                raise MaterialRuntimeError(_UNAVAILABLE)
            self._started = True
            if (type(now_epoch) is not int or not context.requested_at <= now_epoch < context.expires_at
                    or p.validate_binding(p._binding, context) is not MaterialBindingStatus.AVAILABLE):
                raise MaterialRuntimeError(_UNAVAILABLE)
            self.verify_ready()
            return _MaterialLeaseUse(self._state,
                acquire=lambda: p.acquire_lease(p._binding, context), release=p.release_lease,
                revoke=lambda lease, reason: p.revoke_lease(lease, reason=reason),
            ).execute_once(request_digest=_original_row_request_digest(context),
                authorization_digest=context.permission.authorization.authorization_digest,
                consumer=p._consume_for_original_row)
        finally:
            p._clear_on_exit()
            self._lock.release()
