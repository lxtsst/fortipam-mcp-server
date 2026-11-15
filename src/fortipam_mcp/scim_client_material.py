"""Inactive, action-bound SCIM material lease; no source selection or registration.

The host supplies a prebound resolver that transfers one fresh mutable buffer.
The existing lease coordinator owns durable consumption. Native disable relays
the original secret just in time; it does not rotate it or expose it to a user.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from threading import RLock
import time
from typing import Protocol, cast, runtime_checkable

from v4_planning.material_provider import (
    C3MaterialBinding, MaterialAccessDenied, MaterialBindingStatus, MaterialLease,
    MaterialLeaseCompletion, MaterialLeaseRequest, MaterialProviderClass,
    MaterialPurpose, MaterialRevocationReason, _OpaqueC3Object,
)
from v4_planning.material_runtime import MaterialUseOutcome

from .scim_client_contract import ScimClientTransition
from .secret_create_191_http_transport import _valid_material_view
from .secret_metadata_http_transport import _zeroize_mutable
from .mutable_json_buffer import _clear_mutable_group

_ERROR = 'The private SCIM material lease is unavailable.'


@runtime_checkable
class ScimMaterialResolver(Protocol):
    @property
    def binding_digest(self) -> str: ...
    def validate_prebound(self) -> MaterialBindingStatus: ...
    def load_scim_material_once(self) -> bytearray:
        """Transfer one new owned buffer, never a shared credential cache."""
        ...


@dataclass(frozen=True, slots=True, repr=False, init=False)
class ScimMaterialBinding(C3MaterialBinding):
    transition_digest: str
    material_binding_digest: str
    action_id: str
    purpose: MaterialPurpose

    def __init__(self, transition: ScimClientTransition, *, restore: bool = False) -> None:
        try:
            if (type(transition) is not ScimClientTransition or type(restore) is not bool
                    or restore and transition.operation == 'create'): raise ValueError
            digest = transition._old_material_binding_digest if restore else transition._new_material_binding_digest
            if type(digest) is not str: raise ValueError
            purpose = {'create': MaterialPurpose.INITIAL_ONBOARDING, 'rotate': MaterialPurpose.CREDENTIAL_ROTATION,
                'disable': MaterialPurpose.JIT_DELIVERY}[transition.operation]
            for name, value in dict(transition_digest=transition.parameters_digest, material_binding_digest=digest,
                    action_id='scim-client-'+transition.operation+('-restore' if restore else ''), purpose=purpose).items():
                object.__setattr__(self, name, value)
        except Exception: raise MaterialAccessDenied(_ERROR) from None


class _ScimLease(MaterialLease):
    __slots__ = ()


class ScimMaterialProvider(_OpaqueC3Object):
    """One exact request, one loading attempt, one private consumer, no retry."""

    def __init__(self, resolver: ScimMaterialResolver, binding: ScimMaterialBinding,
            request: MaterialLeaseRequest, *, clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (not isinstance(resolver, ScimMaterialResolver) or type(binding) is not ScimMaterialBinding
                    or type(request) is not MaterialLeaseRequest or not callable(clock)
                    or resolver.binding_digest != binding.material_binding_digest or request.action_id != binding.action_id
                    or request.action_version != '1.0.0' or request.purpose is not binding.purpose
                    or request.provider_class is not MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE
                    or request.expires_at - request.requested_at > 60): raise ValueError
            request.__post_init__()
            self._resolver, self._binding, self._request = resolver, binding, request
            self._clock, self._last_now, self._failed = clock, -1, False
            self._attempted = self._consumed = self._closed = False
            self._buffer: bytearray | None = None
            self._lease: _ScimLease | None = None
            self._lock = RLock()
        except Exception: raise MaterialAccessDenied(_ERROR) from None

    def _status(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> MaterialBindingStatus:
        if binding is not self._binding or type(request) is not MaterialLeaseRequest or request != self._request:
            return MaterialBindingStatus.INCOMPATIBLE
        try:
            now = self._clock()
            if (self._failed or self._closed or type(now) is not int or now < self._last_now
                    or now < self._request.requested_at
                    or self._resolver.binding_digest != self._binding.material_binding_digest): raise ValueError
            self._last_now = now
            if now >= self._request.expires_at:
                self._clear()
                return MaterialBindingStatus.EXPIRED
            return MaterialBindingStatus.AVAILABLE
        except Exception:
            self._failed = True
            self._clear()
            return MaterialBindingStatus.UNAVAILABLE

    def _clear(self) -> None:
        try:
            if self._buffer is not None: _zeroize_mutable(self._buffer)
        finally:
            self._buffer = None

    def _ready(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> MaterialBindingStatus:
        status = self._status(binding, request)
        if status is not MaterialBindingStatus.AVAILABLE or self._attempted:
            return status if not self._attempted else MaterialBindingStatus.UNAVAILABLE
        try: source = self._resolver.validate_prebound()
        except Exception: return MaterialBindingStatus.UNAVAILABLE
        status = self._status(binding, request)
        if status is not MaterialBindingStatus.AVAILABLE: return status
        return source if type(source) is MaterialBindingStatus else MaterialBindingStatus.UNAVAILABLE

    def validate_binding(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> MaterialBindingStatus:
        with self._lock:
            return self._ready(binding, request)

    def acquire_lease(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> MaterialLease:
        candidate: object = None
        with self._lock:
            try:
                if self._ready(binding, request) is not MaterialBindingStatus.AVAILABLE: raise ValueError
                self._attempted = True
                candidate = self._resolver.load_scim_material_once()
                if type(candidate) is not bytearray or not 1 <= len(candidate) <= 59: raise ValueError
                with memoryview(candidate) as view:
                    if not _valid_material_view(view): raise ValueError
                if self._status(binding, request) is not MaterialBindingStatus.AVAILABLE: raise ValueError
                self._buffer, candidate = candidate, None
                self._lease = _ScimLease()
                return self._lease
            except Exception: raise MaterialAccessDenied(_ERROR) from None
            finally:
                items = cast(tuple[object, ...] | list[object], candidate) if type(candidate) in (tuple, list) else (candidate,)
                _clear_mutable_group(items, _zeroize_mutable)

    def consume(self, binding: ScimMaterialBinding, lease: MaterialLease, request: MaterialLeaseRequest,
            consumer: Callable[[memoryview], MaterialUseOutcome]) -> MaterialUseOutcome:
        """Only a private action consumer receives a temporary readonly view."""
        with self._lock:
            if lease is not self._lease or self._lease is None or self._consumed:
                return MaterialUseOutcome.FAILED
            self._consumed = True
            try:
                if self._status(binding, request) is not MaterialBindingStatus.AVAILABLE or self._buffer is None:
                    return MaterialUseOutcome.FAILED
                with memoryview(self._buffer).toreadonly() as view:
                    outcome = consumer(view)
                if self._status(binding, request) is not MaterialBindingStatus.AVAILABLE:
                    return MaterialUseOutcome.TIMED_OUT
                return outcome if type(outcome) is MaterialUseOutcome else MaterialUseOutcome.FAILED
            finally: self._clear()

    def release_lease(self, lease: MaterialLease) -> MaterialLeaseCompletion:
        with self._lock:
            if lease is not self._lease or self._lease is None or not self._consumed: raise MaterialAccessDenied(_ERROR)
            status = self._status(self._binding, self._request)
            self.close()
            return MaterialLeaseCompletion.RELEASED if status is MaterialBindingStatus.AVAILABLE else MaterialLeaseCompletion.UNKNOWN

    def revoke_lease(self, lease: MaterialLease, *, reason: MaterialRevocationReason) -> MaterialLeaseCompletion:
        with self._lock:
            if lease is not self._lease or self._lease is None or type(reason) is not MaterialRevocationReason:
                raise MaterialAccessDenied(_ERROR)
            self.close()
            return MaterialLeaseCompletion.REVOKED

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._clear()
