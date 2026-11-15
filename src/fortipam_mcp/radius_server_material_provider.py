"""Private single-use material lease for the fixed disposable RADIUS action.

Only a trusted prebound lab loader may acquire the existing fixture's material.
This module supplies no loader, credential registration, remote access or MCP
surface. Release/revoke clear this lease's local copy, not the live server input.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from threading import Lock
import time
from typing import Protocol, cast

from v4_planning.material_provider import (
    C3MaterialBinding, MaterialAccessDenied, MaterialBindingStatus, MaterialLease,
    MaterialLeaseCompletion, MaterialLeaseRequest, MaterialProviderClass,
    MaterialPurpose, MaterialRevocationReason, _OpaqueC3Object,
)
from v4_planning.material_runtime import MaterialUseOutcome, material_lease_request_digest

from .radius_server_contract import (
    ACTION_ID, ACTION_VERSION, RadiusServerCreateBinding, RadiusServerCreateOutcome,
)
from .secret_metadata_http_transport import _zeroize_mutable

MAX_RADIUS_SERVER_LEASE_SECONDS = 60
_ALPHABET = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_UNAVAILABLE = "The private RADIUS server material provider is unavailable."


class RadiusServerMaterialLoader(Protocol):
    """Trusted lab-only acquisition; validate must never read the material value."""

    def validate_prebound(self, binding: RadiusServerCreateBinding,
                          request: MaterialLeaseRequest) -> MaterialBindingStatus: ...

    def load_radius_material_once(self, binding: RadiusServerCreateBinding,
                                 request: MaterialLeaseRequest) -> bytearray: ...


class RadiusServerMaterialTransport(Protocol):
    def _create_and_verify_with_material(self, binding: RadiusServerCreateBinding,
            request: MaterialLeaseRequest, secret: memoryview) -> RadiusServerCreateOutcome: ...


class _RadiusServerMaterialLease(MaterialLease):
    __slots__ = ()


def _clear_candidate(candidate: object) -> None:
    if type(candidate) is bytearray:
        _zeroize_mutable(candidate)
    elif type(candidate) in (tuple, list):
        for item in cast(tuple[object, ...] | list[object], candidate):
            if type(item) is bytearray:
                _zeroize_mutable(item)


class RadiusServerMaterialProvider(_OpaqueC3Object):
    """Pin one lab action/request and consume its loading attempt before entry."""

    __slots__ = ("_binding", "_binding_digest", "_request", "_request_digest", "_loader",
        "_clock", "_last_clock", "_clock_failed", "_lock", "_load_attempted", "_lease", "_buffer", "_consumed")
    _display_name = "RadiusServerMaterialProvider"

    def __init__(self, loader: RadiusServerMaterialLoader, *, binding: RadiusServerCreateBinding,
                 request: MaterialLeaseRequest, clock: Callable[[], int] | None = None) -> None:
        try:
            if type(binding) is not RadiusServerCreateBinding or type(request) is not MaterialLeaseRequest:
                raise ValueError
            pinned = replace(request)
            if (pinned.action_id != ACTION_ID or pinned.action_version != ACTION_VERSION
                or pinned.provider_class is not MaterialProviderClass.OWNED_LAB_FIXTURE_REFERENCE
                or pinned.purpose is not MaterialPurpose.INITIAL_ONBOARDING
                or pinned.expires_at - pinned.requested_at > MAX_RADIUS_SERVER_LEASE_SECONDS
                or not callable(getattr(loader, "validate_prebound", None))
                or not callable(getattr(loader, "load_radius_material_once", None))
                or clock is not None and not callable(clock)):
                raise ValueError
            self._binding_digest = binding.parameters_digest
            self._request_digest = material_lease_request_digest(pinned)
        except Exception:
            raise MaterialAccessDenied(_UNAVAILABLE) from None
        self._binding, self._request, self._loader = binding, pinned, loader
        self._clock = clock or (lambda: int(time.time()))
        self._last_clock: int | None = None
        self._clock_failed = False
        self._lock = Lock()
        self._load_attempted = self._consumed = False
        self._lease: _RadiusServerMaterialLease | None = None
        self._buffer: bytearray | None = None

    def _matches(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> bool:
        try:
            return (binding is self._binding and binding.parameters_digest == self._binding_digest
                and type(request) is MaterialLeaseRequest and request == self._request
                and material_lease_request_digest(request) == self._request_digest)
        except Exception:
            return False

    def _context_status(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> MaterialBindingStatus:
        if not self._matches(binding, request):
            return MaterialBindingStatus.INCOMPATIBLE
        try:
            now = self._clock()
            if (self._clock_failed or type(now) is not int or now < self._request.requested_at
                or self._last_clock is not None and now < self._last_clock):
                raise ValueError
            self._last_clock = now
        except Exception:
            self._clock_failed = True
            return MaterialBindingStatus.UNAVAILABLE
        if not self._matches(binding, request):
            return MaterialBindingStatus.INCOMPATIBLE
        return MaterialBindingStatus.EXPIRED if now >= self._request.expires_at else MaterialBindingStatus.AVAILABLE

    def _validate_locked(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> MaterialBindingStatus:
        status = self._context_status(binding, request)
        if status is not MaterialBindingStatus.AVAILABLE:
            return status
        if self._load_attempted:
            return MaterialBindingStatus.UNAVAILABLE
        try:
            source = self._loader.validate_prebound(self._binding, self._request)
        except Exception:
            return MaterialBindingStatus.UNAVAILABLE
        status = self._context_status(binding, request)
        if status is not MaterialBindingStatus.AVAILABLE:
            return status
        return source if type(source) is MaterialBindingStatus else MaterialBindingStatus.UNAVAILABLE

    def validate_binding(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> MaterialBindingStatus:
        if not self._lock.acquire(blocking=False):
            return MaterialBindingStatus.UNAVAILABLE
        try:
            status = self._validate_locked(binding, request)
            if status is MaterialBindingStatus.EXPIRED or self._clock_failed:
                self._clear()
            return status
        finally:
            self._lock.release()

    def acquire_lease(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> MaterialLease:
        if not self._lock.acquire(blocking=False):
            raise MaterialAccessDenied(_UNAVAILABLE)
        candidate: object = None
        try:
            status = self._validate_locked(binding, request)
            if status is not MaterialBindingStatus.AVAILABLE:
                if status is MaterialBindingStatus.EXPIRED or self._clock_failed:
                    self._clear()
                raise MaterialAccessDenied(_UNAVAILABLE)
            self._load_attempted = True
            candidate = self._loader.load_radius_material_once(self._binding, self._request)
            if (type(candidate) is not bytearray or len(candidate) != 32
                or any(value not in _ALPHABET for value in candidate)
                or self._context_status(binding, request) is not MaterialBindingStatus.AVAILABLE):
                raise MaterialAccessDenied(_UNAVAILABLE)
            self._buffer = candidate
            self._lease = _RadiusServerMaterialLease()
            candidate = None
            return self._lease
        except Exception:
            raise MaterialAccessDenied(_UNAVAILABLE) from None
        finally:
            _clear_candidate(candidate)
            self._lock.release()

    def _clear(self) -> None:
        _clear_candidate(self._buffer)
        self._buffer = None

    def _consume_for_radius_transport(self, binding: RadiusServerCreateBinding, lease: MaterialLease,
            request: MaterialLeaseRequest, transport: RadiusServerMaterialTransport) -> MaterialUseOutcome:
        if not self._lock.acquire(blocking=False):
            return MaterialUseOutcome.FAILED
        view = None
        try:
            if lease is not self._lease or self._lease is None or self._consumed:
                return MaterialUseOutcome.FAILED
            self._consumed = True
            status = self._context_status(binding, request)
            if status is MaterialBindingStatus.EXPIRED:
                return MaterialUseOutcome.TIMED_OUT
            if status is not MaterialBindingStatus.AVAILABLE or self._buffer is None:
                return MaterialUseOutcome.FAILED
            view = memoryview(self._buffer).toreadonly()
            outcome = transport._create_and_verify_with_material(binding, request, view)
            status = self._context_status(binding, request)
            if status is MaterialBindingStatus.EXPIRED:
                return MaterialUseOutcome.TIMED_OUT
            if status is not MaterialBindingStatus.AVAILABLE:
                return MaterialUseOutcome.FAILED
            if outcome is RadiusServerCreateOutcome.VERIFIED_CREATED:
                return MaterialUseOutcome.VERIFIED
            if outcome is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED:
                return MaterialUseOutcome.AMBIGUOUS
            return MaterialUseOutcome.FAILED
        except TimeoutError:
            return MaterialUseOutcome.TIMED_OUT
        except Exception:
            return MaterialUseOutcome.FAILED
        finally:
            if view is not None:
                view.release()
            if lease is self._lease:
                self._clear()
            self._lock.release()

    def _finish(self, lease: MaterialLease, *, revoked: bool) -> MaterialLeaseCompletion:
        if not self._lock.acquire(blocking=False):
            raise MaterialAccessDenied(_UNAVAILABLE)
        try:
            if lease is not self._lease or self._lease is None:
                raise MaterialAccessDenied(_UNAVAILABLE)
            status = self._context_status(self._binding, self._request)
            self._clear()
            self._lease = None
            if revoked:
                return MaterialLeaseCompletion.REVOKED
            if status is MaterialBindingStatus.EXPIRED:
                return MaterialLeaseCompletion.EXPIRED
            return (MaterialLeaseCompletion.RELEASED if status is MaterialBindingStatus.AVAILABLE
                    else MaterialLeaseCompletion.UNKNOWN)
        finally:
            self._lock.release()

    def release_lease(self, lease: MaterialLease) -> MaterialLeaseCompletion:
        return self._finish(lease, revoked=False)

    def revoke_lease(self, lease: MaterialLease, *, reason: MaterialRevocationReason) -> MaterialLeaseCompletion:
        if type(reason) is not MaterialRevocationReason:
            raise MaterialAccessDenied(_UNAVAILABLE)
        return self._finish(lease, revoked=True)


class RadiusServerLeaseTransport(_OpaqueC3Object):
    """Use the shared coordinator without exposing a general material accessor."""

    __slots__ = ("_provider", "_transport")
    _display_name = "RadiusServerLeaseTransport"

    def __init__(self, provider: RadiusServerMaterialProvider, transport: RadiusServerMaterialTransport) -> None:
        if (type(provider) is not RadiusServerMaterialProvider
            or not callable(getattr(transport, "_create_and_verify_with_material", None))):
            raise MaterialAccessDenied(_UNAVAILABLE)
        self._provider, self._transport = provider, transport

    def consume(self, lease: MaterialLease) -> MaterialUseOutcome:
        return self._provider._consume_for_radius_transport(
            self._provider._binding, lease, self._provider._request, self._transport)
