"""One-use private material lease for the fixed LDAP server create action.

The owner injects an already-bound loader. No material source, selector, path,
environment variable, registry, or general material accessor is exposed here.
The fixed synchronous transport owns its bounded network timeout.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from threading import Lock
import time
from typing import Protocol, cast

from v4_planning.material_provider import (
    C3MaterialBinding,
    MaterialAccessDenied,
    MaterialBindingStatus,
    MaterialLease,
    MaterialLeaseCompletion,
    MaterialLeaseRequest,
    MaterialProviderClass,
    MaterialPurpose,
    MaterialRevocationReason,
    _OpaqueC3Object,
)
from v4_planning.material_runtime import MaterialUseOutcome, material_lease_request_digest

from .ldap_server_contract import (
    ACTION_ID,
    ACTION_VERSION,
    LdapServerCreateBinding,
    LdapServerCreateOutcome,
)
from .secret_create_central_lab_provider import CentralLabSecretCreateResolverLoader, _zeroize

MAX_LDAP_SERVER_LEASE_SECONDS = 60
_UNAVAILABLE = "The private LDAP server material provider is unavailable."


class LdapServerMaterialTransport(Protocol):
    """Only this fixed internal operation receives temporary material views."""

    def _create_and_verify_with_material(
        self,
        binding: LdapServerCreateBinding,
        request: MaterialLeaseRequest,
        username: memoryview,
        password: memoryview,
    ) -> LdapServerCreateOutcome: ...


class _LdapServerMaterialLease(MaterialLease):
    __slots__ = ()


def _clear_candidate(candidate: object) -> None:
    if type(candidate) in (tuple, list):
        for value in cast(tuple[object, ...] | list[object], candidate):
            if type(value) is bytearray:
                _zeroize(value)


class LdapServerMaterialProvider(_OpaqueC3Object):
    """Issue at most one lease for one complete, pinned action request."""

    __slots__ = (
        "_binding", "_binding_digest", "_request", "_request_digest", "_loader",
        "_clock", "_lock", "_load_attempted", "_lease", "_buffers", "_consumed",
    )
    _display_name = "LdapServerMaterialProvider"

    def __init__(
        self,
        resolver_loader: CentralLabSecretCreateResolverLoader,
        *,
        binding: LdapServerCreateBinding,
        request: MaterialLeaseRequest,
        clock: Callable[[], int] | None = None,
    ) -> None:
        try:
            if type(binding) is not LdapServerCreateBinding or type(request) is not MaterialLeaseRequest:
                raise ValueError
            pinned_request = replace(request)
            selected_clock = clock if clock is not None else lambda: int(time.time())
            if (
                request.action_id != ACTION_ID or request.action_version != ACTION_VERSION
                or request.provider_class is not MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE
                or request.purpose is not MaterialPurpose.INITIAL_ONBOARDING
                or request.expires_at - request.requested_at > MAX_LDAP_SERVER_LEASE_SECONDS
                or not callable(getattr(resolver_loader, "validate_prebound", None))
                or not callable(getattr(resolver_loader, "load_secret_create_material_once", None))
                or not callable(selected_clock)
            ):
                raise ValueError
            self._binding_digest = binding.parameters_digest
            self._request_digest = material_lease_request_digest(pinned_request)
        except Exception:
            raise MaterialAccessDenied(_UNAVAILABLE) from None
        self._binding = binding
        self._request = pinned_request
        self._loader = resolver_loader
        self._clock = selected_clock
        self._lock = Lock()
        self._load_attempted = False
        self._lease: _LdapServerMaterialLease | None = None
        self._buffers: tuple[bytearray, bytearray] | None = None
        self._consumed = False

    def _matches(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> bool:
        try:
            return (
                binding is self._binding
                and binding.parameters_digest == self._binding_digest
                and type(request) is MaterialLeaseRequest
                and request == self._request
                and material_lease_request_digest(request) == self._request_digest
            )
        except Exception:
            return False

    def _context_status(
        self, binding: C3MaterialBinding, request: MaterialLeaseRequest,
    ) -> MaterialBindingStatus:
        if not self._matches(binding, request):
            return MaterialBindingStatus.INCOMPATIBLE
        try:
            now = self._clock()
        except Exception:
            return MaterialBindingStatus.UNAVAILABLE
        if not self._matches(binding, request):
            return MaterialBindingStatus.INCOMPATIBLE
        if type(now) is not int or now < self._request.requested_at:
            return MaterialBindingStatus.UNAVAILABLE
        if now >= self._request.expires_at:
            return MaterialBindingStatus.EXPIRED
        return MaterialBindingStatus.AVAILABLE

    def _validate_locked(
        self, binding: C3MaterialBinding, request: MaterialLeaseRequest,
    ) -> MaterialBindingStatus:
        status = self._context_status(binding, request)
        if status is not MaterialBindingStatus.AVAILABLE:
            return status
        if self._load_attempted:
            return MaterialBindingStatus.UNAVAILABLE
        try:
            source_status = self._loader.validate_prebound()
        except Exception:
            return MaterialBindingStatus.UNAVAILABLE
        status = self._context_status(binding, request)
        if status is not MaterialBindingStatus.AVAILABLE:
            return status
        return source_status if type(source_status) is MaterialBindingStatus else MaterialBindingStatus.UNAVAILABLE

    def validate_binding(
        self, binding: C3MaterialBinding, request: MaterialLeaseRequest,
    ) -> MaterialBindingStatus:
        if not self._lock.acquire(blocking=False):
            return MaterialBindingStatus.UNAVAILABLE
        try:
            status = self._validate_locked(binding, request)
            if status is MaterialBindingStatus.EXPIRED:
                self._clear()
            return status
        finally:
            self._lock.release()

    def acquire_lease(
        self, binding: C3MaterialBinding, request: MaterialLeaseRequest,
    ) -> MaterialLease:
        if not self._lock.acquire(blocking=False):
            raise MaterialAccessDenied(_UNAVAILABLE)
        candidate: object = None
        try:
            status = self._validate_locked(binding, request)
            if status is not MaterialBindingStatus.AVAILABLE:
                if status is MaterialBindingStatus.EXPIRED:
                    self._clear()
                raise MaterialAccessDenied(_UNAVAILABLE)
            # Consume the loading attempt before entering owner-side code.
            self._load_attempted = True
            candidate = self._loader.load_secret_create_material_once()
            if (type(candidate) is not tuple or len(candidate) != 2
                or any(type(value) is not bytearray for value in candidate)):
                raise MaterialAccessDenied(_UNAVAILABLE)
            username, password = candidate
            if (username is password or len(username) != len(self._binding.username)
                or any(value != ord(expected) for value, expected in zip(username, self._binding.username))
                or not 1 <= len(password) <= 128
                or any(value in (0, 10, 13) for value in password)
                or self._context_status(binding, request) is not MaterialBindingStatus.AVAILABLE):
                raise MaterialAccessDenied(_UNAVAILABLE)
            self._buffers = (username, password)
            self._lease = _LdapServerMaterialLease()
            candidate = None
            return self._lease
        except Exception:
            raise MaterialAccessDenied(_UNAVAILABLE) from None
        finally:
            _clear_candidate(candidate)
            self._lock.release()

    def _clear(self) -> None:
        _clear_candidate(self._buffers)
        self._buffers = None

    def _consume_for_ldap_transport(
        self,
        binding: LdapServerCreateBinding,
        lease: MaterialLease,
        request: MaterialLeaseRequest,
        transport: LdapServerMaterialTransport,
    ) -> MaterialUseOutcome:
        if not self._lock.acquire(blocking=False):
            return MaterialUseOutcome.FAILED
        views: tuple[memoryview, memoryview] | None = None
        try:
            if lease is not self._lease or self._lease is None or self._consumed:
                return MaterialUseOutcome.FAILED
            # An attempted consumption of our lease is terminal even if its
            # supplied context is invalid. The coordinator must reconcile.
            self._consumed = True
            status = self._context_status(binding, request)
            if status is MaterialBindingStatus.EXPIRED:
                return MaterialUseOutcome.TIMED_OUT
            if status is not MaterialBindingStatus.AVAILABLE or self._buffers is None:
                return MaterialUseOutcome.FAILED
            views = (memoryview(self._buffers[0]).toreadonly(),
                     memoryview(self._buffers[1]).toreadonly())
            outcome = transport._create_and_verify_with_material(binding, request, views[0], views[1])
            status = self._context_status(binding, request)
            if status is MaterialBindingStatus.EXPIRED:
                return MaterialUseOutcome.TIMED_OUT
            if status is not MaterialBindingStatus.AVAILABLE:
                return MaterialUseOutcome.FAILED
            if outcome is LdapServerCreateOutcome.VERIFIED_CREATED:
                return MaterialUseOutcome.VERIFIED
            if outcome is LdapServerCreateOutcome.RECONCILIATION_REQUIRED:
                return MaterialUseOutcome.AMBIGUOUS
            return MaterialUseOutcome.FAILED
        except TimeoutError:
            return MaterialUseOutcome.TIMED_OUT
        except Exception:
            return MaterialUseOutcome.FAILED
        finally:
            if views is not None:
                for view in views:
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
            if status is not MaterialBindingStatus.AVAILABLE:
                return MaterialLeaseCompletion.UNKNOWN
            return MaterialLeaseCompletion.RELEASED
        finally:
            self._lock.release()

    def release_lease(self, lease: MaterialLease) -> MaterialLeaseCompletion:
        return self._finish(lease, revoked=False)

    def revoke_lease(
        self, lease: MaterialLease, *, reason: MaterialRevocationReason,
    ) -> MaterialLeaseCompletion:
        if type(reason) is not MaterialRevocationReason:
            raise MaterialAccessDenied(_UNAVAILABLE)
        return self._finish(lease, revoked=True)


class LdapServerLeaseTransport(_OpaqueC3Object):
    """Connect the fixed transport to the shared material lease coordinator."""

    __slots__ = ("_provider", "_transport")
    _display_name = "LdapServerLeaseTransport"

    def __init__(self, provider: LdapServerMaterialProvider, transport: LdapServerMaterialTransport) -> None:
        if (not isinstance(provider, LdapServerMaterialProvider)
            or not callable(getattr(transport, "_create_and_verify_with_material", None))):
            raise MaterialAccessDenied(_UNAVAILABLE)
        self._provider = provider
        self._transport = transport

    def consume(self, lease: MaterialLease) -> MaterialUseOutcome:
        return self._provider._consume_for_ldap_transport(
            self._provider._binding, lease, self._provider._request, self._transport,
        )

    def create_and_verify(
        self, binding: LdapServerCreateBinding, lease: MaterialLease, request: MaterialLeaseRequest,
    ) -> LdapServerCreateOutcome:
        outcome = self._provider._consume_for_ldap_transport(binding, lease, request, self._transport)
        return (LdapServerCreateOutcome.VERIFIED_CREATED if outcome is MaterialUseOutcome.VERIFIED
                else LdapServerCreateOutcome.RECONCILIATION_REQUIRED)
