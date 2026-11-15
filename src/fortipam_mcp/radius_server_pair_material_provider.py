"""Private paired lease with durable reservation before either source is loaded.

Acquisition cannot roll back either source. Both values are delivered together,
or all acquired buffers are cleared and the group remains consumed. No loader,
M4 authority, HTTP transport, worker deployment or MCP registration is provided.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
import hmac
from threading import Lock
import time
from typing import Literal, Protocol

from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import (
    C3MaterialBinding, MaterialAccessDenied, MaterialBindingStatus, MaterialLease,
    MaterialLeaseCompletion, MaterialLeaseRequest, MaterialProviderClass,
    MaterialPurpose, MaterialRevocationReason, _OpaqueC3Object,
)
from v4_planning.material_runtime import (
    MaterialRuntimeOutcome, MaterialUseClaimState, MaterialUseOutcome, material_lease_request_digest,
)
from v4_planning.models import require_digest

from .ldap_server_projection import _digest
from .radius_server_contract import RadiusServerCreateOutcome
from .radius_server_material_provider import _clear_candidate
from .radius_server_pair_contract import ACTION_ID, ACTION_VERSION, CONTRACT, RadiusServerPairBinding, _material

_ERROR = "The private paired RADIUS material provider is unavailable."


class RadiusServerPairMaterialLoader(Protocol):
    """Trusted fixed sources; validation reads metadata only, never material."""

    def validate_prebound(self, binding: RadiusServerPairBinding, request: MaterialLeaseRequest,
                         source_policy_digest: str) -> MaterialBindingStatus: ...

    def load_endpoint_once(self, binding: RadiusServerPairBinding, request: MaterialLeaseRequest,
            ordinal: Literal["primary", "secondary"], source_policy_digest: str) -> bytearray: ...


class RadiusServerPairMaterialTransport(Protocol):
    def _create_and_verify_pair_material(self, binding: RadiusServerPairBinding, request: MaterialLeaseRequest,
            primary: memoryview, secondary: memoryview) -> RadiusServerCreateOutcome: ...


class _PairLease(MaterialLease):
    __slots__ = ()


class RadiusServerPairMaterialProvider(_OpaqueC3Object):
    """One prebound pair, one request, one durable source-group reservation."""

    __slots__ = ("_binding", "_parameters", "_request", "_request_digest", "_source_digest",
        "_loader", "_store", "_reservation", "_owned", "_guard", "_enabled", "_clock",
        "_last_clock", "_clock_failed", "_lock", "_attempted", "_lease", "_buffers", "_consumed", "_verified")
    _display_name = "RadiusServerPairMaterialProvider"

    def __init__(self, loader: RadiusServerPairMaterialLoader, *, binding: RadiusServerPairBinding,
            request: MaterialLeaseRequest, source_policy_digest: str,
            source_reservation_store: PersistentMaterialUseStateStore,
            execution_guard: Callable[[RadiusServerPairBinding, MaterialLeaseRequest], None],
            acquisition_enabled: bool = False, clock: Callable[[], int] | None = None) -> None:
        try:
            if (type(binding) is not RadiusServerPairBinding or type(request) is not MaterialLeaseRequest
                    or type(source_reservation_store) is not PersistentMaterialUseStateStore
                    or type(acquisition_enabled) is not bool or not callable(execution_guard)
                    or clock is not None and not callable(clock)):
                raise ValueError
            pinned = replace(request)
            if (pinned.action_id != ACTION_ID or pinned.action_version != ACTION_VERSION
                    or pinned.provider_class is not MaterialProviderClass.OWNED_LAB_FIXTURE_REFERENCE
                    or pinned.purpose is not MaterialPurpose.INITIAL_ONBOARDING
                    or pinned.expires_at - pinned.requested_at > 60
                    or not callable(getattr(loader, "validate_prebound", None))
                    or not callable(getattr(loader, "load_endpoint_once", None))):
                raise ValueError
            require_digest(source_policy_digest, "source_policy_digest")
            self._binding, self._parameters = binding, binding.parameters_digest
            self._request, self._request_digest = pinned, material_lease_request_digest(pinned)
            self._source_digest, self._loader, self._store = source_policy_digest, loader, source_reservation_store
            # Stable across request/authorization renewal for this bound pair.
            self._reservation = _digest({"contract": CONTRACT + ":source-group-v1", "parameters": self._parameters})
            self._guard, self._enabled = execution_guard, acquisition_enabled
            self._clock = clock or (lambda: int(time.time()))
            self._last_clock: int | None = None
            self._clock_failed = False
            self._lock = Lock()
            self._attempted = self._owned = self._consumed = self._verified = False
            self._lease: _PairLease | None = None
            self._buffers: tuple[bytearray, bytearray] | None = None
        except Exception:
            raise MaterialAccessDenied(_ERROR) from None

    def _matches(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> bool:
        try:
            return (binding is self._binding and binding.parameters_digest == self._parameters
                and type(request) is MaterialLeaseRequest and request == self._request
                and material_lease_request_digest(request) == self._request_digest)
        except Exception:
            return False

    def _status(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> MaterialBindingStatus:
        try:
            if not self._matches(binding, request):
                return MaterialBindingStatus.INCOMPATIBLE
            now = self._clock()
            if (self._clock_failed or type(now) is not int or now < request.requested_at
                    or self._last_clock is not None and now < self._last_clock):
                self._clock_failed = True
                raise ValueError
            self._last_clock = now
            if now >= request.expires_at:
                return MaterialBindingStatus.EXPIRED
            return MaterialBindingStatus.AVAILABLE if self._enabled else MaterialBindingStatus.UNAVAILABLE
        except Exception:
            self._clock_failed = True
            return MaterialBindingStatus.UNAVAILABLE

    def _check(self) -> None:
        status = self._status(self._binding, self._request)
        if status is MaterialBindingStatus.EXPIRED:
            raise TimeoutError
        if status is not MaterialBindingStatus.AVAILABLE:
            raise ValueError
        if self._guard(self._binding, self._request) is not None:
            raise ValueError
        status = self._status(self._binding, self._request)
        if status is MaterialBindingStatus.EXPIRED:
            raise TimeoutError
        if status is not MaterialBindingStatus.AVAILABLE:
            raise ValueError
        if self._owned:
            claim = self._store._inspect_claim(request_digest=self._reservation,
                authorization_digest=self._request.authorization_digest)
            if claim.state is not MaterialUseClaimState.IN_PROGRESS:
                raise ValueError

    def _validate(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> MaterialBindingStatus:
        status = self._status(binding, request)
        if status is not MaterialBindingStatus.AVAILABLE:
            return status
        if self._attempted or self._store.claim_count != 0:
            return MaterialBindingStatus.UNAVAILABLE
        self._check()
        result = self._loader.validate_prebound(self._binding, self._request, self._source_digest)
        self._check()
        return result if type(result) is MaterialBindingStatus else MaterialBindingStatus.UNAVAILABLE

    def validate_binding(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> MaterialBindingStatus:
        if not self._lock.acquire(blocking=False):
            return MaterialBindingStatus.UNAVAILABLE
        try:
            status = self._validate(binding, request)
            if status is MaterialBindingStatus.EXPIRED or self._clock_failed or not self._enabled:
                self._clear()
                self._finalize(MaterialRuntimeOutcome.RECONCILIATION_REQUIRED)
            return status
        except Exception:
            return MaterialBindingStatus.UNAVAILABLE
        finally:
            self._lock.release()

    def _finalize(self, outcome: MaterialRuntimeOutcome) -> bool:
        if not self._owned:
            return False
        try:
            self._store.finalize(request_digest=self._reservation,
                authorization_digest=self._request.authorization_digest, outcome=outcome)
            return True
        except Exception:
            return False
        finally:
            self._owned = False

    def acquire_lease(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> MaterialLease:
        if not self._lock.acquire(blocking=False):
            raise MaterialAccessDenied(_ERROR)
        primary: object = None
        secondary: object = None
        try:
            if self._validate(binding, request) is not MaterialBindingStatus.AVAILABLE:
                raise ValueError
            self._attempted = True
            claim = self._store.claim(request_digest=self._reservation,
                authorization_digest=self._request.authorization_digest)
            if claim.state is not MaterialUseClaimState.NEW:
                raise ValueError
            self._owned = True
            self._check()
            primary = self._loader.load_endpoint_once(self._binding, self._request, "primary", self._source_digest)
            if type(primary) is not bytearray:
                raise ValueError
            self._check()
            with memoryview(primary).toreadonly() as view:
                if not _material(view):
                    raise ValueError
            secondary = self._loader.load_endpoint_once(self._binding, self._request, "secondary", self._source_digest)
            if type(secondary) is not bytearray or secondary is primary:
                raise ValueError
            self._check()
            with memoryview(primary).toreadonly() as p, memoryview(secondary).toreadonly() as s:
                if not _material(p) or not _material(s) or hmac.compare_digest(p, s):
                    raise ValueError
            self._buffers = primary, secondary
            primary = secondary = None
            self._lease = _PairLease()
            return self._lease
        except Exception:
            self._clear()
            self._finalize(MaterialRuntimeOutcome.RECONCILIATION_REQUIRED)
            raise MaterialAccessDenied(_ERROR) from None
        finally:
            _clear_candidate(primary)
            _clear_candidate(secondary)
            self._lock.release()

    def _clear(self) -> None:
        _clear_candidate(self._buffers)
        self._buffers = None

    def _consume(self, lease: MaterialLease, transport: RadiusServerPairMaterialTransport) -> MaterialUseOutcome:
        if not self._lock.acquire(blocking=False):
            return MaterialUseOutcome.FAILED
        try:
            if self._lease is None or lease is not self._lease or self._consumed:
                return MaterialUseOutcome.FAILED
            self._consumed = True
            self._check()
            if self._buffers is None:
                raise ValueError
            with memoryview(self._buffers[0]).toreadonly() as p, memoryview(self._buffers[1]).toreadonly() as s:
                if not _material(p) or not _material(s) or hmac.compare_digest(p, s):
                    raise ValueError
                outcome = transport._create_and_verify_pair_material(self._binding, self._request, p, s)
            self._check()
            if outcome is RadiusServerCreateOutcome.VERIFIED_CREATED:
                self._verified = True
                return MaterialUseOutcome.VERIFIED
            return MaterialUseOutcome.AMBIGUOUS if outcome is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED else MaterialUseOutcome.FAILED
        except TimeoutError:
            return MaterialUseOutcome.TIMED_OUT
        except Exception:
            return MaterialUseOutcome.FAILED
        finally:
            if lease is self._lease:
                self._clear()
            self._lock.release()

    def _finish(self, lease: MaterialLease, *, revoked: bool) -> MaterialLeaseCompletion:
        if not self._lock.acquire(blocking=False):
            raise MaterialAccessDenied(_ERROR)
        try:
            if self._lease is None or lease is not self._lease:
                raise MaterialAccessDenied(_ERROR)
            status = self._status(self._binding, self._request)
            self._clear()
            self._lease = None
            verified = not revoked and self._verified and status is MaterialBindingStatus.AVAILABLE
            if not self._finalize(MaterialRuntimeOutcome.VERIFIED_AND_RELEASED if verified
                    else MaterialRuntimeOutcome.RECONCILIATION_REQUIRED):
                return MaterialLeaseCompletion.UNKNOWN
            if revoked:
                return MaterialLeaseCompletion.REVOKED
            if status is MaterialBindingStatus.EXPIRED:
                return MaterialLeaseCompletion.EXPIRED
            return MaterialLeaseCompletion.RELEASED if verified else MaterialLeaseCompletion.UNKNOWN
        finally:
            self._lock.release()

    def release_lease(self, lease: MaterialLease) -> MaterialLeaseCompletion:
        return self._finish(lease, revoked=False)

    def revoke_lease(self, lease: MaterialLease, *, reason: MaterialRevocationReason) -> MaterialLeaseCompletion:
        if type(reason) is not MaterialRevocationReason:
            raise MaterialAccessDenied(_ERROR)
        return self._finish(lease, revoked=True)

    def close(self) -> None:
        self._enabled = False
        if self._lock.acquire(blocking=False):
            try:
                self._clear()
                self._finalize(MaterialRuntimeOutcome.RECONCILIATION_REQUIRED)
            finally:
                self._lock.release()


class RadiusServerPairLeaseTransport(_OpaqueC3Object):
    """Fixed two-view handoff for the existing C3 coordinator."""

    __slots__ = ("_provider", "_transport")
    _display_name = "RadiusServerPairLeaseTransport"

    def __init__(self, provider: RadiusServerPairMaterialProvider, transport: RadiusServerPairMaterialTransport) -> None:
        if (type(provider) is not RadiusServerPairMaterialProvider
                or not callable(getattr(transport, "_create_and_verify_pair_material", None))):
            raise MaterialAccessDenied(_ERROR)
        self._provider, self._transport = provider, transport

    def consume(self, lease: MaterialLease) -> MaterialUseOutcome:
        return self._provider._consume(lease, self._transport)
