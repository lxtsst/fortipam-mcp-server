"""Inactive three-slot Approval Email lease, not an observed-token relay.

A host-prebound resolver transfers three new mutable buffers. No resolver,
inventory access, HTTP binding, grant issuer or MCP entry is supplied. Only the
existing protected executor may compose this with its material-use coordinator.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from contextlib import ExitStack
from dataclasses import dataclass
import hmac
from threading import RLock
import time
from typing import Protocol, cast, runtime_checkable

from v4_planning import canonical_digest
from v4_planning.material_provider import (
    C3MaterialBinding, MaterialAccessDenied, MaterialBindingStatus, MaterialLease,
    MaterialLeaseCompletion, MaterialLeaseRequest, MaterialProviderClass,
    MaterialPurpose, MaterialRevocationReason, _OpaqueC3Object,
)
from v4_planning.material_runtime import MaterialUseOutcome

from .approval_delivery_material_contract import ApprovalDeliveryMaterialDraft, _LOCAL_MATERIAL_BYTES, _ROLES, _pins
from .mutable_json_buffer import _erase_transfer_storage
from .secret_create_191_http_transport import _valid_utf8

CONTRACT = "fortipam-build29-approval-email-three-slot-lease-local/v1"
_ERROR = "The private approval-delivery material lease is unavailable."


@runtime_checkable
class ApprovalDeliveryMaterialResolver(Protocol):
    @property
    def binding_digest(self) -> str: ...
    def validate_prebound(self) -> MaterialBindingStatus: ...
    def load_approval_material_once(self) -> tuple[bytearray, bytearray, bytearray]:
        """Transfer fresh owned username/credential/client-secret, in that order.

        No borrowed cache, observed response token or caller-selected lookup is
        accepted. The resolver must clean any untransferred data on its errors.
        """
        ...


@dataclass(frozen=True, slots=True, repr=False, init=False)
class ApprovalDeliveryMaterialBinding(C3MaterialBinding):
    intent_digest: str
    material_binding_digest: str
    action_id: str
    purpose: MaterialPurpose
    _enabled: bool
    _protocol: str
    _source_pins: tuple[str, str, str]

    def __init__(self, draft: ApprovalDeliveryMaterialDraft, *, restore: bool = False) -> None:
        try:
            if (type(draft) is not ApprovalDeliveryMaterialDraft or type(restore) is not bool
                    or draft._source_pins != _pins()):
                raise ValueError
            phase = "restore" if restore else "configure"
            attributes = dict(intent_digest=canonical_digest(dict(contract=CONTRACT, phase=phase,
                    input=draft.input_nonmaterial_digest, request=draft.request_nonmaterial_digest)),
                material_binding_digest=canonical_digest(dict(contract=CONTRACT,
                    roles=dict(zip(_ROLES, draft._binding_digests, strict=True)))),
                action_id="approval-delivery-" + phase, purpose=MaterialPurpose.JIT_DELIVERY,
                _enabled=draft.enabled, _protocol=draft.protocol, _source_pins=draft._source_pins)
            for name, value in attributes.items():
                object.__setattr__(self, name, value)
        except Exception:
            raise MaterialAccessDenied(_ERROR) from None


def _erase_transferred(value: object) -> None:
    """Attempt every transferred mutable owner, including malformed bundles."""
    items: Iterable[object]
    if type(value) in (tuple, list):
        items = cast(tuple[object, ...] | list[object], value)
    elif type(value) is dict:
        items = cast(dict[object, object], value).values()
    else:
        items = (value,)
    failure: BaseException | None = None
    for item in items:
        if type(item) is bytearray:
            try:
                _erase_transfer_storage(item)
            except BaseException as error:
                if failure is None:
                    failure = error
    if failure is not None:
        if isinstance(failure, Exception):
            raise MaterialAccessDenied(_ERROR) from None
        raise failure


class _ApprovalDeliveryLease(MaterialLease):
    __slots__ = ()


class ApprovalDeliveryMaterialProvider(_OpaqueC3Object):
    """One exact request/load/use; all slots, including inactive ones, are owned.

    JIT_DELIVERY is private fixed-configuration consumption, not credential
    rotation or user delivery. This provider is not an availability/custody
    producer. The host must qualify its source before any operational binding.
    """

    def __init__(self, resolver: ApprovalDeliveryMaterialResolver, binding: ApprovalDeliveryMaterialBinding,
            request: MaterialLeaseRequest, *, clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (not isinstance(resolver, ApprovalDeliveryMaterialResolver)
                    or type(binding) is not ApprovalDeliveryMaterialBinding or type(request) is not MaterialLeaseRequest
                    or not callable(clock) or request.action_id != binding.action_id or request.action_version != "1.0.0"
                    or request.provider_class is not MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE
                    or request.purpose is not binding.purpose or request.expires_at - request.requested_at > 60):
                raise ValueError
            reference = resolver.binding_digest
            if type(reference) is not str or not hmac.compare_digest(reference, binding.material_binding_digest):
                raise ValueError
            request.__post_init__()
            self._resolver, self._binding, self._request, self._clock = resolver, binding, request, clock
            self._last_now, self._closed, self._failed = -1, False, False
            self._attempted = self._consumed = False
            self._checking = False
            self._buffers: tuple[bytearray, ...] = ()
            self._lease: _ApprovalDeliveryLease | None = None
            self._lock = RLock()
        except Exception:
            raise MaterialAccessDenied(_ERROR) from None

    def _matches(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> bool:
        return binding is self._binding and type(request) is MaterialLeaseRequest and request == self._request

    def _clear(self) -> None:
        buffers, self._buffers = self._buffers, ()
        _erase_transferred(buffers)

    def _context_status(self) -> MaterialBindingStatus:
        now, reference = self._clock(), self._resolver.binding_digest
        if (self._failed or self._closed or type(now) is not int or now < self._last_now
                or now < self._request.requested_at or type(reference) is not str
                or not hmac.compare_digest(reference, self._binding.material_binding_digest)
                or self._binding._source_pins != _pins()):
            raise ValueError
        self._last_now = now
        if now >= self._request.expires_at:
            self._clear()
            return MaterialBindingStatus.EXPIRED
        return MaterialBindingStatus.AVAILABLE

    def _status(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> MaterialBindingStatus:
        if not self._matches(binding, request):
            return MaterialBindingStatus.INCOMPATIBLE
        if self._checking:
            return MaterialBindingStatus.UNAVAILABLE
        self._checking = True
        try:
            status = self._context_status()
            if status is not MaterialBindingStatus.AVAILABLE:
                return status
            if self._resolver.validate_prebound() is not MaterialBindingStatus.AVAILABLE:
                raise ValueError
            return self._context_status()
        except BaseException as error:
            self._failed = True
            self._clear()
            if not isinstance(error, Exception):
                raise
            return MaterialBindingStatus.UNAVAILABLE
        finally:
            self._checking = False

    def validate_binding(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> MaterialBindingStatus:
        if not self._matches(binding, request):
            return MaterialBindingStatus.INCOMPATIBLE
        try:
            with self._lock:
                status = self._status(binding, request)
                return MaterialBindingStatus.UNAVAILABLE if self._attempted and status is MaterialBindingStatus.AVAILABLE else status
        except BaseException as error:
            self._failed = True
            self.close()
            if isinstance(error, Exception):
                return MaterialBindingStatus.UNAVAILABLE
            raise

    def acquire_lease(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> MaterialLease:
        if not self._matches(binding, request):
            raise MaterialAccessDenied(_ERROR)
        candidate: object = None
        owns_attempt = False
        try:
            try:
                with self._lock:
                    if self._attempted or self._checking:
                        raise MaterialAccessDenied(_ERROR)
                    # Claim before clock/reference/status callbacks can reenter.
                    owns_attempt = True
                    self._attempted = True
                    if self._status(binding, request) is not MaterialBindingStatus.AVAILABLE:
                        raise ValueError
                    candidate = self._resolver.load_approval_material_once()
                    if type(candidate) is not tuple or len(candidate) != 3:
                        raise ValueError
                    if any(type(value) is not bytearray for value in candidate) or len({id(value) for value in candidate}) != 3:
                        raise ValueError
                    buffers = cast(tuple[bytearray, ...], candidate)
                    for buffer in buffers:
                        if len(buffer) > _LOCAL_MATERIAL_BYTES:
                            raise ValueError
                        with memoryview(buffer) as view:
                            if not _valid_utf8(view):
                                raise ValueError
                    active = 1 if self._binding._protocol == "imaps" else 2
                    if self._binding._enabled and (not buffers[0] or not buffers[active]):
                        raise ValueError
                    if self._status(binding, request) is not MaterialBindingStatus.AVAILABLE:
                        raise ValueError
                    lease = _ApprovalDeliveryLease()
                    self._buffers, self._lease, candidate = buffers, lease, None
                    return lease
            except BaseException:
                try:
                    if owns_attempt:
                        self._failed = True
                        self.close()
                finally:
                    _erase_transferred(candidate)
                raise
        except Exception:
            raise MaterialAccessDenied(_ERROR) from None

    def consume(self, binding: ApprovalDeliveryMaterialBinding, lease: MaterialLease, request: MaterialLeaseRequest,
            consumer: Callable[[memoryview, memoryview, memoryview], MaterialUseOutcome]) -> MaterialUseOutcome:
        if (not self._matches(binding, request) or lease is not self._lease
                or self._lease is None or self._consumed):
            return MaterialUseOutcome.FAILED
        try:
            try:
                with self._lock:
                    if self._consumed:
                        return MaterialUseOutcome.FAILED
                    self._consumed = True
                    try:
                        if self._status(binding, request) is not MaterialBindingStatus.AVAILABLE or len(self._buffers) != 3:
                            return MaterialUseOutcome.FAILED
                        with ExitStack() as views:
                            username, credential, client_secret = tuple(
                                views.enter_context(memoryview(buffer).toreadonly()) for buffer in self._buffers)
                            outcome = consumer(username, credential, client_secret)
                        status = self._status(binding, request)
                        if status is MaterialBindingStatus.EXPIRED:
                            return MaterialUseOutcome.TIMED_OUT
                        if status is not MaterialBindingStatus.AVAILABLE:
                            return MaterialUseOutcome.FAILED
                        return outcome if type(outcome) is MaterialUseOutcome else MaterialUseOutcome.FAILED
                    finally:
                        self._clear()
            except BaseException:
                self.close()
                raise
        except Exception:
            raise MaterialAccessDenied(_ERROR) from None

    def release_lease(self, lease: MaterialLease) -> MaterialLeaseCompletion:
        if lease is not self._lease or self._lease is None or not self._consumed:
            raise MaterialAccessDenied(_ERROR)
        try:
            with self._lock:
                status = self._status(self._binding, self._request)
        finally:
            self.close()
        return MaterialLeaseCompletion.RELEASED if status is MaterialBindingStatus.AVAILABLE else MaterialLeaseCompletion.UNKNOWN

    def revoke_lease(self, lease: MaterialLease, *, reason: MaterialRevocationReason) -> MaterialLeaseCompletion:
        if lease is not self._lease or self._lease is None or type(reason) is not MaterialRevocationReason:
            raise MaterialAccessDenied(_ERROR)
        self.close()
        return MaterialLeaseCompletion.REVOKED

    def close(self) -> None:
        self._closed = True
        try:
            with self._lock:
                self._clear()
        except BaseException:
            # Cancellation while waiting for the owner lock must still finish
            # disposal before it escapes. Failed wipes already erase in place.
            with self._lock:
                self._clear()
            raise
