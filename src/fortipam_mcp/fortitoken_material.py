"""Unregistered action-bound FortiToken selector lease; no material source.

The prebound resolver transfers one fresh bytearray to one private consumer.
Revoke uses JIT_DELIVERY solely to match the existing selector, without user
delivery, activation or credential rotation. No MCP or execution registration.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from threading import RLock
import time
from typing import Protocol, cast, runtime_checkable

from v4_planning.material_provider import (C3MaterialBinding, MaterialAccessDenied, MaterialBindingStatus,
    MaterialLease, MaterialLeaseCompletion, MaterialLeaseRequest, MaterialProviderClass,
    MaterialPurpose, MaterialRevocationReason, _OpaqueC3Object)
from v4_planning.material_runtime import MaterialUseOutcome

from .fortitoken_user_contract import FortitokenUserPlan, _validate_token, expected_fortitoken_user_state
from .secret_metadata_http_transport import _zeroize_mutable

_ERROR = 'The private FortiToken material lease is unavailable.'


@runtime_checkable
class FortitokenMaterialResolver(Protocol):
    @property
    def binding_digest(self) -> str: ...
    def validate_prebound(self) -> MaterialBindingStatus: ...
    def load_token_once(self) -> bytearray:
        """Transfer one new owned buffer, never a shared cache or string."""
        ...


@dataclass(frozen=True, slots=True, repr=False, init=False)
class FortitokenMaterialBinding(C3MaterialBinding):
    intent_digest: str
    token_reference_digest: str
    action_id: str
    purpose: MaterialPurpose

    def __init__(self, plan: FortitokenUserPlan, *, restore: bool = False) -> None:
        try:
            if type(plan) is not FortitokenUserPlan or type(restore) is not bool: raise ValueError
            plan.__post_init__()
            selected = FortitokenUserPlan(expected_fortitoken_user_state(plan),
                'revoke' if plan.operation == 'assign' else 'assign') if restore else plan
            if restore and expected_fortitoken_user_state(selected).digest != plan.current.digest: raise ValueError
            for name,value in dict(intent_digest=selected.digest,token_reference_digest=plan.current.binding.token_reference_digest,
                    action_id='fortitoken-user-'+plan.operation+('-restore' if restore else ''),purpose=MaterialPurpose.INITIAL_ONBOARDING
                    if selected.operation == 'assign' else MaterialPurpose.JIT_DELIVERY).items():
                object.__setattr__(self,name,value)
        except Exception: raise MaterialAccessDenied(_ERROR) from None


class _FortitokenLease(MaterialLease):
    __slots__ = ()


class FortitokenMaterialProvider(_OpaqueC3Object):
    """One exact control request, one loading attempt and one private use."""
    def __init__(self, resolver: FortitokenMaterialResolver, binding: FortitokenMaterialBinding,
            request: MaterialLeaseRequest, *, clock: Callable[[],int] = lambda:int(time.time())) -> None:
        try:
            if (not isinstance(resolver,FortitokenMaterialResolver) or type(binding) is not FortitokenMaterialBinding
                    or type(request) is not MaterialLeaseRequest or not callable(clock)
                    or resolver.binding_digest != binding.token_reference_digest or request.action_id != binding.action_id
                    or request.action_version != '1.0.0' or request.purpose is not binding.purpose
                    or request.provider_class is not MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE
                    or request.expires_at-request.requested_at > 60): raise ValueError
            request.__post_init__()
            self._resolver,self._binding,self._request,self._clock = resolver,binding,request,clock
            self._last_now,self._closed,self._failed = -1,False,False
            self._attempted = self._consumed = False
            self._buffer: bytearray | None = None
            self._lease: _FortitokenLease | None = None
            self._lock = RLock()
        except Exception: raise MaterialAccessDenied(_ERROR) from None

    def _clear(self) -> None:
        if self._buffer is not None: _zeroize_mutable(self._buffer)
        self._buffer = None

    def _status(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> MaterialBindingStatus:
        if binding is not self._binding or type(request) is not MaterialLeaseRequest or request != self._request:
            return MaterialBindingStatus.INCOMPATIBLE
        try:
            def current_status() -> MaterialBindingStatus:
                now = self._clock()
                if (self._closed or self._failed or type(now) is not int or now < self._last_now
                        or now < request.requested_at or self._resolver.binding_digest != self._binding.token_reference_digest): raise ValueError
                self._last_now = now
                if now >= request.expires_at:
                    self._clear()
                    return MaterialBindingStatus.EXPIRED
                return MaterialBindingStatus.AVAILABLE
            status = current_status()
            if status is not MaterialBindingStatus.AVAILABLE: return status
            if self._resolver.validate_prebound() is not MaterialBindingStatus.AVAILABLE: raise ValueError
            return current_status()
        except Exception:
            self._failed = True; self._clear()
            return MaterialBindingStatus.UNAVAILABLE

    def validate_binding(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> MaterialBindingStatus:
        with self._lock:
            status = self._status(binding,request)
            return MaterialBindingStatus.UNAVAILABLE if self._attempted else status

    def acquire_lease(self, binding: C3MaterialBinding, request: MaterialLeaseRequest) -> MaterialLease:
        candidate: object = None
        with self._lock:
            try:
                if self._attempted or self._status(binding,request) is not MaterialBindingStatus.AVAILABLE: raise ValueError
                self._attempted = True; candidate = self._resolver.load_token_once()
                if type(candidate) is not bytearray: raise ValueError
                with memoryview(candidate) as view: _validate_token(view)
                if self._status(binding,request) is not MaterialBindingStatus.AVAILABLE: raise ValueError
                self._buffer,candidate = candidate,None
                self._lease = _FortitokenLease()
                return self._lease
            except Exception: raise MaterialAccessDenied(_ERROR) from None
            finally:
                items = cast(tuple[object,...] | list[object],candidate) if type(candidate) in (tuple,list) else (candidate,)
                for item in items:
                    if type(item) is bytearray: _zeroize_mutable(item)

    def consume(self, binding: FortitokenMaterialBinding, lease: MaterialLease, request: MaterialLeaseRequest,
            consumer: Callable[[memoryview],MaterialUseOutcome]) -> MaterialUseOutcome:
        with self._lock:
            if lease is not self._lease or self._lease is None or self._consumed: return MaterialUseOutcome.FAILED
            self._consumed = True
            try:
                if self._status(binding,request) is not MaterialBindingStatus.AVAILABLE or self._buffer is None:
                    return MaterialUseOutcome.FAILED
                with memoryview(self._buffer).toreadonly() as view: outcome = consumer(view)
                status = self._status(binding,request)
                if status is MaterialBindingStatus.EXPIRED: return MaterialUseOutcome.TIMED_OUT
                if status is not MaterialBindingStatus.AVAILABLE: return MaterialUseOutcome.FAILED
                return outcome if type(outcome) is MaterialUseOutcome else MaterialUseOutcome.FAILED
            finally: self._clear()

    def release_lease(self, lease: MaterialLease) -> MaterialLeaseCompletion:
        with self._lock:
            if lease is not self._lease or self._lease is None or not self._consumed: raise MaterialAccessDenied(_ERROR)
            status = self._status(self._binding,self._request); self.close()
            return MaterialLeaseCompletion.RELEASED if status is MaterialBindingStatus.AVAILABLE else MaterialLeaseCompletion.UNKNOWN

    def revoke_lease(self, lease: MaterialLease, *, reason: MaterialRevocationReason) -> MaterialLeaseCompletion:
        with self._lock:
            if lease is not self._lease or self._lease is None or type(reason) is not MaterialRevocationReason: raise MaterialAccessDenied(_ERROR)
            self.close(); return MaterialLeaseCompletion.REVOKED

    def close(self) -> None:
        with self._lock:
            self._closed = True; self._clear()
