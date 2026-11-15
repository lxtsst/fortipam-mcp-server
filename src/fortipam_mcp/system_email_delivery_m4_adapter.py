"""Local-only M4 test-mail effect with distinct configuration and send ledgers.

Backend receipts/capture observations are protocol data, not native ACK or
receiver provenance. No native transport is implemented or enabled here.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass,replace
from threading import RLock
import hmac
import time
from typing import Protocol,runtime_checkable

from v4_planning import (
    DenyAllM4AuthorizationVerifier,M4AdapterAmbiguous,M4AdapterDenied,
    M4AuthorizationVerifier,M4ExecutionAuthorization,M4ExecutionPlan,canonical_digest,
)
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .m4_execution_store import PersistentM4ExecutionStateStore
from .system_email_delivery_contract import SystemEmailCaptureObservation,SystemEmailDeliveryBinding
from .system_email_m4_adapter import SystemEmailBackendReceipt,SystemEmailM4Adapter,system_email_state_digest
from .system_email_native_source import SystemEmailSourceBoundDraft

CONTRACT="fortipam_v4_system_email_local_delivery_candidate_v1"
_ERROR="The private system-email test delivery is unavailable."


@dataclass(frozen=True,slots=True,repr=False)
class SystemEmailDeliveryInspection(_OpaqueC3Object):
    configuration: SystemEmailSourceBoundDraft
    capture: SystemEmailCaptureObservation
    sender_in_flight: int
    quiescence_complete: bool

    def __post_init__(self) -> None:
        if (type(self.configuration)is not SystemEmailSourceBoundDraft
                or type(self.capture)is not SystemEmailCaptureObservation
                or type(self.sender_in_flight)is not int or self.sender_in_flight<0
                or type(self.quiescence_complete)is not bool):raise ValueError(_ERROR)


def validate_delivery_scope(binding: SystemEmailDeliveryBinding,snapshot: SystemEmailDeliveryInspection,*,
        window_digest: str|None=None,require_capture: bool=True) -> None:
    if (type(binding)is not SystemEmailDeliveryBinding or type(snapshot)is not SystemEmailDeliveryInspection
            or system_email_state_digest(snapshot.configuration)!=binding.configuration_digest
            or snapshot.configuration.source_serial_digest!=binding.source_serial_digest
            or snapshot.capture.capture_scope_digest!=binding.capture_scope_digest
            or snapshot.capture.recipient_digest!=binding.recipient_digest
            or (window_digest is not None and snapshot.capture.window_digest!=window_digest)
            or (require_capture and not snapshot.capture.complete)
            or not snapshot.quiescence_complete or snapshot.sender_in_flight!=0):
        raise ValueError(_ERROR)


def delivery_state_digest(binding: SystemEmailDeliveryBinding,snapshot: SystemEmailDeliveryInspection) -> str:
    return canonical_digest({"contract":CONTRACT,"binding":binding.parameters_digest,
        "configuration":system_email_state_digest(snapshot.configuration),
        "scope":snapshot.capture.capture_scope_digest,"recipient":snapshot.capture.recipient_digest,
        "window":snapshot.capture.window_digest,"complete":snapshot.capture.complete,
        "messages":snapshot.capture.matched_messages,"in_flight":snapshot.sender_in_flight,
        "quiescence_complete":snapshot.quiescence_complete})


def delivery_execution_digests(binding: SystemEmailDeliveryBinding,baseline: SystemEmailDeliveryInspection,
        context_digest: str) -> tuple[str,str,str]:
    require_digest(context_digest,"context_digest");validate_delivery_scope(binding,baseline)
    if baseline.capture.matched_messages!=0:raise ValueError(_ERROR)
    current=delivery_state_digest(binding,baseline)
    expected=delivery_state_digest(binding,replace(baseline,capture=replace(baseline.capture,matched_messages=1)))
    return current,expected,canonical_digest({"contract":CONTRACT,"context":context_digest,
        "binding":binding.parameters_digest,"current":current,"expected":expected})


@runtime_checkable
class SystemEmailDeliveryBackend(Protocol):
    def inspect(self,binding: SystemEmailDeliveryBinding) -> SystemEmailDeliveryInspection: ...

    def send_test(self,binding: SystemEmailDeliveryBinding,*,before_send: Callable[[],int],
        timeout_seconds: int) -> SystemEmailBackendReceipt: ...


class SystemEmailDeliveryM4Adapter(_OpaqueC3Object):
    """One owned test send; never retry or infer delivery from HTTP success."""

    def __init__(self,binding: SystemEmailDeliveryBinding,baseline: SystemEmailDeliveryInspection,
            configuration_update: SystemEmailM4Adapter,backend: SystemEmailDeliveryBackend,
            plan: M4ExecutionPlan,authorization: M4ExecutionAuthorization,
            store: PersistentM4ExecutionStateStore,*,context_digest: str,allowed_requester_digest: str,
            authorization_verifier: M4AuthorizationVerifier|None=None,execution_enabled: bool=False,
            clock: Callable[[],int]=lambda:int(time.time())) -> None:
        try:
            if (type(binding)is not SystemEmailDeliveryBinding or type(configuration_update)is not SystemEmailM4Adapter
                    or not isinstance(backend,SystemEmailDeliveryBackend)
                    or type(store)is not PersistentM4ExecutionStateStore
                    or type(execution_enabled)is not bool or not callable(clock)):
                raise ValueError
            configuration_update._require_verified_update()
            original=configuration_update._store
            if original.claim_count!=1:raise ValueError
            validate_delivery_store_separation(original,store)
            if execution_enabled and not store.monotonic_checkpoint_protocol_bound:raise ValueError
            if (binding.configuration_digest!=configuration_update._plan.expected_state_digest
                    or binding.source_serial_digest!=configuration_update._transition.original.source_serial_digest
                    or allowed_requester_digest!=configuration_update._requester
                    or context_digest!=configuration_update._binding):raise ValueError
            require_digest(allowed_requester_digest,"requester_digest")
            self._binding,self._baseline,self._configuration=binding,baseline,configuration_update
            self._backend,self._store,self._context=backend,store,context_digest
            self._plan,self._authorization=plan,authorization
            self._requester=allowed_requester_digest
            self._verifier=authorization_verifier or DenyAllM4AuthorizationVerifier()
            self._enabled,self._clock=execution_enabled,clock
            self._last_now=-1;self._lock=RLock();self._dispatched=False
            self._admitted=False;self._send_verified=False;self._receipt: SystemEmailBackendReceipt|None=None
            self._check_plan()
        except Exception:raise M4AdapterDenied(_ERROR)from None

    def _check_plan(self) -> None:
        current,expected,parameters=delivery_execution_digests(self._binding,self._baseline,self._context)
        p,a=self._plan,self._authorization;p.__post_init__();a.__post_init__()
        if (p.action_id!="system-email-test-delivery"or p.action_version!="1.0.0"or p.adapter_ref!=CONTRACT
                or p.revision!=1 or p.compensation_ref is not None or p.requester_digest!=self._requester
                or p.parameters_digest!=parameters or p.expected_current_digest!=current or p.expected_state_digest!=expected
                or p.plan_ref!="system-email-test-delivery-"+parameters
                or p.target_ref!="system-email-singleton-"+self._binding.source_serial_digest
                or p.idempotency_digest!=canonical_digest({"binding":parameters,"phase":"test-delivery"})
                or a.plan_ref!=p.plan_ref or a.plan_digest!=p.plan_digest or a.requester_digest!=p.requester_digest):raise ValueError

    def _check(self,plan: M4ExecutionPlan) -> None:
        try:
            if not self._enabled or plan is not self._plan:raise ValueError
            self._check_plan();now=self._clock()
            if (type(now)is not int or now<self._last_now
                    or not self._authorization.issued_at<=now<min(plan.expires_at,self._authorization.expires_at)):
                self._enabled=False;raise ValueError
            self._last_now=now;self._verifier.verify(plan,self._authorization,now_epoch=now)
        except Exception:raise M4AdapterDenied(_ERROR)from None

    def _inspect(self,*,require_capture: bool=True,for_restore: bool=False) -> SystemEmailDeliveryInspection:
        self._configuration._require_verified_update()
        # The restore kernel owns the second configuration claim before its
        # pre-send guard runs; this does not qualify another delivery claim.
        allowed=(1,2)if for_restore else(1,)
        if self._configuration._store.claim_count not in allowed:raise M4AdapterDenied(_ERROR)
        snapshot=self._backend.inspect(self._binding)
        validate_delivery_scope(self._binding,snapshot,window_digest=self._baseline.capture.window_digest,
            require_capture=require_capture)
        return snapshot

    def read_current(self,plan: M4ExecutionPlan) -> str:
        with self._lock:
            self._check(plan)
            try:return delivery_state_digest(self._binding,self._inspect())
            except Exception:raise M4AdapterAmbiguous(_ERROR)from None

    def _before_send(self,plan: M4ExecutionPlan) -> int:
        _require_m4_dispatch_ownership(plan,self._authorization,self._store)
        with self._lock:
            self._check(plan)
            if self._admitted:raise M4AdapterDenied(_ERROR)
            self._admitted=True;self._store.verify_ready()
            if self.read_current(plan)!=plan.expected_current_digest:raise M4AdapterDenied(_ERROR)
            self._check(plan);_require_m4_dispatch_ownership(plan,self._authorization,self._store)
            self._send_verified=True
            return min(plan.expires_at,self._authorization.expires_at)-self._last_now

    def dispatch(self,plan: M4ExecutionPlan) -> None:
        with self._lock:
            self._check(plan);_require_m4_dispatch_ownership(plan,self._authorization,self._store)
            if self._dispatched:raise M4AdapterDenied(_ERROR)
            self._dispatched=True
            try:
                receipt=self._backend.send_test(self._binding,before_send=lambda:self._before_send(plan),
                    timeout_seconds=min(plan.expires_at,self._authorization.expires_at)-self._last_now)
                if (not self._send_verified or type(receipt)is not SystemEmailBackendReceipt
                        or not hmac.compare_digest(receipt.source_serial_digest,self._binding.source_serial_digest)
                        or not hmac.compare_digest(receipt.request_digest,self._binding.request_digest)):raise ValueError
                self._receipt=receipt
            except Exception:raise M4AdapterAmbiguous(_ERROR)from None

    def read_postcondition(self,plan: M4ExecutionPlan) -> str:
        with self._lock:
            self._check(plan)
            try:
                if self._receipt is None:raise ValueError
                snapshot=self._inspect()
                if snapshot.capture.matched_messages==0:raise ValueError
                return delivery_state_digest(self._binding,snapshot)
            except Exception:raise M4AdapterAmbiguous(_ERROR)from None

    def require_safe_restore(self) -> None:
        """Require fresh quiescence without adopting an uncertain send result."""
        with self._lock:
            try:self._inspect(require_capture=False,for_restore=True)
            except Exception:raise M4AdapterDenied(_ERROR)from None


def validate_delivery_store_separation(configuration: PersistentM4ExecutionStateStore,
        delivery: PersistentM4ExecutionStateStore) -> None:
    if (type(delivery)is not PersistentM4ExecutionStateStore or delivery is configuration
            or delivery._path==configuration._path or delivery._key_path==configuration._key_path
            or hmac.compare_digest(delivery._key,configuration._key)
            or delivery._checkpoint_store_ref==configuration._checkpoint_store_ref):raise ValueError(_ERROR)
    configuration.verify_ready();delivery.verify_ready()
