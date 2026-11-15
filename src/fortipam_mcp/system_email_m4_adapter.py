"""Unregistered system-email M4 adapter with an injected local backend.

There is deliberately no HTTP backend or native ACK parser here. Backend
receipts exercise the local protocol only; they do not qualify an appliance
ACK, SMTP isolation or delivery. Defaults deny execution. A future qualified
host must supply the backend, exact protected binding and authorization.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hmac
from threading import RLock
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
from .system_email_configuration_contract import SystemEmailEmptyAuthDraft
from .system_email_configuration_transition import SystemEmailConfigurationTransition
from .system_email_native_source import SystemEmailSourceBoundDraft

CONTRACT="fortipam_v4_system_email_local_candidate_v1"
_ERROR="The private system-email execution is unavailable."


def system_email_state_digest(source: SystemEmailSourceBoundDraft) -> str:
    return canonical_digest({"contract":CONTRACT,"serial":source.source_serial_digest,
        "schema":source.source_schema_digest,"forwarded":source.draft.request_digest,
        "unforwarded":source.draft.unforwarded_state_digest})


def system_email_execution_digests(transition: SystemEmailConfigurationTransition,
        binding_digest: str) -> tuple[str,str,str]:
    """Private state/parameter hashes; neither an intent nor an authorization."""
    require_digest(binding_digest,"binding_digest")
    original=transition.original
    current=system_email_state_digest(original)
    expected=canonical_digest({"contract":CONTRACT,"serial":original.source_serial_digest,
        "schema":original.source_schema_digest,"forwarded":transition.proposed.request_digest,
        "unforwarded":original.draft.unforwarded_state_digest})
    parameters=canonical_digest({"contract":CONTRACT,"binding":binding_digest,
        "current":current,"expected":expected})
    return current,expected,parameters


@dataclass(frozen=True,slots=True,repr=False)
class SystemEmailBackendReceipt(_OpaqueC3Object):
    """Local backend acknowledgement; no native ACK qualification is implied."""
    source_serial_digest: str
    request_digest: str

    def __post_init__(self) -> None:
        require_digest(self.source_serial_digest,"source_serial_digest")
        require_digest(self.request_digest,"request_digest")


@runtime_checkable
class SystemEmailConfigurationBackend(Protocol):
    def inspect(self) -> SystemEmailSourceBoundDraft: ...

    def submit(self,draft: SystemEmailEmptyAuthDraft,*,before_send: Callable[[],int],
        timeout_seconds: int) -> SystemEmailBackendReceipt:
        """Call the one-use guard immediately before sending; honor its budget."""
        ...


class SystemEmailM4Adapter(_OpaqueC3Object):
    """One M4-owned submission, with separately authorized same-instance restore."""

    def __init__(self,transition: SystemEmailConfigurationTransition,
            backend: SystemEmailConfigurationBackend,plan: M4ExecutionPlan,
            authorization: M4ExecutionAuthorization,store: PersistentM4ExecutionStateStore,*,
            binding_digest: str,allowed_requester_digest: str,
            authorization_verifier: M4AuthorizationVerifier|None=None,
            execution_enabled: bool=False,clock: Callable[[],int]=lambda:int(time.time())) -> None:
        try:
            if (type(transition) is not SystemEmailConfigurationTransition
                    or not isinstance(backend,SystemEmailConfigurationBackend)
                    or type(store) is not PersistentM4ExecutionStateStore
                    or type(execution_enabled) is not bool or not callable(clock)):
                raise ValueError
            if execution_enabled and not store.monotonic_checkpoint_protocol_bound:raise ValueError
            store.verify_ready()
            require_digest(allowed_requester_digest,"requester_digest")
            self._transition,self._backend,self._store=transition,backend,store
            self._plan,self._authorization=plan,authorization
            self._binding,self._requester=binding_digest,allowed_requester_digest
            self._verifier=authorization_verifier or DenyAllM4AuthorizationVerifier()
            self._enabled,self._clock=execution_enabled,clock
            self._last_now=-1;self._lock=RLock()
            self._dispatched=False;self._receipt: SystemEmailBackendReceipt|None=None
            self._send_admitted=False;self._send_verified=False
            self._original: SystemEmailM4Adapter|None=None
            self._restore_guard: Callable[[],None]|None=None
            self._check_plan()
        except Exception:raise M4AdapterDenied(_ERROR)from None

    def _check_plan(self) -> None:
        current,expected,parameters=system_email_execution_digests(self._transition,self._binding)
        phase="update"if self._original is None else"restore"
        p,a=self._plan,self._authorization
        p.__post_init__();a.__post_init__()
        if (p.action_id!="system-email-"+phase or p.action_version!="1.0.0"
                or p.adapter_ref!=CONTRACT or p.revision!=1 or p.compensation_ref is not None
                or p.requester_digest!=self._requester
                or p.parameters_digest!=parameters
                or p.plan_ref!="system-email-"+phase+"-"+parameters
                or p.target_ref!="system-email-singleton-"+self._transition.original.source_serial_digest
                or p.idempotency_digest!=canonical_digest({"binding":parameters,"phase":phase})
                or p.expected_current_digest!=(current if phase=="update"else expected)
                or p.expected_state_digest!=(expected if phase=="update"else current)
                or a.plan_ref!=p.plan_ref or a.plan_digest!=p.plan_digest
                or a.requester_digest!=p.requester_digest):
            raise ValueError

    def _check(self,plan: M4ExecutionPlan) -> None:
        try:
            if not self._enabled or plan is not self._plan:raise ValueError
            self._check_plan();now=self._clock()
            if (type(now) is not int or now<self._last_now
                    or not self._authorization.issued_at<=now<min(plan.expires_at,self._authorization.expires_at)):
                self._enabled=False;raise ValueError
            self._last_now=now
            self._verifier.verify(plan,self._authorization,now_epoch=now)
        except Exception:raise M4AdapterDenied(_ERROR)from None

    def _require_verified_update(self) -> None:
        if self._original is not None or self._receipt is None:raise M4AdapterDenied(_ERROR)
        p,a=self._plan,self._authorization
        claim=self._store.inspect_claim(plan_ref=p.plan_ref,requester_digest=p.requester_digest,
            idempotency_digest=p.idempotency_digest,authorization_digest=a.authorization_digest,
            context_digest=canonical_digest({"plan_digest":p.plan_digest,
                "authorization_digest":a.authorization_digest,"revision":p.revision}))
        if (claim.result is None or claim.result.outcome!="succeeded"
                or claim.result.verification!="verified"or claim.result.compensation!="not_requested"):
            raise M4AdapterDenied(_ERROR)

    def read_current(self,plan: M4ExecutionPlan) -> str:
        with self._lock:
            self._check(plan)
            if self._original is not None:self._original._require_verified_update()
            try:
                source=self._backend.inspect()
                if type(source) is not SystemEmailSourceBoundDraft:raise ValueError
                return system_email_state_digest(source)
            except Exception:raise M4AdapterAmbiguous(_ERROR)from None

    def dispatch(self,plan: M4ExecutionPlan) -> None:
        with self._lock:
            self._check(plan)
            _require_m4_dispatch_ownership(plan,self._authorization,self._store)
            if self._dispatched:raise M4AdapterDenied(_ERROR)
            self._dispatched=True
            draft=self._transition.proposed if self._original is None else self._transition.original.draft
            try:
                receipt=self._backend.submit(draft,before_send=lambda:self._before_send(plan),
                    timeout_seconds=min(plan.expires_at,self._authorization.expires_at)-self._last_now)
                if (not self._send_verified or type(receipt) is not SystemEmailBackendReceipt
                        or not hmac.compare_digest(receipt.source_serial_digest,self._transition.original.source_serial_digest)
                        or not hmac.compare_digest(receipt.request_digest,draft.request_digest)):
                    raise ValueError
                self._receipt=receipt
            except Exception:raise M4AdapterAmbiguous(_ERROR)from None

    def _before_send(self,plan: M4ExecutionPlan) -> int:
        # Reject foreign/copy-context workers before taking the dispatch lock.
        _require_m4_dispatch_ownership(plan,self._authorization,self._store)
        with self._lock:
            self._check(plan)
            _require_m4_dispatch_ownership(plan,self._authorization,self._store)
            if self._send_admitted:raise M4AdapterDenied(_ERROR)
            self._send_admitted=True
            self._store.verify_ready()
            if self._restore_guard is not None:self._restore_guard()
            if self.read_current(plan)!=plan.expected_current_digest:raise M4AdapterDenied(_ERROR)
            self._check(plan)
            _require_m4_dispatch_ownership(plan,self._authorization,self._store)
            self._send_verified=True
            return min(plan.expires_at,self._authorization.expires_at)-self._last_now

    def read_postcondition(self,plan: M4ExecutionPlan) -> str:
        with self._lock:
            self._check(plan)
            if self._receipt is None:raise M4AdapterAmbiguous(_ERROR)
            try:
                source=self._backend.inspect()
                if type(source) is not SystemEmailSourceBoundDraft:raise ValueError
                return system_email_state_digest(source)
            except Exception:raise M4AdapterAmbiguous(_ERROR)from None

    def bind_restore(self,plan: M4ExecutionPlan,authorization: M4ExecutionAuthorization,*,
            authorization_verifier: M4AuthorizationVerifier|None=None,
            execution_enabled: bool=False,before_restore: Callable[[],None]|None=None) -> SystemEmailM4Adapter:
        """Retain the original local receipt and require a separate M4 grant."""
        try:
            with self._lock:
                self._require_verified_update()
                if type(execution_enabled) is not bool:raise ValueError
                if before_restore is not None and not callable(before_restore):raise ValueError
                if execution_enabled and not self._store.monotonic_checkpoint_protocol_bound:raise ValueError
                restore=object.__new__(SystemEmailM4Adapter)
                restore.__dict__.update(self.__dict__)
                restore._original=self
                restore._plan,restore._authorization=plan,authorization
                restore._verifier=authorization_verifier or DenyAllM4AuthorizationVerifier()
                restore._enabled=execution_enabled;restore._dispatched=False;restore._receipt=None
                restore._send_admitted=False;restore._send_verified=False
                restore._restore_guard=before_restore
                restore._check_plan()
                return restore
        except Exception:raise M4AdapterDenied(_ERROR)from None
