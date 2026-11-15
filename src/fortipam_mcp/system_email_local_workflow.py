"""Local-only system-email preview, authorization and durable M4 composition.

Backends and a protected issuer are supplied separately; this workflow does not
register startup or issue permissions. The authority independently verifies
intent and the applicable approval policy;
the workflow cannot promote its own preview into an execution authorization.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import secrets
from threading import RLock
import time
from typing import Literal,Protocol

from v4_planning import (
    DenyAllM4AuthorizationVerifier,M4AuthorizationDenied,M4ExecutionAuthorization,
    M4ExecutionKernel,M4ExecutionPlan,M4ExecutionResult,canonical_digest,
)
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .m4_execution_store import PersistentM4ExecutionStateStore
from .system_email_configuration_transition import SystemEmailConfigurationTransition
from .system_email_delivery_contract import SystemEmailDeliveryBinding
from .system_email_delivery_m4_adapter import (
    CONTRACT as DELIVERY_ADAPTER_CONTRACT,SystemEmailDeliveryBackend,
    SystemEmailDeliveryInspection,SystemEmailDeliveryM4Adapter,delivery_execution_digests,
    validate_delivery_store_separation,
)
from .system_email_m4_adapter import (
    CONTRACT as CONFIGURATION_ADAPTER_CONTRACT,
    SystemEmailConfigurationBackend,SystemEmailM4Adapter,system_email_execution_digests,
)

CONTRACT="fortipam_v4_system_email_local_workflow_v1"
_ERROR="The private system-email workflow is unavailable."
Phase=Literal["update","restore","test-delivery"]


@dataclass(frozen=True,slots=True,repr=False)
class SystemEmailAuthorizationRequest(_OpaqueC3Object):
    """Value-free binding request, not human intent, approval or authorization."""
    phase: Phase
    preview_ref: str
    requester_digest: str
    transport_digest: str
    summary_digest: str
    parameters_digest: str
    expected_current_digest: str
    expected_state_digest: str
    target_ref: str
    created_at: int
    expires_at: int
    adapter_ref: str=CONFIGURATION_ADAPTER_CONTRACT


class SystemEmailWorkflowAuthority(Protocol):
    def authorize(self,request: SystemEmailAuthorizationRequest) -> tuple[M4ExecutionPlan,M4ExecutionAuthorization]: ...

    def verify(self,plan: M4ExecutionPlan,authorization: M4ExecutionAuthorization,*,now_epoch: int) -> None: ...


class DenyAllSystemEmailWorkflowAuthority(DenyAllM4AuthorizationVerifier):
    def authorize(self,request: SystemEmailAuthorizationRequest) -> tuple[M4ExecutionPlan,M4ExecutionAuthorization]:
        raise M4AuthorizationDenied(_ERROR)


def system_email_preview_content(transition: SystemEmailConfigurationTransition, phase: Phase,
        preview_ref: str, created_at: int, *, policy_mode: str|None=None) -> dict[str,object]:
    """Reproducible value-free C/P/E for the planner and protected issuer."""
    values=transition.preview()
    if phase=="restore":
        values={**values,"Current State":{"verified_original_update":True},
            "Proposed Changes":{"restore_original_configuration":True},
            "Expected State":{"same_device_and_schema":True,"all_original_values_restored":True}}
    elif phase=="test-delivery":
        values={"Current State":{"verified_original_update":True,"complete_empty_capture":True},
            "Proposed Changes":{"one_fixed_test_message":True,"arbitrary_recipient":False},
            "Expected State":{"matching_capture_count":1,"configuration_preserved":True},
            "configuration_write_authorized":False,"smtp_send_authorized":False}
    public={**values,"contract":CONTRACT,"phase":phase,"preview_ref":preview_ref,
        "expires_at":created_at+60,"native_backend_qualified":False,"device_write_executed":False}
    if policy_mode is not None:public["authorization_policy_mode"]=policy_mode
    return public


class SystemEmailLocalWorkflow(_OpaqueC3Object):
    """One fixed source/proposal, pinned operator/client and dedicated ledger."""

    def __init__(self,transition: SystemEmailConfigurationTransition,
            backend: SystemEmailConfigurationBackend,store: PersistentM4ExecutionStateStore,*,
            binding_digest: str,allowed_requester_digest: str,allowed_transport_digest: str,
            authority: SystemEmailWorkflowAuthority|None=None,update_enabled: bool=False,
            restore_enabled: bool=False,clock: Callable[[],int]=lambda:int(time.time()),
            delivery_binding: SystemEmailDeliveryBinding|None=None,
            delivery_backend: SystemEmailDeliveryBackend|None=None,
            delivery_store: PersistentM4ExecutionStateStore|None=None,delivery_enabled: bool=False) -> None:
        try:
            if (type(transition) is not SystemEmailConfigurationTransition
                    or type(store) is not PersistentM4ExecutionStateStore
                    or type(update_enabled) is not bool or type(restore_enabled) is not bool
                    or type(delivery_enabled) is not bool
                    or not callable(clock)):
                raise ValueError
            if (update_enabled or restore_enabled)and not store.monotonic_checkpoint_protocol_bound:raise ValueError
            store.verify_ready()
            for value in(binding_digest,allowed_requester_digest,allowed_transport_digest):
                require_digest(value,"binding_digest")
            self._transition,self._backend,self._store=transition,backend,store
            self._requester,self._transport=allowed_requester_digest,allowed_transport_digest
            self._binding=canonical_digest({"binding":binding_digest,
                "requester":self._requester,"transport":self._transport})
            supplied=(delivery_binding is not None,delivery_backend is not None,delivery_store is not None)
            if any(supplied)and not all(supplied):raise ValueError
            if delivery_enabled and not all(supplied):raise ValueError
            if all(supplied):
                if type(delivery_binding)is not SystemEmailDeliveryBinding or type(delivery_store)is not PersistentM4ExecutionStateStore:raise ValueError
                validate_delivery_store_separation(store,delivery_store)
                if delivery_enabled and not delivery_store.monotonic_checkpoint_protocol_bound:raise ValueError
                if (delivery_binding.configuration_digest!=system_email_execution_digests(transition,self._binding)[1]
                        or delivery_binding.source_serial_digest!=transition.original.source_serial_digest):raise ValueError
            self._delivery_binding,self._delivery_backend,self._delivery_store=delivery_binding,delivery_backend,delivery_store
            self._delivery_baseline: SystemEmailDeliveryInspection|None=None
            self._authority=authority or DenyAllSystemEmailWorkflowAuthority()
            self._enabled={"update":update_enabled,"restore":restore_enabled}
            if all(supplied):self._enabled["test-delivery"]=delivery_enabled
            self._clock,self._last_now,self._closed=clock,-1,False
            self._lock=RLock()
            self._previews: dict[Phase,SystemEmailAuthorizationRequest]={}
            self._issued: dict[Phase,tuple[M4ExecutionPlan,M4ExecutionAuthorization]]={}
            self._adapters: dict[Phase,SystemEmailM4Adapter|SystemEmailDeliveryM4Adapter]={}
            self._results: dict[Phase,M4ExecutionResult]={}
        except Exception:raise ValueError(_ERROR)from None

    def _now(self) -> int:
        now=self._clock()
        if self._closed or type(now) is not int or now<0 or now<self._last_now:
            self._closed=True;raise ValueError(_ERROR)
        self._last_now=now
        return now

    def _identity(self,requester_digest: str,transport_digest: str) -> None:
        if requester_digest!=self._requester or transport_digest!=self._transport:
            raise ValueError(_ERROR)

    def _unconsumed(self,phase: Phase) -> None:
        if self._store.claim_count!=(0 if phase=="update"else 1):raise ValueError(_ERROR)
        if phase!="update":self._original_update()._require_verified_update()
        if self._delivery_store is not None:
            if phase in("update","test-delivery")and self._delivery_store.claim_count!=0:raise ValueError(_ERROR)
            if phase=="restore":self._safe_delivery_restore()

    @property
    def has_delivery(self) -> bool:
        return self._delivery_binding is not None

    def _original_update(self) -> SystemEmailM4Adapter:
        adapter=self._adapters["update"]
        if type(adapter)is not SystemEmailM4Adapter:raise ValueError(_ERROR)
        return adapter

    def _safe_delivery_restore(self) -> None:
        if self._delivery_store is None or self._delivery_store.claim_count==0:return
        adapter=self._adapters.get("test-delivery")
        if type(adapter)is not SystemEmailDeliveryM4Adapter:raise ValueError(_ERROR)
        adapter.require_safe_restore()

    def preview(self,phase: Phase,*,requester_digest: str,transport_digest: str) -> dict[str,object]:
        try:
            with self._lock:
                self._identity(requester_digest,transport_digest);created=self._now()
                if phase not in self._enabled:raise ValueError
                self._unconsumed(phase)
                if phase=="test-delivery":
                    if self._delivery_binding is None or self._delivery_backend is None:raise ValueError
                    baseline=self._delivery_backend.inspect(self._delivery_binding)
                    current,expected,parameters=delivery_execution_digests(self._delivery_binding,baseline,self._binding)
                    self._delivery_baseline=baseline
                else:
                    source=self._backend.inspect()
                    if phase=="update":self._transition.verify_restored(source)
                    else:self._transition.verify_applied(source)
                    current,expected,parameters=system_email_execution_digests(self._transition,self._binding)
                if self._now()>=created+60:raise ValueError
                ref="system-email-preview-"+secrets.token_urlsafe(24)
                public=system_email_preview_content(self._transition,phase,ref,created,
                    policy_mode=getattr(self._authority,"policy_mode",None))
                request=SystemEmailAuthorizationRequest(phase,ref,self._requester,self._transport,
                    canonical_digest(public),parameters,expected if phase=="restore"else current,
                    current if phase=="restore"else expected,
                    "system-email-singleton-"+self._transition.original.source_serial_digest,created,created+60,
                    DELIVERY_ADAPTER_CONTRACT if phase=="test-delivery"else CONFIGURATION_ADAPTER_CONTRACT)
                self._previews[phase]=request
                self._issued.pop(phase,None);self._adapters.pop(phase,None)
                return public
        except Exception:raise ValueError(_ERROR)from None

    def authorize(self,phase: Phase,preview_ref: str,*,requester_digest: str,
            transport_digest: str) -> dict[str,object]:
        try:
            with self._lock:
                self._identity(requester_digest,transport_digest);self._unconsumed(phase)
                request=self._previews[phase]
                if (not self._enabled[phase]or request.preview_ref!=preview_ref or phase in self._issued
                        or not request.created_at<=self._now()<request.expires_at):raise ValueError
                plan,authorization=self._authority.authorize(request)
                if (type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization
                        or plan.summary_digest!=request.summary_digest or plan.expires_at!=request.expires_at
                        or authorization.issued_at<request.created_at
                        or authorization.expires_at>request.expires_at
                        or not request.created_at<=self._now()<request.expires_at):raise ValueError
                adapter: SystemEmailM4Adapter|SystemEmailDeliveryM4Adapter
                if phase=="update":
                    adapter=SystemEmailM4Adapter(self._transition,self._backend,plan,authorization,self._store,
                        binding_digest=self._binding,allowed_requester_digest=self._requester,
                        authorization_verifier=self,execution_enabled=self._enabled[phase],clock=self._now)
                elif phase=="restore":
                    adapter=self._original_update().bind_restore(plan,authorization,
                        authorization_verifier=self,execution_enabled=self._enabled[phase],
                        before_restore=self._safe_delivery_restore if self.has_delivery else None)
                else:
                    if (self._delivery_binding is None or self._delivery_baseline is None
                            or self._delivery_backend is None or self._delivery_store is None):raise ValueError
                    adapter=SystemEmailDeliveryM4Adapter(self._delivery_binding,self._delivery_baseline,
                        self._original_update(),self._delivery_backend,plan,authorization,self._delivery_store,
                        context_digest=self._binding,allowed_requester_digest=self._requester,
                        authorization_verifier=self,execution_enabled=self._enabled[phase],clock=self._now)
                self._issued[phase]=(plan,authorization);self._adapters[phase]=adapter
                try:self.verify(plan,authorization,now_epoch=self._now())
                except Exception:
                    self._issued.pop(phase,None);self._adapters.pop(phase,None);raise
                return {"contract":CONTRACT,"phase":phase,"preview_ref":preview_ref,
                    "authorization_ref":authorization.authorization_ref,"expires_at":authorization.expires_at,
                    "local_execution":"authorized_once","native_backend_qualified":False,
                    "device_write_executed":False}
        except Exception:raise ValueError(_ERROR)from None

    def verify(self,plan: M4ExecutionPlan,authorization: M4ExecutionAuthorization,*,now_epoch: int) -> None:
        try:
            with self._lock:
                phase: Phase=("update"if plan.action_id=="system-email-update"else
                    "test-delivery"if plan.action_id=="system-email-test-delivery"else"restore")
                request=self._previews[phase];issued=self._issued[phase];now=self._now()
                if (not self._enabled[phase]or plan is not issued[0]or authorization is not issued[1]
                        or type(now_epoch) is not int or not request.created_at<=now_epoch<=now<request.expires_at
                        or plan.summary_digest!=request.summary_digest):raise ValueError
                self._authority.verify(plan,authorization,now_epoch=now_epoch)
        except Exception:raise M4AuthorizationDenied(_ERROR)from None

    def execute(self,phase: Phase,authorization_ref: str,*,requester_digest: str,
            transport_digest: str) -> dict[str,object]:
        try:
            with self._lock:
                self._identity(requester_digest,transport_digest)
                plan,authorization=self._issued[phase]
                if authorization.authorization_ref!=authorization_ref:raise ValueError
                self.verify(plan,authorization,now_epoch=self._now())
                store=self._delivery_store if phase=="test-delivery"else self._store
                if store is None:raise ValueError
                result=M4ExecutionKernel(self._adapters[phase],self,store,clock=self._now).execute(plan,authorization)
                self._results[phase]=result
                return {"contract":CONTRACT,"phase":phase,"native_backend_qualified":False,**result.as_dict()}
        except Exception:raise ValueError(_ERROR)from None

    def outcome(self,*,requester_digest: str,transport_digest: str) -> dict[str,object]:
        """Summarize owned local results; neither redispatch nor adopt a journal."""
        try:
            with self._lock:
                self._identity(requester_digest,transport_digest);self._now()
                configuration_claims=self._store.claim_count
                delivery_claims=self._delivery_store.claim_count if self._delivery_store is not None else 0
                phases: tuple[Phase,...]=("update","test-delivery","restore")if self.has_delivery else("update","restore")
                verified={phase:(phase in self._results and self._results[phase].outcome=="succeeded"
                    and self._results[phase].verification=="verified")for phase in phases}
                complete=all(verified.values())and configuration_claims==2 and delivery_claims==int(self.has_delivery)
                stopped=(any(not verified[p]for p in self._results)
                    or configuration_claims+delivery_claims>len(self._results))
                return {"contract":CONTRACT,"workflow_outcome":"verified_locally"if complete else
                    "reconciliation_required"if stopped else"incomplete",
                    "phase_verified_locally":verified,"delivery_included":self.has_delivery,
                    "configuration_claims":configuration_claims,"delivery_claims":delivery_claims,
                    "native_backend_qualified":False,"native_delivery_qualified":False,
                    "raw_message_content_returned":False}
        except Exception:raise ValueError(_ERROR)from None

    def close(self) -> None:
        with self._lock:
            self._closed=True;self._issued.clear();self._previews.clear();self._adapters.clear()
