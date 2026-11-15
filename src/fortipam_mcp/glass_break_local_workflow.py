"""Fixed local glass-breaking workflow; independent exit and non-dispatch queries.

No grant issuer, native qualifier, scheduler, privileged read or login/logout is
provided. The producer retains the cookie window and independent recovery path.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass,replace
import math
import secrets
from typing import Literal,Protocol

from v4_planning import (DenyAllM4AuthorizationVerifier,M4AuthorizationDenied,M4ExecutionAuthorization,
    M4ExecutionKernel,M4ExecutionPlan,M4ExecutionResult,canonical_digest)
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest,require_ref
from .glass_break_m4 import CONTRACT as ADAPTER,GlassBreakM4Adapter,GlassBreakM4Session,GlassBreakStep

CONTRACT = 'fortipam-glass-break-local-workflow/v1'
Phase = Literal['activate','deactivate']
PHASES: tuple[Phase,...] = ('activate','deactivate')
_ERROR = 'The private glass-breaking workflow is unavailable.'


def glass_break_step_binding(session: GlassBreakM4Session, step: GlassBreakStep) -> tuple[str,str,str]:
    return step.action_id,ADAPTER,'glass-break-'+session._initial.baseline.binding_digest


def glass_break_preview_content(session: GlassBreakM4Session, step: GlassBreakStep, reference: str,
        created_at: int, expires_at: int, *, policy_mode: str | None=None) -> dict[str,object]:
    public: dict[str,object] = dict(contract=CONTRACT,phase='deactivate' if step.deactivate else 'activate',preview_ref=reference,
        created_at=created_at,expires_at=expires_at,parent_intent=session._initial.preview(),
        **{'Current State':dict(original_physical_cookie_plan_bound=True,complete_role_mode_readback_matched_locally=True,
                original_sealed_activation_required=step.deactivate,duration_overdue_at_preview=step.declared_duration_overdue),
           'Proposed Changes':dict(request_activation=not step.deactivate,request_independent_exit=step.deactivate,
                maximum_elevation_seconds=session._scope.maximum_elevation_seconds,exit_reserve_seconds=session._scope.exit_reserve_seconds,
                reason_privately_bound=True,role_or_secret_change_requested=False),
           'Expected State':dict(explicit_mode_true_required=not step.deactivate,explicit_mode_false_required=step.deactivate,
                complete_role_preservation_required=True,independent_incident_audit_observer_required=True),
           'Security Changes':dict(all_folder_secret_request_launch_access_affected=True,cleartext_access_may_be_possible=True,
                external_duration_enforcement_required=True,native_automatic_expiry_verified=False,
                late_exit_allowed_with_separate_authority=True,late_exit_does_not_verify_duration=True,
                exit_does_not_recall_notifications_or_disclosures=True)},
        execution_authorized=False,native_backend_qualified=False,native_subject_or_session_scope_verified=False)
    if policy_mode is not None: public['authorization_policy_mode']=policy_mode
    return public


@dataclass(frozen=True,slots=True,repr=False)
class GlassBreakAuthorizationRequest(_OpaqueC3Object):
    phase: Phase
    preview_ref: str
    requester_digest: str
    transport_digest: str
    root_digest: str
    summary_digest: str
    parameters_digest: str
    expected_current_digest: str
    expected_state_digest: str
    action_id: str
    adapter_ref: str
    target_ref: str
    created_at: int
    expires_at: int


class GlassBreakWorkflowAuthority(Protocol):
    def authorize(self, request: GlassBreakAuthorizationRequest) -> tuple[M4ExecutionPlan,M4ExecutionAuthorization]: ...
    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None: ...


class DenyAllGlassBreakWorkflowAuthority(DenyAllM4AuthorizationVerifier):
    def authorize(self, request: GlassBreakAuthorizationRequest) -> tuple[M4ExecutionPlan,M4ExecutionAuthorization]:
        raise M4AuthorizationDenied(_ERROR)


class GlassBreakLocalWorkflow(_OpaqueC3Object):
    def __init__(self, session: GlassBreakM4Session, *, allowed_transport_digest: str,
            authority: GlassBreakWorkflowAuthority | None=None, enabled_phases: tuple[Phase,...]=(),
            source_guard: Callable[[],bool] | None=None) -> None:
        try:
            if (type(session) is not GlassBreakM4Session or type(enabled_phases) is not tuple
                    or len(set(enabled_phases))!=len(enabled_phases) or any(phase not in PHASES for phase in enabled_phases)
                    or source_guard is not None and not callable(source_guard)): raise ValueError
            require_digest(allowed_transport_digest,'glass-breaking client'); session._pins()
            if session._workflow is not None or session._adapters or session._store.claim_count: raise ValueError
            self._session=self._session_pin=session; self._root=session._domain_pin
            self._store,self._checkpoint=session._store,session._checkpoint
            self._transport,self._requester=allowed_transport_digest,session._scope.requester_digest
            self._identity_pin=(self._requester,self._transport)
            self._authority=self._authority_pin=authority or DenyAllGlassBreakWorkflowAuthority()
            self._guard=self._guard_pin=source_guard; self._enabled={phase:phase in enabled_phases for phase in PHASES}
            self._previews: dict[Phase,GlassBreakAuthorizationRequest] = {}
            self._issued: dict[Phase,tuple[M4ExecutionPlan,M4ExecutionAuthorization]] = {}
            self._adapters: dict[Phase,GlassBreakM4Adapter] = {}
            self._results: dict[Phase,M4ExecutionResult] = {}; self._attempted: set[Phase] = set(); self._closed=False
            self._timing_epoch,self._timing_mono=session._source._last_epoch,session._source._last_mono
            self._timing_fault=False; self._overdue_seen=False; self._exit_duration: bool | None=None
            session._workflow=self
        except Exception: raise ValueError(_ERROR) from None

    def _identity(self, requester_digest: str, transport_digest: str) -> None:
        if (self._closed or (self._requester,self._transport)!=self._identity_pin
                or (requester_digest,transport_digest)!=self._identity_pin): raise ValueError

    def _integrity(self, *, query: bool=False) -> None:
        session=self._session
        if (session is not self._session_pin or session._workflow is not self or session._store is not self._store
                or self._store._monotonic_checkpoint is not self._checkpoint or session._domain()!=self._root
                or self._authority is not self._authority_pin): raise ValueError
        self._store.verify_ready()
        if not query: session._pins()

    def _gate(self, phase: Phase) -> None:
        if (self._enabled[phase] is not True or phase=='activate' and self._timing_fault
                or self._guard is None or self._guard is not self._guard_pin or self._guard() is not True): raise ValueError
        self._integrity()

    def preview(self, phase: Phase, *, requester_digest: str, transport_digest: str) -> dict[str,object]:
        try:
            with self._session._lock:
                self._identity(requester_digest,transport_digest); self._integrity()
                if phase not in PHASES or phase in self._attempted: raise ValueError
                if phase in self._issued:
                    self._session._release_expired_unused(self._adapters[phase]); del self._issued[phase]; del self._adapters[phase]
                prepared=self._session.prepare_step(deactivate=phase=='deactivate'); now=self._session._now()
                expires=min(now+60,prepared.expires_at); reference='glass-break-preview-'+secrets.token_hex(24)
                public=glass_break_preview_content(self._session,prepared,reference,now,expires,policy_mode=getattr(self._authority,'policy_mode',None))
                action,adapter,target=glass_break_step_binding(self._session,prepared)
                self._previews[phase]=GlassBreakAuthorizationRequest(phase,reference,requester_digest,transport_digest,self._root,
                    canonical_digest(public),prepared.parameters_digest,prepared.expected_current_digest,prepared.expected_state_digest,
                    action,adapter,target,now,expires)
                return public
        except Exception: raise ValueError(_ERROR) from None

    def authorize(self, preview_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str,object]:
        try:
            with self._session._lock:
                self._identity(requester_digest,transport_digest); require_ref(preview_ref,'glass-breaking preview')
                phase,request=next((phase,request) for phase,request in self._previews.items() if request.preview_ref==preview_ref)
                self._gate(phase)
                if phase in self._attempted or phase in self._issued or self._session._now()>=request.expires_at: raise ValueError
                plan,authorization=self._authority.authorize(request)
                if (type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization
                        or (plan.summary_digest,plan.parameters_digest)!=(request.summary_digest,request.parameters_digest)
                        or (plan.expected_current_digest,plan.expected_state_digest)!=(request.expected_current_digest,request.expected_state_digest)
                        or (plan.action_id,plan.adapter_ref,plan.target_ref)!=(request.action_id,request.adapter_ref,request.target_ref)
                        or plan.expires_at!=request.expires_at
                        or not request.created_at<=authorization.issued_at<=self._session._now()<authorization.expires_at<=request.expires_at): raise ValueError
                self._gate(phase); self._authority.verify(plan,authorization,now_epoch=self._session._now()); step=self._session._prepared
                if step is None or step.deactivate is not (phase=='deactivate'): raise ValueError
                adapter=self._session.bind_step(step,plan,authorization,authorization_verifier=self,execution_enabled=True)
                self._adapters[phase]=adapter; self._issued[phase]=(plan,authorization)
                return dict(contract=CONTRACT,phase=phase,authorization_ref=authorization.authorization_ref,
                    expires_at=authorization.expires_at,native_backend_qualified=False)
        except Exception: raise ValueError(_ERROR) from None

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            phase=next(phase for phase,pair in self._issued.items() if pair[0] is plan and pair[1] is authorization)
            self._gate(phase)
            if type(now_epoch) is not int or now_epoch>self._session._now(): raise ValueError
            self._authority.verify(plan,authorization,now_epoch=now_epoch); self._gate(phase)
        except Exception: raise M4AuthorizationDenied(_ERROR) from None

    def _result(self, phase: Phase, result: M4ExecutionResult, *, replay: bool=False) -> dict[str,object]:
        return {**(replace(result,idempotent_replay=True) if replay else result).as_dict(),'native_backend_qualified':False,
            'declared_duration_verified_locally':self._exit_duration if phase=='deactivate' and result.outcome=='succeeded' else None}

    def execute(self, authorization_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str,object]:
        try:
            with self._session._lock:
                self._identity(requester_digest,transport_digest); require_ref(authorization_ref,'glass-breaking authorization')
                phase,(plan,authorization)=next((phase,pair) for phase,pair in self._issued.items() if pair[1].authorization_ref==authorization_ref)
                if phase in self._results:
                    self._integrity(query=True); return self._result(phase,self._results[phase],replay=True)
                if phase in self._attempted: raise ValueError
                self.verify(plan,authorization,now_epoch=self._session._now()); self._attempted.add(phase); adapter=self._adapters[phase]
                try: result=M4ExecutionKernel(adapter,self,self._store,clock=self._session._now).execute(plan,authorization)
                except BaseException:
                    try:
                        untouched=(self._store.claim_count==adapter._step.claim_index-1 and not adapter._dispatched
                            and not adapter._send_admitted and adapter._receipt is None)
                    except Exception: untouched=False
                    if untouched: self._attempted.discard(phase)
                    raise
                if phase=='deactivate' and result.outcome=='succeeded':
                    self._local_timing()
                    duration=self._session._duration_verified_locally
                    self._exit_duration=False if duration is False or self._overdue_seen else None if self._timing_fault else duration
                self._results[phase]=result; return self._result(phase,result)
        except Exception: raise ValueError(_ERROR) from None

    def _local_timing(self) -> tuple[bool | None,bool | None]:
        # Local clock observation only; do not read the actor, touch cookies or
        # contact grants. Bad/rolled-back clocks cannot prove usable timing.
        source=self._session._source
        if self._timing_fault: return None,None
        try: epoch=source._clock(); mono=source._http_clock()
        except Exception:
            self._timing_fault=True; return None,None
        if (type(epoch) is not int or epoch<max(source._last_epoch,self._timing_epoch) or type(mono) not in (int,float)
                or not math.isfinite(mono) or mono<max(source._last_mono,self._timing_mono)):
            self._timing_fault=True; return None,None
        self._timing_epoch,self._timing_mono=epoch,float(mono)
        expired=source._closed or mono>=source._owner_expiry
        start_epoch,start_mono=self._session._activation_epoch,self._session._activation_mono
        if start_epoch is None or start_mono is None: return expired,None
        overdue=epoch>start_epoch+self._session._scope.maximum_elevation_seconds or mono>start_mono+self._session._scope.maximum_elevation_seconds
        self._overdue_seen=self._overdue_seen or overdue
        return expired,overdue

    def outcome(self, *, requester_digest: str, transport_digest: str) -> dict[str,object]:
        try:
            with self._session._lock:
                self._identity(requester_digest,transport_digest); self._integrity(query=True)
                verified: dict[str,bool] = {}; unresolved=False
                for phase in PHASES:
                    result=self._results.get(phase); local=False
                    if phase in self._attempted:
                        claim=self._adapters[phase]._claim()
                        local=(result is not None and result.outcome=='succeeded' and result.verification=='verified'
                            and claim.result==result and self._adapters[phase]._receipt is not None and self._adapters[phase]._post_verified)
                        if not local: unresolved=True
                    verified[phase]=local
                expired,overdue=self._local_timing(); duration=self._exit_duration
                if unresolved: state='reconciliation_required'
                elif all(verified.values()):
                    state='verified_locally' if duration is True else 'exited_after_declared_duration_locally' if duration is False else 'reconciliation_required'
                elif verified['activate']:
                    state='out_of_band_recovery_required' if expired is not False else 'deactivation_required' if overdue is True else 'active_locally' if overdue is False else 'reconciliation_required'
                else: state='not_started'
                return dict(contract=CONTRACT,workflow_outcome=state,phase_verified_locally=verified,execution_claims=self._store.claim_count,
                    declared_duration_verified_locally=duration if verified['deactivate'] else None,
                    active_mode_may_remain=not verified['deactivate'] and bool(self._attempted),
                    original_window_expired_locally=expired,live_configuration_verified=False,native_backend_qualified=False,
                    native_subject_or_session_scope_verified=False,notifications_or_disclosures_reversed=False)
        except Exception: raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._session._lock: self._closed=True
