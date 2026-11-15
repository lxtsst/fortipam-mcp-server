"""Fixed alert workflow with opaque references and per-object authorization.

This factory-only local composition never supplies native eligibility evidence,
issues Reference grants, dispatches queries, or promotes a previously uncertain
attempt from a later matching view. Configuration restoration cannot recall mail.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass,replace
import secrets
from typing import Protocol

from v4_planning import (DenyAllM4AuthorizationVerifier,M4AuthorizationDenied,M4ExecutionAuthorization,
    M4ExecutionKernel,M4ExecutionPlan,M4ExecutionResult,canonical_digest)
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest,require_ref
from .email_alert_compound_contract import EmailAlertCompoundPlan,Step,STEPS
from .email_alert_m4 import CONTRACT as ADAPTER,EmailAlertM4Adapter,EmailAlertM4Session,EmailAlertStep

CONTRACT = 'fortipam-email-alert-local-workflow/v1'
Phase = tuple[Step,bool]
PHASES: tuple[Phase,...] = (*((step,False) for step in STEPS),*((step,True) for step in reversed(STEPS)))
_ERROR = 'The private email-alert workflow is unavailable.'


def email_alert_step_binding(session: EmailAlertM4Session, step: EmailAlertStep) -> tuple[str,str,str]:
    return step.action_id,ADAPTER,'email-alert-'+canonical_digest(dict(initial=session._initial.digest,step=step.name))


def email_alert_preview_content(initial: EmailAlertCompoundPlan, step: EmailAlertStep, reference: str,
        created_at: int, expires_at: int, *, policy_mode: str | None = None) -> dict[str,object]:
    parent = initial.preview()
    public: dict[str,object] = dict(contract=CONTRACT,step=step.name,restore=step.restore,preview_ref=reference,
        created_at=created_at,expires_at=expires_at,parent_intent=parent,
        **{'Current State':dict(original_physical_plan_bound=True,full_prefix_matched_locally=True,
                master_enabled_locally=initial.expected(step.before).master_enabled(),original_sealed_receipt_required=step.restore),
           'Proposed Changes':dict(fixed_object_index=STEPS.index(step.name)+1,configure_fixed_scope=not step.restore,
                restore_only_original_configuration=step.restore,trigger_write_requested=False,credential_submitted=False),
           'Expected State':dict(master_enabled_locally=initial.expected(step.after).master_enabled(),complete_fixed_readback_required=True,
                independent_effects_required=True,separate_recovery_grant_required=True),
           'Security Changes':dict(external_email_possible=True,configuration_restore_does_not_recall_mail=True,
                sender_quiescence_required=True,certificate_empty_reverse_subtree_qualified=False)},
        execution_authorized=False,native_backend_qualified=False,delivery_verified=False)
    if policy_mode is not None: public['authorization_policy_mode'] = policy_mode
    return public


@dataclass(frozen=True,slots=True,repr=False)
class EmailAlertAuthorizationRequest(_OpaqueC3Object):
    step: Step
    restore: bool
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


class EmailAlertWorkflowAuthority(Protocol):
    def authorize(self, request: EmailAlertAuthorizationRequest) -> tuple[M4ExecutionPlan,M4ExecutionAuthorization]: ...
    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None: ...


class DenyAllEmailAlertWorkflowAuthority(DenyAllM4AuthorizationVerifier):
    def authorize(self, request: EmailAlertAuthorizationRequest) -> tuple[M4ExecutionPlan,M4ExecutionAuthorization]:
        raise M4AuthorizationDenied(_ERROR)


class EmailAlertLocalWorkflow(_OpaqueC3Object):
    def __init__(self, session: EmailAlertM4Session, *, allowed_transport_digest: str,
            authority: EmailAlertWorkflowAuthority | None = None, enabled_phases: tuple[Phase,...] = (),
            source_guard: Callable[[],bool] | None = None) -> None:
        try:
            if (type(session) is not EmailAlertM4Session or type(enabled_phases) is not tuple
                    or len(set(enabled_phases)) != len(enabled_phases) or any(type(p) is not tuple or len(p)!=2
                        or p[0] not in STEPS or type(p[1]) is not bool for p in enabled_phases)
                    or source_guard is not None and not callable(source_guard)): raise ValueError
            require_digest(allowed_transport_digest,'email-alert client'); session._pins()
            if session._workflow is not None or session._adapters or session._store.claim_count: raise ValueError
            self._session = self._session_pin = session; self._root = session._domain_pin
            self._store,self._checkpoint = session._store,session._checkpoint
            self._transport,self._requester = allowed_transport_digest,session._scope.requester_digest
            self._identity_pin = (self._requester,self._transport)
            self._authority = self._authority_pin = authority or DenyAllEmailAlertWorkflowAuthority()
            self._guard = self._guard_pin = source_guard; self._enabled = {p:p in enabled_phases for p in PHASES}
            self._previews: dict[Phase,EmailAlertAuthorizationRequest] = {}
            self._issued: dict[Phase,tuple[M4ExecutionPlan,M4ExecutionAuthorization]] = {}
            self._adapters: dict[Phase,EmailAlertM4Adapter] = {}
            self._results: dict[Phase,M4ExecutionResult] = {}; self._attempted: set[Phase] = set(); self._closed = False
            session._workflow = self
        except Exception: raise ValueError(_ERROR) from None

    def _identity(self, requester_digest: str, transport_digest: str) -> None:
        if (self._closed or (self._requester,self._transport) != self._identity_pin
                or (requester_digest,transport_digest) != self._identity_pin): raise ValueError

    def _integrity(self, *, query: bool = False) -> None:
        s = self._session
        if (s is not self._session_pin or s._workflow is not self or s._store is not self._store
                or s._store._monotonic_checkpoint is not self._checkpoint or s._domain() != self._root
                or self._authority is not self._authority_pin): raise ValueError
        self._store.verify_ready()
        if not query: s._pins()

    def _gate(self, phase: Phase) -> None:
        if (self._enabled[phase] is not True or self._guard is None or self._guard is not self._guard_pin
                or self._guard() is not True): raise ValueError
        self._integrity()

    def preview(self, step: Step, *, restore: bool = False, requester_digest: str, transport_digest: str) -> dict[str,object]:
        try:
            with self._session._lock:
                self._identity(requester_digest,transport_digest); self._integrity(); phase = (step,restore)
                if step not in STEPS or type(restore) is not bool or phase in self._attempted: raise ValueError
                if phase in self._issued:
                    self._session._release_expired_unused(self._adapters[phase])
                    del self._issued[phase]; del self._adapters[phase]
                prepared = self._session.prepare_step(step,restore=restore)
                now = self._session._now(); expires = min(now+60,prepared.expires_at)
                reference = 'email-alert-preview-'+secrets.token_hex(24)
                public = email_alert_preview_content(self._session._initial,prepared,reference,now,expires,
                    policy_mode=getattr(self._authority,'policy_mode',None))
                action,adapter,target = email_alert_step_binding(self._session,prepared)
                self._previews[phase] = EmailAlertAuthorizationRequest(step,restore,reference,requester_digest,transport_digest,self._root,
                    canonical_digest(public),prepared.parameters_digest,prepared.expected_current_digest,prepared.expected_state_digest,
                    action,adapter,target,now,expires)
                return public
        except Exception: raise ValueError(_ERROR) from None

    def authorize(self, preview_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str,object]:
        try:
            with self._session._lock:
                self._identity(requester_digest,transport_digest); require_ref(preview_ref,'email-alert preview')
                phase,request = next((p,r) for p,r in self._previews.items() if r.preview_ref == preview_ref)
                self._gate(phase)
                if phase in self._attempted or phase in self._issued or self._session._now() >= request.expires_at: raise ValueError
                plan,authorization = self._authority.authorize(request)
                if (type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization
                        or plan.summary_digest != request.summary_digest or plan.parameters_digest != request.parameters_digest
                        or (plan.expected_current_digest,plan.expected_state_digest) != (request.expected_current_digest,request.expected_state_digest)
                        or (plan.action_id,plan.adapter_ref,plan.target_ref) != (request.action_id,request.adapter_ref,request.target_ref)
                        or plan.expires_at != request.expires_at
                        or not request.created_at <= authorization.issued_at <= self._session._now() < authorization.expires_at <= request.expires_at): raise ValueError
                self._gate(phase); self._authority.verify(plan,authorization,now_epoch=self._session._now())
                prepared = self._session._prepared
                if prepared is None or (prepared.name,prepared.restore) != phase: raise ValueError
                adapter = self._session.bind_step(prepared,plan,authorization,authorization_verifier=self,execution_enabled=True)
                self._adapters[phase] = adapter; self._issued[phase] = (plan,authorization)
                return dict(contract=CONTRACT,step=phase[0],restore=phase[1],authorization_ref=authorization.authorization_ref,
                    expires_at=authorization.expires_at,native_backend_qualified=False)
        except Exception: raise ValueError(_ERROR) from None

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            phase = next(p for p,pair in self._issued.items() if pair[0] is plan and pair[1] is authorization)
            self._gate(phase)
            if type(now_epoch) is not int or now_epoch > self._session._now(): raise ValueError
            self._authority.verify(plan,authorization,now_epoch=now_epoch); self._gate(phase)
        except Exception: raise M4AuthorizationDenied(_ERROR) from None

    def execute(self, authorization_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str,object]:
        try:
            with self._session._lock:
                self._identity(requester_digest,transport_digest); require_ref(authorization_ref,'email-alert authorization')
                phase,(plan,authorization) = next((p,pair) for p,pair in self._issued.items() if pair[1].authorization_ref == authorization_ref)
                if phase in self._results:
                    self._integrity(query=True)
                    return {**replace(self._results[phase],idempotent_replay=True).as_dict(),'native_backend_qualified':False,'delivery_verified':False}
                if phase in self._attempted: raise ValueError
                self.verify(plan,authorization,now_epoch=self._session._now()); self._attempted.add(phase)
                adapter = self._adapters[phase]
                try: result = M4ExecutionKernel(adapter,self,self._store,clock=self._session._now).execute(plan,authorization)
                except BaseException:
                    try:
                        untouched = (self._store.claim_count == adapter._step.claim_index-1 and not adapter._dispatched
                            and not adapter._send_admitted and adapter._receipt is None)
                    except Exception: untouched = False
                    if untouched: self._attempted.discard(phase)
                    raise
                self._results[phase] = result
                return {**result.as_dict(),'native_backend_qualified':False,'delivery_verified':False}
        except Exception: raise ValueError(_ERROR) from None

    def outcome(self, *, requester_digest: str, transport_digest: str) -> dict[str,object]:
        try:
            with self._session._lock:
                self._identity(requester_digest,transport_digest); self._integrity(query=True)
                verified: dict[str,bool] = {}; unresolved = False
                for phase in PHASES:
                    result = self._results.get(phase); local = False
                    if phase in self._attempted:
                        claim = self._adapters[phase]._claim()
                        local = (result is not None and result.outcome == 'succeeded' and result.verification == 'verified'
                            and claim.result == result and self._adapters[phase]._receipt is not None and self._adapters[phase]._post_verified)
                        if not local: unresolved = True
                    verified[phase[0]+('_restore' if phase[1] else '_update')] = local
                required = [(name,restore) for name in self._session._initial.changed_steps for restore in (False,True)]
                complete = all(verified[name+('_restore' if restore else '_update')] for name,restore in required)
                forward = {name for name in self._session._initial.changed_steps if verified[name+'_update']}
                reverse = {name for name in self._session._initial.changed_steps if verified[name+'_restore']}
                state = ('reconciliation_required' if unresolved else 'verified_locally' if complete else
                    'partial_prefix_restored_locally' if reverse and forward == reverse else 'in_progress_locally' if self._attempted else 'not_started')
                return dict(contract=CONTRACT,workflow_outcome=state,phase_verified_locally=verified,
                    execution_claims=self._store.claim_count,native_backend_qualified=False,delivery_verified=False,
                    live_configuration_verified=False,configuration_restore_does_not_recall_mail=True)
        except Exception: raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._session._lock: self._closed = True
