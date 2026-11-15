"""Inactive glass-breaking lab policy over independent activation and exit grants.

Only the existing read-only Unix Reference client is used. This module cannot
issue/revoke grants or qualify native schema, session scope, incident isolation,
ACKs, duration enforcement or recovery.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict,dataclass
import hashlib
import hmac
from pathlib import Path
from typing import Any

from v4_planning import M4AuthorizationDenied,M4ExecutionAuthorization,M4ExecutionPlan,VerifiedReferenceDecision,canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest,require_ref
from .glass_break_local_workflow import (GlassBreakAuthorizationRequest,Phase,PHASES,
    glass_break_preview_content,glass_break_step_binding)
from .glass_break_m4 import GlassBreakM4Session,GlassBreakStep
from .ldap_server_runtime import _key
from .reference_authority_sidecar import UnixReferenceAuthorityClient

POLICY = 'fortipam-mcp-lab-auto-glass-break-local-candidate-v1'
PURPOSES = ('permission','standing_intent','lab_policy')
_ERROR = 'The private glass-break protected authorization is unavailable.'


@dataclass(frozen=True,slots=True,repr=False)
class _Issued(_OpaqueC3Object):
    request: GlassBreakAuthorizationRequest
    step: GlassBreakStep
    decisions: tuple[VerifiedReferenceDecision,...]
    issued_at: int
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization


class GlassBreakProtectedLabAuthority(_OpaqueC3Object):
    @property
    def policy_mode(self) -> str: return 'lab_auto'

    def __init__(self, session: GlassBreakM4Session, *, reference_authority: UnixReferenceAuthorityClient,
            authority_key_file: Path, transport_digest: str, environment_ref: str, scope_ref: str, audience_ref: str,
            execution_enabled: bool = False, source_guard: Callable[[],bool] | None = None) -> None:
        try:
            if (type(session) is not GlassBreakM4Session or type(reference_authority) is not UnixReferenceAuthorityClient
                    or type(execution_enabled) is not bool or source_guard is not None and not callable(source_guard)): raise ValueError
            require_digest(transport_digest,'glass-break client')
            for ref in (environment_ref,scope_ref,audience_ref): require_ref(ref,'glass-break lab scope')
            if (session._scope.scope_digest != canonical_digest(scope_ref) or session._scope.audience_digest != canonical_digest(audience_ref)
                    or session._adapters or session._store.claim_count): raise ValueError
            self._session = self._session_pin = session
            self._reference,self._settings = reference_authority,reference_authority._settings
            self._key_file = Path(authority_key_file); self._key = _key(self._key_file)
            if hmac.compare_digest(self._key,session._store._key): raise ValueError
            self._transport,self._environment,self._scope,self._audience = transport_digest,environment_ref,scope_ref,audience_ref
            self._enabled = execution_enabled; self._guard = self._guard_pin = source_guard; self._closed = False
            self._issued: dict[Phase,_Issued] = {}
            self._namespace = canonical_digest(self._namespace_content()); self._integrity()
        except Exception: raise M4AuthorizationDenied(_ERROR) from None

    def _namespace_content(self) -> dict[str,Any]:
        return dict(policy=POLICY,policy_mode='lab_auto',reason='disposable_lab_local_implementation',root=self._session._domain_pin,
            transport=self._transport,environment=self._environment,scope=self._scope,audience=self._audience,
            authority=self._reference.authority_ref,reference_socket=str(self._settings.socket_path),signing_key=hashlib.sha256(self._key).hexdigest())

    def _integrity(self) -> None:
        self._session._pins()
        if (self._session is not self._session_pin or self._reference._settings != self._settings
                or canonical_digest(self._namespace_content()) != self._namespace
                or not hmac.compare_digest(_key(self._key_file),self._key)): raise ValueError
        self._reference.verify_ready()

    def _live(self) -> int:
        if (self._closed or not self._enabled or self._guard is None or self._guard is not self._guard_pin
                or self._guard() is not True): raise ValueError
        self._integrity(); return self._session._now()

    def reference_for(self, phase: Phase, purpose: str) -> str:
        if phase not in PHASES or purpose not in PURPOSES: raise ValueError(_ERROR)
        return 'glass-break-reference-'+canonical_digest(dict(namespace=self._namespace,phase=phase,purpose=purpose))

    def _permissions(self, phase: Phase, now: int) -> tuple[VerifiedReferenceDecision,...]:
        decisions=[]
        for purpose in PURPOSES:
            ref=self.reference_for(phase,purpose); kind='glass_break_'+purpose
            decision=self._reference.authorize(ref,reference_kind=kind,requester_digest=self._session._scope.requester_digest,
                environment_ref=self._environment,scope_ref=self._scope,now_epoch=now)
            if (type(decision) is not VerifiedReferenceDecision or decision.authorized is not True
                    or decision.reference_digest != canonical_digest(ref) or decision.reference_kind != kind
                    or decision.requester_digest != self._session._scope.requester_digest or decision.authority_ref != self._reference.authority_ref
                    or decision.environment_digest != canonical_digest(self._environment) or decision.scope_digest != canonical_digest(self._scope)
                    or decision.checked_at != now or not now < decision.expires_at): raise ValueError
            decisions.append(decision)
        return tuple(decisions)

    def _request(self, request: GlassBreakAuthorizationRequest, now: int) -> GlassBreakStep:
        if type(request) is not GlassBreakAuthorizationRequest or request.phase not in PHASES: raise ValueError
        require_ref(request.preview_ref,'glass-breaking preview'); step=self._session._prepared
        if type(step) is not GlassBreakStep or step.deactivate is not (request.phase=='deactivate'): raise ValueError
        binding=glass_break_step_binding(self._session,step)
        if (type(request.created_at) is not int or request.created_at < 0 or type(request.expires_at) is not int
                or not request.created_at <= now < request.expires_at <= min(request.created_at+60,step.expires_at)
                or request.requester_digest != self._session._scope.requester_digest or request.transport_digest != self._transport
                or request.root_digest != self._session._domain_pin or (request.action_id,request.adapter_ref,request.target_ref) != binding
                or (request.parameters_digest,request.expected_current_digest,request.expected_state_digest)
                    != (step.parameters_digest,step.expected_current_digest,step.expected_state_digest)
                or request.summary_digest != canonical_digest(glass_break_preview_content(self._session,step,request.preview_ref,
                    request.created_at,request.expires_at,policy_mode='lab_auto'))): raise ValueError
        return step

    def _mac(self, purpose: str, value: Any) -> str:
        return hmac.new(self._key,POLICY.encode()+b'\0'+purpose.encode()+b'\0'+canonical_digest(value).encode(),hashlib.sha256).hexdigest()

    def _derive(self, request: GlassBreakAuthorizationRequest, decisions: tuple[VerifiedReferenceDecision,...], issued_at: int
            ) -> tuple[M4ExecutionPlan,M4ExecutionAuthorization]:
        context=dict(namespace=self._namespace,request=asdict(request),grants=[d.as_dict() for d in decisions],issued_at=issued_at)
        intent,approval=self._mac('standing-intent',context),self._mac('lab-policy',context)
        fields: dict[str,Any] = dict(plan_ref=request.action_id+'-'+request.parameters_digest,revision=1,action_id=request.action_id,
            action_version='1.0.0',adapter_ref=request.adapter_ref,target_ref=request.target_ref,requester_digest=request.requester_digest,
            summary_digest=request.summary_digest,confirmation_digest=intent,approval_digest=approval,parameters_digest=request.parameters_digest,
            expected_current_digest=request.expected_current_digest,expected_state_digest=request.expected_state_digest,
            idempotency_digest=canonical_digest(dict(action=request.action_id,parameters=request.parameters_digest)),expires_at=request.expires_at,compensation_ref=None)
        plan=M4ExecutionPlan(**fields,plan_digest=canonical_digest(fields))
        values: dict[str,Any] = dict(authorization_ref='glass-break-lab-auth-'+self._mac('authorization',context),plan_ref=plan.plan_ref,
            plan_digest=plan.plan_digest,requester_digest=request.requester_digest,confirmation_ref='glass-break-standing-intent-'+intent,
            confirmation_digest=intent,approval_ref='glass-break-lab-policy-'+approval,approval_digest=approval,
            approver_digest=self._mac('policy-principal',self._namespace),issued_at=issued_at,
            expires_at=min(request.expires_at,*(d.expires_at for d in decisions)),one_time=True,execution_authorized=True)
        return plan,M4ExecutionAuthorization(**values,authorization_digest=canonical_digest(values))

    def authorize(self, request: GlassBreakAuthorizationRequest) -> tuple[M4ExecutionPlan,M4ExecutionAuthorization]:
        try:
            with self._session._lock:
                now=self._live(); self._request(request,now); phase=request.phase
                decisions=self._permissions(phase,now)
                self._session.prepare_step(deactivate=request.phase=='deactivate')
                now=self._live(); step=self._request(request,now); plan,authorization=self._derive(request,decisions,now)
                if now >= authorization.expires_at: raise ValueError
                self._issued[phase]=_Issued(request,step,decisions,now,plan,authorization)
                return plan,authorization
        except Exception: raise M4AuthorizationDenied(_ERROR) from None

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            with self._session._lock:
                issued=next(item for item in self._issued.values() if item.plan is plan and item.authorization is authorization)
                now=self._live(); step=self._request(issued.request,now)
                if (step is not issued.step or type(now_epoch) is not int or not authorization.issued_at <= now_epoch <= now < authorization.expires_at
                        or (plan,authorization) != self._derive(issued.request,issued.decisions,issued.issued_at)): raise ValueError
                current=self._permissions(issued.request.phase,now)
                if self._live() >= min(authorization.expires_at,*(d.expires_at for d in current)): raise ValueError
        except Exception: raise M4AuthorizationDenied(_ERROR) from None

    def close(self) -> None:
        with self._session._lock: self._closed=True
