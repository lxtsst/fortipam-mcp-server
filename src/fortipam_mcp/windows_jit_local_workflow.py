"""Fixed local JIT workflow with independent per-step authority; no startup binding."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
import hashlib
import hmac
import secrets
from typing import Literal, Protocol

from v4_planning import (DenyAllM4AuthorizationVerifier, M4AuthorizationDenied, M4AuthorizationVerifier, M4ExecutionAuthorization,
    M4ExecutionKernel, M4ExecutionPlan, M4ExecutionResult, canonical_digest)
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .m4_execution_store import PersistentM4ExecutionStateStore
from .windows_jit_script_m4 import (CONTRACT as SCRIPT_ADAPTER, JitScriptStep,
    WindowsJitScriptM4Adapter, WindowsJitScriptM4Session)
from .windows_jit_secret_contract import WindowsJitSecretPlan
from .windows_jit_secret_m4 import (CONTRACT as SECRET_ADAPTER, JitSecretBackend, JitSecretEvidenceReader,
    JitSecretExecutionScope, JitSecretStep, WindowsJitSecretM4Adapter, WindowsJitSecretM4Session)
from .windows_jit_secret_source import WindowsJitSecretSource

CONTRACT = 'fortipam_v4_windows_jit_local_workflow_v1'
_ERROR = 'The private Windows JIT workflow is unavailable.'
Phase = Literal['grant_create','revoke_create','configure','restore','revoke_remove','grant_remove']
PHASES: tuple[Phase,...] = ('grant_create','revoke_create','configure','restore','revoke_remove','grant_remove')
_SCRIPT_PHASES = {'grant_create':(0,False),'revoke_create':(1,False),'revoke_remove':(1,True),'grant_remove':(0,True)}
Step = JitScriptStep | JitSecretStep
Adapter = WindowsJitScriptM4Adapter | WindowsJitSecretM4Adapter


class WindowsJitLocalBundle(_OpaqueC3Object):
    """One original Script session and one lazily bound Secret journal.

    The private backend factory accepts only the actual fixed Secret plan;
    inputs and source/material/effects identities are pinned before any grant.
    """
    def __init__(self, scripts: WindowsJitScriptM4Session, secret_source: WindowsJitSecretSource,
            secret_scope: JitSecretExecutionScope, secret_evidence: JitSecretEvidenceReader,
            secret_store: PersistentM4ExecutionStateStore,
            secret_backend_factory: Callable[[WindowsJitSecretPlan],JitSecretBackend], *,
            source_guard: Callable[[],bool] | None = None) -> None:
        try:
            if (type(scripts) is not WindowsJitScriptM4Session or type(secret_source) is not WindowsJitSecretSource
                    or secret_source._scripts is not scripts._source or type(secret_scope) is not JitSecretExecutionScope
                    or secret_scope.requester_digest != scripts._scope.requester_digest
                    or secret_scope.configuration_source_digest != secret_source._source
                    or not isinstance(secret_evidence,JitSecretEvidenceReader)
                    or type(secret_store) is not PersistentM4ExecutionStateStore
                    or not callable(secret_backend_factory) or source_guard is not None and not callable(source_guard)): raise ValueError
            self._scripts,self._source,self._scope,self._evidence,self._store = scripts,secret_source,secret_scope,secret_evidence,secret_store
            self._factory = self._factory_pin = secret_backend_factory
            self._guard = self._guard_pin = source_guard; self._checkpoint = secret_store._monotonic_checkpoint
            self._secret: WindowsJitSecretM4Session | None = None
            self._steps: dict[Phase,Step] = {}; self._claimed = False
            with scripts._lock:
                scripts._pins(); secret_store.verify_ready()
                if (scripts._jit_workflow is not None or scripts._jit_secret_session is not None
                        or scripts._store.claim_count or scripts._pending is not None or scripts._adapters
                        or secret_store.claim_count or not secret_store.monotonic_checkpoint_protocol_bound
                        or secret_store._path.resolve() == scripts._store._path.resolve()
                        or secret_store._key_path.resolve() == scripts._store._key_path.resolve()): raise ValueError
                self._root = self._domain(); self.integrity()
                scripts._jit_workflow = self; self._claimed = True
        except Exception: raise ValueError(_ERROR) from None

    def _domain(self) -> str:
        s = self._store
        if not hmac.compare_digest(s._key,s._load_key()): raise ValueError
        return canonical_digest(dict(contract=CONTRACT,scripts=self._scripts._domain_pin,
            secret_source=self._source._source,secret_binding=asdict(self._source._binding),schema=self._source._schema_pin,
            scope=asdict(self._scope),database=hashlib.sha256(str(s._path.resolve()).encode()).hexdigest(),
            key_file=hashlib.sha256(str(s._key_path.resolve()).encode()).hexdigest(),key=hashlib.sha256(s._key).hexdigest(),
            checkpoint=s._checkpoint_store_ref,authority=getattr(s._monotonic_checkpoint,'authority_ref',None)))

    def integrity(self) -> None:
        self._scripts._pins(); self._source._available(); self._store.verify_ready()
        if (self._claimed and self._scripts._jit_workflow is not self or self._domain() != self._root
                or self._store._monotonic_checkpoint is not self._checkpoint or self._factory is not self._factory_pin
                or self._guard is None or self._guard is not self._guard_pin or self._guard() is not True
                or self._scripts._jit_secret_session is not self._secret): raise ValueError(_ERROR)

    def _secret_session(self) -> WindowsJitSecretM4Session:
        self.integrity()
        if self._secret is None:
            self._scripts._settled()
            for i in (0,1): self._scripts._adapters[(i,False)]._require_verified()
            plan = self._source.prepare_plan(); backend = self._factory(plan)
            self._secret = WindowsJitSecretM4Session(self._source,plan,self._scripts,self._scope,backend,
                self._evidence,self._store,source_guard=self._guard)
        return self._secret

    def prepare(self, phase: Phase) -> Step:
        with self._scripts._lock:
            self.integrity()
            if phase in _SCRIPT_PHASES:
                index,remove = _SCRIPT_PHASES[phase]; step: Step = self._scripts.prepare_step(index,remove=remove)
            elif phase == 'configure': step = self._secret_session().prepare_step()
            elif phase == 'restore' and self._secret is not None: step = self._secret.prepare_step(restore=True)
            else: raise ValueError(_ERROR)
            self._steps[phase] = step; return step

    def binding(self, phase: Phase, step: Step) -> tuple[str,str,str]:
        if phase in _SCRIPT_PHASES and type(step) is JitScriptStep:
            index,remove = _SCRIPT_PHASES[phase]
            if (step.index,step.remove) != (index,remove): raise ValueError(_ERROR)
            target = 'jit-script-'+canonical_digest(dict(definitions=self._scripts._source._definition_digest,index=index))
            return step.action_id,SCRIPT_ADAPTER,target
        if phase in ('configure','restore') and type(step) is JitSecretStep and step.restore is (phase == 'restore'):
            return step.action_id,SECRET_ADAPTER,'jit-secret-'+canonical_digest(self._source._binding.identity)
        raise ValueError(_ERROR)

    def current_step(self, phase: Phase) -> Step:
        self.integrity(); step = self._steps[phase]; self.binding(phase,step)
        session = self._scripts if type(step) is JitScriptStep else self._secret
        if session is None or session._prepared is not step: raise ValueError(_ERROR)
        return step

    def bind(self, phase: Phase, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
            verifier: M4AuthorizationVerifier) -> tuple[Adapter,PersistentM4ExecutionStateStore]:
        step = self.current_step(phase)
        if type(step) is JitScriptStep:
            return self._scripts.bind_step(step,plan,authorization,authorization_verifier=verifier,execution_enabled=True),self._scripts._store
        if self._secret is None or type(step) is not JitSecretStep: raise ValueError(_ERROR)
        return self._secret.bind_step(step,plan,authorization,authorization_verifier=verifier,execution_enabled=True),self._store

    def release_expired_unused(self, phase: Phase, adapter: Adapter) -> None:
        self.integrity()
        if phase in _SCRIPT_PHASES and type(adapter) is WindowsJitScriptM4Adapter:
            self._scripts._release_expired_unused(adapter)
        elif phase in ('configure','restore') and type(adapter) is WindowsJitSecretM4Adapter and self._secret is not None:
            self._secret._release_expired_unused(adapter)
        else: raise ValueError(_ERROR)
        self._steps.pop(phase,None)


@dataclass(frozen=True,slots=True,repr=False)
class JitAuthorizationRequest(_OpaqueC3Object):
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


class JitWorkflowAuthority(Protocol):
    def authorize(self, request: JitAuthorizationRequest) -> tuple[M4ExecutionPlan,M4ExecutionAuthorization]: ...
    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None: ...


class DenyAllJitWorkflowAuthority(DenyAllM4AuthorizationVerifier):
    def authorize(self, request: JitAuthorizationRequest) -> tuple[M4ExecutionPlan,M4ExecutionAuthorization]:
        raise M4AuthorizationDenied(_ERROR)


def jit_preview_content(phase: Phase, preview_ref: str, created_at: int, *, policy_mode: str | None = None) -> dict[str,object]:
    if phase not in PHASES: raise ValueError(_ERROR)
    public: dict[str,object] = dict(contract=CONTRACT,phase=phase,preview_ref=preview_ref,expires_at=created_at+60,
        **{'Current State':dict(original_plan_bound_locally=True,independent_preconditions_reported=True,
                original_receipt_and_sealed_readback_required=phase in ('restore','grant_remove','revoke_remove')),
           'Proposed Changes':dict(create_fixed_definition=phase.endswith('_create'),remove_owned_definition=phase.endswith('_remove'),
                definition_purpose=('local_administrators_membership_grant' if phase.startswith('grant_') else
                    'local_administrators_membership_revoke') if phase in _SCRIPT_PHASES else None,
                script_execution_requested=False,configure_fixed_checkout=phase == 'configure',
                checkout_duration_minutes=5 if phase == 'configure' else None,
                renewal_enabled=False if phase == 'configure' else None,checkin_password_change_requested=False,
                restore_original_checkout=phase == 'restore',credential_submitted=False),
           'Expected State':dict(fixed_readback_required=True,independent_material_continuity_required=phase in ('configure','restore'),
                separate_recovery_grant_required=True),
           'Security Changes':dict(script_failure_blocks_checkout=False,group_removal_revokes_existing_logon_privilege=False,
                configuration_proves_privilege=False)},
        execution_authorized=False,device_write_executed=False,native_backend_qualified=False,jit_privilege_effect_verified=False)
    if policy_mode is not None: public['authorization_policy_mode'] = policy_mode
    return public


class WindowsJitLocalWorkflow(_OpaqueC3Object):
    def __init__(self, bundle: WindowsJitLocalBundle, *, allowed_transport_digest: str,
            authority: JitWorkflowAuthority | None = None, enabled_phases: tuple[Phase,...] = (),
            source_guard: Callable[[],bool] | None = None) -> None:
        try:
            if (type(bundle) is not WindowsJitLocalBundle or type(enabled_phases) is not tuple
                    or len(set(enabled_phases)) != len(enabled_phases) or any(p not in PHASES for p in enabled_phases)
                    or source_guard is not None and not callable(source_guard)): raise ValueError
            require_digest(allowed_transport_digest,'JIT client'); bundle.integrity()
            self._bundle,self._transport,self._requester = bundle,allowed_transport_digest,bundle._scope.requester_digest
            self._authority = authority or DenyAllJitWorkflowAuthority()
            self._guard = self._guard_pin = source_guard; self._enabled = {p:p in enabled_phases for p in PHASES}
            self._previews: dict[Phase,JitAuthorizationRequest] = {}
            self._issued: dict[Phase,tuple[M4ExecutionPlan,M4ExecutionAuthorization]] = {}
            self._adapters: dict[Phase,tuple[Adapter,PersistentM4ExecutionStateStore]] = {}
            self._results: dict[Phase,M4ExecutionResult] = {}; self._attempted: set[Phase] = set(); self._closed = False
        except Exception: raise ValueError(_ERROR) from None

    def _now(self) -> int:
        if self._closed: raise ValueError(_ERROR)
        return self._bundle._scripts._now()

    def _identity(self, requester_digest: str, transport_digest: str) -> None:
        self._now()
        if (requester_digest,transport_digest) != (self._requester,self._transport): raise ValueError(_ERROR)

    def _gate(self, phase: Phase) -> None:
        if (not self._enabled[phase] or self._guard is None or self._guard is not self._guard_pin
                or self._guard() is not True): raise ValueError(_ERROR)
        self._bundle.integrity(); self._now()

    def preview(self, phase: Phase, *, requester_digest: str, transport_digest: str) -> dict[str,object]:
        try:
            with self._bundle._scripts._lock:
                self._identity(requester_digest,transport_digest)
                if phase not in PHASES or phase in self._attempted: raise ValueError
                if phase in self._issued:
                    self._bundle.release_expired_unused(phase,self._adapters[phase][0])
                    del self._issued[phase]; del self._adapters[phase]
                step = self._bundle.prepare(phase); action,adapter,target = self._bundle.binding(phase,step)
                now = self._now(); ref = 'windows-jit-preview-'+secrets.token_hex(24)
                public = jit_preview_content(phase,ref,now,policy_mode=getattr(self._authority,'policy_mode',None))
                self._previews[phase] = JitAuthorizationRequest(phase,ref,requester_digest,transport_digest,self._bundle._root,
                    canonical_digest(public),step.parameters_digest,step.expected_current_digest,step.expected_state_digest,
                    action,adapter,target,now,now+60)
                return public
        except Exception: raise ValueError(_ERROR) from None

    def authorize(self, phase: Phase, preview_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str,object]:
        try:
            with self._bundle._scripts._lock:
                self._identity(requester_digest,transport_digest); self._gate(phase)
                if phase in self._attempted or phase in self._issued: raise ValueError
                request = self._previews[phase]
                if type(preview_ref) is not str or preview_ref != request.preview_ref or self._now() >= request.expires_at: raise ValueError
                plan,authorization = self._authority.authorize(request)
                if (type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization
                        or plan.summary_digest != request.summary_digest or plan.parameters_digest != request.parameters_digest
                        or (plan.expected_current_digest,plan.expected_state_digest) != (request.expected_current_digest,request.expected_state_digest)
                        or (plan.action_id,plan.adapter_ref,plan.target_ref) != (request.action_id,request.adapter_ref,request.target_ref)
                        or plan.expires_at != request.expires_at
                        or not request.created_at <= authorization.issued_at <= self._now() < authorization.expires_at <= request.expires_at): raise ValueError
                self._gate(phase); self._authority.verify(plan,authorization,now_epoch=self._now())
                self._adapters[phase] = self._bundle.bind(phase,plan,authorization,self)
                self._issued[phase] = (plan,authorization)
                return dict(contract=CONTRACT,phase=phase,authorization_ref=authorization.authorization_ref,
                    expires_at=authorization.expires_at,native_backend_qualified=False)
        except Exception: raise ValueError(_ERROR) from None

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            phase = next(p for p,pair in self._issued.items() if pair[0] is plan and pair[1] is authorization)
            self._gate(phase)
            if type(now_epoch) is not int or now_epoch > self._now(): raise ValueError
            self._authority.verify(plan,authorization,now_epoch=now_epoch); self._gate(phase)
        except Exception: raise M4AuthorizationDenied(_ERROR) from None

    def execute(self, phase: Phase, authorization_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str,object]:
        try:
            with self._bundle._scripts._lock:
                self._identity(requester_digest,transport_digest); plan,authorization = self._issued[phase]
                if type(authorization_ref) is not str or authorization_ref != authorization.authorization_ref: raise ValueError
                if phase in self._results: return {**replace(self._results[phase],idempotent_replay=True).as_dict(),
                    'native_backend_qualified':False,'jit_privilege_effect_verified':False}
                if phase in self._attempted: raise ValueError
                self.verify(plan,authorization,now_epoch=self._now()); self._attempted.add(phase)
                adapter,store = self._adapters[phase]
                try:
                    result = M4ExecutionKernel(adapter,self,store,clock=self._now).execute(plan,authorization)
                except BaseException:
                    try:
                        untouched = (store.claim_count == adapter._step.claim_index-1 and not adapter._dispatched
                            and not adapter._send_admitted and adapter._receipt is None)
                    except Exception: untouched = False
                    if untouched: self._attempted.discard(phase)
                    raise
                self._results[phase] = result
                return {**result.as_dict(),'native_backend_qualified':False,'jit_privilege_effect_verified':False}
        except Exception: raise ValueError(_ERROR) from None

    def outcome(self, *, requester_digest: str, transport_digest: str) -> dict[str,object]:
        try:
            with self._bundle._scripts._lock:
                self._identity(requester_digest,transport_digest)
                verified = {p:p in self._results and self._results[p].outcome == 'succeeded'
                    and self._results[p].verification == 'verified' for p in PHASES}
                state = ('verified_locally' if all(verified.values()) else 'reconciliation_required' if
                    any(not verified[p] for p in self._attempted) else 'in_progress_locally' if self._attempted else 'not_started')
                return dict(contract=CONTRACT,workflow_outcome=state,phase_verified_locally=verified,
                    script_execution_claims=self._bundle._scripts._store.claim_count,secret_execution_claims=self._bundle._store.claim_count,
                    native_backend_qualified=False,jit_privilege_effect_verified=False)
        except Exception: raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._bundle._scripts._lock: self._closed = True
