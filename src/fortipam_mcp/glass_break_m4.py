"""Default-closed original-receipt glass-breaking lifecycle on one cookie window.

Activation reserves time for independently authorized deactivation. A late exit
may reduce privilege but cannot prove the declared duration. Neither logout nor
authorization expiry is native deactivation. No real eligibility producer,
scheduler, implicit compensation, role/Secret access or runtime Tool is supplied.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict,dataclass
import hashlib
import hmac
from threading import RLock
from typing import Protocol,runtime_checkable

from v4_planning import (DenyAllM4AuthorizationVerifier,M4AdapterAmbiguous,M4AdapterDenied,
    M4AuthorizationVerifier,M4ExecutionAuthorization,M4ExecutionPlan,canonical_digest)
from v4_planning.execution_kernel import M4Claim,_require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest
from .glass_break_contract import GlassBreakPlan
from .glass_break_source import GlassBreakObservation,GlassBreakSource
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable

CONTRACT = 'fortipam_glass_break_original_m4_local_v1'
_ERROR = 'The private glass-breaking M4 candidate is unavailable.'


@dataclass(frozen=True,slots=True,repr=False)
class GlassBreakExecutionScope(_OpaqueC3Object):
    binding_digest: str
    requester_digest: str
    scope_digest: str
    audience_digest: str
    configuration_source_digest: str
    effects_source_digest: str
    effects_digest: str
    incident_digest: str
    maximum_elevation_seconds: int
    exit_reserve_seconds: int

    def __post_init__(self) -> None:
        for key,value in asdict(self).items():
            if key.endswith('_digest'): require_digest(value,'glass-breaking execution scope')
        if (self.configuration_source_digest==self.effects_source_digest
                or type(self.maximum_elevation_seconds) is not int or not 1<=self.maximum_elevation_seconds<=300
                or type(self.exit_reserve_seconds) is not int or not 1<=self.exit_reserve_seconds<=30): raise ValueError


@dataclass(frozen=True,slots=True,repr=False)
class GlassBreakEvidence(_OpaqueC3Object):
    source_digest: str
    configuration_digest: str
    effects_digest: str
    activation_receipt_digest: str | None
    phase_receipt_digest: str | None
    actor_permission_verified: bool
    complete_native_role_schema_verified: bool
    account_and_session_scope_verified: bool
    object_history_clear_verified: bool
    isolated_instance_verified: bool
    incident_drill_scope_authorized: bool
    operator_approver_separation_verified: bool
    independent_observer_ready: bool
    native_action_ack_semantics_verified: bool
    audit_recording_preserved: bool
    log_export_preserved: bool
    notification_scope_verified: bool
    reason_audit_supported_verified: bool
    maximum_duration_enforcement_ready: bool
    out_of_band_deactivation_ready: bool
    no_secret_access_or_launch_verified: bool
    post_incident_review_rotation_plan_verified: bool
    activation_notification_observed: bool
    reason_retained_verified: bool
    deactivation_observed: bool
    original_continuity_verified: bool
    phase_receipt_correlated: bool
    complete: bool
    pending_notifications: int
    active_uncontrolled_sessions: int
    observed_at: int
    expires_at: int

    def __post_init__(self) -> None:
        for name in ('source_digest','configuration_digest','effects_digest'): require_digest(getattr(self,name),'glass-breaking evidence')
        for name in ('activation_receipt_digest','phase_receipt_digest'):
            value=getattr(self,name)
            if value is not None: require_digest(value,'glass-breaking receipt correlation')
        for name,value in asdict(self).items():
            if name.endswith('_digest') or name in ('pending_notifications','active_uncontrolled_sessions','observed_at','expires_at'): continue
            if type(value) is not bool: raise ValueError
        if (any(type(value) is not int or value<0 for value in (self.pending_notifications,self.active_uncontrolled_sessions))
                or type(self.observed_at) is not int or type(self.expires_at) is not int
                or not 0<=self.observed_at<self.expires_at<=self.observed_at+10): raise ValueError


@runtime_checkable
class GlassBreakEvidenceReader(Protocol):
    def observe(self, configuration_digest: str, *, deactivate: bool, activation_receipt_digest: str | None,
            phase_receipt_digest: str | None) -> GlassBreakEvidence: ...


@dataclass(frozen=True,slots=True,repr=False)
class GlassBreakReceipt(_OpaqueC3Object):
    source_digest: str
    parameters_digest: str
    deactivate: bool
    ack_digest: str

    def __post_init__(self) -> None:
        for value in (self.source_digest,self.parameters_digest,self.ack_digest): require_digest(value,'glass-breaking receipt')
        if type(self.deactivate) is not bool: raise ValueError

    @property
    def digest(self) -> str: return canonical_digest(asdict(self))


@runtime_checkable
class GlassBreakBackend(Protocol):
    def submit(self, body: memoryview, *, deactivate: bool, parameters_digest: str,
            before_send: Callable[[],int], timeout_seconds: int) -> GlassBreakReceipt: ...


@dataclass(frozen=True,slots=True,repr=False)
class GlassBreakStep(_OpaqueC3Object):
    deactivate: bool
    parameters_digest: str
    expected_current_digest: str
    expected_state_digest: str
    claim_index: int
    observed_at: int
    fresh_until: int
    expires_at: int
    declared_duration_overdue: bool

    @property
    def action_id(self) -> str: return 'glass-break-'+('deactivate' if self.deactivate else 'activate')


class GlassBreakM4Session(_OpaqueC3Object):
    def __init__(self, source: GlassBreakSource, initial: GlassBreakPlan, scope: GlassBreakExecutionScope,
            backend: GlassBreakBackend, evidence: GlassBreakEvidenceReader, store: PersistentM4ExecutionStateStore, *,
            source_guard: Callable[[],bool] | None = None) -> None:
        try:
            if (type(source) is not GlassBreakSource or type(initial) is not GlassBreakPlan or type(scope) is not GlassBreakExecutionScope
                    or source._plan is not initial or source._origin is None or source._origin is not source._latest
                    or source._origin.state is not initial.baseline or source._m4_session is not None
                    or scope.configuration_source_digest!=source._binding.source_digest or scope.incident_digest!=initial.incident.digest
                    or not isinstance(backend,GlassBreakBackend) or not isinstance(evidence,GlassBreakEvidenceReader)
                    or type(store) is not PersistentM4ExecutionStateStore or source_guard is not None and not callable(source_guard)): raise ValueError
            initial.__post_init__(); scope.__post_init__(); source._available(); store.verify_ready()
            if store.claim_count or not store.monotonic_checkpoint_protocol_bound: raise ValueError
            self._source,self._initial,self._scope,self._backend,self._evidence,self._store=source,initial,scope,backend,evidence,store
            self._origin,self._checkpoint=source._origin,store._monotonic_checkpoint
            self._guard=self._guard_pin=source_guard; self._failed=False
            self._pending: GlassBreakM4Adapter | None = None
            self._prepared: GlassBreakStep | None = None
            self._adapters: dict[bool,GlassBreakM4Adapter] = {}; self._settled_count=0
            self._workflow: object | None = None
            self._activation_epoch: int | None = None
            self._activation_mono: float | None = None
            self._duration_verified_locally: bool | None = None
            self._lock=RLock()
            if not self._origin.observed_at<=self._now()<self._origin.expires_at: raise ValueError
            self._domain_pin=self._domain(); self._pins(binding=True); source._m4_session=self
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def _now(self) -> int:
        if self._failed: raise M4AdapterDenied(_ERROR)
        return self._source._epoch()

    def _domain(self) -> str:
        store=self._store
        if not hmac.compare_digest(store._key,store._load_key()): raise ValueError
        return canonical_digest(dict(contract=CONTRACT,scope=asdict(self._scope),initial=self._initial.digest,
            database=hashlib.sha256(str(store._path.resolve()).encode()).hexdigest(),
            key_file=hashlib.sha256(str(store._key_path.resolve()).encode()).hexdigest(),key=hashlib.sha256(store._key).hexdigest(),
            checkpoint=store._checkpoint_store_ref,authority=getattr(store._monotonic_checkpoint,'authority_ref',None)))

    def _pins(self, *, binding: bool=False) -> None:
        self._source._available(); self._now(); self._store.verify_ready()
        if (self._domain()!=self._domain_pin or self._store._monotonic_checkpoint is not self._checkpoint
                or self._source._plan is not self._initial or self._source._origin is not self._origin
                or (self._source._m4_session is not None if binding else self._source._m4_session is not self)
                or self._guard is None or self._guard is not self._guard_pin or self._guard() is not True): raise ValueError

    def _state(self, configuration: str) -> str:
        return canonical_digest(dict(contract=CONTRACT,configuration=configuration,effects=self._scope.effects_digest,
            configuration_source=self._scope.configuration_source_digest,effects_source=self._scope.effects_source_digest))

    def _snapshot(self, deactivate: bool, activation: GlassBreakReceipt | None, phase: GlassBreakReceipt | None
            ) -> tuple[GlassBreakObservation,int]:
        self._pins(); observed=self._source.read(); now=self._now()
        expected_activation=None if activation is None else activation.digest
        expected_phase=None if phase is None else phase.digest
        evidence=self._evidence.observe(observed.state.digest,deactivate=deactivate,
            activation_receipt_digest=expected_activation,phase_receipt_digest=expected_phase)
        if (type(evidence) is not GlassBreakEvidence or evidence.source_digest!=self._scope.effects_source_digest
                or evidence.configuration_digest!=observed.state.digest or evidence.effects_digest!=self._scope.effects_digest
                or evidence.activation_receipt_digest!=expected_activation or evidence.phase_receipt_digest!=expected_phase
                or evidence.original_continuity_verified is not (activation is not None)
                or evidence.phase_receipt_correlated is not (phase is not None)
                or evidence.activation_notification_observed is not (activation is not None)
                or evidence.reason_retained_verified is not (activation is not None)
                or evidence.deactivation_observed is not (deactivate and phase is not None)
                or evidence.pending_notifications!=0 or evidence.active_uncontrolled_sessions!=0
                or not all((evidence.actor_permission_verified,evidence.complete_native_role_schema_verified,
                    evidence.account_and_session_scope_verified,evidence.object_history_clear_verified,evidence.isolated_instance_verified,
                    evidence.incident_drill_scope_authorized,evidence.operator_approver_separation_verified,evidence.independent_observer_ready,
                    evidence.native_action_ack_semantics_verified,evidence.audit_recording_preserved,evidence.log_export_preserved,evidence.notification_scope_verified,
                    evidence.reason_audit_supported_verified,evidence.maximum_duration_enforcement_ready,evidence.out_of_band_deactivation_ready,
                    evidence.no_secret_access_or_launch_verified,evidence.post_incident_review_rotation_plan_verified,evidence.complete))
                or not observed.observed_at<=now<observed.expires_at or not evidence.observed_at<=now<evidence.expires_at): raise ValueError
        self._pins(); fresh_until=min(observed.expires_at,evidence.expires_at)
        if self._now()>=fresh_until: raise ValueError
        return observed,fresh_until

    def _overdue(self) -> bool:
        if self._activation_epoch is None or self._activation_mono is None: raise ValueError
        return (self._now()>self._activation_epoch+self._scope.maximum_elevation_seconds
            or self._source._now()>self._activation_mono+self._scope.maximum_elevation_seconds)

    def _settled(self) -> None:
        self._pins()
        if self._pending is not None:
            adapter=self._pending; result=adapter._claim().result
            if result is None or self._store.claim_count!=adapter._step.claim_index: raise ValueError
            try: adapter._require_verified()
            except Exception: self._failed=True; raise
            self._settled_count=adapter._step.claim_index; self._pending=None
        if self._store.claim_count!=self._settled_count: raise ValueError

    def prepare_step(self, *, deactivate: bool=False) -> GlassBreakStep:
        try:
            with self._lock:
                self._settled()
                if type(deactivate) is not bool or deactivate in self._adapters: raise ValueError
                original=self._adapters.get(False) if deactivate else None
                if deactivate:
                    if original is None: raise ValueError
                    original._require_verified()
                elif self._adapters: raise ValueError
                receipt=None if original is None else original._receipt
                observed,fresh_until=self._snapshot(deactivate,receipt,None)
                current=self._initial.expected() if deactivate else self._initial.baseline
                expected=self._initial.baseline if deactivate else self._initial.expected()
                if observed.state.digest!=current.digest: raise ValueError
                now=self._now(); remaining=int(self._source._owner_expiry-self._source._now())
                reserve=1 if deactivate else self._scope.maximum_elevation_seconds+self._scope.exit_reserve_seconds
                expires=min(observed.observed_at+60,now+remaining-reserve)
                if now>=expires: raise ValueError
                parameters=canonical_digest(dict(domain=self._domain_pin,deactivate=deactivate,
                    original_receipt=None if receipt is None else receipt.digest))
                step=GlassBreakStep(deactivate,parameters,self._state(current.digest),self._state(expected.digest),self._settled_count+1,
                    observed.observed_at,fresh_until,expires,self._overdue() if deactivate else False)
                self._prepared=step; return step
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def bind_step(self, step: GlassBreakStep, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *,
            authorization_verifier: M4AuthorizationVerifier | None=None, execution_enabled: bool=False) -> GlassBreakM4Adapter:
        try:
            with self._lock:
                self._pins()
                if (type(step) is not GlassBreakStep or step is not self._prepared or self._pending is not None
                        or self._store.claim_count!=step.claim_index-1 or not step.observed_at<=self._now()<min(step.fresh_until,step.expires_at)): raise ValueError
                adapter=GlassBreakM4Adapter(self,step,plan,authorization,authorization_verifier=authorization_verifier,execution_enabled=execution_enabled)
                self._adapters[step.deactivate]=adapter; self._pending=adapter; return adapter
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def _release_expired_unused(self, adapter: GlassBreakM4Adapter) -> None:
        try:
            with self._lock:
                self._pins()
                if (type(adapter) is not GlassBreakM4Adapter or self._pending is not adapter or self._prepared is not adapter._step
                        or self._adapters.get(adapter._step.deactivate) is not adapter or self._store.claim_count!=adapter._step.claim_index-1
                        or adapter._receipt is not None or any((adapter._dispatched,adapter._send_admitted,adapter._send_verified,adapter._post_verified))
                        or self._now()<min(adapter._plan.expires_at,adapter._authorization.expires_at,adapter._step.expires_at)): raise ValueError
                del self._adapters[adapter._step.deactivate]; self._pending=None; self._prepared=None
        except Exception: raise M4AdapterDenied(_ERROR) from None


class GlassBreakM4Adapter(_OpaqueC3Object):
    def __init__(self, session: GlassBreakM4Session, step: GlassBreakStep, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *,
            authorization_verifier: M4AuthorizationVerifier | None=None, execution_enabled: bool=False) -> None:
        if type(execution_enabled) is not bool: raise M4AdapterDenied(_ERROR)
        self._session,self._step,self._plan,self._authorization=session,step,plan,authorization
        self._verifier=authorization_verifier or DenyAllM4AuthorizationVerifier(); self._enabled=execution_enabled
        self._receipt: GlassBreakReceipt | None = None
        self._dispatched=self._send_admitted=self._send_verified=self._post_verified=False
        self._check_plan()

    def _check_plan(self) -> None:
        p,a,step=self._plan,self._authorization,self._step; p.__post_init__(); a.__post_init__()
        if (p.action_id!=step.action_id or p.action_version!='1.0.0' or p.adapter_ref!=CONTRACT or p.revision!=1
                or p.plan_ref!=step.action_id+'-'+step.parameters_digest or p.parameters_digest!=step.parameters_digest
                or p.target_ref!='glass-break-'+self._session._initial.baseline.binding_digest
                or p.requester_digest!=self._session._scope.requester_digest or p.compensation_ref is not None
                or (p.expected_current_digest,p.expected_state_digest)!=(step.expected_current_digest,step.expected_state_digest)
                or p.idempotency_digest!=canonical_digest(dict(action=step.action_id,parameters=step.parameters_digest))
                or a.plan_ref!=p.plan_ref or a.plan_digest!=p.plan_digest or a.requester_digest!=p.requester_digest
                or max(p.expires_at,a.expires_at)-a.issued_at>60 or max(p.expires_at,a.expires_at)>step.expires_at): raise M4AdapterDenied(_ERROR)

    def _check(self) -> None:
        try:
            s=self._session; s._pins(); self._check_plan(); now=s._now()
            if (not self._enabled or s._pending is not self or s._adapters.get(self._step.deactivate) is not self
                    or s._store.claim_count!=self._step.claim_index
                    or not self._authorization.issued_at<=now<min(self._plan.expires_at,self._authorization.expires_at,self._step.expires_at)): raise ValueError
            self._verifier.verify(self._plan,self._authorization,now_epoch=now); s._pins()
            if s._now()>=min(self._plan.expires_at,self._authorization.expires_at,self._step.expires_at): raise ValueError
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def _claim(self) -> M4Claim:
        p,a=self._plan,self._authorization
        return self._session._store.inspect_claim(plan_ref=p.plan_ref,requester_digest=p.requester_digest,idempotency_digest=p.idempotency_digest,
            authorization_digest=a.authorization_digest,context_digest=canonical_digest(dict(plan_digest=p.plan_digest,authorization_digest=a.authorization_digest,revision=p.revision)))

    def _require_verified(self) -> None:
        result=self._claim().result
        if (self._receipt is None or not self._post_verified or result is None or result.outcome!='succeeded'
                or result.verification!='verified' or result.compensation!='not_requested'): raise M4AdapterDenied(_ERROR)

    def _snapshot(self) -> str:
        s=self._session
        original=s._adapters[False] if self._step.deactivate else self
        if self._step.deactivate: original._require_verified()
        observed,_=s._snapshot(self._step.deactivate,original._receipt,self._receipt)
        return s._state(observed.state.digest)

    def read_current(self, plan: M4ExecutionPlan) -> str:
        with self._session._lock:
            if plan is not self._plan: raise M4AdapterDenied(_ERROR)
            self._check()
            try:
                state=self._snapshot(); self._check(); return state
            except Exception: raise M4AdapterAmbiguous(_ERROR) from None

    def _before_send(self) -> int:
        _require_m4_dispatch_ownership(self._plan,self._authorization,self._session._store)
        with self._session._lock:
            self._check()
            if self._send_admitted: raise M4AdapterDenied(_ERROR)
            self._send_admitted=True
            if self.read_current(self._plan)!=self._step.expected_current_digest: raise M4AdapterDenied(_ERROR)
            s=self._session; self._check()
            if not self._step.deactivate:
                if s._source._owner_expiry-s._source._now()<s._scope.maximum_elevation_seconds+s._scope.exit_reserve_seconds: raise ValueError
            _require_m4_dispatch_ownership(self._plan,self._authorization,s._store)
            if not self._step.deactivate: s._activation_epoch,s._activation_mono=s._now(),s._source._now()
            self._send_verified=True
            return min(self._plan.expires_at,self._authorization.expires_at,self._step.expires_at)-s._now()

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        _require_m4_dispatch_ownership(plan,self._authorization,self._session._store)
        body=bytearray()
        with self._session._lock:
            if plan is not self._plan: raise M4AdapterDenied(_ERROR)
            self._check()
            if self._dispatched: raise M4AdapterDenied(_ERROR)
            self._dispatched=True
            try:
                s=self._session; deactivate=self._step.deactivate
                body=s._initial.compile(s._initial.expected() if deactivate else s._initial.baseline,deactivate=deactivate)
                with memoryview(body).toreadonly() as view:
                    receipt=s._backend.submit(view,deactivate=deactivate,parameters_digest=self._step.parameters_digest,
                        before_send=self._before_send,timeout_seconds=min(self._plan.expires_at,self._authorization.expires_at,self._step.expires_at)-s._now())
                if (not self._send_verified or type(receipt) is not GlassBreakReceipt or receipt.source_digest!=s._scope.configuration_source_digest
                        or receipt.parameters_digest!=self._step.parameters_digest or receipt.deactivate is not deactivate): raise ValueError
                self._receipt=receipt
                if self._snapshot()!=self._step.expected_state_digest: raise ValueError
                if deactivate: s._duration_verified_locally=not s._overdue()
                self._post_verified=True
            except Exception: raise M4AdapterAmbiguous(_ERROR) from None
            finally: _zeroize_mutable(body)

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        with self._session._lock:
            if plan is not self._plan: raise M4AdapterDenied(_ERROR)
            self._check()
            if self._receipt is None or not self._post_verified: raise M4AdapterAmbiguous(_ERROR)
            try:
                state=self._snapshot(); self._check(); return state
            except Exception: raise M4AdapterAmbiguous(_ERROR) from None
