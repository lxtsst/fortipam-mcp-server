"""Default-closed ordered alert updates and original-receipt reverse recovery.

Only a clean physical source/plan and checkpointed empty ledger may bind once.
Every changed object has separate authorization, ACK and complete readback.
UNKNOWN, interrupted or unsealed claims freeze the compound session. No real
eligibility producer, HTTP writer, MCP execution or native qualification exists
here; injected positive evidence/receipts are contracts, not authority by label.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict,dataclass
import hashlib
import hmac
from threading import RLock
import time
from typing import Protocol,runtime_checkable

from v4_planning import (DenyAllM4AuthorizationVerifier,M4AdapterAmbiguous,M4AdapterDenied,
    M4AuthorizationVerifier,M4ExecutionAuthorization,M4ExecutionPlan,canonical_digest)
from v4_planning.execution_kernel import M4Claim,_require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest
from .email_alert_compound_contract import EmailAlertCompoundPlan,Step,STEPS
from .email_alert_compound_source import EmailAlertCompoundObservation,EmailAlertCompoundSource
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable

CONTRACT = 'fortipam_email_alert_original_m4_local_v1'
_ERROR = 'The private email-alert M4 candidate is unavailable.'


@dataclass(frozen=True,slots=True,repr=False)
class EmailAlertExecutionScope(_OpaqueC3Object):
    binding_digest: str
    requester_digest: str
    scope_digest: str
    audience_digest: str
    configuration_source_digest: str
    effects_source_digest: str
    effects_digest: str

    def __post_init__(self) -> None:
        for value in asdict(self).values(): require_digest(value,'email-alert execution scope')
        if self.configuration_source_digest == self.effects_source_digest: raise ValueError


@dataclass(frozen=True,slots=True,repr=False)
class EmailAlertEvidence(_OpaqueC3Object):
    source_digest: str
    configuration_digest: str
    effects_digest: str
    original_receipt_digest: str | None
    actor_permission_verified: bool
    complete_native_schema_verified: bool
    critical_graph_qualified: bool
    object_history_clear_verified: bool
    native_put_semantics_verified: bool
    certificate_merge_verified: bool
    reverse_service_preservation_verified: bool
    certificate_device_model_verified: bool
    isolated_mail_service_verified: bool
    recipient_scope_verified: bool
    external_delivery_impact_accepted: bool
    sender_quiescent: bool
    independent_recovery_ready: bool
    original_continuity_verified: bool
    complete: bool
    pending_messages: int
    observed_at: int
    expires_at: int

    def __post_init__(self) -> None:
        for value in (self.source_digest,self.configuration_digest,self.effects_digest): require_digest(value,'email-alert evidence')
        if self.original_receipt_digest is not None: require_digest(self.original_receipt_digest,'email-alert custody')
        if (any(type(value) is not bool for key,value in asdict(self).items() if key.endswith(('_verified','_qualified','_accepted','_ready'))
                or key in ('sender_quiescent','complete')) or type(self.pending_messages) is not int or self.pending_messages < 0
                or type(self.observed_at) is not int or type(self.expires_at) is not int
                or not 0 <= self.observed_at < self.expires_at <= self.observed_at+10): raise ValueError


@runtime_checkable
class EmailAlertEvidenceReader(Protocol):
    def observe(self, configuration_digest: str, *, step: Step, restore: bool,
            original_receipt_digest: str | None) -> EmailAlertEvidence: ...


@dataclass(frozen=True,slots=True,repr=False)
class EmailAlertReceipt(_OpaqueC3Object):
    source_digest: str
    parameters_digest: str
    step: Step
    restore: bool
    native_ack_digest: str

    def __post_init__(self) -> None:
        for value in (self.source_digest,self.parameters_digest,self.native_ack_digest): require_digest(value,'email-alert receipt')
        if self.step not in STEPS or type(self.restore) is not bool: raise ValueError

    @property
    def digest(self) -> str: return canonical_digest(asdict(self))


@runtime_checkable
class EmailAlertBackend(Protocol):
    def submit(self, body: memoryview, *, step: Step, restore: bool, parameters_digest: str,
            before_send: Callable[[],int], timeout_seconds: int) -> EmailAlertReceipt: ...


@dataclass(frozen=True,slots=True,repr=False)
class EmailAlertStep(_OpaqueC3Object):
    name: Step
    restore: bool
    before: int
    after: int
    parameters_digest: str
    expected_current_digest: str
    expected_state_digest: str
    claim_index: int
    observed_at: int
    fresh_until: int
    expires_at: int

    @property
    def action_id(self) -> str:
        return 'email-alert-'+self.name.replace('_','-')+('-restore' if self.restore else '-update')


class EmailAlertM4Session(_OpaqueC3Object):
    def __init__(self, source: EmailAlertCompoundSource, initial: EmailAlertCompoundPlan, scope: EmailAlertExecutionScope,
            backend: EmailAlertBackend, evidence: EmailAlertEvidenceReader, store: PersistentM4ExecutionStateStore, *,
            source_guard: Callable[[],bool] | None = None, clock: Callable[[],int] = lambda:int(time.time())) -> None:
        try:
            if (type(source) is not EmailAlertCompoundSource or type(initial) is not EmailAlertCompoundPlan
                    or type(scope) is not EmailAlertExecutionScope or source._plan is not initial or source._origin is None
                    or source._origin is not source._latest or source._m4_session is not None
                    or source._origin.state.digest != initial.baseline.digest or not initial.changed_steps
                    or source._origin.source_digest != scope.configuration_source_digest
                    or not isinstance(backend,EmailAlertBackend) or not isinstance(evidence,EmailAlertEvidenceReader)
                    or type(store) is not PersistentM4ExecutionStateStore
                    or source_guard is not None and not callable(source_guard) or not callable(clock)): raise ValueError
            scope.__post_init__(); initial.__post_init__(); store.verify_ready()
            if store.claim_count or not store.monotonic_checkpoint_protocol_bound: raise ValueError
            self._source,self._initial,self._scope,self._backend,self._evidence,self._store = source,initial,scope,backend,evidence,store
            self._origin = source._origin; self._checkpoint = store._monotonic_checkpoint
            self._guard = self._guard_pin = source_guard; self._clock = clock
            self._last_now,self._failed,self._restoring = -1,False,False
            self._pending: EmailAlertM4Adapter | None = None
            self._prepared: EmailAlertStep | None = None
            self._workflow: object | None = None
            self._adapters: dict[tuple[Step,bool],EmailAlertM4Adapter] = {}
            self._applied: list[Step] = []; self._settled_count = 0; self._lock = RLock()
            if not self._origin.observed_at <= self._now() < self._origin.expires_at: raise ValueError
            self._domain_pin = self._domain(); self._pins(binding=True); source._m4_session = self
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def _now(self) -> int:
        now = self._clock()
        if self._failed or type(now) is not int or now < 0 or now < self._last_now:
            self._failed = True; raise M4AdapterDenied(_ERROR)
        self._last_now = now; return now

    def _domain(self) -> str:
        store = self._store
        if not hmac.compare_digest(store._key,store._load_key()): raise ValueError
        return canonical_digest(dict(contract=CONTRACT,scope=asdict(self._scope),initial=self._initial.digest,
            database=hashlib.sha256(str(store._path.resolve()).encode()).hexdigest(),
            key_file=hashlib.sha256(str(store._key_path.resolve()).encode()).hexdigest(),key=hashlib.sha256(store._key).hexdigest(),
            checkpoint=store._checkpoint_store_ref,authority=getattr(store._monotonic_checkpoint,'authority_ref',None)))

    def _pins(self, *, binding: bool = False) -> None:
        self._source._available(); self._now(); self._store.verify_ready()
        if (self._domain() != self._domain_pin or self._store._monotonic_checkpoint is not self._checkpoint
                or self._source._plan is not self._initial or self._source._origin is not self._origin
                or (self._source._m4_session is not None if binding else self._source._m4_session is not self)
                or self._guard is None or self._guard is not self._guard_pin or self._guard() is not True): raise ValueError

    def _state(self, configuration: str) -> str:
        return canonical_digest(dict(contract=CONTRACT,configuration=configuration,effects=self._scope.effects_digest,
            configuration_source=self._scope.configuration_source_digest,effects_source=self._scope.effects_source_digest))

    def _snapshot(self, name: Step, restore: bool, receipt: EmailAlertReceipt | None) -> tuple[EmailAlertCompoundObservation,int]:
        self._pins(); observed = self._source.read(); now = self._now()
        if observed.source_digest != self._scope.configuration_source_digest or not observed.observed_at <= now < observed.expires_at: raise ValueError
        expected_receipt = receipt.digest if receipt is not None else None
        evidence = self._evidence.observe(observed.state.digest,step=name,restore=restore,original_receipt_digest=expected_receipt)
        if (type(evidence) is not EmailAlertEvidence or evidence.source_digest != self._scope.effects_source_digest
                or evidence.configuration_digest != observed.state.digest or evidence.effects_digest != self._scope.effects_digest
                or evidence.original_receipt_digest != expected_receipt
                or evidence.original_continuity_verified is not (receipt is not None)
                or evidence.pending_messages != 0 or not all((evidence.actor_permission_verified,evidence.complete_native_schema_verified,
                    evidence.critical_graph_qualified,evidence.object_history_clear_verified,evidence.native_put_semantics_verified,evidence.isolated_mail_service_verified,
                    evidence.recipient_scope_verified,evidence.external_delivery_impact_accepted,evidence.sender_quiescent,
                    evidence.independent_recovery_ready,evidence.complete))
                or name == 'certificate' and not all((evidence.certificate_merge_verified,evidence.reverse_service_preservation_verified,
                    evidence.certificate_device_model_verified)) or not evidence.observed_at <= now < evidence.expires_at): raise ValueError
        self._pins(); fresh_until = min(observed.expires_at,evidence.expires_at)
        if self._now() >= fresh_until: raise ValueError
        return observed,fresh_until

    def _settled(self) -> None:
        self._pins()
        if self._pending is not None:
            adapter = self._pending; result = adapter._claim().result
            if result is None or self._store.claim_count != adapter._step.claim_index: raise ValueError
            try: adapter._require_verified()
            except Exception:
                self._failed = True; raise
            if adapter._step.restore: self._applied.pop()
            else: self._applied.append(adapter._step.name)
            self._settled_count = adapter._step.claim_index; self._pending = None
        if self._store.claim_count != self._settled_count: raise ValueError

    def prepare_step(self, name: Step, *, restore: bool = False) -> EmailAlertStep:
        try:
            with self._lock:
                self._settled()
                if name not in STEPS or type(restore) is not bool or (name,restore) in self._adapters: raise ValueError
                if restore:
                    if not self._applied or self._applied[-1] != name: raise ValueError
                    original = self._adapters[(name,False)]; original._require_verified(); receipt = original._receipt
                else:
                    changes = self._initial.changed_steps
                    if self._restoring or len(self._applied) >= len(changes) or changes[len(self._applied)] != name: raise ValueError
                    receipt = None
                for applied in self._applied: self._adapters[(applied,False)]._require_verified()
                index = STEPS.index(name); before,after = (index+1,index) if restore else (index,index+1)
                observed,fresh_until = self._snapshot(name,restore,receipt)
                if observed.state.digest != self._initial.expected(before).digest: raise ValueError
                parameters = canonical_digest(dict(domain=self._domain_pin,step=name,restore=restore,before=before,after=after,
                    original_receipt=None if receipt is None else receipt.digest))
                step = EmailAlertStep(name,restore,before,after,parameters,self._state(observed.state.digest),
                    self._state(self._initial.expected(after).digest),self._settled_count+1,observed.observed_at,fresh_until,observed.observed_at+60)
                self._prepared = step; return step
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def bind_step(self, step: EmailAlertStep, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *,
            authorization_verifier: M4AuthorizationVerifier | None = None, execution_enabled: bool = False) -> EmailAlertM4Adapter:
        try:
            with self._lock:
                self._pins()
                if (type(step) is not EmailAlertStep or step is not self._prepared or self._pending is not None
                        or self._store.claim_count != step.claim_index-1
                        or not step.observed_at <= self._now() < step.fresh_until): raise ValueError
                adapter = EmailAlertM4Adapter(self,step,plan,authorization,
                    authorization_verifier=authorization_verifier,execution_enabled=execution_enabled)
                self._adapters[(step.name,step.restore)] = adapter; self._pending = adapter
                if step.restore: self._restoring = True
                return adapter
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def _release_expired_unused(self, adapter: EmailAlertM4Adapter) -> None:
        try:
            with self._lock:
                self._pins()
                if (type(adapter) is not EmailAlertM4Adapter or self._pending is not adapter
                        or self._prepared is not adapter._step or self._adapters.get((adapter._step.name,adapter._step.restore)) is not adapter
                        or self._store.claim_count != adapter._step.claim_index-1 or adapter._receipt is not None
                        or any((adapter._dispatched,adapter._send_admitted,adapter._send_verified,adapter._post_verified))
                        or self._now() < min(adapter._plan.expires_at,adapter._authorization.expires_at,adapter._step.expires_at)): raise ValueError
                del self._adapters[(adapter._step.name,adapter._step.restore)]
                self._pending = None; self._prepared = None
        except Exception: raise M4AdapterDenied(_ERROR) from None


class EmailAlertM4Adapter(_OpaqueC3Object):
    def __init__(self, session: EmailAlertM4Session, step: EmailAlertStep, plan: M4ExecutionPlan,
            authorization: M4ExecutionAuthorization, *, authorization_verifier: M4AuthorizationVerifier | None = None,
            execution_enabled: bool = False) -> None:
        if type(execution_enabled) is not bool: raise M4AdapterDenied(_ERROR)
        self._session,self._step,self._plan,self._authorization = session,step,plan,authorization
        self._verifier = authorization_verifier or DenyAllM4AuthorizationVerifier(); self._enabled = execution_enabled
        self._receipt: EmailAlertReceipt | None = None
        self._dispatched = self._send_admitted = self._send_verified = self._post_verified = False
        self._check_plan()

    def _check_plan(self) -> None:
        p,a,step = self._plan,self._authorization,self._step; p.__post_init__(); a.__post_init__()
        target = 'email-alert-'+canonical_digest(dict(initial=self._session._initial.digest,step=step.name))
        if (p.action_id != step.action_id or p.action_version != '1.0.0' or p.adapter_ref != CONTRACT or p.revision != 1
                or p.plan_ref != step.action_id+'-'+step.parameters_digest or p.parameters_digest != step.parameters_digest
                or p.target_ref != target or p.requester_digest != self._session._scope.requester_digest or p.compensation_ref is not None
                or p.expected_current_digest != step.expected_current_digest or p.expected_state_digest != step.expected_state_digest
                or p.idempotency_digest != canonical_digest(dict(action=step.action_id,parameters=step.parameters_digest))
                or a.plan_ref != p.plan_ref or a.plan_digest != p.plan_digest or a.requester_digest != p.requester_digest
                or max(p.expires_at,a.expires_at)-a.issued_at > 60 or max(p.expires_at,a.expires_at) > step.expires_at): raise M4AdapterDenied(_ERROR)

    def _check(self) -> None:
        try:
            s = self._session; s._pins(); self._check_plan(); now = s._now()
            if (not self._enabled or s._pending is not self or s._adapters.get((self._step.name,self._step.restore)) is not self
                    or s._store.claim_count != self._step.claim_index
                    or not self._authorization.issued_at <= now < min(self._plan.expires_at,self._authorization.expires_at,self._step.expires_at)): raise ValueError
            self._verifier.verify(self._plan,self._authorization,now_epoch=now); s._pins()
            if s._now() >= min(self._plan.expires_at,self._authorization.expires_at,self._step.expires_at): raise ValueError
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def _claim(self) -> M4Claim:
        p,a = self._plan,self._authorization
        return self._session._store.inspect_claim(plan_ref=p.plan_ref,requester_digest=p.requester_digest,
            idempotency_digest=p.idempotency_digest,authorization_digest=a.authorization_digest,
            context_digest=canonical_digest(dict(plan_digest=p.plan_digest,authorization_digest=a.authorization_digest,revision=p.revision)))

    def _require_verified(self) -> None:
        result = self._claim().result
        if (self._receipt is None or not self._post_verified or result is None or result.outcome != 'succeeded'
                or result.verification != 'verified' or result.compensation != 'not_requested'): raise M4AdapterDenied(_ERROR)

    def _snapshot(self) -> str:
        s,step = self._session,self._step
        original = s._adapters[(step.name,False)] if step.restore else self
        if step.restore: original._require_verified()
        for applied in s._applied: s._adapters[(applied,False)]._require_verified()
        observed,_ = s._snapshot(step.name,step.restore,original._receipt)
        return s._state(observed.state.digest)

    def read_current(self, plan: M4ExecutionPlan) -> str:
        with self._session._lock:
            if plan is not self._plan: raise M4AdapterDenied(_ERROR)
            self._check()
            try:
                state = self._snapshot(); self._check(); return state
            except Exception: raise M4AdapterAmbiguous(_ERROR) from None

    def _before_send(self) -> int:
        _require_m4_dispatch_ownership(self._plan,self._authorization,self._session._store)
        with self._session._lock:
            self._check()
            if self._send_admitted: raise M4AdapterDenied(_ERROR)
            self._send_admitted = True
            if self.read_current(self._plan) != self._step.expected_current_digest: raise M4AdapterDenied(_ERROR)
            self._check(); _require_m4_dispatch_ownership(self._plan,self._authorization,self._session._store)
            self._send_verified = True
            return min(self._plan.expires_at,self._authorization.expires_at,self._step.expires_at)-self._session._last_now

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        _require_m4_dispatch_ownership(plan,self._authorization,self._session._store)
        body = bytearray()
        with self._session._lock:
            if plan is not self._plan: raise M4AdapterDenied(_ERROR)
            self._check()
            if self._dispatched: raise M4AdapterDenied(_ERROR)
            self._dispatched = True
            try:
                step,s = self._step,self._session
                body = s._initial.compile(step.name,s._initial.expected(step.before),restore=step.restore)
                with memoryview(body).toreadonly() as view:
                    receipt = s._backend.submit(view,step=step.name,restore=step.restore,parameters_digest=step.parameters_digest,
                        before_send=self._before_send,timeout_seconds=min(step.expires_at,self._plan.expires_at,self._authorization.expires_at)-s._last_now)
                if (not self._send_verified or type(receipt) is not EmailAlertReceipt
                        or receipt.source_digest != s._scope.configuration_source_digest or receipt.parameters_digest != step.parameters_digest
                        or receipt.step != step.name or receipt.restore is not step.restore): raise ValueError
                self._receipt = receipt
                if self._snapshot() != step.expected_state_digest: raise ValueError
                self._post_verified = True
            except Exception: raise M4AdapterAmbiguous(_ERROR) from None
            finally: _zeroize_mutable(body)

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        with self._session._lock:
            if plan is not self._plan: raise M4AdapterDenied(_ERROR)
            self._check()
            if self._receipt is None or not self._post_verified: raise M4AdapterAmbiguous(_ERROR)
            try:
                state = self._snapshot(); self._check(); return state
            except Exception: raise M4AdapterAmbiguous(_ERROR) from None
