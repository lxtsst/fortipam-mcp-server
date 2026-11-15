"""Default-closed original-receipt M4 lifecycle for two fixed Script definitions.

Each definition has its own create and independent removal claim. No Script
execution, Secret assignment, real eligibility producer or startup binding is
provided. A matching view cannot repair UNKNOWN or confer original custody.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import hashlib
import hmac
from threading import RLock
import time
from typing import Protocol, runtime_checkable

from v4_planning import (DenyAllM4AuthorizationVerifier, M4AdapterAmbiguous, M4AdapterDenied,
    M4AuthorizationVerifier, M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest)
from v4_planning.execution_kernel import M4Claim
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable
from .windows_jit_script_source import (CONTRACT as SOURCE_CONTRACT, WindowsJitScriptObservation,
    WindowsJitScriptPlan, WindowsJitScriptSource, _encoded)

CONTRACT = 'fortipam_windows_jit_script_original_m4_local_v1'
_ERROR = 'The private Windows JIT Script M4 candidate is unavailable.'


@dataclass(frozen=True, slots=True, repr=False)
class JitScriptExecutionScope(_OpaqueC3Object):
    binding_digest: str
    requester_digest: str
    scope_digest: str
    audience_digest: str
    configuration_source_digest: str
    effects_source_digest: str
    effects_digest: str

    def __post_init__(self) -> None:
        for value in asdict(self).values(): require_digest(value,'JIT Script execution scope')
        if self.configuration_source_digest == self.effects_source_digest: raise ValueError


@dataclass(frozen=True, slots=True, repr=False)
class JitScriptEvidence(_OpaqueC3Object):
    source_digest: str
    configuration_digest: str
    effects_digest: str
    original_receipt_digest: str | None
    global_namespace_verified: bool
    actor_permission_verified: bool
    complete_reference_scope_verified: bool
    unattached_definition_verified: bool
    native_semantics_verified: bool
    independent_recovery_ready: bool
    original_continuity_verified: bool
    complete: bool
    active_uses: int
    observed_at: int
    expires_at: int

    def __post_init__(self) -> None:
        for value in (self.source_digest,self.configuration_digest,self.effects_digest): require_digest(value,'JIT Script evidence')
        if self.original_receipt_digest is not None: require_digest(self.original_receipt_digest,'JIT Script custody')
        if (any(type(value) is not bool for value in (self.global_namespace_verified,self.actor_permission_verified,
                self.complete_reference_scope_verified,self.unattached_definition_verified,self.native_semantics_verified,
                self.independent_recovery_ready,self.original_continuity_verified,self.complete))
                or type(self.active_uses) is not int or self.active_uses < 0
                or type(self.observed_at) is not int or type(self.expires_at) is not int
                or not 0 <= self.observed_at < self.expires_at <= self.observed_at+10): raise ValueError


@runtime_checkable
class JitScriptEvidenceReader(Protocol):
    def observe(self, configuration_digest: str, *, index: int, remove: bool,
            original_receipt_digest: str | None) -> JitScriptEvidence: ...


@dataclass(frozen=True, slots=True, repr=False)
class JitScriptReceipt(_OpaqueC3Object):
    source_digest: str
    parameters_digest: str
    index: int
    remove: bool
    native_ack_digest: str

    def __post_init__(self) -> None:
        for value in (self.source_digest,self.parameters_digest,self.native_ack_digest): require_digest(value,'JIT Script receipt')
        if type(self.index) is not int or self.index not in (0,1) or type(self.remove) is not bool: raise ValueError

    @property
    def digest(self) -> str: return canonical_digest(asdict(self))


@runtime_checkable
class JitScriptBackend(Protocol):
    def submit(self, body: memoryview | None, *, index: int, remove: bool, parameters_digest: str,
            before_send: Callable[[],int], timeout_seconds: int) -> JitScriptReceipt: ...


@dataclass(frozen=True, slots=True, repr=False)
class JitScriptStep(_OpaqueC3Object):
    index: int
    remove: bool
    before: tuple[bool,bool]
    after: tuple[bool,bool]
    parameters_digest: str
    expected_current_digest: str
    expected_state_digest: str
    claim_index: int
    observed_at: int
    expires_at: int

    @property
    def action_id(self) -> str:
        return 'jit-script-'+('grant' if self.index == 0 else 'revoke')+('-remove' if self.remove else '-create')


class WindowsJitScriptM4Session(_OpaqueC3Object):
    def __init__(self, source: WindowsJitScriptSource, initial: WindowsJitScriptPlan, scope: JitScriptExecutionScope,
            backend: JitScriptBackend, evidence: JitScriptEvidenceReader, store: PersistentM4ExecutionStateStore, *,
            source_guard: Callable[[],bool] | None = None, clock: Callable[[],int] = lambda:int(time.time())) -> None:
        try:
            if (type(source) is not WindowsJitScriptSource or type(initial) is not WindowsJitScriptPlan
                    or source._plan is not initial or source._latest is not initial._origin
                    or type(scope) is not JitScriptExecutionScope
                    or any(initial._origin.present) or initial._origin.source_digest != scope.configuration_source_digest
                    or not isinstance(backend,JitScriptBackend)
                    or not isinstance(evidence,JitScriptEvidenceReader) or type(store) is not PersistentM4ExecutionStateStore
                    or source_guard is not None and not callable(source_guard) or not callable(clock)): raise ValueError
            store.verify_ready()
            if store.claim_count or not store.monotonic_checkpoint_protocol_bound: raise ValueError
            self._source,self._initial,self._scope,self._backend,self._evidence,self._store = source,initial,scope,backend,evidence,store
            self._checkpoint = store._monotonic_checkpoint
            self._guard = self._guard_pin = source_guard; self._clock = clock
            self._last_now,self._failed = -1,False
            self._pending: WindowsJitScriptM4Adapter | None = None
            self._prepared: JitScriptStep | None = None
            self._adapters: dict[tuple[int,bool],WindowsJitScriptM4Adapter] = {}
            self._jit_secret_session: object | None = None
            self._jit_workflow: object | None = None
            self._settled_count = 0; self._lock = RLock()
            if not initial._origin.observed_at <= self._now() < initial._origin.expires_at: raise ValueError
            if len(initial._origin._names) != initial._origin.script_count: raise ValueError
            self._domain_pin = self._domain(); self._pins()
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def _now(self) -> int:
        now = self._clock()
        if self._failed or type(now) is not int or now < 0 or now < self._last_now:
            self._failed = True
            raise M4AdapterDenied(_ERROR)
        self._last_now = now; return now

    def _domain(self) -> str:
        s = self._store
        if not hmac.compare_digest(s._key,s._load_key()): raise ValueError
        return canonical_digest(dict(contract=CONTRACT,scope=asdict(self._scope),baseline=self._initial._origin.state_digest,
            definitions=self._source._definition_digest,database=hashlib.sha256(str(s._path.resolve()).encode()).hexdigest(),
            key_file=hashlib.sha256(str(s._key_path.resolve()).encode()).hexdigest(),key=hashlib.sha256(s._key).hexdigest(),
            checkpoint=s._checkpoint_store_ref,authority=getattr(s._monotonic_checkpoint,'authority_ref',None)))

    def _pins(self) -> None:
        self._source._available(); self._now(); self._store.verify_ready()
        if (self._domain() != self._domain_pin or self._store._monotonic_checkpoint is not self._checkpoint
                or self._guard is None or self._guard is not self._guard_pin or self._guard() is not True): raise ValueError

    def _metadata(self, index: int) -> dict[str,object]:
        return dict(q_origin_key=self._source._expected[index]['name'],q_mkey_type='string',q_name='script',q_path='secret',
            q_ref=0,q_type=1,q_no_edit=False,q_no_rename=False,q_static=False,q_global_entry=False)

    def _configuration(self, present: tuple[bool,bool]) -> str:
        names = sorted((*self._initial._origin._names,*(body['name'] for body,exists in zip(self._source._expected,present) if exists)))
        return canonical_digest(dict(contract=SOURCE_CONTRACT,source=self._scope.configuration_source_digest,
            schema=self._initial._origin.schema_digest,definitions=self._source._definition_digest,
            namespace=canonical_digest(dict(names=names)),candidates=[self._metadata(i) if exists else None for i,exists in enumerate(present)]))

    def _state(self, configuration: str) -> str:
        return canonical_digest(dict(contract=CONTRACT,configuration=configuration,effects=self._scope.effects_digest,
            configuration_source=self._scope.configuration_source_digest,effects_source=self._scope.effects_source_digest))

    def _snapshot(self, index: int, remove: bool, receipt: JitScriptReceipt | None) -> WindowsJitScriptObservation:
        self._pins(); observed = self._source.read(); now = self._now()
        if (observed.source_digest != self._scope.configuration_source_digest
                or observed.schema_digest != self._initial._origin.schema_digest
                or observed.state_digest != self._configuration(observed.present)
                or not observed.observed_at <= now < observed.expires_at): raise ValueError
        expected_receipt = receipt.digest if receipt is not None else None
        evidence = self._evidence.observe(observed.state_digest,index=index,remove=remove,original_receipt_digest=expected_receipt)
        if (type(evidence) is not JitScriptEvidence or evidence.source_digest != self._scope.effects_source_digest
                or evidence.configuration_digest != observed.state_digest or evidence.effects_digest != self._scope.effects_digest
                or evidence.original_receipt_digest != expected_receipt
                or evidence.original_continuity_verified is not (receipt is not None)
                or evidence.active_uses != 0 or not all((evidence.global_namespace_verified,evidence.actor_permission_verified,
                    evidence.complete_reference_scope_verified,evidence.unattached_definition_verified,evidence.native_semantics_verified,
                    evidence.independent_recovery_ready,evidence.complete))
                or not evidence.observed_at <= now < evidence.expires_at): raise ValueError
        self._pins()
        if self._now() >= min(observed.expires_at,evidence.expires_at): raise ValueError
        return observed

    def _settled(self) -> None:
        self._pins()
        if self._pending is not None:
            result = self._pending._claim().result
            if result is None or self._store.claim_count != self._pending._step.claim_index: raise ValueError
            self._settled_count = self._pending._step.claim_index; self._pending = None
        if self._store.claim_count != self._settled_count: raise ValueError

    def prepare_step(self, index: int, *, remove: bool = False) -> JitScriptStep:
        try:
            with self._lock:
                self._settled()
                if type(index) is not int or index not in (0,1) or type(remove) is not bool or (index,remove) in self._adapters: raise ValueError
                original = self._adapters.get((index,False)) if remove else None
                if remove:
                    if original is None: raise ValueError
                    original._require_verified()
                elif index == 1:
                    self._adapters[(0,False)]._require_verified()
                receipt = original._receipt if original is not None else None
                observed = self._snapshot(index,remove,receipt); before = observed.present
                if before[index] is not remove or not remove and before != ((False,False) if index == 0 else (True,False)): raise ValueError
                after = tuple(not value if i == index else value for i,value in enumerate(before))
                parameters = canonical_digest(dict(domain=self._domain_pin,index=index,remove=remove,before=list(before),after=list(after),
                    original_receipt=None if receipt is None else receipt.digest))
                step = JitScriptStep(index,remove,before,(after[0],after[1]),parameters,self._state(self._configuration(before)),
                    self._state(self._configuration((after[0],after[1]))),self._settled_count+1,observed.observed_at,observed.observed_at+60)
                self._prepared = step; return step
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def _release_expired_unused(self, adapter: WindowsJitScriptM4Adapter) -> None:
        try:
            with self._lock:
                self._pins()
                if (type(adapter) is not WindowsJitScriptM4Adapter or self._pending is not adapter
                        or self._prepared is not adapter._step or self._adapters.get((adapter._step.index,adapter._step.remove)) is not adapter
                        or self._store.claim_count != adapter._step.claim_index-1
                        or any((adapter._dispatched,adapter._send_admitted,adapter._send_verified,adapter._post_verified))
                        or adapter._receipt is not None
                        or self._now() < min(adapter._plan.expires_at,adapter._authorization.expires_at,adapter._step.expires_at)): raise ValueError
                del self._adapters[(adapter._step.index,adapter._step.remove)]
                self._pending = None; self._prepared = None
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def bind_step(self, step: JitScriptStep, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *,
            authorization_verifier: M4AuthorizationVerifier | None = None, execution_enabled: bool = False) -> WindowsJitScriptM4Adapter:
        try:
            with self._lock:
                self._pins()
                if (type(step) is not JitScriptStep or step is not self._prepared or self._pending is not None
                        or self._store.claim_count != step.claim_index-1
                        or not step.observed_at <= self._now() < min(step.expires_at,step.observed_at+10)): raise ValueError
                adapter = WindowsJitScriptM4Adapter(self,step,plan,authorization,
                    authorization_verifier=authorization_verifier,execution_enabled=execution_enabled)
                self._adapters[(step.index,step.remove)] = adapter; self._pending = adapter; return adapter
        except Exception: raise M4AdapterDenied(_ERROR) from None


class WindowsJitScriptM4Adapter(_OpaqueC3Object):
    def __init__(self, session: WindowsJitScriptM4Session, step: JitScriptStep, plan: M4ExecutionPlan,
            authorization: M4ExecutionAuthorization, *, authorization_verifier: M4AuthorizationVerifier | None = None,
            execution_enabled: bool = False) -> None:
        if type(execution_enabled) is not bool: raise M4AdapterDenied(_ERROR)
        self._session,self._step,self._plan,self._authorization = session,step,plan,authorization
        self._verifier = authorization_verifier or DenyAllM4AuthorizationVerifier(); self._enabled = execution_enabled
        self._receipt: JitScriptReceipt | None = None
        self._dispatched = self._send_admitted = self._send_verified = self._post_verified = False
        self._check_plan()

    def _check_plan(self) -> None:
        p,a,step = self._plan,self._authorization,self._step; p.__post_init__(); a.__post_init__()
        target = 'jit-script-'+canonical_digest(dict(definitions=self._session._source._definition_digest,index=step.index))
        if (p.action_id != step.action_id or p.action_version != '1.0.0' or p.adapter_ref != CONTRACT or p.revision != 1
                or p.plan_ref != step.action_id+'-'+step.parameters_digest or p.parameters_digest != step.parameters_digest
                or p.target_ref != target or p.requester_digest != self._session._scope.requester_digest or p.compensation_ref is not None
                or p.expected_current_digest != step.expected_current_digest or p.expected_state_digest != step.expected_state_digest
                or p.idempotency_digest != canonical_digest(dict(action=step.action_id,parameters=step.parameters_digest))
                or a.plan_ref != p.plan_ref or a.plan_digest != p.plan_digest or a.requester_digest != p.requester_digest
                or max(p.expires_at,a.expires_at)-a.issued_at > 60
                or max(p.expires_at,a.expires_at) > step.expires_at): raise M4AdapterDenied(_ERROR)

    def _check(self) -> None:
        try:
            s = self._session; s._pins(); self._check_plan(); now = s._now()
            if (not self._enabled or s._pending is not self or s._adapters.get((self._step.index,self._step.remove)) is not self
                    or s._store.claim_count != self._step.claim_index
                    or not self._authorization.issued_at <= now < min(self._plan.expires_at,self._authorization.expires_at,self._step.expires_at)):
                raise ValueError
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
        original = s._adapters[(step.index,False)] if step.remove else self
        if step.remove: original._require_verified()
        observed = s._snapshot(step.index,step.remove,original._receipt)
        return s._state(observed.state_digest)

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
                if step.remove:
                    receipt = s._backend.submit(None,index=step.index,remove=True,parameters_digest=step.parameters_digest,
                        before_send=self._before_send,timeout_seconds=step.expires_at-s._last_now)
                else:
                    body = bytearray(_encoded(s._source._expected[step.index]))
                    with memoryview(body).toreadonly() as view:
                        receipt = s._backend.submit(view,index=step.index,remove=False,parameters_digest=step.parameters_digest,
                            before_send=self._before_send,timeout_seconds=step.expires_at-s._last_now)
                if (not self._send_verified or type(receipt) is not JitScriptReceipt
                        or receipt.source_digest != s._scope.configuration_source_digest
                        or receipt.parameters_digest != step.parameters_digest or receipt.index != step.index or receipt.remove is not step.remove): raise ValueError
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
