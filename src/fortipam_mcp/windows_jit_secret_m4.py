"""Default-closed JIT metadata update and independent restore through M4.

No credential loader, native writer, eligibility producer or MCP execution
binding is provided. Original Script receipts do not supply Secret custody or
Password/TOTP continuity. Those require an independent qualified source.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import hashlib
import hmac
from typing import Protocol, runtime_checkable

from v4_planning import (DenyAllM4AuthorizationVerifier, M4AdapterAmbiguous, M4AdapterDenied,
    M4AuthorizationVerifier, M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest)
from v4_planning.execution_kernel import M4Claim, _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable
from .windows_jit_script_m4 import WindowsJitScriptM4Session
from .windows_jit_script_source import CONTRACT as SCRIPT_SOURCE_CONTRACT
from .windows_jit_secret_contract import WindowsJitSecretPlan, _encoded
from .windows_jit_secret_source import WindowsJitSecretObservation, WindowsJitSecretSource

CONTRACT = 'fortipam_windows_jit_secret_original_m4_local_v1'
_ERROR = 'The private Windows JIT Secret M4 candidate is unavailable.'


@dataclass(frozen=True,slots=True,repr=False)
class JitSecretExecutionScope(_OpaqueC3Object):
    binding_digest: str
    requester_digest: str
    scope_digest: str
    audience_digest: str
    configuration_source_digest: str
    effects_source_digest: str
    effects_digest: str
    original_subject_receipt_digest: str
    material_preservation_digest: str

    def __post_init__(self) -> None:
        for value in asdict(self).values(): require_digest(value,'JIT Secret scope')
        if self.configuration_source_digest == self.effects_source_digest: raise ValueError


@dataclass(frozen=True,slots=True,repr=False)
class JitSecretEvidence(_OpaqueC3Object):
    source_digest: str
    configuration_digest: str
    effects_digest: str
    original_subject_receipt_digest: str
    material_preservation_digest: str
    original_update_receipt_digest: str | None
    actor_permission_verified: bool
    original_subject_custody_verified: bool
    associated_admin_verified: bool
    standalone_target_verified: bool
    complete_reference_scope_verified: bool
    no_active_checkout_or_session_verified: bool
    native_patch_semantics_verified: bool
    material_continuity_verified: bool
    independent_recovery_ready: bool
    script_reference_scope_verified: bool
    complete: bool
    observed_at: int
    expires_at: int

    def __post_init__(self) -> None:
        for value in (self.source_digest,self.configuration_digest,self.effects_digest,
                self.original_subject_receipt_digest,self.material_preservation_digest): require_digest(value,'JIT Secret evidence')
        if self.original_update_receipt_digest is not None: require_digest(self.original_update_receipt_digest,'JIT update receipt')
        if (any(type(value) is not bool for value in (self.actor_permission_verified,self.original_subject_custody_verified,
                self.associated_admin_verified,self.standalone_target_verified,self.complete_reference_scope_verified,
                self.no_active_checkout_or_session_verified,self.native_patch_semantics_verified,self.material_continuity_verified,
                self.independent_recovery_ready,self.script_reference_scope_verified,self.complete))
                or type(self.observed_at) is not int or type(self.expires_at) is not int
                or not 0 <= self.observed_at < self.expires_at <= self.observed_at+10): raise ValueError


@runtime_checkable
class JitSecretEvidenceReader(Protocol):
    def observe(self, configuration_digest: str, *, restore: bool,
            original_update_receipt_digest: str | None) -> JitSecretEvidence: ...


@dataclass(frozen=True,slots=True,repr=False)
class JitSecretReceipt(_OpaqueC3Object):
    source_digest: str
    parameters_digest: str
    restore: bool
    native_ack_digest: str

    def __post_init__(self) -> None:
        for value in (self.source_digest,self.parameters_digest,self.native_ack_digest): require_digest(value,'JIT Secret receipt')
        if type(self.restore) is not bool: raise ValueError

    @property
    def digest(self) -> str: return canonical_digest(asdict(self))


@runtime_checkable
class JitSecretBackend(Protocol):
    def submit(self, body: memoryview, *, restore: bool, parameters_digest: str,
            before_send: Callable[[],int], timeout_seconds: int) -> JitSecretReceipt: ...


@dataclass(frozen=True,slots=True,repr=False)
class JitSecretStep(_OpaqueC3Object):
    restore: bool
    parameters_digest: str
    expected_current_digest: str
    expected_state_digest: str
    claim_index: int
    observed_at: int
    expires_at: int

    @property
    def action_id(self) -> str: return 'jit-secret-restore' if self.restore else 'jit-secret-configure'


class WindowsJitSecretM4Session(_OpaqueC3Object):
    def __init__(self, source: WindowsJitSecretSource, initial: WindowsJitSecretPlan,
            scripts: WindowsJitScriptM4Session, scope: JitSecretExecutionScope,
            backend: JitSecretBackend, evidence: JitSecretEvidenceReader, store: PersistentM4ExecutionStateStore, *,
            source_guard: Callable[[],bool] | None = None) -> None:
        try:
            if (type(source) is not WindowsJitSecretSource or type(initial) is not WindowsJitSecretPlan
                    or type(scripts) is not WindowsJitScriptM4Session or source._scripts is not scripts._source
                    or source._plan is not initial or source._plan_origin is None or source._latest is not source._plan_origin
                    or source._plan_origin.secret is not initial.baseline or type(scope) is not JitSecretExecutionScope
                    or scope.configuration_source_digest != source._source
                    or scope.effects_source_digest in (source._source,source._scripts._source)
                    or not isinstance(backend,JitSecretBackend) or not isinstance(evidence,JitSecretEvidenceReader)
                    or type(store) is not PersistentM4ExecutionStateStore or store is scripts._store
                    or source_guard is not None and not callable(source_guard)): raise ValueError
            initial.__post_init__(); store.verify_ready()
            if store.claim_count or not store.monotonic_checkpoint_protocol_bound: raise ValueError
            self._source,self._initial,self._scripts,self._scope,self._backend,self._evidence,self._store = source,initial,scripts,scope,backend,evidence,store
            self._guard = self._guard_pin = source_guard; self._checkpoint = store._monotonic_checkpoint
            self._script_domain = scripts._domain_pin
            self._script_receipts = tuple(scripts._adapters[(i,False)]._receipt for i in (0,1))
            self._pending: WindowsJitSecretM4Adapter | None = None
            self._claimed = False
            self._prepared: JitSecretStep | None = None
            self._adapters: dict[bool,WindowsJitSecretM4Adapter] = {}; self._settled_count = 0
            origin = source._plan_origin
            if not origin.observed_at <= scripts._now() < origin.expires_at: raise ValueError
            if store._path.resolve() == scripts._store._path.resolve(): raise ValueError
            if store._key_path.resolve() == scripts._store._key_path.resolve(): raise ValueError
            self._domain_pin = self._domain()
            with scripts._lock:
                if scripts._jit_secret_session is not None: raise ValueError
                self._pins(); scripts._jit_secret_session = self; self._claimed = True
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def _domain(self) -> str:
        s = self._store
        if not hmac.compare_digest(s._key,s._load_key()): raise ValueError
        return canonical_digest(dict(contract=CONTRACT,scope=asdict(self._scope),baseline=self._initial.baseline.digest,
            scripts=self._script_domain,receipts=[None if r is None else r.digest for r in self._script_receipts],
            source=self._source._source,binding=asdict(self._source._binding),schema=self._source._schema_pin,
            database=hashlib.sha256(str(s._path.resolve()).encode()).hexdigest(),
            key_file=hashlib.sha256(str(s._key_path.resolve()).encode()).hexdigest(),key=hashlib.sha256(s._key).hexdigest(),
            checkpoint=s._checkpoint_store_ref,authority=getattr(s._monotonic_checkpoint,'authority_ref',None)))

    def _pins(self) -> None:
        self._source._available(); self._scripts._settled(); self._store.verify_ready()
        if (self._claimed and self._scripts._jit_secret_session is not self
                or self._scripts._domain_pin != self._script_domain or self._domain() != self._domain_pin
                or self._store._monotonic_checkpoint is not self._checkpoint or self._guard is None
                or self._guard is not self._guard_pin or self._guard() is not True): raise ValueError
        for i,receipt in enumerate(self._script_receipts):
            original = self._scripts._adapters[(i,False)]; original._require_verified()
            if receipt is None or original._receipt is not receipt: raise ValueError

    def _script_state(self, applied: bool) -> str:
        s = self._scripts; origin = s._initial._origin
        names = sorted((*origin._names,*(body['name'] for body in s._source._expected)))
        return canonical_digest(dict(contract=SCRIPT_SOURCE_CONTRACT,source=s._source._source,schema=origin.schema_digest,
            definitions=s._source._definition_digest,namespace=canonical_digest(dict(names=names)),
            candidates=[dict(s._metadata(i),q_ref=1 if applied else 0) for i in (0,1)]))

    def _configuration(self, applied: bool) -> str:
        state = self._initial.expected() if applied else self._initial.baseline
        return canonical_digest(dict(source=self._source._source,scripts=self._script_state(applied),secret=state.digest))

    def _state(self, configuration: str) -> str:
        return canonical_digest(dict(contract=CONTRACT,configuration=configuration,effects=self._scope.effects_digest,
            material=self._scope.material_preservation_digest,subject=self._scope.original_subject_receipt_digest))

    def _snapshot(self, restore: bool, receipt: JitSecretReceipt | None) -> tuple[WindowsJitSecretObservation,str]:
        self._pins(); observed = self._source.read(); now = self._scripts._now()
        if observed.source_digest != self._scope.configuration_source_digest or not observed.observed_at <= now < observed.expires_at: raise ValueError
        configuration = canonical_digest(dict(source=observed.source_digest,scripts=observed.scripts.state_digest,secret=observed.secret.digest))
        expected_receipt = None if receipt is None else receipt.digest
        e = self._evidence.observe(configuration,restore=restore,original_update_receipt_digest=expected_receipt)
        if (type(e) is not JitSecretEvidence or e.source_digest != self._scope.effects_source_digest
                or e.configuration_digest != configuration or e.effects_digest != self._scope.effects_digest
                or e.original_subject_receipt_digest != self._scope.original_subject_receipt_digest
                or e.material_preservation_digest != self._scope.material_preservation_digest
                or e.original_update_receipt_digest != expected_receipt
                or not all((e.actor_permission_verified,e.original_subject_custody_verified,e.associated_admin_verified,
                    e.standalone_target_verified,e.complete_reference_scope_verified,e.no_active_checkout_or_session_verified,
                    e.native_patch_semantics_verified,e.material_continuity_verified,e.independent_recovery_ready,
                    e.script_reference_scope_verified,e.complete)) or not e.observed_at <= now < e.expires_at): raise ValueError
        self._pins()
        if self._scripts._now() >= min(e.expires_at,observed.expires_at): raise ValueError
        return observed,self._state(configuration)

    def _settled(self) -> None:
        self._pins()
        if self._pending is not None:
            if self._pending._claim().result is None or self._store.claim_count != self._pending._step.claim_index: raise ValueError
            self._settled_count = self._pending._step.claim_index; self._pending = None
        if self._store.claim_count != self._settled_count: raise ValueError

    def prepare_step(self, *, restore: bool = False) -> JitSecretStep:
        try:
            with self._scripts._lock:
                self._settled()
                if type(restore) is not bool or restore in self._adapters: raise ValueError
                original = self._adapters.get(False) if restore else None
                if restore:
                    if original is None: raise ValueError
                    original._require_verified()
                receipt = None if original is None else original._receipt
                observed,state = self._snapshot(restore,receipt)
                if state != self._state(self._configuration(restore)): raise ValueError
                parameters = canonical_digest(dict(domain=self._domain_pin,restore=restore,
                    original_update=None if receipt is None else receipt.digest))
                step = JitSecretStep(restore,parameters,state,self._state(self._configuration(not restore)),
                    self._settled_count+1,observed.observed_at,observed.observed_at+60)
                self._prepared = step; return step
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def _release_expired_unused(self, adapter: WindowsJitSecretM4Adapter) -> None:
        try:
            with self._scripts._lock:
                self._pins()
                if (type(adapter) is not WindowsJitSecretM4Adapter or self._pending is not adapter
                        or self._prepared is not adapter._step or self._adapters.get(adapter._step.restore) is not adapter
                        or self._store.claim_count != adapter._step.claim_index-1
                        or any((adapter._dispatched,adapter._send_admitted,adapter._send_verified,adapter._post_verified))
                        or adapter._receipt is not None
                        or self._scripts._now() < min(adapter._plan.expires_at,adapter._authorization.expires_at,adapter._step.expires_at)): raise ValueError
                del self._adapters[adapter._step.restore]
                self._pending = None; self._prepared = None
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def bind_step(self, step: JitSecretStep, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *,
            authorization_verifier: M4AuthorizationVerifier | None = None, execution_enabled: bool = False) -> WindowsJitSecretM4Adapter:
        try:
            with self._scripts._lock:
                self._pins(); now = self._scripts._now()
                if (type(step) is not JitSecretStep or step is not self._prepared or self._pending is not None
                        or self._store.claim_count != step.claim_index-1 or not step.observed_at <= now < step.observed_at+10): raise ValueError
                adapter = WindowsJitSecretM4Adapter(self,step,plan,authorization,
                    authorization_verifier=authorization_verifier,execution_enabled=execution_enabled)
                self._pending = adapter; self._adapters[step.restore] = adapter; return adapter
        except Exception: raise M4AdapterDenied(_ERROR) from None


class WindowsJitSecretM4Adapter(_OpaqueC3Object):
    def __init__(self, session: WindowsJitSecretM4Session, step: JitSecretStep, plan: M4ExecutionPlan,
            authorization: M4ExecutionAuthorization, *, authorization_verifier: M4AuthorizationVerifier | None = None,
            execution_enabled: bool = False) -> None:
        if type(execution_enabled) is not bool: raise M4AdapterDenied(_ERROR)
        self._session,self._step,self._plan,self._authorization = session,step,plan,authorization
        self._enabled = execution_enabled; self._verifier = authorization_verifier or DenyAllM4AuthorizationVerifier()
        self._receipt: JitSecretReceipt | None = None
        self._dispatched = self._send_admitted = self._send_verified = self._post_verified = False
        self._check_plan()

    def _check_plan(self) -> None:
        p,a,s,step = self._plan,self._authorization,self._session,self._step; p.__post_init__(); a.__post_init__()
        if (p.action_id != step.action_id or p.action_version != '1.0.0' or p.adapter_ref != CONTRACT or p.revision != 1
                or p.plan_ref != step.action_id+'-'+step.parameters_digest or p.parameters_digest != step.parameters_digest
                or p.target_ref != 'jit-secret-'+canonical_digest(s._initial.baseline.binding.identity)
                or p.requester_digest != s._scope.requester_digest or p.compensation_ref is not None
                or p.expected_current_digest != step.expected_current_digest or p.expected_state_digest != step.expected_state_digest
                or p.idempotency_digest != canonical_digest(dict(action=step.action_id,parameters=step.parameters_digest))
                or a.plan_ref != p.plan_ref or a.plan_digest != p.plan_digest or a.requester_digest != p.requester_digest
                or max(p.expires_at,a.expires_at)-a.issued_at > 60
                or max(p.expires_at,a.expires_at) > step.expires_at): raise M4AdapterDenied(_ERROR)

    def _check(self) -> None:
        try:
            s = self._session; s._pins(); self._check_plan(); now = s._scripts._now()
            if (not self._enabled or s._pending is not self or s._adapters.get(self._step.restore) is not self
                    or s._store.claim_count != self._step.claim_index
                    or not self._authorization.issued_at <= now < min(self._plan.expires_at,self._authorization.expires_at,self._step.expires_at)): raise ValueError
            self._verifier.verify(self._plan,self._authorization,now_epoch=now); s._pins()
            if s._scripts._now() >= min(self._plan.expires_at,self._authorization.expires_at,self._step.expires_at): raise ValueError
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

    def _snapshot(self) -> tuple[WindowsJitSecretObservation,str]:
        original = self._session._adapters[False] if self._step.restore else self
        if self._step.restore: original._require_verified()
        return self._session._snapshot(self._step.restore,original._receipt)

    def read_current(self, plan: M4ExecutionPlan) -> str:
        with self._session._scripts._lock:
            if plan is not self._plan: raise M4AdapterDenied(_ERROR)
            self._check()
            try:
                _,state = self._snapshot(); self._check(); return state
            except Exception: raise M4AdapterAmbiguous(_ERROR) from None

    def _before_send(self) -> int:
        s = self._session; _require_m4_dispatch_ownership(self._plan,self._authorization,s._store)
        with s._scripts._lock:
            self._check()
            if self._send_admitted: raise M4AdapterDenied(_ERROR)
            self._send_admitted = True
            if self.read_current(self._plan) != self._step.expected_current_digest: raise M4AdapterDenied(_ERROR)
            self._check(); _require_m4_dispatch_ownership(self._plan,self._authorization,s._store); self._send_verified = True
            return min(self._plan.expires_at,self._authorization.expires_at,self._step.expires_at)-s._scripts._last_now

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        s,step = self._session,self._step; _require_m4_dispatch_ownership(plan,self._authorization,s._store)
        body = bytearray()
        with s._scripts._lock:
            if plan is not self._plan: raise M4AdapterDenied(_ERROR)
            self._check()
            if self._dispatched: raise M4AdapterDenied(_ERROR)
            self._dispatched = True
            try:
                current,_ = self._snapshot()
                body = bytearray(_encoded(s._initial.compile_metadata_patch(current.secret,restore=step.restore)))
                with memoryview(body).toreadonly() as view:
                    receipt = s._backend.submit(view,restore=step.restore,parameters_digest=step.parameters_digest,
                        before_send=self._before_send,timeout_seconds=step.expires_at-s._scripts._last_now)
                if (not self._send_verified or type(receipt) is not JitSecretReceipt
                        or receipt.source_digest != s._scope.configuration_source_digest
                        or receipt.parameters_digest != step.parameters_digest or receipt.restore is not step.restore): raise ValueError
                self._receipt = receipt
                if self._snapshot()[1] != step.expected_state_digest: raise ValueError
                self._post_verified = True
            except Exception: raise M4AdapterAmbiguous(_ERROR) from None
            finally: _zeroize_mutable(body)

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        with self._session._scripts._lock:
            if plan is not self._plan: raise M4AdapterDenied(_ERROR)
            self._check()
            if self._receipt is None or not self._post_verified: raise M4AdapterAmbiguous(_ERROR)
            try:
                _,state = self._snapshot(); self._check(); return state
            except Exception: raise M4AdapterAmbiguous(_ERROR) from None
