"""Default-closed local MFA M4 candidate with independent effect evidence.

No native submission transport, permission/effect producer, real resolver,
startup or MCP execution binding is supplied. Matching a current selector or
configuration cannot substitute for custody, continuity or recovery evidence.
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
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import (MaterialBindingStatus, MaterialLeaseRequest,
    MaterialProviderClass, _OpaqueC3Object)
from v4_planning.material_runtime import (MaterialLeaseCoordinator, MaterialRuntimeOutcome,
    MaterialUseClaimState, MaterialUseOutcome, material_lease_request_digest)
from v4_planning.models import require_digest

from .fortitoken_material import FortitokenMaterialBinding, FortitokenMaterialProvider, FortitokenMaterialResolver
from .fortitoken_user_contract import FortitokenUserPlan, FortitokenUserState, expected_fortitoken_user_state
from .fortitoken_user_source import FortitokenUserSource
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable

CONTRACT = 'fortipam_fortitoken_local_m4_candidate_v1'
_ERROR = 'The private FortiToken execution candidate is unavailable.'


@dataclass(frozen=True, slots=True, repr=False)
class FortitokenExecutionScope(_OpaqueC3Object):
    binding_digest: str
    requester_digest: str
    scope_digest: str
    audience_digest: str
    configuration_source_digest: str
    token_source_digest: str
    effects_source_digest: str
    effects_digest: str

    def __post_init__(self) -> None:
        for value in asdict(self).values(): require_digest(value,'FortiToken scope')
        if len({self.configuration_source_digest,self.token_source_digest,self.effects_source_digest}) != 3: raise ValueError


@dataclass(frozen=True, slots=True, repr=False)
class FortitokenExecutionEvidence(_OpaqueC3Object):
    configuration_digest: str
    token_source_digest: str
    effects_source_digest: str
    token_reference_digest: str | None
    effects_digest: str
    in_flight: int
    token_custody_verified: bool
    material_continuity_verified: bool
    native_semantics_verified: bool
    inventory_license_verified: bool
    permission_verified: bool
    delivery_isolation_verified: bool
    recovery_ready: bool
    complete: bool
    observed_at: int
    expires_at: int

    def __post_init__(self) -> None:
        for value in (self.configuration_digest,self.token_source_digest,self.effects_source_digest,self.effects_digest):
            require_digest(value,'FortiToken evidence')
        if self.token_reference_digest is not None: require_digest(self.token_reference_digest,'FortiToken reference')
        if (type(self.in_flight) is not int or self.in_flight < 0
                or any(type(value) is not bool for value in (self.token_custody_verified,self.material_continuity_verified,
                    self.native_semantics_verified,self.inventory_license_verified,self.permission_verified,
                    self.delivery_isolation_verified,self.recovery_ready,self.complete))
                or type(self.observed_at) is not int or type(self.expires_at) is not int
                or not 0 <= self.observed_at < self.expires_at <= self.observed_at+10): raise ValueError


@runtime_checkable
class FortitokenEvidenceReader(Protocol):
    def observe(self, configuration_digest: str) -> FortitokenExecutionEvidence: ...


@dataclass(frozen=True, slots=True, repr=False)
class FortitokenBackendReceipt(_OpaqueC3Object):
    source_digest: str
    parameters_digest: str
    restore: bool

    def __post_init__(self) -> None:
        for value in (self.source_digest,self.parameters_digest): require_digest(value,'FortiToken receipt')
        if type(self.restore) is not bool: raise ValueError


@runtime_checkable
class FortitokenConfigurationBackend(Protocol):
    def submit(self, body: memoryview, *, parameters_digest: str, restore: bool,
        before_send: Callable[[],int], timeout_seconds: int) -> FortitokenBackendReceipt: ...


def _state_digest(state: FortitokenUserState, reference: str | None, scope: FortitokenExecutionScope) -> str:
    return canonical_digest(dict(contract=CONTRACT,configuration=state.digest,source=scope.configuration_source_digest,
        token_reference=reference,effects=scope.effects_digest))


def _inverse(intent: FortitokenUserPlan) -> FortitokenUserPlan:
    inverse = FortitokenUserPlan(expected_fortitoken_user_state(intent),'revoke' if intent.operation == 'assign' else 'assign')
    if expected_fortitoken_user_state(inverse).digest != intent.current.digest: raise M4AdapterDenied(_ERROR)
    return inverse


def fortitoken_execution_digests(intent: FortitokenUserPlan, scope: FortitokenExecutionScope,
        store: PersistentM4ExecutionStateStore, material: PersistentMaterialUseStateStore) -> tuple[str,str,str]:
    if (type(intent) is not FortitokenUserPlan or type(scope) is not FortitokenExecutionScope
            or type(store) is not PersistentM4ExecutionStateStore or type(material) is not PersistentMaterialUseStateStore):
        raise M4AdapterDenied(_ERROR)
    _inverse(intent); proposed = expected_fortitoken_user_state(intent)
    reference = intent.current.binding.token_reference_digest
    current = _state_digest(intent.current,reference if intent.current.token_present else None,scope)
    expected = _state_digest(proposed,reference if proposed.token_present else None,scope)
    domains = []
    for journal in (store,material):
        if not hmac.compare_digest(journal._key,journal._load_key()): raise M4AdapterDenied(_ERROR)
        domains.append(dict(database=hashlib.sha256(str(journal._path.resolve()).encode()).hexdigest(),
            key_file=hashlib.sha256(str(journal._key_path.resolve()).encode()).hexdigest(),
            key=hashlib.sha256(journal._key).hexdigest(),checkpoint=journal._checkpoint_store_ref,
            authority=getattr(journal._monotonic_checkpoint,'authority_ref',None)))
    return current,expected,canonical_digest(dict(contract=CONTRACT,intent=intent.digest,scope=asdict(scope),domains=domains))


def _validate_stores(store: PersistentM4ExecutionStateStore, material: PersistentMaterialUseStateStore, *, enabled: bool) -> None:
    if type(store) is not PersistentM4ExecutionStateStore or type(material) is not PersistentMaterialUseStateStore:
        raise ValueError
    paths = (store._path,store._key_path,material._path,material._key_path)
    if (len({path.resolve() for path in paths}) != 4 or material.shares_key_material_with(store)
            or store._checkpoint_store_ref == material._checkpoint_store_ref
            or enabled and not (store.monotonic_checkpoint_protocol_bound and material.monotonic_checkpoint_protocol_bound)):
        raise ValueError
    store.verify_ready(); material.verify_ready()


def fortitoken_material_request(intent: FortitokenUserPlan, scope: FortitokenExecutionScope,
        plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *,
        restore: bool = False) -> tuple[FortitokenMaterialBinding,MaterialLeaseRequest]:
    binding = FortitokenMaterialBinding(intent,restore=restore)
    request = MaterialLeaseRequest(plan.action_id,plan.action_version,plan.plan_digest,plan.approval_digest,
        authorization.authorization_digest,scope.scope_digest,scope.audience_digest,
        MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE,binding.purpose,
        authorization.issued_at,min(plan.expires_at,authorization.expires_at))
    return binding,request


def read_fortitoken_execution_state(intent: FortitokenUserPlan, scope: FortitokenExecutionScope,
        source: FortitokenUserSource, evidence_reader: FortitokenEvidenceReader,
        recovery: FortitokenMaterialResolver, clock: Callable[[],int]) -> str:
    observed = source.read(); state = observed.state; evidence = evidence_reader.observe(state.digest); now = clock()
    if (observed.source_digest != scope.configuration_source_digest or state.binding.digest != intent.current.binding.digest
            or type(evidence) is not FortitokenExecutionEvidence or evidence.configuration_digest != state.digest
            or evidence.token_source_digest != scope.token_source_digest or evidence.effects_source_digest != scope.effects_source_digest
            or not all((evidence.complete,evidence.token_custody_verified,evidence.material_continuity_verified,
                evidence.native_semantics_verified,evidence.inventory_license_verified,evidence.permission_verified,
                evidence.delivery_isolation_verified,evidence.recovery_ready)) or evidence.in_flight != 0
            or not observed.observed_at <= now < observed.expires_at
            or not evidence.observed_at <= now < evidence.expires_at
            or recovery.binding_digest != intent.current.binding.token_reference_digest
            or recovery.validate_prebound() is not MaterialBindingStatus.AVAILABLE): raise ValueError
    if (state.token_present != (evidence.token_reference_digest is not None)
            or clock() >= min(observed.expires_at,evidence.expires_at)): raise ValueError
    return canonical_digest(dict(contract=CONTRACT,configuration=state.digest,source=scope.configuration_source_digest,
        token_reference=evidence.token_reference_digest,effects=evidence.effects_digest))


class FortitokenLocalM4Adapter(_OpaqueC3Object):
    def __init__(self, intent: FortitokenUserPlan, source: FortitokenUserSource, backend: FortitokenConfigurationBackend,
            evidence: FortitokenEvidenceReader, resolver: FortitokenMaterialResolver, recovery: FortitokenMaterialResolver,
            plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, store: PersistentM4ExecutionStateStore,
            material: PersistentMaterialUseStateStore, *, scope: FortitokenExecutionScope,
            authorization_verifier: M4AuthorizationVerifier | None = None, execution_enabled: bool = False,
            source_guard: Callable[[],bool] | None = None, clock: Callable[[],int] = lambda:int(time.time())) -> None:
        try:
            if (type(intent) is not FortitokenUserPlan or type(source) is not FortitokenUserSource
                    or type(scope) is not FortitokenExecutionScope or not isinstance(backend,FortitokenConfigurationBackend)
                    or not isinstance(evidence,FortitokenEvidenceReader) or not isinstance(resolver,FortitokenMaterialResolver)
                    or not isinstance(recovery,FortitokenMaterialResolver) or type(execution_enabled) is not bool
                    or not callable(clock) or source_guard is not None and not callable(source_guard)
                    or source._source != scope.configuration_source_digest): raise ValueError
            _validate_stores(store,material,enabled=execution_enabled)
            self._intent,self._source,self._backend,self._evidence,self._scope = intent,source,backend,evidence,scope
            self._resolver,self._recovery,self._store,self._material_store = resolver,recovery,store,material
            self._plan,self._authorization = plan,authorization
            self._verifier = authorization_verifier or DenyAllM4AuthorizationVerifier()
            self._enabled,self._guard,self._clock = execution_enabled,source_guard,clock
            self._last_now,self._failed_clock = -1,False
            self._original: FortitokenLocalM4Adapter | None = None
            self._receipt: FortitokenBackendReceipt | None = None
            self._dispatched = self._send_admitted = self._send_verified = self._material_verified = False
            self._lock = RLock()
            self._prepare_material(); self._check_plan(); source.bind_plan(intent)
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def _prepare_material(self) -> None:
        base = self._original._intent if self._original is not None else self._intent
        binding,request = fortitoken_material_request(base,self._scope,self._plan,self._authorization,
            restore=self._original is not None)
        self._material_binding,self._material_request = binding,request
        self._provider = FortitokenMaterialProvider(self._resolver,binding,request,clock=self._clock)

    def _check_plan(self) -> None:
        base = self._original._intent if self._original is not None else self._intent
        current,expected,parameters = fortitoken_execution_digests(base,self._scope,self._store,self._material_store)
        if self._original is not None: current,expected = expected,current
        p,a = self._plan,self._authorization; p.__post_init__(); a.__post_init__()
        action = self._material_binding.action_id
        if (p.action_id != action or p.action_version != '1.0.0' or p.adapter_ref != CONTRACT or p.revision != 1
                or p.compensation_ref is not None or p.requester_digest != self._scope.requester_digest
                or p.parameters_digest != parameters or p.plan_ref != action+'-'+parameters
                or p.target_ref != 'fortitoken-user-'+base.current.binding.digest
                or p.idempotency_digest != canonical_digest(dict(parameters=parameters,action=action))
                or p.expected_current_digest != current or p.expected_state_digest != expected
                or a.plan_ref != p.plan_ref or a.plan_digest != p.plan_digest or a.requester_digest != p.requester_digest
                or self._material_binding.intent_digest != self._intent.digest
                or self._recovery.binding_digest != base.current.binding.token_reference_digest): raise ValueError

    def _now(self) -> int:
        now = self._clock()
        if self._failed_clock or type(now) is not int or now < 0 or now < self._last_now:
            self._failed_clock = True; self._enabled = False
            raise M4AdapterDenied(_ERROR)
        self._last_now = now
        return now

    def _check(self, plan: M4ExecutionPlan) -> None:
        try:
            if not self._enabled or plan is not self._plan or self._guard is None or self._guard() is not True: raise ValueError
            self._check_plan(); now = self._now()
            if not self._authorization.issued_at <= now < min(plan.expires_at,self._authorization.expires_at): raise ValueError
            self._verifier.verify(plan,self._authorization,now_epoch=now)
            self._store.verify_ready(); self._material_store.verify_ready()
            if self._guard() is not True or self._now() >= min(plan.expires_at,self._authorization.expires_at): raise ValueError
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def _snapshot(self) -> str:
        return read_fortitoken_execution_state(self._intent,self._scope,self._source,self._evidence,self._recovery,self._now)

    def read_current(self, plan: M4ExecutionPlan) -> str:
        with self._lock:
            self._check(plan)
            if self._original is not None: self._original._require_verified()
            try:
                state = self._snapshot(); self._check(plan)
                return state
            except Exception: raise M4AdapterAmbiguous(_ERROR) from None

    def _before_send(self) -> int:
        _require_m4_dispatch_ownership(self._plan,self._authorization,self._store)
        with self._lock:
            self._check(self._plan)
            if self._send_admitted: raise M4AdapterDenied(_ERROR)
            self._send_admitted = True
            if self.read_current(self._plan) != self._plan.expected_current_digest: raise M4AdapterDenied(_ERROR)
            self._check(self._plan)
            _require_m4_dispatch_ownership(self._plan,self._authorization,self._store)
            self._send_verified = True
            return min(self._plan.expires_at,self._authorization.expires_at)-self._last_now

    def _consume(self, token: memoryview) -> MaterialUseOutcome:
        body = bytearray()
        try:
            body = self._source.compile_body(self._intent,token_reference_digest=self._material_binding.token_reference_digest,token=token)
            with memoryview(body).toreadonly() as view:
                receipt = self._backend.submit(view,parameters_digest=self._plan.parameters_digest,restore=self._original is not None,
                    before_send=self._before_send,timeout_seconds=min(self._plan.expires_at,self._authorization.expires_at)-self._last_now)
            if (not self._send_verified or type(receipt) is not FortitokenBackendReceipt
                    or receipt.source_digest != self._scope.configuration_source_digest
                    or receipt.parameters_digest != self._plan.parameters_digest or receipt.restore is not (self._original is not None)):
                raise ValueError
            self._receipt = receipt
            observed = self._source.read_matching_token(token_reference_digest=self._material_binding.token_reference_digest,token=token)\
                if self._intent.operation == 'assign' else self._source.read()
            self._source.verify_postcondition(self._intent,observed)
            if self._original is not None: self._source.verify_original_nonmaterial_state(self._original._intent,observed)
            if self._snapshot() != self._plan.expected_state_digest: raise ValueError
            return MaterialUseOutcome.VERIFIED
        finally: _zeroize_mutable(body)

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        _require_m4_dispatch_ownership(plan,self._authorization,self._store)
        with self._lock:
            self._check(plan)
            if self._dispatched: raise M4AdapterDenied(_ERROR)
            self._dispatched = True
            try:
                restore = self._original is not None
                if self._store.claim_count != (2 if restore else 1) or self._material_store.claim_count != (1 if restore else 0): raise ValueError
                outcome = MaterialLeaseCoordinator(self._provider,self._material_store).execute_once(
                    self._material_binding,self._material_request,
                    lambda lease:self._provider.consume(self._material_binding,lease,self._material_request,self._consume),now_epoch=self._now())
                if outcome is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED: raise ValueError
                self._material_verified = True
            except Exception: raise M4AdapterAmbiguous(_ERROR) from None
            finally: self._provider.close()

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        with self._lock:
            self._check(plan)
            if self._receipt is None or not self._material_verified: raise M4AdapterAmbiguous(_ERROR)
            try:
                state = self._snapshot(); self._check(plan)
                return state
            except Exception: raise M4AdapterAmbiguous(_ERROR) from None

    def _require_verified(self) -> None:
        if self._original is not None or self._receipt is None or not self._material_verified: raise M4AdapterDenied(_ERROR)
        p,a = self._plan,self._authorization
        claim = self._store.inspect_claim(plan_ref=p.plan_ref,requester_digest=p.requester_digest,idempotency_digest=p.idempotency_digest,
            authorization_digest=a.authorization_digest,context_digest=canonical_digest(dict(plan_digest=p.plan_digest,
                authorization_digest=a.authorization_digest,revision=p.revision)))
        material = self._material_store._inspect_claim(request_digest=material_lease_request_digest(self._material_request),
            authorization_digest=a.authorization_digest)
        if (claim.result is None or claim.result.outcome != 'succeeded' or claim.result.verification != 'verified'
                or claim.result.compensation != 'not_requested' or material.state is not MaterialUseClaimState.REPLAY
                or material.outcome is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED): raise M4AdapterDenied(_ERROR)

    def bind_restore(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *,
            resolver: FortitokenMaterialResolver, authorization_verifier: M4AuthorizationVerifier | None = None,
            execution_enabled: bool = False) -> FortitokenLocalM4Adapter:
        try:
            with self._lock:
                self._require_verified()
                if self._failed_clock or type(execution_enabled) is not bool or not isinstance(resolver,FortitokenMaterialResolver): raise ValueError
                _validate_stores(self._store,self._material_store,enabled=execution_enabled)
                observed = self._source.read(); inverse = FortitokenUserPlan(observed.state,
                    'revoke' if self._intent.operation == 'assign' else 'assign')
                if inverse.digest != _inverse(self._intent).digest: raise ValueError
                restore = object.__new__(FortitokenLocalM4Adapter); restore.__dict__.update(self.__dict__)
                restore._original = self; restore._intent = inverse
                restore._plan,restore._authorization,restore._resolver = plan,authorization,resolver
                restore._verifier = authorization_verifier or DenyAllM4AuthorizationVerifier()
                restore._enabled = execution_enabled; restore._receipt = None
                restore._dispatched = restore._send_admitted = restore._send_verified = restore._material_verified = False
                restore._prepare_material(); restore._check_plan(); self._source.bind_plan(inverse)
                return restore
        except Exception: raise M4AdapterDenied(_ERROR) from None
