"""Default-closed SCIM rotate/disable M4 candidate with separate C3 consumption.

Only local injected peers are implemented. Native ACKs, credential/effect
producers and ID/absence-recovery qualification remain unbound. Creation is
explicitly refused here until those additional native contracts exist.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
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

from .m4_execution_store import PersistentM4ExecutionStateStore
from .scim_client_contract import (ScimClientTransition, ScimNonmaterialState, _context,
    build_scim_request_with_material)
from .scim_client_material import ScimMaterialBinding, ScimMaterialProvider, ScimMaterialResolver
from .secret_metadata_http_transport import _zeroize_mutable

CONTRACT = 'fortipam_v4_scim_local_m4_candidate_v1'
_ERROR = 'The private SCIM execution candidate is unavailable.'


@dataclass(frozen=True, slots=True, repr=False)
class ScimExecutionScope(_OpaqueC3Object):
    binding_digest: str
    requester_digest: str
    scope_digest: str
    audience_digest: str
    configuration_source_digest: str
    credential_source_digest: str
    effects_source_digest: str
    effects_digest: str

    def __post_init__(self) -> None:
        for value in asdict(self).values(): require_digest(value, 'SCIM execution scope')
        if len({self.configuration_source_digest, self.credential_source_digest, self.effects_source_digest}) != 3:
            raise M4AdapterDenied(_ERROR)


@dataclass(frozen=True, slots=True, repr=False)
class ScimConfigurationReadback(_OpaqueC3Object):
    state: ScimNonmaterialState
    context: bytes
    source_digest: str

    def __post_init__(self) -> None:
        if (type(self.state) is not ScimNonmaterialState or type(self.context) is not bytes
                or _context(json.loads(self.context)) != self.context): raise ValueError
        self.state._values()
        require_digest(self.source_digest, 'SCIM configuration source')

    @property
    def digest(self) -> str:
        return canonical_digest(dict(configuration=hashlib.sha256(self.state._encoded).hexdigest(),
            context=hashlib.sha256(self.context).hexdigest(), source=self.source_digest))


@dataclass(frozen=True, slots=True, repr=False)
class ScimExecutionEvidence(_OpaqueC3Object):
    configuration_digest: str
    credential_source_digest: str
    effects_source_digest: str
    material_binding_digest: str
    effects_digest: str
    in_flight: int
    recovery_ready: bool
    complete: bool
    observed_at: int
    expires_at: int

    def __post_init__(self) -> None:
        for value in (self.configuration_digest, self.credential_source_digest, self.effects_source_digest,
                self.material_binding_digest, self.effects_digest): require_digest(value, 'SCIM evidence')
        if (type(self.in_flight) is not int or self.in_flight < 0 or type(self.recovery_ready) is not bool
                or type(self.complete) is not bool or type(self.observed_at) is not int or type(self.expires_at) is not int
                or not 0 <= self.observed_at < self.expires_at <= self.observed_at + 10): raise ValueError


@dataclass(frozen=True, slots=True, repr=False)
class ScimBackendReceipt(_OpaqueC3Object):
    source_digest: str
    parameters_digest: str
    restore: bool

    def __post_init__(self) -> None:
        require_digest(self.source_digest, 'SCIM receipt source')
        require_digest(self.parameters_digest, 'SCIM receipt parameters')
        if type(self.restore) is not bool: raise ValueError


@runtime_checkable
class ScimConfigurationBackend(Protocol):
    def inspect(self) -> ScimConfigurationReadback: ...
    def submit(self, body: memoryview, *, parameters_digest: str, restore: bool,
            before_send: Callable[[], int], timeout_seconds: int) -> ScimBackendReceipt: ...


@runtime_checkable
class ScimEvidenceReader(Protocol):
    def observe(self, configuration_digest: str) -> ScimExecutionEvidence: ...


def _state_digest(readback: ScimConfigurationReadback, material: str, effects: str) -> str:
    return canonical_digest(dict(contract=CONTRACT, configuration=readback.digest, material=material, effects=effects))


def scim_execution_digests(transition: ScimClientTransition, scope: ScimExecutionScope,
        execution_store: PersistentM4ExecutionStateStore, material_store: PersistentMaterialUseStateStore) -> tuple[str, str, str]:
    if (type(transition) is not ScimClientTransition or type(scope) is not ScimExecutionScope
            or transition.operation == 'create'): raise M4AdapterDenied(_ERROR)
    original = ScimConfigurationReadback(transition._original, transition._context, scope.configuration_source_digest)
    proposed = ScimConfigurationReadback(transition._proposed, transition._context, scope.configuration_source_digest)
    if type(transition._old_material_binding_digest) is not str: raise M4AdapterDenied(_ERROR)
    current = _state_digest(original, transition._old_material_binding_digest, scope.effects_digest)
    expected = _state_digest(proposed, transition._new_material_binding_digest, scope.effects_digest)
    if type(execution_store) is not PersistentM4ExecutionStateStore or type(material_store) is not PersistentMaterialUseStateStore:
        raise M4AdapterDenied(_ERROR)
    domains = []
    for store in (execution_store, material_store):
        if not hmac.compare_digest(store._key, store._load_key()): raise M4AdapterDenied(_ERROR)
        domains.append(dict(database=hashlib.sha256(str(store._path.resolve()).encode()).hexdigest(),
            key_file=hashlib.sha256(str(store._key_path.resolve()).encode()).hexdigest(),
            key=hashlib.sha256(store._key).hexdigest(), checkpoint=store._checkpoint_store_ref,
            authority=getattr(store._monotonic_checkpoint, 'authority_ref', None)))
    parameters = canonical_digest(dict(contract=CONTRACT, transition=transition.parameters_digest,
        scope=asdict(scope), domains=domains))
    return current, expected, parameters


def validate_scim_execution_stores(store: PersistentM4ExecutionStateStore,
        material_store: PersistentMaterialUseStateStore, *, require_checkpoint: bool) -> None:
    if type(store) is not PersistentM4ExecutionStateStore or type(material_store) is not PersistentMaterialUseStateStore:
        raise M4AdapterDenied(_ERROR)
    paths = (store._path, store._key_path, material_store._path, material_store._key_path)
    if (len({path.resolve() for path in paths}) != 4 or material_store.shares_key_material_with(store)
            or store._checkpoint_store_ref == material_store._checkpoint_store_ref
            or require_checkpoint and not (store.monotonic_checkpoint_protocol_bound
                and material_store.monotonic_checkpoint_protocol_bound)): raise M4AdapterDenied(_ERROR)
    store.verify_ready(); material_store.verify_ready()


def scim_material_request(transition: ScimClientTransition, scope: ScimExecutionScope,
        plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *,
        restore: bool = False) -> tuple[ScimMaterialBinding, MaterialLeaseRequest]:
    binding = ScimMaterialBinding(transition, restore=restore)
    request = MaterialLeaseRequest(plan.action_id, plan.action_version, plan.plan_digest,
        plan.approval_digest, authorization.authorization_digest, scope.scope_digest, scope.audience_digest,
        MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE, binding.purpose,
        authorization.issued_at, min(plan.expires_at, authorization.expires_at))
    return binding, request


def read_scim_execution_state(transition: ScimClientTransition, scope: ScimExecutionScope,
        backend: ScimConfigurationBackend, evidence_reader: ScimEvidenceReader,
        recovery: ScimMaterialResolver, clock: Callable[[], int]) -> str:
    """Fixed minimized source read, shared across preview, issuance and M4 guards."""
    readback = backend.inspect()
    if type(readback) is not ScimConfigurationReadback or readback.source_digest != scope.configuration_source_digest:
        raise ValueError
    evidence = evidence_reader.observe(readback.digest)
    now = clock()
    if (type(evidence) is not ScimExecutionEvidence or evidence.configuration_digest != readback.digest
            or evidence.credential_source_digest != scope.credential_source_digest
            or evidence.effects_source_digest != scope.effects_source_digest
            or not evidence.complete or evidence.in_flight != 0 or not evidence.recovery_ready
            or not evidence.observed_at <= now < evidence.expires_at
            or recovery.binding_digest != transition._old_material_binding_digest
            or recovery.validate_prebound() is not MaterialBindingStatus.AVAILABLE
            or clock() >= evidence.expires_at): raise ValueError
    return _state_digest(readback, evidence.material_binding_digest, evidence.effects_digest)


class ScimLocalM4Adapter(_OpaqueC3Object):
    def __init__(self, transition: ScimClientTransition, backend: ScimConfigurationBackend,
            evidence: ScimEvidenceReader, resolver: ScimMaterialResolver, recovery_resolver: ScimMaterialResolver,
            plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
            store: PersistentM4ExecutionStateStore, material_store: PersistentMaterialUseStateStore, *,
            scope: ScimExecutionScope, authorization_verifier: M4AuthorizationVerifier | None = None,
            execution_enabled: bool = False, source_guard: Callable[[], bool] | None = None,
            clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(transition) is not ScimClientTransition or transition.operation == 'create'
                    or type(scope) is not ScimExecutionScope or not isinstance(backend, ScimConfigurationBackend)
                    or not isinstance(evidence, ScimEvidenceReader) or not isinstance(resolver, ScimMaterialResolver)
                    or not isinstance(recovery_resolver, ScimMaterialResolver)
                    or type(store) is not PersistentM4ExecutionStateStore
                    or type(material_store) is not PersistentMaterialUseStateStore
                    or type(execution_enabled) is not bool or not callable(clock)
                    or source_guard is not None and not callable(source_guard)): raise ValueError
            validate_scim_execution_stores(store, material_store, require_checkpoint=execution_enabled)
            self._transition, self._scope, self._backend, self._evidence = transition, scope, backend, evidence
            self._resolver, self._recovery = resolver, recovery_resolver
            self._store, self._material_store = store, material_store
            self._plan, self._authorization = plan, authorization
            self._verifier = authorization_verifier or DenyAllM4AuthorizationVerifier()
            self._enabled, self._guard, self._clock = execution_enabled, source_guard, clock
            self._last_now = -1
            self._original: ScimLocalM4Adapter | None = None
            self._dispatched = self._send_admitted = self._send_verified = False
            self._receipt: ScimBackendReceipt | None = None
            self._material_verified = False
            self._lock = RLock()
            self._prepare_material()
            self._check_plan()
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def _prepare_material(self) -> None:
        self._material_binding, self._material_request = scim_material_request(self._transition, self._scope,
            self._plan, self._authorization, restore=self._original is not None)
        self._provider = ScimMaterialProvider(self._resolver, self._material_binding, self._material_request, clock=self._clock)

    def _check_plan(self) -> None:
        p, a = self._plan, self._authorization
        p.__post_init__(); a.__post_init__()
        current, expected, parameters = scim_execution_digests(self._transition, self._scope, self._store, self._material_store)
        restore = self._original is not None
        if restore: current, expected = expected, current
        action = self._material_binding.action_id
        if (p.action_id != action or p.action_version != '1.0.0' or p.adapter_ref != CONTRACT or p.revision != 1
                or p.compensation_ref is not None or p.requester_digest != self._scope.requester_digest
                or p.parameters_digest != parameters or p.plan_ref != action+'-'+parameters
                or p.target_ref != 'scim-singleton-'+json.loads(self._transition._context)['serial_digest']
                or p.idempotency_digest != canonical_digest(dict(parameters=parameters, action=action))
                or p.expected_current_digest != current or p.expected_state_digest != expected
                or a.plan_ref != p.plan_ref or a.plan_digest != p.plan_digest or a.requester_digest != p.requester_digest
                or self._recovery.binding_digest != self._transition._old_material_binding_digest): raise ValueError

    def _now(self) -> int:
        now = self._clock()
        if type(now) is not int or now < self._last_now:
            self._enabled = False
            raise M4AdapterDenied(_ERROR)
        self._last_now = now
        return now

    def _check(self, plan: M4ExecutionPlan) -> None:
        try:
            if not self._enabled or plan is not self._plan or self._guard is None or self._guard() is not True: raise ValueError
            self._check_plan()
            now = self._now()
            if not self._authorization.issued_at <= now < min(plan.expires_at, self._authorization.expires_at): raise ValueError
            self._verifier.verify(plan, self._authorization, now_epoch=now)
            if self._now() >= min(plan.expires_at, self._authorization.expires_at): raise ValueError
            self._store.verify_ready(); self._material_store.verify_ready()
            if (not self._enabled or self._guard() is not True
                    or self._now() >= min(plan.expires_at, self._authorization.expires_at)): raise ValueError
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def _snapshot(self) -> str:
        return read_scim_execution_state(self._transition, self._scope, self._backend, self._evidence, self._recovery, self._now)

    def read_current(self, plan: M4ExecutionPlan) -> str:
        with self._lock:
            self._check(plan)
            if self._original is not None: self._original._require_verified()
            try:
                state = self._snapshot()
                self._check(plan)
                return state
            except Exception: raise M4AdapterAmbiguous(_ERROR) from None

    def _before_send(self) -> int:
        _require_m4_dispatch_ownership(self._plan, self._authorization, self._store)
        with self._lock:
            self._check(self._plan)
            if self._send_admitted: raise M4AdapterDenied(_ERROR)
            self._send_admitted = True
            if self.read_current(self._plan) != self._plan.expected_current_digest: raise M4AdapterDenied(_ERROR)
            self._check(self._plan)
            _require_m4_dispatch_ownership(self._plan, self._authorization, self._store)
            self._send_verified = True
            return min(self._plan.expires_at, self._authorization.expires_at)-self._last_now

    def _consume(self, material: memoryview) -> MaterialUseOutcome:
        body = bytearray()
        try:
            restore = self._original is not None
            body = build_scim_request_with_material(self._transition, material,
                current=self._transition._proposed if restore else self._transition._original,
                context=json.loads(self._transition._context),
                material_binding_digest=self._material_binding.material_binding_digest, restore=restore)
            with memoryview(body).toreadonly() as view:
                receipt = self._backend.submit(view, parameters_digest=self._plan.parameters_digest, restore=restore,
                    before_send=self._before_send, timeout_seconds=min(self._plan.expires_at,
                        self._authorization.expires_at)-self._last_now)
            if (not self._send_verified or type(receipt) is not ScimBackendReceipt
                    or receipt.source_digest != self._scope.configuration_source_digest
                    or receipt.parameters_digest != self._plan.parameters_digest or receipt.restore is not restore): raise ValueError
            self._receipt = receipt
            if self._snapshot() != self._plan.expected_state_digest: raise ValueError
            return MaterialUseOutcome.VERIFIED
        finally: _zeroize_mutable(body)

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        _require_m4_dispatch_ownership(plan, self._authorization, self._store)
        with self._lock:
            self._check(plan)
            if self._dispatched: raise M4AdapterDenied(_ERROR)
            self._dispatched = True
            try:
                restore = self._original is not None
                if (self._store.claim_count != (2 if restore else 1)
                        or self._material_store.claim_count != (1 if restore else 0)): raise ValueError
                outcome = MaterialLeaseCoordinator(self._provider, self._material_store).execute_once(
                    self._material_binding, self._material_request,
                    lambda lease: self._provider.consume(self._material_binding, lease, self._material_request, self._consume),
                    now_epoch=self._now())
                if outcome is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED: raise ValueError
                self._material_verified = True
            except Exception: raise M4AdapterAmbiguous(_ERROR) from None
            finally: self._provider.close()

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        with self._lock:
            self._check(plan)
            if self._receipt is None or not self._material_verified: raise M4AdapterAmbiguous(_ERROR)
            try:
                state = self._snapshot()
                self._check(plan)
                return state
            except Exception: raise M4AdapterAmbiguous(_ERROR) from None

    def _require_verified(self) -> None:
        if self._original is not None or self._receipt is None or not self._material_verified: raise M4AdapterDenied(_ERROR)
        p, a = self._plan, self._authorization
        claim = self._store.inspect_claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest,
            idempotency_digest=p.idempotency_digest, authorization_digest=a.authorization_digest,
            context_digest=canonical_digest(dict(plan_digest=p.plan_digest, authorization_digest=a.authorization_digest, revision=p.revision)))
        material = self._material_store._inspect_claim(request_digest=material_lease_request_digest(self._material_request),
            authorization_digest=a.authorization_digest)
        if (claim.result is None or claim.result.outcome != 'succeeded' or claim.result.verification != 'verified'
                or claim.result.compensation != 'not_requested' or material.state is not MaterialUseClaimState.REPLAY
                or material.outcome is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED): raise M4AdapterDenied(_ERROR)

    def bind_restore(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *,
            resolver: ScimMaterialResolver, authorization_verifier: M4AuthorizationVerifier | None = None,
            execution_enabled: bool = False) -> ScimLocalM4Adapter:
        try:
            with self._lock:
                self._require_verified()
                if type(execution_enabled) is not bool or not isinstance(resolver, ScimMaterialResolver): raise ValueError
                restore = object.__new__(ScimLocalM4Adapter); restore.__dict__.update(self.__dict__)
                restore._original = self
                restore._plan, restore._authorization, restore._resolver = plan, authorization, resolver
                restore._enabled = execution_enabled
                restore._verifier = authorization_verifier or DenyAllM4AuthorizationVerifier()
                restore._dispatched = restore._send_admitted = restore._send_verified = restore._material_verified = False
                restore._receipt = None
                restore._prepare_material(); restore._check_plan()
                return restore
        except Exception: raise M4AdapterDenied(_ERROR) from None
