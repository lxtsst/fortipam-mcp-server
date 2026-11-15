"""Default-closed independent-material M4 candidate with no HTTP backend.

Configuration reads, qualification evidence and original-material recovery have
separate contracts. Synthetic receipts exercise only this local protocol; they
do not establish native ACK, permissions, mail isolation or restoration rights.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import hashlib
import hmac
from threading import RLock
import time
from typing import Protocol, runtime_checkable

from v4_planning import (
    DenyAllM4AuthorizationVerifier, M4AdapterAmbiguous, M4AdapterDenied,
    M4AuthorizationVerifier, M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest,
)
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import (
    MaterialBindingStatus, MaterialLeaseRequest, MaterialProviderClass, _OpaqueC3Object,
)
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_runtime import (
    MaterialLeaseCoordinator, MaterialRuntimeOutcome, MaterialUseClaimState,
    MaterialUseOutcome, material_lease_request_digest,
)
from v4_planning.models import require_digest

from .approval_delivery_execution_contract import ApprovalDeliveryExecutionIntent, ApprovalDeliveryReadback
from .approval_delivery_material import ApprovalDeliveryMaterialBinding, ApprovalDeliveryMaterialProvider, ApprovalDeliveryMaterialResolver
from .approval_delivery_material_contract import build_approval_delivery_material_body, _ROLES
from .m4_execution_store import PersistentM4ExecutionStateStore
from .mutable_json_buffer import _erase_transfer_storage

CONTRACT = "fortipam_approval_delivery_local_m4_candidate_v1"
_ERROR = "The private approval-delivery execution is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class ApprovalDeliveryExecutionScope(_OpaqueC3Object):
    binding_digest: str
    requester_digest: str
    scope_digest: str
    audience_digest: str
    configuration_source_digest: str
    material_source_digest: str
    qualification_source_digest: str
    preservation_digest: str

    def __post_init__(self) -> None:
        for value in asdict(self).values(): require_digest(value, "Approval Email scope")
        if len({self.configuration_source_digest, self.material_source_digest, self.qualification_source_digest}) != 3:
            raise ValueError


@dataclass(frozen=True, slots=True, repr=False)
class ApprovalDeliveryExecutionEvidence(_OpaqueC3Object):
    configuration_digest: str
    material_source_digest: str
    qualification_source_digest: str
    material_binding_digest: str
    preservation_digest: str
    in_flight: int
    complete: bool
    whole_singleton_verified: bool
    native_merge_and_material_semantics_verified: bool
    native_ack_qualified: bool
    material_custody_verified: bool
    permission_verified: bool
    workload_identity_isolated: bool
    delivery_isolation_verified: bool
    object_history_verified: bool
    recovery_ready: bool
    observed_at: int
    expires_at: int

    def __post_init__(self) -> None:
        for value in (self.configuration_digest, self.material_source_digest, self.qualification_source_digest,
                self.material_binding_digest, self.preservation_digest): require_digest(value, "Approval Email evidence")
        flags = (self.complete, self.whole_singleton_verified, self.native_merge_and_material_semantics_verified,
            self.native_ack_qualified, self.material_custody_verified, self.permission_verified,
            self.workload_identity_isolated, self.delivery_isolation_verified, self.object_history_verified, self.recovery_ready)
        if (any(type(flag) is not bool for flag in flags) or type(self.in_flight) is not int or self.in_flight < 0
                or type(self.observed_at) is not int or type(self.expires_at) is not int
                or not 0 <= self.observed_at < self.expires_at <= self.observed_at + 10): raise ValueError


@dataclass(frozen=True, slots=True, repr=False)
class ApprovalDeliveryBackendReceipt(_OpaqueC3Object):
    source_digest: str
    parameters_digest: str
    restore: bool

    def __post_init__(self) -> None:
        for value in (self.source_digest, self.parameters_digest): require_digest(value, "Approval Email receipt")
        if type(self.restore) is not bool: raise ValueError


@runtime_checkable
class ApprovalDeliveryBackend(Protocol):
    def inspect(self) -> ApprovalDeliveryReadback: ...
    def submit(self, body: memoryview, *, parameters_digest: str, restore: bool,
        before_send: Callable[[], int], timeout_seconds: int) -> ApprovalDeliveryBackendReceipt: ...


@runtime_checkable
class ApprovalDeliveryEvidenceReader(Protocol):
    def observe(self, configuration_digest: str) -> ApprovalDeliveryExecutionEvidence: ...


def _state_digest(readback: ApprovalDeliveryReadback, material: str, scope: ApprovalDeliveryExecutionScope) -> str:
    # material/preservation are opaque custody/reference facts, never hashes
    # of protected values or unrestricted singleton responses.
    return canonical_digest(dict(contract=CONTRACT, configuration=readback.digest,
        material=material, preservation=scope.preservation_digest))


def _validate_stores(execution: PersistentM4ExecutionStateStore, material: PersistentMaterialUseStateStore, *, enabled: bool) -> None:
    if type(execution) is not PersistentM4ExecutionStateStore or type(material) is not PersistentMaterialUseStateStore:
        raise M4AdapterDenied(_ERROR)
    paths = (execution._path, execution._key_path, material._path, material._key_path)
    if (len({path.resolve() for path in paths}) != 4 or material.shares_key_material_with(execution)
            or execution._checkpoint_store_ref == material._checkpoint_store_ref
            or enabled and not (execution.monotonic_checkpoint_protocol_bound and material.monotonic_checkpoint_protocol_bound)):
        raise M4AdapterDenied(_ERROR)
    execution.verify_ready(); material.verify_ready()


def approval_delivery_execution_digests(intent: ApprovalDeliveryExecutionIntent, scope: ApprovalDeliveryExecutionScope,
        execution: PersistentM4ExecutionStateStore, material: PersistentMaterialUseStateStore) -> tuple[str, str, str]:
    if (type(intent) is not ApprovalDeliveryExecutionIntent or type(scope) is not ApprovalDeliveryExecutionScope
            or intent.original.source_digest != scope.configuration_source_digest): raise ValueError
    _validate_stores(execution, material, enabled=False)
    current = _state_digest(intent.original, intent.material_binding(restore=True).material_binding_digest, scope)
    expected = _state_digest(intent.expected_readback(), intent.material_binding().material_binding_digest, scope)
    domains = []
    for store in (execution, material):
        if not hmac.compare_digest(store._key, store._load_key()): raise ValueError
        domains.append(dict(database=hashlib.sha256(str(store._path.resolve()).encode()).hexdigest(),
            key_file=hashlib.sha256(str(store._key_path.resolve()).encode()).hexdigest(),
            key=hashlib.sha256(store._key).hexdigest(), checkpoint=store._checkpoint_store_ref,
            authority=getattr(store._monotonic_checkpoint, "authority_ref", None)))
    return current, expected, canonical_digest(dict(contract=CONTRACT, intent=intent.digest, scope=asdict(scope), domains=domains))


def approval_delivery_material_request(intent: ApprovalDeliveryExecutionIntent, scope: ApprovalDeliveryExecutionScope,
        plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, restore: bool = False
        ) -> tuple[ApprovalDeliveryMaterialBinding, MaterialLeaseRequest]:
    binding = intent.material_binding(restore=restore)
    request = MaterialLeaseRequest(plan.action_id, plan.action_version, plan.plan_digest, plan.approval_digest,
        authorization.authorization_digest, scope.scope_digest, scope.audience_digest,
        MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE, binding.purpose,
        authorization.issued_at, min(plan.expires_at, authorization.expires_at))
    return binding, request


def read_approval_delivery_execution_state(intent: ApprovalDeliveryExecutionIntent, scope: ApprovalDeliveryExecutionScope,
        backend: ApprovalDeliveryBackend, evidence_reader: ApprovalDeliveryEvidenceReader,
        recovery: ApprovalDeliveryMaterialResolver, clock: Callable[[], int]) -> str:
    observed = backend.inspect()
    if (type(observed) is not ApprovalDeliveryReadback or observed.source_digest != scope.configuration_source_digest
            or observed.serial_digest != intent.original.serial_digest or observed.schema_digest != intent.original.schema_digest):
        raise ValueError
    evidence = evidence_reader.observe(observed.digest)
    now = clock()
    if (type(evidence) is not ApprovalDeliveryExecutionEvidence or evidence.configuration_digest != observed.digest
            or evidence.material_source_digest != scope.material_source_digest
            or evidence.qualification_source_digest != scope.qualification_source_digest
            or evidence.preservation_digest != scope.preservation_digest or evidence.in_flight != 0
            or not all((evidence.complete, evidence.whole_singleton_verified, evidence.native_merge_and_material_semantics_verified,
                evidence.native_ack_qualified, evidence.material_custody_verified, evidence.permission_verified,
                evidence.workload_identity_isolated, evidence.delivery_isolation_verified, evidence.object_history_verified, evidence.recovery_ready))
            or not max(observed.observed_at, evidence.observed_at) <= now < min(observed.expires_at, evidence.expires_at)
            or recovery.validate_prebound() is not MaterialBindingStatus.AVAILABLE
            or recovery.binding_digest != intent.material_binding(restore=True).material_binding_digest
            or clock() >= min(observed.expires_at, evidence.expires_at)):
        raise ValueError
    return _state_digest(observed, evidence.material_binding_digest, scope)


class ApprovalDeliveryM4Adapter(_OpaqueC3Object):
    def __init__(self, intent: ApprovalDeliveryExecutionIntent, backend: ApprovalDeliveryBackend,
            evidence: ApprovalDeliveryEvidenceReader, resolver: ApprovalDeliveryMaterialResolver,
            recovery: ApprovalDeliveryMaterialResolver, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
            execution: PersistentM4ExecutionStateStore, material: PersistentMaterialUseStateStore, *,
            scope: ApprovalDeliveryExecutionScope, authorization_verifier: M4AuthorizationVerifier | None = None,
            execution_enabled: bool = False, source_guard: Callable[[], bool] | None = None,
            clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(intent) is not ApprovalDeliveryExecutionIntent or type(scope) is not ApprovalDeliveryExecutionScope
                    or not isinstance(backend, ApprovalDeliveryBackend) or not isinstance(evidence, ApprovalDeliveryEvidenceReader)
                    or not isinstance(resolver, ApprovalDeliveryMaterialResolver) or not isinstance(recovery, ApprovalDeliveryMaterialResolver)
                    or resolver is recovery or type(execution_enabled) is not bool or not callable(clock)
                    or source_guard is not None and not callable(source_guard)):
                raise ValueError
            _validate_stores(execution, material, enabled=execution_enabled)
            self._intent, self._scope, self._backend, self._evidence = intent, scope, backend, evidence
            self._resolver, self._recovery, self._store, self._material_store = resolver, recovery, execution, material
            self._plan, self._authorization = plan, authorization
            self._verifier = authorization_verifier or DenyAllM4AuthorizationVerifier()
            self._enabled, self._guard, self._guard_pin, self._clock = execution_enabled, source_guard, source_guard, clock
            self._last_now, self._failed_clock = -1, False
            self._original: ApprovalDeliveryM4Adapter | None = None
            self._receipt: ApprovalDeliveryBackendReceipt | None = None
            self._dispatched = self._send_admitted = self._send_verified = self._material_verified = False
            self._lock = RLock()
            self._prepare_material(); self._check_plan()
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def _prepare_material(self) -> None:
        binding, request = approval_delivery_material_request(self._intent, self._scope, self._plan,
            self._authorization, restore=self._original is not None)
        self._material_binding, self._material_request = binding, request
        self._provider = ApprovalDeliveryMaterialProvider(self._resolver, binding, request, clock=self._now)

    def _check_plan(self) -> None:
        current, expected, parameters = approval_delivery_execution_digests(self._intent, self._scope, self._store, self._material_store)
        if self._original is not None: current, expected = expected, current
        p, a = self._plan, self._authorization
        p.__post_init__(); a.__post_init__()
        action = self._material_binding.action_id
        if (p.action_id != action or p.action_version != "1.0.0" or p.adapter_ref != CONTRACT or p.revision != 1
                or p.compensation_ref is not None or p.requester_digest != self._scope.requester_digest
                or p.parameters_digest != parameters or p.plan_ref != action + "-" + parameters
                or p.target_ref != "approval-email-singleton-" + self._intent.original.serial_digest
                or p.idempotency_digest != canonical_digest(dict(parameters=parameters, action=action))
                or p.expected_current_digest != current or p.expected_state_digest != expected
                or a.plan_ref != p.plan_ref or a.plan_digest != p.plan_digest or a.requester_digest != p.requester_digest
                or self._recovery.binding_digest != self._intent.material_binding(restore=True).material_binding_digest):
            raise ValueError

    def _now(self) -> int:
        now = self._clock()
        if self._failed_clock or type(now) is not int or now < 0 or now < self._last_now:
            self._failed_clock = True; self._enabled = False
            raise M4AdapterDenied(_ERROR)
        self._last_now = now
        return now

    def _check(self, plan: M4ExecutionPlan, *, material_ready: bool = False) -> None:
        try:
            authorization, guard, verifier = self._authorization, self._guard, self._verifier
            provider = self._provider
            def pinned() -> None:
                if (not self._enabled or plan is not self._plan or self._authorization is not authorization
                        or guard is None or self._guard is not guard or self._guard_pin is not guard
                        or self._verifier is not verifier): raise ValueError
                if material_ready and (self._provider is not provider or provider._closed or provider._failed
                        or provider._binding is not self._material_binding or provider._request is not self._material_request
                        or not provider._consumed or provider._lease is None or len(provider._buffers) != 3): raise ValueError
            pinned()
            if guard is None or guard() is not True: raise ValueError
            pinned()
            self._check_plan(); now = self._now()
            if not authorization.issued_at <= now < min(plan.expires_at, authorization.expires_at): raise ValueError
            verifier.verify(plan, authorization, now_epoch=now)
            self._store.verify_ready(); self._material_store.verify_ready()
            pinned()
            if guard() is not True: raise ValueError
            pinned()
            # The final guard can revoke a source that was available earlier.
            # Source callbacks finish before the final authorization checks;
            # no guard runs after this material readiness observation.
            if material_ready and provider._status(self._material_binding, self._material_request) is not MaterialBindingStatus.AVAILABLE:
                raise ValueError
            pinned()
            self._check_plan(); now = self._now()
            if not authorization.issued_at <= now < min(plan.expires_at, authorization.expires_at): raise ValueError
            # The last guard may revoke an already checked grant. Verify again,
            # then finish with pure pin checks after the clock callback.
            verifier.verify(plan, authorization, now_epoch=now)
            now = self._now()
            pinned()
            if not authorization.issued_at <= now < min(plan.expires_at, authorization.expires_at): raise ValueError
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def _snapshot(self) -> str:
        return read_approval_delivery_execution_state(self._intent, self._scope, self._backend,
            self._evidence, self._recovery, self._now)

    def read_current(self, plan: M4ExecutionPlan) -> str:
        with self._lock:
            self._check(plan)
            if self._original is not None: self._original._require_verified()
            try:
                result = self._snapshot(); self._check(plan)
                return result
            except Exception:
                raise M4AdapterAmbiguous(_ERROR) from None

    def _before_send(self) -> int:
        _require_m4_dispatch_ownership(self._plan, self._authorization, self._store)
        with self._lock:
            self._check(self._plan)
            if self._send_admitted: raise M4AdapterDenied(_ERROR)
            self._send_admitted = True
            if self.read_current(self._plan) != self._plan.expected_current_digest: raise M4AdapterDenied(_ERROR)
            if self._provider._status(self._material_binding, self._material_request) is not MaterialBindingStatus.AVAILABLE:
                raise M4AdapterDenied(_ERROR)
            self._check(self._plan, material_ready=True)
            _require_m4_dispatch_ownership(self._plan, self._authorization, self._store)
            self._send_verified = True
            return min(self._plan.expires_at, self._authorization.expires_at) - self._last_now

    def _consume(self, username: memoryview, credential: memoryview, client_secret: memoryview) -> MaterialUseOutcome:
        body = bytearray()
        try:
            restore = self._original is not None
            draft = self._intent.original_draft if restore else self._intent.proposed
            body = build_approval_delivery_material_body(draft, username=username, credential=credential,
                client_secret=client_secret, material_binding_digests=dict(zip(_ROLES, draft._binding_digests, strict=True)))
            with memoryview(body).toreadonly() as view:
                receipt = self._backend.submit(view, parameters_digest=self._plan.parameters_digest, restore=restore,
                    before_send=self._before_send, timeout_seconds=min(self._plan.expires_at, self._authorization.expires_at) - self._last_now)
            if (not self._send_verified or type(receipt) is not ApprovalDeliveryBackendReceipt
                    or receipt.source_digest != self._scope.configuration_source_digest
                    or receipt.parameters_digest != self._plan.parameters_digest or receipt.restore is not restore): raise ValueError
            self._receipt = receipt
            if self._snapshot() != self._plan.expected_state_digest: raise ValueError
            return MaterialUseOutcome.VERIFIED
        finally:
            _erase_transfer_storage(body)

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        _require_m4_dispatch_ownership(plan, self._authorization, self._store)
        with self._lock:
            self._check(plan)
            if self._dispatched: raise M4AdapterDenied(_ERROR)
            self._dispatched = True
            try:
                restore = self._original is not None
                if self._store.claim_count != (2 if restore else 1) or self._material_store.claim_count != (1 if restore else 0): raise ValueError
                outcome = MaterialLeaseCoordinator(self._provider, self._material_store).execute_once(
                    self._material_binding, self._material_request,
                    lambda lease: self._provider.consume(self._material_binding, lease, self._material_request, self._consume),
                    now_epoch=self._now())
                if outcome is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED: raise ValueError
                self._material_verified = True
            except Exception:
                raise M4AdapterAmbiguous(_ERROR) from None
            finally:
                self._provider.close()

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        with self._lock:
            self._check(plan)
            if self._receipt is None or not self._material_verified: raise M4AdapterAmbiguous(_ERROR)
            try:
                result = self._snapshot(); self._check(plan)
                return result
            except Exception:
                raise M4AdapterAmbiguous(_ERROR) from None

    def _require_verified(self) -> None:
        if self._original is not None or self._receipt is None or not self._material_verified: raise M4AdapterDenied(_ERROR)
        p, a = self._plan, self._authorization
        claim = self._store.inspect_claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest,
            idempotency_digest=p.idempotency_digest, authorization_digest=a.authorization_digest,
            context_digest=canonical_digest(dict(plan_digest=p.plan_digest, authorization_digest=a.authorization_digest, revision=p.revision)))
        material = self._material_store._inspect_claim(request_digest=material_lease_request_digest(self._material_request),
            authorization_digest=a.authorization_digest)
        if (claim.result is None or claim.result.outcome != "succeeded" or claim.result.verification != "verified"
                or claim.result.compensation != "not_requested" or material.state is not MaterialUseClaimState.REPLAY
                or material.outcome is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED): raise M4AdapterDenied(_ERROR)

    def bind_restore(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *,
            resolver: ApprovalDeliveryMaterialResolver, authorization_verifier: M4AuthorizationVerifier | None = None,
            execution_enabled: bool = False, source_guard: Callable[[], bool] | None = None) -> ApprovalDeliveryM4Adapter:
        try:
            with self._lock:
                self._require_verified()
                if (self._failed_clock or type(execution_enabled) is not bool
                        or not isinstance(resolver, ApprovalDeliveryMaterialResolver) or resolver is self._resolver
                        or source_guard is not None and not callable(source_guard)): raise ValueError
                _validate_stores(self._store, self._material_store, enabled=execution_enabled)
                restore = object.__new__(ApprovalDeliveryM4Adapter)
                restore.__dict__.update(self.__dict__)
                restore._original, restore._plan, restore._authorization, restore._resolver = self, plan, authorization, resolver
                restore._verifier = authorization_verifier or DenyAllM4AuthorizationVerifier()
                restore._guard = restore._guard_pin = self._guard if source_guard is None else source_guard
                restore._enabled, restore._receipt = execution_enabled, None
                restore._dispatched = restore._send_admitted = restore._send_verified = restore._material_verified = False
                restore._prepare_material(); restore._check_plan()
                return restore
        except Exception:
            raise M4AdapterDenied(_ERROR) from None
