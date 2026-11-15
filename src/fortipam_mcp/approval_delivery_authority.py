"""Inactive protected lab policy for fixed Approval Email configure and restore.

Existing Reference Authority supplies three independent grants per phase. The
read-only client here cannot issue grants or qualify a native source/backend.
"""
from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import hmac
from pathlib import Path
from threading import RLock
import time
from typing import Any, Iterator

from v4_planning import (M4AuthorizationDenied, M4ExecutionAuthorization, M4ExecutionPlan,
    VerifiedReferenceDecision, canonical_digest)
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.material_runtime import MaterialRuntimeOutcome, MaterialUseClaimState, material_lease_request_digest
from v4_planning.models import require_digest, require_ref

from .ldap_server_runtime import _key
from .m4_execution_store import PersistentM4ExecutionStateStore
from .reference_authority_sidecar import UnixReferenceAuthorityClient
from .approval_delivery_execution_contract import ApprovalDeliveryExecutionIntent
from .approval_delivery_local_workflow import Phase, ApprovalDeliveryAuthorizationRequest, approval_delivery_preview_content
from .approval_delivery_material import ApprovalDeliveryMaterialResolver
from .approval_delivery_m4 import (CONTRACT as ADAPTER, ApprovalDeliveryExecutionScope, ApprovalDeliveryBackend,
    ApprovalDeliveryEvidenceReader, approval_delivery_execution_digests, approval_delivery_material_request, read_approval_delivery_execution_state, _validate_stores)

POLICY = 'fortipam-mcp-lab-auto-approval_delivery-local-candidate-v1'
PURPOSES = ('permission', 'standing_intent', 'lab_policy')
_ERROR = 'The private Approval Email protected authorization is unavailable.'


@dataclass(frozen=True, slots=True, repr=False)
class _Issued(_OpaqueC3Object):
    request: ApprovalDeliveryAuthorizationRequest
    decisions: tuple[VerifiedReferenceDecision, ...]
    issued_at: int
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization


class ApprovalDeliveryProtectedLabAuthority(_OpaqueC3Object):
    @property
    def policy_mode(self) -> str: return 'lab_auto'

    def __init__(self, intent: ApprovalDeliveryExecutionIntent, scope: ApprovalDeliveryExecutionScope,
            backend: ApprovalDeliveryBackend, evidence: ApprovalDeliveryEvidenceReader, recovery: ApprovalDeliveryMaterialResolver,
            store: PersistentM4ExecutionStateStore, material_store: PersistentMaterialUseStateStore, *,
            reference_authority: UnixReferenceAuthorityClient, authority_key_file: Path,
            transport_digest: str, environment_ref: str, scope_ref: str, audience_ref: str,
            execution_enabled: bool = False, source_guard: Callable[[], bool] | None = None,
            clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(intent) is not ApprovalDeliveryExecutionIntent or type(scope) is not ApprovalDeliveryExecutionScope
                    or not isinstance(backend, ApprovalDeliveryBackend) or not isinstance(evidence, ApprovalDeliveryEvidenceReader)
                    or not isinstance(recovery, ApprovalDeliveryMaterialResolver) or type(reference_authority) is not UnixReferenceAuthorityClient
                    or type(execution_enabled) is not bool or not callable(clock)
                    or source_guard is not None and not callable(source_guard)): raise ValueError
            _validate_stores(store, material_store, enabled=True)
            require_digest(transport_digest, 'Approval Email client')
            for ref in (environment_ref, scope_ref, audience_ref): require_ref(ref, 'Approval Email lab scope')
            self._intent, self._scope, self._backend, self._evidence, self._recovery = intent, scope, backend, evidence, recovery
            self._store, self._material = store, material_store
            self._reference, self._reference_settings = reference_authority, reference_authority._settings
            self._key_file = Path(authority_key_file); self._key = _key(self._key_file)
            if any(hmac.compare_digest(self._key, item._key) for item in (store, material_store)): raise ValueError
            self._transport, self._environment, self._scope_ref, self._audience = transport_digest, environment_ref, scope_ref, audience_ref
            self._enabled, self._guard, self._guard_pin, self._clock = execution_enabled, source_guard, source_guard, clock
            self._last_now, self._failed_clock, self._closed = -1, False, False
            self._checkpoints = (store._monotonic_checkpoint, material_store._monotonic_checkpoint)
            self._namespace = canonical_digest(self._namespace_content())
            self._issued: dict[Phase, _Issued] = {}
            self._lock = RLock()
            self._busy = False
            self._integrity()
        except Exception: raise M4AuthorizationDenied(_ERROR) from None

    @contextmanager
    def _entered(self) -> Iterator[None]:
        with self._lock:
            if self._busy: raise ValueError
            self._busy = True
            try: yield
            finally: self._busy = False

    def _namespace_content(self) -> dict[str, Any]:
        return dict(policy=POLICY, policy_mode='lab_auto', reason='disposable_lab_local_implementation',
            parameters=approval_delivery_execution_digests(self._intent, self._scope, self._store, self._material)[2],
            transport=self._transport, environment=self._environment, scope=self._scope_ref, audience=self._audience,
            authority=self._reference.authority_ref, reference_socket=str(self._reference_settings.socket_path),
            signing_key=hashlib.sha256(self._key).hexdigest())

    def _integrity(self) -> None:
        if (self._reference._settings != self._reference_settings or canonical_digest(self._namespace_content()) != self._namespace
                or not hmac.compare_digest(_key(self._key_file), self._key)): raise ValueError
        stores: list[PersistentM4ExecutionStateStore | PersistentMaterialUseStateStore] = [self._store, self._material]
        for store, checkpoint in zip(stores, self._checkpoints):
            if store._monotonic_checkpoint is not checkpoint: raise ValueError
            store.verify_ready()
        self._reference.verify_ready()

    def _now(self) -> int:
        try:
            now = self._clock()
            if (self._closed or self._failed_clock or type(now) is not int or now < 0 or now < self._last_now): raise ValueError
            self._last_now = now
            return now
        except Exception:
            self._failed_clock = True
            raise M4AuthorizationDenied(_ERROR) from None

    def _live(self) -> int:
        guard = self._guard
        if self._closed or not self._enabled or guard is None or guard is not self._guard_pin or guard() is not True: raise ValueError
        self._integrity()
        now = self._now()
        if self._closed or not self._enabled or self._guard is not guard or self._guard_pin is not guard: raise ValueError
        return now

    def reference_for(self, phase: Phase, purpose: str) -> str:
        if phase not in ('configure', 'restore') or purpose not in PURPOSES: raise ValueError(_ERROR)
        return 'approval_delivery-reference-'+canonical_digest(dict(namespace=self._namespace, phase=phase, purpose=purpose))

    def _permissions(self, phase: Phase, now: int) -> tuple[VerifiedReferenceDecision, ...]:
        decisions = []
        for purpose in PURPOSES:
            ref = self.reference_for(phase, purpose); kind = 'approval_delivery_'+purpose
            decision = self._reference.authorize(ref, reference_kind=kind, requester_digest=self._scope.requester_digest,
                environment_ref=self._environment, scope_ref=self._scope_ref, now_epoch=now)
            if (type(decision) is not VerifiedReferenceDecision or decision.authorized is not True
                    or decision.reference_digest != canonical_digest(ref) or decision.reference_kind != kind
                    or decision.requester_digest != self._scope.requester_digest or decision.authority_ref != self._reference.authority_ref
                    or decision.environment_digest != canonical_digest(self._environment) or decision.scope_digest != canonical_digest(self._scope_ref)
                    or decision.checked_at != now or not now < decision.expires_at): raise ValueError
            decisions.append(decision)
        return tuple(decisions)

    def _request(self, request: ApprovalDeliveryAuthorizationRequest, now: int) -> None:
        if type(request) is not ApprovalDeliveryAuthorizationRequest or request.phase not in ('configure', 'restore'): raise ValueError
        require_ref(request.preview_ref, 'Approval Email preview')
        current, expected, parameters = approval_delivery_execution_digests(self._intent, self._scope, self._store, self._material)
        if request.phase == 'restore': current, expected = expected, current
        if (type(request.created_at) is not int or request.created_at < 0 or type(request.expires_at) is not int
                or request.expires_at != request.created_at+60 or not request.created_at <= now < request.expires_at
                or request.requester_digest != self._scope.requester_digest or request.transport_digest != self._transport
                or request.target_ref != 'approval-email-singleton-'+self._intent.original.serial_digest
                or (request.expected_current_digest, request.expected_state_digest, request.parameters_digest) != (current, expected, parameters)
                or request.summary_digest != canonical_digest(approval_delivery_preview_content(self._intent, request.phase,
                    request.preview_ref, request.created_at, policy_mode='lab_auto'))): raise ValueError

    def _current(self, request: ApprovalDeliveryAuthorizationRequest) -> None:
        restore = request.phase == 'restore'
        if self._store.claim_count != int(restore) or self._material.claim_count != int(restore): raise ValueError
        if restore:
            issued = self._issued['configure']; p, a = issued.plan, issued.authorization
            claim = self._store.inspect_claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest, idempotency_digest=p.idempotency_digest,
                authorization_digest=a.authorization_digest, context_digest=canonical_digest(dict(plan_digest=p.plan_digest,
                    authorization_digest=a.authorization_digest, revision=p.revision)))
            _, material_request = approval_delivery_material_request(self._intent, self._scope, p, a)
            material = self._material._inspect_claim(request_digest=material_lease_request_digest(material_request), authorization_digest=a.authorization_digest)
            if (claim.result is None or claim.result.outcome != 'succeeded' or claim.result.verification != 'verified'
                    or claim.result.compensation != 'not_requested' or material.state is not MaterialUseClaimState.REPLAY
                    or material.outcome is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED): raise ValueError
        if read_approval_delivery_execution_state(self._intent, self._scope, self._backend, self._evidence,
                self._recovery, self._now) != request.expected_current_digest: raise ValueError

    def _mac(self, purpose: str, value: Any) -> str:
        return hmac.new(self._key, POLICY.encode()+b'\0'+purpose.encode()+b'\0'+canonical_digest(value).encode(), hashlib.sha256).hexdigest()

    def _derive(self, request: ApprovalDeliveryAuthorizationRequest, decisions: tuple[VerifiedReferenceDecision, ...], issued_at: int
            ) -> tuple[M4ExecutionPlan, M4ExecutionAuthorization]:
        context = dict(namespace=self._namespace, request=asdict(request), grants=[d.as_dict() for d in decisions], issued_at=issued_at)
        intent, approval = self._mac('standing-intent', context), self._mac('lab-policy', context)
        action = 'approval-delivery-'+request.phase
        fields: dict[str, Any] = dict(plan_ref=action+'-'+request.parameters_digest, revision=1, action_id=action,
            action_version='1.0.0', adapter_ref=ADAPTER, target_ref=request.target_ref, requester_digest=self._scope.requester_digest,
            summary_digest=request.summary_digest, confirmation_digest=intent, approval_digest=approval, parameters_digest=request.parameters_digest,
            expected_current_digest=request.expected_current_digest, expected_state_digest=request.expected_state_digest,
            idempotency_digest=canonical_digest(dict(parameters=request.parameters_digest, action=action)), expires_at=request.expires_at, compensation_ref=None)
        plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
        values: dict[str, Any] = dict(authorization_ref='approval_delivery-lab-auth-'+self._mac('authorization', context), plan_ref=plan.plan_ref,
            plan_digest=plan.plan_digest, requester_digest=self._scope.requester_digest, confirmation_ref='approval_delivery-standing-intent-'+intent,
            confirmation_digest=intent, approval_ref='approval_delivery-lab-policy-'+approval, approval_digest=approval,
            approver_digest=self._mac('lab-policy-principal', self._namespace), issued_at=issued_at,
            expires_at=min(request.expires_at, *(d.expires_at for d in decisions)), one_time=True, execution_authorized=True)
        return plan, M4ExecutionAuthorization(**values, authorization_digest=canonical_digest(values))

    def authorize(self, request: ApprovalDeliveryAuthorizationRequest) -> tuple[M4ExecutionPlan, M4ExecutionAuthorization]:
        try:
            with self._entered():
                now = self._live(); self._request(request, now)
                decisions = self._permissions(request.phase, now)
                self._current(request)
                now = self._live(); self._request(request, now)
                plan, authorization = self._derive(request, decisions, now)
                if now >= authorization.expires_at: raise ValueError
                self._issued[request.phase] = _Issued(request, decisions, now, plan, authorization)
                return plan, authorization
        except Exception: raise M4AuthorizationDenied(_ERROR) from None

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            with self._entered():
                issued = next(item for item in self._issued.values() if item.plan is plan and item.authorization is authorization)
                now = self._live(); self._request(issued.request, now)
                if (type(now_epoch) is not int or not authorization.issued_at <= now_epoch <= now < authorization.expires_at
                        or (plan, authorization) != self._derive(issued.request, issued.decisions, issued.issued_at)): raise ValueError
                current = self._permissions(issued.request.phase, now)
                if self._live() >= min(authorization.expires_at, *(d.expires_at for d in current)): raise ValueError
        except Exception: raise M4AuthorizationDenied(_ERROR) from None

    def close(self) -> None:
        with self._lock: self._closed = True
