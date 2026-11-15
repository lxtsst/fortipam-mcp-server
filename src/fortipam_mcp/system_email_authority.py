"""Default-closed protected lab policy for the three fixed email candidates.

Read-only Reference Authority queries supply separate permission, standing
intent and lab-policy grants. This is not human approval, native qualification
or runtime registration. The planner cannot create grants through this module.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import hashlib
import hmac
from pathlib import Path
from threading import RLock
import time
from typing import Any

from v4_planning import M4AuthorizationDenied, M4ExecutionAuthorization, M4ExecutionPlan, VerifiedReferenceDecision, canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest, require_ref

from .ldap_server_runtime import _key
from .m4_execution_store import PersistentM4ExecutionStateStore
from .reference_authority_sidecar import UnixReferenceAuthorityClient
from .system_email_configuration_transition import SystemEmailConfigurationTransition
from .system_email_delivery_contract import SystemEmailDeliveryBinding
from .system_email_delivery_m4_adapter import (
    CONTRACT as DELIVERY_ADAPTER, SystemEmailDeliveryBackend, delivery_execution_digests, validate_delivery_store_separation,
)
from .system_email_local_workflow import Phase, SystemEmailAuthorizationRequest, system_email_preview_content
from .system_email_m4_adapter import CONTRACT as CONFIGURATION_ADAPTER, SystemEmailConfigurationBackend, system_email_execution_digests

POLICY = 'fortipam-mcp-lab-auto-system-email-local-candidate-v1'
PURPOSES = ('permission', 'standing_intent', 'lab_policy')
_ERROR = 'The private system-email protected authorization is unavailable.'
_PHASES: tuple[Phase, ...] = ('update', 'test-delivery', 'restore')


@dataclass(frozen=True, slots=True, repr=False)
class _Issued(_OpaqueC3Object):
    request: SystemEmailAuthorizationRequest
    decisions: tuple[VerifiedReferenceDecision, ...]
    issued_at: int
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization


class SystemEmailProtectedLabAuthority(_OpaqueC3Object):
    """One pinned proposal, operator/client, store pair and protected lab scope."""
    @property
    def policy_mode(self) -> str:
        return 'lab_auto'

    def __init__(self, transition: SystemEmailConfigurationTransition, backend: SystemEmailConfigurationBackend,
                 store: PersistentM4ExecutionStateStore, delivery_binding: SystemEmailDeliveryBinding,
                 delivery_backend: SystemEmailDeliveryBackend, delivery_store: PersistentM4ExecutionStateStore, *,
                 reference_authority: UnixReferenceAuthorityClient, authority_key_file: Path,
                 binding_digest: str, requester_digest: str, transport_digest: str,
                 environment_ref: str, scope_ref: str, audience_ref: str, window_digest: str,
                 execution_enabled: bool = False, source_guard: Callable[[Phase], bool] | None = None,
                 clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(transition) is not SystemEmailConfigurationTransition
                    or not isinstance(backend, SystemEmailConfigurationBackend)
                    or type(store) is not PersistentM4ExecutionStateStore
                    or type(delivery_binding) is not SystemEmailDeliveryBinding
                    or not isinstance(delivery_backend, SystemEmailDeliveryBackend)
                    or type(reference_authority) is not UnixReferenceAuthorityClient
                    or type(execution_enabled) is not bool or not callable(clock)
                    or source_guard is not None and not callable(source_guard)):
                raise ValueError
            validate_delivery_store_separation(store, delivery_store)
            if not store.monotonic_checkpoint_protocol_bound or not delivery_store.monotonic_checkpoint_protocol_bound:
                raise ValueError
            for value in (binding_digest, requester_digest, transport_digest, window_digest): require_digest(value, 'binding')
            for value in (environment_ref, scope_ref, audience_ref): require_ref(value, 'lab_scope')
            self._transition, self._backend, self._store = transition, backend, store
            self._delivery, self._sender, self._send_store = delivery_binding, delivery_backend, delivery_store
            self._reference, self._reference_settings = reference_authority, reference_authority._settings
            self._authority_ref = reference_authority.authority_ref
            self._key_file = Path(authority_key_file); self._key = _key(self._key_file)
            if any(hmac.compare_digest(self._key, item._key) for item in (store, delivery_store)): raise ValueError
            self._requester, self._transport = requester_digest, transport_digest
            self._environment, self._scope, self._audience, self._window = environment_ref, scope_ref, audience_ref, window_digest
            self._context = canonical_digest({'binding': binding_digest, 'requester': requester_digest, 'transport': transport_digest})
            if (delivery_binding.source_serial_digest != transition.original.source_serial_digest
                    or delivery_binding.configuration_digest != system_email_execution_digests(transition, self._context)[1]):
                raise ValueError
            self._enabled, self._guard, self._guard_pin = execution_enabled, source_guard, source_guard
            self._clock, self._last_now, self._clock_failed, self._closed = clock, -1, False, False
            self._checkpoints = (store._monotonic_checkpoint, delivery_store._monotonic_checkpoint)
            self._namespace = canonical_digest(self._namespace_content())
            self._issued: dict[Phase, _Issued] = {}
            self._lock = RLock()
            self._integrity()
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _namespace_content(self) -> dict[str, Any]:
        return dict(policy=POLICY, policy_mode='lab_auto', reason='disposable_lab_local_implementation',
            context=self._context, parameters=system_email_execution_digests(self._transition, self._context)[2],
            delivery=self._delivery.parameters_digest, window=self._window, requester=self._requester, transport=self._transport,
            environment=self._environment, scope=self._scope, audience=self._audience, authority=self._authority_ref,
            reference_socket=str(self._reference_settings.socket_path), signing_key=hashlib.sha256(self._key).hexdigest(),
            ledgers=[dict(database=str(s._path), key_file=str(s._key_path), key=hashlib.sha256(s._key).hexdigest(),
                checkpoint=s._checkpoint_store_ref, authority=getattr(s._monotonic_checkpoint, 'authority_ref'))
                for s in (self._store, self._send_store)])

    def _integrity(self) -> None:
        if (self._reference._settings != self._reference_settings or self._reference.authority_ref != self._authority_ref
                or canonical_digest(self._namespace_content()) != self._namespace
                or not hmac.compare_digest(_key(self._key_file), self._key)):
            raise ValueError
        for store, checkpoint in zip((self._store, self._send_store), self._checkpoints):
            if store._monotonic_checkpoint is not checkpoint or not hmac.compare_digest(store._load_key(), store._key):
                raise ValueError
            store.verify_ready()
        self._reference.verify_ready()

    def _now(self) -> int:
        try:
            now = self._clock()
            if self._closed or self._clock_failed or type(now) is not int or now < 0 or now < self._last_now: raise ValueError
            self._last_now = now; return now
        except Exception:
            self._clock_failed = True
            raise M4AuthorizationDenied(_ERROR) from None

    def _live(self, phase: Phase) -> int:
        if (self._closed or not self._enabled or phase not in _PHASES or self._guard is None
                or self._guard is not self._guard_pin or self._guard(phase) is not True): raise ValueError
        self._integrity()
        return self._now()

    def reference_for(self, phase: Phase, purpose: str) -> str:
        """Opaque reference for a trusted grant issuer; never creates a grant."""
        if phase not in _PHASES or purpose not in PURPOSES: raise ValueError(_ERROR)
        return 'system-email-reference-' + canonical_digest({'namespace': self._namespace, 'phase': phase, 'purpose': purpose})

    def _permissions(self, phase: Phase, now: int) -> tuple[VerifiedReferenceDecision, ...]:
        decisions = []
        for purpose in PURPOSES:
            reference = self.reference_for(phase, purpose); kind = 'system_email_' + purpose
            decision = self._reference.authorize(reference, reference_kind=kind, requester_digest=self._requester,
                environment_ref=self._environment, scope_ref=self._scope, now_epoch=now)
            if (type(decision) is not VerifiedReferenceDecision or decision.authorized is not True
                    or decision.reference_digest != canonical_digest(reference) or decision.reference_kind != kind
                    or decision.authority_ref != self._authority_ref or decision.requester_digest != self._requester
                    or decision.environment_digest != canonical_digest(self._environment)
                    or decision.scope_digest != canonical_digest(self._scope)
                    or decision.checked_at != now or not now < decision.expires_at): raise ValueError
            decisions.append(decision)
        return tuple(decisions)

    def _request(self, request: SystemEmailAuthorizationRequest, now: int) -> None:
        if type(request) is not SystemEmailAuthorizationRequest or request.phase not in _PHASES: raise ValueError
        require_ref(request.preview_ref, 'preview_ref')
        if (type(request.created_at) is not int or request.created_at < 0 or type(request.expires_at) is not int
                or request.expires_at != request.created_at + 60 or not request.created_at <= now < request.expires_at
                or request.requester_digest != self._requester or request.transport_digest != self._transport
                or request.target_ref != 'system-email-singleton-' + self._transition.original.source_serial_digest
                or request.adapter_ref != (DELIVERY_ADAPTER if request.phase == 'test-delivery' else CONFIGURATION_ADAPTER)
                or request.summary_digest != canonical_digest(system_email_preview_content(
                    self._transition, request.phase, request.preview_ref, request.created_at, policy_mode='lab_auto'))): raise ValueError
        if request.phase != 'test-delivery':
            current, expected, parameters = system_email_execution_digests(self._transition, self._context)
            if request.phase == 'restore': current, expected = expected, current
            if (request.expected_current_digest, request.expected_state_digest, request.parameters_digest) != (current, expected, parameters):
                raise ValueError

    def _original_update(self) -> None:
        issued = self._issued['update']; p, a = issued.plan, issued.authorization
        claim = self._store.inspect_claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest,
            idempotency_digest=p.idempotency_digest, authorization_digest=a.authorization_digest,
            context_digest=canonical_digest({'plan_digest': p.plan_digest, 'authorization_digest': a.authorization_digest, 'revision': p.revision}))
        if (claim.result is None or claim.result.outcome != 'succeeded' or claim.result.verification != 'verified'
                or claim.result.compensation != 'not_requested'): raise ValueError

    def _current(self, request: SystemEmailAuthorizationRequest) -> None:
        phase = request.phase
        if self._store.claim_count != (0 if phase == 'update' else 1): raise ValueError
        if self._send_store.claim_count not in ((0, 1) if phase == 'restore' else (0,)): raise ValueError
        if phase != 'update': self._original_update()
        if phase == 'test-delivery':
            observed = self._sender.inspect(self._delivery)
            if observed.capture.window_digest != self._window: raise ValueError
            current, expected, parameters = delivery_execution_digests(self._delivery, observed, self._context)
        else:
            observed_configuration = self._backend.inspect()
            if phase == 'update': self._transition.verify_restored(observed_configuration)
            else: self._transition.verify_applied(observed_configuration)
            current, expected, parameters = system_email_execution_digests(self._transition, self._context)
            if phase == 'restore': current, expected = expected, current
        if (request.expected_current_digest, request.expected_state_digest, request.parameters_digest) != (current, expected, parameters):
            raise ValueError

    def _mac(self, purpose: str, context: Any) -> str:
        return hmac.new(self._key, POLICY.encode() + b'\x00' + purpose.encode() + b'\x00'
            + canonical_digest(context).encode(), hashlib.sha256).hexdigest()

    def _derive(self, request: SystemEmailAuthorizationRequest, decisions: tuple[VerifiedReferenceDecision, ...],
                issued_at: int) -> tuple[M4ExecutionPlan, M4ExecutionAuthorization]:
        context = dict(namespace=self._namespace, request=asdict(request), grants=[d.as_dict() for d in decisions], issued_at=issued_at)
        intent, approval = self._mac('standing-intent', context), self._mac('lab-policy', context)
        fields: dict[str, Any] = dict(plan_ref='system-email-'+request.phase+'-'+request.parameters_digest, revision=1,
            action_id='system-email-'+request.phase, action_version='1.0.0', adapter_ref=request.adapter_ref,
            target_ref=request.target_ref, requester_digest=self._requester, summary_digest=request.summary_digest,
            confirmation_digest=intent, approval_digest=approval, parameters_digest=request.parameters_digest,
            expected_current_digest=request.expected_current_digest, expected_state_digest=request.expected_state_digest,
            idempotency_digest=canonical_digest({'binding': request.parameters_digest, 'phase': request.phase}),
            expires_at=request.expires_at, compensation_ref=None)
        plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
        values: dict[str, Any] = dict(authorization_ref='system-email-lab-auth-'+self._mac('authorization', context),
            plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=self._requester,
            confirmation_ref='system-email-standing-intent-'+intent, confirmation_digest=intent,
            approval_ref='system-email-lab-policy-'+approval, approval_digest=approval,
            approver_digest=self._mac('lab-policy-principal', self._namespace), issued_at=issued_at,
            expires_at=min(request.expires_at, *(decision.expires_at for decision in decisions)),
            one_time=True, execution_authorized=True)
        return plan, M4ExecutionAuthorization(**values, authorization_digest=canonical_digest(values))

    def authorize(self, request: SystemEmailAuthorizationRequest) -> tuple[M4ExecutionPlan, M4ExecutionAuthorization]:
        try:
            with self._lock:
                if type(request) is not SystemEmailAuthorizationRequest: raise ValueError
                now = self._live(request.phase); self._request(request, now)
                decisions = self._permissions(request.phase, now)
                self._current(request)
                now = self._live(request.phase); self._request(request, now)
                plan, authorization = self._derive(request, decisions, now)
                if not now < authorization.expires_at: raise ValueError
                self._issued[request.phase] = _Issued(request, decisions, now, plan, authorization)
                return plan, authorization
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            with self._lock:
                issued = next(item for item in self._issued.values() if item.plan is plan and item.authorization is authorization)
                now = self._live(issued.request.phase); self._request(issued.request, now)
                if (type(now_epoch) is not int or not authorization.issued_at <= now_epoch <= now < authorization.expires_at
                        or (plan, authorization) != self._derive(issued.request, issued.decisions, issued.issued_at)):
                    raise ValueError
                current_permissions = self._permissions(issued.request.phase, now)
                if self._live(issued.request.phase) >= min(authorization.expires_at,
                        *(decision.expires_at for decision in current_permissions)): raise ValueError
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
