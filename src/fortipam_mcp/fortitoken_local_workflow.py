"""Private fixed FortiToken preview/independent authorization/M4 workflow, no startup binding."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import secrets
from threading import RLock
import time
from typing import Literal, Protocol

from v4_planning import (DenyAllM4AuthorizationVerifier, M4AuthorizationDenied,
    M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionPlan, M4ExecutionResult, canonical_digest)
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .m4_execution_store import PersistentM4ExecutionStateStore
from .fortitoken_user_contract import FortitokenUserPlan, expected_fortitoken_user_state
from .fortitoken_user_source import FortitokenUserSource
from .fortitoken_material import FortitokenMaterialResolver
from .fortitoken_local_m4 import (FortitokenLocalM4Adapter, FortitokenExecutionScope, FortitokenConfigurationBackend,
    FortitokenEvidenceReader, fortitoken_execution_digests, read_fortitoken_execution_state, _validate_stores)

CONTRACT = 'fortipam_v4_fortitoken_local_workflow_v1'
_ERROR = 'The private FortiToken workflow is unavailable.'
Phase = Literal['apply', 'restore']


@dataclass(frozen=True, slots=True, repr=False)
class FortitokenAuthorizationRequest(_OpaqueC3Object):
    phase: Phase
    preview_ref: str
    requester_digest: str
    transport_digest: str
    summary_digest: str
    parameters_digest: str
    expected_current_digest: str
    expected_state_digest: str
    target_ref: str
    created_at: int
    expires_at: int


class FortitokenWorkflowAuthority(Protocol):
    def authorize(self, request: FortitokenAuthorizationRequest) -> tuple[M4ExecutionPlan, M4ExecutionAuthorization]: ...
    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None: ...


class DenyAllFortitokenWorkflowAuthority(DenyAllM4AuthorizationVerifier):
    def authorize(self, request: FortitokenAuthorizationRequest) -> tuple[M4ExecutionPlan, M4ExecutionAuthorization]:
        raise M4AuthorizationDenied(_ERROR)


def fortitoken_preview_content(intent: FortitokenUserPlan, phase: Phase, preview_ref: str,
        created_at: int, *, policy_mode: str | None = None) -> dict[str,object]:
    if phase not in ('apply','restore'): raise ValueError(_ERROR)
    selected = FortitokenUserPlan(expected_fortitoken_user_state(intent),
        'revoke' if intent.operation == 'assign' else 'assign') if phase == 'restore' else intent
    public = selected.preview()
    public['Current State'] = dict(disabled_local_standard_profile=True,token_selector_present=selected.current.token_present,
        configuration_matches_bound_plan_locally=True,source_preconditions_reported=True,
        original_update_verified_locally=phase == 'restore')
    if phase == 'restore':
        public['Expected State'] = dict(restore_original_nonmaterial_configuration=True,
            independent_material_continuity_required=True,independent_mfa_effect_required=True,
            complete_postcondition_qualified=False)
    public.update(contract=CONTRACT,operation=intent.operation,effective_operation=selected.operation,
        phase=phase,preview_ref=preview_ref,expires_at=created_at+60,device_write_executed=False,native_backend_qualified=False)
    if policy_mode is not None: public['authorization_policy_mode'] = policy_mode
    return public


class FortitokenLocalWorkflow(_OpaqueC3Object):
    def __init__(self, intent: FortitokenUserPlan, source: FortitokenUserSource, backend: FortitokenConfigurationBackend, evidence: FortitokenEvidenceReader,
            resolver: FortitokenMaterialResolver, recovery_resolver: FortitokenMaterialResolver,
            store: PersistentM4ExecutionStateStore, material_store: PersistentMaterialUseStateStore, *,
            scope: FortitokenExecutionScope, allowed_transport_digest: str, authority: FortitokenWorkflowAuthority | None = None,
            apply_enabled: bool = False, restore_enabled: bool = False, source_guard: Callable[[], bool] | None = None,
            clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(intent) is not FortitokenUserPlan
                    or type(source) is not FortitokenUserSource
                    or type(scope) is not FortitokenExecutionScope or type(apply_enabled) is not bool or type(restore_enabled) is not bool
                    or not isinstance(backend, FortitokenConfigurationBackend) or not isinstance(evidence, FortitokenEvidenceReader)
                    or not isinstance(resolver, FortitokenMaterialResolver) or not isinstance(recovery_resolver, FortitokenMaterialResolver)
                    or type(store) is not PersistentM4ExecutionStateStore or type(material_store) is not PersistentMaterialUseStateStore
                    or not callable(clock) or source_guard is not None and not callable(source_guard)): raise ValueError
            require_digest(allowed_transport_digest, 'FortiToken transport')
            fortitoken_execution_digests(intent, scope, store, material_store)
            _validate_stores(store, material_store, enabled=apply_enabled or restore_enabled)
            if store.claim_count or material_store.claim_count: raise ValueError
            self._intent, self._source, self._scope, self._backend, self._evidence = intent, source, scope, backend, evidence
            self._resolver, self._recovery = resolver, recovery_resolver
            self._store, self._material = store, material_store
            self._transport, self._authority = allowed_transport_digest, authority or DenyAllFortitokenWorkflowAuthority()
            self._enabled = {'apply': apply_enabled, 'restore': restore_enabled}
            self._guard, self._clock, self._last_now, self._closed = source_guard, clock, -1, False
            self._previews: dict[Phase, FortitokenAuthorizationRequest] = {}
            self._issued: dict[Phase, tuple[M4ExecutionPlan, M4ExecutionAuthorization]] = {}
            self._adapters: dict[Phase, FortitokenLocalM4Adapter] = {}
            self._results: dict[Phase, M4ExecutionResult] = {}
            self._attempted: set[Phase] = set()
            self._lock = RLock()
            source.bind_plan(intent)
        except Exception: raise ValueError(_ERROR) from None

    @property
    def operation(self) -> str: return self._intent.operation

    def _now(self) -> int:
        now = self._clock()
        if self._closed or type(now) is not int or now < 0 or now < self._last_now:
            self._closed = True
            raise ValueError(_ERROR)
        self._last_now = now
        return now

    def _identity(self, requester_digest: str, transport_digest: str) -> None:
        self._now()
        if requester_digest != self._scope.requester_digest or transport_digest != self._transport: raise ValueError

    def _source_ready(self) -> bool:
        return not self._closed and self._guard is not None and self._guard() is True

    def _gate(self, phase: Phase) -> None:
        if phase not in self._enabled or not self._enabled[phase] or not self._source_ready(): raise ValueError

    def _phase_ready(self, phase: Phase) -> None:
        if phase not in ('apply', 'restore') or phase in self._attempted: raise ValueError
        if phase == 'apply':
            if self._store.claim_count or self._material.claim_count: raise ValueError
        else:
            if self._store.claim_count != 1 or self._material.claim_count != 1: raise ValueError
            self._adapters['apply']._require_verified()

    def preview(self, phase: Phase, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest); self._phase_ready(phase)
                current, expected, parameters = fortitoken_execution_digests(self._intent, self._scope, self._store, self._material)
                if phase == 'restore': current, expected = expected, current
                observed = read_fortitoken_execution_state(self._intent, self._scope, self._source, self._evidence, self._recovery, self._now)
                if observed != current: raise ValueError
                now = self._now(); reference = 'fortitoken-preview-'+secrets.token_hex(24)
                public = fortitoken_preview_content(self._intent, phase, reference, now, policy_mode=getattr(self._authority, 'policy_mode', None))
                request = FortitokenAuthorizationRequest(phase, reference, requester_digest, transport_digest, canonical_digest(public),
                    parameters, current, expected, 'fortitoken-user-'+self._intent.current.binding.digest, now, now+60)
                self._previews[phase] = request
                self._issued.pop(phase, None); self._adapters.pop(phase, None)
                return public
        except Exception: raise ValueError(_ERROR) from None

    def authorize(self, phase: Phase, preview_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest); self._gate(phase); self._phase_ready(phase)
                request = self._previews[phase]
                if (type(preview_ref) is not str or preview_ref != request.preview_ref
                        or not request.created_at <= self._now() < request.expires_at): raise ValueError
                plan, authorization = self._authority.authorize(request)
                if (type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization
                        or plan.summary_digest != request.summary_digest or plan.parameters_digest != request.parameters_digest
                        or plan.expected_current_digest != request.expected_current_digest or plan.expected_state_digest != request.expected_state_digest
                        or plan.target_ref != request.target_ref or plan.expires_at != request.expires_at
                        or not request.created_at <= authorization.issued_at <= self._now() < authorization.expires_at <= request.expires_at): raise ValueError
                if phase == 'apply':
                    adapter = FortitokenLocalM4Adapter(self._intent, self._source, self._backend, self._evidence, self._resolver, self._recovery,
                        plan, authorization, self._store, self._material, scope=self._scope, authorization_verifier=self._authority,
                        execution_enabled=self._enabled[phase], source_guard=self._source_ready, clock=self._now)
                else:
                    adapter = self._adapters['apply'].bind_restore(plan, authorization, resolver=self._recovery,
                        authorization_verifier=self._authority, execution_enabled=self._enabled[phase])
                self._authority.verify(plan, authorization, now_epoch=self._now())
                self._issued[phase], self._adapters[phase] = (plan, authorization), adapter
                return dict(contract=CONTRACT, phase=phase, authorization_ref=authorization.authorization_ref,
                    expires_at=authorization.expires_at, native_backend_qualified=False)
        except Exception: raise ValueError(_ERROR) from None

    def execute(self, phase: Phase, authorization_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                plan, authorization = self._issued[phase]
                if type(authorization_ref) is not str or authorization_ref != authorization.authorization_ref: raise ValueError
                if phase in self._results:
                    return {**replace(self._results[phase], idempotent_replay=True).as_dict(), 'native_backend_qualified': False}
                if phase in self._attempted: raise ValueError
                self._gate(phase); self._phase_ready(phase)
                # This candidate authority rechecks read-only grants. Reject a
                # known-invalid permission before reserving a dispatch; M4
                # still verifies independently after its durable reservation.
                self._authority.verify(plan, authorization, now_epoch=self._now())
                self._attempted.add(phase)
                try:
                    result = M4ExecutionKernel(self._adapters[phase], self._authority, self._store, clock=self._now).execute(plan, authorization)
                except BaseException:
                    # A rejected, unconsumed authorization may be renewed. An
                    # uncertain store or any consumed position stays terminal.
                    try: untouched = self._store.claim_count == self._material.claim_count == (1 if phase == 'restore' else 0)
                    except Exception: untouched = False
                    if untouched: self._attempted.discard(phase)
                    raise
                self._results[phase] = result
                return {**result.as_dict(), 'native_backend_qualified': False}
        except Exception: raise ValueError(_ERROR) from None

    def outcome(self, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        try:
            with self._lock:
                self._identity(requester_digest, transport_digest)
                verified = {phase: phase in self._results and self._results[phase].outcome == 'succeeded'
                    and self._results[phase].verification == 'verified' for phase in ('apply', 'restore')}
                state = ('verified_locally' if all(verified.values()) else 'reconciliation_required' if
                    any(phase not in self._results or not verified[phase] for phase in self._attempted) else
                    'applied_locally' if verified['apply'] else 'not_started')
                return dict(contract=CONTRACT, operation=self.operation, workflow_outcome=state, phase_verified_locally=verified,
                    execution_claims=self._store.claim_count, material_claims=self._material.claim_count,
                    native_backend_qualified=False, mfa_login_verified=False)
        except Exception: raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
