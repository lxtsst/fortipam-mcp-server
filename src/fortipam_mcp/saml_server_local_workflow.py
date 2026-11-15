"""Private SAML inert-fixture preview, protected authorization and owned result."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import secrets
from threading import RLock
import time
from typing import Literal, Protocol

from v4_planning import (DenyAllM4AuthorizationVerifier, M4AuthorizationDenied, M4ExecutionAuthorization,
    M4ExecutionKernel, M4ExecutionPlan, M4ExecutionResult, canonical_digest)
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .m4_execution_store import PersistentM4ExecutionStateStore
from .saml_server_contract import preview_saml_create
from .saml_server_native_source import SamlNativeObservation
from .saml_server_local_m4 import (SamlConfigurationBackend, SamlExecutionScope, SamlLocalM4Adapter,
    read_saml_execution_state, saml_execution_digests)

CONTRACT = 'fortipam_saml_inert_fixture_local_workflow_v1'
_ERROR = 'The private SAML workflow is unavailable.'
Phase = Literal['create','remove']


@dataclass(frozen=True, slots=True, repr=False)
class SamlAuthorizationRequest(_OpaqueC3Object):
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


class SamlWorkflowAuthority(Protocol):
    def authorize(self, request: SamlAuthorizationRequest) -> tuple[M4ExecutionPlan,M4ExecutionAuthorization]: ...
    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None: ...


class DenyAllSamlWorkflowAuthority(DenyAllM4AuthorizationVerifier):
    def authorize(self, request: SamlAuthorizationRequest) -> tuple[M4ExecutionPlan,M4ExecutionAuthorization]:
        raise M4AuthorizationDenied(_ERROR)


def saml_preview_content(initial: SamlNativeObservation, phase: Phase, preview_ref: str, created_at: int, *,
        policy_mode: str | None = None) -> dict[str,object]:
    plan = initial.plan
    public = preview_saml_create(plan,plan._source,plan._defaults,**plan._context)
    if phase == 'create':
        public['Current State'] = dict(configuration_field_count=22,candidate_absence_verified_locally=True,
            runtime_isolation_reported=True,independent_recovery_reported=True)
    else:
        public.update({'Current State':dict(owned_creation_verified_locally=True,record_field_count=32),
            'Proposed Changes':dict(remove_original_fixture=True),
            'Expected State':dict(restore_original_collection=True,restore_certificate_reference_count=True),
            'Security Changes':dict(remove_owned_inert_fixture=True)})
    public.update(contract=CONTRACT,phase=phase,preview_ref=preview_ref,expires_at=created_at+60,
        device_write_executed=False,native_backend_qualified=False)
    if policy_mode is not None: public['authorization_policy_mode'] = policy_mode
    return public


class SamlLocalWorkflow(_OpaqueC3Object):
    def __init__(self, initial: SamlNativeObservation, scope: SamlExecutionScope, backend: SamlConfigurationBackend,
            store: PersistentM4ExecutionStateStore, *, allowed_transport_digest: str,
            authority: SamlWorkflowAuthority | None = None, create_enabled: bool = False, remove_enabled: bool = False,
            source_guard: Callable[[],bool] | None = None, clock: Callable[[],int] = lambda:int(time.time())) -> None:
        try:
            if (type(initial) is not SamlNativeObservation or type(scope) is not SamlExecutionScope
                    or not isinstance(backend,SamlConfigurationBackend) or type(store) is not PersistentM4ExecutionStateStore
                    or type(create_enabled) is not bool or type(remove_enabled) is not bool or not callable(clock)
                    or source_guard is not None and not callable(source_guard)): raise ValueError
            require_digest(allowed_transport_digest,'SAML transport'); saml_execution_digests(initial,scope,store)
            store.verify_ready()
            if (create_enabled or remove_enabled) and not store.monotonic_checkpoint_protocol_bound: raise ValueError
            self._initial,self._scope,self._backend,self._store = initial,scope,backend,store
            self._transport,self._authority = allowed_transport_digest,authority or DenyAllSamlWorkflowAuthority()
            self._enabled = {'create':create_enabled,'remove':remove_enabled}
            self._guard,self._clock,self._last_now,self._closed = source_guard,clock,-1,False
            self._previews: dict[Phase,SamlAuthorizationRequest] = {}
            self._issued: dict[Phase,tuple[M4ExecutionPlan,M4ExecutionAuthorization]] = {}
            self._adapters: dict[Phase,SamlLocalM4Adapter] = {}
            self._results: dict[Phase,M4ExecutionResult] = {}
            self._attempted: set[Phase] = set()
            self._lock = RLock()
        except Exception: raise ValueError(_ERROR) from None

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
        if phase not in ('create','remove') or phase in self._attempted: raise ValueError
        if phase == 'create':
            if self._store.claim_count: raise ValueError
        else:
            if self._store.claim_count != 1: raise ValueError
            self._adapters['create']._require_verified()

    def preview(self, phase: Phase, *, requester_digest: str, transport_digest: str) -> dict[str,object]:
        try:
            with self._lock:
                self._identity(requester_digest,transport_digest); self._phase_ready(phase)
                current,expected,parameters = saml_execution_digests(self._initial,self._scope,self._store)
                if phase == 'remove': current,expected = expected,current
                created = self._adapters['create']._created_record if phase == 'remove' else None
                if read_saml_execution_state(self._initial,self._scope,self._backend,self._now,created_record=created)[0] != current: raise ValueError
                now = self._now(); ref = 'saml-preview-'+secrets.token_hex(24)
                public = saml_preview_content(self._initial,phase,ref,now,policy_mode=getattr(self._authority,'policy_mode',None))
                self._previews[phase] = SamlAuthorizationRequest(phase,ref,requester_digest,transport_digest,canonical_digest(public),
                    parameters,current,expected,'saml-fixture-'+self._initial.plan.binding.digest,now,now+60)
                self._issued.pop(phase,None); self._adapters.pop(phase,None)
                return public
        except Exception: raise ValueError(_ERROR) from None

    def authorize(self, phase: Phase, preview_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str,object]:
        try:
            with self._lock:
                self._identity(requester_digest,transport_digest); self._gate(phase); self._phase_ready(phase)
                request = self._previews[phase]
                if (type(preview_ref) is not str or preview_ref != request.preview_ref
                        or not request.created_at <= self._now() < request.expires_at): raise ValueError
                plan,authorization = self._authority.authorize(request)
                if (type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization
                        or plan.summary_digest != request.summary_digest or plan.parameters_digest != request.parameters_digest
                        or plan.expected_current_digest != request.expected_current_digest or plan.expected_state_digest != request.expected_state_digest
                        or plan.target_ref != request.target_ref or plan.expires_at != request.expires_at
                        or not request.created_at <= authorization.issued_at <= self._now() < authorization.expires_at <= request.expires_at): raise ValueError
                if phase == 'create':
                    adapter = SamlLocalM4Adapter(self._initial,self._scope,self._backend,plan,authorization,self._store,
                        authorization_verifier=self._authority,execution_enabled=self._enabled[phase],source_guard=self._source_ready,clock=self._now)
                else:
                    adapter = self._adapters['create'].bind_restore(plan,authorization,authorization_verifier=self._authority,
                        execution_enabled=self._enabled[phase])
                self._authority.verify(plan,authorization,now_epoch=self._now())
                self._issued[phase],self._adapters[phase] = (plan,authorization),adapter
                return dict(contract=CONTRACT,phase=phase,authorization_ref=authorization.authorization_ref,
                    expires_at=authorization.expires_at,native_backend_qualified=False)
        except Exception: raise ValueError(_ERROR) from None

    def execute(self, phase: Phase, authorization_ref: str, *, requester_digest: str, transport_digest: str) -> dict[str,object]:
        try:
            with self._lock:
                self._identity(requester_digest,transport_digest)
                plan,authorization = self._issued[phase]
                if type(authorization_ref) is not str or authorization_ref != authorization.authorization_ref: raise ValueError
                if phase in self._results:
                    return {**replace(self._results[phase],idempotent_replay=True).as_dict(),'native_backend_qualified':False}
                if phase in self._attempted: raise ValueError
                self._gate(phase); self._phase_ready(phase)
                self._authority.verify(plan,authorization,now_epoch=self._now())
                self._attempted.add(phase)
                try: result = M4ExecutionKernel(self._adapters[phase],self._authority,self._store,clock=self._now).execute(plan,authorization)
                except BaseException:
                    try: untouched = self._store.claim_count == int(phase == 'remove')
                    except Exception: untouched = False
                    if untouched: self._attempted.discard(phase)
                    raise
                self._results[phase] = result
                return {**result.as_dict(),'native_backend_qualified':False}
        except Exception: raise ValueError(_ERROR) from None

    def outcome(self, *, requester_digest: str, transport_digest: str) -> dict[str,object]:
        try:
            with self._lock:
                self._identity(requester_digest,transport_digest)
                verified = {phase:phase in self._results and self._results[phase].outcome == 'succeeded'
                    and self._results[phase].verification == 'verified' for phase in ('create','remove')}
                state = ('verified_locally' if all(verified.values()) else 'reconciliation_required' if
                    any(phase not in self._results or not verified[phase] for phase in self._attempted) else
                    'created_locally' if verified['create'] else 'not_started')
                return dict(contract=CONTRACT,workflow_outcome=state,phase_verified_locally=verified,
                    execution_claims=self._store.claim_count,native_backend_qualified=False,saml_login_verified=False)
        except Exception: raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._lock: self._closed = True
