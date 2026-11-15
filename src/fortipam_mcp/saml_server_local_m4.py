"""Default-closed local SAML fixture creation and original-receipt removal.

This module binds the frozen inert-fixture codec to the existing M4 kernel.
It supplies no native mutation transport, role permission, login qualification,
shared-runtime isolation producer, startup binding or recovery adoption path.
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
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .m4_execution_store import PersistentM4ExecutionStateStore
from .saml_server_contract import build_saml_create_body, verify_created_saml_record
from .saml_server_native_source import SamlNativeObservation, _encoded
from .secret_metadata_http_transport import _zeroize_mutable

CONTRACT = 'fortipam_saml_inert_fixture_local_m4_v1'
_ERROR = 'The private SAML execution candidate is unavailable.'


@dataclass(frozen=True, slots=True, repr=False)
class SamlExecutionScope(_OpaqueC3Object):
    binding_digest: str
    requester_digest: str
    scope_digest: str
    audience_digest: str
    configuration_source_digest: str
    dependency_source_digest: str

    def __post_init__(self) -> None:
        for value in asdict(self).values(): require_digest(value,'SAML execution scope')
        if self.configuration_source_digest == self.dependency_source_digest: raise ValueError


@dataclass(frozen=True, slots=True, repr=False)
class SamlBackendReceipt(_OpaqueC3Object):
    source_digest: str
    parameters_digest: str
    restore: bool

    def __post_init__(self) -> None:
        for value in (self.source_digest,self.parameters_digest): require_digest(value,'SAML receipt')
        if type(self.restore) is not bool: raise ValueError


@runtime_checkable
class SamlConfigurationBackend(Protocol):
    def inspect(self) -> SamlNativeObservation: ...
    def submit(self, body: memoryview | None, *, parameters_digest: str, restore: bool,
            before_send: Callable[[],int], timeout_seconds: int) -> SamlBackendReceipt: ...


def saml_execution_digests(initial: SamlNativeObservation, scope: SamlExecutionScope,
        store: PersistentM4ExecutionStateStore) -> tuple[str,str,str]:
    if (type(initial) is not SamlNativeObservation or initial._candidate is not None
            or type(scope) is not SamlExecutionScope or type(store) is not PersistentM4ExecutionStateStore
            or initial.source_digest != scope.configuration_source_digest
            or initial.dependencies.source_digest != scope.dependency_source_digest
            or not initial.dependencies.complete or not initial.dependencies.runtime_isolation_verified
            or not initial.dependencies.independent_recovery_ready or initial.plan._source['cert'] != ''
            or not hmac.compare_digest(store._key,store._load_key())): raise M4AdapterDenied(_ERROR)
    parameters = canonical_digest(dict(contract=CONTRACT,baseline=initial.digest,scope=asdict(scope),
        domain=dict(database=hashlib.sha256(str(store._path.resolve()).encode()).hexdigest(),
            key_file=hashlib.sha256(str(store._key_path.resolve()).encode()).hexdigest(),
            key=hashlib.sha256(store._key).hexdigest(),checkpoint=store._checkpoint_store_ref,
            authority=getattr(store._monotonic_checkpoint,'authority_ref',None))))
    def state(present: bool) -> str:
        return canonical_digest(dict(contract=CONTRACT,baseline=initial.digest,present=present))
    return state(False),state(True),parameters


def read_saml_execution_state(initial: SamlNativeObservation, scope: SamlExecutionScope,
        backend: SamlConfigurationBackend, clock: Callable[[],int], *,
        created_record: bytes | None = None) -> tuple[str,bytes | None]:
    """One source join for preview, protected issuance and the final M4 guard."""
    observed = backend.inspect(); now = clock()
    if (type(observed) is not SamlNativeObservation or observed.plan.digest != initial.plan.digest
            or observed.source_digest != scope.configuration_source_digest
            or observed.dependencies.source_digest != scope.dependency_source_digest
            or not observed.dependencies.complete or not observed.dependencies.runtime_isolation_verified
            or not observed.dependencies.independent_recovery_ready
            or observed.dependencies.certificate_reference_count != initial.dependencies.certificate_reference_count
                + (1 if observed._candidate is not None else 0)
            or not observed.dependencies.observed_at <= now < observed.dependencies.expires_at): raise ValueError
    rows = json.loads(observed._collection)
    without = [row for row in rows if row['name'] != initial.plan.binding.name]
    if _encoded(without) != initial._collection: raise ValueError
    if observed._candidate is not None:
        candidate = json.loads(observed._candidate)
        verify_created_saml_record(candidate,initial.plan,initial.plan._source,initial.plan._defaults,**initial.plan._context)
        if created_record is not None and observed._candidate != created_record: raise ValueError
    if clock() >= observed.dependencies.expires_at: raise ValueError
    return canonical_digest(dict(contract=CONTRACT,baseline=initial.digest,present=observed._candidate is not None)),observed._candidate


class SamlLocalM4Adapter(_OpaqueC3Object):
    def __init__(self, initial: SamlNativeObservation, scope: SamlExecutionScope, backend: SamlConfigurationBackend,
            plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, store: PersistentM4ExecutionStateStore, *,
            authorization_verifier: M4AuthorizationVerifier | None = None, execution_enabled: bool = False,
            source_guard: Callable[[],bool] | None = None, clock: Callable[[],int] = lambda:int(time.time())) -> None:
        try:
            if (type(initial) is not SamlNativeObservation or type(scope) is not SamlExecutionScope
                    or not isinstance(backend,SamlConfigurationBackend) or type(store) is not PersistentM4ExecutionStateStore
                    or type(execution_enabled) is not bool or not callable(clock)
                    or source_guard is not None and not callable(source_guard)): raise ValueError
            store.verify_ready()
            if execution_enabled and not store.monotonic_checkpoint_protocol_bound: raise ValueError
            self._initial,self._scope,self._backend,self._store = initial,scope,backend,store
            self._plan,self._authorization = plan,authorization
            self._verifier = authorization_verifier or DenyAllM4AuthorizationVerifier()
            self._enabled,self._guard,self._clock = execution_enabled,source_guard,clock
            self._last_now = -1
            self._original: SamlLocalM4Adapter | None = None
            self._receipt: SamlBackendReceipt | None = None
            self._created_record: bytes | None = None
            self._dispatched = self._send_admitted = self._send_verified = self._post_verified = False
            self._lock = RLock()
            self._check_plan()
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def _check_plan(self) -> None:
        current,expected,parameters = saml_execution_digests(self._initial,self._scope,self._store)
        restore = self._original is not None
        if restore: current,expected = expected,current
        action = 'saml-inert-fixture-'+('remove' if restore else 'create')
        p,a = self._plan,self._authorization
        p.__post_init__(); a.__post_init__()
        if (p.action_id != action or p.action_version != '1.0.0' or p.adapter_ref != CONTRACT
                or p.plan_ref != action+'-'+parameters or p.parameters_digest != parameters
                or p.target_ref != 'saml-fixture-'+self._initial.plan.binding.digest
                or p.requester_digest != self._scope.requester_digest or p.compensation_ref is not None
                or p.expected_current_digest != current or p.expected_state_digest != expected
                or p.idempotency_digest != canonical_digest(dict(parameters=parameters,action=action))
                or a.plan_ref != p.plan_ref or a.plan_digest != p.plan_digest or a.requester_digest != p.requester_digest
                or min(p.expires_at,a.expires_at)-a.issued_at > 60): raise ValueError

    def _now(self) -> int:
        now = self._clock()
        if type(now) is not int or now < 0 or now < self._last_now:
            self._enabled = False
            raise M4AdapterDenied(_ERROR)
        self._last_now = now
        return now

    def _check(self, plan: M4ExecutionPlan) -> None:
        try:
            if not self._enabled or plan is not self._plan or self._guard is None or self._guard() is not True: raise ValueError
            self._check_plan(); now = self._now()
            if not self._authorization.issued_at <= now < min(plan.expires_at,self._authorization.expires_at): raise ValueError
            self._verifier.verify(plan,self._authorization,now_epoch=now)
            self._store.verify_ready()
            if (self._guard() is not True or self._now() >= min(plan.expires_at,self._authorization.expires_at)): raise ValueError
        except Exception: raise M4AdapterDenied(_ERROR) from None

    def _snapshot(self) -> str:
        owner = self._original if self._original is not None else self
        state,candidate = read_saml_execution_state(self._initial,self._scope,self._backend,self._now,
            created_record=owner._created_record)
        if self._receipt is not None and self._original is None and candidate is not None: self._created_record = candidate
        return state

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

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        _require_m4_dispatch_ownership(plan,self._authorization,self._store)
        body = bytearray()
        with self._lock:
            self._check(plan)
            if self._dispatched: raise M4AdapterDenied(_ERROR)
            self._dispatched = True
            try:
                restore = self._original is not None
                if self._store.claim_count != (2 if restore else 1): raise ValueError
                if restore:
                    receipt = self._backend.submit(None,parameters_digest=plan.parameters_digest,restore=True,
                        before_send=self._before_send,timeout_seconds=min(plan.expires_at,self._authorization.expires_at)-self._last_now)
                else:
                    original = self._initial.plan
                    body = build_saml_create_body(original,original._source,original._defaults,**original._context)
                    with memoryview(body).toreadonly() as view:
                        receipt = self._backend.submit(view,parameters_digest=plan.parameters_digest,restore=False,
                            before_send=self._before_send,timeout_seconds=min(plan.expires_at,self._authorization.expires_at)-self._last_now)
                if (not self._send_verified or type(receipt) is not SamlBackendReceipt
                        or receipt.source_digest != self._scope.configuration_source_digest
                        or receipt.parameters_digest != plan.parameters_digest or receipt.restore is not restore): raise ValueError
                self._receipt = receipt
                if self._snapshot() != plan.expected_state_digest: raise ValueError
                self._post_verified = True
            except Exception: raise M4AdapterAmbiguous(_ERROR) from None
            finally: _zeroize_mutable(body)

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        with self._lock:
            self._check(plan)
            if self._receipt is None or not self._post_verified: raise M4AdapterAmbiguous(_ERROR)
            try:
                state = self._snapshot(); self._check(plan)
                return state
            except Exception: raise M4AdapterAmbiguous(_ERROR) from None

    def _require_verified(self) -> None:
        if (self._original is not None or self._receipt is None or self._created_record is None
                or not self._post_verified): raise M4AdapterDenied(_ERROR)
        p,a = self._plan,self._authorization
        claim = self._store.inspect_claim(plan_ref=p.plan_ref,requester_digest=p.requester_digest,
            idempotency_digest=p.idempotency_digest,authorization_digest=a.authorization_digest,
            context_digest=canonical_digest(dict(plan_digest=p.plan_digest,authorization_digest=a.authorization_digest,revision=p.revision)))
        if (claim.result is None or claim.result.outcome != 'succeeded' or claim.result.verification != 'verified'
                or claim.result.compensation != 'not_requested'): raise M4AdapterDenied(_ERROR)

    def bind_restore(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *,
            authorization_verifier: M4AuthorizationVerifier | None = None, execution_enabled: bool = False) -> SamlLocalM4Adapter:
        try:
            with self._lock:
                self._require_verified()
                if type(execution_enabled) is not bool: raise ValueError
                restore = object.__new__(SamlLocalM4Adapter); restore.__dict__.update(self.__dict__)
                restore._original = self
                restore._plan,restore._authorization = plan,authorization
                restore._verifier = authorization_verifier or DenyAllM4AuthorizationVerifier()
                restore._enabled = execution_enabled
                restore._receipt = None
                restore._dispatched = restore._send_admitted = restore._send_verified = restore._post_verified = False
                restore._check_plan()
                return restore
        except Exception: raise M4AdapterDenied(_ERROR) from None
