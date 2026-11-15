"""Default-closed private M4 composition for one bound RADIUS pair create."""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import time
from typing import Protocol

from v4_planning import (
    M4AdapterAmbiguous, M4AdapterDenied, M4AuthorizationDenied,
    M4AuthorizationVerifier, M4ExecutionAuthorization, M4ExecutionKernel,
    M4ExecutionPlan, M4ExecutionResult, canonical_digest,
)
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.execution_kernel import _reserve_m4_material_acquisition, _require_m4_material_acquisition_ownership
from v4_planning.material_provider import MaterialLeaseRequest, _OpaqueC3Object
from v4_planning.material_runtime import MaterialLeaseCoordinator, MaterialRuntimeOutcome, MaterialUseClaimState, material_lease_request_digest
from v4_planning.models import require_digest

from .radius_server_pair_contract import ACTION_ID, ACTION_VERSION, CONTRACT, RadiusServerPairBinding
from .radius_server_pair_http_transport import FortiPamRadiusPairHttpTransport
from .radius_server_pair_material_provider import RadiusServerPairLeaseTransport, RadiusServerPairMaterialProvider
from .radius_pair_fixture_material_loader import RadiusPairFixtureMaterialLoader
from .m4_execution_store import PersistentM4ExecutionStateStore

ADAPTER_REF = "fortipam-700-build29-radius-pair-http-candidate-v1"
TARGET_REF = "radius-server-pair-create"
_UNAVAILABLE = "Protected RADIUS server execution is unavailable."


class RadiusPairM4Guard(_OpaqueC3Object):
    """One runtime's original active acquisition; this object grants no approval."""

    __slots__ = ("_runtime",)
    _runtime: ProtectedRadiusPairM4Runtime | None
    _display_name = "RadiusPairM4Guard"

    def __init__(self) -> None:
        object.__setattr__(self, "_runtime", None)

    def __setattr__(self, name: str, value: object) -> None:
        raise M4AuthorizationDenied(_UNAVAILABLE)

    def __delattr__(self, name: str) -> None:
        raise M4AuthorizationDenied(_UNAVAILABLE)

    def _bind(self, runtime: ProtectedRadiusPairM4Runtime) -> None:
        if type(runtime) is not ProtectedRadiusPairM4Runtime or self._runtime is not None:
            raise M4AuthorizationDenied(_UNAVAILABLE)
        object.__setattr__(self, "_runtime", runtime)

    def __call__(self, binding: RadiusServerPairBinding, request: MaterialLeaseRequest) -> None:
        try:
            if self._runtime is None:
                raise ValueError
            self._runtime._guard_material_source(binding, request)
        except Exception:
            raise M4AuthorizationDenied(_UNAVAILABLE) from None

    def authorize_create(self, binding: RadiusServerPairBinding, request: MaterialLeaseRequest,
                         current_digest: str) -> bool:
        self(binding, request)
        assert self._runtime is not None
        self._runtime._guard_c3_claims(request)
        provider = self._runtime._provider
        if not provider._consumed or provider._lease is None or provider._buffers is None:
            raise M4AuthorizationDenied(_UNAVAILABLE)
        active = self._runtime._active_binding
        if active is None or current_digest != active.plan.expected_current_digest:
            raise M4AuthorizationDenied(_UNAVAILABLE)
        return True

    def authorize_acquisition(self, binding: RadiusServerPairBinding, request: MaterialLeaseRequest,
                              ordinal: str) -> None:
        self(binding, request)
        if ordinal not in {"primary", "secondary"} or self._runtime is None:
            raise M4AuthorizationDenied(_UNAVAILABLE)
        self._runtime._guard_c3_claims(request)


class RadiusPairM4ExecutionBinding(_OpaqueC3Object):
    """Owner-resolved execution records; never a planning or MCP value."""

    __slots__ = (
        "plan", "authorization", "material_binding", "lease_request",
        "policy_decision_digest", "scope_digest", "audience_digest",
    )
    _display_name = "RadiusPairM4ExecutionBinding"
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization
    material_binding: RadiusServerPairBinding
    lease_request: MaterialLeaseRequest
    policy_decision_digest: str
    scope_digest: str
    audience_digest: str

    def __init__(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
                 material_binding: RadiusServerPairBinding, lease_request: MaterialLeaseRequest,
                 policy_decision_digest: str, scope_digest: str, audience_digest: str) -> None:
        for name, value in (("plan", plan), ("authorization", authorization),
                ("material_binding", material_binding), ("lease_request", lease_request),
                ("policy_decision_digest", policy_decision_digest),
                ("scope_digest", scope_digest), ("audience_digest", audience_digest)):
            object.__setattr__(self, name, value)

    def __setattr__(self, name: str, value: object) -> None:
        raise M4AuthorizationDenied(_UNAVAILABLE)

    def __delattr__(self, name: str) -> None:
        raise M4AuthorizationDenied(_UNAVAILABLE)


class RadiusPairM4BindingResolver(Protocol):
    def resolve_execution_binding(self, authorization_ref: str) -> RadiusPairM4ExecutionBinding: ...


def expected_state_digest(binding: RadiusServerPairBinding) -> str:
    """Fixed salted outcome, returned only after exact owned-object readback."""
    try:
        if type(binding) is not RadiusServerPairBinding:
            raise ValueError
        return canonical_digest({"contract": CONTRACT, "parameters_digest": binding.parameters_digest,
                                 "state": "created-owned-verified"})
    except Exception:
        raise M4AuthorizationDenied(_UNAVAILABLE) from None


class _RadiusPairM4Adapter:
    def __init__(self, runtime: ProtectedRadiusPairM4Runtime, binding: RadiusPairM4ExecutionBinding) -> None:
        self._runtime, self._binding = runtime, binding

    def _check(self, plan: M4ExecutionPlan) -> None:
        if plan is not self._binding.plan:
            raise M4AdapterDenied(_UNAVAILABLE)
        self._runtime._check_gate()
        try:
            self._runtime._validate(self._binding, self._binding.authorization.authorization_ref)
        except Exception:
            raise M4AdapterDenied(_UNAVAILABLE) from None

    def read_current(self, plan: M4ExecutionPlan) -> str:
        self._check(plan)
        try:
            return self._runtime._transport.inspect_create().state_digest
        except Exception:
            raise M4AdapterAmbiguous(_UNAVAILABLE) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        self._check(plan)
        try:
            # Revalidate server authorization immediately before acquiring C3.
            self._runtime._verifier.verify(plan, self._binding.authorization,
                now_epoch=self._runtime._clock())
            self._check(plan)
            _reserve_m4_material_acquisition(plan, self._binding.authorization, self._runtime._execution_store)
            self._runtime._active_binding = self._binding
            outcome = MaterialLeaseCoordinator(
                self._runtime._provider, self._runtime._material_store,
            ).execute_once(
                self._binding.material_binding, self._binding.lease_request,
                RadiusServerPairLeaseTransport(self._runtime._provider, self._runtime._transport).consume,
                now_epoch=self._runtime._clock(),
            )
            if outcome is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED:
                raise ValueError
        except Exception:
            raise M4AdapterAmbiguous(_UNAVAILABLE) from None
        finally:
            self._runtime._active_binding = None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        self._check(plan)
        try:
            if self._runtime._transport.inspect_owned() is not True:
                raise ValueError
            return expected_state_digest(self._binding.material_binding)
        except Exception:
            raise M4AdapterAmbiguous(_UNAVAILABLE) from None


class ProtectedRadiusPairM4Runtime(_OpaqueC3Object):
    """Resolve one private authorization; M4 and C3 retain separate durable claims."""

    __slots__ = (
        "_resolver", "_verifier", "_execution_store", "_material_store",
        "_provider", "_transport", "_requester_digest", "_enabled", "_clock",
        "_source", "_guard", "_namespace", "_active_binding",
    )
    _display_name = "ProtectedRadiusPairM4Runtime"

    def __init__(
        self, resolver: RadiusPairM4BindingResolver, authorization_verifier: M4AuthorizationVerifier,
        execution_store: PersistentM4ExecutionStateStore, material_store: PersistentMaterialUseStateStore,
        provider: RadiusServerPairMaterialProvider, transport: FortiPamRadiusPairHttpTransport, *,
        authenticated_requester_digest: str, execution_enabled: bool = False,
        clock: Callable[[], int] | None = None,
    ) -> None:
        try:
            require_digest(authenticated_requester_digest, "requester_digest")
            if (type(execution_enabled) is not bool
                or type(execution_store) is not PersistentM4ExecutionStateStore
                or type(material_store) is not PersistentMaterialUseStateStore
                or type(provider) is not RadiusServerPairMaterialProvider
                or type(provider._loader) is not RadiusPairFixtureMaterialLoader
                or type(provider._guard) is not RadiusPairM4Guard
                or type(transport) is not FortiPamRadiusPairHttpTransport
                or not callable(getattr(resolver, "resolve_execution_binding", None))
                or not callable(getattr(authorization_verifier, "verify", None))
                or clock is not None and not callable(clock)):
                raise ValueError
        except Exception:
            raise M4AuthorizationDenied(_UNAVAILABLE) from None

        self._resolver, self._verifier = resolver, authorization_verifier
        self._execution_store, self._material_store = execution_store, material_store
        self._provider, self._transport = provider, transport
        self._requester_digest, self._enabled = authenticated_requester_digest, execution_enabled
        self._clock = clock if clock is not None else lambda: int(time.time())
        self._source = provider._loader
        self._guard = provider._guard
        self._active_binding: RadiusPairM4ExecutionBinding | None = None
        try:
            self._namespace = self._bindings()
            if type(self._guard) is not RadiusPairM4Guard:
                raise ValueError
            self._guard._bind(self)
        except Exception:
            raise M4AuthorizationDenied(_UNAVAILABLE) from None

    def _bindings(self) -> str:
        p, source, t, guard = self._provider, self._source, self._transport, self._guard
        if (type(source) is not RadiusPairFixtureMaterialLoader or type(guard) is not RadiusPairM4Guard
                or p._loader is not source
                or p._guard is not guard or source._guard is not guard
                or getattr(t._authorize_create, "__self__", None) is not guard
                or getattr(t._authorize_create, "__func__", None) is not RadiusPairM4Guard.authorize_create
                or getattr(source._acquisition_guard, "__self__", None) is not guard
                or getattr(source._acquisition_guard, "__func__", None) is not RadiusPairM4Guard.authorize_acquisition
                or not p._binding is source._binding is t._binding
                or p._source_digest != source._source_digest):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        stores = (self._execution_store, self._material_store, p._store)
        paths = [path for s in stores for path in (s._path, s._key_path)] + [source._key, source._known_hosts]
        if (len(set(paths)) != len(paths)
                or len({s._key for s in stores}) != len(stores)
                or any(t._directory == path or t._directory in path.parents for path in paths)):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        reserved = set(paths)
        for s in stores:
            if any(type(s._path)(str(s._path) + suffix) in reserved for suffix in ("-wal", "-shm", "-journal")):
                raise M4AuthorizationDenied(_UNAVAILABLE)
        return canonical_digest({"contract": CONTRACT, "parameters": p._binding.parameters_digest,
            "request_digest": p._request_digest, "source_policy": p._source_digest,
            "api_origin": t._config.base_url, "api_ca_file": t._config.ca_file,
            "api_identity": hashlib.sha256(t._config.bearer_token.encode()).hexdigest(), "serial": t._serial,
            "journal": str(t._directory), "paths": [str(path) for path in paths],
            "store_keys": [hashlib.sha256(s._key).hexdigest() for s in stores],
            "source_host": source._host, "requester": self._requester_digest})

    def _guard_material_source(self, material_binding: RadiusServerPairBinding, request: MaterialLeaseRequest) -> None:
        self._check_gate()
        binding = self._active_binding
        if binding is None or material_binding is not binding.material_binding or request != binding.lease_request:
            raise M4AuthorizationDenied(_UNAVAILABLE)
        _require_m4_material_acquisition_ownership(binding.plan, binding.authorization, self._execution_store)
        self._validate(binding, binding.authorization.authorization_ref)
        self._verifier.verify(binding.plan, binding.authorization, now_epoch=self._clock())
        self._check_gate()

    def _guard_c3_claims(self, request: MaterialLeaseRequest) -> None:
        # Metadata validation may precede C3 claims; value acquisition and POST
        # may not. Neither a persisted M4 claim nor a callback is sufficient.
        if not self._provider._owned or not self._provider._attempted:
            raise M4AuthorizationDenied(_UNAVAILABLE)
        usage = self._material_store._inspect_claim(request_digest=material_lease_request_digest(request),
            authorization_digest=request.authorization_digest)
        group = self._provider._store._inspect_claim(request_digest=self._provider._reservation,
            authorization_digest=request.authorization_digest)
        if usage.state is not MaterialUseClaimState.IN_PROGRESS or group.state is not MaterialUseClaimState.IN_PROGRESS:
            raise M4AuthorizationDenied(_UNAVAILABLE)

    def _check_gate(self) -> None:
        if (self._enabled is not True or self._transport._owned_connect_enabled is not False
                or self._transport._execution_enabled is not True
                or self._provider._enabled is not True or self._source._enabled is not True
                or self._guard._runtime is not self or self._bindings() != self._namespace):
            raise M4AdapterDenied(_UNAVAILABLE)

    def _validate(self, binding: RadiusPairM4ExecutionBinding, authorization_ref: str) -> None:
        try:
            if (type(binding) is not RadiusPairM4ExecutionBinding
                or type(binding.plan) is not M4ExecutionPlan
                or type(binding.authorization) is not M4ExecutionAuthorization
                or type(binding.lease_request) is not MaterialLeaseRequest
                or type(binding.material_binding) is not RadiusServerPairBinding):
                raise ValueError
            plan, auth, request = binding.plan, binding.authorization, binding.lease_request
            plan.__post_init__()
            auth.__post_init__()
            request.__post_init__()
            for digest in (binding.policy_decision_digest, binding.scope_digest, binding.audience_digest):
                require_digest(digest, "binding_digest")
            if (
                auth.authorization_ref != authorization_ref
                or plan.requester_digest != self._requester_digest
                or auth.requester_digest != plan.requester_digest
                or auth.plan_ref != plan.plan_ref or auth.plan_digest != plan.plan_digest
                or auth.confirmation_digest != plan.confirmation_digest
                or auth.approval_digest != plan.approval_digest
                or plan.action_id != ACTION_ID or plan.action_version != ACTION_VERSION
                or plan.adapter_ref != ADAPTER_REF or plan.target_ref != TARGET_REF
                or plan.compensation_ref is not None
                or binding.material_binding is not self._provider._binding
                or binding.material_binding is not self._transport._binding
                or not self._provider._matches(binding.material_binding, request)
                or request != self._transport._request
                or not callable(self._transport._authorize_create)
                or request.action_id != ACTION_ID or request.action_version != ACTION_VERSION
                or request.plan_digest != plan.plan_digest
                or request.authorization_digest != auth.authorization_digest
                or request.policy_decision_digest != binding.policy_decision_digest
                or request.scope_digest != binding.scope_digest
                or request.audience_digest != binding.audience_digest
                or request.requested_at < auth.issued_at
                or request.expires_at > auth.expires_at or request.expires_at > plan.expires_at
                or plan.expected_current_digest != self._transport._expected
                or plan.parameters_digest != binding.material_binding.parameters_digest
                or plan.expected_state_digest != expected_state_digest(binding.material_binding)
            ):
                raise ValueError
        except Exception:
            raise M4AuthorizationDenied(_UNAVAILABLE) from None

    def _resolve_binding(self, authorization_ref: str) -> RadiusPairM4ExecutionBinding:
        try:
            binding = self._resolver.resolve_execution_binding(authorization_ref)
            self._validate(binding, authorization_ref)
            verify_binding = getattr(self._verifier, "verify_binding", None)
            if verify_binding is not None:
                if not callable(verify_binding):
                    raise ValueError
                verify_binding(binding)
            return binding
        except Exception:
            raise M4AuthorizationDenied(_UNAVAILABLE) from None

    def inspect_execution_plan(self, authorization_ref: str) -> M4ExecutionPlan:
        return self._resolve_binding(authorization_ref).plan

    def inspect_binding_digest(self, authorization_ref: str) -> str:
        return self._resolve_binding(authorization_ref).material_binding.parameters_digest

    def execute_bound(self, authorization_ref: str) -> M4ExecutionResult:
        self._check_gate()
        binding = self._resolve_binding(authorization_ref)
        try:
            self._execution_store.verify_ready()
            self._material_store.verify_ready()
            self._provider._store.verify_ready()
        except Exception:
            raise M4AuthorizationDenied(_UNAVAILABLE) from None
        return M4ExecutionKernel(
            _RadiusPairM4Adapter(self, binding), self._verifier,
            self._execution_store, clock=self._clock,
        ).execute(binding.plan, binding.authorization)

    def close(self) -> None:
        self._enabled = False
        self._transport._execution_enabled = False
        self._source.close()
        self._provider.close()
