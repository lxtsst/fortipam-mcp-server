"""Internal M4 binding for one C3-backed Secret create action.

The resolver keeps the opaque material binding and all authorization records
inside the trusted runtime.  The public call accepts only one authorization
reference.  M4 performs the final current-state check and independent readback;
the existing material runtime supplies single-use C3 acquisition and revocation.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import time
import re
from typing import Protocol

from v4_planning import (
    M4AdapterAmbiguous,
    M4AuthorizationDenied,
    M4AuthorizationVerifier,
    M4ExecutionAdapter,
    M4ExecutionAuthorization,
    M4ExecutionKernel,
    M4ExecutionPlan,
    M4ExecutionResult,
    M4ExecutionStateStore,
)
from v4_planning.material_provider import C3MaterialBinding, MaterialLeaseRequest
from v4_planning.material_runtime import MaterialRuntimeOutcome
from v4_planning.secret_create_adapter import (
    SECRET_CREATE_ACTION_ID,
    SECRET_CREATE_ACTION_VERSION,
    require_secret_create_lease_request,
)
from v4_planning.secret_create_runtime import SecretCreateMaterialRuntime


_DIGEST = re.compile(r"^[a-f0-9]{64}$")


class SecretCreateM4RuntimeError(RuntimeError):
    """Stable error for an unavailable protected Secret-create binding."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretCreateM4ExecutionBinding:
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization
    material_binding: C3MaterialBinding
    lease_request: MaterialLeaseRequest
    policy_decision_digest: str
    scope_digest: str
    audience_digest: str


class SecretCreateM4BindingResolver(Protocol):
    def resolve_execution_binding(
        self,
        authorization_ref: str,
    ) -> SecretCreateM4ExecutionBinding: ...


class SecretCreateProjectionReader(Protocol):
    """Fixed no-material current and postcondition projection reads."""

    def inspect_onboarding_binding_digest(self) -> str: ...

    def read_current(self, plan: M4ExecutionPlan) -> str: ...

    def read_postcondition(self, plan: M4ExecutionPlan) -> str: ...


class _SecretCreateM4Adapter(M4ExecutionAdapter):
    def __init__(
        self,
        binding: SecretCreateM4ExecutionBinding,
        material_runtime: SecretCreateMaterialRuntime,
        reader: SecretCreateProjectionReader,
        clock: Callable[[], int],
    ) -> None:
        self._binding = binding
        self._material_runtime = material_runtime
        self._reader = reader
        self._clock = clock

    def read_current(self, plan: M4ExecutionPlan) -> str:
        return self._reader.read_current(plan)

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        del plan
        try:
            outcome = self._material_runtime.execute_once(
                self._binding.material_binding,
                self._binding.lease_request,
                now_epoch=self._clock(),
            )
        except Exception as exc:
            raise M4AdapterAmbiguous(
                "Secret-create material execution requires reconciliation."
            ) from exc
        if outcome is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED:
            raise M4AdapterAmbiguous(
                "Secret-create material execution requires reconciliation."
            )

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        return self._reader.read_postcondition(plan)


class ProtectedSecretCreateM4Runtime:
    """Execute only one exact protected Secret-create authorization reference."""

    def __init__(
        self,
        resolver: SecretCreateM4BindingResolver,
        authorization_verifier: M4AuthorizationVerifier,
        execution_store: M4ExecutionStateStore,
        material_runtime: SecretCreateMaterialRuntime,
        projection_reader: SecretCreateProjectionReader,
        *,
        authenticated_requester_digest: str,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._resolver = resolver
        self._authorization_verifier = authorization_verifier
        self._execution_store = execution_store
        self._material_runtime = material_runtime
        self._projection_reader = projection_reader
        self._requester_digest = authenticated_requester_digest
        self._clock = clock or (lambda: int(time.time()))

    def inspect_execution_plan(self, authorization_ref: str) -> M4ExecutionPlan:
        """Resolve and validate the value-free plan for an internal binder."""

        return self._resolve_binding(authorization_ref).plan

    def inspect_onboarding_binding_digest(self, authorization_ref: str) -> str:
        """Return only the private selector digest for Scheme integrity checks."""

        self._resolve_binding(authorization_ref)
        return self._projection_binding_digest()

    def _projection_binding_digest(self) -> str:
        try:
            digest = self._projection_reader.inspect_onboarding_binding_digest()
        except Exception as exc:
            raise SecretCreateM4RuntimeError(
                "Protected Secret-create execution binding is unavailable."
            ) from exc
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise SecretCreateM4RuntimeError(
                "Protected Secret-create execution binding is unavailable."
            )
        return digest

    def execute_bound(
        self,
        authorization_ref: str,
        *,
        expected_onboarding_binding_digest: str | None = None,
    ) -> M4ExecutionResult:
        binding = self._resolve_binding(authorization_ref)
        if expected_onboarding_binding_digest is not None:
            if (
                _DIGEST.fullmatch(expected_onboarding_binding_digest) is None
                or self._projection_binding_digest()
                != expected_onboarding_binding_digest
            ):
                raise M4AuthorizationDenied(
                    "Secret-create binding is not authorized for the exact Scheme."
                )
        adapter = _SecretCreateM4Adapter(
            binding,
            self._material_runtime,
            self._projection_reader,
            self._clock,
        )
        return M4ExecutionKernel(
            adapter,
            self._authorization_verifier,
            self._execution_store,
            clock=self._clock,
        ).execute(binding.plan, binding.authorization)

    def _resolve_binding(
        self,
        authorization_ref: str,
    ) -> SecretCreateM4ExecutionBinding:
        try:
            binding = self._resolver.resolve_execution_binding(authorization_ref)
            self._validate(binding, authorization_ref)
            verify_binding = getattr(
                self._authorization_verifier,
                "verify_binding",
                None,
            )
            if verify_binding is not None:
                if not callable(verify_binding):
                    raise SecretCreateM4RuntimeError(
                        "Protected Secret-create execution binding is unavailable."
                    )
                verify_binding(binding)
        except (M4AuthorizationDenied, SecretCreateM4RuntimeError):
            raise
        except Exception as exc:
            raise SecretCreateM4RuntimeError(
                "Protected Secret-create execution binding is unavailable."
            ) from exc
        return binding

    def _validate(
        self,
        binding: SecretCreateM4ExecutionBinding,
        authorization_ref: str,
    ) -> None:
        plan = binding.plan
        authorization = binding.authorization
        request = require_secret_create_lease_request(binding.lease_request)
        if (
            authorization.authorization_ref != authorization_ref
            or plan.requester_digest != self._requester_digest
            or plan.action_id != SECRET_CREATE_ACTION_ID
            or plan.action_version != SECRET_CREATE_ACTION_VERSION
            or request.plan_digest != plan.plan_digest
            or request.authorization_digest != authorization.authorization_digest
            or request.policy_decision_digest != binding.policy_decision_digest
            or request.scope_digest != binding.scope_digest
            or request.audience_digest != binding.audience_digest
            or request.requested_at < authorization.issued_at
            or request.expires_at > authorization.expires_at
            or request.expires_at > plan.expires_at
            or any(
                _DIGEST.fullmatch(value) is None
                for value in (
                    binding.policy_decision_digest,
                    binding.scope_digest,
                    binding.audience_digest,
                )
            )
        ):
            raise M4AuthorizationDenied(
                "Secret-create binding is not authorized for the exact plan."
            )


__all__ = [
    "ProtectedSecretCreateM4Runtime",
    "SecretCreateM4BindingResolver",
    "SecretCreateM4ExecutionBinding",
    "SecretCreateM4RuntimeError",
    "SecretCreateProjectionReader",
]
