"""Protected M4 runtime for one fixed Secret interactive-approval update."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import time
from typing import Protocol

from v4_planning import (
    AuthoritativeProjection,
    M4AdapterAmbiguous,
    M4AuthorizationDenied,
    M4AuthorizationVerifier,
    M4ExecutionAdapter,
    M4ExecutionAuthorization,
    M4ExecutionKernel,
    M4ExecutionPlan,
    M4ExecutionResult,
    M4ExecutionStateStore,
    ObjectClass,
    canonical_digest,
)

from .approval_and_observe_projection_source import (
    ApprovalAndObserveBinding,
    SecretApprovalReadTransport,
    approval_and_observe_projection_contract,
)
from .secret_metadata_http_transport import SecretApprovalProjectionInspection


SECRET_APPROVAL_ACTION_ID = "secret-approval-enable"
SECRET_APPROVAL_ACTION_VERSION = "1.0.0"
SECRET_APPROVAL_ADAPTER_REF = "fortipam-secret-approval-cli-191"
_UNAVAILABLE = "Protected Secret approval execution is unavailable."


class SecretApprovalM4RuntimeError(RuntimeError):
    """Stable non-disclosing error for an unavailable BP008 binding."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretApprovalM4ExecutionBinding:
    """Exact M4 records and private selectors retained in trusted memory."""

    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization
    approval_binding: ApprovalAndObserveBinding


class SecretApprovalM4BindingResolver(Protocol):
    def resolve_execution_binding(
        self,
        authorization_ref: str,
    ) -> SecretApprovalM4ExecutionBinding: ...


class SecretApprovalWriteTransport(Protocol):
    def enable_interactive_approval(
        self,
        secret_id: int,
        approval_profile_name: str,
    ) -> None: ...


class _SecretApprovalM4Adapter(M4ExecutionAdapter):
    def __init__(
        self,
        binding: SecretApprovalM4ExecutionBinding,
        write_transport: SecretApprovalWriteTransport,
        read_transport: SecretApprovalReadTransport,
    ) -> None:
        self._binding = binding
        self._write_transport = write_transport
        self._read_transport = read_transport

    def read_current(self, plan: M4ExecutionPlan) -> str:
        return self._read_digest(plan)

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        del plan
        binding = self._binding.approval_binding
        try:
            self._write_transport.enable_interactive_approval(
                binding.secret_id,
                binding.approval_profile_name,
            )
        except Exception as exc:
            raise M4AdapterAmbiguous(
                "Secret approval update requires reconciliation."
            ) from exc

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        return self._read_digest(plan)

    def _read_digest(self, plan: M4ExecutionPlan) -> str:
        binding = self._binding.approval_binding
        try:
            value = self._read_transport.inspect_approval_projection(
                binding.folder_path,
                binding.secret_name,
                binding.approval_profile_name,
                expected_secret_id=binding.secret_id,
            )
        except Exception as exc:
            raise M4AdapterAmbiguous(
                "Secret approval projection is unavailable."
            ) from exc
        if not isinstance(value, SecretApprovalProjectionInspection):
            raise M4AdapterAmbiguous(
                "Secret approval projection is unavailable."
            )
        projection = AuthoritativeProjection.from_mapping(
            contract=approval_and_observe_projection_contract(
                ObjectClass.SECRET_APPROVAL_BINDING
            ),
            object_ref=plan.target_ref,
            observed_at=0,
            fresh_until=1,
            fields={
                "exists": value.secret_exists,
                "approval_profile_attached": value.approval_profile_matches,
                "interactive_approval_required": (
                    value.interactive_approval_required
                ),
                "job_approval_required": value.job_approval_required,
                "owner_bypass_allowed": value.owner_bypass_allowed,
            },
        )
        return projection.state_digest


class ProtectedSecretApprovalM4Runtime:
    """Execute only one independently authorized, one-time BP008 binding."""

    def __init__(
        self,
        resolver: SecretApprovalM4BindingResolver,
        authorization_verifier: M4AuthorizationVerifier,
        execution_store: M4ExecutionStateStore,
        write_transport: SecretApprovalWriteTransport,
        read_transport: SecretApprovalReadTransport,
        *,
        authenticated_requester_digest: str,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if (
            not callable(getattr(write_transport, "enable_interactive_approval", None))
            or not callable(
                getattr(read_transport, "inspect_approval_projection", None)
            )
        ):
            raise SecretApprovalM4RuntimeError(_UNAVAILABLE)
        self._resolver = resolver
        self._authorization_verifier = authorization_verifier
        self._execution_store = execution_store
        self._write_transport = write_transport
        self._read_transport = read_transport
        self._requester_digest = authenticated_requester_digest
        self._clock = clock or (lambda: int(time.time()))

    def inspect_execution_plan(self, authorization_ref: str) -> M4ExecutionPlan:
        return self._resolve_binding(authorization_ref).plan

    def inspect_approval_binding_digest(self, authorization_ref: str) -> str:
        """Return only the digest needed for Scheme-to-private binding integrity."""

        return secret_approval_binding_digest(
            self._resolve_binding(authorization_ref).approval_binding
        )

    def execute_bound(
        self,
        authorization_ref: str,
        *,
        expected_approval_binding_digest: str,
    ) -> M4ExecutionResult:
        binding = self._resolve_binding(authorization_ref)
        if (
            secret_approval_binding_digest(binding.approval_binding)
            != expected_approval_binding_digest
        ):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        adapter = _SecretApprovalM4Adapter(
            binding,
            self._write_transport,
            self._read_transport,
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
    ) -> SecretApprovalM4ExecutionBinding:
        try:
            binding = self._resolver.resolve_execution_binding(authorization_ref)
            self._validate(binding, authorization_ref)
        except (M4AuthorizationDenied, SecretApprovalM4RuntimeError):
            raise
        except Exception as exc:
            raise SecretApprovalM4RuntimeError(_UNAVAILABLE) from exc
        return binding

    def _validate(
        self,
        binding: SecretApprovalM4ExecutionBinding,
        authorization_ref: str,
    ) -> None:
        if not isinstance(binding, SecretApprovalM4ExecutionBinding):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        plan = binding.plan
        authorization = binding.authorization
        approval = binding.approval_binding
        if (
            authorization.authorization_ref != authorization_ref
            or plan.requester_digest != self._requester_digest
            or plan.action_id != SECRET_APPROVAL_ACTION_ID
            or plan.action_version != SECRET_APPROVAL_ACTION_VERSION
            or plan.adapter_ref != SECRET_APPROVAL_ADAPTER_REF
            or plan.target_ref != approval.secret_approval_object_ref
            or plan.parameters_digest
            != secret_approval_parameters_digest(approval)
        ):
            raise M4AuthorizationDenied(_UNAVAILABLE)


def secret_approval_binding_digest(binding: ApprovalAndObserveBinding) -> str:
    """Bind private selectors without returning any selector to the caller."""

    if not isinstance(binding, ApprovalAndObserveBinding):
        raise SecretApprovalM4RuntimeError(_UNAVAILABLE)
    return canonical_digest(
        {
            "approval_profile_name": binding.approval_profile_name,
            "approval_profile_object_ref": binding.approval_profile_object_ref,
            "approval_profile_ref": binding.approval_profile_ref,
            "folder_path": binding.folder_path,
            "secret_approval_object_ref": binding.secret_approval_object_ref,
            "secret_id": binding.secret_id,
            "secret_name": binding.secret_name,
        }
    )


def secret_approval_parameters_digest(binding: ApprovalAndObserveBinding) -> str:
    """Bind the private selector set and the only permitted approval change."""

    return canonical_digest(
        {
            "action_id": SECRET_APPROVAL_ACTION_ID,
            "action_version": SECRET_APPROVAL_ACTION_VERSION,
            "approval_binding_digest": secret_approval_binding_digest(binding),
            "approval_profile_attached": True,
            "interactive_approval_required": True,
            "job_approval_required": False,
            "owner_bypass_allowed": False,
        }
    )
__all__ = [
    "ProtectedSecretApprovalM4Runtime",
    "SECRET_APPROVAL_ACTION_ID",
    "SECRET_APPROVAL_ACTION_VERSION",
    "SECRET_APPROVAL_ADAPTER_REF",
    "SecretApprovalM4BindingResolver",
    "SecretApprovalM4ExecutionBinding",
    "SecretApprovalM4RuntimeError",
    "SecretApprovalWriteTransport",
    "secret_approval_binding_digest",
    "secret_approval_parameters_digest",
]
