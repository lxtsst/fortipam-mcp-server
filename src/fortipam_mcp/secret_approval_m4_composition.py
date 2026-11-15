"""Direct trusted composition for one unregistered BP008 M4 runner."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import time

from v4_planning import (
    ApprovalReceiptAuthenticationAuthority,
    M4ExecutionStateStore,
)
from v4_planning.models import require_digest, require_ref

from .approval_and_observe_projection_source import (
    ApprovalAndObserveBinding,
    SecretApprovalReadTransport,
)
from .secret_approval_action_sequence import (
    ExactSecretApprovalM4RunnerFactory,
    ProtectedSecretApprovalRunnerBinding,
)
from .secret_approval_m4_authorization import (
    PlanningChainSecretApprovalM4AuthorizationVerifier,
    SecretApprovalPlanningChainReader,
    promote_secret_approval_m4_binding,
)
from .secret_approval_m4_runtime import (
    ProtectedSecretApprovalM4Runtime,
    SecretApprovalM4ExecutionBinding,
    SecretApprovalM4RuntimeError,
    SecretApprovalWriteTransport,
)


_UNAVAILABLE = "Protected Secret approval runtime composition is unavailable."


@dataclass(frozen=True, slots=True)
class _FixedSecretApprovalM4BindingResolver:
    authorization_ref: str
    binding: SecretApprovalM4ExecutionBinding

    def resolve_execution_binding(
        self,
        authorization_ref: str,
    ) -> SecretApprovalM4ExecutionBinding:
        if authorization_ref != self.authorization_ref:
            raise SecretApprovalM4RuntimeError(_UNAVAILABLE)
        return self.binding


def assemble_secret_approval_m4_runner_factory(
    *,
    planning: SecretApprovalPlanningChainReader,
    receipt_authenticator: ApprovalReceiptAuthenticationAuthority,
    approval_binding: ApprovalAndObserveBinding,
    source_plan_ref: str,
    approval_receipt_ref: str,
    approver_authority_ref: str,
    authorization_ref: str,
    read_transport: SecretApprovalReadTransport,
    write_transport: SecretApprovalWriteTransport,
    execution_store: M4ExecutionStateStore,
    authenticated_requester_digest: str,
    clock: Callable[[], int] | None = None,
) -> ExactSecretApprovalM4RunnerFactory:
    """Compose one exact runner without registering a Tool or enabling a Gate."""

    trusted_clock = clock or (lambda: int(time.time()))
    try:
        require_ref(source_plan_ref, "source_plan_ref")
        require_ref(approval_receipt_ref, "approval_receipt_ref")
        require_ref(approver_authority_ref, "approver_authority_ref")
        require_ref(authorization_ref, "authorization_ref")
        require_digest(
            authenticated_requester_digest,
            "authenticated_requester_digest",
        )
        now_epoch = trusted_clock()
        if type(now_epoch) is not int:
            raise ValueError("trusted clock is invalid")
        execution_binding = promote_secret_approval_m4_binding(
            planning,
            receipt_authenticator,
            approval_binding,
            source_plan_ref=source_plan_ref,
            approval_receipt_ref=approval_receipt_ref,
            approver_authority_ref=approver_authority_ref,
            authorization_ref=authorization_ref,
            now_epoch=now_epoch,
        )
        source_plan = planning.get_plan(source_plan_ref)
        if (
            source_plan.plan_ref != execution_binding.plan.plan_ref
            or source_plan.requester_digest != authenticated_requester_digest
            or source_plan.requester_digest
            != execution_binding.plan.requester_digest
            or len(source_plan.lines) != 1
        ):
            raise ValueError("source plan binding is invalid")
        verifier = PlanningChainSecretApprovalM4AuthorizationVerifier(
            planning,
            receipt_authenticator,
            approval_binding,
            source_plan_ref=source_plan_ref,
            approval_receipt_ref=approval_receipt_ref,
            approver_authority_ref=approver_authority_ref,
            authorization_ref=authorization_ref,
        )
        runtime = ProtectedSecretApprovalM4Runtime(
            _FixedSecretApprovalM4BindingResolver(
                authorization_ref,
                execution_binding,
            ),
            verifier,
            execution_store,
            write_transport,
            read_transport,
            authenticated_requester_digest=authenticated_requester_digest,
            clock=trusted_clock,
        )
        return ExactSecretApprovalM4RunnerFactory(
            ProtectedSecretApprovalRunnerBinding(
                source_plan.plan_digest,
                source_plan.lines[0].line_ref,
                source_plan.requester_digest,
                authorization_ref,
                runtime.inspect_approval_binding_digest(authorization_ref),
                runtime,
            )
        )
    except SecretApprovalM4RuntimeError:
        raise
    except Exception as exc:
        raise SecretApprovalM4RuntimeError(_UNAVAILABLE) from exc


__all__ = ["assemble_secret_approval_m4_runner_factory"]
