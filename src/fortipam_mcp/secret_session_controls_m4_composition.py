"""Trusted composition of one confirmed BP006 existing-Secret control update."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import time

from v4_planning import ApprovalReceiptAuthenticationAuthority, M4ExecutionStateStore
from v4_planning.models import PreparedPlan, SchemeDraft

from .onboarding_action_coordinator import BoundFixedActionRunner
from .secret_onboarding_projection_source import (
    SecretOnboardingBinding,
    SecretOnboardingProductBinding,
)
from .secret_approval_m4_authorization import SecretApprovalPlanningChainReader
from .secret_session_controls_m4_authorization import (
    PlanningChainSecretSessionControlsM4AuthorizationVerifier,
    promote_secret_session_controls_m4_binding,
)
from .secret_session_controls_m4_runtime import (
    ProtectedSecretSessionControlsM4Runtime,
    RdpEventFilterReadTransport,
    SecretSessionControlsBinding,
    SecretSessionControlsM4ExecutionBinding,
    SecretSessionControlsM4RuntimeError,
    SecretSessionControlsReadTransport,
    SecretSessionControlsWriteTransport,
    secret_session_controls_binding_digest,
)
from .secret_session_controls_ssh_transport import (
    FortiPamSecretSessionControlsSshTransport,
)
from .v4_plan_runtime import V4PlanningPrincipal

_UNAVAILABLE = "Protected Secret session-controls composition is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class _FixedBindingResolver:
    authorization_ref: str
    binding: SecretSessionControlsM4ExecutionBinding

    def resolve_execution_binding(self, authorization_ref: str) -> SecretSessionControlsM4ExecutionBinding:
        if authorization_ref != self.authorization_ref:
            raise SecretSessionControlsM4RuntimeError(_UNAVAILABLE)
        return self.binding


@dataclass(frozen=True, slots=True, repr=False)
class _Runner:
    line_ref: str
    depends_on: tuple[str, ...]
    authorization_ref: str
    binding_digest: str
    runtime: ProtectedSecretSessionControlsM4Runtime

    def execute_bound(self) -> Mapping[str, object]:
        return self.runtime.execute_bound(
            self.authorization_ref,
            expected_session_controls_binding_digest=self.binding_digest,
        ).as_dict()


@dataclass(frozen=True, slots=True, repr=False)
class ExactSecretSessionControlsM4RunnerFactory:
    """Keep the verified Scheme and its private M4 association in one process."""

    source_plan: PreparedPlan
    onboarding_binding: SecretOnboardingBinding
    execution_binding: SecretSessionControlsM4ExecutionBinding
    runtime: ProtectedSecretSessionControlsM4Runtime

    def bind(
        self,
        plan: PreparedPlan,
        line_ref: str,
        principal: V4PlanningPrincipal,
        *,
        draft: SchemeDraft | None = None,
        onboarding_binding: SecretOnboardingProductBinding | None = None,
    ) -> BoundFixedActionRunner:
        expected = self.execution_binding
        authorization_ref = expected.authorization.authorization_ref
        digest = secret_session_controls_binding_digest(expected.session_controls_binding)
        if (
            plan != self.source_plan
            or len(plan.lines) != 1
            or plan.lines[0].line_ref != line_ref
            or plan.requester_digest != principal.requester.digest
            or onboarding_binding != self.onboarding_binding
            or draft is None
            or draft.scheme_id != plan.scheme_id
            or draft.environment_ref != plan.environment_ref
            or draft.scope_ref != plan.scope_ref
            or self.runtime.inspect_execution_plan(authorization_ref) != expected.plan
            or self.runtime.inspect_session_controls_binding_digest(authorization_ref) != digest
        ):
            raise SecretSessionControlsM4RuntimeError(_UNAVAILABLE)
        return _Runner(line_ref, (), authorization_ref, digest, self.runtime)


def assemble_secret_session_controls_m4_runner_factory(
    *,
    planning: SecretApprovalPlanningChainReader,
    receipt_authenticator: ApprovalReceiptAuthenticationAuthority,
    onboarding_binding: SecretOnboardingBinding,
    session_controls_binding: SecretSessionControlsBinding,
    source_plan_ref: str,
    approval_receipt_ref: str,
    approver_authority_ref: str,
    authorization_ref: str,
    read_transport: SecretSessionControlsReadTransport,
    write_transport: SecretSessionControlsWriteTransport,
    rdp_event_filter_transport: RdpEventFilterReadTransport,
    execution_store: M4ExecutionStateStore,
    authenticated_requester_digest: str,
    clock: Callable[[], int] | None = None,
) -> ExactSecretSessionControlsM4RunnerFactory:
    """Promote the claimed chain only for the fixed SSH fallback transport.

    The SSH adapter identity is bound into the M4 plan.  A structurally
    compatible REST transport cannot substitute for it.
    """

    trusted_clock = clock or (lambda: int(time.time()))
    try:
        if not isinstance(write_transport, FortiPamSecretSessionControlsSshTransport):
            raise SecretSessionControlsM4RuntimeError(_UNAVAILABLE)
        execution_binding = promote_secret_session_controls_m4_binding(
            planning,
            receipt_authenticator,
            session_controls_binding,
            onboarding_binding=onboarding_binding,
            source_plan_ref=source_plan_ref,
            approval_receipt_ref=approval_receipt_ref,
            approver_authority_ref=approver_authority_ref,
            authorization_ref=authorization_ref,
            now_epoch=trusted_clock(),
        )
        source_plan = planning.get_plan(source_plan_ref)
        if source_plan.requester_digest != authenticated_requester_digest:
            raise SecretSessionControlsM4RuntimeError(_UNAVAILABLE)
        verifier = PlanningChainSecretSessionControlsM4AuthorizationVerifier(
            planning,
            receipt_authenticator,
            session_controls_binding,
            onboarding_binding=onboarding_binding,
            source_plan_ref=source_plan_ref,
            approval_receipt_ref=approval_receipt_ref,
            approver_authority_ref=approver_authority_ref,
            authorization_ref=authorization_ref,
        )
        runtime = ProtectedSecretSessionControlsM4Runtime(
            _FixedBindingResolver(authorization_ref, execution_binding),
            verifier,
            execution_store,
            write_transport,
            read_transport,
            rdp_event_filter_transport,
            authenticated_requester_digest=authenticated_requester_digest,
            clock=trusted_clock,
        )
        return ExactSecretSessionControlsM4RunnerFactory(
            source_plan, onboarding_binding, execution_binding, runtime,
        )
    except SecretSessionControlsM4RuntimeError:
        raise
    except Exception as exc:
        raise SecretSessionControlsM4RuntimeError(_UNAVAILABLE) from exc
