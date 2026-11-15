"""Same-process composition for the exact confirmed BP007 service update."""

from dataclasses import dataclass
from collections.abc import Callable, Mapping

from v4_planning import M4AuthorizationDenied, M4ExecutionStateStore, ApprovalReceiptAuthenticationAuthority
from v4_planning.models import PreparedPlan, SchemeDraft
from .onboarding_action_coordinator import BoundFixedActionRunner
from .secret_approval_m4_authorization import SecretApprovalPlanningChainReader
from .secret_onboarding_projection_source import WebSecretOnboardingBinding, SecretOnboardingProductBinding
from .v4_plan_runtime import V4PlanningPrincipal
from .web_secret_service_m4_adapter import WebSecretServiceBinding, WebServiceReader, parameters_digest
from .web_secret_service_m4_runtime import ProtectedWebSecretServiceM4Runtime, WebSecretServiceExecutionBinding
from .web_secret_service_ssh_transport import FortiPamWebSecretServiceSshTransport
from .web_secret_service_m4_authorization import (
    promote_web_secret_service_m4_binding, PlanningChainWebSecretServiceM4AuthorizationVerifier,
)

_UNAVAILABLE = "Web Secret service composition is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class _Resolver:
    binding: WebSecretServiceExecutionBinding

    def resolve_execution_binding(self, authorization_ref: str) -> WebSecretServiceExecutionBinding:
        if authorization_ref != self.binding.authorization.authorization_ref:
            raise M4AuthorizationDenied(_UNAVAILABLE)
        return self.binding


@dataclass(frozen=True, slots=True, repr=False)
class _Runner:
    line_ref: str
    depends_on: tuple[str, ...]
    authorization_ref: str
    binding_digest: str
    runtime: ProtectedWebSecretServiceM4Runtime

    def execute_bound(self) -> Mapping[str, object]:
        return self.runtime.execute_bound(
            self.authorization_ref, expected_binding_digest=self.binding_digest,
        ).as_dict()


@dataclass(frozen=True, slots=True, repr=False)
class ExactWebSecretServiceM4RunnerFactory:
    source_plan: PreparedPlan
    onboarding_binding: WebSecretOnboardingBinding
    execution_binding: WebSecretServiceExecutionBinding
    runtime: ProtectedWebSecretServiceM4Runtime

    def bind(
        self, plan: PreparedPlan, line_ref: str, principal: V4PlanningPrincipal,
        *, draft: SchemeDraft | None = None,
        onboarding_binding: SecretOnboardingProductBinding | None = None,
    ) -> BoundFixedActionRunner:
        if (
            plan != self.source_plan or len(plan.lines) != 1
            or plan.lines[0].line_ref != line_ref
            or plan.requester_digest != principal.requester.digest
            or onboarding_binding != self.onboarding_binding
            or draft is None or draft.scheme_id != plan.scheme_id
            or draft.environment_ref != plan.environment_ref or draft.scope_ref != plan.scope_ref
        ):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        return _Runner(
            line_ref, (), self.execution_binding.authorization.authorization_ref,
            parameters_digest(self.execution_binding.service), self.runtime,
        )


def assemble_web_secret_service_m4_runner_factory(
    *, planning: SecretApprovalPlanningChainReader,
    receipt_authenticator: ApprovalReceiptAuthenticationAuthority,
    onboarding_binding: WebSecretOnboardingBinding, service_binding: WebSecretServiceBinding,
    source_plan_ref: str, approval_receipt_ref: str, approver_authority_ref: str,
    authorization_ref: str, read_transport: WebServiceReader,
    write_transport: FortiPamWebSecretServiceSshTransport,
    execution_store: M4ExecutionStateStore, authenticated_requester_digest: str,
    clock: Callable[[], int],
) -> ExactWebSecretServiceM4RunnerFactory:
    binding = promote_web_secret_service_m4_binding(
        planning, receipt_authenticator, service_binding,
        onboarding_binding=onboarding_binding, source_plan_ref=source_plan_ref,
        approval_receipt_ref=approval_receipt_ref, approver_authority_ref=approver_authority_ref,
        authorization_ref=authorization_ref, now_epoch=clock(),
    )
    source_plan = planning.get_plan(source_plan_ref)
    if source_plan.requester_digest != authenticated_requester_digest:
        raise M4AuthorizationDenied(_UNAVAILABLE)
    verifier = PlanningChainWebSecretServiceM4AuthorizationVerifier(
        planning, receipt_authenticator, service_binding,
        onboarding_binding=onboarding_binding, source_plan_ref=source_plan_ref,
        approval_receipt_ref=approval_receipt_ref, approver_authority_ref=approver_authority_ref,
        authorization_ref=authorization_ref,
    )
    runtime = ProtectedWebSecretServiceM4Runtime(
        _Resolver(binding), verifier, execution_store, read_transport, write_transport,
        authenticated_requester_digest=authenticated_requester_digest, clock=clock,
    )
    return ExactWebSecretServiceM4RunnerFactory(source_plan, onboarding_binding, binding, runtime)
