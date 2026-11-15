"""Fixed, default-closed build-29 BP008 runner composition.

Construction performs no protected reads. A claimed signed planning chain and
its exact draft are checked before the private provider produces a full state.
Product/source qualification and material lifecycle remain provider-owned.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from threading import Lock
import time
from typing import Protocol

from v4_planning import M4ExecutionStateStore, ApprovalReceiptAuthenticationAuthority
from v4_planning.models import FinalIntentSummary, PreparedPlan, SchemeDraft, require_ref

from .approval_and_observe_projection_source import ApprovalAndObserveBinding
from .onboarding_action_coordinator import BoundFixedActionRunner, OnboardingActionCoordinatorError
from .secret_approval_build29_http_transport import (
    FortiPamSecretApprovalBuild29HttpTransport, SecretApprovalBuild29PrivateState,
)
from .secret_approval_build29_m4_authorization import (
    PlanningChainSecretApprovalBuild29M4AuthorizationVerifier,
    promote_secret_approval_build29_m4_binding, validate_build29_planning_chain,
)
from .secret_approval_build29_m4_runtime import (
    ProtectedSecretApprovalBuild29M4Runtime, SecretApprovalBuild29QualificationVerifier,
    assemble_secret_approval_build29_m4_runtime,
)
from .secret_approval_build29_projection_source import _qualify_desired, _qualify_scheme
from .secret_approval_m4_authorization import SecretApprovalPlanningChainReader
from .v4_plan_runtime import V4PlanningPrincipal


_UNAVAILABLE = "Protected build-29 Secret approval composition is unavailable."


class SecretApprovalBuild29M4CompositionError(OnboardingActionCoordinatorError):
    """Stable value-free refusal, including a failed private provider call."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretApprovalBuild29PrivateTransition:
    """A provider-owned sealed transport paired with two canonical full states."""

    transport: FortiPamSecretApprovalBuild29HttpTransport
    baseline: SecretApprovalBuild29PrivateState
    expected_private_state: SecretApprovalBuild29PrivateState
    expected_binding_digest: str


class SecretApprovalBuild29PrivateTransitionProducer(Protocol):
    """One fixed protected producer; no caller-supplied endpoint or body.

    Its implementation authenticates the native/material/permission witnesses
    for this exact binding and owns all protected buffers and transport cleanup.
    Composition calls it only after the material-free signed-chain predicate.
    """

    def produce(self, approval_binding: ApprovalAndObserveBinding) -> SecretApprovalBuild29PrivateTransition: ...


@dataclass(frozen=True, slots=True, repr=False)
class _SecretApprovalBuild29Runner:
    line_ref: str
    depends_on: tuple[str, ...]
    authorization_ref: str
    binding_digest: str
    runtime: ProtectedSecretApprovalBuild29M4Runtime

    def execute_bound(self) -> Mapping[str, object]:
        return self.runtime.execute_bound(
            self.authorization_ref, expected_binding_digest=self.binding_digest,
        ).as_dict()


@dataclass(frozen=True, slots=True, repr=False)
class _BoundContext:
    plan: PreparedPlan
    draft: SchemeDraft
    principal: V4PlanningPrincipal
    approval_binding: ApprovalAndObserveBinding
    line_ref: str
    runner: _SecretApprovalBuild29Runner


class SecretApprovalBuild29M4RunnerFactory:
    """Delay private production until one exact claimed BP008 plan is bound.

    A successful rebind returns the same runtime and therefore the same
    transport ownership. Failed production cannot be retried through this
    factory. Independent restore authorization is outside this enable factory.
    """

    def __init__(
        self, *, planning: SecretApprovalPlanningChainReader,
        receipt_authenticator: ApprovalReceiptAuthenticationAuthority,
        producer: SecretApprovalBuild29PrivateTransitionProducer,
        execution_store: M4ExecutionStateStore,
        source_plan_ref: str, approval_receipt_ref: str, approver_authority_ref: str,
        authorization_ref: str, authorized_environment_ref: str, authorized_scope_ref: str,
        qualification_verifier: SecretApprovalBuild29QualificationVerifier | None = None,
        execution_enabled: bool = False, clock: Callable[[], int] | None = None,
    ) -> None:
        try:
            for ref in (source_plan_ref, approval_receipt_ref, approver_authority_ref,
                        authorization_ref, authorized_environment_ref, authorized_scope_ref):
                require_ref(ref, "protected reference")
            if type(execution_enabled) is not bool or not callable(getattr(producer, "produce", None)):
                raise ValueError
            if clock is not None and not callable(clock):
                raise ValueError
            self._planning = planning
            self._authenticator = receipt_authenticator
            self._producer = producer
            self._store = execution_store
            self._source_plan_ref = source_plan_ref
            self._receipt_ref = approval_receipt_ref
            self._authority_ref = approver_authority_ref
            self._authorization_ref = authorization_ref
            self._environment = authorized_environment_ref
            self._scope = authorized_scope_ref
            self._qualifier = qualification_verifier
            self._enabled = execution_enabled
            self._clock = clock or (lambda: int(time.time()))
            self._bound: _BoundContext | None = None
            self._production_attempted = False
            self._lock = Lock()
        except Exception:
            raise SecretApprovalBuild29M4CompositionError(_UNAVAILABLE) from None

    def bind(
        self, plan: PreparedPlan, line_ref: str, principal: V4PlanningPrincipal,
        *, draft: SchemeDraft, approval_binding: ApprovalAndObserveBinding,
    ) -> BoundFixedActionRunner:
        with self._lock:
            try:
                if (self._enabled is not True or self._qualifier is None
                        or type(plan) is not PreparedPlan or type(draft) is not SchemeDraft
                        or type(principal) is not V4PlanningPrincipal
                        or type(approval_binding) is not ApprovalAndObserveBinding
                        or plan.plan_ref != self._source_plan_ref
                        or len(plan.lines) != 1 or plan.lines[0].line_ref != line_ref
                        or plan.lines[0].target_ref != approval_binding.secret_approval_object_ref
                        or plan.requester_digest != principal.requester.digest):
                    raise ValueError
                if self._bound is not None:
                    bound = self._bound
                    if (plan != bound.plan or draft != bound.draft or principal != bound.principal
                            or approval_binding != bound.approval_binding or line_ref != bound.line_ref):
                        raise ValueError
                _qualify_scheme(draft, principal.requester)
                _qualify_desired(draft, approval_binding)
                now_epoch = self._clock()
                chain = validate_build29_planning_chain(
                    self._planning, self._authenticator, approval_binding,
                    source_plan_ref=self._source_plan_ref, approval_receipt_ref=self._receipt_ref,
                    approver_authority_ref=self._authority_ref,
                    authenticated_requester_digest=principal.requester.digest,
                    authorized_environment_ref=self._environment, authorized_scope_ref=self._scope,
                    now_epoch=now_epoch,
                )
                if chain.plan != plan:
                    raise ValueError
                _validate_draft_summary(draft, chain.summary)
                if self._bound is not None:
                    return self._bound.runner
                if self._production_attempted:
                    raise ValueError
                self._production_attempted = True
                transition = self._producer.produce(approval_binding)
                if type(transition) is not SecretApprovalBuild29PrivateTransition:
                    raise ValueError
                binding = promote_secret_approval_build29_m4_binding(
                    self._planning, self._authenticator, approval_binding,
                    source_plan_ref=self._source_plan_ref, approval_receipt_ref=self._receipt_ref,
                    approver_authority_ref=self._authority_ref, authorization_ref=self._authorization_ref,
                    authenticated_requester_digest=principal.requester.digest,
                    authorized_environment_ref=self._environment, authorized_scope_ref=self._scope,
                    now_epoch=self._clock(), transport=transition.transport, baseline=transition.baseline,
                    expected_private_state=transition.expected_private_state,
                    expected_binding_digest=transition.expected_binding_digest,
                )
                # Promotion re-reads the chain after production. It must still
                # be the exact public plan/receipt checked before production.
                if (binding.plan.plan_ref != chain.plan.plan_ref or binding.plan.revision != chain.plan.revision
                        or binding.plan.requester_digest != chain.plan.requester_digest
                        or binding.plan.summary_digest != chain.summary.summary_digest
                        or binding.plan.confirmation_digest != chain.plan.confirmation_digest
                        or binding.plan.approval_digest != chain.receipt.receipt_digest):
                    raise ValueError
                verifier = PlanningChainSecretApprovalBuild29M4AuthorizationVerifier(
                    self._planning, self._authenticator, approval_binding,
                    source_plan_ref=self._source_plan_ref, approval_receipt_ref=self._receipt_ref,
                    approver_authority_ref=self._authority_ref, authorization_ref=self._authorization_ref,
                    authenticated_requester_digest=principal.requester.digest,
                    authorized_environment_ref=self._environment, authorized_scope_ref=self._scope,
                    transport=transition.transport, baseline=transition.baseline,
                    expected_private_state=transition.expected_private_state,
                    expected_binding_digest=transition.expected_binding_digest,
                )
                runtime = assemble_secret_approval_build29_m4_runtime(
                    binding, authorization_verifier=verifier, execution_store=self._store,
                    authenticated_requester_digest=principal.requester.digest,
                    qualification_verifier=self._qualifier, execution_enabled=self._enabled,
                    clock=self._clock,
                )
                runner = _SecretApprovalBuild29Runner(
                    line_ref, (), self._authorization_ref,
                    runtime.inspect_binding_digest(self._authorization_ref), runtime,
                )
                self._bound = _BoundContext(plan, draft, principal, approval_binding, line_ref, runner)
                return runner
            except Exception:
                raise SecretApprovalBuild29M4CompositionError(_UNAVAILABLE) from None


def _validate_draft_summary(draft: SchemeDraft, summary: FinalIntentSummary) -> None:
    """Bind every draft attribute carried into the signed intent summary."""
    for name in (
        "scheme_id", "scheme_version", "registry_schema_version", "blueprint_ref",
        "environment_ref", "scope_ref", "owner_ref", "audience_ref", "outcome_code",
        "approval_class", "separation_required", "risk_class", "external_effects",
        "evidence_policy", "maintenance_class", "reversibility_class", "reconciliation_strategy",
        "material_reference_metadata",
    ):
        if getattr(draft, name) != getattr(summary, name):
            raise ValueError
    for draft_name, summary_name in (
        ("assumption_codes", "assumptions"), ("excluded_scope_codes", "excluded_scope"),
        ("verification_codes", "verification_codes"), ("stop_codes", "stop_codes"),
        ("unresolved_gap_codes", "unresolved_gaps"), ("evidence_refs", "facts"),
    ):
        if getattr(draft, draft_name) != getattr(summary, summary_name):
            raise ValueError
    if summary.expires_at > summary.created_at + draft.summary_ttl_seconds:
        raise ValueError
