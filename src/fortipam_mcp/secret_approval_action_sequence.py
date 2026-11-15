"""Bind the BP008 Secret approval Plan line to one fixed protected write."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol

from v4_planning import (
    ChangeKind,
    M4ExecutionPlan,
    M4ExecutionResult,
    ObjectClass,
    PlanLine,
    PreparedPlan,
    SchemeDraft,
    SchemeId,
)

from .approval_and_observe_projection_source import (
    ApprovalAndObserveBinding,
    FortiPamApprovalAndObserveProjectionSource,
)
from .secret_approval_build29_projection_source import FortiPamSecretApprovalBuild29ProjectionSource
from .onboarding_action_coordinator import (
    BoundFixedActionRunner,
    OnboardingActionCoordinatorError,
    ResolvedFixedActionSequence,
)
from .v4_plan_runtime import OAuthBoundV4PlanServices, V4PlanningPrincipal
from .secret_approval_m4_runtime import (
    SECRET_APPROVAL_ACTION_ID,
    SECRET_APPROVAL_ACTION_VERSION,
    secret_approval_binding_digest,
    secret_approval_parameters_digest,
)


class SecretApprovalBoundRuntime(Protocol):
    """Protected M4 runtime for one independently authorized BP008 line."""

    def inspect_execution_plan(self, authorization_ref: str) -> M4ExecutionPlan: ...

    def inspect_approval_binding_digest(self, authorization_ref: str) -> str: ...

    def execute_bound(
        self,
        authorization_ref: str,
        *,
        expected_approval_binding_digest: str,
    ) -> M4ExecutionResult: ...


class SecretApprovalM4RunnerFactory(Protocol):
    """Resolve an independently authorized M4 runner for one BP008 line."""

    def bind(
        self,
        plan: PreparedPlan,
        line_ref: str,
        principal: V4PlanningPrincipal,
        *,
        draft: SchemeDraft,
        approval_binding: ApprovalAndObserveBinding,
    ) -> BoundFixedActionRunner: ...


@dataclass(frozen=True, slots=True)
class ProtectedSecretApprovalRunnerBinding:
    """Value-free Scheme-to-M4 association kept inside trusted composition."""

    scheme_plan_digest: str
    line_ref: str
    requester_digest: str
    authorization_ref: str
    approval_binding_digest: str
    runtime: SecretApprovalBoundRuntime


@dataclass(frozen=True, slots=True)
class _SecretApprovalM4Runner:
    line_ref: str
    depends_on: tuple[str, ...]
    authorization_ref: str
    approval_binding_digest: str
    runtime: SecretApprovalBoundRuntime

    def execute_bound(self) -> Mapping[str, object]:
        return self.runtime.execute_bound(
            self.authorization_ref,
            expected_approval_binding_digest=self.approval_binding_digest,
        ).as_dict()


class ExactSecretApprovalM4RunnerFactory:
    """Bind one exact Scheme line to a pre-authorized protected M4 runtime."""

    def __init__(self, binding: ProtectedSecretApprovalRunnerBinding) -> None:
        self._binding = binding

    def bind(
        self,
        plan: PreparedPlan,
        line_ref: str,
        principal: V4PlanningPrincipal,
        *,
        draft: SchemeDraft,
        approval_binding: ApprovalAndObserveBinding,
    ) -> BoundFixedActionRunner:
        del draft
        binding = self._binding
        line = next((item for item in plan.lines if item.line_ref == line_ref), None)
        if (
            binding.scheme_plan_digest != plan.plan_digest
            or binding.line_ref != line_ref
            or binding.requester_digest != principal.requester.digest
            or line is None
            or not binding.authorization_ref
            or binding.approval_binding_digest
            != secret_approval_binding_digest(approval_binding)
        ):
            raise OnboardingActionCoordinatorError(
                "Protected Secret approval M4 runner binding is unavailable."
            )
        _validate_bound_m4_plan(
            binding.runtime,
            binding.authorization_ref,
            plan,
            line,
            approval_binding,
        )
        try:
            runtime_binding_digest = binding.runtime.inspect_approval_binding_digest(
                binding.authorization_ref
            )
        except Exception as exc:
            raise OnboardingActionCoordinatorError(
                "Protected Secret approval M4 runner binding is unavailable."
            ) from exc
        if runtime_binding_digest != binding.approval_binding_digest:
            raise OnboardingActionCoordinatorError(
                "Protected Secret approval M4 runner binding is unavailable."
            )
        return _SecretApprovalM4Runner(
            line.line_ref,
            line.depends_on,
            binding.authorization_ref,
            binding.approval_binding_digest,
            binding.runtime,
        )


class SecretApprovalFixedActionSequenceResolver:
    """Resolve exactly one confirmed BP008 Secret approval update line."""

    def __init__(
        self,
        plan_services: OAuthBoundV4PlanServices,
        projection_source: FortiPamApprovalAndObserveProjectionSource | FortiPamSecretApprovalBuild29ProjectionSource,
        runner_factory: SecretApprovalM4RunnerFactory,
    ) -> None:
        if not callable(getattr(runner_factory, "bind", None)):
            raise OnboardingActionCoordinatorError(
                "Secret approval fixed action is unavailable."
            )
        self._plan_services = plan_services
        self._projection_source = projection_source
        self._runner_factory = runner_factory

    def resolve(
        self,
        plan_ref: str,
        scheme_draft_ref: str,
        principal: V4PlanningPrincipal,
    ) -> ResolvedFixedActionSequence:
        try:
            plan, draft = self._plan_services.resolve_execution_context(
                plan_ref,
                scheme_draft_ref,
                principal,
            )
            binding = self._projection_source.resolve_private_binding(
                draft,
                principal.requester,
            )
            line = self._validate_plan(plan, draft, binding)
            runner = self._runner_factory.bind(
                plan,
                line.line_ref,
                principal,
                draft=draft,
                approval_binding=binding,
            )
        except OnboardingActionCoordinatorError:
            raise
        except Exception as exc:
            raise OnboardingActionCoordinatorError(
                "Secret approval fixed action is unavailable."
            ) from exc
        return ResolvedFixedActionSequence(
            plan.plan_ref,
            plan.requester_digest,
            (
                runner,
            ),
        )

    @staticmethod
    def _validate_plan(
        plan: PreparedPlan,
        draft: SchemeDraft,
        binding: ApprovalAndObserveBinding,
    ) -> PlanLine:
        desired = {item.object_ref: item for item in draft.desired_objects}
        profile = desired.get(binding.approval_profile_object_ref)
        secret = desired.get(binding.secret_approval_object_ref)
        line = plan.lines[0] if len(plan.lines) == 1 else None
        if (
            plan.scheme_id is not SchemeId.APPROVAL_AND_OBSERVE
            or draft.scheme_id is not SchemeId.APPROVAL_AND_OBSERVE
            or draft.blueprint_ref != "FPA-BP-008"
            or draft.outcome_code != "require_interactive_approval"
            or line is None
            or line.target_ref != binding.secret_approval_object_ref
            or line.target_class is not ObjectClass.SECRET_APPROVAL_BINDING
            or line.change_kind is not ChangeKind.UPDATE
            or line.depends_on
            or profile is None
            or profile.object_class is not ObjectClass.APPROVAL_PROFILE_BINDING
            or dict(profile.desired_fields)
            != {
                "profile_mode": "single_tier",
                "profile_ref": binding.approval_profile_ref,
            }
            or secret is None
            or secret.object_class is not ObjectClass.SECRET_APPROVAL_BINDING
            or dict(secret.desired_fields)
            != {
                "approval_profile_attached": True,
                "interactive_approval_required": True,
                "job_approval_required": False,
                "owner_bypass_allowed": False,
            }
        ):
            raise OnboardingActionCoordinatorError(
                "Secret approval Plan is not the exact fixed update subset."
            )
        return line


def _validate_bound_m4_plan(
    runtime: SecretApprovalBoundRuntime,
    authorization_ref: str,
    scheme_plan: PreparedPlan,
    line: PlanLine,
    approval_binding: ApprovalAndObserveBinding,
) -> None:
    try:
        m4_plan = runtime.inspect_execution_plan(authorization_ref)
    except Exception as exc:
        raise OnboardingActionCoordinatorError(
            "Protected Secret approval M4 runner binding is unavailable."
        ) from exc
    if (
        not isinstance(m4_plan, M4ExecutionPlan)
        or m4_plan.action_id != SECRET_APPROVAL_ACTION_ID
        or m4_plan.action_version != SECRET_APPROVAL_ACTION_VERSION
        or m4_plan.plan_ref != scheme_plan.plan_ref
        or m4_plan.revision != scheme_plan.revision
        or m4_plan.requester_digest != scheme_plan.requester_digest
        or m4_plan.summary_digest != scheme_plan.summary_digest
        or m4_plan.confirmation_digest != scheme_plan.confirmation_digest
        or m4_plan.target_ref != line.target_ref
        or m4_plan.expected_current_digest != line.expected_current_digest
        or m4_plan.expected_state_digest != line.expected_state_digest
        or m4_plan.parameters_digest
        != secret_approval_parameters_digest(approval_binding)
    ):
        raise OnboardingActionCoordinatorError(
            "Protected Secret approval M4 runner binding is unavailable."
        )


__all__ = [
    "ExactSecretApprovalM4RunnerFactory",
    "ProtectedSecretApprovalRunnerBinding",
    "SecretApprovalFixedActionSequenceResolver",
    "SecretApprovalM4RunnerFactory",
]
