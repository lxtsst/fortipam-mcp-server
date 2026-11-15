"""Exact in-process execution boundary for the BP008 approval Scheme."""

from __future__ import annotations

from collections.abc import Mapping
import os

from v4_planning import SchemeId
from v4_planning.models import require_ref

from .onboarding_action_coordinator import (
    OnboardingActionCoordinator,
    OnboardingActionSequenceResult,
)
from .onboarding_execution_mcp_action import V4ExecutionPlanServices
from .v4_plan_runtime import V4PlanningPrincipal


V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOL = (
    "execute_v4_approval_and_observe_workflow"
)
V4_APPROVAL_AND_OBSERVE_EXECUTION_FEATURE_ENV = (
    "FORTIPAM_MCP_V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOLS_ENABLED"
)
V4_APPROVAL_AND_OBSERVE_EXECUTION_UNAVAILABLE = (
    "FortiPAM V4 approval workflow execution is unavailable."
)


class V4ApprovalAndObserveExecutionConfigurationError(ValueError):
    """Raised when the BP008 execution Tool opt-in is malformed."""


class V4ApprovalAndObserveExecutionRuntimeError(RuntimeError):
    """Stable non-disclosing BP008 execution failure."""


def load_v4_approval_and_observe_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the independent Tool-registration opt-in, defaulting to disabled."""

    env = os.environ if environment is None else environment
    raw = env.get(V4_APPROVAL_AND_OBSERVE_EXECUTION_FEATURE_ENV)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4ApprovalAndObserveExecutionConfigurationError(
        f"{V4_APPROVAL_AND_OBSERVE_EXECUTION_FEATURE_ENV} must be exactly true or false."
    )


class ProtectedApprovalAndObserveMcpAction:
    """Execute only one exact, already-confirmed BP008 Scheme Plan."""

    def __init__(
        self,
        plan_services: V4ExecutionPlanServices,
        coordinator: OnboardingActionCoordinator,
        *,
        authorized_environment_ref: str,
        authorized_scope_ref: str,
        execution_enabled: bool = False,
    ) -> None:
        self._plan_services = plan_services
        self._coordinator = coordinator
        self._authorized_environment_ref = require_ref(
            authorized_environment_ref,
            "authorized_environment_ref",
        )
        self._authorized_scope_ref = require_ref(
            authorized_scope_ref,
            "authorized_scope_ref",
        )
        self._execution_enabled = execution_enabled

    def execute(
        self,
        plan_ref: str,
        scheme_draft_ref: str,
        principal: V4PlanningPrincipal,
    ) -> dict[str, object]:
        try:
            if self._execution_enabled is not True:
                raise PermissionError("execution gate denied")
            plan, draft = self._plan_services.resolve_execution_context(
                plan_ref,
                scheme_draft_ref,
                principal,
            )
            if (
                plan.plan_ref != plan_ref
                or plan.requester_digest != principal.requester.digest
                or plan.scheme_id is not SchemeId.APPROVAL_AND_OBSERVE
                or draft.scheme_id is not SchemeId.APPROVAL_AND_OBSERVE
                or draft.blueprint_ref != "FPA-BP-008"
                or draft.outcome_code != "require_interactive_approval"
                or plan.environment_ref != self._authorized_environment_ref
                or draft.environment_ref != self._authorized_environment_ref
                or plan.scope_ref != self._authorized_scope_ref
                or draft.scope_ref != self._authorized_scope_ref
            ):
                raise PermissionError("execution context mismatch")
            result = self._coordinator.execute(
                plan_ref,
                scheme_draft_ref,
                principal,
            )
            if not isinstance(result, OnboardingActionSequenceResult):
                raise TypeError("invalid coordinator result")
            response = result.as_dict()
            response.update(
                {
                    "authorization_scope": "source_bound_approval_workflow",
                    "policy_mode": "independent_approval",
                }
            )
            return response
        except Exception as exc:
            raise V4ApprovalAndObserveExecutionRuntimeError(
                V4_APPROVAL_AND_OBSERVE_EXECUTION_UNAVAILABLE
            ) from exc


__all__ = [
    "ProtectedApprovalAndObserveMcpAction",
    "V4_APPROVAL_AND_OBSERVE_EXECUTION_FEATURE_ENV",
    "V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOL",
    "V4_APPROVAL_AND_OBSERVE_EXECUTION_UNAVAILABLE",
    "V4ApprovalAndObserveExecutionConfigurationError",
    "V4ApprovalAndObserveExecutionRuntimeError",
    "load_v4_approval_and_observe_execution_feature",
]
