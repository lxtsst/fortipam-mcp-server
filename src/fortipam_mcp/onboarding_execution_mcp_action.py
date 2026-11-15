"""Exact MCP boundaries for the two source-bound onboarding workflows."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any, Protocol

from v4_planning import PreparedPlan, SchemeDraft, SchemeId
from v4_planning.models import require_ref

from .folder_mcp_action import folder_action_principal_from_access_token
from .onboarding_action_coordinator import (
    FixedActionResolutionError,
    OnboardingActionCoordinatorError,
    OnboardingActionCoordinator,
    OnboardingActionSequenceResult,
)
from .v4_plan_runtime import V4PlanningPrincipal


V4_ONBOARDING_EXECUTION_PREFIX = "FORTIPAM_MCP_V4_ONBOARDING_EXECUTION_"
V4_ONBOARDING_EXECUTION_FEATURE_ENV = (
    f"{V4_ONBOARDING_EXECUTION_PREFIX}TOOLS_ENABLED"
)
V4_ONBOARDING_EXECUTION_GATE_ENV = "FORTIPAM_MCP_V4_ONBOARDING_EXECUTION_ENABLED"
V4_ACCESS_DOMAIN_AUTHORIZED_ENVIRONMENT_ENV = (
    f"{V4_ONBOARDING_EXECUTION_PREFIX}ACCESS_DOMAIN_AUTHORIZED_ENVIRONMENT_REF"
)
V4_ACCESS_DOMAIN_AUTHORIZED_SCOPE_ENV = (
    f"{V4_ONBOARDING_EXECUTION_PREFIX}ACCESS_DOMAIN_AUTHORIZED_SCOPE_REF"
)
V4_ACCESS_DOMAIN_EXECUTION_TOOL = "execute_v4_access_domain_workflow"
V4_SECRET_ONBOARDING_EXECUTION_TOOL = "execute_v4_secret_onboarding_workflow"
V4_ONBOARDING_EXECUTION_UNAVAILABLE = (
    "FortiPAM V4 onboarding execution is unavailable."
)


class V4OnboardingExecutionConfigurationError(ValueError):
    """Raised when an onboarding execution opt-in is malformed."""


class V4OnboardingExecutionRuntimeError(RuntimeError):
    """Stable, non-disclosing onboarding execution failure."""


class V4ExecutionPlanServices(Protocol):
    """Resolve one already-confirmed exact plan and Scheme draft."""

    def resolve_execution_context(
        self,
        plan_ref: str,
        scheme_draft_ref: str,
        principal: V4PlanningPrincipal,
    ) -> tuple[PreparedPlan, SchemeDraft]: ...


def load_v4_onboarding_execution_feature(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the Tool-registration opt-in, defaulting to disabled."""

    return _load_exact_boolean(V4_ONBOARDING_EXECUTION_FEATURE_ENV, environment)


def load_v4_onboarding_execution_gate(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Load the final execution gate, independently defaulting to denied."""

    return _load_exact_boolean(V4_ONBOARDING_EXECUTION_GATE_ENV, environment)


def load_v4_access_domain_authorized_scope(
    environment: Mapping[str, str] | None = None,
) -> tuple[str, str]:
    """Load the exact Access Domain environment and scope binding."""

    env = os.environ if environment is None else environment
    try:
        return (
            require_ref(
                env[V4_ACCESS_DOMAIN_AUTHORIZED_ENVIRONMENT_ENV],
                "authorized_access_domain_environment_ref",
            ),
            require_ref(
                env[V4_ACCESS_DOMAIN_AUTHORIZED_SCOPE_ENV],
                "authorized_access_domain_scope_ref",
            ),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise V4OnboardingExecutionConfigurationError(
            "Access Domain onboarding authorization scope is unavailable."
        ) from exc


def onboarding_execution_principal_from_access_token(
    access_token: Any,
    planning_settings: Any,
) -> V4PlanningPrincipal:
    """Require the existing plan plus operate OAuth authorization."""

    try:
        principal = folder_action_principal_from_access_token(
            access_token,
            planning_settings,
        )
        if not isinstance(principal, V4PlanningPrincipal):
            raise TypeError("validated planning principal required")
        return principal
    except Exception as exc:
        raise V4OnboardingExecutionRuntimeError(
            V4_ONBOARDING_EXECUTION_UNAVAILABLE
        ) from exc


class ProtectedAccessDomainOnboardingMcpAction:
    """Execute only the fixed Access Domain Scheme profile."""

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
                or plan.scheme_id is not SchemeId.ACCESS_DOMAIN
                or draft.scheme_id is not SchemeId.ACCESS_DOMAIN
                or draft.blueprint_ref != "FPA-BP-004"
                or draft.outcome_code != "establish_access_domain"
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
                    "authorization_scope": "source_bound_onboarding",
                    "lab_exception_applied": True,
                    "policy_mode": "lab_auto",
                }
            )
            return response
        except Exception as exc:
            raise V4OnboardingExecutionRuntimeError(
                V4_ONBOARDING_EXECUTION_UNAVAILABLE
            ) from exc


class ProtectedSecretOnboardingMcpAction:
    """Execute one accepted Linux SSH/SFTP or Windows RDP onboarding profile."""

    def __init__(
        self,
        plan_services: V4ExecutionPlanServices,
        coordinator: OnboardingActionCoordinator,
        *,
        authorized_environment_ref: str,
        authorized_scope_ref: str,
        execution_enabled: bool = False,
        policy_mode: str = "lab_auto",
    ) -> None:
        if policy_mode not in {"lab_auto", "independent_approval"}:
            raise V4OnboardingExecutionConfigurationError("Onboarding policy mode is invalid.")
        self._policy_mode = policy_mode
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
            try:
                plan, draft = self._plan_services.resolve_execution_context(
                    plan_ref,
                    scheme_draft_ref,
                    principal,
                )
            except Exception:
                raise FixedActionResolutionError("fixed_action_context") from None
            accepted_profile = (
                ("FPA-BP-005", "onboard_privileged_resource"),
                ("FPA-BP-006", "onboard_windows_rdp_resource"),
                ("FPA-BP-007", "onboard_web_account"),
            )
            if (
                plan.plan_ref != plan_ref
                or plan.requester_digest != principal.requester.digest
                or plan.scheme_id is not SchemeId.SECRET_ONBOARDING
                or draft.scheme_id is not SchemeId.SECRET_ONBOARDING
                or (draft.blueprint_ref, draft.outcome_code)
                not in accepted_profile
                or plan.environment_ref != self._authorized_environment_ref
                or draft.environment_ref != self._authorized_environment_ref
                or plan.scope_ref != self._authorized_scope_ref
                or draft.scope_ref != self._authorized_scope_ref
            ):
                raise PermissionError("execution context mismatch")
            try:
                result = self._coordinator.execute(
                    plan_ref,
                    scheme_draft_ref,
                    principal,
                )
            except OnboardingActionCoordinatorError:
                # Sequence validation and dependency ordering fail before any
                # runner starts. Preserve only the fixed failure stage, never
                # the exception text or private binding context.
                response = OnboardingActionSequenceResult(
                    outcome="reconciliation_required",
                    completed_line_refs=(),
                    stopped_line_ref=None,
                    pre_write_status="unavailable",
                    post_write_status=None,
                    reconciliation_required=True,
                    failure_stage="fixed_action_resolution",
                ).as_dict()
            else:
                if not isinstance(result, OnboardingActionSequenceResult):
                    raise TypeError("invalid coordinator result")
                response = result.as_dict()
            response.update(
                {
                    "authorization_scope": "source_bound_onboarding",
                    "lab_exception_applied": self._policy_mode == "lab_auto",
                    "policy_mode": self._policy_mode,
                }
            )
            return response
        except FixedActionResolutionError as exc:
            response = OnboardingActionSequenceResult(
                outcome="reconciliation_required",
                completed_line_refs=(),
                stopped_line_ref=None,
                pre_write_status="unavailable",
                post_write_status=None,
                reconciliation_required=True,
                failure_stage=exc.failure_stage,
            ).as_dict()
            response.update(
                {
                    "authorization_scope": "source_bound_onboarding",
                    "lab_exception_applied": self._policy_mode == "lab_auto",
                    "policy_mode": self._policy_mode,
                }
            )
            return response
        except Exception as exc:
            raise V4OnboardingExecutionRuntimeError(
                V4_ONBOARDING_EXECUTION_UNAVAILABLE
            ) from exc


def _load_exact_boolean(
    name: str,
    environment: Mapping[str, str] | None,
) -> bool:
    env = os.environ if environment is None else environment
    raw = env.get(name)
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise V4OnboardingExecutionConfigurationError(
        f"{name} must be exactly true or false."
    )


__all__ = [
    "ProtectedAccessDomainOnboardingMcpAction",
    "ProtectedSecretOnboardingMcpAction",
    "V4_ACCESS_DOMAIN_AUTHORIZED_ENVIRONMENT_ENV",
    "V4_ACCESS_DOMAIN_AUTHORIZED_SCOPE_ENV",
    "V4_ACCESS_DOMAIN_EXECUTION_TOOL",
    "V4_ONBOARDING_EXECUTION_FEATURE_ENV",
    "V4_ONBOARDING_EXECUTION_GATE_ENV",
    "V4_ONBOARDING_EXECUTION_PREFIX",
    "V4_ONBOARDING_EXECUTION_UNAVAILABLE",
    "V4_SECRET_ONBOARDING_EXECUTION_TOOL",
    "V4OnboardingExecutionConfigurationError",
    "V4OnboardingExecutionRuntimeError",
    "load_v4_access_domain_authorized_scope",
    "load_v4_onboarding_execution_feature",
    "load_v4_onboarding_execution_gate",
    "onboarding_execution_principal_from_access_token",
]
