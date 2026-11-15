"""Default-off MCP boundary for the single fixed BP014 AD Source workflow."""

from collections.abc import Mapping
import os
from typing import Any

from v4_planning import ChangeKind, ObjectClass, PlanState, PreparedPlan, SchemeDraft, SchemeId
from v4_planning.models import require_ref

from .ad_discovery_action_sequence import AdDiscoveryFixedActionSequenceResolver
from .ad_discovery_lab_auto_runtime import AdDiscoveryLabAutoRunnerFactory
from .ad_discovery_projection_source import CONTRACT_ID, OUTCOME, ad_discovery_projection_contract
from .onboarding_action_coordinator import (
    FixedActionResolutionError, OnboardingActionCoordinator,
    OnboardingActionCoordinatorError, OnboardingActionSequenceResult,
)
from .onboarding_execution_mcp_action import (
    V4ExecutionPlanServices, onboarding_execution_principal_from_access_token,
)
from .v4_plan_runtime import V4PlanningPrincipal


V4_AD_DISCOVERY_EXECUTION_FEATURE_ENV = "FORTIPAM_MCP_V4_AD_DISCOVERY_EXECUTION_TOOLS_ENABLED"
V4_AD_DISCOVERY_EXECUTION_TOOL = "execute_v4_ad_discovery_workflow"
V4_AD_DISCOVERY_EXECUTION_UNAVAILABLE = "FortiPAM V4 AD Discovery execution is unavailable."
_SAFE_FAILURE_STAGES = frozenset({
    "pre_write_projection", "fixed_action_context", "fixed_action_resolution",
    "fixed_action_private_binding", "fixed_action_plan_validation", "fixed_action_runner_binding",
    "fixed_action_runner_promotion", "fixed_action_runner_promotion_freshness",
    "fixed_action_runner_promotion_context", "fixed_action_runner_promotion_shape",
    "fixed_action_runner_runtime_binding", "fixed_action_execution", "fixed_action_verification",
    "post_write_projection", "post_write_comparison",
})
_CLASSES = frozenset({ObjectClass.FOLDER_BINDING, ObjectClass.DOMAIN_TARGET_BINDING,
    ObjectClass.TEMPLATE_BINDING, ObjectClass.DOMAIN_SECRET_METADATA, ObjectClass.DISCOVERY_SOURCE_METADATA})


class V4AdDiscoveryExecutionConfigurationError(ValueError):
    """Malformed local AD execution configuration."""


class V4AdDiscoveryExecutionRuntimeError(RuntimeError):
    """Stable error without private transport or authorization details."""


def load_v4_ad_discovery_execution_feature(environment: Mapping[str, str] | None = None) -> bool:
    env = os.environ if environment is None else environment
    raw = env.get(V4_AD_DISCOVERY_EXECUTION_FEATURE_ENV)
    if raw is None or (type(raw) is str and raw == "false"):
        return False
    if type(raw) is str and raw == "true":
        return True
    raise V4AdDiscoveryExecutionConfigurationError(
        f"{V4_AD_DISCOVERY_EXECUTION_FEATURE_ENV} must be exactly true or false.")


def ad_discovery_execution_principal_from_access_token(access_token: Any,
                                                       planning_settings: Any) -> V4PlanningPrincipal:
    try:
        return onboarding_execution_principal_from_access_token(access_token, planning_settings)
    except Exception:
        raise V4AdDiscoveryExecutionRuntimeError(V4_AD_DISCOVERY_EXECUTION_UNAVAILABLE) from None


def _reconciliation(stage: str) -> OnboardingActionSequenceResult:
    return OnboardingActionSequenceResult("reconciliation_required", (), None,
        "unavailable", None, True, stage)


class ProtectedAdDiscoveryMcpAction:
    """Resolve exact C2 artifacts; write rights remain the runner's responsibility."""

    def __init__(self, plan_services: V4ExecutionPlanServices,
                 coordinator: OnboardingActionCoordinator, *, authorized_environment_ref: str,
                 authorized_scope_ref: str, execution_enabled: bool = False) -> None:
        try:
            if (type(execution_enabled) is not bool or type(coordinator) is not OnboardingActionCoordinator
                or not callable(getattr(plan_services, "resolve_execution_context", None))):
                raise ValueError
            self._environment = require_ref(authorized_environment_ref, "AD authorized environment")
            self._scope = require_ref(authorized_scope_ref, "AD authorized scope")
        except Exception:
            raise V4AdDiscoveryExecutionConfigurationError(V4_AD_DISCOVERY_EXECUTION_UNAVAILABLE) from None
        self._services, self._coordinator, self._enabled = plan_services, coordinator, execution_enabled

    def execution_preflight_available(self) -> bool:
        """Only local exact composition and gates; no credentials or device reads."""
        try:
            resolver = self._coordinator._resolver
            if self._enabled is not True or type(resolver) is not AdDiscoveryFixedActionSequenceResolver:
                return False
            factory = resolver._factory
            if type(factory) is not AdDiscoveryLabAutoRunnerFactory:
                return False
            planning = factory._promoter._source._owner._config
            owner, writer = factory._owner_config, factory._writer._config
            return (factory._gate is True and factory._promoter._standing is True
                and factory._promoter._environment == self._environment
                and factory._promoter._scope == self._scope
                and resolver._source._binding == factory._promoter._binding
                and planning.base_url == owner.base_url == writer.base_url
                and planning.ca_file == owner.ca_file == writer.ca_file)
        except Exception:
            return False

    def _validate(self, plan: PreparedPlan, draft: SchemeDraft, plan_ref: str,
                  principal: V4PlanningPrincipal) -> None:
        if (type(plan) is not PreparedPlan or type(draft) is not SchemeDraft
            or plan.plan_ref != plan_ref or plan.requester_digest != principal.requester.digest
            or plan.state is not PlanState.PREPARED_NON_EXECUTABLE
            or plan.scheme_id is not SchemeId.BULK_ONBOARDING or draft.scheme_id is not SchemeId.BULK_ONBOARDING
            or plan.scheme_version != "1.0.0" or draft.scheme_version != "1.0.0"
            or plan.registry_schema_version != draft.registry_schema_version
            or draft.blueprint_ref != "FPA-BP-014" or draft.outcome_code != OUTCOME
            or draft.material_reference_metadata is not None or draft.risk_class != "medium"
            or plan.environment_ref != self._environment or draft.environment_ref != self._environment
            or plan.scope_ref != self._scope or draft.scope_ref != self._scope
            or plan.dispatchable is not False or plan.adapter_registry_bound is not False
            or plan.executor_runtime_packaged is not False or plan.executor_mcp_exposed is not False
            or plan.planner_runtime_packaged is not True or len(plan.lines) != 1
            or len(draft.desired_objects) != 5
            or {item.object_class for item in draft.desired_objects} != _CLASSES):
            raise ValueError
        by_class = {item.object_class: item for item in draft.desired_objects}
        for item in draft.desired_objects:
            if item.desired_exists is not True:
                raise ValueError
            ad_discovery_projection_contract(item.object_class).validate_fields(
                {"exists": True, **dict(item.desired_fields)}, complete=True)
        source = by_class[ObjectClass.DISCOVERY_SOURCE_METADATA]
        if (dict(source.desired_fields) != {
            "source_type": "active_directory", "account_discovery": True,
            "domain_secret_ref": by_class[ObjectClass.DOMAIN_SECRET_METADATA].object_ref,
            "periodic_scanning_disabled": True, "auto_onboarding_disabled": True,
            "existing_secret_method": True, "no_scan_timestamp": True,
        } or dict(by_class[ObjectClass.DOMAIN_SECRET_METADATA].desired_fields) != {
            "inherit_permission": True, "non_privileged_account": True,
            "services_disabled": True, "target_association_matches": True,
        } or dict(by_class[ObjectClass.DOMAIN_TARGET_BINDING].desired_fields)["target_relation_matches"] is not True
          or dict(by_class[ObjectClass.TEMPLATE_BINDING].desired_fields)["compatibility"] != "compatible"):
            raise ValueError
        line = plan.lines[0]
        if (line.target_class is not ObjectClass.DISCOVERY_SOURCE_METADATA
            or line.target_ref != source.object_ref or line.change_kind is not ChangeKind.CREATE
            or line.depends_on or line.dispatchable is not False or line.adapter != "none"
            or line.projection_contract_ref != CONTRACT_ID
            or line.action_family_ref != "discovery-and-smart-association-plan"
            or line.action_family_version != "1.0.0"):
            raise ValueError

    @staticmethod
    def _response(result: OnboardingActionSequenceResult, line_ref: str | None) -> dict[str, object]:
        if (type(result) is not OnboardingActionSequenceResult
            or type(result.outcome) is not str
            or result.outcome not in {"succeeded", "precondition_failed", "execution_failed", "reconciliation_required"}
            or type(result.pre_write_status) is not str
            or result.pre_write_status not in {"match", "invalidated", "unknown", "unavailable"}
            or (result.post_write_status is not None and (type(result.post_write_status) is not str
                or result.post_write_status not in {"expected_state_matches", "expected_state_mismatch", "comparison_unknown", "unavailable"}))
            or type(result.completed_line_refs) is not tuple
            or result.completed_line_refs not in {(), (line_ref,)}
            or (result.stopped_line_ref is not None and result.stopped_line_ref != line_ref)
            or type(result.reconciliation_required) is not bool
            or (result.failure_stage is not None and (type(result.failure_stage) is not str
                or result.failure_stage not in _SAFE_FAILURE_STAGES))):
            raise ValueError
        if result.outcome == "succeeded" and (
            result.completed_line_refs != (line_ref,) or line_ref is None
            or result.pre_write_status != "match" or result.post_write_status != "expected_state_matches"
            or result.stopped_line_ref is not None or result.reconciliation_required or result.failure_stage is not None):
            raise ValueError
        if result.outcome == "reconciliation_required" and result.reconciliation_required is not True:
            raise ValueError
        return {
            "outcome": result.outcome, "completed_line_refs": list(result.completed_line_refs),
            "stopped_line_ref": result.stopped_line_ref, "pre_write_status": result.pre_write_status,
            "post_write_status": result.post_write_status,
            "reconciliation_required": result.reconciliation_required,
            **({"failure_stage": result.failure_stage} if result.failure_stage is not None else {}),
            "authorization_scope": "source_bound_ad_discovery", "policy_mode": "lab_auto",
            "lab_exception_applied": True,
        }

    def execute(self, plan_ref: str, scheme_draft_ref: str,
                principal: V4PlanningPrincipal) -> dict[str, object]:
        try:
            if not self._enabled or type(principal) is not V4PlanningPrincipal:
                raise ValueError
            require_ref(plan_ref, "AD plan reference")
            require_ref(scheme_draft_ref, "AD draft reference")
            try:
                plan, draft = self._services.resolve_execution_context(plan_ref, scheme_draft_ref, principal)
            except Exception:
                return self._response(_reconciliation("fixed_action_context"), None)
            self._validate(plan, draft, plan_ref, principal)
            try:
                result = self._coordinator.execute(plan_ref, scheme_draft_ref, principal)
            except FixedActionResolutionError as exc:
                stage = exc.failure_stage if exc.failure_stage in _SAFE_FAILURE_STAGES else "fixed_action_resolution"
                result = _reconciliation(stage)
            except OnboardingActionCoordinatorError:
                result = _reconciliation("fixed_action_resolution")
            return self._response(result, plan.lines[0].line_ref)
        except Exception:
            raise V4AdDiscoveryExecutionRuntimeError(V4_AD_DISCOVERY_EXECUTION_UNAVAILABLE) from None
