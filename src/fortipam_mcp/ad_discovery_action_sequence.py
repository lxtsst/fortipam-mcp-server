"""One fixed BP014 Source line, independently authorized by standing lab policy."""

from typing import Protocol

from v4_planning import PreparedPlan, SchemeDraft

from .ad_discovery_projection_source import AdDiscoveryPlanningBinding, AdDiscoveryPlanningSource
from .onboarding_action_coordinator import (
    BoundFixedActionRunner, FixedActionResolutionError, ResolvedFixedActionSequence,
)
from .v4_plan_runtime import OAuthBoundV4PlanServices, V4PlanningPrincipal


class AdDiscoveryM4RunnerFactory(Protocol):
    def bind(self, plan: PreparedPlan, line_ref: str, principal: V4PlanningPrincipal, *,
             draft: SchemeDraft | None = None,
             discovery_binding: AdDiscoveryPlanningBinding | None = None) -> BoundFixedActionRunner: ...


class AdDiscoveryFixedActionSequenceResolver:
    def __init__(self, plan_services: OAuthBoundV4PlanServices,
                 projection_source: AdDiscoveryPlanningSource,
                 runner_factory: AdDiscoveryM4RunnerFactory) -> None:
        if type(projection_source) is not AdDiscoveryPlanningSource:
            raise FixedActionResolutionError("fixed_action_private_binding")
        self._services, self._source, self._factory = plan_services, projection_source, runner_factory

    def resolve(self, plan_ref: str, scheme_draft_ref: str,
                principal: V4PlanningPrincipal) -> ResolvedFixedActionSequence:
        try:
            plan, draft = self._services.resolve_execution_context(plan_ref, scheme_draft_ref, principal)
        except Exception:
            raise FixedActionResolutionError("fixed_action_context") from None
        return self.bind_prepared(plan, draft, principal)

    def bind_prepared(self, plan: PreparedPlan, draft: SchemeDraft,
                      principal: V4PlanningPrincipal) -> ResolvedFixedActionSequence:
        try:
            binding = self._source._binding
            digest = self._source.inspect_private_binding_digest(draft, principal.requester)
            if type(plan) is not PreparedPlan or len(plan.lines) != 1:
                raise ValueError
            line = plan.lines[0]
            runner = self._factory.bind(plan, line.line_ref, principal,
                draft=draft, discovery_binding=binding)
            if (runner.line_ref != line.line_ref or runner.depends_on
                or getattr(runner, "discovery_binding_digest", None) != digest):
                raise ValueError
            return ResolvedFixedActionSequence(plan.plan_ref, plan.requester_digest, (runner,))
        except FixedActionResolutionError:
            raise
        except Exception:
            raise FixedActionResolutionError("fixed_action_private_binding") from None
