"""Internal coordinator for one already-confirmed onboarding Scheme.

The coordinator does not turn an M3 plan into executable caller input.  A
trusted resolver must instead return the exact fixed-action runners whose
independent execution authorizations are already bound to that protected plan.
This module only supplies Scheme-level pre-write comparison, dependency order,
fail-closed stopping, and final Scheme-level readback.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .v4_plan_runtime import V4PlanningPrincipal


class OnboardingActionCoordinatorError(RuntimeError):
    """Raised when a protected action sequence is unavailable or malformed."""


_FAILURE_STAGES = frozenset(
    {
        "pre_write_projection",
        "fixed_action_resolution",
        "fixed_action_context",
        "fixed_action_private_binding",
        "fixed_action_plan_validation",
        "fixed_action_runner_binding",
        "fixed_action_runner_promotion",
        "fixed_action_runner_promotion_freshness",
        "fixed_action_runner_promotion_context",
        "fixed_action_runner_promotion_shape",
        "fixed_action_runner_promotion_material",
        "fixed_action_runner_material_binding",
        "fixed_action_runner_runtime_binding",
        "fixed_action_execution",
        "fixed_action_verification",
        "fixed_action_target_http_dispatch",
        "fixed_action_target_acknowledgement",
        "fixed_action_target_preview",
        "fixed_action_target_confirmation",
        "fixed_action_target_execution",
        "fixed_action_target_address_conflict",
        "post_write_projection",
        "post_write_comparison",
    }
)
_RUNNER_FAILURE_STAGE_MAP = {
    "target_create_post": "fixed_action_target_http_dispatch",
    "target_create_acknowledgement": "fixed_action_target_acknowledgement",
    "target_create_preview": "fixed_action_target_preview",
    "target_create_confirmation": "fixed_action_target_confirmation",
    "target_create_execution": "fixed_action_target_execution",
}


class FixedActionResolutionError(OnboardingActionCoordinatorError):
    """Value-free classification for a failed protected-action bind step."""

    def __init__(self, failure_stage: str, message: str | None = None) -> None:
        if failure_stage not in _FAILURE_STAGES or not failure_stage.startswith(
            "fixed_action_"
        ):
            raise OnboardingActionCoordinatorError(
                "Onboarding action failure stage is invalid."
            )
        super().__init__(message or "Protected fixed action resolution is unavailable.")
        self.failure_stage = failure_stage


class BoundFixedActionRunner(Protocol):
    """One exact action with its authorization and product binding kept private."""

    @property
    def line_ref(self) -> str: ...

    @property
    def depends_on(self) -> tuple[str, ...]: ...

    def execute_bound(self) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class ResolvedFixedActionSequence:
    """Value-free result of resolving all independently authorized plan lines."""

    plan_ref: str
    requester_digest: str
    runners: tuple[BoundFixedActionRunner, ...]


class FixedActionSequenceResolver(Protocol):
    """Resolve exact child authorizations without accepting action parameters."""

    def resolve(
        self,
        plan_ref: str,
        scheme_draft_ref: str,
        principal: V4PlanningPrincipal,
    ) -> ResolvedFixedActionSequence: ...


class SchemeComparisonServices(Protocol):
    """Source-backed comparison calls owned by the combined planning Host."""

    def evaluate_pre_write(
        self,
        plan_ref: str,
        scheme_draft_ref: str,
        principal: V4PlanningPrincipal,
    ) -> dict[str, object]: ...

    def evaluate_post_write(
        self,
        plan_ref: str,
        scheme_draft_ref: str,
        principal: V4PlanningPrincipal,
    ) -> dict[str, object]: ...


@dataclass(frozen=True, slots=True)
class OnboardingActionSequenceResult:
    outcome: str
    completed_line_refs: tuple[str, ...]
    stopped_line_ref: str | None
    pre_write_status: str
    post_write_status: str | None
    reconciliation_required: bool
    failure_stage: str | None = None

    def __post_init__(self) -> None:
        if self.failure_stage is not None and self.failure_stage not in _FAILURE_STAGES:
            raise OnboardingActionCoordinatorError(
                "Onboarding action failure stage is invalid."
            )

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "completed_line_refs": list(self.completed_line_refs),
            "outcome": self.outcome,
            "post_write_status": self.post_write_status,
            "pre_write_status": self.pre_write_status,
            "reconciliation_required": self.reconciliation_required,
            "stopped_line_ref": self.stopped_line_ref,
        }
        if self.failure_stage is not None:
            result["failure_stage"] = self.failure_stage
        return result


class DenyAllFixedActionSequenceResolver:
    """Default boundary: local Host composition has no execution authority."""

    def resolve(
        self,
        plan_ref: str,
        scheme_draft_ref: str,
        principal: V4PlanningPrincipal,
    ) -> ResolvedFixedActionSequence:
        del plan_ref, scheme_draft_ref, principal
        raise OnboardingActionCoordinatorError(
            "No protected fixed-action sequence resolver is configured."
        )


class OnboardingActionCoordinator:
    """Run one protected fixed-action DAG under one confirmed Scheme."""

    def __init__(
        self,
        comparisons: SchemeComparisonServices,
        resolver: FixedActionSequenceResolver | None = None,
    ) -> None:
        self._comparisons = comparisons
        self._resolver = resolver or DenyAllFixedActionSequenceResolver()

    def execute(
        self,
        plan_ref: str,
        scheme_draft_ref: str,
        principal: V4PlanningPrincipal,
    ) -> OnboardingActionSequenceResult:
        try:
            pre_write = self._comparisons.evaluate_pre_write(
                plan_ref,
                scheme_draft_ref,
                principal,
            )
        except Exception:
            return OnboardingActionSequenceResult(
                "reconciliation_required",
                (),
                None,
                "unavailable",
                None,
                True,
                "pre_write_projection",
            )
        try:
            pre_status = _status(pre_write, "pre-write")
        except OnboardingActionCoordinatorError:
            return OnboardingActionSequenceResult(
                "reconciliation_required",
                (),
                None,
                "unavailable",
                None,
                True,
                "pre_write_projection",
            )
        if pre_status != "match":
            return OnboardingActionSequenceResult(
                "precondition_failed",
                (),
                None,
                pre_status,
                None,
                False,
            )

        try:
            sequence = self._resolver.resolve(plan_ref, scheme_draft_ref, principal)
        except FixedActionResolutionError as exc:
            return OnboardingActionSequenceResult(
                "reconciliation_required",
                (),
                None,
                pre_status,
                None,
                True,
                exc.failure_stage,
            )
        except OnboardingActionCoordinatorError:
            raise
        except Exception:
            return OnboardingActionSequenceResult(
                "reconciliation_required",
                (),
                None,
                pre_status,
                None,
                True,
                "fixed_action_resolution",
            )
        try:
            self._validate_sequence(sequence, plan_ref, principal)
            ordered = self._dependency_order(sequence.runners)
        except OnboardingActionCoordinatorError:
            return OnboardingActionSequenceResult(
                "reconciliation_required",
                (),
                None,
                pre_status,
                None,
                True,
                "fixed_action_resolution",
            )

        completed: list[str] = []
        for runner in ordered:
            try:
                result = runner.execute_bound()
            except Exception:
                return OnboardingActionSequenceResult(
                    "reconciliation_required",
                    tuple(completed),
                    runner.line_ref,
                    pre_status,
                    None,
                    True,
                    "fixed_action_execution",
                )
            if not _verified_success(result):
                uncertain = (
                    result.get("outcome") == "reconciliation_required"
                    or result.get("verification") == "unknown"
                )
                runner_failure_stage = result.get("failure_stage")
                if (
                    runner_failure_stage == "target_create_post"
                    and result.get("failure_product_error_class")
                    == "duplicate_target_address"
                ):
                    failure_stage = "fixed_action_target_address_conflict"
                elif (
                    isinstance(runner_failure_stage, str)
                    and runner_failure_stage in _RUNNER_FAILURE_STAGE_MAP
                ):
                    failure_stage = _RUNNER_FAILURE_STAGE_MAP[runner_failure_stage]
                else:
                    failure_stage = "fixed_action_verification"
                return OnboardingActionSequenceResult(
                    "reconciliation_required" if uncertain else "execution_failed",
                    tuple(completed),
                    runner.line_ref,
                    pre_status,
                    None,
                    uncertain,
                    failure_stage,
                )
            completed.append(runner.line_ref)

        try:
            post_write = self._comparisons.evaluate_post_write(
                plan_ref,
                scheme_draft_ref,
                principal,
            )
        except Exception:
            return OnboardingActionSequenceResult(
                "reconciliation_required",
                tuple(completed),
                None,
                pre_status,
                "unavailable",
                True,
                "post_write_projection",
            )
        post_status = _status(post_write, "post-write")
        if post_status != "expected_state_matches":
            return OnboardingActionSequenceResult(
                "reconciliation_required",
                tuple(completed),
                None,
                pre_status,
                post_status,
                True,
                "post_write_comparison",
            )
        return OnboardingActionSequenceResult(
            "succeeded",
            tuple(completed),
            None,
            pre_status,
            post_status,
            False,
        )

    @staticmethod
    def _validate_sequence(
        sequence: ResolvedFixedActionSequence,
        plan_ref: str,
        principal: V4PlanningPrincipal,
    ) -> None:
        if sequence.plan_ref != plan_ref:
            raise OnboardingActionCoordinatorError(
                "Resolved action sequence does not match the requested plan."
            )
        if sequence.requester_digest != principal.requester.digest:
            raise OnboardingActionCoordinatorError(
                "Resolved action sequence does not match the authenticated requester."
            )
        if not sequence.runners:
            raise OnboardingActionCoordinatorError(
                "Resolved action sequence contains no fixed actions."
            )

    @staticmethod
    def _dependency_order(
        runners: tuple[BoundFixedActionRunner, ...],
    ) -> tuple[BoundFixedActionRunner, ...]:
        by_ref: dict[str, BoundFixedActionRunner] = {}
        for runner in runners:
            if not runner.line_ref or runner.line_ref in by_ref:
                raise OnboardingActionCoordinatorError(
                    "Fixed-action line references must be unique and non-empty."
                )
            by_ref[runner.line_ref] = runner
        for runner in runners:
            if runner.line_ref in runner.depends_on or any(
                dependency not in by_ref for dependency in runner.depends_on
            ):
                raise OnboardingActionCoordinatorError(
                    "Fixed-action dependencies are incomplete or self-referential."
                )

        pending = list(runners)
        completed: set[str] = set()
        ordered: list[BoundFixedActionRunner] = []
        while pending:
            ready = [
                runner
                for runner in pending
                if all(dependency in completed for dependency in runner.depends_on)
            ]
            if not ready:
                raise OnboardingActionCoordinatorError(
                    "Fixed-action dependencies contain a cycle."
                )
            for runner in ready:
                pending.remove(runner)
                completed.add(runner.line_ref)
                ordered.append(runner)
        return tuple(ordered)


def _status(result: Mapping[str, Any], phase: str) -> str:
    status = result.get("status")
    if not isinstance(status, str) or not status:
        raise OnboardingActionCoordinatorError(
            f"The {phase} comparison returned no categorical status."
        )
    return status


def _verified_success(result: Mapping[str, object]) -> bool:
    return result.get("outcome") == "succeeded" and result.get("verification") == "verified"


__all__ = [
    "BoundFixedActionRunner",
    "DenyAllFixedActionSequenceResolver",
    "FixedActionResolutionError",
    "FixedActionSequenceResolver",
    "OnboardingActionCoordinator",
    "OnboardingActionCoordinatorError",
    "OnboardingActionSequenceResult",
    "ResolvedFixedActionSequence",
    "SchemeComparisonServices",
]
