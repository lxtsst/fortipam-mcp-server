from __future__ import annotations

from dataclasses import dataclass

import pytest

from fortipam_mcp.onboarding_action_coordinator import (
    FixedActionResolutionError,
    OnboardingActionCoordinator,
    OnboardingActionCoordinatorError,
    ResolvedFixedActionSequence,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from fortipam_mcp.v4_runtime_host import V4PlanHostComponents
from test_v4_m3 import _requester


PLAN_REF = "scheme-plan-reference-0001"
DRAFT_REF = "scheme-draft-reference-001"


@dataclass
class _Runner:
    line_ref: str
    depends_on: tuple[str, ...]
    calls: list[str]
    outcome: str = "succeeded"
    verification: str = "verified"
    raises: bool = False
    failure_stage: str | None = None
    failure_product_error_class: str | None = None

    def execute_bound(self) -> dict[str, object]:
        self.calls.append(self.line_ref)
        if self.raises:
            raise RuntimeError("result unavailable")
        result: dict[str, object] = {
            "outcome": self.outcome,
            "verification": self.verification,
        }
        if self.failure_stage is not None:
            result["failure_stage"] = self.failure_stage
        if self.failure_product_error_class is not None:
            result["failure_product_error_class"] = self.failure_product_error_class
        return result


class _Resolver:
    def __init__(self, runners: tuple[_Runner, ...], *, raises: bool = False) -> None:
        self.runners = runners
        self.raises = raises
        self.calls = 0

    def resolve(
        self,
        plan_ref: str,
        scheme_draft_ref: str,
        principal: V4PlanningPrincipal,
    ) -> ResolvedFixedActionSequence:
        assert plan_ref == PLAN_REF
        assert scheme_draft_ref == DRAFT_REF
        self.calls += 1
        if self.raises:
            raise RuntimeError("private action binding unavailable")
        return ResolvedFixedActionSequence(
            plan_ref,
            principal.requester.digest,
            self.runners,
        )


class _Comparisons:
    def __init__(
        self,
        *,
        pre: str = "match",
        post: str = "expected_state_matches",
        raises_pre: bool = False,
        raises_post: bool = False,
    ) -> None:
        self.pre = pre
        self.post = post
        self.raises_pre = raises_pre
        self.raises_post = raises_post
        self.calls: list[str] = []

    def evaluate_pre_write(
        self,
        plan_ref: str,
        scheme_draft_ref: str,
        principal: V4PlanningPrincipal,
    ) -> dict[str, object]:
        del plan_ref, scheme_draft_ref, principal
        self.calls.append("pre")
        if self.raises_pre:
            raise RuntimeError("private pre-write projection unavailable")
        return {"status": self.pre}

    def evaluate_post_write(
        self,
        plan_ref: str,
        scheme_draft_ref: str,
        principal: V4PlanningPrincipal,
    ) -> dict[str, object]:
        del plan_ref, scheme_draft_ref, principal
        self.calls.append("post")
        if self.raises_post:
            raise RuntimeError("postcondition unavailable")
        return {"status": self.post}


def _principal() -> V4PlanningPrincipal:
    return V4PlanningPrincipal(_requester(), "a" * 64)


def test_executes_one_resolved_sequence_in_dependency_order() -> None:
    calls: list[str] = []
    runners = (
        _Runner("line-acl-0001", ("line-folder-0001",), calls),
        _Runner("line-folder-0001", (), calls),
    )
    resolver = _Resolver(runners)
    comparisons = _Comparisons()

    result = OnboardingActionCoordinator(comparisons, resolver).execute(
        PLAN_REF, DRAFT_REF, _principal()
    )

    assert result.outcome == "succeeded"
    assert result.completed_line_refs == ("line-folder-0001", "line-acl-0001")
    assert calls == ["line-folder-0001", "line-acl-0001"]
    assert comparisons.calls == ["pre", "post"]
    assert resolver.calls == 1


def test_prewrite_drift_stops_before_every_action() -> None:
    calls: list[str] = []
    runner = _Runner("line-folder-0001", (), calls)
    comparisons = _Comparisons(pre="invalidated")

    result = OnboardingActionCoordinator(
        comparisons, _Resolver((runner,))
    ).execute(PLAN_REF, DRAFT_REF, _principal())

    assert result.outcome == "precondition_failed"
    assert calls == []
    assert comparisons.calls == ["pre"]


def test_unavailable_prewrite_returns_a_fixed_non_disclosing_stage() -> None:
    calls: list[str] = []
    runner = _Runner("line-folder-0001", (), calls)
    comparisons = _Comparisons(raises_pre=True)

    result = OnboardingActionCoordinator(
        comparisons, _Resolver((runner,))
    ).execute(PLAN_REF, DRAFT_REF, _principal())

    assert result.outcome == "reconciliation_required"
    assert result.failure_stage == "pre_write_projection"
    assert result.completed_line_refs == ()
    assert calls == []


def test_invalid_prewrite_category_returns_projection_stage_without_escaping() -> None:
    comparisons = _Comparisons(pre="")
    calls: list[str] = []

    result = OnboardingActionCoordinator(
        comparisons, _Resolver((_Runner("line-folder-0001", (), calls),))
    ).execute(PLAN_REF, DRAFT_REF, _principal())

    assert result.outcome == "reconciliation_required"
    assert result.failure_stage == "pre_write_projection"
    assert result.pre_write_status == "unavailable"
    assert calls == []


def test_unavailable_action_resolution_returns_a_fixed_non_disclosing_stage() -> None:
    calls: list[str] = []
    resolver = _Resolver((_Runner("line-folder-0001", (), calls),), raises=True)

    result = OnboardingActionCoordinator(
        _Comparisons(), resolver
    ).execute(PLAN_REF, DRAFT_REF, _principal())

    assert result.outcome == "reconciliation_required"
    assert result.failure_stage == "fixed_action_resolution"
    assert result.completed_line_refs == ()
    assert calls == []


def test_resolution_can_report_one_safe_internal_binding_stage() -> None:
    class _SafeStageResolver:
        def resolve(
            self,
            plan_ref: str,
            scheme_draft_ref: str,
            principal: V4PlanningPrincipal,
        ) -> ResolvedFixedActionSequence:
            del plan_ref, scheme_draft_ref, principal
            raise FixedActionResolutionError("fixed_action_runner_binding")

    result = OnboardingActionCoordinator(
        _Comparisons(), _SafeStageResolver()
    ).execute(PLAN_REF, DRAFT_REF, _principal())

    assert result.outcome == "reconciliation_required"
    assert result.failure_stage == "fixed_action_runner_binding"
    assert result.completed_line_refs == ()


@pytest.mark.parametrize(
    "runners",
    [
        (
            _Runner("line-folder-0001", ("line-acl-0001",), []),
            _Runner("line-acl-0001", ("line-folder-0001",), []),
        ),
        (
            _Runner("line-folder-0001", (), []),
            _Runner("line-folder-0001", (), []),
        ),
    ],
)
def test_invalid_sequence_returns_resolution_stage_without_running_action(runners) -> None:
    calls: list[str] = []
    for runner in runners:
        runner.calls = calls

    result = OnboardingActionCoordinator(
        _Comparisons(), _Resolver(runners)
    ).execute(PLAN_REF, DRAFT_REF, _principal())

    assert result.outcome == "reconciliation_required"
    assert result.failure_stage == "fixed_action_resolution"
    assert result.completed_line_refs == ()
    assert calls == []


def test_uncertain_action_stops_dependents_and_requires_reconciliation() -> None:
    calls: list[str] = []
    runners = (
        _Runner(
            "line-folder-0001",
            (),
            calls,
            outcome="reconciliation_required",
            verification="unknown",
        ),
        _Runner("line-acl-0001", ("line-folder-0001",), calls),
    )

    result = OnboardingActionCoordinator(
        _Comparisons(), _Resolver(runners)
    ).execute(PLAN_REF, DRAFT_REF, _principal())

    assert result.outcome == "reconciliation_required"
    assert result.reconciliation_required is True
    assert result.stopped_line_ref == "line-folder-0001"
    assert result.failure_stage == "fixed_action_verification"
    assert calls == ["line-folder-0001"]


@pytest.mark.parametrize(
    ("runner_stage", "expected_stage"),
    [
        ("target_create_post", "fixed_action_target_http_dispatch"),
        ("target_create_preview", "fixed_action_target_preview"),
        ("target_create_confirmation", "fixed_action_target_confirmation"),
        ("target_create_execution", "fixed_action_target_execution"),
        (
            "target_create_acknowledgement",
            "fixed_action_target_acknowledgement",
        ),
        ("unrecognized-private-detail", "fixed_action_verification"),
    ],
)
def test_runner_failure_stage_is_narrowly_allowlisted(
    runner_stage: str,
    expected_stage: str,
) -> None:
    calls: list[str] = []
    runner = _Runner(
        "line-target-0001",
        (),
        calls,
        outcome="reconciliation_required",
        verification="unknown",
        failure_stage=runner_stage,
    )

    result = OnboardingActionCoordinator(
        _Comparisons(), _Resolver((runner,))
    ).execute(PLAN_REF, DRAFT_REF, _principal())

    assert result.outcome == "reconciliation_required"
    assert result.failure_stage == expected_stage
    assert calls == ["line-target-0001"]


def test_target_duplicate_address_result_is_narrowly_classified() -> None:
    calls: list[str] = []
    runner = _Runner(
        "line-target-0001",
        (),
        calls,
        outcome="reconciliation_required",
        verification="unknown",
        failure_stage="target_create_post",
        failure_product_error_class="duplicate_target_address",
    )

    result = OnboardingActionCoordinator(
        _Comparisons(), _Resolver((runner,))
    ).execute(PLAN_REF, DRAFT_REF, _principal())

    assert result.failure_stage == "fixed_action_target_address_conflict"
    assert "failure_product_error_class" not in result.as_dict()
    assert calls == ["line-target-0001"]


def test_runner_exception_returns_a_fixed_non_disclosing_stage() -> None:
    calls: list[str] = []
    result = OnboardingActionCoordinator(
        _Comparisons(),
        _Resolver((_Runner("line-folder-0001", (), calls, raises=True),)),
    ).execute(PLAN_REF, DRAFT_REF, _principal())

    assert result.outcome == "reconciliation_required"
    assert result.failure_stage == "fixed_action_execution"
    assert result.completed_line_refs == ()
    assert calls == ["line-folder-0001"]


def test_postwrite_mismatch_never_claims_scheme_success() -> None:
    calls: list[str] = []
    comparisons = _Comparisons(post="expected_state_mismatch")
    result = OnboardingActionCoordinator(
        comparisons,
        _Resolver((_Runner("line-target-0001", (), calls),)),
    ).execute(PLAN_REF, DRAFT_REF, _principal())

    assert result.outcome == "reconciliation_required"
    assert result.completed_line_refs == ("line-target-0001",)
    assert result.post_write_status == "expected_state_mismatch"
    assert result.failure_stage == "post_write_comparison"


def test_postwrite_read_failure_requires_reconciliation() -> None:
    calls: list[str] = []
    result = OnboardingActionCoordinator(
        _Comparisons(raises_post=True),
        _Resolver((_Runner("line-target-0001", (), calls),)),
    ).execute(PLAN_REF, DRAFT_REF, _principal())

    assert result.outcome == "reconciliation_required"
    assert result.completed_line_refs == ("line-target-0001",)
    assert result.post_write_status == "unavailable"
    assert result.reconciliation_required is True
    assert result.failure_stage == "post_write_projection"


def test_rejects_incomplete_or_cyclic_dependencies_before_prewrite() -> None:
    comparisons = _Comparisons()
    missing = (_Runner("line-acl-0001", ("line-folder-0001",), []),)
    missing_result = OnboardingActionCoordinator(
        comparisons, _Resolver(missing)
    ).execute(PLAN_REF, DRAFT_REF, _principal())
    assert missing_result.outcome == "reconciliation_required"
    assert missing_result.failure_stage == "fixed_action_resolution"
    assert missing_result.completed_line_refs == ()

    cyclic = (
        _Runner("line-folder-0001", ("line-acl-0001",), []),
        _Runner("line-acl-0001", ("line-folder-0001",), []),
    )
    cyclic_result = OnboardingActionCoordinator(
        comparisons, _Resolver(cyclic)
    ).execute(PLAN_REF, DRAFT_REF, _principal())
    assert cyclic_result.outcome == "reconciliation_required"
    assert cyclic_result.failure_stage == "fixed_action_resolution"
    assert cyclic_result.completed_line_refs == ()
    assert comparisons.calls == ["pre", "pre"]


def test_host_components_bind_internal_coordinator_without_tool_registration() -> None:
    comparisons = _Comparisons()
    resolver = _Resolver((_Runner("line-folder-0001", (), []),))
    components = V4PlanHostComponents(  # type: ignore[arg-type]
        plan_services=comparisons,
        confirmation_service=object(),
    )

    coordinator = components.bind_onboarding_action_coordinator(resolver)

    assert isinstance(coordinator, OnboardingActionCoordinator)
