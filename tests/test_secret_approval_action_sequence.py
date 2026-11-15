from __future__ import annotations

from dataclasses import replace

import pytest

from fortipam_mcp.approval_and_observe_projection_source import (
    ApprovalAndObserveBinding,
)
from fortipam_mcp.secret_approval_action_sequence import (
    ExactSecretApprovalM4RunnerFactory,
    ProtectedSecretApprovalRunnerBinding,
    SecretApprovalFixedActionSequenceResolver,
)
from fortipam_mcp.onboarding_action_coordinator import (
    OnboardingActionCoordinatorError,
)
from fortipam_mcp.secret_approval_m4_runtime import (
    SECRET_APPROVAL_ACTION_ID,
    SECRET_APPROVAL_ACTION_VERSION,
    SECRET_APPROVAL_ADAPTER_REF,
    secret_approval_binding_digest,
    secret_approval_parameters_digest,
)
from test_v4_m3 import _plan, _requester
from test_v4_planning import _approval_and_observe_draft
from v4_planning import (
    ChangeKind,
    M4Compensation,
    M4ExecutionPlan,
    M4ExecutionResult,
    M4Outcome,
    M4Verification,
    ObjectClass,
    SchemeId,
    canonical_digest,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal


PLAN_REF = "approval-prepared-plan-ref01"
DRAFT_REF = "approval-scheme-draft-ref01"


def _binding() -> ApprovalAndObserveBinding:
    return ApprovalAndObserveBinding(
        approval_profile_object_ref="approval-profile-object-ref01",
        approval_profile_ref="approval-profile-ref0001",
        approval_profile_name="mcp-v4-approval-profile-01",
        secret_approval_object_ref="secret-approval-object-ref01",
        folder_path="Public/folder",
        secret_name="mcp-v4-secret-metadata-01",
        secret_id=42,
    )


def _context():
    requester = _requester()
    draft = _approval_and_observe_draft()
    base = _plan(requester)
    line = replace(
        base.lines[0],
        target_ref=_binding().secret_approval_object_ref,
        target_class=ObjectClass.SECRET_APPROVAL_BINDING,
        change_kind=ChangeKind.UPDATE,
        depends_on=(),
    )
    content = dict(base.canonical_content())
    content.update(
        {
            "environment_ref": draft.environment_ref,
            "lines": [line.as_dict()],
            "plan_ref": PLAN_REF,
            "scheme_id": SchemeId.APPROVAL_AND_OBSERVE.value,
            "scheme_version": draft.scheme_version,
            "scope_ref": draft.scope_ref,
        }
    )
    plan = replace(
        base,
        environment_ref=draft.environment_ref,
        lines=(line,),
        plan_ref=PLAN_REF,
        scheme_id=SchemeId.APPROVAL_AND_OBSERVE,
        scheme_version=draft.scheme_version,
        scope_ref=draft.scope_ref,
        plan_digest=canonical_digest(content),
    )
    principal = V4PlanningPrincipal(requester, "a" * 64)
    return principal, draft, plan


class _Services:
    def __init__(self) -> None:
        self.principal, self.draft, self.plan = _context()

    def resolve_execution_context(self, plan_ref, draft_ref, principal):
        assert (plan_ref, draft_ref, principal) == (
            PLAN_REF,
            DRAFT_REF,
            self.principal,
        )
        return self.plan, self.draft


class _Source:
    def resolve_private_binding(self, draft, requester):
        assert draft == _context()[1]
        assert requester == _context()[0].requester
        return _binding()


class _Runtime:
    def __init__(self, plan: M4ExecutionPlan) -> None:
        self.plan = plan
        self.calls: list[str] = []

    def inspect_execution_plan(self, authorization_ref: str) -> M4ExecutionPlan:
        assert authorization_ref == "approval-authorization-ref01"
        self.calls.append("inspect")
        return self.plan

    def execute_bound(
        self,
        authorization_ref: str,
        *,
        expected_approval_binding_digest: str,
    ) -> M4ExecutionResult:
        assert authorization_ref == "approval-authorization-ref01"
        assert expected_approval_binding_digest == secret_approval_binding_digest(
            _binding()
        )
        self.calls.append("execute")
        return M4ExecutionResult(
            M4Outcome.SUCCEEDED,
            M4Verification.VERIFIED,
            M4Compensation.NOT_REQUESTED,
            False,
        )

    def inspect_approval_binding_digest(self, authorization_ref: str) -> str:
        assert authorization_ref == "approval-authorization-ref01"
        return secret_approval_binding_digest(_binding())


def _m4_plan(plan) -> M4ExecutionPlan:
    line = plan.lines[0]
    parameters_digest = secret_approval_parameters_digest(_binding())
    content = {
        "action_id": SECRET_APPROVAL_ACTION_ID,
        "action_version": SECRET_APPROVAL_ACTION_VERSION,
        "adapter_ref": SECRET_APPROVAL_ADAPTER_REF,
        "approval_digest": "b" * 64,
        "compensation_ref": None,
        "confirmation_digest": plan.confirmation_digest,
        "expected_current_digest": line.expected_current_digest,
        "expected_state_digest": line.expected_state_digest,
        "expires_at": plan.expires_at,
        "idempotency_digest": "3" * 64,
        "parameters_digest": parameters_digest,
        "plan_ref": plan.plan_ref,
        "requester_digest": plan.requester_digest,
        "revision": plan.revision,
        "summary_digest": plan.summary_digest,
        "target_ref": line.target_ref,
    }
    return M4ExecutionPlan(
        plan_ref=plan.plan_ref,
        revision=plan.revision,
        action_id=SECRET_APPROVAL_ACTION_ID,
        action_version=SECRET_APPROVAL_ACTION_VERSION,
        adapter_ref=SECRET_APPROVAL_ADAPTER_REF,
        target_ref=line.target_ref,
        requester_digest=plan.requester_digest,
        summary_digest=plan.summary_digest,
        confirmation_digest=plan.confirmation_digest,
        approval_digest="b" * 64,
        parameters_digest=parameters_digest,
        expected_current_digest=line.expected_current_digest,
        expected_state_digest=line.expected_state_digest,
        idempotency_digest="3" * 64,
        expires_at=plan.expires_at,
        compensation_ref=None,
        plan_digest=canonical_digest(content),
    )


def test_resolver_binds_one_exact_secret_approval_update_and_safe_readback() -> None:
    services = _Services()
    runtime = _Runtime(_m4_plan(services.plan))
    factory = ExactSecretApprovalM4RunnerFactory(
        ProtectedSecretApprovalRunnerBinding(
            services.plan.plan_digest,
            services.plan.lines[0].line_ref,
            services.plan.requester_digest,
            "approval-authorization-ref01",
            secret_approval_binding_digest(_binding()),
            runtime,
        )
    )
    resolver = SecretApprovalFixedActionSequenceResolver(
        services,  # type: ignore[arg-type]
        _Source(),  # type: ignore[arg-type]
        factory,
    )

    sequence = resolver.resolve(PLAN_REF, DRAFT_REF, services.principal)
    result = sequence.runners[0].execute_bound()

    assert runtime.calls == ["inspect", "execute"]
    assert result == {
        "outcome": "succeeded",
        "verification": "verified",
        "compensation": "not_requested",
        "idempotent_replay": False,
    }


def test_resolver_rejects_private_selector_binding_drift() -> None:
    services = _Services()
    runtime = _Runtime(_m4_plan(services.plan))
    factory = ExactSecretApprovalM4RunnerFactory(
        ProtectedSecretApprovalRunnerBinding(
            services.plan.plan_digest,
            services.plan.lines[0].line_ref,
            services.plan.requester_digest,
            "approval-authorization-ref01",
            "0" * 64,
            runtime,
        )
    )
    resolver = SecretApprovalFixedActionSequenceResolver(
        services,  # type: ignore[arg-type]
        _Source(),  # type: ignore[arg-type]
        factory,
    )

    with pytest.raises(OnboardingActionCoordinatorError):
        resolver.resolve(PLAN_REF, DRAFT_REF, services.principal)

    assert runtime.calls == []


def test_resolver_rejects_m4_parameter_binding_drift() -> None:
    services = _Services()
    m4_plan = _m4_plan(services.plan)
    content = dict(m4_plan.canonical_content())
    content["parameters_digest"] = "0" * 64
    runtime = _Runtime(
        replace(
            m4_plan,
            parameters_digest="0" * 64,
            plan_digest=canonical_digest(content),
        )
    )
    factory = ExactSecretApprovalM4RunnerFactory(
        ProtectedSecretApprovalRunnerBinding(
            services.plan.plan_digest,
            services.plan.lines[0].line_ref,
            services.plan.requester_digest,
            "approval-authorization-ref01",
            secret_approval_binding_digest(_binding()),
            runtime,
        )
    )
    resolver = SecretApprovalFixedActionSequenceResolver(
        services,  # type: ignore[arg-type]
        _Source(),  # type: ignore[arg-type]
        factory,
    )

    with pytest.raises(OnboardingActionCoordinatorError):
        resolver.resolve(PLAN_REF, DRAFT_REF, services.principal)

    assert runtime.calls == ["inspect"]
