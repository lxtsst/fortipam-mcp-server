from __future__ import annotations

import asyncio
from types import SimpleNamespace

from mcp import Client
import pytest

from fortipam_mcp import server as server_module
from fortipam_mcp.onboarding_action_coordinator import (
    OnboardingActionSequenceResult,
)
from fortipam_mcp.onboarding_execution_mcp_action import (
    ProtectedAccessDomainOnboardingMcpAction,
    ProtectedSecretOnboardingMcpAction,
    V4_ACCESS_DOMAIN_EXECUTION_TOOL,
    V4_ONBOARDING_EXECUTION_UNAVAILABLE,
    V4_SECRET_ONBOARDING_EXECUTION_TOOL,
    V4OnboardingExecutionRuntimeError,
)
from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from v4_planning import AuthenticatedRequester, SchemeId


PLAN_REF = "onboarding-plan-ref0001"
DRAFT_REF = "onboarding-draft-ref001"
ENVIRONMENT_REF = "onboarding-environment-ref01"
SCOPE_REF = "onboarding-scope-ref001"


class _PlanServices:
    def __init__(
        self,
        principal: V4PlanningPrincipal,
        scheme_id: SchemeId,
        blueprint_ref: str,
        outcome_code: str,
    ) -> None:
        self.calls: list[tuple[str, str, object]] = []
        self.plan = SimpleNamespace(
            plan_ref=PLAN_REF,
            requester_digest=principal.requester.digest,
            scheme_id=scheme_id,
            environment_ref=ENVIRONMENT_REF,
            scope_ref=SCOPE_REF,
        )
        self.draft = SimpleNamespace(
            scheme_id=scheme_id,
            blueprint_ref=blueprint_ref,
            outcome_code=outcome_code,
            environment_ref=ENVIRONMENT_REF,
            scope_ref=SCOPE_REF,
        )

    def resolve_execution_context(self, plan_ref, scheme_draft_ref, principal):
        self.calls.append((plan_ref, scheme_draft_ref, principal))
        return self.plan, self.draft


class _Coordinator:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, object]] = []

    def execute(self, plan_ref, scheme_draft_ref, principal):
        self.calls.append((plan_ref, scheme_draft_ref, principal))
        return OnboardingActionSequenceResult(
            "succeeded",
            ("fixed-line-ref0001",),
            None,
            "match",
            "expected_state_matches",
            False,
        )


def _principal() -> V4PlanningPrincipal:
    return V4PlanningPrincipal(
        AuthenticatedRequester("onboarding-requester-ref01", "operator"),
        "a" * 64,
    )


def _actions(principal: V4PlanningPrincipal, *, execution_enabled: bool):
    access_services = _PlanServices(
        principal,
        SchemeId.ACCESS_DOMAIN,
        "FPA-BP-004",
        "establish_access_domain",
    )
    secret_services = _PlanServices(
        principal,
        SchemeId.SECRET_ONBOARDING,
        "FPA-BP-005",
        "onboard_privileged_resource",
    )
    access_coordinator = _Coordinator()
    secret_coordinator = _Coordinator()
    access_action = ProtectedAccessDomainOnboardingMcpAction(
        access_services,  # type: ignore[arg-type]
        access_coordinator,  # type: ignore[arg-type]
        authorized_environment_ref=ENVIRONMENT_REF,
        authorized_scope_ref=SCOPE_REF,
        execution_enabled=execution_enabled,
    )
    secret_action = ProtectedSecretOnboardingMcpAction(
        secret_services,  # type: ignore[arg-type]
        secret_coordinator,  # type: ignore[arg-type]
        authorized_environment_ref=ENVIRONMENT_REF,
        authorized_scope_ref=SCOPE_REF,
        execution_enabled=execution_enabled,
    )
    return (
        access_action,
        secret_action,
        access_services,
        secret_services,
        access_coordinator,
        secret_coordinator,
    )


def test_execution_gate_denies_before_plan_or_coordinator_resolution() -> None:
    principal = _principal()
    access_action, _, services, _, coordinator, _ = _actions(
        principal,
        execution_enabled=False,
    )

    with pytest.raises(
        V4OnboardingExecutionRuntimeError,
        match=V4_ONBOARDING_EXECUTION_UNAVAILABLE,
    ):
        access_action.execute(PLAN_REF, DRAFT_REF, principal)

    assert services.calls == []
    assert coordinator.calls == []

    (
        enabled_action,
        _,
        environment_services,
        _,
        environment_coordinator,
        _,
    ) = _actions(principal, execution_enabled=True)
    environment_services.plan.environment_ref = "wrong-environment-ref01"
    with pytest.raises(V4OnboardingExecutionRuntimeError):
        enabled_action.execute(PLAN_REF, DRAFT_REF, principal)
    assert len(environment_services.calls) == 1
    assert environment_coordinator.calls == []

    (
        scope_action,
        _,
        scope_services,
        _,
        scope_coordinator,
        _,
    ) = _actions(principal, execution_enabled=True)
    scope_services.draft.scope_ref = "wrong-scope-ref0001"
    with pytest.raises(V4OnboardingExecutionRuntimeError):
        scope_action.execute(PLAN_REF, DRAFT_REF, principal)
    assert len(scope_services.calls) == 1
    assert scope_coordinator.calls == []


def test_secret_execution_action_accepts_exact_windows_rdp_profile() -> None:
    principal = _principal()
    services = _PlanServices(
        principal,
        SchemeId.SECRET_ONBOARDING,
        "FPA-BP-006",
        "onboard_windows_rdp_resource",
    )
    coordinator = _Coordinator()
    action = ProtectedSecretOnboardingMcpAction(
        services,  # type: ignore[arg-type]
        coordinator,  # type: ignore[arg-type]
        authorized_environment_ref=ENVIRONMENT_REF,
        authorized_scope_ref=SCOPE_REF,
        execution_enabled=True,
    )

    result = action.execute(PLAN_REF, DRAFT_REF, principal)

    assert result["outcome"] == "succeeded"
    assert coordinator.calls == [(PLAN_REF, DRAFT_REF, principal)]


def test_server_exposes_only_dual_opt_in_exact_onboarding_entrypoints(
    monkeypatch,
) -> None:
    principal = _principal()
    (
        access_action,
        secret_action,
        access_services,
        secret_services,
        access_coordinator,
        secret_coordinator,
    ) = _actions(principal, execution_enabled=True)

    default_server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_http_oauth=True,
    )
    with pytest.raises(RuntimeError, match="only by the v4-controlled profile"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_PLAN_ONLY,
            v4_access_domain_execution_action=access_action,
            v4_secret_onboarding_execution_action=secret_action,
            v4_onboarding_execution_enabled=True,
            v4_http_oauth=True,
        )
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_access_domain_execution_action=access_action,
        v4_secret_onboarding_execution_action=secret_action,
        v4_onboarding_execution_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(
        server,
        "_v4_onboarding_execution_principal",
        lambda: principal,
    )

    async def _exercise():
        async with Client(default_server.mcp) as client:
            default_tools = {tool.name for tool in (await client.list_tools()).tools}
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            access_result = await client.call_tool(
                V4_ACCESS_DOMAIN_EXECUTION_TOOL,
                {"plan_ref": PLAN_REF, "scheme_draft_ref": DRAFT_REF},
            )
            secret_result = await client.call_tool(
                V4_SECRET_ONBOARDING_EXECUTION_TOOL,
                {"plan_ref": PLAN_REF, "scheme_draft_ref": DRAFT_REF},
            )
            rejected = await client.call_tool(
                V4_ACCESS_DOMAIN_EXECUTION_TOOL,
                {
                    "plan_ref": PLAN_REF,
                    "scheme_draft_ref": DRAFT_REF,
                    "child_action": "caller-controlled",
                },
            )
        return default_tools, tools.tools, access_result, secret_result, rejected

    default_tools, tools, access_result, secret_result, rejected = asyncio.run(
        _exercise()
    )
    by_name = {tool.name: tool for tool in tools}
    assert V4_ACCESS_DOMAIN_EXECUTION_TOOL not in default_tools
    assert V4_SECRET_ONBOARDING_EXECUTION_TOOL not in default_tools
    assert set(by_name[V4_ACCESS_DOMAIN_EXECUTION_TOOL].input_schema["properties"]) == {
        "plan_ref",
        "scheme_draft_ref",
    }
    assert set(by_name[V4_SECRET_ONBOARDING_EXECUTION_TOOL].input_schema["properties"]) == {
        "plan_ref",
        "scheme_draft_ref",
    }
    assert access_result.structured_content["outcome"] == "succeeded"
    assert secret_result.structured_content["outcome"] == "succeeded"
    for result in (access_result.structured_content, secret_result.structured_content):
        assert result["policy_mode"] == "lab_auto"
        assert result["lab_exception_applied"] is True
        assert result["authorization_scope"] == "source_bound_onboarding"
    assert rejected.is_error is True
    expected_call = (PLAN_REF, DRAFT_REF, principal)
    assert access_services.calls == [expected_call]
    assert secret_services.calls == [expected_call]
    assert access_coordinator.calls == [expected_call]
    assert secret_coordinator.calls == [expected_call]
