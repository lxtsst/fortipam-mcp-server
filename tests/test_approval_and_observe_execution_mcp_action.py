from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace

from mcp import Client
import pytest

from fortipam_mcp import http_server as http_server_module
from fortipam_mcp import server as server_module
from fortipam_mcp.approval_and_observe_execution_mcp_action import (
    ProtectedApprovalAndObserveMcpAction,
    V4_APPROVAL_AND_OBSERVE_EXECUTION_FEATURE_ENV,
    V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOL,
    V4_APPROVAL_AND_OBSERVE_EXECUTION_UNAVAILABLE,
    V4ApprovalAndObserveExecutionConfigurationError,
    V4ApprovalAndObserveExecutionRuntimeError,
    load_v4_approval_and_observe_execution_feature,
)
from fortipam_mcp.onboarding_action_coordinator import (
    OnboardingActionSequenceResult,
)
from fortipam_mcp.http_server import HttpConfigurationError, HttpServerSettings
from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV, RuntimeProfile
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from fortipam_mcp.v4_runtime_host import (
    V4PlanHostComponents,
    V4_SYNTHETIC_HOST_MODE_ENV,
    synthetic_v4_plan_host_factory,
)
from test_http_server import _v4_bound_environment
from v4_planning import AuthenticatedRequester, SchemeId


PLAN_REF = "approval-plan-reference01"
DRAFT_REF = "approval-draft-reference1"
ENVIRONMENT_REF = "approval-environment-ref01"
SCOPE_REF = "approval-scope-reference01"


class _NeverCalled:
    def __init__(self) -> None:
        self.calls = 0

    def resolve_execution_context(self, *args: object) -> None:
        self.calls += 1

    def execute(self, *args: object) -> None:
        self.calls += 1


class _PlanServices:
    def __init__(self, principal: V4PlanningPrincipal) -> None:
        self.calls: list[tuple[str, str, object]] = []
        self.plan = SimpleNamespace(
            plan_ref=PLAN_REF,
            requester_digest=principal.requester.digest,
            scheme_id=SchemeId.APPROVAL_AND_OBSERVE,
            environment_ref=ENVIRONMENT_REF,
            scope_ref=SCOPE_REF,
        )
        self.draft = SimpleNamespace(
            scheme_id=SchemeId.APPROVAL_AND_OBSERVE,
            blueprint_ref="FPA-BP-008",
            outcome_code="require_interactive_approval",
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
        AuthenticatedRequester("approval-requester-ref01", "operator"),
        "a" * 64,
    )


def _action(principal: V4PlanningPrincipal) -> tuple[
    ProtectedApprovalAndObserveMcpAction,
    _PlanServices,
    _Coordinator,
]:
    services = _PlanServices(principal)
    coordinator = _Coordinator()
    action = ProtectedApprovalAndObserveMcpAction(
        services,  # type: ignore[arg-type]
        coordinator,  # type: ignore[arg-type]
        authorized_environment_ref=ENVIRONMENT_REF,
        authorized_scope_ref=SCOPE_REF,
        execution_enabled=True,
    )
    return action, services, coordinator


def test_default_execution_gate_denies_before_plan_or_runner_resolution() -> None:
    services = _NeverCalled()
    coordinator = _NeverCalled()
    action = ProtectedApprovalAndObserveMcpAction(
        services,  # type: ignore[arg-type]
        coordinator,  # type: ignore[arg-type]
        authorized_environment_ref="approval-environment-ref01",
        authorized_scope_ref="approval-scope-reference01",
    )
    principal = V4PlanningPrincipal(
        AuthenticatedRequester("approval-requester-ref01", "operator"),
        "a" * 64,
    )

    with pytest.raises(
        V4ApprovalAndObserveExecutionRuntimeError,
        match=V4_APPROVAL_AND_OBSERVE_EXECUTION_UNAVAILABLE,
    ):
        action.execute(
            PLAN_REF,
            DRAFT_REF,
            principal,
        )

    assert services.calls == 0
    assert coordinator.calls == 0


def test_feature_opt_in_is_exact_and_defaults_off() -> None:
    assert load_v4_approval_and_observe_execution_feature({}) is False
    assert (
        load_v4_approval_and_observe_execution_feature(
            {V4_APPROVAL_AND_OBSERVE_EXECUTION_FEATURE_ENV: "false"}
        )
        is False
    )
    assert (
        load_v4_approval_and_observe_execution_feature(
            {V4_APPROVAL_AND_OBSERVE_EXECUTION_FEATURE_ENV: "true"}
        )
        is True
    )
    with pytest.raises(
        V4ApprovalAndObserveExecutionConfigurationError,
        match="exactly true or false",
    ):
        load_v4_approval_and_observe_execution_feature(
            {V4_APPROVAL_AND_OBSERVE_EXECUTION_FEATURE_ENV: "TRUE"}
        )


def test_server_registers_only_the_exact_opted_in_approval_tool(monkeypatch) -> None:
    principal = _principal()
    action, services, coordinator = _action(principal)
    default_server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_http_oauth=True,
    )
    with pytest.raises(RuntimeError, match="only by the v4-controlled profile"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_PLAN_ONLY,
            v4_approval_and_observe_execution_action=action,
            v4_approval_and_observe_execution_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_approval_and_observe_execution_action=action,
            v4_http_oauth=True,
        )
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_approval_and_observe_execution_action=action,
        v4_approval_and_observe_execution_enabled=True,
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
            result = await client.call_tool(
                V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOL,
                {"plan_ref": PLAN_REF, "scheme_draft_ref": DRAFT_REF},
            )
            rejected = await client.call_tool(
                V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOL,
                {
                    "plan_ref": PLAN_REF,
                    "scheme_draft_ref": DRAFT_REF,
                    "approval_receipt": "caller-controlled",
                },
            )
        return default_tools, tools.tools, result, rejected

    default_tools, tools, result, rejected = asyncio.run(_exercise())
    by_name = {tool.name: tool for tool in tools}
    assert V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOL not in default_tools
    assert set(
        by_name[V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOL].input_schema["properties"]
    ) == {"plan_ref", "scheme_draft_ref"}
    assert result.structured_content["outcome"] == "succeeded"
    assert result.structured_content["policy_mode"] == "independent_approval"
    assert (
        result.structured_content["authorization_scope"]
        == "source_bound_approval_workflow"
    )
    assert rejected.is_error is True
    expected_call = (PLAN_REF, DRAFT_REF, principal)
    assert services.calls == [expected_call]
    assert coordinator.calls == [expected_call]


def test_http_composition_requires_and_registers_one_trusted_approval_factory(
    tmp_path,
    monkeypatch,
) -> None:
    environment, host_settings = _v4_bound_environment(tmp_path)
    environment.update(
        {
            RUNTIME_PROFILE_ENV: "v4-controlled",
            V4_SYNTHETIC_HOST_MODE_ENV: "source-backed-approval-and-observe",
        }
    )
    disabled_settings = HttpServerSettings.from_environment(environment)
    enabled_settings = HttpServerSettings.from_environment(
        {
            **environment,
            V4_APPROVAL_AND_OBSERVE_EXECUTION_FEATURE_ENV: "true",
        }
    )
    base_host_factory = synthetic_v4_plan_host_factory(host_settings)

    def host_factory(provider, confirmation_settings) -> V4PlanHostComponents:
        return replace(
            base_host_factory(provider, confirmation_settings),
            approval_and_observe_projection_source=object(),  # type: ignore[arg-type]
        )

    def execution_factory(components: V4PlanHostComponents):
        return ProtectedApprovalAndObserveMcpAction(
            components.plan_services,
            _NeverCalled(),  # type: ignore[arg-type]
            authorized_environment_ref=ENVIRONMENT_REF,
            authorized_scope_ref=SCOPE_REF,
        )

    servers: list[server_module.FortiPamMcpServer] = []
    real_server = server_module.FortiPamMcpServer

    def capture_server(**kwargs):
        server = real_server(**kwargs)
        servers.append(server)
        return server

    monkeypatch.setattr(http_server_module, "FortiPamMcpServer", capture_server)

    with pytest.raises(HttpConfigurationError, match="feature is disabled"):
        http_server_module.create_http_app(
            disabled_settings,
            v4_plan_host_factory=host_factory,
            v4_approval_and_observe_execution_factory=execution_factory,
        )
    with pytest.raises(HttpConfigurationError, match="trusted execution factory"):
        http_server_module.create_http_app(
            enabled_settings,
            v4_plan_host_factory=host_factory,
        )
    with pytest.raises(HttpConfigurationError, match="invalid binding"):
        http_server_module.create_http_app(
            enabled_settings,
            v4_plan_host_factory=host_factory,
            v4_approval_and_observe_execution_factory=(
                lambda _components: object()  # type: ignore[return-value]
            ),
        )
    with pytest.raises(HttpConfigurationError, match="source-backed approval"):
        http_server_module.create_http_app(
            enabled_settings,
            v4_plan_host_factory=base_host_factory,
            v4_approval_and_observe_execution_factory=execution_factory,
        )

    http_server_module.create_http_app(
        enabled_settings,
        v4_plan_host_factory=host_factory,
        v4_approval_and_observe_execution_factory=execution_factory,
    )

    async def tool_names(server):
        async with Client(server.mcp) as client:
            return {tool.name for tool in (await client.list_tools()).tools}

    assert V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOL in asyncio.run(
        tool_names(servers[-1])
    )
