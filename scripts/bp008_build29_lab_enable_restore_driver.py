"""Protected, in-process BP008 lab handoff; no CLI, paths, or signing keys.

The operator supplies an actual main context/components/provider and tokens
obtained by the independent SDK OAuth flow. All public returns contain refs.
The independent qualification issuer receives ``private_qualification_target``
in protected memory and writes the manifest consumed by the existing verifier.
This helper neither issues qualification nor replaces production dependencies.
"""

from __future__ import annotations

import asyncio
import hmac
from collections.abc import Callable
from typing import Any, Protocol, cast

import httpx2 as httpx
from mcp.types import CallToolResult
from v4_planning import AuthenticatedApprover, M2PlanningEngine, M3PlanOnlyWorkflowService, M4Outcome

from fortipam_mcp.local_oauth import LocalOAuthProvider
from fortipam_mcp.secret_approval_build29_main_factory import (
    SecretApprovalBuild29MainContext, LINUX_RUNTIME_CONTRACT, LINUX_REMOTE_RUNTIME_CONTRACT,
)
from fortipam_mcp.secret_approval_action_sequence import SecretApprovalFixedActionSequenceResolver
from fortipam_mcp.secret_approval_build29_m4_composition import SecretApprovalBuild29M4RunnerFactory
from fortipam_mcp.secret_approval_build29_m4_runtime import (
    SecretApprovalBuild29M4ExecutionBinding, assemble_secret_approval_build29_m4_runtime,
    secret_approval_build29_binding_digest,
)
from fortipam_mcp.secret_approval_build29_projection_source import FortiPamSecretApprovalBuild29ProjectionSource
from fortipam_mcp.secret_approval_build29_restore import (
    SecretApprovalBuild29OwnedRestoreSource, PlanningChainSecretApprovalBuild29RestoreAuthorizationVerifier,
    promote_secret_approval_build29_restore_binding, secret_approval_build29_restore_projection_contract,
)
from fortipam_mcp.secret_approval_build29_runtime_provider import (
    OwnerOnlySecretApprovalBuild29QualificationVerifier, OwnerOnlySecretApprovalBuild29LinuxQualificationVerifier,
)
from fortipam_mcp.v4_confirmation_http import V4ConfirmationSettings
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal, planning_principal_from_access_token
from fortipam_mcp.v4_runtime_host import V4PlanHostComponents
from scripts.v4_https_oauth_acceptance import _affirm_browser_confirmation


class Build29LabDriverDenied(RuntimeError):
    """Stable protected-harness refusal."""


class McpSession(Protocol):
    async def call_tool(self, name: str, arguments: dict[str, object]) -> CallToolResult: ...


class Build29MainLabCapture:
    """Wrap existing create_http_app callbacks, preserving their real results.

    Pass ``host_factory(actual_host_factory)`` and ``execution_factory`` to
    the existing app constructor. This does not patch main or read any assets.
    An actual-main entrypoint harness may capture the same objects instead.
    """

    def __init__(self, context: SecretApprovalBuild29MainContext) -> None:
        if type(context) is not SecretApprovalBuild29MainContext:
            raise Build29LabDriverDenied("Protected build-29 lab capture is unavailable.")
        self.context = context
        self.components: V4PlanHostComponents | None = None
        self.provider: LocalOAuthProvider | None = None

    def __repr__(self) -> str:
        return "<Build29MainLabCapture protected>"

    def host_factory(self, actual: Callable[[LocalOAuthProvider, V4ConfirmationSettings], V4PlanHostComponents]) -> Callable[[LocalOAuthProvider, V4ConfirmationSettings], V4PlanHostComponents]:
        def capture(provider: LocalOAuthProvider, settings: V4ConfirmationSettings) -> V4PlanHostComponents:
            if self.components is not None:
                raise Build29LabDriverDenied("Protected build-29 lab capture is unavailable.")
            components = actual(provider, settings)
            self.components, self.provider = components, provider
            return components
        return capture

    def execution_factory(self, components: V4PlanHostComponents) -> Any:
        if components is not self.components:
            raise Build29LabDriverDenied("Protected build-29 lab capture is unavailable.")
        return self.context.execution_factory(components)

    def driver(self, authorization: V4PlanningAuthorizationSettings) -> Build29LabEnableRestoreDriver:
        if self.components is None or self.provider is None:
            raise Build29LabDriverDenied("Protected build-29 lab capture is unavailable.")
        return Build29LabEnableRestoreDriver(self.context, self.components, self.provider, authorization)


class Build29LabEnableRestoreDriver:
    """One same-instance enable MCP dispatch followed by independent restore."""

    def __init__(self, context: SecretApprovalBuild29MainContext, components: V4PlanHostComponents,
                 provider: LocalOAuthProvider, authorization: V4PlanningAuthorizationSettings) -> None:
        if (type(context) is not SecretApprovalBuild29MainContext or context._components is not components
                or context._action is None or type(provider) is not LocalOAuthProvider
                or components.confirmation_service._provider is not provider):
            raise Build29LabDriverDenied("Protected build-29 lab driver is unavailable.")
        resolver = context._action._coordinator._resolver
        if type(resolver) is not SecretApprovalFixedActionSequenceResolver:
            raise Build29LabDriverDenied("Protected build-29 lab driver is unavailable.")
        factory = resolver._runner_factory
        if type(factory) is not SecretApprovalBuild29M4RunnerFactory:
            raise Build29LabDriverDenied("Protected build-29 lab driver is unavailable.")
        qualifier_type = (OwnerOnlySecretApprovalBuild29LinuxQualificationVerifier
                          if context._settings["contract"] in {LINUX_RUNTIME_CONTRACT, LINUX_REMOTE_RUNTIME_CONTRACT}
                          else OwnerOnlySecretApprovalBuild29QualificationVerifier)
        if type(factory._qualifier) is not qualifier_type:
            raise Build29LabDriverDenied("Protected build-29 lab driver is unavailable.")
        self._components, self._provider, self._authorization, self._factory = components, provider, authorization, factory
        self._enable_refs: dict[str, object] | None = None
        self._enable_succeeded = False
        self._enable_dispatched = False
        self._restore: dict[str, Any] | None = None

    def __repr__(self) -> str:
        return "<Build29LabEnableRestoreDriver protected>"

    async def _principal(self, raw_token: str) -> V4PlanningPrincipal:
        token = await self._provider.load_access_token(raw_token)
        if token is None or "fortipam:operate" not in token.scopes:
            raise Build29LabDriverDenied("Protected build-29 lab OAuth authority is unavailable.")
        return planning_principal_from_access_token(token, self._authorization)

    async def bind_enable(self, raw_token: str, *, plan_ref: str, scheme_draft_ref: str) -> dict[str, object]:
        principal = await self._principal(raw_token)
        plan, draft = self._components.plan_services.resolve_execution_context(plan_ref, scheme_draft_ref, principal)
        source = self._components.approval_and_observe_projection_source
        if type(source) is not FortiPamSecretApprovalBuild29ProjectionSource or len(plan.lines) != 1:
            raise Build29LabDriverDenied("Protected build-29 enable binding is unavailable.")
        binding = source._resolver.resolve(draft, principal.requester)
        await asyncio.to_thread(self._factory.bind, plan, plan.lines[0].line_ref, principal,
                                draft=draft, approval_binding=binding)
        self._enable_refs = {"plan_ref": plan_ref, "scheme_draft_ref": scheme_draft_ref}
        return dict(self._enable_refs)

    def private_qualification_target(self, operation: str) -> SecretApprovalBuild29M4ExecutionBinding:
        """Private issuer input; never serialize into MCP, plan, or public proof."""
        if operation == "enable" and self._factory._bound is not None:
            return self._factory._bound.runner.runtime._binding
        if operation == "restore" and self._restore is not None and "binding" in self._restore:
            return self._restore["binding"]  # type: ignore[no-any-return]
        raise Build29LabDriverDenied("Protected build-29 qualification target is unavailable.")

    async def execute_enable_mcp(self, session: McpSession) -> dict[str, object]:
        if self._enable_refs is None or self._enable_dispatched:
            raise Build29LabDriverDenied("Protected build-29 enable dispatch is unavailable.")
        binding = self.private_qualification_target("enable")
        cast(OwnerOnlySecretApprovalBuild29QualificationVerifier, self._factory._qualifier).verify(binding_digest=secret_approval_build29_binding_digest(binding),
                                       plan_digest=binding.plan.plan_digest, now_epoch=self._factory._clock())
        self._enable_dispatched = True
        result = await session.call_tool("execute_v4_approval_and_observe_workflow", dict(self._enable_refs))
        structured = result.structured_content
        owned = binding.transport._ownership
        if (result.is_error is not False
                or not isinstance(structured, dict) or structured.get("outcome") != "succeeded"
                or structured.get("reconciliation_required") is not False
                or owned is None or owned[0] != binding.baseline
                or owned[1].state_digest != binding.plan.expected_state_digest):
            raise Build29LabDriverDenied("Protected build-29 enable requires reconciliation.")
        self._enable_succeeded = True
        return dict(self._enable_refs)

    async def preview_restore(self, raw_token: str, *, ownership_evidence_ref: str) -> dict[str, object]:
        if not self._enable_succeeded or self._restore is not None or self._factory._bound is None:
            raise Build29LabDriverDenied("Protected build-29 restore intent is unavailable.")
        principal = await self._principal(raw_token)
        bound = self._factory._bound
        if principal != bound.principal:
            raise Build29LabDriverDenied("Protected build-29 restore intent is unavailable.")
        categorical = self._components.approval_and_observe_projection_source
        if type(categorical) is not FortiPamSecretApprovalBuild29ProjectionSource:
            raise Build29LabDriverDenied("Protected build-29 restore intent is unavailable.")
        source = SecretApprovalBuild29OwnedRestoreSource(categorical, bound.draft, principal.requester,
            bound.runner.runtime._binding, ownership_evidence_ref=ownership_evidence_ref)
        original = self._components.plan_services._workflow
        old = original._planning_engine
        registry = {"registry_kind": "fortipam_v4_administrative_registry",
                    "schema_version": old._registry.schema_version,
                    "schemes": list(old._registry._schemes.values()),
                    "blueprints": list(old._registry._blueprints.values()), "actions": list(old._registry._actions.values())}
        engine = M2PlanningEngine(registry, old._issuer, old._reference_authorizer,
            projection_contract_resolver=lambda _scheme, kind: secret_approval_build29_restore_projection_contract(kind),
            approval_restore_profile_enabled=True)
        workflow = M3PlanOnlyWorkflowService(engine, original._store, original._policy, original._approval_gate)
        now = self._factory._clock()
        summary = workflow.compile_summary(source.draft, principal.requester,
                                           source.project(source.draft, principal.requester, now_epoch=now), now_epoch=now)
        url = self._components.confirmation_service.issue(summary, principal.requester,
            principal_namespace_digest=principal.transport_namespace_digest, now_epoch=now)
        # Private harness handle for this exact source-owned draft. It does not
        # advertise a new draft resolver or restore Tool on the main MCP app.
        draft_ref = old._issuer.issue("restore-scheme-draft")
        self._restore = dict(source=source, workflow=workflow, principal=principal, summary=summary, url=url, draft_ref=draft_ref)
        return {"scheme_draft_ref": draft_ref}

    async def confirm_prepare_restore(self, client: httpx.AsyncClient, *, username: str, password: str) -> dict[str, object]:
        state = self._require_restore()
        service = self._components.confirmation_service
        await _affirm_browser_confirmation(client, state["url"], origin=service._origin, username=username, password=password)
        principal, summary, workflow = state["principal"], state["summary"], state["workflow"]
        pins = dict(principal_namespace_digest=principal.transport_namespace_digest,
                    summary_ref=summary.summary_ref, summary_revision=summary.revision, now_epoch=self._factory._clock())
        interaction = service.verify(principal.requester, **pins)
        confirmation = workflow.confirm_intent(summary.summary_ref, principal.requester, interaction, now_epoch=pins["now_epoch"])
        service.claim(principal.requester, **pins)
        plan = workflow.prepare_plan(summary.summary_ref, confirmation.confirmation_ref, principal.requester, now_epoch=self._factory._clock())
        state["plan"] = plan
        return {"plan_ref": plan.plan_ref, "scheme_draft_ref": state["draft_ref"]}

    async def approve_claim_promote_restore(self, approver: AuthenticatedApprover, *, authorization_ref: str) -> dict[str, object]:
        state = self._require_restore()
        if "plan" not in state or "binding" in state:
            raise Build29LabDriverDenied("Protected build-29 restore approval is unavailable.")
        workflow, plan, principal = state["workflow"], state["plan"], state["principal"]
        decision = await asyncio.to_thread(workflow.request_approval, plan.plan_ref, principal.requester, now_epoch=self._factory._clock())
        receipt = await asyncio.to_thread(workflow.approve, decision.decision_ref, approver,
                                         requester=principal.requester, now_epoch=self._factory._clock())
        claim = await asyncio.to_thread(workflow.claim_approval, receipt.receipt_ref, plan.plan_ref, principal.requester)
        if claim.approval_validated is not True:
            raise Build29LabDriverDenied("Protected build-29 restore approval is unavailable.")
        pins = dict(source_plan_ref=plan.plan_ref, approval_receipt_ref=receipt.receipt_ref,
                    approver_authority_ref=self._factory._authority_ref, authorization_ref=authorization_ref)
        binding = await asyncio.to_thread(promote_secret_approval_build29_restore_binding,
            self._factory._planning, self._factory._authenticator, state["source"], **pins, now_epoch=self._factory._clock())
        state.update(binding=binding, pins=pins)
        return {"plan_ref": plan.plan_ref, "scheme_draft_ref": state["draft_ref"]}

    async def execute_restore(self, qualifier: OwnerOnlySecretApprovalBuild29QualificationVerifier) -> dict[str, object]:
        state = self._require_restore()
        if "binding" not in state or state.get("dispatched"):
            raise Build29LabDriverDenied("Protected build-29 restore dispatch is unavailable.")
        qualifier_type = (OwnerOnlySecretApprovalBuild29LinuxQualificationVerifier
                          if state["binding"].transport._linux_target_name is not None
                          else OwnerOnlySecretApprovalBuild29QualificationVerifier)
        if type(qualifier) is not qualifier_type:
            raise Build29LabDriverDenied("Protected build-29 restore dispatch is unavailable.")
        trusted = self._factory._qualifier
        if (type(trusted) is not qualifier_type
                or qualifier._authority != trusted._authority or not hmac.compare_digest(qualifier._key, trusted._key)):
            raise Build29LabDriverDenied("Protected build-29 restore qualification authority is unavailable.")
        binding = state["binding"]
        verifier = PlanningChainSecretApprovalBuild29RestoreAuthorizationVerifier(
            self._factory._planning, self._factory._authenticator, state["source"], **state["pins"])
        runtime = assemble_secret_approval_build29_m4_runtime(binding, authorization_verifier=verifier,
            execution_store=self._factory._store, authenticated_requester_digest=state["principal"].requester.digest,
            qualification_verifier=qualifier, execution_enabled=True, clock=self._factory._clock)
        # Refusal before dispatch is retryable; a consumed/uncertain dispatch is not.
        qualifier.verify(binding_digest=secret_approval_build29_binding_digest(binding),
                         plan_digest=binding.plan.plan_digest, now_epoch=self._factory._clock())
        state["dispatched"] = True
        result = await asyncio.to_thread(runtime.execute_bound, binding.authorization.authorization_ref,
                                         expected_binding_digest=secret_approval_build29_binding_digest(binding))
        if result.outcome is not M4Outcome.SUCCEEDED:
            raise Build29LabDriverDenied("Protected build-29 restore requires reconciliation.")
        return {"plan_ref": state["plan"].plan_ref, "scheme_draft_ref": state["draft_ref"]}

    def _require_restore(self) -> dict[str, Any]:
        if self._restore is None:
            raise Build29LabDriverDenied("Protected build-29 restore intent is unavailable.")
        return self._restore
