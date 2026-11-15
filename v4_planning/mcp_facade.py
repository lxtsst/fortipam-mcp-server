"""Four-operation, non-executing V4 plan-only MCP facade contract.

The host transport owns authentication, time, confirmation interaction, and
projection selection. This package deliberately supplies deny-all defaults so
importing or instantiating the facade cannot create authority. A reviewed host
may inject a fake-only or source-backed projection provider; the planning
engine still validates its exact contract and references. No executor is
accepted by this contract.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
import time
from typing import Protocol

from .canonical import CanonicalValue, normalize
from .models import (
    AuthenticatedRequester,
    AuthoritativeProjection,
    PlanningContractError,
    SchemeDraft,
    VerifiedConfirmationInteraction,
    FinalIntentSummary,
)
from .workflow_service import M3PlanOnlyWorkflowService


V4_PLAN_RUNTIME_VERSION = "4.0.0-beta.7"
V4_PLAN_ONLY_OPERATIONS = (
    "status",
    "preview",
    "consume_confirmation",
    "prepare_plan",
)
V4_PLAN_ONLY_BLOCKERS = (
    "approval_receipt_not_independently_signed",
    "confirmation_transport_unbound",
    "external_monotonic_checkpoint_unbound",
    "independent_approver_identity_unbound",
    "live_projection_unbound",
    "product_idempotency_unproven",
    "scheme_draft_issuance_unbound",
)


class V4PlanOnlyFacadeError(PlanningContractError):
    """Stable failure for a denied or incomplete plan-only facade transition."""


class TrustedPrincipalResolver(Protocol):
    """Resolve a requester only from a host-owned authenticated context."""

    def resolve(self, transport_context: object) -> AuthenticatedRequester: ...


class PlanningProjectionProvider(Protocol):
    """Supply one closed projection set through a trusted host binding."""

    mode: str

    def project(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
        *,
        now_epoch: int,
    ) -> Sequence[AuthoritativeProjection]: ...


class TrustedConfirmationConsumer(Protocol):
    """Consume a host-authenticated human interaction outside model input."""

    def issue(
        self,
        transport_context: object,
        requester: AuthenticatedRequester,
        *,
        summary: FinalIntentSummary,
        now_epoch: int,
    ) -> str: ...

    def verify(
        self,
        transport_context: object,
        requester: AuthenticatedRequester,
        *,
        summary_ref: str,
        summary_revision: int,
        now_epoch: int,
    ) -> VerifiedConfirmationInteraction: ...

    def claim(
        self,
        transport_context: object,
        requester: AuthenticatedRequester,
        *,
        summary_ref: str,
        summary_revision: int,
        now_epoch: int,
    ) -> None: ...


class DenyAllTrustedPrincipalResolver:
    """Default principal boundary: no authenticated host binding, no planning."""

    def resolve(self, transport_context: object) -> AuthenticatedRequester:
        del transport_context
        raise V4PlanOnlyFacadeError("Trusted principal transport is unavailable.")


class DenyAllPlanningProjectionProvider:
    """Default projection boundary: never synthesize or contact product state."""

    mode = "deny_all"

    def project(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
        *,
        now_epoch: int,
    ) -> Sequence[AuthoritativeProjection]:
        del draft, requester, now_epoch
        raise V4PlanOnlyFacadeError("Fake-only planning projection is unavailable.")


class DenyAllTrustedConfirmationConsumer:
    """Default confirmation boundary: model text cannot become confirmation."""

    def issue(
        self,
        transport_context: object,
        requester: AuthenticatedRequester,
        *,
        summary: FinalIntentSummary,
        now_epoch: int,
    ) -> str:
        del transport_context, requester, summary, now_epoch
        raise V4PlanOnlyFacadeError("Trusted human confirmation is unavailable.")

    def verify(
        self,
        transport_context: object,
        requester: AuthenticatedRequester,
        *,
        summary_ref: str,
        summary_revision: int,
        now_epoch: int,
    ) -> VerifiedConfirmationInteraction:
        del transport_context, requester, summary_ref, summary_revision, now_epoch
        raise V4PlanOnlyFacadeError("Trusted human confirmation is unavailable.")

    def claim(
        self,
        transport_context: object,
        requester: AuthenticatedRequester,
        *,
        summary_ref: str,
        summary_revision: int,
        now_epoch: int,
    ) -> None:
        del transport_context, requester, summary_ref, summary_revision, now_epoch
        raise V4PlanOnlyFacadeError("Trusted human confirmation is unavailable.")


class V4PlanOnlyMcpFacade:
    """Expose exactly four planning operations and no execution transition."""

    def __init__(
        self,
        workflow: M3PlanOnlyWorkflowService,
        *,
        principal_resolver: TrustedPrincipalResolver | None = None,
        projection_provider: PlanningProjectionProvider | None = None,
        confirmation_consumer: TrustedConfirmationConsumer | None = None,
        clock: Callable[[], int] | None = None,
        planner_mcp_exposed: bool = False,
    ) -> None:
        self._workflow = workflow
        self._principal_resolver = (
            principal_resolver or DenyAllTrustedPrincipalResolver()
        )
        self._projection_provider = (
            projection_provider or DenyAllPlanningProjectionProvider()
        )
        self._confirmation_consumer = (
            confirmation_consumer or DenyAllTrustedConfirmationConsumer()
        )
        self._confirmation_transport_bound = not isinstance(
            self._confirmation_consumer,
            DenyAllTrustedConfirmationConsumer,
        )
        self._clock = clock or (lambda: int(time.time()))
        if type(planner_mcp_exposed) is not bool:
            raise V4PlanOnlyFacadeError("Planner exposure metadata is invalid.")
        self._planner_mcp_exposed = planner_mcp_exposed
        if self._projection_provider.mode not in {
            "deny_all",
            "fake_only",
            "source_backed",
        }:
            raise V4PlanOnlyFacadeError(
                "Planning projection mode is unsupported."
            )
        registration = getattr(
            self._projection_provider,
            "contract_registered",
            False,
        )
        if type(registration) is not bool:
            raise V4PlanOnlyFacadeError(
                "Planning projection registration metadata is invalid."
            )
        self._projection_contract_registered = registration

    def status(self) -> dict[str, CanonicalValue]:
        """Return static exposure truth without authenticating or reading state."""

        return {
            "adapter_registry_bound": True,
            "blocker_codes": [
                code
                for code in V4_PLAN_ONLY_BLOCKERS
                if not (
                    code == "confirmation_transport_unbound"
                    and self._confirmation_transport_bound
                )
                and not (
                    code == "live_projection_unbound"
                    and self._projection_provider.mode == "source_backed"
                    and self._projection_contract_registered
                )
            ],
            "confirmation_transport_bound": self._confirmation_transport_bound,
            "device_access": self._projection_provider.mode == "source_backed",
            "dispatchable": False,
            "executor_mcp_exposed": False,
            "executor_runtime_packaged": True,
            "operation_names": list(V4_PLAN_ONLY_OPERATIONS),
            "planner_mcp_exposed": self._planner_mcp_exposed,
            "planner_runtime_packaged": True,
            "product_write_enabled": False,
            "projection_contract_registered": (
                self._projection_contract_registered
            ),
            "projection_mode": self._projection_provider.mode,
            "runtime_profile": "v4-plan-only",
            "runtime_version": V4_PLAN_RUNTIME_VERSION,
        }

    def preview(
        self,
        draft: SchemeDraft,
        *,
        transport_context: object,
        prior_summary_ref: str | None = None,
    ) -> dict[str, CanonicalValue]:
        """Compile Current/Proposed/Expected from a trusted projection provider."""

        requester = self._principal(transport_context)
        now_epoch = self._now()
        if self._projection_provider.mode not in {"fake_only", "source_backed"}:
            raise V4PlanOnlyFacadeError("Planning projection is unavailable.")
        projections = self._projection_provider.project(
            draft,
            requester,
            now_epoch=now_epoch,
        )
        summary = self._workflow.compile_summary(
            draft,
            requester,
            projections,
            now_epoch=now_epoch,
            prior_summary_ref=prior_summary_ref,
        )
        confirmation_url = self._confirmation_consumer.issue(
            transport_context,
            requester,
            summary=summary,
            now_epoch=now_epoch,
        )
        if not confirmation_url.startswith("https://"):
            raise V4PlanOnlyFacadeError("Trusted confirmation URL is invalid.")
        payload = dict(summary.as_dict())
        payload.update(
            {
                "confirmation_state": "awaiting_human_reauthentication",
                "confirmation_url": confirmation_url,
            }
        )
        return normalize(payload)  # type: ignore[return-value]

    def consume_confirmation(
        self,
        summary_ref: str,
        summary_revision: int,
        *,
        transport_context: object,
    ) -> dict[str, CanonicalValue]:
        """Consume only a host-issued authenticated-human interaction."""

        requester = self._principal(transport_context)
        now_epoch = self._now()
        interaction = self._confirmation_consumer.verify(
            transport_context,
            requester,
            summary_ref=summary_ref,
            summary_revision=summary_revision,
            now_epoch=now_epoch,
        )
        if interaction.decision != "affirm":
            self._confirmation_consumer.claim(
                transport_context,
                requester,
                summary_ref=summary_ref,
                summary_revision=summary_revision,
                now_epoch=now_epoch,
            )
            raise V4PlanOnlyFacadeError("The requester denied the Final Intent Summary.")
        record = self._workflow.confirm_intent(
            summary_ref,
            requester,
            interaction,
            now_epoch=now_epoch,
        )
        self._confirmation_consumer.claim(
            transport_context,
            requester,
            summary_ref=summary_ref,
            summary_revision=summary_revision,
            now_epoch=now_epoch,
        )
        payload = dict(record.canonical_content())
        payload["record_digest"] = record.record_digest
        return normalize(payload)  # type: ignore[return-value]

    def prepare_plan(
        self,
        summary_ref: str,
        confirmation_ref: str,
        *,
        transport_context: object,
    ) -> dict[str, CanonicalValue]:
        """Prepare one immutable plan whose execution exposure stays false."""

        requester = self._principal(transport_context)
        plan = self._workflow.prepare_plan(
            summary_ref,
            confirmation_ref,
            requester,
            now_epoch=self._now(),
        )
        payload = dict(plan.canonical_content())
        payload.update({"plan_digest": plan.plan_digest, "state": plan.state.value})
        if plan.planner_mcp_exposed is not self._planner_mcp_exposed:
            raise V4PlanOnlyFacadeError("Prepared plan exposure metadata is inconsistent.")
        return normalize(payload)  # type: ignore[return-value]

    def _evaluate_pre_write(
        self,
        plan_ref: str,
        draft: SchemeDraft,
        *,
        transport_context: object,
    ) -> dict[str, CanonicalValue]:
        """Run the trusted source reread needed immediately before execution."""

        requester = self._principal(transport_context)
        now_epoch = self._now()
        projections = self._projection_provider.project(
            draft,
            requester,
            now_epoch=now_epoch,
        )
        result = self._workflow.evaluate_pre_write(
            plan_ref,
            projections,
            now_epoch=now_epoch,
        )
        return normalize(
            {
                "evaluated_at": result.evaluated_at,
                "observed_state_digest": result.observed_state_digest,
                "plan_ref": result.plan_ref,
                "reason_codes": list(result.reason_codes),
                "status": result.status.value,
            }
        )  # type: ignore[return-value]

    def _evaluate_post_write(
        self,
        plan_ref: str,
        draft: SchemeDraft,
        *,
        transport_context: object,
    ) -> dict[str, CanonicalValue]:
        """Run trusted readback comparison without claiming a product mutation."""

        requester = self._principal(transport_context)
        now_epoch = self._now()
        projections = self._projection_provider.project(
            draft,
            requester,
            now_epoch=now_epoch,
        )
        result = self._workflow.evaluate_post_write(
            plan_ref,
            projections,
            now_epoch=now_epoch,
        )
        return normalize(
            {
                "actual_state_digest": result.actual_state_digest,
                "evaluated_at": result.evaluated_at,
                "expected_state_digest": result.expected_state_digest,
                "mutation_observed": result.mutation_observed,
                "operational_success": result.operational_success,
                "plan_ref": result.plan_ref,
                "reason_codes": list(result.reason_codes),
                "status": result.status.value,
            }
        )  # type: ignore[return-value]

    def _principal(self, transport_context: object) -> AuthenticatedRequester:
        requester = self._principal_resolver.resolve(transport_context)
        if not isinstance(requester, AuthenticatedRequester):
            raise V4PlanOnlyFacadeError("Trusted principal resolution failed.")
        return requester

    def _now(self) -> int:
        value = self._clock()
        if type(value) is not int:
            raise V4PlanOnlyFacadeError("Trusted planning clock is invalid.")
        return value


__all__ = [
    "DenyAllPlanningProjectionProvider",
    "DenyAllTrustedConfirmationConsumer",
    "DenyAllTrustedPrincipalResolver",
    "PlanningProjectionProvider",
    "TrustedConfirmationConsumer",
    "TrustedPrincipalResolver",
    "V4_PLAN_ONLY_BLOCKERS",
    "V4_PLAN_ONLY_OPERATIONS",
    "V4_PLAN_RUNTIME_VERSION",
    "V4PlanOnlyFacadeError",
    "V4PlanOnlyMcpFacade",
]
