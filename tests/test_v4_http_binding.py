from __future__ import annotations

import pytest

from test_v4_planning import (
    Authorizer,
    Issuer,
    NOW,
    _absent_projections,
    _access_draft,
    _promoted_registry,
)
from v4_planning import (
    AuthenticatedRequester,
    InMemoryProtectedPlanningStore,
    M2PlanningEngine,
    M3ApprovalGate,
    M3PlanOnlyWorkflowService,
    M3PlanPolicy,
    SchemeDraft,
    VerifiedConfirmationInteraction,
)

from fortipam_mcp.v4_plan_runtime import (
    OAuthBoundV4PlanServices,
    V4PlanningRuntimeError,
    V4PlanningPrincipal,
    unbound_v4_plan_status,
)


class DraftProvider:
    def __init__(self, draft: SchemeDraft) -> None:
        self.draft = draft

    def resolve(
        self,
        scheme_draft_ref: str,
        requester: AuthenticatedRequester,
    ) -> SchemeDraft:
        assert scheme_draft_ref == "scheme-draft-ref-0001"
        assert requester.principal_class == "operator"
        return self.draft


class FakeOnlyProjections:
    mode = "fake_only"

    def __init__(self, engine: M2PlanningEngine) -> None:
        self.engine = engine

    def project(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
        *,
        now_epoch: int,
    ):
        del requester
        assert now_epoch == NOW
        return _absent_projections(self.engine, draft)


class ConfirmationConsumer:
    def __init__(self) -> None:
        self.summary: dict[str, object] | None = None

    def issue(
        self,
        transport_context: object,
        requester: AuthenticatedRequester,
        *,
        summary: object,
        now_epoch: int,
    ) -> str:
        del transport_context, requester, summary, now_epoch
        return "https://mcp.example.com/fpamcp-v4/oauth/v4/confirm/test-challenge"

    def verify(
        self,
        transport_context: object,
        requester: AuthenticatedRequester,
        *,
        summary_ref: str,
        summary_revision: int,
        now_epoch: int,
    ) -> VerifiedConfirmationInteraction:
        del transport_context
        assert self.summary is not None
        return VerifiedConfirmationInteraction(
            interaction_ref="interaction-ref-0001",
            interaction_type="authenticated_human_confirmation",
            nonce_digest="2" * 64,
            requester_digest=requester.digest,
            audience_ref=str(self.summary["audience_ref"]),
            summary_ref=summary_ref,
            summary_revision=summary_revision,
            summary_digest=str(self.summary["summary_digest"]),
            decision="affirm",
            confirmed_at=now_epoch,
            expires_at=NOW + 100,
        )

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


class SequenceClock:
    def __init__(self, *values: int) -> None:
        self._values = iter(values)

    def __call__(self) -> int:
        return next(self._values)


def test_oauth_bound_services_reach_only_non_executable_facade_transitions() -> None:
    draft = _access_draft()
    issuer = Issuer()
    engine = M2PlanningEngine(
        _promoted_registry(),
        issuer,
        Authorizer((draft,)),
        planner_mcp_exposed=True,
    )
    workflow = M3PlanOnlyWorkflowService(
        engine,
        InMemoryProtectedPlanningStore(clock=lambda: NOW + 50),
        M3PlanPolicy(issuer),
        M3ApprovalGate(issuer),
    )
    confirmations = ConfirmationConsumer()
    services = OAuthBoundV4PlanServices(
        workflow,
        draft_provider=DraftProvider(draft),
        projection_provider=FakeOnlyProjections(engine),
        confirmation_consumer=confirmations,
        clock=SequenceClock(NOW, NOW + 1, NOW + 2),
    )
    with pytest.raises(V4PlanningRuntimeError, match="unavailable"):
        OAuthBoundV4PlanServices(
            workflow,
            draft_provider=DraftProvider(draft),
            projection_provider=FakeOnlyProjections(engine),
            confirmation_consumer=ConfirmationConsumer(),
            reference_authority_checkpoint_protocol_bound=True,
        )
    requester = AuthenticatedRequester("a" * 64, "operator")
    principal = V4PlanningPrincipal(requester, "9" * 64)

    preview = services.preview("scheme-draft-ref-0001", principal)
    confirmations.summary = dict(preview)
    confirmation = services.confirm(
        str(preview["summary_ref"]),
        int(preview["revision"]),
        principal,
    )
    plan = services.prepare(
        str(preview["summary_ref"]),
        str(confirmation["confirmation_ref"]),
        principal,
    )

    assert services.status()["planner_mcp_exposed"] is True
    assert services.status()["reference_authorization_protocol_bound"] is False
    assert services.status()["secret_create_execution_preflight_available"] is False
    assert plan["planner_mcp_exposed"] is True
    assert plan["dispatchable"] is False
    assert plan["adapter_registry_bound"] is False
    assert plan["executor_runtime_packaged"] is False


@pytest.mark.parametrize("result", [True, False, 1, "true", RuntimeError("unavailable")])
def test_create_execution_preflight_is_separate_and_fails_closed(result) -> None:
    draft = _access_draft()
    issuer = Issuer()
    engine = M2PlanningEngine(_promoted_registry(), issuer, Authorizer((draft,)))
    workflow = M3PlanOnlyWorkflowService(
        engine, InMemoryProtectedPlanningStore(clock=lambda: NOW),
        M3PlanPolicy(issuer), M3ApprovalGate(issuer),
    )

    class Proxy:
        def is_available(self):
            return True

    services = OAuthBoundV4PlanServices(
        workflow, draft_provider=DraftProvider(draft),
        projection_provider=FakeOnlyProjections(engine),
        confirmation_consumer=ConfirmationConsumer(),
        secret_create_readiness_proxy_probe=Proxy(), clock=lambda: NOW,
    )
    assert unbound_v4_plan_status()["secret_create_execution_preflight_available"] is False
    assert services.status()["secret_create_private_runtime_available"] is True
    assert services.status()["secret_create_execution_preflight_available"] is False
    calls = []

    def probe():
        calls.append(True)
        if isinstance(result, Exception):
            raise result
        return result

    services.bind_secret_create_execution_preflight_probe(probe)
    for _ in range(2):
        status = services.status()
        assert status["secret_create_execution_preflight_available"] is (result is True)
        assert status["secret_create_private_runtime_available"] is True
        assert status["dispatchable"] is False
    assert len(calls) == 2
    with pytest.raises(V4PlanningRuntimeError, match="unavailable"):
        services.bind_secret_create_execution_preflight_probe(probe)
