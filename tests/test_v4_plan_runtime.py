from __future__ import annotations

import inspect
from pathlib import Path
from zipfile import ZipFile

import pytest

from test_v4_planning import (
    Issuer,
    NOW,
    _absent_projections,
    _access_draft,
    _engine,
    _requester,
)
from v4_planning import (
    AuthenticatedRequester,
    DenyAllPlanningProjectionProvider,
    InMemoryProtectedPlanningStore,
    M3ApprovalGate,
    M3PlanOnlyWorkflowService,
    M3PlanPolicy,
    V4_PLAN_ONLY_OPERATIONS,
    V4PlanOnlyFacadeError,
    V4PlanOnlyMcpFacade,
    require_v4_plan_only_profile,
)
from v4_planning.models import SchemeDraft, VerifiedConfirmationInteraction

from scripts.build_v4_plan_runtime import build


class Resolver:
    def __init__(self, context: object, requester: AuthenticatedRequester) -> None:
        self.context = context
        self.requester = requester

    def resolve(self, transport_context: object) -> AuthenticatedRequester:
        if transport_context is not self.context:
            raise V4PlanOnlyFacadeError("Untrusted transport context.")
        return self.requester


class FakeOnlyProjections:
    mode = "fake_only"

    def __init__(self, engine) -> None:
        self.engine = engine

    def project(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
        *,
        now_epoch: int,
    ):
        del requester
        assert NOW <= now_epoch <= NOW + 4
        return _absent_projections(self.engine, draft)


class SourceBackedProjections(FakeOnlyProjections):
    mode = "source_backed"
    contract_registered = True


class ConfirmationConsumer:
    def __init__(self) -> None:
        self.summary: dict[str, object] | None = None
        self.decision = "affirm"
        self.claimed = False

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
        assert self.summary["summary_ref"] == summary_ref
        assert self.summary["revision"] == summary_revision
        assert now_epoch == NOW + 1
        return VerifiedConfirmationInteraction(
            interaction_ref="interaction-ref-0001",
            interaction_type="authenticated_human_confirmation",
            nonce_digest="1" * 64,
            requester_digest=requester.digest,
            audience_ref=str(self.summary["audience_ref"]),
            summary_ref=summary_ref,
            summary_revision=summary_revision,
            summary_digest=str(self.summary["summary_digest"]),
            decision=self.decision,
            confirmed_at=NOW + 1,
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
        del transport_context, requester
        assert self.summary is not None
        assert self.summary["summary_ref"] == summary_ref
        assert self.summary["revision"] == summary_revision
        assert now_epoch == NOW + 1
        self.claimed = True


class SequenceClock:
    def __init__(self, *values: int) -> None:
        self.values = iter(values)

    def __call__(self) -> int:
        return next(self.values)


def _facade():
    draft = _access_draft()
    engine = _engine(draft)
    requester = _requester()
    context = object()
    confirmations = ConfirmationConsumer()
    issuer = Issuer()
    workflow = M3PlanOnlyWorkflowService(
        engine,
        InMemoryProtectedPlanningStore(clock=lambda: NOW + 50),
        M3PlanPolicy(issuer),
        M3ApprovalGate(issuer),
    )
    facade = V4PlanOnlyMcpFacade(
        workflow,
        principal_resolver=Resolver(context, requester),
        projection_provider=FakeOnlyProjections(engine),
        confirmation_consumer=confirmations,
        clock=SequenceClock(NOW, NOW + 1, NOW + 2, NOW + 3, NOW + 4),
    )
    return facade, confirmations, draft, context


def test_facade_has_exactly_four_plan_only_operations_and_truthful_status() -> None:
    facade = V4PlanOnlyMcpFacade(
        object(),  # type: ignore[arg-type]
        projection_provider=DenyAllPlanningProjectionProvider(),
    )
    public_methods = {
        name
        for name, member in inspect.getmembers(V4PlanOnlyMcpFacade, inspect.isfunction)
        if not name.startswith("_")
    }
    assert public_methods == set(V4_PLAN_ONLY_OPERATIONS)
    assert not public_methods & {"apply", "approve", "execute", "rollback"}
    status = facade.status()
    assert status["planner_runtime_packaged"] is True
    assert status["planner_mcp_exposed"] is False
    assert status["executor_runtime_packaged"] is True
    assert status["adapter_registry_bound"] is True
    assert status["executor_mcp_exposed"] is False
    assert status["product_write_enabled"] is False
    assert "external_monotonic_checkpoint_unbound" in status["blocker_codes"]
    assert "scheme_draft_issuance_unbound" in status["blocker_codes"]


def test_source_backed_projection_status_removes_only_its_own_blocker() -> None:
    draft = _access_draft()
    engine = _engine(draft)
    requester = _requester()
    context = object()
    issuer = Issuer()
    facade = V4PlanOnlyMcpFacade(
        M3PlanOnlyWorkflowService(
            engine,
            InMemoryProtectedPlanningStore(clock=lambda: NOW + 50),
            M3PlanPolicy(issuer),
            M3ApprovalGate(issuer),
        ),
        principal_resolver=Resolver(context, requester),
        projection_provider=SourceBackedProjections(engine),
        confirmation_consumer=ConfirmationConsumer(),
        clock=SequenceClock(NOW),
    )

    status = facade.status()

    assert status["projection_mode"] == "source_backed"
    assert status["projection_contract_registered"] is True
    assert status["device_access"] is True
    assert "live_projection_unbound" not in status["blocker_codes"]
    assert "product_idempotency_unproven" in status["blocker_codes"]
    assert status["dispatchable"] is False
    assert status["product_write_enabled"] is False


def test_default_boundaries_deny_preview_and_profile_requires_exact_opt_in() -> None:
    facade = V4PlanOnlyMcpFacade(object())  # type: ignore[arg-type]
    with pytest.raises(V4PlanOnlyFacadeError, match="principal"):
        facade.preview(_access_draft(), transport_context=object())
    with pytest.raises(ValueError, match="must be exactly"):
        require_v4_plan_only_profile({})
    assert require_v4_plan_only_profile(
        {"FORTIPAM_MCP_RUNTIME_PROFILE": "v4-plan-only"}
    ).value == "v4-plan-only"


def test_fake_only_preview_trusted_confirmation_and_plan_remain_non_executable() -> None:
    facade, confirmations, draft, context = _facade()
    preview = facade.preview(draft, transport_context=context)
    confirmations.summary = dict(preview)
    confirmation = facade.consume_confirmation(
        str(preview["summary_ref"]),
        int(preview["revision"]),
        transport_context=context,
    )
    plan = facade.prepare_plan(
        str(preview["summary_ref"]),
        str(confirmation["confirmation_ref"]),
        transport_context=context,
    )
    assert plan["state"] == "prepared_non_executable"
    assert plan["planner_runtime_packaged"] is True
    assert plan["planner_mcp_exposed"] is False
    assert plan["executor_runtime_packaged"] is False
    assert plan["executor_mcp_exposed"] is False
    assert plan["dispatchable"] is False
    assert plan["adapter_registry_bound"] is False
    prewrite = facade._evaluate_pre_write(
        str(plan["plan_ref"]),
        draft,
        transport_context=context,
    )
    postwrite = facade._evaluate_post_write(
        str(plan["plan_ref"]),
        draft,
        transport_context=context,
    )
    assert prewrite["status"] == "match"
    assert postwrite["status"] == "expected_state_mismatch"
    assert postwrite["mutation_observed"] is False
    assert postwrite["operational_success"] is False


def test_denied_browser_decision_is_claimed_without_planning_confirmation() -> None:
    facade, confirmations, draft, context = _facade()
    preview = facade.preview(draft, transport_context=context)
    confirmations.summary = dict(preview)
    confirmations.decision = "deny"

    with pytest.raises(V4PlanOnlyFacadeError, match="denied"):
        facade.consume_confirmation(
            str(preview["summary_ref"]),
            int(preview["revision"]),
            transport_context=context,
        )
    assert confirmations.claimed is True


def test_separate_v4_pre_release_wheel_contains_no_v3_server(tmp_path: Path) -> None:
    wheel = build(tmp_path)
    with ZipFile(wheel) as archive:
        members = set(archive.namelist())
        metadata_name = next(name for name in members if name.endswith(".dist-info/METADATA"))
        metadata = archive.read(metadata_name).decode("utf-8")
    assert "Name: fortipam-mcp-v4-plan-runtime" in metadata
    assert "Version: 4.0.0b7" in metadata
    assert "v4_planning/mcp_facade.py" in members
    assert "v4_planning/runtime_profile.py" in members
    assert not any(name.startswith("fortipam_mcp/") for name in members)
