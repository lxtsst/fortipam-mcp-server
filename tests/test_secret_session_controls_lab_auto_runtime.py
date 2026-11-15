from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from fortipam_mcp.secret_session_controls_lab_auto_runtime import (
    LAB_AUTO_SECRET_SESSION_CONTROLS_TTL_SECONDS,
    LabAutoSecretSessionControlsPromoter,
    build_lab_auto_secret_session_controls_runner_factory,
)
from fortipam_mcp.secret_session_controls_m4_runtime import (
    SECRET_SESSION_CONTROLS_ADAPTER_REF,
    RdpEventFilterReadTransport,
    SecretSessionControlsReadTransport,
    SecretSessionControlsWriteTransport,
)
from fortipam_mcp.secret_session_controls_m4_authorization import (
    SecretApprovalPlanningChainReader,
)
from test_secret_session_controls_m4_authorization import (
    _binding,
    _claimed_chain,
    _onboarding_binding,
)
from test_v4_planning import NOW
from v4_planning import M4AuthorizationDenied, PreparedPlan, canonical_digest


def _promoter(plan: PreparedPlan) -> LabAutoSecretSessionControlsPromoter:
    return LabAutoSecretSessionControlsPromoter(
        b"a" * 32,
        authorized_environment_ref=plan.environment_ref,
        authorized_scope_ref=plan.scope_ref,
    )


def test_lab_auto_promotion_uses_stored_bp006_summary_confirmation_and_plan() -> None:
    planning, _authenticator, plan, _receipt = _claimed_chain()
    summary = planning.get_summary(plan.summary_ref, plan.summary_revision)
    confirmation = planning.get_confirmation(plan.confirmation_ref)

    artifacts = _promoter(plan).promote(
        summary, confirmation, plan, _binding(),
        onboarding_binding=_onboarding_binding(), now_epoch=NOW + 5,
    )

    assert artifacts.binding.plan.adapter_ref == SECRET_SESSION_CONTROLS_ADAPTER_REF
    assert artifacts.binding.plan.expires_at - (NOW + 5) <= LAB_AUTO_SECRET_SESSION_CONTROLS_TTL_SECONDS
    assert artifacts.binding.authorization.one_time is True
    assert artifacts.audit_attributes == {"lab_auto": True}

    later = _promoter(plan).promote(
        summary, confirmation, plan, _binding(),
        onboarding_binding=_onboarding_binding(), now_epoch=NOW + 6,
    )
    assert later.binding.plan.idempotency_digest == artifacts.binding.plan.idempotency_digest


def test_lab_auto_promotion_rejects_confirmation_or_baseline_drift() -> None:
    planning, _authenticator, plan, _receipt = _claimed_chain()
    summary = planning.get_summary(plan.summary_ref, plan.summary_revision)
    confirmation = planning.get_confirmation(plan.confirmation_ref)

    altered_content = dict(confirmation.canonical_content())
    altered_content["summary_digest"] = "0" * 64
    altered_confirmation = replace(
        confirmation,
        summary_digest="0" * 64,
        record_digest=canonical_digest(altered_content),
    )
    with pytest.raises(M4AuthorizationDenied):
        _promoter(plan).promote(
            summary, altered_confirmation, plan, _binding(),
            onboarding_binding=_onboarding_binding(), now_epoch=NOW + 5,
        )
    with pytest.raises(M4AuthorizationDenied):
        _promoter(plan).promote(
            summary, confirmation, plan, replace(_binding(), preserved_identity_relations_digest="2" * 64),
            onboarding_binding=_onboarding_binding(), now_epoch=NOW + 5,
        )

    changed_plan_content = dict(plan.canonical_content())
    changed_plan_content["requester_digest"] = "0" * 64
    changed_plan = replace(
        plan,
        requester_digest="0" * 64,
        plan_digest=canonical_digest(changed_plan_content),
    )
    with pytest.raises(M4AuthorizationDenied):
        _promoter(plan).promote(
            summary, confirmation, changed_plan, _binding(),
            onboarding_binding=_onboarding_binding(), now_epoch=NOW + 5,
        )


def test_lab_auto_factory_rejects_reused_protected_path(tmp_path) -> None:
    """The controls ledger must not share its authority key or database path."""

    shared = tmp_path / "shared"
    environment = {
        "FORTIPAM_MCP_SECRET_CREATE_LAB_AUTO_AUTHORITY_KEY_FILE": str(shared),
        "FORTIPAM_MCP_SECRET_CREATE_LAB_AUTO_EXECUTION_STATE_DB": str(shared),
        "FORTIPAM_MCP_SECRET_CREATE_LAB_AUTO_EXECUTION_STATE_HMAC_KEY_FILE": str(
            tmp_path / "execution-key"
        ),
        "FORTIPAM_MCP_SECRET_CREATE_LAB_AUTO_AUTHORIZED_ENVIRONMENT_REF": (
            "secret-environment-ref01"
        ),
        "FORTIPAM_MCP_SECRET_CREATE_LAB_AUTO_AUTHORIZED_SCOPE_REF": (
            "secret-scope-ref000001"
        ),
    }

    with pytest.raises(M4AuthorizationDenied):
        build_lab_auto_secret_session_controls_runner_factory(
            environment,
            planning=cast(SecretApprovalPlanningChainReader, object()),
            read_transport=cast(SecretSessionControlsReadTransport, object()),
            write_transport=cast(SecretSessionControlsWriteTransport, object()),
            rdp_event_filter_transport=cast(RdpEventFilterReadTransport, object()),
        )


@pytest.mark.parametrize("source_backed", [False, True])
def test_source_backed_host_registry_feeds_exact_controls_authorization(monkeypatch, source_backed) -> None:
    import test_secret_session_controls_m4_authorization as fixtures
    from fortipam_mcp.v4_runtime_host import _planning_registry

    registry = _planning_registry(source_backed=source_backed)
    monkeypatch.setattr(fixtures, "_promoted_registry", lambda: registry)
    planning, _authenticator, plan, _receipt = fixtures._claimed_chain()
    summary = planning.get_summary(plan.summary_ref, plan.summary_revision)
    confirmation = planning.get_confirmation(plan.confirmation_ref)
    promoter = LabAutoSecretSessionControlsPromoter(
        b"a" * 32, authorized_environment_ref=plan.environment_ref,
        authorized_scope_ref=plan.scope_ref,
    )
    if not source_backed:
        with pytest.raises(M4AuthorizationDenied):
            promoter.promote(
                summary, confirmation, plan, fixtures._binding(),
                onboarding_binding=fixtures._onboarding_binding(), now_epoch=NOW + 5,
            )
        return
    artifacts = promoter.promote(
        summary, confirmation, plan, fixtures._binding(),
        onboarding_binding=fixtures._onboarding_binding(), now_epoch=NOW + 5,
    )
    assert summary.action_family_ref == "windows-and-ad-privileged-access-plan"
    assert artifacts.binding.plan.action_id == fixtures.SECRET_SESSION_CONTROLS_ACTION_ID
    assert all(action["executable"] is False and action["adapter"] == "none"
               for action in registry["actions"])


def test_source_backed_families_match_catalog_without_enabling_actions() -> None:
    from fortipam_mcp.v4_runtime_host import _planning_registry
    from scripts.v4_registry import load_registry

    registry = _planning_registry(source_backed=True)
    catalog = {item["id"]: item["action_refs"] for item in load_registry()["blueprints"]}
    assert all(item["action_refs"] == catalog[item["id"]] for item in registry["blueprints"])
    assert {action["id"] for action in registry["actions"]} == {
        item["action_refs"][0] for item in registry["blueprints"]
    }
    assert all(action["executable"] is False and action["adapter"] == "none"
               and action["atomic_contract"] is False for action in registry["actions"])
