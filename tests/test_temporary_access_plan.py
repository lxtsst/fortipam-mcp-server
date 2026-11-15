from __future__ import annotations

from typing import cast

from fortipam_mcp.temporary_access_plan import (
    V4_TEMPORARY_ACCESS_PLAN_CONTRACT,
    temporary_access_plan_requirements,
)


def test_temporary_access_plan_is_version_bounded_and_non_executable() -> None:
    result = temporary_access_plan_requirements()

    assert result["contract"] == V4_TEMPORARY_ACCESS_PLAN_CONTRACT
    assert result["action_family"] == "sponsored-and-temporary-access-plan"
    assert result["blueprint_ref"] == "FPA-BP-015"
    assert result["skill_sku"] == "FPA-SK-015"
    assert result["source_version"] == "1.9.1"
    assert result["target_version"] == "7.0.0"
    assert result["target_version_validation_required"] is True
    assert result["planning_status"] == "requirements_only"
    assert result["source_contract_status"] == (
        "requirements_only_no_product_write_contract"
    )
    assert result["candidate_api_contract_available"] is False

    for key in (
        "configuration_ready",
        "execution_authorized",
        "fortipam_contacted",
        "external_identity_service_contacted",
        "protected_material_loaded",
        "access_effect_applied",
        "local_state_written",
        "raw_source_content_returned",
    ):
        assert result[key] is False


def test_temporary_access_plan_keeps_required_controls_distinct() -> None:
    result = temporary_access_plan_requirements()

    assert result["required_information"] == [
        "sponsor",
        "scope",
        "end_date",
        "group",
        "review_cadence",
        "revocation_owner",
    ]
    assert result["control_layers"] == [
        "identity",
        "group_membership",
        "entitlement",
        "schedule",
        "approval_and_sponsor_visibility",
        "audit_and_access_review",
    ]
    assert result["project_acceptance_requirements"] == [
        "sponsor_visibility",
        "expiry_or_explicit_revoke_negative_test",
        "minimized_audit_evidence",
        "partial_result_reconciliation",
    ]
    blocked_operations = cast(list[str], result["blocked_operations"])
    assert "configuration_write" in blocked_operations
    assert "execution_authorization" in blocked_operations


def test_temporary_access_plan_returns_fresh_mutable_collections() -> None:
    first = temporary_access_plan_requirements()
    second = temporary_access_plan_requirements()

    cast(list[object], first["required_information"]).clear()
    cast(list[object], first["control_layers"]).clear()
    cast(list[object], first["project_acceptance_requirements"]).clear()
    cast(list[object], first["blocked_operations"]).clear()

    assert second["required_information"]
    assert second["control_layers"]
    assert second["project_acceptance_requirements"]
    assert second["blocked_operations"]
