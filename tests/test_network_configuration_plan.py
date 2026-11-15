from __future__ import annotations

from fortipam_mcp.network_configuration_plan import (
    V4_DNS_BUILD_CONTRACT,
    V4_DNS_PLAN_CONTRACT,
    V4_ROUTE_BUILD_CONTRACT,
    V4_ROUTE_PLAN_CONTRACT,
    build_dns_plan,
    build_route_plan,
    dns_plan_requirements,
    route_plan_requirements,
)


def _assert_common_boundary(result: dict[str, object]) -> None:
    assert result["source_version"] == "1.9.0"
    assert result["target_version"] == "1.9.1"
    assert result["target_version_validation_required"] is True
    assert result["planning_status"] == "requirements_only"
    assert result["configuration_ready"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False
    assert result["local_state_written"] is False
    assert result["raw_source_content_returned"] is False


def test_route_plan_is_version_bounded_and_non_executable() -> None:
    result = route_plan_requirements()

    _assert_common_boundary(result)
    assert result["contract"] == V4_ROUTE_PLAN_CONTRACT
    assert result["action_family"] == "route.configure"
    assert "configuration_write" in result["blocked_operations"]
    assert "reachability_probe" in result["blocked_operations"]


def test_dns_plan_is_version_bounded_and_non_executable() -> None:
    result = dns_plan_requirements()

    _assert_common_boundary(result)
    assert result["contract"] == V4_DNS_PLAN_CONTRACT
    assert result["action_family"] == "dns.configure"
    assert "configuration_write" in result["blocked_operations"]
    assert "dns_query_or_reachability_probe" in result["blocked_operations"]


def test_network_plan_results_return_fresh_mutable_collections() -> None:
    first_route = route_plan_requirements()
    second_route = route_plan_requirements()
    first_dns = dns_plan_requirements()
    second_dns = dns_plan_requirements()

    first_route["documented_requirements"].clear()  # type: ignore[union-attr]
    first_dns["project_acceptance_requirements"].clear()  # type: ignore[union-attr]

    assert second_route["documented_requirements"]
    assert second_dns["project_acceptance_requirements"]


def test_route_builder_reports_only_categorical_missing_evidence() -> None:
    result = build_route_plan(
        target_contract_verified=True,
        current_route_table_verified=True,
        fixed_change_owner_approved=True,
        dependency_impact_analyzed=False,
        out_of_band_recovery_verified=True,
        ha_ordering_verified=True,
        pre_post_checks_defined=True,
        rollback_reconciliation_approved=True,
    )

    assert result["contract"] == V4_ROUTE_BUILD_CONTRACT
    assert result["action_family"] == "route.configure"
    assert result["planning_status"] == "incomplete_evidence"
    assert result["missing_requirements"] == ["dependency_impact_analyzed"]
    assert result["satisfied_requirement_count"] == 7
    assert result["requirement_count"] == 8
    assert result["plan_ready"] is False
    assert result["configuration_execution_ready"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False


def test_dns_builder_can_be_ready_for_review_but_never_execution() -> None:
    result = build_dns_plan(
        target_contract_verified=True,
        current_dns_configuration_verified=True,
        fixed_change_owner_approved=True,
        dependency_impact_analyzed=True,
        resolver_tls_trust_verified=True,
        out_of_band_recovery_verified=True,
        pre_post_checks_defined=True,
        rollback_reconciliation_approved=True,
    )

    assert result["contract"] == V4_DNS_BUILD_CONTRACT
    assert result["planning_status"] == "ready_for_operator_review"
    assert result["missing_requirements"] == []
    assert result["plan_ready"] is True
    assert result["authoritative_device_state_observed"] is False
    assert result["configuration_execution_ready"] is False
    assert result["execution_authorized"] is False
    assert result["local_state_written"] is False


def test_network_builders_reject_non_boolean_evidence() -> None:
    values: dict[str, object] = {
        "target_contract_verified": True,
        "current_route_table_verified": True,
        "fixed_change_owner_approved": True,
        "dependency_impact_analyzed": True,
        "out_of_band_recovery_verified": True,
        "ha_ordering_verified": True,
        "pre_post_checks_defined": True,
        "rollback_reconciliation_approved": "yes",
    }

    try:
        build_route_plan(**values)  # type: ignore[arg-type]
    except ValueError as exc:
        assert str(exc) == "Network plan evidence must be boolean."
    else:
        raise AssertionError("non-boolean route evidence was accepted")
