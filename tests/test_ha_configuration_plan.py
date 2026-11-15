from __future__ import annotations

from fortipam_mcp.ha_configuration_plan import (
    V4_HA_CONFIGURE_BUILD_CONTRACT,
    V4_HA_CONFIGURE_PLAN_CONTRACT,
    V4_HA_MAINTENANCE_BUILD_CONTRACT,
    V4_HA_MAINTENANCE_PLAN_CONTRACT,
    V4_HA_RECONCILE_BUILD_CONTRACT,
    V4_HA_RECONCILE_PLAN_CONTRACT,
    build_ha_configure_plan,
    build_ha_maintenance_plan,
    build_ha_reconcile_plan,
    ha_configure_plan_requirements,
    ha_maintenance_plan_requirements,
    ha_reconcile_plan_requirements,
)


def _assert_common_boundary(result: dict[str, object]) -> None:
    assert result["source_version"] == "1.9.1"
    assert result["target_version"] == "1.9.1"
    assert result["target_version_validation_required"] is False
    assert result["planning_status"] == "requirements_only"
    assert result["configuration_ready"] is False
    assert result["execution_authorized"] is False
    assert result["fortipam_contacted"] is False
    assert result["local_state_written"] is False
    assert result["raw_source_content_returned"] is False


def test_ha_configure_plan_is_source_pinned_and_non_executable() -> None:
    result = ha_configure_plan_requirements()

    _assert_common_boundary(result)
    assert result["contract"] == V4_HA_CONFIGURE_PLAN_CONTRACT
    assert result["action_family"] == "ha.configure"
    assert "cluster_create_join_remove_or_mode_change" in result["blocked_operations"]
    assert "configuration_write" in result["blocked_operations"]


def test_ha_maintenance_plan_is_source_pinned_and_non_executable() -> None:
    result = ha_maintenance_plan_requirements()

    _assert_common_boundary(result)
    assert result["contract"] == V4_HA_MAINTENANCE_PLAN_CONTRACT
    assert result["action_family"] == "ha.maintenance"
    assert "maintenance_activate_renew_or_deactivate" in result["blocked_operations"]


def test_ha_reconcile_plan_is_source_pinned_and_non_executable() -> None:
    result = ha_reconcile_plan_requirements()

    _assert_common_boundary(result)
    assert result["contract"] == V4_HA_RECONCILE_PLAN_CONTRACT
    assert result["action_family"] == "ha.reconcile"
    assert "automatic_repair_or_synchronization" in result["blocked_operations"]
    assert "raw_status_configuration_log_or_recording_output" in result[
        "blocked_operations"
    ]


def test_ha_plan_results_return_fresh_mutable_collections() -> None:
    first = ha_configure_plan_requirements()
    second = ha_configure_plan_requirements()
    maintenance = ha_maintenance_plan_requirements()
    reconcile = ha_reconcile_plan_requirements()

    first["documented_requirements"].clear()  # type: ignore[union-attr]
    maintenance["project_acceptance_requirements"].clear()  # type: ignore[union-attr]
    reconcile["blocked_operations"].clear()  # type: ignore[union-attr]

    assert second["documented_requirements"]
    assert ha_maintenance_plan_requirements()["project_acceptance_requirements"]
    assert ha_reconcile_plan_requirements()["blocked_operations"]


def test_ha_configure_builder_reports_categorical_missing_evidence() -> None:
    result = build_ha_configure_plan(
        target_contract_verified=True,
        complete_member_state_verified=True,
        fixed_topology_owner_approved=True,
        platform_license_compatibility_verified=True,
        heartbeat_failure_domains_reviewed=False,
        management_recovery_verified=True,
        backup_impact_window_approved=True,
        ordered_change_rollback_readback_approved=True,
        protected_material_custody_ready=True,
    )

    assert result["contract"] == V4_HA_CONFIGURE_BUILD_CONTRACT
    assert result["planning_status"] == "incomplete_evidence"
    assert result["missing_requirements"] == [
        "heartbeat_failure_domains_reviewed"
    ]
    assert result["satisfied_requirement_count"] == 8
    assert result["requirement_count"] == 9
    assert result["configuration_execution_ready"] is False
    assert result["execution_authorized"] is False


def test_ha_maintenance_builder_can_be_ready_for_review_only() -> None:
    result = build_ha_maintenance_plan(
        target_contract_verified=True,
        current_cluster_state_verified=True,
        fixed_scope_owner_approved=True,
        service_impact_analyzed=True,
        expiry_recovery_verified=True,
        pre_post_health_checks_defined=True,
        deactivation_reconciliation_approved=True,
    )

    assert result["contract"] == V4_HA_MAINTENANCE_BUILD_CONTRACT
    assert result["planning_status"] == "ready_for_operator_review"
    assert result["plan_ready"] is True
    assert result["authoritative_device_state_observed"] is False
    assert result["configuration_execution_ready"] is False
    assert result["fortipam_contacted"] is False


def test_ha_reconcile_builder_never_repairs_or_authorizes() -> None:
    result = build_ha_reconcile_plan(
        readonly_contract_verified=True,
        expected_member_inventory_approved=True,
        categorical_health_grammar_verified=True,
        per_node_evidence_accounted_for=True,
        uncertain_states_fail_closed=True,
        automatic_changes_disabled=True,
        separate_remediation_control_verified=False,
    )

    assert result["contract"] == V4_HA_RECONCILE_BUILD_CONTRACT
    assert result["action_family"] == "ha.reconcile"
    assert result["missing_requirements"] == [
        "separate_remediation_control_verified"
    ]
    assert result["plan_ready"] is False
    assert result["configuration_execution_ready"] is False
    assert result["execution_authorized"] is False
    assert result["local_state_written"] is False


def test_ha_builder_rejects_non_boolean_evidence() -> None:
    values: dict[str, object] = {
        "readonly_contract_verified": True,
        "expected_member_inventory_approved": True,
        "categorical_health_grammar_verified": True,
        "per_node_evidence_accounted_for": True,
        "uncertain_states_fail_closed": True,
        "automatic_changes_disabled": True,
        "separate_remediation_control_verified": 1,
    }

    try:
        build_ha_reconcile_plan(**values)  # type: ignore[arg-type]
    except ValueError as exc:
        assert str(exc) == "HA plan evidence must be boolean."
    else:
        raise AssertionError("non-boolean HA evidence was accepted")
