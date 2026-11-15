"""Source-pinned FortiPAM HA planning requirements.

These no-input contracts summarize the FortiPAM 1.9.1 Active-Passive HA
planning boundary.  They contain no topology values, device adapter, mutable
operation, or execution authority.
"""

from __future__ import annotations


V4_HA_CONFIGURE_PLAN_TOOL = "get_v4_ha_configure_plan_requirements"
V4_HA_CONFIGURE_PLAN_CONTRACT = "fortipam_v4_ha_configure_plan_v1"
V4_HA_CONFIGURE_BUILD_TOOL = "build_v4_ha_configure_plan"
V4_HA_CONFIGURE_BUILD_CONTRACT = "fortipam_v4_ha_configure_plan_builder_v1"
V4_HA_MAINTENANCE_PLAN_TOOL = "get_v4_ha_maintenance_plan_requirements"
V4_HA_MAINTENANCE_PLAN_CONTRACT = "fortipam_v4_ha_maintenance_plan_v1"
V4_HA_MAINTENANCE_BUILD_TOOL = "build_v4_ha_maintenance_plan"
V4_HA_MAINTENANCE_BUILD_CONTRACT = "fortipam_v4_ha_maintenance_plan_builder_v1"
V4_HA_RECONCILE_PLAN_TOOL = "get_v4_ha_reconcile_plan_requirements"
V4_HA_RECONCILE_PLAN_CONTRACT = "fortipam_v4_ha_reconcile_plan_v1"
V4_HA_RECONCILE_BUILD_TOOL = "build_v4_ha_reconcile_plan"
V4_HA_RECONCILE_BUILD_CONTRACT = "fortipam_v4_ha_reconcile_plan_builder_v1"

_CONFIGURE_DOCUMENTED_REQUIREMENTS = (
    "standalone_or_active_passive_mode",
    "one_primary_and_up_to_two_passive_members",
    "same_device_model_version_and_vm_platform",
    "non_dhcp_interface_addresses_before_cluster_configuration",
    "cluster_group_name_and_shared_password",
    "device_priority_and_per_node_override_behavior",
    "one_or_more_dedicated_heartbeat_interfaces",
    "unicast_or_broadcast_heartbeat_design",
    "optional_reserved_management_interface_and_static_route",
    "license_capacity_review_for_each_member",
    "configuration_synchronization_and_primary_only_task_behavior",
    "primary_local_log_and_recording_constraints",
)

_CONFIGURE_ACCEPTANCE_REQUIREMENTS = (
    "exact_1_9_1_field_and_transport_contract_verified",
    "complete_current_state_for_every_candidate_member_verified",
    "fixed_member_topology_interfaces_group_and_priorities_owner_approved",
    "model_version_platform_and_license_compatibility_verified",
    "heartbeat_isolation_bandwidth_and_failure_domains_reviewed",
    "management_and_out_of_band_recovery_paths_verified",
    "configuration_backup_and_service_impact_window_approved",
    "ordered_per_node_join_failover_rollback_and_readback_plan_approved",
    "credential_material_kept_outside_model_mcp_and_plan_state",
)

_CONFIGURE_BLOCKED_OPERATIONS = (
    "device_or_cluster_state_read",
    "member_interface_address_or_topology_input",
    "group_name_id_password_or_peer_input",
    "license_certificate_or_credential_input",
    "interface_route_or_heartbeat_change",
    "cluster_create_join_remove_or_mode_change",
    "reboot_shutdown_failover_or_maintenance_change",
    "configuration_write",
    "execution_authorization",
)

_MAINTENANCE_DOCUMENTED_REQUIREMENTS = (
    "critical_process_suspension_impact",
    "maximum_duration_and_operator_reason",
    "renewal_and_deactivation_lifecycle",
    "post_failover_primary_maintenance_state",
    "cluster_role_and_service_availability_check",
    "planned_work_and_recovery_sequence",
)

_MAINTENANCE_ACCEPTANCE_REQUIREMENTS = (
    "exact_1_9_1_maintenance_and_ha_transport_contract_verified",
    "current_role_sync_health_and_maintenance_state_verified",
    "fixed_member_duration_reason_and_work_scope_owner_approved",
    "critical_process_session_and_availability_impact_analyzed",
    "out_of_band_access_and_expiry_recovery_verified",
    "pre_and_post_cluster_health_readback_defined",
    "separately_confirmed_deactivation_and_failure_reconciliation_approved",
)

_MAINTENANCE_BLOCKED_OPERATIONS = (
    "device_or_cluster_state_read",
    "member_duration_reason_or_work_scope_input",
    "maintenance_activate_renew_or_deactivate",
    "session_or_process_control",
    "failover_reboot_or_shutdown",
    "firmware_license_backup_or_restore_operation",
    "configuration_write",
    "execution_authorization",
)

_RECONCILE_DOCUMENTED_REQUIREMENTS = (
    "cluster_member_role_status_and_uptime",
    "configuration_synchronization_state",
    "model_version_platform_and_license_compatibility",
    "heartbeat_and_monitored_interface_health",
    "priority_override_and_primary_selection",
    "maintenance_and_recent_failover_state",
    "primary_local_log_and_recording_boundaries",
)

_RECONCILE_ACCEPTANCE_REQUIREMENTS = (
    "exact_1_9_1_read_only_status_contract_verified",
    "fixed_complete_member_inventory_and_expected_roles_owner_approved",
    "categorical_role_health_and_in_sync_grammar_verified",
    "per_node_unsynchronized_settings_and_local_evidence_accounted_for",
    "stale_partial_split_brain_and_unknown_states_fail_closed",
    "no_automatic_repair_failover_join_remove_or_write",
    "separate_remediation_preview_and_authorization_required",
)

_RECONCILE_BLOCKED_OPERATIONS = (
    "device_or_cluster_state_read",
    "member_selector_or_expected_topology_input",
    "raw_status_configuration_log_or_recording_output",
    "automatic_repair_or_synchronization",
    "member_join_remove_or_role_change",
    "maintenance_failover_reboot_or_shutdown",
    "configuration_write",
    "execution_authorization",
)

_CONFIGURE_PLAN_EVIDENCE_FIELDS = (
    "target_contract_verified",
    "complete_member_state_verified",
    "fixed_topology_owner_approved",
    "platform_license_compatibility_verified",
    "heartbeat_failure_domains_reviewed",
    "management_recovery_verified",
    "backup_impact_window_approved",
    "ordered_change_rollback_readback_approved",
    "protected_material_custody_ready",
)

_MAINTENANCE_PLAN_EVIDENCE_FIELDS = (
    "target_contract_verified",
    "current_cluster_state_verified",
    "fixed_scope_owner_approved",
    "service_impact_analyzed",
    "expiry_recovery_verified",
    "pre_post_health_checks_defined",
    "deactivation_reconciliation_approved",
)

_RECONCILE_PLAN_EVIDENCE_FIELDS = (
    "readonly_contract_verified",
    "expected_member_inventory_approved",
    "categorical_health_grammar_verified",
    "per_node_evidence_accounted_for",
    "uncertain_states_fail_closed",
    "automatic_changes_disabled",
    "separate_remediation_control_verified",
)


def _requirements(
    *,
    contract: str,
    action_family: str,
    documented: tuple[str, ...],
    acceptance: tuple[str, ...],
    blocked: tuple[str, ...],
) -> dict[str, object]:
    return {
        "contract": contract,
        "action_family": action_family,
        "source_version": "1.9.1",
        "target_version": "1.9.1",
        "target_version_validation_required": False,
        "planning_status": "requirements_only",
        "documented_requirements": list(documented),
        "project_acceptance_requirements": list(acceptance),
        "blocked_operations": list(blocked),
        "configuration_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "local_state_written": False,
        "raw_source_content_returned": False,
    }


def ha_configure_plan_requirements() -> dict[str, object]:
    """Return fixed non-executable HA configuration requirements."""

    return _requirements(
        contract=V4_HA_CONFIGURE_PLAN_CONTRACT,
        action_family="ha.configure",
        documented=_CONFIGURE_DOCUMENTED_REQUIREMENTS,
        acceptance=_CONFIGURE_ACCEPTANCE_REQUIREMENTS,
        blocked=_CONFIGURE_BLOCKED_OPERATIONS,
    )


def ha_maintenance_plan_requirements() -> dict[str, object]:
    """Return fixed non-executable HA maintenance requirements."""

    return _requirements(
        contract=V4_HA_MAINTENANCE_PLAN_CONTRACT,
        action_family="ha.maintenance",
        documented=_MAINTENANCE_DOCUMENTED_REQUIREMENTS,
        acceptance=_MAINTENANCE_ACCEPTANCE_REQUIREMENTS,
        blocked=_MAINTENANCE_BLOCKED_OPERATIONS,
    )


def ha_reconcile_plan_requirements() -> dict[str, object]:
    """Return fixed non-executable HA reconciliation requirements."""

    return _requirements(
        contract=V4_HA_RECONCILE_PLAN_CONTRACT,
        action_family="ha.reconcile",
        documented=_RECONCILE_DOCUMENTED_REQUIREMENTS,
        acceptance=_RECONCILE_ACCEPTANCE_REQUIREMENTS,
        blocked=_RECONCILE_BLOCKED_OPERATIONS,
    )


def _build_plan(
    *,
    contract: str,
    action_family: str,
    evidence_fields: tuple[str, ...],
    evidence: dict[str, bool],
) -> dict[str, object]:
    if any(type(value) is not bool for value in evidence.values()):
        raise ValueError("HA plan evidence must be boolean.")
    missing = [name for name in evidence_fields if not evidence[name]]
    return {
        "contract": contract,
        "action_family": action_family,
        "source_version": "1.9.1",
        "target_version": "1.9.1",
        "target_version_validation_required": False,
        "planning_status": (
            "ready_for_operator_review" if not missing else "incomplete_evidence"
        ),
        "evidence_origin": "caller_attested_categorical_inputs",
        "missing_requirements": missing,
        "satisfied_requirement_count": len(evidence_fields) - len(missing),
        "requirement_count": len(evidence_fields),
        "plan_ready": not missing,
        "authoritative_device_state_observed": False,
        "configuration_execution_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "local_state_written": False,
        "protected_material_accepted": False,
        "raw_source_content_returned": False,
    }


def build_ha_configure_plan(
    *,
    target_contract_verified: bool,
    complete_member_state_verified: bool,
    fixed_topology_owner_approved: bool,
    platform_license_compatibility_verified: bool,
    heartbeat_failure_domains_reviewed: bool,
    management_recovery_verified: bool,
    backup_impact_window_approved: bool,
    ordered_change_rollback_readback_approved: bool,
    protected_material_custody_ready: bool,
) -> dict[str, object]:
    """Evaluate a value-free, caller-attested HA configuration checklist."""

    return _build_plan(
        contract=V4_HA_CONFIGURE_BUILD_CONTRACT,
        action_family="ha.configure",
        evidence_fields=_CONFIGURE_PLAN_EVIDENCE_FIELDS,
        evidence={
            "target_contract_verified": target_contract_verified,
            "complete_member_state_verified": complete_member_state_verified,
            "fixed_topology_owner_approved": fixed_topology_owner_approved,
            "platform_license_compatibility_verified": platform_license_compatibility_verified,
            "heartbeat_failure_domains_reviewed": heartbeat_failure_domains_reviewed,
            "management_recovery_verified": management_recovery_verified,
            "backup_impact_window_approved": backup_impact_window_approved,
            "ordered_change_rollback_readback_approved": ordered_change_rollback_readback_approved,
            "protected_material_custody_ready": protected_material_custody_ready,
        },
    )


def build_ha_maintenance_plan(
    *,
    target_contract_verified: bool,
    current_cluster_state_verified: bool,
    fixed_scope_owner_approved: bool,
    service_impact_analyzed: bool,
    expiry_recovery_verified: bool,
    pre_post_health_checks_defined: bool,
    deactivation_reconciliation_approved: bool,
) -> dict[str, object]:
    """Evaluate a value-free, caller-attested HA maintenance checklist."""

    return _build_plan(
        contract=V4_HA_MAINTENANCE_BUILD_CONTRACT,
        action_family="ha.maintenance",
        evidence_fields=_MAINTENANCE_PLAN_EVIDENCE_FIELDS,
        evidence={
            "target_contract_verified": target_contract_verified,
            "current_cluster_state_verified": current_cluster_state_verified,
            "fixed_scope_owner_approved": fixed_scope_owner_approved,
            "service_impact_analyzed": service_impact_analyzed,
            "expiry_recovery_verified": expiry_recovery_verified,
            "pre_post_health_checks_defined": pre_post_health_checks_defined,
            "deactivation_reconciliation_approved": deactivation_reconciliation_approved,
        },
    )


def build_ha_reconcile_plan(
    *,
    readonly_contract_verified: bool,
    expected_member_inventory_approved: bool,
    categorical_health_grammar_verified: bool,
    per_node_evidence_accounted_for: bool,
    uncertain_states_fail_closed: bool,
    automatic_changes_disabled: bool,
    separate_remediation_control_verified: bool,
) -> dict[str, object]:
    """Evaluate a value-free, caller-attested HA reconciliation checklist."""

    return _build_plan(
        contract=V4_HA_RECONCILE_BUILD_CONTRACT,
        action_family="ha.reconcile",
        evidence_fields=_RECONCILE_PLAN_EVIDENCE_FIELDS,
        evidence={
            "readonly_contract_verified": readonly_contract_verified,
            "expected_member_inventory_approved": expected_member_inventory_approved,
            "categorical_health_grammar_verified": categorical_health_grammar_verified,
            "per_node_evidence_accounted_for": per_node_evidence_accounted_for,
            "uncertain_states_fail_closed": uncertain_states_fail_closed,
            "automatic_changes_disabled": automatic_changes_disabled,
            "separate_remediation_control_verified": separate_remediation_control_verified,
        },
    )


__all__ = [
    "V4_HA_CONFIGURE_BUILD_CONTRACT",
    "V4_HA_CONFIGURE_BUILD_TOOL",
    "V4_HA_CONFIGURE_PLAN_CONTRACT",
    "V4_HA_CONFIGURE_PLAN_TOOL",
    "V4_HA_MAINTENANCE_BUILD_CONTRACT",
    "V4_HA_MAINTENANCE_BUILD_TOOL",
    "V4_HA_MAINTENANCE_PLAN_CONTRACT",
    "V4_HA_MAINTENANCE_PLAN_TOOL",
    "V4_HA_RECONCILE_BUILD_CONTRACT",
    "V4_HA_RECONCILE_BUILD_TOOL",
    "V4_HA_RECONCILE_PLAN_CONTRACT",
    "V4_HA_RECONCILE_PLAN_TOOL",
    "build_ha_configure_plan",
    "build_ha_maintenance_plan",
    "build_ha_reconcile_plan",
    "ha_configure_plan_requirements",
    "ha_maintenance_plan_requirements",
    "ha_reconcile_plan_requirements",
]
