"""Source-bounded FortiPAM route and DNS planning requirements.

The available official configuration guidance is version 1.9.0.  These
no-input contracts target a future 1.9.1 validation and never promote those
GUI field categories into an executable API or CLI contract.
"""

from __future__ import annotations


V4_ROUTE_PLAN_TOOL = "get_v4_route_plan_requirements"
V4_ROUTE_PLAN_CONTRACT = "fortipam_v4_route_plan_v1"
V4_ROUTE_BUILD_TOOL = "build_v4_route_plan"
V4_ROUTE_BUILD_CONTRACT = "fortipam_v4_route_plan_builder_v1"
V4_DNS_PLAN_TOOL = "get_v4_dns_plan_requirements"
V4_DNS_PLAN_CONTRACT = "fortipam_v4_dns_plan_v1"
V4_DNS_BUILD_TOOL = "build_v4_dns_plan"
V4_DNS_BUILD_CONTRACT = "fortipam_v4_dns_plan_builder_v1"

_ROUTE_DOCUMENTED_REQUIREMENTS = (
    "ipv4_destination_and_network_mask",
    "gateway_unless_blackhole_interface",
    "selected_interface_or_blackhole",
    "administrative_distance",
    "optional_comments",
    "enabled_or_disabled_status",
    "route_controls_fortipam_traffic_flow",
)

_ROUTE_ACCEPTANCE_REQUIREMENTS = (
    "exact_1_9_1_field_and_transport_contract_verified",
    "current_complete_route_table_and_sequence_verified",
    "fixed_destination_gateway_interface_and_distance_owner_approved",
    "management_data_fortiguard_dns_ntp_ha_and_target_paths_impact_analyzed",
    "out_of_band_console_and_lockout_recovery_verified",
    "ha_peer_ordering_and_synchronization_verified",
    "categorical_pre_and_post_reachability_checks_defined",
    "separately_confirmed_rollback_and_failure_reconciliation_approved",
)

_ROUTE_BLOCKED_OPERATIONS = (
    "device_state_read",
    "destination_gateway_interface_or_distance_input",
    "route_sequence_or_status_input",
    "route_create_update_delete_or_clone",
    "blackhole_route_change",
    "reachability_probe",
    "configuration_write",
    "execution_authorization",
)

_DNS_DOCUMENTED_REQUIREMENTS = (
    "fortiguard_or_specified_dns_server_mode",
    "primary_and_secondary_ipv4_or_ipv6_servers",
    "up_to_eight_local_domain_names",
    "clear_text_dns_dot_and_doh_protocol_controls",
    "ssl_certificate_selection",
    "up_to_four_server_hostnames",
    "dns_supports_appliance_name_resolution",
)

_DNS_ACCEPTANCE_REQUIREMENTS = (
    "exact_1_9_1_field_and_transport_contract_verified",
    "current_complete_dns_configuration_verified",
    "fixed_resolvers_protocols_domains_certificate_and_hostnames_owner_approved",
    "management_fortiguard_license_ntp_ha_and_target_dependencies_analyzed",
    "resolver_reachability_and_validated_tls_trust_verified",
    "out_of_band_console_and_name_resolution_recovery_verified",
    "categorical_pre_and_post_resolution_checks_defined",
    "separately_confirmed_rollback_and_failure_reconciliation_approved",
)

_DNS_BLOCKED_OPERATIONS = (
    "device_state_read",
    "resolver_domain_certificate_or_hostname_input",
    "dns_protocol_or_server_mode_input",
    "dns_query_or_reachability_probe",
    "certificate_import_or_selection",
    "configuration_write",
    "execution_authorization",
)

_ROUTE_PLAN_EVIDENCE_FIELDS = (
    "target_contract_verified",
    "current_route_table_verified",
    "fixed_change_owner_approved",
    "dependency_impact_analyzed",
    "out_of_band_recovery_verified",
    "ha_ordering_verified",
    "pre_post_checks_defined",
    "rollback_reconciliation_approved",
)

_DNS_PLAN_EVIDENCE_FIELDS = (
    "target_contract_verified",
    "current_dns_configuration_verified",
    "fixed_change_owner_approved",
    "dependency_impact_analyzed",
    "resolver_tls_trust_verified",
    "out_of_band_recovery_verified",
    "pre_post_checks_defined",
    "rollback_reconciliation_approved",
)


def route_plan_requirements() -> dict[str, object]:
    """Return a fixed 1.9.0-source/1.9.1-target route boundary."""

    return {
        "contract": V4_ROUTE_PLAN_CONTRACT,
        "action_family": "route.configure",
        "source_version": "1.9.0",
        "target_version": "1.9.1",
        "target_version_validation_required": True,
        "planning_status": "requirements_only",
        "documented_requirements": list(_ROUTE_DOCUMENTED_REQUIREMENTS),
        "project_acceptance_requirements": list(_ROUTE_ACCEPTANCE_REQUIREMENTS),
        "blocked_operations": list(_ROUTE_BLOCKED_OPERATIONS),
        "configuration_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "local_state_written": False,
        "raw_source_content_returned": False,
    }


def dns_plan_requirements() -> dict[str, object]:
    """Return a fixed 1.9.0-source/1.9.1-target DNS boundary."""

    return {
        "contract": V4_DNS_PLAN_CONTRACT,
        "action_family": "dns.configure",
        "source_version": "1.9.0",
        "target_version": "1.9.1",
        "target_version_validation_required": True,
        "planning_status": "requirements_only",
        "documented_requirements": list(_DNS_DOCUMENTED_REQUIREMENTS),
        "project_acceptance_requirements": list(_DNS_ACCEPTANCE_REQUIREMENTS),
        "blocked_operations": list(_DNS_BLOCKED_OPERATIONS),
        "configuration_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "local_state_written": False,
        "raw_source_content_returned": False,
    }


def _build_plan(
    *,
    contract: str,
    action_family: str,
    evidence_fields: tuple[str, ...],
    evidence: dict[str, bool],
) -> dict[str, object]:
    if any(type(value) is not bool for value in evidence.values()):
        raise ValueError("Network plan evidence must be boolean.")
    missing = [name for name in evidence_fields if not evidence[name]]
    return {
        "contract": contract,
        "action_family": action_family,
        "source_version": "1.9.0",
        "target_version": "1.9.1",
        "target_version_validation_required": True,
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


def build_route_plan(
    *,
    target_contract_verified: bool,
    current_route_table_verified: bool,
    fixed_change_owner_approved: bool,
    dependency_impact_analyzed: bool,
    out_of_band_recovery_verified: bool,
    ha_ordering_verified: bool,
    pre_post_checks_defined: bool,
    rollback_reconciliation_approved: bool,
) -> dict[str, object]:
    """Evaluate a value-free, caller-attested route planning checklist."""

    return _build_plan(
        contract=V4_ROUTE_BUILD_CONTRACT,
        action_family="route.configure",
        evidence_fields=_ROUTE_PLAN_EVIDENCE_FIELDS,
        evidence={
            "target_contract_verified": target_contract_verified,
            "current_route_table_verified": current_route_table_verified,
            "fixed_change_owner_approved": fixed_change_owner_approved,
            "dependency_impact_analyzed": dependency_impact_analyzed,
            "out_of_band_recovery_verified": out_of_band_recovery_verified,
            "ha_ordering_verified": ha_ordering_verified,
            "pre_post_checks_defined": pre_post_checks_defined,
            "rollback_reconciliation_approved": rollback_reconciliation_approved,
        },
    )


def build_dns_plan(
    *,
    target_contract_verified: bool,
    current_dns_configuration_verified: bool,
    fixed_change_owner_approved: bool,
    dependency_impact_analyzed: bool,
    resolver_tls_trust_verified: bool,
    out_of_band_recovery_verified: bool,
    pre_post_checks_defined: bool,
    rollback_reconciliation_approved: bool,
) -> dict[str, object]:
    """Evaluate a value-free, caller-attested DNS planning checklist."""

    return _build_plan(
        contract=V4_DNS_BUILD_CONTRACT,
        action_family="dns.configure",
        evidence_fields=_DNS_PLAN_EVIDENCE_FIELDS,
        evidence={
            "target_contract_verified": target_contract_verified,
            "current_dns_configuration_verified": current_dns_configuration_verified,
            "fixed_change_owner_approved": fixed_change_owner_approved,
            "dependency_impact_analyzed": dependency_impact_analyzed,
            "resolver_tls_trust_verified": resolver_tls_trust_verified,
            "out_of_band_recovery_verified": out_of_band_recovery_verified,
            "pre_post_checks_defined": pre_post_checks_defined,
            "rollback_reconciliation_approved": rollback_reconciliation_approved,
        },
    )


__all__ = [
    "V4_DNS_BUILD_CONTRACT",
    "V4_DNS_BUILD_TOOL",
    "V4_DNS_PLAN_CONTRACT",
    "V4_DNS_PLAN_TOOL",
    "V4_ROUTE_BUILD_CONTRACT",
    "V4_ROUTE_BUILD_TOOL",
    "V4_ROUTE_PLAN_CONTRACT",
    "V4_ROUTE_PLAN_TOOL",
    "build_dns_plan",
    "build_route_plan",
    "dns_plan_requirements",
    "route_plan_requirements",
]
