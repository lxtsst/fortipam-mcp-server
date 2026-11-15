"""Source-bounded FortiPAM delivery and integration planning requirements."""

from __future__ import annotations


V4_APPROVAL_DELIVERY_PLAN_TOOL = "get_v4_approval_delivery_plan_requirements"
V4_FABRIC_CONNECTOR_PLAN_TOOL = "get_v4_fabric_connector_plan_requirements"
V4_SECRET_GATEWAY_CHAIN_PLAN_TOOL = "get_v4_secret_gateway_chain_plan_requirements"
V4_REVERSE_SERVICE_PLAN_TOOL = "get_v4_reverse_service_plan_requirements"
V4_ZTNA_TAG_CREATE_PLAN_TOOL = "get_v4_ztna_tag_create_plan_requirements"
V4_ZTNA_TAG_GROUP_CREATE_PLAN_TOOL = "get_v4_ztna_tag_group_create_plan_requirements"

_CONTRACTS = {
    "approval-delivery.configure": "fortipam_v4_approval_delivery_plan_v1",
    "fabric-connector.configure": "fortipam_v4_fabric_connector_plan_v1",
    "secret-gateway.chain.configure": "fortipam_v4_secret_gateway_chain_plan_v1",
    "reverse-service.configure": "fortipam_v4_reverse_service_plan_v1",
    "ztna-tag.create": "fortipam_v4_ztna_tag_create_plan_v1",
    "ztna-tag-group.create": "fortipam_v4_ztna_tag_group_create_plan_v1",
}


def _requirements(
    action_family: str,
    documented: tuple[str, ...],
    acceptance: tuple[str, ...],
    blocked: tuple[str, ...],
) -> dict[str, object]:
    return {
        "contract": _CONTRACTS[action_family],
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
        "external_service_contacted": False,
        "protected_material_loaded": False,
        "topology_loaded": False,
        "notification_sent": False,
        "trust_changed": False,
        "routing_changed": False,
        "tag_changed": False,
        "policy_effect_applied": False,
        "local_state_written": False,
        "raw_source_content_returned": False,
    }


def approval_delivery_plan_requirements() -> dict[str, object]:
    return _requirements(
        "approval-delivery.configure",
        (
            "smtp_or_microsoft_graph_delivery_mode",
            "mailbox_sender_tenant_application_and_permission_dependencies",
            "protected_client_secret_or_mail_authentication_material",
            "approval_profile_template_and_recipient_routing",
            "tls_oauth_delivery_failure_and_retry_behavior",
            "privacy_rate_limit_audit_and_notification_impact",
        ),
        (
            "exact_1_9_1_configuration_transport_and_categorical_readback_verified",
            "fixed_nonproduction_mail_tenant_mailbox_and_disabled_baseline_approved",
            "protected_material_provider_isolated_from_model_and_mcp",
            "sender_recipient_scope_permissions_and_consent_prevalidated",
            "isolated_sink_and_no_external_delivery_test_mode_verified",
            "retry_rate_limit_privacy_and_failure_behavior_tested",
            "disable_or_rollback_contract_verified",
            "reconciliation_permissions_and_live_acceptance_completed",
        ),
        (
            "device_mailbox_tenant_profile_template_or_recipient_state_read",
            "endpoint_mailbox_tenant_application_secret_recipient_or_selector_input",
            "approval_delivery_enable_disable_or_update",
            "oauth_consent_permission_or_mailbox_change",
            "test_or_live_email_delivery",
            "identity_recipient_delivery_or_raw_result_return",
            "execution_authorization",
        ),
    )


def fabric_connector_plan_requirements() -> dict[str, object]:
    return _requirements(
        "fabric-connector.configure",
        (
            "connector_type_endpoint_and_management_domain",
            "interface_route_dns_and_tls_dependencies",
            "certificate_server_identity_and_authentication_material",
            "remote_inventory_synchronization_and_object_scope",
            "availability_trust_and_cross_system_impact",
            "disable_disconnect_and_recovery_semantics",
        ),
        (
            "exact_1_9_1_configuration_transport_and_categorical_readback_verified",
            "fixed_isolated_peer_endpoint_and_disabled_baseline_approved",
            "protected_material_and_topology_provider_isolated_from_mcp",
            "network_tls_identity_permissions_and_ownership_prevalidated",
            "bounded_sync_object_scope_and_no_policy_effect_verified",
            "disconnect_failure_timeout_and_recovery_tests_approved",
            "disable_or_rollback_contract_verified",
            "cross_system_reconciliation_and_live_acceptance_completed",
        ),
        (
            "device_peer_network_connector_or_inventory_state_read",
            "endpoint_interface_domain_certificate_credential_or_selector_input",
            "fabric_connector_create_update_enable_disable_or_delete",
            "remote_connection_inventory_or_synchronization",
            "route_dns_trust_policy_or_object_change",
            "topology_identity_inventory_or_raw_result_return",
            "execution_authorization",
        ),
    )


def secret_gateway_chain_plan_requirements() -> dict[str, object]:
    return _requirements(
        "secret-gateway.chain.configure",
        (
            "ordered_gateway_hops_and_forwarding_direction",
            "interfaces_addresses_routes_ports_and_service_dependencies",
            "gateway_identity_certificate_and_trust_requirements",
            "target_secret_policy_and_launcher_binding_impact",
            "loop_reachability_latency_and_failure_behavior",
            "chain_detach_reorder_and_recovery_semantics",
        ),
        (
            "exact_1_9_1_chain_transport_and_categorical_readback_verified",
            "fixed_disabled_isolated_gateways_and_unbound_baseline_approved",
            "protected_topology_and_material_provider_isolated_from_mcp",
            "hop_order_loop_route_port_tls_and_identity_checks_verified",
            "no_secret_target_policy_launcher_or_session_effect_prevalidated",
            "partial_chain_timeout_and_failure_recovery_tests_approved",
            "detach_or_rollback_contract_verified",
            "cross_hop_reconciliation_permissions_and_live_acceptance_completed",
        ),
        (
            "device_gateway_network_target_secret_policy_or_session_state_read",
            "gateway_hop_interface_address_port_certificate_or_selector_input",
            "gateway_chain_create_update_reorder_attach_detach_or_delete",
            "network_connection_forwarding_or_reachability_test",
            "route_trust_target_secret_policy_launcher_or_session_change",
            "topology_identity_or_raw_result_return",
            "execution_authorization",
        ),
    )


def reverse_service_plan_requirements() -> dict[str, object]:
    return _requirements(
        "reverse-service.configure",
        (
            "listener_interface_address_port_and_service_protocol",
            "certificate_common_name_and_tls_dependencies",
            "backend_target_gateway_and_route_dependencies",
            "authentication_policy_and_secret_binding_impact",
            "listener_conflict_exposure_and_availability_effect",
            "disable_drain_cleanup_and_recovery_semantics",
        ),
        (
            "exact_1_9_1_configuration_transport_and_categorical_readback_verified",
            "fixed_nonroutable_interface_port_backend_and_disabled_baseline_approved",
            "protected_topology_and_material_provider_isolated_from_mcp",
            "port_conflict_tls_identity_route_and_exposure_checks_verified",
            "no_external_listener_backend_or_policy_effect_prevalidated",
            "failure_timeout_drain_and_cleanup_tests_approved",
            "disable_or_rollback_contract_verified",
            "cross_system_reconciliation_permissions_and_live_acceptance_completed",
        ),
        (
            "device_network_listener_backend_policy_or_session_state_read",
            "interface_address_port_protocol_certificate_backend_or_selector_input",
            "reverse_service_create_update_enable_disable_or_delete",
            "listener_start_stop_connection_or_backend_test",
            "route_trust_policy_secret_or_session_change",
            "topology_identity_or_raw_result_return",
            "execution_authorization",
        ),
    )


def ztna_tag_create_plan_requirements() -> dict[str, object]:
    return _requirements(
        "ztna-tag.create",
        (
            "ems_connector_and_tag_synchronization_prerequisite",
            "tag_name_identifier_and_endpoint_posture_semantics",
            "access_proxy_policy_and_secret_control_references",
            "refresh_staleness_and_missing_endpoint_behavior",
            "authorization_access_and_session_impact",
            "reference_cleanup_and_lifecycle_semantics",
        ),
        (
            "exact_1_9_1_create_transport_and_categorical_readback_verified",
            "fixed_isolated_ems_tag_and_absent_unreferenced_baseline_approved",
            "no_external_topology_or_identity_input_enforced",
            "ems_ownership_sync_freshness_and_tag_identity_prevalidated",
            "zero_policy_secret_group_and_session_references_verified",
            "stale_missing_duplicate_and_failure_tests_approved",
            "rollback_or_delete_contract_verified",
            "cross_system_reconciliation_permissions_and_live_acceptance_completed",
        ),
        (
            "device_ems_tag_policy_secret_endpoint_or_session_state_read",
            "connector_tag_endpoint_policy_secret_or_selector_input",
            "ztna_tag_create_update_refresh_or_delete",
            "ems_synchronization_or_endpoint_query",
            "policy_secret_access_or_session_change",
            "tag_endpoint_identity_or_raw_result_return",
            "execution_authorization",
        ),
    )


def ztna_tag_group_create_plan_requirements() -> dict[str, object]:
    return _requirements(
        "ztna-tag-group.create",
        (
            "group_name_member_tags_and_boolean_match_semantics",
            "ems_connector_sync_and_member_freshness_dependencies",
            "access_proxy_policy_and_secret_control_references",
            "empty_missing_duplicate_and_stale_member_behavior",
            "authorization_access_and_session_impact",
            "reference_cleanup_and_lifecycle_semantics",
        ),
        (
            "exact_1_9_1_create_transport_and_categorical_readback_verified",
            "fixed_isolated_members_and_absent_unreferenced_group_approved",
            "no_external_topology_or_identity_input_enforced",
            "member_identity_boolean_semantics_and_sync_freshness_prevalidated",
            "zero_policy_secret_and_session_references_verified",
            "empty_missing_duplicate_stale_and_failure_tests_approved",
            "rollback_or_delete_contract_verified",
            "cross_system_reconciliation_permissions_and_live_acceptance_completed",
        ),
        (
            "device_ems_tag_group_policy_secret_endpoint_or_session_state_read",
            "connector_group_member_endpoint_policy_secret_or_selector_input",
            "ztna_tag_group_create_update_refresh_or_delete",
            "ems_synchronization_or_endpoint_query",
            "policy_secret_access_or_session_change",
            "tag_group_endpoint_identity_or_raw_result_return",
            "execution_authorization",
        ),
    )


__all__ = [
    "V4_APPROVAL_DELIVERY_PLAN_TOOL",
    "V4_FABRIC_CONNECTOR_PLAN_TOOL",
    "V4_SECRET_GATEWAY_CHAIN_PLAN_TOOL",
    "V4_REVERSE_SERVICE_PLAN_TOOL",
    "V4_ZTNA_TAG_CREATE_PLAN_TOOL",
    "V4_ZTNA_TAG_GROUP_CREATE_PLAN_TOOL",
    "approval_delivery_plan_requirements",
    "fabric_connector_plan_requirements",
    "secret_gateway_chain_plan_requirements",
    "reverse_service_plan_requirements",
    "ztna_tag_create_plan_requirements",
    "ztna_tag_group_create_plan_requirements",
]
