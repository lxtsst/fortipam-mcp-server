"""Source-bounded FortiPAM SCIM-client lifecycle requirements."""

from __future__ import annotations


V4_SCIM_CLIENT_CREATE_PLAN_TOOL = "get_v4_scim_client_create_plan_requirements"
V4_SCIM_CLIENT_CREATE_PLAN_CONTRACT = "fortipam_v4_scim_client_create_plan_v1"
V4_SCIM_CLIENT_ROTATE_PLAN_TOOL = "get_v4_scim_client_rotate_plan_requirements"
V4_SCIM_CLIENT_ROTATE_PLAN_CONTRACT = "fortipam_v4_scim_client_rotate_plan_v1"
V4_SCIM_CLIENT_DISABLE_PLAN_TOOL = "get_v4_scim_client_disable_plan_requirements"
V4_SCIM_CLIENT_DISABLE_PLAN_CONTRACT = "fortipam_v4_scim_client_disable_plan_v1"

_COMMON_BLOCKED_OPERATIONS = (
    "fortipam_or_scim_system_state_read",
    "endpoint_interface_certificate_or_authentication_material_input",
    "scim_request_connection_or_tls_test",
    "scim_client_create_update_rotate_disable_or_delete",
    "user_group_role_apl_or_saml_change",
    "user_provision_update_deprovision_or_session_termination",
    "configuration_write",
    "execution_authorization",
)


def _requirements(
    *,
    contract: str,
    action_family: str,
    documented: tuple[str, ...],
    acceptance: tuple[str, ...],
) -> dict[str, object]:
    return {
        "contract": contract,
        "action_family": action_family,
        "source_version": "1.9.0",
        "target_version": "1.9.1",
        "target_version_validation_required": True,
        "planning_status": "requirements_only",
        "documented_requirements": list(documented),
        "project_acceptance_requirements": list(acceptance),
        "blocked_operations": list(_COMMON_BLOCKED_OPERATIONS),
        "configuration_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "scim_system_contacted": False,
        "protected_material_loaded": False,
        "provisioning_effect_applied": False,
        "local_state_written": False,
        "raw_source_content_returned": False,
    }


def scim_client_create_plan_requirements() -> dict[str, object]:
    """Return fixed non-executable SCIM-client creation requirements."""

    return _requirements(
        contract=V4_SCIM_CLIENT_CREATE_PLAN_CONTRACT,
        action_family="scim-client.create",
        documented=(
            "advertised_host_service_port_and_generated_scim_url",
            "server_certificate_and_listening_interfaces",
            "authentication_method_and_protected_secret",
            "remote_provider_ca_and_optional_client_identity_check",
            "saml_scim_client_and_group_attribute_binding",
            "apl_user_group_role_and_session_enforcement_dependencies",
        ),
        acceptance=(
            "exact_1_9_1_transport_fields_and_redacted_readback_verified",
            "fixed_nonproduction_scim_system_and_absent_name_owner_approved",
            "protected_authentication_material_provider_isolated_from_mcp",
            "tls_server_client_identity_interface_and_egress_controls_verified",
            "saml_apl_group_role_and_attribute_mapping_prevalidated",
            "provision_update_deprovision_and_active_session_impact_analyzed",
            "local_admin_and_non_scim_recovery_path_verified",
            "negative_positive_failure_reconciliation_and_rollback_tests_approved",
        ),
    )


def scim_client_rotate_plan_requirements() -> dict[str, object]:
    """Return fixed non-executable SCIM-client rotation requirements."""

    return _requirements(
        contract=V4_SCIM_CLIENT_ROTATE_PLAN_CONTRACT,
        action_family="scim-client.rotate",
        documented=(
            "existing_client_complete_baseline",
            "authentication_secret_or_certificate_rotation_scope",
            "provider_and_fortipam_cutover_order",
            "tls_identity_and_interface_continuity",
            "saml_apl_group_and_role_dependencies",
            "provisioning_and_active_session_continuity",
        ),
        acceptance=(
            "exact_1_9_1_update_transport_and_redacted_readback_verified",
            "fixed_existing_client_and_complete_dependency_baseline_verified",
            "new_and_retiring_material_overlap_and_cutover_owner_approved",
            "protected_material_provider_isolated_from_model_and_mcp",
            "tls_and_provider_acceptance_before_old_material_retirement_verified",
            "provisioning_queue_user_group_and_active_session_impact_analyzed",
            "rollback_window_and_local_admin_recovery_verified",
            "negative_positive_partial_cutover_and_failure_tests_approved",
        ),
    )


def scim_client_disable_plan_requirements() -> dict[str, object]:
    """Return fixed non-executable SCIM-client disable requirements."""

    return _requirements(
        contract=V4_SCIM_CLIENT_DISABLE_PLAN_CONTRACT,
        action_family="scim-client.disable",
        documented=(
            "existing_client_complete_baseline",
            "inbound_scim_service_and_profile_status",
            "saml_apl_group_role_and_attribute_dependencies",
            "pending_provisioning_and_deprovisioning_impact",
            "currently_logged_in_user_authorization_impact",
            "re_enable_and_local_admin_recovery",
        ),
        acceptance=(
            "exact_1_9_1_disable_transport_and_redacted_readback_verified",
            "fixed_existing_client_and_complete_dependency_baseline_verified",
            "provisioning_freeze_deprovisioning_and_session_impact_owner_approved",
            "external_scim_sender_quiescence_verified",
            "saml_apl_group_role_and_user_state_consistency_verified",
            "local_admin_and_non_scim_access_recovery_verified",
            "re_enable_or_rollback_contract_verified",
            "negative_positive_failure_reconciliation_tests_approved",
        ),
    )


__all__ = [
    "V4_SCIM_CLIENT_CREATE_PLAN_CONTRACT",
    "V4_SCIM_CLIENT_CREATE_PLAN_TOOL",
    "V4_SCIM_CLIENT_ROTATE_PLAN_CONTRACT",
    "V4_SCIM_CLIENT_ROTATE_PLAN_TOOL",
    "V4_SCIM_CLIENT_DISABLE_PLAN_CONTRACT",
    "V4_SCIM_CLIENT_DISABLE_PLAN_TOOL",
    "scim_client_create_plan_requirements",
    "scim_client_rotate_plan_requirements",
    "scim_client_disable_plan_requirements",
]
