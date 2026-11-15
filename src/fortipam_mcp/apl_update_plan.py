"""Source-bounded FortiPAM Auto Provision Rule update requirements."""

from __future__ import annotations


V4_APL_UPDATE_PLAN_TOOL = "get_v4_apl_update_plan_requirements"
V4_APL_UPDATE_PLAN_CONTRACT = "fortipam_v4_apl_update_plan_v1"


def apl_update_plan_requirements() -> dict[str, object]:
    """Return fixed non-executable Auto Provision Rule update requirements."""

    return {
        "contract": V4_APL_UPDATE_PLAN_CONTRACT,
        "action_family": "apl.update",
        "source_version": "1.9.0",
        "target_version": "1.9.1",
        "target_version_validation_required": True,
        "planning_status": "requirements_only",
        "documented_requirements": [
            "existing_rule_status_order_and_complete_baseline",
            "remote_group_role_and_delegation_user_dependencies",
            "login_schedule_and_trusted_host_restrictions",
            "provisioned_user_license_and_auto_purge_behavior",
            "out_of_sync_and_next_successful_login_effect",
            "saml_scim_attribute_and_session_dependencies",
        ],
        "project_acceptance_requirements": [
            "exact_1_9_1_update_transport_and_redacted_readback_verified",
            "fixed_disabled_nonproduction_rule_and_complete_baseline_approved",
            "remote_group_role_delegation_schedule_and_trust_dependencies_verified",
            "rule_order_matching_and_existing_provisioned_user_impact_analyzed",
            "out_of_sync_auto_purge_license_and_active_session_effects_approved",
            "local_admin_and_non_apl_authentication_recovery_verified",
            "rollback_and_reenable_contract_verified",
            "negative_positive_failure_reconciliation_tests_approved",
        ],
        "blocked_operations": [
            "fortipam_identity_provider_or_scim_state_read",
            "rule_group_role_user_schedule_network_or_attribute_input",
            "apl_create_update_reorder_enable_disable_or_delete",
            "user_provision_deprovision_purge_or_session_termination",
            "authentication_login_or_mapping_test",
            "configuration_write",
            "execution_authorization",
        ],
        "configuration_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "identity_system_contacted": False,
        "provisioning_effect_applied": False,
        "authentication_effect_applied": False,
        "local_state_written": False,
        "raw_source_content_returned": False,
    }


__all__ = [
    "V4_APL_UPDATE_PLAN_CONTRACT",
    "V4_APL_UPDATE_PLAN_TOOL",
    "apl_update_plan_requirements",
]
