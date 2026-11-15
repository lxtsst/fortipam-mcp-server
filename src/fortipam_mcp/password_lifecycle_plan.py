"""Source-bounded FortiPAM password-lifecycle planning requirements."""

from __future__ import annotations


V4_PASSWORD_CHANGER_CREATE_PLAN_TOOL = (
    "get_v4_password_changer_create_plan_requirements"
)
V4_PASSWORD_VERIFICATION_PLAN_TOOL = (
    "get_v4_password_verification_plan_requirements"
)
V4_CHECKOUT_POLICY_PLAN_TOOL = "get_v4_checkout_policy_plan_requirements"
V4_JIT_POLICY_PLAN_TOOL = "get_v4_jit_policy_plan_requirements"
V4_SERVICE_ACCOUNT_UPDATE_PLAN_TOOL = (
    "get_v4_service_account_update_plan_requirements"
)

_CONTRACTS = {
    "password-changer.create": "fortipam_v4_password_changer_create_plan_v1",
    "password-verification.configure": "fortipam_v4_password_verification_plan_v1",
    "checkout-policy.configure": "fortipam_v4_checkout_policy_plan_v1",
    "jit-policy.configure": "fortipam_v4_jit_policy_plan_v1",
    "service-account.update": "fortipam_v4_service_account_update_plan_v1",
}

_PASSWORD_CHANGER_COLLECTION_PATH = "/api/v2/cmdb/secret/password-changer"
_PASSWORD_CHANGER_DETAIL_PATH = "/api/v2/cmdb/secret/password-changer/{name}"


def _password_changer_create_api_candidate() -> dict[str, object]:
    """Return fixed non-callable catalog evidence for Password Changer creation."""

    return {
        "source": "sanitized_fndn_ui_catalog_1_9_0",
        "status": "catalogued_body_unproven",
        "create": {
            "method": "POST",
            "path": _PASSWORD_CHANGER_COLLECTION_PATH,
            "required_body": True,
            "body_schema_available": False,
        },
        "detail_readback": {
            "method": "GET",
            "path": _PASSWORD_CHANGER_DETAIL_PATH,
            "response_schema_available": False,
        },
        "target_version_validated": False,
        "live_call_permitted": False,
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
        "source_version": "1.9.0",
        "target_version": "1.9.1",
        "target_version_validation_required": True,
        "planning_status": "requirements_only",
        "documented_requirements": list(documented),
        "project_acceptance_requirements": list(acceptance),
        "blocked_operations": list(blocked),
        "configuration_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "target_contacted": False,
        "protected_material_loaded": False,
        "credential_changed_or_verified": False,
        "privilege_changed": False,
        "script_executed": False,
        "local_state_written": False,
        "raw_source_content_returned": False,
    }


def password_changer_create_plan_requirements() -> dict[str, object]:
    result = _requirements(
        "password-changer.create",
        (
            "supported_default_type_and_clone_only_customization",
            "changer_verifier_change_mode_and_verify_mode",
            "template_secret_target_and_password_policy_dependencies",
            "protected_procedure_and_authentication_material",
            "tls_protocol_port_and_server_identity_requirements",
            "reconciliation_and_reference_impact",
        ),
        (
            "exact_1_9_1_create_transport_and_redacted_readback_verified",
            "fixed_nonproduction_default_clone_and_absent_name_approved",
            "protected_procedure_and_material_provider_isolated_from_mcp",
            "template_secret_target_policy_and_reference_impact_verified",
            "tls_target_authentication_and_least_privilege_prevalidated",
            "changer_and_verifier_negative_positive_tests_approved",
            "rollback_or_delete_contract_verified",
            "failure_reconciliation_and_live_acceptance_completed",
        ),
        (
            "device_target_template_secret_or_changer_state_read",
            "name_type_procedure_authentication_policy_or_target_input",
            "password_changer_create_clone_update_or_delete",
            "secret_template_or_target_assignment_change",
            "password_change_verify_or_reconcile",
            "configuration_write",
            "execution_authorization",
        ),
    )
    result["candidate_api_contract"] = _password_changer_create_api_candidate()
    return result


def password_verification_plan_requirements() -> dict[str, object]:
    return _requirements(
        "password-verification.configure",
        (
            "secret_owner_configuration_prerequisite",
            "automatic_verification_enable_interval_and_start_time",
            "password_changer_verifier_target_and_template_dependencies",
            "target_reachability_and_credential_accuracy_effect",
            "verification_status_time_and_failure_categories",
            "reconciliation_and_manual_verification_interaction",
        ),
        (
            "exact_1_9_1_configuration_transport_and_categorical_readback_verified",
            "fixed_disabled_nonproduction_secret_and_complete_baseline_approved",
            "protected_credential_provider_isolated_from_model_and_mcp",
            "interval_schedule_load_target_and_lockout_impact_analyzed",
            "verifier_tls_authentication_and_least_privilege_verified",
            "manual_automatic_and_reconciliation_interactions_tested",
            "disable_or_rollback_contract_verified",
            "negative_positive_failure_reconciliation_tests_approved",
        ),
        (
            "device_target_secret_or_verifier_state_read",
            "secret_interval_schedule_changer_target_or_credential_input",
            "automatic_verification_enable_disable_or_update",
            "manual_or_automatic_password_verification",
            "password_change_or_reconciliation",
            "raw_status_time_target_or_credential_return",
            "execution_authorization",
        ),
    )


def checkout_policy_plan_requirements() -> dict[str, object]:
    return _requirements(
        "checkout-policy.configure",
        (
            "secret_checkout_and_checkin_lifecycle",
            "optional_powershell_or_ssh_script_assignment",
            "privileged_or_associated_secret_credential_resolution",
            "target_connectivity_and_script_failure_behavior",
            "approval_duration_session_and_password_change_dependencies",
            "checkin_cleanup_and_recovery_requirements",
        ),
        (
            "exact_1_9_1_configuration_transport_and_readback_verified",
            "fixed_nonproduction_secret_target_and_complete_baseline_approved",
            "protected_script_and_credential_provider_isolated_from_mcp",
            "checkout_approval_duration_and_concurrency_controls_verified",
            "target_command_and_output_limits_prevalidated",
            "checkin_failure_timeout_and_orphaned_access_recovery_verified",
            "disable_or_rollback_contract_verified",
            "negative_positive_failure_reconciliation_tests_approved",
        ),
        (
            "device_target_secret_checkout_or_session_state_read",
            "secret_script_command_target_credential_duration_or_approval_input",
            "checkout_policy_enable_disable_or_update",
            "secret_checkout_checkin_or_launch",
            "script_command_or_password_change_execution",
            "credential_result_or_session_return",
            "execution_authorization",
        ),
    )


def jit_policy_plan_requirements() -> dict[str, object]:
    return _requirements(
        "jit-policy.configure",
        (
            "checkout_and_checkin_script_pair",
            "windows_target_winrm_connectivity",
            "privileged_or_associated_secret_admin_credential_resolution",
            "temporary_group_membership_elevation_and_removal",
            "script_failure_warning_without_checkout_block",
            "orphaned_privilege_detection_and_recovery",
        ),
        (
            "exact_1_9_1_jit_configuration_and_categorical_readback_verified",
            "fixed_disposable_windows_target_user_group_and_secret_approved",
            "protected_script_and_admin_material_provider_isolated_from_mcp",
            "winrm_tls_network_command_and_group_scope_prevalidated",
            "time_bound_elevation_and_checkin_removal_verified",
            "failure_timeout_cancel_and_orphaned_privilege_recovery_verified",
            "rollback_and_emergency_deescalation_contract_verified",
            "negative_positive_failure_reconciliation_tests_approved",
        ),
        (
            "device_target_secret_group_or_privilege_state_read",
            "script_command_target_user_group_credential_or_duration_input",
            "jit_policy_enable_disable_or_update",
            "checkout_checkin_or_session_launch",
            "powershell_winrm_or_privilege_change_execution",
            "credential_output_or_identity_return",
            "execution_authorization",
        ),
    )


def service_account_update_plan_requirements() -> dict[str, object]:
    return _requirements(
        "service-account.update",
        (
            "dependency_updater_service_name_and_restart_behavior",
            "base_secret_target_and_service_account_dependencies",
            "current_and_proposed_credential_synchronization",
            "service_stop_restart_and_availability_impact",
            "dependency_refresh_status_and_failure_behavior",
            "password_change_reconciliation_and_rollback_interaction",
        ),
        (
            "exact_1_9_1_update_transport_and_categorical_readback_verified",
            "fixed_disposable_service_target_secret_and_dependency_approved",
            "protected_current_and_replacement_material_provider_isolated_from_mcp",
            "service_name_account_target_and_restart_scope_prevalidated",
            "availability_dependency_order_and_password_change_impact_analyzed",
            "target_and_service_credential_consistency_readback_verified",
            "rollback_or_reconciliation_contract_verified",
            "negative_positive_partial_update_and_failure_tests_approved",
        ),
        (
            "device_target_secret_dependency_or_service_state_read",
            "secret_target_service_account_credential_or_restart_input",
            "dependency_updater_create_update_or_assignment_change",
            "service_account_credential_update",
            "service_stop_restart_or_target_command_execution",
            "credential_status_or_raw_result_return",
            "execution_authorization",
        ),
    )


__all__ = [
    "V4_PASSWORD_CHANGER_CREATE_PLAN_TOOL",
    "V4_PASSWORD_VERIFICATION_PLAN_TOOL",
    "V4_CHECKOUT_POLICY_PLAN_TOOL",
    "V4_JIT_POLICY_PLAN_TOOL",
    "V4_SERVICE_ACCOUNT_UPDATE_PLAN_TOOL",
    "password_changer_create_plan_requirements",
    "password_verification_plan_requirements",
    "checkout_policy_plan_requirements",
    "jit_policy_plan_requirements",
    "service_account_update_plan_requirements",
]
