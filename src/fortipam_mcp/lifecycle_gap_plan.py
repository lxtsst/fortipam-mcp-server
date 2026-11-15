"""Source-bounded lifecycle-gap and Secret-metadata planning requirements."""

from __future__ import annotations


V4_TARGET_DISABLE_PLAN_TOOL = "get_v4_target_disable_plan_requirements"
V4_SECRET_METADATA_UPDATE_PLAN_TOOL = (
    "get_v4_secret_metadata_update_plan_requirements"
)
V4_APPROVAL_PROFILE_DISABLE_PLAN_TOOL = (
    "get_v4_approval_profile_disable_plan_requirements"
)
V4_SECRET_DISABLE_CONTRACT_GAP_TOOL = (
    "get_v4_secret_disable_contract_gap"
)
V4_LAUNCHER_DISABLE_CONTRACT_GAP_TOOL = (
    "get_v4_launcher_disable_contract_gap"
)

_CONTRACTS = {
    "target.disable": "fortipam_v4_target_disable_plan_v1",
    "secret.update-metadata": "fortipam_v4_secret_metadata_update_plan_v1",
    "approval-profile.disable": "fortipam_v4_approval_profile_disable_plan_v1",
    "secret.disable": "fortipam_v4_secret_disable_contract_gap_v1",
    "launcher.disable": "fortipam_v4_launcher_disable_contract_gap_v1",
}


def _requirements(
    action_family: str,
    source_version: str,
    target_validation_required: bool,
    lifecycle_contract_established: bool,
    documented: tuple[str, ...],
    acceptance: tuple[str, ...],
    blocked: tuple[str, ...],
) -> dict[str, object]:
    return {
        "contract": _CONTRACTS[action_family],
        "action_family": action_family,
        "source_version": source_version,
        "target_version": "1.9.1",
        "target_version_validation_required": target_validation_required,
        "planning_status": "requirements_only",
        "lifecycle_contract_established": lifecycle_contract_established,
        "documented_requirements": list(documented),
        "project_acceptance_requirements": list(acceptance),
        "blocked_operations": list(blocked),
        "configuration_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "protected_material_loaded": False,
        "target_state_changed": False,
        "secret_metadata_changed": False,
        "approval_profile_state_changed": False,
        "access_or_session_effect_applied": False,
        "local_state_written": False,
        "raw_source_content_returned": False,
    }


def _target_version_unavailable(result: dict[str, object]) -> dict[str, object]:
    result["planning_status"] = "product_unavailable_in_target_version"
    result["action_available"] = False
    result["resolution_requires_implementation"] = False
    result["resolution_scope"] = "fortipam_1_9_1_only"
    return result


def target_disable_plan_requirements() -> dict[str, object]:
    result = _requirements(
        "target.disable",
        "1.9.1",
        False,
        False,
        (
            "target_create_edit_delete_semantics_are_documented",
            "target_web_proxy_feature_enable_disable_is_not_target_lifecycle",
            "no_target_lifecycle_disable_field_or_command_is_established",
            "no_status_field_may_be_guessed_or_repurposed",
            "target_secret_policy_launcher_and_session_reference_impact",
            "availability_recovery_and_reenable_semantics_required",
        ),
        (
            "authoritative_1_9_1_target_lifecycle_field_or_command_obtained",
            "exact_read_write_and_categorical_readback_contract_verified",
            "fixed_nonproduction_target_and_complete_baseline_approved",
            "secret_policy_launcher_and_active_session_impact_prevalidated",
            "disable_reenable_and_rollback_semantics_verified",
            "negative_wrong_feature_and_drift_tests_approved",
            "least_privilege_and_failure_reconciliation_verified",
            "live_acceptance_completed",
        ),
        (
            "device_target_secret_policy_launcher_or_session_state_read",
            "target_feature_status_or_selector_input",
            "target_create_update_disable_delete_or_web_proxy_change",
            "secret_policy_launcher_or_session_change",
            "reachability_or_authentication_test",
            "identity_target_or_raw_result_return",
            "execution_authorization",
        ),
    )
    return _target_version_unavailable(result)


def secret_metadata_update_plan_requirements() -> dict[str, object]:
    return _requirements(
        "secret.update-metadata",
        "latest-provider-guidance",
        True,
        False,
        (
            "provider_guidance_supports_value_bearing_secret_crud",
            "native_secret_records_may_contain_value_beside_metadata",
            "metadata_only_delta_must_exclude_secret_material",
            "template_field_schema_and_required_field_preservation",
            "folder_target_policy_launcher_and_access_reference_impact",
            "no_readback_rollback_and_reconciliation_semantics",
        ),
        (
            "exact_1_9_1_metadata_only_update_transport_verified",
            "fixed_nonproduction_secret_and_complete_redacted_baseline_approved",
            "field_level_allowlist_excludes_every_material_value",
            "protected_material_provider_is_not_invoked_for_metadata_delta",
            "template_folder_target_policy_launcher_preservation_verified",
            "access_request_launch_and_session_impact_prevalidated",
            "rollback_and_no_material_categorical_readback_verified",
            "least_privilege_failure_reconciliation_and_live_acceptance_completed",
        ),
        (
            "device_secret_field_material_or_reference_state_read",
            "secret_metadata_value_template_folder_target_policy_or_selector_input",
            "secret_create_update_move_disable_or_delete",
            "credential_key_token_or_protected_field_change",
            "folder_target_policy_launcher_access_or_session_change",
            "secret_material_identity_or_raw_result_return",
            "execution_authorization",
        ),
    )


def approval_profile_disable_plan_requirements() -> dict[str, object]:
    result = _requirements(
        "approval-profile.disable",
        "1.9.1",
        False,
        False,
        (
            "approval_profile_create_update_and_tier_semantics_are_documented",
            "no_profile_lifecycle_disable_field_or_command_is_established",
            "approval_tier_or_email_controls_are_not_profile_lifecycle",
            "no_status_or_feature_field_may_be_guessed_or_repurposed",
            "secret_policy_request_and_pending_approval_reference_impact",
            "availability_recovery_and_reenable_semantics_required",
        ),
        (
            "authoritative_1_9_1_profile_lifecycle_field_or_command_obtained",
            "exact_read_write_and_categorical_readback_contract_verified",
            "fixed_unreferenced_nonproduction_profile_and_baseline_approved",
            "tier_template_secret_policy_and_pending_request_impact_prevalidated",
            "disable_reenable_and_rollback_semantics_verified",
            "negative_wrong_feature_and_drift_tests_approved",
            "least_privilege_and_failure_reconciliation_verified",
            "live_acceptance_completed",
        ),
        (
            "device_profile_tier_template_policy_request_or_session_state_read",
            "profile_feature_status_or_selector_input",
            "approval_profile_create_update_disable_or_delete",
            "tier_template_delivery_policy_or_request_change",
            "approval_notification_or_access_test",
            "identity_profile_request_or_raw_result_return",
            "execution_authorization",
        ),
    )
    return _target_version_unavailable(result)


def secret_disable_contract_gap() -> dict[str, object]:
    result = _requirements(
        "secret.disable",
        "1.9.1",
        False,
        False,
        (
            "secret_create_edit_delete_and_feature_settings_are_documented",
            "observed_secret_status_fields_belong_to_nested_feature_settings",
            "totp_status_is_not_secret_entry_lifecycle_state",
            "no_secret_entry_disable_field_or_command_is_established",
            "no_nested_status_field_may_be_guessed_or_repurposed",
            "access_request_launch_session_and_reference_impact_required",
        ),
        (
            "authoritative_1_9_1_secret_lifecycle_field_or_command_obtained",
            "exact_read_write_and_categorical_readback_contract_verified",
            "fixed_nonproduction_secret_and_redacted_baseline_approved",
            "material_reference_access_request_launch_and_session_impact_prevalidated",
            "disable_reenable_and_no_material_rollback_semantics_verified",
            "negative_nested_feature_and_drift_tests_approved",
            "least_privilege_failure_reconciliation_and_live_acceptance_completed",
        ),
        (
            "device_secret_material_feature_reference_access_or_session_state_read",
            "secret_feature_status_material_reference_or_selector_input",
            "secret_create_update_move_disable_or_delete",
            "credential_key_token_totp_or_nested_feature_change",
            "access_request_launch_or_session_change",
            "secret_material_identity_or_raw_result_return",
            "execution_authorization",
        ),
    )
    return _target_version_unavailable(result)


def launcher_disable_contract_gap() -> dict[str, object]:
    result = _requirements(
        "launcher.disable",
        "1.9.1",
        False,
        False,
        (
            "launcher_create_clone_edit_delete_and_matcher_semantics_are_documented",
            "bounded_launcher_reads_exposed_no_lifecycle_status_field",
            "launcher_timeout_matcher_and_command_fields_are_not_lifecycle_state",
            "no_launcher_disable_field_or_command_is_established",
            "no_status_or_feature_field_may_be_guessed_or_repurposed",
            "secret_template_policy_launch_and_session_reference_impact_required",
        ),
        (
            "authoritative_1_9_1_launcher_lifecycle_field_or_command_obtained",
            "exact_read_write_and_categorical_readback_contract_verified",
            "fixed_unattached_nonproduction_launcher_and_baseline_approved",
            "secret_template_policy_launch_and_active_session_impact_prevalidated",
            "disable_reenable_and_rollback_semantics_verified",
            "negative_wrong_field_and_drift_tests_approved",
            "least_privilege_failure_reconciliation_and_live_acceptance_completed",
        ),
        (
            "device_launcher_secret_template_policy_launch_or_session_state_read",
            "launcher_feature_status_command_matcher_or_selector_input",
            "launcher_create_clone_update_disable_or_delete",
            "secret_template_policy_matcher_launch_or_session_change",
            "executable_command_identity_or_raw_result_return",
            "execution_authorization",
        ),
    )
    return _target_version_unavailable(result)


__all__ = [
    "V4_TARGET_DISABLE_PLAN_TOOL",
    "V4_SECRET_METADATA_UPDATE_PLAN_TOOL",
    "V4_APPROVAL_PROFILE_DISABLE_PLAN_TOOL",
    "V4_SECRET_DISABLE_CONTRACT_GAP_TOOL",
    "V4_LAUNCHER_DISABLE_CONTRACT_GAP_TOOL",
    "target_disable_plan_requirements",
    "secret_metadata_update_plan_requirements",
    "approval_profile_disable_plan_requirements",
    "secret_disable_contract_gap",
    "launcher_disable_contract_gap",
]
