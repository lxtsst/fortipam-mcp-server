"""Source-bounded FortiPAM Secret onboarding planning requirements."""

from __future__ import annotations


V4_SECRET_BULK_IMPORT_PLAN_TOOL = "get_v4_secret_bulk_import_plan_requirements"
V4_SECRET_BULK_IMPORT_BUILD_TOOL = "build_v4_secret_bulk_import_plan"
V4_SECRET_BULK_IMPORT_BUILD_CONTRACT = (
    "fortipam_v4_secret_bulk_import_plan_builder_v1"
)
V4_SECRET_BULK_IMPORT_APPLY_TOOL = "get_v4_secret_bulk_import_apply_requirements"
V4_LAUNCHER_CLONE_PLAN_TOOL = "get_v4_launcher_clone_plan_requirements"
V4_POLICY_ASSIGN_PLAN_TOOL = "get_v4_policy_assign_plan_requirements"

_CONTRACTS = {
    "secret.bulk-import.plan": "fortipam_v4_secret_bulk_import_plan_v1",
    "secret.bulk-import.apply": "fortipam_v4_secret_bulk_import_apply_v1",
    "launcher.clone": "fortipam_v4_launcher_clone_plan_v1",
    "policy.assign": "fortipam_v4_policy_assign_plan_v1",
}

_SECRET_BULK_IMPORT_PLAN_EVIDENCE_FIELDS = (
    "template_schema_verified",
    "fixed_scope_dependencies_verified",
    "protected_file_custody_ready",
    "value_free_preview_verified",
    "duplicate_conflict_policy_verified",
    "bounded_row_limits_defined",
    "preview_binding_verified",
    "cleanup_recovery_approved",
)


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
        "protected_material_loaded": False,
        "import_file_loaded": False,
        "secret_created": False,
        "launcher_cloned": False,
        "policy_assigned": False,
        "session_effect_applied": False,
        "local_state_written": False,
        "raw_source_content_returned": False,
    }


def secret_bulk_import_plan_requirements() -> dict[str, object]:
    return _requirements(
        "secret.bulk-import.plan",
        (
            "product_template_schema_and_required_columns",
            "folder_target_template_and_secret_type_dependencies",
            "credential_and_protected_field_custody",
            "duplicate_existing_object_and_conflict_detection",
            "row_level_validation_and_redacted_error_categories",
            "preview_expiry_and_apply_binding",
        ),
        (
            "exact_1_9_1_template_and_import_schema_verified",
            "fixed_isolated_folder_targets_and_secret_types_approved",
            "protected_file_provider_isolated_from_model_and_mcp",
            "value_free_preview_and_row_count_limits_verified",
            "duplicate_conflict_and_partial_failure_policy_verified",
            "no_credential_identity_or_object_identifier_return_enforced",
            "preview_expiry_and_exact_apply_binding_verified",
            "cleanup_reconciliation_permissions_and_live_acceptance_completed",
        ),
        (
            "device_folder_target_template_or_secret_state_read",
            "file_row_credential_folder_target_template_or_selector_input",
            "template_download_or_import_file_load",
            "secret_create_update_overwrite_or_delete",
            "credential_validation_or_target_contact",
            "identity_object_or_row_result_return",
            "execution_authorization",
        ),
    )


def secret_bulk_import_apply_requirements() -> dict[str, object]:
    return _requirements(
        "secret.bulk-import.apply",
        (
            "exact_unexpired_preview_and_file_digest_binding",
            "all_or_nothing_or_documented_partial_import_semantics",
            "duplicate_conflict_skip_and_overwrite_behavior",
            "per_row_creation_and_dependency_order",
            "credential_no_readback_and_redacted_result_policy",
            "failure_reconciliation_cleanup_and_compensation",
        ),
        (
            "exact_1_9_1_apply_transport_and_categorical_readback_verified",
            "fixed_isolated_scope_and_absent_object_set_approved",
            "protected_file_provider_isolated_from_model_and_mcp",
            "one_time_preview_bound_authorization_and_drift_rejection_verified",
            "overwrite_disabled_and_duplicate_behavior_prevalidated",
            "bounded_count_timeout_cancel_and_partial_failure_tests_approved",
            "categorical_presence_no_credential_readback_verified",
            "cleanup_compensation_reconciliation_permissions_and_live_acceptance_completed",
        ),
        (
            "device_folder_target_template_or_secret_state_read",
            "file_row_credential_folder_target_template_preview_or_selector_input",
            "bulk_import_execute_retry_resume_or_overwrite",
            "secret_create_update_delete_or_credential_change",
            "target_authentication_or_connectivity_test",
            "credential_identity_object_or_row_result_return",
            "execution_authorization",
        ),
    )


def build_secret_bulk_import_plan(
    *,
    template_schema_verified: bool,
    fixed_scope_dependencies_verified: bool,
    protected_file_custody_ready: bool,
    value_free_preview_verified: bool,
    duplicate_conflict_policy_verified: bool,
    bounded_row_limits_defined: bool,
    preview_binding_verified: bool,
    cleanup_recovery_approved: bool,
) -> dict[str, object]:
    """Evaluate a value-free, caller-attested bulk-import planning checklist."""

    evidence = {
        "template_schema_verified": template_schema_verified,
        "fixed_scope_dependencies_verified": fixed_scope_dependencies_verified,
        "protected_file_custody_ready": protected_file_custody_ready,
        "value_free_preview_verified": value_free_preview_verified,
        "duplicate_conflict_policy_verified": duplicate_conflict_policy_verified,
        "bounded_row_limits_defined": bounded_row_limits_defined,
        "preview_binding_verified": preview_binding_verified,
        "cleanup_recovery_approved": cleanup_recovery_approved,
    }
    if any(type(value) is not bool for value in evidence.values()):
        raise ValueError("Secret bulk-import plan evidence must be boolean.")
    missing = [
        name
        for name in _SECRET_BULK_IMPORT_PLAN_EVIDENCE_FIELDS
        if not evidence[name]
    ]
    return {
        "contract": V4_SECRET_BULK_IMPORT_BUILD_CONTRACT,
        "action_family": "secret.bulk-import.plan",
        "target_version": "1.9.1",
        "planning_status": (
            "ready_for_operator_review" if not missing else "incomplete_evidence"
        ),
        "evidence_origin": "caller_attested_categorical_inputs",
        "missing_requirements": missing,
        "satisfied_requirement_count": (
            len(_SECRET_BULK_IMPORT_PLAN_EVIDENCE_FIELDS) - len(missing)
        ),
        "requirement_count": len(_SECRET_BULK_IMPORT_PLAN_EVIDENCE_FIELDS),
        "plan_ready": not missing,
        "authoritative_device_state_observed": False,
        "import_file_loaded": False,
        "preview_generated": False,
        "apply_execution_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "local_state_written": False,
        "protected_material_accepted": False,
        "raw_source_content_returned": False,
    }


def launcher_clone_plan_requirements() -> dict[str, object]:
    return _requirements(
        "launcher.clone",
        (
            "source_launcher_complete_projection",
            "destination_name_and_absence_requirement",
            "protocol_client_port_timeout_and_matcher_preservation",
            "template_secret_target_and_policy_reference_exclusion",
            "credential_parameter_and_protected_field_handling",
            "clone_lifecycle_and_session_control_impact",
        ),
        (
            "exact_1_9_1_clone_transport_and_categorical_readback_verified",
            "fixed_unattached_source_and_absent_destination_approved",
            "complete_preserved_field_allowlist_and_digest_verified",
            "protected_parameter_provider_isolated_from_mcp",
            "template_secret_target_policy_reference_exclusion_verified",
            "no_launch_or_session_effect_acceptance_tested",
            "rollback_or_delete_contract_verified",
            "failure_reconciliation_permissions_and_live_acceptance_completed",
        ),
        (
            "device_launcher_template_secret_target_or_policy_state_read",
            "source_destination_parameter_reference_or_selector_input",
            "launcher_clone_create_update_disable_or_delete",
            "template_secret_target_or_policy_association_change",
            "client_launch_or_session_change",
            "protected_parameter_or_raw_projection_return",
            "execution_authorization",
        ),
    )


def policy_assign_plan_requirements() -> dict[str, object]:
    return _requirements(
        "policy.assign",
        (
            "secret_and_secret_policy_complete_baselines",
            "existing_policy_reference_and_assignment_precedence",
            "access_approval_launcher_recording_filter_and_clipboard_effects",
            "folder_inheritance_and_secret_override_interaction",
            "active_request_launch_and_session_impact",
            "detach_restore_and_rollback_semantics",
        ),
        (
            "exact_1_9_1_assignment_transport_and_categorical_readback_verified",
            "fixed_nonproduction_secret_policy_and_unassigned_baseline_approved",
            "complete_secret_and_policy_preservation_projection_verified",
            "folder_inheritance_precedence_and_access_impact_prevalidated",
            "active_request_launch_and_session_absence_verified",
            "detach_restore_and_rollback_contract_verified",
            "negative_positive_drift_and_failure_reconciliation_tests_approved",
            "least_privilege_and_live_acceptance_completed",
        ),
        (
            "device_secret_policy_folder_request_or_session_state_read",
            "secret_policy_folder_user_or_selector_input",
            "secret_policy_assign_detach_update_or_delete",
            "folder_inheritance_acl_or_approval_change",
            "launch_access_request_or_session_change",
            "identity_secret_policy_or_raw_projection_return",
            "execution_authorization",
        ),
    )


__all__ = [
    "V4_SECRET_BULK_IMPORT_PLAN_TOOL",
    "V4_SECRET_BULK_IMPORT_BUILD_TOOL",
    "V4_SECRET_BULK_IMPORT_BUILD_CONTRACT",
    "V4_SECRET_BULK_IMPORT_APPLY_TOOL",
    "V4_LAUNCHER_CLONE_PLAN_TOOL",
    "V4_POLICY_ASSIGN_PLAN_TOOL",
    "secret_bulk_import_plan_requirements",
    "build_secret_bulk_import_plan",
    "secret_bulk_import_apply_requirements",
    "launcher_clone_plan_requirements",
    "policy_assign_plan_requirements",
]
