"""Source-bounded FortiPAM Discovery and Job workflow requirements."""

from __future__ import annotations


V4_DISCOVERY_ENTRY_CREATE_PLAN_TOOL = "get_v4_discovery_entry_create_plan_requirements"
V4_DISCOVERY_RUN_PLAN_TOOL = "get_v4_discovery_run_plan_requirements"
V4_DISCOVERY_REVIEW_PLAN_TOOL = "get_v4_discovery_review_plan_requirements"
V4_JOB_CREATE_PLAN_TOOL = "get_v4_job_create_plan_requirements"
V4_JOB_EXECUTE_PLAN_TOOL = "get_v4_job_execute_plan_requirements"

_CONTRACTS = {
    "discovery-entry.create": "fortipam_v4_discovery_entry_create_plan_v1",
    "discovery.run": "fortipam_v4_discovery_run_plan_v1",
    "discovery.review": "fortipam_v4_discovery_review_plan_v1",
    "job.create": "fortipam_v4_job_create_plan_v1",
    "job.execute": "fortipam_v4_job_execute_plan_v1",
}

_DISCOVERY_ENTRY_CREATE_PATH = "/api/v2/cmdb/secret/discovery"
_DISCOVERY_ENTRY_DETAIL_PATH = "/api/v2/cmdb/secret/discovery/{name}"


def _discovery_entry_api_candidate() -> dict[str, object]:
    """Return fixed non-callable catalog evidence for Discovery entry creation."""

    return {
        "source": "sanitized_fndn_ui_catalog_1_9_0",
        "status": "catalogued_body_unproven",
        "create": {
            "method": "POST",
            "path": _DISCOVERY_ENTRY_CREATE_PATH,
            "required_body": True,
            "body_schema_available": False,
        },
        "detail_readback": {
            "method": "GET",
            "path": _DISCOVERY_ENTRY_DETAIL_PATH,
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
        "network_scan_performed": False,
        "script_executed": False,
        "protected_material_loaded": False,
        "discovery_results_returned": False,
        "local_state_written": False,
        "raw_source_content_returned": False,
    }


def discovery_entry_create_plan_requirements() -> dict[str, object]:
    result = _requirements(
        "discovery-entry.create",
        (
            "active_directory_unix_or_fortios_source_type",
            "target_and_secret_reference_or_bounded_address_port_range",
            "account_only_or_resource_and_account_scope",
            "one_time_or_recurring_schedule",
            "directory_search_base_and_source_dependencies",
            "credential_privilege_and_network_scan_impact",
        ),
        (
            "exact_1_9_1_create_transport_and_redacted_readback_verified",
            "fixed_nonproduction_range_target_and_secret_references_approved",
            "protected_credential_provider_isolated_from_model_and_mcp",
            "network_ownership_segmentation_rate_and_egress_limits_verified",
            "schedule_overlap_and_scan_load_impact_analyzed",
            "result_retention_import_and_secret_creation_effects_disabled",
            "rollback_or_delete_contract_verified",
            "negative_positive_failure_reconciliation_tests_approved",
        ),
        (
            "device_target_directory_or_network_state_read",
            "address_port_target_secret_schedule_or_search_base_input",
            "discovery_entry_create_update_enable_disable_or_delete",
            "network_scan_account_or_resource_discovery",
            "result_import_secret_or_target_creation",
            "configuration_write",
            "execution_authorization",
        ),
    )
    result["candidate_api_contract"] = _discovery_entry_api_candidate()
    return result


def discovery_run_plan_requirements() -> dict[str, object]:
    return _requirements(
        "discovery.run",
        (
            "existing_disabled_entry_complete_baseline",
            "source_type_target_range_port_and_credential_dependencies",
            "manual_scan_or_scheduled_execution_scope",
            "network_account_and_resource_enumeration_impact",
            "result_retention_and_import_separation",
            "rate_timeout_cancel_and_failure_behavior",
        ),
        (
            "exact_1_9_1_scan_trigger_and_categorical_status_contract_verified",
            "fixed_nonproduction_entry_and_current_revision_owner_approved",
            "protected_credential_provider_isolated_from_model_and_mcp",
            "network_scope_rate_concurrency_timeout_and_cancel_limits_verified",
            "result_identifiers_accounts_addresses_and_ports_redacted",
            "automatic_import_and_mutation_disabled",
            "failure_cleanup_and_repeat_suppression_verified",
            "negative_positive_partial_scan_and_reconciliation_tests_approved",
        ),
        (
            "device_target_directory_or_network_state_read",
            "entry_range_target_secret_or_schedule_input",
            "network_scan_account_or_resource_discovery",
            "raw_status_result_address_port_account_or_credential_return",
            "result_import_secret_or_target_creation",
            "configuration_write",
            "execution_authorization",
        ),
    )


def discovery_review_plan_requirements() -> dict[str, object]:
    return _requirements(
        "discovery.review",
        (
            "fixed_completed_run_and_source_revision",
            "categorical_result_count_and_management_state",
            "sensitive_address_port_account_and_credential_fields",
            "view_refresh_and_import_separation",
            "retention_access_and_audit_requirements",
            "duplicate_stale_and_partial_result_handling",
        ),
        (
            "exact_1_9_1_result_query_and_minimized_projection_verified",
            "fixed_owned_nonproduction_run_reference_approved",
            "identity_address_port_account_and_credential_redaction_verified",
            "least_privilege_secret_discovery_read_permission_verified",
            "stale_partial_duplicate_and_error_categories_defined",
            "import_create_update_and_delete_operations_structurally_absent",
            "retention_and_audit_requirements_verified",
            "negative_positive_schema_and_oversize_tests_approved",
        ),
        (
            "caller_supplied_run_source_result_or_account_input",
            "network_scan_or_refresh",
            "raw_result_address_port_account_credential_or_identity_return",
            "result_import_secret_or_target_creation",
            "result_update_or_delete",
            "configuration_write",
            "execution_authorization",
        ),
    )


def job_create_plan_requirements() -> dict[str, object]:
    return _requirements(
        "job.create",
        (
            "requester_secret_and_optional_associated_secret",
            "disabled_by_default_activation_decision",
            "one_time_or_recurring_schedule",
            "ssh_script_ssh_procedure_web_api_or_powershell_type",
            "newline_mode_and_protected_script_content",
            "approval_maintenance_mode_result_and_log_dependencies",
        ),
        (
            "exact_1_9_1_create_transport_and_redacted_readback_verified",
            "fixed_disabled_nonproduction_job_and_secret_dependencies_approved",
            "script_and_credential_material_provider_isolated_from_model_and_mcp",
            "requester_approval_target_and_command_scope_prevalidated",
            "schedule_concurrency_timeout_output_and_maintenance_impact_analyzed",
            "job_created_disabled_with_no_automatic_execution_verified",
            "rollback_or_delete_contract_verified",
            "negative_positive_failure_reconciliation_tests_approved",
        ),
        (
            "device_target_or_secret_state_read",
            "requester_secret_schedule_type_script_or_command_input",
            "job_create_update_activate_disable_or_delete",
            "script_command_procedure_or_api_execution",
            "credential_or_result_log_return",
            "configuration_write",
            "execution_authorization",
        ),
    )


def job_execute_plan_requirements() -> dict[str, object]:
    return _requirements(
        "job.execute",
        (
            "existing_job_secret_requester_and_script_revision",
            "approval_request_and_authorization_state",
            "maintenance_mode_and_target_availability",
            "one_time_or_recurring_execution_scope",
            "timeout_cancel_idempotency_and_concurrency_behavior",
            "result_log_output_and_credential_redaction",
        ),
        (
            "exact_1_9_1_execute_transport_status_and_readback_verified",
            "fixed_nonproduction_job_revision_target_and_window_owner_approved",
            "protected_script_and_credential_provider_isolated_from_mcp",
            "independent_approval_requester_and_least_privilege_verified",
            "command_target_network_timeout_and_output_limits_verified",
            "maintenance_cancel_retry_and_ambiguous_commit_behavior_defined",
            "categorical_result_and_audit_readback_verified",
            "negative_positive_failure_reconciliation_and_replay_tests_approved",
        ),
        (
            "device_target_job_secret_or_approval_state_read",
            "job_requester_secret_script_command_target_or_schedule_input",
            "approval_request_or_confirmation",
            "script_command_procedure_or_api_execution",
            "raw_result_log_output_credential_or_identity_return",
            "configuration_write",
            "execution_authorization",
        ),
    )


__all__ = [
    "V4_DISCOVERY_ENTRY_CREATE_PLAN_TOOL",
    "V4_DISCOVERY_RUN_PLAN_TOOL",
    "V4_DISCOVERY_REVIEW_PLAN_TOOL",
    "V4_JOB_CREATE_PLAN_TOOL",
    "V4_JOB_EXECUTE_PLAN_TOOL",
    "discovery_entry_create_plan_requirements",
    "discovery_run_plan_requirements",
    "discovery_review_plan_requirements",
    "job_create_plan_requirements",
    "job_execute_plan_requirements",
]
