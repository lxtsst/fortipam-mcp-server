"""Source-bounded FortiPAM Secret experience planning requirements."""

from __future__ import annotations


V4_INSTRUCTION_PROFILE_CREATE_PLAN_TOOL = (
    "get_v4_instruction_profile_create_plan_requirements"
)
V4_EVENT_SUBSCRIPTION_PLAN_TOOL = (
    "get_v4_event_subscription_plan_requirements"
)

_CONTRACTS = {
    "instruction-profile.create": "fortipam_v4_instruction_profile_create_plan_v1",
    "event-subscription.configure": "fortipam_v4_event_subscription_plan_v1",
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
        "protected_material_loaded": False,
        "instruction_content_loaded": False,
        "resource_uploaded": False,
        "subscription_changed": False,
        "notification_sent": False,
        "secret_attachment_changed": False,
        "local_state_written": False,
        "raw_source_content_returned": False,
    }


def instruction_profile_create_plan_requirements() -> dict[str, object]:
    return _requirements(
        "instruction-profile.create",
        (
            "profile_name_and_formatted_instruction_content",
            "optional_instruction_resource_uploads",
            "resource_linking_and_content_rendering",
            "later_secret_attachment_and_visibility_scope",
            "content_safety_size_type_and_retention_controls",
            "reference_impact_and_profile_lifecycle",
        ),
        (
            "exact_1_9_1_create_transport_and_categorical_readback_verified",
            "fixed_absent_nonproduction_name_and_unattached_baseline_approved",
            "protected_content_and_resource_provider_isolated_from_mcp",
            "content_size_type_rendering_and_active_content_policy_verified",
            "secret_reference_and_viewer_permission_impact_prevalidated",
            "resource_upload_replacement_and_cleanup_contract_verified",
            "rollback_or_delete_contract_verified",
            "failure_reconciliation_and_live_acceptance_completed",
        ),
        (
            "device_profile_resource_or_secret_state_read",
            "name_content_resource_secret_or_selector_input",
            "instruction_profile_create_update_or_delete",
            "resource_upload_download_replace_or_delete",
            "secret_attachment_or_visibility_change",
            "content_or_resource_return",
            "execution_authorization",
        ),
    )


def event_subscription_plan_requirements() -> dict[str, object]:
    return _requirements(
        "event-subscription.configure",
        (
            "currently_authenticated_user_scope",
            "single_secret_permission_prerequisite",
            "secret_event_category_selection",
            "global_email_notification_and_user_email_dependencies",
            "automatic_disablement_after_permission_loss",
            "notification_delivery_privacy_and_rate_impact",
        ),
        (
            "exact_1_9_1_configuration_transport_and_categorical_readback_verified",
            "fixed_owner_identity_secret_and_disabled_baseline_approved",
            "no_other_user_or_arbitrary_secret_selection_enforced",
            "email_dependency_recipient_and_event_scope_prevalidated",
            "no_notification_validation_mode_or_sink_isolation_verified",
            "permission_loss_auto_disable_and_access_revocation_tested",
            "disable_or_rollback_contract_verified",
            "failure_reconciliation_and_live_acceptance_completed",
        ),
        (
            "device_user_secret_subscription_or_email_state_read",
            "user_secret_event_email_recipient_or_selector_input",
            "event_subscription_enable_disable_or_update",
            "secret_permission_or_user_email_change",
            "email_test_or_notification_delivery",
            "identity_secret_event_or_delivery_result_return",
            "execution_authorization",
        ),
    )


__all__ = [
    "V4_INSTRUCTION_PROFILE_CREATE_PLAN_TOOL",
    "V4_EVENT_SUBSCRIPTION_PLAN_TOOL",
    "instruction_profile_create_plan_requirements",
    "event_subscription_plan_requirements",
]
