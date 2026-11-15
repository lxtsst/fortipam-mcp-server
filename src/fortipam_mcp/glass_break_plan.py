"""Source-pinned FortiPAM 1.9.1 glass-breaking planning requirements.

This module accepts no identity, role, reason, incident, device route,
credential, Secret reference, mutable state, or execution decision.  It returns
only documented impact and the project evidence required before any future
break-glass activation can be considered.
"""

from __future__ import annotations


V4_GLASS_BREAK_PLAN_TOOL = "get_v4_glass_break_plan_requirements"
V4_GLASS_BREAK_PLAN_CONTRACT = "fortipam_v4_glass_break_plan_v1"

_DOCUMENTED_REQUIREMENTS = (
    "reserved_for_exceptional_disaster_recovery_situations",
    "permission_limited_to_few_administrators",
    "activation_requires_glass_breaking_role_permission",
    "activation_requires_operator_reason",
    "activation_bypasses_normal_access_controls",
    "activation_exposes_all_folders_secrets_requests_and_launches",
    "secret_clear_text_can_be_accessed",
    "all_administrator_activity_should_be_logged_for_audit",
    "session_launch_recording_is_enforced_by_default",
    "entry_notification_can_be_configured_separately",
    "mode_has_an_explicit_deactivation_operation",
)

_PROJECT_ACCEPTANCE_REQUIREMENTS = (
    "declared_incident_and_disaster_recovery_condition_verified",
    "independent_human_approver_and_operator_separation_verified",
    "named_least_privilege_role_eligibility_verified",
    "all_secret_and_launch_access_impact_explicitly_acknowledged",
    "activation_reason_retention_and_audit_owner_verified",
    "session_recording_and_log_export_preserved",
    "out_of_band_notification_and_observer_path_verified",
    "maximum_duration_and_deactivation_criteria_approved",
    "post_incident_access_review_and_credential_rotation_plan_approved",
    "failure_reconciliation_and_operator_recovery_approved",
)

_BLOCKED_OPERATIONS = (
    "device_state_read",
    "identity_role_reason_or_incident_input",
    "glass_break_permission_change",
    "glass_break_activation",
    "glass_break_deactivation",
    "folder_secret_or_request_enumeration",
    "credential_or_clear_text_access",
    "secret_launch",
    "notification_configuration_or_delivery",
    "session_recording_change",
    "execution_authorization",
)


def glass_break_plan_requirements() -> dict[str, object]:
    """Return a fixed, value-free FortiPAM 1.9.1 break-glass boundary."""

    return {
        "contract": V4_GLASS_BREAK_PLAN_CONTRACT,
        "action_family": "glass-break.activate",
        "target_version": "1.9.1",
        "planning_status": "requirements_only",
        "documented_requirements": list(_DOCUMENTED_REQUIREMENTS),
        "project_acceptance_requirements": list(
            _PROJECT_ACCEPTANCE_REQUIREMENTS
        ),
        "blocked_operations": list(_BLOCKED_OPERATIONS),
        "activation_ready": False,
        "access_elevated": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "local_state_written": False,
        "protected_material_accepted": False,
        "secret_material_returned": False,
        "raw_source_content_returned": False,
    }


__all__ = [
    "V4_GLASS_BREAK_PLAN_CONTRACT",
    "V4_GLASS_BREAK_PLAN_TOOL",
    "glass_break_plan_requirements",
]
