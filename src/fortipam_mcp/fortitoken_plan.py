"""Source-bounded FortiPAM FortiToken assignment and revocation requirements."""

from __future__ import annotations


V4_FORTITOKEN_ASSIGN_PLAN_TOOL = "get_v4_fortitoken_assign_plan_requirements"
V4_FORTITOKEN_ASSIGN_PLAN_CONTRACT = "fortipam_v4_fortitoken_assign_plan_v1"
V4_FORTITOKEN_REVOKE_PLAN_TOOL = "get_v4_fortitoken_revoke_plan_requirements"
V4_FORTITOKEN_REVOKE_PLAN_CONTRACT = "fortipam_v4_fortitoken_revoke_plan_v1"

_COMMON_BLOCKED_OPERATIONS = (
    "fortipam_forticloud_or_mobile_service_state_read",
    "user_token_serial_activation_seed_email_or_otp_input",
    "token_create_import_activate_provision_refresh_edit_or_delete",
    "user_two_factor_assignment_change",
    "email_push_sms_or_activation_delivery",
    "login_mfa_push_or_otp_test",
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
        "forticloud_contacted": False,
        "mobile_service_contacted": False,
        "protected_material_loaded": False,
        "mfa_effect_applied": False,
        "notification_sent": False,
        "local_state_written": False,
        "raw_source_content_returned": False,
    }


def fortitoken_assign_plan_requirements() -> dict[str, object]:
    """Return fixed non-executable FortiToken assignment requirements."""

    return _requirements(
        contract=V4_FORTITOKEN_ASSIGN_PLAN_CONTRACT,
        action_family="fortitoken.assign",
        documented=(
            "hard_or_mobile_token_type_and_inventory_status",
            "token_serial_activation_provisioning_and_drift_state",
            "fixed_local_or_remote_user_and_email_dependency",
            "two_factor_authentication_type_and_token_selection",
            "mobile_activation_notification_and_expiry",
            "login_otp_or_push_verification_and_recovery",
        ),
        acceptance=(
            "exact_1_9_1_assignment_transport_and_redacted_readback_verified",
            "fixed_nonprivileged_disabled_test_user_and_unassigned_token_approved",
            "serial_activation_seed_and_otp_material_provider_isolated_from_mcp",
            "token_inventory_license_activation_and_drift_baseline_verified",
            "email_push_network_certificate_and_forticloud_dependencies_verified",
            "mfa_enrollment_login_lockout_and_break_glass_impact_analyzed",
            "alternate_admin_and_token_recovery_path_verified",
            "negative_positive_expiry_replay_failure_and_rollback_tests_approved",
        ),
    )


def fortitoken_revoke_plan_requirements() -> dict[str, object]:
    """Return fixed non-executable FortiToken revocation requirements."""

    return _requirements(
        contract=V4_FORTITOKEN_REVOKE_PLAN_CONTRACT,
        action_family="fortitoken.revoke",
        documented=(
            "existing_user_token_assignment_and_inventory_status",
            "user_two_factor_authentication_and_alternate_method",
            "active_login_session_and_lockout_impact",
            "token_activation_provisioning_and_mobile_state",
            "token_reassignment_retention_or_deletion_scope",
            "notification_audit_and_recovery_requirements",
        ),
        acceptance=(
            "exact_1_9_1_unassignment_transport_and_redacted_readback_verified",
            "fixed_user_token_complete_baseline_and_owner_approval_verified",
            "active_session_lockout_and_privileged_access_impact_analyzed",
            "alternate_mfa_or_local_admin_recovery_verified",
            "token_inventory_retention_reassignment_and_mobile_state_decided",
            "notification_and_audit_evidence_requirements_verified",
            "reassignment_or_rollback_contract_verified",
            "negative_positive_failure_reconciliation_tests_approved",
        ),
    )


__all__ = [
    "V4_FORTITOKEN_ASSIGN_PLAN_CONTRACT",
    "V4_FORTITOKEN_ASSIGN_PLAN_TOOL",
    "V4_FORTITOKEN_REVOKE_PLAN_CONTRACT",
    "V4_FORTITOKEN_REVOKE_PLAN_TOOL",
    "fortitoken_assign_plan_requirements",
    "fortitoken_revoke_plan_requirements",
]
