"""Source-pinned FortiPAM 1.9.1 license-install planning requirements.

This module accepts no license artifact, registration code, account detail,
device route, credential, mutable state, or execution decision.  It returns
only documented operational facts plus the project evidence required before a
future exact license-install package can be designed.
"""

from __future__ import annotations


V4_LICENSE_INSTALL_PLAN_TOOL = "get_v4_license_install_plan_requirements"
V4_LICENSE_INSTALL_PLAN_CONTRACT = "fortipam_v4_license_install_plan_v1"
V4_LICENSE_INSTALL_BUILD_TOOL = "build_v4_license_install_plan"
V4_LICENSE_INSTALL_BUILD_CONTRACT = "fortipam_v4_license_install_plan_builder_v1"

_DOCUMENTED_REQUIREMENTS = (
    "license_registration_and_download_occur_in_forticloud",
    "license_file_is_downloaded_to_operator_computer",
    "fortinet_registration_recognition_can_take_up_to_thirty_minutes",
    "license_upload_requires_maintenance_mode",
    "gui_upload_uses_operator_selected_local_license_file",
    "appliance_boot_completes_before_license_status_verification",
    "license_status_is_verified_after_boot",
    "floating_license_behavior_requires_vm_and_ha_review",
)

_DOCUMENTED_EVALUATION_LIMITS = (
    "maximum_two_users",
    "fifteen_day_expiry",
    "no_valid_serial_number",
    "no_forticare_support",
    "antivirus_and_dlp_not_supported",
)

_PROJECT_ACCEPTANCE_REQUIREMENTS = (
    "entitlement_and_registration_owner_verified_outside_mcp",
    "exact_appliance_model_deployment_and_ha_mode_verified",
    "license_file_integrity_and_custody_kept_outside_mcp",
    "configuration_backup_and_recovery_path_verified",
    "maintenance_window_and_reboot_outage_approved",
    "console_or_break_fix_access_verified",
    "post_boot_license_status_and_capacity_checks_defined",
    "failure_reconciliation_and_operator_recovery_approved",
)

_BLOCKED_OPERATIONS = (
    "forticloud_authentication_or_registration",
    "registration_code_input_or_output",
    "license_file_input_or_output",
    "device_state_read",
    "maintenance_mode_change",
    "gui_license_upload",
    "scp_license_upload",
    "reboot",
    "execution_authorization",
)

_PLAN_EVIDENCE_FIELDS = (
    "entitlement_owner_verified",
    "deployment_ha_mode_verified",
    "license_custody_ready",
    "backup_recovery_verified",
    "maintenance_reboot_approved",
    "break_fix_access_verified",
    "post_boot_checks_defined",
    "failure_recovery_approved",
)


def license_install_plan_requirements() -> dict[str, object]:
    """Return a fixed, value-free FortiPAM 1.9.1 licensing boundary."""

    return {
        "contract": V4_LICENSE_INSTALL_PLAN_CONTRACT,
        "action_family": "license.install",
        "target_version": "1.9.1",
        "planning_status": "requirements_only",
        "documented_requirements": list(_DOCUMENTED_REQUIREMENTS),
        "documented_evaluation_limits": list(_DOCUMENTED_EVALUATION_LIMITS),
        "project_acceptance_requirements": list(
            _PROJECT_ACCEPTANCE_REQUIREMENTS
        ),
        "blocked_operations": list(_BLOCKED_OPERATIONS),
        "license_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "forticloud_contacted": False,
        "local_state_written": False,
        "protected_material_accepted": False,
        "raw_source_content_returned": False,
    }


def build_license_install_plan(
    *,
    entitlement_owner_verified: bool,
    deployment_ha_mode_verified: bool,
    license_custody_ready: bool,
    backup_recovery_verified: bool,
    maintenance_reboot_approved: bool,
    break_fix_access_verified: bool,
    post_boot_checks_defined: bool,
    failure_recovery_approved: bool,
) -> dict[str, object]:
    """Evaluate a value-free, caller-attested license planning checklist."""

    evidence = {
        "entitlement_owner_verified": entitlement_owner_verified,
        "deployment_ha_mode_verified": deployment_ha_mode_verified,
        "license_custody_ready": license_custody_ready,
        "backup_recovery_verified": backup_recovery_verified,
        "maintenance_reboot_approved": maintenance_reboot_approved,
        "break_fix_access_verified": break_fix_access_verified,
        "post_boot_checks_defined": post_boot_checks_defined,
        "failure_recovery_approved": failure_recovery_approved,
    }
    if any(type(value) is not bool for value in evidence.values()):
        raise ValueError("License install plan evidence must be boolean.")
    missing = [name for name in _PLAN_EVIDENCE_FIELDS if not evidence[name]]
    return {
        "contract": V4_LICENSE_INSTALL_BUILD_CONTRACT,
        "action_family": "license.install",
        "target_version": "1.9.1",
        "planning_status": (
            "ready_for_operator_review" if not missing else "incomplete_evidence"
        ),
        "evidence_origin": "caller_attested_categorical_inputs",
        "missing_requirements": missing,
        "satisfied_requirement_count": len(_PLAN_EVIDENCE_FIELDS) - len(missing),
        "requirement_count": len(_PLAN_EVIDENCE_FIELDS),
        "plan_ready": not missing,
        "authoritative_device_state_observed": False,
        "license_artifact_verified": False,
        "license_execution_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "forticloud_contacted": False,
        "local_state_written": False,
        "protected_material_accepted": False,
        "raw_source_content_returned": False,
    }


__all__ = [
    "V4_LICENSE_INSTALL_BUILD_CONTRACT",
    "V4_LICENSE_INSTALL_BUILD_TOOL",
    "V4_LICENSE_INSTALL_PLAN_CONTRACT",
    "V4_LICENSE_INSTALL_PLAN_TOOL",
    "license_install_plan_requirements",
    "build_license_install_plan",
]
