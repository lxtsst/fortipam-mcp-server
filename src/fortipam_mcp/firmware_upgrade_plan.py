"""Source-pinned FortiPAM 1.9.1 firmware-upgrade planning requirements.

This module deliberately exposes no firmware artifact, device route, command,
credential, mutable state, or execution decision.  It records only the bounded
requirements established by the FortiPAM 1.9.1 Release Notes and the additional
project acceptance evidence required before a future exact upgrade package can
be designed.
"""

from __future__ import annotations


V4_FIRMWARE_UPGRADE_PLAN_TOOL = "get_v4_firmware_upgrade_plan_requirements"
V4_FIRMWARE_UPGRADE_PLAN_CONTRACT = "fortipam_v4_firmware_upgrade_plan_v1"
V4_FIRMWARE_UPGRADE_BUILD_TOOL = "build_v4_firmware_upgrade_plan"
V4_FIRMWARE_UPGRADE_BUILD_CONTRACT = "fortipam_v4_firmware_upgrade_plan_builder_v1"

_DOCUMENTED_PREREQUISITES = (
    "full_configuration_backup_completed",
    "firmware_image_downloaded_from_forticloud",
    "firmware_image_md5_matches_fortinet",
    "fortipam_registration_confirmed",
    "target_release_notes_reviewed_in_full",
    "maintenance_mode_active_before_upload",
    "client_software_storage_limit_checked",
    "customized_login_pages_backed_up",
)

_DOCUMENTED_EFFECTS = (
    "firmware_upload_reboots_appliance",
    "temporary_unavailability_during_reboot",
    "configuration_restore_discards_changes_since_backup",
    "configuration_restore_ends_active_sessions",
)

_PROJECT_ACCEPTANCE_REQUIREMENTS = (
    "exact_current_version_and_supported_path_verified",
    "deployment_mode_and_ha_procedure_verified",
    "encrypted_backup_custody_verified",
    "isolated_restore_test_passed",
    "maintenance_window_and_session_handling_approved",
    "pre_upgrade_and_post_upgrade_checks_defined",
    "failure_reconciliation_and_operator_rollback_approved",
)

_BLOCKED_OPERATIONS = (
    "device_state_read",
    "upgrade_path_inference",
    "firmware_download",
    "firmware_upload",
    "maintenance_mode_change",
    "backup_create_or_restore",
    "reboot",
    "execution_authorization",
)

_PLAN_EVIDENCE_FIELDS = (
    "current_version_path_verified",
    "deployment_ha_procedure_ready",
    "backup_custody_verified",
    "isolated_restore_test_passed",
    "maintenance_window_approved",
    "pre_post_checks_defined",
    "failure_rollback_approved",
)


def firmware_upgrade_plan_requirements() -> dict[str, object]:
    """Return a fixed, value-free 1.9.1 planning boundary."""

    return {
        "contract": V4_FIRMWARE_UPGRADE_PLAN_CONTRACT,
        "action_family": "firmware.upgrade.plan",
        "target_version": "1.9.1",
        "documented_upgrade_origins": ["1.7.x", "1.8.x"],
        "planning_status": "requirements_only",
        "documented_prerequisites": list(_DOCUMENTED_PREREQUISITES),
        "documented_effects": list(_DOCUMENTED_EFFECTS),
        "project_acceptance_requirements": list(
            _PROJECT_ACCEPTANCE_REQUIREMENTS
        ),
        "blocked_operations": list(_BLOCKED_OPERATIONS),
        "execution_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "local_state_written": False,
        "protected_material_accepted": False,
        "raw_source_content_returned": False,
    }


def build_firmware_upgrade_plan(
    *,
    current_version_path_verified: bool,
    deployment_ha_procedure_ready: bool,
    backup_custody_verified: bool,
    isolated_restore_test_passed: bool,
    maintenance_window_approved: bool,
    pre_post_checks_defined: bool,
    failure_rollback_approved: bool,
) -> dict[str, object]:
    """Evaluate a value-free, caller-attested firmware planning checklist."""

    evidence = {
        "current_version_path_verified": current_version_path_verified,
        "deployment_ha_procedure_ready": deployment_ha_procedure_ready,
        "backup_custody_verified": backup_custody_verified,
        "isolated_restore_test_passed": isolated_restore_test_passed,
        "maintenance_window_approved": maintenance_window_approved,
        "pre_post_checks_defined": pre_post_checks_defined,
        "failure_rollback_approved": failure_rollback_approved,
    }
    if any(type(value) is not bool for value in evidence.values()):
        raise ValueError("Firmware upgrade plan evidence must be boolean.")
    missing = [name for name in _PLAN_EVIDENCE_FIELDS if not evidence[name]]
    return {
        "contract": V4_FIRMWARE_UPGRADE_BUILD_CONTRACT,
        "action_family": "firmware.upgrade.plan",
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
        "firmware_artifact_verified": False,
        "upgrade_execution_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "local_state_written": False,
        "protected_material_accepted": False,
        "raw_source_content_returned": False,
    }


__all__ = [
    "V4_FIRMWARE_UPGRADE_BUILD_CONTRACT",
    "V4_FIRMWARE_UPGRADE_BUILD_TOOL",
    "V4_FIRMWARE_UPGRADE_PLAN_CONTRACT",
    "V4_FIRMWARE_UPGRADE_PLAN_TOOL",
    "firmware_upgrade_plan_requirements",
    "build_firmware_upgrade_plan",
]
