"""Source-pinned FortiPAM 1.9.1 backup/restore planning requirements.

This module accepts no backup artifact, password, encryption key, device route,
credential, mutable state, or execution decision.  It returns only documented
operational facts plus the project evidence required before a future exact
backup or restore package can be designed.
"""

from __future__ import annotations


V4_BACKUP_RESTORE_PLAN_TOOL = "get_v4_backup_restore_plan_requirements"
V4_BACKUP_RESTORE_PLAN_CONTRACT = "fortipam_v4_backup_restore_plan_v1"
V4_BACKUP_RESTORE_BUILD_TOOL = "build_v4_backup_restore_plan"
V4_BACKUP_RESTORE_BUILD_CONTRACT = "fortipam_v4_backup_restore_plan_builder_v1"
V4_BACKUP_CREATE_PLAN_TOOL = "get_v4_backup_create_plan_requirements"
V4_BACKUP_CREATE_PLAN_CONTRACT = "fortipam_v4_backup_create_plan_v1"
V4_BACKUP_CREATE_BUILD_TOOL = "build_v4_backup_create_plan"
V4_BACKUP_CREATE_BUILD_CONTRACT = "fortipam_v4_backup_create_plan_builder_v1"

_DOCUMENTED_BACKUP_REQUIREMENTS = (
    "regular_configuration_backup",
    "post_change_configuration_backup",
    "full_configuration_backup_before_firmware_upgrade",
    "local_computer_download_destination",
    "optional_backup_file_encryption",
)

_BACKUP_PROJECT_ACCEPTANCE_REQUIREMENTS = (
    "source_appliance_version_and_backup_scope_recorded",
    "operator_controlled_destination_kept_outside_mcp",
    "backup_encryption_policy_approved",
    "backup_encryption_password_custody_kept_outside_mcp",
    "artifact_integrity_record_kept_outside_mcp",
    "offline_storage_and_retention_policy_verified",
    "isolated_restore_test_defined",
    "failure_reconciliation_and_operator_recovery_approved",
)

_BLOCKED_BACKUP_OPERATIONS = (
    "device_state_read",
    "backup_create_dispatch",
    "backup_download",
    "backup_artifact_input_or_output",
    "password_or_encryption_key_input_or_output",
    "maintenance_mode_change",
    "restore_dispatch",
    "reboot",
    "execution_authorization",
)

_DOCUMENTED_REQUIREMENTS = (
    "regular_and_post_change_configuration_backup",
    "full_configuration_backup_before_firmware_upgrade",
    "local_computer_backup_and_restore_source",
    "backup_file_encryption_supported",
    "restore_requires_maintenance_mode",
    "encrypted_restore_requires_matching_password",
    "in_use_configuration_backed_up_during_restore",
    "private_data_encryption_key_required_on_replacement_appliance",
)

_DOCUMENTED_RESTORE_EFFECTS = (
    "changes_since_backup_are_lost",
    "active_sessions_are_ended",
    "appliance_reboots",
    "operator_must_log_in_again",
)

_PROJECT_ACCEPTANCE_REQUIREMENTS = (
    "exact_source_and_destination_version_compatibility_verified",
    "deployment_mode_and_ha_restore_procedure_verified",
    "backup_encryption_password_custody_kept_outside_mcp",
    "private_data_encryption_key_custody_kept_outside_mcp",
    "artifact_integrity_and_offline_storage_verified",
    "isolated_restore_test_passed",
    "data_loss_session_outage_and_maintenance_window_approved",
    "pre_restore_and_post_restore_checks_defined",
    "failure_reconciliation_and_operator_recovery_approved",
)

_BLOCKED_OPERATIONS = (
    "device_state_read",
    "backup_download",
    "backup_upload",
    "backup_artifact_input_or_output",
    "password_or_encryption_key_input_or_output",
    "maintenance_mode_change",
    "restore_dispatch",
    "session_termination",
    "reboot",
    "execution_authorization",
)

_PLAN_EVIDENCE_FIELDS = (
    "source_destination_version_compatible",
    "deployment_restore_procedure_ready",
    "protected_material_custody_ready",
    "artifact_integrity_verified",
    "isolated_restore_test_passed",
    "maintenance_window_approved",
    "pre_post_checks_defined",
    "failure_recovery_approved",
)

_BACKUP_PLAN_EVIDENCE_FIELDS = (
    "source_appliance_version_recorded",
    "operator_destination_ready",
    "encryption_policy_approved",
    "protected_material_custody_ready",
    "artifact_integrity_record_ready",
    "retention_policy_verified",
    "isolated_restore_test_defined",
    "failure_recovery_approved",
)


def backup_create_plan_requirements() -> dict[str, object]:
    """Return a fixed, value-free FortiPAM 1.9.1 backup boundary."""

    return {
        "contract": V4_BACKUP_CREATE_PLAN_CONTRACT,
        "action_family": "backup.create",
        "target_version": "1.9.1",
        "planning_status": "requirements_only",
        "documented_requirements": list(_DOCUMENTED_BACKUP_REQUIREMENTS),
        "project_acceptance_requirements": list(
            _BACKUP_PROJECT_ACCEPTANCE_REQUIREMENTS
        ),
        "blocked_operations": list(_BLOCKED_BACKUP_OPERATIONS),
        "backup_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "local_state_written": False,
        "protected_material_accepted": False,
        "raw_source_content_returned": False,
    }


def backup_restore_plan_requirements() -> dict[str, object]:
    """Return a fixed, value-free FortiPAM 1.9.1 planning boundary."""

    return {
        "contract": V4_BACKUP_RESTORE_PLAN_CONTRACT,
        "action_family": "backup.restore.plan",
        "target_version": "1.9.1",
        "planning_status": "requirements_only",
        "documented_requirements": list(_DOCUMENTED_REQUIREMENTS),
        "documented_restore_effects": list(_DOCUMENTED_RESTORE_EFFECTS),
        "project_acceptance_requirements": list(
            _PROJECT_ACCEPTANCE_REQUIREMENTS
        ),
        "blocked_operations": list(_BLOCKED_OPERATIONS),
        "backup_ready": False,
        "restore_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "local_state_written": False,
        "protected_material_accepted": False,
        "raw_source_content_returned": False,
    }


def build_backup_create_plan(
    *,
    source_appliance_version_recorded: bool,
    operator_destination_ready: bool,
    encryption_policy_approved: bool,
    protected_material_custody_ready: bool,
    artifact_integrity_record_ready: bool,
    retention_policy_verified: bool,
    isolated_restore_test_defined: bool,
    failure_recovery_approved: bool,
) -> dict[str, object]:
    """Evaluate a value-free, caller-attested backup planning checklist."""

    evidence = {
        "source_appliance_version_recorded": source_appliance_version_recorded,
        "operator_destination_ready": operator_destination_ready,
        "encryption_policy_approved": encryption_policy_approved,
        "protected_material_custody_ready": protected_material_custody_ready,
        "artifact_integrity_record_ready": artifact_integrity_record_ready,
        "retention_policy_verified": retention_policy_verified,
        "isolated_restore_test_defined": isolated_restore_test_defined,
        "failure_recovery_approved": failure_recovery_approved,
    }
    if any(type(value) is not bool for value in evidence.values()):
        raise ValueError("Backup create plan evidence must be boolean.")
    missing = [name for name in _BACKUP_PLAN_EVIDENCE_FIELDS if not evidence[name]]
    return {
        "contract": V4_BACKUP_CREATE_BUILD_CONTRACT,
        "action_family": "backup.create",
        "target_version": "1.9.1",
        "planning_status": (
            "ready_for_operator_review" if not missing else "incomplete_evidence"
        ),
        "evidence_origin": "caller_attested_categorical_inputs",
        "missing_requirements": missing,
        "satisfied_requirement_count": len(_BACKUP_PLAN_EVIDENCE_FIELDS)
        - len(missing),
        "requirement_count": len(_BACKUP_PLAN_EVIDENCE_FIELDS),
        "plan_ready": not missing,
        "authoritative_device_state_observed": False,
        "backup_execution_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "local_state_written": False,
        "protected_material_accepted": False,
        "raw_source_content_returned": False,
    }


def build_backup_restore_plan(
    *,
    source_destination_version_compatible: bool,
    deployment_restore_procedure_ready: bool,
    protected_material_custody_ready: bool,
    artifact_integrity_verified: bool,
    isolated_restore_test_passed: bool,
    maintenance_window_approved: bool,
    pre_post_checks_defined: bool,
    failure_recovery_approved: bool,
) -> dict[str, object]:
    """Evaluate a value-free, caller-attested restore planning checklist."""

    evidence = {
        "source_destination_version_compatible": source_destination_version_compatible,
        "deployment_restore_procedure_ready": deployment_restore_procedure_ready,
        "protected_material_custody_ready": protected_material_custody_ready,
        "artifact_integrity_verified": artifact_integrity_verified,
        "isolated_restore_test_passed": isolated_restore_test_passed,
        "maintenance_window_approved": maintenance_window_approved,
        "pre_post_checks_defined": pre_post_checks_defined,
        "failure_recovery_approved": failure_recovery_approved,
    }
    if any(type(value) is not bool for value in evidence.values()):
        raise ValueError("Backup restore plan evidence must be boolean.")
    missing = [name for name in _PLAN_EVIDENCE_FIELDS if not evidence[name]]
    return {
        "contract": V4_BACKUP_RESTORE_BUILD_CONTRACT,
        "action_family": "backup.restore.plan",
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
        "restore_execution_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "local_state_written": False,
        "protected_material_accepted": False,
        "raw_source_content_returned": False,
    }


__all__ = [
    "V4_BACKUP_CREATE_BUILD_CONTRACT",
    "V4_BACKUP_CREATE_BUILD_TOOL",
    "V4_BACKUP_CREATE_PLAN_CONTRACT",
    "V4_BACKUP_CREATE_PLAN_TOOL",
    "V4_BACKUP_RESTORE_PLAN_CONTRACT",
    "V4_BACKUP_RESTORE_PLAN_TOOL",
    "V4_BACKUP_RESTORE_BUILD_CONTRACT",
    "V4_BACKUP_RESTORE_BUILD_TOOL",
    "backup_create_plan_requirements",
    "backup_restore_plan_requirements",
    "build_backup_create_plan",
    "build_backup_restore_plan",
]
