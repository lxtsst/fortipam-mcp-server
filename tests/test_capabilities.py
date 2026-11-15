from __future__ import annotations

from typing import cast

import pytest

from fortipam_mcp.capabilities import (
    ACTION_FAMILY_EVIDENCE_STATUS,
    DEFAULT_CAPABILITY_REGISTRY,
    ExecutionMode,
    LOCAL_VERIFICATION_ELIGIBLE_ACTION_FAMILIES,
    ActionFamilyEvidenceStatus,
    TOOL_PACK_ACTION_FAMILIES,
    ToolPack,
    get_capability_matrix,
)
from fortipam_mcp.mcp_smoke import (
    EXPECTED_TOOLS,
    LAB_ADMIN_TOOLS,
    LAB_EXPECTED_TOOLS,
    V4_CONTROLLED_TOOLS,
    V4_PLAN_TOOLS,
)


V4_TARGET_TOOLS = (
    "preview_v4_ssh_target_create",
    "confirm_v4_ssh_target_create",
    "execute_confirmed_v4_ssh_target",
    "preview_v4_ssh_target_delete",
    "confirm_v4_ssh_target_delete",
    "execute_confirmed_v4_ssh_target_delete",
)
V4_TARGET_UPDATE_TOOLS = (
    "preview_v4_target_update_description",
    "confirm_v4_target_update_description",
    "execute_confirmed_v4_target_update_description",
)
V4_CERTIFICATE_CSR_TOOLS = (
    "preview_v4_certificate_csr_generate",
    "confirm_v4_certificate_csr_generate",
    "execute_confirmed_v4_certificate_csr_generate",
)
V4_SECRET_METADATA_TOOLS = (
    "preview_v4_secret_metadata_create",
    "confirm_v4_secret_metadata_create",
    "execute_confirmed_v4_secret_metadata_create",
)
V4_INTERFACE_WEB_PROXY_TOOLS = (
    "preview_v4_interface_explicit_web_proxy_enable",
    "confirm_v4_interface_explicit_web_proxy_enable",
    "execute_confirmed_v4_interface_explicit_web_proxy_enable",
    "preview_v4_interface_explicit_web_proxy_rollback",
    "confirm_v4_interface_explicit_web_proxy_rollback",
    "execute_confirmed_v4_interface_explicit_web_proxy_rollback",
)
V4_LOCAL_USER_DISABLE_TOOLS = (
    "preview_v4_local_user_disable",
    "confirm_v4_local_user_disable",
    "execute_confirmed_v4_local_user_disable",
)
V4_LOCAL_USER_CREATE_TOOLS = (
    "preview_v4_local_user_create",
    "confirm_v4_local_user_create",
    "execute_confirmed_v4_local_user_create",
)
V4_LOCAL_USER_RESET_TOOLS = (
    "preview_v4_local_user_reset",
    "confirm_v4_local_user_reset",
    "execute_confirmed_v4_local_user_reset",
)
V4_ROLE_CREATE_TOOLS = (
    "preview_v4_role_create",
    "confirm_v4_role_create",
    "execute_confirmed_v4_role_create",
)
V4_ROLE_UPDATE_TOOLS = (
    "preview_v4_role_diagnostics_enable",
    "confirm_v4_role_diagnostics_enable",
    "execute_confirmed_v4_role_diagnostics_enable",
)
V4_ROLE_ASSIGN_TOOLS = (
    "preview_v4_role_assign",
    "confirm_v4_role_assign",
    "execute_confirmed_v4_role_assign",
)
V4_DLP_FILE_PATTERN_TOOLS = (
    "preview_v4_dlp_file_pattern_create",
    "confirm_v4_dlp_file_pattern_create",
    "execute_confirmed_v4_dlp_file_pattern_create",
    "preview_v4_dlp_file_pattern_delete",
    "confirm_v4_dlp_file_pattern_delete",
    "execute_confirmed_v4_dlp_file_pattern_delete",
)
V4_DLP_SENSOR_TOOLS = (
    "preview_v4_dlp_sensor_create",
    "confirm_v4_dlp_sensor_create",
    "execute_confirmed_v4_dlp_sensor_create",
    "preview_v4_dlp_sensor_delete",
    "confirm_v4_dlp_sensor_delete",
    "execute_confirmed_v4_dlp_sensor_delete",
)
V4_ANTIVIRUS_PROFILE_TOOLS = (
    "preview_v4_antivirus_profile_create",
    "confirm_v4_antivirus_profile_create",
    "execute_confirmed_v4_antivirus_profile_create",
    "preview_v4_antivirus_profile_delete",
    "confirm_v4_antivirus_profile_delete",
    "execute_confirmed_v4_antivirus_profile_delete",
)
V4_RDP_EVENT_FILTER_TOOLS = (
    "preview_v4_rdp_event_filter_create",
    "confirm_v4_rdp_event_filter_create",
    "execute_confirmed_v4_rdp_event_filter_create",
    "preview_v4_rdp_event_filter_delete",
    "confirm_v4_rdp_event_filter_delete",
    "execute_confirmed_v4_rdp_event_filter_delete",
)
V4_SECRET_POLICY_TOOLS = (
    "preview_v4_secret_policy_create",
    "confirm_v4_secret_policy_create",
    "execute_confirmed_v4_secret_policy_create",
    "preview_v4_secret_policy_update",
    "confirm_v4_secret_policy_update",
    "execute_confirmed_v4_secret_policy_update",
)
V4_SSH_FILTER_TOOLS = (
    "preview_v4_ssh_filter_create",
    "confirm_v4_ssh_filter_create",
    "execute_confirmed_v4_ssh_filter_create",
    "preview_v4_ssh_filter_delete",
    "confirm_v4_ssh_filter_delete",
    "execute_confirmed_v4_ssh_filter_delete",
)
V4_LAUNCHER_TOOLS = (
    "preview_v4_launcher_create",
    "confirm_v4_launcher_create",
    "execute_confirmed_v4_launcher_create",
    "preview_v4_launcher_timeout_update",
    "confirm_v4_launcher_timeout_update",
    "execute_confirmed_v4_launcher_timeout_update",
    "preview_v4_launcher_command_line_matcher_configure",
    "confirm_v4_launcher_command_line_matcher_configure",
    "execute_confirmed_v4_launcher_command_line_matcher_configure",
)
V4_TEMPLATE_TOOLS = (
    "preview_v4_template_create",
    "confirm_v4_template_create",
    "execute_confirmed_v4_template_create",
    "preview_v4_template_web_vnc_port_update",
    "confirm_v4_template_web_vnc_port_update",
    "execute_confirmed_v4_template_web_vnc_port_update",
)
V4_TEMPLATE_ARCHIVE_TOOLS = (
    "preview_v4_disposable_template_archive",
    "confirm_v4_disposable_template_archive",
    "execute_confirmed_v4_disposable_template_archive",
)
V4_DEPENDENCY_UPDATER_TOOLS = (
    "preview_v4_dependency_updater_create",
    "confirm_v4_dependency_updater_create",
    "execute_confirmed_v4_dependency_updater_create",
)
V4_SECRET_GATEWAY_TOOLS = (
    "preview_v4_secret_gateway_create",
    "confirm_v4_secret_gateway_create",
    "execute_confirmed_v4_secret_gateway_create",
)
V4_CLIENT_INTEGRITY_TOOLS = (
    "preview_v4_client_integrity_configure",
    "confirm_v4_client_integrity_configure",
    "execute_confirmed_v4_client_integrity_configure",
)
V4_CHARACTER_SET_TOOLS = (
    "preview_v4_character_set_create",
    "confirm_v4_character_set_create",
    "execute_confirmed_v4_character_set_create",
    "preview_v4_character_set_delete",
    "confirm_v4_character_set_delete",
    "execute_confirmed_v4_character_set_delete",
)
V4_WINDOWS_APP_FILTER_TOOLS = (
    "preview_v4_windows_app_filter_create",
    "confirm_v4_windows_app_filter_create",
    "execute_confirmed_v4_windows_app_filter_create",
    "preview_v4_windows_app_filter_delete",
    "confirm_v4_windows_app_filter_delete",
    "execute_confirmed_v4_windows_app_filter_delete",
)
V4_RECORDING_POLICY_TOOLS = (
    "preview_v4_recording_policy_enable",
    "confirm_v4_recording_policy_enable",
    "execute_confirmed_v4_recording_policy_enable",
)
V4_PASSWORD_POLICY_TOOLS = (
    "preview_v4_password_policy_create",
    "confirm_v4_password_policy_create",
    "execute_confirmed_v4_password_policy_create",
    "preview_v4_password_policy_delete",
    "confirm_v4_password_policy_delete",
    "execute_confirmed_v4_password_policy_delete",
)
V4_REPORT_LAYOUT_TOOLS = (
    "preview_v4_report_layout_create",
    "confirm_v4_report_layout_create",
    "execute_confirmed_v4_report_layout_create",
    "preview_v4_report_layout_delete",
    "confirm_v4_report_layout_delete",
    "execute_confirmed_v4_report_layout_delete",
)
V4_ZTNA_ACCESS_PROXY_TOOLS = (
    "preview_v4_ztna_access_proxy_client_certificate",
    "confirm_v4_ztna_access_proxy_client_certificate",
    "execute_confirmed_v4_ztna_access_proxy_client_certificate",
    "preview_v4_ztna_access_proxy_client_certificate_rollback",
    "confirm_v4_ztna_access_proxy_client_certificate_rollback",
    "execute_confirmed_v4_ztna_access_proxy_client_certificate_rollback",
)
V4_ZTNA_USER_CONTROL_TOOLS = (
    "preview_v4_ztna_user_control_configure",
    "confirm_v4_ztna_user_control_configure",
    "execute_confirmed_v4_ztna_user_control_configure",
    "preview_v4_ztna_user_control_rollback",
    "confirm_v4_ztna_user_control_rollback",
    "execute_confirmed_v4_ztna_user_control_rollback",
)
V4_ZTNA_WAD_DEBUG_TOOLS = (
    "preview_v4_ztna_wad_debug_diagnostic",
    "confirm_v4_ztna_wad_debug_diagnostic",
    "execute_confirmed_v4_ztna_wad_debug_diagnostic",
)
V4_SNMP_AGENT_TOOLS = (
    "preview_v4_snmp_agent_enable",
    "confirm_v4_snmp_agent_enable",
    "execute_confirmed_v4_snmp_agent_enable",
    "preview_v4_snmp_agent_rollback",
    "confirm_v4_snmp_agent_rollback",
    "execute_confirmed_v4_snmp_agent_rollback",
)
V4_LOGGING_DISK_TOOLS = (
    "preview_v4_logging_disk_disable",
    "confirm_v4_logging_disk_disable",
    "execute_confirmed_v4_logging_disk_disable",
)
V4_FORTIANALYZER_TOOLS = (
    "preview_v4_fortianalyzer_enable",
    "confirm_v4_fortianalyzer_enable",
    "execute_confirmed_v4_fortianalyzer_enable",
)
V4_MAINTENANCE_MODE_TOOLS = (
    "preview_v4_maintenance_mode_enable",
    "confirm_v4_maintenance_mode_enable",
    "execute_confirmed_v4_maintenance_mode_enable",
    "preview_v4_maintenance_mode_rollback",
    "confirm_v4_maintenance_mode_rollback",
    "execute_confirmed_v4_maintenance_mode_rollback",
)
V4_SECRET_AUDIT_TOOLS = (
    "preview_v4_secret_audit_generate",
    "confirm_v4_secret_audit_generate",
    "execute_confirmed_v4_secret_audit_generate",
)
V4_SECRET_AUDIT_SUMMARY_TOOLS = ("summarize_v4_secret_access_audit",)
V4_TERRAFORM_PLAN_REPORT_TOOLS = ("summarize_v4_synthetic_terraform_plan",)
V4_ACTIVE_LAUNCH_TOOLS = (
    "observe_v4_active_launches",
    "preview_v4_active_launch_disconnect",
    "confirm_v4_active_launch_disconnect",
    "execute_confirmed_v4_active_launch_disconnect",
)
V4_AUTOMATION_TRIGGER_TOOLS = (
    "preview_v4_automation_trigger_create",
    "confirm_v4_automation_trigger_create",
    "execute_confirmed_v4_automation_trigger_create",
    "preview_v4_automation_trigger_delete",
    "confirm_v4_automation_trigger_delete",
    "execute_confirmed_v4_automation_trigger_delete",
)
V4_AUTOMATION_ACTION_TOOLS = (
    "preview_v4_automation_action_create",
    "confirm_v4_automation_action_create",
    "execute_confirmed_v4_automation_action_create",
    "preview_v4_automation_action_delete",
    "confirm_v4_automation_action_delete",
    "execute_confirmed_v4_automation_action_delete",
)
V4_AUTOMATION_STITCH_TOOLS = (
    "preview_v4_automation_stitch_create",
    "confirm_v4_automation_stitch_create",
    "execute_confirmed_v4_automation_stitch_create",
    "preview_v4_automation_stitch_delete",
    "confirm_v4_automation_stitch_delete",
    "execute_confirmed_v4_automation_stitch_delete",
)
V4_USER_GROUP_TOOLS = (
    "preview_v4_user_group_create",
    "confirm_v4_user_group_create",
    "execute_confirmed_v4_user_group_create",
)
V4_USER_GROUP_MEMBERSHIP_TOOLS = (
    "preview_v4_user_group_membership_change",
    "confirm_v4_user_group_membership_change",
    "execute_confirmed_v4_user_group_membership_change",
)
V4_APL_TOOLS = (
    "preview_v4_auto_provision_rule_create",
    "confirm_v4_auto_provision_rule_create",
    "execute_confirmed_v4_auto_provision_rule_create",
)
V4_APL_DISABLE_TOOLS = (
    "preview_v4_auto_provision_rule_disable",
    "confirm_v4_auto_provision_rule_disable",
    "execute_confirmed_v4_auto_provision_rule_disable",
)
V4_SCHEDULE_TOOLS = (
    "preview_v4_schedule_create",
    "confirm_v4_schedule_create",
    "execute_confirmed_v4_schedule_create",
    "preview_v4_schedule_delete",
    "confirm_v4_schedule_delete",
    "execute_confirmed_v4_schedule_delete",
)
V4_SCHEDULE_ASSIGN_TOOLS = (
    "preview_v4_schedule_assign",
    "confirm_v4_schedule_assign",
    "execute_confirmed_v4_schedule_assign",
    "preview_v4_schedule_assignment_detach",
    "confirm_v4_schedule_assignment_detach",
    "execute_confirmed_v4_schedule_assignment_detach",
)
V4_APPROVAL_PROFILE_TOOLS = (
    "preview_v4_approval_profile_create",
    "confirm_v4_approval_profile_create",
    "execute_confirmed_v4_approval_profile_create",
)
V4_APPROVAL_PROFILE_UPDATE_TOOLS = (
    "preview_v4_approval_profile_description_update",
    "confirm_v4_approval_profile_description_update",
    "execute_confirmed_v4_approval_profile_description_update",
    "preview_v4_approval_profile_delete",
    "confirm_v4_approval_profile_delete",
    "execute_confirmed_v4_approval_profile_delete",
)
V4_APPROVAL_EMAIL_TEMPLATE_TOOLS = (
    "preview_v4_approval_email_template_create",
    "confirm_v4_approval_email_template_create",
    "execute_confirmed_v4_approval_email_template_create",
)
V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_TOOLS = (
    "preview_v4_approval_email_template_content_update",
    "confirm_v4_approval_email_template_content_update",
    "execute_confirmed_v4_approval_email_template_content_update",
    "preview_v4_approval_email_template_delete",
    "confirm_v4_approval_email_template_delete",
    "execute_confirmed_v4_approval_email_template_delete",
)


def test_local_verified_actions_are_explicitly_non_mutating() -> None:
    verified = {
        action_family
        for action_family, status in ACTION_FAMILY_EVIDENCE_STATUS.items()
        if status is ActionFamilyEvidenceStatus.VERIFIED
    }

    assert verified == LOCAL_VERIFICATION_ELIGIBLE_ACTION_FAMILIES
    assert {
        "backup.create",
        "license.install",
        "system-email.configure",
        "email-alert.configure",
        "secret.bulk-import.apply",
    }.isdisjoint(verified)
V4_FOLDER_ACL_TOOLS = (
    "preview_v4_folder_user_acl_grant",
    "confirm_v4_folder_user_acl_grant",
    "execute_confirmed_v4_folder_user_acl_grant",
    "preview_v4_folder_user_acl_revoke",
    "confirm_v4_folder_user_acl_revoke",
    "execute_confirmed_v4_folder_user_acl_revoke",
    "preview_v4_public_child_folder_rename",
    "confirm_v4_public_child_folder_rename",
    "execute_confirmed_v4_public_child_folder_rename",
    "preview_v4_empty_public_child_folder_archive",
    "confirm_v4_empty_public_child_folder_archive",
    "execute_confirmed_v4_empty_public_child_folder_archive",
    "preview_v4_public_child_folder_policy_assign",
    "confirm_v4_public_child_folder_policy_assign",
    "execute_confirmed_v4_public_child_folder_policy_assign",
    "preview_v4_public_child_folder_policy_detach",
    "confirm_v4_public_child_folder_policy_detach",
    "execute_confirmed_v4_public_child_folder_policy_detach",
)
V4_CLASSIFICATION_TAG_TOOLS = (
    "preview_v4_classification_tag_create",
    "confirm_v4_classification_tag_create",
    "execute_confirmed_v4_classification_tag_create",
    "preview_v4_classification_tag_delete",
    "confirm_v4_classification_tag_delete",
    "execute_confirmed_v4_classification_tag_delete",
)
V4_CLASSIFICATION_TAG_ASSIGN_TOOLS = (
    "preview_v4_classification_tag_assign",
    "confirm_v4_classification_tag_assign",
    "execute_confirmed_v4_classification_tag_assign",
    "preview_v4_classification_tag_assign_rollback",
    "confirm_v4_classification_tag_assign_rollback",
    "execute_confirmed_v4_classification_tag_assign_rollback",
)
V4_ADDRESS_TOOLS = (
    "preview_v4_ipv4_address_create",
    "confirm_v4_ipv4_address_create",
    "execute_confirmed_v4_ipv4_address_create",
    "preview_v4_ipv4_address_delete",
    "confirm_v4_ipv4_address_delete",
    "execute_confirmed_v4_ipv4_address_delete",
)
V4_ADDRESS_GROUP_TOOLS = (
    "preview_v4_address_group_create",
    "confirm_v4_address_group_create",
    "execute_confirmed_v4_address_group_create",
    "preview_v4_address_group_delete",
    "confirm_v4_address_group_delete",
    "execute_confirmed_v4_address_group_delete",
)
V4_ZTNA_DIAGNOSTIC_TOOLS = (
    "get_v4_ztna_device_context_diagnostic",
    "get_v4_ztna_folder_control_posture",
)
V4_HA_RECONCILIATION_TOOLS = ("get_v4_ha_reconciliation_assessment",)
V4_APPROVAL_REQUEST_OBSERVATION_TOOLS = ("observe_v4_bound_secret_request",)


def test_registry_describes_the_exact_frozen_tool_surface() -> None:
    registry = DEFAULT_CAPABILITY_REGISTRY

    assert registry.tool_names == (
        EXPECTED_TOOLS
        + V4_HA_RECONCILIATION_TOOLS
        + LAB_ADMIN_TOOLS
        + V4_PLAN_TOOLS
        + V4_APPROVAL_REQUEST_OBSERVATION_TOOLS
        + V4_CONTROLLED_TOOLS
        + V4_FOLDER_ACL_TOOLS
        + V4_CLASSIFICATION_TAG_TOOLS
        + V4_CLASSIFICATION_TAG_ASSIGN_TOOLS
        + V4_ADDRESS_TOOLS
        + V4_ADDRESS_GROUP_TOOLS
        + V4_ZTNA_DIAGNOSTIC_TOOLS
        + V4_TARGET_TOOLS
        + V4_TARGET_UPDATE_TOOLS
        + V4_CERTIFICATE_CSR_TOOLS
        + V4_SECRET_METADATA_TOOLS
        + V4_INTERFACE_WEB_PROXY_TOOLS
        + V4_LOCAL_USER_DISABLE_TOOLS
        + V4_LOCAL_USER_CREATE_TOOLS
        + V4_LOCAL_USER_RESET_TOOLS
        + V4_ROLE_CREATE_TOOLS
        + V4_ROLE_UPDATE_TOOLS
        + V4_ROLE_ASSIGN_TOOLS
        + V4_DLP_FILE_PATTERN_TOOLS
        + V4_DLP_SENSOR_TOOLS
        + V4_ANTIVIRUS_PROFILE_TOOLS
        + V4_RDP_EVENT_FILTER_TOOLS
        + V4_SECRET_POLICY_TOOLS
        + V4_SSH_FILTER_TOOLS
        + V4_LAUNCHER_TOOLS
        + V4_TEMPLATE_TOOLS
        + V4_TEMPLATE_ARCHIVE_TOOLS
        + V4_DEPENDENCY_UPDATER_TOOLS
        + V4_SECRET_GATEWAY_TOOLS
        + V4_CLIENT_INTEGRITY_TOOLS
        + V4_CHARACTER_SET_TOOLS
        + V4_WINDOWS_APP_FILTER_TOOLS
        + V4_RECORDING_POLICY_TOOLS
        + V4_PASSWORD_POLICY_TOOLS
        + V4_REPORT_LAYOUT_TOOLS
        + V4_ZTNA_ACCESS_PROXY_TOOLS
        + V4_ZTNA_USER_CONTROL_TOOLS
        + V4_ZTNA_WAD_DEBUG_TOOLS
        + V4_SNMP_AGENT_TOOLS
        + V4_LOGGING_DISK_TOOLS
        + V4_FORTIANALYZER_TOOLS
        + V4_MAINTENANCE_MODE_TOOLS
        + V4_SECRET_AUDIT_TOOLS
        + V4_SECRET_AUDIT_SUMMARY_TOOLS
        + V4_TERRAFORM_PLAN_REPORT_TOOLS
        + V4_ACTIVE_LAUNCH_TOOLS
        + V4_AUTOMATION_TRIGGER_TOOLS
        + V4_AUTOMATION_ACTION_TOOLS
        + V4_AUTOMATION_STITCH_TOOLS
        + V4_USER_GROUP_TOOLS
        + V4_USER_GROUP_MEMBERSHIP_TOOLS
        + V4_APL_TOOLS
        + V4_APL_DISABLE_TOOLS
        + V4_SCHEDULE_TOOLS
        + V4_SCHEDULE_ASSIGN_TOOLS
        + V4_APPROVAL_PROFILE_TOOLS
        + V4_APPROVAL_PROFILE_UPDATE_TOOLS
        + V4_APPROVAL_EMAIL_TEMPLATE_TOOLS
        + V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_TOOLS
    )
    assert len(registry.capabilities) == 383
    assert all(capability.description for capability in registry.capabilities)
    assert all(capability.supported_product_versions for capability in registry.capabilities)
    diagnostic_tools = {
        "create_ha_diagnostic_baseline",
        "compare_ha_diagnostic_baseline",
        "correlate_ha_api_cli_posture",
        "get_v4_ha_reconciliation_assessment",
    }
    lab_execute_tools = {"execute_confirmed_v31_lab_operation"}
    v4_state_tools = {
        "preview_v4_administrative_intent",
        "confirm_v4_administrative_intent",
        "prepare_v4_non_executable_plan",
    }
    v4_folder_confirmation_tools = {
        "confirm_v4_child_folder_create",
        "confirm_v4_folder_user_acl_grant",
        "confirm_v4_folder_user_acl_revoke",
        "confirm_v4_public_child_folder_rename",
        "confirm_v4_empty_public_child_folder_archive",
        "confirm_v4_public_child_folder_policy_assign",
        "confirm_v4_public_child_folder_policy_detach",
        "confirm_v4_classification_tag_create",
        "confirm_v4_classification_tag_delete",
        "confirm_v4_classification_tag_assign",
        "confirm_v4_classification_tag_assign_rollback",
            "confirm_v4_ipv4_address_create",
            "confirm_v4_ipv4_address_delete",
            "confirm_v4_address_group_create",
            "confirm_v4_address_group_delete",
    }
    v4_target_confirmation_tools = {
        "confirm_v4_ssh_target_create",
        "confirm_v4_ssh_target_delete",
        "confirm_v4_target_update_description",
        "confirm_v4_certificate_csr_generate",
        "confirm_v4_secret_metadata_create",
        "confirm_v4_interface_explicit_web_proxy_enable",
        "confirm_v4_interface_explicit_web_proxy_rollback",
    }
    v4_local_user_confirmation_tools = {
        "confirm_v4_local_user_disable",
        "confirm_v4_local_user_create",
        "confirm_v4_local_user_reset",
        "confirm_v4_role_create",
        "confirm_v4_role_diagnostics_enable",
        "confirm_v4_role_assign",
        "confirm_v4_dlp_file_pattern_create",
        "confirm_v4_dlp_file_pattern_delete",
        "confirm_v4_dlp_sensor_create",
        "confirm_v4_dlp_sensor_delete",
        "confirm_v4_antivirus_profile_create",
        "confirm_v4_antivirus_profile_delete",
        "confirm_v4_rdp_event_filter_create",
        "confirm_v4_rdp_event_filter_delete",
        "confirm_v4_secret_policy_create",
            "confirm_v4_secret_policy_update",
            "confirm_v4_ssh_filter_create",
            "confirm_v4_ssh_filter_delete",
            "confirm_v4_launcher_create",
            "confirm_v4_launcher_timeout_update",
            "confirm_v4_launcher_command_line_matcher_configure",
            "confirm_v4_template_create",
            "confirm_v4_template_web_vnc_port_update",
            "confirm_v4_disposable_template_archive",
        "confirm_v4_dependency_updater_create",
        "confirm_v4_secret_gateway_create",
            "confirm_v4_client_integrity_configure",
            "confirm_v4_character_set_create",
            "confirm_v4_character_set_delete",
            "confirm_v4_windows_app_filter_create",
            "confirm_v4_windows_app_filter_delete",
            "confirm_v4_recording_policy_enable",
                "confirm_v4_password_policy_create",
                "confirm_v4_password_policy_delete",
                "confirm_v4_report_layout_create",
                "confirm_v4_report_layout_delete",
        "confirm_v4_ztna_access_proxy_client_certificate",
        "confirm_v4_ztna_access_proxy_client_certificate_rollback",
        "confirm_v4_ztna_user_control_configure",
        "confirm_v4_ztna_user_control_rollback",
        "confirm_v4_ztna_wad_debug_diagnostic",
        "confirm_v4_snmp_agent_enable",
        "confirm_v4_snmp_agent_rollback",
        "confirm_v4_logging_disk_disable",
        "confirm_v4_fortianalyzer_enable",
        "confirm_v4_maintenance_mode_enable",
        "confirm_v4_maintenance_mode_rollback",
        "confirm_v4_secret_audit_generate",
        "confirm_v4_active_launch_disconnect",
        "confirm_v4_automation_trigger_create",
        "confirm_v4_automation_trigger_delete",
            "confirm_v4_automation_action_create",
            "confirm_v4_automation_action_delete",
            "confirm_v4_automation_stitch_create",
            "confirm_v4_automation_stitch_delete",
            "confirm_v4_user_group_create",
            "confirm_v4_user_group_membership_change",
            "confirm_v4_auto_provision_rule_create",
            "confirm_v4_auto_provision_rule_disable",
            "confirm_v4_schedule_create",
            "confirm_v4_schedule_delete",
            "confirm_v4_schedule_assign",
            "confirm_v4_schedule_assignment_detach",
            "confirm_v4_approval_profile_create",
        "confirm_v4_approval_profile_description_update",
        "confirm_v4_approval_profile_delete",
        "confirm_v4_approval_email_template_create",
        "confirm_v4_approval_email_template_content_update",
        "confirm_v4_approval_email_template_delete",
    }
    v4_device_write_tools = {
        "execute_confirmed_v4_child_folder",
        "execute_confirmed_v4_folder_user_acl_grant",
        "execute_confirmed_v4_folder_user_acl_revoke",
        "execute_confirmed_v4_public_child_folder_rename",
        "execute_confirmed_v4_empty_public_child_folder_archive",
        "execute_confirmed_v4_public_child_folder_policy_assign",
        "execute_confirmed_v4_public_child_folder_policy_detach",
        "execute_confirmed_v4_classification_tag_create",
        "execute_confirmed_v4_classification_tag_delete",
        "execute_confirmed_v4_classification_tag_assign",
        "execute_confirmed_v4_classification_tag_assign_rollback",
            "execute_confirmed_v4_ipv4_address_create",
            "execute_confirmed_v4_ipv4_address_delete",
            "execute_confirmed_v4_address_group_create",
            "execute_confirmed_v4_address_group_delete",
            "execute_confirmed_v4_ssh_target",
            "execute_confirmed_v4_ssh_target_delete",
            "execute_confirmed_v4_target_update_description",
            "execute_confirmed_v4_certificate_csr_generate",
            "execute_confirmed_v4_secret_metadata_create",
        "execute_confirmed_v4_interface_explicit_web_proxy_enable",
        "execute_confirmed_v4_interface_explicit_web_proxy_rollback",
        "execute_confirmed_v4_local_user_disable",
        "execute_confirmed_v4_local_user_create",
        "execute_confirmed_v4_local_user_reset",
        "execute_confirmed_v4_role_create",
        "execute_confirmed_v4_role_diagnostics_enable",
        "execute_confirmed_v4_role_assign",
        "execute_confirmed_v4_dlp_file_pattern_create",
        "execute_confirmed_v4_dlp_file_pattern_delete",
        "execute_confirmed_v4_dlp_sensor_create",
        "execute_confirmed_v4_dlp_sensor_delete",
        "execute_confirmed_v4_antivirus_profile_create",
        "execute_confirmed_v4_antivirus_profile_delete",
        "execute_confirmed_v4_rdp_event_filter_create",
        "execute_confirmed_v4_rdp_event_filter_delete",
        "execute_confirmed_v4_secret_policy_create",
            "execute_confirmed_v4_secret_policy_update",
            "execute_confirmed_v4_ssh_filter_create",
            "execute_confirmed_v4_ssh_filter_delete",
            "execute_confirmed_v4_launcher_create",
            "execute_confirmed_v4_launcher_timeout_update",
            "execute_confirmed_v4_launcher_command_line_matcher_configure",
            "execute_confirmed_v4_template_create",
            "execute_confirmed_v4_template_web_vnc_port_update",
            "execute_confirmed_v4_disposable_template_archive",
        "execute_confirmed_v4_dependency_updater_create",
        "execute_confirmed_v4_secret_gateway_create",
            "execute_confirmed_v4_client_integrity_configure",
            "execute_confirmed_v4_character_set_create",
            "execute_confirmed_v4_character_set_delete",
            "execute_confirmed_v4_windows_app_filter_create",
            "execute_confirmed_v4_windows_app_filter_delete",
            "execute_confirmed_v4_recording_policy_enable",
                "execute_confirmed_v4_password_policy_create",
                "execute_confirmed_v4_password_policy_delete",
                "execute_confirmed_v4_report_layout_create",
                "execute_confirmed_v4_report_layout_delete",
        "execute_confirmed_v4_ztna_access_proxy_client_certificate",
        "execute_confirmed_v4_ztna_access_proxy_client_certificate_rollback",
            "execute_confirmed_v4_ztna_user_control_configure",
            "execute_confirmed_v4_ztna_user_control_rollback",
            "execute_confirmed_v4_ztna_wad_debug_diagnostic",
        "execute_confirmed_v4_snmp_agent_enable",
        "execute_confirmed_v4_snmp_agent_rollback",
            "execute_confirmed_v4_logging_disk_disable",
            "execute_confirmed_v4_fortianalyzer_enable",
            "execute_confirmed_v4_maintenance_mode_enable",
            "execute_confirmed_v4_maintenance_mode_rollback",
        "execute_confirmed_v4_secret_audit_generate",
            "execute_confirmed_v4_active_launch_disconnect",
            "execute_confirmed_v4_automation_trigger_create",
            "execute_confirmed_v4_automation_trigger_delete",
            "execute_confirmed_v4_automation_action_create",
            "execute_confirmed_v4_automation_action_delete",
            "execute_confirmed_v4_automation_stitch_create",
            "execute_confirmed_v4_automation_stitch_delete",
            "execute_confirmed_v4_user_group_create",
            "execute_confirmed_v4_user_group_membership_change",
            "execute_confirmed_v4_auto_provision_rule_create",
            "execute_confirmed_v4_auto_provision_rule_disable",
            "execute_confirmed_v4_schedule_create",
            "execute_confirmed_v4_schedule_delete",
            "execute_confirmed_v4_schedule_assign",
            "execute_confirmed_v4_schedule_assignment_detach",
            "execute_confirmed_v4_approval_profile_create",
        "execute_confirmed_v4_approval_profile_description_update",
        "execute_confirmed_v4_approval_profile_delete",
        "execute_confirmed_v4_approval_email_template_create",
        "execute_confirmed_v4_approval_email_template_content_update",
        "execute_confirmed_v4_approval_email_template_delete",
    }
    assert {
        capability.tool_name
        for capability in registry.capabilities
        if capability.annotation()["local_state_write"] is True
    } == (
        diagnostic_tools
        | lab_execute_tools
        | v4_state_tools
        | v4_folder_confirmation_tools
        | v4_target_confirmation_tools
        | v4_local_user_confirmation_tools
        | v4_device_write_tools
    )
    assert {
        capability.tool_name
        for capability in registry.capabilities
        if capability.annotation()["device_write"] is True
    } == v4_device_write_tools
    assert {
        capability.tool_name
        for capability in registry.capabilities
        if capability.annotation()["destructive"] is True
            } == {
                "execute_confirmed_v4_ipv4_address_delete",
                "execute_confirmed_v4_classification_tag_delete",
                "execute_confirmed_v4_ssh_target_delete",
                "execute_confirmed_v4_address_group_delete",
                "execute_confirmed_v4_antivirus_profile_delete",
            "execute_confirmed_v4_rdp_event_filter_delete",
            "execute_confirmed_v4_ssh_filter_delete",
            "execute_confirmed_v4_dlp_sensor_delete",
            "execute_confirmed_v4_dlp_file_pattern_delete",
            "execute_confirmed_v4_character_set_delete",
        "execute_confirmed_v4_windows_app_filter_delete",
        "execute_confirmed_v4_password_policy_delete",
        "execute_confirmed_v4_report_layout_delete",
            "execute_confirmed_v4_automation_stitch_delete",
            "execute_confirmed_v4_automation_trigger_delete",
            "execute_confirmed_v4_automation_action_delete",
            "execute_confirmed_v4_schedule_delete",
            "execute_confirmed_v4_approval_email_template_delete",
        "execute_confirmed_v4_approval_profile_delete",
    }
    non_idempotent = (
        {"summarize_v4_synthetic_terraform_plan"}
        | diagnostic_tools
        | v4_state_tools
        | v4_folder_confirmation_tools
        | v4_target_confirmation_tools
        | v4_local_user_confirmation_tools
    )
    assert all(
        capability.annotation()["idempotent"]
        is (capability.tool_name not in non_idempotent)
        for capability in registry.capabilities
    )


def test_execution_mode_and_contact_invariants_are_explicit() -> None:
    capabilities = DEFAULT_CAPABILITY_REGISTRY.capabilities

    live_tools = {
        capability.tool_name
        for capability in capabilities
        if capability.execution_mode is ExecutionMode.LIVE
    }
    assert live_tools == {
        "get_overall_health_summary",
        "get_system_status_summary",
        "get_system_global_summary",
        "get_approval_profile_summary",
        "get_fortianalyzer_delivery_posture_summary",
        "get_license_support_posture_summary",
        "get_ha_configuration_posture_summary",
        "get_recording_storage_health_summary",
        "get_password_changer_configuration_posture_summary",
            "get_ems_connection_posture_summary",
            "get_cli_ha_configuration_summary",
            "get_cli_ha_status_summary",
            "get_cli_ha_checksum_summary",
            "create_ha_diagnostic_baseline",
            "compare_ha_diagnostic_baseline",
            "correlate_ha_api_cli_posture",
            "get_v4_ha_reconciliation_assessment",
            "observe_v4_bound_secret_request",
            "preview_v4_child_folder_create",
            "confirm_v4_child_folder_create",
            "execute_confirmed_v4_child_folder",
            "preview_v4_folder_user_acl_grant",
            "confirm_v4_folder_user_acl_grant",
            "execute_confirmed_v4_folder_user_acl_grant",
            "preview_v4_folder_user_acl_revoke",
            "confirm_v4_folder_user_acl_revoke",
            "execute_confirmed_v4_folder_user_acl_revoke",
            "preview_v4_public_child_folder_rename",
            "confirm_v4_public_child_folder_rename",
            "execute_confirmed_v4_public_child_folder_rename",
            "preview_v4_empty_public_child_folder_archive",
            "confirm_v4_empty_public_child_folder_archive",
            "execute_confirmed_v4_empty_public_child_folder_archive",
            "preview_v4_public_child_folder_policy_assign",
            "confirm_v4_public_child_folder_policy_assign",
            "execute_confirmed_v4_public_child_folder_policy_assign",
            "preview_v4_public_child_folder_policy_detach",
            "confirm_v4_public_child_folder_policy_detach",
            "execute_confirmed_v4_public_child_folder_policy_detach",
            "preview_v4_classification_tag_create",
            "confirm_v4_classification_tag_create",
            "execute_confirmed_v4_classification_tag_create",
            "preview_v4_classification_tag_delete",
            "confirm_v4_classification_tag_delete",
            "execute_confirmed_v4_classification_tag_delete",
            "preview_v4_classification_tag_assign",
            "confirm_v4_classification_tag_assign",
            "execute_confirmed_v4_classification_tag_assign",
            "preview_v4_classification_tag_assign_rollback",
            "confirm_v4_classification_tag_assign_rollback",
            "execute_confirmed_v4_classification_tag_assign_rollback",
            "preview_v4_ipv4_address_create",
            "confirm_v4_ipv4_address_create",
            "execute_confirmed_v4_ipv4_address_create",
            "preview_v4_ipv4_address_delete",
            "confirm_v4_ipv4_address_delete",
            "execute_confirmed_v4_ipv4_address_delete",
                "preview_v4_address_group_create",
                "confirm_v4_address_group_create",
                "execute_confirmed_v4_address_group_create",
                "preview_v4_address_group_delete",
                "confirm_v4_address_group_delete",
                "execute_confirmed_v4_address_group_delete",
            "get_v4_ztna_device_context_diagnostic",
            "get_v4_ztna_folder_control_posture",
            "preview_v4_ssh_target_create",
            "confirm_v4_ssh_target_create",
            "execute_confirmed_v4_ssh_target",
            "preview_v4_target_update_description",
            "confirm_v4_target_update_description",
            "execute_confirmed_v4_target_update_description",
            "preview_v4_ssh_target_delete",
            "confirm_v4_ssh_target_delete",
            "execute_confirmed_v4_ssh_target_delete",
            "preview_v4_certificate_csr_generate",
            "confirm_v4_certificate_csr_generate",
            "execute_confirmed_v4_certificate_csr_generate",
            "preview_v4_secret_metadata_create",
            "confirm_v4_secret_metadata_create",
            "execute_confirmed_v4_secret_metadata_create",
            "preview_v4_interface_explicit_web_proxy_enable",
            "confirm_v4_interface_explicit_web_proxy_enable",
            "execute_confirmed_v4_interface_explicit_web_proxy_enable",
            "preview_v4_interface_explicit_web_proxy_rollback",
            "confirm_v4_interface_explicit_web_proxy_rollback",
            "execute_confirmed_v4_interface_explicit_web_proxy_rollback",
            "preview_v4_local_user_disable",
            "confirm_v4_local_user_disable",
            "execute_confirmed_v4_local_user_disable",
            "preview_v4_local_user_create",
            "confirm_v4_local_user_create",
            "execute_confirmed_v4_local_user_create",
            "preview_v4_local_user_reset",
            "confirm_v4_local_user_reset",
            "execute_confirmed_v4_local_user_reset",
            "preview_v4_role_create",
            "confirm_v4_role_create",
            "execute_confirmed_v4_role_create",
            "preview_v4_role_diagnostics_enable",
            "confirm_v4_role_diagnostics_enable",
            "execute_confirmed_v4_role_diagnostics_enable",
            "preview_v4_role_assign",
            "confirm_v4_role_assign",
            "execute_confirmed_v4_role_assign",
            "preview_v4_dlp_file_pattern_create",
            "confirm_v4_dlp_file_pattern_create",
            "execute_confirmed_v4_dlp_file_pattern_create",
            "preview_v4_dlp_file_pattern_delete",
            "confirm_v4_dlp_file_pattern_delete",
            "execute_confirmed_v4_dlp_file_pattern_delete",
            "preview_v4_dlp_sensor_create",
            "confirm_v4_dlp_sensor_create",
            "execute_confirmed_v4_dlp_sensor_create",
            "preview_v4_dlp_sensor_delete",
            "confirm_v4_dlp_sensor_delete",
            "execute_confirmed_v4_dlp_sensor_delete",
            "preview_v4_antivirus_profile_create",
            "confirm_v4_antivirus_profile_create",
            "execute_confirmed_v4_antivirus_profile_create",
            "preview_v4_antivirus_profile_delete",
            "confirm_v4_antivirus_profile_delete",
            "execute_confirmed_v4_antivirus_profile_delete",
            "preview_v4_rdp_event_filter_create",
            "confirm_v4_rdp_event_filter_create",
            "execute_confirmed_v4_rdp_event_filter_create",
            "preview_v4_rdp_event_filter_delete",
            "confirm_v4_rdp_event_filter_delete",
            "execute_confirmed_v4_rdp_event_filter_delete",
            "preview_v4_secret_policy_create",
            "confirm_v4_secret_policy_create",
            "execute_confirmed_v4_secret_policy_create",
            "preview_v4_secret_policy_update",
            "confirm_v4_secret_policy_update",
            "execute_confirmed_v4_secret_policy_update",
            "preview_v4_ssh_filter_create",
            "confirm_v4_ssh_filter_create",
            "execute_confirmed_v4_ssh_filter_create",
            "preview_v4_ssh_filter_delete",
            "confirm_v4_ssh_filter_delete",
            "execute_confirmed_v4_ssh_filter_delete",
            "preview_v4_launcher_create",
            "confirm_v4_launcher_create",
            "execute_confirmed_v4_launcher_create",
                "preview_v4_launcher_timeout_update",
                "confirm_v4_launcher_timeout_update",
                "execute_confirmed_v4_launcher_timeout_update",
                "preview_v4_launcher_command_line_matcher_configure",
                "confirm_v4_launcher_command_line_matcher_configure",
                "execute_confirmed_v4_launcher_command_line_matcher_configure",
            "preview_v4_template_create",
            "confirm_v4_template_create",
            "execute_confirmed_v4_template_create",
            "preview_v4_template_web_vnc_port_update",
            "confirm_v4_template_web_vnc_port_update",
            "execute_confirmed_v4_template_web_vnc_port_update",
            "preview_v4_disposable_template_archive",
            "confirm_v4_disposable_template_archive",
            "execute_confirmed_v4_disposable_template_archive",
            "preview_v4_dependency_updater_create",
            "confirm_v4_dependency_updater_create",
            "execute_confirmed_v4_dependency_updater_create",
            "preview_v4_secret_gateway_create",
            "confirm_v4_secret_gateway_create",
            "execute_confirmed_v4_secret_gateway_create",
                "preview_v4_client_integrity_configure",
                "confirm_v4_client_integrity_configure",
                "execute_confirmed_v4_client_integrity_configure",
                "preview_v4_character_set_create",
                "confirm_v4_character_set_create",
                "execute_confirmed_v4_character_set_create",
                "preview_v4_character_set_delete",
                "confirm_v4_character_set_delete",
                "execute_confirmed_v4_character_set_delete",
                    "preview_v4_windows_app_filter_create",
                    "confirm_v4_windows_app_filter_create",
                    "execute_confirmed_v4_windows_app_filter_create",
                    "preview_v4_windows_app_filter_delete",
                    "confirm_v4_windows_app_filter_delete",
                    "execute_confirmed_v4_windows_app_filter_delete",
                    "preview_v4_recording_policy_enable",
                    "confirm_v4_recording_policy_enable",
                    "execute_confirmed_v4_recording_policy_enable",
                        "preview_v4_password_policy_create",
                "confirm_v4_password_policy_create",
                "execute_confirmed_v4_password_policy_create",
                    "preview_v4_password_policy_delete",
                    "confirm_v4_password_policy_delete",
                    "execute_confirmed_v4_password_policy_delete",
                    "preview_v4_report_layout_create",
                "confirm_v4_report_layout_create",
                "execute_confirmed_v4_report_layout_create",
                "preview_v4_report_layout_delete",
                "confirm_v4_report_layout_delete",
                "execute_confirmed_v4_report_layout_delete",
            "preview_v4_ztna_access_proxy_client_certificate",
            "confirm_v4_ztna_access_proxy_client_certificate",
            "execute_confirmed_v4_ztna_access_proxy_client_certificate",
            "preview_v4_ztna_access_proxy_client_certificate_rollback",
            "confirm_v4_ztna_access_proxy_client_certificate_rollback",
            "execute_confirmed_v4_ztna_access_proxy_client_certificate_rollback",
            "preview_v4_ztna_user_control_configure",
            "confirm_v4_ztna_user_control_configure",
            "execute_confirmed_v4_ztna_user_control_configure",
            "preview_v4_ztna_user_control_rollback",
            "confirm_v4_ztna_user_control_rollback",
            "execute_confirmed_v4_ztna_user_control_rollback",
            "preview_v4_ztna_wad_debug_diagnostic",
            "confirm_v4_ztna_wad_debug_diagnostic",
            "execute_confirmed_v4_ztna_wad_debug_diagnostic",
            "preview_v4_snmp_agent_enable",
            "confirm_v4_snmp_agent_enable",
            "execute_confirmed_v4_snmp_agent_enable",
            "preview_v4_snmp_agent_rollback",
            "confirm_v4_snmp_agent_rollback",
            "execute_confirmed_v4_snmp_agent_rollback",
            "preview_v4_logging_disk_disable",
            "confirm_v4_logging_disk_disable",
            "execute_confirmed_v4_logging_disk_disable",
            "preview_v4_fortianalyzer_enable",
            "confirm_v4_fortianalyzer_enable",
            "execute_confirmed_v4_fortianalyzer_enable",
            "preview_v4_maintenance_mode_enable",
            "confirm_v4_maintenance_mode_enable",
            "execute_confirmed_v4_maintenance_mode_enable",
            "preview_v4_maintenance_mode_rollback",
            "confirm_v4_maintenance_mode_rollback",
            "execute_confirmed_v4_maintenance_mode_rollback",
            "preview_v4_secret_audit_generate",
            "confirm_v4_secret_audit_generate",
            "execute_confirmed_v4_secret_audit_generate",
            "summarize_v4_secret_access_audit",
            "observe_v4_active_launches",
            "preview_v4_active_launch_disconnect",
            "confirm_v4_active_launch_disconnect",
            "execute_confirmed_v4_active_launch_disconnect",
            "preview_v4_automation_trigger_create",
            "confirm_v4_automation_trigger_create",
            "execute_confirmed_v4_automation_trigger_create",
            "preview_v4_automation_trigger_delete",
            "confirm_v4_automation_trigger_delete",
            "execute_confirmed_v4_automation_trigger_delete",
            "preview_v4_automation_action_create",
            "confirm_v4_automation_action_create",
            "execute_confirmed_v4_automation_action_create",
            "preview_v4_automation_action_delete",
            "confirm_v4_automation_action_delete",
            "execute_confirmed_v4_automation_action_delete",
            "preview_v4_automation_stitch_create",
            "confirm_v4_automation_stitch_create",
            "execute_confirmed_v4_automation_stitch_create",
            "preview_v4_automation_stitch_delete",
            "confirm_v4_automation_stitch_delete",
            "execute_confirmed_v4_automation_stitch_delete",
            "preview_v4_user_group_create",
            "confirm_v4_user_group_create",
            "execute_confirmed_v4_user_group_create",
            "preview_v4_user_group_membership_change",
            "confirm_v4_user_group_membership_change",
            "execute_confirmed_v4_user_group_membership_change",
            "preview_v4_auto_provision_rule_create",
            "confirm_v4_auto_provision_rule_create",
            "execute_confirmed_v4_auto_provision_rule_create",
            "preview_v4_auto_provision_rule_disable",
            "confirm_v4_auto_provision_rule_disable",
            "execute_confirmed_v4_auto_provision_rule_disable",
            "preview_v4_schedule_create",
            "confirm_v4_schedule_create",
            "execute_confirmed_v4_schedule_create",
            "preview_v4_schedule_delete",
            "confirm_v4_schedule_delete",
            "execute_confirmed_v4_schedule_delete",
                "preview_v4_schedule_assign",
                "confirm_v4_schedule_assign",
                "execute_confirmed_v4_schedule_assign",
                "preview_v4_schedule_assignment_detach",
                "confirm_v4_schedule_assignment_detach",
                "execute_confirmed_v4_schedule_assignment_detach",
            "preview_v4_approval_profile_create",
            "confirm_v4_approval_profile_create",
            "execute_confirmed_v4_approval_profile_create",
            "preview_v4_approval_profile_description_update",
            "confirm_v4_approval_profile_description_update",
            "execute_confirmed_v4_approval_profile_description_update",
            "preview_v4_approval_profile_delete",
            "confirm_v4_approval_profile_delete",
            "execute_confirmed_v4_approval_profile_delete",
            "preview_v4_approval_email_template_create",
            "confirm_v4_approval_email_template_create",
            "execute_confirmed_v4_approval_email_template_create",
            "preview_v4_approval_email_template_content_update",
            "confirm_v4_approval_email_template_content_update",
            "execute_confirmed_v4_approval_email_template_content_update",
            "preview_v4_approval_email_template_delete",
            "confirm_v4_approval_email_template_delete",
            "execute_confirmed_v4_approval_email_template_delete",
        }
    assert all(
        capability.contacts_fortipam
        is (capability.execution_mode is ExecutionMode.LIVE)
        for capability in capabilities
    )
    assert {
        capability.tool_name
        for capability in capabilities
        if capability.execution_mode is ExecutionMode.LAB_SIMULATED
    } == {
        "preview_v31_lab_public_folder",
        "preview_v31_lab_target",
        "preview_v31_lab_secret_metadata",
        "preview_v31_lab_local_user",
        "preview_v31_lab_folder_access_assignment",
        "execute_confirmed_v31_lab_operation",
    }


def test_sanitized_matrix_is_static_and_excludes_endpoint_and_secret_fields() -> None:
    matrix = get_capability_matrix()

    assert matrix["schema_version"] == "1.3"
    assert matrix["current_surface_only"] is True
    assert matrix["action_evidence_is_authorization"] is False
    assert matrix["network_call_executed"] is False
    assert matrix["fortipam_contacted"] is False
    assert matrix["tool_count"] == 383
    assert matrix["action_inventory"] == {
        "total": 131,
        "mapped": 131,
        "unmapped": 0,
        "mapped_supplemental": 4,
        "states": {
            "lab_accepted": 96,
            "implemented_not_accepted": 5,
            "documented_not_accepted": 21,
            "verified": 5,
            "source_gated": 0,
            "product_unavailable": 4,
        },
        "implemented_readiness": {
            "ready_for_authorized_preview": 0,
            "baseline_unavailable": 3,
            "reconciliation_required_non_retry": 2,
            "ready_actions": [],
        },
    }
    inventory = cast(dict[str, object], matrix["action_inventory"])
    states = cast(dict[str, int], inventory["states"])
    states["lab_accepted"] = 0
    readiness = cast(dict[str, object], inventory["implemented_readiness"])
    ready_actions = cast(list[str], readiness["ready_actions"])
    ready_actions.clear()
    refreshed = get_capability_matrix()
    refreshed_inventory = cast(dict[str, object], refreshed["action_inventory"])
    refreshed_states = cast(dict[str, int], refreshed_inventory["states"])
    assert refreshed_states["lab_accepted"] == 96
    refreshed_readiness = cast(
        dict[str, object], refreshed_inventory["implemented_readiness"]
    )
    assert refreshed_readiness["ready_actions"] == []
    tools = cast(list[dict[str, object]], matrix["tools"])
    assert {tool["tool_name"] for tool in tools} == set(
            LAB_EXPECTED_TOOLS
            + V4_PLAN_TOOLS
            + V4_APPROVAL_REQUEST_OBSERVATION_TOOLS
            + V4_CONTROLLED_TOOLS
        + V4_FOLDER_ACL_TOOLS
        + V4_CLASSIFICATION_TAG_TOOLS
        + V4_CLASSIFICATION_TAG_ASSIGN_TOOLS
        + V4_ADDRESS_TOOLS
        + V4_ADDRESS_GROUP_TOOLS
        + V4_ZTNA_DIAGNOSTIC_TOOLS
        + V4_HA_RECONCILIATION_TOOLS
        + V4_TARGET_TOOLS
        + V4_TARGET_UPDATE_TOOLS
        + V4_CERTIFICATE_CSR_TOOLS
        + V4_SECRET_METADATA_TOOLS
        + V4_INTERFACE_WEB_PROXY_TOOLS
        + V4_LOCAL_USER_DISABLE_TOOLS
        + V4_LOCAL_USER_CREATE_TOOLS
        + V4_LOCAL_USER_RESET_TOOLS
        + V4_ROLE_CREATE_TOOLS
        + V4_ROLE_UPDATE_TOOLS
        + V4_ROLE_ASSIGN_TOOLS
        + V4_DLP_FILE_PATTERN_TOOLS
        + V4_DLP_SENSOR_TOOLS
        + V4_ANTIVIRUS_PROFILE_TOOLS
        + V4_RDP_EVENT_FILTER_TOOLS
        + V4_SECRET_POLICY_TOOLS
        + V4_SSH_FILTER_TOOLS
        + V4_LAUNCHER_TOOLS
        + V4_TEMPLATE_TOOLS
        + V4_TEMPLATE_ARCHIVE_TOOLS
        + V4_DEPENDENCY_UPDATER_TOOLS
        + V4_SECRET_GATEWAY_TOOLS
        + V4_CLIENT_INTEGRITY_TOOLS
        + V4_CHARACTER_SET_TOOLS
        + V4_WINDOWS_APP_FILTER_TOOLS
        + V4_RECORDING_POLICY_TOOLS
        + V4_PASSWORD_POLICY_TOOLS
        + V4_REPORT_LAYOUT_TOOLS
        + V4_ZTNA_ACCESS_PROXY_TOOLS
        + V4_ZTNA_USER_CONTROL_TOOLS
        + V4_ZTNA_WAD_DEBUG_TOOLS
        + V4_SNMP_AGENT_TOOLS
        + V4_LOGGING_DISK_TOOLS
        + V4_FORTIANALYZER_TOOLS
        + V4_MAINTENANCE_MODE_TOOLS
        + V4_SECRET_AUDIT_TOOLS
        + V4_SECRET_AUDIT_SUMMARY_TOOLS
        + V4_TERRAFORM_PLAN_REPORT_TOOLS
        + V4_ACTIVE_LAUNCH_TOOLS
        + V4_AUTOMATION_TRIGGER_TOOLS
        + V4_AUTOMATION_ACTION_TOOLS
        + V4_AUTOMATION_STITCH_TOOLS
        + V4_USER_GROUP_TOOLS
        + V4_USER_GROUP_MEMBERSHIP_TOOLS
        + V4_APL_TOOLS
        + V4_APL_DISABLE_TOOLS
        + V4_SCHEDULE_TOOLS
        + V4_SCHEDULE_ASSIGN_TOOLS
        + V4_APPROVAL_PROFILE_TOOLS
        + V4_APPROVAL_PROFILE_UPDATE_TOOLS
        + V4_APPROVAL_EMAIL_TEMPLATE_TOOLS
        + V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_TOOLS
    )
    rendered = repr(matrix).lower()
    for forbidden_field in (
        "'path':",
        "'parameter':",
        "'token':",
        "'credential':",
        "'host':",
    ):
        assert forbidden_field not in rendered


def test_pack_and_explicit_tool_filters_intersect_without_side_effects() -> None:
    selected = get_capability_matrix(
        enabled_packs=[ToolPack.APPROVAL_READ],
        enabled_tools=["plan_approval_profile_read", "get_system_status_summary"],
    )

    assert selected["tool_count"] == 1
    assert selected["tools"] == [
        {
            "tool_name": "plan_approval_profile_read",
            "description": "Validate the fixed approval-profile read plan.",
            "pack": "approval-read",
            "execution_mode": "plan",
            "risk_level": "low",
            "input_scope": "none",
            "supported_product_versions": ["1.9.1"],
            "contacts_fortipam": False,
            "device_write": False,
            "local_state_write": False,
            "read_only": True,
            "destructive": False,
            "idempotent": True,
        }
    ]


@pytest.mark.parametrize("invalid", (["unknown"], ["not-a-tool"]))
def test_filter_rejects_unknown_pack_or_tool(invalid: list[str]) -> None:
    with pytest.raises(ValueError):
        if invalid == ["unknown"]:
            get_capability_matrix(enabled_packs=invalid)
        else:
            get_capability_matrix(enabled_tools=invalid)
