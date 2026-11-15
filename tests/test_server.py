from __future__ import annotations

import asyncio
import logging
from typing import Annotated

from mcp import Client
from mcp.shared.exceptions import MCPError
from pydantic import BeforeValidator
import pytest

from fortipam_mcp import __version__
from fortipam_mcp.config import ConfigurationError
from fortipam_mcp.env import EnvironmentLoadReport
from fortipam_mcp.mcp_smoke import (
    EXPECTED_TOOLS,
    LAB_EXPECTED_TOOLS,
    V4_CONTROLLED_EXPECTED_TOOLS,
    V4_EXPECTED_TOOLS,
)
from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp import server as server_module


V4_SECRET_METADATA_CAPABILITY_TOOLS = {
    "preview_v4_secret_metadata_create",
    "confirm_v4_secret_metadata_create",
    "execute_confirmed_v4_secret_metadata_create",
}
V4_INTERFACE_WEB_PROXY_CAPABILITY_TOOLS = {
    "preview_v4_interface_explicit_web_proxy_enable",
    "confirm_v4_interface_explicit_web_proxy_enable",
    "execute_confirmed_v4_interface_explicit_web_proxy_enable",
    "preview_v4_interface_explicit_web_proxy_rollback",
    "confirm_v4_interface_explicit_web_proxy_rollback",
    "execute_confirmed_v4_interface_explicit_web_proxy_rollback",
}
V4_CERTIFICATE_CSR_CAPABILITY_TOOLS = {
    "preview_v4_certificate_csr_generate",
    "confirm_v4_certificate_csr_generate",
    "execute_confirmed_v4_certificate_csr_generate",
}
V4_TARGET_CREATE_CAPABILITY_TOOLS = {
    "preview_v4_ssh_target_create",
    "confirm_v4_ssh_target_create",
    "execute_confirmed_v4_ssh_target",
    "preview_v4_ssh_target_delete",
    "confirm_v4_ssh_target_delete",
    "execute_confirmed_v4_ssh_target_delete",
}
V4_TARGET_UPDATE_CAPABILITY_TOOLS = {
    "preview_v4_target_update_description",
    "confirm_v4_target_update_description",
    "execute_confirmed_v4_target_update_description",
}
V4_CLASSIFICATION_TAG_ASSIGN_CAPABILITY_TOOLS = {
    "preview_v4_classification_tag_assign",
    "confirm_v4_classification_tag_assign",
    "execute_confirmed_v4_classification_tag_assign",
    "preview_v4_classification_tag_assign_rollback",
    "confirm_v4_classification_tag_assign_rollback",
    "execute_confirmed_v4_classification_tag_assign_rollback",
}
V4_FOLDER_ACL_GRANT_CAPABILITY_TOOLS = {
    "preview_v4_folder_user_acl_grant",
    "confirm_v4_folder_user_acl_grant",
    "execute_confirmed_v4_folder_user_acl_grant",
}
V4_FOLDER_ACL_REVOKE_CAPABILITY_TOOLS = {
    "preview_v4_folder_user_acl_revoke",
    "confirm_v4_folder_user_acl_revoke",
    "execute_confirmed_v4_folder_user_acl_revoke",
}
V4_FOLDER_RENAME_CAPABILITY_TOOLS = {
    "preview_v4_public_child_folder_rename",
    "confirm_v4_public_child_folder_rename",
    "execute_confirmed_v4_public_child_folder_rename",
}
V4_FOLDER_ARCHIVE_CAPABILITY_TOOLS = {
    "preview_v4_empty_public_child_folder_archive",
    "confirm_v4_empty_public_child_folder_archive",
    "execute_confirmed_v4_empty_public_child_folder_archive",
}
V4_FOLDER_POLICY_ASSIGN_CAPABILITY_TOOLS = {
    "preview_v4_public_child_folder_policy_assign",
    "confirm_v4_public_child_folder_policy_assign",
    "execute_confirmed_v4_public_child_folder_policy_assign",
}
V4_FOLDER_POLICY_DETACH_CAPABILITY_TOOLS = {
    "preview_v4_public_child_folder_policy_detach",
    "confirm_v4_public_child_folder_policy_detach",
    "execute_confirmed_v4_public_child_folder_policy_detach",
}
V4_CLASSIFICATION_TAG_CREATE_CAPABILITY_TOOLS = {
    "preview_v4_classification_tag_create",
    "confirm_v4_classification_tag_create",
    "execute_confirmed_v4_classification_tag_create",
    "preview_v4_classification_tag_delete",
    "confirm_v4_classification_tag_delete",
    "execute_confirmed_v4_classification_tag_delete",
}
V4_DLP_FILE_PATTERN_CAPABILITY_TOOLS = {
    "preview_v4_dlp_file_pattern_create",
    "confirm_v4_dlp_file_pattern_create",
    "execute_confirmed_v4_dlp_file_pattern_create",
    "preview_v4_dlp_file_pattern_delete",
    "confirm_v4_dlp_file_pattern_delete",
    "execute_confirmed_v4_dlp_file_pattern_delete",
}
V4_DLP_SENSOR_CAPABILITY_TOOLS = {
    "preview_v4_dlp_sensor_create",
    "confirm_v4_dlp_sensor_create",
    "execute_confirmed_v4_dlp_sensor_create",
    "preview_v4_dlp_sensor_delete",
    "confirm_v4_dlp_sensor_delete",
    "execute_confirmed_v4_dlp_sensor_delete",
}
V4_ANTIVIRUS_PROFILE_CAPABILITY_TOOLS = {
    "preview_v4_antivirus_profile_create",
    "confirm_v4_antivirus_profile_create",
    "execute_confirmed_v4_antivirus_profile_create",
    "preview_v4_antivirus_profile_delete",
    "confirm_v4_antivirus_profile_delete",
    "execute_confirmed_v4_antivirus_profile_delete",
}
V4_RDP_EVENT_FILTER_CAPABILITY_TOOLS = {
    "preview_v4_rdp_event_filter_create",
    "confirm_v4_rdp_event_filter_create",
    "execute_confirmed_v4_rdp_event_filter_create",
    "preview_v4_rdp_event_filter_delete",
    "confirm_v4_rdp_event_filter_delete",
    "execute_confirmed_v4_rdp_event_filter_delete",
}
V4_SECRET_POLICY_CAPABILITY_TOOLS = {
    "preview_v4_secret_policy_create",
    "confirm_v4_secret_policy_create",
    "execute_confirmed_v4_secret_policy_create",
    "preview_v4_secret_policy_update",
    "confirm_v4_secret_policy_update",
    "execute_confirmed_v4_secret_policy_update",
}
V4_SSH_FILTER_CAPABILITY_TOOLS = {
    "preview_v4_ssh_filter_create",
    "confirm_v4_ssh_filter_create",
    "execute_confirmed_v4_ssh_filter_create",
    "preview_v4_ssh_filter_delete",
    "confirm_v4_ssh_filter_delete",
    "execute_confirmed_v4_ssh_filter_delete",
}
V4_LAUNCHER_CAPABILITY_TOOLS = {
    "preview_v4_launcher_create",
    "confirm_v4_launcher_create",
    "execute_confirmed_v4_launcher_create",
}
V4_LAUNCHER_UPDATE_CAPABILITY_TOOLS = {
    "preview_v4_launcher_timeout_update",
    "confirm_v4_launcher_timeout_update",
    "execute_confirmed_v4_launcher_timeout_update",
}
V4_LAUNCHER_MATCHER_CAPABILITY_TOOLS = {
    "preview_v4_launcher_command_line_matcher_configure",
    "confirm_v4_launcher_command_line_matcher_configure",
    "execute_confirmed_v4_launcher_command_line_matcher_configure",
}
V4_TEMPLATE_CAPABILITY_TOOLS = {
    "preview_v4_template_create",
    "confirm_v4_template_create",
    "execute_confirmed_v4_template_create",
    "preview_v4_template_web_vnc_port_update",
    "confirm_v4_template_web_vnc_port_update",
    "execute_confirmed_v4_template_web_vnc_port_update",
}
V4_TEMPLATE_ARCHIVE_CAPABILITY_TOOLS = {
    "preview_v4_disposable_template_archive",
    "confirm_v4_disposable_template_archive",
    "execute_confirmed_v4_disposable_template_archive",
}
V4_DEPENDENCY_UPDATER_CAPABILITY_TOOLS = {
    "preview_v4_dependency_updater_create",
    "confirm_v4_dependency_updater_create",
    "execute_confirmed_v4_dependency_updater_create",
}
V4_SECRET_GATEWAY_CAPABILITY_TOOLS = {
    "preview_v4_secret_gateway_create",
    "confirm_v4_secret_gateway_create",
    "execute_confirmed_v4_secret_gateway_create",
}
V4_CLIENT_INTEGRITY_CAPABILITY_TOOLS = {
    "preview_v4_client_integrity_configure",
    "confirm_v4_client_integrity_configure",
    "execute_confirmed_v4_client_integrity_configure",
}
V4_CHARACTER_SET_CAPABILITY_TOOLS = {
    "preview_v4_character_set_create",
    "confirm_v4_character_set_create",
    "execute_confirmed_v4_character_set_create",
    "preview_v4_character_set_delete",
    "confirm_v4_character_set_delete",
    "execute_confirmed_v4_character_set_delete",
}
V4_WINDOWS_APP_FILTER_CAPABILITY_TOOLS = {
    "preview_v4_windows_app_filter_create",
    "confirm_v4_windows_app_filter_create",
    "execute_confirmed_v4_windows_app_filter_create",
    "preview_v4_windows_app_filter_delete",
    "confirm_v4_windows_app_filter_delete",
    "execute_confirmed_v4_windows_app_filter_delete",
}
V4_RECORDING_POLICY_CAPABILITY_TOOLS = {
    "preview_v4_recording_policy_enable",
    "confirm_v4_recording_policy_enable",
    "execute_confirmed_v4_recording_policy_enable",
}
V4_PASSWORD_POLICY_CAPABILITY_TOOLS = {
    "preview_v4_password_policy_create",
    "confirm_v4_password_policy_create",
    "execute_confirmed_v4_password_policy_create",
    "preview_v4_password_policy_delete",
    "confirm_v4_password_policy_delete",
    "execute_confirmed_v4_password_policy_delete",
}
V4_REPORT_LAYOUT_CAPABILITY_TOOLS = {
    "preview_v4_report_layout_create",
    "confirm_v4_report_layout_create",
    "execute_confirmed_v4_report_layout_create",
    "preview_v4_report_layout_delete",
    "confirm_v4_report_layout_delete",
    "execute_confirmed_v4_report_layout_delete",
}
V4_ADDRESS_CAPABILITY_TOOLS = {
    "preview_v4_ipv4_address_create",
    "confirm_v4_ipv4_address_create",
    "execute_confirmed_v4_ipv4_address_create",
    "preview_v4_ipv4_address_delete",
    "confirm_v4_ipv4_address_delete",
    "execute_confirmed_v4_ipv4_address_delete",
}
V4_ADDRESS_GROUP_CAPABILITY_TOOLS = {
    "preview_v4_address_group_create",
    "confirm_v4_address_group_create",
    "execute_confirmed_v4_address_group_create",
    "preview_v4_address_group_delete",
    "confirm_v4_address_group_delete",
    "execute_confirmed_v4_address_group_delete",
}
V4_ZTNA_ACCESS_PROXY_CAPABILITY_TOOLS = {
    "preview_v4_ztna_access_proxy_client_certificate",
    "confirm_v4_ztna_access_proxy_client_certificate",
    "execute_confirmed_v4_ztna_access_proxy_client_certificate",
    "preview_v4_ztna_access_proxy_client_certificate_rollback",
    "confirm_v4_ztna_access_proxy_client_certificate_rollback",
    "execute_confirmed_v4_ztna_access_proxy_client_certificate_rollback",
}
V4_ZTNA_USER_CONTROL_CAPABILITY_TOOLS = {
    "preview_v4_ztna_user_control_configure",
    "confirm_v4_ztna_user_control_configure",
    "execute_confirmed_v4_ztna_user_control_configure",
    "preview_v4_ztna_user_control_rollback",
    "confirm_v4_ztna_user_control_rollback",
    "execute_confirmed_v4_ztna_user_control_rollback",
}
V4_ZTNA_WAD_DEBUG_CAPABILITY_TOOLS = {
    "preview_v4_ztna_wad_debug_diagnostic",
    "confirm_v4_ztna_wad_debug_diagnostic",
    "execute_confirmed_v4_ztna_wad_debug_diagnostic",
}
V4_ZTNA_FOLDER_POSTURE_CAPABILITY_TOOLS = {
    "get_v4_ztna_folder_control_posture",
}
V4_SNMP_AGENT_CAPABILITY_TOOLS = {
    "preview_v4_snmp_agent_enable",
    "confirm_v4_snmp_agent_enable",
    "execute_confirmed_v4_snmp_agent_enable",
    "preview_v4_snmp_agent_rollback",
    "confirm_v4_snmp_agent_rollback",
    "execute_confirmed_v4_snmp_agent_rollback",
}
V4_LOGGING_DISK_CAPABILITY_TOOLS = {
    "preview_v4_logging_disk_disable",
    "confirm_v4_logging_disk_disable",
    "execute_confirmed_v4_logging_disk_disable",
}
V4_FORTIANALYZER_CAPABILITY_TOOLS = {
    "preview_v4_fortianalyzer_enable",
    "confirm_v4_fortianalyzer_enable",
    "execute_confirmed_v4_fortianalyzer_enable",
}
V4_MAINTENANCE_MODE_CAPABILITY_TOOLS = {
    "preview_v4_maintenance_mode_enable",
    "confirm_v4_maintenance_mode_enable",
    "execute_confirmed_v4_maintenance_mode_enable",
    "preview_v4_maintenance_mode_rollback",
    "confirm_v4_maintenance_mode_rollback",
    "execute_confirmed_v4_maintenance_mode_rollback",
}
V4_SECRET_AUDIT_CAPABILITY_TOOLS = {
    "preview_v4_secret_audit_generate",
    "confirm_v4_secret_audit_generate",
    "execute_confirmed_v4_secret_audit_generate",
}
V4_ACTIVE_LAUNCH_CAPABILITY_TOOLS = {
    "observe_v4_active_launches",
    "preview_v4_active_launch_disconnect",
    "confirm_v4_active_launch_disconnect",
    "execute_confirmed_v4_active_launch_disconnect",
}
V4_AUTOMATION_TRIGGER_CAPABILITY_TOOLS = {
    "preview_v4_automation_trigger_create",
    "confirm_v4_automation_trigger_create",
    "execute_confirmed_v4_automation_trigger_create",
    "preview_v4_automation_trigger_delete",
    "confirm_v4_automation_trigger_delete",
    "execute_confirmed_v4_automation_trigger_delete",
}
V4_AUTOMATION_ACTION_CAPABILITY_TOOLS = {
    "preview_v4_automation_action_create",
    "confirm_v4_automation_action_create",
    "execute_confirmed_v4_automation_action_create",
    "preview_v4_automation_action_delete",
    "confirm_v4_automation_action_delete",
    "execute_confirmed_v4_automation_action_delete",
}
V4_AUTOMATION_STITCH_CAPABILITY_TOOLS = {
    "preview_v4_automation_stitch_create",
    "confirm_v4_automation_stitch_create",
    "execute_confirmed_v4_automation_stitch_create",
    "preview_v4_automation_stitch_delete",
    "confirm_v4_automation_stitch_delete",
    "execute_confirmed_v4_automation_stitch_delete",
}
V4_USER_GROUP_CAPABILITY_TOOLS = {
    "preview_v4_user_group_create",
    "confirm_v4_user_group_create",
    "execute_confirmed_v4_user_group_create",
}
V4_USER_GROUP_MEMBERSHIP_CAPABILITY_TOOLS = {
    "preview_v4_user_group_membership_change",
    "confirm_v4_user_group_membership_change",
    "execute_confirmed_v4_user_group_membership_change",
}
V4_APL_CAPABILITY_TOOLS = {
    "preview_v4_auto_provision_rule_create",
    "confirm_v4_auto_provision_rule_create",
    "execute_confirmed_v4_auto_provision_rule_create",
}
V4_APL_DISABLE_CAPABILITY_TOOLS = {
    "preview_v4_auto_provision_rule_disable",
    "confirm_v4_auto_provision_rule_disable",
    "execute_confirmed_v4_auto_provision_rule_disable",
}
V4_SCHEDULE_CAPABILITY_TOOLS = {
    "preview_v4_schedule_create",
    "confirm_v4_schedule_create",
    "execute_confirmed_v4_schedule_create",
    "preview_v4_schedule_delete",
    "confirm_v4_schedule_delete",
    "execute_confirmed_v4_schedule_delete",
}
V4_SCHEDULE_ASSIGN_CAPABILITY_TOOLS = {
    "preview_v4_schedule_assign",
    "confirm_v4_schedule_assign",
    "execute_confirmed_v4_schedule_assign",
    "preview_v4_schedule_assignment_detach",
    "confirm_v4_schedule_assignment_detach",
    "execute_confirmed_v4_schedule_assignment_detach",
}
V4_LOCAL_USER_DISABLE_CAPABILITY_TOOLS = {
    "preview_v4_local_user_disable",
    "confirm_v4_local_user_disable",
    "execute_confirmed_v4_local_user_disable",
}
V4_LOCAL_USER_CREATE_CAPABILITY_TOOLS = {
    "preview_v4_local_user_create",
    "confirm_v4_local_user_create",
    "execute_confirmed_v4_local_user_create",
}
V4_LOCAL_USER_RESET_CAPABILITY_TOOLS = {
    "preview_v4_local_user_reset",
    "confirm_v4_local_user_reset",
    "execute_confirmed_v4_local_user_reset",
}
V4_ROLE_CREATE_CAPABILITY_TOOLS = {
    "preview_v4_role_create",
    "confirm_v4_role_create",
    "execute_confirmed_v4_role_create",
}
V4_ROLE_UPDATE_CAPABILITY_TOOLS = {
    "preview_v4_role_diagnostics_enable",
    "confirm_v4_role_diagnostics_enable",
    "execute_confirmed_v4_role_diagnostics_enable",
}
V4_ROLE_ASSIGN_CAPABILITY_TOOLS = {
    "preview_v4_role_assign",
    "confirm_v4_role_assign",
    "execute_confirmed_v4_role_assign",
}
V4_APPROVAL_PROFILE_CAPABILITY_TOOLS = {
    "preview_v4_approval_profile_create",
    "confirm_v4_approval_profile_create",
    "execute_confirmed_v4_approval_profile_create",
}
V4_APPROVAL_PROFILE_UPDATE_CAPABILITY_TOOLS = {
    "preview_v4_approval_profile_description_update",
    "confirm_v4_approval_profile_description_update",
    "execute_confirmed_v4_approval_profile_description_update",
    "preview_v4_approval_profile_delete",
    "confirm_v4_approval_profile_delete",
    "execute_confirmed_v4_approval_profile_delete",
}
V4_APPROVAL_EMAIL_TEMPLATE_CAPABILITY_TOOLS = {
    "preview_v4_approval_email_template_create",
    "confirm_v4_approval_email_template_create",
    "execute_confirmed_v4_approval_email_template_create",
}
V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_CAPABILITY_TOOLS = {
    "preview_v4_approval_email_template_content_update",
    "confirm_v4_approval_email_template_content_update",
    "execute_confirmed_v4_approval_email_template_content_update",
    "preview_v4_approval_email_template_delete",
    "confirm_v4_approval_email_template_delete",
    "execute_confirmed_v4_approval_email_template_delete",
}
V4_DLP_CAPABILITY_TOOLS = (
    V4_DLP_FILE_PATTERN_CAPABILITY_TOOLS | V4_DLP_SENSOR_CAPABILITY_TOOLS
)
V4_NONDEFAULT_CAPABILITY_TOOLS = (
    V4_CERTIFICATE_CSR_CAPABILITY_TOOLS
    | V4_DLP_CAPABILITY_TOOLS
    | V4_ANTIVIRUS_PROFILE_CAPABILITY_TOOLS
    | V4_RDP_EVENT_FILTER_CAPABILITY_TOOLS
    | V4_SECRET_POLICY_CAPABILITY_TOOLS
    | V4_SSH_FILTER_CAPABILITY_TOOLS
    | V4_LAUNCHER_CAPABILITY_TOOLS
    | V4_LAUNCHER_UPDATE_CAPABILITY_TOOLS
    | V4_LAUNCHER_MATCHER_CAPABILITY_TOOLS
    | V4_TEMPLATE_CAPABILITY_TOOLS
    | V4_DEPENDENCY_UPDATER_CAPABILITY_TOOLS
    | V4_SECRET_GATEWAY_CAPABILITY_TOOLS
    | V4_CLIENT_INTEGRITY_CAPABILITY_TOOLS
    | V4_WINDOWS_APP_FILTER_CAPABILITY_TOOLS
    | V4_RECORDING_POLICY_CAPABILITY_TOOLS
    | V4_ACTIVE_LAUNCH_CAPABILITY_TOOLS
    | V4_AUTOMATION_TRIGGER_CAPABILITY_TOOLS
    | V4_AUTOMATION_ACTION_CAPABILITY_TOOLS
    | V4_AUTOMATION_STITCH_CAPABILITY_TOOLS
    | V4_USER_GROUP_CAPABILITY_TOOLS
    | V4_USER_GROUP_MEMBERSHIP_CAPABILITY_TOOLS
    | V4_APL_CAPABILITY_TOOLS
    | V4_APL_DISABLE_CAPABILITY_TOOLS
    | V4_SCHEDULE_CAPABILITY_TOOLS
    | V4_SCHEDULE_ASSIGN_CAPABILITY_TOOLS
    | V4_APPROVAL_PROFILE_CAPABILITY_TOOLS
    | V4_APPROVAL_PROFILE_UPDATE_CAPABILITY_TOOLS
    | V4_APPROVAL_EMAIL_TEMPLATE_CAPABILITY_TOOLS
    | V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_CAPABILITY_TOOLS
    | {"get_v4_ha_reconciliation_assessment", "observe_v4_bound_secret_request"}
)


def test_mcp_v2_registers_expected_tools_without_live_configuration(monkeypatch) -> None:
    environment_loads = 0

    def _load_environment() -> EnvironmentLoadReport:
        nonlocal environment_loads
        environment_loads += 1
        return EnvironmentLoadReport(source="test", loaded=False)

    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        _load_environment,
    )

    def _unconfigured():
        raise ConfigurationError("test-only unconfigured server")

    monkeypatch.setattr(server_module, "load_config", _unconfigured)
    server = server_module.FortiPamMcpServer()

    assert environment_loads == 0

    async def _list_tools() -> tuple[dict[str, dict], dict[str, object]]:
        async with Client(server.mcp) as client:
            result = await client.list_tools()
            return (
                {tool.name: tool.input_schema for tool in result.tools},
                {tool.name: tool.annotations for tool in result.tools},
            )

    schemas, annotations = asyncio.run(_list_tools())
    assert set(schemas) == set(EXPECTED_TOOLS)
    local_state_tools = set(server_module.DIAGNOSTIC_TOOLS)
    for tool_name in EXPECTED_TOOLS:
        assert schemas[tool_name].get("additionalProperties") is False
        annotation = annotations[tool_name]
        assert annotation is not None
        assert annotation.read_only_hint is (tool_name not in local_state_tools)
        assert annotation.destructive_hint is False
        assert annotation.idempotent_hint is (tool_name not in set(server_module.DIAGNOSTIC_TOOLS))
        assert annotation.open_world_hint is False
    for tool_name in set(server_module.LIVE_TOOLS) - {
        "create_ha_diagnostic_baseline",
        "compare_ha_diagnostic_baseline",
    }:
        assert schemas[tool_name].get("properties") == {}
        assert schemas[tool_name].get("required", []) == []
    for tool_name in (
        "create_ha_diagnostic_baseline",
        "compare_ha_diagnostic_baseline",
    ):
        assert set(schemas[tool_name].get("properties", {})) == {"baseline_id"}
        assert schemas[tool_name].get("required") == ["baseline_id"]
    assert set(schemas).isdisjoint(server_module.LAB_ADMIN_TOOLS)
    assert environment_loads == 0


def test_lab_simulated_profile_registers_exact_lab_surface_without_credentials(
    monkeypatch,
) -> None:
    def _unexpected_environment_load() -> EnvironmentLoadReport:
        raise AssertionError("Listing LAB tools must not load credentials.")

    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        _unexpected_environment_load,
    )
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.LAB_SIMULATED
    )

    async def _list_tools() -> dict[str, dict]:
        async with Client(server.mcp) as client:
            result = await client.list_tools()
        return {tool.name: tool.input_schema for tool in result.tools}

    schemas = asyncio.run(_list_tools())
    assert set(schemas) == set(LAB_EXPECTED_TOOLS)
    assert len(schemas) == 34
    assert set(server_module.LAB_ADMIN_PREVIEW_TOOLS) == {
        "preview_v31_lab_public_folder",
        "preview_v31_lab_target",
        "preview_v31_lab_secret_metadata",
        "preview_v31_lab_local_user",
        "preview_v31_lab_folder_access_assignment",
    }
    expected_lab_preview_schemas = {
        "preview_v31_lab_public_folder": {
            "folder_ref",
            "parent_folder_ref",
            "folder_type",
            "folder_permission",
            "vault_permission",
            "allowed_launcher_type",
            "vault_policy_ref",
            "user_permission",
            "group_permission",
        },
        "preview_v31_lab_target": {
            "target_ref",
            "target_class",
            "template_ref",
            "address_ref",
            "gateway_ref",
        },
        "preview_v31_lab_secret_metadata": {
            "secret_ref",
            "name_ref",
            "folder_ref",
            "template_ref",
            "target_ref",
            "field_desc_ref",
        },
        "preview_v31_lab_local_user": {
            "user_ref",
            "name_ref",
            "status",
            "access_profile_ref",
            "display_name_ref",
            "comments_ref",
            "schedule_ref",
            "two_factor",
        },
        "preview_v31_lab_folder_access_assignment": {
            "assignment_ref",
            "folder_ref",
            "subject_ref",
            "folder_permission",
            "vault_permission",
            "allowed_launcher_type",
        },
    }
    for tool_name, expected_properties in expected_lab_preview_schemas.items():
        assert set(schemas[tool_name].get("properties", {})) == expected_properties
        expected_required = (
            expected_properties - {"vault_policy_ref", "user_permission", "group_permission"}
            if tool_name == "preview_v31_lab_public_folder"
            else expected_properties
        )
        assert sorted(schemas[tool_name].get("required", [])) == sorted(expected_required)
    assert set(schemas[server_module.LAB_ADMIN_EXECUTE_TOOL].get("properties", {})) == {
        "confirmation_token",
        "confirmation_digest",
        "idempotency_key",
    }
    assert schemas[server_module.LAB_ADMIN_EXECUTE_TOOL].get("required") == [
        "confirmation_token",
        "confirmation_digest",
        "idempotency_key",
    ]


def test_live_tool_rejects_unknown_input_before_loading_credentials(monkeypatch) -> None:
    def _unexpected_environment_load() -> EnvironmentLoadReport:
        raise AssertionError("Rejected tool input must not load credentials.")

    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        _unexpected_environment_load,
    )
    server = server_module.FortiPamMcpServer()

    async def _call_tool() -> tuple[bool, str]:
        async with Client(server.mcp) as client:
            result = await client.call_tool(
                "get_system_status_summary",
                {"path": "/not-authorized-negative-test"},
            )
        return result.is_error, repr(result)

    rejected, response = asyncio.run(_call_tool())
    assert rejected is True
    assert "Tool arguments are invalid." in response
    assert "input_value" not in response
    assert "/not-authorized-negative-test" not in response


def test_tool_validation_runs_once_and_sanitizes_declared_validation_failure() -> None:
    validated_values: list[object] = []

    def _record_validation(value: object) -> object:
        validated_values.append(value)
        return value

    mcp = server_module.MCP_SERVER_CLASS("safe-validation-test")

    async def parse_count(
        value: int,
    ) -> dict[str, int]:
        return {"value": value}

    parse_count.__annotations__["value"] = Annotated[
        int,
        BeforeValidator(_record_validation),
    ]
    mcp.tool()(parse_count)
    server_module._harden_mcp_input_validation(mcp)

    async def _call_tools() -> tuple[dict[str, object], bool, str]:
        async with Client(mcp) as client:
            accepted = await client.call_tool("parse_count", {"value": "7"})
            rejected = await client.call_tool(
                "parse_count",
                {"value": "protected-marker-not-returned"},
            )
        return (
            accepted.structured_content,
            bool(rejected.is_error),
            repr(rejected),
        )

    accepted, rejected, response = asyncio.run(_call_tools())
    assert accepted == {"value": 7}
    assert rejected is True
    assert validated_values == ["7", "protected-marker-not-returned"]
    assert "Tool arguments are invalid." in response
    assert "protected-marker-not-returned" not in response
    assert "input_value" not in response


def test_prompt_validation_sanitizes_declared_failure_before_logging(
    caplog: pytest.LogCaptureFixture,
) -> None:
    mcp = server_module.MCP_SERVER_CLASS("safe-prompt-validation-test")

    @mcp.tool()
    async def health() -> dict[str, bool]:
        return {"ok": True}

    @mcp.prompt()
    def render_count(count: int = 1) -> str:
        return f"Count category: {count > 0}"

    server_module._harden_mcp_input_validation(mcp)

    async def _call_prompts() -> str:
        async with Client(mcp) as client:
            accepted = await client.get_prompt(
                "render_count",
                arguments={"count": "2"},
            )
            assert accepted.messages
            with pytest.raises(MCPError) as rejected:
                await client.get_prompt(
                    "render_count",
                    arguments={"count": "protected-prompt-marker"},
                )
        return str(rejected.value)

    response = asyncio.run(_call_prompts())
    assert "protected-prompt-marker" not in response
    assert "input_value" not in response
    assert "protected-prompt-marker" not in caplog.text
    assert "input_value" not in caplog.text


def test_cli_tools_are_no_input_and_dispatch_only_to_fixed_methods(monkeypatch) -> None:
    def _unexpected_environment_load() -> EnvironmentLoadReport:
        raise AssertionError("Injected CLI tools must not reload credentials.")

    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        _unexpected_environment_load,
    )
    server = server_module.FortiPamMcpServer()

    class _FixedCliTools:
        async def get_ha_configuration_summary(self) -> dict[str, object]:
            return {"workflow_id": "ha_configuration", "raw_cli_returned": False}

        async def get_ha_status_summary(self) -> dict[str, object]:
            return {"workflow_id": "ha_status", "raw_cli_returned": False}

        async def get_ha_checksum_summary(self) -> dict[str, object]:
            return {"workflow_id": "ha_checksum", "raw_cli_returned": False}

    server._cli_tools = _FixedCliTools()  # type: ignore[assignment]

    async def _call_tools() -> list[dict]:
        async with Client(server.mcp) as client:
            results = []
            for name in server_module.CLI_TOOLS:
                result = await client.call_tool(name, {})
                results.append(result.structured_content)
            rejected = await client.call_tool(
                "get_cli_ha_configuration_summary", {"command": "show full-configuration"}
            )
            assert rejected.is_error is True
        return results

    results = asyncio.run(_call_tools())
    assert [result["workflow_id"] for result in results] == [
        "ha_configuration",
        "ha_status",
        "ha_checksum",
    ]
    assert all(result["raw_cli_returned"] is False for result in results)


def test_server_info_distinguishes_live_tools_from_fixed_routes(monkeypatch) -> None:
    def _unexpected_environment_load() -> EnvironmentLoadReport:
        raise AssertionError("Server metadata must not load credentials.")

    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        _unexpected_environment_load,
    )
    server = server_module.FortiPamMcpServer()

    async def _call_tool() -> dict:
        async with Client(server.mcp) as client:
            result = await client.call_tool("get_server_info", {})
        return result.structured_content

    info = asyncio.run(_call_tool())

    assert info["version"] == __version__
    assert info["compiled_fortipam_route_count"] == 9
    assert info["compiled_cli_workflow_count"] == 3
    assert info["live_tools"] == list(server_module.LIVE_TOOLS)
    assert len(info["live_tools"]) == 16
    assert info["device_write_enabled"] is False
    assert info["runtime_profile"] == "readonly"
    assert info["lab_admin_enabled"] is False
    assert info["lab_admin_tool_count"] == 0
    assert info["credential_source_loaded"] is False


def test_v4_controlled_profile_registers_only_the_protected_folder_action(
    monkeypatch,
) -> None:
    class _Action:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append((authorization_ref, principal))
            return {
                "contract": "fortipam_v4_child_folder_execution_v1",
                "outcome": "succeeded",
                "verification": "verified",
                "compensation": "not_requested",
                "idempotent_replay": False,
                "credentials_returned": False,
                "raw_response_returned": False,
            }

    action = _Action()
    principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=action,
        v4_folder_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_folder_action_principal", lambda: principal)

    async def _exercise() -> tuple[set[str], dict[str, object], bool]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            result = await client.call_tool(
                "execute_confirmed_v4_child_folder",
                {"authorization_ref": "folder-authorization-ref-0001"},
            )
            rejected = await client.call_tool(
                "execute_confirmed_v4_child_folder",
                {
                    "authorization_ref": "folder-authorization-ref-0001",
                    "name": "caller-controlled-name",
                },
            )
        return (
            {tool.name for tool in tools.tools},
            result.structured_content,
            bool(rejected.is_error),
        )

    tools, result, rejected = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS)
    assert result["outcome"] == "succeeded"
    assert action.calls == [("folder-authorization-ref-0001", principal)]
    assert rejected is True


def test_folder_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="exact feature opt-in"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="only by the v4-controlled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_PLAN_ONLY,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_folder_acl_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _FolderAclAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            folder_id: int,
            username: str,
            folder_permission: str,
            secret_permission: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert (folder_id, username, folder_permission, secret_permission) == (
                4,
                "mcp-folder-acl-user-01",
                "view",
                "view",
            )
            return {"preview_ref": "folder-acl-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "folder-acl-preview-00000001"
            return {"authorization_ref": "folder-acl-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "folder-acl-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    acl_action = _FolderAclAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_folder_acl_action=acl_action,
        v4_folder_acl_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_folder_acl_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_folder_user_acl_grant",
                {
                    "folder_id": 4,
                    "username": "mcp-folder-acl-user-01",
                    "folder_permission": "view",
                    "secret_permission": "view",
                },
            )
            confirmation = await client.call_tool(
                "confirm_v4_folder_user_acl_grant",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_folder_user_acl_grant",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | {
        "preview_v4_folder_user_acl_grant",
        "confirm_v4_folder_user_acl_grant",
        "execute_confirmed_v4_folder_user_acl_grant",
    }
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert acl_action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_folder_acl_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_folder_acl_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="only by the v4-controlled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_PLAN_ONLY,
            v4_folder_acl_action=object(),
            v4_folder_acl_action_enabled=True,
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_folder_acl_revoke_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _FolderAclRevokeAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            folder_id: int,
            username: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert (folder_id, username) == (4, "mcp-folder-acl-user-01")
            return {"preview_ref": "folder-acl-revoke-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "folder-acl-revoke-preview-00000001"
            return {"authorization_ref": "folder-acl-revoke-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "folder-acl-revoke-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    revoke_action = _FolderAclRevokeAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_folder_acl_revoke_action=revoke_action,
        v4_folder_acl_revoke_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_folder_acl_revoke_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_folder_user_acl_revoke",
                {"folder_id": 4, "username": "mcp-folder-acl-user-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_folder_user_acl_revoke",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_folder_user_acl_revoke",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | {
        "preview_v4_folder_user_acl_revoke",
        "confirm_v4_folder_user_acl_revoke",
        "execute_confirmed_v4_folder_user_acl_revoke",
    }
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert revoke_action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_folder_acl_revoke_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_folder_acl_revoke_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_folder_acl_revoke_action=object(),
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="only by the v4-controlled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_PLAN_ONLY,
            v4_folder_acl_revoke_action=object(),
            v4_folder_acl_revoke_action_enabled=True,
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_classification_tag_create_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _ClassificationTagAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            name: str,
            description: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert (name, description) == (
                "mcp-classification-tag-01",
                "MCP classification tag test",
            )
            return {"preview_ref": "classification-tag-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "classification-tag-preview-00000001"
            return {"authorization_ref": "classification-tag-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "classification-tag-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_delete(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview_delete", principal))
            return {"preview_ref": "classification-tag-delete-preview-00000001"}

        def confirm_delete(
            self,
            preview_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("confirm_delete", principal))
            assert preview_ref == "classification-tag-delete-preview-00000001"
            return {
                "authorization_ref": (
                    "classification-tag-delete-authorized-00000001"
                )
            }

        def execute_delete(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute_delete", principal))
            assert (
                authorization_ref
                == "classification-tag-delete-authorized-00000001"
            )
            return {"outcome": "succeeded", "verification": "verified"}

    tag_action = _ClassificationTagAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_classification_tag_action=tag_action,
        v4_classification_tag_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_classification_tag_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_classification_tag_create",
                {
                    "name": "mcp-classification-tag-01",
                    "description": "MCP classification tag test",
                },
            )
            confirmation = await client.call_tool(
                "confirm_v4_classification_tag_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_classification_tag_create",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
            delete_preview = await client.call_tool(
                "preview_v4_classification_tag_delete",
                {},
            )
            delete_confirmation = await client.call_tool(
                "confirm_v4_classification_tag_delete",
                {"preview_ref": delete_preview.structured_content["preview_ref"]},
            )
            await client.call_tool(
                "execute_confirmed_v4_classification_tag_delete",
                {
                    "authorization_ref": (
                        delete_confirmation.structured_content["authorization_ref"]
                    )
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | {
        "preview_v4_classification_tag_create",
        "confirm_v4_classification_tag_create",
        "execute_confirmed_v4_classification_tag_create",
        "preview_v4_classification_tag_delete",
        "confirm_v4_classification_tag_delete",
        "execute_confirmed_v4_classification_tag_delete",
    }
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert tag_action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_delete", planning_principal),
        ("confirm_delete", operating_principal),
        ("execute_delete", operating_principal),
    ]


def test_classification_tag_action_cannot_bypass_its_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_classification_tag_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_classification_tag_action=object(),
            v4_classification_tag_action_enabled=False,
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_ipv4_address_create_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _AddressAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            name: str,
            cidr: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert (name, cidr) == ("mcp-address-01", "198.51.100.10/32")
            return {"preview_ref": "address-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "address-preview-00000001"
            return {"authorization_ref": "address-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "address-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_delete(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview_delete", principal))
            return {"preview_ref": "address-delete-preview-00000001"}

        def confirm_delete(
            self,
            preview_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("confirm_delete", principal))
            assert preview_ref == "address-delete-preview-00000001"
            return {"authorization_ref": "address-delete-authorized-00000001"}

        def execute_delete(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute_delete", principal))
            assert authorization_ref == "address-delete-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _AddressAction()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_address_action=action,
        v4_address_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(
        server,
        "_v4_address_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_ipv4_address_create",
                {"name": "mcp-address-01", "cidr": "198.51.100.10/32"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_ipv4_address_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_ipv4_address_create",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
            delete_preview = await client.call_tool(
                "preview_v4_ipv4_address_delete",
                {},
            )
            delete_confirmation = await client.call_tool(
                "confirm_v4_ipv4_address_delete",
                {"preview_ref": delete_preview.structured_content["preview_ref"]},
            )
            delete_result = await client.call_tool(
                "execute_confirmed_v4_ipv4_address_delete",
                {
                    "authorization_ref": delete_confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return (
            {tool.name for tool in tools.tools},
            result.structured_content,
            delete_result.structured_content,
        )

    tools, result, delete_result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | {
        "preview_v4_ipv4_address_create",
        "confirm_v4_ipv4_address_create",
        "execute_confirmed_v4_ipv4_address_create",
        "preview_v4_ipv4_address_delete",
        "confirm_v4_ipv4_address_delete",
        "execute_confirmed_v4_ipv4_address_delete",
    }
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert delete_result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", operating_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_delete", operating_principal),
        ("confirm_delete", operating_principal),
        ("execute_delete", operating_principal),
    ]


def test_address_action_cannot_bypass_its_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_address_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_address_action=object(),
            v4_address_action_enabled=False,
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_address_group_create_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _AddressGroupAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            group_name: str,
            member_name: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert (group_name, member_name) == (
                "mcp-address-group-01",
                "mcp-address-01",
            )
            return {"preview_ref": "address-group-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "address-group-preview-00000001"
            return {"authorization_ref": "address-group-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "address-group-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _AddressGroupAction()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_address_group_action=action,
        v4_address_group_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(
        server,
        "_v4_address_group_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_address_group_create",
                {
                    "group_name": "mcp-address-group-01",
                    "member_name": "mcp-address-01",
                },
            )
            confirmation = await client.call_tool(
                "confirm_v4_address_group_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_address_group_create",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | {
        "preview_v4_address_group_create",
        "confirm_v4_address_group_create",
        "execute_confirmed_v4_address_group_create",
        "preview_v4_address_group_delete",
        "confirm_v4_address_group_delete",
        "execute_confirmed_v4_address_group_delete",
    }
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", operating_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_v4_controlled_profile_exposes_fixed_address_group_delete_without_selector(
    monkeypatch,
) -> None:
    class _FolderAction:
        pass

    class _AddressGroupAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview_delete(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview_delete", principal))
            return {"preview_ref": "address-group-delete-preview-1"}

        def confirm_delete(
            self,
            preview_ref: str,
            principal: object,
        ) -> dict[str, object]:
            assert preview_ref == "address-group-delete-preview-1"
            self.calls.append(("confirm_delete", principal))
            return {"authorization_ref": "address-group-delete-authorized-1"}

        def execute_delete(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            assert authorization_ref == "address-group-delete-authorized-1"
            self.calls.append(("execute_delete", principal))
            return {"outcome": "succeeded", "verification": "verified"}

    action = _AddressGroupAction()
    principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_address_group_action=action,
        v4_address_group_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(
        server,
        "_v4_address_group_action_principal",
        lambda: principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool("preview_v4_address_group_delete", {})
            confirmation = await client.call_tool(
                "confirm_v4_address_group_delete",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_address_group_delete",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert V4_ADDRESS_GROUP_CAPABILITY_TOOLS <= tools
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview_delete", principal),
        ("confirm_delete", principal),
        ("execute_delete", principal),
    ]


def test_address_group_action_cannot_bypass_its_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_address_group_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_address_group_action=object(),
            v4_address_group_action_enabled=False,
            v4_http_oauth=True,
        )


def test_v4_plan_only_profile_exposes_fixed_ztna_diagnostic_when_bound() -> None:
    class _ZtnaDiagnostic:
        def __init__(self) -> None:
            self.calls = 0

        def collect(self) -> dict[str, object]:
            self.calls += 1
            return {
                "execution_status": "succeeded",
                "first_failed_gate": "wad_device_context_absent",
                "raw_cli_returned": False,
            }

    diagnostic = _ZtnaDiagnostic()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_PLAN_ONLY,
        v4_ztna_device_context_diagnostic=diagnostic,
        v4_ztna_device_context_diagnostic_enabled=True,
        v4_http_oauth=True,
    )

    async def _exercise() -> tuple[dict[str, dict], dict[str, object], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            result = await client.call_tool("get_v4_ztna_device_context_diagnostic", {})
            matrix = await client.call_tool("get_capability_matrix", {})
        return (
            {tool.name: tool.input_schema for tool in tools.tools},
            result.structured_content,
            matrix.structured_content,
        )

    schemas, result, matrix = asyncio.run(_exercise())
    assert set(schemas) == set(V4_EXPECTED_TOOLS) | {
        "get_v4_ztna_device_context_diagnostic"
    }
    schema = schemas["get_v4_ztna_device_context_diagnostic"]
    assert schema.get("properties") == {}
    assert schema.get("required", []) == []
    assert schema.get("additionalProperties") is False
    assert result == {
        "execution_status": "succeeded",
        "first_failed_gate": "wad_device_context_absent",
        "raw_cli_returned": False,
    }
    assert diagnostic.calls == 1
    assert {
        tool["tool_name"] for tool in matrix["tools"]  # type: ignore[index]
    } == (
        set(V4_EXPECTED_TOOLS)
        | {
            "get_v4_ztna_device_context_diagnostic",
            "get_v4_ztna_folder_control_posture",
        }
        | V4_NONDEFAULT_CAPABILITY_TOOLS
    )


def test_v4_plan_only_exposes_bound_secret_request_observation(monkeypatch) -> None:
    class _Observation:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def observe(
            self,
            request_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append((request_ref, principal))
            return {
                "contract": "fortipam-v4-secret-request-observation-v1",
                "request_exists": True,
                "request_type": "launcher",
                "lifecycle_state": "pending",
                "approval_progress": "tier1",
                "action_status": "needed",
                "raw_values_returned": False,
            }

    observation = _Observation()
    principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_PLAN_ONLY,
        v4_secret_request_observation=observation,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: principal)

    async def _exercise() -> tuple[dict[str, dict], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            result = await client.call_tool(
                "observe_v4_bound_secret_request",
                {"request_ref": "opaque-request-reference01"},
            )
        return (
            {tool.name: tool.input_schema for tool in tools.tools},
            result.structured_content,
        )

    schemas, result = asyncio.run(_exercise())

    assert set(schemas) == set(V4_EXPECTED_TOOLS) | {
        "observe_v4_bound_secret_request"
    }
    assert set(
        schemas["observe_v4_bound_secret_request"].get("properties", {})
    ) == {"request_ref"}
    assert result["lifecycle_state"] == "pending"
    assert result["raw_values_returned"] is False
    assert observation.calls == [("opaque-request-reference01", principal)]


def test_secret_request_observation_is_v4_http_only() -> None:
    with pytest.raises(RuntimeError, match="only by a V4 HTTP profile"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.READONLY,
            v4_secret_request_observation=object(),
        )


def test_v4_secret_request_create_registration_is_explicit_and_bound(
    monkeypatch,
) -> None:
    class _Action:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def execute(
            self,
            intent_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append((intent_ref, principal))
            return {
                "contract": "fortipam-v4-secret-request-create-result-v1",
                "outcome": "bound",
                "request_bound": True,
                "reconciliation_required": False,
                "raw_values_returned": False,
                "request_identifiers_returned": False,
                "request_intent_returned": False,
            }

    action = _Action()
    principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_secret_request_create_action=action,
        v4_secret_request_create_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(
        server,
        "_v4_secret_request_create_principal",
        lambda: principal,
    )

    async def _exercise() -> tuple[dict[str, dict], dict[str, object], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            result = await client.call_tool(
                "create_v4_bound_secret_request",
                {"intent_ref": "opaque-request-intent-reference01"},
            )
            info = await client.call_tool("get_server_info", {})
        return (
            {tool.name: tool.input_schema for tool in tools.tools},
            result.structured_content,
            info.structured_content,
        )

    schemas, result, info = asyncio.run(_exercise())
    assert set(schemas) == set(V4_CONTROLLED_EXPECTED_TOOLS) | {
        "create_v4_bound_secret_request"
    }
    assert set(schemas["create_v4_bound_secret_request"].get("properties", {})) == {
        "intent_ref"
    }
    assert result["request_bound"] is True
    assert result["request_identifiers_returned"] is False
    assert action.calls == [("opaque-request-intent-reference01", principal)]
    assert info["v4_secret_request_create_bound"] is True
    assert info["v4_secret_request_create_tool_count"] == 1

    with pytest.raises(RuntimeError, match="requires its exact action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_secret_request_create_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_secret_request_create_action=object(),
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="only by the v4-controlled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_PLAN_ONLY,
            v4_secret_request_create_action=object(),
            v4_secret_request_create_enabled=True,
            v4_http_oauth=True,
        )


def test_ztna_diagnostic_cannot_bypass_its_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound diagnostic host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_PLAN_ONLY,
            v4_ztna_device_context_diagnostic_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_PLAN_ONLY,
            v4_ztna_device_context_diagnostic=object(),
            v4_ztna_device_context_diagnostic_enabled=False,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="only by a V4 HTTP profile"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.READONLY,
            v4_ztna_device_context_diagnostic=object(),
            v4_ztna_device_context_diagnostic_enabled=True,
        )


def test_v4_plan_only_profile_exposes_folder_ztna_posture_when_bound() -> None:
    class _FolderPosture:
        def __init__(self) -> None:
            self.calls = 0

        def collect(self) -> dict[str, object]:
            self.calls += 1
            return {
                "execution_status": "succeeded",
                "folder_ztna_control": "inherits_parent",
                "tag_value_returned": False,
            }

    posture = _FolderPosture()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_PLAN_ONLY,
        v4_ztna_folder_posture=posture,
        v4_ztna_folder_posture_enabled=True,
        v4_http_oauth=True,
    )

    async def _exercise() -> tuple[dict[str, dict], dict[str, object], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            result = await client.call_tool("get_v4_ztna_folder_control_posture", {})
            matrix = await client.call_tool("get_capability_matrix", {})
        return (
            {tool.name: tool.input_schema for tool in tools.tools},
            result.structured_content,
            matrix.structured_content,
        )

    schemas, result, matrix = asyncio.run(_exercise())
    assert set(schemas) == set(V4_EXPECTED_TOOLS) | {
        "get_v4_ztna_folder_control_posture"
    }
    schema = schemas["get_v4_ztna_folder_control_posture"]
    assert schema.get("properties") == {}
    assert schema.get("required", []) == []
    assert schema.get("additionalProperties") is False
    assert result == {
        "execution_status": "succeeded",
        "folder_ztna_control": "inherits_parent",
        "tag_value_returned": False,
    }
    assert posture.calls == 1
    assert {
        tool["tool_name"] for tool in matrix["tools"]  # type: ignore[index]
    } == (
        set(V4_EXPECTED_TOOLS)
        | {
            "get_v4_ztna_device_context_diagnostic",
            "get_v4_ztna_folder_control_posture",
        }
        | V4_NONDEFAULT_CAPABILITY_TOOLS
    )


def test_ztna_folder_posture_cannot_bypass_its_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound diagnostic host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_PLAN_ONLY,
            v4_ztna_folder_posture_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_PLAN_ONLY,
            v4_ztna_folder_posture=object(),
            v4_ztna_folder_posture_enabled=False,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="only by a V4 HTTP profile"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.READONLY,
            v4_ztna_folder_posture=object(),
            v4_ztna_folder_posture_enabled=True,
        )


def test_v4_controlled_profile_exposes_public_child_folder_rename_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _FolderRenameAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            folder_id: int,
            new_name: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert (folder_id, new_name) == (4, "mcp-renamed-folder-01")
            return {"preview_ref": "folder-rename-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "folder-rename-preview-00000001"
            return {"authorization_ref": "folder-rename-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "folder-rename-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    rename_action = _FolderRenameAction()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_folder_rename_action=rename_action,
        v4_folder_rename_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(
        server,
        "_v4_folder_rename_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_public_child_folder_rename",
                {"folder_id": 4, "new_name": "mcp-renamed-folder-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_public_child_folder_rename",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_public_child_folder_rename",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert {
        "preview_v4_public_child_folder_rename",
        "confirm_v4_public_child_folder_rename",
        "execute_confirmed_v4_public_child_folder_rename",
    } <= tools
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert rename_action.calls == [
        ("preview", operating_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_folder_rename_action_cannot_bypass_its_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_folder_rename_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_folder_rename_action=object(),
            v4_folder_rename_action_enabled=False,
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_empty_folder_archive_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _FolderArchiveAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, folder_id: int, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert folder_id == 4
            return {"preview_ref": "folder-archive-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "folder-archive-preview-00000001"
            return {"authorization_ref": "folder-archive-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "folder-archive-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    archive_action = _FolderArchiveAction()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_folder_archive_action=archive_action,
        v4_folder_archive_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(
        server,
        "_v4_folder_archive_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_empty_public_child_folder_archive",
                {"folder_id": 4},
            )
            confirmation = await client.call_tool(
                "confirm_v4_empty_public_child_folder_archive",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_empty_public_child_folder_archive",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert {
        "preview_v4_empty_public_child_folder_archive",
        "confirm_v4_empty_public_child_folder_archive",
        "execute_confirmed_v4_empty_public_child_folder_archive",
    } <= tools
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert archive_action.calls == [
        ("preview", operating_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_folder_archive_action_cannot_bypass_its_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_folder_archive_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_folder_archive_action=object(),
            v4_folder_archive_action_enabled=False,
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_folder_policy_assignment_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _FolderPolicyAssignAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            folder_id: int,
            policy_name: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert (folder_id, policy_name) == (4, "mcp-policy-01")
            return {"preview_ref": "folder-policy-assign-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "folder-policy-assign-preview-00000001"
            return {"authorization_ref": "folder-policy-assign-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "folder-policy-assign-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _FolderPolicyAssignAction()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_folder_policy_assign_action=action,
        v4_folder_policy_assign_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(
        server,
        "_v4_folder_policy_assign_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_public_child_folder_policy_assign",
                {"folder_id": 4, "policy_name": "mcp-policy-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_public_child_folder_policy_assign",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_public_child_folder_policy_assign",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert {
        "preview_v4_public_child_folder_policy_assign",
        "confirm_v4_public_child_folder_policy_assign",
        "execute_confirmed_v4_public_child_folder_policy_assign",
    } <= tools
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", operating_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_folder_policy_assignment_cannot_bypass_its_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_folder_policy_assign_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_folder_policy_assign_action=object(),
            v4_folder_policy_assign_action_enabled=False,
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_folder_policy_detach_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _FolderPolicyDetachAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, folder_id: int, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert folder_id == 4
            return {"preview_ref": "folder-policy-detach-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "folder-policy-detach-preview-00000001"
            return {"authorization_ref": "folder-policy-detach-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "folder-policy-detach-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _FolderPolicyDetachAction()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_folder_policy_detach_action=action,
        v4_folder_policy_detach_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(
        server,
        "_v4_folder_policy_detach_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_public_child_folder_policy_detach",
                {"folder_id": 4},
            )
            confirmation = await client.call_tool(
                "confirm_v4_public_child_folder_policy_detach",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_public_child_folder_policy_detach",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert {
        "preview_v4_public_child_folder_policy_detach",
        "confirm_v4_public_child_folder_policy_detach",
        "execute_confirmed_v4_public_child_folder_policy_detach",
    } <= tools
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", operating_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_folder_policy_detach_cannot_bypass_its_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_folder_policy_detach_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_folder_policy_detach_action=object(),
            v4_folder_policy_detach_action_enabled=False,
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_target_only_when_its_feature_is_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _TargetAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            target_name: str,
            address: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert target_name == "mcp-target-01"
            assert address == "192.0.2.10"
            return {"preview_ref": "target-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "target-preview-00000001"
            return {"authorization_ref": "target-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "target-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_delete(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview_delete", principal))
            return {"preview_ref": "target-delete-preview-00000001"}

        def confirm_delete(
            self,
            preview_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("confirm_delete", principal))
            assert preview_ref == "target-delete-preview-00000001"
            return {"authorization_ref": "target-delete-authorized-00000001"}

        def execute_delete(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute_delete", principal))
            assert authorization_ref == "target-delete-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    target_action = _TargetAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_target_action=target_action,
        v4_target_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(server, "_v4_target_action_principal", lambda: operating_principal)

    async def _exercise() -> tuple[
        set[str],
        dict[str, object],
        dict[str, object],
    ]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_ssh_target_create",
                {"target_name": "mcp-target-01", "address": "192.0.2.10"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_ssh_target_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_ssh_target",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
            delete_preview = await client.call_tool(
                "preview_v4_ssh_target_delete",
                {},
            )
            delete_confirmation = await client.call_tool(
                "confirm_v4_ssh_target_delete",
                {"preview_ref": delete_preview.structured_content["preview_ref"]},
            )
            delete_result = await client.call_tool(
                "execute_confirmed_v4_ssh_target_delete",
                {
                    "authorization_ref": (
                        delete_confirmation.structured_content["authorization_ref"]
                    )
                },
            )
        return (
            {tool.name for tool in tools.tools},
            result.structured_content,
            delete_result.structured_content,
        )

    tools, result, delete_result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_TARGET_CREATE_CAPABILITY_TOOLS
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert delete_result == {"outcome": "succeeded", "verification": "verified"}
    assert target_action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_delete", planning_principal),
        ("confirm_delete", operating_principal),
        ("execute_delete", operating_principal),
    ]


def test_v4_controlled_profile_exposes_secret_metadata_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _SecretMetadataAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            folder_path: str,
            secret_name: str,
            template: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert folder_path == "Public/mcp-v4-folder-01"
            assert secret_name == "mcp-v4-secret-metadata-01"
            assert template == "windows"
            return {"preview_ref": "secret-metadata-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "secret-metadata-preview-00000001"
            return {"authorization_ref": "secret-metadata-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "secret-metadata-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _SecretMetadataAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_secret_metadata_action=action,
        v4_secret_metadata_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_secret_metadata_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object], set[str]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_secret_metadata_create",
                {
                    "folder_path": "Public/mcp-v4-folder-01",
                    "secret_name": "mcp-v4-secret-metadata-01",
                    "template": "windows",
                },
            )
            confirmation = await client.call_tool(
                "confirm_v4_secret_metadata_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_secret_metadata_create",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
            matrix = await client.call_tool("get_capability_matrix", {})
        return (
            {tool.name for tool in tools.tools},
            result.structured_content,
            {tool["tool_name"] for tool in matrix.structured_content["tools"]},
        )

    tools, result, matrix_tools = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_SECRET_METADATA_CAPABILITY_TOOLS
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert V4_SECRET_METADATA_CAPABILITY_TOOLS <= matrix_tools
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_secret_metadata_action_cannot_bypass_its_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_secret_metadata_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_secret_metadata_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_interface_web_proxy_action_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _InterfaceWebProxyAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            return {"preview_ref": "interface-web-proxy-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "interface-web-proxy-preview-00000001"
            return {"authorization_ref": "interface-web-proxy-authorized-00000001"}

        def execute(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "interface-web-proxy-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_rollback(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview_rollback", principal))
            return {"preview_ref": "interface-web-proxy-rollback-preview-00000001"}

        def confirm_rollback(
            self,
            preview_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("confirm_rollback", principal))
            assert preview_ref == "interface-web-proxy-rollback-preview-00000001"
            return {
                "authorization_ref": "interface-web-proxy-rollback-authorized-00000001"
            }

        def execute_rollback(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute_rollback", principal))
            assert (
                authorization_ref
                == "interface-web-proxy-rollback-authorized-00000001"
            )
            return {"outcome": "succeeded", "verification": "verified"}

    action = _InterfaceWebProxyAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_interface_web_proxy_action=action,
        v4_interface_web_proxy_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(
        server,
        "_v4_interface_web_proxy_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object], set[str]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_interface_explicit_web_proxy_enable",
                {},
            )
            confirmation = await client.call_tool(
                "confirm_v4_interface_explicit_web_proxy_enable",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_interface_explicit_web_proxy_enable",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
            rollback_preview = await client.call_tool(
                "preview_v4_interface_explicit_web_proxy_rollback",
                {},
            )
            rollback_confirmation = await client.call_tool(
                "confirm_v4_interface_explicit_web_proxy_rollback",
                {"preview_ref": rollback_preview.structured_content["preview_ref"]},
            )
            rollback_result = await client.call_tool(
                "execute_confirmed_v4_interface_explicit_web_proxy_rollback",
                {
                    "authorization_ref": rollback_confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
            assert rollback_result.structured_content == {
                "outcome": "succeeded",
                "verification": "verified",
            }
            matrix = await client.call_tool("get_capability_matrix", {})
        return (
            {tool.name for tool in tools.tools},
            result.structured_content,
            {tool["tool_name"] for tool in matrix.structured_content["tools"]},
        )

    tools, result, matrix_tools = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS)
        | V4_INTERFACE_WEB_PROXY_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert V4_INTERFACE_WEB_PROXY_CAPABILITY_TOOLS <= matrix_tools
    assert action.calls == [
        ("preview", operating_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_rollback", operating_principal),
        ("confirm_rollback", operating_principal),
        ("execute_rollback", operating_principal),
    ]


def test_interface_web_proxy_action_cannot_bypass_its_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_interface_web_proxy_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_interface_web_proxy_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_api_target_update_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _TargetUpdateAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            target_name: str,
            description: str | None,
            principal: object,
            configuration_profile: str,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert target_name == "mcp-target-web-01"
            assert description is None
            assert configuration_profile == "web_proxy_enable"
            return {"preview_ref": "target-web-proxy-enable-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "target-web-proxy-enable-preview-00000001"
            return {"authorization_ref": "target-web-proxy-enable-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "target-web-proxy-enable-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    target_update_action = _TargetUpdateAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_target_update_action=target_update_action,
        v4_target_update_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_target_update_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[
        set[str],
        dict[str, object],
        dict[str, object],
    ]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_target_update_description",
                {
                    "target_name": "mcp-target-web-01",
                    "configuration_profile": "web_proxy_enable",
                },
            )
            confirmation = await client.call_tool(
                "confirm_v4_target_update_description",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_target_update_description",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert {
        "preview_v4_target_update_description",
        "confirm_v4_target_update_description",
        "execute_confirmed_v4_target_update_description",
    } <= tools
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert target_update_action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_target_update_action_cannot_bypass_its_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_target_update_action=object(),
            v4_target_update_action_enabled=False,
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_classification_tag_assign_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        pass

    class _AssignmentAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            target_name: str,
            classification_tag_name: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert target_name == "mcp-v4-target-update-01"
            assert classification_tag_name == "mcp-v4-classification-tag-01"
            return {
                "preview_ref": "classification-tag-assign-preview-00000001"
            }

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "classification-tag-assign-preview-00000001"
            return {
                "authorization_ref": (
                    "classification-tag-assign-authorized-00000001"
                )
            }

        def execute(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert (
                authorization_ref
                == "classification-tag-assign-authorized-00000001"
            )
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_rollback(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview_rollback", principal))
            return {
                "preview_ref": (
                    "classification-tag-assign-rollback-preview-00000001"
                )
            }

        def confirm_rollback(
            self,
            preview_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("confirm_rollback", principal))
            assert (
                preview_ref
                == "classification-tag-assign-rollback-preview-00000001"
            )
            return {
                "authorization_ref": (
                    "classification-tag-assign-rollback-authorized-00000001"
                )
            }

        def execute_rollback(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute_rollback", principal))
            assert (
                authorization_ref
                == "classification-tag-assign-rollback-authorized-00000001"
            )
            return {"outcome": "succeeded", "verification": "verified"}

    action = _AssignmentAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_classification_tag_assign_action=action,
        v4_classification_tag_assign_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_classification_tag_assign_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_classification_tag_assign",
                {
                    "target_name": "mcp-v4-target-update-01",
                    "classification_tag_name": "mcp-v4-classification-tag-01",
                },
            )
            confirmation = await client.call_tool(
                "confirm_v4_classification_tag_assign",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_classification_tag_assign",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
            rollback_preview = await client.call_tool(
                "preview_v4_classification_tag_assign_rollback",
                {},
            )
            rollback_confirmation = await client.call_tool(
                "confirm_v4_classification_tag_assign_rollback",
                {
                    "preview_ref": rollback_preview.structured_content[
                        "preview_ref"
                    ]
                },
            )
            rollback_result = await client.call_tool(
                "execute_confirmed_v4_classification_tag_assign_rollback",
                {
                    "authorization_ref": rollback_confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return (
            {tool.name for tool in tools.tools},
            result.structured_content,
            rollback_result.structured_content,
        )

    tools, result, rollback_result = asyncio.run(_exercise())
    assert {
        "preview_v4_classification_tag_assign",
        "confirm_v4_classification_tag_assign",
        "execute_confirmed_v4_classification_tag_assign",
        "preview_v4_classification_tag_assign_rollback",
        "confirm_v4_classification_tag_assign_rollback",
        "execute_confirmed_v4_classification_tag_assign_rollback",
    } <= tools
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert rollback_result == {
        "outcome": "succeeded",
        "verification": "verified",
    }
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_rollback", planning_principal),
        ("confirm_rollback", operating_principal),
        ("execute_rollback", operating_principal),
    ]


def test_classification_tag_assign_cannot_bypass_its_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_classification_tag_assign_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_classification_tag_assign_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_certificate_csr_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _CertificateCsrAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            certificate_name: str,
            subject_ipv4: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert certificate_name == "mcp-v4-cert-b105"
            assert subject_ipv4 == "127.0.0.1"
            return {"preview_ref": "certificate-csr-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "certificate-csr-preview-00000001"
            return {"authorization_ref": "certificate-csr-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "certificate-csr-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _CertificateCsrAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_certificate_csr_action=action,
        v4_certificate_csr_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_certificate_csr_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_certificate_csr_generate",
                {
                    "certificate_name": "mcp-v4-cert-b105",
                    "subject_ipv4": "127.0.0.1",
                },
            )
            confirmation = await client.call_tool(
                "confirm_v4_certificate_csr_generate",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_certificate_csr_generate",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert V4_CERTIFICATE_CSR_CAPABILITY_TOOLS <= tools
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_certificate_csr_action_cannot_bypass_its_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_certificate_csr_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_certificate_csr_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_local_user_disable_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _LocalUserAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, username: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert username == "mcp-user-01"
            return {"preview_ref": "local-user-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "local-user-preview-00000001"
            return {"authorization_ref": "local-user-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "local-user-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    local_user_action = _LocalUserAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_local_user_disable_action=local_user_action,
        v4_local_user_disable_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_local_user_disable_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_local_user_disable",
                {"username": "mcp-user-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_local_user_disable",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_local_user_disable",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | {
        "preview_v4_local_user_disable",
        "confirm_v4_local_user_disable",
        "execute_confirmed_v4_local_user_disable",
    }
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert local_user_action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_local_user_disable_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_local_user_disable_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="only by the v4-controlled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_PLAN_ONLY,
            v4_local_user_disable_action=object(),
            v4_local_user_disable_action_enabled=True,
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_local_user_create_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _LocalUserCreateAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, username: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert username == "mcp-user-create-01"
            return {"preview_ref": "local-user-create-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "local-user-create-preview-00000001"
            return {"authorization_ref": "local-user-create-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "local-user-create-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    create_action = _LocalUserCreateAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_local_user_create_action=create_action,
        v4_local_user_create_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_local_user_create_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_local_user_create",
                {"username": "mcp-user-create-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_local_user_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_local_user_create",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | {
        "preview_v4_local_user_create",
        "confirm_v4_local_user_create",
        "execute_confirmed_v4_local_user_create",
    }
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert create_action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_local_user_create_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_local_user_create_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="only by the v4-controlled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_PLAN_ONLY,
            v4_local_user_create_action=object(),
            v4_local_user_create_action_enabled=True,
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_local_user_reset_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _LocalUserResetAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, username: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert username == "mcp-v4-user-01"
            return {"preview_ref": "local-user-reset-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "local-user-reset-preview-00000001"
            return {"authorization_ref": "local-user-reset-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "local-user-reset-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    reset_action = _LocalUserResetAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_local_user_reset_action=reset_action,
        v4_local_user_reset_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_local_user_reset_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_local_user_reset",
                {"username": "mcp-v4-user-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_local_user_reset",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_local_user_reset",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | {
        "preview_v4_local_user_reset",
        "confirm_v4_local_user_reset",
        "execute_confirmed_v4_local_user_reset",
    }
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert reset_action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_local_user_reset_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_local_user_reset_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="only by the v4-controlled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_PLAN_ONLY,
            v4_local_user_reset_action=object(),
            v4_local_user_reset_action_enabled=True,
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_role_create_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _RoleCreateAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, role_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert role_name == "mcp-v4-role-01"
            return {"preview_ref": "role-create-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "role-create-preview-00000001"
            return {"authorization_ref": "role-create-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "role-create-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    create_action = _RoleCreateAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_role_create_action=create_action,
        v4_role_create_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_role_create_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_role_create",
                {"role_name": "mcp-v4-role-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_role_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_role_create",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | {
        "preview_v4_role_create",
        "confirm_v4_role_create",
        "execute_confirmed_v4_role_create",
    }
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert create_action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_role_create_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_role_create_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_role_create_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_role_update_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _RoleUpdateAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, role_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert role_name == "mcp-v4-role-01"
            return {"preview_ref": "role-update-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "role-update-preview-00000001"
            return {"authorization_ref": "role-update-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "role-update-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    update_action = _RoleUpdateAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_role_update_action=update_action,
        v4_role_update_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_role_update_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_role_diagnostics_enable",
                {"role_name": "mcp-v4-role-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_role_diagnostics_enable",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_role_diagnostics_enable",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | {
        "preview_v4_role_diagnostics_enable",
        "confirm_v4_role_diagnostics_enable",
        "execute_confirmed_v4_role_diagnostics_enable",
    }
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert update_action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_role_update_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_role_update_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_role_update_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_role_assign_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _RoleAssignAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            username: str,
            role_name: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert username == "mcp-v4-user-01"
            assert role_name == "mcp-v4-role-01"
            return {"preview_ref": "role-assign-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "role-assign-preview-00000001"
            return {"authorization_ref": "role-assign-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "role-assign-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    assign_action = _RoleAssignAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_role_assign_action=assign_action,
        v4_role_assign_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_role_assign_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_role_assign",
                {"username": "mcp-v4-user-01", "role_name": "mcp-v4-role-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_role_assign",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_role_assign",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | {
        "preview_v4_role_assign",
        "confirm_v4_role_assign",
        "execute_confirmed_v4_role_assign",
    }
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert assign_action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_role_assign_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_role_assign_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_role_assign_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_dlp_file_pattern_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _DlpFilePatternAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            pattern_id: int,
            pattern_name: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert pattern_id == 1001
            assert pattern_name == "mcp-v4-dlp-pattern-01"
            return {"preview_ref": "dlp-file-pattern-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "dlp-file-pattern-preview-00000001"
            return {"authorization_ref": "dlp-file-pattern-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "dlp-file-pattern-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    dlp_action = _DlpFilePatternAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_dlp_file_pattern_action=dlp_action,
        v4_dlp_file_pattern_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_dlp_file_pattern_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_dlp_file_pattern_create",
                {"pattern_id": 1001, "pattern_name": "mcp-v4-dlp-pattern-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_dlp_file_pattern_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_dlp_file_pattern_create",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_DLP_FILE_PATTERN_CAPABILITY_TOOLS
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert dlp_action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_dlp_file_pattern_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_dlp_file_pattern_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_dlp_file_pattern_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_dlp_sensor_only_when_bound(monkeypatch) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _DlpSensorAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            sensor_name: str,
            file_pattern_id: int | None,
            file_pattern_name: str | None,
            principal: object,
            configuration_profile: str,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert sensor_name == "mcp-v4-dlp-regexp-sensor-01"
            assert configuration_profile == "regexp_sentinel"
            assert file_pattern_id is None
            assert file_pattern_name is None
            return {"preview_ref": "dlp-regexp-sensor-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "dlp-regexp-sensor-preview-00000001"
            return {"authorization_ref": "dlp-regexp-sensor-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "dlp-regexp-sensor-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    dlp_action = _DlpSensorAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_dlp_sensor_action=dlp_action,
        v4_dlp_sensor_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_dlp_sensor_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_dlp_sensor_create",
                {
                    "sensor_name": "mcp-v4-dlp-regexp-sensor-01",
                    "configuration_profile": "regexp_sentinel",
                },
            )
            confirmation = await client.call_tool(
                "confirm_v4_dlp_sensor_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_dlp_sensor_create",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_DLP_SENSOR_CAPABILITY_TOOLS
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert dlp_action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_dlp_sensor_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_dlp_sensor_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_dlp_sensor_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_antivirus_profile_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _AntivirusProfileAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, profile_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert profile_name == "mcp-v4-av-profile-01"
            return {"preview_ref": "antivirus-profile-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "antivirus-profile-preview-00000001"
            return {"authorization_ref": "antivirus-profile-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "antivirus-profile-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_delete(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview_delete", principal))
            return {"preview_ref": "antivirus-profile-delete-preview-00000001"}

        def confirm_delete(
            self,
            preview_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("confirm_delete", principal))
            assert preview_ref == "antivirus-profile-delete-preview-00000001"
            return {
                "authorization_ref": "antivirus-profile-delete-authorized-00000001"
            }

        def execute_delete(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute_delete", principal))
            assert authorization_ref == "antivirus-profile-delete-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _AntivirusProfileAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_antivirus_profile_action=action,
        v4_antivirus_profile_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_antivirus_profile_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[
        set[str],
        dict[str, object],
        dict[str, object],
    ]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_antivirus_profile_create",
                {"profile_name": "mcp-v4-av-profile-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_antivirus_profile_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_antivirus_profile_create",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
            delete_preview = await client.call_tool(
                "preview_v4_antivirus_profile_delete",
                {},
            )
            delete_confirmation = await client.call_tool(
                "confirm_v4_antivirus_profile_delete",
                {"preview_ref": delete_preview.structured_content["preview_ref"]},
            )
            delete_result = await client.call_tool(
                "execute_confirmed_v4_antivirus_profile_delete",
                {
                    "authorization_ref": delete_confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return (
            {tool.name for tool in tools.tools},
            result.structured_content,
            delete_result.structured_content,
        )

    tools, result, delete_result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS)
        | V4_ANTIVIRUS_PROFILE_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert delete_result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_delete", planning_principal),
        ("confirm_delete", operating_principal),
        ("execute_delete", operating_principal),
    ]


def test_antivirus_profile_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_antivirus_profile_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_antivirus_profile_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_can_register_profile_actions_together() -> None:
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_antivirus_profile_action=object(),
        v4_antivirus_profile_action_enabled=True,
        v4_rdp_event_filter_action=object(),
        v4_rdp_event_filter_action_enabled=True,
        v4_ssh_filter_action=object(),
        v4_ssh_filter_action_enabled=True,
        v4_http_oauth=True,
    )

    async def _list_tools() -> set[str]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
        return {tool.name for tool in tools.tools}

    assert asyncio.run(_list_tools()) == (
        set(V4_CONTROLLED_EXPECTED_TOOLS)
        | V4_ANTIVIRUS_PROFILE_CAPABILITY_TOOLS
        | V4_RDP_EVENT_FILTER_CAPABILITY_TOOLS
        | V4_SSH_FILTER_CAPABILITY_TOOLS
    )


def test_v4_controlled_profile_can_register_target_api_actions_together() -> None:
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_target_action=object(),
        v4_target_action_enabled=True,
        v4_target_update_action=object(),
        v4_target_update_action_enabled=True,
        v4_certificate_csr_action=object(),
        v4_certificate_csr_action_enabled=True,
        v4_classification_tag_assign_action=object(),
        v4_classification_tag_assign_action_enabled=True,
        v4_http_oauth=True,
    )

    async def _list_tools() -> set[str]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
        return {tool.name for tool in tools.tools}

    assert asyncio.run(_list_tools()) == (
        set(V4_CONTROLLED_EXPECTED_TOOLS)
        | V4_TARGET_CREATE_CAPABILITY_TOOLS
        | V4_TARGET_UPDATE_CAPABILITY_TOOLS
        | V4_CERTIFICATE_CSR_CAPABILITY_TOOLS
        | V4_CLASSIFICATION_TAG_ASSIGN_CAPABILITY_TOOLS
    )


def test_v4_controlled_profile_can_register_folder_api_actions_together() -> None:
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_acl_action=object(),
        v4_folder_acl_action_enabled=True,
        v4_folder_acl_revoke_action=object(),
        v4_folder_acl_revoke_action_enabled=True,
        v4_folder_rename_action=object(),
        v4_folder_rename_action_enabled=True,
        v4_folder_archive_action=object(),
        v4_folder_archive_action_enabled=True,
        v4_folder_policy_assign_action=object(),
        v4_folder_policy_assign_action_enabled=True,
        v4_folder_policy_detach_action=object(),
        v4_folder_policy_detach_action_enabled=True,
        v4_classification_tag_action=object(),
        v4_classification_tag_action_enabled=True,
        v4_http_oauth=True,
    )

    async def _list_tools() -> set[str]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
        return {tool.name for tool in tools.tools}

    assert asyncio.run(_list_tools()) == (
        set(V4_CONTROLLED_EXPECTED_TOOLS)
        | V4_FOLDER_ACL_GRANT_CAPABILITY_TOOLS
        | V4_FOLDER_ACL_REVOKE_CAPABILITY_TOOLS
        | V4_FOLDER_RENAME_CAPABILITY_TOOLS
        | V4_FOLDER_ARCHIVE_CAPABILITY_TOOLS
        | V4_FOLDER_POLICY_ASSIGN_CAPABILITY_TOOLS
        | V4_FOLDER_POLICY_DETACH_CAPABILITY_TOOLS
        | V4_CLASSIFICATION_TAG_CREATE_CAPABILITY_TOOLS
    )


def test_v4_controlled_profile_can_register_central_rest_actions_together() -> None:
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_character_set_action=object(),
        v4_character_set_action_enabled=True,
        v4_windows_app_filter_action=object(),
        v4_windows_app_filter_action_enabled=True,
        v4_recording_policy_action=object(),
        v4_recording_policy_action_enabled=True,
        v4_report_layout_action=object(),
        v4_report_layout_action_enabled=True,
        v4_http_oauth=True,
    )

    async def _list_tools() -> set[str]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
        return {tool.name for tool in tools.tools}

    assert asyncio.run(_list_tools()) == (
        set(V4_CONTROLLED_EXPECTED_TOOLS)
        | V4_CHARACTER_SET_CAPABILITY_TOOLS
        | V4_WINDOWS_APP_FILTER_CAPABILITY_TOOLS
        | V4_RECORDING_POLICY_CAPABILITY_TOOLS
        | V4_REPORT_LAYOUT_CAPABILITY_TOOLS
    )


def test_v4_controlled_profile_can_bind_current_unified_actions() -> None:
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=object(),
        v4_folder_action_enabled=True,
        v4_antivirus_profile_action=object(),
        v4_antivirus_profile_action_enabled=True,
        v4_rdp_event_filter_action=object(),
        v4_rdp_event_filter_action_enabled=True,
        v4_ssh_filter_action=object(),
        v4_ssh_filter_action_enabled=True,
        v4_target_action=object(),
        v4_target_action_enabled=True,
        v4_target_update_action=object(),
        v4_target_update_action_enabled=True,
        v4_certificate_csr_action=object(),
        v4_certificate_csr_action_enabled=True,
        v4_classification_tag_assign_action=object(),
        v4_classification_tag_assign_action_enabled=True,
        v4_folder_acl_action=object(),
        v4_folder_acl_action_enabled=True,
        v4_folder_acl_revoke_action=object(),
        v4_folder_acl_revoke_action_enabled=True,
        v4_folder_rename_action=object(),
        v4_folder_rename_action_enabled=True,
        v4_folder_archive_action=object(),
        v4_folder_archive_action_enabled=True,
        v4_folder_policy_assign_action=object(),
        v4_folder_policy_assign_action_enabled=True,
        v4_folder_policy_detach_action=object(),
        v4_folder_policy_detach_action_enabled=True,
        v4_classification_tag_action=object(),
        v4_classification_tag_action_enabled=True,
        v4_character_set_action=object(),
        v4_character_set_action_enabled=True,
        v4_windows_app_filter_action=object(),
        v4_windows_app_filter_action_enabled=True,
        v4_recording_policy_action=object(),
        v4_recording_policy_action_enabled=True,
        v4_password_policy_action=object(),
        v4_password_policy_action_enabled=True,
        v4_report_layout_action=object(),
        v4_report_layout_action_enabled=True,
        v4_address_action=object(),
        v4_address_action_enabled=True,
        v4_address_group_action=object(),
        v4_address_group_action_enabled=True,
        v4_automation_trigger_action=object(),
        v4_automation_trigger_action_enabled=True,
        v4_automation_action_action=object(),
        v4_automation_action_action_enabled=True,
        v4_automation_stitch_action=object(),
        v4_automation_stitch_action_enabled=True,
        v4_secret_gateway_action=object(),
        v4_secret_gateway_action_enabled=True,
        v4_client_integrity_action=object(),
        v4_client_integrity_action_enabled=True,
        v4_interface_web_proxy_action=object(),
        v4_interface_web_proxy_action_enabled=True,
        v4_ztna_access_proxy_action=object(),
        v4_ztna_access_proxy_action_enabled=True,
        v4_ztna_wad_debug_action=object(),
        v4_ztna_wad_debug_action_enabled=True,
        v4_ztna_folder_posture=object(),
        v4_ztna_folder_posture_enabled=True,
        v4_dependency_updater_action=object(),
        v4_dependency_updater_action_enabled=True,
        v4_template_action=object(),
        v4_template_action_enabled=True,
        v4_template_archive_action=object(),
        v4_template_archive_action_enabled=True,
        v4_fortianalyzer_action=object(),
        v4_fortianalyzer_action_enabled=True,
        v4_logging_disk_action=object(),
        v4_logging_disk_action_enabled=True,
        v4_secret_audit_action=object(),
        v4_secret_audit_action_enabled=True,
        v4_active_launch_action=object(),
        v4_active_launch_action_enabled=True,
        v4_dlp_file_pattern_action=object(),
        v4_dlp_file_pattern_action_enabled=True,
        v4_dlp_sensor_action=object(),
        v4_dlp_sensor_action_enabled=True,
        v4_secret_policy_action=object(),
        v4_secret_policy_action_enabled=True,
        v4_launcher_action=object(),
        v4_launcher_action_enabled=True,
        v4_launcher_update_action=object(),
        v4_launcher_update_action_enabled=True,
        v4_launcher_matcher_action=object(),
        v4_launcher_matcher_action_enabled=True,
        v4_approval_profile_action=object(),
        v4_approval_profile_action_enabled=True,
        v4_approval_profile_update_action=object(),
        v4_approval_profile_update_action_enabled=True,
        v4_approval_email_template_action=object(),
        v4_approval_email_template_action_enabled=True,
        v4_approval_email_template_update_action=object(),
        v4_approval_email_template_update_action_enabled=True,
        v4_snmp_agent_action=object(),
        v4_snmp_agent_action_enabled=True,
        v4_maintenance_mode_action=object(),
        v4_maintenance_mode_action_enabled=True,
        v4_user_group_action=object(),
        v4_user_group_action_enabled=True,
        v4_user_group_membership_action=object(),
        v4_user_group_membership_action_enabled=True,
        v4_apl_action=object(),
        v4_apl_action_enabled=True,
        v4_apl_disable_action=object(),
        v4_apl_disable_action_enabled=True,
        v4_schedule_action=object(),
        v4_schedule_action_enabled=True,
        v4_schedule_assign_action=object(),
        v4_schedule_assign_action_enabled=True,
        v4_local_user_disable_action=object(),
        v4_local_user_disable_action_enabled=True,
        v4_local_user_create_action=object(),
        v4_local_user_create_action_enabled=True,
        v4_local_user_reset_action=object(),
        v4_local_user_reset_action_enabled=True,
        v4_role_create_action=object(),
        v4_role_create_action_enabled=True,
        v4_role_update_action=object(),
        v4_role_update_action_enabled=True,
        v4_role_assign_action=object(),
        v4_role_assign_action_enabled=True,
        v4_http_oauth=True,
    )

    async def _inspect() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            info = await client.call_tool("get_server_info", {})
        return {tool.name for tool in tools.tools}, info.structured_content

    tools, info = asyncio.run(_inspect())
    assert len(tools) == 363
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS)
        | V4_ANTIVIRUS_PROFILE_CAPABILITY_TOOLS
        | V4_RDP_EVENT_FILTER_CAPABILITY_TOOLS
        | V4_SSH_FILTER_CAPABILITY_TOOLS
        | V4_TARGET_CREATE_CAPABILITY_TOOLS
        | V4_TARGET_UPDATE_CAPABILITY_TOOLS
        | V4_CERTIFICATE_CSR_CAPABILITY_TOOLS
        | V4_CLASSIFICATION_TAG_ASSIGN_CAPABILITY_TOOLS
        | V4_FOLDER_ACL_GRANT_CAPABILITY_TOOLS
        | V4_FOLDER_ACL_REVOKE_CAPABILITY_TOOLS
        | V4_FOLDER_RENAME_CAPABILITY_TOOLS
        | V4_FOLDER_ARCHIVE_CAPABILITY_TOOLS
        | V4_FOLDER_POLICY_ASSIGN_CAPABILITY_TOOLS
        | V4_FOLDER_POLICY_DETACH_CAPABILITY_TOOLS
        | V4_CLASSIFICATION_TAG_CREATE_CAPABILITY_TOOLS
        | V4_CHARACTER_SET_CAPABILITY_TOOLS
        | V4_WINDOWS_APP_FILTER_CAPABILITY_TOOLS
        | V4_RECORDING_POLICY_CAPABILITY_TOOLS
        | V4_PASSWORD_POLICY_CAPABILITY_TOOLS
        | V4_REPORT_LAYOUT_CAPABILITY_TOOLS
        | V4_ADDRESS_CAPABILITY_TOOLS
        | V4_ADDRESS_GROUP_CAPABILITY_TOOLS
        | V4_AUTOMATION_TRIGGER_CAPABILITY_TOOLS
        | V4_AUTOMATION_ACTION_CAPABILITY_TOOLS
        | V4_AUTOMATION_STITCH_CAPABILITY_TOOLS
        | V4_SECRET_GATEWAY_CAPABILITY_TOOLS
        | V4_CLIENT_INTEGRITY_CAPABILITY_TOOLS
        | V4_INTERFACE_WEB_PROXY_CAPABILITY_TOOLS
        | V4_ZTNA_ACCESS_PROXY_CAPABILITY_TOOLS
        | V4_ZTNA_WAD_DEBUG_CAPABILITY_TOOLS
        | V4_ZTNA_FOLDER_POSTURE_CAPABILITY_TOOLS
        | V4_DEPENDENCY_UPDATER_CAPABILITY_TOOLS
        | V4_TEMPLATE_CAPABILITY_TOOLS
        | V4_TEMPLATE_ARCHIVE_CAPABILITY_TOOLS
        | V4_FORTIANALYZER_CAPABILITY_TOOLS
        | V4_LOGGING_DISK_CAPABILITY_TOOLS
        | V4_SECRET_AUDIT_CAPABILITY_TOOLS
        | V4_ACTIVE_LAUNCH_CAPABILITY_TOOLS
        | V4_DLP_CAPABILITY_TOOLS
        | V4_SECRET_POLICY_CAPABILITY_TOOLS
        | V4_LAUNCHER_CAPABILITY_TOOLS
        | V4_LAUNCHER_UPDATE_CAPABILITY_TOOLS
        | V4_LAUNCHER_MATCHER_CAPABILITY_TOOLS
        | V4_APPROVAL_PROFILE_CAPABILITY_TOOLS
        | V4_APPROVAL_PROFILE_UPDATE_CAPABILITY_TOOLS
        | V4_APPROVAL_EMAIL_TEMPLATE_CAPABILITY_TOOLS
        | V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_CAPABILITY_TOOLS
        | V4_SNMP_AGENT_CAPABILITY_TOOLS
        | V4_MAINTENANCE_MODE_CAPABILITY_TOOLS
        | V4_USER_GROUP_CAPABILITY_TOOLS
        | V4_USER_GROUP_MEMBERSHIP_CAPABILITY_TOOLS
        | V4_APL_CAPABILITY_TOOLS
        | V4_APL_DISABLE_CAPABILITY_TOOLS
        | V4_SCHEDULE_CAPABILITY_TOOLS
        | V4_SCHEDULE_ASSIGN_CAPABILITY_TOOLS
        | V4_LOCAL_USER_DISABLE_CAPABILITY_TOOLS
        | V4_LOCAL_USER_CREATE_CAPABILITY_TOOLS
        | V4_LOCAL_USER_RESET_CAPABILITY_TOOLS
        | V4_ROLE_CREATE_CAPABILITY_TOOLS
        | V4_ROLE_UPDATE_CAPABILITY_TOOLS
        | V4_ROLE_ASSIGN_CAPABILITY_TOOLS
    )
    assert info["v4_folder_action_bound"] is True
    assert info["v4_certificate_csr_action_bound"] is True
    assert info["v4_folder_archive_action_bound"] is True
    assert info["v4_folder_policy_assign_action_bound"] is True
    assert info["v4_folder_policy_detach_action_bound"] is True
    assert info["v4_target_action_tool_count"] == 6
    assert info["v4_password_policy_action_bound"] is True
    assert info["v4_password_policy_action_tool_count"] == 6
    assert info["v4_report_layout_action_bound"] is True
    assert info["v4_report_layout_action_tool_count"] == 6
    assert info["v4_address_action_bound"] is True
    assert info["v4_address_action_tool_count"] == 6
    assert info["v4_address_group_action_bound"] is True
    assert info["v4_automation_trigger_action_bound"] is True
    assert info["v4_automation_action_action_bound"] is True
    assert info["v4_automation_stitch_action_bound"] is True
    assert info["v4_secret_gateway_action_bound"] is True
    assert info["v4_client_integrity_action_bound"] is True
    assert info["v4_interface_web_proxy_action_bound"] is True
    assert info["v4_interface_web_proxy_action_tool_count"] == 6
    assert info["v4_ztna_access_proxy_action_bound"] is True
    assert info["v4_ztna_access_proxy_action_tool_count"] == 6
    assert info["v4_ztna_wad_debug_action_bound"] is True
    assert info["v4_ztna_wad_debug_action_tool_count"] == 3
    assert info["v4_ztna_folder_posture_bound"] is True
    assert info["v4_ztna_folder_posture_tool_count"] == 1
    assert info["v4_dependency_updater_action_bound"] is True
    assert info["v4_template_action_bound"] is True
    assert info["v4_template_archive_action_bound"] is True
    assert info["v4_fortianalyzer_action_bound"] is True
    assert info["v4_logging_disk_action_bound"] is True
    assert info["v4_secret_audit_action_bound"] is True
    assert info["v4_active_launch_action_bound"] is True
    assert info["v4_active_launch_action_tool_count"] == 4
    assert info["v4_dlp_file_pattern_action_bound"] is True
    assert info["v4_dlp_sensor_action_bound"] is True
    assert info["v4_secret_policy_action_bound"] is True
    assert info["v4_launcher_action_bound"] is True
    assert info["v4_launcher_update_action_bound"] is True
    assert info["v4_launcher_matcher_action_bound"] is True
    assert info["v4_approval_profile_action_bound"] is True
    assert info["v4_approval_profile_update_action_bound"] is True
    assert info["v4_approval_email_template_action_bound"] is True
    assert info["v4_approval_email_template_update_action_bound"] is True
    assert info["v4_snmp_agent_action_bound"] is True
    assert info["v4_snmp_agent_action_tool_count"] == 6
    assert info["v4_maintenance_mode_action_bound"] is True
    assert info["v4_maintenance_mode_action_tool_count"] == 6
    assert info["v4_user_group_action_bound"] is True
    assert info["v4_user_group_membership_action_bound"] is True
    assert info["v4_auto_provision_rule_action_bound"] is True
    assert info["v4_auto_provision_rule_disable_action_bound"] is True
    assert info["v4_schedule_action_bound"] is True
    assert info["v4_schedule_assign_action_bound"] is True
    assert info["v4_local_user_disable_action_bound"] is True
    assert info["v4_local_user_create_action_bound"] is True
    assert info["v4_local_user_reset_action_bound"] is True
    assert info["v4_role_create_action_bound"] is True
    assert info["v4_role_update_action_bound"] is True
    assert info["v4_role_assign_action_bound"] is True


def test_v4_controlled_profile_exposes_rdp_event_filter_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _RdpEventFilterAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, profile_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert profile_name == "mcp-v4-rdp-event-filter-01"
            return {"preview_ref": "rdp-event-filter-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "rdp-event-filter-preview-00000001"
            return {"authorization_ref": "rdp-event-filter-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "rdp-event-filter-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_delete(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview_delete", principal))
            return {"preview_ref": "rdp-event-filter-delete-preview-00000001"}

        def confirm_delete(
            self,
            preview_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("confirm_delete", principal))
            assert preview_ref == "rdp-event-filter-delete-preview-00000001"
            return {
                "authorization_ref": "rdp-event-filter-delete-authorized-00000001"
            }

        def execute_delete(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute_delete", principal))
            assert authorization_ref == "rdp-event-filter-delete-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _RdpEventFilterAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_rdp_event_filter_action=action,
        v4_rdp_event_filter_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_rdp_event_filter_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[
        set[str], dict[str, object], dict[str, object]
    ]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_rdp_event_filter_create",
                {"profile_name": "mcp-v4-rdp-event-filter-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_rdp_event_filter_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_rdp_event_filter_create",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
            delete_preview = await client.call_tool(
                "preview_v4_rdp_event_filter_delete",
                {},
            )
            delete_confirmation = await client.call_tool(
                "confirm_v4_rdp_event_filter_delete",
                {"preview_ref": delete_preview.structured_content["preview_ref"]},
            )
            delete_result = await client.call_tool(
                "execute_confirmed_v4_rdp_event_filter_delete",
                {
                    "authorization_ref": delete_confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return (
            {tool.name for tool in tools.tools},
            result.structured_content,
            delete_result.structured_content,
        )

    tools, result, delete_result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS)
        | V4_RDP_EVENT_FILTER_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert delete_result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_delete", planning_principal),
        ("confirm_delete", operating_principal),
        ("execute_delete", operating_principal),
    ]


def test_rdp_event_filter_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_rdp_event_filter_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_rdp_event_filter_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_secret_policy_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _SecretPolicyAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, policy_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert policy_name == "mcp-v4-secret-policy-01"
            return {"preview_ref": "secret-policy-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "secret-policy-preview-00000001"
            return {"authorization_ref": "secret-policy-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "secret-policy-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_update(self, policy_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview_update", principal))
            assert policy_name == "mcp-v4-secret-policy-01"
            return {"preview_ref": "secret-policy-update-preview-00000001"}

        def confirm_update(
            self,
            preview_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("confirm_update", principal))
            assert preview_ref == "secret-policy-update-preview-00000001"
            return {"authorization_ref": "secret-policy-update-authorized-00000001"}

        def execute_update(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute_update", principal))
            assert authorization_ref == "secret-policy-update-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _SecretPolicyAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_secret_policy_action=action,
        v4_secret_policy_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_secret_policy_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_secret_policy_create",
                {"policy_name": "mcp-v4-secret-policy-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_secret_policy_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_secret_policy_create",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
            update_preview = await client.call_tool(
                "preview_v4_secret_policy_update",
                {"policy_name": "mcp-v4-secret-policy-01"},
            )
            update_confirmation = await client.call_tool(
                "confirm_v4_secret_policy_update",
                {"preview_ref": update_preview.structured_content["preview_ref"]},
            )
            update_result = await client.call_tool(
                "execute_confirmed_v4_secret_policy_update",
                {
                    "authorization_ref": update_confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return (
            {tool.name for tool in tools.tools},
            result.structured_content,
            update_result.structured_content,
        )

    tools, result, update_result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS)
        | V4_SECRET_POLICY_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert update_result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_update", planning_principal),
        ("confirm_update", operating_principal),
        ("execute_update", operating_principal),
    ]


def test_secret_policy_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_secret_policy_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_secret_policy_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_ssh_filter_only_when_bound(monkeypatch) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _SshFilterAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, profile_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert profile_name == "mcp-v4-ssh-filter-01"
            return {"preview_ref": "ssh-filter-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "ssh-filter-preview-00000001"
            return {"authorization_ref": "ssh-filter-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "ssh-filter-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_delete(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview_delete", principal))
            return {"preview_ref": "ssh-filter-delete-preview-00000001"}

        def confirm_delete(
            self,
            preview_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("confirm_delete", principal))
            assert preview_ref == "ssh-filter-delete-preview-00000001"
            return {"authorization_ref": "ssh-filter-delete-authorized-00000001"}

        def execute_delete(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute_delete", principal))
            assert authorization_ref == "ssh-filter-delete-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _SshFilterAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_ssh_filter_action=action,
        v4_ssh_filter_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_ssh_filter_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[
        set[str], dict[str, object], dict[str, object]
    ]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_ssh_filter_create",
                {"profile_name": "mcp-v4-ssh-filter-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_ssh_filter_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_ssh_filter_create",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
            delete_preview = await client.call_tool(
                "preview_v4_ssh_filter_delete",
                {},
            )
            delete_confirmation = await client.call_tool(
                "confirm_v4_ssh_filter_delete",
                {"preview_ref": delete_preview.structured_content["preview_ref"]},
            )
            delete_result = await client.call_tool(
                "execute_confirmed_v4_ssh_filter_delete",
                {
                    "authorization_ref": delete_confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return (
            {tool.name for tool in tools.tools},
            result.structured_content,
            delete_result.structured_content,
        )

    tools, result, delete_result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_SSH_FILTER_CAPABILITY_TOOLS
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert delete_result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_delete", planning_principal),
        ("confirm_delete", operating_principal),
        ("execute_delete", operating_principal),
    ]


def test_ssh_filter_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_ssh_filter_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_ssh_filter_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_launcher_only_when_bound(monkeypatch) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _LauncherAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, launcher_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert launcher_name == "mcp-v4-launcher-01"
            return {"preview_ref": "launcher-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "launcher-preview-00000001"
            return {"authorization_ref": "launcher-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "launcher-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _LauncherAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_launcher_action=action,
        v4_launcher_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_launcher_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_launcher_create",
                {"launcher_name": "mcp-v4-launcher-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_launcher_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_launcher_create",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_LAUNCHER_CAPABILITY_TOOLS
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_launcher_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_launcher_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_launcher_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_launcher_update_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _LauncherUpdateAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, launcher_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert launcher_name == "mcp-v4-launcher-01"
            return {"preview_ref": "launcher-update-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "launcher-update-preview-00000001"
            return {"authorization_ref": "launcher-update-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "launcher-update-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _LauncherUpdateAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_launcher_update_action=action,
        v4_launcher_update_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_launcher_update_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_launcher_timeout_update",
                {"launcher_name": "mcp-v4-launcher-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_launcher_timeout_update",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_launcher_timeout_update",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_LAUNCHER_UPDATE_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_launcher_update_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_launcher_update_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_launcher_update_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_launcher_matcher_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _LauncherMatcherAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, launcher_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert launcher_name == "mcp-v4-launcher-01"
            return {"preview_ref": "launcher-matcher-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "launcher-matcher-preview-00000001"
            return {"authorization_ref": "launcher-matcher-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "launcher-matcher-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _LauncherMatcherAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_launcher_matcher_action=action,
        v4_launcher_matcher_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_launcher_matcher_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_launcher_command_line_matcher_configure",
                {"launcher_name": "mcp-v4-launcher-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_launcher_command_line_matcher_configure",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_launcher_command_line_matcher_configure",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_LAUNCHER_MATCHER_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_launcher_matcher_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_launcher_matcher_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_launcher_matcher_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_template_only_when_bound(monkeypatch) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _TemplateAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, template_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert template_name == "mcp-v4-template-01"
            return {"preview_ref": "template-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "template-preview-00000001"
            return {"authorization_ref": "template-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "template-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_update(self, template_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview_update", principal))
            assert template_name == "mcp-v4-template-01"
            return {"preview_ref": "template-update-preview-00000001"}

        def confirm_update(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm_update", principal))
            assert preview_ref == "template-update-preview-00000001"
            return {"authorization_ref": "template-update-authorized-00000001"}

        def execute_update(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute_update", principal))
            assert authorization_ref == "template-update-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _TemplateAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_template_action=action,
        v4_template_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_template_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_template_create",
                {"template_name": "mcp-v4-template-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_template_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_template_create",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
            update_preview = await client.call_tool(
                "preview_v4_template_web_vnc_port_update",
                {"template_name": "mcp-v4-template-01"},
            )
            update_confirmation = await client.call_tool(
                "confirm_v4_template_web_vnc_port_update",
                {"preview_ref": update_preview.structured_content["preview_ref"]},
            )
            update_result = await client.call_tool(
                "execute_confirmed_v4_template_web_vnc_port_update",
                {
                    "authorization_ref": update_confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return (
            {tool.name for tool in tools.tools},
            result.structured_content,
            update_result.structured_content,
        )

    tools, result, update_result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_TEMPLATE_CAPABILITY_TOOLS
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert update_result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_update", planning_principal),
        ("confirm_update", operating_principal),
        ("execute_update", operating_principal),
    ]


def test_template_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_template_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_template_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_template_archive_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _TemplateArchiveAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, template_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert template_name == "mcp-v4-template-archive-01"
            return {"preview_ref": "template-archive-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "template-archive-preview-00000001"
            return {"authorization_ref": "template-archive-authorized-00000001"}

        def execute(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "template-archive-authorized-00000001"
            return {"outcome": "succeeded", "verification": "absent"}

    action = _TemplateArchiveAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_template_archive_action=action,
        v4_template_archive_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_template_archive_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_disposable_template_archive",
                {"template_name": "mcp-v4-template-archive-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_disposable_template_archive",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_disposable_template_archive",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_TEMPLATE_ARCHIVE_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "absent"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_template_archive_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="Template archive action requires"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_template_archive_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_template_archive_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_dependency_updater_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _DependencyUpdaterAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            updater_name: str,
            service_name: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert updater_name == "mcp-v4-dependency-updater-01"
            assert service_name == "McpV4LabService"
            return {"preview_ref": "dependency-updater-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "dependency-updater-preview-00000001"
            return {"authorization_ref": "dependency-updater-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "dependency-updater-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _DependencyUpdaterAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_dependency_updater_action=action,
        v4_dependency_updater_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_dependency_updater_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_dependency_updater_create",
                {
                    "updater_name": "mcp-v4-dependency-updater-01",
                    "service_name": "McpV4LabService",
                },
            )
            confirmation = await client.call_tool(
                "confirm_v4_dependency_updater_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_dependency_updater_create",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_DEPENDENCY_UPDATER_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_dependency_updater_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_dependency_updater_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_dependency_updater_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_secret_gateway_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _SecretGatewayAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, gateway_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert gateway_name == "mcp-v4-secret-gateway-01"
            return {"preview_ref": "secret-gateway-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "secret-gateway-preview-00000001"
            return {"authorization_ref": "secret-gateway-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "secret-gateway-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _SecretGatewayAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_secret_gateway_action=action,
        v4_secret_gateway_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_secret_gateway_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_secret_gateway_create",
                {"gateway_name": "mcp-v4-secret-gateway-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_secret_gateway_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_secret_gateway_create",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_SECRET_GATEWAY_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_secret_gateway_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_secret_gateway_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_secret_gateway_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_client_integrity_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _ClientIntegrityAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            client_software_name: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert client_software_name == "mcp-v4-client-integrity-01"
            return {"preview_ref": "client-integrity-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "client-integrity-preview-00000001"
            return {"authorization_ref": "client-integrity-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "client-integrity-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _ClientIntegrityAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_client_integrity_action=action,
        v4_client_integrity_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_client_integrity_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_client_integrity_configure",
                {"client_software_name": "mcp-v4-client-integrity-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_client_integrity_configure",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_client_integrity_configure",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_CLIENT_INTEGRITY_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_client_integrity_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_client_integrity_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_client_integrity_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_ztna_access_proxy_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _ZtnaAccessProxyAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            endpoint_access_mode: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert endpoint_access_mode == "mixed_access"
            return {"preview_ref": "ztna-access-proxy-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "ztna-access-proxy-preview-00000001"
            return {"authorization_ref": "ztna-access-proxy-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "ztna-access-proxy-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _ZtnaAccessProxyAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_ztna_access_proxy_action=action,
        v4_ztna_access_proxy_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_ztna_access_proxy_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_ztna_access_proxy_client_certificate",
                {"endpoint_access_mode": "mixed_access"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_ztna_access_proxy_client_certificate",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_ztna_access_proxy_client_certificate",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_ZTNA_ACCESS_PROXY_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_ztna_access_proxy_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_ztna_access_proxy_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_ztna_access_proxy_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_ztna_user_control_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _ZtnaUserControlAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            return {"preview_ref": "ztna-user-control-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "ztna-user-control-preview-00000001"
            return {"authorization_ref": "ztna-user-control-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "ztna-user-control-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_rollback(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview_rollback", principal))
            return {"preview_ref": "ztna-user-control-rollback-preview-00000001"}

        def confirm_rollback(
            self, preview_ref: str, principal: object
        ) -> dict[str, object]:
            self.calls.append(("confirm_rollback", principal))
            assert preview_ref == "ztna-user-control-rollback-preview-00000001"
            return {
                "authorization_ref": "ztna-user-control-rollback-authorized-00000001"
            }

        def execute_rollback(
            self, authorization_ref: str, principal: object
        ) -> dict[str, object]:
            self.calls.append(("execute_rollback", principal))
            assert authorization_ref == "ztna-user-control-rollback-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _ZtnaUserControlAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_ztna_user_control_action=action,
        v4_ztna_user_control_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_ztna_user_control_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool("preview_v4_ztna_user_control_configure")
            confirmation = await client.call_tool(
                "confirm_v4_ztna_user_control_configure",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_ztna_user_control_configure",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
            rollback_preview = await client.call_tool(
                "preview_v4_ztna_user_control_rollback"
            )
            rollback_confirmation = await client.call_tool(
                "confirm_v4_ztna_user_control_rollback",
                {"preview_ref": rollback_preview.structured_content["preview_ref"]},
            )
            rollback_result = await client.call_tool(
                "execute_confirmed_v4_ztna_user_control_rollback",
                {
                    "authorization_ref": rollback_confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return (
            {tool.name for tool in tools.tools},
            result.structured_content,
            rollback_result.structured_content,
        )

    tools, result, rollback_result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_ZTNA_USER_CONTROL_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert rollback_result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_rollback", planning_principal),
        ("confirm_rollback", operating_principal),
        ("execute_rollback", operating_principal),
    ]


def test_ztna_user_control_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_ztna_user_control_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_ztna_user_control_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_ztna_wad_debug_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _WadDebugAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            return {"preview_ref": "ztna-wad-debug-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "ztna-wad-debug-preview-00000001"
            return {"authorization_ref": "ztna-wad-debug-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "ztna-wad-debug-authorized-00000001"
            return {"outcome": "succeeded", "global_debug_cleanup_confirmed": True}

    action = _WadDebugAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_ztna_wad_debug_action=action,
        v4_ztna_wad_debug_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_ztna_wad_debug_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool("preview_v4_ztna_wad_debug_diagnostic")
            confirmation = await client.call_tool(
                "confirm_v4_ztna_wad_debug_diagnostic",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_ztna_wad_debug_diagnostic",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_ZTNA_WAD_DEBUG_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "global_debug_cleanup_confirmed": True}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_ztna_wad_debug_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_ztna_wad_debug_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_ztna_wad_debug_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_snmp_agent_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _SnmpAgentAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            return {"preview_ref": "snmp-agent-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "snmp-agent-preview-00000001"
            return {"authorization_ref": "snmp-agent-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "snmp-agent-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_rollback(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview_rollback", principal))
            return {"preview_ref": "snmp-agent-rollback-preview-00000001"}

        def confirm_rollback(
            self,
            preview_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("confirm_rollback", principal))
            assert preview_ref == "snmp-agent-rollback-preview-00000001"
            return {"authorization_ref": "snmp-agent-rollback-authorized-00000001"}

        def execute_rollback(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute_rollback", principal))
            assert authorization_ref == "snmp-agent-rollback-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _SnmpAgentAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_snmp_agent_action=action,
        v4_snmp_agent_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_snmp_agent_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool("preview_v4_snmp_agent_enable")
            confirmation = await client.call_tool(
                "confirm_v4_snmp_agent_enable",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_snmp_agent_enable",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
            rollback_preview = await client.call_tool("preview_v4_snmp_agent_rollback")
            rollback_confirmation = await client.call_tool(
                "confirm_v4_snmp_agent_rollback",
                {"preview_ref": rollback_preview.structured_content["preview_ref"]},
            )
            rollback_result = await client.call_tool(
                "execute_confirmed_v4_snmp_agent_rollback",
                {
                    "authorization_ref": rollback_confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
            assert rollback_result.structured_content == {
                "outcome": "succeeded",
                "verification": "verified",
            }
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_SNMP_AGENT_CAPABILITY_TOOLS
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_rollback", operating_principal),
        ("confirm_rollback", operating_principal),
        ("execute_rollback", operating_principal),
    ]


def test_snmp_agent_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_snmp_agent_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_snmp_agent_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_logging_disk_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _LoggingDiskAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            return {"preview_ref": "logging-disk-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "logging-disk-preview-00000001"
            return {"authorization_ref": "logging-disk-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "logging-disk-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _LoggingDiskAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_logging_disk_action=action,
        v4_logging_disk_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_logging_disk_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool("preview_v4_logging_disk_disable")
            confirmation = await client.call_tool(
                "confirm_v4_logging_disk_disable",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_logging_disk_disable",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_LOGGING_DISK_CAPABILITY_TOOLS
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_logging_disk_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_logging_disk_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_logging_disk_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_fortianalyzer_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _FortiAnalyzerAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            return {"preview_ref": "fortianalyzer-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "fortianalyzer-preview-00000001"
            return {"authorization_ref": "fortianalyzer-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "fortianalyzer-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _FortiAnalyzerAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_fortianalyzer_action=action,
        v4_fortianalyzer_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_fortianalyzer_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool("preview_v4_fortianalyzer_enable")
            confirmation = await client.call_tool(
                "confirm_v4_fortianalyzer_enable",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_fortianalyzer_enable",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_FORTIANALYZER_CAPABILITY_TOOLS
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_fortianalyzer_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_fortianalyzer_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_fortianalyzer_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_maintenance_mode_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _MaintenanceModeAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            return {"preview_ref": "maintenance-mode-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "maintenance-mode-preview-00000001"
            return {"authorization_ref": "maintenance-mode-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "maintenance-mode-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_rollback(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview_rollback", principal))
            return {"preview_ref": "maintenance-mode-rollback-preview-00000001"}

        def confirm_rollback(
            self,
            preview_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("confirm_rollback", principal))
            assert preview_ref == "maintenance-mode-rollback-preview-00000001"
            return {
                "authorization_ref": "maintenance-mode-rollback-authorized-00000001"
            }

        def execute_rollback(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute_rollback", principal))
            assert authorization_ref == "maintenance-mode-rollback-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _MaintenanceModeAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_maintenance_mode_action=action,
        v4_maintenance_mode_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_maintenance_mode_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool("preview_v4_maintenance_mode_enable")
            confirmation = await client.call_tool(
                "confirm_v4_maintenance_mode_enable",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_maintenance_mode_enable",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
            rollback_preview = await client.call_tool(
                "preview_v4_maintenance_mode_rollback"
            )
            rollback_confirmation = await client.call_tool(
                "confirm_v4_maintenance_mode_rollback",
                {
                    "preview_ref": rollback_preview.structured_content[
                        "preview_ref"
                    ]
                },
            )
            rollback_result = await client.call_tool(
                "execute_confirmed_v4_maintenance_mode_rollback",
                {
                    "authorization_ref": rollback_confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return (
            {tool.name for tool in tools.tools},
            result.structured_content,
            rollback_result.structured_content,
        )

    tools, result, rollback_result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_MAINTENANCE_MODE_CAPABILITY_TOOLS
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert rollback_result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_rollback", planning_principal),
        ("confirm_rollback", operating_principal),
        ("execute_rollback", operating_principal),
    ]


def test_maintenance_mode_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_maintenance_mode_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_maintenance_mode_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_secret_audit_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _SecretAuditAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            return {"preview_ref": "secret-audit-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "secret-audit-preview-00000001"
            return {"authorization_ref": "secret-audit-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "secret-audit-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _SecretAuditAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_secret_audit_action=action,
        v4_secret_audit_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_secret_audit_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool("preview_v4_secret_audit_generate")
            confirmation = await client.call_tool(
                "confirm_v4_secret_audit_generate",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_secret_audit_generate",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_SECRET_AUDIT_CAPABILITY_TOOLS
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_secret_audit_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_secret_audit_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_secret_audit_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_active_launch_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _ActiveLaunchAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def observe(self, principal: object) -> dict[str, object]:
            self.calls.append(("observe", principal))
            return {"active_launch_refs": [{"launch_ref": "active-launch-ref-00000001"}]}

        def preview_disconnect(
            self,
            launch_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert launch_ref == "active-launch-ref-00000001"
            return {"preview_ref": "active-launch-disconnect-preview-00000001"}

        def confirm_disconnect(
            self,
            preview_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "active-launch-disconnect-preview-00000001"
            return {"authorization_ref": "active-launch-disconnect-authorized-00000001"}

        def execute_disconnect(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "active-launch-disconnect-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _ActiveLaunchAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_active_launch_action=action,
        v4_active_launch_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(
        server,
        "_v4_active_launch_action_principal",
        lambda: operating_principal,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            observation = await client.call_tool("observe_v4_active_launches")
            launch_ref = observation.structured_content["active_launch_refs"][0]["launch_ref"]
            preview = await client.call_tool(
                "preview_v4_active_launch_disconnect",
                {"launch_ref": launch_ref},
            )
            confirmation = await client.call_tool(
                "confirm_v4_active_launch_disconnect",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_active_launch_disconnect",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_ACTIVE_LAUNCH_CAPABILITY_TOOLS
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("observe", planning_principal),
        ("preview", operating_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_active_launch_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_active_launch_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_active_launch_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_character_set_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _CharacterSetAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert name == "mcp-v4-char-set-01"
            return {"preview_ref": "character-set-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "character-set-preview-00000001"
            return {"authorization_ref": "character-set-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "character-set-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _CharacterSetAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_character_set_action=action,
        v4_character_set_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_character_set_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_character_set_create",
                {"name": "mcp-v4-char-set-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_character_set_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_character_set_create",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_CHARACTER_SET_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_character_set_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_character_set_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_character_set_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_windows_app_filter_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _WindowsAppFilterAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert name == "mcp-v4-winapp-filter-01"
            return {"preview_ref": "windows-app-filter-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "windows-app-filter-preview-00000001"
            return {"authorization_ref": "windows-app-filter-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "windows-app-filter-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_delete(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview_delete", principal))
            return {"preview_ref": "windows-app-filter-delete-preview-00000001"}

        def confirm_delete(
            self,
            preview_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("confirm_delete", principal))
            assert preview_ref == "windows-app-filter-delete-preview-00000001"
            return {
                "authorization_ref": (
                    "windows-app-filter-delete-authorized-00000001"
                )
            }

        def execute_delete(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute_delete", principal))
            assert (
                authorization_ref
                == "windows-app-filter-delete-authorized-00000001"
            )
            return {"outcome": "succeeded", "verification": "verified"}

    action = _WindowsAppFilterAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_windows_app_filter_action=action,
        v4_windows_app_filter_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_windows_app_filter_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_windows_app_filter_create",
                {"name": "mcp-v4-winapp-filter-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_windows_app_filter_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_windows_app_filter_create",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
            delete_preview = await client.call_tool(
                "preview_v4_windows_app_filter_delete",
                {},
            )
            delete_confirmation = await client.call_tool(
                "confirm_v4_windows_app_filter_delete",
                {"preview_ref": delete_preview.structured_content["preview_ref"]},
            )
            delete_result = await client.call_tool(
                "execute_confirmed_v4_windows_app_filter_delete",
                {
                    "authorization_ref": delete_confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, {
            "create": result.structured_content,
            "delete": delete_result.structured_content,
        }

    tools, result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_WINDOWS_APP_FILTER_CAPABILITY_TOOLS
    )
    assert result == {
        "create": {"outcome": "succeeded", "verification": "verified"},
        "delete": {"outcome": "succeeded", "verification": "verified"},
    }
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_delete", planning_principal),
        ("confirm_delete", operating_principal),
        ("execute_delete", operating_principal),
    ]


def test_windows_app_filter_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_windows_app_filter_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_windows_app_filter_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_recording_policy_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _RecordingPolicyAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, policy_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert policy_name == "mcp-v4-secret-policy-recording-01"
            return {"preview_ref": "recording-policy-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "recording-policy-preview-00000001"
            return {"authorization_ref": "recording-policy-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "recording-policy-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _RecordingPolicyAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_recording_policy_action=action,
        v4_recording_policy_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_recording_policy_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_recording_policy_enable",
                {"policy_name": "mcp-v4-secret-policy-recording-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_recording_policy_enable",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_recording_policy_enable",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_RECORDING_POLICY_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_recording_policy_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_recording_policy_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_recording_policy_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_password_policy_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _PasswordPolicyAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert name == "mcp-v4-password-policy-01"
            return {"preview_ref": "password-policy-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "password-policy-preview-00000001"
            return {"authorization_ref": "password-policy-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "password-policy-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _PasswordPolicyAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_password_policy_action=action,
        v4_password_policy_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_password_policy_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_password_policy_create",
                {"name": "mcp-v4-password-policy-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_password_policy_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_password_policy_create",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_PASSWORD_POLICY_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_password_policy_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_password_policy_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_password_policy_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_report_layout_only_when_bound(
    monkeypatch,
) -> None:
    class _ReportLayoutAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert name == "MCPV4ReportB163Test"
            return {"preview_ref": "report-layout-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "report-layout-preview-00000001"
            return {"authorization_ref": "report-layout-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "report-layout-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_delete(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview_delete", principal))
            return {"preview_ref": "report-layout-delete-preview-00000001"}

        def confirm_delete(
            self, preview_ref: str, principal: object
        ) -> dict[str, object]:
            self.calls.append(("confirm_delete", principal))
            assert preview_ref == "report-layout-delete-preview-00000001"
            return {
                "authorization_ref": "report-layout-delete-authorized-00000001"
            }

        def execute_delete(
            self, authorization_ref: str, principal: object
        ) -> dict[str, object]:
            self.calls.append(("execute_delete", principal))
            assert authorization_ref == "report-layout-delete-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _ReportLayoutAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_report_layout_action=action,
        v4_report_layout_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_report_layout_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[
        set[str], dict[str, object], dict[str, object]
    ]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_report_layout_create",
                {"name": "MCPV4ReportB163Test"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_report_layout_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_report_layout_create",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
            delete_preview = await client.call_tool(
                "preview_v4_report_layout_delete",
                {},
            )
            delete_confirmation = await client.call_tool(
                "confirm_v4_report_layout_delete",
                {"preview_ref": delete_preview.structured_content["preview_ref"]},
            )
            delete_result = await client.call_tool(
                "execute_confirmed_v4_report_layout_delete",
                {
                    "authorization_ref": delete_confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return (
            {tool.name for tool in tools.tools},
            result.structured_content,
            delete_result.structured_content,
        )

    tools, result, delete_result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_REPORT_LAYOUT_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert delete_result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_delete", planning_principal),
        ("confirm_delete", operating_principal),
        ("execute_delete", operating_principal),
    ]


def test_report_layout_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_report_layout_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_report_layout_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_automation_trigger_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _AutomationTriggerAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, trigger_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert trigger_name == "mcp-v4-automation-trigger-01"
            return {"preview_ref": "automation-trigger-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "automation-trigger-preview-00000001"
            return {"authorization_ref": "automation-trigger-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "automation-trigger-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _AutomationTriggerAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_automation_trigger_action=action,
        v4_automation_trigger_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_automation_trigger_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_automation_trigger_create",
                {"trigger_name": "mcp-v4-automation-trigger-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_automation_trigger_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_automation_trigger_create",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_AUTOMATION_TRIGGER_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_automation_trigger_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_automation_trigger_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_automation_trigger_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_automation_action_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _AutomationAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, action_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert action_name == "mcp-v4-automation-action-01"
            return {"preview_ref": "automation-action-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "automation-action-preview-00000001"
            return {"authorization_ref": "automation-action-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "automation-action-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_delete(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview_delete", principal))
            return {"preview_ref": "automation-action-delete-preview-00000001"}

        def confirm_delete(
            self,
            preview_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("confirm_delete", principal))
            assert preview_ref == "automation-action-delete-preview-00000001"
            return {
                "authorization_ref": "automation-action-delete-authorized-00000001"
            }

        def execute_delete(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute_delete", principal))
            assert authorization_ref == "automation-action-delete-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _AutomationAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_automation_action_action=action,
        v4_automation_action_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_automation_action_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_automation_action_create",
                {"action_name": "mcp-v4-automation-action-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_automation_action_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_automation_action_create",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
            delete_preview = await client.call_tool(
                "preview_v4_automation_action_delete",
                {},
            )
            delete_confirmation = await client.call_tool(
                "confirm_v4_automation_action_delete",
                {"preview_ref": delete_preview.structured_content["preview_ref"]},
            )
            delete_result = await client.call_tool(
                "execute_confirmed_v4_automation_action_delete",
                {
                    "authorization_ref": delete_confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return (
            {tool.name for tool in tools.tools},
            result.structured_content,
            delete_result.structured_content,
        )

    tools, result, delete_result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_AUTOMATION_ACTION_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert delete_result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_delete", operating_principal),
        ("confirm_delete", operating_principal),
        ("execute_delete", operating_principal),
    ]


def test_automation_action_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_automation_action_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_automation_action_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_automation_stitch_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _AutomationStitchAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            stitch_name: str,
            trigger_name: str,
            action_name: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert stitch_name == "mcp-v4-automation-stitch-01"
            assert trigger_name == "mcp-v4-automation-trigger-01"
            assert action_name == "mcp-v4-automation-action-01"
            return {"preview_ref": "automation-stitch-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "automation-stitch-preview-00000001"
            return {"authorization_ref": "automation-stitch-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "automation-stitch-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_delete(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview_delete", principal))
            return {"preview_ref": "automation-stitch-delete-preview-00000001"}

        def confirm_delete(
            self,
            preview_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("confirm_delete", principal))
            assert preview_ref == "automation-stitch-delete-preview-00000001"
            return {
                "authorization_ref": "automation-stitch-delete-authorized-00000001"
            }

        def execute_delete(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute_delete", principal))
            assert authorization_ref == "automation-stitch-delete-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _AutomationStitchAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_automation_stitch_action=action,
        v4_automation_stitch_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_automation_stitch_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_automation_stitch_create",
                {
                    "stitch_name": "mcp-v4-automation-stitch-01",
                    "trigger_name": "mcp-v4-automation-trigger-01",
                    "action_name": "mcp-v4-automation-action-01",
                },
            )
            confirmation = await client.call_tool(
                "confirm_v4_automation_stitch_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_automation_stitch_create",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
            delete_preview = await client.call_tool(
                "preview_v4_automation_stitch_delete",
                {},
            )
            delete_confirmation = await client.call_tool(
                "confirm_v4_automation_stitch_delete",
                {"preview_ref": delete_preview.structured_content["preview_ref"]},
            )
            delete_result = await client.call_tool(
                "execute_confirmed_v4_automation_stitch_delete",
                {
                    "authorization_ref": delete_confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return (
            {tool.name for tool in tools.tools},
            result.structured_content,
            delete_result.structured_content,
        )

    tools, result, delete_result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_AUTOMATION_STITCH_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert delete_result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_delete", operating_principal),
        ("confirm_delete", operating_principal),
        ("execute_delete", operating_principal),
    ]


def test_automation_stitch_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_automation_stitch_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_automation_stitch_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_user_group_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _UserGroupAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            user_group_name: str,
            ldap_server_name: str,
            ldap_group_dn: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert user_group_name == "mcp-v4-user-group-01"
            assert ldap_server_name == "lab-ldap"
            assert ldap_group_dn == "cn=PAM_Group,cn=users,dc=fortipam,dc=ca"
            return {"preview_ref": "user-group-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "user-group-preview-00000001"
            return {"authorization_ref": "user-group-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "user-group-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _UserGroupAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_user_group_action=action,
        v4_user_group_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_user_group_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_user_group_create",
                {
                    "user_group_name": "mcp-v4-user-group-01",
                    "ldap_server_name": "lab-ldap",
                    "ldap_group_dn": "cn=PAM_Group,cn=users,dc=fortipam,dc=ca",
                },
            )
            confirmation = await client.call_tool(
                "confirm_v4_user_group_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_user_group_create",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_USER_GROUP_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_user_group_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_user_group_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_user_group_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_user_group_membership_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _UserGroupMembershipAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            user_group_name: str,
            ldap_server_name: str,
            primary_ldap_group_dn: str,
            additional_ldap_group_dn: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert user_group_name == "mcp-v4-user-group-01"
            assert ldap_server_name == "lab-ldap"
            assert primary_ldap_group_dn == "cn=PAM_Primary,cn=users,dc=fortipam,dc=ca"
            assert additional_ldap_group_dn == "cn=PAM_Secondary,cn=users,dc=fortipam,dc=ca"
            return {"preview_ref": "user-group-membership-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "user-group-membership-preview-00000001"
            return {"authorization_ref": "user-group-membership-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "user-group-membership-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _UserGroupMembershipAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_user_group_membership_action=action,
        v4_user_group_membership_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_user_group_membership_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_user_group_membership_change",
                {
                    "user_group_name": "mcp-v4-user-group-01",
                    "ldap_server_name": "lab-ldap",
                    "primary_ldap_group_dn": "cn=PAM_Primary,cn=users,dc=fortipam,dc=ca",
                    "additional_ldap_group_dn": "cn=PAM_Secondary,cn=users,dc=fortipam,dc=ca",
                },
            )
            confirmation = await client.call_tool(
                "confirm_v4_user_group_membership_change",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_user_group_membership_change",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS)
        | V4_USER_GROUP_MEMBERSHIP_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_user_group_membership_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_user_group_membership_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_user_group_membership_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_apl_only_when_bound(monkeypatch) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _AplAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            auto_provision_rule_name: str,
            remote_user_group_name: str,
            role_name: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert auto_provision_rule_name == "mcp-v4-apl-01"
            assert remote_user_group_name == "mcp-v4-user-group-01"
            assert role_name == "mcp-v4-role-01"
            return {"preview_ref": "apl-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "apl-preview-00000001"
            return {"authorization_ref": "apl-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "apl-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _AplAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_apl_action=action,
        v4_apl_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_apl_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_auto_provision_rule_create",
                {
                    "auto_provision_rule_name": "mcp-v4-apl-01",
                    "remote_user_group_name": "mcp-v4-user-group-01",
                    "role_name": "mcp-v4-role-01",
                },
            )
            confirmation = await client.call_tool(
                "confirm_v4_auto_provision_rule_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_auto_provision_rule_create",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_APL_CAPABILITY_TOOLS
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_apl_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_apl_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_apl_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_apl_disable_only_when_bound(monkeypatch) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _AplDisableAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            auto_provision_rule_name: str,
            remote_user_group_name: str,
            role_name: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert auto_provision_rule_name == "mcp-v4-apl-01"
            assert remote_user_group_name == "mcp-v4-user-group-01"
            assert role_name == "mcp-v4-role-01"
            return {"preview_ref": "apl-disable-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "apl-disable-preview-00000001"
            return {"authorization_ref": "apl-disable-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "apl-disable-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _AplDisableAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_apl_disable_action=action,
        v4_apl_disable_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_apl_disable_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_auto_provision_rule_disable",
                {
                    "auto_provision_rule_name": "mcp-v4-apl-01",
                    "remote_user_group_name": "mcp-v4-user-group-01",
                    "role_name": "mcp-v4-role-01",
                },
            )
            confirmation = await client.call_tool(
                "confirm_v4_auto_provision_rule_disable",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_auto_provision_rule_disable",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_APL_DISABLE_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_apl_disable_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_apl_disable_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_apl_disable_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_schedule_only_when_bound(monkeypatch) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _ScheduleAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, schedule_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert schedule_name == "mcp-v4-schedule-01"
            return {"preview_ref": "schedule-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "schedule-preview-00000001"
            return {"authorization_ref": "schedule-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "schedule-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _ScheduleAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_schedule_action=action,
        v4_schedule_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_schedule_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_schedule_create",
                {"schedule_name": "mcp-v4-schedule-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_schedule_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_schedule_create",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_SCHEDULE_CAPABILITY_TOOLS
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_schedule_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_schedule_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_schedule_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_schedule_assign_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _ScheduleAssignAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(
            self,
            username: str,
            schedule_name: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert username == "mcp-v4-user-b57"
            assert schedule_name == "mcp-v4-schedule-b66"
            return {"preview_ref": "schedule-assign-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "schedule-assign-preview-00000001"
            return {"authorization_ref": "schedule-assign-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "schedule-assign-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_detach(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview_detach", principal))
            return {"preview_ref": "schedule-detach-preview-00000001"}

        def confirm_detach(
            self,
            preview_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("confirm_detach", principal))
            assert preview_ref == "schedule-detach-preview-00000001"
            return {"authorization_ref": "schedule-detach-authorized-00000001"}

        def execute_detach(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute_detach", principal))
            assert authorization_ref == "schedule-detach-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _ScheduleAssignAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_schedule_assign_action=action,
        v4_schedule_assign_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_schedule_assign_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[
        set[str], dict[str, object], dict[str, object]
    ]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_schedule_assign",
                {
                    "username": "mcp-v4-user-b57",
                    "schedule_name": "mcp-v4-schedule-b66",
                },
            )
            confirmation = await client.call_tool(
                "confirm_v4_schedule_assign",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_schedule_assign",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
            detach_preview = await client.call_tool(
                "preview_v4_schedule_assignment_detach",
                {},
            )
            detach_confirmation = await client.call_tool(
                "confirm_v4_schedule_assignment_detach",
                {"preview_ref": detach_preview.structured_content["preview_ref"]},
            )
            detach_result = await client.call_tool(
                "execute_confirmed_v4_schedule_assignment_detach",
                {
                    "authorization_ref": detach_confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return (
            {tool.name for tool in tools.tools},
            result.structured_content,
            detach_result.structured_content,
        )

    tools, result, detach_result = asyncio.run(_exercise())
    assert tools == set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_SCHEDULE_ASSIGN_CAPABILITY_TOOLS
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert detach_result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_detach", planning_principal),
        ("confirm_detach", operating_principal),
        ("execute_detach", operating_principal),
    ]


def test_schedule_assign_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_schedule_assign_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_schedule_assign_action=object(),
            v4_http_oauth=True,
        )
def test_v4_controlled_profile_exposes_approval_profile_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _ApprovalProfileAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, profile_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert profile_name == "mcp-v4-approval-profile-01"
            return {"preview_ref": "approval-profile-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "approval-profile-preview-00000001"
            return {"authorization_ref": "approval-profile-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "approval-profile-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _ApprovalProfileAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_approval_profile_action=action,
        v4_approval_profile_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_approval_profile_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_approval_profile_create",
                {"profile_name": "mcp-v4-approval-profile-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_approval_profile_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_approval_profile_create",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS) | V4_APPROVAL_PROFILE_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_approval_profile_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_approval_profile_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_approval_profile_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_approval_profile_update_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _ApprovalProfileUpdateAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, profile_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert profile_name == "mcp-v4-approval-profile-01"
            return {"preview_ref": "approval-profile-update-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "approval-profile-update-preview-00000001"
            return {"authorization_ref": "approval-profile-update-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "approval-profile-update-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_delete(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview_delete", principal))
            return {"preview_ref": "approval-profile-delete-preview-00000001"}

        def confirm_delete(
            self,
            preview_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("confirm_delete", principal))
            assert preview_ref == "approval-profile-delete-preview-00000001"
            return {
                "authorization_ref": "approval-profile-delete-authorized-00000001"
            }

        def execute_delete(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute_delete", principal))
            assert authorization_ref == "approval-profile-delete-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _ApprovalProfileUpdateAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_approval_profile_update_action=action,
        v4_approval_profile_update_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_approval_profile_update_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_approval_profile_description_update",
                {"profile_name": "mcp-v4-approval-profile-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_approval_profile_description_update",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_approval_profile_description_update",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
            delete_preview = await client.call_tool(
                "preview_v4_approval_profile_delete",
                {},
            )
            delete_confirmation = await client.call_tool(
                "confirm_v4_approval_profile_delete",
                {"preview_ref": delete_preview.structured_content["preview_ref"]},
            )
            delete_result = await client.call_tool(
                "execute_confirmed_v4_approval_profile_delete",
                {
                    "authorization_ref": delete_confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return (
            {tool.name for tool in tools.tools},
            result.structured_content,
            delete_result.structured_content,
        )

    tools, result, delete_result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS)
        | V4_APPROVAL_PROFILE_UPDATE_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert delete_result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_delete", operating_principal),
        ("confirm_delete", operating_principal),
        ("execute_delete", operating_principal),
    ]


def test_approval_profile_update_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_approval_profile_update_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_approval_profile_update_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_approval_email_template_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _ApprovalEmailTemplateAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, template_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert template_name == "mcp-v4-approval-email-template-01"
            return {"preview_ref": "approval-email-template-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "approval-email-template-preview-00000001"
            return {"authorization_ref": "approval-email-template-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "approval-email-template-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

    action = _ApprovalEmailTemplateAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_approval_email_template_action=action,
        v4_approval_email_template_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_approval_email_template_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_approval_email_template_create",
                {"template_name": "mcp-v4-approval-email-template-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_approval_email_template_create",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_approval_email_template_create",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return {tool.name for tool in tools.tools}, result.structured_content

    tools, result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS)
        | V4_APPROVAL_EMAIL_TEMPLATE_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
    ]


def test_approval_email_template_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_approval_email_template_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_approval_email_template_action=object(),
            v4_http_oauth=True,
        )


def test_v4_controlled_profile_exposes_approval_email_template_update_only_when_bound(
    monkeypatch,
) -> None:
    class _FolderAction:
        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            return {"outcome": "succeeded"}

    class _ApprovalEmailTemplateUpdateAction:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def preview(self, template_name: str, principal: object) -> dict[str, object]:
            self.calls.append(("preview", principal))
            assert template_name == "mcp-v4-approval-email-template-01"
            return {"preview_ref": "approval-email-template-update-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("confirm", principal))
            assert preview_ref == "approval-email-template-update-preview-00000001"
            return {
                "authorization_ref": "approval-email-template-update-authorized-00000001"
            }

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            self.calls.append(("execute", principal))
            assert authorization_ref == "approval-email-template-update-authorized-00000001"
            return {"outcome": "succeeded", "verification": "verified"}

        def preview_delete(self, principal: object) -> dict[str, object]:
            self.calls.append(("preview_delete", principal))
            return {"preview_ref": "approval-email-template-delete-preview-00000001"}

        def confirm_delete(
            self,
            preview_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("confirm_delete", principal))
            assert preview_ref == "approval-email-template-delete-preview-00000001"
            return {
                "authorization_ref": (
                    "approval-email-template-delete-authorized-00000001"
                )
            }

        def execute_delete(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append(("execute_delete", principal))
            assert (
                authorization_ref
                == "approval-email-template-delete-authorized-00000001"
            )
            return {"outcome": "succeeded", "verification": "verified"}

    action = _ApprovalEmailTemplateUpdateAction()
    planning_principal = object()
    operating_principal = object()
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=_FolderAction(),
        v4_folder_action_enabled=True,
        v4_approval_email_template_update_action=action,
        v4_approval_email_template_update_action_enabled=True,
        v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: planning_principal)
    monkeypatch.setattr(
        server,
        "_v4_approval_email_template_update_action_principal",
        lambda: operating_principal,
    )

    async def _exercise() -> tuple[set[str], dict[str, object], dict[str, object]]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            preview = await client.call_tool(
                "preview_v4_approval_email_template_content_update",
                {"template_name": "mcp-v4-approval-email-template-01"},
            )
            confirmation = await client.call_tool(
                "confirm_v4_approval_email_template_content_update",
                {"preview_ref": preview.structured_content["preview_ref"]},
            )
            result = await client.call_tool(
                "execute_confirmed_v4_approval_email_template_content_update",
                {
                    "authorization_ref": confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
            delete_preview = await client.call_tool(
                "preview_v4_approval_email_template_delete",
                {},
            )
            delete_confirmation = await client.call_tool(
                "confirm_v4_approval_email_template_delete",
                {"preview_ref": delete_preview.structured_content["preview_ref"]},
            )
            delete_result = await client.call_tool(
                "execute_confirmed_v4_approval_email_template_delete",
                {
                    "authorization_ref": delete_confirmation.structured_content[
                        "authorization_ref"
                    ]
                },
            )
        return (
            {tool.name for tool in tools.tools},
            result.structured_content,
            delete_result.structured_content,
        )

    tools, result, delete_result = asyncio.run(_exercise())
    assert tools == (
        set(V4_CONTROLLED_EXPECTED_TOOLS)
        | V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_CAPABILITY_TOOLS
    )
    assert result == {"outcome": "succeeded", "verification": "verified"}
    assert delete_result == {"outcome": "succeeded", "verification": "verified"}
    assert action.calls == [
        ("preview", planning_principal),
        ("confirm", operating_principal),
        ("execute", operating_principal),
        ("preview_delete", operating_principal),
        ("confirm_delete", operating_principal),
        ("execute_delete", operating_principal),
    ]


def test_approval_email_template_update_cannot_bypass_profile_or_feature_gate() -> None:
    with pytest.raises(RuntimeError, match="requires a bound action host"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_approval_email_template_update_action_enabled=True,
            v4_http_oauth=True,
        )
    with pytest.raises(RuntimeError, match="cannot be bound while its feature is disabled"):
        server_module.FortiPamMcpServer(
            runtime_profile=RuntimeProfile.V4_CONTROLLED,
            v4_folder_action=object(),
            v4_folder_action_enabled=True,
            v4_approval_email_template_update_action=object(),
            v4_http_oauth=True,
        )


def test_lab_admin_tools_are_in_memory_and_never_load_credentials(monkeypatch) -> None:
    def _unexpected_environment_load() -> EnvironmentLoadReport:
        raise AssertionError("LAB administrative tools must not load credentials.")

    monkeypatch.setattr(server_module, "load_runtime_environment", _unexpected_environment_load)
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.LAB_SIMULATED
    )

    async def _preview_and_execute() -> tuple[dict, dict]:
        async with Client(server.mcp) as client:
            preview = await client.call_tool(
                "preview_v31_lab_public_folder",
                {
                    "folder_ref": "folder-ref-lab-01",
                    "parent_folder_ref": "folder-ref-root-01",
                    "folder_type": "public",
                    "folder_permission": "manage",
                    "vault_permission": "use",
                    "allowed_launcher_type": "ssh",
                },
            )
            assert preview.is_error is False
            body = preview.structured_content
            execute = await client.call_tool(
                "execute_confirmed_v31_lab_operation",
                {
                    "confirmation_token": body["confirmation_token"],
                    "confirmation_digest": body["confirmation_digest"],
                    "idempotency_key": "idempotency-key-mcp-lab-0001",
                },
            )
            assert execute.is_error is False
        return body, execute.structured_content

    preview, result = asyncio.run(_preview_and_execute())
    assert preview["adapter_kind"] == "lab_simulated"
    assert preview["lab_adapter"] is True
    assert preview["device_contacted"] is False
    assert preview["fortipam_contacted"] is False
    assert preview["device_write"] is False
    assert result["adapter_kind"] == "lab_simulated"
    assert result["lab_adapter"] is True
    assert result["device_contacted"] is False
    assert result["fortipam_contacted"] is False
    assert result["device_write"] is False
    assert result["readback"]["readback_verified"] is True


def test_capability_matrix_tool_is_offline_and_static(monkeypatch) -> None:
    def _unexpected_environment_load() -> EnvironmentLoadReport:
        raise AssertionError("Capability metadata must not load credentials.")

    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        _unexpected_environment_load,
    )
    server = server_module.FortiPamMcpServer()

    async def _call_tool() -> dict:
        async with Client(server.mcp) as client:
            result = await client.call_tool("get_capability_matrix", {})
        return result.structured_content

    matrix = asyncio.run(_call_tool())

    assert matrix["tool_count"] == len(EXPECTED_TOOLS) + len(V4_NONDEFAULT_CAPABILITY_TOOLS)
    assert matrix["network_call_executed"] is False
    assert matrix["fortipam_contacted"] is False
    assert {tool["tool_name"] for tool in matrix["tools"]} == (
        set(EXPECTED_TOOLS) | V4_NONDEFAULT_CAPABILITY_TOOLS
    )


def test_lab_capability_matrix_matches_registered_surface_without_credentials(
    monkeypatch,
) -> None:
    def _unexpected_environment_load() -> EnvironmentLoadReport:
        raise AssertionError("LAB capability metadata must not load credentials.")

    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        _unexpected_environment_load,
    )
    server = server_module.FortiPamMcpServer(
        runtime_profile=RuntimeProfile.LAB_SIMULATED
    )

    async def _call_tool() -> dict:
        async with Client(server.mcp) as client:
            result = await client.call_tool("get_capability_matrix", {})
        return result.structured_content

    matrix = asyncio.run(_call_tool())

    assert matrix["tool_count"] == len(LAB_EXPECTED_TOOLS) + len(V4_NONDEFAULT_CAPABILITY_TOOLS)
    assert matrix["network_call_executed"] is False
    assert matrix["fortipam_contacted"] is False
    assert {tool["tool_name"] for tool in matrix["tools"]} == (
        set(LAB_EXPECTED_TOOLS) | V4_NONDEFAULT_CAPABILITY_TOOLS
    )


def test_server_suppresses_dependency_request_urls(monkeypatch) -> None:
    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        lambda: EnvironmentLoadReport(source="test", loaded=False),
    )

    def _unconfigured():
        raise ConfigurationError("test-only unconfigured server")

    monkeypatch.setattr(server_module, "load_config", _unconfigured)
    server_module.FortiPamMcpServer()

    assert logging.getLogger("httpx").level >= logging.WARNING
    assert logging.getLogger("httpcore").level >= logging.WARNING


def test_operational_scenario_tools_work_through_mcp_without_credentials(
    monkeypatch,
) -> None:
    def _unexpected_environment_load() -> EnvironmentLoadReport:
        raise AssertionError("Offline scenario tools must not load credentials.")

    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        _unexpected_environment_load,
    )
    server = server_module.FortiPamMcpServer()

    async def _call_tools() -> tuple[dict, dict, dict]:
        async with Client(server.mcp) as client:
            status = await client.call_tool("get_scenario_catalog_status", {})
            search = await client.call_tool(
                "search_operational_scenarios",
                {"query": "self approval"},
            )
            scenario = await client.call_tool(
                "get_operational_scenario",
                {"scenario_id": "self-approval-control"},
            )
        return (
            status.structured_content,
            search.structured_content,
            scenario.structured_content,
        )

    status, search, scenario = asyncio.run(_call_tools())

    assert status["scenario_count"] == 19
    assert search["results"][0]["scenario_id"] == "self-approval-control"
    assert scenario["scenario"]["live_call_permitted"] is False


@pytest.mark.parametrize("enabled", [False, True])
def test_bound_web_target_optional_tools_use_existing_principal_boundaries(tmp_path, monkeypatch, enabled) -> None:
    from test_web_target_live_workflow import build
    from test_v4_m3 import _requester
    from fortipam_mcp.target_mcp_action import ProtectedTargetMcpAction
    from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
    workflow, transport, _, binding = build(tmp_path)
    action = ProtectedTargetMcpAction(object(), web_workflow=workflow if enabled else None)
    server = server_module.FortiPamMcpServer(runtime_profile=RuntimeProfile.V4_CONTROLLED,
        v4_folder_action=object(), v4_folder_action_enabled=True,
        v4_target_action=action, v4_target_action_enabled=True, v4_http_oauth=True)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    boundary_calls = []
    def planning(): boundary_calls.append("plan"); return principal
    def operating(): boundary_calls.append("operate"); return principal
    monkeypatch.setattr(server, "_v4_planning_principal", planning)
    monkeypatch.setattr(server, "_v4_target_action_principal", operating)
    async def exercise():
        async with Client(server.mcp) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            names = set(server_module.V4_WEB_TARGET_ACTION_TOOLS)
            assert names.intersection(tools) == (names if enabled else set())
            if not enabled: return
            preview_name, confirm_name, execute_name = server_module.V4_WEB_TARGET_ACTION_TOOLS
            assert not tools[preview_name].input_schema.get("properties")
            assert set(tools[confirm_name].input_schema["properties"]) == {"preview_ref"}
            assert set(tools[execute_name].input_schema["properties"]) == {"authorization_ref"}
            rejected = await client.call_tool(preview_name, {"web_url": "https://other.example.test"})
            assert rejected.is_error is True
            preview = (await client.call_tool(preview_name, {})).structured_content
            assert binding.web_url not in str(preview) and binding.target_name not in str(preview)
            auth = (await client.call_tool(confirm_name, {"preview_ref": preview["preview_ref"]})).structured_content
            rejected = await client.call_tool(execute_name, {"authorization_ref": auth["authorization_ref"]})
            assert rejected.is_error is True
    asyncio.run(exercise())
    assert transport.writes == 0
    assert boundary_calls == (["plan", "operate", "operate"] if enabled else [])
