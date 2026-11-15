"""Hardened Streamable HTTP entrypoint for the read-only FortiPAM MCP server."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from fnmatch import fnmatchcase
import hmac
import ipaddress
import os
from pathlib import Path
import secrets
import ssl
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from mcp.server.auth.provider import AccessToken
from mcp.server.auth.provider import ProviderTokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl

from .approval_service import (
    CONTROLLED_OPERATION_PREFIX,
    ApprovalServiceConfigurationError,
    ApprovalServiceSettings,
    LocalApprovalService,
    approval_settings_from_environment,
)
from .address_http_transport import ENV_PREFIX as ADDRESS_TRANSPORT_ENV_PREFIX
from .address_mcp_action import (
    V4_ADDRESS_ACTION_FEATURE_ENV,
    V4AddressActionConfigurationError,
    build_v4_address_action,
    load_v4_address_action_feature,
)
from .address_group_mcp_action import (
    V4_ADDRESS_GROUP_ACTION_FEATURE_ENV,
    V4AddressGroupActionConfigurationError,
    build_v4_address_group_action,
    load_v4_address_group_action_feature,
)
from .address_group_ssh_transport import (
    ENV_PREFIX as ADDRESS_GROUP_CLI_TRANSPORT_ENV_PREFIX,
)
from .ztna_device_context_diagnostic import (
    ENV_PREFIX as ZTNA_DEVICE_CONTEXT_DIAGNOSTIC_ENV_PREFIX,
    V4_ZTNA_DEVICE_CONTEXT_DIAGNOSTIC_FEATURE_ENV,
    ZtnaDeviceContextDiagnosticConfigurationError,
    build_v4_ztna_device_context_diagnostic,
    load_v4_ztna_device_context_diagnostic_feature,
)
from .ztna_folder_control_posture import (
    ENV_PREFIX as ZTNA_FOLDER_POSTURE_ENV_PREFIX,
    V4_ZTNA_FOLDER_POSTURE_FEATURE_ENV,
    ZtnaFolderControlPostureConfigurationError,
    build_v4_ztna_folder_control_posture,
    load_v4_ztna_folder_posture_feature,
)
from .diagnostic_service import (
    DIAGNOSTIC_DB_ENV,
    DIAGNOSTIC_HMAC_KEY_FILE_ENV,
    DIAGNOSTIC_PREFIX,
    DiagnosticServiceError,
    DiagnosticServiceSettings,
    diagnostic_settings_from_environment,
)
from .ha_reconciliation import (
    HA_RECONCILIATION_FEATURE_ENV,
    HA_RECONCILIATION_PREREQUISITES_ENV,
    HA_RECONCILIATION_QUERY_PERMISSION_ENV,
    HaReconciliationError,
    HaReconciliationRuntimeBinding,
    OwnerOnlyHaReconciliationPrerequisiteProvider,
    OwnerOnlyHaReconciliationQueryPermissionProvider,
    load_ha_reconciliation_feature,
    prerequisite_provider_from_environment,
    query_permission_provider_from_environment,
)
from .env import EnvironmentFileError, load_prefixed_environment_file
from .folder_http_transport import (
    ENV_PREFIX as FOLDER_TRANSPORT_ENV_PREFIX,
    FOLDER_ACL_ENV_PREFIX,
    FOLDER_ARCHIVE_ENV_PREFIX,
    FolderTransportConfigurationError,
    FortiPamFolderHttpTransport,
    load_folder_transport_config,
)
from .folder_acl_mcp_action import (
    V4_FOLDER_ACL_ACTION_PREFIX,
    V4_FOLDER_ACL_EXECUTION_ENV,
    V4FolderAclActionConfigurationError,
    build_v4_folder_acl_action,
    load_v4_folder_acl_action_feature,
)
from .folder_acl_revoke_mcp_action import (
    V4_FOLDER_ACL_REVOKE_ACTION_PREFIX,
    V4FolderAclRevokeActionConfigurationError,
    build_v4_folder_acl_revoke_action,
    load_v4_folder_acl_revoke_action_feature,
)
from .classification_tag_mcp_action import (
    V4_CLASSIFICATION_TAG_ACTION_FEATURE_ENV,
    V4_CLASSIFICATION_TAG_DELETE_ACTION_FEATURE_ENV,
    V4_CLASSIFICATION_TAG_DELETE_EXECUTION_ENV,
    V4_CLASSIFICATION_TAG_DELETE_SELECTOR_PREFIX,
    V4ClassificationTagActionConfigurationError,
    build_v4_classification_tag_action,
    load_v4_classification_tag_action_feature,
)
from .classification_tag_assign_mcp_action import (
    V4_CLASSIFICATION_TAG_ASSIGN_ACTION_FEATURE_ENV,
    V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_SELECTOR_PREFIX,
    V4ClassificationTagAssignActionConfigurationError,
    build_v4_classification_tag_assign_action,
    load_v4_classification_tag_assign_action_feature,
)
from .folder_rename_mcp_action import (
    V4_FOLDER_RENAME_ACTION_FEATURE_ENV,
    V4FolderRenameActionConfigurationError,
    build_v4_folder_rename_action,
    load_v4_folder_rename_action_feature,
)
from .folder_archive_mcp_action import (
    V4_FOLDER_ARCHIVE_ACTION_FEATURE_ENV,
    V4FolderArchiveActionConfigurationError,
    build_v4_folder_archive_action,
    load_v4_folder_archive_action_feature,
)
from .folder_policy_assign_mcp_action import (
    V4_FOLDER_POLICY_ASSIGN_ACTION_PREFIX,
    V4FolderPolicyAssignActionConfigurationError,
    build_v4_folder_policy_assign_action,
    load_v4_folder_policy_assign_action_feature,
)
from .folder_policy_detach_mcp_action import (
    V4_FOLDER_POLICY_DETACH_ACTION_PREFIX,
    V4FolderPolicyDetachActionConfigurationError,
    build_v4_folder_policy_detach_action,
    load_v4_folder_policy_detach_action_feature,
)
from .folder_mcp_action import (
    V4_FOLDER_ACTION_PREFIX,
    V4_FOLDER_EXECUTION_ENV,
    V4FolderActionConfigurationError,
    build_v4_folder_action,
    load_v4_folder_action_feature,
)
from .onboarding_execution_mcp_action import (
    ProtectedAccessDomainOnboardingMcpAction,
    ProtectedSecretOnboardingMcpAction,
    V4_ONBOARDING_EXECUTION_PREFIX,
    V4OnboardingExecutionConfigurationError,
    load_v4_access_domain_authorized_scope,
    load_v4_onboarding_execution_feature,
    load_v4_onboarding_execution_gate,
)
from .approval_and_observe_execution_mcp_action import (
    ProtectedApprovalAndObserveMcpAction,
    V4ApprovalAndObserveExecutionConfigurationError,
    load_v4_approval_and_observe_execution_feature,
)
from .onboarding_action_coordinator import OnboardingActionCoordinatorError
from .ad_discovery_mcp_action import (
    ProtectedAdDiscoveryMcpAction,
    load_v4_ad_discovery_execution_feature,
)
from .secret_onboarding_action_sequence import (
    SecretOnboardingFixedActionSequenceResolver,
)
from .local_user_mcp_action import (
    V4_LOCAL_USER_DISABLE_ACTION_PREFIX,
    V4LocalUserDisableActionConfigurationError,
    build_v4_local_user_disable_action,
    load_v4_local_user_disable_action_feature,
)
from .local_user_http_transport import ENV_PREFIX as LOCAL_USER_TRANSPORT_ENV_PREFIX
from .local_user_create_mcp_action import (
    V4_LOCAL_USER_CREATE_ACTION_PREFIX,
    V4LocalUserCreateActionConfigurationError,
    build_v4_local_user_create_action,
    load_v4_local_user_create_action_feature,
)
from .local_user_reset_mcp_action import (
    V4_LOCAL_USER_RESET_ACTION_PREFIX,
    V4LocalUserResetActionConfigurationError,
    build_v4_local_user_reset_action,
    load_v4_local_user_reset_action_feature,
)
from .local_user_create_ssh_transport import (
    ENV_PREFIX as LOCAL_USER_CREATE_TRANSPORT_ENV_PREFIX,
)
from .role_create_mcp_action import (
    V4_ROLE_CREATE_ACTION_PREFIX,
    V4RoleCreateActionConfigurationError,
    build_v4_role_create_action,
    load_v4_role_create_action_feature,
)
from .role_create_ssh_transport import (
    ENV_PREFIX as ROLE_CREATE_TRANSPORT_ENV_PREFIX,
    UPDATE_ENV_PREFIX as ROLE_UPDATE_TRANSPORT_ENV_PREFIX,
)
from .role_update_mcp_action import (
    V4_ROLE_UPDATE_ACTION_PREFIX,
    V4RoleUpdateActionConfigurationError,
    build_v4_role_update_action,
    load_v4_role_update_action_feature,
)
from .role_assign_mcp_action import (
    V4_ROLE_ASSIGN_ACTION_PREFIX,
    V4RoleAssignActionConfigurationError,
    build_v4_role_assign_action,
    load_v4_role_assign_action_feature,
)
from .role_assign_http_transport import ENV_PREFIX as ROLE_ASSIGN_TRANSPORT_ENV_PREFIX
from .dlp_file_pattern_mcp_action import (
    V4_DLP_FILE_PATTERN_ACTION_PREFIX,
    V4DlpFilePatternActionConfigurationError,
    build_v4_dlp_file_pattern_action,
    load_v4_dlp_file_pattern_action_feature,
)
from .dlp_file_pattern_ssh_transport import (
    ENV_PREFIX as DLP_FILE_PATTERN_TRANSPORT_ENV_PREFIX,
)
from .dlp_sensor_mcp_action import (
    V4_DLP_SENSOR_ACTION_PREFIX,
    V4DlpSensorActionConfigurationError,
    build_v4_dlp_sensor_action,
    load_v4_dlp_sensor_action_feature,
)
from .dlp_sensor_ssh_transport import ENV_PREFIX as DLP_SENSOR_TRANSPORT_ENV_PREFIX
from .antivirus_profile_mcp_action import (
    V4_ANTIVIRUS_PROFILE_ACTION_PREFIX,
    V4AntivirusProfileActionConfigurationError,
    build_v4_antivirus_profile_action,
    load_v4_antivirus_profile_action_feature,
)
from .antivirus_profile_ssh_transport import (
    ENV_PREFIX as ANTIVIRUS_PROFILE_TRANSPORT_ENV_PREFIX,
)
from .rdp_event_filter_mcp_action import (
    V4_RDP_EVENT_FILTER_ACTION_PREFIX,
    V4RdpEventFilterActionConfigurationError,
    build_v4_rdp_event_filter_action,
    load_v4_rdp_event_filter_action_feature,
)
from .rdp_event_filter_ssh_transport import (
    ENV_PREFIX as RDP_EVENT_FILTER_TRANSPORT_ENV_PREFIX,
    FortiPamRdpEventFilterSshTransport,
    RdpEventFilterSshTransportConfigurationError,
    load_rdp_event_filter_ssh_transport_config,
)
from .secret_policy_mcp_action import (
    V4_SECRET_POLICY_ACTION_PREFIX,
    V4SecretPolicyActionConfigurationError,
    build_v4_secret_policy_action,
    load_v4_secret_policy_action_feature,
)
from .secret_policy_ssh_transport import (
    ENV_PREFIX as SECRET_POLICY_TRANSPORT_ENV_PREFIX,
    FortiPamSecretPolicySshTransport,
    SecretPolicySshTransportConfigurationError,
    load_secret_policy_ssh_transport_config,
)
from .ssh_filter_mcp_action import (
    V4_SSH_FILTER_ACTION_PREFIX,
    V4SshFilterActionConfigurationError,
    build_v4_ssh_filter_action,
    load_v4_ssh_filter_action_feature,
)
from .ssh_filter_ssh_transport import (
    ENV_PREFIX as SSH_FILTER_TRANSPORT_ENV_PREFIX,
)
from .launcher_mcp_action import (
    V4_LAUNCHER_ACTION_PREFIX,
    V4LauncherActionConfigurationError,
    build_v4_launcher_action,
    load_v4_launcher_action_feature,
)
from .launcher_update_mcp_action import (
    V4_LAUNCHER_UPDATE_ACTION_PREFIX,
    V4LauncherUpdateActionConfigurationError,
    build_v4_launcher_update_action,
    load_v4_launcher_update_action_feature,
)
from .launcher_matcher_mcp_action import (
    V4_LAUNCHER_MATCHER_ACTION_PREFIX,
    V4LauncherMatcherActionConfigurationError,
    build_v4_launcher_matcher_action,
    load_v4_launcher_matcher_action_feature,
)
from .launcher_ssh_transport import (
    ENV_PREFIX as LAUNCHER_TRANSPORT_ENV_PREFIX,
    FortiPamLauncherSshTransport,
    LauncherSshTransportConfigurationError,
    MATCHER_ENV_PREFIX as LAUNCHER_MATCHER_TRANSPORT_ENV_PREFIX,
    UPDATE_ENV_PREFIX as LAUNCHER_UPDATE_TRANSPORT_ENV_PREFIX,
    load_launcher_ssh_transport_config,
)
from .template_mcp_action import (
    V4_TEMPLATE_ACTION_PREFIX,
    V4TemplateActionConfigurationError,
    build_v4_template_action,
    load_v4_template_action_feature,
)
from .template_archive_mcp_action import (
    V4_TEMPLATE_ARCHIVE_ACTION_PREFIX,
    V4TemplateArchiveActionConfigurationError,
    build_v4_template_archive_action,
    load_v4_template_archive_action_feature,
)
from .template_archive_http_transport import (
    ENV_PREFIX as TEMPLATE_ARCHIVE_HTTP_TRANSPORT_ENV_PREFIX,
)
from .template_ssh_transport import (
    ENV_PREFIX as TEMPLATE_TRANSPORT_ENV_PREFIX,
    TEMPLATE_ARCHIVE_SSH_ENV_PREFIX,
)
from .dependency_updater_mcp_action import (
    V4_DEPENDENCY_UPDATER_ACTION_PREFIX,
    V4DependencyUpdaterActionConfigurationError,
    build_v4_dependency_updater_action,
    load_v4_dependency_updater_action_feature,
)
from .dependency_updater_ssh_transport import (
    ENV_PREFIX as DEPENDENCY_UPDATER_TRANSPORT_ENV_PREFIX,
)
from .secret_gateway_mcp_action import (
    V4_SECRET_GATEWAY_ACTION_PREFIX,
    V4SecretGatewayActionConfigurationError,
    build_v4_secret_gateway_action,
    load_v4_secret_gateway_action_feature,
)
from .secret_gateway_ssh_transport import (
    ENV_PREFIX as SECRET_GATEWAY_TRANSPORT_ENV_PREFIX,
)
from .client_integrity_mcp_action import (
    V4_CLIENT_INTEGRITY_ACTION_PREFIX,
    V4ClientIntegrityActionConfigurationError,
    build_v4_client_integrity_action,
    load_v4_client_integrity_action_feature,
)
from .client_integrity_ssh_transport import (
    ENV_PREFIX as CLIENT_INTEGRITY_TRANSPORT_ENV_PREFIX,
)
from .character_set_mcp_action import (
    V4_CHARACTER_SET_ACTION_PREFIX,
    V4CharacterSetActionConfigurationError,
    build_v4_character_set_action,
    load_v4_character_set_action_feature,
)
from .character_set_http_transport import (
    ENV_PREFIX as CHARACTER_SET_TRANSPORT_ENV_PREFIX,
)
from .windows_app_filter_mcp_action import (
    V4_WINDOWS_APP_FILTER_ACTION_PREFIX,
    V4WindowsAppFilterActionConfigurationError,
    build_v4_windows_app_filter_action,
    load_v4_windows_app_filter_action_feature,
)
from .windows_app_filter_http_transport import (
    ENV_PREFIX as WINDOWS_APP_FILTER_TRANSPORT_ENV_PREFIX,
)
from .recording_policy_mcp_action import (
    V4_RECORDING_POLICY_ACTION_PREFIX,
    V4RecordingPolicyActionConfigurationError,
    build_v4_recording_policy_action,
    load_v4_recording_policy_action_feature,
)
from .recording_policy_http_transport import (
    ENV_PREFIX as RECORDING_POLICY_TRANSPORT_ENV_PREFIX,
    FortiPamRecordingPolicyHttpTransport,
    RecordingPolicyHttpTransportConfigurationError,
    load_recording_policy_http_transport_config,
)
from .password_policy_mcp_action import (
    V4_PASSWORD_POLICY_ACTION_PREFIX,
    V4PasswordPolicyActionConfigurationError,
    build_v4_password_policy_action,
    load_v4_password_policy_action_feature,
)
from .password_policy_http_transport import (
    ENV_PREFIX as PASSWORD_POLICY_TRANSPORT_ENV_PREFIX,
)
from .report_layout_mcp_action import (
    V4_REPORT_LAYOUT_ACTION_PREFIX,
    V4ReportLayoutActionConfigurationError,
    build_v4_report_layout_action,
    load_v4_report_layout_action_feature,
)
from .ztna_access_proxy_client_certificate_mcp_action import (
    V4_ZTNA_ACCESS_PROXY_ACTION_PREFIX,
    V4ZtnaAccessProxyActionConfigurationError,
    build_v4_ztna_access_proxy_action,
    load_v4_ztna_access_proxy_action_feature,
)
from .ztna_access_proxy_client_certificate_ssh_transport import (
    ENV_PREFIX as ZTNA_ACCESS_PROXY_TRANSPORT_ENV_PREFIX,
)
from .ztna_user_control_mcp_action import (
    V4_ZTNA_USER_CONTROL_ACTION_PREFIX,
    V4ZtnaUserControlActionConfigurationError,
    build_v4_ztna_user_control_action,
    load_v4_ztna_user_control_action_feature,
)
from .ztna_user_control_ssh_transport import (
    ENV_PREFIX as ZTNA_USER_CONTROL_TRANSPORT_ENV_PREFIX,
)
from .ztna_wad_debug_mcp_action import (
    V4_ZTNA_WAD_DEBUG_ACTION_PREFIX,
    V4ZtnaWadDebugActionConfigurationError,
    build_v4_ztna_wad_debug_action,
    load_v4_ztna_wad_debug_action_feature,
)
from .ztna_wad_debug_ssh_transport import (
    ENV_PREFIX as ZTNA_WAD_DEBUG_TRANSPORT_ENV_PREFIX,
)
from .snmp_agent_mcp_action import (
    V4_SNMP_AGENT_ACTION_PREFIX,
    V4SnmpAgentActionConfigurationError,
    build_v4_snmp_agent_action,
    load_v4_snmp_agent_action_feature,
)
from .snmp_agent_status_http_transport import (
    ENV_PREFIX as SNMP_AGENT_STATUS_HTTP_TRANSPORT_ENV_PREFIX,
)
from .snmp_agent_ssh_transport import ENV_PREFIX as SNMP_AGENT_TRANSPORT_ENV_PREFIX
from .logging_disk_mcp_action import (
    V4_LOGGING_DISK_ACTION_PREFIX,
    V4LoggingDiskActionConfigurationError,
    build_v4_logging_disk_action,
    load_v4_logging_disk_action_feature,
)
from .logging_disk_ssh_transport import ENV_PREFIX as LOGGING_DISK_TRANSPORT_ENV_PREFIX
from .fortianalyzer_mcp_action import (
    V4_FORTIANALYZER_ACTION_PREFIX,
    V4FortiAnalyzerActionConfigurationError,
    build_v4_fortianalyzer_action,
    load_v4_fortianalyzer_action_feature,
)
from .fortianalyzer_ssh_transport import (
    ENV_PREFIX as FORTIANALYZER_TRANSPORT_ENV_PREFIX,
)
from .maintenance_mode_mcp_action import (
    V4_MAINTENANCE_MODE_ACTION_PREFIX,
    V4MaintenanceModeActionConfigurationError,
    build_v4_maintenance_mode_action,
    load_v4_maintenance_mode_action_feature,
)
from .maintenance_mode_status_http_transport import (
    ENV_PREFIX as MAINTENANCE_MODE_STATUS_HTTP_TRANSPORT_ENV_PREFIX,
)
from .maintenance_mode_ssh_transport import (
    ENV_PREFIX as MAINTENANCE_MODE_TRANSPORT_ENV_PREFIX,
)
from .secret_audit_mcp_action import (
    V4_SECRET_AUDIT_ACTION_PREFIX,
    V4SecretAuditActionConfigurationError,
    build_v4_secret_audit_action,
    load_v4_secret_audit_action_feature,
)
from .terraform_plan_report_mcp_read import (
    ProtectedTerraformPlanReport, TerraformPlanReportError,
    build_terraform_plan_report, load_terraform_plan_report_feature,
)
from .secret_audit_summary_mcp_read import (
    V4_SECRET_AUDIT_SUMMARY_FEATURE_ENV,
    V4SecretAuditSummaryError,
    build_v4_secret_audit_summary_read,
    load_v4_secret_audit_summary_feature,
)
from .secret_audit_ssh_transport import (
    ENV_PREFIX as SECRET_AUDIT_TRANSPORT_ENV_PREFIX,
)
from .active_launch_mcp_action import (
    V4_ACTIVE_LAUNCH_ACTION_PREFIX,
    V4ActiveLaunchActionConfigurationError,
    build_v4_active_launch_action,
    load_v4_active_launch_action_feature,
)
from .active_launch_ssh_transport import (
    ENV_PREFIX as ACTIVE_LAUNCH_TRANSPORT_ENV_PREFIX,
)
from .automation_trigger_mcp_action import (
    V4_AUTOMATION_TRIGGER_ACTION_PREFIX,
    V4AutomationTriggerActionConfigurationError,
    build_v4_automation_trigger_action,
    load_v4_automation_trigger_action_feature,
)
from .automation_trigger_ssh_transport import (
    ENV_PREFIX as AUTOMATION_TRIGGER_TRANSPORT_ENV_PREFIX,
)
from .automation_action_mcp_action import (
    V4_AUTOMATION_ACTION_ACTION_PREFIX,
    V4AutomationActionActionConfigurationError,
    build_v4_automation_action_action,
    load_v4_automation_action_action_feature,
)
from .automation_action_ssh_transport import (
    ENV_PREFIX as AUTOMATION_ACTION_TRANSPORT_ENV_PREFIX,
)
from .automation_stitch_mcp_action import (
    V4_AUTOMATION_STITCH_ACTION_PREFIX,
    V4AutomationStitchActionConfigurationError,
    build_v4_automation_stitch_action,
    load_v4_automation_stitch_action_feature,
)
from .automation_stitch_ssh_transport import (
    ENV_PREFIX as AUTOMATION_STITCH_TRANSPORT_ENV_PREFIX,
)
from .user_group_mcp_action import (
    V4_USER_GROUP_ACTION_PREFIX,
    V4UserGroupActionConfigurationError,
    build_v4_user_group_action,
    load_v4_user_group_action_feature,
)
from .user_group_ssh_transport import (
    ENV_PREFIX as USER_GROUP_TRANSPORT_ENV_PREFIX,
    MEMBERSHIP_ENV_PREFIX as USER_GROUP_MEMBERSHIP_TRANSPORT_ENV_PREFIX,
)
from .user_group_membership_mcp_action import (
    V4_USER_GROUP_MEMBERSHIP_ACTION_PREFIX,
    V4UserGroupMembershipActionConfigurationError,
    build_v4_user_group_membership_action,
    load_v4_user_group_membership_action_feature,
)
from .apl_mcp_action import (
    V4_APL_ACTION_PREFIX,
    V4AplActionConfigurationError,
    build_v4_apl_action,
    load_v4_apl_action_feature,
)
from .apl_disable_mcp_action import (
    V4_APL_DISABLE_ACTION_PREFIX,
    V4AplDisableActionConfigurationError,
    build_v4_apl_disable_action,
    load_v4_apl_disable_action_feature,
)
from .apl_ssh_transport import (
    DISABLE_ENV_PREFIX as APL_DISABLE_TRANSPORT_ENV_PREFIX,
    ENV_PREFIX as APL_TRANSPORT_ENV_PREFIX,
)
from .schedule_mcp_action import (
    V4_SCHEDULE_ACTION_PREFIX,
    V4ScheduleActionConfigurationError,
    build_v4_schedule_action,
    load_v4_schedule_action_feature,
)
from .schedule_assign_mcp_action import (
    V4_SCHEDULE_ASSIGN_ACTION_FEATURE_ENV,
    V4ScheduleAssignActionConfigurationError,
    build_v4_schedule_assign_action,
    load_v4_schedule_assign_action_feature,
)
from .schedule_assign_http_transport import (
    ENV_PREFIX as SCHEDULE_ASSIGN_TRANSPORT_ENV_PREFIX,
)
from .schedule_ssh_transport import (
    ENV_PREFIX as SCHEDULE_TRANSPORT_ENV_PREFIX,
)
from .approval_profile_mcp_action import (
    V4_APPROVAL_PROFILE_ACTION_PREFIX,
    V4ApprovalProfileActionConfigurationError,
    build_v4_approval_profile_action,
    load_v4_approval_profile_action_feature,
)
from .approval_profile_ssh_transport import (
    ENV_PREFIX as APPROVAL_PROFILE_TRANSPORT_ENV_PREFIX,
    UPDATE_ENV_PREFIX as APPROVAL_PROFILE_UPDATE_TRANSPORT_ENV_PREFIX,
    ApprovalProfileSshTransportConfigurationError,
    FortiPamApprovalProfileSshTransport,
    load_approval_profile_ssh_transport_config,
)
from .approval_profile_http_transport import (
    FortiPamApprovalProfileHttpTransport,
)
from .approval_profile_update_mcp_action import (
    V4_APPROVAL_PROFILE_UPDATE_ACTION_PREFIX,
    V4ApprovalProfileUpdateActionConfigurationError,
    build_v4_approval_profile_update_action,
    load_v4_approval_profile_update_action_feature,
)
from .approval_email_template_mcp_action import (
    V4_APPROVAL_EMAIL_TEMPLATE_ACTION_PREFIX,
    V4ApprovalEmailTemplateActionConfigurationError,
    build_v4_approval_email_template_action,
    load_v4_approval_email_template_action_feature,
)
from .approval_email_template_ssh_transport import (
    ENV_PREFIX as APPROVAL_EMAIL_TEMPLATE_TRANSPORT_ENV_PREFIX,
    UPDATE_ENV_PREFIX as APPROVAL_EMAIL_TEMPLATE_UPDATE_TRANSPORT_ENV_PREFIX,
)
from .approval_email_template_update_mcp_action import (
    V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_PREFIX,
    V4ApprovalEmailTemplateUpdateActionConfigurationError,
    build_v4_approval_email_template_update_action,
    load_v4_approval_email_template_update_action_feature,
)
from .target_mcp_action import (
    V4_TARGET_ACTION_FEATURE_ENV,
    V4_TARGET_DELETE_ACTION_FEATURE_ENV,
    V4_TARGET_DELETE_EXECUTION_ENV,
    V4_TARGET_DELETE_SELECTOR_PREFIX,
    V4_TARGET_EXECUTION_ENV,
    V4TargetActionConfigurationError,
    build_v4_target_action,
    load_v4_target_action_feature,
)
from .target_http_transport import (
    ENV_PREFIX as TARGET_TRANSPORT_ENV_PREFIX,
    FortiPamTargetHttpTransport,
    TargetHttpTransportConfigurationError,
    load_target_http_transport_config,
)
from .target_ssh_transport import ENV_PREFIX as TARGET_SSH_TRANSPORT_ENV_PREFIX
from .secret_metadata_mcp_action import (
    V4_SECRET_METADATA_ACTION_FEATURE_ENV,
    V4SecretMetadataActionConfigurationError,
    build_v4_secret_metadata_action,
    load_v4_secret_metadata_action_feature,
)
from .secret_metadata_http_transport import (
    ENV_PREFIX as SECRET_METADATA_TRANSPORT_ENV_PREFIX,
    FortiPamSecretMetadataHttpTransport,
    SecretMetadataHttpTransportConfigurationError,
    load_secret_metadata_http_transport_config,
)
from .secret_request_http_transport import (
    OwnerOnlySecretRequestObservationBindingResolver,
)
from .secret_request_mcp_observation import (
    ProtectedSecretRequestMcpObservation,
    build_v4_secret_request_observation_transport,
)
from .secret_request_create_mcp_action import (
    V4_SECRET_REQUEST_CREATE_PREFIX,
    V4SecretRequestCreateConfigurationError,
    build_v4_secret_request_create_action,
    load_v4_secret_request_create_feature,
)
from .secret_create_191_private_adapter import load_winrm_collector_private_binding
from .domain_secret_projection_reader import (
    DomainSecretPlanningSource, load_domain_secret_planning_binding,
)
from .target_bound_web_projection_reader import (
    TargetBoundWebPlanningSource, load_target_bound_web_planning_binding,
)
from .secret_create_lab_auto_runtime import (
    LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_PROFILE,
    LAB_AUTO_SECRET_CREATE_WINRM_700_CANDIDATE_PROFILE,
    LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE,
    LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE,
    LAB_AUTO_SECRET_CREATE_DOMAIN_700_PROFILE,
    LAB_AUTO_SECRET_CREATE_ENV_PREFIX,
    build_fortipam_191_lab_auto_secret_runner_factory,
    load_lab_auto_secret_create_authorized_scope,
)
from .secret_session_controls_ssh_transport import (
    FortiPamSecretSessionControlsSshTransport,
    load_secret_session_controls_ssh_transport_config,
)
from .secret_session_controls_lab_auto_runtime import (
    build_lab_auto_secret_session_controls_runner_factory,
)
from .web_secret_service_lab_auto_runtime import (
    build_lab_auto_web_secret_service_runner_factory,
)
from .interface_web_proxy_mcp_action import (
    V4_INTERFACE_WEB_PROXY_ACTION_FEATURE_ENV,
    V4InterfaceWebProxyActionConfigurationError,
    build_v4_interface_web_proxy_action,
    load_v4_interface_web_proxy_action_feature,
)
from .interface_web_proxy_ssh_transport import (
    ENV_PREFIX as INTERFACE_WEB_PROXY_TRANSPORT_ENV_PREFIX,
)
from .target_update_mcp_action import (
    V4_TARGET_UPDATE_ACTION_FEATURE_ENV,
    V4TargetUpdateActionConfigurationError,
    build_v4_target_update_action,
    load_v4_target_update_action_feature,
)
from .certificate_csr_mcp_action import (
    V4_CERTIFICATE_CSR_ACTION_FEATURE_ENV,
    V4CertificateCsrActionConfigurationError,
    build_v4_certificate_csr_action,
    load_v4_certificate_csr_action_feature,
)
from .certificate_csr_http_transport import (
    ENV_PREFIX as CERTIFICATE_CSR_TRANSPORT_ENV_PREFIX,
)
from .local_oauth import (
    LocalOAuthConfigurationError,
    LocalOAuthProvider,
    LocalOAuthSettings,
    local_oauth_settings_from_environment,
)
from .runtime_profile import (
    RUNTIME_PROFILE_ENV,
    RuntimeProfile,
    RuntimeProfileError,
    load_runtime_profile,
)
from .server import FortiPamMcpServer
from .v4_confirmation_http import (
    LocalIntentConfirmationService,
    V4ConfirmationHttpError,
    V4ConfirmationSettings,
    confirmation_settings_from_environment,
)
from .v4_runtime_host import (
    V4PlanHostComponents,
    V4RuntimeHostError,
    V4_SYNTHETIC_HOST_MODE_ENV,
    access_domain_v4_plan_host_factory,
    approval_and_observe_v4_plan_host_factory,
    secret_approval_build29_v4_plan_host_factory,
    onboarding_v4_plan_host_factory,
    secret_onboarding_v4_plan_host_factory,
    target_bound_web_v4_plan_host_factory,
    domain_secret_v4_plan_host_factory,
    synthetic_host_settings_from_environment,
    synthetic_v4_plan_host_factory,
)
from .access_domain_projection_source import (
    AccessDomainProjectionSourceError,
    OwnerOnlyAccessDomainBindingResolver,
)
from .secret_onboarding_projection_source import (
    OwnerOnlySecretOnboardingBindingResolver,
    SecretOnboardingProjectionSourceError,
)
from .approval_and_observe_projection_source import (
    ApprovalAndObserveProjectionSourceError,
    OwnerOnlyApprovalAndObserveBindingResolver,
)

HTTP_PREFIX = "FORTIPAM_MCP_HTTP_"
HTTP_ENV_FILE_VARIABLE = f"{HTTP_PREFIX}ENV_FILE"
DEFAULT_PATH = "/mcp"
DEFAULT_PORT = 8000
DEFAULT_SCOPE = "fortipam:read"
V4_PLANNING_ENV_PREFIX = "FORTIPAM_MCP_V4_PLAN_"
SAFE_JWT_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"}
)


class HttpConfigurationError(ValueError):
    """Raised when the remote MCP listener would be unsafe or incomplete."""


@dataclass(frozen=True, slots=True)
class HttpServerSettings:
    """Validated Streamable HTTP settings without secret disclosure."""

    host: str
    port: int
    path: str
    auth_mode: str
    bearer_token: str | None
    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...]
    public_url: str | None
    oauth_issuer: str | None
    oauth_jwks_url: str | None
    oauth_audience: str | None
    oauth_required_scopes: tuple[str, ...]
    oauth_algorithms: tuple[str, ...]
    local_oauth: LocalOAuthSettings | None
    diagnostic: DiagnosticServiceSettings | None
    controlled_operation: ApprovalServiceSettings | None
    runtime_profile: RuntimeProfile
    v4_planning_authorization: Any
    v4_confirmation: V4ConfirmationSettings | None
    v4_onboarding_execution_enabled: bool = False
    v4_approval_and_observe_execution_enabled: bool = False
    v4_ad_discovery_execution_enabled: bool = False
    v4_folder_action_enabled: bool = False
    v4_folder_acl_action_enabled: bool = False
    v4_folder_acl_revoke_action_enabled: bool = False
    v4_classification_tag_action_enabled: bool = False
    v4_classification_tag_assign_action_enabled: bool = False
    v4_address_action_enabled: bool = False
    v4_address_group_action_enabled: bool = False
    v4_ztna_device_context_diagnostic_enabled: bool = False
    v4_ha_reconciliation_enabled: bool = False
    v4_ha_reconciliation_prerequisite_provider: OwnerOnlyHaReconciliationPrerequisiteProvider | None = None
    v4_ha_reconciliation_query_permission_provider: OwnerOnlyHaReconciliationQueryPermissionProvider | None = None
    v4_ztna_folder_posture_enabled: bool = False
    v4_folder_rename_action_enabled: bool = False
    v4_folder_archive_action_enabled: bool = False
    v4_folder_policy_assign_action_enabled: bool = False
    v4_folder_policy_detach_action_enabled: bool = False
    v4_target_action_enabled: bool = False
    v4_secret_metadata_action_enabled: bool = False
    v4_interface_web_proxy_action_enabled: bool = False
    v4_target_update_action_enabled: bool = False
    v4_certificate_csr_action_enabled: bool = False
    v4_local_user_disable_action_enabled: bool = False
    v4_local_user_create_action_enabled: bool = False
    v4_local_user_reset_action_enabled: bool = False
    v4_role_create_action_enabled: bool = False
    v4_role_update_action_enabled: bool = False
    v4_role_assign_action_enabled: bool = False
    v4_dlp_file_pattern_action_enabled: bool = False
    v4_dlp_sensor_action_enabled: bool = False
    v4_antivirus_profile_action_enabled: bool = False
    v4_rdp_event_filter_action_enabled: bool = False
    v4_secret_policy_action_enabled: bool = False
    v4_ssh_filter_action_enabled: bool = False
    v4_launcher_action_enabled: bool = False
    v4_launcher_update_action_enabled: bool = False
    v4_launcher_matcher_action_enabled: bool = False
    v4_template_action_enabled: bool = False
    v4_template_archive_action_enabled: bool = False
    v4_dependency_updater_action_enabled: bool = False
    v4_secret_gateway_action_enabled: bool = False
    v4_client_integrity_action_enabled: bool = False
    v4_character_set_action_enabled: bool = False
    v4_windows_app_filter_action_enabled: bool = False
    v4_recording_policy_action_enabled: bool = False
    v4_password_policy_action_enabled: bool = False
    v4_report_layout_action_enabled: bool = False
    v4_ztna_access_proxy_action_enabled: bool = False
    v4_ztna_user_control_action_enabled: bool = False
    v4_ztna_wad_debug_action_enabled: bool = False
    v4_snmp_agent_action_enabled: bool = False
    v4_logging_disk_action_enabled: bool = False
    v4_fortianalyzer_action_enabled: bool = False
    v4_maintenance_mode_action_enabled: bool = False
    v4_secret_audit_action_enabled: bool = False
    v4_secret_audit_summary_enabled: bool = False
    v4_terraform_plan_report_enabled: bool = False
    v4_active_launch_action_enabled: bool = False
    v4_automation_trigger_action_enabled: bool = False
    v4_automation_action_action_enabled: bool = False
    v4_automation_stitch_action_enabled: bool = False
    v4_user_group_action_enabled: bool = False
    v4_user_group_membership_action_enabled: bool = False
    v4_apl_action_enabled: bool = False
    v4_apl_disable_action_enabled: bool = False
    v4_schedule_action_enabled: bool = False
    v4_schedule_assign_action_enabled: bool = False
    v4_approval_profile_action_enabled: bool = False
    v4_approval_profile_update_action_enabled: bool = False
    v4_approval_email_template_action_enabled: bool = False
    v4_approval_email_template_update_action_enabled: bool = False
    v4_secret_request_create_enabled: bool = False

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str] | None = None,
    ) -> "HttpServerSettings":
        """Load and validate remote transport configuration."""

        env = os.environ if environment is None else environment
        try:
            runtime_profile = load_runtime_profile(env)
        except RuntimeProfileError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        host = _value(env, "HOST") or "127.0.0.1"
        port = _port(_value(env, "PORT"))
        path = _path(_value(env, "PATH") or DEFAULT_PATH)
        auth_mode = (_value(env, "AUTH_MODE") or "bearer").lower()
        if auth_mode not in {"none", "bearer", "oauth", "local_oauth"}:
            raise HttpConfigurationError(
                "FORTIPAM_MCP_HTTP_AUTH_MODE must be none, bearer, oauth, or local_oauth."
            )
        insecure_private_ip_lab = _insecure_private_ip_lab_enabled(env)

        allowed_hosts = _csv(_value(env, "ALLOWED_HOSTS"))
        if not allowed_hosts:
            if _is_loopback(host):
                allowed_hosts = (f"127.0.0.1:{port}", f"localhost:{port}")
            else:
                raise HttpConfigurationError(
                    "Non-loopback HTTP listeners require explicit allowed hosts."
                )

        bearer_token = _value(env, "BEARER_TOKEN")
        public_url = _optional_public_url(
            _value(env, "PUBLIC_URL"),
            "public URL",
            allow_insecure_private_ip_lab=insecure_private_ip_lab,
        )
        oauth_issuer = _optional_https_url(
            _value(env, "OAUTH_ISSUER"), "OAuth issuer"
        )
        oauth_jwks_url = _optional_https_url(
            _value(env, "OAUTH_JWKS_URL"), "OAuth JWKS URL"
        )
        oauth_audience = _optional_https_url(
            _value(env, "OAUTH_AUDIENCE"), "OAuth audience"
        )
        oauth_required_scopes = _csv(_value(env, "OAUTH_REQUIRED_SCOPES")) or (
            DEFAULT_SCOPE,
        )
        oauth_algorithms = _csv(_value(env, "OAUTH_ALGORITHMS")) or ("RS256",)
        allowed_origins = _csv(_value(env, "ALLOWED_ORIGINS"))
        if set(oauth_algorithms) - SAFE_JWT_ALGORITHMS:
            raise HttpConfigurationError(
                "OAuth algorithms must use an approved asymmetric JWT algorithm."
            )

        if auth_mode == "none" and not _is_loopback(host):
            raise HttpConfigurationError(
                "Unauthenticated Streamable HTTP is restricted to loopback."
            )
        if auth_mode == "bearer" and (bearer_token is None or len(bearer_token) < 32):
            raise HttpConfigurationError(
                "Bearer mode requires a token containing at least 32 characters."
            )
        if auth_mode == "oauth":
            missing = [
                label
                for label, value in (
                    ("PUBLIC_URL", public_url),
                    ("OAUTH_ISSUER", oauth_issuer),
                    ("OAUTH_JWKS_URL", oauth_jwks_url),
                    ("OAUTH_AUDIENCE", oauth_audience),
                )
                if value is None
            ]
            if missing:
                raise HttpConfigurationError(
                    "OAuth mode requires complete public URL, issuer, JWKS, and audience settings."
                )
            if public_url != oauth_audience:
                raise HttpConfigurationError(
                    "OAuth audience must exactly match the canonical MCP public URL."
                )
            if urlsplit(public_url).path != path:
                raise HttpConfigurationError(
                    "The public URL path must match the configured MCP endpoint path."
                )

        local_oauth: LocalOAuthSettings | None = None
        if auth_mode == "local_oauth":
            if public_url is None:
                raise HttpConfigurationError(
                    "Local OAuth mode requires the canonical MCP public URL."
                )
            if urlsplit(public_url).path != path:
                raise HttpConfigurationError(
                    "The public URL path must match the configured MCP endpoint path."
                )
            try:
                local_oauth = local_oauth_settings_from_environment(
                    env,
                    prefix=HTTP_PREFIX,
                    public_url=public_url,
                    allow_insecure_private_ip_lab=insecure_private_ip_lab,
                )
            except LocalOAuthConfigurationError as exc:
                raise HttpConfigurationError(str(exc)) from exc

        if insecure_private_ip_lab:
            if runtime_profile is not RuntimeProfile.V4_CONTROLLED or auth_mode != "local_oauth":
                raise HttpConfigurationError(
                    "The insecure private-IP lab exception requires v4-controlled local OAuth."
                )
            if public_url is None or not _is_private_lab_http_url(public_url):
                raise HttpConfigurationError(
                    "The insecure private-IP lab exception requires an HTTP 10/8 public URL."
                )
            public_host = urlsplit(public_url).hostname
            assert public_host is not None
            if allowed_hosts != (public_host,):
                raise HttpConfigurationError(
                    "The insecure private-IP lab exception requires one exact IP allowed host."
                )
            if allowed_origins != (f"http://{public_host}",):
                raise HttpConfigurationError(
                    "The insecure private-IP lab exception requires one exact IP allowed origin."
                )

        v4_http_profile = runtime_profile in {
            RuntimeProfile.V4_PLAN_ONLY,
            RuntimeProfile.V4_CONTROLLED,
        }
        if v4_http_profile and auth_mode != "local_oauth":
            raise HttpConfigurationError(
                "The V4 HTTP profile requires embedded local OAuth authentication."
            )

        try:
            v4_onboarding_execution_enabled = (
                load_v4_onboarding_execution_feature(env)
            )
        except V4OnboardingExecutionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if v4_onboarding_execution_enabled and (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            or auth_mode != "local_oauth"
            or _exact_value(env, V4_SYNTHETIC_HOST_MODE_ENV)
            not in {"source-backed-onboarding", "source-backed-secret-onboarding"}
        ):
            raise HttpConfigurationError(
                "Onboarding execution Tools require the v4-controlled local OAuth source-backed onboarding profile."
            )

        try:
            v4_ad_discovery_execution_enabled = load_v4_ad_discovery_execution_feature(env)
        except ValueError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if v4_ad_discovery_execution_enabled and (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            or auth_mode != "local_oauth"
            or _exact_value(env, V4_SYNTHETIC_HOST_MODE_ENV) != "source-backed-ad-discovery"
        ):
            raise HttpConfigurationError(
                "AD Discovery execution requires the v4-controlled local OAuth fixed AD host."
            )

        try:
            v4_approval_and_observe_execution_enabled = (
                load_v4_approval_and_observe_execution_feature(env)
            )
        except V4ApprovalAndObserveExecutionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if v4_approval_and_observe_execution_enabled and (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            or auth_mode != "local_oauth"
            or _exact_value(env, V4_SYNTHETIC_HOST_MODE_ENV)
            not in {"source-backed-approval-and-observe", "source-backed-approval-and-observe-build29"}
        ):
            raise HttpConfigurationError(
                "Approval execution Tool requires the v4-controlled local OAuth source-backed approval profile."
            )

        try:
            v4_secret_request_create_enabled = (
                load_v4_secret_request_create_feature(env)
            )
        except V4SecretRequestCreateConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if v4_secret_request_create_enabled and (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            or auth_mode != "local_oauth"
            or _exact_value(env, V4_SYNTHETIC_HOST_MODE_ENV)
            != "source-backed-approval-and-observe"
        ):
            raise HttpConfigurationError(
                "Secret Request Create requires the v4-controlled local OAuth source-backed approval profile."
            )

        try:
            v4_folder_action_enabled = load_v4_folder_action_feature(env)
        except V4FolderActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_folder_action_enabled
        ):
            raise HttpConfigurationError(
                "The child Folder feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_folder_acl_action_enabled = load_v4_folder_acl_action_feature(env)
        except V4FolderAclActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_folder_acl_action_enabled
        ):
            raise HttpConfigurationError(
                "The Folder ACL feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_folder_acl_revoke_action_enabled = (
                load_v4_folder_acl_revoke_action_feature(env)
            )
        except V4FolderAclRevokeActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_folder_acl_revoke_action_enabled
        ):
            raise HttpConfigurationError(
                "The Folder ACL revoke feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_classification_tag_action_enabled = (
                load_v4_classification_tag_action_feature(env)
            )
        except V4ClassificationTagActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_classification_tag_action_enabled
        ):
            raise HttpConfigurationError(
                "The Classification Tag feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_classification_tag_assign_action_enabled = (
                load_v4_classification_tag_assign_action_feature(env)
            )
        except V4ClassificationTagAssignActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_classification_tag_assign_action_enabled
        ):
            raise HttpConfigurationError(
                "The Classification Tag assignment feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_address_action_enabled = load_v4_address_action_feature(env)
        except V4AddressActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_address_action_enabled
        ):
            raise HttpConfigurationError(
                "The IPv4 Address feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_address_group_action_enabled = load_v4_address_group_action_feature(
                env
            )
        except V4AddressGroupActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_address_group_action_enabled
        ):
            raise HttpConfigurationError(
                "The Address Group feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_ztna_device_context_diagnostic_enabled = (
                load_v4_ztna_device_context_diagnostic_feature(env)
            )
        except ZtnaDeviceContextDiagnosticConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if not v4_http_profile and v4_ztna_device_context_diagnostic_enabled:
            raise HttpConfigurationError(
                "The ZTNA diagnostic feature may be enabled only by a V4 HTTP profile."
            )
        try:
            v4_ha_reconciliation_enabled = load_ha_reconciliation_feature(env)
            v4_ha_reconciliation_prerequisite_provider = (
                prerequisite_provider_from_environment(env)
            )
            v4_ha_reconciliation_query_permission_provider = (
                query_permission_provider_from_environment(env)
            )
        except HaReconciliationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        ha_reconciliation_providers_present = (
            v4_ha_reconciliation_prerequisite_provider is not None
            or v4_ha_reconciliation_query_permission_provider is not None
        )
        if not v4_http_profile and (
            v4_ha_reconciliation_enabled or ha_reconciliation_providers_present
        ):
            raise HttpConfigurationError(
                "HA reconciliation may be configured only by a V4 HTTP profile."
            )
        if not v4_ha_reconciliation_enabled and ha_reconciliation_providers_present:
            raise HttpConfigurationError(
                "HA reconciliation providers cannot be configured while the feature is disabled."
            )
        if v4_ha_reconciliation_enabled and not (
            v4_ha_reconciliation_prerequisite_provider is not None
            and v4_ha_reconciliation_query_permission_provider is not None
        ):
            raise HttpConfigurationError(
                "Enabled HA reconciliation requires both owner-only provider files."
            )
        try:
            v4_ztna_folder_posture_enabled = load_v4_ztna_folder_posture_feature(
                env
            )
        except ZtnaFolderControlPostureConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if not v4_http_profile and v4_ztna_folder_posture_enabled:
            raise HttpConfigurationError(
                "The ZTNA Folder posture diagnostic feature may be enabled only by a V4 HTTP profile."
            )
        try:
            v4_folder_rename_action_enabled = load_v4_folder_rename_action_feature(
                env
            )
        except V4FolderRenameActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_folder_rename_action_enabled
        ):
            raise HttpConfigurationError(
                "The Folder rename feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_folder_archive_action_enabled = load_v4_folder_archive_action_feature(
                env
            )
        except V4FolderArchiveActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_folder_archive_action_enabled
        ):
            raise HttpConfigurationError(
                "The Folder archive feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_folder_policy_assign_action_enabled = (
                load_v4_folder_policy_assign_action_feature(env)
            )
        except V4FolderPolicyAssignActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_folder_policy_assign_action_enabled
        ):
            raise HttpConfigurationError(
                "The Folder policy assignment feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_folder_policy_detach_action_enabled = (
                load_v4_folder_policy_detach_action_feature(env)
            )
        except V4FolderPolicyDetachActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_folder_policy_detach_action_enabled
        ):
            raise HttpConfigurationError(
                "The Folder policy detach feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_target_action_enabled = load_v4_target_action_feature(env)
        except V4TargetActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_target_action_enabled
        ):
            raise HttpConfigurationError(
                "The API Target feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_secret_metadata_action_enabled = (
                load_v4_secret_metadata_action_feature(env)
            )
        except V4SecretMetadataActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_secret_metadata_action_enabled
        ):
            raise HttpConfigurationError(
                "The Secret metadata feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_interface_web_proxy_action_enabled = (
                load_v4_interface_web_proxy_action_feature(env)
            )
        except V4InterfaceWebProxyActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_interface_web_proxy_action_enabled
        ):
            raise HttpConfigurationError(
                "The interface Explicit Web Proxy feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_target_update_action_enabled = load_v4_target_update_action_feature(env)
        except V4TargetUpdateActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_target_update_action_enabled
        ):
            raise HttpConfigurationError(
                "The API Target update feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_certificate_csr_action_enabled = (
                load_v4_certificate_csr_action_feature(env)
            )
        except V4CertificateCsrActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_certificate_csr_action_enabled
        ):
            raise HttpConfigurationError(
                "The certificate CSR feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_local_user_disable_action_enabled = (
                load_v4_local_user_disable_action_feature(env)
            )
        except V4LocalUserDisableActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_local_user_disable_action_enabled
        ):
            raise HttpConfigurationError(
                "The Local User disable feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_local_user_create_action_enabled = (
                load_v4_local_user_create_action_feature(env)
            )
        except V4LocalUserCreateActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_local_user_create_action_enabled
        ):
            raise HttpConfigurationError(
                "The Local User create feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_local_user_reset_action_enabled = (
                load_v4_local_user_reset_action_feature(env)
            )
        except V4LocalUserResetActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_local_user_reset_action_enabled
        ):
            raise HttpConfigurationError(
                "The Local User reset feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_role_create_action_enabled = load_v4_role_create_action_feature(env)
        except V4RoleCreateActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_role_create_action_enabled
        ):
            raise HttpConfigurationError(
                "The Role create feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_role_update_action_enabled = load_v4_role_update_action_feature(env)
        except V4RoleUpdateActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_role_update_action_enabled
        ):
            raise HttpConfigurationError(
                "The Role update feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_role_assign_action_enabled = load_v4_role_assign_action_feature(env)
        except V4RoleAssignActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_role_assign_action_enabled
        ):
            raise HttpConfigurationError(
                "The Role assignment feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_dlp_file_pattern_action_enabled = (
                load_v4_dlp_file_pattern_action_feature(env)
            )
        except V4DlpFilePatternActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_dlp_file_pattern_action_enabled
        ):
            raise HttpConfigurationError(
                "The DLP file-pattern feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_dlp_sensor_action_enabled = load_v4_dlp_sensor_action_feature(env)
        except V4DlpSensorActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if runtime_profile is not RuntimeProfile.V4_CONTROLLED and v4_dlp_sensor_action_enabled:
            raise HttpConfigurationError(
                "The DLP Sensor feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_antivirus_profile_action_enabled = (
                load_v4_antivirus_profile_action_feature(env)
            )
        except V4AntivirusProfileActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_antivirus_profile_action_enabled
        ):
            raise HttpConfigurationError(
                "The AntiVirus Profile feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_rdp_event_filter_action_enabled = (
                load_v4_rdp_event_filter_action_feature(env)
            )
        except V4RdpEventFilterActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_rdp_event_filter_action_enabled
        ):
            raise HttpConfigurationError(
                "The RDP event-filter feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_secret_policy_action_enabled = load_v4_secret_policy_action_feature(env)
        except V4SecretPolicyActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_secret_policy_action_enabled
        ):
            raise HttpConfigurationError(
                "The Secret Policy feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_ssh_filter_action_enabled = load_v4_ssh_filter_action_feature(env)
        except V4SshFilterActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_ssh_filter_action_enabled
        ):
            raise HttpConfigurationError(
                "The SSH Filter feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_launcher_action_enabled = load_v4_launcher_action_feature(env)
        except V4LauncherActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_launcher_action_enabled
        ):
            raise HttpConfigurationError(
                "The Launcher feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_launcher_update_action_enabled = (
                load_v4_launcher_update_action_feature(env)
            )
        except V4LauncherUpdateActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_launcher_update_action_enabled
        ):
            raise HttpConfigurationError(
                "The Launcher update feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_launcher_matcher_action_enabled = (
                load_v4_launcher_matcher_action_feature(env)
            )
        except V4LauncherMatcherActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_launcher_matcher_action_enabled
        ):
            raise HttpConfigurationError(
                "The Launcher matcher feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_template_action_enabled = load_v4_template_action_feature(env)
        except V4TemplateActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_template_action_enabled
        ):
            raise HttpConfigurationError(
                "The Template feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_template_archive_action_enabled = (
                load_v4_template_archive_action_feature(env)
            )
        except V4TemplateArchiveActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_template_archive_action_enabled
        ):
            raise HttpConfigurationError(
                "The Template archive feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_dependency_updater_action_enabled = (
                load_v4_dependency_updater_action_feature(env)
            )
        except V4DependencyUpdaterActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_dependency_updater_action_enabled
        ):
            raise HttpConfigurationError(
                "The Dependency Updater feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_secret_gateway_action_enabled = load_v4_secret_gateway_action_feature(
                env
            )
        except V4SecretGatewayActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_secret_gateway_action_enabled
        ):
            raise HttpConfigurationError(
                "The Secret Gateway feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_client_integrity_action_enabled = (
                load_v4_client_integrity_action_feature(env)
            )
        except V4ClientIntegrityActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_client_integrity_action_enabled
        ):
            raise HttpConfigurationError(
                "The client-integrity feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_character_set_action_enabled = load_v4_character_set_action_feature(env)
        except V4CharacterSetActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_character_set_action_enabled
        ):
            raise HttpConfigurationError(
                "The Character Set feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_windows_app_filter_action_enabled = (
                load_v4_windows_app_filter_action_feature(env)
            )
        except V4WindowsAppFilterActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_windows_app_filter_action_enabled
        ):
            raise HttpConfigurationError(
                "The Windows App Filter feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_recording_policy_action_enabled = (
                load_v4_recording_policy_action_feature(env)
            )
        except V4RecordingPolicyActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_recording_policy_action_enabled
        ):
            raise HttpConfigurationError(
                "The Recording Policy feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_password_policy_action_enabled = (
                load_v4_password_policy_action_feature(env)
            )
        except V4PasswordPolicyActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_password_policy_action_enabled
        ):
            raise HttpConfigurationError(
                "The Password Policy feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_report_layout_action_enabled = (
                load_v4_report_layout_action_feature(env)
            )
        except V4ReportLayoutActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_report_layout_action_enabled
        ):
            raise HttpConfigurationError(
                "The Report Layout feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_ztna_access_proxy_action_enabled = (
                load_v4_ztna_access_proxy_action_feature(env)
            )
        except V4ZtnaAccessProxyActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_ztna_access_proxy_action_enabled
        ):
            raise HttpConfigurationError(
                "The ZTNA Access Proxy feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_ztna_user_control_action_enabled = (
                load_v4_ztna_user_control_action_feature(env)
            )
        except V4ZtnaUserControlActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_ztna_user_control_action_enabled
        ):
            raise HttpConfigurationError(
                "The ZTNA user-control feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_ztna_wad_debug_action_enabled = (
                load_v4_ztna_wad_debug_action_feature(env)
            )
        except V4ZtnaWadDebugActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_ztna_wad_debug_action_enabled
        ):
            raise HttpConfigurationError(
                "The ZTNA WAD debug feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_snmp_agent_action_enabled = load_v4_snmp_agent_action_feature(env)
        except V4SnmpAgentActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_snmp_agent_action_enabled
        ):
            raise HttpConfigurationError(
                "The SNMP agent feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_logging_disk_action_enabled = load_v4_logging_disk_action_feature(env)
        except V4LoggingDiskActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_logging_disk_action_enabled
        ):
            raise HttpConfigurationError(
                "The logging-disk feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_fortianalyzer_action_enabled = load_v4_fortianalyzer_action_feature(env)
        except V4FortiAnalyzerActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_fortianalyzer_action_enabled
        ):
            raise HttpConfigurationError(
                "The FortiAnalyzer feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_maintenance_mode_action_enabled = (
                load_v4_maintenance_mode_action_feature(env)
            )
        except V4MaintenanceModeActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_maintenance_mode_action_enabled
        ):
            raise HttpConfigurationError(
                "The maintenance-mode feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_secret_audit_action_enabled = load_v4_secret_audit_action_feature(
                env
            )
        except V4SecretAuditActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_secret_audit_action_enabled
        ):
            raise HttpConfigurationError(
                "The Secret Audit feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_secret_audit_summary_enabled = load_v4_secret_audit_summary_feature(env)
        except V4SecretAuditSummaryError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_secret_audit_summary_enabled
        ):
            raise HttpConfigurationError(
                "The Secret Audit summary may be enabled only by the v4-controlled profile."
            )
        try:
            v4_active_launch_action_enabled = load_v4_active_launch_action_feature(
                env
            )
        except V4ActiveLaunchActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_active_launch_action_enabled
        ):
            raise HttpConfigurationError(
                "The active-launch feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_automation_trigger_action_enabled = (
                load_v4_automation_trigger_action_feature(env)
            )
        except V4AutomationTriggerActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_automation_trigger_action_enabled
        ):
            raise HttpConfigurationError(
                "The Automation Trigger feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_automation_action_action_enabled = (
                load_v4_automation_action_action_feature(env)
            )
        except V4AutomationActionActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_automation_action_action_enabled
        ):
            raise HttpConfigurationError(
                "The Automation Action feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_automation_stitch_action_enabled = (
                load_v4_automation_stitch_action_feature(env)
            )
        except V4AutomationStitchActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_automation_stitch_action_enabled
        ):
            raise HttpConfigurationError(
                "The Automation Stitch feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_user_group_action_enabled = load_v4_user_group_action_feature(env)
        except V4UserGroupActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_user_group_action_enabled
        ):
            raise HttpConfigurationError(
                "The User Group feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_user_group_membership_action_enabled = (
                load_v4_user_group_membership_action_feature(env)
            )
        except V4UserGroupMembershipActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_user_group_membership_action_enabled
        ):
            raise HttpConfigurationError(
                "The User Group membership feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_apl_action_enabled = load_v4_apl_action_feature(env)
        except V4AplActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if runtime_profile is not RuntimeProfile.V4_CONTROLLED and v4_apl_action_enabled:
            raise HttpConfigurationError(
                "The Auto-Provision Rule feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_apl_disable_action_enabled = load_v4_apl_disable_action_feature(env)
        except V4AplDisableActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_apl_disable_action_enabled
        ):
            raise HttpConfigurationError(
                "The Auto-Provision Rule disable feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_schedule_action_enabled = load_v4_schedule_action_feature(env)
        except V4ScheduleActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if runtime_profile is not RuntimeProfile.V4_CONTROLLED and v4_schedule_action_enabled:
            raise HttpConfigurationError(
                "The Schedule feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_schedule_assign_action_enabled = (
                load_v4_schedule_assign_action_feature(env)
            )
        except V4ScheduleAssignActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_schedule_assign_action_enabled
        ):
            raise HttpConfigurationError(
                "The Schedule assignment feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_approval_profile_action_enabled = (
                load_v4_approval_profile_action_feature(env)
            )
        except V4ApprovalProfileActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_approval_profile_action_enabled
        ):
            raise HttpConfigurationError(
                "The Approval Profile feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_approval_profile_update_action_enabled = (
                load_v4_approval_profile_update_action_feature(env)
            )
        except V4ApprovalProfileUpdateActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_approval_profile_update_action_enabled
        ):
            raise HttpConfigurationError(
                "The Approval Profile update feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_approval_email_template_action_enabled = (
                load_v4_approval_email_template_action_feature(env)
            )
        except V4ApprovalEmailTemplateActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_approval_email_template_action_enabled
        ):
            raise HttpConfigurationError(
                "The Approval Email Template feature may be enabled only by the v4-controlled profile."
            )
        try:
            v4_approval_email_template_update_action_enabled = (
                load_v4_approval_email_template_update_action_feature(env)
            )
        except V4ApprovalEmailTemplateUpdateActionConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if (
            runtime_profile is not RuntimeProfile.V4_CONTROLLED
            and v4_approval_email_template_update_action_enabled
        ):
            raise HttpConfigurationError(
                "The Approval Email Template update feature may be enabled only by the v4-controlled profile."
            )

        try:
            v4_terraform_plan_report_enabled = load_terraform_plan_report_feature(env)
        except TerraformPlanReportError:
            raise HttpConfigurationError("The synthetic Terraform report configuration is unavailable.") from None
        if v4_terraform_plan_report_enabled and runtime_profile is not RuntimeProfile.V4_CONTROLLED:
            raise HttpConfigurationError("The Terraform report requires the controlled OAuth profile.")

        v4_planning_authorization: Any = None
        v4_confirmation: V4ConfirmationSettings | None = None
        if v4_http_profile:
            assert public_url is not None
            try:
                from .v4_plan_runtime import (
                    V4PlanningRuntimeError,
                    planning_authorization_settings_from_environment,
                )

                v4_planning_authorization = (
                    planning_authorization_settings_from_environment(
                        env,
                        expected_resource=public_url,
                        allow_insecure_private_ip_lab=insecure_private_ip_lab,
                    )
                )
            except V4PlanningRuntimeError as exc:
                raise HttpConfigurationError(str(exc)) from exc
            try:
                v4_confirmation = confirmation_settings_from_environment(env)
            except V4ConfirmationHttpError as exc:
                raise HttpConfigurationError(str(exc)) from exc
        if v4_onboarding_execution_enabled and v4_confirmation is None:
            raise HttpConfigurationError(
                "Onboarding execution Tools require V4 confirmation state."
            )
        if v4_ad_discovery_execution_enabled and v4_confirmation is None:
            raise HttpConfigurationError("AD Discovery execution requires V4 confirmation state.")
        if (
            v4_approval_and_observe_execution_enabled
            and v4_confirmation is None
        ):
            raise HttpConfigurationError(
                "Approval execution Tool requires V4 confirmation state."
            )

        diagnostic: DiagnosticServiceSettings | None = None
        diagnostic_requested = any(
            _exact_value(env, name) is not None
            for name in (DIAGNOSTIC_DB_ENV, DIAGNOSTIC_HMAC_KEY_FILE_ENV)
        )
        if diagnostic_requested and auth_mode not in {"oauth", "local_oauth"}:
            raise HttpConfigurationError(
                "Diagnostic state requires HTTP OAuth authentication."
            )
        if auth_mode in {"oauth", "local_oauth"}:
            assert public_url is not None
            try:
                diagnostic = diagnostic_settings_from_environment(
                    env,
                    expected_resource=public_url,
                )
            except DiagnosticServiceError as exc:
                raise HttpConfigurationError(str(exc)) from exc
        if v4_ha_reconciliation_enabled and diagnostic is None:
            raise HttpConfigurationError(
                "Enabled HA reconciliation requires configured HTTP OAuth diagnostics."
            )

        try:
            controlled_operation = approval_settings_from_environment(env)
        except ApprovalServiceConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if controlled_operation is not None and auth_mode != "local_oauth":
            raise HttpConfigurationError(
                "Controlled-operation approval requires embedded local OAuth."
            )

        return cls(
            host=host,
            port=port,
            path=path,
            auth_mode=auth_mode,
            bearer_token=bearer_token,
            allowed_hosts=allowed_hosts,
            allowed_origins=allowed_origins,
            public_url=public_url,
            oauth_issuer=oauth_issuer,
            oauth_jwks_url=oauth_jwks_url,
            oauth_audience=oauth_audience,
            oauth_required_scopes=oauth_required_scopes,
            oauth_algorithms=oauth_algorithms,
            local_oauth=local_oauth,
            diagnostic=diagnostic,
            controlled_operation=controlled_operation,
            runtime_profile=runtime_profile,
            v4_planning_authorization=v4_planning_authorization,
            v4_confirmation=v4_confirmation,
            v4_onboarding_execution_enabled=v4_onboarding_execution_enabled,
            v4_ad_discovery_execution_enabled=v4_ad_discovery_execution_enabled,
            v4_approval_and_observe_execution_enabled=(
                v4_approval_and_observe_execution_enabled
            ),
            v4_folder_action_enabled=v4_folder_action_enabled,
            v4_folder_acl_action_enabled=v4_folder_acl_action_enabled,
            v4_folder_acl_revoke_action_enabled=v4_folder_acl_revoke_action_enabled,
            v4_classification_tag_action_enabled=(
                v4_classification_tag_action_enabled
            ),
            v4_classification_tag_assign_action_enabled=(
                v4_classification_tag_assign_action_enabled
            ),
            v4_address_action_enabled=v4_address_action_enabled,
            v4_address_group_action_enabled=v4_address_group_action_enabled,
            v4_ztna_device_context_diagnostic_enabled=(
                v4_ztna_device_context_diagnostic_enabled
            ),
            v4_ha_reconciliation_enabled=v4_ha_reconciliation_enabled,
            v4_ha_reconciliation_prerequisite_provider=(
                v4_ha_reconciliation_prerequisite_provider
            ),
            v4_ha_reconciliation_query_permission_provider=(
                v4_ha_reconciliation_query_permission_provider
            ),
            v4_ztna_folder_posture_enabled=v4_ztna_folder_posture_enabled,
            v4_folder_rename_action_enabled=v4_folder_rename_action_enabled,
            v4_folder_archive_action_enabled=v4_folder_archive_action_enabled,
            v4_folder_policy_assign_action_enabled=(
                v4_folder_policy_assign_action_enabled
            ),
            v4_folder_policy_detach_action_enabled=(
                v4_folder_policy_detach_action_enabled
            ),
            v4_target_action_enabled=v4_target_action_enabled,
            v4_secret_metadata_action_enabled=v4_secret_metadata_action_enabled,
            v4_interface_web_proxy_action_enabled=(
                v4_interface_web_proxy_action_enabled
            ),
            v4_target_update_action_enabled=v4_target_update_action_enabled,
            v4_certificate_csr_action_enabled=(
                v4_certificate_csr_action_enabled
            ),
            v4_local_user_disable_action_enabled=(
                v4_local_user_disable_action_enabled
            ),
            v4_local_user_create_action_enabled=(
                v4_local_user_create_action_enabled
            ),
            v4_local_user_reset_action_enabled=(
                v4_local_user_reset_action_enabled
            ),
            v4_role_create_action_enabled=v4_role_create_action_enabled,
            v4_role_update_action_enabled=v4_role_update_action_enabled,
            v4_role_assign_action_enabled=v4_role_assign_action_enabled,
            v4_dlp_file_pattern_action_enabled=v4_dlp_file_pattern_action_enabled,
            v4_dlp_sensor_action_enabled=v4_dlp_sensor_action_enabled,
            v4_antivirus_profile_action_enabled=(
                v4_antivirus_profile_action_enabled
            ),
            v4_rdp_event_filter_action_enabled=(
                v4_rdp_event_filter_action_enabled
            ),
            v4_secret_policy_action_enabled=v4_secret_policy_action_enabled,
            v4_ssh_filter_action_enabled=v4_ssh_filter_action_enabled,
            v4_launcher_action_enabled=v4_launcher_action_enabled,
            v4_launcher_update_action_enabled=v4_launcher_update_action_enabled,
            v4_launcher_matcher_action_enabled=v4_launcher_matcher_action_enabled,
            v4_template_action_enabled=v4_template_action_enabled,
            v4_template_archive_action_enabled=(
                v4_template_archive_action_enabled
            ),
            v4_dependency_updater_action_enabled=v4_dependency_updater_action_enabled,
            v4_secret_gateway_action_enabled=v4_secret_gateway_action_enabled,
            v4_client_integrity_action_enabled=v4_client_integrity_action_enabled,
            v4_character_set_action_enabled=v4_character_set_action_enabled,
            v4_windows_app_filter_action_enabled=(
                v4_windows_app_filter_action_enabled
            ),
            v4_recording_policy_action_enabled=(
                v4_recording_policy_action_enabled
            ),
            v4_password_policy_action_enabled=(
                v4_password_policy_action_enabled
            ),
            v4_report_layout_action_enabled=v4_report_layout_action_enabled,
            v4_ztna_access_proxy_action_enabled=(
                v4_ztna_access_proxy_action_enabled
            ),
            v4_ztna_user_control_action_enabled=(
                v4_ztna_user_control_action_enabled
            ),
            v4_ztna_wad_debug_action_enabled=(
                v4_ztna_wad_debug_action_enabled
            ),
            v4_snmp_agent_action_enabled=v4_snmp_agent_action_enabled,
            v4_logging_disk_action_enabled=v4_logging_disk_action_enabled,
            v4_fortianalyzer_action_enabled=v4_fortianalyzer_action_enabled,
            v4_maintenance_mode_action_enabled=v4_maintenance_mode_action_enabled,
            v4_secret_audit_action_enabled=v4_secret_audit_action_enabled,
            v4_secret_audit_summary_enabled=v4_secret_audit_summary_enabled,
            v4_terraform_plan_report_enabled=v4_terraform_plan_report_enabled,
            v4_active_launch_action_enabled=v4_active_launch_action_enabled,
            v4_automation_trigger_action_enabled=(
                v4_automation_trigger_action_enabled
            ),
            v4_automation_action_action_enabled=(
                v4_automation_action_action_enabled
            ),
            v4_automation_stitch_action_enabled=(
                v4_automation_stitch_action_enabled
            ),
            v4_user_group_action_enabled=v4_user_group_action_enabled,
            v4_user_group_membership_action_enabled=(
                v4_user_group_membership_action_enabled
            ),
            v4_apl_action_enabled=v4_apl_action_enabled,
            v4_apl_disable_action_enabled=v4_apl_disable_action_enabled,
            v4_schedule_action_enabled=v4_schedule_action_enabled,
            v4_schedule_assign_action_enabled=v4_schedule_assign_action_enabled,
            v4_approval_profile_action_enabled=(
                v4_approval_profile_action_enabled
            ),
            v4_approval_profile_update_action_enabled=(
                v4_approval_profile_update_action_enabled
            ),
            v4_approval_email_template_action_enabled=(
                v4_approval_email_template_action_enabled
            ),
            v4_approval_email_template_update_action_enabled=(
                v4_approval_email_template_update_action_enabled
            ),
            v4_secret_request_create_enabled=(
                v4_secret_request_create_enabled
            ),
        )


class StaticBearerMiddleware:
    """Require one deployment token without exposing it to the MCP server."""

    def __init__(self, app: Any, *, token: str, protected_path: str) -> None:
        self._app = app
        self._token = token
        self._protected_path = protected_path

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Any,
        send: Any,
    ) -> None:
        if scope.get("type") != "http" or scope.get("path") != self._protected_path:
            await self._app(scope, receive, send)
            return
        headers = {
            key.lower(): value
            for key, value in scope.get("headers", ())
            if isinstance(key, bytes) and isinstance(value, bytes)
        }
        authorization = headers.get(b"authorization", b"").decode(
            "latin-1", errors="ignore"
        )
        scheme, separator, supplied = authorization.partition(" ")
        valid = (
            separator == " "
            and scheme.lower() == "bearer"
            and bool(supplied)
            and secrets.compare_digest(supplied, self._token)
        )
        if not valid:
            body = b'{"error":"unauthorized"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode("ascii")),
                        (b"www-authenticate", b'Bearer realm="fortipam-mcp"'),
                        (b"cache-control", b"no-store"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self._app(scope, receive, send)


class AllowedHostMiddleware:
    """Apply the configured Host allowlist to MCP and embedded auth routes."""

    def __init__(self, app: Any, *, allowed_hosts: tuple[str, ...]) -> None:
        self._app = app
        self._allowed_hosts = tuple(host.lower() for host in allowed_hosts)

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Any,
        send: Any,
    ) -> None:
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return
        headers = {
            key.lower(): value
            for key, value in scope.get("headers", ())
            if isinstance(key, bytes) and isinstance(value, bytes)
        }
        host = headers.get(b"host", b"").decode("latin-1", errors="ignore").lower()
        if not host or not any(fnmatchcase(host, pattern) for pattern in self._allowed_hosts):
            body = b'{"error":"untrusted_host"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 421,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode("ascii")),
                        (b"cache-control", b"no-store"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self._app(scope, receive, send)


class OAuthJwtTokenVerifier:
    """Validate IdP JWT access tokens as MCP resource-server credentials."""

    def __init__(
        self,
        *,
        issuer: str,
        jwks_url: str,
        audience: str,
        algorithms: tuple[str, ...],
    ) -> None:
        import jwt
        import truststore

        self._jwt = jwt
        self._issuer = issuer
        self._audience = audience
        self._algorithms = algorithms
        ssl_context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._jwks_client = jwt.PyJWKClient(
            jwks_url,
            cache_keys=True,
            lifespan=300,
            timeout=10,
            ssl_context=ssl_context,
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return validated access metadata or a non-disclosing failure."""

        try:
            signing_key = await asyncio.to_thread(
                self._jwks_client.get_signing_key_from_jwt,
                token,
            )
            claims = self._jwt.decode(
                token,
                signing_key.key,
                algorithms=list(self._algorithms),
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iss", "aud"]},
            )
        except Exception:
            return None
        scopes = _token_scopes(claims)
        client_id = str(claims.get("client_id") or claims.get("azp") or "unknown")
        subject = claims.get("sub")
        expires_at = claims.get("exp")
        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=list(scopes),
            expires_at=int(expires_at) if isinstance(expires_at, int) else None,
            resource=self._audience,
            subject=str(subject) if subject is not None else None,
            claims=dict(claims),
        )


def create_http_app(
    settings: HttpServerSettings,
    *,
    v4_plan_services: Any = None,
    v4_plan_host_factory: Any = None,
    v4_secret_request_observation: Any = None,
    v4_onboarding_execution_factory: Callable[
        [V4PlanHostComponents],
        tuple[
            ProtectedAccessDomainOnboardingMcpAction | None,
            ProtectedSecretOnboardingMcpAction,
        ],
    ]
    | None = None,
    v4_approval_and_observe_execution_factory: (
        Callable[
            [V4PlanHostComponents],
            ProtectedApprovalAndObserveMcpAction,
        ]
        | None
    ) = None,
    v4_ad_discovery_execution_factory: (
        Callable[[V4PlanHostComponents], ProtectedAdDiscoveryMcpAction] | None
    ) = None,
    v4_isolated_folder_action: Any = None,
    v4_isolated_folder_policy_transition_candidate_action: Any = None,
    v4_folder_traversal_action: Any = None,
    v4_local_user_reset_candidate_action: Any = None,
    v4_local_user_reset_owned_action: Any = None,
    v4_password_verification_candidate_action: Any = None,
    v4_password_change_schedule_candidate_action: Any = None,
    v4_secret_description_update_candidate_action: Any = None,
    v4_secret_dlp_association_candidate_action: Any = None,
    v4_secret_event_subscription_candidate: Any = None,
    v4_secret_checkout_association_candidate_action: Any = None,
    v4_secret_checkout_effect_candidate_action: Any = None,
    v4_job_request_deny_candidate_action: Any = None,
    v4_secret_request_approval_revoke_candidate_action: Any = None,
    v4_ldap_server_candidate_action: Any = None,
    v4_system_email_local_candidate_action: Any = None,
    v4_email_alert_general_preview_action: Any = None,
    v4_approval_delivery_preview_action: Any = None,
    v4_license_vm_preview_action: Any = None,
    v4_approval_delivery_local_candidate_action: Any = None,
    v4_email_alert_local_candidate_action: Any = None,
    v4_glass_break_preview_action: Any = None,
    v4_glass_break_local_candidate_action: Any = None,
    v4_scim_local_candidate_action: Any = None,
    v4_saml_local_candidate_action: Any = None,
    v4_fortitoken_local_preview_action: Any = None,
    v4_fortitoken_local_candidate_action: Any = None,
    v4_windows_jit_script_preview_action: Any = None,
    v4_windows_jit_local_candidate_action: Any = None,
    v4_radius_server_lifecycle_candidate_action: Any = None,
    v4_radius_server_pair_lifecycle_candidate_action: Any = None,
    v4_radius_user_lifecycle_candidate_action: Any = None,
    v4_jwt_owner_candidate_action: Any = None,
    v4_jwt_rotation_candidate_action: Any = None,
    v4_job_definition_owned_candidate_action: Any = None,
    v4_job_execution_owned_candidate_action: Any = None,
    v4_radius_user_recovery_candidate_action: Any = None,
    v4_ldap_server_update_candidate_action: Any = None,
    v4_apl_role_update_candidate_action: Any = None,
    v4_disabled_route_candidate_action: Any = None,
    v4_dns_timeout_candidate_action: Any = None,
    v4_crl_candidate_action: Any = None,
    v4_remote_certificate_candidate_action: Any = None,
    v4_ems_timeout_candidate_action: Any = None,
    v4_ems_tag_candidate_action: Any = None,
    v4_ems_tag_principal_binding: Any = None,
    v4_ems_rule_set_metadata_action: Any = None,
    v4_logging_disk_size_candidate_action: Any = None,
    v4_backup_export_candidate_action: Any = None,
    secret_bulk_import_action: Any = None,
    secret_bulk_import_runtime: Any = None,
    owner_file_intake_issuer: Any = None,
    v4_ztna_group_candidate_action: Any = None,
    v4_instruction_profile_candidate_action: Any = None,
    v4_instruction_feature_candidate_action: Any = None,
    v4_instruction_quota_candidate_action: Any = None,
    v4_instruction_quota_recovery_candidate_action: Any = None,
    v4_job_request_approve_candidate_action: Any = None,
    v4_password_changer_candidate_action: Any = None,
    v4_disabled_job_candidate_action: Any = None,
    v4_fixed_job_activation_candidate_action: Any = None,
    v4_password_changer_delete_candidate_action: Any = None,
    v4_unix_discovery_candidate_action: Any = None,
    v4_unix_discovery_cleanup_action: Any = None,
    v4_unix_scanned_source_recovery_action: Any = None,
    v4_launcher_clone_actions: Any = None,
    v4_client_integrity_native_actions: Any = None,
    v4_putty_integrity_association_actions: Any = None,
    v4_unix_discovery_run_action: Any = None,
    v4_unix_discovery_review_action: Any = None,
    v4_password_rotation_candidate_action: Any = None,
    v4_folder_action: Any = None,
    v4_folder_acl_action: Any = None,
    v4_folder_acl_revoke_action: Any = None,
    v4_classification_tag_action: Any = None,
    v4_classification_tag_assign_action: Any = None,
    v4_address_action: Any = None,
    v4_address_group_action: Any = None,
    v4_ztna_device_context_diagnostic: Any = None,
    v4_ha_reconciliation: HaReconciliationRuntimeBinding | None = None,
    v4_ztna_folder_posture: Any = None,
    v4_folder_rename_action: Any = None,
    v4_folder_archive_action: Any = None,
    v4_folder_policy_assign_action: Any = None,
    v4_folder_policy_detach_action: Any = None,
    v4_target_action: Any = None,
    v4_secret_metadata_action: Any = None,
    v4_interface_web_proxy_action: Any = None,
    v4_target_update_action: Any = None,
    v4_certificate_csr_action: Any = None,
    v4_local_user_disable_action: Any = None,
    v4_local_user_create_action: Any = None,
    v4_local_user_reset_action: Any = None,
    v4_role_create_action: Any = None,
    v4_role_update_action: Any = None,
    v4_role_assign_action: Any = None,
    v4_dlp_file_pattern_action: Any = None,
    v4_dlp_sensor_action: Any = None,
    v4_antivirus_profile_action: Any = None,
    v4_rdp_event_filter_action: Any = None,
    v4_secret_policy_action: Any = None,
    v4_ssh_filter_action: Any = None,
    v4_launcher_action: Any = None,
    v4_launcher_update_action: Any = None,
    v4_launcher_matcher_action: Any = None,
    v4_template_action: Any = None,
    v4_template_archive_action: Any = None,
    v4_dependency_updater_action: Any = None,
    v4_secret_gateway_action: Any = None,
    v4_client_integrity_action: Any = None,
    v4_character_set_action: Any = None,
    v4_windows_app_filter_action: Any = None,
    v4_recording_policy_action: Any = None,
    v4_password_policy_action: Any = None,
    v4_report_layout_action: Any = None,
    v4_ztna_access_proxy_action: Any = None,
    v4_ztna_user_control_action: Any = None,
    v4_ztna_wad_debug_action: Any = None,
    v4_snmp_agent_action: Any = None,
    v4_logging_disk_action: Any = None,
    v4_fortianalyzer_action: Any = None,
    v4_maintenance_mode_action: Any = None,
    v4_secret_audit_action: Any = None,
    v4_secret_audit_summary: Any = None,
    v4_terraform_plan_report: ProtectedTerraformPlanReport | None = None,
    v4_active_launch_action: Any = None,
    v4_automation_trigger_action: Any = None,
    v4_automation_action_action: Any = None,
    v4_automation_stitch_action: Any = None,
    v4_user_group_action: Any = None,
    v4_user_group_membership_action: Any = None,
    v4_apl_action: Any = None,
    v4_apl_disable_action: Any = None,
    v4_schedule_action: Any = None,
    v4_schedule_assign_action: Any = None,
    v4_approval_profile_action: Any = None,
    v4_approval_profile_update_action: Any = None,
    v4_approval_email_template_action: Any = None,
    v4_approval_email_template_update_action: Any = None,
    v4_secret_request_create_action: Any = None,
) -> Any:
    """Create the hardened ASGI app for one validated transport configuration."""

    auth_settings: AuthSettings | None = None
    token_verifier: Any = None
    custom_http_routes: list[Any] = []
    v4_access_domain_execution_action: (
        ProtectedAccessDomainOnboardingMcpAction | None
    ) = None
    v4_secret_onboarding_execution_action: (
        ProtectedSecretOnboardingMcpAction | None
    ) = None
    v4_approval_and_observe_execution_action: (
        ProtectedApprovalAndObserveMcpAction | None
    ) = None
    v4_ad_discovery_execution_action: ProtectedAdDiscoveryMcpAction | None = None
    if owner_file_intake_issuer is not None:
        from .secret_bulk_import_issuer_runtime import _OwnerFileIntakeIssuerRuntime
        if (type(owner_file_intake_issuer) is not _OwnerFileIntakeIssuerRuntime
                or settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != 'local_oauth'
                or owner_file_intake_issuer._settings != settings.local_oauth):
            raise HttpConfigurationError('Private intake issuer requires its exact controlled OAuth host.')
    if v4_plan_services is not None and v4_plan_host_factory is not None:
        raise HttpConfigurationError("V4 planning host configuration is ambiguous.")
    if settings.v4_onboarding_execution_enabled:
        if (
            settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
            or settings.auth_mode != "local_oauth"
            or settings.v4_confirmation is None
        ):
            raise HttpConfigurationError(
                "Onboarding execution Tools require v4-controlled local OAuth confirmation state."
            )
        if v4_onboarding_execution_factory is None:
            raise HttpConfigurationError(
                "Enabled onboarding execution Tools require one trusted execution factory."
            )
        if v4_plan_host_factory is None:
            raise HttpConfigurationError(
                "Enabled onboarding execution Tools require source-backed onboarding host components."
            )
    elif v4_onboarding_execution_factory is not None:
        raise HttpConfigurationError(
            "An onboarding execution factory cannot be bound while its feature is disabled."
        )
    if settings.v4_approval_and_observe_execution_enabled:
        if (
            settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
            or settings.auth_mode != "local_oauth"
            or settings.v4_confirmation is None
        ):
            raise HttpConfigurationError(
                "Approval execution Tool requires v4-controlled local OAuth confirmation state."
            )
        if v4_approval_and_observe_execution_factory is None:
            raise HttpConfigurationError(
                "Enabled approval execution Tool requires one trusted execution factory."
            )
        if v4_plan_host_factory is None:
            raise HttpConfigurationError(
                "Enabled approval execution Tool requires source-backed approval host components."
            )
    elif v4_approval_and_observe_execution_factory is not None:
        raise HttpConfigurationError(
            "An approval execution factory cannot be bound while its feature is disabled."
        )
    if settings.v4_ad_discovery_execution_enabled:
        if (
            settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
            or settings.auth_mode != "local_oauth"
            or settings.v4_confirmation is None
            or v4_plan_host_factory is None
            or v4_ad_discovery_execution_factory is None
        ):
            raise HttpConfigurationError(
                "AD Discovery execution requires controlled local OAuth confirmation and fixed factories."
            )
    elif v4_ad_discovery_execution_factory is not None:
        raise HttpConfigurationError("AD Discovery factory cannot bind while its feature is disabled.")
    if v4_isolated_folder_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Isolated Folder candidate requires controlled OAuth operation authority.")
    if v4_isolated_folder_policy_transition_candidate_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Isolated Folder Policy transition requires controlled OAuth operation authority.")
    if v4_password_verification_candidate_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Password verification candidate requires controlled OAuth operation authority.")
    if v4_password_change_schedule_candidate_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Password change schedule candidate requires controlled OAuth operation authority.")
    if v4_secret_dlp_association_candidate_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Secret DLP association candidate requires controlled OAuth operation authority.")
    if v4_secret_description_update_candidate_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Secret description update candidate requires controlled OAuth operation authority.")
    if v4_secret_event_subscription_candidate is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Secret event subscription candidate requires controlled OAuth operation authority.")
    if v4_secret_checkout_association_candidate_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Secret checkout association candidate requires controlled OAuth operation authority.")
    if v4_secret_checkout_effect_candidate_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Secret checkout effect candidate requires controlled OAuth operation authority.")
    if v4_secret_request_approval_revoke_candidate_action is not None:
        from .secret_request_approval_revoke_mcp_action import SecretRequestApprovalRevokeMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_secret_request_approval_revoke_candidate_action) is not SecretRequestApprovalRevokeMcpAction):
            raise HttpConfigurationError("Request approval withdrawal requires controlled OAuth operation authority.")
    if v4_ldap_server_candidate_action is not None:
        from .ldap_server_mcp_action import LdapServerMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_ldap_server_candidate_action) is not LdapServerMcpAction):
            raise HttpConfigurationError("LDAP creation requires controlled OAuth operation authority.")
    if v4_system_email_local_candidate_action is not None:
        from .system_email_local_mcp_action import SystemEmailLocalMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_system_email_local_candidate_action) is not SystemEmailLocalMcpAction):
            raise HttpConfigurationError("Local system-email candidate requires controlled OAuth operation authority.")
    if v4_scim_local_candidate_action is not None:
        from .scim_client_local_mcp_action import ScimLocalMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth" or settings.v4_planning_authorization is None
                or type(v4_scim_local_candidate_action) is not ScimLocalMcpAction):
            raise HttpConfigurationError("Local SCIM candidate requires controlled OAuth operation authority.")
    if v4_saml_local_candidate_action is not None:
        from .saml_server_local_mcp_action import SamlLocalMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth" or settings.v4_planning_authorization is None
                or type(v4_saml_local_candidate_action) is not SamlLocalMcpAction):
            raise HttpConfigurationError("Local SAML candidate requires controlled OAuth operation authority.")
    if v4_email_alert_general_preview_action is not None:
        from .email_alert_general_preview_action import EmailAlertGeneralPreviewAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth" or settings.v4_planning_authorization is None
                or type(v4_email_alert_general_preview_action) is not EmailAlertGeneralPreviewAction):
            raise HttpConfigurationError("Local general email-alert preview requires controlled OAuth planning authority.")
    if v4_license_vm_preview_action is not None:
        from .license_vm_preview_action import LicenseVmPreviewAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth" or settings.v4_planning_authorization is None
                or type(v4_license_vm_preview_action) is not LicenseVmPreviewAction):
            raise HttpConfigurationError("License VM preview requires controlled OAuth planning authority.")
    if v4_approval_delivery_preview_action is not None:
        from .approval_delivery_preview_action import ApprovalDeliveryPreviewAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth" or settings.v4_planning_authorization is None
                or type(v4_approval_delivery_preview_action) is not ApprovalDeliveryPreviewAction):
            raise HttpConfigurationError("Approval-delivery preview requires controlled OAuth planning authority.")
    if v4_approval_delivery_local_candidate_action is not None:
        from .approval_delivery_local_mcp_action import ApprovalDeliveryLocalMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth" or settings.v4_planning_authorization is None
                or type(v4_approval_delivery_local_candidate_action) is not ApprovalDeliveryLocalMcpAction):
            raise HttpConfigurationError("Local Approval Email candidate requires controlled OAuth operation authority.")
    if v4_email_alert_local_candidate_action is not None:
        from .email_alert_local_mcp_action import EmailAlertLocalMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth" or settings.v4_planning_authorization is None
                or type(v4_email_alert_local_candidate_action) is not EmailAlertLocalMcpAction):
            raise HttpConfigurationError("Local email-alert candidate requires controlled OAuth operation authority.")
    if v4_glass_break_preview_action is not None:
        from .glass_break_preview_action import GlassBreakPreviewAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth" or settings.v4_planning_authorization is None
                or type(v4_glass_break_preview_action) is not GlassBreakPreviewAction):
            raise HttpConfigurationError("Local glass-breaking preview requires controlled OAuth planning authority.")
    if v4_glass_break_local_candidate_action is not None:
        from .glass_break_local_mcp_action import GlassBreakLocalMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth" or settings.v4_planning_authorization is None
                or type(v4_glass_break_local_candidate_action) is not GlassBreakLocalMcpAction):
            raise HttpConfigurationError("Local glass-breaking candidate requires controlled OAuth operation authority.")
    if v4_fortitoken_local_preview_action is not None:
        from .fortitoken_local_preview_action import FortitokenLocalPreviewAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth" or settings.v4_planning_authorization is None
                or type(v4_fortitoken_local_preview_action) is not FortitokenLocalPreviewAction):
            raise HttpConfigurationError("Local FortiToken previews require controlled OAuth planning authority.")
    if v4_windows_jit_script_preview_action is not None:
        from .windows_jit_script_preview_action import WindowsJitScriptPreviewAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth" or settings.v4_planning_authorization is None
                or type(v4_windows_jit_script_preview_action) is not WindowsJitScriptPreviewAction):
            raise HttpConfigurationError("Local Windows JIT Script preview requires controlled OAuth planning authority.")
    if v4_windows_jit_local_candidate_action is not None:
        from .windows_jit_local_mcp_action import WindowsJitLocalMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth" or settings.v4_planning_authorization is None
                or type(v4_windows_jit_local_candidate_action) is not WindowsJitLocalMcpAction):
            raise HttpConfigurationError("Local Windows JIT candidate requires controlled OAuth operation authority.")
    if v4_fortitoken_local_candidate_action is not None:
        from .fortitoken_local_mcp_action import FortitokenLocalMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth" or settings.v4_planning_authorization is None
                or type(v4_fortitoken_local_candidate_action) is not FortitokenLocalMcpAction):
            raise HttpConfigurationError("Local FortiToken candidate requires controlled OAuth operation authority.")
    if v4_jwt_owner_candidate_action is not None:
        from .jwt_manual_key_owner_mcp_action import JwtManualKeyOwnerMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_jwt_owner_candidate_action) is not JwtManualKeyOwnerMcpAction):
            raise HttpConfigurationError("Owner JWT requires controlled OAuth operation authority.")
    if v4_job_execution_owned_candidate_action is not None:
        from .job_execution_owned_mcp_action import JobExecutionOwnedMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None or v4_job_definition_owned_candidate_action is not None
                or v4_fixed_job_activation_candidate_action is not None
                or type(v4_job_execution_owned_candidate_action) is not JobExecutionOwnedMcpAction):
            raise HttpConfigurationError("Owned Job execution requires an exclusive controlled OAuth profile.")
    if v4_job_definition_owned_candidate_action is not None:
        from .job_definition_owned_mcp_action import JobDefinitionOwnedMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None or v4_disabled_job_candidate_action is not None
                or type(v4_job_definition_owned_candidate_action) is not JobDefinitionOwnedMcpAction):
            raise HttpConfigurationError("Owned Job requires an exclusive controlled OAuth profile.")
    if v4_jwt_rotation_candidate_action is not None:
        from .jwt_rotation_mcp_action import JwtRotationMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None or v4_jwt_owner_candidate_action is not None
                or type(v4_jwt_rotation_candidate_action) is not JwtRotationMcpAction):
            raise HttpConfigurationError("JWT rotation requires an exclusive controlled OAuth profile.")
    if v4_radius_user_recovery_candidate_action is not None:
        from .radius_remote_user_recovery_mcp_action import RadiusRemoteUserRecoveryMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_radius_user_recovery_candidate_action) is not RadiusRemoteUserRecoveryMcpAction
                or v4_radius_user_lifecycle_candidate_action is not None
                or v4_radius_server_pair_lifecycle_candidate_action is not None):
            raise HttpConfigurationError("RADIUS User recovery requires an exclusive controlled OAuth profile.")
    if v4_radius_user_lifecycle_candidate_action is not None:
        from .radius_remote_user_lifecycle_mcp_action import RadiusRemoteUserLifecycleMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_radius_user_lifecycle_candidate_action) is not RadiusRemoteUserLifecycleMcpAction
                or v4_radius_server_pair_lifecycle_candidate_action is not None):
            raise HttpConfigurationError("RADIUS User lifecycle requires an exclusive controlled OAuth profile.")
    if v4_radius_server_pair_lifecycle_candidate_action is not None:
        from .radius_server_pair_lifecycle_mcp_action import RadiusServerPairLifecycleMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_radius_server_pair_lifecycle_candidate_action) is not RadiusServerPairLifecycleMcpAction):
            raise HttpConfigurationError("Paired RADIUS lifecycle requires controlled OAuth operation authority.")
    if v4_radius_server_lifecycle_candidate_action is not None:
        from .radius_server_lifecycle_mcp_action import RadiusServerLifecycleMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_radius_server_lifecycle_candidate_action) is not RadiusServerLifecycleMcpAction):
            raise HttpConfigurationError("RADIUS lifecycle requires controlled OAuth operation authority.")
    if v4_ldap_server_update_candidate_action is not None:
        from .ldap_server_update_mcp_action import LdapServerUpdateMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_ldap_server_update_candidate_action) is not LdapServerUpdateMcpAction):
            raise HttpConfigurationError("LDAP update requires controlled OAuth operation authority.")
    if v4_dns_timeout_candidate_action is not None:
        from .dns_timeout_mcp_action import DnsTimeoutMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_dns_timeout_candidate_action) is not DnsTimeoutMcpAction):
            raise HttpConfigurationError("DNS timeout requires controlled OAuth operation authority.")
    if v4_crl_candidate_action is not None:
        from .crl_import_mcp_action import NativeCrlMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_crl_candidate_action) is not NativeCrlMcpAction):
            raise HttpConfigurationError("CRL requires controlled OAuth operation authority.")
    if v4_remote_certificate_candidate_action is not None:
        from .remote_certificate_mcp_action import NativeRemoteCertificateMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_remote_certificate_candidate_action) is not NativeRemoteCertificateMcpAction):
            raise HttpConfigurationError("Remote certificate requires controlled OAuth operation authority.")
    if v4_ems_timeout_candidate_action is not None:
        from .ems_timeout_mcp_action import EmsTimeoutMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_ems_timeout_candidate_action) is not EmsTimeoutMcpAction):
            raise HttpConfigurationError("EMS timeout requires controlled OAuth operation authority.")
    if v4_ems_tag_candidate_action is not None:
        from .ems_tag_mcp_action import EmsTagMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.local_oauth is None
                or settings.v4_planning_authorization is None
                or settings.v4_planning_authorization.insecure_private_ip_lab
                or type(v4_ems_tag_candidate_action) is not EmsTagMcpAction):
            raise HttpConfigurationError("Original EMS Tag requires controlled HTTPS OAuth operation authority.")
    if v4_ems_tag_principal_binding is not None:
        from .ems_tag_principal_binding import EmsTagPrincipalBinding
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth" or settings.local_oauth is None
                or settings.v4_planning_authorization is None
                or settings.v4_planning_authorization.insecure_private_ip_lab
                or type(v4_ems_tag_principal_binding) is not EmsTagPrincipalBinding
                or v4_ems_tag_candidate_action is not None
                or hmac.compare_digest(v4_ems_tag_principal_binding._key,
                    settings.v4_planning_authorization.namespace_hmac_key)):
            raise HttpConfigurationError("EMS requester binding requires isolated controlled HTTPS OAuth metadata authority.")
    if v4_ems_rule_set_metadata_action is not None:
        from .ems_rule_set_metadata_mcp_action import EmsRuleSetMetadataAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth" or settings.local_oauth is None
                or settings.v4_planning_authorization is None
                or settings.v4_planning_authorization.insecure_private_ip_lab
                or type(v4_ems_rule_set_metadata_action) is not EmsRuleSetMetadataAction
                or v4_ems_tag_candidate_action is not None or v4_ems_tag_principal_binding is not None):
            raise HttpConfigurationError("EMS rule-set metadata requires isolated controlled HTTPS OAuth planning authority.")
    if v4_logging_disk_size_candidate_action is not None:
        from .logging_disk_size_mcp_action import LoggingDiskSizeMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_logging_disk_size_candidate_action) is not LoggingDiskSizeMcpAction):
            raise HttpConfigurationError("disk log file size requires controlled OAuth operation authority.")
    if v4_backup_export_candidate_action is not None:
        from .backup_export_mcp_action import BackupExportMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_backup_export_candidate_action) is not BackupExportMcpAction):
            raise HttpConfigurationError("Encrypted backup requires controlled OAuth operation authority.")
    if secret_bulk_import_action is not None:
        from .secret_bulk_import_mcp_action import SecretBulkImportMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.local_oauth is None
                or settings.v4_planning_authorization is None
                or type(secret_bulk_import_action) is not SecretBulkImportMcpAction):
            raise HttpConfigurationError("Text import requires controlled OAuth operation authority.")
    if secret_bulk_import_runtime is not None:
        from .secret_bulk_import_runtime import _OriginalTextImportRuntime
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.local_oauth is None
                or settings.v4_planning_authorization is None
                or type(secret_bulk_import_runtime) is not _OriginalTextImportRuntime
                or owner_file_intake_issuer is None
                or secret_bulk_import_runtime._issuer is not owner_file_intake_issuer
                or secret_bulk_import_action is not None):
            raise HttpConfigurationError("Text import startup requires its controlled OAuth issuer.")
    if v4_ztna_group_candidate_action is not None:
        from .ztna_group_mcp_action import NativeZtnaGroupMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_ztna_group_candidate_action) is not NativeZtnaGroupMcpAction):
            raise HttpConfigurationError("ZTNA group requires controlled OAuth operation authority.")
    if v4_disabled_route_candidate_action is not None:
        from .disabled_route_mcp_action import DisabledRouteMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_disabled_route_candidate_action) is not DisabledRouteMcpAction):
            raise HttpConfigurationError("Disabled route requires controlled OAuth operation authority.")
    if v4_apl_role_update_candidate_action is not None:
        from .apl_role_update_mcp_action import AplRoleUpdateMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_apl_role_update_candidate_action) is not AplRoleUpdateMcpAction):
            raise HttpConfigurationError("APL Role update requires controlled OAuth operation authority.")
    if v4_instruction_profile_candidate_action is not None:
        from .instruction_profile_mcp_action import InstructionProfileMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_instruction_profile_candidate_action) is not InstructionProfileMcpAction):
            raise HttpConfigurationError("Instruction Profile requires controlled OAuth operation authority.")
    if v4_instruction_feature_candidate_action is not None:
        from .instruction_feature_mcp_action import InstructionFeatureMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_instruction_feature_candidate_action) is not InstructionFeatureMcpAction):
            raise HttpConfigurationError("Instruction feature requires controlled OAuth operation authority.")
    if v4_instruction_quota_candidate_action is not None:
        from .instruction_quota_mcp_action import InstructionQuotaMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_instruction_quota_candidate_action) is not InstructionQuotaMcpAction):
            raise HttpConfigurationError("Instruction quota requires controlled OAuth operation authority.")
    if v4_instruction_quota_recovery_candidate_action is not None:
        from .instruction_quota_recovery_mcp_action import InstructionQuotaRecoveryMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth"
                or settings.v4_planning_authorization is None
                or type(v4_instruction_quota_recovery_candidate_action) is not InstructionQuotaRecoveryMcpAction
                or v4_instruction_quota_candidate_action is not None):
            raise HttpConfigurationError("Instruction quota incident correction requires exclusive controlled OAuth authority.")
    if v4_job_request_deny_candidate_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Job Request denial candidate requires controlled OAuth operation authority.")
    if v4_job_request_approve_candidate_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Job Request approval candidate requires controlled OAuth operation authority.")
    if v4_password_changer_candidate_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Password Changer candidate requires controlled OAuth operation authority.")
    if v4_disabled_job_candidate_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Disabled Job candidate requires controlled OAuth operation authority.")
    if v4_fixed_job_activation_candidate_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Fixed Job activation requires controlled OAuth operation authority.")
    if v4_password_changer_delete_candidate_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Password Changer recovery requires controlled OAuth operation authority.")
    if v4_unix_discovery_candidate_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Unix Discovery candidate requires controlled OAuth operation authority.")
    if v4_unix_discovery_run_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Unix Discovery scan requires controlled OAuth operation authority.")
    if v4_launcher_clone_actions is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Launcher clone requires controlled OAuth operation authority.")
    if v4_client_integrity_native_actions is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Native Client Integrity requires controlled OAuth operation authority.")
    if v4_putty_integrity_association_actions is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Windows Client Integrity association requires controlled OAuth operation authority.")
    if v4_unix_discovery_cleanup_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Unix Discovery cleanup requires controlled OAuth operation authority.")
    if v4_unix_scanned_source_recovery_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Scanned Source recovery requires controlled OAuth operation authority.")
    if v4_unix_discovery_review_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Unix Discovery review requires controlled OAuth read authority.")
    if v4_password_rotation_candidate_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Password rotation candidate requires controlled OAuth operation authority.")
    if v4_folder_traversal_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Folder traversal candidate requires controlled OAuth operation authority.")
    if v4_local_user_reset_candidate_action is not None and (
        settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
        or settings.auth_mode != "local_oauth"
        or settings.v4_planning_authorization is None
    ):
        raise HttpConfigurationError("Local User reset candidate requires controlled OAuth operation authority.")
    if v4_local_user_reset_owned_action is not None:
        from .local_user_reset_owned_mcp import LocalResetOwnedMcpAction
        if (settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
            or settings.auth_mode != "local_oauth" or settings.v4_planning_authorization is None
            or type(v4_local_user_reset_owned_action) is not LocalResetOwnedMcpAction):
            raise HttpConfigurationError("Original-owned reset requires its controlled OAuth operation binding.")
        if v4_local_user_reset_candidate_action is not None or settings.v4_local_user_reset_action_enabled:
            raise HttpConfigurationError("Original-owned reset cannot share a host with a legacy reset binding.")
    if settings.v4_folder_action_enabled and v4_folder_action is None:
        raise HttpConfigurationError(
            "The enabled child Folder feature requires a bound action host."
        )
    if not settings.v4_folder_action_enabled and v4_folder_action is not None:
        raise HttpConfigurationError(
            "A child Folder action host cannot be bound while its feature is disabled."
        )
    if settings.v4_folder_acl_action_enabled and v4_folder_acl_action is None:
        raise HttpConfigurationError(
            "The enabled Folder ACL feature requires a bound action host."
        )
    if not settings.v4_folder_acl_action_enabled and v4_folder_acl_action is not None:
        raise HttpConfigurationError(
            "A Folder ACL action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_folder_acl_revoke_action_enabled
        and v4_folder_acl_revoke_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Folder ACL revoke feature requires a bound action host."
        )
    if (
        not settings.v4_folder_acl_revoke_action_enabled
        and v4_folder_acl_revoke_action is not None
    ):
        raise HttpConfigurationError(
            "A Folder ACL revoke action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_classification_tag_action_enabled
        and v4_classification_tag_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Classification Tag feature requires a bound action host."
        )
    if (
        not settings.v4_classification_tag_action_enabled
        and v4_classification_tag_action is not None
    ):
        raise HttpConfigurationError(
            "A Classification Tag action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_classification_tag_assign_action_enabled
        and v4_classification_tag_assign_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Classification Tag assignment feature requires a bound action host."
        )
    if (
        not settings.v4_classification_tag_assign_action_enabled
        and v4_classification_tag_assign_action is not None
    ):
        raise HttpConfigurationError(
            "A Classification Tag assignment host cannot be bound while its feature is disabled."
        )
    if settings.v4_address_action_enabled and v4_address_action is None:
        raise HttpConfigurationError(
            "The enabled IPv4 Address feature requires a bound action host."
        )
    if not settings.v4_address_action_enabled and v4_address_action is not None:
        raise HttpConfigurationError(
            "An IPv4 Address action host cannot be bound while its feature is disabled."
        )
    if settings.v4_address_group_action_enabled and v4_address_group_action is None:
        raise HttpConfigurationError(
            "The enabled Address Group feature requires a bound action host."
        )
    if (
        not settings.v4_address_group_action_enabled
        and v4_address_group_action is not None
    ):
        raise HttpConfigurationError(
            "An Address Group action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_ztna_device_context_diagnostic_enabled
        and v4_ztna_device_context_diagnostic is None
    ):
        raise HttpConfigurationError(
            "The enabled ZTNA diagnostic feature requires a bound diagnostic host."
        )
    if (
        not settings.v4_ztna_device_context_diagnostic_enabled
        and v4_ztna_device_context_diagnostic is not None
    ):
        raise HttpConfigurationError(
            "A ZTNA diagnostic host cannot be bound while its feature is disabled."
        )
    if settings.v4_ha_reconciliation_enabled:
        providers_bound = (
            settings.v4_ha_reconciliation_prerequisite_provider is not None
            and settings.v4_ha_reconciliation_query_permission_provider is not None
        )
        if v4_ha_reconciliation is None and not providers_bound:
            raise HttpConfigurationError(
                "Enabled HA reconciliation requires a runtime binding or both owner-only providers."
            )
        if v4_ha_reconciliation is not None and providers_bound:
            raise HttpConfigurationError(
                "HA reconciliation accepts either a runtime binding or provider files, not both."
            )
    elif v4_ha_reconciliation is not None:
        raise HttpConfigurationError(
            "An HA reconciliation runtime cannot be bound while its feature is disabled."
        )
    if settings.v4_ztna_folder_posture_enabled and v4_ztna_folder_posture is None:
        raise HttpConfigurationError(
            "The enabled ZTNA Folder posture diagnostic feature requires a bound diagnostic host."
        )
    if (
        not settings.v4_ztna_folder_posture_enabled
        and v4_ztna_folder_posture is not None
    ):
        raise HttpConfigurationError(
            "A ZTNA Folder posture diagnostic host cannot be bound while its feature is disabled."
        )
    if settings.v4_folder_rename_action_enabled and v4_folder_rename_action is None:
        raise HttpConfigurationError(
            "The enabled Folder rename feature requires a bound action host."
        )
    if (
        not settings.v4_folder_rename_action_enabled
        and v4_folder_rename_action is not None
    ):
        raise HttpConfigurationError(
            "A Folder rename action host cannot be bound while its feature is disabled."
        )
    if settings.v4_folder_archive_action_enabled and v4_folder_archive_action is None:
        raise HttpConfigurationError(
            "The enabled Folder archive feature requires a bound action host."
        )
    if (
        not settings.v4_folder_archive_action_enabled
        and v4_folder_archive_action is not None
    ):
        raise HttpConfigurationError(
            "A Folder archive action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_folder_policy_assign_action_enabled
        and v4_folder_policy_assign_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Folder policy assignment feature requires a bound action host."
        )
    if (
        not settings.v4_folder_policy_assign_action_enabled
        and v4_folder_policy_assign_action is not None
    ):
        raise HttpConfigurationError(
            "A Folder policy assignment action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_folder_policy_detach_action_enabled
        and v4_folder_policy_detach_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Folder policy detach feature requires a bound action host."
        )
    if (
        not settings.v4_folder_policy_detach_action_enabled
        and v4_folder_policy_detach_action is not None
    ):
        raise HttpConfigurationError(
            "A Folder policy detach action host cannot be bound while its feature is disabled."
        )
    if settings.v4_target_action_enabled and v4_target_action is None:
        raise HttpConfigurationError(
            "The enabled API Target feature requires a bound action host."
        )
    if not settings.v4_target_action_enabled and v4_target_action is not None:
        raise HttpConfigurationError(
            "An API Target action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_secret_metadata_action_enabled
        and v4_secret_metadata_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Secret metadata feature requires a bound action host."
        )
    if (
        not settings.v4_secret_metadata_action_enabled
        and v4_secret_metadata_action is not None
    ):
        raise HttpConfigurationError(
            "A Secret metadata action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_interface_web_proxy_action_enabled
        and v4_interface_web_proxy_action is None
    ):
        raise HttpConfigurationError(
            "The enabled interface Explicit Web Proxy feature requires a bound action host."
        )
    if (
        not settings.v4_interface_web_proxy_action_enabled
        and v4_interface_web_proxy_action is not None
    ):
        raise HttpConfigurationError(
            "An interface Explicit Web Proxy action host cannot be bound while its feature is disabled."
        )
    if settings.v4_target_update_action_enabled and v4_target_update_action is None:
        raise HttpConfigurationError(
            "The enabled API Target update feature requires a bound action host."
        )
    if (
        not settings.v4_target_update_action_enabled
        and v4_target_update_action is not None
    ):
        raise HttpConfigurationError(
            "An API Target update action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_certificate_csr_action_enabled
        and v4_certificate_csr_action is None
    ):
        raise HttpConfigurationError(
            "The enabled certificate CSR feature requires a bound action host."
        )
    if (
        not settings.v4_certificate_csr_action_enabled
        and v4_certificate_csr_action is not None
    ):
        raise HttpConfigurationError(
            "A certificate CSR action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_local_user_disable_action_enabled
        and v4_local_user_disable_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Local User disable feature requires a bound action host."
        )
    if (
        not settings.v4_local_user_disable_action_enabled
        and v4_local_user_disable_action is not None
    ):
        raise HttpConfigurationError(
            "A Local User disable action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_local_user_create_action_enabled
        and v4_local_user_create_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Local User create feature requires a bound action host."
        )
    if (
        not settings.v4_local_user_create_action_enabled
        and v4_local_user_create_action is not None
    ):
        raise HttpConfigurationError(
            "A Local User create action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_local_user_reset_action_enabled
        and v4_local_user_reset_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Local User reset feature requires a bound action host."
        )
    if (
        not settings.v4_local_user_reset_action_enabled
        and v4_local_user_reset_action is not None
    ):
        raise HttpConfigurationError(
            "A Local User reset action host cannot be bound while its feature is disabled."
        )
    if settings.v4_role_create_action_enabled and v4_role_create_action is None:
        raise HttpConfigurationError(
            "The enabled Role create feature requires a bound action host."
        )
    if not settings.v4_role_create_action_enabled and v4_role_create_action is not None:
        raise HttpConfigurationError(
            "A Role create action host cannot be bound while its feature is disabled."
        )
    if settings.v4_role_update_action_enabled and v4_role_update_action is None:
        raise HttpConfigurationError(
            "The enabled Role update feature requires a bound action host."
        )
    if not settings.v4_role_update_action_enabled and v4_role_update_action is not None:
        raise HttpConfigurationError(
            "A Role update action host cannot be bound while its feature is disabled."
        )
    if settings.v4_role_assign_action_enabled and v4_role_assign_action is None:
        raise HttpConfigurationError(
            "The enabled Role assignment feature requires a bound action host."
        )
    if not settings.v4_role_assign_action_enabled and v4_role_assign_action is not None:
        raise HttpConfigurationError(
            "A Role assignment action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_dlp_file_pattern_action_enabled
        and v4_dlp_file_pattern_action is None
    ):
        raise HttpConfigurationError(
            "The enabled DLP file-pattern feature requires a bound action host."
        )
    if (
        not settings.v4_dlp_file_pattern_action_enabled
        and v4_dlp_file_pattern_action is not None
    ):
        raise HttpConfigurationError(
            "A DLP file-pattern action host cannot be bound while its feature is disabled."
        )
    if settings.v4_dlp_sensor_action_enabled and v4_dlp_sensor_action is None:
        raise HttpConfigurationError(
            "The enabled DLP Sensor feature requires a bound action host."
        )
    if not settings.v4_dlp_sensor_action_enabled and v4_dlp_sensor_action is not None:
        raise HttpConfigurationError(
            "A DLP Sensor action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_antivirus_profile_action_enabled
        and v4_antivirus_profile_action is None
    ):
        raise HttpConfigurationError(
            "The enabled AntiVirus Profile feature requires a bound action host."
        )
    if (
        not settings.v4_antivirus_profile_action_enabled
        and v4_antivirus_profile_action is not None
    ):
        raise HttpConfigurationError(
            "An AntiVirus Profile action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_rdp_event_filter_action_enabled
        and v4_rdp_event_filter_action is None
    ):
        raise HttpConfigurationError(
            "The enabled RDP event-filter feature requires a bound action host."
        )
    if (
        not settings.v4_rdp_event_filter_action_enabled
        and v4_rdp_event_filter_action is not None
    ):
        raise HttpConfigurationError(
            "An RDP event-filter action host cannot be bound while its feature is disabled."
        )
    if settings.v4_secret_policy_action_enabled and v4_secret_policy_action is None:
        raise HttpConfigurationError(
            "The enabled Secret Policy feature requires a bound action host."
        )
    if (
        not settings.v4_secret_policy_action_enabled
        and v4_secret_policy_action is not None
    ):
        raise HttpConfigurationError(
            "A Secret Policy action host cannot be bound while its feature is disabled."
        )
    if settings.v4_ssh_filter_action_enabled and v4_ssh_filter_action is None:
        raise HttpConfigurationError(
            "The enabled SSH Filter feature requires a bound action host."
        )
    if (
        not settings.v4_ssh_filter_action_enabled
        and v4_ssh_filter_action is not None
    ):
        raise HttpConfigurationError(
            "An SSH Filter action host cannot be bound while its feature is disabled."
        )
    if settings.v4_launcher_action_enabled and v4_launcher_action is None:
        raise HttpConfigurationError(
            "The enabled Launcher feature requires a bound action host."
        )
    if not settings.v4_launcher_action_enabled and v4_launcher_action is not None:
        raise HttpConfigurationError(
            "A Launcher action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_launcher_update_action_enabled
        and v4_launcher_update_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Launcher update feature requires a bound action host."
        )
    if (
        not settings.v4_launcher_update_action_enabled
        and v4_launcher_update_action is not None
    ):
        raise HttpConfigurationError(
            "A Launcher update action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_launcher_matcher_action_enabled
        and v4_launcher_matcher_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Launcher matcher feature requires a bound action host."
        )
    if (
        not settings.v4_launcher_matcher_action_enabled
        and v4_launcher_matcher_action is not None
    ):
        raise HttpConfigurationError(
            "A Launcher matcher action host cannot be bound while its feature is disabled."
        )
    if settings.v4_template_action_enabled and v4_template_action is None:
        raise HttpConfigurationError(
            "The enabled Template feature requires a bound action host."
        )
    if not settings.v4_template_action_enabled and v4_template_action is not None:
        raise HttpConfigurationError(
            "A Template action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_template_archive_action_enabled
        and v4_template_archive_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Template archive feature requires a bound action host."
        )
    if (
        not settings.v4_template_archive_action_enabled
        and v4_template_archive_action is not None
    ):
        raise HttpConfigurationError(
            "A Template archive action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_dependency_updater_action_enabled
        and v4_dependency_updater_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Dependency Updater feature requires a bound action host."
        )
    if (
        not settings.v4_dependency_updater_action_enabled
        and v4_dependency_updater_action is not None
    ):
        raise HttpConfigurationError(
            "A Dependency Updater action host cannot be bound while its feature is disabled."
        )
    if settings.v4_secret_gateway_action_enabled and v4_secret_gateway_action is None:
        raise HttpConfigurationError(
            "The enabled Secret Gateway feature requires a bound action host."
        )
    if (
        not settings.v4_secret_gateway_action_enabled
        and v4_secret_gateway_action is not None
    ):
        raise HttpConfigurationError(
            "A Secret Gateway action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_client_integrity_action_enabled
        and v4_client_integrity_action is None
    ):
        raise HttpConfigurationError(
            "The enabled client-integrity feature requires a bound action host."
        )
    if (
        not settings.v4_client_integrity_action_enabled
        and v4_client_integrity_action is not None
    ):
        raise HttpConfigurationError(
            "A client-integrity action host cannot be bound while its feature is disabled."
        )
    if settings.v4_character_set_action_enabled and v4_character_set_action is None:
        raise HttpConfigurationError(
            "The enabled Character Set feature requires a bound action host."
        )
    if (
        not settings.v4_character_set_action_enabled
        and v4_character_set_action is not None
    ):
        raise HttpConfigurationError(
            "A Character Set action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_windows_app_filter_action_enabled
        and v4_windows_app_filter_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Windows App Filter feature requires a bound action host."
        )
    if (
        not settings.v4_windows_app_filter_action_enabled
        and v4_windows_app_filter_action is not None
    ):
        raise HttpConfigurationError(
            "A Windows App Filter action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_recording_policy_action_enabled
        and v4_recording_policy_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Recording Policy feature requires a bound action host."
        )
    if (
        not settings.v4_recording_policy_action_enabled
        and v4_recording_policy_action is not None
    ):
        raise HttpConfigurationError(
            "A Recording Policy action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_password_policy_action_enabled
        and v4_password_policy_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Password Policy feature requires a bound action host."
        )
    if (
        not settings.v4_password_policy_action_enabled
        and v4_password_policy_action is not None
    ):
        raise HttpConfigurationError(
            "A Password Policy action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_report_layout_action_enabled
        and v4_report_layout_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Report Layout feature requires a bound action host."
        )
    if (
        not settings.v4_report_layout_action_enabled
        and v4_report_layout_action is not None
    ):
        raise HttpConfigurationError(
            "A Report Layout action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_ztna_access_proxy_action_enabled
        and v4_ztna_access_proxy_action is None
    ):
        raise HttpConfigurationError(
            "The enabled ZTNA Access Proxy feature requires a bound action host."
        )
    if (
        not settings.v4_ztna_access_proxy_action_enabled
        and v4_ztna_access_proxy_action is not None
    ):
        raise HttpConfigurationError(
            "A ZTNA Access Proxy action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_ztna_user_control_action_enabled
        and v4_ztna_user_control_action is None
    ):
        raise HttpConfigurationError(
            "The enabled ZTNA user-control feature requires a bound action host."
        )
    if (
        not settings.v4_ztna_user_control_action_enabled
        and v4_ztna_user_control_action is not None
    ):
        raise HttpConfigurationError(
            "A ZTNA user-control action host cannot be bound while its feature is disabled."
        )
    if settings.v4_ztna_wad_debug_action_enabled and v4_ztna_wad_debug_action is None:
        raise HttpConfigurationError(
            "The enabled ZTNA WAD debug feature requires a bound action host."
        )
    if (
        not settings.v4_ztna_wad_debug_action_enabled
        and v4_ztna_wad_debug_action is not None
    ):
        raise HttpConfigurationError(
            "A ZTNA WAD debug action host cannot be bound while its feature is disabled."
        )
    if settings.v4_snmp_agent_action_enabled and v4_snmp_agent_action is None:
        raise HttpConfigurationError(
            "The enabled SNMP agent feature requires a bound action host."
        )
    if (
        not settings.v4_snmp_agent_action_enabled
        and v4_snmp_agent_action is not None
    ):
        raise HttpConfigurationError(
            "An SNMP agent action host cannot be bound while its feature is disabled."
        )
    if settings.v4_logging_disk_action_enabled and v4_logging_disk_action is None:
        raise HttpConfigurationError(
            "The enabled logging-disk feature requires a bound action host."
        )
    if (
        not settings.v4_logging_disk_action_enabled
        and v4_logging_disk_action is not None
    ):
        raise HttpConfigurationError(
            "A logging-disk action host cannot be bound while its feature is disabled."
        )
    if settings.v4_fortianalyzer_action_enabled and v4_fortianalyzer_action is None:
        raise HttpConfigurationError(
            "The enabled FortiAnalyzer feature requires a bound action host."
        )
    if (
        not settings.v4_fortianalyzer_action_enabled
        and v4_fortianalyzer_action is not None
    ):
        raise HttpConfigurationError(
            "A FortiAnalyzer action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_maintenance_mode_action_enabled
        and v4_maintenance_mode_action is None
    ):
        raise HttpConfigurationError(
            "The enabled maintenance-mode feature requires a bound action host."
        )
    if (
        not settings.v4_maintenance_mode_action_enabled
        and v4_maintenance_mode_action is not None
    ):
        raise HttpConfigurationError(
            "A maintenance-mode action host cannot be bound while its feature is disabled."
        )
    if settings.v4_secret_audit_action_enabled and v4_secret_audit_action is None:
        raise HttpConfigurationError(
            "The enabled Secret Audit feature requires a bound action host."
        )
    if (
        not settings.v4_secret_audit_action_enabled
        and v4_secret_audit_action is not None
    ):
        raise HttpConfigurationError(
            "A Secret Audit action host cannot be bound while its feature is disabled."
        )
    if (settings.v4_terraform_plan_report_enabled != (v4_terraform_plan_report is not None)
            or v4_terraform_plan_report is not None and (
                settings.runtime_profile is not RuntimeProfile.V4_CONTROLLED
                or settings.auth_mode != "local_oauth" or settings.v4_planning_authorization is None
                or type(v4_terraform_plan_report) is not ProtectedTerraformPlanReport)):
        raise HttpConfigurationError("The Terraform report requires its enabled controlled OAuth host.")
    if settings.v4_secret_audit_summary_enabled != (v4_secret_audit_summary is not None):
        raise HttpConfigurationError(
            "The Secret Audit summary feature and host must match."
        )
    if settings.v4_active_launch_action_enabled and v4_active_launch_action is None:
        raise HttpConfigurationError(
            "The enabled active-launch feature requires a bound action host."
        )
    if (
        not settings.v4_active_launch_action_enabled
        and v4_active_launch_action is not None
    ):
        raise HttpConfigurationError(
            "An active-launch action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_automation_trigger_action_enabled
        and v4_automation_trigger_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Automation Trigger feature requires a bound action host."
        )
    if (
        not settings.v4_automation_trigger_action_enabled
        and v4_automation_trigger_action is not None
    ):
        raise HttpConfigurationError(
            "An Automation Trigger action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_automation_action_action_enabled
        and v4_automation_action_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Automation Action feature requires a bound action host."
        )
    if (
        not settings.v4_automation_action_action_enabled
        and v4_automation_action_action is not None
    ):
        raise HttpConfigurationError(
            "An Automation Action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_automation_stitch_action_enabled
        and v4_automation_stitch_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Automation Stitch feature requires a bound action host."
        )
    if (
        not settings.v4_automation_stitch_action_enabled
        and v4_automation_stitch_action is not None
    ):
        raise HttpConfigurationError(
            "An Automation Stitch action host cannot be bound while its feature is disabled."
        )
    if settings.v4_user_group_action_enabled and v4_user_group_action is None:
        raise HttpConfigurationError(
            "The enabled User Group feature requires a bound action host."
        )
    if (
        not settings.v4_user_group_action_enabled
        and v4_user_group_action is not None
    ):
        raise HttpConfigurationError(
            "A User Group action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_user_group_membership_action_enabled
        and v4_user_group_membership_action is None
    ):
        raise HttpConfigurationError(
            "The enabled User Group membership feature requires a bound action host."
        )
    if (
        not settings.v4_user_group_membership_action_enabled
        and v4_user_group_membership_action is not None
    ):
        raise HttpConfigurationError(
            "A User Group membership action host cannot be bound while its feature is disabled."
        )
    if settings.v4_apl_action_enabled and v4_apl_action is None:
        raise HttpConfigurationError(
            "The enabled Auto-Provision Rule feature requires a bound action host."
        )
    if not settings.v4_apl_action_enabled and v4_apl_action is not None:
        raise HttpConfigurationError(
            "An Auto-Provision Rule action host cannot be bound while its feature is disabled."
        )
    if settings.v4_apl_disable_action_enabled and v4_apl_disable_action is None:
        raise HttpConfigurationError(
            "The enabled Auto-Provision Rule disable feature requires a bound action host."
        )
    if (
        not settings.v4_apl_disable_action_enabled
        and v4_apl_disable_action is not None
    ):
        raise HttpConfigurationError(
            "An Auto-Provision Rule disable action host cannot be bound while its feature is disabled."
        )
    if settings.v4_schedule_action_enabled and v4_schedule_action is None:
        raise HttpConfigurationError(
            "The enabled Schedule feature requires a bound action host."
        )
    if not settings.v4_schedule_action_enabled and v4_schedule_action is not None:
        raise HttpConfigurationError(
            "A Schedule action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_schedule_assign_action_enabled
        and v4_schedule_assign_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Schedule assignment feature requires a bound action host."
        )
    if (
        not settings.v4_schedule_assign_action_enabled
        and v4_schedule_assign_action is not None
    ):
        raise HttpConfigurationError(
            "A Schedule assignment host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_approval_profile_action_enabled
        and v4_approval_profile_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Approval Profile feature requires a bound action host."
        )
    if (
        not settings.v4_approval_profile_action_enabled
        and v4_approval_profile_action is not None
    ):
        raise HttpConfigurationError(
            "An Approval Profile action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_approval_profile_update_action_enabled
        and v4_approval_profile_update_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Approval Profile update feature requires a bound action host."
        )
    if (
        not settings.v4_approval_profile_update_action_enabled
        and v4_approval_profile_update_action is not None
    ):
        raise HttpConfigurationError(
            "An Approval Profile update action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_approval_email_template_action_enabled
        and v4_approval_email_template_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Approval Email Template feature requires a bound action host."
        )
    if (
        not settings.v4_approval_email_template_action_enabled
        and v4_approval_email_template_action is not None
    ):
        raise HttpConfigurationError(
            "An Approval Email Template action host cannot be bound while its feature is disabled."
        )
    if (
        settings.v4_approval_email_template_update_action_enabled
        and v4_approval_email_template_update_action is None
    ):
        raise HttpConfigurationError(
            "The enabled Approval Email Template update feature requires a bound action host."
        )
    if (
        not settings.v4_approval_email_template_update_action_enabled
        and v4_approval_email_template_update_action is not None
    ):
        raise HttpConfigurationError(
            "An Approval Email Template update action host cannot be bound while its feature is disabled."
        )
    if (
        getattr(settings, "v4_secret_request_create_enabled", False)
        and v4_secret_request_create_action is None
    ):
        raise HttpConfigurationError(
            "Enabled Secret Request Create requires a bound action host."
        )
    if (
        not getattr(settings, "v4_secret_request_create_enabled", False)
        and v4_secret_request_create_action is not None
    ):
        raise HttpConfigurationError(
            "A Secret Request Create action host cannot be bound while its feature is disabled."
        )
    if settings.auth_mode == "oauth":
        assert settings.oauth_issuer is not None
        assert settings.oauth_jwks_url is not None
        assert settings.oauth_audience is not None
        assert settings.public_url is not None
        auth_settings = AuthSettings(
            issuer_url=AnyHttpUrl(settings.oauth_issuer),
            resource_server_url=AnyHttpUrl(settings.public_url),
            required_scopes=list(settings.oauth_required_scopes),
            # OAuthJwtTokenVerifier validates the configured audience itself.
            validate_token_resource=False,
        )
        token_verifier = OAuthJwtTokenVerifier(
            issuer=settings.oauth_issuer,
            jwks_url=settings.oauth_jwks_url,
            audience=settings.oauth_audience,
            algorithms=settings.oauth_algorithms,
        )
    if settings.auth_mode == "local_oauth":
        assert settings.local_oauth is not None
        assert settings.public_url is not None
        provider = (LocalOAuthProvider(settings.local_oauth) if owner_file_intake_issuer is None
                    else owner_file_intake_issuer.provider)
        auth_settings = AuthSettings(
            issuer_url=AnyHttpUrl(settings.local_oauth.issuer),
            resource_server_url=AnyHttpUrl(settings.public_url),
            required_scopes=[settings.local_oauth.scope],
            # LocalOAuthProvider rejects tokens for any other resource.
            validate_token_resource=False,
        )
        token_verifier = ProviderTokenVerifier(provider)
        custom_http_routes.extend(provider.authorization_routes())
        if settings.controlled_operation is not None:
            approval_service = LocalApprovalService(
                provider,
                settings.controlled_operation,
            )
            custom_http_routes.extend(approval_service.routes())
        if settings.v4_confirmation is not None:
            if v4_plan_host_factory is None:
                raise HttpConfigurationError(
                    "V4 confirmation state requires a bound plan-only host factory."
                )
            try:
                components = v4_plan_host_factory(provider, settings.v4_confirmation)
            except V4RuntimeHostError as exc:
                raise HttpConfigurationError(str(exc)) from exc
            confirmation_service = getattr(components, "confirmation_service", None)
            candidate_services = getattr(components, "plan_services", None)
            if (
                not isinstance(confirmation_service, LocalIntentConfirmationService)
                or candidate_services is None
            ):
                raise HttpConfigurationError("V4 planning host components are invalid.")
            custom_http_routes.extend(confirmation_service.routes())
            v4_plan_services = candidate_services
            if settings.v4_onboarding_execution_enabled:
                if (
                    not isinstance(components, V4PlanHostComponents)
                    or components.secret_onboarding_projection_source is None
                ):
                    raise HttpConfigurationError(
                        "Onboarding execution requires exact source-backed onboarding host components."
                    )
                assert v4_onboarding_execution_factory is not None
                try:
                    actions = v4_onboarding_execution_factory(components)
                except Exception as exc:
                    raise HttpConfigurationError(
                        "Trusted onboarding execution factory is unavailable."
                    ) from exc
                if (
                    type(actions) is not tuple
                    or len(actions) != 2
                    or (
                        actions[0] is not None
                        if components.access_domain_projection_source is None
                        else not isinstance(
                            actions[0], ProtectedAccessDomainOnboardingMcpAction
                        )
                    )
                    or not isinstance(
                        actions[1], ProtectedSecretOnboardingMcpAction
                    )
                ):
                    raise HttpConfigurationError(
                        "Trusted onboarding execution factory returned an invalid binding."
                    )
                (
                    v4_access_domain_execution_action,
                    v4_secret_onboarding_execution_action,
                ) = actions
            if settings.v4_approval_and_observe_execution_enabled:
                if (
                    not isinstance(components, V4PlanHostComponents)
                    or components.approval_and_observe_projection_source is None
                ):
                    raise HttpConfigurationError(
                        "Approval execution requires exact source-backed approval host components."
                    )
                assert v4_approval_and_observe_execution_factory is not None
                try:
                    approval_action = (
                        v4_approval_and_observe_execution_factory(components)
                    )
                except Exception as exc:
                    raise HttpConfigurationError(
                        "Trusted approval execution factory is unavailable."
                    ) from exc
                if not isinstance(
                    approval_action,
                    ProtectedApprovalAndObserveMcpAction,
                ):
                    raise HttpConfigurationError(
                        "Trusted approval execution factory returned an invalid binding."
                    )
                v4_approval_and_observe_execution_action = approval_action

            if settings.v4_ad_discovery_execution_enabled:
                if (
                    not isinstance(components, V4PlanHostComponents)
                    or components.ad_discovery_projection_source is None
                ):
                    raise HttpConfigurationError("AD Discovery execution requires exact AD host components.")
                assert v4_ad_discovery_execution_factory is not None
                try:
                    ad_action = v4_ad_discovery_execution_factory(components)
                except Exception:
                    raise HttpConfigurationError("Trusted AD Discovery factory is unavailable.") from None
                if type(ad_action) is not ProtectedAdDiscoveryMcpAction:
                    raise HttpConfigurationError("Trusted AD Discovery factory returned an invalid binding.")
                v4_ad_discovery_execution_action = ad_action

    server = FortiPamMcpServer(
        auth_settings=auth_settings,
        token_verifier=token_verifier,
        custom_http_routes=custom_http_routes,
        diagnostic_settings=settings.diagnostic,
        runtime_profile=settings.runtime_profile,
        v4_plan_services=v4_plan_services,
        v4_planning_authorization=settings.v4_planning_authorization,
        v4_secret_request_observation=v4_secret_request_observation,
        v4_access_domain_execution_action=v4_access_domain_execution_action,
        v4_secret_onboarding_execution_action=(
            v4_secret_onboarding_execution_action
        ),
        v4_onboarding_execution_enabled=(
            settings.v4_onboarding_execution_enabled
        ),
        v4_ad_discovery_execution_action=v4_ad_discovery_execution_action,
        v4_ad_discovery_execution_enabled=settings.v4_ad_discovery_execution_enabled,
        v4_approval_and_observe_execution_action=(
            v4_approval_and_observe_execution_action
        ),
        v4_approval_and_observe_execution_enabled=(
            settings.v4_approval_and_observe_execution_enabled
        ),
        v4_folder_action=v4_folder_action,
        v4_folder_action_enabled=settings.v4_folder_action_enabled,
        v4_folder_acl_action=v4_folder_acl_action,
        v4_folder_acl_action_enabled=settings.v4_folder_acl_action_enabled,
        v4_folder_acl_revoke_action=v4_folder_acl_revoke_action,
        v4_folder_acl_revoke_action_enabled=(
            settings.v4_folder_acl_revoke_action_enabled
        ),
        v4_classification_tag_action=v4_classification_tag_action,
        v4_classification_tag_action_enabled=(
            settings.v4_classification_tag_action_enabled
        ),
        v4_classification_tag_assign_action=v4_classification_tag_assign_action,
        v4_classification_tag_assign_action_enabled=(
            settings.v4_classification_tag_assign_action_enabled
        ),
        v4_address_action=v4_address_action,
        v4_address_action_enabled=settings.v4_address_action_enabled,
        v4_address_group_action=v4_address_group_action,
        v4_address_group_action_enabled=settings.v4_address_group_action_enabled,
        v4_ztna_device_context_diagnostic=v4_ztna_device_context_diagnostic,
        v4_ztna_device_context_diagnostic_enabled=(
            settings.v4_ztna_device_context_diagnostic_enabled
        ),
        v4_ha_reconciliation=v4_ha_reconciliation,
        v4_ha_reconciliation_prerequisite_provider=(
            None
            if v4_ha_reconciliation is not None
            else settings.v4_ha_reconciliation_prerequisite_provider
        ),
        v4_ha_reconciliation_query_permission_provider=(
            None
            if v4_ha_reconciliation is not None
            else settings.v4_ha_reconciliation_query_permission_provider
        ),
        v4_ha_reconciliation_enabled=settings.v4_ha_reconciliation_enabled,
        v4_ztna_folder_posture=v4_ztna_folder_posture,
        v4_ztna_folder_posture_enabled=settings.v4_ztna_folder_posture_enabled,
        v4_folder_rename_action=v4_folder_rename_action,
        v4_folder_rename_action_enabled=settings.v4_folder_rename_action_enabled,
        v4_folder_archive_action=v4_folder_archive_action,
        v4_folder_archive_action_enabled=settings.v4_folder_archive_action_enabled,
        v4_folder_policy_assign_action=v4_folder_policy_assign_action,
        v4_folder_policy_assign_action_enabled=(
            settings.v4_folder_policy_assign_action_enabled
        ),
        v4_folder_policy_detach_action=v4_folder_policy_detach_action,
        v4_folder_policy_detach_action_enabled=(
            settings.v4_folder_policy_detach_action_enabled
        ),
        v4_target_action=v4_target_action,
        v4_target_action_enabled=settings.v4_target_action_enabled,
        v4_secret_metadata_action=v4_secret_metadata_action,
        v4_secret_metadata_action_enabled=(
            settings.v4_secret_metadata_action_enabled
        ),
        v4_interface_web_proxy_action=v4_interface_web_proxy_action,
        v4_interface_web_proxy_action_enabled=(
            settings.v4_interface_web_proxy_action_enabled
        ),
        v4_target_update_action=v4_target_update_action,
        v4_target_update_action_enabled=settings.v4_target_update_action_enabled,
        v4_certificate_csr_action=v4_certificate_csr_action,
        v4_certificate_csr_action_enabled=(
            settings.v4_certificate_csr_action_enabled
        ),
        v4_local_user_disable_action=v4_local_user_disable_action,
        v4_local_user_disable_action_enabled=(
            settings.v4_local_user_disable_action_enabled
        ),
        v4_local_user_create_action=v4_local_user_create_action,
        v4_local_user_create_action_enabled=(
            settings.v4_local_user_create_action_enabled
        ),
        v4_local_user_reset_action=v4_local_user_reset_action,
        v4_local_user_reset_action_enabled=(
            settings.v4_local_user_reset_action_enabled
        ),
        v4_role_create_action=v4_role_create_action,
        v4_role_create_action_enabled=settings.v4_role_create_action_enabled,
        v4_role_update_action=v4_role_update_action,
        v4_role_update_action_enabled=settings.v4_role_update_action_enabled,
        v4_role_assign_action=v4_role_assign_action,
        v4_role_assign_action_enabled=settings.v4_role_assign_action_enabled,
        v4_dlp_file_pattern_action=v4_dlp_file_pattern_action,
        v4_dlp_file_pattern_action_enabled=(
            settings.v4_dlp_file_pattern_action_enabled
        ),
        v4_dlp_sensor_action=v4_dlp_sensor_action,
        v4_dlp_sensor_action_enabled=settings.v4_dlp_sensor_action_enabled,
        v4_antivirus_profile_action=v4_antivirus_profile_action,
        v4_antivirus_profile_action_enabled=(
            settings.v4_antivirus_profile_action_enabled
        ),
        v4_rdp_event_filter_action=v4_rdp_event_filter_action,
        v4_rdp_event_filter_action_enabled=(
            settings.v4_rdp_event_filter_action_enabled
        ),
        v4_secret_policy_action=v4_secret_policy_action,
        v4_secret_policy_action_enabled=settings.v4_secret_policy_action_enabled,
        v4_ssh_filter_action=v4_ssh_filter_action,
        v4_ssh_filter_action_enabled=settings.v4_ssh_filter_action_enabled,
        v4_launcher_action=v4_launcher_action,
        v4_launcher_action_enabled=settings.v4_launcher_action_enabled,
        v4_launcher_update_action=v4_launcher_update_action,
        v4_launcher_update_action_enabled=(
            settings.v4_launcher_update_action_enabled
        ),
        v4_launcher_matcher_action=v4_launcher_matcher_action,
        v4_launcher_matcher_action_enabled=(
            settings.v4_launcher_matcher_action_enabled
        ),
        v4_template_action=v4_template_action,
        v4_template_action_enabled=settings.v4_template_action_enabled,
        v4_template_archive_action=v4_template_archive_action,
        v4_template_archive_action_enabled=(
            settings.v4_template_archive_action_enabled
        ),
        v4_dependency_updater_action=v4_dependency_updater_action,
        v4_dependency_updater_action_enabled=(
            settings.v4_dependency_updater_action_enabled
        ),
        v4_secret_gateway_action=v4_secret_gateway_action,
        v4_secret_gateway_action_enabled=settings.v4_secret_gateway_action_enabled,
        v4_client_integrity_action=v4_client_integrity_action,
        v4_client_integrity_action_enabled=(
            settings.v4_client_integrity_action_enabled
        ),
        v4_character_set_action=v4_character_set_action,
        v4_character_set_action_enabled=settings.v4_character_set_action_enabled,
        v4_windows_app_filter_action=v4_windows_app_filter_action,
        v4_windows_app_filter_action_enabled=(
            settings.v4_windows_app_filter_action_enabled
        ),
        v4_recording_policy_action=v4_recording_policy_action,
        v4_recording_policy_action_enabled=(
            settings.v4_recording_policy_action_enabled
        ),
        v4_password_policy_action=v4_password_policy_action,
        v4_password_policy_action_enabled=(
            settings.v4_password_policy_action_enabled
        ),
        v4_report_layout_action=v4_report_layout_action,
        v4_report_layout_action_enabled=(
            settings.v4_report_layout_action_enabled
        ),
        v4_ztna_access_proxy_action=v4_ztna_access_proxy_action,
        v4_ztna_access_proxy_action_enabled=(
            settings.v4_ztna_access_proxy_action_enabled
        ),
        v4_ztna_user_control_action=v4_ztna_user_control_action,
        v4_ztna_user_control_action_enabled=(
            settings.v4_ztna_user_control_action_enabled
        ),
        v4_ztna_wad_debug_action=v4_ztna_wad_debug_action,
        v4_ztna_wad_debug_action_enabled=(
            settings.v4_ztna_wad_debug_action_enabled
        ),
        v4_snmp_agent_action=v4_snmp_agent_action,
        v4_snmp_agent_action_enabled=settings.v4_snmp_agent_action_enabled,
        v4_logging_disk_action=v4_logging_disk_action,
        v4_logging_disk_action_enabled=settings.v4_logging_disk_action_enabled,
        v4_fortianalyzer_action=v4_fortianalyzer_action,
        v4_fortianalyzer_action_enabled=settings.v4_fortianalyzer_action_enabled,
        v4_maintenance_mode_action=v4_maintenance_mode_action,
        v4_maintenance_mode_action_enabled=(
            settings.v4_maintenance_mode_action_enabled
        ),
        v4_secret_audit_action=v4_secret_audit_action,
        v4_secret_audit_action_enabled=settings.v4_secret_audit_action_enabled,
        v4_secret_audit_summary=v4_secret_audit_summary,
        v4_terraform_plan_report=v4_terraform_plan_report,
        v4_terraform_plan_report_enabled=settings.v4_terraform_plan_report_enabled,
        v4_secret_audit_summary_enabled=settings.v4_secret_audit_summary_enabled,
        v4_active_launch_action=v4_active_launch_action,
        v4_active_launch_action_enabled=settings.v4_active_launch_action_enabled,
        v4_automation_trigger_action=v4_automation_trigger_action,
        v4_automation_trigger_action_enabled=(
            settings.v4_automation_trigger_action_enabled
        ),
        v4_automation_action_action=v4_automation_action_action,
        v4_automation_action_action_enabled=(
            settings.v4_automation_action_action_enabled
        ),
        v4_automation_stitch_action=v4_automation_stitch_action,
        v4_automation_stitch_action_enabled=(
            settings.v4_automation_stitch_action_enabled
        ),
        v4_user_group_action=v4_user_group_action,
        v4_user_group_action_enabled=settings.v4_user_group_action_enabled,
        v4_user_group_membership_action=v4_user_group_membership_action,
        v4_user_group_membership_action_enabled=(
            settings.v4_user_group_membership_action_enabled
        ),
        v4_apl_action=v4_apl_action,
        v4_apl_action_enabled=settings.v4_apl_action_enabled,
        v4_apl_disable_action=v4_apl_disable_action,
        v4_apl_disable_action_enabled=settings.v4_apl_disable_action_enabled,
        v4_schedule_action=v4_schedule_action,
        v4_schedule_action_enabled=settings.v4_schedule_action_enabled,
        v4_schedule_assign_action=v4_schedule_assign_action,
        v4_schedule_assign_action_enabled=(
            settings.v4_schedule_assign_action_enabled
        ),
        v4_approval_profile_action=v4_approval_profile_action,
        v4_approval_profile_action_enabled=(
            settings.v4_approval_profile_action_enabled
        ),
        v4_approval_profile_update_action=v4_approval_profile_update_action,
        v4_approval_profile_update_action_enabled=(
            settings.v4_approval_profile_update_action_enabled
        ),
        v4_approval_email_template_action=v4_approval_email_template_action,
        v4_approval_email_template_action_enabled=(
            settings.v4_approval_email_template_action_enabled
        ),
        v4_approval_email_template_update_action=(
            v4_approval_email_template_update_action
        ),
        v4_approval_email_template_update_action_enabled=(
            settings.v4_approval_email_template_update_action_enabled
        ),
        v4_secret_request_create_action=v4_secret_request_create_action,
        v4_secret_request_create_enabled=(
            getattr(settings, "v4_secret_request_create_enabled", False)
        ),
        v4_secret_dlp_association_candidate_action=v4_secret_dlp_association_candidate_action,
        v4_http_oauth=settings.auth_mode == "local_oauth",
    )
    if v4_isolated_folder_action is not None:
        from .isolated_folder_mcp_action import register_isolated_folder_tools
        register_isolated_folder_tools(server, v4_isolated_folder_action)
    if v4_isolated_folder_policy_transition_candidate_action is not None:
        from .isolated_folder_policy_transition_mcp_action import register_isolated_folder_policy_transition_candidate_tools
        register_isolated_folder_policy_transition_candidate_tools(server, v4_isolated_folder_policy_transition_candidate_action)
    if v4_folder_traversal_action is not None:
        from .folder_traversal_mcp_action import register_folder_traversal_tools
        register_folder_traversal_tools(server, v4_folder_traversal_action)
    if v4_local_user_reset_candidate_action is not None:
        from .local_user_reset_candidate_mcp_action import register_local_user_reset_candidate_tools
        register_local_user_reset_candidate_tools(server, v4_local_user_reset_candidate_action)
    if v4_local_user_reset_owned_action is not None:
        from .local_user_reset_owned_mcp import register_local_reset_owned_tools
        register_local_reset_owned_tools(server, v4_local_user_reset_owned_action)
    if v4_password_verification_candidate_action is not None:
        from .password_verification_mcp_action import register_password_verification_candidate_tools
        register_password_verification_candidate_tools(server, v4_password_verification_candidate_action)
    if v4_password_change_schedule_candidate_action is not None:
        from .password_change_schedule_mcp_action import register_password_change_schedule_candidate_tools
        register_password_change_schedule_candidate_tools(server, v4_password_change_schedule_candidate_action)
    if v4_secret_description_update_candidate_action is not None:
        from .secret_description_update_mcp_action import register_secret_description_update_candidate_tools
        register_secret_description_update_candidate_tools(server, v4_secret_description_update_candidate_action)
    if v4_secret_event_subscription_candidate is not None:
        from .secret_event_subscription_mcp_action import register_secret_event_subscription_candidate_tools
        register_secret_event_subscription_candidate_tools(server, v4_secret_event_subscription_candidate)
    if v4_secret_checkout_association_candidate_action is not None:
        from .secret_checkout_association_mcp_action import register_secret_checkout_association_candidate_tools
        register_secret_checkout_association_candidate_tools(server, v4_secret_checkout_association_candidate_action)
    if v4_secret_checkout_effect_candidate_action is not None:
        from .secret_checkout_effect_mcp_action import register_secret_checkout_effect_candidate_tools
        register_secret_checkout_effect_candidate_tools(server, v4_secret_checkout_effect_candidate_action)
    if v4_secret_request_approval_revoke_candidate_action is not None:
        from .secret_request_approval_revoke_mcp_action import register_secret_request_approval_revoke_tools
        register_secret_request_approval_revoke_tools(server, v4_secret_request_approval_revoke_candidate_action)
    if v4_ldap_server_candidate_action is not None:
        from .ldap_server_mcp_action import register_ldap_server_candidate_tools
        register_ldap_server_candidate_tools(server, v4_ldap_server_candidate_action)
    if v4_system_email_local_candidate_action is not None:
        from .system_email_local_mcp_action import register_system_email_local_candidate_tools
        register_system_email_local_candidate_tools(server, v4_system_email_local_candidate_action)
    if v4_scim_local_candidate_action is not None:
        from .scim_client_local_mcp_action import register_scim_local_candidate_tools
        register_scim_local_candidate_tools(server, v4_scim_local_candidate_action)
    if v4_saml_local_candidate_action is not None:
        from .saml_server_local_mcp_action import register_saml_local_candidate_tools
        register_saml_local_candidate_tools(server, v4_saml_local_candidate_action)
    if v4_email_alert_general_preview_action is not None:
        from .email_alert_general_preview_action import register_email_alert_general_preview_tool
        register_email_alert_general_preview_tool(server, v4_email_alert_general_preview_action)
    if v4_license_vm_preview_action is not None:
        from .license_vm_preview_action import register_license_vm_preview_tool
        register_license_vm_preview_tool(server, v4_license_vm_preview_action)
    if v4_approval_delivery_preview_action is not None:
        from .approval_delivery_preview_action import register_approval_delivery_preview_tool
        register_approval_delivery_preview_tool(server, v4_approval_delivery_preview_action)
    if v4_approval_delivery_local_candidate_action is not None:
        from .approval_delivery_local_mcp_action import register_approval_delivery_local_candidate_tools
        register_approval_delivery_local_candidate_tools(server, v4_approval_delivery_local_candidate_action)
    if v4_email_alert_local_candidate_action is not None:
        from .email_alert_local_mcp_action import register_email_alert_local_candidate_tools
        register_email_alert_local_candidate_tools(server, v4_email_alert_local_candidate_action)
    if v4_glass_break_preview_action is not None:
        from .glass_break_preview_action import register_glass_break_preview_tool
        register_glass_break_preview_tool(server, v4_glass_break_preview_action)
    if v4_glass_break_local_candidate_action is not None:
        from .glass_break_local_mcp_action import register_glass_break_local_candidate_tools
        register_glass_break_local_candidate_tools(server, v4_glass_break_local_candidate_action)
    if v4_fortitoken_local_preview_action is not None:
        from .fortitoken_local_preview_action import register_fortitoken_local_preview_tools
        register_fortitoken_local_preview_tools(server, v4_fortitoken_local_preview_action)
    if v4_windows_jit_script_preview_action is not None:
        from .windows_jit_script_preview_action import register_windows_jit_script_preview_tool
        register_windows_jit_script_preview_tool(server, v4_windows_jit_script_preview_action)
    if v4_windows_jit_local_candidate_action is not None:
        from .windows_jit_local_mcp_action import register_windows_jit_local_candidate_tools
        register_windows_jit_local_candidate_tools(server, v4_windows_jit_local_candidate_action)
    if v4_fortitoken_local_candidate_action is not None:
        from .fortitoken_local_mcp_action import register_fortitoken_local_candidate_tools
        register_fortitoken_local_candidate_tools(server, v4_fortitoken_local_candidate_action)
    if v4_radius_server_lifecycle_candidate_action is not None:
        from .radius_server_lifecycle_mcp_action import register_radius_server_lifecycle_candidate_tools
        register_radius_server_lifecycle_candidate_tools(server, v4_radius_server_lifecycle_candidate_action)
    if v4_radius_user_recovery_candidate_action is not None:
        from .radius_remote_user_recovery_mcp_action import register_radius_remote_user_recovery_tools
        register_radius_remote_user_recovery_tools(server, v4_radius_user_recovery_candidate_action)
    if v4_radius_user_lifecycle_candidate_action is not None:
        from .radius_remote_user_lifecycle_mcp_action import register_radius_remote_user_lifecycle_tools
        register_radius_remote_user_lifecycle_tools(server, v4_radius_user_lifecycle_candidate_action)
    if v4_jwt_owner_candidate_action is not None:
        from .jwt_manual_key_owner_mcp_action import register_jwt_manual_key_owner_tools
        register_jwt_manual_key_owner_tools(server, v4_jwt_owner_candidate_action)
    if v4_job_execution_owned_candidate_action is not None:
        from .job_execution_owned_mcp_action import register_job_execution_owned_tools
        register_job_execution_owned_tools(server, v4_job_execution_owned_candidate_action)
    if v4_job_definition_owned_candidate_action is not None:
        from .job_definition_owned_mcp_action import register_job_definition_owned_tools
        register_job_definition_owned_tools(server, v4_job_definition_owned_candidate_action)
    if v4_jwt_rotation_candidate_action is not None:
        from .jwt_rotation_mcp_action import register_jwt_rotation_tools
        register_jwt_rotation_tools(server, v4_jwt_rotation_candidate_action)
    if v4_radius_server_pair_lifecycle_candidate_action is not None:
        from .radius_server_pair_lifecycle_mcp_action import register_radius_server_pair_lifecycle_candidate_tools
        register_radius_server_pair_lifecycle_candidate_tools(server, v4_radius_server_pair_lifecycle_candidate_action)
    if v4_ldap_server_update_candidate_action is not None:
        from .ldap_server_update_mcp_action import register_ldap_server_update_candidate_tools
        register_ldap_server_update_candidate_tools(server, v4_ldap_server_update_candidate_action)
    if v4_dns_timeout_candidate_action is not None:
        from .dns_timeout_mcp_action import register_dns_timeout_candidate_tools
        register_dns_timeout_candidate_tools(server, v4_dns_timeout_candidate_action)
    if v4_crl_candidate_action is not None:
        from .crl_import_mcp_action import register_crl_candidate_tools
        register_crl_candidate_tools(server, v4_crl_candidate_action)
    if v4_remote_certificate_candidate_action is not None:
        from .remote_certificate_mcp_action import register_remote_certificate_candidate_tools
        register_remote_certificate_candidate_tools(server, v4_remote_certificate_candidate_action)
    if v4_ems_timeout_candidate_action is not None:
        from .ems_timeout_mcp_action import register_ems_timeout_candidate_tools
        register_ems_timeout_candidate_tools(server, v4_ems_timeout_candidate_action)
    if v4_ems_tag_candidate_action is not None:
        from .ems_tag_mcp_action import register_ems_tag_candidate_tools
        register_ems_tag_candidate_tools(server, v4_ems_tag_candidate_action)
    if v4_ems_tag_principal_binding is not None:
        from .ems_tag_principal_binding import register_ems_tag_principal_binding_tool
        register_ems_tag_principal_binding_tool(server, v4_ems_tag_principal_binding)
    if v4_ems_rule_set_metadata_action is not None:
        from .ems_rule_set_metadata_mcp_action import register_ems_rule_set_metadata_tools
        register_ems_rule_set_metadata_tools(server, v4_ems_rule_set_metadata_action)
    if v4_logging_disk_size_candidate_action is not None:
        from .logging_disk_size_mcp_action import register_logging_disk_size_candidate_tools
        register_logging_disk_size_candidate_tools(server, v4_logging_disk_size_candidate_action)
    if v4_backup_export_candidate_action is not None:
        from .backup_export_mcp_action import register_backup_export_candidate_tools
        register_backup_export_candidate_tools(server, v4_backup_export_candidate_action)
    if secret_bulk_import_action is not None:
        from .secret_bulk_import_mcp_action import register_secret_bulk_import_candidate_tools
        register_secret_bulk_import_candidate_tools(server, secret_bulk_import_action)
    if v4_ztna_group_candidate_action is not None:
        from .ztna_group_mcp_action import register_ztna_group_candidate_tools
        register_ztna_group_candidate_tools(server, v4_ztna_group_candidate_action)
    if v4_disabled_route_candidate_action is not None:
        from .disabled_route_mcp_action import register_disabled_route_candidate_tools
        register_disabled_route_candidate_tools(server, v4_disabled_route_candidate_action)
    if v4_apl_role_update_candidate_action is not None:
        from .apl_role_update_mcp_action import register_apl_role_update_candidate_tools
        register_apl_role_update_candidate_tools(server, v4_apl_role_update_candidate_action)
    if v4_instruction_profile_candidate_action is not None:
        from .instruction_profile_mcp_action import register_instruction_profile_candidate_tools
        register_instruction_profile_candidate_tools(server, v4_instruction_profile_candidate_action)
    if v4_instruction_feature_candidate_action is not None:
        from .instruction_feature_mcp_action import register_instruction_feature_candidate_tools
        register_instruction_feature_candidate_tools(server, v4_instruction_feature_candidate_action)
    if v4_instruction_quota_candidate_action is not None:
        from .instruction_quota_mcp_action import register_instruction_quota_candidate_tools
        register_instruction_quota_candidate_tools(server, v4_instruction_quota_candidate_action)
    if v4_instruction_quota_recovery_candidate_action is not None:
        from .instruction_quota_recovery_mcp_action import register_instruction_quota_recovery_candidate_tools
        register_instruction_quota_recovery_candidate_tools(server, v4_instruction_quota_recovery_candidate_action)
    if v4_job_request_deny_candidate_action is not None:
        from .job_request_deny_mcp_action import register_job_request_deny_candidate_tools
        register_job_request_deny_candidate_tools(server, v4_job_request_deny_candidate_action)
    if v4_job_request_approve_candidate_action is not None:
        from .job_request_approve_mcp_action import register_job_request_approve_candidate_tools
        register_job_request_approve_candidate_tools(server, v4_job_request_approve_candidate_action)
    if v4_password_changer_candidate_action is not None:
        from .password_changer_mcp_action import register_password_changer_candidate_tools
        register_password_changer_candidate_tools(server, v4_password_changer_candidate_action)
    if v4_disabled_job_candidate_action is not None:
        from .job_definition_mcp_action import register_disabled_job_candidate_tools
        register_disabled_job_candidate_tools(server, v4_disabled_job_candidate_action)
    if v4_fixed_job_activation_candidate_action is not None:
        from .job_activation_mcp_action import register_fixed_job_activation_candidate_tools
        register_fixed_job_activation_candidate_tools(server, v4_fixed_job_activation_candidate_action)
    if v4_password_changer_delete_candidate_action is not None:
        from .password_changer_delete_mcp_action import register_password_changer_delete_candidate_tools
        register_password_changer_delete_candidate_tools(server, v4_password_changer_delete_candidate_action)
    if v4_unix_discovery_candidate_action is not None:
        from .discovery_entry_mcp_action import register_unix_discovery_candidate_tools
        register_unix_discovery_candidate_tools(server, v4_unix_discovery_candidate_action)
    if v4_unix_discovery_run_action is not None:
        from .discovery_run_mcp_action import register_unix_discovery_run_candidate_tools
        register_unix_discovery_run_candidate_tools(server, v4_unix_discovery_run_action)
    if v4_launcher_clone_actions is not None:
        from .launcher_clone_mcp_action import register_launcher_clone_tools
        register_launcher_clone_tools(server, v4_launcher_clone_actions)
    if v4_client_integrity_native_actions is not None:
        from .client_integrity_native_mcp_action import register_native_client_integrity_tools
        register_native_client_integrity_tools(server, v4_client_integrity_native_actions)
    if v4_putty_integrity_association_actions is not None:
        from .putty_integrity_association_mcp_action import register_putty_integrity_association_tools
        register_putty_integrity_association_tools(server, v4_putty_integrity_association_actions)
    if v4_unix_discovery_cleanup_action is not None:
        from .discovery_cleanup_mcp_action import register_unix_discovery_cleanup_tools
        register_unix_discovery_cleanup_tools(server, v4_unix_discovery_cleanup_action)
    if v4_unix_scanned_source_recovery_action is not None:
        from .unix_discovery_scanned_recovery_runtime import register_unix_scanned_source_recovery_tools
        register_unix_scanned_source_recovery_tools(server, v4_unix_scanned_source_recovery_action)
    if v4_unix_discovery_review_action is not None:
        from .discovery_review_mcp_action import register_unix_discovery_review_tool
        register_unix_discovery_review_tool(server, v4_unix_discovery_review_action)
    if v4_password_rotation_candidate_action is not None:
        from .password_rotation_mcp_action import register_password_rotation_candidate_tools
        register_password_rotation_candidate_tools(server, v4_password_rotation_candidate_action)
    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=list(settings.allowed_hosts),
        allowed_origins=list(settings.allowed_origins),
    )
    app: Any = server.mcp.streamable_http_app(
        streamable_http_path=settings.path,
        json_response=True,
        stateless_http=True,
        max_request_body_size=1_048_576,
        transport_security=transport_security,
        host=settings.host,
    )
    if settings.auth_mode == "bearer":
        assert settings.bearer_token is not None
        app = StaticBearerMiddleware(
            app,
            token=settings.bearer_token,
            protected_path=settings.path,
        )
    app = AllowedHostMiddleware(app, allowed_hosts=settings.allowed_hosts)
    if secret_bulk_import_runtime is not None:
        secret_bulk_import_runtime.bind_server(server)
        app = secret_bulk_import_runtime.wrap(app)
    if owner_file_intake_issuer is not None:
        app = owner_file_intake_issuer.wrap(app)
    if v4_radius_server_lifecycle_candidate_action is not None:
        from .radius_server_lifecycle_mcp_action import wrap_radius_server_lifecycle_shutdown
        app = wrap_radius_server_lifecycle_shutdown(app, v4_radius_server_lifecycle_candidate_action)
    if v4_radius_user_recovery_candidate_action is not None:
        from .radius_remote_user_recovery_mcp_action import wrap_radius_remote_user_recovery_shutdown
        app = wrap_radius_remote_user_recovery_shutdown(app, v4_radius_user_recovery_candidate_action)
    if v4_radius_user_lifecycle_candidate_action is not None:
        from .radius_remote_user_lifecycle_mcp_action import wrap_radius_remote_user_lifecycle_shutdown
        app = wrap_radius_remote_user_lifecycle_shutdown(app, v4_radius_user_lifecycle_candidate_action)
    if v4_jwt_owner_candidate_action is not None:
        from .jwt_manual_key_owner_mcp_action import wrap_jwt_manual_key_owner_shutdown
        app = wrap_jwt_manual_key_owner_shutdown(app, v4_jwt_owner_candidate_action)
    if v4_job_execution_owned_candidate_action is not None:
        from .job_execution_owned_mcp_action import wrap_job_execution_owned_shutdown
        app = wrap_job_execution_owned_shutdown(app, v4_job_execution_owned_candidate_action)
    if v4_job_definition_owned_candidate_action is not None:
        from .job_definition_owned_mcp_action import wrap_job_definition_owned_shutdown
        app = wrap_job_definition_owned_shutdown(app, v4_job_definition_owned_candidate_action)
    if v4_jwt_rotation_candidate_action is not None:
        from .jwt_rotation_mcp_action import wrap_jwt_rotation_shutdown
        app = wrap_jwt_rotation_shutdown(app, v4_jwt_rotation_candidate_action)
    if v4_radius_server_pair_lifecycle_candidate_action is not None:
        from .radius_server_pair_lifecycle_mcp_action import wrap_radius_server_pair_lifecycle_shutdown
        app = wrap_radius_server_pair_lifecycle_shutdown(app, v4_radius_server_pair_lifecycle_candidate_action)
    if v4_local_user_reset_owned_action is not None:
        from .local_user_reset_owned_mcp import wrap_local_reset_owned_shutdown
        app = wrap_local_reset_owned_shutdown(app, v4_local_user_reset_owned_action)
    if v4_ems_rule_set_metadata_action is not None:
        from .ems_rule_set_metadata_mcp_action import wrap_ems_rule_set_metadata_shutdown
        app = wrap_ems_rule_set_metadata_shutdown(app, v4_ems_rule_set_metadata_action)
    if v4_license_vm_preview_action is not None:
        from .license_vm_preview_action import wrap_license_vm_preview_shutdown
        app = wrap_license_vm_preview_shutdown(app, v4_license_vm_preview_action)
    if v4_approval_delivery_preview_action is not None:
        from .approval_delivery_preview_action import wrap_approval_delivery_preview_shutdown
        app = wrap_approval_delivery_preview_shutdown(app, v4_approval_delivery_preview_action)
    if v4_approval_delivery_local_candidate_action is not None:
        from .approval_delivery_local_mcp_action import wrap_approval_delivery_local_shutdown
        app = wrap_approval_delivery_local_shutdown(app, v4_approval_delivery_local_candidate_action)
    return app


def _build_default_onboarding_execution_factory(
    environment: Mapping[str, str],
    *,
    secret_binding_resolver: OwnerOnlySecretOnboardingBindingResolver | None = None,
) -> Callable[
    [V4PlanHostComponents],
    tuple[
        ProtectedAccessDomainOnboardingMcpAction | None,
        ProtectedSecretOnboardingMcpAction,
    ],
]:
    """Compose the bounded lab-auto onboarding actions for the HTTP host."""

    try:
        execution_enabled = load_v4_onboarding_execution_gate(environment)
        secret_only = environment.get(V4_SYNTHETIC_HOST_MODE_ENV) == (
            "source-backed-secret-onboarding"
        )
        internal_environment = dict(environment)
        internal_gate = "true" if execution_enabled else "false"
        internal_environment[V4_FOLDER_EXECUTION_ENV] = internal_gate
        internal_environment[V4_FOLDER_ACL_EXECUTION_ENV] = internal_gate
        internal_environment[V4_TARGET_EXECUTION_ENV] = internal_gate
        internal_environment[V4_TARGET_DELETE_ACTION_FEATURE_ENV] = "false"
        internal_environment[V4_TARGET_DELETE_EXECUTION_ENV] = "false"
        internal_folder_action = (
            None if secret_only else build_v4_folder_action(internal_environment)
        )
        internal_acl_action = (
            None if secret_only else build_v4_folder_acl_action(internal_environment)
        )
        internal_target_action = (
            None if secret_only else build_v4_target_action(internal_environment)
        )
        mode = environment.get(
            f"{V4_ONBOARDING_EXECUTION_PREFIX}MODE", "secret_create_lab_auto"
        )
        if mode not in {
            "secret_create_lab_auto",
            "existing_session_controls_lab_auto",
            "existing_web_service_lab_auto",
        }:
            raise V4OnboardingExecutionConfigurationError(
                "Onboarding execution mode is invalid."
            )
        if environment.get(f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}PROFILE") == LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE and (
            not secret_only or mode != "secret_create_lab_auto"
        ):
            raise V4OnboardingExecutionConfigurationError("Target-bound Web requires secret-only create composition.")
        if environment.get(f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}PROFILE") == LAB_AUTO_SECRET_CREATE_DOMAIN_700_PROFILE and (
            not secret_only or mode != "secret_create_lab_auto"
        ):
            raise V4OnboardingExecutionConfigurationError("Domain Secret requires secret-only create composition.")
        runner_factory = (
            build_fortipam_191_lab_auto_secret_runner_factory(environment)
            if mode == "secret_create_lab_auto"
            else None
        )
        access_environment_ref, access_scope_ref = (
            (None, None) if secret_only
            else load_v4_access_domain_authorized_scope(environment)
        )
        secret_environment_ref, secret_scope_ref = (
            load_lab_auto_secret_create_authorized_scope(environment)
        )
    except (
        OnboardingActionCoordinatorError,
        V4FolderActionConfigurationError,
        V4FolderAclActionConfigurationError,
        V4TargetActionConfigurationError,
        V4OnboardingExecutionConfigurationError,
    ) as exc:
        raise HttpConfigurationError(
            "Default onboarding execution binding is unavailable."
        ) from exc

    def bind(
        components: V4PlanHostComponents,
    ) -> tuple[
        ProtectedAccessDomainOnboardingMcpAction | None,
        ProtectedSecretOnboardingMcpAction,
    ]:
        if secret_only and components.access_domain_projection_source is not None:
            raise HttpConfigurationError(
                "Secret-only execution cannot bind an Access Domain source."
            )
        if mode in {"existing_session_controls_lab_auto", "existing_web_service_lab_auto"}:
            planning = components._secret_approval_planning_reader
            if planning is None or secret_binding_resolver is None:
                raise HttpConfigurationError(
                    "Default onboarding execution binding is unavailable."
                )
            config = load_secret_metadata_http_transport_config(environment)
            read_transport = FortiPamSecretMetadataHttpTransport(
                config,
                bound_secret_name=secret_binding_resolver.bound_secret_name(),
            )
            controls_factory = None
            web_service_factory = None
            if mode == "existing_session_controls_lab_auto":
                profile_transport = _build_optional_onboarding_rdp_event_filter_transport(
                    environment
                )
                if profile_transport is None:
                    raise HttpConfigurationError(
                        "Default onboarding execution binding is unavailable."
                    )
                controls_factory = build_lab_auto_secret_session_controls_runner_factory(
                    environment,
                    planning=planning,
                    read_transport=read_transport,
                    write_transport=FortiPamSecretSessionControlsSshTransport(
                        load_secret_session_controls_ssh_transport_config(environment)
                    ),
                    rdp_event_filter_transport=profile_transport,
                    clock=components._clock,
                )
            else:
                web_service_factory = build_lab_auto_web_secret_service_runner_factory(
                    environment, planning=planning, reader=read_transport,
                    metadata_base_url=config.base_url,
                    clock=components._clock,
                )
            source = components.secret_onboarding_projection_source
            if source is None:
                raise HttpConfigurationError(
                    "Default onboarding execution binding is unavailable."
                )
            access_action = None
            if not secret_only:
                assert internal_acl_action is not None
                assert access_environment_ref is not None and access_scope_ref is not None
                access_action = ProtectedAccessDomainOnboardingMcpAction(
                    components.plan_services,
                    components.bind_access_domain_action_coordinator(
                        internal_acl_action,
                        internal_folder_action,
                        internal_acl_action,
                    ),
                    authorized_environment_ref=access_environment_ref,
                    authorized_scope_ref=access_scope_ref,
                    execution_enabled=False,
                )
            onboarding_runner_factory = controls_factory or web_service_factory
            if onboarding_runner_factory is None:
                raise HttpConfigurationError(
                    "Default onboarding execution binding is unavailable."
                )
            controls_resolver = SecretOnboardingFixedActionSequenceResolver(
                components.plan_services,
                source,
                onboarding_runner_factory,
                session_controls_runner_factory=controls_factory,
                web_service_runner_factory=web_service_factory,
            )
            secret_action = ProtectedSecretOnboardingMcpAction(
                components.plan_services,
                components.bind_onboarding_action_coordinator(controls_resolver),
                authorized_environment_ref=secret_environment_ref,
                authorized_scope_ref=secret_scope_ref,
                execution_enabled=execution_enabled,
                policy_mode="lab_auto",
            )
            return access_action, secret_action
        assert runner_factory is not None
        if secret_only:
            source = components.secret_onboarding_projection_source
            if source is None:
                raise HttpConfigurationError("Secret onboarding source is unavailable.")
            resolver = SecretOnboardingFixedActionSequenceResolver(
                components.plan_services, source, runner_factory,
                domain_secret_runner_factory=(
                    runner_factory if isinstance(source, DomainSecretPlanningSource) else None
                ),
                target_bound_web_runner_factory=(
                    runner_factory if isinstance(source, TargetBoundWebPlanningSource) else None
                ),
            )
            secret_action = ProtectedSecretOnboardingMcpAction(
                components.plan_services,
                components.bind_onboarding_action_coordinator(resolver),
                authorized_environment_ref=secret_environment_ref,
                authorized_scope_ref=secret_scope_ref,
                execution_enabled=execution_enabled,
                policy_mode="lab_auto",
            )
            components.plan_services.bind_secret_create_execution_preflight_probe(
                runner_factory.execution_preflight_available
            )
            return None, secret_action
        assert internal_acl_action is not None
        assert access_environment_ref is not None and access_scope_ref is not None
        actions = components.bind_onboarding_execution_mcp_actions(
            internal_acl_action,
            runner_factory,
            folder_action=internal_folder_action,
            group_acl_action=internal_acl_action,
            target_action=internal_target_action,
            authorized_environment_ref=access_environment_ref,
            authorized_scope_ref=access_scope_ref,
            authorized_secret_environment_ref=secret_environment_ref,
            authorized_secret_scope_ref=secret_scope_ref,
            execution_enabled=execution_enabled,
        )
        components.plan_services.bind_secret_create_execution_preflight_probe(
            runner_factory.execution_preflight_available
        )
        return actions

    return bind


def _build_optional_onboarding_launcher_transport(
    environment: Mapping[str, str],
) -> Any | None:
    """Bind Launcher reads only when this optional onboarding input is enabled."""

    enabled = environment.get(f"{LAUNCHER_TRANSPORT_ENV_PREFIX}ENABLED")
    if enabled is None or enabled == "false":
        return None
    return FortiPamLauncherSshTransport(
        load_launcher_ssh_transport_config(environment)
    )


def _build_optional_onboarding_secret_policy_transport(
    environment: Mapping[str, str],
) -> Any | None:
    """Bind clipboard-policy reads only after their transport is enabled."""

    enabled = environment.get(f"{SECRET_POLICY_TRANSPORT_ENV_PREFIX}ENABLED")
    if enabled is None or enabled == "false":
        return None
    return FortiPamSecretPolicySshTransport(
        load_secret_policy_ssh_transport_config(environment)
    )


def _build_optional_onboarding_recording_policy_transport(
    environment: Mapping[str, str],
) -> Any | None:
    """Bind recording-policy reads only after their transport is enabled."""

    enabled = environment.get(f"{RECORDING_POLICY_TRANSPORT_ENV_PREFIX}ENABLED")
    if enabled is None or enabled == "false":
        return None
    return FortiPamRecordingPolicyHttpTransport(
        load_recording_policy_http_transport_config(environment)
    )


def _build_optional_onboarding_rdp_event_filter_transport(
    environment: Mapping[str, str],
) -> Any | None:
    """Bind fixed categorical RDP event-filter reads only when enabled."""

    enabled = environment.get(f"{RDP_EVENT_FILTER_TRANSPORT_ENV_PREFIX}ENABLED")
    if enabled is None or enabled == "false":
        return None
    return FortiPamRdpEventFilterSshTransport(
        load_rdp_event_filter_ssh_transport_config(environment)
    )


def main() -> None:
    """Run the Streamable HTTP server from validated environment settings."""

    import uvicorn
    from .local_user_reset_owned_mcp import LocalResetOwnedMcpError

    v4_local_user_reset_owned_action: Any = None
    v4_terraform_plan_report: ProtectedTerraformPlanReport | None = None
    v4_radius_server_lifecycle_candidate_action: Any = None
    v4_radius_server_pair_lifecycle_candidate_action: Any = None
    v4_radius_user_lifecycle_candidate_action: Any = None
    v4_jwt_owner_candidate_action: Any = None
    v4_jwt_rotation_candidate_action: Any = None
    v4_job_definition_owned_candidate_action: Any = None
    v4_job_execution_owned_candidate_action: Any = None
    v4_radius_user_recovery_candidate_action: Any = None
    try:
        load_http_runtime_environment()
        settings = HttpServerSettings.from_environment()
        v4_plan_host_factory: Any = None
        v4_ad_discovery_execution_factory: Any = None
        v4_approval_and_observe_execution_factory: Any = None
        v4_secret_request_observation: Any = None
        secret_binding_resolver: OwnerOnlySecretOnboardingBindingResolver | None = None
        if settings.v4_confirmation is not None:
            host_settings = synthetic_host_settings_from_environment(os.environ)
            if host_settings is None:
                raise V4RuntimeHostError("V4 plan host settings are unavailable.")
            if host_settings.host_mode == "source-backed-ad-discovery":
                from .ad_discovery_runtime_host import build_ad_discovery_runtime_host
                v4_plan_host_factory, v4_ad_discovery_execution_factory = (
                    build_ad_discovery_runtime_host(host_settings, os.environ)
                )
            elif host_settings.host_mode == "source-backed-access-domain":
                binding_path = host_settings.access_domain_binding_path
                if binding_path is None:
                    raise V4RuntimeHostError(
                        "V4 Access Domain binding settings are unavailable."
                    )
                v4_plan_host_factory = access_domain_v4_plan_host_factory(
                    host_settings,
                    folder_transport=FortiPamFolderHttpTransport(
                        load_folder_transport_config(os.environ)
                    ),
                    binding_resolver=OwnerOnlyAccessDomainBindingResolver(
                        binding_path
                    ),
                )
            elif host_settings.host_mode == "source-backed-secret-onboarding":
                binding_path = host_settings.secret_onboarding_binding_path
                if binding_path is None:
                    raise V4RuntimeHostError(
                        "V4 Secret onboarding binding settings are unavailable."
                    )
                if os.environ.get(f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}PROFILE") == LAB_AUTO_SECRET_CREATE_DOMAIN_700_PROFILE:
                    configured_path = Path(os.environ.get(
                        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}DOMAIN_BINDING_FILE", "",
                    ))
                    if configured_path != binding_path:
                        raise V4RuntimeHostError("Domain Secret binding paths must match.")
                    try:
                        domain_binding = load_domain_secret_planning_binding(configured_path)
                        from .owner_collector_runtime import owner_login_provider
                        from .domain_secret_namespace_candidate import (
                            owner_domain_namespace_transport, load_domain_secret_namespace_settings,
                        )
                        domain_owner = owner_login_provider(os.environ)
                        if domain_owner is None:
                            raise ValueError
                        domain_transport = owner_domain_namespace_transport(
                            load_secret_metadata_http_transport_config(os.environ),
                            domain_binding.create_binding, domain_owner,
                            namespace_settings=load_domain_secret_namespace_settings(os.environ),
                        )
                    except Exception:
                        raise V4RuntimeHostError("Domain Secret planning binding is unavailable.") from None
                    v4_plan_host_factory = domain_secret_v4_plan_host_factory(
                        host_settings, binding=domain_binding,
                        secret_transport=domain_transport,
                    )
                elif os.environ.get(f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}PROFILE") == LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE:
                    configured_path = Path(os.environ.get(
                        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}TARGET_WEB_BINDING_FILE", "",
                    ))
                    if configured_path != binding_path:
                        raise V4RuntimeHostError("Target-bound Web binding paths must match.")
                    try:
                        web_binding = load_target_bound_web_planning_binding(configured_path)
                    except Exception:
                        raise V4RuntimeHostError("Target-bound Web planning binding is unavailable.") from None
                    v4_plan_host_factory = target_bound_web_v4_plan_host_factory(
                        host_settings, binding=web_binding,
                        secret_transport=FortiPamSecretMetadataHttpTransport(
                            load_secret_metadata_http_transport_config(os.environ),
                            bound_secret_name=web_binding.create_binding.secret_name,
                        ),
                    )
                else:
                    secret_binding_resolver = OwnerOnlySecretOnboardingBindingResolver(
                        binding_path
                    )
                    secret_transport = FortiPamSecretMetadataHttpTransport(
                        load_secret_metadata_http_transport_config(os.environ),
                        bound_secret_name=secret_binding_resolver.bound_secret_name(),
                    )
                    collector_binding = (load_winrm_collector_private_binding(Path(os.environ.get(
                        f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}COLLECTOR_BINDING_FILE", "")))
                        if os.environ.get(f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}PROFILE") == LAB_AUTO_SECRET_CREATE_WINRM_700_CANDIDATE_PROFILE
                        else None)
                    from .owner_collector_runtime import owner_login_provider, owner_collector_transport
                    from .owner_rdp_runtime import load_rdp_owner_settings, OwnerRdpSessionMetadataTransport
                    owner_credentials = owner_login_provider(os.environ)
                    rdp_owner = load_rdp_owner_settings(os.environ)
                    if rdp_owner is not None and (
                        os.environ.get(f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}PROFILE") != LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE
                        or owner_credentials is None or rdp_owner.secret_name != secret_binding_resolver.bound_secret_name()
                    ):
                        raise V4RuntimeHostError("The fixed RDP Owner profile is unavailable.")
                    if owner_credentials is not None:
                        if rdp_owner is not None:
                            secret_transport = OwnerRdpSessionMetadataTransport(
                                load_secret_metadata_http_transport_config(os.environ), rdp_owner, owner_credentials)
                        elif collector_binding is None:
                            raise V4RuntimeHostError("Owner sessions require the bound collector candidate.")
                        else:
                            secret_transport = owner_collector_transport(
                                load_secret_metadata_http_transport_config(os.environ), collector_binding, owner_credentials)
                    v4_plan_host_factory = secret_onboarding_v4_plan_host_factory(
                        host_settings,
                        secret_transport=secret_transport,
                        target_transport=(
                            None
                            if os.environ.get(f"{LAB_AUTO_SECRET_CREATE_ENV_PREFIX}PROFILE")
                            == LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_PROFILE
                            else FortiPamTargetHttpTransport(
                                load_target_http_transport_config(os.environ)
                            )
                        ),
                        launcher_transport=(
                            _build_optional_onboarding_launcher_transport(os.environ)
                        ),
                        binding_resolver=secret_binding_resolver,
                        collector_binding=collector_binding,
                        folder_policy_transport=secret_transport,
                        secret_policy_clipboard_transport=(
                            _build_optional_onboarding_secret_policy_transport(os.environ)
                        ),
                        recording_policy_transport=(
                            _build_optional_onboarding_recording_policy_transport(os.environ)
                        ),
                        rdp_event_filter_transport=(
                            _build_optional_onboarding_rdp_event_filter_transport(os.environ)
                        ),
                    )
            elif host_settings.host_mode == "source-backed-onboarding":
                access_binding_path = host_settings.access_domain_binding_path
                secret_binding_path = host_settings.secret_onboarding_binding_path
                if access_binding_path is None or secret_binding_path is None:
                    raise V4RuntimeHostError(
                        "V4 onboarding binding settings are unavailable."
                    )
                secret_binding_resolver = OwnerOnlySecretOnboardingBindingResolver(
                    secret_binding_path
                )
                secret_transport = FortiPamSecretMetadataHttpTransport(
                    load_secret_metadata_http_transport_config(os.environ),
                    bound_secret_name=secret_binding_resolver.bound_secret_name(),
                )
                v4_plan_host_factory = onboarding_v4_plan_host_factory(
                    host_settings,
                    folder_transport=FortiPamFolderHttpTransport(
                        load_folder_transport_config(os.environ)
                    ),
                    access_domain_binding_resolver=(
                        OwnerOnlyAccessDomainBindingResolver(access_binding_path)
                    ),
                    secret_transport=secret_transport,
                    target_transport=FortiPamTargetHttpTransport(
                        load_target_http_transport_config(os.environ)
                    ),
                    launcher_transport=(
                        _build_optional_onboarding_launcher_transport(os.environ)
                    ),
                    secret_binding_resolver=secret_binding_resolver,
                    secret_folder_policy_transport=secret_transport,
                    secret_policy_clipboard_transport=(
                        _build_optional_onboarding_secret_policy_transport(os.environ)
                    ),
                    recording_policy_transport=(
                        _build_optional_onboarding_recording_policy_transport(os.environ)
                    ),
                    rdp_event_filter_transport=(
                        _build_optional_onboarding_rdp_event_filter_transport(os.environ)
                    ),
                )
            elif host_settings.host_mode == "source-backed-approval-and-observe-build29":
                from .secret_approval_build29_main_factory import build_secret_approval_build29_main_context

                binding_path = host_settings.approval_and_observe_binding_path
                if binding_path is None:
                    raise V4RuntimeHostError("V4 build-29 approval binding settings are unavailable.")
                try:
                    approval_context = build_secret_approval_build29_main_context(
                        os.environ, binding_path=binding_path,
                        execution_enabled=settings.v4_approval_and_observe_execution_enabled,
                    )
                    approval_authenticator = None
                    approver_authority = None
                    if settings.v4_approval_and_observe_execution_enabled:
                        approval_authenticator, approver_authority = approval_context.planning_authorities()
                    v4_plan_host_factory = secret_approval_build29_v4_plan_host_factory(
                        host_settings,
                        secret_transport=approval_context.secret_transport,
                        approval_profile_transport=approval_context.approval_profile_transport,
                        binding_resolver=approval_context.binding_resolver,
                        approval_receipt_authenticator=approval_authenticator,
                        approver_authorization_authority=approver_authority,
                    )
                    if settings.v4_approval_and_observe_execution_enabled:
                        v4_approval_and_observe_execution_factory = approval_context.execution_factory
                except Exception:
                    raise HttpConfigurationError("V4 build-29 approval runtime is unavailable.") from None
            elif host_settings.host_mode == "source-backed-approval-and-observe":
                binding_path = host_settings.approval_and_observe_binding_path
                if binding_path is None:
                    raise V4RuntimeHostError(
                        "V4 approval and observation binding settings are unavailable."
                    )
                secret_config = load_secret_metadata_http_transport_config(os.environ)
                v4_plan_host_factory = approval_and_observe_v4_plan_host_factory(
                    host_settings,
                    secret_transport=FortiPamSecretMetadataHttpTransport(
                        secret_config
                    ),
                    approval_profile_transport=FortiPamApprovalProfileHttpTransport(
                        secret_config
                    ),
                    binding_resolver=OwnerOnlyApprovalAndObserveBindingResolver(
                        binding_path
                    ),
                )
                request_binding_path = (
                    host_settings.secret_request_observation_binding_path
                )
                if request_binding_path is not None:
                    v4_secret_request_observation = (
                        ProtectedSecretRequestMcpObservation(
                            build_v4_secret_request_observation_transport(
                                secret_config, os.environ,
                            ),
                            OwnerOnlySecretRequestObservationBindingResolver(
                                request_binding_path
                            ),
                        )
                    )
            else:
                v4_plan_host_factory = synthetic_v4_plan_host_factory(host_settings)
        v4_folder_action: Any = None
        v4_folder_acl_action: Any = None
        v4_folder_acl_revoke_action: Any = None
        v4_classification_tag_action: Any = None
        v4_classification_tag_assign_action: Any = None
        v4_address_action: Any = None
        v4_address_group_action: Any = None
        v4_ztna_device_context_diagnostic: Any = None
        v4_ztna_folder_posture: Any = None
        v4_folder_rename_action: Any = None
        v4_folder_archive_action: Any = None
        v4_folder_policy_assign_action: Any = None
        v4_folder_policy_detach_action: Any = None
        v4_target_action: Any = None
        v4_secret_metadata_action: Any = None
        v4_interface_web_proxy_action: Any = None
        v4_target_update_action: Any = None
        v4_certificate_csr_action: Any = None
        v4_local_user_disable_action: Any = None
        v4_local_user_create_action: Any = None
        v4_local_user_reset_action: Any = None
        v4_role_create_action: Any = None
        v4_role_update_action: Any = None
        v4_role_assign_action: Any = None
        v4_dlp_file_pattern_action: Any = None
        v4_dlp_sensor_action: Any = None
        v4_antivirus_profile_action: Any = None
        v4_rdp_event_filter_action: Any = None
        v4_secret_policy_action: Any = None
        v4_ssh_filter_action: Any = None
        v4_launcher_action: Any = None
        v4_launcher_update_action: Any = None
        v4_launcher_matcher_action: Any = None
        v4_template_action: Any = None
        v4_template_archive_action: Any = None
        v4_dependency_updater_action: Any = None
        v4_secret_gateway_action: Any = None
        v4_client_integrity_action: Any = None
        v4_character_set_action: Any = None
        v4_windows_app_filter_action: Any = None
        v4_recording_policy_action: Any = None
        v4_password_policy_action: Any = None
        v4_report_layout_action: Any = None
        v4_ztna_access_proxy_action: Any = None
        v4_ztna_user_control_action: Any = None
        v4_ztna_wad_debug_action: Any = None
        v4_snmp_agent_action: Any = None
        v4_logging_disk_action: Any = None
        v4_fortianalyzer_action: Any = None
        v4_maintenance_mode_action: Any = None
        v4_secret_audit_action: Any = None
        v4_secret_audit_summary: Any = None
        v4_active_launch_action: Any = None
        v4_automation_trigger_action: Any = None
        v4_automation_action_action: Any = None
        v4_automation_stitch_action: Any = None
        v4_user_group_action: Any = None
        v4_user_group_membership_action: Any = None
        v4_apl_action: Any = None
        v4_apl_disable_action: Any = None
        v4_schedule_action: Any = None
        v4_schedule_assign_action: Any = None
        v4_approval_profile_action: Any = None
        v4_approval_profile_update_action: Any = None
        v4_approval_email_template_action: Any = None
        v4_approval_email_template_update_action: Any = None
        v4_secret_request_create_action: Any = None
        if settings.v4_folder_action_enabled:
            v4_folder_action = build_v4_folder_action(os.environ)
        if settings.v4_folder_acl_action_enabled:
            v4_folder_acl_action = build_v4_folder_acl_action(os.environ)
        if settings.v4_folder_acl_revoke_action_enabled:
            v4_folder_acl_revoke_action = build_v4_folder_acl_revoke_action(os.environ)
        if settings.v4_classification_tag_action_enabled:
            v4_classification_tag_action = build_v4_classification_tag_action(
                os.environ
            )
        if getattr(settings, "v4_classification_tag_assign_action_enabled", False):
            v4_classification_tag_assign_action = (
                build_v4_classification_tag_assign_action(os.environ)
            )
        if settings.v4_address_action_enabled:
            v4_address_action = build_v4_address_action(os.environ)
        if settings.v4_address_group_action_enabled:
            v4_address_group_action = build_v4_address_group_action(os.environ)
        if getattr(settings, "v4_ztna_device_context_diagnostic_enabled", False):
            v4_ztna_device_context_diagnostic = (
                build_v4_ztna_device_context_diagnostic(os.environ)
            )
        if getattr(settings, "v4_ztna_folder_posture_enabled", False):
            v4_ztna_folder_posture = build_v4_ztna_folder_control_posture(os.environ)
        if settings.v4_folder_rename_action_enabled:
            v4_folder_rename_action = build_v4_folder_rename_action(os.environ)
        if getattr(settings, "v4_folder_archive_action_enabled", False):
            v4_folder_archive_action = build_v4_folder_archive_action(os.environ)
        if settings.v4_folder_policy_assign_action_enabled:
            v4_folder_policy_assign_action = build_v4_folder_policy_assign_action(
                os.environ
            )
        if settings.v4_folder_policy_detach_action_enabled:
            v4_folder_policy_detach_action = build_v4_folder_policy_detach_action(
                os.environ
            )
        if settings.v4_target_action_enabled:
            v4_target_action = build_v4_target_action(os.environ)
        if getattr(settings, "v4_secret_metadata_action_enabled", False):
            v4_secret_metadata_action = build_v4_secret_metadata_action(os.environ)
        if getattr(settings, "v4_interface_web_proxy_action_enabled", False):
            v4_interface_web_proxy_action = build_v4_interface_web_proxy_action(
                os.environ
            )
        if settings.v4_target_update_action_enabled:
            v4_target_update_action = build_v4_target_update_action(os.environ)
        if settings.v4_certificate_csr_action_enabled:
            v4_certificate_csr_action = build_v4_certificate_csr_action(os.environ)
        if settings.v4_local_user_disable_action_enabled:
            v4_local_user_disable_action = build_v4_local_user_disable_action(
                os.environ
            )
        if settings.v4_local_user_create_action_enabled:
            v4_local_user_create_action = build_v4_local_user_create_action(
                os.environ
            )
        if settings.v4_local_user_reset_action_enabled:
            v4_local_user_reset_action = build_v4_local_user_reset_action(
                os.environ
            )
        if settings.v4_role_create_action_enabled:
            v4_role_create_action = build_v4_role_create_action(os.environ)
        if settings.v4_role_update_action_enabled:
            v4_role_update_action = build_v4_role_update_action(os.environ)
        if settings.v4_role_assign_action_enabled:
            v4_role_assign_action = build_v4_role_assign_action(os.environ)
        if settings.v4_dlp_file_pattern_action_enabled:
            v4_dlp_file_pattern_action = build_v4_dlp_file_pattern_action(os.environ)
        if settings.v4_dlp_sensor_action_enabled:
            v4_dlp_sensor_action = build_v4_dlp_sensor_action(os.environ)
        if settings.v4_antivirus_profile_action_enabled:
            v4_antivirus_profile_action = build_v4_antivirus_profile_action(
                os.environ
            )
        if settings.v4_rdp_event_filter_action_enabled:
            v4_rdp_event_filter_action = build_v4_rdp_event_filter_action(
                os.environ
            )
        if settings.v4_secret_policy_action_enabled:
            v4_secret_policy_action = build_v4_secret_policy_action(os.environ)
        if settings.v4_ssh_filter_action_enabled:
            v4_ssh_filter_action = build_v4_ssh_filter_action(os.environ)
        if settings.v4_launcher_action_enabled:
            v4_launcher_action = build_v4_launcher_action(os.environ)
        if settings.v4_launcher_update_action_enabled:
            v4_launcher_update_action = build_v4_launcher_update_action(os.environ)
        if settings.v4_launcher_matcher_action_enabled:
            v4_launcher_matcher_action = build_v4_launcher_matcher_action(os.environ)
        if settings.v4_template_action_enabled:
            v4_template_action = build_v4_template_action(os.environ)
        if settings.v4_template_archive_action_enabled:
            v4_template_archive_action = build_v4_template_archive_action(os.environ)
        if settings.v4_dependency_updater_action_enabled:
            v4_dependency_updater_action = build_v4_dependency_updater_action(
                os.environ
            )
        if settings.v4_secret_gateway_action_enabled:
            v4_secret_gateway_action = build_v4_secret_gateway_action(os.environ)
        if settings.v4_client_integrity_action_enabled:
            v4_client_integrity_action = build_v4_client_integrity_action(
                os.environ
            )
        if settings.v4_character_set_action_enabled:
            v4_character_set_action = build_v4_character_set_action(os.environ)
        if settings.v4_windows_app_filter_action_enabled:
            v4_windows_app_filter_action = build_v4_windows_app_filter_action(
                os.environ
            )
        if settings.v4_recording_policy_action_enabled:
            v4_recording_policy_action = build_v4_recording_policy_action(os.environ)
        if settings.v4_password_policy_action_enabled:
            v4_password_policy_action = build_v4_password_policy_action(os.environ)
        if settings.v4_report_layout_action_enabled:
            v4_report_layout_action = build_v4_report_layout_action(os.environ)
        if settings.v4_ztna_access_proxy_action_enabled:
            v4_ztna_access_proxy_action = build_v4_ztna_access_proxy_action(
                os.environ
            )
        if settings.v4_ztna_user_control_action_enabled:
            v4_ztna_user_control_action = build_v4_ztna_user_control_action(
                os.environ
            )
        if settings.v4_ztna_wad_debug_action_enabled:
            v4_ztna_wad_debug_action = build_v4_ztna_wad_debug_action(os.environ)
        if settings.v4_snmp_agent_action_enabled:
            v4_snmp_agent_action = build_v4_snmp_agent_action(os.environ)
        if settings.v4_logging_disk_action_enabled:
            v4_logging_disk_action = build_v4_logging_disk_action(os.environ)
        if settings.v4_fortianalyzer_action_enabled:
            v4_fortianalyzer_action = build_v4_fortianalyzer_action(os.environ)
        if settings.v4_maintenance_mode_action_enabled:
            v4_maintenance_mode_action = build_v4_maintenance_mode_action(os.environ)
        if settings.v4_secret_audit_action_enabled:
            v4_secret_audit_action = build_v4_secret_audit_action(os.environ)
        if settings.v4_terraform_plan_report_enabled:
            v4_terraform_plan_report = build_terraform_plan_report(os.environ)
        if settings.v4_secret_audit_summary_enabled:
            v4_secret_audit_summary = build_v4_secret_audit_summary_read(os.environ)
        if settings.v4_active_launch_action_enabled:
            v4_active_launch_action = build_v4_active_launch_action(os.environ)
        if settings.v4_automation_trigger_action_enabled:
            v4_automation_trigger_action = build_v4_automation_trigger_action(
                os.environ
            )
        if settings.v4_automation_action_action_enabled:
            v4_automation_action_action = build_v4_automation_action_action(
                os.environ
            )
        if settings.v4_automation_stitch_action_enabled:
            v4_automation_stitch_action = build_v4_automation_stitch_action(
                os.environ
            )
        if settings.v4_user_group_action_enabled:
            v4_user_group_action = build_v4_user_group_action(os.environ)
        if settings.v4_user_group_membership_action_enabled:
            v4_user_group_membership_action = build_v4_user_group_membership_action(
                os.environ
            )
        if settings.v4_apl_action_enabled:
            v4_apl_action = build_v4_apl_action(os.environ)
        if settings.v4_apl_disable_action_enabled:
            v4_apl_disable_action = build_v4_apl_disable_action(os.environ)
        if settings.v4_schedule_action_enabled:
            v4_schedule_action = build_v4_schedule_action(os.environ)
        if settings.v4_schedule_assign_action_enabled:
            v4_schedule_assign_action = build_v4_schedule_assign_action(os.environ)
        if settings.v4_approval_profile_action_enabled:
            v4_approval_profile_action = build_v4_approval_profile_action(
                os.environ
            )
        if settings.v4_approval_profile_update_action_enabled:
            v4_approval_profile_update_action = (
                build_v4_approval_profile_update_action(os.environ)
            )
        if settings.v4_approval_email_template_action_enabled:
            v4_approval_email_template_action = (
                build_v4_approval_email_template_action(os.environ)
            )
        if settings.v4_approval_email_template_update_action_enabled:
            v4_approval_email_template_update_action = (
                build_v4_approval_email_template_update_action(os.environ)
            )
        if getattr(settings, "v4_secret_request_create_enabled", False):
            v4_secret_request_create_action = (
                build_v4_secret_request_create_action(os.environ)
            )
        v4_onboarding_execution_factory = None
        if settings.v4_onboarding_execution_enabled:
            v4_onboarding_execution_factory = (
                _build_default_onboarding_execution_factory(
                    os.environ,
                    secret_binding_resolver=secret_binding_resolver,
                )
            )
        from .isolated_folder_mcp_action import build_isolated_folder_candidate
        v4_isolated_folder_action = build_isolated_folder_candidate(os.environ)
        from .folder_traversal_mcp_action import build_folder_traversal_candidate
        v4_folder_traversal_action = build_folder_traversal_candidate(os.environ)
        from .local_user_reset_candidate_mcp_action import build_local_user_reset_candidate
        v4_local_user_reset_candidate_action = build_local_user_reset_candidate(os.environ)
        from .local_user_reset_owned_runtime import build_local_reset_owned_candidate
        v4_local_user_reset_owned_action = build_local_reset_owned_candidate(os.environ)
        from .password_verification_mcp_action import build_password_verification_candidate
        v4_password_verification_candidate_action = build_password_verification_candidate(os.environ)
        from .password_change_schedule_mcp_action import build_password_change_schedule_candidate
        v4_password_change_schedule_candidate_action = build_password_change_schedule_candidate(os.environ)
        from .secret_description_update_mcp_action import build_secret_description_update_candidate
        v4_secret_description_update_candidate_action = build_secret_description_update_candidate(os.environ)
        from .secret_event_subscription_mcp_action import build_secret_event_subscription_candidate
        v4_secret_event_subscription_candidate = build_secret_event_subscription_candidate(os.environ)
        from .secret_checkout_association_mcp_action import build_secret_checkout_association_candidate
        v4_secret_checkout_association_candidate_action = build_secret_checkout_association_candidate(os.environ)
        from .secret_checkout_effect_mcp_action import build_secret_checkout_effect_candidate
        v4_secret_checkout_effect_candidate_action = build_secret_checkout_effect_candidate(os.environ)
        from .job_request_deny_mcp_action import build_job_request_deny_candidate
        v4_job_request_deny_candidate_action = build_job_request_deny_candidate(os.environ)
        from .secret_request_approval_revoke_runtime import build_secret_request_approval_revoke_candidate
        v4_secret_request_approval_revoke_candidate_action = build_secret_request_approval_revoke_candidate(os.environ)
        from .ldap_server_runtime import build_ldap_server_candidate
        v4_ldap_server_candidate_action = build_ldap_server_candidate(os.environ)
        from .radius_server_lifecycle_runtime import build_radius_server_lifecycle_candidate
        v4_radius_server_lifecycle_candidate_action = build_radius_server_lifecycle_candidate(os.environ)
        from .radius_remote_user_recovery_runtime import build_radius_remote_user_recovery_candidate
        try:
            v4_radius_user_recovery_candidate_action = build_radius_remote_user_recovery_candidate(os.environ)
        except ValueError:
            raise HttpConfigurationError("RADIUS User recovery startup is unavailable.") from None
        from .radius_remote_user_lifecycle_runtime import build_radius_remote_user_lifecycle_candidate
        try:
            v4_radius_user_lifecycle_candidate_action = build_radius_remote_user_lifecycle_candidate(os.environ)
        except ValueError:
            raise HttpConfigurationError("RADIUS User lifecycle startup is unavailable.") from None
        from .jwt_manual_key_owner_runtime import build_jwt_manual_key_owner_candidate
        try:
            v4_jwt_owner_candidate_action = build_jwt_manual_key_owner_candidate(os.environ)
        except ValueError:
            raise HttpConfigurationError("Owner JWT startup is unavailable.") from None
        from .job_execution_owned_runtime import build_job_execution_owned_candidate
        try:
            v4_job_execution_owned_candidate_action = build_job_execution_owned_candidate(os.environ)
        except ValueError:
            raise HttpConfigurationError("Owned Job execution startup is unavailable.") from None
        from .job_definition_owned_runtime import build_job_definition_owned_candidate
        try:
            v4_job_definition_owned_candidate_action = build_job_definition_owned_candidate(os.environ)
        except ValueError:
            raise HttpConfigurationError("Owned Job startup is unavailable.") from None
        from .jwt_rotation_runtime import build_jwt_rotation_candidate
        try:
            v4_jwt_rotation_candidate_action = build_jwt_rotation_candidate(os.environ)
        except ValueError:
            raise HttpConfigurationError("JWT rotation startup is unavailable.") from None
        from .radius_server_pair_lifecycle_runtime import build_radius_server_pair_lifecycle_candidate
        try:
            v4_radius_server_pair_lifecycle_candidate_action = build_radius_server_pair_lifecycle_candidate(os.environ)
        except ValueError:
            raise HttpConfigurationError("Paired RADIUS lifecycle startup is unavailable.") from None
        from .ldap_server_update_runtime import build_ldap_server_update_candidate
        v4_ldap_server_update_candidate_action = build_ldap_server_update_candidate(os.environ)
        from .dns_timeout_runtime import build_dns_timeout_candidate
        v4_dns_timeout_candidate_action = build_dns_timeout_candidate(os.environ)
        from .crl_import_runtime import build_crl_candidate
        v4_crl_candidate_action = build_crl_candidate(os.environ)
        from .remote_certificate_runtime import build_remote_certificate_candidate
        v4_remote_certificate_candidate_action = build_remote_certificate_candidate(os.environ)
        from .ems_timeout_runtime import build_ems_timeout_candidate
        v4_ems_timeout_candidate_action = build_ems_timeout_candidate(os.environ)
        from .logging_disk_size_runtime import build_logging_disk_size_candidate
        v4_logging_disk_size_candidate_action = build_logging_disk_size_candidate(os.environ)
        from .backup_export_runtime import build_backup_export_candidate
        v4_backup_export_candidate_action = build_backup_export_candidate(os.environ)
        from .secret_bulk_import_issuer_runtime import build_owner_file_intake_issuer
        owner_file_intake_issuer = build_owner_file_intake_issuer(os.environ,
            settings=settings.local_oauth, runtime_profile=settings.runtime_profile)
        from .secret_bulk_import_runtime import build_secret_bulk_import_runtime
        try:
            secret_bulk_import_runtime = build_secret_bulk_import_runtime(os.environ,
                issuer=owner_file_intake_issuer, runtime_profile=settings.runtime_profile)
        except ValueError:
            raise HttpConfigurationError("Text import startup is unavailable.") from None
        from .ztna_group_runtime import build_ztna_group_candidate
        v4_ztna_group_candidate_action = build_ztna_group_candidate(os.environ)
        from .disabled_route_runtime import build_disabled_route_candidate
        v4_disabled_route_candidate_action = build_disabled_route_candidate(os.environ)
        from .apl_role_update_runtime import build_apl_role_update_candidate
        v4_apl_role_update_candidate_action = build_apl_role_update_candidate(os.environ)
        from .instruction_profile_runtime import build_instruction_profile_candidate
        v4_instruction_profile_candidate_action = build_instruction_profile_candidate(os.environ)
        from .instruction_feature_runtime import build_instruction_feature_candidate
        v4_instruction_feature_candidate_action = build_instruction_feature_candidate(os.environ)
        from .instruction_quota_runtime import build_instruction_quota_candidate
        from .instruction_quota_recovery_runtime import build_instruction_quota_recovery_candidate
        from .instruction_quota_recovery_mcp_action import InstructionQuotaRecoveryMcpAction
        quota_recovery = build_instruction_quota_recovery_candidate(os.environ)
        v4_instruction_quota_recovery_candidate_action = (
            InstructionQuotaRecoveryMcpAction(quota_recovery, execution_enabled=quota_recovery._enabled)
            if quota_recovery is not None else None)
        v4_instruction_quota_candidate_action = (
            build_instruction_quota_candidate(os.environ) if quota_recovery is None else None)
        from .job_request_approve_mcp_action import build_job_request_approve_candidate
        v4_job_request_approve_candidate_action = build_job_request_approve_candidate(os.environ)
        from .password_changer_mcp_action import build_password_changer_candidate
        v4_password_changer_candidate_action = build_password_changer_candidate(os.environ)
        from .job_definition_mcp_action import build_disabled_job_candidate
        v4_disabled_job_candidate_action = build_disabled_job_candidate(os.environ)
        from .job_activation_mcp_action import build_fixed_job_activation_candidate
        v4_fixed_job_activation_candidate_action = build_fixed_job_activation_candidate(os.environ)
        from .password_changer_delete_mcp_action import build_password_changer_delete_candidate
        v4_password_changer_delete_candidate_action = build_password_changer_delete_candidate(os.environ)
        from .discovery_entry_mcp_action import build_unix_discovery_candidate
        v4_unix_discovery_candidate_action = build_unix_discovery_candidate(os.environ)
        from .discovery_cleanup_mcp_action import build_unix_discovery_cleanup_candidate
        v4_unix_discovery_cleanup_action = build_unix_discovery_cleanup_candidate(os.environ)
        from .launcher_clone_mcp_action import build_launcher_clone_candidate
        v4_launcher_clone_actions = build_launcher_clone_candidate(os.environ)
        from .client_integrity_native_mcp_action import build_native_client_integrity_candidate
        v4_client_integrity_native_actions = build_native_client_integrity_candidate(os.environ)
        from .putty_integrity_association_mcp_action import build_putty_integrity_association_candidate
        v4_putty_integrity_association_actions = build_putty_integrity_association_candidate(os.environ)
        from .discovery_run_mcp_action import build_unix_discovery_run_candidate
        v4_unix_discovery_run_action = build_unix_discovery_run_candidate(os.environ)
        from .discovery_review_mcp_action import build_unix_discovery_review
        v4_unix_discovery_review_action = build_unix_discovery_review(os.environ)
        from .password_rotation_mcp_action import build_password_rotation_candidate
        v4_password_rotation_candidate_action = build_password_rotation_candidate(os.environ)
        app = create_http_app(
            settings,
            v4_plan_host_factory=v4_plan_host_factory,
            v4_secret_request_observation=v4_secret_request_observation,
            v4_onboarding_execution_factory=v4_onboarding_execution_factory,
            v4_ad_discovery_execution_factory=v4_ad_discovery_execution_factory,
            v4_approval_and_observe_execution_factory=v4_approval_and_observe_execution_factory,
            v4_isolated_folder_action=v4_isolated_folder_action,
            v4_folder_traversal_action=v4_folder_traversal_action,
            v4_local_user_reset_candidate_action=v4_local_user_reset_candidate_action,
            v4_local_user_reset_owned_action=v4_local_user_reset_owned_action,
            v4_password_verification_candidate_action=v4_password_verification_candidate_action,
            v4_password_change_schedule_candidate_action=v4_password_change_schedule_candidate_action,
            v4_secret_description_update_candidate_action=v4_secret_description_update_candidate_action,
            v4_secret_event_subscription_candidate=v4_secret_event_subscription_candidate,
            v4_secret_checkout_association_candidate_action=v4_secret_checkout_association_candidate_action,
            v4_secret_checkout_effect_candidate_action=v4_secret_checkout_effect_candidate_action,
            v4_job_request_deny_candidate_action=v4_job_request_deny_candidate_action,
            v4_secret_request_approval_revoke_candidate_action=v4_secret_request_approval_revoke_candidate_action,
            v4_ldap_server_candidate_action=v4_ldap_server_candidate_action,
            v4_radius_server_lifecycle_candidate_action=v4_radius_server_lifecycle_candidate_action,
            v4_radius_server_pair_lifecycle_candidate_action=v4_radius_server_pair_lifecycle_candidate_action,
            v4_radius_user_lifecycle_candidate_action=v4_radius_user_lifecycle_candidate_action,
            v4_jwt_owner_candidate_action=v4_jwt_owner_candidate_action,
            v4_jwt_rotation_candidate_action=v4_jwt_rotation_candidate_action,
            v4_job_definition_owned_candidate_action=v4_job_definition_owned_candidate_action,
            v4_job_execution_owned_candidate_action=v4_job_execution_owned_candidate_action,
            v4_radius_user_recovery_candidate_action=v4_radius_user_recovery_candidate_action,
            v4_ldap_server_update_candidate_action=v4_ldap_server_update_candidate_action,
            v4_apl_role_update_candidate_action=v4_apl_role_update_candidate_action,
            v4_disabled_route_candidate_action=v4_disabled_route_candidate_action,
            v4_dns_timeout_candidate_action=v4_dns_timeout_candidate_action,
            v4_crl_candidate_action=v4_crl_candidate_action,
            v4_remote_certificate_candidate_action=v4_remote_certificate_candidate_action,
            v4_ems_timeout_candidate_action=v4_ems_timeout_candidate_action,
            v4_logging_disk_size_candidate_action=v4_logging_disk_size_candidate_action,
            v4_backup_export_candidate_action=v4_backup_export_candidate_action,
            owner_file_intake_issuer=owner_file_intake_issuer,
            secret_bulk_import_runtime=secret_bulk_import_runtime,
            v4_ztna_group_candidate_action=v4_ztna_group_candidate_action,
            v4_instruction_profile_candidate_action=v4_instruction_profile_candidate_action,
            v4_instruction_feature_candidate_action=v4_instruction_feature_candidate_action,
            v4_instruction_quota_candidate_action=v4_instruction_quota_candidate_action,
            v4_instruction_quota_recovery_candidate_action=v4_instruction_quota_recovery_candidate_action,
            v4_job_request_approve_candidate_action=v4_job_request_approve_candidate_action,
            v4_password_changer_candidate_action=v4_password_changer_candidate_action,
            v4_disabled_job_candidate_action=v4_disabled_job_candidate_action,
            v4_fixed_job_activation_candidate_action=v4_fixed_job_activation_candidate_action,
            v4_password_changer_delete_candidate_action=v4_password_changer_delete_candidate_action,
            v4_unix_discovery_candidate_action=v4_unix_discovery_candidate_action,
            v4_unix_discovery_cleanup_action=v4_unix_discovery_cleanup_action,
            v4_launcher_clone_actions=v4_launcher_clone_actions,
            v4_client_integrity_native_actions=v4_client_integrity_native_actions,
            v4_putty_integrity_association_actions=v4_putty_integrity_association_actions,
            v4_unix_discovery_run_action=v4_unix_discovery_run_action,
            v4_unix_discovery_review_action=v4_unix_discovery_review_action,
            v4_password_rotation_candidate_action=v4_password_rotation_candidate_action,
            v4_folder_action=v4_folder_action,
            v4_folder_acl_action=v4_folder_acl_action,
            v4_folder_acl_revoke_action=v4_folder_acl_revoke_action,
            v4_classification_tag_action=v4_classification_tag_action,
            v4_classification_tag_assign_action=(
                v4_classification_tag_assign_action
            ),
            v4_address_action=v4_address_action,
            v4_address_group_action=v4_address_group_action,
            v4_ztna_device_context_diagnostic=v4_ztna_device_context_diagnostic,
            v4_ztna_folder_posture=v4_ztna_folder_posture,
            v4_folder_rename_action=v4_folder_rename_action,
            v4_folder_archive_action=v4_folder_archive_action,
            v4_folder_policy_assign_action=v4_folder_policy_assign_action,
            v4_folder_policy_detach_action=v4_folder_policy_detach_action,
            v4_target_action=v4_target_action,
            v4_secret_metadata_action=v4_secret_metadata_action,
            v4_interface_web_proxy_action=v4_interface_web_proxy_action,
            v4_target_update_action=v4_target_update_action,
            v4_certificate_csr_action=v4_certificate_csr_action,
            v4_local_user_disable_action=v4_local_user_disable_action,
            v4_local_user_create_action=v4_local_user_create_action,
            v4_local_user_reset_action=v4_local_user_reset_action,
            v4_role_create_action=v4_role_create_action,
            v4_role_update_action=v4_role_update_action,
            v4_role_assign_action=v4_role_assign_action,
            v4_dlp_file_pattern_action=v4_dlp_file_pattern_action,
            v4_dlp_sensor_action=v4_dlp_sensor_action,
            v4_antivirus_profile_action=v4_antivirus_profile_action,
            v4_rdp_event_filter_action=v4_rdp_event_filter_action,
            v4_secret_policy_action=v4_secret_policy_action,
            v4_ssh_filter_action=v4_ssh_filter_action,
            v4_launcher_action=v4_launcher_action,
            v4_launcher_update_action=v4_launcher_update_action,
            v4_launcher_matcher_action=v4_launcher_matcher_action,
            v4_template_action=v4_template_action,
            v4_template_archive_action=v4_template_archive_action,
            v4_dependency_updater_action=v4_dependency_updater_action,
            v4_secret_gateway_action=v4_secret_gateway_action,
            v4_client_integrity_action=v4_client_integrity_action,
            v4_character_set_action=v4_character_set_action,
            v4_windows_app_filter_action=v4_windows_app_filter_action,
            v4_recording_policy_action=v4_recording_policy_action,
            v4_password_policy_action=v4_password_policy_action,
            v4_report_layout_action=v4_report_layout_action,
            v4_ztna_access_proxy_action=v4_ztna_access_proxy_action,
            v4_ztna_user_control_action=v4_ztna_user_control_action,
            v4_ztna_wad_debug_action=v4_ztna_wad_debug_action,
            v4_snmp_agent_action=v4_snmp_agent_action,
            v4_logging_disk_action=v4_logging_disk_action,
            v4_fortianalyzer_action=v4_fortianalyzer_action,
            v4_maintenance_mode_action=v4_maintenance_mode_action,
            v4_secret_audit_action=v4_secret_audit_action,
            v4_secret_audit_summary=v4_secret_audit_summary,
            v4_terraform_plan_report=v4_terraform_plan_report,
            v4_active_launch_action=v4_active_launch_action,
            v4_automation_trigger_action=v4_automation_trigger_action,
            v4_automation_action_action=v4_automation_action_action,
            v4_automation_stitch_action=v4_automation_stitch_action,
            v4_user_group_action=v4_user_group_action,
            v4_user_group_membership_action=v4_user_group_membership_action,
            v4_apl_action=v4_apl_action,
            v4_apl_disable_action=v4_apl_disable_action,
            v4_schedule_action=v4_schedule_action,
            v4_schedule_assign_action=v4_schedule_assign_action,
            v4_approval_profile_action=v4_approval_profile_action,
            v4_approval_profile_update_action=v4_approval_profile_update_action,
            v4_approval_email_template_action=v4_approval_email_template_action,
            v4_approval_email_template_update_action=(
                v4_approval_email_template_update_action
            ),
            v4_secret_request_create_action=v4_secret_request_create_action,
        )
    except (
        EnvironmentFileError,
        AccessDomainProjectionSourceError,
        ApprovalAndObserveProjectionSourceError,
        SecretOnboardingProjectionSourceError,
        ApprovalProfileSshTransportConfigurationError,
        FolderTransportConfigurationError,
        SecretMetadataHttpTransportConfigurationError,
        TargetHttpTransportConfigurationError,
        LauncherSshTransportConfigurationError,
        SecretPolicySshTransportConfigurationError,
        RecordingPolicyHttpTransportConfigurationError,
        RdpEventFilterSshTransportConfigurationError,
        HaReconciliationError,
        HttpConfigurationError,
        V4ConfirmationHttpError,
        V4RuntimeHostError,
        V4FolderActionConfigurationError,
        V4FolderAclActionConfigurationError,
        V4FolderAclRevokeActionConfigurationError,
        V4ClassificationTagActionConfigurationError,
        V4ScheduleAssignActionConfigurationError,
        V4AddressActionConfigurationError,
        V4AddressGroupActionConfigurationError,
        ZtnaDeviceContextDiagnosticConfigurationError,
        V4FolderRenameActionConfigurationError,
        V4FolderPolicyAssignActionConfigurationError,
        V4FolderPolicyDetachActionConfigurationError,
        V4TargetActionConfigurationError,
        V4RoleCreateActionConfigurationError,
        V4RoleAssignActionConfigurationError,
        V4DlpFilePatternActionConfigurationError,
        V4DlpSensorActionConfigurationError,
        V4AntivirusProfileActionConfigurationError,
        V4RdpEventFilterActionConfigurationError,
        V4SecretPolicyActionConfigurationError,
        V4SshFilterActionConfigurationError,
        V4LauncherActionConfigurationError,
        V4LauncherUpdateActionConfigurationError,
        V4LauncherMatcherActionConfigurationError,
        V4TemplateActionConfigurationError,
        V4TemplateArchiveActionConfigurationError,
        V4DependencyUpdaterActionConfigurationError,
        V4SecretGatewayActionConfigurationError,
        V4ClientIntegrityActionConfigurationError,
        V4CharacterSetActionConfigurationError,
        V4RecordingPolicyActionConfigurationError,
        V4PasswordPolicyActionConfigurationError,
        V4ReportLayoutActionConfigurationError,
        V4ZtnaWadDebugActionConfigurationError,
        V4ZtnaAccessProxyActionConfigurationError,
        V4FortiAnalyzerActionConfigurationError,
        V4SecretAuditActionConfigurationError,
        V4ActiveLaunchActionConfigurationError,
        V4AutomationTriggerActionConfigurationError,
        V4AutomationActionActionConfigurationError,
        V4AutomationStitchActionConfigurationError,
        V4UserGroupActionConfigurationError,
        V4UserGroupMembershipActionConfigurationError,
        V4AplActionConfigurationError,
        V4AplDisableActionConfigurationError,
        V4ApprovalProfileActionConfigurationError,
        V4ApprovalProfileUpdateActionConfigurationError,
        V4ApprovalEmailTemplateActionConfigurationError,
        V4ApprovalEmailTemplateUpdateActionConfigurationError,
        V4SecretRequestCreateConfigurationError,
        V4TargetUpdateActionConfigurationError,
        V4CertificateCsrActionConfigurationError,
        V4LocalUserDisableActionConfigurationError,
        V4LocalUserCreateActionConfigurationError,
        V4LocalUserResetActionConfigurationError,
        LocalResetOwnedMcpError,
        TerraformPlanReportError,
    ) as exc:
        if v4_terraform_plan_report is not None:
            v4_terraform_plan_report.close()
        if v4_local_user_reset_owned_action is not None:
            v4_local_user_reset_owned_action.close()
        if v4_radius_server_lifecycle_candidate_action is not None:
            v4_radius_server_lifecycle_candidate_action.close()
        if v4_radius_server_pair_lifecycle_candidate_action is not None:
            v4_radius_server_pair_lifecycle_candidate_action.close()
        if v4_radius_user_recovery_candidate_action is not None:
            v4_radius_user_recovery_candidate_action.close()
        if v4_radius_user_lifecycle_candidate_action is not None:
            v4_radius_user_lifecycle_candidate_action.close()
        if v4_jwt_owner_candidate_action is not None:
            v4_jwt_owner_candidate_action.close()
        if v4_jwt_rotation_candidate_action is not None:
            v4_jwt_rotation_candidate_action.close()
        if v4_job_definition_owned_candidate_action is not None:
            v4_job_definition_owned_candidate_action.close()
        if v4_job_execution_owned_candidate_action is not None:
            v4_job_execution_owned_candidate_action.close()
        raise SystemExit(str(exc)) from None
    config = uvicorn.Config(
        app,
        host=settings.host,
        port=settings.port,
        log_level="warning",
        access_log=False,
        server_header=False,
    )
    runner = uvicorn.Server(config)
    if secret_bulk_import_runtime is not None:
        secret_bulk_import_runtime.bind_runner(runner)
    try:
        asyncio.run(runner.serve())
    finally:
        if v4_terraform_plan_report is not None:
            v4_terraform_plan_report.close()
        if v4_local_user_reset_owned_action is not None:
            v4_local_user_reset_owned_action.close()
        if secret_bulk_import_runtime is not None:
            secret_bulk_import_runtime.close()
        if v4_radius_server_lifecycle_candidate_action is not None:
            v4_radius_server_lifecycle_candidate_action.close()
        if v4_radius_server_pair_lifecycle_candidate_action is not None:
            v4_radius_server_pair_lifecycle_candidate_action.close()
        if v4_radius_user_recovery_candidate_action is not None:
            v4_radius_user_recovery_candidate_action.close()
        if v4_radius_user_lifecycle_candidate_action is not None:
            v4_radius_user_lifecycle_candidate_action.close()
        if v4_jwt_owner_candidate_action is not None:
            v4_jwt_owner_candidate_action.close()
        if v4_jwt_rotation_candidate_action is not None:
            v4_jwt_rotation_candidate_action.close()
        if v4_job_definition_owned_candidate_action is not None:
            v4_job_definition_owned_candidate_action.close()
        if v4_job_execution_owned_candidate_action is not None:
            v4_job_execution_owned_candidate_action.close()


def load_http_runtime_environment() -> bool:
    """Load an owner-only HTTP settings file without disclosing its location."""

    from .folder_traversal_mcp_action import PREFIX as folder_traversal_prefix
    from .isolated_folder_mcp_action import PREFIX as isolated_folder_prefix

    configured = os.environ.get(HTTP_ENV_FILE_VARIABLE)
    if not configured:
        return False
    path = os.path.expanduser(configured)
    if not os.path.isfile(path):
        raise HttpConfigurationError("The configured HTTP environment file was not found.")
    environment_path = Path(path)
    load_prefixed_environment_file(environment_path, HTTP_PREFIX)
    load_prefixed_environment_file(environment_path, RUNTIME_PROFILE_ENV)
    load_prefixed_environment_file(environment_path, DIAGNOSTIC_PREFIX)
    load_prefixed_environment_file(environment_path, HA_RECONCILIATION_FEATURE_ENV)
    load_prefixed_environment_file(
        environment_path, HA_RECONCILIATION_PREREQUISITES_ENV
    )
    load_prefixed_environment_file(
        environment_path, HA_RECONCILIATION_QUERY_PERMISSION_ENV
    )
    load_prefixed_environment_file(environment_path, CONTROLLED_OPERATION_PREFIX)
    load_prefixed_environment_file(environment_path, "FORTIPAM_MCP_V4_OWNED_RESET_")
    load_prefixed_environment_file(environment_path, V4_PLANNING_ENV_PREFIX)
    load_prefixed_environment_file(environment_path, "FORTIPAM_MCP_V4_TERRAFORM_PLAN_REPORT_")
    load_prefixed_environment_file(environment_path, 'FORTIPAM_MCP_V4_OWNER_FILE_ISSUER_')
    load_prefixed_environment_file(environment_path, 'FORTIPAM_MCP_V4_SECRET_BULK_IMPORT_')
    load_prefixed_environment_file(environment_path, "FORTIPAM_MCP_V4_LDAP_SERVER_700_")
    load_prefixed_environment_file(environment_path, "FORTIPAM_MCP_V4_RADIUS_PRIMARY_LIFECYCLE_700_")
    load_prefixed_environment_file(environment_path, "FORTIPAM_MCP_V4_RADIUS_PAIR_LIFECYCLE_700_")
    load_prefixed_environment_file(environment_path, "FORTIPAM_MCP_V4_RADIUS_USER_LIFECYCLE_700_")
    load_prefixed_environment_file(environment_path, "FORTIPAM_MCP_V4_JWT_OWNER_700_")
    load_prefixed_environment_file(environment_path, "FORTIPAM_MCP_V4_JWT_ROTATION_700_")
    load_prefixed_environment_file(environment_path, "FORTIPAM_MCP_V4_OWNED_JOB_700_")
    load_prefixed_environment_file(environment_path, "FORTIPAM_MCP_V4_OWNED_JOB_EXECUTION_700_")
    load_prefixed_environment_file(environment_path, "FORTIPAM_MCP_V4_RADIUS_USER_RECOVERY_700_")
    load_prefixed_environment_file(environment_path, "FORTIPAM_MCP_V4_LDAP_SERVER_UPDATE_700_")
    load_prefixed_environment_file(environment_path, "FORTIPAM_MCP_V4_APL_ROLE_UPDATE_700_")
    load_prefixed_environment_file(environment_path, "FORTIPAM_MCP_V4_INSTRUCTION_PROFILE_700_")
    load_prefixed_environment_file(environment_path, "FORTIPAM_MCP_V4_INSTRUCTION_FEATURE_700_")
    load_prefixed_environment_file(environment_path, "FORTIPAM_MCP_V4_INSTRUCTION_QUOTA_700_")
    load_prefixed_environment_file(environment_path, "FORTIPAM_MCP_V4_APPROVAL_BUILD29_")
    load_prefixed_environment_file(
        environment_path, "FORTIPAM_MCP_V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOLS_ENABLED",
    )
    load_prefixed_environment_file(
        environment_path,
        V4_ONBOARDING_EXECUTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        LAB_AUTO_SECRET_CREATE_ENV_PREFIX,
    )
    load_prefixed_environment_file(environment_path, V4_FOLDER_ACTION_PREFIX)
    load_prefixed_environment_file(environment_path, isolated_folder_prefix)
    load_prefixed_environment_file(environment_path, folder_traversal_prefix)
    load_prefixed_environment_file(environment_path, FOLDER_TRANSPORT_ENV_PREFIX)
    load_prefixed_environment_file(environment_path, V4_FOLDER_ACL_ACTION_PREFIX)
    load_prefixed_environment_file(
        environment_path,
        V4_FOLDER_ACL_REVOKE_ACTION_PREFIX,
    )
    load_prefixed_environment_file(environment_path, FOLDER_ACL_ENV_PREFIX)
    load_prefixed_environment_file(
        environment_path,
        V4_CLASSIFICATION_TAG_ACTION_FEATURE_ENV,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_CLASSIFICATION_TAG_DELETE_ACTION_FEATURE_ENV,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_CLASSIFICATION_TAG_DELETE_EXECUTION_ENV,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_CLASSIFICATION_TAG_DELETE_SELECTOR_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_CLASSIFICATION_TAG_ASSIGN_ACTION_FEATURE_ENV,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_CLASSIFICATION_TAG_ASSIGN_ROLLBACK_SELECTOR_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_SCHEDULE_ASSIGN_ACTION_FEATURE_ENV,
    )
    load_prefixed_environment_file(
        environment_path,
        SCHEDULE_ASSIGN_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(environment_path, V4_ADDRESS_ACTION_FEATURE_ENV)
    load_prefixed_environment_file(environment_path, ADDRESS_TRANSPORT_ENV_PREFIX)
    load_prefixed_environment_file(
        environment_path,
        V4_ADDRESS_GROUP_ACTION_FEATURE_ENV,
    )
    load_prefixed_environment_file(
        environment_path,
        ADDRESS_GROUP_CLI_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_ZTNA_DEVICE_CONTEXT_DIAGNOSTIC_FEATURE_ENV,
    )
    load_prefixed_environment_file(
        environment_path,
        ZTNA_DEVICE_CONTEXT_DIAGNOSTIC_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_ZTNA_FOLDER_POSTURE_FEATURE_ENV,
    )
    load_prefixed_environment_file(environment_path, ZTNA_FOLDER_POSTURE_ENV_PREFIX)
    load_prefixed_environment_file(
        environment_path,
        V4_FOLDER_RENAME_ACTION_FEATURE_ENV,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_FOLDER_ARCHIVE_ACTION_FEATURE_ENV,
    )
    load_prefixed_environment_file(environment_path, FOLDER_ARCHIVE_ENV_PREFIX)
    load_prefixed_environment_file(
        environment_path,
        V4_FOLDER_POLICY_ASSIGN_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_FOLDER_POLICY_DETACH_ACTION_PREFIX,
    )
    load_prefixed_environment_file(environment_path, V4_TARGET_ACTION_FEATURE_ENV)
    load_prefixed_environment_file(
        environment_path,
        V4_TARGET_DELETE_ACTION_FEATURE_ENV,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_TARGET_DELETE_EXECUTION_ENV,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_TARGET_DELETE_SELECTOR_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_SECRET_METADATA_ACTION_FEATURE_ENV,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_INTERFACE_WEB_PROXY_ACTION_FEATURE_ENV,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_TARGET_UPDATE_ACTION_FEATURE_ENV,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_CERTIFICATE_CSR_ACTION_FEATURE_ENV,
    )
    load_prefixed_environment_file(environment_path, TARGET_TRANSPORT_ENV_PREFIX)
    load_prefixed_environment_file(environment_path, TARGET_SSH_TRANSPORT_ENV_PREFIX)
    load_prefixed_environment_file(
        environment_path,
        CERTIFICATE_CSR_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        SECRET_METADATA_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        INTERFACE_WEB_PROXY_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_LOCAL_USER_DISABLE_ACTION_PREFIX,
    )
    load_prefixed_environment_file(environment_path, LOCAL_USER_TRANSPORT_ENV_PREFIX)
    load_prefixed_environment_file(
        environment_path,
        V4_LOCAL_USER_CREATE_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_LOCAL_USER_RESET_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        LOCAL_USER_CREATE_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_ROLE_CREATE_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        ROLE_CREATE_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_ROLE_UPDATE_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        ROLE_UPDATE_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_ROLE_ASSIGN_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        ROLE_ASSIGN_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_DLP_FILE_PATTERN_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        DLP_FILE_PATTERN_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_DLP_SENSOR_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        DLP_SENSOR_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_ANTIVIRUS_PROFILE_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        ANTIVIRUS_PROFILE_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_RDP_EVENT_FILTER_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        RDP_EVENT_FILTER_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_SECRET_POLICY_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        SECRET_POLICY_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_SSH_FILTER_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        SSH_FILTER_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_LAUNCHER_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        LAUNCHER_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_LAUNCHER_UPDATE_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        LAUNCHER_UPDATE_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_LAUNCHER_MATCHER_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        LAUNCHER_MATCHER_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_TEMPLATE_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        TEMPLATE_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_TEMPLATE_ARCHIVE_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        TEMPLATE_ARCHIVE_SSH_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        TEMPLATE_ARCHIVE_HTTP_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_DEPENDENCY_UPDATER_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        DEPENDENCY_UPDATER_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_SECRET_GATEWAY_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        SECRET_GATEWAY_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_CLIENT_INTEGRITY_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        CLIENT_INTEGRITY_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_CHARACTER_SET_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        CHARACTER_SET_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_WINDOWS_APP_FILTER_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        WINDOWS_APP_FILTER_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_RECORDING_POLICY_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        RECORDING_POLICY_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_PASSWORD_POLICY_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        PASSWORD_POLICY_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_REPORT_LAYOUT_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_ZTNA_ACCESS_PROXY_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        ZTNA_ACCESS_PROXY_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_ZTNA_USER_CONTROL_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        ZTNA_USER_CONTROL_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_ZTNA_WAD_DEBUG_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        ZTNA_WAD_DEBUG_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_SNMP_AGENT_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        SNMP_AGENT_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        SNMP_AGENT_STATUS_HTTP_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_LOGGING_DISK_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        LOGGING_DISK_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_FORTIANALYZER_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        FORTIANALYZER_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_MAINTENANCE_MODE_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        MAINTENANCE_MODE_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        MAINTENANCE_MODE_STATUS_HTTP_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_SECRET_AUDIT_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_SECRET_AUDIT_SUMMARY_FEATURE_ENV.removesuffix("ENABLED"),
    )
    load_prefixed_environment_file(
        environment_path,
        SECRET_AUDIT_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_ACTIVE_LAUNCH_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        ACTIVE_LAUNCH_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_AUTOMATION_TRIGGER_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        AUTOMATION_TRIGGER_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_AUTOMATION_ACTION_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        AUTOMATION_ACTION_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_AUTOMATION_STITCH_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        AUTOMATION_STITCH_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_USER_GROUP_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        USER_GROUP_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_USER_GROUP_MEMBERSHIP_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        USER_GROUP_MEMBERSHIP_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_APL_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        APL_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_APL_DISABLE_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        APL_DISABLE_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_SCHEDULE_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        SCHEDULE_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_APPROVAL_PROFILE_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        APPROVAL_PROFILE_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_APPROVAL_PROFILE_UPDATE_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        APPROVAL_PROFILE_UPDATE_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_APPROVAL_EMAIL_TEMPLATE_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        APPROVAL_EMAIL_TEMPLATE_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        APPROVAL_EMAIL_TEMPLATE_UPDATE_TRANSPORT_ENV_PREFIX,
    )
    load_prefixed_environment_file(
        environment_path,
        V4_SECRET_REQUEST_CREATE_PREFIX,
    )
    return True


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    raw = environment.get(f"{HTTP_PREFIX}{suffix}")
    if raw is None:
        return None
    value = raw.strip()
    return value or None


def _exact_value(environment: Mapping[str, str], name: str) -> str | None:
    raw = environment.get(name)
    if raw is None:
        return None
    value = raw.strip()
    return value or None


def _port(raw: str | None) -> int:
    if raw is None:
        return DEFAULT_PORT
    try:
        port = int(raw)
    except ValueError as exc:
        raise HttpConfigurationError("HTTP port must be numeric.") from exc
    if not 1 <= port <= 65535:
        raise HttpConfigurationError("HTTP port is outside the valid range.")
    return port


def _path(raw: str) -> str:
    if (
        not raw.startswith("/")
        or raw == "/"
        or raw.endswith("/")
        or "?" in raw
        or "#" in raw
        or "\\" in raw
        or any(segment in {".", ".."} for segment in raw.split("/"))
    ):
        raise HttpConfigurationError(
            "The MCP HTTP path must be one absolute path without traversal or a trailing slash."
        )
    return raw


def _csv(raw: str | None) -> tuple[str, ...]:
    if raw is None:
        return ()
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _optional_public_url(
    raw: str | None,
    label: str,
    *,
    allow_insecure_private_ip_lab: bool,
) -> str | None:
    if raw is None:
        return None
    parsed = urlsplit(raw)
    if allow_insecure_private_ip_lab and _is_private_lab_http_url(raw):
        return raw.rstrip("/")
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise HttpConfigurationError(f"The {label} must be an HTTPS URL.")
    return raw.rstrip("/")


def _optional_https_url(raw: str | None, label: str) -> str | None:
    return _optional_public_url(raw, label, allow_insecure_private_ip_lab=False)


def _insecure_private_ip_lab_enabled(environment: Mapping[str, str]) -> bool:
    raw = _value(environment, "INSECURE_PRIVATE_IP_LAB")
    if raw is None or raw == "false":
        return False
    if raw != "true":
        raise HttpConfigurationError(
            "FORTIPAM_MCP_HTTP_INSECURE_PRIVATE_IP_LAB must be exactly true or false."
        )
    return True


def _is_private_lab_http_url(raw: str) -> bool:
    parsed = urlsplit(raw)
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.port is not None
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        return False
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return False
    return address.version == 4 and address in ipaddress.ip_network((0x0A000000, 8))


def _is_loopback(host: str) -> bool:
    return host.lower() in {"127.0.0.1", "::1", "localhost"}


def _token_scopes(claims: Mapping[str, Any]) -> tuple[str, ...]:
    raw_scope = claims.get("scope")
    if isinstance(raw_scope, str):
        return tuple(item for item in raw_scope.split() if item)
    raw_scp = claims.get("scp")
    if isinstance(raw_scp, list):
        return tuple(str(item) for item in raw_scp if str(item))
    return ()


if __name__ == "__main__":
    main()
