"""Static, non-executing metadata for the FortiPAM MCP tool surface.

This registry is deliberately separate from MCP tool registration.  It can
describe the current surface and model a future allowlisted tool-pack selector,
but it cannot enable, disable, register, or dispatch any FortiPAM operation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable


CAPABILITY_MATRIX_SCHEMA_VERSION = "1.3"


class ToolPack(StrEnum):
    """Stable identifiers for bounded, opt-in future tool-pack configuration."""

    CORE = "core"
    KNOWLEDGE = "knowledge"
    API_DISCOVERY = "api-discovery"
    PLATFORM_READ = "platform-read"
    APPROVAL_READ = "approval-read"
    LOGGING_READ = "logging-read"
    RESILIENCE_READ = "resilience-read"
    RECORDING_READ = "recording-read"
    PASSWORD_LIFECYCLE_READ = "password-lifecycle-read"
    INTEGRATION_READ = "integration-read"
    CLI_DIAGNOSTICS = "cli-diagnostics"
    DIAGNOSTIC_STATE = "diagnostic-state"
    LAB_ADMIN = "lab-admin"
    V4_PLAN = "v4-plan"
    V4_APPROVAL_REQUEST_OBSERVATION = "v4-approval-request-observation"
    V4_FOLDER_ACTION = "v4-folder-action"
    V4_FOLDER_ACL_ACTION = "v4-folder-acl-action"
    V4_CLASSIFICATION_TAG_ACTION = "v4-classification-tag-action"
    V4_ADDRESS_ACTION = "v4-address-action"
    V4_ADDRESS_GROUP_ACTION = "v4-address-group-action"
    V4_ZTNA_DIAGNOSTIC = "v4-ztna-diagnostic"
    V4_TARGET_ACTION = "v4-target-action"
    V4_CERTIFICATE_CSR_ACTION = "v4-certificate-csr-action"
    V4_SECRET_METADATA_ACTION = "v4-secret-metadata-action"
    V4_INTERFACE_WEB_PROXY_ACTION = "v4-interface-web-proxy-action"
    V4_LOCAL_USER_ACTION = "v4-local-user-action"
    V4_ROLE_ACTION = "v4-role-action"
    V4_DLP_FILE_PATTERN_ACTION = "v4-dlp-file-pattern-action"
    V4_DLP_SENSOR_ACTION = "v4-dlp-sensor-action"
    V4_ANTIVIRUS_PROFILE_ACTION = "v4-antivirus-profile-action"
    V4_RDP_EVENT_FILTER_ACTION = "v4-rdp-event-filter-action"
    V4_SECRET_POLICY_ACTION = "v4-secret-policy-action"
    V4_SSH_FILTER_ACTION = "v4-ssh-filter-action"
    V4_LAUNCHER_ACTION = "v4-launcher-action"
    V4_TEMPLATE_ACTION = "v4-template-action"
    V4_TEMPLATE_ARCHIVE_ACTION = "v4-template-archive-action"
    V4_DEPENDENCY_UPDATER_ACTION = "v4-dependency-updater-action"
    V4_SECRET_GATEWAY_ACTION = "v4-secret-gateway-action"
    V4_CLIENT_INTEGRITY_ACTION = "v4-client-integrity-action"
    V4_CHARACTER_SET_ACTION = "v4-character-set-action"
    V4_WINDOWS_APP_FILTER_ACTION = "v4-windows-app-filter-action"
    V4_RECORDING_POLICY_ACTION = "v4-recording-policy-action"
    V4_PASSWORD_POLICY_ACTION = "v4-password-policy-action"
    V4_REPORT_LAYOUT_ACTION = "v4-report-layout-action"
    V4_ZTNA_ACCESS_PROXY_ACTION = "v4-ztna-access-proxy-action"
    V4_ZTNA_USER_CONTROL_ACTION = "v4-ztna-user-control-action"
    V4_ZTNA_WAD_DEBUG_ACTION = "v4-ztna-wad-debug-action"
    V4_SNMP_AGENT_ACTION = "v4-snmp-agent-action"
    V4_LOGGING_DISK_ACTION = "v4-logging-disk-action"
    V4_FORTIANALYZER_ACTION = "v4-fortianalyzer-action"
    V4_MAINTENANCE_MODE_ACTION = "v4-maintenance-mode-action"
    V4_SECRET_AUDIT_ACTION = "v4-secret-audit-action"
    V4_SECRET_AUDIT_SUMMARY = "v4-secret-audit-summary"
    V4_TERRAFORM_PLAN_REPORT = "v4-terraform-plan-report"
    V4_ACTIVE_LAUNCH_ACTION = "v4-active-launch-action"
    V4_AUTOMATION_TRIGGER_ACTION = "v4-automation-trigger-action"
    V4_AUTOMATION_ACTION_ACTION = "v4-automation-action-action"
    V4_AUTOMATION_STITCH_ACTION = "v4-automation-stitch-action"
    V4_USER_GROUP_ACTION = "v4-user-group-action"
    V4_APL_ACTION = "v4-auto-provision-rule-action"
    V4_SCHEDULE_ACTION = "v4-schedule-action"
    V4_APPROVAL_PROFILE_ACTION = "v4-approval-profile-action"
    V4_APPROVAL_PROFILE_UPDATE_ACTION = "v4-approval-profile-update-action"
    V4_APPROVAL_EMAIL_TEMPLATE_ACTION = "v4-approval-email-template-action"
    V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION = "v4-approval-email-template-update-action"


class ActionFamilyEvidenceStatus(StrEnum):
    """Non-authorizing evidence maturity for a reviewed action family."""

    DOCUMENTED = "documented"
    IMPLEMENTED = "implemented"
    LAB_ACCEPTED = "lab_accepted"
    VERIFIED = "verified"
    PRODUCT_UNAVAILABLE = "product_unavailable"


TOOL_PACK_ACTION_FAMILIES: dict[ToolPack, tuple[str, ...]] = {
    ToolPack.V4_PLAN: (
        "firmware.upgrade.plan",
        "backup.create",
        "backup.restore.plan",
        "license.install",
        "system-email.configure",
        "email-alert.configure",
        "glass-break.activate",
        "route.configure",
        "dns.configure",
        "ha.configure",
        "ha.maintenance",
        "ha.reconcile",
        "certificate.import",
        "crl.import",
        "ldap-server.configure",
        "radius-server.configure",
        "saml-server.configure",
        "jwt-key.create",
        "jwt-key.rotate",
        "scim-client.create",
        "scim-client.rotate",
        "scim-client.disable",
        "fortitoken.assign",
        "fortitoken.revoke",
        "apl.update",
        "discovery-entry.create",
        "discovery.run",
        "discovery.review",
        "job.create",
        "job.execute",
        "password-changer.create",
        "password-verification.configure",
        "checkout-policy.configure",
        "jit-policy.configure",
        "service-account.update",
        "instruction-profile.create",
        "event-subscription.configure",
        "secret.bulk-import.plan",
        "secret.bulk-import.apply",
        "launcher.clone",
        "policy.assign",
        "approval-delivery.configure",
        "fabric-connector.configure",
        "secret-gateway.chain.configure",
        "reverse-service.configure",
        "ztna-tag.create",
        "ztna-tag-group.create",
        "target.disable",
        "secret.update-metadata",
        "approval-profile.disable",
        "secret.disable",
        "launcher.disable",
    ),
    ToolPack.V4_FOLDER_ACTION: ("folder.create",),
    ToolPack.V4_FOLDER_ACL_ACTION: (
        "folder.acl.grant",
        "folder.acl.revoke",
        "folder.rename",
        "folder.archive",
        "folder.policy.assign",
        "folder.policy.detach",
    ),
    ToolPack.V4_CLASSIFICATION_TAG_ACTION: (
        "classification-tag.create",
        "classification-tag.assign",
        "classification-tag.delete",
    ),
    ToolPack.V4_ADDRESS_ACTION: ("address.create", "address.delete"),
    ToolPack.V4_ADDRESS_GROUP_ACTION: (
        "address-group.create",
        "address-group.delete",
    ),
    ToolPack.V4_ZTNA_DIAGNOSTIC: (
        "ztna-device-context-diagnostic",
        "ztna-folder-control-posture",
    ),
    ToolPack.V4_TARGET_ACTION: ("target.create", "target.update", "target.delete"),
    ToolPack.V4_CERTIFICATE_CSR_ACTION: ("certificate.create",),
    ToolPack.V4_SECRET_METADATA_ACTION: ("secret.create-from-reference",),
    ToolPack.V4_INTERFACE_WEB_PROXY_ACTION: ("interface.configure",),
    ToolPack.V4_LOCAL_USER_ACTION: (
        "local-user.create",
        "local-user.disable",
        "local-user.reset",
    ),
    ToolPack.V4_ROLE_ACTION: ("role.create", "role.update", "role.assign"),
    ToolPack.V4_DLP_FILE_PATTERN_ACTION: (
        "dlp-pattern.create",
        "dlp-pattern.delete",
    ),
    ToolPack.V4_DLP_SENSOR_ACTION: ("dlp-profile.create", "dlp-profile.delete"),
    ToolPack.V4_ANTIVIRUS_PROFILE_ACTION: (
        "antivirus-profile.create",
        "antivirus-profile.delete",
    ),
    ToolPack.V4_RDP_EVENT_FILTER_ACTION: (
        "rdp-event-filter.create",
        "rdp-event-filter.delete",
    ),
    ToolPack.V4_SECRET_POLICY_ACTION: ("policy.create", "policy.update"),
    ToolPack.V4_SSH_FILTER_ACTION: ("ssh-filter.create", "ssh-filter.delete"),
    ToolPack.V4_LAUNCHER_ACTION: (
        "launcher.create",
        "launcher.update",
        "launcher.matcher.configure",
    ),
    ToolPack.V4_TEMPLATE_ACTION: ("template.create", "template.update"),
    ToolPack.V4_TEMPLATE_ARCHIVE_ACTION: ("template.archive",),
    ToolPack.V4_DEPENDENCY_UPDATER_ACTION: ("dependency-updater.create",),
    ToolPack.V4_SECRET_GATEWAY_ACTION: ("secret-gateway.create",),
    ToolPack.V4_CLIENT_INTEGRITY_ACTION: ("client-integrity.configure",),
    ToolPack.V4_CHARACTER_SET_ACTION: ("charset.create",),
    ToolPack.V4_WINDOWS_APP_FILTER_ACTION: ("windows-app-filter.create",),
    ToolPack.V4_RECORDING_POLICY_ACTION: ("recording-policy.configure",),
    ToolPack.V4_PASSWORD_POLICY_ACTION: ("password-policy.create",),
    ToolPack.V4_REPORT_LAYOUT_ACTION: ("report.create", "report.schedule"),
    ToolPack.V4_ZTNA_ACCESS_PROXY_ACTION: (
        "ztna-access-proxy-client-certificate-policy",
    ),
    ToolPack.V4_ZTNA_USER_CONTROL_ACTION: ("ztna-user-control.configure",),
    ToolPack.V4_ZTNA_WAD_DEBUG_ACTION: ("ztna-wad-debug-capture",),
    ToolPack.V4_SNMP_AGENT_ACTION: ("snmp.configure",),
    ToolPack.V4_LOGGING_DISK_ACTION: ("logging-disk.configure",),
    ToolPack.V4_FORTIANALYZER_ACTION: ("fortianalyzer.configure",),
    ToolPack.V4_MAINTENANCE_MODE_ACTION: ("maintenance-mode.configure",),
    ToolPack.V4_SECRET_AUDIT_ACTION: ("secret-audit.generate",),
    ToolPack.V4_SECRET_AUDIT_SUMMARY: (),
    ToolPack.V4_TERRAFORM_PLAN_REPORT: (),
    ToolPack.V4_ACTIVE_LAUNCH_ACTION: ("session.observe", "session.disconnect"),
    ToolPack.V4_AUTOMATION_TRIGGER_ACTION: (
        "automation-trigger.create",
        "automation-trigger.delete",
    ),
    ToolPack.V4_AUTOMATION_ACTION_ACTION: (
        "automation-action.create",
        "automation-action.delete",
    ),
    ToolPack.V4_AUTOMATION_STITCH_ACTION: (
        "automation-stitch.create",
        "automation-stitch.delete",
    ),
    ToolPack.V4_USER_GROUP_ACTION: (
        "user-group.create",
        "user-group.membership.change",
    ),
    ToolPack.V4_APL_ACTION: ("apl.create", "apl.disable"),
    ToolPack.V4_SCHEDULE_ACTION: ("schedule.create", "schedule.assign"),
    ToolPack.V4_APPROVAL_PROFILE_ACTION: ("approval-profile.create",),
    ToolPack.V4_APPROVAL_PROFILE_UPDATE_ACTION: (
        "approval-profile.update",
        "approval-profile.delete",
    ),
    ToolPack.V4_APPROVAL_EMAIL_TEMPLATE_ACTION: (
        "approval-email-template.create",
    ),
    ToolPack.V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION: (
        "approval-email-template.update",
        "approval-email-template.delete",
    ),
}


LOCAL_VERIFICATION_ELIGIBLE_ACTION_FAMILIES = frozenset(
    {
        "firmware.upgrade.plan",
        "backup.restore.plan",
        "secret.bulk-import.plan",
        "discovery.review",
        "ztna-device-context-diagnostic",
        "ztna-folder-control-posture",
        "session.observe",
    }
)


_ACTION_FAMILY_EVIDENCE_GROUPS: dict[
    ActionFamilyEvidenceStatus, frozenset[str]
] = {
    ActionFamilyEvidenceStatus.LAB_ACCEPTED: frozenset(
        {
            "ztna-wad-debug-capture",
            "backup.create",
            "local-user.reset",
            "fabric-connector.configure",
            "folder.create",
            "folder.archive",
            "instruction-profile.create",
            "launcher.clone",
            "folder.acl.grant",
            "folder.acl.revoke",
            "folder.rename",
            "folder.policy.assign",
            "folder.policy.detach",
            "classification-tag.create",
            "classification-tag.assign",
            "classification-tag.delete",
            "address.create",
            "address.delete",
            "address-group.create",
            "address-group.delete",
            "target.create",
            "target.update",
            "secret.update-metadata",
            "certificate.create",
            "certificate.import",
            "ztna-tag-group.create",
            "interface.configure",
            "route.configure",
            "dns.configure",
            "local-user.create",
            "local-user.disable",
            "role.create",
            "role.update",
            "target.delete",
            "role.assign",
            "dlp-pattern.create",
            "dlp-pattern.delete",
            "dlp-profile.create",
            "dlp-profile.delete",
            "antivirus-profile.create",
            "antivirus-profile.delete",
            "rdp-event-filter.create",
            "rdp-event-filter.delete",
            "policy.create",
            "policy.update",
            "ssh-filter.create",
            "ssh-filter.delete",
            "launcher.create",
            "launcher.update",
            "launcher.matcher.configure",
            "template.create",
            "template.update",
            "template.archive",
            "dependency-updater.create",
            "password-changer.create",
            "secret-gateway.create",
            "secret.create-from-reference",
            "charset.create",
            "windows-app-filter.create",
            "recording-policy.configure",
            "password-policy.create",
            "password-verification.configure",
            "checkout-policy.configure",
            "event-subscription.configure",
            "secret-audit.generate",
            "session.disconnect",
            "report.create",
            "report.schedule",
            "snmp.configure",
            "logging-disk.configure",
            "maintenance-mode.configure",
            "automation-trigger.create",
            "automation-trigger.delete",
            "automation-action.create",
            "automation-action.delete",
            "automation-stitch.create",
            "automation-stitch.delete",
            "user-group.create",
            "user-group.membership.change",
            "apl.create",
            "apl.disable",
            "apl.update",
            "ldap-server.configure",
            "jwt-key.create",
            "jwt-key.rotate",
            "job.create",
            "job.execute",
            "discovery-entry.create",
            "discovery.run",
            "schedule.create",
            "schedule.assign",
            "approval-profile.create",
            "approval-profile.update",
            "approval-profile.delete",
            "approval-email-template.create",
            "approval-email-template.update",
            "approval-email-template.delete",
        }
    ),
    ActionFamilyEvidenceStatus.IMPLEMENTED: frozenset(
        {
            "client-integrity.configure",
            "fortianalyzer.configure",
            "ztna-access-proxy-client-certificate-policy",
            "ztna-user-control.configure",
            "ha.reconcile",
            "crl.import",
        }
    ),
    ActionFamilyEvidenceStatus.DOCUMENTED: frozenset(
        {
            "license.install",
            "system-email.configure",
            "email-alert.configure",
            "glass-break.activate",
            "ha.configure",
            "ha.maintenance",
            "radius-server.configure",
            "saml-server.configure",
            "scim-client.create",
            "scim-client.rotate",
            "scim-client.disable",
            "fortitoken.assign",
            "fortitoken.revoke",
            "jit-policy.configure",
            "service-account.update",
            "secret.bulk-import.apply",
            "policy.assign",
            "approval-delivery.configure",
            "secret-gateway.chain.configure",
            "reverse-service.configure",
            "ztna-tag.create",
        }
    ),
    ActionFamilyEvidenceStatus.VERIFIED: LOCAL_VERIFICATION_ELIGIBLE_ACTION_FAMILIES,
    ActionFamilyEvidenceStatus.PRODUCT_UNAVAILABLE: frozenset(
        {
            "target.disable",
            "approval-profile.disable",
            "secret.disable",
            "launcher.disable",
        }
    ),
}

_mapped_action_families = frozenset(
    action_family
    for action_families in TOOL_PACK_ACTION_FAMILIES.values()
    for action_family in action_families
)
_classified_action_families = frozenset(
    action_family
    for action_families in _ACTION_FAMILY_EVIDENCE_GROUPS.values()
    for action_family in action_families
)
if sum(map(len, _ACTION_FAMILY_EVIDENCE_GROUPS.values())) != len(
    _classified_action_families
):
    raise RuntimeError("Action-family evidence groups must not overlap.")
if _classified_action_families != _mapped_action_families:
    raise RuntimeError("Every mapped action family needs one evidence status.")

ACTION_FAMILY_EVIDENCE_STATUS: dict[str, ActionFamilyEvidenceStatus] = {
    action_family: status
    for status, action_families in _ACTION_FAMILY_EVIDENCE_GROUPS.items()
    for action_family in action_families
}

EXACT_ACTION_STATE_COUNTS: dict[str, int] = {
    "lab_accepted": 96,
    "implemented_not_accepted": 5,
    "documented_not_accepted": 21,
    "verified": 5,
    "source_gated": 0,
    "product_unavailable": 4,
}

READY_IMPLEMENTED_ACTIONS: tuple[str, ...] = ()

IMPLEMENTED_ACTION_READINESS_SUMMARY: dict[str, object] = {
    "ready_for_authorized_preview": 0,
    "baseline_unavailable": 3,
    "reconciliation_required_non_retry": 2,
    "ready_actions": list(READY_IMPLEMENTED_ACTIONS),
}

EXACT_ACTION_INVENTORY_SUMMARY: dict[str, object] = {
    "total": 131,
    "mapped": 131,
    "unmapped": 0,
    "mapped_supplemental": 4,
    "states": EXACT_ACTION_STATE_COUNTS,
    "implemented_readiness": IMPLEMENTED_ACTION_READINESS_SUMMARY,
}


class ExecutionMode(StrEnum):
    """Whether a tool only uses local metadata, plans, or contacts FortiPAM."""

    OFFLINE = "offline"
    PLAN = "plan"
    LIVE = "live"
    LAB_SIMULATED = "lab_simulated"


class RiskLevel(StrEnum):
    """Risk of invoking the fixed-purpose MCP tool, not an API permission tier."""

    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"


class InputScope(StrEnum):
    """The caller-controlled input shape accepted by the existing tool."""

    NONE = "none"
    BOUNDED_QUERY = "bounded_query"
    EXACT_API_OPERATION = "exact_api_operation"
    EXACT_SCENARIO_ID = "exact_scenario_id"
    CONSTRAINED_BASELINE_ID = "constrained_baseline_id"
    LAB_ADMIN_PREVIEW = "lab_admin_preview"
    LAB_CONFIRMATION = "lab_confirmation"
    V4_PLAN_REFERENCE = "v4_plan_reference"
    V4_REQUEST_REFERENCE = "v4_request_reference"
    V4_FIRMWARE_UPGRADE_PLAN = "v4_firmware_upgrade_plan"
    V4_BACKUP_CREATE_PLAN = "v4_backup_create_plan"
    V4_BACKUP_RESTORE_PLAN = "v4_backup_restore_plan"
    V4_LICENSE_INSTALL_PLAN = "v4_license_install_plan"
    V4_SYSTEM_EMAIL_PLAN = "v4_system_email_plan"
    V4_EMAIL_ALERT_PLAN = "v4_email_alert_plan"
    V4_ROUTE_PLAN = "v4_route_plan"
    V4_DNS_PLAN = "v4_dns_plan"
    V4_HA_CONFIGURE_PLAN = "v4_ha_configure_plan"
    V4_HA_MAINTENANCE_PLAN = "v4_ha_maintenance_plan"
    V4_HA_RECONCILE_PLAN = "v4_ha_reconcile_plan"
    V4_SECRET_BULK_IMPORT_PLAN = "v4_secret_bulk_import_plan"
    V4_FOLDER_CREATE_PREVIEW = "v4_folder_create_preview"
    V4_FOLDER_ACL_GRANT_PREVIEW = "v4_folder_acl_grant_preview"
    V4_FOLDER_ACL_REVOKE_PREVIEW = "v4_folder_acl_revoke_preview"
    V4_FOLDER_RENAME_PREVIEW = "v4_folder_rename_preview"
    V4_FOLDER_ARCHIVE_PREVIEW = "v4_folder_archive_preview"
    V4_FOLDER_POLICY_ASSIGN_PREVIEW = "v4_folder_policy_assign_preview"
    V4_FOLDER_POLICY_DETACH_PREVIEW = "v4_folder_policy_detach_preview"
    V4_CLASSIFICATION_TAG_CREATE_PREVIEW = "v4_classification_tag_create_preview"
    V4_CLASSIFICATION_TAG_ASSIGN_PREVIEW = "v4_classification_tag_assign_preview"
    V4_ADDRESS_CREATE_PREVIEW = "v4_address_create_preview"
    V4_ADDRESS_GROUP_CREATE_PREVIEW = "v4_address_group_create_preview"
    V4_TARGET_CREATE_PREVIEW = "v4_target_create_preview"
    V4_TARGET_UPDATE_PREVIEW = "v4_target_update_preview"
    V4_CERTIFICATE_CSR_GENERATE_PREVIEW = "v4_certificate_csr_generate_preview"
    V4_SECRET_METADATA_CREATE_PREVIEW = "v4_secret_metadata_create_preview"
    V4_INTERFACE_WEB_PROXY_ENABLE_PREVIEW = "v4_interface_explicit_web_proxy_enable_preview"
    V4_LOCAL_USER_CREATE_PREVIEW = "v4_local_user_create_preview"
    V4_LOCAL_USER_RESET_PREVIEW = "v4_local_user_reset_preview"
    V4_LOCAL_USER_DISABLE_PREVIEW = "v4_local_user_disable_preview"
    V4_ROLE_CREATE_PREVIEW = "v4_role_create_preview"
    V4_ROLE_UPDATE_PREVIEW = "v4_role_update_preview"
    V4_ROLE_ASSIGN_PREVIEW = "v4_role_assign_preview"
    V4_DLP_FILE_PATTERN_CREATE_PREVIEW = "v4_dlp_file_pattern_create_preview"
    V4_DLP_SENSOR_CREATE_PREVIEW = "v4_dlp_sensor_create_preview"
    V4_ANTIVIRUS_PROFILE_CREATE_PREVIEW = "v4_antivirus_profile_create_preview"
    V4_RDP_EVENT_FILTER_CREATE_PREVIEW = "v4_rdp_event_filter_create_preview"
    V4_SECRET_POLICY_CREATE_PREVIEW = "v4_secret_policy_create_preview"
    V4_SECRET_POLICY_UPDATE_PREVIEW = "v4_secret_policy_update_preview"
    V4_SSH_FILTER_CREATE_PREVIEW = "v4_ssh_filter_create_preview"
    V4_LAUNCHER_CREATE_PREVIEW = "v4_launcher_create_preview"
    V4_LAUNCHER_UPDATE_PREVIEW = "v4_launcher_update_preview"
    V4_LAUNCHER_MATCHER_CONFIGURE_PREVIEW = "v4_launcher_matcher_configure_preview"
    V4_TEMPLATE_CREATE_PREVIEW = "v4_template_create_preview"
    V4_TEMPLATE_UPDATE_PREVIEW = "v4_template_update_preview"
    V4_TEMPLATE_ARCHIVE_PREVIEW = "v4_template_archive_preview"
    V4_DEPENDENCY_UPDATER_CREATE_PREVIEW = "v4_dependency_updater_create_preview"
    V4_SECRET_GATEWAY_CREATE_PREVIEW = "v4_secret_gateway_create_preview"
    V4_CLIENT_INTEGRITY_CONFIGURE_PREVIEW = "v4_client_integrity_configure_preview"
    V4_CHARACTER_SET_CREATE_PREVIEW = "v4_character_set_create_preview"
    V4_WINDOWS_APP_FILTER_CREATE_PREVIEW = "v4_windows_app_filter_create_preview"
    V4_RECORDING_POLICY_ENABLE_PREVIEW = "v4_recording_policy_enable_preview"
    V4_PASSWORD_POLICY_CREATE_PREVIEW = "v4_password_policy_create_preview"
    V4_REPORT_LAYOUT_CREATE_PREVIEW = "v4_report_layout_create_preview"
    V4_ZTNA_ACCESS_PROXY_CLIENT_CERTIFICATE_PREVIEW = (
        "v4_ztna_access_proxy_client_certificate_preview"
    )
    V4_ZTNA_USER_CONTROL_CONFIGURE_PREVIEW = "v4_ztna_user_control_configure_preview"
    V4_ZTNA_WAD_DEBUG_PREVIEW = "v4_ztna_wad_debug_preview"
    V4_SNMP_AGENT_ENABLE_PREVIEW = "v4_snmp_agent_enable_preview"
    V4_LOGGING_DISK_DISABLE_PREVIEW = "v4_logging_disk_disable_preview"
    V4_FORTIANALYZER_ENABLE_PREVIEW = "v4_fortianalyzer_enable_preview"
    V4_MAINTENANCE_MODE_ENABLE_PREVIEW = "v4_maintenance_mode_enable_preview"
    V4_ACTIVE_LAUNCH_DISCONNECT_PREVIEW = "v4_active_launch_disconnect_preview"
    V4_AUTOMATION_TRIGGER_CREATE_PREVIEW = "v4_automation_trigger_create_preview"
    V4_AUTOMATION_ACTION_CREATE_PREVIEW = "v4_automation_action_create_preview"
    V4_AUTOMATION_STITCH_CREATE_PREVIEW = "v4_automation_stitch_create_preview"
    V4_USER_GROUP_CREATE_PREVIEW = "v4_user_group_create_preview"
    V4_USER_GROUP_MEMBERSHIP_CHANGE_PREVIEW = (
        "v4_user_group_membership_change_preview"
    )
    V4_APL_CREATE_PREVIEW = "v4_auto_provision_rule_create_preview"
    V4_APL_DISABLE_PREVIEW = "v4_auto_provision_rule_disable_preview"
    V4_SCHEDULE_CREATE_PREVIEW = "v4_schedule_create_preview"
    V4_SCHEDULE_ASSIGN_PREVIEW = "v4_schedule_assign_preview"
    V4_APPROVAL_PROFILE_CREATE_PREVIEW = "v4_approval_profile_create_preview"
    V4_APPROVAL_PROFILE_UPDATE_PREVIEW = "v4_approval_profile_update_preview"
    V4_APPROVAL_EMAIL_TEMPLATE_CREATE_PREVIEW = (
        "v4_approval_email_template_create_preview"
    )
    V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_PREVIEW = (
        "v4_approval_email_template_update_preview"
    )
    V4_AUTHORIZATION_REFERENCE = "v4_authorization_reference"


@dataclass(frozen=True, slots=True)
class ToolPackDefinition:
    """One logical group of fixed-purpose MCP tools."""

    identifier: ToolPack
    description: str

    def annotation(self) -> dict[str, object]:
        """Return only static, non-sensitive pack metadata."""

        return {
            "id": self.identifier.value,
            "description": self.description,
            "action_families": list(
                TOOL_PACK_ACTION_FAMILIES.get(self.identifier, ())
            ),
            "action_family_evidence": [
                {
                    "id": action_family,
                    "status": ACTION_FAMILY_EVIDENCE_STATUS[action_family].value,
                }
                for action_family in TOOL_PACK_ACTION_FAMILIES.get(
                    self.identifier, ()
                )
            ],
        }


@dataclass(frozen=True, slots=True)
class Capability:
    """The reviewed execution contract for one currently registered MCP tool."""

    tool_name: str
    description: str
    pack: ToolPack
    execution_mode: ExecutionMode
    risk_level: RiskLevel
    input_scope: InputScope
    supported_product_versions: tuple[str, ...]
    contacts_fortipam: bool
    local_state_write: bool = False
    idempotent: bool = True
    device_write: bool = False
    destructive: bool = False

    def __post_init__(self) -> None:
        if not self.tool_name:
            raise ValueError("Capability tool_name must not be empty.")
        if not self.description:
            raise ValueError("Capability description must not be empty.")
        if not self.supported_product_versions:
            raise ValueError("Capability must declare evidence-bound product versions.")
        if self.execution_mode is ExecutionMode.LIVE and not self.contacts_fortipam:
            raise ValueError("A live capability must contact FortiPAM.")
        if self.execution_mode is not ExecutionMode.LIVE and self.contacts_fortipam:
            raise ValueError("Offline and plan capabilities must not contact FortiPAM.")
        if self.device_write and (
            self.execution_mode is not ExecutionMode.LIVE
            or not self.contacts_fortipam
        ):
            raise ValueError("A device-write capability must be a live FortiPAM call.")
        if self.destructive and not self.device_write:
            raise ValueError("A destructive capability must declare a device write.")

    def annotation(self) -> dict[str, object]:
        """Return a sanitizer-friendly, deterministic tool annotation.

        The result intentionally excludes URL paths, parameter names, device
        configuration, identities, tokens, and response content. It is safe
        to expose from the reviewed ``get_capability_matrix`` MCP tool because
        that tool is no-input, offline, and covered by the V1.3 freeze.
        """

        return {
            "tool_name": self.tool_name,
            "description": self.description,
            "pack": self.pack.value,
            "execution_mode": self.execution_mode.value,
            "risk_level": self.risk_level.value,
            "input_scope": self.input_scope.value,
            "supported_product_versions": list(self.supported_product_versions),
            "contacts_fortipam": self.contacts_fortipam,
            "device_write": self.device_write,
            "local_state_write": self.local_state_write,
            "read_only": not (self.local_state_write or self.device_write),
            "destructive": self.destructive,
            "idempotent": self.idempotent,
        }


class CapabilityRegistry:
    """Immutable registry with a pure future pack/tool selection model."""

    def __init__(
        self,
        packs: Iterable[ToolPackDefinition],
        capabilities: Iterable[Capability],
    ) -> None:
        self._packs = tuple(packs)
        self._capabilities = tuple(capabilities)
        pack_ids = {definition.identifier for definition in self._packs}
        if len(pack_ids) != len(self._packs):
            raise ValueError("Tool pack identifiers must be unique.")
        names = {capability.tool_name for capability in self._capabilities}
        if len(names) != len(self._capabilities):
            raise ValueError("Capability tool names must be unique.")
        if {capability.pack for capability in self._capabilities} - pack_ids:
            raise ValueError("Every capability must reference a registered tool pack.")

    @property
    def capabilities(self) -> tuple[Capability, ...]:
        """Return the immutable capability sequence in deterministic order."""

        return self._capabilities

    @property
    def tool_names(self) -> tuple[str, ...]:
        """Return current tool names in their reviewed deterministic order."""

        return tuple(capability.tool_name for capability in self._capabilities)

    def select(
        self,
        *,
        enabled_packs: Iterable[ToolPack | str] | None = None,
        enabled_tools: Iterable[str] | None = None,
    ) -> tuple[Capability, ...]:
        """Purely select reviewed tools; this never alters an MCP server.

        Both selectors are allowlists.  Supplying both returns their
        intersection, preventing a named tool from bypassing a disabled pack.
        Omitting either selector means that dimension remains unrestricted.
        """

        packs = _normalize_packs(enabled_packs, self._packs)
        tools = _normalize_tools(enabled_tools, self._capabilities)
        return tuple(
            capability
            for capability in self._capabilities
            if (packs is None or capability.pack in packs)
            and (tools is None or capability.tool_name in tools)
        )

    def sanitized_matrix(
        self,
        *,
        enabled_packs: Iterable[ToolPack | str] | None = None,
        enabled_tools: Iterable[str] | None = None,
    ) -> dict[str, object]:
        """Produce static metadata for the capability-matrix MCP tool."""

        selected = self.select(
            enabled_packs=enabled_packs,
            enabled_tools=enabled_tools,
        )
        selected_pack_ids = {capability.pack for capability in selected}
        return {
            "schema_version": CAPABILITY_MATRIX_SCHEMA_VERSION,
            "current_surface_only": True,
            "action_evidence_is_authorization": False,
            "network_call_executed": False,
            "fortipam_contacted": False,
            "tool_count": len(selected),
            "action_inventory": EXACT_ACTION_INVENTORY_SUMMARY
            | {
                "states": dict(EXACT_ACTION_STATE_COUNTS),
                "implemented_readiness": IMPLEMENTED_ACTION_READINESS_SUMMARY
                | {
                    "ready_actions": list(READY_IMPLEMENTED_ACTIONS)
                },
            },
            "packs": [
                definition.annotation()
                | {
                    "tool_count": sum(
                        capability.pack is definition.identifier
                        for capability in selected
                    ),
                    "selected": definition.identifier in selected_pack_ids,
                }
                for definition in self._packs
            ],
            "tools": [capability.annotation() for capability in selected],
        }


_PACKS = (
    ToolPackDefinition(ToolPack.CORE, "Local server metadata and safe configuration presence."),
    ToolPackDefinition(ToolPack.KNOWLEDGE, "Offline operational-scenario evidence."),
    ToolPackDefinition(ToolPack.API_DISCOVERY, "Offline sanitized API catalog discovery."),
    ToolPackDefinition(ToolPack.PLATFORM_READ, "Fixed system and license posture reads."),
    ToolPackDefinition(ToolPack.APPROVAL_READ, "Fixed approval-policy posture reads and plans."),
    ToolPackDefinition(ToolPack.LOGGING_READ, "Fixed FortiAnalyzer delivery posture reads."),
    ToolPackDefinition(ToolPack.RESILIENCE_READ, "Fixed high-availability configuration posture reads."),
    ToolPackDefinition(ToolPack.RECORDING_READ, "Fixed log and recording storage posture reads."),
    ToolPackDefinition(ToolPack.PASSWORD_LIFECYCLE_READ, "Fixed password-changer configuration posture reads."),
    ToolPackDefinition(ToolPack.INTEGRATION_READ, "Fixed Fortinet integration connection-posture reads."),
    ToolPackDefinition(ToolPack.CLI_DIAGNOSTICS, "Fixed categorical CLI diagnostics over pinned SSH."),
    ToolPackDefinition(ToolPack.DIAGNOSTIC_STATE, "HTTP-OAuth-only immutable local diagnostic baselines and categorical correlation."),
    ToolPackDefinition(ToolPack.LAB_ADMIN, "In-memory V3.1 administrative workflow demonstration; never contacts FortiPAM."),
    ToolPackDefinition(ToolPack.V4_PLAN, "HTTP local-OAuth-only V4 planning state; never contacts or changes FortiPAM."),
    ToolPackDefinition(ToolPack.V4_APPROVAL_REQUEST_OBSERVATION, "Optional HTTP OAuth read of one owner-file-bound existing Secret request; no search, create, decision, or device write."),
    ToolPackDefinition(ToolPack.V4_FOLDER_ACTION, "Explicitly enabled HTTP OAuth child Folder execution from a protected authorization reference."),
    ToolPackDefinition(ToolPack.V4_FOLDER_ACL_ACTION, "Explicitly enabled HTTP OAuth Public child-Folder full-projection updates, including user ACL, rename, and explicit Secret Policy workflows with fixed REST readback."),
    ToolPackDefinition(ToolPack.V4_CLASSIFICATION_TAG_ACTION, "Explicitly enabled HTTP OAuth Classification Tag creation, fixed accepted-Tag recovery, and exact existing-Target assignment with bounded REST/SSH readback."),
    ToolPackDefinition(ToolPack.V4_ADDRESS_ACTION, "Explicitly enabled HTTP OAuth IPv4 ipmask Address creation plus fixed accepted-target REST recovery, with independent create/delete gates, complete-record digest, strict SSH reference count, and categorical REST/SSH readback."),
    ToolPackDefinition(ToolPack.V4_ADDRESS_GROUP_ACTION, "Explicitly enabled HTTP OAuth single-member Address Group creation plus fixed accepted-target REST recovery, with independent create/delete gates, complete-record digest, calibrated SSH reference count, and categorical REST/SSH readback."),
    ToolPackDefinition(ToolPack.V4_ZTNA_DIAGNOSTIC, "Explicitly enabled HTTP OAuth fixed ZTNA Access Proxy, dynamic-endpoint, WAD device-context, and Folder-control posture diagnostics without raw CLI disclosure."),
    ToolPackDefinition(ToolPack.V4_TARGET_ACTION, "Explicitly enabled HTTP OAuth Target create, fixed delete recovery, and fixed description-update or Web Proxy enable execution through REST API readback."),
    ToolPackDefinition(ToolPack.V4_CERTIFICATE_CSR_ACTION, "Explicitly enabled HTTP OAuth generation of one laboratory-prefixed file-based RSA-2048 CSR through exact REST readback; it accepts no password, organization, SAN, SCEP, upload, certificate, private key, CA, or CRL material and returns no generated material."),
    ToolPackDefinition(ToolPack.V4_SECRET_METADATA_ACTION, "Explicitly enabled HTTP OAuth creation of one laboratory-prefixed Secret metadata object through fixed REST API readback. It sends an empty field list and never accepts, reads, returns, logs, or persists Secret field values."),
    ToolPackDefinition(ToolPack.V4_INTERFACE_WEB_PROXY_ACTION, "Explicitly enabled HTTP OAuth transition of one private existing interface's Explicit Web Proxy between the exact disabled pre-action state and enabled state, with separately gated fixed rollback and categorical SSH CLI readback; it does not alter an interface address, proxy port, CA, VIP, route, Secret, Target, or traffic policy."),
    ToolPackDefinition(ToolPack.V4_LOCAL_USER_ACTION, "Explicitly enabled HTTP OAuth Local User create, disable, and bounded password-reset execution with fixed readback."),
    ToolPackDefinition(ToolPack.V4_ROLE_ACTION, "Explicitly enabled HTTP OAuth creation of one unassigned laboratory-prefixed guide-example Role, its fixed diagnostics-permission update, or REST assignment of one such Role to one disabled laboratory Local User."),
    ToolPackDefinition(ToolPack.V4_DLP_FILE_PATTERN_ACTION, "Explicitly enabled HTTP OAuth creation plus fixed accepted-target recovery for one single-PDF DLP File Pattern, with independent create/delete gates, full-record digest, complete REST/SSH Sensor reference scans, and dual absence readback."),
    ToolPackDefinition(ToolPack.V4_DLP_SENSOR_ACTION, "Explicitly enabled HTTP OAuth creation of one laboratory-prefixed DLP Sensor with either one fixed HTTP-GET PDF file-type block filter or one fixed HTTP-GET Regexp sentinel block filter, with categorical CLI readback and no arbitrary expression input."),
    ToolPackDefinition(ToolPack.V4_ANTIVIRUS_PROFILE_ACTION, "Explicitly enabled HTTP OAuth creation plus fixed accepted-target recovery for one AntiVirus Profile with independent create/delete final-dispatch gates, full-record REST digest, categorical SSH projection, complete Secret reference scan, and dual REST/SSH absence readback."),
    ToolPackDefinition(ToolPack.V4_RDP_EVENT_FILTER_ACTION, "Explicitly enabled HTTP OAuth creation of one laboratory-prefixed RDP event-filter Profile and fixed recovery of the accepted unreferenced b35 Profile, with independent dispatch gates and categorical readback."),
    ToolPackDefinition(ToolPack.V4_SECRET_POLICY_ACTION, "Explicitly enabled HTTP OAuth creation of one unattached laboratory-prefixed Secret Policy with fixed SSH Filter and RDP clipboard settings and categorical CLI readback."),
    ToolPackDefinition(ToolPack.V4_SSH_FILTER_ACTION, "Explicitly enabled HTTP OAuth creation of one unattached laboratory-prefixed SSH Filter Profile with a fixed deny-rm command rule and categorical CLI readback."),
    ToolPackDefinition(ToolPack.V4_LAUNCHER_ACTION, "Explicitly enabled HTTP OAuth creation of one unattached laboratory-prefixed native RDP Launcher or one exact baseline-bound timeout update with categorical CLI readback."),
    ToolPackDefinition(ToolPack.V4_TEMPLATE_ACTION, "Explicitly enabled HTTP OAuth creation of one unattached laboratory-prefixed Web VNC Template with two mandatory metadata fields, or one baseline-bound Web VNC Launcher-port update, with categorical CLI readback."),
    ToolPackDefinition(ToolPack.V4_TEMPLATE_ARCHIVE_ACTION, "Explicitly enabled HTTP OAuth irreversible archive of one unreferenced, disposable laboratory Template through a fixed REST API route and categorical SSH readback."),
    ToolPackDefinition(ToolPack.V4_DEPENDENCY_UPDATER_ACTION, "Explicitly enabled HTTP OAuth creation of one unattached laboratory-prefixed Windows-service Dependency Updater with restart disabled and categorical CLI readback."),
    ToolPackDefinition(ToolPack.V4_SECRET_GATEWAY_ACTION, "Explicitly enabled HTTP OAuth creation of one disabled laboratory-prefixed Forward Secret Gateway with a documentation IPv4 address and categorical CLI readback; it creates no Target, Secret, chain, reverse-service, certificate, or traffic-forwarding effect."),
    ToolPackDefinition(ToolPack.V4_CLIENT_INTEGRITY_ACTION, "Explicitly enabled HTTP OAuth creation of one unbound laboratory-prefixed Client Software certificate-integrity precondition with categorical CLI readback; it creates no Launcher, Template, Secret, Target, download, or session effect."),
    ToolPackDefinition(ToolPack.V4_CHARACTER_SET_ACTION, "Explicitly enabled HTTP OAuth creation of one unassociated laboratory-prefixed Character Set with the documented fixed symbol profile plus independently gated deletion of that exact accepted unreferenced Character Set, with categorical REST readback and no Password Policy, Template, Secret, Target, generated password, association, or session effect."),
    ToolPackDefinition(ToolPack.V4_WINDOWS_APP_FILTER_ACTION, "Explicitly enabled HTTP OAuth creation plus fixed accepted-target recovery for minimal Windows App Filter Profiles, with separate final-dispatch gates, categorical REST readback, and no caller-supplied filters, exceptions, Secret, Target, policy, or session effect."),
    ToolPackDefinition(ToolPack.V4_RECORDING_POLICY_ACTION, "Explicitly enabled HTTP OAuth transition of one existing laboratory-prefixed Secret Policy from a supported non-recording baseline to Session Recording enabled through a fixed REST body and categorical readback; it changes no other Policy field, Folder, Secret, association, Target, or session."),
    ToolPackDefinition(ToolPack.V4_PASSWORD_POLICY_ACTION, "Explicitly enabled HTTP OAuth creation of one unassociated laboratory-prefixed Password Policy with four default Character Sets plus independently gated deletion of that exact accepted policy, with categorical REST readback and no Template, Secret, authentication material, generated password, association, or session effect."),
    ToolPackDefinition(ToolPack.V4_REPORT_LAYOUT_ACTION, "Explicitly enabled HTTP OAuth creation of one alphanumeric Report Layout as an exact eligible default-layout clone plus independently gated deletion of that exact accepted clone, with categorical REST readback and no report generation or content return."),
    ToolPackDefinition(ToolPack.V4_ZTNA_ACCESS_PROXY_ACTION, "Explicitly enabled HTTP OAuth configuration of one private Access Proxy's client-certificate prerequisite for an explicit managed-only or mixed-access decision, with categorical CLI readback; it never changes EMS tags, proxy policy, Folder, Secret, session, or WAD debug."),
    ToolPackDefinition(ToolPack.V4_ZTNA_USER_CONTROL_ACTION, "Explicitly enabled HTTP OAuth transition of one private Access Proxy policy between the exact disabled pre-action state and enabled Access-level ZTNA using its existing EMS tag, with separately gated fixed rollback and categorical CLI readback; it never changes the Access Proxy, certificate handling, EMS/tag, Folder, Secret, session, or WAD debug."),
    ToolPackDefinition(ToolPack.V4_ZTNA_WAD_DEBUG_ACTION, "Explicitly enabled HTTP OAuth, confirmation-gated and time-boxed WAD debug diagnostic using only fixed secret, gateway, and service-connection categories, with automatic debug-disable cleanup and categorical evidence; it accepts no endpoint, tag, identity, Target, Secret, session, command, or persistent configuration input."),
    ToolPackDefinition(ToolPack.V4_SNMP_AGENT_ACTION, "Explicitly enabled HTTP OAuth transition of the existing system SNMP Agent between the exact disabled pre-action state and enabled state, with independently gated fixed recovery and categorical API/CLI readback; it never changes SNMP communities, SNMPv3 users, notification destinations, interface administrative access, or sends a query or trap."),
    ToolPackDefinition(ToolPack.V4_LOGGING_DISK_ACTION, "Explicitly enabled HTTP OAuth transition of FortiPAM disk logging from enabled to disabled only after proving memory logging remains enabled, with categorical CLI readback; it never changes remote syslog, event categories, disk encryption, or logging retention."),
    ToolPackDefinition(ToolPack.V4_FORTIANALYZER_ACTION, "Explicitly enabled HTTP OAuth transition of one existing configured FortiAnalyzer delivery setting from disabled to enabled with categorical CLI readback; it never changes the server, upload schedule, certificate, authorization, filter, or logging category."),
    ToolPackDefinition(ToolPack.V4_MAINTENANCE_MODE_ACTION, "Explicitly enabled HTTP OAuth transition of FortiPAM maintenance mode between exact disabled and enabled states, with independently gated fixed recovery and categorical API/CLI readback; it never reboots, uploads firmware or a license, restores configuration, or changes TPM, disk encryption, storage, or other settings."),
    ToolPackDefinition(ToolPack.V4_SECRET_AUDIT_ACTION, "Explicitly enabled HTTP OAuth generation of one fixed Secret Audit report through categorical SSH CLI readback; it accepts no report scope and returns no report content, filename, identity, Target, Folder, Secret, or permission data."),
    ToolPackDefinition(ToolPack.V4_SECRET_AUDIT_SUMMARY, "Separately enabled FortiPAM 7.0 read-only aggregate of the latest existing Secret Access Audit report; it returns counts only, with no report filename, row, identity, or resource value."),
    ToolPackDefinition(ToolPack.V4_TERRAFORM_PLAN_REPORT, "Separately enabled no-input structural report from one prebound signed synthetic Terraform plan; OAuth caller binding does not qualify production trust, full review or apply."),
    ToolPackDefinition(ToolPack.V4_ACTIVE_LAUNCH_ACTION, "Explicitly enabled HTTP OAuth observation of active FortiPAM launches through opaque short-lived references, plus confirmation-gated disconnect of exactly one referenced launch through categorical SSH CLI readback; it cannot list or clear raw WAD identifiers, clear every launch, return session metadata, or run caller-controlled CLI."),
    ToolPackDefinition(ToolPack.V4_AUTOMATION_TRIGGER_ACTION, "Explicitly enabled HTTP OAuth creation and independently gated fixed recovery of one unbound laboratory-prefixed event-log Automation Trigger with one fixed message regex and categorical readback; it creates no Automation Action or Stitch."),
    ToolPackDefinition(ToolPack.V4_AUTOMATION_ACTION_ACTION, "Explicitly enabled HTTP OAuth creation plus independently gated fixed recovery of one unbound laboratory-prefixed email Automation Action with a fixed non-routable recipient and categorical REST/CLI readback; it creates no Automation Stitch and never tests or executes automation."),
    ToolPackDefinition(ToolPack.V4_AUTOMATION_STITCH_ACTION, "Explicitly enabled HTTP OAuth creation of one disabled laboratory-prefixed Automation Stitch referencing pre-existing V4 Trigger and Action objects, plus independently gated fixed recovery of only the exact accepted unreferenced Stitch with dependency-preservation readback; it never enables, tests, or executes automation."),
    ToolPackDefinition(ToolPack.V4_USER_GROUP_ACTION, "Explicitly enabled HTTP OAuth creation of one unattached laboratory-prefixed remote LDAP User Group or one baseline-bound second remote-group match, with categorical CLI readback; it creates no Role assignment, Auto-Provision Rule, Folder/Secret ACL, user import, or session effect."),
    ToolPackDefinition(ToolPack.V4_APL_ACTION, "Explicitly enabled HTTP OAuth creation of one disabled laboratory-prefixed Auto-Provision Rule or disabling of one exact enabled V4 rule baseline, with categorical CLI readback; neither changes users, groups, Roles, identity servers, or login flow."),
    ToolPackDefinition(ToolPack.V4_SCHEDULE_ACTION, "Explicitly enabled HTTP OAuth creation of one unattached laboratory-prefixed recurring Schedule or assignment of one existing Schedule to one disabled laboratory Local User; each operation has an independent feature gate, exact authorization, confirmation, and categorical preservation readback."),
    ToolPackDefinition(ToolPack.V4_APPROVAL_PROFILE_ACTION, "Explicitly enabled HTTP OAuth creation of one unattached laboratory-prefixed single-tier Approval Profile with one fixed local approver and categorical CLI readback; it creates no Secret association or approval request."),
    ToolPackDefinition(ToolPack.V4_APPROVAL_PROFILE_UPDATE_ACTION, "Explicitly enabled HTTP OAuth fixed-description update of one laboratory Approval Profile plus independently gated recovery of only the exact accepted unreferenced Profile, with categorical REST/CLI readback and no Secret association, access request, or approval execution."),
    ToolPackDefinition(ToolPack.V4_APPROVAL_EMAIL_TEMPLATE_ACTION, "Explicitly enabled HTTP OAuth creation of one unassociated laboratory-prefixed Approval Email Template with fixed subject and content and categorical CLI readback; it enables no mail server and creates no Profile or Secret association."),
    ToolPackDefinition(ToolPack.V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION, "Explicitly enabled HTTP OAuth fixed subject/content update of one laboratory Approval Email Template plus independently gated recovery of only the exact accepted unreferenced Template, with categorical REST/CLI readback and no email server, Profile, Secret association, delivery, or approval execution."),
)


_CAPABILITIES = (
    Capability("get_server_info", "Return static server scope and metadata.", ToolPack.CORE, ExecutionMode.OFFLINE, RiskLevel.NONE, InputScope.NONE, ("1.9.0", "1.9.1"), False),
    Capability("health_check", "Return local process health without contacting FortiPAM.", ToolPack.CORE, ExecutionMode.OFFLINE, RiskLevel.NONE, InputScope.NONE, ("1.9.0", "1.9.1"), False),
    Capability("get_capability_matrix", "Describe reviewed Tool Packs and current tool contracts.", ToolPack.CORE, ExecutionMode.OFFLINE, RiskLevel.NONE, InputScope.NONE, ("1.9.0", "1.9.1"), False),
    Capability("fortipam_configuration_status", "Report local configuration presence without values.", ToolPack.CORE, ExecutionMode.OFFLINE, RiskLevel.LOW, InputScope.NONE, ("1.9.1",), False),
    Capability("get_api_catalog_status", "Return sanitized FortiPAM 1.9 catalog coverage.", ToolPack.API_DISCOVERY, ExecutionMode.OFFLINE, RiskLevel.LOW, InputScope.NONE, ("1.9.0",), False),
    Capability("search_api_catalog", "Search offline sanitized API metadata.", ToolPack.API_DISCOVERY, ExecutionMode.OFFLINE, RiskLevel.LOW, InputScope.BOUNDED_QUERY, ("1.9.0",), False),
    Capability("classify_api_operation", "Classify one exact catalog operation offline.", ToolPack.API_DISCOVERY, ExecutionMode.OFFLINE, RiskLevel.LOW, InputScope.EXACT_API_OPERATION, ("1.9.0",), False),
    Capability("get_scenario_catalog_status", "Return advisory scenario catalog coverage.", ToolPack.KNOWLEDGE, ExecutionMode.OFFLINE, RiskLevel.LOW, InputScope.NONE, ("1.9.0", "1.9.1"), False),
    Capability("search_operational_scenarios", "Search advisory operational scenarios offline.", ToolPack.KNOWLEDGE, ExecutionMode.OFFLINE, RiskLevel.LOW, InputScope.BOUNDED_QUERY, ("1.9.0", "1.9.1"), False),
    Capability("get_operational_scenario", "Return one advisory evidence plan without execution.", ToolPack.KNOWLEDGE, ExecutionMode.OFFLINE, RiskLevel.LOW, InputScope.EXACT_SCENARIO_ID, ("1.9.0", "1.9.1"), False),
    Capability("plan_curated_reads", "Validate all fixed live-read plans without a network call.", ToolPack.PLATFORM_READ, ExecutionMode.PLAN, RiskLevel.LOW, InputScope.NONE, ("1.9.1",), False),
    Capability("plan_approval_profile_read", "Validate the fixed approval-profile read plan.", ToolPack.APPROVAL_READ, ExecutionMode.PLAN, RiskLevel.LOW, InputScope.NONE, ("1.9.1",), False),
    Capability("get_overall_health_summary", "Aggregate the seven fixed reads into bounded health evidence.", ToolPack.PLATFORM_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_system_status_summary", "Return a structural summary from the fixed system-status read.", ToolPack.PLATFORM_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_system_global_summary", "Return a structural summary from the fixed system-global read.", ToolPack.PLATFORM_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_approval_profile_summary", "Return a structural summary from the fixed approval-profile read.", ToolPack.APPROVAL_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_fortianalyzer_delivery_posture_summary", "Return minimized FortiAnalyzer delivery posture.", ToolPack.LOGGING_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_license_support_posture_summary", "Return minimized license and support posture.", ToolPack.PLATFORM_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_ha_configuration_posture_summary", "Return minimized HA configuration posture.", ToolPack.RESILIENCE_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_recording_storage_health_summary", "Return minimized recording-storage health posture.", ToolPack.RECORDING_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_password_changer_configuration_posture_summary", "Return minimized password-changer configuration posture.", ToolPack.PASSWORD_LIFECYCLE_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_ems_connection_posture_summary", "Return minimized EMS connection and certificate posture.", ToolPack.INTEGRATION_READ, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_cli_ha_configuration_summary", "Return minimized HA configuration evidence from one fixed CLI workflow.", ToolPack.CLI_DIAGNOSTICS, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_cli_ha_status_summary", "Return minimized HA state and synchronization categories from one fixed CLI workflow.", ToolPack.CLI_DIAGNOSTICS, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_cli_ha_checksum_summary", "Return minimized HA checksum agreement categories from one fixed CLI workflow.", ToolPack.CLI_DIAGNOSTICS, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("create_ha_diagnostic_baseline", "Create one immutable local HA posture baseline from a fixed API projection.", ToolPack.DIAGNOSTIC_STATE, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.CONSTRAINED_BASELINE_ID, ("1.9.1",), True, True, False),
    Capability("compare_ha_diagnostic_baseline", "Compare current fixed HA posture with one owned immutable local baseline.", ToolPack.DIAGNOSTIC_STATE, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.CONSTRAINED_BASELINE_ID, ("1.9.1",), True, True, False),
    Capability("correlate_ha_api_cli_posture", "Correlate fixed HA API and CLI evidence into a closed categorical state.", ToolPack.DIAGNOSTIC_STATE, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True, True, False),
    Capability("get_v4_ha_reconciliation_assessment", "Reconcile four fixed HA API and CLI evidence contracts behind dedicated permission proof and return one categorical status.", ToolPack.DIAGNOSTIC_STATE, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True, True, False),
    Capability("preview_v31_lab_public_folder", "Preview one in-memory LAB Public Folder transition.", ToolPack.LAB_ADMIN, ExecutionMode.LAB_SIMULATED, RiskLevel.LOW, InputScope.LAB_ADMIN_PREVIEW, ("1.9.1",), False),
    Capability("preview_v31_lab_target", "Preview one in-memory LAB Target metadata transition.", ToolPack.LAB_ADMIN, ExecutionMode.LAB_SIMULATED, RiskLevel.LOW, InputScope.LAB_ADMIN_PREVIEW, ("1.9.1",), False),
    Capability("preview_v31_lab_secret_metadata", "Preview one in-memory LAB Secret metadata transition without material.", ToolPack.LAB_ADMIN, ExecutionMode.LAB_SIMULATED, RiskLevel.LOW, InputScope.LAB_ADMIN_PREVIEW, ("1.9.1",), False),
    Capability("preview_v31_lab_local_user", "Preview one in-memory LAB Local User metadata transition without a password.", ToolPack.LAB_ADMIN, ExecutionMode.LAB_SIMULATED, RiskLevel.LOW, InputScope.LAB_ADMIN_PREVIEW, ("1.9.1",), False),
    Capability("preview_v31_lab_folder_access_assignment", "Preview one in-memory LAB Folder access-assignment transition.", ToolPack.LAB_ADMIN, ExecutionMode.LAB_SIMULATED, RiskLevel.LOW, InputScope.LAB_ADMIN_PREVIEW, ("1.9.1",), False),
    Capability("execute_confirmed_v31_lab_operation", "Execute one exact confirmed in-memory LAB transition with verified local readback.", ToolPack.LAB_ADMIN, ExecutionMode.LAB_SIMULATED, RiskLevel.MODERATE, InputScope.LAB_CONFIRMATION, ("1.9.1",), False, True),
    Capability("preview_v4_administrative_intent", "Preview one server-issued V4 Scheme as Current, Proposed, and Expected planning state.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.LOW, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), False, True, False),
    Capability("confirm_v4_administrative_intent", "Consume one trusted human confirmation for an exact V4 Summary revision.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), False, True, False),
    Capability("prepare_v4_non_executable_plan", "Prepare one immutable V4 plan with no executor or product adapter.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), False, True, False),
    Capability("get_v4_plan_status", "Return V4 planning exposure and blocker metadata.", ToolPack.V4_PLAN, ExecutionMode.OFFLINE, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_firmware_upgrade_plan_requirements", "Return fixed source-pinned FortiPAM 1.9.1 upgrade planning requirements without accepting artifacts or enabling execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("build_v4_firmware_upgrade_plan", "Build a value-free FortiPAM 1.9.1 firmware-upgrade readiness plan from seven categorical attestations without accepting protected material, reading a device, or authorizing upgrade execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.V4_FIRMWARE_UPGRADE_PLAN, ("1.9.1",), False),
    Capability("get_v4_backup_create_plan_requirements", "Return fixed source-pinned FortiPAM 1.9.1 backup-creation planning requirements without reading a device, accepting protected material, or enabling execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("build_v4_backup_create_plan", "Build a value-free FortiPAM 1.9.1 backup-creation readiness plan from eight categorical attestations without accepting protected material, reading a device, or authorizing backup execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.V4_BACKUP_CREATE_PLAN, ("1.9.1",), False),
    Capability("get_v4_backup_restore_plan_requirements", "Return fixed source-pinned FortiPAM 1.9.1 backup/restore planning requirements without accepting artifacts, passwords, or execution authority.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("build_v4_backup_restore_plan", "Build a value-free FortiPAM 1.9.1 backup-restore readiness plan from eight categorical attestations without accepting protected material, reading a device, or authorizing restore execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.V4_BACKUP_RESTORE_PLAN, ("1.9.1",), False),
    Capability("get_v4_license_install_plan_requirements", "Return fixed source-pinned FortiPAM 1.9.1 license-install planning requirements without accepting a license file, registration code, account detail, or execution authority.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("build_v4_license_install_plan", "Build a value-free FortiPAM 1.9.1 license-install readiness plan from eight categorical attestations without accepting protected material or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.V4_LICENSE_INSTALL_PLAN, ("1.9.1",), False),
    Capability("get_v4_system_email_plan_requirements", "Return fixed source-pinned FortiPAM 1.9.1 system-email planning requirements without accepting endpoints, accounts, passwords, sender identities, certificates, or delivery authority.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("build_v4_system_email_plan", "Build a value-free FortiPAM 1.9.1 system-email readiness plan from nine categorical attestations without accepting connection, identity, credential, or delivery values.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.V4_SYSTEM_EMAIL_PLAN, ("1.9.1",), False),
    Capability("get_v4_email_alert_plan_requirements", "Return fixed source-pinned FortiPAM 1.9.1 email-alert planning requirements without accepting sender, recipient, category, threshold, or delivery values.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("build_v4_email_alert_plan", "Build a value-free FortiPAM 1.9.1 email-alert readiness plan from eight categorical attestations without accepting sender, recipient, event, threshold, content, or delivery values.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.V4_EMAIL_ALERT_PLAN, ("1.9.1",), False),
    Capability("get_v4_glass_break_plan_requirements", "Return fixed source-pinned FortiPAM 1.9.1 glass-breaking planning requirements without accepting identities, roles, reasons, incidents, Secret references, or elevation authority.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_route_plan_requirements", "Return fixed FortiPAM route-planning requirements from a 1.9.0 source while explicitly requiring 1.9.1 validation and accepting no network values or execution authority.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("build_v4_route_plan", "Build a value-free FortiPAM route readiness plan from eight categorical attestations without accepting network values, reading a device, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.V4_ROUTE_PLAN, ("1.9.1",), False),
    Capability("get_v4_dns_plan_requirements", "Return fixed FortiPAM DNS-planning requirements from a 1.9.0 source while explicitly requiring 1.9.1 validation and accepting no resolver, certificate, or execution values.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("build_v4_dns_plan", "Build a value-free FortiPAM DNS readiness plan from eight categorical attestations without accepting resolver, domain, certificate, or execution values.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.V4_DNS_PLAN, ("1.9.1",), False),
    Capability("get_v4_ha_configure_plan_requirements", "Return fixed source-pinned FortiPAM 1.9.1 Active-Passive HA configuration requirements without accepting deployment or execution values.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("build_v4_ha_configure_plan", "Build a value-free FortiPAM 1.9.1 HA configuration readiness plan from nine categorical attestations without accepting topology, credentials, or execution values.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.V4_HA_CONFIGURE_PLAN, ("1.9.1",), False),
    Capability("get_v4_ha_maintenance_plan_requirements", "Return fixed source-pinned FortiPAM 1.9.1 HA maintenance requirements without accepting member, duration, reason, work, or execution values.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("build_v4_ha_maintenance_plan", "Build a value-free FortiPAM 1.9.1 HA maintenance readiness plan from seven categorical attestations without accepting member, duration, reason, work, or execution values.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.V4_HA_MAINTENANCE_PLAN, ("1.9.1",), False),
    Capability("get_v4_ha_reconcile_plan_requirements", "Return fixed source-pinned FortiPAM 1.9.1 HA reconciliation requirements without reading or returning cluster state, repairing synchronization, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("build_v4_ha_reconcile_plan", "Build a value-free FortiPAM 1.9.1 HA reconciliation readiness plan from seven categorical attestations without reading cluster state, repairing synchronization, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.V4_HA_RECONCILE_PLAN, ("1.9.1",), False),
    Capability("get_v4_certificate_import_plan_requirements", "Return fixed source-pinned FortiPAM 1.9.1 certificate-import requirements without loading protected material, contacting a device, changing trust, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_crl_import_plan_requirements", "Return fixed FortiPAM CRL-import requirements from a 1.0.3 source while requiring 1.9.1 validation and without loading protected material, contacting services, changing trust, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_ldap_server_plan_requirements", "Return fixed FortiPAM LDAP-server requirements from a 1.8.1 source while requiring 1.9.1 validation and without contacting systems, loading protected material, changing authentication, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_radius_server_plan_requirements", "Return fixed FortiPAM RADIUS-server requirements from a 1.8.0 source while requiring 1.9.1 validation and without contacting systems, loading protected material, changing authentication, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_saml_server_plan_requirements", "Return fixed FortiPAM SAML-server requirements from a 1.8.1 source while requiring 1.9.1 validation and without contacting systems, loading protected material, changing authentication, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_temporary_access_plan_requirements", "Return fixed source-bounded FortiPAM 7.0 sponsored and temporary-access requirements without accepting identities or access values, contacting systems, changing access, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("7.0.0",), False),
    Capability("get_v4_jwt_key_create_plan_requirements", "Return fixed FortiPAM JWT-key creation requirements from a 1.8.1 source while requiring 1.9.1 validation and without loading key material, contacting systems, changing authentication, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_jwt_key_rotate_plan_requirements", "Return fixed FortiPAM JWT-key rotation requirements from a 1.8.1 source while requiring 1.9.1 validation and without loading key material, contacting systems, changing authentication, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_scim_client_create_plan_requirements", "Return fixed FortiPAM SCIM-client creation requirements from a 1.9.0 source while requiring 1.9.1 validation and without contacting systems, loading protected material, changing provisioning, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_scim_client_rotate_plan_requirements", "Return fixed FortiPAM SCIM-client rotation requirements from a 1.9.0 source while requiring 1.9.1 validation and without contacting systems, loading protected material, changing provisioning, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_scim_client_disable_plan_requirements", "Return fixed FortiPAM SCIM-client disable requirements from a 1.9.0 source while requiring 1.9.1 validation and without contacting systems, changing provisioning or sessions, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_fortitoken_assign_plan_requirements", "Return fixed FortiPAM FortiToken assignment requirements from a 1.9.0 source while requiring 1.9.1 validation and without loading token material, contacting services, changing MFA, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_fortitoken_revoke_plan_requirements", "Return fixed FortiPAM FortiToken revocation requirements from a 1.9.0 source while requiring 1.9.1 validation and without loading token material, contacting services, changing MFA or sessions, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_apl_update_plan_requirements", "Return fixed FortiPAM Auto Provision Rule update requirements from a 1.9.0 source while requiring 1.9.1 validation and without contacting systems, changing provisioning or sessions, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_discovery_entry_create_plan_requirements", "Return fixed FortiPAM Discovery-entry creation requirements and non-callable 1.9.0 catalog candidates while requiring 1.9.1 schema validation and without scanning networks, loading protected material, creating objects, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_discovery_run_plan_requirements", "Return fixed FortiPAM Discovery-run requirements from a 1.9.0 source while requiring 1.9.1 validation and without scanning networks, returning results, creating objects, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_discovery_review_plan_requirements", "Return fixed FortiPAM Discovery-review requirements from a 1.9.0 source while requiring 1.9.1 validation and without reading results, returning sensitive data, importing objects, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_job_create_plan_requirements", "Return fixed FortiPAM Job creation requirements from a 1.9.0 source while requiring 1.9.1 validation and without loading scripts or Secrets, creating jobs, executing commands, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_job_execute_plan_requirements", "Return fixed FortiPAM Job execution requirements from a 1.9.0 source while requiring 1.9.1 validation and without loading scripts or Secrets, contacting targets, executing commands, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_password_changer_create_plan_requirements", "Return fixed FortiPAM Password Changer creation requirements from a 1.9.0 source while requiring 1.9.1 validation and without loading protected material, contacting targets, changing credentials, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_password_verification_plan_requirements", "Return fixed FortiPAM password-verification requirements from a 1.9.0 source while requiring 1.9.1 validation and without loading protected material, contacting targets, verifying credentials, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_checkout_policy_plan_requirements", "Return fixed FortiPAM checkout-policy requirements from a 1.9.0 source while requiring 1.9.1 validation and without loading scripts or Secrets, contacting targets, executing commands, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_jit_policy_plan_requirements", "Return fixed FortiPAM JIT-policy requirements from a 1.9.0 source while requiring 1.9.1 validation and without loading scripts or identities, contacting targets, changing privileges, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_service_account_update_plan_requirements", "Return fixed FortiPAM service-account update requirements from a 1.9.0 source while requiring 1.9.1 validation and without loading credentials, contacting targets, changing services, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_instruction_profile_create_plan_requirements", "Return fixed FortiPAM Instruction Profile creation requirements from a 1.9.1 source without loading content or resources, contacting FortiPAM, uploading material, attaching Secrets, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_event_subscription_plan_requirements", "Return fixed FortiPAM Event Subscription requirements from a 1.9.1 source without accepting identity, Secret, event, or email values, contacting FortiPAM, sending notifications, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_secret_bulk_import_plan_requirements", "Return fixed FortiPAM Secret bulk-import planning requirements from a 1.9.1 source without loading files or credentials, contacting systems, creating Secrets, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("build_v4_secret_bulk_import_plan", "Build a value-free FortiPAM 1.9.1 Secret bulk-import readiness plan from eight categorical attestations without loading files or credentials, generating an import preview, contacting FortiPAM, or authorizing apply execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.V4_SECRET_BULK_IMPORT_PLAN, ("1.9.1",), False),
    Capability("get_v4_secret_bulk_import_apply_requirements", "Return fixed FortiPAM Secret bulk-import apply requirements from a 1.9.1 source without loading files or credentials, contacting systems, creating Secrets, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_launcher_clone_plan_requirements", "Return fixed FortiPAM Launcher clone requirements from a 1.9.1 source without accepting object selectors or protected values, contacting FortiPAM, cloning a Launcher, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_policy_assign_plan_requirements", "Return fixed FortiPAM Secret Policy assignment requirements from a 1.9.1 source without accepting Secret or Policy selectors, contacting FortiPAM, changing access or sessions, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_approval_delivery_plan_requirements", "Return fixed FortiPAM approval-delivery requirements from a 1.9.1 source without accepting mail, tenant, credential, or recipient values, contacting services, sending notifications, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_fabric_connector_plan_requirements", "Return fixed FortiPAM Fabric Connector requirements from a 1.9.1 source without accepting topology or credentials, contacting systems, changing trust or routing, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_secret_gateway_chain_plan_requirements", "Return fixed FortiPAM Secret Gateway chain requirements from a 1.9.1 source without accepting topology or credentials, contacting systems, changing forwarding, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_reverse_service_plan_requirements", "Return fixed FortiPAM Reverse Service requirements from a 1.9.1 source without accepting listener or backend values, contacting systems, changing routing or trust, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_ztna_tag_create_plan_requirements", "Return fixed FortiPAM ZTNA Tag creation requirements from a 1.9.1 source without accepting connector, tag, endpoint, Policy, or Secret values, contacting EMS, changing access, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_ztna_tag_group_create_plan_requirements", "Return fixed FortiPAM ZTNA Tag Group creation requirements from a 1.9.1 source without accepting connector, group, member, endpoint, Policy, or Secret values, contacting EMS, changing access, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_target_disable_plan_requirements", "Return fixed evidence that an independent Target lifecycle-disable action is unavailable in FortiPAM 1.9.1 while rejecting Web Proxy controls as a substitute, without accepting Target values, contacting a device, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_secret_metadata_update_plan_requirements", "Return fixed FortiPAM Secret metadata-update requirements from provider guidance while requiring an exact 1.9.1 metadata-only contract and without loading material, contacting a device, changing a Secret, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_approval_profile_disable_plan_requirements", "Return fixed evidence that an independent Approval Profile lifecycle-disable action is unavailable in FortiPAM 1.9.1 while rejecting tier or email controls as substitutes, without accepting Profile values, contacting a device, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_secret_disable_contract_gap", "Return fixed evidence that an independent Secret lifecycle-disable action is unavailable in FortiPAM 1.9.1 while rejecting nested feature status as a substitute, without accepting Secret values, contacting a device, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("get_v4_launcher_disable_contract_gap", "Return fixed evidence that an independent Launcher lifecycle-disable action is unavailable in FortiPAM 1.9.1 while rejecting matcher, command, and timeout fields as substitutes, without accepting Launcher values, contacting a device, or authorizing execution.", ToolPack.V4_PLAN, ExecutionMode.PLAN, RiskLevel.NONE, InputScope.NONE, ("1.9.1",), False),
    Capability("observe_v4_bound_secret_request", "Read one owner-file-bound existing Secret request by opaque reference and return only categorical lifecycle state without search, creation, approval, denial, or modification.", ToolPack.V4_APPROVAL_REQUEST_OBSERVATION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_REQUEST_REFERENCE, ("1.9.1",), True),
    Capability("preview_v4_child_folder_create", "Read actual Folder state and render one bounded Current/Proposed/Expected child Folder preview.", ToolPack.V4_FOLDER_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_FOLDER_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_child_folder_create", "Re-read one exact child Folder preview and record a single execution confirmation.", ToolPack.V4_FOLDER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_child_folder", "Execute one exact protected and previously confirmed child Folder authorization with verified readback.", ToolPack.V4_FOLDER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_folder_user_acl_grant", "Read actual Public child Folder state and render one bounded Current/Proposed/Expected user ACL grant preview.", ToolPack.V4_FOLDER_ACL_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_FOLDER_ACL_GRANT_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_folder_user_acl_grant", "Re-read one exact Public child Folder ACL preview and record a single execution confirmation.", ToolPack.V4_FOLDER_ACL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_folder_user_acl_grant", "Execute one exact protected and previously confirmed Public child Folder user ACL grant with API readback.", ToolPack.V4_FOLDER_ACL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_folder_user_acl_revoke", "Read actual Public child Folder state and render one bounded Current/Proposed/Expected direct user ACL revoke preview.", ToolPack.V4_FOLDER_ACL_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_FOLDER_ACL_REVOKE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_folder_user_acl_revoke", "Re-read one exact Public child Folder direct user ACL revoke preview and record a single execution confirmation.", ToolPack.V4_FOLDER_ACL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_folder_user_acl_revoke", "Execute one exact protected and previously confirmed Public child Folder direct user ACL revoke with API readback.", ToolPack.V4_FOLDER_ACL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_public_child_folder_rename", "Read actual Public child Folder state and render one bounded Current/Proposed/Expected rename preview.", ToolPack.V4_FOLDER_ACL_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_FOLDER_RENAME_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_public_child_folder_rename", "Re-read one exact Public child Folder rename preview and record a single execution confirmation.", ToolPack.V4_FOLDER_ACL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_public_child_folder_rename", "Execute one exact protected and previously confirmed Public child Folder rename with API readback.", ToolPack.V4_FOLDER_ACL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_empty_public_child_folder_archive", "Read one isolated empty V4 Public child Folder and render one bounded irreversible Current/Proposed/Expected archive preview.", ToolPack.V4_FOLDER_ACL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_FOLDER_ARCHIVE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_empty_public_child_folder_archive", "Re-read one exact empty V4 Public child Folder archive preview and record a single execution confirmation.", ToolPack.V4_FOLDER_ACL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_empty_public_child_folder_archive", "Permanently delete one exact protected and previously confirmed empty isolated V4 Public child Folder with API collection readback.", ToolPack.V4_FOLDER_ACL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_public_child_folder_policy_assign", "Read actual Public child Folder state and render one bounded Current/Proposed/Expected explicit Secret Policy assignment preview.", ToolPack.V4_FOLDER_ACL_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_FOLDER_POLICY_ASSIGN_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_public_child_folder_policy_assign", "Re-read one exact Public child Folder policy-assignment preview and record a single execution confirmation.", ToolPack.V4_FOLDER_ACL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_public_child_folder_policy_assign", "Execute one exact protected and previously confirmed Public child Folder explicit Secret Policy assignment with API readback.", ToolPack.V4_FOLDER_ACL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_public_child_folder_policy_detach", "Read one exact Public child Folder with explicit policy and render one bounded Current/Proposed/Expected parent-policy-inheritance preview.", ToolPack.V4_FOLDER_ACL_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_FOLDER_POLICY_DETACH_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_public_child_folder_policy_detach", "Re-read one exact Public child Folder explicit-policy baseline and record a single execution confirmation.", ToolPack.V4_FOLDER_ACL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_public_child_folder_policy_detach", "Execute one exact protected and previously confirmed Public child Folder parent-policy-inheritance transition with API readback; it preserves ACL and ZTNA projections.", ToolPack.V4_FOLDER_ACL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_classification_tag_create", "Read actual Classification Tag state and render one bounded Current/Proposed/Expected create preview.", ToolPack.V4_CLASSIFICATION_TAG_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_CLASSIFICATION_TAG_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_classification_tag_create", "Re-read one exact Classification Tag create preview and record a single execution confirmation.", ToolPack.V4_CLASSIFICATION_TAG_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_classification_tag_create", "Execute one exact protected and previously confirmed Classification Tag create with API readback.", ToolPack.V4_CLASSIFICATION_TAG_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_classification_tag_delete", "Read only the exact accepted Classification Tag complete record, protected Target default state, and strict CMDB zero-reference state, then render one destructive recovery preview without selectors.", ToolPack.V4_CLASSIFICATION_TAG_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_classification_tag_delete", "Re-read the fixed Tag digest, protected Target default state, and zero-reference state, then record one short-lived requester-bound destructive confirmation.", ToolPack.V4_CLASSIFICATION_TAG_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_classification_tag_delete", "Permanently delete only the exact previously confirmed unreferenced accepted Classification Tag through one fixed bodyless REST DELETE with categorical absence and protected-Target preservation readback.", ToolPack.V4_CLASSIFICATION_TAG_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True, destructive=True),
    Capability("preview_v4_classification_tag_assign", "Read one exact laboratory Target and existing Classification Tag and render a bounded Current/Proposed/Expected class-only assignment preview.", ToolPack.V4_CLASSIFICATION_TAG_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_CLASSIFICATION_TAG_ASSIGN_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_classification_tag_assign", "Re-read one exact default-Classification Target and Tag pair and record a single execution confirmation.", ToolPack.V4_CLASSIFICATION_TAG_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_classification_tag_assign", "Execute one exact protected and previously confirmed Target class-only Classification Tag assignment with Target and Tag preservation readback.", ToolPack.V4_CLASSIFICATION_TAG_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_classification_tag_assign_rollback", "Read the fixed accepted Target and Classification Tag assignment and render a value-minimized class=Other rollback preview without accepting or returning selectors.", ToolPack.V4_CLASSIFICATION_TAG_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_classification_tag_assign_rollback", "Re-read the fixed Target/Tag assignment digest and record one requester-bound rollback confirmation.", ToolPack.V4_CLASSIFICATION_TAG_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_classification_tag_assign_rollback", "Restore only the exact accepted Target Classification to Other through one fixed class-only PUT with Target and Tag preservation readback.", ToolPack.V4_CLASSIFICATION_TAG_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_ipv4_address_create", "Read actual IPv4 Address state and render one bounded Current/Proposed/Expected ipmask create preview.", ToolPack.V4_ADDRESS_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_ADDRESS_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_ipv4_address_create", "Re-read one exact IPv4 Address create preview and record a single execution confirmation.", ToolPack.V4_ADDRESS_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_ipv4_address_create", "Execute one exact protected and previously confirmed IPv4 ipmask Address create with API readback.", ToolPack.V4_ADDRESS_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_ipv4_address_delete", "Read only the exact accepted b63 IPv4 ipmask Address complete record and strict CMDB zero-reference state, then render one destructive recovery preview without accepting or returning a selector.", ToolPack.V4_ADDRESS_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_ipv4_address_delete", "Re-read the exact accepted Address digest, IPv4 ipmask projection, and zero-reference state, then record one short-lived requester-bound destructive confirmation.", ToolPack.V4_ADDRESS_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_ipv4_address_delete", "Delete only the exact previously confirmed accepted unreferenced b63 Address through one fixed bodyless REST DELETE and REST/SSH categorical absence readback, with separate create compensation required.", ToolPack.V4_ADDRESS_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True, destructive=True),
    Capability("preview_v4_address_group_create", "Read actual Address Group and IPv4 ipmask member eligibility state and render one bounded Current/Proposed/Expected single-member create preview.", ToolPack.V4_ADDRESS_GROUP_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_ADDRESS_GROUP_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_address_group_create", "Re-read one exact Address Group create preview and record a single execution confirmation.", ToolPack.V4_ADDRESS_GROUP_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_address_group_create", "Execute one exact protected and previously confirmed single-member Address Group create with fixed SSH CLI readback.", ToolPack.V4_ADDRESS_GROUP_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_address_group_delete", "Read only the exact accepted b65 Address Group complete record, fixed one-member REST/SSH projection, preserved b63 IPv4 Address, and calibrated CMDB zero-reference state, then render one destructive Current/Proposed/Expected recovery preview without accepting or returning a selector.", ToolPack.V4_ADDRESS_GROUP_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_address_group_delete", "Re-read the exact accepted Address Group digest, fixed projection, preserved member, and calibrated zero-reference state, then record one short-lived requester-bound destructive confirmation.", ToolPack.V4_ADDRESS_GROUP_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_address_group_delete", "Delete only the exact previously confirmed accepted unreferenced b65 Address Group through one fixed bodyless REST DELETE and REST/SSH categorical absence readback while preserving b63 Address, with separate create compensation required.", ToolPack.V4_ADDRESS_GROUP_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True, destructive=True),
    Capability("get_v4_ztna_device_context_diagnostic", "Run fixed server-configured ZTNA Access Proxy, dynamic-endpoint, and WAD device-context diagnostics without raw CLI disclosure.", ToolPack.V4_ZTNA_DIAGNOSTIC, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("get_v4_ztna_folder_control_posture", "Run a fixed server-configured Folder ZTNA inheritance and Tag-observability diagnostic without returning Folder or Tag values.", ToolPack.V4_ZTNA_DIAGNOSTIC, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("preview_v4_ssh_target_create", "Read actual Target state and render one bounded Current/Proposed/Expected IPv4 SSH Target preview; the retained Tool name uses a REST API backend.", ToolPack.V4_TARGET_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_TARGET_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_ssh_target_create", "Re-read one exact API Target preview and record a single execution confirmation.", ToolPack.V4_TARGET_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_ssh_target", "Execute one exact protected and previously confirmed IPv4 SSH Target authorization through REST API readback.", ToolPack.V4_TARGET_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_ssh_target_delete", "Read only the exact accepted Target complete record, default Classification, accepted-Tag absence, SSH presence, and strict CMDB zero-reference state, then render one destructive recovery preview without selectors.", ToolPack.V4_TARGET_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1", "7.0.0"), True),
    Capability("confirm_v4_ssh_target_delete", "Re-read the protected Target digest, default Classification, accepted-Tag absence, SSH presence, and zero references, then record one short-lived requester-bound destructive confirmation.", ToolPack.V4_TARGET_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1", "7.0.0"), True, True, False),
    Capability("execute_confirmed_v4_ssh_target_delete", "Permanently delete only the exact previously confirmed, unchanged, unreferenced accepted Target through one fixed bodyless REST DELETE with REST/SSH absence and accepted-Tag-absence readback.", ToolPack.V4_TARGET_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1", "7.0.0"), True, True, True, device_write=True, destructive=True),
    Capability("preview_v4_target_update_description", "Read actual Target state and render one bounded Current/Proposed/Expected Target description-update or fixed Web Proxy enable preview through REST API.", ToolPack.V4_TARGET_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_TARGET_UPDATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_target_update_description", "Re-read one exact Target description-update or fixed Web Proxy enable preview and record a single execution confirmation.", ToolPack.V4_TARGET_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_target_update_description", "Execute one exact protected and previously confirmed Target description update or fixed Web Proxy enable transition through REST API readback.", ToolPack.V4_TARGET_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_certificate_csr_generate", "Read exact local-certificate and name-availability state and render one bounded Current/Proposed/Expected file-based RSA-2048 CSR-generation preview without accepting or returning generated material.", ToolPack.V4_CERTIFICATE_CSR_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_CERTIFICATE_CSR_GENERATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_certificate_csr_generate", "Re-read one exact CSR-generation preview and record a single execution confirmation.", ToolPack.V4_CERTIFICATE_CSR_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_certificate_csr_generate", "Execute one exact protected and previously confirmed file-based RSA-2048 CSR generation through REST API and return only categorical object, CSR, and private-key presence readback.", ToolPack.V4_CERTIFICATE_CSR_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_secret_metadata_create", "Read actual Folder and Secret presence state and render one bounded Current/Proposed/Expected Secret metadata-only create preview. No Secret field value is accepted or returned.", ToolPack.V4_SECRET_METADATA_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_SECRET_METADATA_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_secret_metadata_create", "Re-read one exact Secret metadata create preview and record a single execution confirmation.", ToolPack.V4_SECRET_METADATA_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_secret_metadata_create", "Execute one exact protected and previously confirmed Secret metadata-only create through REST API readback. No Secret field value is accepted, returned, logged, or persisted by MCP.", ToolPack.V4_SECRET_METADATA_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_interface_explicit_web_proxy_enable", "Read actual protected interface state and render one bounded Current/Proposed/Expected Explicit Web Proxy enable preview.", ToolPack.V4_INTERFACE_WEB_PROXY_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_INTERFACE_WEB_PROXY_ENABLE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_interface_explicit_web_proxy_enable", "Re-read one exact Explicit Web Proxy enable preview and record a single execution confirmation.", ToolPack.V4_INTERFACE_WEB_PROXY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_interface_explicit_web_proxy_enable", "Execute one exact protected and previously confirmed Explicit Web Proxy enable transition with fixed SSH CLI readback.", ToolPack.V4_INTERFACE_WEB_PROXY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_interface_explicit_web_proxy_rollback", "Read the protected interface's exact enabled Explicit Web Proxy state and render one bounded rollback preview to the original disabled state.", ToolPack.V4_INTERFACE_WEB_PROXY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_interface_explicit_web_proxy_rollback", "Re-read one exact Explicit Web Proxy rollback preview and record a single rollback execution confirmation.", ToolPack.V4_INTERFACE_WEB_PROXY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_interface_explicit_web_proxy_rollback", "Restore one exact protected and previously confirmed interface to Explicit Web Proxy disable with categorical SSH CLI readback only.", ToolPack.V4_INTERFACE_WEB_PROXY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_local_user_disable", "Read actual Local User state and render one bounded Current/Proposed/Expected disable preview.", ToolPack.V4_LOCAL_USER_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_LOCAL_USER_DISABLE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_local_user_disable", "Re-read one exact Local User disable preview and record a single execution confirmation.", ToolPack.V4_LOCAL_USER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_local_user_disable", "Execute one exact protected and previously confirmed Local User disable authorization with REST readback.", ToolPack.V4_LOCAL_USER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_local_user_create", "Read actual Local User state and render one bounded Current/Proposed/Expected disabled Guest Local User preview.", ToolPack.V4_LOCAL_USER_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_LOCAL_USER_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_local_user_create", "Re-read one exact Local User create preview and record a single execution confirmation.", ToolPack.V4_LOCAL_USER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_local_user_create", "Execute one exact protected and previously confirmed disabled Guest Local User authorization with CLI readback.", ToolPack.V4_LOCAL_USER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_local_user_reset", "Read the exact disabled Guest laboratory Local User baseline and render one bounded Current/Proposed/Expected generated-password reset preview.", ToolPack.V4_LOCAL_USER_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_LOCAL_USER_RESET_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_local_user_reset", "Re-read one exact Local User reset preview and record a single execution confirmation.", ToolPack.V4_LOCAL_USER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_local_user_reset", "Execute one exact protected and previously confirmed disabled Guest Local User password reset with CLI readback and no password return.", ToolPack.V4_LOCAL_USER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_role_create", "Read actual custom Role state and render one bounded Current/Proposed/Expected unassigned guide-example Role preview.", ToolPack.V4_ROLE_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_ROLE_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_role_create", "Re-read one exact Role create preview and record a single execution confirmation.", ToolPack.V4_ROLE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_role_create", "Execute one exact protected and previously confirmed unassigned guide-example Role authorization with CLI readback.", ToolPack.V4_ROLE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_role_diagnostics_enable", "Read one exact unassigned guide-example Role and render one bounded Current/Proposed/Expected diagnostics-enable preview.", ToolPack.V4_ROLE_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_ROLE_UPDATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_role_diagnostics_enable", "Re-read one exact Role diagnostics-enable preview and record a single execution confirmation.", ToolPack.V4_ROLE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_role_diagnostics_enable", "Execute one exact protected and previously confirmed Role diagnostics-enable update with CLI readback.", ToolPack.V4_ROLE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_role_assign", "Read one disabled laboratory Local User and one laboratory Role, then render one bounded Current/Proposed/Expected REST assignment preview.", ToolPack.V4_ROLE_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_ROLE_ASSIGN_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_role_assign", "Re-read one exact Role assignment preview and record a single execution confirmation.", ToolPack.V4_ROLE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_role_assign", "Execute one exact protected and previously confirmed Role assignment with REST API readback.", ToolPack.V4_ROLE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_dlp_file_pattern_create", "Read actual DLP file-pattern state and render one bounded Current/Proposed/Expected laboratory single-PDF pattern preview.", ToolPack.V4_DLP_FILE_PATTERN_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_DLP_FILE_PATTERN_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_dlp_file_pattern_create", "Re-read one exact DLP file-pattern create preview and record a single execution confirmation.", ToolPack.V4_DLP_FILE_PATTERN_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_dlp_file_pattern_create", "Execute one exact protected and previously confirmed laboratory single-PDF DLP file-pattern authorization with CLI readback.", ToolPack.V4_DLP_FILE_PATTERN_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_dlp_file_pattern_delete", "Read only the exact accepted b32 DLP File Pattern full-record digest, fixed REST/SSH projection, complete REST/SSH DLP Sensor references, and preserved fixed Regexp Sensor, then render one destructive Current/Proposed/Expected recovery preview without accepting or returning an ID, name, or content.", ToolPack.V4_DLP_FILE_PATTERN_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_dlp_file_pattern_delete", "Re-read the exact accepted DLP File Pattern digest, fixed projection, zero-reference state, and Regexp Sensor preservation, then record one short-lived requester-bound destructive confirmation.", ToolPack.V4_DLP_FILE_PATTERN_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_dlp_file_pattern_delete", "Delete only the exact previously confirmed accepted unreferenced b32 DLP File Pattern through one fixed bodyless REST DELETE and dual REST/SSH categorical absence readback while preserving the fixed Regexp Sensor, with separate create compensation required.", ToolPack.V4_DLP_FILE_PATTERN_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True, destructive=True),
    Capability("preview_v4_dlp_sensor_create", "Read actual DLP Sensor state and render one bounded Current/Proposed/Expected laboratory HTTP-GET PDF file-type or fixed Regexp sentinel block Sensor preview.", ToolPack.V4_DLP_SENSOR_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_DLP_SENSOR_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_dlp_sensor_create", "Re-read one exact DLP Sensor create preview and record a single execution confirmation.", ToolPack.V4_DLP_SENSOR_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_dlp_sensor_create", "Execute one exact protected and previously confirmed laboratory DLP Sensor with a fixed HTTP-GET PDF file-type or fixed Regexp sentinel block filter and categorical CLI readback.", ToolPack.V4_DLP_SENSOR_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_dlp_sensor_delete", "Read only the exact accepted b34 PDF DLP Sensor full-record digest, fixed REST/SSH projection, preserved File Pattern binding, and complete bounded Secret/Policy references, then render one destructive Current/Proposed/Expected recovery preview without accepting or returning its name or content.", ToolPack.V4_DLP_SENSOR_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_dlp_sensor_delete", "Re-read the exact accepted DLP Sensor REST/SSH digest, File Pattern binding, and zero-reference projection, then record one short-lived requester-bound destructive confirmation.", ToolPack.V4_DLP_SENSOR_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_dlp_sensor_delete", "Delete only the exact previously confirmed accepted unreferenced b34 PDF DLP Sensor through one fixed bodyless REST DELETE and dual REST/SSH categorical absence readback while preserving its File Pattern, with separate create compensation required.", ToolPack.V4_DLP_SENSOR_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True, destructive=True),
    Capability("preview_v4_antivirus_profile_create", "Read actual AntiVirus Profile state and render one bounded Current/Proposed/Expected laboratory HTTP and SSH block Profile preview.", ToolPack.V4_ANTIVIRUS_PROFILE_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_ANTIVIRUS_PROFILE_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_antivirus_profile_create", "Re-read one exact AntiVirus Profile create preview and record a single execution confirmation.", ToolPack.V4_ANTIVIRUS_PROFILE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_antivirus_profile_create", "Execute one exact protected and previously confirmed laboratory AntiVirus Profile with fixed HTTP and SSH block settings and categorical CLI readback.", ToolPack.V4_ANTIVIRUS_PROFILE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_antivirus_profile_delete", "Read only the exact accepted AntiVirus Profile full-record digest, fixed SSH HTTP/SSH block projection, and complete bounded Secret references, then render one destructive Current/Proposed/Expected recovery preview without accepting or returning its name or content.", ToolPack.V4_ANTIVIRUS_PROFILE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_antivirus_profile_delete", "Re-read the exact accepted AntiVirus Profile REST/SSH digest and zero-reference projection, then record one short-lived requester-bound destructive confirmation.", ToolPack.V4_ANTIVIRUS_PROFILE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_antivirus_profile_delete", "Delete only the exact previously confirmed accepted unreferenced AntiVirus Profile through one fixed REST DELETE and dual REST/SSH categorical absence readback, with separate create compensation required.", ToolPack.V4_ANTIVIRUS_PROFILE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True, destructive=True),
    Capability("preview_v4_rdp_event_filter_create", "Read actual RDP event-filter Profile state and render one bounded Current/Proposed/Expected unattached laboratory Profile preview.", ToolPack.V4_RDP_EVENT_FILTER_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_RDP_EVENT_FILTER_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_rdp_event_filter_create", "Re-read one exact RDP event-filter Profile create preview and record a single execution confirmation.", ToolPack.V4_RDP_EVENT_FILTER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_rdp_event_filter_create", "Execute one exact protected and previously confirmed laboratory RDP event-filter Profile with fixed enabled event categories and categorical CLI readback.", ToolPack.V4_RDP_EVENT_FILTER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_rdp_event_filter_delete", "Read only the exact accepted RDP event-filter full-record digest, fixed SSH three-event projection, and complete bounded Secret and Policy references, then render one destructive Current/Proposed/Expected recovery preview without accepting or returning its name or content.", ToolPack.V4_RDP_EVENT_FILTER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_rdp_event_filter_delete", "Re-read the exact accepted RDP event-filter REST/SSH digest and zero-reference projection, then record one short-lived requester-bound destructive confirmation.", ToolPack.V4_RDP_EVENT_FILTER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_rdp_event_filter_delete", "Delete only the exact previously confirmed accepted unreferenced RDP event-filter Profile through one fixed REST DELETE and dual REST/SSH categorical absence readback, with separate create compensation required.", ToolPack.V4_RDP_EVENT_FILTER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True, destructive=True),
    Capability("preview_v4_secret_policy_create", "Read actual Secret Policy state and render one bounded Current/Proposed/Expected unattached laboratory Policy preview.", ToolPack.V4_SECRET_POLICY_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_SECRET_POLICY_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_secret_policy_create", "Re-read one exact Secret Policy create preview and record a single execution confirmation.", ToolPack.V4_SECRET_POLICY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_secret_policy_create", "Execute one exact protected and previously confirmed laboratory Secret Policy with fixed SSH Filter and RDP clipboard settings and categorical CLI readback.", ToolPack.V4_SECRET_POLICY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_secret_policy_update", "Read one exact local Secret Policy baseline and render a bounded Current/Proposed/Expected RDP clipboard update preview.", ToolPack.V4_SECRET_POLICY_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_SECRET_POLICY_UPDATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_secret_policy_update", "Re-read one exact Secret Policy update baseline and record a single execution confirmation.", ToolPack.V4_SECRET_POLICY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_secret_policy_update", "Execute one exact protected and previously confirmed local Secret Policy update that changes only RDP clipboard blocking and returns categorical CLI readback.", ToolPack.V4_SECRET_POLICY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_ssh_filter_create", "Read actual SSH Filter Profile state and render one bounded Current/Proposed/Expected fixed deny-rm Profile preview.", ToolPack.V4_SSH_FILTER_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_SSH_FILTER_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_ssh_filter_create", "Re-read one exact SSH Filter Profile create preview and record a single execution confirmation.", ToolPack.V4_SSH_FILTER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_ssh_filter_create", "Execute one exact protected and previously confirmed unattached SSH Filter Profile with categorical SSH CLI readback.", ToolPack.V4_SSH_FILTER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_ssh_filter_delete", "Read only the exact accepted SSH Filter full-record digest, fixed SSH deny-rm projection, and complete bounded Secret and Policy references, then render one destructive Current/Proposed/Expected recovery preview without accepting or returning its name or content.", ToolPack.V4_SSH_FILTER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_ssh_filter_delete", "Re-read the exact accepted SSH Filter REST/SSH digest and zero-reference projection, then record one short-lived requester-bound destructive confirmation.", ToolPack.V4_SSH_FILTER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_ssh_filter_delete", "Delete only the exact previously confirmed accepted unreferenced SSH Filter Profile through one fixed REST DELETE and dual REST/SSH categorical absence readback, with separate create compensation required.", ToolPack.V4_SSH_FILTER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True, destructive=True),
    Capability("preview_v4_launcher_create", "Read actual Launcher state and render one bounded Current/Proposed/Expected unattached native RDP Launcher preview.", ToolPack.V4_LAUNCHER_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_LAUNCHER_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_launcher_create", "Re-read one exact Launcher create preview and record a single execution confirmation.", ToolPack.V4_LAUNCHER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_launcher_create", "Execute one exact protected and previously confirmed unattached native RDP Launcher with categorical SSH CLI readback.", ToolPack.V4_LAUNCHER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_launcher_timeout_update", "Read the exact native RDP Launcher create baseline and render one bounded Current/Proposed/Expected timeout update preview.", ToolPack.V4_LAUNCHER_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_LAUNCHER_UPDATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_launcher_timeout_update", "Re-read one exact Launcher timeout update preview and record a single execution confirmation.", ToolPack.V4_LAUNCHER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_launcher_timeout_update", "Execute one exact protected and previously confirmed native RDP Launcher timeout update with categorical SSH CLI readback and no command, association, target, or session change.", ToolPack.V4_LAUNCHER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_launcher_command_line_matcher_configure", "Read the exact uncustomized native RDP Launcher create baseline and render one bounded Current/Proposed/Expected CommandLine matcher configuration preview.", ToolPack.V4_LAUNCHER_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_LAUNCHER_MATCHER_CONFIGURE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_launcher_command_line_matcher_configure", "Re-read one exact Launcher matcher baseline and record a single execution confirmation.", ToolPack.V4_LAUNCHER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_launcher_command_line_matcher_configure", "Execute one exact protected and previously confirmed native RDP Launcher CommandLine matcher configuration with categorical SSH CLI readback and no command, association, target, or session change.", ToolPack.V4_LAUNCHER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_template_create", "Read actual Template state and render one bounded Current/Proposed/Expected unattached Web VNC Template preview.", ToolPack.V4_TEMPLATE_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_TEMPLATE_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_template_create", "Re-read one exact Template create preview and record a single execution confirmation.", ToolPack.V4_TEMPLATE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_template_create", "Execute one exact protected and previously confirmed unattached Web VNC Template with categorical SSH CLI readback.", ToolPack.V4_TEMPLATE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_template_web_vnc_port_update", "Read one exact Web VNC Template create baseline and render one bounded Current/Proposed/Expected Launcher-port update preview.", ToolPack.V4_TEMPLATE_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_TEMPLATE_UPDATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_template_web_vnc_port_update", "Re-read one exact Web VNC Template port-update preview and record a single execution confirmation.", ToolPack.V4_TEMPLATE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_template_web_vnc_port_update", "Execute one exact protected and previously confirmed Web VNC Template Launcher-port update with categorical SSH CLI readback and no field, access, Secret, Target, or session change.", ToolPack.V4_TEMPLATE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_disposable_template_archive", "Read one disposable Template and direct Secret and Target reference posture, then render one bounded Current/Proposed/Expected irreversible archive preview.", ToolPack.V4_TEMPLATE_ARCHIVE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_TEMPLATE_ARCHIVE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_disposable_template_archive", "Re-read one exact disposable Template archive preview and record a single execution confirmation.", ToolPack.V4_TEMPLATE_ARCHIVE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_disposable_template_archive", "Irreversibly archive one exact protected and previously confirmed unreferenced disposable Template through a fixed REST API route with categorical SSH readback.", ToolPack.V4_TEMPLATE_ARCHIVE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_dependency_updater_create", "Read actual Dependency Updater state and render one bounded Current/Proposed/Expected unattached Windows-service updater preview.", ToolPack.V4_DEPENDENCY_UPDATER_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_DEPENDENCY_UPDATER_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_dependency_updater_create", "Re-read one exact Dependency Updater create preview and record a single execution confirmation.", ToolPack.V4_DEPENDENCY_UPDATER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_dependency_updater_create", "Execute one exact protected and previously confirmed unattached Windows-service Dependency Updater with categorical SSH CLI readback.", ToolPack.V4_DEPENDENCY_UPDATER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_secret_gateway_create", "Read actual Secret Gateway state and render one bounded Current/Proposed/Expected disabled Forward Gateway preview.", ToolPack.V4_SECRET_GATEWAY_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_SECRET_GATEWAY_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_secret_gateway_create", "Re-read one exact Secret Gateway create preview and record a single execution confirmation.", ToolPack.V4_SECRET_GATEWAY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_secret_gateway_create", "Execute one exact protected and previously confirmed disabled Forward Secret Gateway with categorical SSH CLI readback and no Target, Secret, chain, reverse-service, certificate, or traffic-forwarding effect.", ToolPack.V4_SECRET_GATEWAY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_client_integrity_configure", "Read actual Client Software state and render one bounded Current/Proposed/Expected unbound certificate-integrity precondition preview.", ToolPack.V4_CLIENT_INTEGRITY_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_CLIENT_INTEGRITY_CONFIGURE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_client_integrity_configure", "Re-read one exact Client Software precondition preview and record a single execution confirmation.", ToolPack.V4_CLIENT_INTEGRITY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_client_integrity_configure", "Execute one exact protected and previously confirmed unbound Client Software certificate-integrity precondition with categorical SSH CLI readback and no Launcher, Template, Secret, Target, download, or session effect.", ToolPack.V4_CLIENT_INTEGRITY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_character_set_create", "Read actual Character Set state and render one bounded Current/Proposed/Expected preview for an unassociated laboratory Character Set with the documented fixed symbol profile.", ToolPack.V4_CHARACTER_SET_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_CHARACTER_SET_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_character_set_create", "Re-read one exact Character Set create preview and record a single execution confirmation.", ToolPack.V4_CHARACTER_SET_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_character_set_create", "Execute one exact protected and previously confirmed unassociated Character Set with categorical REST readback and no Password Policy, Template, Secret, Target, generated password, or session effect.", ToolPack.V4_CHARACTER_SET_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_character_set_delete", "Read only the exact accepted Character Set and Password Policy dependency projection, then render one bounded destructive Current/Proposed/Expected recovery preview without accepting or returning its name or value.", ToolPack.V4_CHARACTER_SET_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_character_set_delete", "Re-read the exact accepted Character Set digest and zero-reference projection, then record one short-lived requester-bound destructive confirmation.", ToolPack.V4_CHARACTER_SET_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_character_set_delete", "Delete only the exact previously confirmed accepted unreferenced Character Set through one fixed REST DELETE and categorical absence readback, with separate create compensation required.", ToolPack.V4_CHARACTER_SET_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True, destructive=True),
    Capability("preview_v4_windows_app_filter_create", "Read actual Windows App Filter Profile state and render one bounded Current/Proposed/Expected preview for a minimal unassociated laboratory Profile with no caller-supplied filter or exception content.", ToolPack.V4_WINDOWS_APP_FILTER_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_WINDOWS_APP_FILTER_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_windows_app_filter_create", "Re-read one exact Windows App Filter Profile create preview and record a single execution confirmation.", ToolPack.V4_WINDOWS_APP_FILTER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_windows_app_filter_create", "Execute one exact protected and previously confirmed minimal Windows App Filter Profile with categorical REST readback and no caller-supplied filters, exceptions, Secret, Target, policy, or session effect.", ToolPack.V4_WINDOWS_APP_FILTER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_windows_app_filter_delete", "Read only the exact accepted Windows App Filter Profile plus the complete bounded Secret reference projection, then render one destructive Current/Proposed/Expected recovery preview without accepting or returning its name, filters, or exceptions.", ToolPack.V4_WINDOWS_APP_FILTER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_windows_app_filter_delete", "Re-read the exact accepted Windows App Filter Profile digest and zero-reference projection, then record one short-lived requester-bound destructive confirmation.", ToolPack.V4_WINDOWS_APP_FILTER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_windows_app_filter_delete", "Delete only the exact previously confirmed accepted unreferenced Windows App Filter Profile through one fixed REST DELETE and categorical absence readback, with separate create compensation required.", ToolPack.V4_WINDOWS_APP_FILTER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True, destructive=True),
    Capability("preview_v4_recording_policy_enable", "Read actual laboratory Secret Policy recording posture and render one bounded Current/Proposed/Expected preview for enabling Session Recording only.", ToolPack.V4_RECORDING_POLICY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_RECORDING_POLICY_ENABLE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_recording_policy_enable", "Re-read one exact Secret Policy recording preview and record a single execution confirmation.", ToolPack.V4_RECORDING_POLICY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_recording_policy_enable", "Enable Session Recording on one exact, previously confirmed laboratory Secret Policy through a fixed REST body and categorical readback only; no other Policy field, Folder, Secret, association, Target, or session is changed.", ToolPack.V4_RECORDING_POLICY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_password_policy_create", "Read actual Password Policy state and render one bounded Current/Proposed/Expected preview for an unassociated laboratory Password Policy with four default Character Sets.", ToolPack.V4_PASSWORD_POLICY_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_PASSWORD_POLICY_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_password_policy_create", "Re-read one exact Password Policy create preview and record a single execution confirmation.", ToolPack.V4_PASSWORD_POLICY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_password_policy_create", "Execute one exact protected and previously confirmed unassociated Password Policy with categorical REST readback and no Template, Secret, authentication material, generated-password, association, or session effect.", ToolPack.V4_PASSWORD_POLICY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_password_policy_delete", "Read only the exact accepted Password Policy and render one bounded destructive Current/Proposed/Expected recovery preview without accepting or returning its name or body.", ToolPack.V4_PASSWORD_POLICY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_password_policy_delete", "Re-read the exact accepted Password Policy digest and record one short-lived requester-bound destructive confirmation.", ToolPack.V4_PASSWORD_POLICY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_password_policy_delete", "Delete only the exact previously confirmed accepted Password Policy through one fixed REST DELETE and categorical absence readback, with separate create compensation required.", ToolPack.V4_PASSWORD_POLICY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True, destructive=True),
    Capability("preview_v4_report_layout_create", "Read the exact target absence and eligible default Report Layout state, then render one bounded Current/Proposed/Expected preview for a daily PDF clone with email disabled and no filters.", ToolPack.V4_REPORT_LAYOUT_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_REPORT_LAYOUT_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_report_layout_create", "Re-read one exact Report Layout create preview and record a single execution confirmation.", ToolPack.V4_REPORT_LAYOUT_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_report_layout_create", "Execute one exact protected and previously confirmed eligible default-layout clone with categorical REST readback, daily PDF scheduling, email disabled, no filters, and no report generation or content return.", ToolPack.V4_REPORT_LAYOUT_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_report_layout_delete", "Read only the exact accepted Report Layout and unchanged eligible default clone, then render one bounded destructive Current/Proposed/Expected recovery preview without returning its name or content.", ToolPack.V4_REPORT_LAYOUT_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_report_layout_delete", "Re-read one exact accepted Report Layout delete preview and record a single requester-bound recovery confirmation.", ToolPack.V4_REPORT_LAYOUT_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_report_layout_delete", "Delete only the exact unchanged accepted Report Layout through the fixed detail route and prove categorical absence without report generation, content access, or automatic retry.", ToolPack.V4_REPORT_LAYOUT_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True, destructive=True),
    Capability("preview_v4_ztna_access_proxy_client_certificate", "Read the private Access Proxy's effective client-certificate baseline and render one bounded Current/Proposed/Expected managed-only or mixed-access prerequisite preview.", ToolPack.V4_ZTNA_ACCESS_PROXY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_ZTNA_ACCESS_PROXY_CLIENT_CERTIFICATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_ztna_access_proxy_client_certificate", "Re-read one exact Access Proxy client-certificate baseline and record a single execution confirmation.", ToolPack.V4_ZTNA_ACCESS_PROXY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_ztna_access_proxy_client_certificate", "Execute one exact protected and previously confirmed Access Proxy client-certificate prerequisite with categorical CLI readback; it does not alter tags, proxy policy, Folder, Secret, session, or WAD debug.", ToolPack.V4_ZTNA_ACCESS_PROXY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_ztna_access_proxy_client_certificate_rollback", "Read the protected Access Proxy's exact enabled client-certificate outcome and render one bounded rollback preview to the original disable/block state.", ToolPack.V4_ZTNA_ACCESS_PROXY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_ztna_access_proxy_client_certificate_rollback", "Re-read one exact ZTNA Access Proxy rollback preview and record a single rollback execution confirmation.", ToolPack.V4_ZTNA_ACCESS_PROXY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_ztna_access_proxy_client_certificate_rollback", "Restore one exact protected and previously confirmed Access Proxy to client-cert disable and empty-cert-action block with categorical CLI readback only.", ToolPack.V4_ZTNA_ACCESS_PROXY_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_ztna_user_control_configure", "Read the private Access Proxy policy and render one bounded Current/Proposed/Expected Access-level ZTNA enable preview using its existing EMS tag.", ToolPack.V4_ZTNA_USER_CONTROL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_ZTNA_USER_CONTROL_CONFIGURE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_ztna_user_control_configure", "Re-read one exact Access-level ZTNA baseline and record a single execution confirmation.", ToolPack.V4_ZTNA_USER_CONTROL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_ztna_user_control_configure", "Execute one exact protected and previously confirmed Access-level ZTNA enable transition with categorical CLI readback; it does not alter Access Proxy certificate handling, EMS/tag, Folder, Secret, session, or WAD debug.", ToolPack.V4_ZTNA_USER_CONTROL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_ztna_user_control_rollback", "Read the protected Access Proxy policy's exact enabled Access-level ZTNA outcome and render one bounded rollback preview to ztna-status disable.", ToolPack.V4_ZTNA_USER_CONTROL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_ztna_user_control_rollback", "Re-read one exact Access-level ZTNA rollback preview and record a single rollback execution confirmation.", ToolPack.V4_ZTNA_USER_CONTROL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_ztna_user_control_rollback", "Restore one exact protected and previously confirmed Access Proxy policy to ztna-status disable with categorical CLI readback only.", ToolPack.V4_ZTNA_USER_CONTROL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_ztna_wad_debug_diagnostic", "Read the global FortiPAM debug state and render one bounded Current/Proposed/Expected time-boxed WAD debug diagnostic preview. It fails closed if debug is already active or unrecognized.", ToolPack.V4_ZTNA_WAD_DEBUG_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_ZTNA_WAD_DEBUG_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_ztna_wad_debug_diagnostic", "Re-read the global debug baseline and record a single time-boxed WAD diagnostic execution confirmation.", ToolPack.V4_ZTNA_WAD_DEBUG_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_ztna_wad_debug_diagnostic", "Run one exact protected and previously confirmed time-boxed WAD debug diagnostic, automatically disable debug, and return categorical device-context, tag-match, and launch evidence only.", ToolPack.V4_ZTNA_WAD_DEBUG_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_snmp_agent_enable", "Read the current FortiPAM system SNMP Agent status and render one bounded Current/Proposed/Expected enable preview without changing SNMP communities, users, notification destinations, or interface access.", ToolPack.V4_SNMP_AGENT_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_SNMP_AGENT_ENABLE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_snmp_agent_enable", "Re-read one exact disabled SNMP Agent baseline and record a single execution confirmation.", ToolPack.V4_SNMP_AGENT_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_snmp_agent_enable", "Execute one exact protected and previously confirmed SNMP Agent enable transition with categorical CLI readback; it does not alter SNMP communities, SNMPv3 users, notification destinations, interface access, or trap/query behavior.", ToolPack.V4_SNMP_AGENT_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_snmp_agent_rollback", "Read the exact enabled SNMP Agent state and render one bounded rollback preview to the original disabled state.", ToolPack.V4_SNMP_AGENT_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_snmp_agent_rollback", "Re-read one exact SNMP Agent rollback preview and record a single rollback execution confirmation.", ToolPack.V4_SNMP_AGENT_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_snmp_agent_rollback", "Restore one exact protected and previously confirmed SNMP Agent to disabled with categorical API and CLI readback only.", ToolPack.V4_SNMP_AGENT_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_logging_disk_disable", "Read current FortiPAM memory and disk logging state and render one bounded Current/Proposed/Expected disk-disable preview without changing remote syslog, event categories, disk encryption, or retention.", ToolPack.V4_LOGGING_DISK_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_LOGGING_DISK_DISABLE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_logging_disk_disable", "Re-read one exact memory-enabled and disk-enabled logging baseline and record a single execution confirmation.", ToolPack.V4_LOGGING_DISK_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_logging_disk_disable", "Execute one exact protected and previously confirmed disk-logging disable transition with categorical CLI readback; it does not alter remote syslog, event categories, disk encryption, or retention.", ToolPack.V4_LOGGING_DISK_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_fortianalyzer_enable", "Read one existing configured FortiAnalyzer delivery setting and render a bounded Current/Proposed/Expected enable preview without exposing or changing server, upload, certificate, authorization, filter, or logging-category configuration.", ToolPack.V4_FORTIANALYZER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_FORTIANALYZER_ENABLE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_fortianalyzer_enable", "Re-read one exact disabled FortiAnalyzer delivery baseline with an unchanged configured-server binding and record a single execution confirmation.", ToolPack.V4_FORTIANALYZER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_fortianalyzer_enable", "Execute one exact protected and previously confirmed FortiAnalyzer delivery enable transition with categorical CLI readback; it does not alter server, upload, certificate, authorization, filter, or logging-category configuration.", ToolPack.V4_FORTIANALYZER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_maintenance_mode_enable", "Read current FortiPAM maintenance mode and render one bounded Current/Proposed/Expected enable preview without requesting reboot, firmware, license, restore, TPM, disk-encryption, storage, or other system changes.", ToolPack.V4_MAINTENANCE_MODE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_MAINTENANCE_MODE_ENABLE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_maintenance_mode_enable", "Re-read one exact disabled FortiPAM maintenance-mode baseline and record a single execution confirmation.", ToolPack.V4_MAINTENANCE_MODE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_maintenance_mode_enable", "Execute one exact protected and previously confirmed FortiPAM maintenance-mode enable transition with categorical CLI readback; it does not request reboot, firmware, license, restore, TPM, disk-encryption, storage, or other system changes.", ToolPack.V4_MAINTENANCE_MODE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_maintenance_mode_rollback", "Read exact enabled FortiPAM maintenance mode and render one bounded rollback preview to ordinary disabled mode without requesting another system change.", ToolPack.V4_MAINTENANCE_MODE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_maintenance_mode_rollback", "Re-read one exact enabled maintenance-mode rollback baseline and record a single rollback execution confirmation.", ToolPack.V4_MAINTENANCE_MODE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_maintenance_mode_rollback", "Restore one exact protected and previously confirmed FortiPAM maintenance mode to ordinary disabled state with categorical API and CLI readback only.", ToolPack.V4_MAINTENANCE_MODE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_secret_audit_generate", "Validate fixed CLI reachability and, when configured, the FortiPAM 7.0 report inventory; render bounded Current/Proposed/Expected without returning report names, content, or resource metadata.", ToolPack.V4_SECRET_AUDIT_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.NONE, ("1.9.1", "7.0.0"), True),
    Capability("confirm_v4_secret_audit_generate", "Revalidate the fixed CLI and optional report-inventory preflight before recording one Secret Audit generation confirmation.", ToolPack.V4_SECRET_AUDIT_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1", "7.0.0"), True, True, False),
    Capability("execute_confirmed_v4_secret_audit_generate", "Generate one protected FortiPAM Secret Audit report through the fixed CLI and, when configured, require a unique new report in the 7.0 API inventory; return no report content, filename, identity, Target, Folder, Secret, or permission data.", ToolPack.V4_SECRET_AUDIT_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1", "7.0.0"), True, True, True, device_write=True),
    Capability("summarize_v4_secret_access_audit", "Read the latest existing FortiPAM 7.0 Secret Access Audit CSV under the dedicated operation principal and return only bounded aggregate counts.", ToolPack.V4_SECRET_AUDIT_SUMMARY, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.NONE, ("7.0.0",), True),
    Capability("summarize_v4_synthetic_terraform_plan", "Read one prebound signed synthetic Terraform plan for its exact OAuth human/client and return only fixed structural counts and unresolved risks.", ToolPack.V4_TERRAFORM_PLAN_REPORT, ExecutionMode.OFFLINE, RiskLevel.MODERATE, InputScope.NONE, ("1.9.1",), False, idempotent=False),
    Capability("observe_v4_active_launches", "Observe active FortiPAM launches through a fixed WAD CLI command and return only opaque short-lived launch references, counts, and categorical status.", ToolPack.V4_ACTIVE_LAUNCH_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.NONE, ("1.9.1",), True),
    Capability("preview_v4_active_launch_disconnect", "Re-read one opaque active-launch reference and render a bounded Current/Proposed/Expected preview for disconnecting exactly one active launch.", ToolPack.V4_ACTIVE_LAUNCH_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_ACTIVE_LAUNCH_DISCONNECT_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_active_launch_disconnect", "Revalidate the selected active launch and record one exact disconnect confirmation.", ToolPack.V4_ACTIVE_LAUNCH_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_active_launch_disconnect", "Disconnect exactly one previously observed and confirmed FortiPAM active launch with categorical SSH CLI readback; it never invokes the clear-all form or returns raw WAD identifiers or session metadata.", ToolPack.V4_ACTIVE_LAUNCH_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_automation_trigger_create", "Read actual Automation Trigger state and render one bounded Current/Proposed/Expected unbound event-log Trigger preview.", ToolPack.V4_AUTOMATION_TRIGGER_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_AUTOMATION_TRIGGER_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_automation_trigger_create", "Re-read one exact Automation Trigger create preview and record a single execution confirmation.", ToolPack.V4_AUTOMATION_TRIGGER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_automation_trigger_create", "Execute one exact protected and previously confirmed unbound Automation Trigger with categorical SSH CLI readback and no Action or Stitch association.", ToolPack.V4_AUTOMATION_TRIGGER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_automation_trigger_delete", "Read only the exact accepted unbound b40 Automation Trigger, verify its complete fixed projection, b44 preservation baseline, and zero references, and render one no-input recovery preview.", ToolPack.V4_AUTOMATION_TRIGGER_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_automation_trigger_delete", "Re-read the exact unchanged Automation Trigger recovery baseline and record a single execution confirmation.", ToolPack.V4_AUTOMATION_TRIGGER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_automation_trigger_delete", "Execute one exact protected and previously confirmed bodyless REST DELETE for only accepted unreferenced b40, with categorical REST/SSH Trigger absence and b44 Action-preservation readback.", ToolPack.V4_AUTOMATION_TRIGGER_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True, destructive=True),
    Capability("preview_v4_automation_action_create", "Read actual Automation Action state and render one bounded Current/Proposed/Expected unbound email Action preview.", ToolPack.V4_AUTOMATION_ACTION_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_AUTOMATION_ACTION_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_automation_action_create", "Re-read one exact Automation Action create preview and record a single execution confirmation.", ToolPack.V4_AUTOMATION_ACTION_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_automation_action_create", "Execute one exact protected and previously confirmed unbound email Automation Action with categorical SSH CLI readback and no Stitch association.", ToolPack.V4_AUTOMATION_ACTION_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_automation_action_delete", "Read only the exact accepted unbound b44 Automation Action, verify its complete fixed REST/SSH projection, absent b40/b68, and zero references, and render one no-input recovery preview.", ToolPack.V4_AUTOMATION_ACTION_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_automation_action_delete", "Re-read the exact unchanged Automation Action recovery baseline and record a single execution confirmation.", ToolPack.V4_AUTOMATION_ACTION_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_automation_action_delete", "Execute one exact protected and previously confirmed bodyless REST DELETE for only accepted unreferenced b44, with categorical REST/SSH Action absence readback.", ToolPack.V4_AUTOMATION_ACTION_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True, destructive=True),
    Capability("preview_v4_automation_stitch_create", "Read actual Automation Stitch, Trigger, and Action state and render one bounded Current/Proposed/Expected disabled Stitch preview.", ToolPack.V4_AUTOMATION_STITCH_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_AUTOMATION_STITCH_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_automation_stitch_create", "Re-read one exact disabled Automation Stitch create preview and record a single execution confirmation.", ToolPack.V4_AUTOMATION_STITCH_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_automation_stitch_create", "Execute one exact protected and previously confirmed disabled Automation Stitch with categorical SSH CLI readback; it never enables, tests, or executes automation.", ToolPack.V4_AUTOMATION_STITCH_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_automation_stitch_delete", "Read only the exact accepted disabled b68 Automation Stitch, verify its complete fixed projection, b40/b44 dependencies, and zero references, and render one no-input recovery preview.", ToolPack.V4_AUTOMATION_STITCH_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_automation_stitch_delete", "Re-read the exact unchanged Automation Stitch recovery baseline and record a single execution confirmation.", ToolPack.V4_AUTOMATION_STITCH_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_automation_stitch_delete", "Execute one exact protected and previously confirmed bodyless REST DELETE for only the accepted unreferenced disabled b68 Automation Stitch, with categorical REST/SSH absence and b40/b44 dependency-preservation readback.", ToolPack.V4_AUTOMATION_STITCH_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True, destructive=True),
    Capability("preview_v4_user_group_create", "Read actual User Group state and render one bounded Current/Proposed/Expected remote LDAP User Group preview.", ToolPack.V4_USER_GROUP_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_USER_GROUP_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_user_group_create", "Re-read one exact remote LDAP User Group create preview and record a single execution confirmation.", ToolPack.V4_USER_GROUP_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_user_group_create", "Execute one exact protected and previously confirmed remote LDAP User Group with categorical SSH CLI readback and no Role, Auto-Provision Rule, Folder/Secret ACL, import, or session change.", ToolPack.V4_USER_GROUP_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_user_group_membership_change", "Read one exact remote LDAP User Group create baseline and render one bounded second-match Current/Proposed/Expected preview.", ToolPack.V4_USER_GROUP_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_USER_GROUP_MEMBERSHIP_CHANGE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_user_group_membership_change", "Re-read one exact one-match remote LDAP User Group baseline and record a single execution confirmation.", ToolPack.V4_USER_GROUP_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_user_group_membership_change", "Execute one exact protected and previously confirmed second remote LDAP group match with categorical SSH CLI readback and no LDAP-server, Role, Auto-Provision Rule, Folder/Secret ACL, import, or session change.", ToolPack.V4_USER_GROUP_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_auto_provision_rule_create", "Read one Auto-Provision Rule and its existing V4 remote LDAP User Group and Role dependencies, then render one bounded disabled-rule Current/Proposed/Expected preview.", ToolPack.V4_APL_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_APL_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_auto_provision_rule_create", "Re-read one exact disabled Auto-Provision Rule create baseline and record a single execution confirmation.", ToolPack.V4_APL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_auto_provision_rule_create", "Execute one exact protected and previously confirmed disabled Auto-Provision Rule with categorical CLI readback; it never enables auto-provisioning or changes users, groups, Roles, identity servers, or login flow.", ToolPack.V4_APL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_auto_provision_rule_disable", "Read one exact enabled V4 Auto-Provision Rule baseline and render one bounded status-disable Current/Proposed/Expected preview.", ToolPack.V4_APL_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_APL_DISABLE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_auto_provision_rule_disable", "Re-read one exact enabled Auto-Provision Rule disable baseline and record a single execution confirmation.", ToolPack.V4_APL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_auto_provision_rule_disable", "Execute one exact protected and previously confirmed Auto-Provision Rule status-disable with categorical CLI readback; it preserves exact references and makes no other lifecycle changes.", ToolPack.V4_APL_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_schedule_create", "Read actual recurring Schedule state and render one bounded Current/Proposed/Expected unattached Schedule preview.", ToolPack.V4_SCHEDULE_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_SCHEDULE_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_schedule_create", "Re-read one exact recurring Schedule create preview and record a single execution confirmation.", ToolPack.V4_SCHEDULE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_schedule_create", "Execute one exact protected and previously confirmed recurring Schedule with categorical SSH CLI readback and no User, Role, policy, Folder, Secret, ACL, or session association.", ToolPack.V4_SCHEDULE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_schedule_delete", "Read only the exact accepted recurring Schedule, verify its complete fixed REST/SSH projection, fixed User unassigned state, and zero User/full-CMDB references, and render one no-input recovery preview.", ToolPack.V4_SCHEDULE_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_schedule_delete", "Re-read the exact unchanged recurring Schedule recovery baseline and record a single execution confirmation.", ToolPack.V4_SCHEDULE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_schedule_delete", "Execute one exact protected and previously confirmed bodyless REST DELETE for only the accepted unreferenced recurring Schedule, with categorical REST/SSH absence and fixed-User preservation readback.", ToolPack.V4_SCHEDULE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True, destructive=True),
    Capability("preview_v4_schedule_assign", "Read one exact disabled laboratory Local User and existing recurring Schedule and render a bounded Current/Proposed/Expected login-Schedule assignment preview.", ToolPack.V4_SCHEDULE_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_SCHEDULE_ASSIGN_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_schedule_assign", "Re-read one unchanged unassigned User/Schedule pair and record a single execution confirmation.", ToolPack.V4_SCHEDULE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_schedule_assign", "Execute one exact protected login-Schedule assignment and verify the User remains disabled/local, all non-schedule User state is preserved, and the Schedule is unchanged.", ToolPack.V4_SCHEDULE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_schedule_assignment_detach", "Read only the accepted fixed User/Schedule assignment, verify complete User/Schedule digests, Role and REST/SSH Schedule projections, and sole-reference state, then render a no-input recovery preview.", ToolPack.V4_SCHEDULE_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_schedule_assignment_detach", "Re-read the exact unchanged fixed Schedule-assignment recovery baseline and record a single execution confirmation.", ToolPack.V4_SCHEDULE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_schedule_assignment_detach", "Execute one exact protected existing-User PUT clearing only the accepted Schedule assignment and verify all non-Schedule User state, Role, complete Schedule, and zero references are preserved.", ToolPack.V4_SCHEDULE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_approval_profile_create", "Read actual Approval Profile state and render one bounded Current/Proposed/Expected unattached single-tier Profile preview.", ToolPack.V4_APPROVAL_PROFILE_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_APPROVAL_PROFILE_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_approval_profile_create", "Re-read one exact Approval Profile create preview and record a single execution confirmation.", ToolPack.V4_APPROVAL_PROFILE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_approval_profile_create", "Execute one exact protected and previously confirmed unattached single-tier Approval Profile with categorical SSH CLI readback and no Secret association or approval request.", ToolPack.V4_APPROVAL_PROFILE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_approval_profile_description_update", "Read one exact Approval Profile baseline and render one bounded Current/Proposed/Expected fixed-description update preview.", ToolPack.V4_APPROVAL_PROFILE_UPDATE_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_APPROVAL_PROFILE_UPDATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_approval_profile_description_update", "Re-read one exact Approval Profile update baseline and record a single execution confirmation.", ToolPack.V4_APPROVAL_PROFILE_UPDATE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_approval_profile_description_update", "Execute one exact protected and previously confirmed Approval Profile fixed-description update with categorical SSH CLI readback and preserved approval baseline.", ToolPack.V4_APPROVAL_PROFILE_UPDATE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_approval_profile_delete", "Read only the exact accepted b36/b38 Approval Profile, verify its complete fixed projection and zero references, and render one no-input recovery preview.", ToolPack.V4_APPROVAL_PROFILE_UPDATE_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_approval_profile_delete", "Re-read the exact unchanged Approval Profile recovery baseline and record a single execution confirmation.", ToolPack.V4_APPROVAL_PROFILE_UPDATE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_approval_profile_delete", "Execute one exact protected and previously confirmed bodyless REST DELETE for only the accepted unreferenced b36/b38 Approval Profile, with categorical REST/SSH absence readback and no other configuration change.", ToolPack.V4_APPROVAL_PROFILE_UPDATE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True, destructive=True),
    Capability("preview_v4_approval_email_template_create", "Read actual Approval Email Template state and render one bounded Current/Proposed/Expected unassociated template preview.", ToolPack.V4_APPROVAL_EMAIL_TEMPLATE_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_APPROVAL_EMAIL_TEMPLATE_CREATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_approval_email_template_create", "Re-read one exact Approval Email Template create preview and record a single execution confirmation.", ToolPack.V4_APPROVAL_EMAIL_TEMPLATE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_approval_email_template_create", "Execute one exact protected and previously confirmed unassociated Approval Email Template with categorical SSH CLI readback and no mail-server, Profile, Secret, or approval execution change.", ToolPack.V4_APPROVAL_EMAIL_TEMPLATE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_approval_email_template_content_update", "Read one exact Approval Email Template create baseline and render one bounded Current/Proposed/Expected fixed subject/content update preview.", ToolPack.V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_PREVIEW, ("1.9.1",), True),
    Capability("confirm_v4_approval_email_template_content_update", "Re-read one exact Approval Email Template update baseline and record a single execution confirmation.", ToolPack.V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_approval_email_template_content_update", "Execute one exact protected and previously confirmed Approval Email Template fixed subject/content update with categorical SSH CLI readback and no email delivery or association.", ToolPack.V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True),
    Capability("preview_v4_approval_email_template_delete", "Read only the exact accepted b37/b39 Approval Email Template, verify its complete fixed projection and zero references, and render one no-input recovery preview.", ToolPack.V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION, ExecutionMode.LIVE, RiskLevel.LOW, InputScope.NONE, ("1.9.1",), True),
    Capability("confirm_v4_approval_email_template_delete", "Re-read the exact unchanged Approval Email Template recovery baseline and record a single execution confirmation.", ToolPack.V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_PLAN_REFERENCE, ("1.9.1",), True, True, False),
    Capability("execute_confirmed_v4_approval_email_template_delete", "Execute one exact protected and previously confirmed bodyless REST DELETE for only the accepted unreferenced b37/b39 Approval Email Template, with categorical REST/SSH absence readback and no other configuration change.", ToolPack.V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION, ExecutionMode.LIVE, RiskLevel.MODERATE, InputScope.V4_AUTHORIZATION_REFERENCE, ("1.9.1",), True, True, True, device_write=True, destructive=True),
)


DEFAULT_CAPABILITY_REGISTRY = CapabilityRegistry(_PACKS, _CAPABILITIES)


def get_capability_matrix(
    *,
    enabled_packs: Iterable[ToolPack | str] | None = None,
    enabled_tools: Iterable[str] | None = None,
) -> dict[str, object]:
    """Return static annotations without contacting FortiPAM."""

    return DEFAULT_CAPABILITY_REGISTRY.sanitized_matrix(
        enabled_packs=enabled_packs,
        enabled_tools=enabled_tools,
    )


def _normalize_packs(
    selected: Iterable[ToolPack | str] | None,
    definitions: tuple[ToolPackDefinition, ...],
) -> frozenset[ToolPack] | None:
    if selected is None:
        return None
    known = {definition.identifier for definition in definitions}
    normalized: set[ToolPack] = set()
    for item in selected:
        try:
            pack = item if isinstance(item, ToolPack) else ToolPack(item)
        except ValueError as exc:
            raise ValueError(f"Unknown tool pack: {item!r}") from exc
        if pack not in known:
            raise ValueError(f"Unregistered tool pack: {pack.value}")
        normalized.add(pack)
    return frozenset(normalized)


def _normalize_tools(
    selected: Iterable[str] | None,
    capabilities: tuple[Capability, ...],
) -> frozenset[str] | None:
    if selected is None:
        return None
    known = {capability.tool_name for capability in capabilities}
    normalized = frozenset(selected)
    unknown = normalized - known
    if unknown:
        raise ValueError(f"Unknown MCP tool(s): {', '.join(sorted(unknown))}")
    return normalized
