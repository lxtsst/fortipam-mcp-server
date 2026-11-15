"""Source-pinned FortiPAM 1.9.1 email configuration planning requirements.

The fixed planning contracts accept no endpoint, account, password,
certificate, sender, recipient, device route, mutable state, or execution
decision.  They return documented field categories and the project evidence
required before any future mail configuration or notification package.
"""

from __future__ import annotations


V4_SYSTEM_EMAIL_PLAN_TOOL = "get_v4_system_email_plan_requirements"
V4_SYSTEM_EMAIL_PLAN_CONTRACT = "fortipam_v4_system_email_plan_v1"
V4_SYSTEM_EMAIL_BUILD_TOOL = "build_v4_system_email_plan"
V4_SYSTEM_EMAIL_BUILD_CONTRACT = "fortipam_v4_system_email_plan_builder_v1"
V4_EMAIL_ALERT_PLAN_TOOL = "get_v4_email_alert_plan_requirements"
V4_EMAIL_ALERT_PLAN_CONTRACT = "fortipam_v4_email_alert_plan_v1"
V4_EMAIL_ALERT_BUILD_TOOL = "build_v4_email_alert_plan"
V4_EMAIL_ALERT_BUILD_CONTRACT = "fortipam_v4_email_alert_plan_builder_v1"

_SYSTEM_EMAIL_DOCUMENTED_REQUIREMENTS = (
    "default_or_custom_email_service_selection",
    "smtp_server_and_port",
    "optional_authentication_username_and_password",
    "none_smtps_or_starttls_security_mode",
    "sender_and_optional_default_reply_to",
    "email_service_supports_alert_token_and_guest_delivery",
    "approval_email_uses_separate_inbound_server_settings",
    "approval_email_can_use_imap_credential_and_server_certificate",
)

_SYSTEM_EMAIL_PROJECT_ACCEPTANCE_REQUIREMENTS = (
    "outbound_and_approval_inbound_scopes_kept_separate",
    "dedicated_nonproduction_mail_service_and_account_approved",
    "dns_egress_port_and_firewall_dependencies_verified",
    "validated_tls_mode_and_trust_anchor_required",
    "credential_custody_kept_outside_mcp",
    "sender_domain_and_relay_policy_verified",
    "no_delivery_test_without_separate_recipient_authority",
    "redacted_configuration_readback_defined",
    "rollback_and_failure_reconciliation_approved",
)

_SYSTEM_EMAIL_BLOCKED_OPERATIONS = (
    "device_state_read",
    "mail_endpoint_or_port_input",
    "username_or_password_input_or_output",
    "sender_reply_to_or_domain_input",
    "certificate_input_or_output",
    "smtp_or_imap_connection",
    "test_email_delivery",
    "configuration_write",
    "execution_authorization",
)

_EMAIL_ALERT_DOCUMENTED_REQUIREMENTS = (
    "email_service_configured_before_alerts",
    "global_email_notification_enablement",
    "critical_system_general_and_certificate_categories",
    "sender_and_recipient_configuration",
    "event_or_severity_selection",
    "event_delivery_interval",
    "certificate_expiry_notice_period",
    "enabled_alerts_can_generate_external_email",
)

_EMAIL_ALERT_PROJECT_ACCEPTANCE_REQUIREMENTS = (
    "exact_alert_categories_and_thresholds_owner_approved",
    "dedicated_nonproduction_recipients_approved",
    "notification_content_and_identity_exposure_reviewed",
    "mail_service_dependency_verified_separately",
    "rate_volume_and_loop_controls_verified",
    "no_test_or_live_notification_without_separate_authority",
    "redacted_configuration_and_delivery_readback_defined",
    "rollback_and_failure_reconciliation_approved",
)

_EMAIL_ALERT_BLOCKED_OPERATIONS = (
    "device_state_read",
    "sender_or_recipient_input",
    "alert_category_or_threshold_input",
    "mail_service_configuration",
    "email_notification_enablement",
    "test_or_live_email_delivery",
    "configuration_write",
    "execution_authorization",
)

_SYSTEM_EMAIL_PLAN_FIELDS = (
    "mail_scopes_separated",
    "nonproduction_service_approved",
    "network_dependencies_verified",
    "tls_trust_verified",
    "credential_custody_ready",
    "sender_relay_policy_verified",
    "delivery_test_separately_gated",
    "redacted_readback_defined",
    "failure_rollback_approved",
)

_EMAIL_ALERT_PLAN_FIELDS = (
    "categories_thresholds_approved",
    "nonproduction_recipients_approved",
    "content_identity_exposure_reviewed",
    "mail_dependency_verified",
    "rate_loop_controls_verified",
    "notification_delivery_separately_gated",
    "redacted_readback_defined",
    "failure_rollback_approved",
)


def system_email_plan_requirements() -> dict[str, object]:
    """Return a fixed, value-free FortiPAM 1.9.1 mail-service boundary."""

    return {
        "contract": V4_SYSTEM_EMAIL_PLAN_CONTRACT,
        "action_family": "system-email.configure",
        "target_version": "1.9.1",
        "planning_status": "requirements_only",
        "documented_requirements": list(_SYSTEM_EMAIL_DOCUMENTED_REQUIREMENTS),
        "project_acceptance_requirements": list(
            _SYSTEM_EMAIL_PROJECT_ACCEPTANCE_REQUIREMENTS
        ),
        "blocked_operations": list(_SYSTEM_EMAIL_BLOCKED_OPERATIONS),
        "configuration_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "mail_service_contacted": False,
        "local_state_written": False,
        "protected_material_accepted": False,
        "raw_source_content_returned": False,
    }


def email_alert_plan_requirements() -> dict[str, object]:
    """Return a fixed, value-free FortiPAM 1.9.1 alert-policy boundary."""

    return {
        "contract": V4_EMAIL_ALERT_PLAN_CONTRACT,
        "action_family": "email-alert.configure",
        "target_version": "1.9.1",
        "planning_status": "requirements_only",
        "documented_requirements": list(_EMAIL_ALERT_DOCUMENTED_REQUIREMENTS),
        "project_acceptance_requirements": list(
            _EMAIL_ALERT_PROJECT_ACCEPTANCE_REQUIREMENTS
        ),
        "blocked_operations": list(_EMAIL_ALERT_BLOCKED_OPERATIONS),
        "configuration_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "mail_service_contacted": False,
        "local_state_written": False,
        "protected_material_accepted": False,
        "raw_source_content_returned": False,
    }


def _build_plan_result(
    *,
    contract: str,
    action_family: str,
    fields: tuple[str, ...],
    evidence: dict[str, bool],
) -> dict[str, object]:
    if any(type(value) is not bool for value in evidence.values()):
        raise ValueError(f"{action_family} plan evidence must be boolean.")
    missing = [name for name in fields if not evidence[name]]
    return {
        "contract": contract,
        "action_family": action_family,
        "target_version": "1.9.1",
        "planning_status": (
            "ready_for_operator_review" if not missing else "incomplete_evidence"
        ),
        "evidence_origin": "caller_attested_categorical_inputs",
        "missing_requirements": missing,
        "satisfied_requirement_count": len(fields) - len(missing),
        "requirement_count": len(fields),
        "plan_ready": not missing,
        "authoritative_device_state_observed": False,
        "mail_service_state_observed": False,
        "configuration_execution_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "mail_service_contacted": False,
        "local_state_written": False,
        "protected_material_accepted": False,
        "raw_source_content_returned": False,
    }


def build_system_email_plan(
    *,
    mail_scopes_separated: bool,
    nonproduction_service_approved: bool,
    network_dependencies_verified: bool,
    tls_trust_verified: bool,
    credential_custody_ready: bool,
    sender_relay_policy_verified: bool,
    delivery_test_separately_gated: bool,
    redacted_readback_defined: bool,
    failure_rollback_approved: bool,
) -> dict[str, object]:
    """Evaluate a value-free, caller-attested system-email checklist."""

    return _build_plan_result(
        contract=V4_SYSTEM_EMAIL_BUILD_CONTRACT,
        action_family="system-email.configure",
        fields=_SYSTEM_EMAIL_PLAN_FIELDS,
        evidence={
            "mail_scopes_separated": mail_scopes_separated,
            "nonproduction_service_approved": nonproduction_service_approved,
            "network_dependencies_verified": network_dependencies_verified,
            "tls_trust_verified": tls_trust_verified,
            "credential_custody_ready": credential_custody_ready,
            "sender_relay_policy_verified": sender_relay_policy_verified,
            "delivery_test_separately_gated": delivery_test_separately_gated,
            "redacted_readback_defined": redacted_readback_defined,
            "failure_rollback_approved": failure_rollback_approved,
        },
    )


def build_email_alert_plan(
    *,
    categories_thresholds_approved: bool,
    nonproduction_recipients_approved: bool,
    content_identity_exposure_reviewed: bool,
    mail_dependency_verified: bool,
    rate_loop_controls_verified: bool,
    notification_delivery_separately_gated: bool,
    redacted_readback_defined: bool,
    failure_rollback_approved: bool,
) -> dict[str, object]:
    """Evaluate a value-free, caller-attested email-alert checklist."""

    return _build_plan_result(
        contract=V4_EMAIL_ALERT_BUILD_CONTRACT,
        action_family="email-alert.configure",
        fields=_EMAIL_ALERT_PLAN_FIELDS,
        evidence={
            "categories_thresholds_approved": categories_thresholds_approved,
            "nonproduction_recipients_approved": nonproduction_recipients_approved,
            "content_identity_exposure_reviewed": content_identity_exposure_reviewed,
            "mail_dependency_verified": mail_dependency_verified,
            "rate_loop_controls_verified": rate_loop_controls_verified,
            "notification_delivery_separately_gated": (
                notification_delivery_separately_gated
            ),
            "redacted_readback_defined": redacted_readback_defined,
            "failure_rollback_approved": failure_rollback_approved,
        },
    )


__all__ = [
    "V4_EMAIL_ALERT_BUILD_CONTRACT",
    "V4_EMAIL_ALERT_BUILD_TOOL",
    "V4_EMAIL_ALERT_PLAN_CONTRACT",
    "V4_EMAIL_ALERT_PLAN_TOOL",
    "V4_SYSTEM_EMAIL_BUILD_CONTRACT",
    "V4_SYSTEM_EMAIL_BUILD_TOOL",
    "V4_SYSTEM_EMAIL_PLAN_CONTRACT",
    "V4_SYSTEM_EMAIL_PLAN_TOOL",
    "build_email_alert_plan",
    "build_system_email_plan",
    "email_alert_plan_requirements",
    "system_email_plan_requirements",
]
