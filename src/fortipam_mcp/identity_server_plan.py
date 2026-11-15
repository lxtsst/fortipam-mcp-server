"""Source-bounded FortiPAM external identity-server planning requirements."""

from __future__ import annotations


V4_LDAP_SERVER_PLAN_TOOL = "get_v4_ldap_server_plan_requirements"
V4_LDAP_SERVER_PLAN_CONTRACT = "fortipam_v4_ldap_server_plan_v1"
V4_RADIUS_SERVER_PLAN_TOOL = "get_v4_radius_server_plan_requirements"
V4_RADIUS_SERVER_PLAN_CONTRACT = "fortipam_v4_radius_server_plan_v1"
V4_SAML_SERVER_PLAN_TOOL = "get_v4_saml_server_plan_requirements"
V4_SAML_SERVER_PLAN_CONTRACT = "fortipam_v4_saml_server_plan_v1"

_IDENTITY_SERVER_PATHS = {
    "ldap": "/api/v2/cmdb/user/ldap",
    "radius": "/api/v2/cmdb/user/radius",
    "saml": "/api/v2/cmdb/user/saml",
}


def _identity_server_api_candidate(server_type: str) -> dict[str, object]:
    """Return one fixed non-callable catalog candidate for an identity server."""

    collection_path = _IDENTITY_SERVER_PATHS[server_type]
    detail_path = f"{collection_path}/{{name}}"
    return {
        "source": "sanitized_fndn_ui_catalog_1_9_0",
        "status": "catalogued_body_unproven",
        "create": {
            "method": "POST",
            "path": collection_path,
            "required_body": True,
            "body_schema_available": False,
        },
        "detail_readback": {
            "method": "GET",
            "path": detail_path,
            "response_schema_available": False,
        },
        "target_version_validated": False,
        "live_call_permitted": False,
    }

_LDAP_DOCUMENTED_REQUIREMENTS = (
    "server_name_address_port_and_directory_type",
    "common_name_identifier_and_distinguished_name",
    "secure_connection_protocol_and_ca_certificate",
    "user_and_group_search_filters_and_bases",
    "group_member_attribute_mapping",
    "bind_account_and_password",
    "connection_test_before_submission",
    "remote_user_group_and_authorization_dependencies",
)

_LDAP_ACCEPTANCE_REQUIREMENTS = (
    "exact_1_9_1_field_transport_and_redacted_readback_contract_verified",
    "fixed_nonproduction_directory_endpoint_and_scope_owner_approved",
    "protected_bind_material_provider_isolated_from_model_and_mcp",
    "tls_protocol_server_identity_and_ca_trust_verified",
    "least_privilege_search_base_filter_and_bind_rights_verified",
    "group_mapping_apl_role_and_login_impact_analyzed",
    "local_break_glass_admin_and_authentication_rollback_verified",
    "negative_positive_and_failure_reconciliation_tests_approved",
)

_LDAP_BLOCKED_OPERATIONS = (
    "device_or_directory_state_read",
    "endpoint_dn_filter_account_password_or_certificate_input",
    "directory_bind_search_or_connection_test",
    "ldap_server_create_update_clone_or_delete",
    "user_group_apl_role_or_user_change",
    "login_authentication_or_provisioning_test",
    "configuration_write",
    "execution_authorization",
)

_RADIUS_DOCUMENTED_REQUIREMENTS = (
    "server_name_and_authentication_type",
    "primary_server_address_and_shared_secret",
    "optional_secondary_server_address_and_shared_secret",
    "primary_reject_and_secondary_no_response_behavior",
    "connection_test_before_submission",
    "remote_user_group_and_authorization_dependencies",
)

_RADIUS_ACCEPTANCE_REQUIREMENTS = (
    "exact_1_9_1_field_transport_and_redacted_readback_contract_verified",
    "fixed_nonproduction_radius_endpoints_and_authentication_type_owner_approved",
    "protected_shared_secret_provider_isolated_from_model_and_mcp",
    "network_source_firewall_timeout_and_server_identity_controls_verified",
    "primary_secondary_reject_timeout_and_failover_behavior_tested",
    "group_mapping_role_and_login_impact_analyzed",
    "local_break_glass_admin_and_authentication_rollback_verified",
    "negative_positive_and_failure_reconciliation_tests_approved",
)

_RADIUS_BLOCKED_OPERATIONS = (
    "device_or_radius_state_read",
    "endpoint_authentication_type_or_shared_secret_input",
    "radius_request_or_connection_test",
    "radius_server_create_update_clone_or_delete",
    "user_group_role_or_user_change",
    "login_authentication_or_authorization_test",
    "configuration_write",
    "execution_authorization",
)

_SAML_DOCUMENTED_REQUIREMENTS = (
    "fortipam_service_provider_role",
    "service_provider_base_entity_sso_and_logout_urls",
    "fortinet_product_or_custom_identity_provider",
    "identity_provider_entity_sso_and_logout_urls",
    "identity_provider_certificate",
    "username_and_group_attribute_mapping",
    "digest_method_and_metadata_exchange",
    "remote_user_or_auto_provision_rule_prerequisite",
    "access_proxy_authentication_scheme_rule_and_login_dependencies",
)

_SAML_ACCEPTANCE_REQUIREMENTS = (
    "exact_1_9_1_field_transport_and_redacted_readback_contract_verified",
    "fixed_nonproduction_sp_idp_metadata_and_certificate_owner_approved",
    "metadata_certificate_and_signing_trust_prevalidated",
    "assertion_audience_recipient_time_replay_and_signature_controls_verified",
    "username_group_apl_role_and_login_mapping_impact_analyzed",
    "wan_callback_access_proxy_and_browser_flow_security_verified",
    "local_break_glass_admin_and_authentication_rollback_verified",
    "negative_positive_and_failure_reconciliation_tests_approved",
)

_SAML_BLOCKED_OPERATIONS = (
    "device_sp_or_idp_state_read",
    "url_entity_certificate_attribute_or_metadata_input",
    "metadata_fetch_upload_or_identity_provider_contact",
    "saml_server_create_update_clone_or_delete",
    "access_proxy_authentication_rule_apl_role_or_user_change",
    "browser_login_assertion_or_logout_test",
    "configuration_write",
    "execution_authorization",
)


def _requirements(
    *,
    contract: str,
    action_family: str,
    source_version: str,
    documented: tuple[str, ...],
    acceptance: tuple[str, ...],
    blocked: tuple[str, ...],
) -> dict[str, object]:
    return {
        "contract": contract,
        "action_family": action_family,
        "source_version": source_version,
        "target_version": "1.9.1",
        "target_version_validation_required": True,
        "planning_status": "requirements_only",
        "documented_requirements": list(documented),
        "project_acceptance_requirements": list(acceptance),
        "blocked_operations": list(blocked),
        "configuration_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "external_identity_service_contacted": False,
        "protected_material_loaded": False,
        "authentication_effect_applied": False,
        "local_state_written": False,
        "raw_source_content_returned": False,
    }


def ldap_server_plan_requirements() -> dict[str, object]:
    """Return fixed non-executable LDAP-server requirements."""

    result = _requirements(
        contract=V4_LDAP_SERVER_PLAN_CONTRACT,
        action_family="ldap-server.configure",
        source_version="1.8.1",
        documented=_LDAP_DOCUMENTED_REQUIREMENTS,
        acceptance=_LDAP_ACCEPTANCE_REQUIREMENTS,
        blocked=_LDAP_BLOCKED_OPERATIONS,
    )
    result["candidate_api_contract"] = _identity_server_api_candidate("ldap")
    return result


def radius_server_plan_requirements() -> dict[str, object]:
    """Return fixed non-executable RADIUS-server requirements."""

    result = _requirements(
        contract=V4_RADIUS_SERVER_PLAN_CONTRACT,
        action_family="radius-server.configure",
        source_version="1.8.0",
        documented=_RADIUS_DOCUMENTED_REQUIREMENTS,
        acceptance=_RADIUS_ACCEPTANCE_REQUIREMENTS,
        blocked=_RADIUS_BLOCKED_OPERATIONS,
    )
    result["candidate_api_contract"] = _identity_server_api_candidate("radius")
    return result


def saml_server_plan_requirements() -> dict[str, object]:
    """Return fixed non-executable SAML-server requirements."""

    result = _requirements(
        contract=V4_SAML_SERVER_PLAN_CONTRACT,
        action_family="saml-server.configure",
        source_version="1.8.1",
        documented=_SAML_DOCUMENTED_REQUIREMENTS,
        acceptance=_SAML_ACCEPTANCE_REQUIREMENTS,
        blocked=_SAML_BLOCKED_OPERATIONS,
    )
    result["candidate_api_contract"] = _identity_server_api_candidate("saml")
    return result


__all__ = [
    "V4_LDAP_SERVER_PLAN_CONTRACT",
    "V4_LDAP_SERVER_PLAN_TOOL",
    "V4_RADIUS_SERVER_PLAN_CONTRACT",
    "V4_RADIUS_SERVER_PLAN_TOOL",
    "V4_SAML_SERVER_PLAN_CONTRACT",
    "V4_SAML_SERVER_PLAN_TOOL",
    "ldap_server_plan_requirements",
    "radius_server_plan_requirements",
    "saml_server_plan_requirements",
]
