"""Source-bounded FortiPAM certificate and CRL import requirements.

The fixed no-input contracts expose planning categories only. They never load
certificate, key, password, revocation, endpoint, or device material and do
not infer an executable import transport.
"""

from __future__ import annotations


V4_CERTIFICATE_IMPORT_PLAN_TOOL = "get_v4_certificate_import_plan_requirements"
V4_CERTIFICATE_IMPORT_PLAN_CONTRACT = "fortipam_v4_certificate_import_plan_v1"
V4_CRL_IMPORT_PLAN_TOOL = "get_v4_crl_import_plan_requirements"
V4_CRL_IMPORT_PLAN_CONTRACT = "fortipam_v4_crl_import_plan_v1"

_CERTIFICATE_IMPORT_PATHS = (
    ("ca", "/api/v2/monitor/vpn-certificate/ca/import"),
    ("local", "/api/v2/monitor/vpn-certificate/local/import"),
    ("remote", "/api/v2/monitor/vpn-certificate/remote/import"),
)
_CRL_IMPORT_PATH = "/api/v2/monitor/vpn-certificate/crl/import"


def _certificate_import_api_candidate() -> dict[str, object]:
    """Return fixed non-callable catalog evidence for certificate imports."""

    return {
        "source": "sanitized_fndn_ui_catalog_1_9_0",
        "status": "catalogued_body_unproven",
        "imports": [
            {
                "certificate_type": certificate_type,
                "method": "POST",
                "path": path,
                "required_body": True,
                "body_schema_available": False,
                "response_schema_available": False,
            }
            for certificate_type, path in _CERTIFICATE_IMPORT_PATHS
        ],
        "target_version_validated": False,
        "live_call_permitted": False,
    }


def _crl_import_api_candidate() -> dict[str, object]:
    """Return fixed non-callable catalog evidence for CRL import."""

    return {
        "source": "sanitized_fndn_ui_catalog_1_9_0",
        "status": "catalogued_body_unproven",
        "import": {
            "method": "POST",
            "path": _CRL_IMPORT_PATH,
            "required_body": True,
            "body_schema_available": False,
            "response_schema_available": False,
        },
        "target_version_validated": False,
        "live_call_permitted": False,
    }

_CERTIFICATE_DOCUMENTED_REQUIREMENTS = (
    "local_certificate_for_existing_device_generated_key",
    "pkcs12_certificate_with_encrypted_private_key",
    "separate_certificate_and_private_key_files",
    "password_and_confirmation_for_private_key_imports",
    "ca_certificate_file_or_online_scep_source",
    "optional_ca_identifier_for_scep",
    "remote_public_certificate_without_private_key",
    "certificate_name_type_and_scope",
)

_CERTIFICATE_ACCEPTANCE_REQUIREMENTS = (
    "exact_1_9_1_import_field_transport_and_response_contract_verified",
    "fixed_certificate_type_scope_name_and_absence_owner_approved",
    "certificate_chain_key_match_algorithm_and_validity_prevalidated",
    "protected_artifact_and_password_provider_isolated_from_model_and_mcp",
    "private_key_export_logging_and_persistence_prevented",
    "existing_bindings_name_collisions_and_trust_impact_analyzed",
    "categorical_fingerprint_key_presence_and_chain_readback_defined",
    "separately_confirmed_binding_rollback_and_failure_reconciliation_approved",
)

_CERTIFICATE_BLOCKED_OPERATIONS = (
    "device_certificate_state_read",
    "certificate_key_password_or_scep_input",
    "artifact_upload_download_or_content_return",
    "private_key_generation_export_or_inspection",
    "certificate_or_ca_import_create_update_delete",
    "certificate_binding_or_trust_change",
    "network_or_scep_contact",
    "configuration_write",
    "execution_authorization",
)

_CRL_DOCUMENTED_REQUIREMENTS = (
    "file_based_or_online_updating_method",
    "http_update_server_option",
    "ldap_server_account_and_password_option",
    "scep_local_certificate_and_server_option",
    "issuer_effective_time_next_update_and_sequence_freshness",
    "revoked_certificate_trust_effect",
)

_CRL_ACCEPTANCE_REQUIREMENTS = (
    "exact_1_9_1_crl_field_transport_and_response_contract_verified",
    "fixed_import_method_issuer_scope_and_absence_owner_approved",
    "crl_signature_issuer_freshness_and_rollback_protection_prevalidated",
    "protected_artifact_account_password_and_certificate_provider_isolated",
    "http_ldap_scep_network_egress_and_tls_trust_approved",
    "existing_crl_certificate_bindings_and_trust_impact_analyzed",
    "categorical_issuer_sequence_validity_and_update_readback_defined",
    "separately_confirmed_replacement_rollback_and_failure_reconciliation_approved",
)

_CRL_BLOCKED_OPERATIONS = (
    "device_certificate_or_crl_state_read",
    "crl_url_ldap_account_password_or_scep_input",
    "artifact_upload_download_or_content_return",
    "http_ldap_scep_or_ca_contact",
    "crl_import_update_delete_or_refresh",
    "certificate_binding_or_trust_change",
    "configuration_write",
    "execution_authorization",
)


def _requirements(
    *,
    contract: str,
    action_family: str,
    source_version: str,
    validation_required: bool,
    documented: tuple[str, ...],
    acceptance: tuple[str, ...],
    blocked: tuple[str, ...],
) -> dict[str, object]:
    return {
        "contract": contract,
        "action_family": action_family,
        "source_version": source_version,
        "target_version": "1.9.1",
        "target_version_validation_required": validation_required,
        "planning_status": "requirements_only",
        "documented_requirements": list(documented),
        "project_acceptance_requirements": list(acceptance),
        "blocked_operations": list(blocked),
        "configuration_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "external_service_contacted": False,
        "local_state_written": False,
        "protected_material_loaded": False,
        "raw_source_content_returned": False,
    }


def certificate_import_plan_requirements() -> dict[str, object]:
    """Return fixed non-executable certificate-import requirements."""

    result = _requirements(
        contract=V4_CERTIFICATE_IMPORT_PLAN_CONTRACT,
        action_family="certificate.import",
        source_version="1.9.1",
        validation_required=False,
        documented=_CERTIFICATE_DOCUMENTED_REQUIREMENTS,
        acceptance=_CERTIFICATE_ACCEPTANCE_REQUIREMENTS,
        blocked=_CERTIFICATE_BLOCKED_OPERATIONS,
    )
    result["candidate_api_contract"] = _certificate_import_api_candidate()
    return result


def crl_import_plan_requirements() -> dict[str, object]:
    """Return fixed source-bounded non-executable CRL-import requirements."""

    result = _requirements(
        contract=V4_CRL_IMPORT_PLAN_CONTRACT,
        action_family="crl.import",
        source_version="1.0.3",
        validation_required=True,
        documented=_CRL_DOCUMENTED_REQUIREMENTS,
        acceptance=_CRL_ACCEPTANCE_REQUIREMENTS,
        blocked=_CRL_BLOCKED_OPERATIONS,
    )
    result["candidate_api_contract"] = _crl_import_api_candidate()
    return result


__all__ = [
    "V4_CERTIFICATE_IMPORT_PLAN_CONTRACT",
    "V4_CERTIFICATE_IMPORT_PLAN_TOOL",
    "V4_CRL_IMPORT_PLAN_CONTRACT",
    "V4_CRL_IMPORT_PLAN_TOOL",
    "certificate_import_plan_requirements",
    "crl_import_plan_requirements",
]
