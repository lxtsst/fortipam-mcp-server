"""Source-bounded FortiPAM JWT-key creation and rotation requirements."""

from __future__ import annotations


V4_JWT_KEY_CREATE_PLAN_TOOL = "get_v4_jwt_key_create_plan_requirements"
V4_JWT_KEY_CREATE_PLAN_CONTRACT = "fortipam_v4_jwt_key_create_plan_v1"
V4_JWT_KEY_ROTATE_PLAN_TOOL = "get_v4_jwt_key_rotate_plan_requirements"
V4_JWT_KEY_ROTATE_PLAN_CONTRACT = "fortipam_v4_jwt_key_rotate_plan_v1"

_JWT_KEY_COLLECTION_PATH = "/api/v2/cmdb/secret/jwt-key"
_JWT_KEY_DETAIL_PATH = "/api/v2/cmdb/secret/jwt-key/{name}"


def _jwt_key_create_api_candidate() -> dict[str, object]:
    """Return fixed non-callable catalog evidence for JWT-key creation."""

    return {
        "source": "sanitized_fndn_ui_catalog_1_9_0",
        "status": "catalogued_body_unproven",
        "create": {
            "method": "POST",
            "path": _JWT_KEY_COLLECTION_PATH,
            "required_body": True,
            "body_schema_available": False,
        },
        "detail_readback": {
            "method": "GET",
            "path": _JWT_KEY_DETAIL_PATH,
            "response_schema_available": False,
        },
        "target_version_validated": False,
        "live_call_permitted": False,
    }


def _jwt_key_rotate_api_candidate() -> dict[str, object]:
    """Return fixed non-callable catalog evidence for JWT-key rotation."""

    return {
        "source": "sanitized_fndn_ui_catalog_1_9_0",
        "status": "catalogued_body_unproven",
        "update": {
            "method": "PUT",
            "path": _JWT_KEY_DETAIL_PATH,
            "required_body": True,
            "body_schema_available": False,
        },
        "detail_readback": {
            "method": "GET",
            "path": _JWT_KEY_DETAIL_PATH,
            "response_schema_available": False,
        },
        "target_version_validated": False,
        "live_call_permitted": False,
    }

_CREATE_DOCUMENTED_REQUIREMENTS = (
    "jwt_key_name",
    "manual_jwks_or_oidc_type",
    "one_or_more_manual_public_keys",
    "jwks_or_oidc_discovery_url",
    "remote_key_check_interval_hours",
    "ca_certificate_for_remote_server_identity",
    "jwt_user_claim_and_lease_dependencies",
)

_CREATE_ACCEPTANCE_REQUIREMENTS = (
    "exact_1_9_1_field_transport_and_redacted_readback_contract_verified",
    "fixed_nonproduction_issuer_audience_key_type_and_absent_name_owner_approved",
    "public_key_or_remote_jwks_provider_isolated_from_model_and_mcp",
    "tls_server_identity_ca_dns_and_egress_controls_verified",
    "algorithm_key_use_issuer_audience_and_claim_policy_prevalidated",
    "jwt_user_role_secret_acl_and_lease_impact_analyzed",
    "local_admin_and_non_jwt_authentication_recovery_verified",
    "negative_positive_expiry_replay_and_failure_tests_approved",
)

_CREATE_BLOCKED_OPERATIONS = (
    "device_or_identity_provider_state_read",
    "key_url_certificate_issuer_audience_or_claim_input",
    "jwks_oidc_metadata_or_key_fetch",
    "jwt_key_create_update_clone_or_delete",
    "jwt_user_role_claim_or_secret_acl_change",
    "jwt_validation_login_or_secret_access_test",
    "configuration_write",
    "execution_authorization",
)

_ROTATE_DOCUMENTED_REQUIREMENTS = (
    "manual_key_list_addition_and_removal",
    "jwks_or_oidc_periodic_key_retrieval",
    "last_check_and_last_update_observation",
    "remote_key_check_interval_hours",
    "ca_certificate_for_remote_server_identity",
    "dependent_jwt_user_claim_and_lease_behavior",
)

_ROTATE_ACCEPTANCE_REQUIREMENTS = (
    "exact_1_9_1_update_transport_and_redacted_readback_contract_verified",
    "fixed_existing_key_complete_baseline_and_dependencies_verified",
    "new_and_retiring_key_identifiers_overlap_and_cutover_owner_approved",
    "protected_key_or_remote_jwks_provider_isolated_from_model_and_mcp",
    "issuer_audience_algorithm_claim_and_cache_behavior_prevalidated",
    "active_jwt_lease_secret_acl_and_revocation_impact_analyzed",
    "old_key_rollback_window_and_local_admin_recovery_verified",
    "negative_positive_stale_fetch_and_failure_reconciliation_tests_approved",
)

_ROTATE_BLOCKED_OPERATIONS = (
    "device_or_identity_provider_state_read",
    "key_url_certificate_issuer_audience_or_claim_input",
    "jwks_oidc_metadata_or_key_fetch",
    "jwt_key_create_update_rotate_or_delete",
    "jwt_user_role_claim_or_secret_acl_change",
    "jwt_validation_login_or_secret_access_test",
    "configuration_write",
    "execution_authorization",
)


def _requirements(
    *,
    contract: str,
    action_family: str,
    documented: tuple[str, ...],
    acceptance: tuple[str, ...],
    blocked: tuple[str, ...],
) -> dict[str, object]:
    return {
        "contract": contract,
        "action_family": action_family,
        "source_version": "1.8.1",
        "target_version": "1.9.1",
        "target_version_validation_required": True,
        "planning_status": "requirements_only",
        "documented_requirements": list(documented),
        "project_acceptance_requirements": list(acceptance),
        "blocked_operations": list(blocked),
        "configuration_ready": False,
        "execution_authorized": False,
        "fortipam_contacted": False,
        "identity_provider_contacted": False,
        "protected_material_loaded": False,
        "authentication_effect_applied": False,
        "local_state_written": False,
        "raw_source_content_returned": False,
    }


def jwt_key_create_plan_requirements() -> dict[str, object]:
    """Return fixed non-executable JWT-key creation requirements."""

    result = _requirements(
        contract=V4_JWT_KEY_CREATE_PLAN_CONTRACT,
        action_family="jwt-key.create",
        documented=_CREATE_DOCUMENTED_REQUIREMENTS,
        acceptance=_CREATE_ACCEPTANCE_REQUIREMENTS,
        blocked=_CREATE_BLOCKED_OPERATIONS,
    )
    result["candidate_api_contract"] = _jwt_key_create_api_candidate()
    return result


def jwt_key_rotate_plan_requirements() -> dict[str, object]:
    """Return fixed non-executable JWT-key rotation requirements."""

    result = _requirements(
        contract=V4_JWT_KEY_ROTATE_PLAN_CONTRACT,
        action_family="jwt-key.rotate",
        documented=_ROTATE_DOCUMENTED_REQUIREMENTS,
        acceptance=_ROTATE_ACCEPTANCE_REQUIREMENTS,
        blocked=_ROTATE_BLOCKED_OPERATIONS,
    )
    result["candidate_api_contract"] = _jwt_key_rotate_api_candidate()
    return result


__all__ = [
    "V4_JWT_KEY_CREATE_PLAN_CONTRACT",
    "V4_JWT_KEY_CREATE_PLAN_TOOL",
    "V4_JWT_KEY_ROTATE_PLAN_CONTRACT",
    "V4_JWT_KEY_ROTATE_PLAN_TOOL",
    "jwt_key_create_plan_requirements",
    "jwt_key_rotate_plan_requirements",
]
